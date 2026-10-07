"""Explicitly scoped, TLS-validated local GET polling. No commands or cloud paths."""
from __future__ import annotations

import base64
import http.client
import ipaddress
import json
import os
import re
import ssl
import stat
import socket
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlencode, urlsplit

from safecadence.security.local_only import LocalPolicy
from .security_import import MAX_BYTES, ImportRejected, decode, timestamp
from .security_store import _identifier, now

SOURCES = frozenset({"wazuh", "crowdsec", "frigate", "home-assistant", "thingsboard"})
_READ_PATHS = (
    re.compile(r"/wazuh-alerts-[A-Za-z0-9.*_-]+/_search\Z"),
    re.compile(r"/v1/alerts\Z"), re.compile(r"/api/events\Z"),
    re.compile(r"/api/states/(?:binary_sensor|sensor)\.[A-Za-z0-9_.-]+\Z"),
    re.compile(r"/api/plugins/telemetry/DEVICE/[a-fA-F0-9-]{36}/values/timeseries\Z"),
)


class ConnectorRejected(ImportRejected):
    """Stable reason codes; never include response bodies, URLs or secrets."""


@contextmanager
def bounded_socket(sock, timeout):
    """Interrupt trickled headers as well as stalled bodies at an absolute deadline."""
    expired = threading.Event()

    def interrupt():
        expired.set()
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    timer = threading.Timer(timeout, interrupt)
    timer.daemon = True
    timer.start()
    try:
        yield expired
    finally:
        timer.cancel()
        timer.join()


def private_file(path, *, maximum=65536):
    """Read owner-only credentials without following a final-component symlink."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or
                hasattr(os, "getuid") and info.st_uid != os.getuid()):
            raise ConnectorRejected("secret_file_permissions")
        data = os.read(fd, maximum + 1)
        if len(data) > maximum:
            raise ConnectorRejected("secret_file_limit")
        return data
    finally:
        os.close(fd)


def local_endpoint(url, approved_targets):
    parsed = urlsplit(url)
    try:
        address = ipaddress.ip_address(parsed.hostname)
        port = parsed.port or 443
    except (ValueError, TypeError):
        raise ConnectorRejected("numeric_local_endpoint_required") from None
    internal = address.is_loopback or any(address.version == net.version and address in net
        for net in map(ipaddress.ip_network, ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")))
    if (not internal or parsed.scheme != "https" or parsed.path not in ("", "/") or
            parsed.query or parsed.fragment or parsed.username or parsed.password or
            (str(address), port) not in approved_targets):
        raise ConnectorRejected("endpoint_not_approved")
    return str(address), port


def approved_targets():
    try:
        rows = json.loads(os.environ.get("SC_LOCAL_INTERNAL_TARGETS", "[]"))
        # Loopback is also explicit for connectors, unlike generic local UI listeners.
        result = tuple((str(ipaddress.ip_address(row["ip"])), row["port"]) for row in rows)
        LocalPolicy(tuple(pair for pair in result if not ipaddress.ip_address(pair[0]).is_loopback))
        if any(isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535 for _, port in result):
            raise ValueError
        return result
    except (ValueError, TypeError, KeyError):
        raise ConnectorRejected("invalid_approved_targets") from None


class LocalHTTPS:
    def __init__(self, endpoint, *, targets, ca_file=None, auth=None,
                 client_cert=None, client_key=None, timeout=10):
        self.host, self.port = local_endpoint(endpoint, targets)
        self.context = ssl.create_default_context(cafile=ca_file)
        if client_cert or client_key:
            if not client_cert or not client_key:
                raise ConnectorRejected("client_certificate_pair_required")
            private_file(client_key)
            self.context.load_cert_chain(client_cert, client_key)
        if not 0 < timeout <= 30:
            raise ConnectorRejected("invalid_timeout")
        self.timeout = timeout
        self.headers = {"Accept": "application/json", "Accept-Encoding": "identity"}
        if auth:
            kind, secret = auth
            if not isinstance(secret, str) or not secret or len(secret) > 8192 or any(c in secret for c in "\r\n"):
                raise ConnectorRejected("invalid_credentials")
            header = "X-Authorization" if kind == "thingsboard" else "Authorization"
            self.headers[header] = secret if kind == "basic" else "Bearer " + secret

    def _request(self, method, path, *, body=None, headers=None):
        connection = http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout, context=self.context)
        started = time.monotonic()
        expired = None
        try:
            connection.connect()
            remaining = self.timeout - (time.monotonic() - started)
            if remaining <= 0:
                raise ConnectorRejected("collection_deadline")
            sock = connection.sock
            with bounded_socket(sock, remaining) as expired:
                connection.request(method, path, body=body, headers={**self.headers, **(headers or {})})
                response = connection.getresponse()
                if expired.is_set():
                    raise ConnectorRejected("collection_deadline")
                if response.status != 200:
                    raise ConnectorRejected("authentication_failed" if response.status in (401, 403)
                                            else "redirect_forbidden" if 300 <= response.status < 400 else "upstream_http_error")
                if response.getheader("Content-Encoding", "identity") != "identity":
                    raise ConnectorRejected("compressed_response_forbidden")
                if response.getheader("Content-Type", "").split(";")[0].lower() != "application/json":
                    raise ConnectorRejected("json_response_required")
                chunks, length = [], 0
                while True:
                    remaining = self.timeout - (time.monotonic() - started)
                    if remaining <= 0:
                        raise ConnectorRejected("collection_deadline")
                    if sock.fileno() >= 0:
                        sock.settimeout(remaining)
                    chunk = response.read1(min(65536, MAX_BYTES + 1 - length))
                    if expired.is_set():
                        raise ConnectorRejected("collection_deadline")
                    if not chunk:
                        break
                    chunks.append(chunk)
                    length += len(chunk)
                    if length > MAX_BYTES:
                        raise ConnectorRejected("response_size_limit")
                return b"".join(chunks)
        except ConnectorRejected:
            raise
        except (OSError, ssl.SSLError, http.client.HTTPException, ValueError):
            raise ConnectorRejected("collection_deadline" if expired is not None and expired.is_set()
                                    else "local_transport_failed") from None
        finally:
            connection.close()

    def get(self, path, query=None):
        if not any(rule.fullmatch(path) for rule in _READ_PATHS):
            raise ConnectorRejected("read_path_forbidden")
        return self._request("GET", path + ("?" + urlencode(query) if query else ""))


def credentials(config):
    value = json.loads(private_file(config["credential_file"]))
    if config["source"] == "wazuh":
        user, password = value["username"], value["password"]
        if not isinstance(user, str) or ":" in user or not isinstance(password, str):
            raise ConnectorRejected("invalid_credentials")
        return "basic", "Basic " + base64.b64encode((user + ":" + password).encode()).decode()
    return config["source"], value["token"]


def _config(value):
    if not isinstance(value, dict) or value.get("source") not in SOURCES:
        raise ConnectorRejected("unsupported_connector")
    for field in ("tenant", "instance", "source_version"):
        _identifier(value[field])
    allowed = {"source", "tenant", "site", "instance", "source_version", "endpoint", "ca_file",
               "credential_file", "client_cert", "client_key", "limit", "index", "device_ids"}
    if set(value) - allowed:
        raise ConnectorRejected("unknown_connector_option")
    limit = value.get("limit", 100)
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
        raise ConnectorRejected("invalid_page_limit")
    return limit


def _rows(transport, config, limit, scope):
    source = config["source"]
    deadline = time.monotonic() + 30
    def get(path, query=None):
        if time.monotonic() >= deadline:
            raise ConnectorRejected("collection_deadline")
        if isinstance(transport, LocalHTTPS):
            transport.timeout = max(0.01, min(transport.timeout, deadline - time.monotonic()))
        result = transport.get(path, query)
        if time.monotonic() >= deadline:
            raise ConnectorRejected("collection_deadline")
        return result

    if source == "wazuh":
        index = config.get("index", "wazuh-alerts-*")
        if not re.fullmatch(r"wazuh-alerts-[A-Za-z0-9.*_-]+", index):
            raise ConnectorRejected("index_scope_forbidden")
        # OpenSearch's GET source parameter is a read-only search request.
        query = json.dumps({"size": limit, "sort": [{"timestamp": "desc"}]})
        rows = decode(get("/" + index + "/_search", {"source": query, "source_content_type": "application/json"}))
        if len(rows) > limit:
            raise ConnectorRejected("upstream_page_limit_exceeded")
        return rows
    if source == "crowdsec":
        rows = decode(get("/v1/alerts", {"limit": limit}))
        if len(rows) > limit:
            raise ConnectorRejected("upstream_page_limit_exceeded")
        return rows
    if source == "home-assistant":
        rows = []
        for entity in scope["entities"]:
            states = decode(get("/api/states/" + entity), unwrap=False)
            if len(states) != 1 or states[0].get("entity_id") != entity:
                raise ConnectorRejected("entity_identity_mismatch")
            state = states[0]
            observed = timestamp(state.get("last_updated"))
            if observed is None:
                raise ConnectorRejected("observation_timestamp_required")
            rows.append({"event_type": "state_changed", "time_fired": observed,
                         "data": {"entity_id": entity, "new_state": state}})
        return rows
    if source == "frigate":
        rows = []
        for camera, zones in scope["cameras"].items():
            events = decode(get("/api/events", {"cameras": camera, "zones": ",".join(zones),
                           "labels": "person,car", "limit": limit, "include_thumbnails": 0}), unwrap=False)
            if len(events) > limit:
                raise ConnectorRejected("upstream_page_limit_exceeded")
            for event in events:
                # An API event has historical zones, not current zone occupancy.
                if event.get("camera") != camera or event.get("label") not in {"person", "car"}:
                    raise ConnectorRejected("camera_scope_mismatch")
                ended = event.get("end_time") is not None
                event_time = timestamp(event.get("end_time") if ended else event.get("start_time"))
                rows.append({"topic": "frigate/events", "captured_at": event_time, "retained": False,
                    "payload": {"type": "end" if ended else "new", "after": {
                        "id": event.get("id"), "camera": camera, "label": event.get("label"),
                        "frame_time": event.get("start_time"), "end_time": event.get("end_time"),
                        "current_zones": [], "entered_zones": event.get("zones", []),
                        "false_positive": event.get("false_positive", False)}}})
        return rows
    rows = []
    from uuid import UUID
    devices = config.get("device_ids", {})
    if set(devices) != set(scope["devices"]):
        raise ConnectorRejected("device_mapping_scope_mismatch")
    for name, spec in scope["devices"].items():
        device_id = str(UUID(devices[name]))
        keys = spec["telemetry"]
        if not keys:
            raise ConnectorRejected("telemetry_scope_required")
        data = decode(get("/api/plugins/telemetry/DEVICE/" + device_id + "/values/timeseries",
                                   {"keys": ",".join(keys)}), unwrap=False)
        if len(data) != 1 or set(data[0]) - set(keys):
            raise ConnectorRejected("telemetry_scope_mismatch")
        for key, samples in data[0].items():
            if not isinstance(samples, list) or len(samples) != 1:
                raise ConnectorRejected("latest_telemetry_required")
            sample = samples[0]
            value = sample["value"]
            if keys[key]["kind"] == "temperature":
                if isinstance(value, bool):
                    raise ConnectorRejected("invalid_temperature_value")
                value = float(value)
            elif value is True or value == "true":
                value = True
            elif value is False or value == "false":
                value = False
            else:
                raise ConnectorRejected("invalid_binary_telemetry")
            rows.append({"export_schema": "netrisk-thingsboard-v1", "type": "telemetry", "device": name,
                         "observed_at": timestamp(sample["ts"] / 1000), "key": key,
                         "value": value, "state": "observed", "unit": keys[key]["unit"]})
    return rows


def poll(store, config, *, targets=None, transport=None):
    """One bounded snapshot, atomic import, and audited outcome. No scheduler side effects."""
    tenant = _identifier(config["tenant"])
    source, instance = _identifier(config["source"]), _identifier(config["instance"])
    try:
        limit = _config(config)
        # Validate endpoint even when testing with an injected transport.
        targets = approved_targets() if targets is None else targets
        local_endpoint(config["endpoint"], targets)
        scope, scope_hash = {}, None
        if source not in {"wazuh", "crowdsec"}:
            site = _identifier(config["site"])
            row = store.conn.execute("SELECT config FROM safety_sources WHERE tenant=? AND site=? AND source=? AND instance=?",
                                     (tenant, site, source, instance)).fetchone()
            if row is None:
                raise ConnectorRejected("source_not_registered")
            registered = json.loads(row[0])
            if registered["source_version"] != config["source_version"]:
                raise ConnectorRejected("source_version_mismatch")
            scope, scope_hash = registered["scope"], registered["scope_hash"]
        transport = transport or LocalHTTPS(config["endpoint"], targets=targets, ca_file=config.get("ca_file"),
                       auth=credentials(config), client_cert=config.get("client_cert"), client_key=config.get("client_key"))
        rows = _rows(transport, config, limit, scope)
        if len(rows) > 10000:
            raise ConnectorRejected("record_count_limit")
        data = json.dumps(rows, allow_nan=False).encode()
        context = dict(source=source, tenant=tenant, instance=instance, collection_mode="local-api", actor="local-connector")
        if scope_hash:
            context.update(site=config["site"], expected_scope_hash=scope_hash)
        else:
            context["source_version"] = config["source_version"]
        receipt = store.import_bytes(data, **context)
        # Page limits deliberately never assert a complete source snapshot.
        result = dict(receipt, connector="reachable", collected_at=now(), coverage="partial snapshot",
                      sensor_health="unknown", live_connector=True, source=source)
        record_connection(store, tenant, source, instance, "accepted", records=len(rows), site=config.get("site"))
        return result
    except (ImportRejected, OSError, ValueError, TypeError, KeyError, sqlite3.Error) as error:
        if isinstance(error, ConnectorRejected) and str(error) == "connector_audit_unavailable":
            raise
        reason = str(error) if isinstance(error, ImportRejected) else "local_storage_failed" if isinstance(error, sqlite3.Error) else "connector_configuration_or_schema_error"
        record_connection(store, tenant, source, instance, "rejected", reason=reason, site=config.get("site"))
        raise ConnectorRejected(reason) from None


def record_connection(store, tenant, source, instance, status, **details):
    store.conn.rollback()
    try:
        with store.conn:
            store.conn.execute("BEGIN IMMEDIATE")
            store._audit(tenant, "local_connector_poll", status, source=source, instance=instance, **details,
                         recommendation="Check approved target, verified TLS, source read permissions, registered scope and supported schema.")
    except sqlite3.Error:
        store.conn.rollback()
        raise ConnectorRejected("connector_audit_unavailable") from None
