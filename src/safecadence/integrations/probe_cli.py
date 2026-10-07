"""Offline provisioning, passive-log spooling and an mTLS-only local collector."""
import hashlib
import ipaddress
import json
import os
import secrets
import sqlite3
import ssl
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import click

from .local_connectors import ConnectorRejected, approved_targets, bounded_socket, private_file
from .probe import CollectorTransport, ProbeCollector, ProbeSpool, scope
from .security_import import MAX_BYTES, ImportRejected, decode


def settings(path):
    values = decode(private_file(path), unwrap=False)
    if len(values) != 1:
        raise ConnectorRejected("one_settings_object_required")
    return values[0]


def spool(config):
    return ProbeSpool(config["spool"], config=config, encryption_key_file=config["encryption_key_file"],
                      max_records=config.get("max_records", 10000), max_bytes=config.get("max_bytes", 32 * 1024 * 1024))


@click.group("probe")
def probe():
    """Forward approved passive logs locally; never execute capture engines or commands."""


@probe.command("provision")
@click.option("--scope", "scope_file", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--directory", required=True, type=click.Path(file_okay=False))
def provision_cmd(scope_file, directory):
    """Create private spool/auth keys in a NEW directory. Transfer enrollment offline."""
    from cryptography.fernet import Fernet
    try:
        with Path(scope_file).open("rb") as stream:
            rows = decode(stream.read(MAX_BYTES + 1), unwrap=False)
        if len(rows) != 1:
            raise ConnectorRejected("one_scope_required")
        value = scope(rows[0])
        root = Path(directory).resolve()
        root.mkdir(mode=0o700, parents=True, exist_ok=False)
        for name, data in (("auth.hex", secrets.token_hex(32).encode()), ("spool.key", Fernet.generate_key())):
            fd = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
        value.update(spool=str(root / "spool.db"), auth_key_file=str(root / "auth.hex"),
                     encryption_key_file=str(root / "spool.key"))
        fd = os.open(root / "probe.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, indent=2)
        click.echo("Private probe settings created. Add validated TLS and collector settings before delivery. No engines started.")
    except (OSError, ValueError, TypeError, ImportRejected, KeyError, sqlite3.Error):
        raise click.ClickException("Provisioning failed; check scope and use a new private directory.") from None


@probe.command("stage")
@click.argument("source", type=click.Choice(["zeek", "suricata"]))
@click.argument("file", type=click.Path(exists=True, dir_okay=False))
@click.option("--config", required=True, type=click.Path(exists=True, dir_okay=False))
def stage_cmd(source, file, config):
    """Validate and encrypt a bounded JSON log batch. Full queues fail closed."""
    queue = None
    try:
        queue = spool(settings(config))
        with Path(file).open("rb") as stream:
            result = queue.stage(stream.read(MAX_BYTES + 1), source=source)
        click.echo(json.dumps(result, indent=2))
    except (OSError, ValueError, TypeError, ImportRejected, KeyError, sqlite3.Error):
        raise click.ClickException("Probe staging failed; preserve source logs and inspect the local audit.") from None
    finally:
        if queue:
            queue.close()


@probe.command("heartbeat")
@click.option("--config", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--metrics", type=click.Path(exists=True, dir_okay=False), default=None)
def heartbeat_cmd(config, metrics):
    """Queue independent health evidence; absent capture metrics remain unknown."""
    queue = None
    try:
        queue = spool(settings(config))
        value = {}
        if metrics:
            with Path(metrics).open("rb") as stream:
                rows = decode(stream.read(65537), unwrap=False)
            if len(rows) != 1:
                raise ConnectorRejected("one_metrics_object_required")
            value = rows[0]
        click.echo(json.dumps(queue.heartbeat(value), indent=2))
    except (OSError, ValueError, TypeError, ImportRejected, KeyError, sqlite3.Error):
        raise click.ClickException("Heartbeat failed; no healthy capture claim was made.") from None
    finally:
        if queue:
            queue.close()


@probe.command("follow")
@click.argument("source", type=click.Choice(["zeek", "suricata"]))
@click.option("--config", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--accept-rotation", is_flag=True, help="Acknowledge a possible collection gap after reviewing retained rotated logs.")
def follow_cmd(source, config, accept_rotation):
    """Queue new complete JSONL records from the exact configured local log path."""
    queue = None
    try:
        value = settings(config)
        path = value["log_files"][source]
        if not isinstance(path, str) or not Path(path).is_absolute():
            raise ConnectorRejected("absolute_approved_log_path_required")
        queue = spool(value)
        click.echo(json.dumps(queue.follow_once(path, source=source, accept_rotation=accept_rotation), indent=2))
    except (OSError, ValueError, TypeError, ImportRejected, KeyError, sqlite3.Error):
        raise click.ClickException("Log follow failed; preserve original and rotated logs, then inspect the local audit.") from None
    finally:
        if queue:
            queue.close()


@probe.command("status")
@click.option("--config", required=True, type=click.Path(exists=True, dir_okay=False))
def status_cmd(config):
    """Show local queue pressure, not field-qualified coverage."""
    queue = None
    try:
        queue = spool(settings(config))
        click.echo(json.dumps(queue.status(), indent=2))
    except (OSError, ValueError, TypeError, ImportRejected, KeyError, sqlite3.Error):
        raise click.ClickException("Probe status unavailable; inspect storage without deleting queued evidence.") from None
    finally:
        if queue:
            queue.close()


@probe.command("deliver")
@click.option("--config", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--limit", type=click.IntRange(1, 100), default=10)
def deliver_cmd(config, limit):
    """Deliver encrypted queue contents over approved internal mTLS; retry safely."""
    queue = None
    try:
        value = settings(config)
        transport = CollectorTransport(value["endpoint"], targets=approved_targets(), ca_file=value["ca_file"],
                                       client_cert=value["client_cert"], client_key=value["client_key"])
        queue = spool(value)
        delivered = 0
        for _ in range(limit):
            result = queue.deliver_one(transport, auth_key_file=value["auth_key_file"])
            delivered += result["delivered"]
            if not result["delivered"]:
                break
        click.echo(json.dumps(dict(delivered=delivered, **queue.status()), indent=2))
    except (OSError, ValueError, TypeError, ImportRejected, KeyError, sqlite3.Error):
        raise click.ClickException("Delivery failed; unacknowledged evidence remains queued.") from None
    finally:
        if queue:
            queue.close()


def collector_handler(database, registry):
    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(10)

        def log_message(self, *_args):
            pass  # No request/body/header logging: use scoped evidence audit.

        def handle(self):
            with bounded_socket(self.connection, 10):
                super().handle()

        def do_POST(self):
            store = None
            try:
                if self.path != "/v1/probe/batch" or self.headers.get("Transfer-Encoding"):
                    raise ConnectorRejected("collector_path_forbidden")
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= MAX_BYTES or self.headers.get("Content-Type") != "application/json":
                    raise ConnectorRejected("collector_body_rejected")
                chunks, total, deadline = [], 0, time.monotonic() + 10
                while total < length:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ConnectorRejected("collector_body_deadline")
                    self.connection.settimeout(remaining)
                    chunk = self.rfile.read1(min(65536, length - total))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                body = b"".join(chunks)
                if len(body) != length:
                    raise ConnectorRejected("collector_body_incomplete")
                values = decode(body, unwrap=False)
                if len(values) != 1:
                    raise ConnectorRejected("one_probe_envelope_required")
                probe_id = values[0].get("probe_id")
                enrolled = settings(registry)["probes"].get(probe_id)
                if enrolled is None:
                    raise ConnectorRejected("probe_not_enrolled")
                store = ProbeCollector(database)
                certificate = hashlib.sha256(self.connection.getpeercert(binary_form=True)).hexdigest()
                result = store.accept(body, self.headers.get("X-Probe-Signature", ""),
                                      enrollment=enrolled, certificate_sha256=certificate)
                self._respond(200, result)
            except (OSError, ValueError, TypeError, KeyError, ImportRejected, sqlite3.Error):
                self._respond(403, {"error": "probe_batch_rejected", "recommendation": "Check enrollment and local audit; preserve queued evidence."})
            finally:
                if store:
                    store.close()

        def _respond(self, status, result):
            data = json.dumps(result).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)
            self.close_connection = True

    return Handler


@probe.command("serve")
@click.option("--registry", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--db", required=True, type=click.Path(dir_okay=False))
@click.option("--cert", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--key", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--client-ca", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--bind", default="127.0.0.1")
@click.option("--port", type=click.IntRange(1, 65535), default=9443)
def serve_cmd(registry, db, cert, key, client_ca, bind, port):
    """Serve enrollment-bound ingestion over mTLS only. No query/command endpoints."""
    from safecadence.security.local_only import LocalPolicy
    try:
        address = ipaddress.ip_address(bind)
        if not address.is_loopback:
            rows = json.loads(os.environ.get("SC_LOCAL_INTERNAL_LISTENERS", "[]"))
            listeners = tuple((row["ip"], row["port"]) for row in rows)
            LocalPolicy(internal_listeners=listeners)
            if (bind, port) not in listeners:
                raise ConnectorRejected("collector_listener_not_approved")
        if address.version != 4:
            raise ConnectorRejected("collector_ipv4_listener_required")
        settings(registry)
        private_file(key)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cert, key)
        context.load_verify_locations(client_ca)
        context.verify_mode = ssl.CERT_REQUIRED
        class TLSServer(HTTPServer):
            def get_request(self):
                connection, remote = self.socket.accept()
                connection.settimeout(5)
                try:
                    return context.wrap_socket(connection, server_side=True), remote
                except Exception:
                    connection.close()
                    raise

        with TLSServer((bind, port), collector_handler(db, registry)) as server:
            click.echo("mTLS-only local probe collector started. Capture health and coverage remain unqualified.")
            server.serve_forever()
    except (OSError, ValueError, TypeError, KeyError, ImportRejected):
        raise click.ClickException("Collector startup failed; verify approved listener and PKI settings.") from None


@probe.command("health")
@click.option("--db", required=True, type=click.Path(dir_okay=False))
@click.option("--tenant", required=True)
@click.option("--stale-after", type=click.IntRange(30, 86400), default=120)
def health_cmd(db, tenant, stale_after):
    """Read scoped collector heartbeat freshness; no report is not an all-clear."""
    store = None
    try:
        store = ProbeCollector(db)
        click.echo(json.dumps(store.health(tenant=tenant, stale_after=stale_after), indent=2))
    except (OSError, ValueError, TypeError, ImportRejected, sqlite3.Error):
        raise click.ClickException("Probe health read failed; health and coverage remain unknown.") from None
    finally:
        if store:
            store.close()


@probe.command("verify-engine")
@click.option("--manifest", required=True, type=click.Path(exists=True, dir_okay=False))
def verify_engine_cmd(manifest):
    """Verify an operator-approved offline engine hash; never download or execute it."""
    try:
        value = settings(manifest)
        if value["source"] not in {"zeek", "suricata"}:
            raise ConnectorRejected("unsupported_probe_engine")
        path = Path(value["binary"])
        if path.is_symlink() or not path.is_file() or not os.access(path, os.X_OK):
            raise ConnectorRejected("engine_binary_invalid")
        sha = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(65536), b""):
                sha.update(chunk)
        if sha.hexdigest() != value["sha256"]:
            raise ConnectorRejected("engine_hash_mismatch")
        click.echo(json.dumps(dict(source=value["source"], version=value["version"], hash_verified=True,
                                  engine_executed=False, publisher_signature_verified=False)))
    except (OSError, ValueError, TypeError, KeyError, ImportRejected):
        raise click.ClickException("Offline engine verification failed; do not start the capture worker.") from None
