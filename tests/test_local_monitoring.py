"""Connector, spool, enrollment and actual loopback TLS tests. No external targets."""
import hashlib
import hmac
import json
import os
import ssl
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
from click.testing import CliRunner
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
import ipaddress

from safecadence.integrations.local_connectors import (
    ConnectorRejected, LocalHTTPS, local_endpoint, poll, private_file,
)
from safecadence.integrations.probe import (
    CollectorTransport, ProbeCollector, ProbeSpool, canonical, scope,
)
from safecadence.integrations.probe_cli import collector_handler, probe
from safecadence.integrations.public_safety_store import PublicSafetyEvidenceStore
from safecadence.integrations.security_store import SecurityEvidenceStore

WAZUH = {"id": "1", "timestamp": "2026-10-06T10:00:00Z", "agent": {"id": "001"},
         "rule": {"level": 12, "description": "Fixture alert"}}
ZEEK = {"uid": "C1", "ts": 1791280800.0, "id.orig_h": "10.1.2.3", "id.resp_h": "10.1.2.4"}
CONFIG = dict(probe_id="probe-a", tenant="acme", site="hq", segment="office", instance="probe-a",
              source_version="fixture-v1", sources=["zeek", "suricata"])


def secret(path, data):
    path.write_bytes(data)
    path.chmod(0o600)
    return str(path)


@pytest.fixture
def probe_env(tmp_path):
    auth = secret(tmp_path / "auth.hex", b"12" * 32)
    key = secret(tmp_path / "spool.key", Fernet.generate_key())
    queue = ProbeSpool(tmp_path / "spool.db", config=CONFIG, encryption_key_file=key)
    collector = ProbeCollector(tmp_path / "collector.db")
    enrolled = dict(CONFIG, enabled=True, auth_key_file=auth, certificate_sha256="a" * 64,
                    expires_at=(datetime.now(timezone.utc) + timedelta(days=1)).isoformat())
    yield tmp_path, queue, collector, enrolled, auth, key
    queue.close()
    collector.close()


def accept(env, body=None, enrollment=None, certificate="a" * 64):
    _, queue, collector, enrolled, *_ = env
    body = body or queue.pending()[1]
    signature = hmac.new(bytes.fromhex("12" * 32), body, hashlib.sha256).hexdigest()
    return collector.accept(body, signature, enrollment=enrollment or enrolled, certificate_sha256=certificate)


@pytest.mark.parametrize("url", ["http://127.0.0.1:9443", "https://8.8.8.8", "https://example.com",
                                 "https://169.254.169.254", "https://192.168.1.2", "https://user:pass@127.0.0.1:9443",
                                 "https://127.0.0.1:9443/path", "https://127.0.0.1:9443?proxy=yes"])
def test_endpoint_fails_closed(url):
    with pytest.raises(ConnectorRejected):
        local_endpoint(url, (("127.0.0.1", 9443),))


def test_explicit_numeric_target_and_no_secret_symlink(tmp_path):
    assert local_endpoint("https://192.168.1.2:9443", (("192.168.1.2", 9443),)) == ("192.168.1.2", 9443)
    p = tmp_path / "secret"
    secret(p, b"token")
    assert private_file(p) == b"token"
    p.chmod(0o644)
    with pytest.raises(ConnectorRejected):
        private_file(p)
    p.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(p)
    with pytest.raises(OSError):
        private_file(link)


class FakeSource:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def get(self, path, query=None):
        self.calls.append((path, query))
        value = self.responses[path]
        if isinstance(value, Exception):
            raise value
        return json.dumps(value).encode()


def config(source, **extra):
    return dict(source=source, tenant="acme", site="hq", instance="source-1", source_version="v1",
                endpoint="https://127.0.0.1:9443", **extra)


def polling(store, source, transport, **extra):
    return poll(store, config(source, **extra), targets=(("127.0.0.1", 9443),), transport=transport)


@pytest.mark.parametrize("source,route,value", [
    ("wazuh", "/wazuh-alerts-*/_search", {"hits": {"hits": [{"_source": WAZUH}]}}),
    ("crowdsec", "/v1/alerts", [{"id": 1, "scenario": "fixture", "created_at": "2026-10-06T10:00:00Z"}]),
])
def test_security_polling_atomic_replay_audit(tmp_path, source, route, value):
    store = SecurityEvidenceStore(tmp_path / "e.db")
    try:
        transport = FakeSource({route: value})
        assert polling(store, source, transport)["inserted"] == 1
        result = polling(store, source, transport)
        assert result["duplicates"] == 1
        assert result["sensor_health"] == "unknown" and result["coverage"] == "partial snapshot"
        assert store.events(tenant="acme")[0]["collection_mode"] == "local-api"
        assert store.audit(tenant="acme")["chain_valid"]
        assert transport.calls[0][1].get("limit", 100) == 100
    finally:
        store.close()


def register(store, source, value):
    return store.register(tenant="acme", site="hq", source=source, instance="source-1", source_version="v1",
                          purpose="facility-safety", scope=value)


def test_home_assistant_scoped_states_and_stale_time(tmp_path):
    store = PublicSafetyEvidenceStore(tmp_path / "e.db")
    try:
        register(store, "home-assistant", {"entities": {"binary_sensor.door": "door"}})
        transport = FakeSource({"/api/states/binary_sensor.door": {"entity_id": "binary_sensor.door", "state": "on",
            "last_updated": "2026-10-06T10:00:00Z", "attributes": {"device_class": "door", "friendly_name": "Private name"}}})
        polling(store, "home-assistant", transport)
        assert polling(store, "home-assistant", transport)["duplicates"] == 1
        event = store.events(tenant="acme", site="hq")[0]
        assert event["observed_at"].startswith("2026-10-06T10:00:00")
        assert "Private name" not in json.dumps(event)
        assert event["live_connector"] and not event["control_allowed"]
        assert store.status(tenant="acme", site="hq")[0]["sensor_health"] == "unknown"
    finally:
        store.close()


def test_frigate_historical_presence_no_media_or_occupancy_claim(tmp_path):
    store = PublicSafetyEvidenceStore(tmp_path / "e.db")
    try:
        register(store, "frigate", {"cameras": {"front": ["entry"]}})
        transport = FakeSource({"/api/events": [{"id": "event-1", "camera": "front", "label": "person", "zones": ["entry"],
                  "start_time": 1791280800, "end_time": 1791280810, "thumbnail": "SECRET_MEDIA", "sub_label": "PERSON_NAME"}]})
        polling(store, "frigate", transport)
        assert polling(store, "frigate", transport)["duplicates"] == 1
        event = store.events(tenant="acme", site="hq")[0]
        assert event["evidence"]["current_zones"] == []
        assert "SECRET_MEDIA" not in json.dumps(event) and "PERSON_NAME" not in json.dumps(event)
        assert transport.calls[0][1]["include_thumbnails"] == 0
    finally:
        store.close()


def test_thingsboard_latest_telemetry_conversion(tmp_path):
    store = PublicSafetyEvidenceStore(tmp_path / "e.db")
    try:
        register(store, "thingsboard", {"devices": {"room": {"telemetry": {"temp": {"kind": "temperature", "unit": "C"}}, "alarm_types": []}}})
        device = "00000000-0000-0000-0000-000000000001"
        transport = FakeSource({"/api/plugins/telemetry/DEVICE/" + device + "/values/timeseries": {
            "temp": [{"ts": 1791280800000, "value": "22.5"}]}})
        result = polling(store, "thingsboard", transport, device_ids={"room": device})
        assert result["inserted"] == 1
        event = store.events(tenant="acme", site="hq")[0]
        assert event["evidence"]["value"] == 22.5
    finally:
        store.close()


def test_poll_scope_change_failure_before_write(tmp_path):
    store = PublicSafetyEvidenceStore(tmp_path / "e.db")
    try:
        register(store, "home-assistant", {"entities": {"binary_sensor.door": "door"}})
        class ChangingSource(FakeSource):
            def get(self, *args, **kwargs):
                register(store, "home-assistant", {"entities": {"binary_sensor.other": "door"}})
                return super().get(*args, **kwargs)
        transport = ChangingSource({"/api/states/binary_sensor.door": {"entity_id": "binary_sensor.door", "state": "on",
          "last_updated": "2026-10-06T10:00:00Z", "attributes": {"device_class": "door"}}})
        with pytest.raises(ConnectorRejected, match="collection_scope_changed"):
            polling(store, "home-assistant", transport)
        assert not store.events(tenant="acme", site="hq")
        assert store.audit(tenant="acme")["chain_valid"]
    finally:
        store.close()


@pytest.mark.parametrize("reason", ["authentication_failed", "redirect_forbidden", "local_transport_failed"])
def test_poll_outage_failure_recommendation(tmp_path, reason):
    store = SecurityEvidenceStore(tmp_path / "e.db")
    try:
        with pytest.raises(ConnectorRejected, match=reason):
            polling(store, "wazuh", FakeSource({"/wazuh-alerts-*/_search": ConnectorRejected(reason)}))
        assert not store.events(tenant="acme")
        audit = store.audit(tenant="acme")
        assert audit["chain_valid"] and audit["records"][-1]["recommendation"]
    finally:
        store.close()


def test_encrypted_spool_and_durable_reopen(probe_env):
    root, queue, _, _, _, key = probe_env
    queue.stage(json.dumps(ZEEK).encode(), source="zeek")
    raw = (root / "spool.db").read_bytes()
    assert b"10.1.2.3" not in raw and b'"uid"' not in raw
    reopened = ProbeSpool(root / "spool.db", config=CONFIG, encryption_key_file=key)
    try:
        assert reopened.pending()[0] == 1
    finally:
        reopened.close()


def test_probe_collect_duplicate_ack_tenant_isolation(probe_env):
    _, queue, collector, *_ = probe_env
    queue.stage(json.dumps(ZEEK).encode(), source="zeek")
    sequence, body, batch_hash = queue.pending()
    receipt = accept(probe_env)
    assert receipt["inserted"] == 1
    assert accept(probe_env)["status"] == "duplicate"
    assert len(collector.events(tenant="acme")) == 1
    assert not collector.events(tenant="other")
    queue.acknowledge(sequence, batch_hash, receipt)
    assert not queue.pending()
    assert collector.events(tenant="acme")[0]["segment"] == "office"
    assert collector.audit(tenant="acme")["chain_valid"]


@pytest.mark.parametrize("change,reason", [({"enabled": False}, "probe_revoked"),
    ({"expires_at": "2020-01-01T00:00:00Z"}, "probe_enrollment_expired"),
    ({"segment": "wrong"}, "probe_scope_mismatch"),
    ({"certificate_sha256": "b" * 64}, "probe_certificate_mismatch")])
def test_enrollment_failures_keep_queue(probe_env, change, reason):
    _, queue, collector, enrolled, *_ = probe_env
    queue.stage(json.dumps(ZEEK).encode(), source="zeek")
    with pytest.raises(ConnectorRejected, match=reason):
        accept(probe_env, enrollment={**enrolled, **change})
    assert queue.pending() and not collector.events(tenant="acme")
    assert collector.audit(tenant="acme")["records"][-1]["reason"] == reason


@pytest.mark.parametrize("change,reason", [({"sequence": 2}, "probe_sequence_gap"),
    ({"sequence": True}, "invalid_probe_sequence"), ({"kind": "command"}, "invalid_probe_kind"),
    ({"source": "wazuh"}, "invalid_probe_records"), ({"tenant": "other"}, "probe_scope_mismatch")])
def test_signed_invalid_envelopes(probe_env, change, reason):
    _, queue, *_ = probe_env
    queue.stage(json.dumps(ZEEK).encode(), source="zeek")
    value = json.loads(queue.pending()[1])
    with pytest.raises(ConnectorRejected, match=reason):
        accept(probe_env, body=canonical({**value, **change}))


def test_signature_collision_and_bad_ack(probe_env):
    _, queue, collector, enrolled, *_ = probe_env
    queue.stage(json.dumps(ZEEK).encode(), source="zeek")
    sequence, body, batch_hash = queue.pending()
    with pytest.raises(ConnectorRejected, match="probe_signature_invalid"):
        collector.accept(body, "0" * 64, enrollment=enrolled, certificate_sha256="a" * 64)
    receipt = accept(probe_env)
    modified = json.loads(body)
    modified["records"][0]["uid"] = "different"
    with pytest.raises(ConnectorRejected, match="probe_sequence_collision"):
        accept(probe_env, body=canonical(modified))
    with pytest.raises(ConnectorRejected, match="collector_receipt_mismatch"):
        queue.acknowledge(sequence, batch_hash, {**receipt, "batch_hash": "wrong"})
    assert queue.pending()


def test_capacity_and_atomic_bad_batch(probe_env):
    root, queue, _, _, _, key = probe_env
    tiny = ProbeSpool(root / "tiny.db", config=CONFIG, encryption_key_file=key, max_records=1)
    try:
        with pytest.raises(ConnectorRejected):
            tiny.stage(canonical([ZEEK, ZEEK]), source="zeek")
        assert tiny.status()["queued_batches"] == 0
        tiny.stage(canonical(ZEEK), source="zeek")
        with pytest.raises(ConnectorRejected):
            tiny.stage(canonical(ZEEK), source="zeek")
        assert tiny.status()["queued_batches"] == 1
        assert tiny.store.audit(tenant="acme")["chain_valid"]
    finally:
        tiny.close()
    with pytest.raises(ConnectorRejected):
        queue.stage(canonical([ZEEK, {"invalid": "data"}]), source="zeek")
    assert queue.status()["queued_batches"] == 0


def test_delivery_outage_and_secret_redaction(probe_env):
    _, queue, *_ = probe_env
    queue.stage(canonical({**ZEEK, "password": "VERY_SECRET"}), source="zeek")
    assert b"VERY_SECRET" not in queue.pending()[1]
    class Offline:
        def send_batch(self, *_):
            raise ConnectorRejected("local_transport_failed")
    with pytest.raises(ConnectorRejected, match="queue_preserved"):
        queue.deliver_one(Offline(), auth_key_file=probe_env[4])
    assert queue.pending()


def test_heartbeat_independent_unknown_health(probe_env):
    _, queue, collector, *_ = probe_env
    queue.heartbeat({"capture_drops": 5, "interface_up": False})
    accept(probe_env)
    assert not collector.events(tenant="acme")
    record = collector.audit(tenant="acme")["records"][-1]
    assert record["heartbeat"]["coverage"] == "unknown"
    assert record["heartbeat"]["metrics"]["capture_drops"] == 5
    with pytest.raises(ConnectorRejected):
        queue.heartbeat({"password": "SECRET"})
    health = collector.health(tenant="acme")[0]
    assert health["heartbeat_state"] == "recent-report" and not health["hardware_qualified"]
    assert not collector.health(tenant="other")
    assert collector.health(tenant="acme", at=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat())[0]["heartbeat_state"] == "stale"


@pytest.fixture
def pki(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Offline test CA")])
    start = datetime.now(timezone.utc) - timedelta(minutes=1)
    ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(start).not_valid_after(start + timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
          .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
          .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, None, None), critical=True)
          .sign(key, hashes.SHA256()))
    root = tmp_path / "pki"
    root.mkdir()
    ca_path = root / "ca.pem"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    result = {"ca": str(ca_path)}
    for role in ("server", "client"):
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, role)]))
                .issuer_name(name).public_key(private.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(start).not_valid_after(start + timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(private.public_key()), critical=False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
                .add_extension(x509.KeyUsage(True, False, True, False, False, False, False, None, None), critical=True)
                .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if role == "server" else ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
                .sign(key, hashes.SHA256()))
        cert_path, key_path = root / (role + ".pem"), root / (role + ".key")
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        secret(key_path, private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        result[role] = str(cert_path), str(key_path), cert.fingerprint(hashes.SHA256()).hex()
    return result


def start_tls(handler, pki, require_client=False):
    server = HTTPServer(("127.0.0.1", 0), handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(*pki["server"][:2])
    if require_client:
        context.load_verify_locations(pki["ca"])
        context.verify_mode = ssl.CERT_REQUIRED
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


@pytest.mark.parametrize("mode,reason", [("redirect", "redirect_forbidden"), ("unauthorized", "authentication_failed"),
                                      ("compressed", "compressed_response_forbidden"), ("html", "json_response_required"),
                                      ("large", "response_size_limit")])
def test_actual_tls_source_failure_modes(pki, mode, reason):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass
        def do_GET(self):
            status = 302 if mode == "redirect" else 401 if mode == "unauthorized" else 200
            self.send_response(status)
            self.send_header("Content-Type", "text/html" if mode == "html" else "application/json")
            if mode == "compressed":
                self.send_header("Content-Encoding", "gzip")
            self.end_headers()
            try:
                self.wfile.write(b"x" * (8 * 1024 * 1024 + 1) if mode == "large" else b"[]")
            except (BrokenPipeError, ConnectionResetError):
                pass
    server, thread = start_tls(Handler, pki)
    try:
        port = server.server_port
        transport = LocalHTTPS(f"https://127.0.0.1:{port}", targets=(("127.0.0.1", port),), ca_file=pki["ca"])
        with pytest.raises(ConnectorRejected, match=reason):
            transport.get("/v1/alerts")
        with pytest.raises(ConnectorRejected, match="read_path_forbidden"):
            transport.get("/api/services/lock/unlock")
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_actual_mtls_collector_retry_and_restart(probe_env, pki):
    root, queue, collector, enrolled, auth, _ = probe_env
    enrolled["certificate_sha256"] = pki["client"][2]
    registry = secret(root / "registry.json", canonical({"probes": {"probe-a": enrolled}}))
    server, thread = start_tls(collector_handler(str(root / "collector.db"), registry), pki, require_client=True)
    try:
        port = server.server_port
        transport = CollectorTransport(f"https://127.0.0.1:{port}", targets=(("127.0.0.1", port),),
                    ca_file=pki["ca"], client_cert=pki["client"][0], client_key=pki["client"][1])
        queue.stage(canonical(ZEEK), source="zeek")
        sequence, body, batch_hash = queue.pending()
        signature = hmac.new(bytes.fromhex("12" * 32), body, hashlib.sha256).hexdigest()
        receipt = json.loads(transport.send_batch(body, signature))
        assert receipt["status"] == "accepted"
        # Simulate a lost acknowledgment, then reconnect/retry using the same body.
        assert queue.deliver_one(transport, auth_key_file=auth)["delivered"] == 1
        assert not queue.pending() and len(collector.events(tenant="acme")) == 1
        queue.heartbeat()
        assert queue.deliver_one(transport, auth_key_file=auth)["sequence"] == 2
        enrolled["enabled"] = False
        secret(root / "registry.json", canonical({"probes": {"probe-a": enrolled}}))
        queue.stage(canonical(ZEEK), source="zeek")
        with pytest.raises(ConnectorRejected, match="queue_preserved"):
            queue.deliver_one(transport, auth_key_file=auth)
        assert queue.pending()
        untrusted = LocalHTTPS(f"https://127.0.0.1:{port}", targets=(("127.0.0.1", port),))
        with pytest.raises(ConnectorRejected, match="local_transport_failed"):
            untrusted.get("/v1/alerts")
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_guarded_process_actual_tls_poll(tmp_path, pki):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass
        def do_GET(self):
            assert self.path.startswith("/wazuh-alerts-")
            data = canonical({"hits": {"hits": [{"_source": WAZUH}]}})
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(data)
    server, thread = start_tls(Handler, pki)
    try:
        port = server.server_port
        credentials = secret(tmp_path / "credentials.json", canonical({"username": "reader", "password": "FIXTURE_ONLY"}))
        value = config("wazuh", credential_file=credentials, ca_file=pki["ca"])
        value["endpoint"] = f"https://127.0.0.1:{port}"
        config_path = tmp_path / "connector.json"
        config_path.write_bytes(canonical(value))
        env = dict(os.environ, SC_LOCAL_INTERNAL_TARGETS=json.dumps([{"ip": "127.0.0.1", "port": port}]), PYTHONPATH="src")
        result = subprocess.run([sys.executable, "-m", "safecadence.security.local_only", "connections", "poll",
                                 "--config", str(config_path), "--db", str(tmp_path / "guard.db")],
                                env=env, capture_output=True, text=True, timeout=20)
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout)["inserted"] == 1
        assert "FIXTURE_ONLY" not in result.stdout
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_provision_cli_private_files(tmp_path):
    path = tmp_path / "scope.json"
    path.write_bytes(canonical(CONFIG))
    runner = CliRunner()
    directory = tmp_path / "new"
    result = runner.invoke(probe, ["provision", "--scope", str(path), "--directory", str(directory)])
    assert result.exit_code == 0, result.output
    assert (directory / "auth.hex").stat().st_mode & 0o777 == 0o600
    value = json.loads((directory / "probe.json").read_bytes())
    assert scope(value) == scope(CONFIG)
    assert runner.invoke(probe, ["provision", "--scope", str(path), "--directory", str(directory)]).exit_code != 0


def test_jsonl_checkpoint_partial_record_and_rotation(probe_env):
    root, queue, *_ = probe_env
    path = root / "conn.log"
    path.write_bytes(canonical(ZEEK) + b"\n" + canonical({**ZEEK, "uid": "C2"})[:20])
    assert queue.follow_once(path, source="zeek")["staged"] == 1
    assert queue.follow_once(path, source="zeek")["partial_record"]
    with path.open("ab") as stream:
        stream.write(canonical({**ZEEK, "uid": "C2"})[20:] + b"\n")
    assert queue.follow_once(path, source="zeek")["staged"] == 1
    assert queue.follow_once(path, source="zeek")["staged"] == 0
    path.rename(root / "rotated.log")
    path.write_bytes(canonical({**ZEEK, "uid": "C3"}) + b"\n")
    with pytest.raises(ConnectorRejected, match="rotation"):
        queue.follow_once(path, source="zeek")
    result = queue.follow_once(path, source="zeek", accept_rotation=True)
    assert result["coverage_warning"].startswith("possible_rotation_gap")


def test_follow_capacity_does_not_advance_offset(probe_env):
    root, _, _, _, _, key = probe_env
    queue = ProbeSpool(root / "limited.db", config=CONFIG, encryption_key_file=key, max_records=1)
    path = root / "conn.log"
    path.write_bytes(canonical(ZEEK) + b"\n")
    try:
        queue.heartbeat()
        with pytest.raises(ConnectorRejected, match="capacity"):
            queue.follow_once(path, source="zeek")
        assert not queue.conn.execute("SELECT key FROM probe_meta WHERE key LIKE 'cursor:%'").fetchall()
    finally:
        queue.close()


def test_spool_tamper_and_changed_scope(probe_env):
    root, queue, _, _, _, key = probe_env
    with pytest.raises(ConnectorRejected, match="spool_scope_changed"):
        ProbeSpool(root / "spool.db", config={**CONFIG, "segment": "another"}, encryption_key_file=key)
    queue.stage(canonical(ZEEK), source="zeek")
    with queue.conn:
        queue.conn.execute("UPDATE probe_queue SET payload=?", (b"not-valid-ciphertext",))
    with pytest.raises(ConnectorRejected, match="spool_integrity_failed"):
        queue.pending()


def test_page_limit_and_live_brand_exclusion(tmp_path):
    store = SecurityEvidenceStore(tmp_path / "e.db")
    try:
        values = {"hits": {"hits": [{"_source": WAZUH}] * 2}}
        with pytest.raises(ConnectorRejected, match="upstream_page_limit_exceeded"):
            polling(store, "wazuh", FakeSource({"/wazuh-alerts-*/_search": values}), limit=1)
        with pytest.raises(ConnectorRejected, match="unsupported_connector"):
            polling(store, "sherlock", FakeSource({}))
        assert not store.events(tenant="acme")
    finally:
        store.close()


def test_storage_failure_never_discards_queue_or_claims_audit(probe_env):
    _, queue, collector, *_ = probe_env
    queue.stage(canonical(ZEEK), source="zeek")
    queue.conn.execute("PRAGMA query_only=ON")
    try:
        with pytest.raises(ConnectorRejected, match="storage_failed_audit_unavailable"):
            queue.stage(canonical(ZEEK), source="zeek")
        assert queue.status()["queued_batches"] == 1 and queue.pending()
    finally:
        queue.conn.execute("PRAGMA query_only=OFF")
    collector.conn.execute("PRAGMA query_only=ON")
    try:
        with pytest.raises(ConnectorRejected, match="collector_storage_failed_audit_unavailable"):
            accept(probe_env)
        assert not collector.events(tenant="acme")
        assert queue.pending()
    finally:
        collector.conn.execute("PRAGMA query_only=OFF")


def test_heartbeat_storage_failure_preserves_queue(probe_env):
    _, queue, *_ = probe_env
    queue.stage(canonical(ZEEK), source="zeek")
    queue.conn.execute("PRAGMA query_only=ON")
    try:
        with pytest.raises(ConnectorRejected, match="storage_failed_audit_unavailable"):
            queue.heartbeat()
        assert queue.status()["queued_batches"] == 1
    finally:
        queue.conn.execute("PRAGMA query_only=OFF")


def test_connector_storage_failure_does_not_claim_audit(tmp_path):
    store = SecurityEvidenceStore(tmp_path / "e.db")
    store.conn.execute("PRAGMA query_only=ON")
    try:
        with pytest.raises(ConnectorRejected, match="connector_audit_unavailable"):
            polling(store, "wazuh", FakeSource({"/wazuh-alerts-*/_search": {"hits": {"hits": [{"_source": WAZUH}]}}}))
        assert not store.events(tenant="acme")
    finally:
        store.close()


def test_follow_blank_lines_checkpoint_without_empty_batch(probe_env):
    root, queue, *_ = probe_env
    path = root / "blank.log"
    path.write_bytes(b"\n \n")
    assert queue.follow_once(path, source="zeek")["staged"] == 0
    assert not queue.pending()
    cursor = queue.conn.execute("SELECT value FROM probe_meta WHERE key LIKE 'cursor:%'").fetchone()
    assert json.loads(cursor[0])["offset"] == 3
    assert queue.follow_once(path, source="zeek")["staged"] == 0


def test_absolute_deadline_interrupts_trickled_tls_headers(pki):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            try:
                for char in b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n[]":
                    self.wfile.write(bytes([char]))
                    self.wfile.flush()
                    time.sleep(0.025)
            except OSError:
                pass

    server, thread = start_tls(Handler, pki)
    try:
        port = server.server_port
        transport = LocalHTTPS(f"https://127.0.0.1:{port}", targets=(("127.0.0.1", port),),
                               ca_file=pki["ca"], timeout=0.2)
        started = time.monotonic()
        with pytest.raises(ConnectorRejected, match="collection_deadline"):
            transport.get("/v1/alerts")
        assert time.monotonic() - started < 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


@pytest.mark.parametrize("command", ["heartbeat", "status", "health"])
def test_probe_cli_storage_errors_are_clean(tmp_path, monkeypatch, command):
    import sqlite3
    import safecadence.integrations.probe_cli as cli

    def unavailable(*args, **kwargs):
        raise sqlite3.OperationalError("FIXTURE_PRIVATE_STORAGE_PATH")

    monkeypatch.setattr(cli, "spool", unavailable)
    monkeypatch.setattr(cli, "ProbeCollector", unavailable)
    config_path = secret(tmp_path / "config.json", canonical(CONFIG))
    args = [command, "--db", str(tmp_path / "e.db"), "--tenant", "acme"] if command == "health" else [command, "--config", config_path]
    result = CliRunner().invoke(probe, args)
    assert result.exit_code == 1 and "Error:" in result.output
    assert "FIXTURE_PRIVATE_STORAGE_PATH" not in result.output and "Traceback" not in result.output
