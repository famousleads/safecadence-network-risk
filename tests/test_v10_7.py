"""
v10.7 tests — Redis queue, Postgres store, S3 store, cluster failover,
ServiceNow / Teams / Splunk integrations.

Every external service is mocked. None of these tests touch the
network or require Redis / Postgres / Splunk / etc. to be installed.
"""

from __future__ import annotations

import io
import json
import os
import socket
import time
from unittest import mock

import pytest


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFECADENCE_HOME", str(tmp_path / "sc_home"))
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path / "sc_data"))
    # Make sure we start each test with a clean env around the v10.7 knobs.
    for var in (
        "SC_REDIS_URL", "SC_POSTGRES_URL",
        "SC_S3_ENDPOINT", "SC_S3_REGION", "SC_S3_BUCKET",
        "SC_S3_ACCESS_KEY", "SC_S3_SECRET_KEY",
        "SC_CLUSTER_PEERS", "SC_NODE_NAME",
        "SC_SERVICENOW_INSTANCE", "SC_SERVICENOW_USER", "SC_SERVICENOW_PASS",
        "SC_TEAMS_WEBHOOK_URL",
        "SC_SPLUNK_HEC_URL", "SC_SPLUNK_HEC_TOKEN",
    ):
        monkeypatch.delenv(var, raising=False)
    # Wipe in-memory queue between tests.
    from safecadence import queue as q
    q.clear_local_for_tests()
    from safecadence.cluster import failover as fo
    fo.reset_for_tests()
    yield


def _fake_urlopen_factory(payload_bytes: bytes, status: int = 200, headers: dict | None = None):
    class _Resp:
        def __init__(self):
            self._buf = io.BytesIO(payload_bytes)
            self.status = status
            self.code = status
            self.headers = headers or {}
        def read(self):
            return self._buf.read()
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
    def _fake(*args, **kwargs):
        return _Resp()
    return _fake


# --------------------------------------------------------------------------
# 1. Redis-backed job queue
# --------------------------------------------------------------------------


def test_queue_falls_back_to_memory_when_redis_unset():
    from safecadence import queue as q
    assert not q.is_redis_configured()
    job_id = q.enqueue("test", {"payload": 1})
    assert isinstance(job_id, str) and len(job_id) >= 8

    out = q.dequeue("test", timeout=1)
    assert out is not None
    jid, payload = out
    assert jid == job_id
    assert payload == {"payload": 1}


def test_queue_set_and_get_status_roundtrip_memory():
    from safecadence import queue as q
    job_id = q.enqueue("test", {"k": "v"})
    q.set_status(job_id, "running")
    s1 = q.get_status(job_id)
    assert s1["status"] == "running"
    q.set_status(job_id, "complete", result={"bytes": 42})
    s2 = q.get_status(job_id)
    assert s2["status"] == "complete"
    assert s2["result"] == {"bytes": 42}


def test_queue_dequeue_returns_none_on_empty():
    from safecadence import queue as q
    assert q.dequeue("missing", timeout=0) is None


def test_redis_queue_roundtrip_with_mocked_socket(monkeypatch):
    """When SC_REDIS_URL is set we route via redis_queue. If the socket
    raises we should *transparently* fall back to in-memory."""
    monkeypatch.setenv("SC_REDIS_URL", "redis://127.0.0.1:6379/0")
    from safecadence import queue as q
    from safecadence.queue import redis_queue as rq

    # Force the redis socket calls to fail so the fallback kicks in.
    def _broken_command(*args, **kwargs):
        raise ConnectionError("simulated redis down")
    monkeypatch.setattr(rq, "_command", _broken_command)

    assert q.is_redis_configured()
    job_id = q.enqueue("rq_test", {"x": 1})
    out = q.dequeue("rq_test", timeout=1)
    assert out is not None
    assert out[1] == {"x": 1}


def test_redis_queue_command_encoding_shape():
    """Sanity: _encode produces well-formed RESP."""
    from safecadence.queue.redis_queue import _encode
    out = _encode("SET", "k", "v")
    assert out.startswith(b"*3\r\n")
    assert b"$3\r\nSET\r\n" in out
    assert b"$1\r\nk\r\n" in out
    assert b"$1\r\nv\r\n" in out


# --------------------------------------------------------------------------
# 2. Postgres store
# --------------------------------------------------------------------------


def test_postgres_store_raises_without_psycopg(monkeypatch):
    from safecadence.storage import postgres_store
    monkeypatch.setattr(postgres_store, "_HAS_PSYCOPG", False)
    with pytest.raises(RuntimeError, match="psycopg"):
        postgres_store.PostgresStore("postgresql://nope")


def test_open_store_returns_postgres_when_env_set(monkeypatch):
    monkeypatch.setenv("SC_POSTGRES_URL", "postgresql://safe:pw@127.0.0.1:5432/sc")
    from safecadence.storage import postgres_store, open_store
    # Patch construction so we don't actually try to connect.
    with mock.patch.object(postgres_store, "PostgresStore") as Pg:
        instance = mock.Mock(name="pg")
        Pg.return_value = instance
        store = open_store()
        assert store is instance
        Pg.assert_called_once_with("postgresql://safe:pw@127.0.0.1:5432/sc")


def test_open_store_falls_back_to_sqlite_without_env(tmp_path):
    from safecadence.storage import open_store, SqliteStore
    p = tmp_path / "history.db"
    store = open_store(db_url=f"sqlite:///{p}")
    try:
        assert isinstance(store, SqliteStore)
    finally:
        store.close()


def test_postgres_store_save_and_list_mocked_psycopg(monkeypatch):
    """Mock psycopg so we can exercise the save → list path without a
    real database."""
    from safecadence.storage import postgres_store

    rows_inserted: list[tuple] = []

    class FakeCursor:
        def __init__(self):
            self._last_result = None
            self.description = None
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def execute(self, sql, params=()):
            sql_l = sql.lower() if isinstance(sql, str) else sql.decode().lower()
            if "insert into scans" in sql_l:
                rows_inserted.append(tuple(params))
                self._last_result = (len(rows_inserted),)
            elif "select id, tenant_id" in sql_l:
                self.description = [
                    ("id",), ("tenant_id",), ("started_at",), ("source",),
                    ("vendor",), ("hostname",), ("ip",), ("site",),
                    ("health",), ("risk",), ("risk_band",), ("eol_status",),
                    ("cves",), ("findings",),
                ]
                self._fetched = [
                    (1, "default", "2026-05-10", "config", "cisco-ios", "rtr1",
                     "10.0.0.1", "hq", 85, 30, "low", "ok", 0, 2),
                ]
            else:
                self.description = None
        def fetchone(self):
            return self._last_result
        def fetchall(self):
            return getattr(self, "_fetched", [])
        def executemany(self, sql, seq):
            for row in seq:
                rows_inserted.append(tuple(row))

    class FakeConn:
        def __init__(self):
            self.closed = False
        def cursor(self):
            return FakeCursor()
        def close(self):
            self.closed = True

    monkeypatch.setattr(postgres_store, "_HAS_PSYCOPG", True)
    monkeypatch.setattr(postgres_store, "psycopg",
                        mock.Mock(connect=lambda dsn, autocommit=True: FakeConn()))

    store = postgres_store.PostgresStore("postgresql://fake")
    new_id = store.save({
        "started_at": "2026-05-10T00:00:00Z",
        "source": "config",
        "vendor": "cisco-ios",
        "asset": {"hostname": "rtr1", "ip": "10.0.0.1", "location": {"site": "hq"}},
        "health_score": 85,
        "risk_score": 30,
        "risk_band": "low",
        "eol": {"status_today": "ok"},
        "cves": [],
        "findings": [{"id": "F1"}, {"id": "F2"}],
        "summary": "ok",
    })
    assert isinstance(new_id, int)
    assert rows_inserted, "save did not invoke an insert"
    listed = store.list(limit=10)
    assert listed and listed[0]["hostname"] == "rtr1"
    store.close()


# --------------------------------------------------------------------------
# 3. S3 / DO Spaces store
# --------------------------------------------------------------------------


def _s3_env(monkeypatch):
    monkeypatch.setenv("SC_S3_ENDPOINT", "https://nyc3.digitaloceanspaces.com")
    monkeypatch.setenv("SC_S3_REGION", "nyc3")
    monkeypatch.setenv("SC_S3_BUCKET", "safecadence-reports")
    monkeypatch.setenv("SC_S3_ACCESS_KEY", "AKIAEXAMPLE")
    monkeypatch.setenv("SC_S3_SECRET_KEY", "SECRETEXAMPLE")


def test_s3_is_configured_toggles_on_env(monkeypatch):
    from safecadence.storage import s3_store as s3
    assert not s3.is_configured()
    _s3_env(monkeypatch)
    assert s3.is_configured()


def test_s3_put_object_signs_and_calls_url(monkeypatch):
    _s3_env(monkeypatch)
    from safecadence.storage import s3_store as s3

    captured: dict = {}

    def fake_urlopen(req, timeout=30):
        captured["url"] = req.full_url
        captured["method"] = req.get_method()
        captured["headers"] = dict(req.header_items())
        captured["data"] = req.data
        class _R:
            status = 200
            headers = {}
            def read(self): return b""
            def __enter__(self): return self
            def __exit__(self, *a): return False
        return _R()
    monkeypatch.setattr(s3._urlreq, "urlopen", fake_urlopen)

    client = s3.S3Store()
    url = client.put_object("reports/x.pdf", b"hello", "application/pdf")
    assert "safecadence-reports/reports/x.pdf" in url
    assert captured["method"] == "PUT"
    # SigV4 marker must be in the auth header
    auth = next((v for k, v in captured["headers"].items() if k.lower() == "authorization"), "")
    assert "AWS4-HMAC-SHA256" in auth
    assert captured["data"] == b"hello"


def test_s3_get_and_delete_object(monkeypatch):
    _s3_env(monkeypatch)
    from safecadence.storage import s3_store as s3

    monkeypatch.setattr(s3._urlreq, "urlopen",
                        _fake_urlopen_factory(b"the-bytes", status=200))
    client = s3.S3Store()
    assert client.get_object("k") == b"the-bytes"

    monkeypatch.setattr(s3._urlreq, "urlopen",
                        _fake_urlopen_factory(b"", status=204))
    client.delete_object("k")  # should not raise


def test_s3_list_objects_parses_xml(monkeypatch):
    _s3_env(monkeypatch)
    from safecadence.storage import s3_store as s3

    body = (
        b'<?xml version="1.0"?>'
        b'<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
        b'<Contents><Key>reports/a.pdf</Key><Size>123</Size>'
        b'<LastModified>2026-05-10T00:00:00Z</LastModified><ETag>"abc"</ETag></Contents>'
        b'<Contents><Key>reports/b.docx</Key><Size>456</Size>'
        b'<LastModified>2026-05-09T00:00:00Z</LastModified><ETag>"def"</ETag></Contents>'
        b'</ListBucketResult>'
    )
    monkeypatch.setattr(s3._urlreq, "urlopen", _fake_urlopen_factory(body))
    client = s3.S3Store()
    objs = client.list_objects(prefix="reports/")
    assert len(objs) == 2
    keys = {o["key"] for o in objs}
    assert keys == {"reports/a.pdf", "reports/b.docx"}
    assert objs[0]["size"] == 123


def test_put_rendered_report_falls_back_to_disk_without_s3(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.reports import templates as tpl
    uri = tpl.put_rendered_report("hello.txt", b"hello world", "text/plain")
    assert uri.startswith("file://")
    written = next((tmp_path / "reports" / "rendered").glob("hello*"))
    assert written.read_bytes() == b"hello world"


def test_put_rendered_report_uses_s3_when_configured(tmp_path, monkeypatch):
    _s3_env(monkeypatch)
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.reports import templates as tpl
    from safecadence.storage import s3_store as s3

    with mock.patch.object(s3, "S3Store") as Client:
        instance = mock.Mock()
        instance.put_object.return_value = "https://example/reports/x"
        Client.return_value = instance
        url = tpl.put_rendered_report("report.pdf", b"%PDF", "application/pdf")
        assert url == "https://example/reports/x"
        instance.put_object.assert_called_once()


# --------------------------------------------------------------------------
# 4. Cluster — health + failover
# --------------------------------------------------------------------------


def test_node_health_returns_expected_shape():
    from safecadence.cluster import health
    out = health.node_health()
    for key in ("node", "ts", "db_status", "redis_status", "s3_status",
                "is_active_node"):
        assert key in out
    assert isinstance(out["ts"], int)


def test_cluster_state_aggregates_peers(monkeypatch):
    monkeypatch.setenv("SC_CLUSTER_PEERS", "10.0.0.6,10.0.0.7")
    from safecadence.cluster import health

    def fake_fetcher(peer, timeout=3.0):
        if peer == "10.0.0.6":
            return {"peer": peer, "reachable": True, "data": {"node": "n6"}}
        return {"peer": peer, "reachable": False, "error": "timeout"}

    state = health.cluster_state(fetcher=fake_fetcher)
    assert state["peer_count"] == 2
    assert state["reachable_peers"] == 1
    assert state["local"]["node"]


def test_failover_single_node_always_active():
    """Without SC_REDIS_URL we should always report active."""
    from safecadence.cluster import failover as fo
    assert fo.am_i_active() is True
    assert fo.try_take_lease() is True
    fo.release_lease()
    # After release we should still be takeable.
    assert fo.try_take_lease() is True


def test_failover_lease_acquire_when_empty(monkeypatch):
    monkeypatch.setenv("SC_REDIS_URL", "redis://127.0.0.1:6379/0")
    from safecadence.cluster import failover as fo

    state = {"value": None}

    def fake_cmd(*args):
        if args[0] == "SET" and "NX" in args:
            if state["value"] is None:
                state["value"] = args[2]
                return "OK"
            return None
        if args[0] == "GET":
            return state["value"].encode() if state["value"] else None
        if args[0] == "DEL":
            state["value"] = None
            return 1
        if args[0] == "SET" and "XX" in args:
            state["value"] = args[2]
            return "OK"
        return None

    monkeypatch.setattr(fo, "_redis_cmd", fake_cmd)
    assert fo.try_take_lease() is True
    assert fo.am_i_active() is True
    assert fo.renew_lease() is True
    fo.release_lease()
    assert state["value"] is None


def test_failover_lease_taken_by_another_node(monkeypatch):
    monkeypatch.setenv("SC_REDIS_URL", "redis://127.0.0.1:6379/0")
    from safecadence.cluster import failover as fo

    state = {"value": "other-node"}

    def fake_cmd(*args):
        if args[0] == "SET" and "NX" in args:
            return None
        if args[0] == "GET":
            return state["value"].encode() if state["value"] else None
        return None

    monkeypatch.setattr(fo, "_redis_cmd", fake_cmd)
    assert fo.try_take_lease() is False
    assert fo.am_i_active() is False


# --------------------------------------------------------------------------
# 5. ServiceNow / Teams / Splunk
# --------------------------------------------------------------------------


def test_servicenow_returns_none_when_unconfigured():
    from safecadence.integrations import servicenow
    assert servicenow.is_configured() is False
    assert servicenow.create_servicenow_incident({"title": "x"}) is None


def test_servicenow_creates_incident(monkeypatch):
    monkeypatch.setenv("SC_SERVICENOW_INSTANCE", "acme")
    monkeypatch.setenv("SC_SERVICENOW_USER", "bot")
    monkeypatch.setenv("SC_SERVICENOW_PASS", "secret")
    from safecadence.integrations import servicenow

    body = json.dumps({"result": {"sys_id": "abc123", "number": "INC0010001"}}).encode()
    monkeypatch.setattr(servicenow._urlreq, "urlopen", _fake_urlopen_factory(body))

    out = servicenow.create_servicenow_incident({
        "title": "Critical CVE", "severity": "critical",
        "hostname": "rtr1", "cve": "CVE-2025-0001",
        "description": "kernel rce",
    })
    assert out is not None
    assert out["sys_id"] == "abc123"
    assert out["number"] == "INC0010001"
    assert "acme.service-now.com" in out["url"]


def test_teams_returns_none_when_unconfigured():
    from safecadence.integrations import teams
    assert teams.is_configured() is False
    assert teams.post_message("hello") is None


def test_teams_posts_card(monkeypatch):
    monkeypatch.setenv("SC_TEAMS_WEBHOOK_URL", "https://outlook.example/webhookb2/abc")
    from safecadence.integrations import teams

    captured: dict = {}

    def fake_urlopen(req, timeout=6.0):
        captured["url"] = req.full_url
        captured["data"] = req.data
        class _R:
            status = 200
            def read(self): return b""
            def __enter__(self): return self
            def __exit__(self, *a): return False
        return _R()
    monkeypatch.setattr(teams._urlreq, "urlopen", fake_urlopen)

    out = teams.post_finding({
        "title": "Bad thing", "severity": "high", "hostname": "rtr1",
        "cve": "CVE-2025-0001", "description": "details",
    })
    assert out == {"status_code": 200}
    payload = json.loads(captured["data"])
    assert payload["@type"] == "MessageCard"
    assert "Bad thing" in payload["title"]
    assert any(f["name"] == "Host" for f in payload["sections"][0]["facts"])


def test_splunk_returns_none_when_unconfigured():
    from safecadence.integrations import splunk
    assert splunk.is_configured() is False
    assert splunk.forward_finding({"title": "x"}) is None


def test_splunk_forwards_event(monkeypatch):
    monkeypatch.setenv("SC_SPLUNK_HEC_URL", "https://splunk.example/services/collector")
    monkeypatch.setenv("SC_SPLUNK_HEC_TOKEN", "token-abc")
    from safecadence.integrations import splunk

    captured: dict = {}

    def fake_urlopen(req, timeout=6.0):
        captured["url"] = req.full_url
        captured["data"] = req.data
        captured["auth"] = req.get_header("Authorization")
        body = json.dumps({"text": "Success", "code": 0}).encode()
        class _R:
            status = 200
            def read(self): return body
            def __enter__(self): return self
            def __exit__(self, *a): return False
        return _R()
    monkeypatch.setattr(splunk._urlreq, "urlopen", fake_urlopen)

    out = splunk.forward_finding({
        "id": "F1", "severity": "critical", "title": "x",
        "hostname": "rtr1", "cve": "CVE-2025-0001",
    })
    assert out["code"] == 0
    assert captured["auth"] == "Splunk token-abc"
    payload = json.loads(captured["data"])
    assert payload["sourcetype"] == "safecadence:finding"
    assert payload["event"]["hostname"] == "rtr1"
