"""Opt-in Cloud Sync — off by default, explicit connect, disconnect purges.

NetRisk is local-first; these tests pin the privacy contract: nothing syncs
unless the user explicitly connects, and disconnecting removes all config.
"""
import json
import os
import tempfile

from safecadence import cloud_sync as cs


def _isolate(monkeypatch):
    d = tempfile.mkdtemp(prefix="nrcloud_")
    monkeypatch.setenv("SC_DATA_DIR", d)
    return d


def test_off_by_default(monkeypatch):
    _isolate(monkeypatch)
    assert cs.is_enabled() is False
    assert cs.status()["connected"] is False
    # push is a no-op when not connected
    assert cs.push({"x": 1})["sent"] is False


def test_rejects_bad_token_and_http(monkeypatch):
    _isolate(monkeypatch)
    for bad in [("nope", "https://x"), ("sgt_ok", "http://insecure")]:
        try:
            cs.connect(bad[0], url=bad[1])
            assert False, "should have raised"
        except ValueError:
            pass


def test_connect_status_disconnect(monkeypatch):
    d = _isolate(monkeypatch)
    token = "sgt_" + "a" * 48
    cs.connect(token, url="https://analyzer.safecadence.com/portal/api/shield/graph/import-netrisk")
    assert cs.is_enabled() is True
    s = cs.status()
    assert s["connected"] and s["enabled"]
    assert s["token"].startswith("sgt_") and "…" in s["token"]   # masked

    cfg = json.loads(open(os.path.join(d, "cloud.json")).read())
    assert cfg["token"] == token and cfg["enabled"] is True
    assert (os.stat(os.path.join(d, "cloud.json")).st_mode & 0o777) == 0o600

    assert cs.disconnect() is True
    assert cs.is_enabled() is False
    assert not os.path.exists(os.path.join(d, "cloud.json"))


def test_pause_resume(monkeypatch):
    _isolate(monkeypatch)
    cs.connect("sgt_" + "b" * 48, url="https://x.safecadence.com/import")
    assert cs.set_enabled(False) is True
    assert cs.is_enabled() is False        # paused, but still connected
    assert cs.status()["connected"] is True
    assert cs.set_enabled(True) is True
    assert cs.is_enabled() is True


def test_push_queues_when_offline(monkeypatch):
    _isolate(monkeypatch)
    # Unreachable host → push fails → payload is queued, not lost.
    cs.connect("sgt_" + "c" * 48, url="https://127.0.0.1:9/import")
    res = cs.push({"hello": "world"}, timeout=1)
    assert res["sent"] is False and res.get("queued") is True
    assert cs.queued_count() == 1
    assert cs.status()["queued"] == 1


def test_flush_requires_connection(monkeypatch):
    _isolate(monkeypatch)
    out = cs.flush_queue()
    assert out["reason"] == "not connected"


def test_disconnect_leaves_no_active_sync(monkeypatch):
    _isolate(monkeypatch)
    cs.connect("sgt_" + "d" * 48, url="https://127.0.0.1:9/import")
    cs.push({"a": 1}, timeout=1)            # queues one
    assert cs.queued_count() == 1
    cs.disconnect()
    # Disconnected → nothing syncs, flush is a no-op.
    assert cs.is_enabled() is False
    assert cs.flush_queue()["reason"] == "not connected"
