"""v9.47 — Activity log JSONL store.

Round-trips records through the on-disk format, exercises the
filter API the /audit page uses.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone, timedelta


def test_append_and_read_day(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.activity import store
    rec = store.ActivityRecord(
        ts="2026-05-07T13:42:11Z",
        actor="alice", method="POST", path="/api/users",
        status=200, ip="127.0.0.1", duration_ms=23,
        request_id="req_abc",
    )
    p = store.append(rec)
    assert p.exists()
    rows = store.read_day("2026-05-07")
    assert len(rows) == 1
    assert rows[0].actor == "alice"
    assert rows[0].request_id == "req_abc"
    # Filter by actor — non-match returns empty
    assert store.read_day("2026-05-07", actor="bob") == []
    # Filter by method
    assert len(store.read_day("2026-05-07", method="POST")) == 1
    assert store.read_day("2026-05-07", method="DELETE") == []
    # Filter by path substring
    assert len(store.read_day("2026-05-07", path_contains="users")) == 1
    assert store.read_day("2026-05-07", path_contains="webhooks") == []


def test_read_range_newest_first(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.activity import store
    today = datetime.now(timezone.utc)
    yesterday = today - timedelta(days=1)
    store.append(store.ActivityRecord(
        ts=yesterday.isoformat(timespec="seconds").replace("+00:00", "Z"),
        actor="alice", method="POST", path="/api/users", status=200,
    ))
    store.append(store.ActivityRecord(
        ts=today.isoformat(timespec="seconds").replace("+00:00", "Z"),
        actor="bob", method="DELETE", path="/api/webhooks/x", status=200,
    ))
    rows = store.read_range(days=2, end=today)
    assert len(rows) == 2
    # newest first
    assert rows[0].actor == "bob"
    assert rows[1].actor == "alice"


def test_append_robust_to_disk_full(monkeypatch, tmp_path):
    """If the JSONL append raises, append() must NOT propagate — that
    would break the request the middleware was wrapping."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.activity import store

    def boom(*a, **kw):
        raise OSError("disk full")

    # Patch Path.open to raise on write mode
    real_open = store.Path.open

    def fake_open(self, mode="r", **kw):
        if "a" in mode or "w" in mode:
            raise OSError("disk full")
        return real_open(self, mode, **kw)

    monkeypatch.setattr(store.Path, "open", fake_open)
    rec = store.ActivityRecord(actor="alice", method="POST",
                                  path="/api/x", status=200)
    # Must not raise
    store.append(rec)


def test_read_day_handles_corrupt_lines(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.activity import store
    p = store._file_for(datetime(2026, 5, 7, tzinfo=timezone.utc))
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        json.dumps({"ts": "2026-05-07T00:00:00Z", "actor": "ok",
                     "method": "POST", "path": "/x", "status": 200}) + "\n" +
        "{not json}\n" +
        json.dumps({"ts": "2026-05-07T00:00:01Z", "actor": "ok2",
                     "method": "POST", "path": "/y", "status": 200}) + "\n",
        encoding="utf-8",
    )
    rows = store.read_day("2026-05-07")
    # Two valid rows survive; corrupt one is dropped silently.
    assert [r.actor for r in rows] == ["ok", "ok2"]
