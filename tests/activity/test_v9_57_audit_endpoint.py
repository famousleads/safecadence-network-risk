"""v9.57 — HTTP-level coverage for /api/activity and the v9.57 fixes.

Pre-v9.57 there were zero HTTP-level tests for /api/activity. The
store and middleware had unit tests, but the actual JSON/CSV path
the auditor hits in the browser was unverified. This file covers:

  #1 read_range cross-day pagination correctness
  #2 CSV export writes its own audit row
  #4 actor_contains substring match
  #5 from_ts / to_ts date-range filter
  #6 extra_filter dict matching
  #7 middleware skip-list expansion
  + capability gate on /api/activity
  + filter combinations
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
from fastapi import FastAPI
from fastapi.testclient import TestClient


def _seed_record(tmp_path, *, day_offset_days=0, **kw):
    """Drop a row directly into the JSONL store. Cheaper than going
    through the middleware for setup-heavy tests."""
    import json
    import os
    activity = tmp_path / "activity"
    activity.mkdir(parents=True, exist_ok=True)
    when = datetime.now(timezone.utc) - timedelta(days=day_offset_days)
    p = activity / when.strftime("%Y-%m-%d.jsonl")
    payload = {
        "ts": kw.get("ts") or when.isoformat(timespec="seconds").replace(
            "+00:00", "Z"),
        "actor": kw.get("actor", "alice"),
        "tenant": kw.get("tenant", "default"),
        "method": kw.get("method", "POST"),
        "path": kw.get("path", "/api/users"),
        "status": kw.get("status", 200),
        "ip": kw.get("ip", "127.0.0.1"),
        "duration_ms": kw.get("duration_ms", 12),
        "request_id": kw.get("request_id", "req_test"),
        "extra": kw.get("extra", {}),
    }
    with p.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload) + "\n")
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass


def _build_app(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_ACTIVITY_DISABLED", "1")
    app = FastAPI()
    from safecadence.ui.v9_pages import register
    register(app)
    return TestClient(app)


# ----------------------------------------------------- #1 cross-day pagination

def test_read_range_does_not_drop_quiet_days(monkeypatch, tmp_path):
    """Pre-v9.57 a busy day 1 plus a quiet day 7 with limit=500 could
    silently drop day-7 records when day 1 alone filled the buffer.
    The fix: pull a per-day cap >= limit, then sort+slice once."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    # Day 0 (today): 50 newest records
    for i in range(50):
        _seed_record(tmp_path, day_offset_days=0, actor="busy",
                     ts=(datetime.now(timezone.utc) -
                          timedelta(seconds=i)).isoformat(
                              timespec="seconds").replace("+00:00", "Z"))
    # Day 6 (a week ago): 1 important record
    week_ago = datetime.now(timezone.utc) - timedelta(days=6)
    _seed_record(tmp_path, day_offset_days=6, actor="alice",
                 ts=week_ago.isoformat(timespec="seconds").replace(
                     "+00:00", "Z"),
                 path="/api/important")
    from safecadence.activity import read_range
    rows = read_range(days=7, limit=500)
    assert len(rows) == 51
    paths = [r.path for r in rows]
    assert "/api/important" in paths


def test_read_range_limit_slices_at_end(monkeypatch, tmp_path):
    """Limit applies AFTER union+sort, not per-day. With 100 rows in
    day 0 and 100 in day 1, asking for limit=50 returns the 50
    newest from day 0 (correct), not 50 from day 0 first then 0
    from day 1."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    for i in range(100):
        _seed_record(tmp_path, day_offset_days=0,
                     ts=(datetime.now(timezone.utc) -
                          timedelta(seconds=i)).isoformat(
                              timespec="seconds").replace("+00:00", "Z"),
                     actor="day0")
    for i in range(100):
        _seed_record(tmp_path, day_offset_days=1,
                     ts=(datetime.now(timezone.utc) -
                          timedelta(days=1, seconds=i)).isoformat(
                              timespec="seconds").replace("+00:00", "Z"),
                     actor="day1")
    from safecadence.activity import read_range
    rows = read_range(days=2, limit=50)
    assert len(rows) == 50
    # All should be from day 0 (newer) since we asked for the 50
    # newest across the union.
    actors = {r.actor for r in rows}
    assert actors == {"day0"}


# ----------------------------------------------------- #4 actor_contains

def test_actor_contains_email_match(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    _seed_record(tmp_path, actor="alice@example.com")
    _seed_record(tmp_path, actor="bob@example.com")
    _seed_record(tmp_path, actor="alice")
    from safecadence.activity import read_range
    rows = read_range(days=1, actor_contains="alice")
    assert len(rows) == 2
    actors = {r.actor for r in rows}
    assert actors == {"alice@example.com", "alice"}


def test_actor_contains_case_insensitive(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    _seed_record(tmp_path, actor="Alice@Example.COM")
    from safecadence.activity import read_range
    rows = read_range(days=1, actor_contains="alice")
    assert len(rows) == 1


# ----------------------------------------------------- #5 date-range

def test_from_ts_and_to_ts_inclusive(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    now = datetime.now(timezone.utc)
    _seed_record(tmp_path, day_offset_days=0,
                 ts=now.isoformat(timespec="seconds").replace("+00:00", "Z"),
                 actor="now")
    _seed_record(tmp_path, day_offset_days=2,
                 ts=(now - timedelta(days=2)).isoformat(
                     timespec="seconds").replace("+00:00", "Z"),
                 actor="2-days-ago")
    _seed_record(tmp_path, day_offset_days=10,
                 ts=(now - timedelta(days=10)).isoformat(
                     timespec="seconds").replace("+00:00", "Z"),
                 actor="10-days-ago")
    from safecadence.activity import read_range
    rows = read_range(
        days=30,
        from_ts=(now - timedelta(days=3)).isoformat(),
        to_ts=now.isoformat(),
    )
    actors = {r.actor for r in rows}
    assert actors == {"now", "2-days-ago"}


# ----------------------------------------------------- #6 extra_filter

def test_extra_filter_action_grant(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    _seed_record(tmp_path, path="/api/capabilities/alice",
                 extra={"action": "grant", "capability": "read.audit"})
    _seed_record(tmp_path, path="/api/capabilities/alice",
                 extra={"action": "revoke", "capability": "read.audit"})
    from safecadence.activity import read_range
    rows = read_range(days=1, extra_filter={"action": "grant"})
    assert len(rows) == 1
    assert rows[0].extra["action"] == "grant"


def test_extra_filter_handles_bool(monkeypatch, tmp_path):
    """JSON true/false flow through as strings via str() coercion."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    _seed_record(tmp_path, extra={"used_ai": True})
    _seed_record(tmp_path, extra={"used_ai": False})
    from safecadence.activity import read_range
    rows = read_range(days=1, extra_filter={"used_ai": "True"})
    assert len(rows) == 1


# ----------------------------------------------------- #2 csv-export audit row

def test_csv_export_writes_audit_row(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    _seed_record(tmp_path, actor="prior-row")
    monkeypatch.delenv("SC_ACTIVITY_DISABLED", raising=False)
    from fastapi import FastAPI
    app = FastAPI()
    from safecadence.ui.v9_pages import register
    register(app)
    client = TestClient(app)
    r = client.get("/api/activity?format=csv&days=1")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    # Now read the activity log and verify a row was written for
    # the export itself.
    from safecadence.activity import read_range
    rows = read_range(days=1, path_contains="/api/activity")
    export_rows = [row for row in rows
                    if (row.extra or {}).get("export") == "csv"]
    assert export_rows, "expected a CSV-export audit row"
    extra = export_rows[0].extra
    assert extra["row_count"] == 1   # the prior-row we seeded
    assert "filter_days" in extra


def test_csv_export_carries_filter_args_in_audit(monkeypatch, tmp_path):
    """The audit row should record what filters the user applied so
    a later auditor can answer 'what slice did alice export?'."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("SC_ACTIVITY_DISABLED", raising=False)
    _seed_record(tmp_path, actor="alice", path="/api/users")
    from fastapi import FastAPI
    app = FastAPI()
    from safecadence.ui.v9_pages import register
    register(app)
    client = TestClient(app)
    r = client.get(
        "/api/activity?format=csv&days=7&actor=alice&path=/api/users"
        "&extra_filter=action=grant"
    )
    assert r.status_code == 200
    from safecadence.activity import read_range
    rows = read_range(days=1, extra_filter={"export": "csv"})
    assert rows
    extra = rows[0].extra
    assert extra["filter_actor"] == "alice"
    assert extra["filter_path"] == "/api/users"
    assert extra["filter_extra"] == "action=grant"


# ----------------------------------------------------- json endpoint shape

def test_endpoint_json_default(monkeypatch, tmp_path):
    client = _build_app(monkeypatch, tmp_path)
    _seed_record(tmp_path, actor="alice")
    r = client.get("/api/activity?days=1")
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 1
    assert body["rows"][0]["actor"] == "alice"


def test_endpoint_actor_substring_via_query(monkeypatch, tmp_path):
    client = _build_app(monkeypatch, tmp_path)
    _seed_record(tmp_path, actor="alice@example.com")
    _seed_record(tmp_path, actor="bob@example.com")
    r = client.get("/api/activity?days=1&actor=alice")
    assert r.status_code == 200
    rows = r.json()["rows"]
    assert len(rows) == 1
    assert "alice" in rows[0]["actor"]


def test_endpoint_extra_filter_via_query(monkeypatch, tmp_path):
    client = _build_app(monkeypatch, tmp_path)
    _seed_record(tmp_path, extra={"action": "grant"})
    _seed_record(tmp_path, extra={"action": "revoke"})
    r = client.get("/api/activity?days=1&extra_filter=action=grant")
    assert r.status_code == 200
    rows = r.json()["rows"]
    assert len(rows) == 1
    assert rows[0]["extra"]["action"] == "grant"


def test_endpoint_extra_filter_malformed_skipped(monkeypatch, tmp_path):
    """Malformed extra_filter entries are silently skipped (a typo
    in one key shouldn't lose the whole filter)."""
    client = _build_app(monkeypatch, tmp_path)
    _seed_record(tmp_path, extra={"action": "grant"})
    r = client.get(
        "/api/activity?days=1&extra_filter=nonsense,action=grant"
    )
    assert r.status_code == 200
    rows = r.json()["rows"]
    assert len(rows) == 1


def test_endpoint_capability_gate_blocks_revoked(monkeypatch, tmp_path):
    """User with explicit revoke on read.activity → 403."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_ACTIVITY_DISABLED", "1")
    from safecadence.capabilities.store import revoke
    # Synthetic admin in single-user mode is `local-admin` with
    # role=admin which short-circuits has_capability. To prove the
    # gate exists we override caller_user via a fake.
    import safecadence.ui._caller as _caller_mod
    real = _caller_mod.caller_user
    try:
        def fake_caller(_request):
            return _caller_mod._SyntheticUser(
                username="auditor", tenant="default",
                roles=["viewer"],
            )
        _caller_mod.caller_user = fake_caller
        revoke("auditor", "read.activity", actor="cto", reason="test")
        from fastapi import FastAPI
        app = FastAPI()
        from safecadence.ui.v9_pages import register
        register(app)
        client = TestClient(app)
        r = client.get("/api/activity?days=1")
        assert r.status_code == 403
    finally:
        _caller_mod.caller_user = real


# ----------------------------------------------------- #7 middleware skip

def test_middleware_skips_palette_keystrokes(monkeypatch, tmp_path):
    """/api/v9/search is hit on every command-palette keystroke;
    must NOT show up in the activity log even with read-logging on."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("SC_ACTIVITY_DISABLED", raising=False)

    from fastapi import FastAPI
    from safecadence.activity import ActivityMiddleware
    app = FastAPI()

    @app.post("/api/v9/search")
    def palette():
        return {"hits": []}

    @app.post("/api/users")
    def users():
        return {"ok": True}

    app.add_middleware(ActivityMiddleware, log_reads=True)
    client = TestClient(app)

    # 5 palette hits (should all be skipped)
    for _ in range(5):
        client.post("/api/v9/search", json={"q": "x"})
    # 1 real action (should be logged)
    client.post("/api/users", json={"username": "alice"})

    from safecadence.activity import read_range
    rows = read_range(days=1)
    paths = [r.path for r in rows]
    assert "/api/users" in paths
    assert "/api/v9/search" not in paths


def test_middleware_populates_extra_source_field(monkeypatch, tmp_path):
    """v9.57.1 — middleware-written rows carry source='http' so the
    auditor can tell them apart from direct-write rows. Pre-v9.57.1
    middleware rows had extra={} which made the rich-vs-poor data
    indistinguishable."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("SC_ACTIVITY_DISABLED", raising=False)

    from fastapi import FastAPI
    from safecadence.activity import ActivityMiddleware
    app = FastAPI()

    @app.post("/api/users")
    def users():
        return {"ok": True}

    app.add_middleware(ActivityMiddleware)
    client = TestClient(app)
    client.post("/api/users?actor_kind=human", json={"x": 1},
                headers={"User-Agent": "test-client/1.0"})

    from safecadence.activity import read_range
    rows = read_range(days=1, path_contains="/api/users")
    matching = [r for r in rows if r.path == "/api/users"]
    assert matching
    extra = matching[0].extra or {}
    assert extra.get("source") == "http"
    # Query string captured (capped)
    assert "actor_kind=human" in (extra.get("query", ""))
    # User agent captured (capped)
    assert "test-client" in (extra.get("ua", ""))


def test_middleware_extra_query_capped(monkeypatch, tmp_path):
    """Hostile-input log bloat defense: query is capped at 500 chars."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("SC_ACTIVITY_DISABLED", raising=False)

    from fastapi import FastAPI
    from safecadence.activity import ActivityMiddleware
    app = FastAPI()

    @app.post("/api/users")
    def users():
        return {"ok": True}

    app.add_middleware(ActivityMiddleware)
    client = TestClient(app)
    huge = "x" * 2000
    client.post(f"/api/users?bloat={huge}", json={})

    from safecadence.activity import read_range
    rows = read_range(days=1, path_contains="/api/users")
    extra = rows[0].extra or {}
    assert len(extra.get("query", "")) <= 500


# ----------------------------------------------------- v9.57.2 #1 tenant scope


def test_endpoint_auto_scopes_to_caller_tenant(monkeypatch, tmp_path):
    """Pre-v9.57.2 the endpoint accepted no tenant arg; in MSP-style
    deploys an auditor for tenant A could see tenant B's rows.
    v9.57.2: non-admins are auto-scoped to their own tenant."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_ACTIVITY_DISABLED", "1")
    _seed_record(tmp_path, actor="alice", tenant="acme",
                  path="/acme-action")
    _seed_record(tmp_path, actor="bob", tenant="globex",
                  path="/globex-action")
    # Override caller_user → tenant=acme, role=viewer
    import safecadence.ui._caller as _caller_mod
    real = _caller_mod.caller_user
    try:
        def fake_caller(_request):
            return _caller_mod._SyntheticUser(
                username="alice", tenant="acme", roles=["viewer"],
            )
        _caller_mod.caller_user = fake_caller
        # Grant viewer floor caps so the gate passes
        from safecadence.capabilities.store import grant
        grant("alice", "read.activity", actor="cto",
              tenant="acme", reason="test")

        from fastapi import FastAPI
        app = FastAPI()
        from safecadence.ui.v9_pages import register
        register(app)
        client = TestClient(app)
        r = client.get("/api/activity?days=1")
        assert r.status_code == 200
        rows = r.json()["rows"]
        paths = {row["path"] for row in rows}
        assert "/acme-action" in paths
        assert "/globex-action" not in paths
    finally:
        _caller_mod.caller_user = real


def test_endpoint_admin_can_request_cross_tenant(monkeypatch, tmp_path):
    """Admins can pass tenant=* to read across tenants."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_ACTIVITY_DISABLED", "1")
    _seed_record(tmp_path, tenant="acme", path="/a")
    _seed_record(tmp_path, tenant="globex", path="/b")
    client = _build_app(monkeypatch, tmp_path)  # synth admin
    r = client.get("/api/activity?days=1&tenant=*")
    assert r.status_code == 200
    paths = {row["path"] for row in r.json()["rows"]}
    assert paths == {"/a", "/b"}


def test_endpoint_403_when_non_admin_passes_other_tenant(
        monkeypatch, tmp_path):
    """Non-admin asking for a different tenant → 403."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_ACTIVITY_DISABLED", "1")
    import safecadence.ui._caller as _caller_mod
    real = _caller_mod.caller_user
    try:
        def fake_caller(_request):
            return _caller_mod._SyntheticUser(
                username="alice", tenant="acme", roles=["viewer"],
            )
        _caller_mod.caller_user = fake_caller
        from safecadence.capabilities.store import grant
        grant("alice", "read.activity", actor="cto",
              tenant="acme", reason="test")
        from fastapi import FastAPI
        app = FastAPI()
        from safecadence.ui.v9_pages import register
        register(app)
        client = TestClient(app)
        r = client.get("/api/activity?days=1&tenant=globex")
        assert r.status_code == 403
        assert "cross-tenant" in r.json()["detail"].lower()
    finally:
        _caller_mod.caller_user = real


# ----------------------------------------------------- v9.57.2 #2 rate limit

def test_endpoint_rate_limit_429(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_AUDIT_RATE_LIMIT", "3")
    monkeypatch.setenv("SC_AUDIT_RATE_WINDOW_SEC", "60")
    client = _build_app(monkeypatch, tmp_path)
    for _ in range(3):
        r = client.get("/api/activity?days=1")
        assert r.status_code == 200
    # 4th gets 429 with retry-after hint
    r = client.get("/api/activity?days=1")
    assert r.status_code == 429
    assert "rate limit" in r.json()["detail"].lower()
    assert "retry" in r.json()["detail"].lower()


# ----------------------------------------------------- v9.57.2 #3 filename

def test_csv_filename_carries_filter_segments(monkeypatch, tmp_path):
    """Auditor downloads three slices, filenames are distinguishable."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("SC_ACTIVITY_DISABLED", raising=False)
    _seed_record(tmp_path, actor="alice")
    from fastapi import FastAPI
    app = FastAPI()
    from safecadence.ui.v9_pages import register
    register(app)
    client = TestClient(app)
    r = client.get(
        "/api/activity?format=csv&actor=alice"
        "&path=/api/capabilities/&method=POST&days=7"
    )
    assert r.status_code == 200
    cd = r.headers["Content-Disposition"]
    # Each segment should land in the filename
    assert "actor-alice" in cd
    # Path slashes get sanitized to underscores; leading/trailing
    # underscores stripped so the segment reads cleanly.
    assert "api_capabilities" in cd
    assert "method-POST" in cd
    assert "days-7" in cd


def test_csv_filename_uses_date_range_when_supplied(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("SC_ACTIVITY_DISABLED", raising=False)
    _seed_record(tmp_path, actor="alice")
    from fastapi import FastAPI
    app = FastAPI()
    from safecadence.ui.v9_pages import register
    register(app)
    client = TestClient(app)
    r = client.get(
        "/api/activity?format=csv"
        "&from_ts=2026-03-01&to_ts=2026-03-15"
    )
    assert r.status_code == 200
    cd = r.headers["Content-Disposition"]
    assert "range-2026-03-01..2026-03-15" in cd
    # When date range is supplied, the days-N segment is replaced
    assert "days-" not in cd


def test_middleware_skip_extends_via_env(monkeypatch, tmp_path):
    """SC_ACTIVITY_SKIP_PREFIXES extends the default skip list."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_ACTIVITY_SKIP_PREFIXES",
                          "/api/internal-noise/,/_metrics")
    monkeypatch.delenv("SC_ACTIVITY_DISABLED", raising=False)

    from fastapi import FastAPI
    from safecadence.activity import ActivityMiddleware
    app = FastAPI()

    @app.post("/api/internal-noise/foo")
    def noise():
        return {"ok": True}

    @app.post("/_metrics/scrape")
    def metrics():
        return {"ok": True}

    @app.post("/api/users")
    def users():
        return {"ok": True}

    app.add_middleware(ActivityMiddleware)
    client = TestClient(app)
    client.post("/api/internal-noise/foo")
    client.post("/_metrics/scrape")
    client.post("/api/users", json={})

    from safecadence.activity import read_range
    paths = [r.path for r in read_range(days=1)]
    assert paths == ["/api/users"]
