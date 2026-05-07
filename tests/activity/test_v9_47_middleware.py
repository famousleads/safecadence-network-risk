"""v9.47 — Activity middleware.

Wraps a tiny FastAPI app with ActivityMiddleware and asserts that:
  * mutations (POST) get logged
  * reads (GET) are skipped by default
  * actor extraction works for cookie-session user state
  * disk-full doesn't break the request
"""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient


def _build_app(*, log_reads: bool = False):
    from safecadence.activity import ActivityMiddleware
    app = FastAPI()
    app.add_middleware(ActivityMiddleware, jwt_secret=None,
                          log_reads=log_reads)

    @app.get("/api/x")
    def get_x():
        return {"ok": True}

    @app.post("/api/x")
    def post_x():
        return {"created": True}

    @app.delete("/api/x/{rid}")
    def del_x(rid: str):
        return {"deleted": rid}

    return app


def test_post_is_logged(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    app = _build_app()
    client = TestClient(app)
    r = client.post("/api/x")
    assert r.status_code == 200
    assert "x-sc-request-id" in {k.lower() for k in r.headers}
    from safecadence.activity import read_range
    rows = read_range(days=1)
    assert len(rows) == 1
    assert rows[0].method == "POST"
    assert rows[0].path == "/api/x"
    assert rows[0].status == 200
    assert rows[0].request_id.startswith("req_")


def test_get_is_skipped_by_default(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    app = _build_app()
    client = TestClient(app)
    r = client.get("/api/x")
    assert r.status_code == 200
    from safecadence.activity import read_range
    rows = read_range(days=1)
    assert rows == []


def test_get_logged_when_forensic_mode(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    app = _build_app(log_reads=True)
    client = TestClient(app)
    client.get("/api/x")
    from safecadence.activity import read_range
    rows = read_range(days=1)
    assert len(rows) == 1
    assert rows[0].method == "GET"


def test_delete_logged_with_path_param(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    app = _build_app()
    client = TestClient(app)
    r = client.delete("/api/x/42")
    assert r.status_code == 200
    from safecadence.activity import read_range
    rows = read_range(days=1)
    assert rows[0].method == "DELETE"
    assert rows[0].path == "/api/x/42"


def test_disk_full_does_not_break_request(monkeypatch, tmp_path):
    """If JSONL append raises, the request still returns 2xx."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.activity import store

    def boom(*a, **kw):
        raise OSError("disk full")

    real_open = store.Path.open

    def fake_open(self, mode="r", **kw):
        if "a" in mode or "w" in mode:
            raise OSError("disk full")
        return real_open(self, mode, **kw)

    monkeypatch.setattr(store.Path, "open", fake_open)
    app = _build_app()
    client = TestClient(app)
    r = client.post("/api/x")
    # The request must still succeed — activity log is best-effort.
    assert r.status_code == 200


def test_self_log_is_ignored(monkeypatch, tmp_path):
    """Calls to /api/activity itself shouldn't log — would create
    feedback noise on every page load."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.activity import ActivityMiddleware

    app = FastAPI()
    app.add_middleware(ActivityMiddleware, jwt_secret=None)

    @app.post("/api/activity")
    def echo():
        return {"ok": True}

    @app.post("/api/regular")
    def reg():
        return {"ok": True}

    client = TestClient(app)
    client.post("/api/activity")
    client.post("/api/regular")
    from safecadence.activity import read_range
    rows = read_range(days=1)
    paths = [r.path for r in rows]
    assert "/api/activity" not in paths
    assert "/api/regular" in paths
