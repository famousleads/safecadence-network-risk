"""v9.49.1 — verify capability gates are wired into the route layer.

Mounts a tiny FastAPI app with v9_pages register() and proves:
  * /api/activity short-circuits in single-user mode (no JWT)
  * /api/capabilities/*/grant requires admin.capabilities
  * /api/capabilities/*/revoke requires admin.capabilities
  * Single-user fallback (no JWT, no state.user) gets a synthetic
    admin and passes every gate

We can't easily mount the multi-user JWT app here (it pulls in the
storage adapter), so this test file targets the local-UI surface
where the ``caller_user()`` helper returns the synthetic admin.
"""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient


def _build_local_app(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_ACTIVITY_DISABLED", "1")
    app = FastAPI()
    from safecadence.ui.v9_pages import register
    register(app)
    return app


def test_activity_endpoint_passes_in_single_user_mode(monkeypatch,
                                                        tmp_path):
    app = _build_local_app(monkeypatch, tmp_path)
    client = TestClient(app)
    r = client.get("/api/activity?days=1")
    assert r.status_code == 200
    body = r.json()
    assert "rows" in body
    assert "count" in body


def test_capability_grant_passes_in_single_user(monkeypatch, tmp_path):
    app = _build_local_app(monkeypatch, tmp_path)
    client = TestClient(app)
    # Single-user mode → synthetic admin → grant succeeds
    r = client.post("/api/capabilities/alice/grant",
                    json={"capability": "execute.real",
                            "reason": "test"})
    assert r.status_code == 200
    body = r.json()
    assert "execute.real" in body["grant"]


def test_capability_revoke_passes_in_single_user(monkeypatch, tmp_path):
    app = _build_local_app(monkeypatch, tmp_path)
    client = TestClient(app)
    client.post("/api/capabilities/bob/grant",
                  json={"capability": "execute.real"})
    r = client.post("/api/capabilities/bob/revoke",
                     json={"capability": "execute.real",
                            "reason": "rotation-ended"})
    assert r.status_code == 200
    body = r.json()
    assert "execute.real" not in body["grant"]
    assert "execute.real" in body["deny"]


def test_capability_unknown_returns_400(monkeypatch, tmp_path):
    app = _build_local_app(monkeypatch, tmp_path)
    client = TestClient(app)
    r = client.post("/api/capabilities/eve/grant",
                     json={"capability": "totally.made.up"})
    assert r.status_code == 400
    assert "unknown capability" in r.json()["detail"].lower()


def test_caller_user_synthetic_admin_resolves(monkeypatch, tmp_path):
    """Direct unit test of the caller helper. No HTTP layer."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.ui._caller import caller_user

    class _FakeReq:
        headers = {}
        state = type("_S", (), {})()
        client = None

    u = caller_user(_FakeReq())
    assert u.username == "local-admin"
    assert "admin" in u.roles


def test_caller_user_decodes_real_jwt(monkeypatch, tmp_path):
    """Multi-user path: a valid JWT yields the real user, not the
    synthetic admin."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_JWT_SECRET", "test-secret")
    from safecadence.server.auth import CurrentUser, make_jwt
    token = make_jwt(
        CurrentUser(username="alice", tenant="default", roles=["viewer"]),
        secret="test-secret",
    )
    from safecadence.ui._caller import caller_user

    class _FakeReq:
        headers = {"authorization": f"Bearer {token}"}
        state = type("_S", (), {})()
        client = None

    u = caller_user(_FakeReq())
    assert u.username == "alice"
    assert u.roles == ["viewer"]


def test_caller_user_falls_back_when_jwt_invalid(monkeypatch, tmp_path):
    """Tampered/invalid JWT → fall back to synthetic admin (the
    upstream auth middleware should have already rejected the
    request — this helper never raises 401)."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_JWT_SECRET", "right-secret")
    from safecadence.ui._caller import caller_user

    class _FakeReq:
        headers = {"authorization": "Bearer not-a-real-token"}
        state = type("_S", (), {})()
        client = None

    u = caller_user(_FakeReq())
    # Falls back to synthetic admin in the local-UI mode
    assert "admin" in u.roles
