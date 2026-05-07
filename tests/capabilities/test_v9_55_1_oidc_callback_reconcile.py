"""v9.55.1 #6 — HTTP-level test for the OIDC callback → capability
reconcile wiring.

reconcile_sso_grants is unit-tested in test_v9_54_sso_caps.py. What
wasn't tested before this file was the actual `/api/auth/oidc/callback`
endpoint that calls it. This file mocks the OIDC token exchange +
ID-token verification so we can exercise the full HTTP path:

  GET /api/auth/oidc/callback?code=...&state=...
    → oidc_callback(cfg, code, state) returns dict with capabilities
    → endpoint mints JWT + calls reconcile_sso_grants
    → response carries cap_summary

Without this test, a future refactor that drops the reconcile call
from the endpoint would not be caught — the unit-level reconcile
tests would still pass.
"""
from __future__ import annotations

from unittest.mock import patch
from fastapi import FastAPI
from fastapi.testclient import TestClient


def _build_app(monkeypatch, tmp_path, *, sso_cfg):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_SSO_CONFIG", str(tmp_path / "sso.json"))
    # v9.56.1 — JWT secret precedence is now env-first, file-fallback.
    # Setting SC_JWT_SECRET alone is enough; the HOME redirect that
    # the v9.55.1 test fixture used is no longer needed.
    monkeypatch.setenv("SC_JWT_SECRET", "test-jwt-secret-x" * 4)
    monkeypatch.setenv("SC_ACTIVITY_DISABLED", "1")
    # Persist the SSO config the callback expects.
    from safecadence.sso import save_config
    save_config(sso_cfg)

    app = FastAPI()
    # The callback lives in platform_api.register; that needs both
    # auth deps. Pass permissive stubs since the OIDC route doesn't
    # require a pre-authenticated caller.
    from safecadence.server.platform_api import register
    from safecadence.server.auth import CurrentUser

    def _u():
        return CurrentUser(username="t", tenant="default", roles=["admin"])

    register(app, get_current_user=_u, require_writer=_u)
    return app


def _fake_oidc_callback_dict(*, capabilities=()):
    """Stand-in for what oidc_callback() would return after a real
    token-exchange + JWT verify. The endpoint only reads these
    fields so we can hand it a dict."""
    return {
        "username": "alice",
        "email": "alice@example.com",
        "name": "Alice Example",
        "role": "viewer",
        "tenant": "default",
        "capabilities": list(capabilities),
        "redirect_after": "",
        "raw_claims": {"sub": "alice", "groups": ["okta-secops"]},
    }


# --------------------------------------------------- happy path

def test_callback_grants_sso_capabilities(monkeypatch, tmp_path):
    """User in 'okta-secops' lands on /callback → reconcile grants
    the configured capabilities, response carries the summary."""
    from safecadence.sso import SSOConfig
    cfg = SSOConfig(
        enabled=True, flow="oidc",
        oidc_issuer="https://idp.example.com",
        oidc_client_id="cid",
        oidc_redirect_uri="https://x/cb",
        capability_map={"okta-secops": ["read.audit", "admin.capabilities"]},
    )
    app = _build_app(monkeypatch, tmp_path, sso_cfg=cfg)
    client = TestClient(app)

    with patch("safecadence.sso.oidc_callback",
                 return_value=_fake_oidc_callback_dict(
                     capabilities=["read.audit", "admin.capabilities"])):
        r = client.get("/api/auth/oidc/callback?code=abc&state=xyz")

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["username"] == "alice"
    # JWT minted
    assert body["access_token"]
    assert body["token_type"] == "bearer"
    # Capability summary surfaced for the front-end
    assert "capabilities" in body
    cap = body["capabilities"]
    assert sorted(cap.get("granted") or []) == [
        "admin.capabilities", "read.audit"]
    assert cap.get("revoked") == []

    # Persistent state: the YAML store actually has the grants
    from safecadence.capabilities.store import get_grant
    rec = get_grant("alice")
    assert "read.audit" in rec.grant
    assert "admin.capabilities" in rec.grant


def test_callback_revokes_when_user_leaves_group(monkeypatch, tmp_path):
    """First login grants admin.capabilities. Second login (without
    that group claim) reconciles to empty — the cap is revoked.
    Manual grants would survive but SSO-managed ones don't."""
    from safecadence.sso import SSOConfig
    cfg = SSOConfig(
        enabled=True, flow="oidc",
        oidc_issuer="https://idp.example.com",
        oidc_client_id="cid",
        oidc_redirect_uri="https://x/cb",
        capability_map={"okta-secops": ["admin.capabilities"]},
    )
    app = _build_app(monkeypatch, tmp_path, sso_cfg=cfg)
    client = TestClient(app)

    # Login 1 — user IS in okta-secops
    with patch("safecadence.sso.oidc_callback",
                 return_value=_fake_oidc_callback_dict(
                     capabilities=["admin.capabilities"])):
        r1 = client.get("/api/auth/oidc/callback?code=a&state=s")
    assert r1.status_code == 200
    assert "admin.capabilities" in r1.json()["capabilities"]["granted"]

    # Login 2 — user no longer in the group
    with patch("safecadence.sso.oidc_callback",
                 return_value=_fake_oidc_callback_dict(capabilities=[])):
        r2 = client.get("/api/auth/oidc/callback?code=b&state=t")
    assert r2.status_code == 200
    cap = r2.json()["capabilities"]
    assert cap.get("granted") == []
    assert cap.get("revoked") == ["admin.capabilities"]


def test_callback_disabled_without_sso(monkeypatch, tmp_path):
    """Hitting the callback when SSO is disabled returns 404, not
    a half-baked 500 with a stack trace."""
    from safecadence.sso import SSOConfig
    cfg = SSOConfig(enabled=False, flow="oidc")
    app = _build_app(monkeypatch, tmp_path, sso_cfg=cfg)
    client = TestClient(app)
    r = client.get("/api/auth/oidc/callback?code=abc&state=xyz")
    assert r.status_code == 404
    assert "OIDC" in r.json()["detail"]


def test_callback_empty_capability_map_still_works(monkeypatch, tmp_path):
    """If capability_map is empty (the default), the reconcile is
    a no-op and the user just gets logged in — the capabilities
    feature must not break the basic SSO login path."""
    from safecadence.sso import SSOConfig
    cfg = SSOConfig(
        enabled=True, flow="oidc",
        oidc_issuer="https://idp.example.com",
        oidc_client_id="cid",
        oidc_redirect_uri="https://x/cb",
        # No capability_map — login should still mint a JWT.
    )
    app = _build_app(monkeypatch, tmp_path, sso_cfg=cfg)
    client = TestClient(app)
    with patch("safecadence.sso.oidc_callback",
                 return_value=_fake_oidc_callback_dict(capabilities=[])):
        r = client.get("/api/auth/oidc/callback?code=a&state=s")
    assert r.status_code == 200
    assert r.json()["access_token"]
    assert r.json()["capabilities"]["granted"] == []
    assert r.json()["capabilities"]["revoked"] == []
