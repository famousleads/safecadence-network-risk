"""
v9.34 #1 — HTTP tests for /api/identity/connect + /disconnect.

Pinned trust property: a credential blob never lands in the vault
unless adapter.test_connection() returned ok. The test
``test_connect_failure_does_not_persist`` exists exactly to defend
that property.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

pytest.importorskip("fastapi")
pytest.importorskip("cryptography")


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFECADENCE_HOME", str(tmp_path))
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_USERS_FILE", str(tmp_path / "users.yaml"))
    monkeypatch.setenv("SC_JIT_STORE", str(tmp_path / "jit.json"))
    monkeypatch.setenv("SC_INTEL_HOME", str(tmp_path / "intel"))
    monkeypatch.setenv("SC_JWT_SECRET",
                        "test-secret-do-not-use-in-prod")
    # Force a deterministic vault key so the test isn't sensitive to
    # whether ~/.safecadence/.identity_vault.key already exists.
    from cryptography.fernet import Fernet
    monkeypatch.setenv("SAFECADENCE_VAULT_KEY",
                        Fernet.generate_key().decode("ascii"))
    from fastapi.testclient import TestClient
    from safecadence.server import create_app
    from safecadence.server.auth import hash_password
    users_file = tmp_path / "users.yaml"
    users_file.write_text(yaml.safe_dump({
        "tenants": {"acme": {"users": [
            {"username": "alice",
              "password_hash": hash_password("hunter2"),
              "roles": ["admin"]},
        ]}}
    }))
    app = create_app(users_file=str(users_file),
                     db_url=f"sqlite:///{tmp_path}/sc.db",
                     jwt_secret="test-secret-do-not-use-in-prod")
    c = TestClient(app)
    r = c.post("/api/login",
                data={"username": "alice", "password": "hunter2"})
    assert r.status_code == 200, r.text
    c._sc_hdr = {"Authorization": f"Bearer {r.json()['access_token']}"}
    return c


def auth(c):
    return c._sc_hdr


def _patch_okta_test_connection(monkeypatch, *, ok: bool, error: str = ""):
    """Stub OktaAdapter.test_connection so the test doesn't need a real
    Okta tenant. The endpoint we're testing is the wrapper, not Okta's
    REST contract — adapter contract has its own dedicated test."""
    from safecadence.platform.adapters import identity_adapters as IA
    monkeypatch.setattr(
        IA.OktaAdapter, "test_connection",
        lambda self: {"ok": ok, "error": error},
    )


def test_connect_test_only_does_not_persist(client, monkeypatch):
    """mode=test_only never writes to the vault even on success."""
    _patch_okta_test_connection(monkeypatch, ok=True)
    r = client.post("/api/identity/connect", headers=auth(client),
                     json={"system": "okta", "target": "acme.okta.com",
                            "credentials": {"api_token": "tok-1"},
                            "mode": "test_only"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["tested"] is True
    assert body["ok"] is True
    assert body["saved"] is False

    # Confirm the vault really is empty.
    from safecadence.identity.vault import IdentityVault
    assert IdentityVault().load_creds("okta") is None


def test_connect_save_persists_after_passing_test(client, monkeypatch):
    _patch_okta_test_connection(monkeypatch, ok=True)
    r = client.post("/api/identity/connect", headers=auth(client),
                     json={"system": "okta", "target": "acme.okta.com",
                            "credentials": {"api_token": "tok-2"},
                            "mode": "save"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True and body["saved"] is True

    from safecadence.identity.vault import IdentityVault
    rec = IdentityVault().load_creds("okta")
    assert rec is not None
    assert rec.target == "acme.okta.com"
    assert rec.credentials == {"api_token": "tok-2"}
    assert rec.last_test_ok is True


def test_connect_failure_does_not_persist(client, monkeypatch):
    """The trust property: a failing test_connection MUST NOT save creds.
    Pinned with mode=save explicitly so a regression that swaps the
    persist-after-test order would fail this test loudly."""
    _patch_okta_test_connection(monkeypatch, ok=False,
                                  error="401 Unauthorized")
    r = client.post("/api/identity/connect", headers=auth(client),
                     json={"system": "okta", "target": "acme.okta.com",
                            "credentials": {"api_token": "BAD"},
                            "mode": "save"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["tested"] is True
    assert body["ok"] is False
    assert body["saved"] is False
    assert "401" in body["error"]

    from safecadence.identity.vault import IdentityVault
    assert IdentityVault().load_creds("okta") is None, (
        "Vault must NOT persist creds whose test_connection failed"
    )


def test_connect_rejects_unknown_system(client):
    r = client.post("/api/identity/connect", headers=auth(client),
                     json={"system": "duo", "target": "x",
                            "credentials": {"x": "y"}, "mode": "save"})
    assert r.status_code == 400


def test_connect_rejects_empty_credentials(client):
    r = client.post("/api/identity/connect", headers=auth(client),
                     json={"system": "okta", "target": "x",
                            "credentials": {}, "mode": "save"})
    assert r.status_code == 400


def test_connect_requires_writer_role(client, monkeypatch):
    """The connect endpoint mutates server state — must be writer-gated."""
    r = client.post("/api/identity/connect",
                     json={"system": "okta", "target": "x",
                            "credentials": {"api_token": "y"},
                            "mode": "test_only"})
    # No bearer header — must be rejected before the body even matters.
    assert r.status_code in (401, 403)


def test_disconnect_removes_saved_record(client, monkeypatch):
    _patch_okta_test_connection(monkeypatch, ok=True)
    client.post("/api/identity/connect", headers=auth(client),
                 json={"system": "okta", "target": "acme.okta.com",
                        "credentials": {"api_token": "t"}, "mode": "save"})
    r = client.post("/api/identity/disconnect/okta", headers=auth(client))
    assert r.status_code == 200
    assert r.json()["disconnected"] is True
    from safecadence.identity.vault import IdentityVault
    assert IdentityVault().load_creds("okta") is None
    # Idempotent.
    r = client.post("/api/identity/disconnect/okta", headers=auth(client))
    assert r.json()["disconnected"] is False


def test_connect_failure_returns_friendly_dns_hint(client, monkeypatch):
    """v9.34.2 — when test_connection fails because the host doesn't
    resolve (the operator typed 'admin' instead of 'acme.okta.com'),
    we surface a hint pointing at the right format. Defends the
    'is this right to you?' UX where users hit raw [Errno 8]."""
    from safecadence.platform.adapters import identity_adapters as IA
    monkeypatch.setattr(
        IA.OktaAdapter, "test_connection",
        lambda self: {
            "ok": False,
            "error": "[Errno 8] nodename nor servname provided, or not known",
        },
    )
    r = client.post("/api/identity/connect", headers=auth(client),
                     json={"system": "okta", "target": "admin",
                            "credentials": {"api_token": "x"},
                            "mode": "test_only"})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is False
    assert "hint" in body and body["hint"], (
        "DNS-resolution failures must include an operator-friendly hint"
    )
    assert "Could not resolve" in body["hint"]
    assert "admin" in body["hint"]
    # Raw error is preserved in `error` for debugging.
    assert "Errno 8" in body["error"]


def test_connect_failure_translates_401_to_credentials_hint(
        client, monkeypatch):
    """The 401 case should hint at credential / scope mismatch."""
    from safecadence.platform.adapters import identity_adapters as IA
    monkeypatch.setattr(
        IA.OktaAdapter, "test_connection",
        lambda self: {"ok": False, "error": "401 Unauthorized"},
    )
    r = client.post("/api/identity/connect", headers=auth(client),
                     json={"system": "okta", "target": "acme.okta.com",
                            "credentials": {"api_token": "x"},
                            "mode": "test_only"})
    body = r.json()
    assert body["ok"] is False
    assert "credentials were rejected" in body["hint"].lower()


def test_connectors_status_promotes_vault_record_over_env(client, monkeypatch):
    """After save, /connectors-status shows source=vault and reports
    the target from the vault record rather than env-var-derived."""
    _patch_okta_test_connection(monkeypatch, ok=True)
    client.post("/api/identity/connect", headers=auth(client),
                 json={"system": "okta", "target": "acme.okta.com",
                        "credentials": {"api_token": "t"}, "mode": "save"})
    r = client.get("/api/identity/connectors-status", headers=auth(client))
    assert r.status_code == 200
    okta = next(s for s in r.json()["systems"] if s["system"] == "okta")
    assert okta["configured"] is True
    assert okta["source"] == "vault"
    assert okta["target"] == "acme.okta.com"
    assert okta["last_test_at"]
