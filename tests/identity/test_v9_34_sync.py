"""
v9.34 #3 — Tests for /api/identity/sync/{system}.

The sync flow is the most operationally important new endpoint in
v9.34 — getting it wrong silently means everything downstream
(/access, /paths, /findings) reads stale data. Pinned properties:

  * Sync against a not-connected system returns 409 (operator must
    save creds first).
  * Sync calls adapter.collect() exactly once and adapter.normalize()
    exactly once — proves we're not double-fetching or skipping
    normalization.
  * The unified asset produced lands in list_assets() so every
    downstream surface can read it.
  * vault.mark_synced() is called on success — the connector strip
    shows "last synced Xs ago" honestly.
  * collect() error → 502, never silently mutates anything.
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
    # v9.34 #3: isolate the platform asset store so tests don't pollute
    # ~/.safecadence/platform_assets/ on the operator's real machine.
    monkeypatch.setenv("SC_PLATFORM_STORE",
                        str(tmp_path / "platform_assets"))
    monkeypatch.setenv("SC_USERS_FILE", str(tmp_path / "users.yaml"))
    monkeypatch.setenv("SC_JIT_STORE", str(tmp_path / "jit.json"))
    monkeypatch.setenv("SC_INTEL_HOME", str(tmp_path / "intel"))
    monkeypatch.setenv("SC_JWT_SECRET",
                        "test-secret-do-not-use-in-prod")
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


def _save_okta_via_connect(client, monkeypatch):
    """Helper: stub test_connection and save creds via /connect so we
    don't violate the trust property in the fixture itself."""
    from safecadence.platform.adapters import identity_adapters as IA
    monkeypatch.setattr(
        IA.OktaAdapter, "test_connection",
        lambda self: {"ok": True, "error": ""},
    )
    r = client.post("/api/identity/connect", headers=auth(client),
                     json={"system": "okta", "target": "acme.okta.com",
                            "credentials": {"api_token": "tok-1"},
                            "mode": "save"})
    assert r.status_code == 200, r.text


# --------------------------------------------------------------- not connected


def test_sync_unconnected_returns_409(client):
    r = client.post("/api/identity/sync/okta", headers=auth(client))
    assert r.status_code == 409
    assert "not connected" in r.json()["detail"].lower()


def test_sync_unknown_system_400(client):
    r = client.post("/api/identity/sync/duo", headers=auth(client))
    assert r.status_code == 400


# ----------------------------------------------------------- happy path


def test_sync_calls_collect_once_and_normalizes(client, monkeypatch):
    """Stub Okta's collect() to return a known shape; assert it was
    called exactly once and the unified asset hit save_asset()."""
    _save_okta_via_connect(client, monkeypatch)
    calls = {"collect": 0, "normalize": 0}
    fake_raw = {
        "users":  [{"id": "u1", "status": "ACTIVE"},
                    {"id": "u2", "status": "ACTIVE"},
                    {"id": "u3", "status": "DEPROVISIONED"}],
        "groups": [{"profile": {"name": "Admins"}, "id": "g1"},
                    {"profile": {"name": "Users"},  "id": "g2"}],
        "policies": [],
    }
    from safecadence.platform.adapters import identity_adapters as IA

    def fake_collect(self, asset_id):
        calls["collect"] += 1
        assert asset_id.startswith("okta:")
        return fake_raw

    real_normalize = IA.OktaAdapter.normalize
    def counting_normalize(self, asset_id, raw):
        calls["normalize"] += 1
        return real_normalize(self, asset_id, raw)

    monkeypatch.setattr(IA.OktaAdapter, "collect", fake_collect)
    monkeypatch.setattr(IA.OktaAdapter, "normalize", counting_normalize)

    r = client.post("/api/identity/sync/okta", headers=auth(client))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True
    assert body["system"] == "okta"
    assert body["target"] == "acme.okta.com"
    assert body["counts"]["users"] == 3
    assert body["counts"]["groups"] == 2
    assert body["asset_id"] == "okta:acme.okta.com"

    assert calls["collect"] == 1, "collect() must be called exactly once"
    assert calls["normalize"] == 1, "normalize() must be called exactly once"


def test_sync_persists_asset_into_list_assets(client, monkeypatch, tmp_path):
    """The asset lands in list_assets() so downstream surfaces can
    read it. This is the link between sync and /access /paths /findings."""
    _save_okta_via_connect(client, monkeypatch)
    from safecadence.platform.adapters import identity_adapters as IA
    monkeypatch.setattr(IA.OktaAdapter, "collect",
                          lambda self, aid: {"users": [], "groups": [], "policies": []})

    r = client.post("/api/identity/sync/okta", headers=auth(client))
    assert r.status_code == 200, r.text

    from safecadence.server.platform_api import list_assets
    assets = list_assets()
    matching = [a for a in assets
                 if (a.get("identity") or {}).get("asset_id")
                     == "okta:acme.okta.com"]
    assert len(matching) == 1, (
        "sync must produce exactly one UnifiedAsset per tenant"
    )


def test_sync_marks_vault_last_synced(client, monkeypatch):
    """After a successful sync, the vault record's last_synced_at is
    populated so the connector strip can render an honest timestamp."""
    _save_okta_via_connect(client, monkeypatch)
    from safecadence.platform.adapters import identity_adapters as IA
    monkeypatch.setattr(IA.OktaAdapter, "collect",
                          lambda self, aid: {"users": [], "groups": []})

    from safecadence.identity.vault import IdentityVault
    before = IdentityVault().load_creds("okta")
    assert before.last_synced_at == ""

    r = client.post("/api/identity/sync/okta", headers=auth(client))
    assert r.status_code == 200, r.text

    after = IdentityVault().load_creds("okta")
    assert after.last_synced_at, (
        "vault.last_synced_at must be set after a successful sync"
    )


def test_sync_collect_failure_returns_502_and_no_asset_written(
        client, monkeypatch):
    """If collect() raises, no UnifiedAsset gets written and the
    operator sees a clear 502. Defends against partial-state writes."""
    _save_okta_via_connect(client, monkeypatch)
    from safecadence.platform.adapters import identity_adapters as IA

    def boom(self, aid):
        raise RuntimeError("simulated 401 from Okta")

    monkeypatch.setattr(IA.OktaAdapter, "collect", boom)

    r = client.post("/api/identity/sync/okta", headers=auth(client))
    assert r.status_code == 502, r.text
    assert "simulated 401" in r.json()["detail"]

    from safecadence.server.platform_api import list_assets
    matching = [a for a in list_assets()
                 if (a.get("identity") or {}).get("asset_id")
                     == "okta:acme.okta.com"]
    assert matching == [], "no asset may be written when collect failed"


def test_sync_collect_returns_error_dict_returns_502(client, monkeypatch):
    """Some adapters return {error: ...} instead of raising. Treat
    that as a sync failure too — same 502."""
    _save_okta_via_connect(client, monkeypatch)
    from safecadence.platform.adapters import identity_adapters as IA
    monkeypatch.setattr(
        IA.OktaAdapter, "collect",
        lambda self, aid: {"error": "rate-limited"},
    )
    r = client.post("/api/identity/sync/okta", headers=auth(client))
    assert r.status_code == 502


def test_sync_requires_writer_role(client):
    r = client.post("/api/identity/sync/okta")    # no bearer
    assert r.status_code in (401, 403)
