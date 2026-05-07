"""
v9.34 #4 — End-to-end integration: connect → sync → downstream surfaces.

This is the test that proves the v9.34 trust + value loop holds end
to end. After a successful connect+sync against a stubbed adapter:

  * The vault holds creds + an updated last_synced_at
  * list_assets() returns the new identity tenant snapshot
  * /api/identity/connectors-status shows source=vault and the
    target from the vault record (not the env-var fallback)
  * /api/identity/findings, /attack-paths, /who-can all respond 200
    against the synced data — the existing modules read from
    list_assets, so this verifies wiring without re-testing each
    module in depth.

The test substitutes Okta's network calls (test_connection + collect)
with stubs so it runs offline. The CODE PATH is real — same adapter,
same compose pipeline — so a regression in any of (vault, sync,
downstream surface) would fail here.
"""

from __future__ import annotations

import pytest
import yaml

pytest.importorskip("fastapi")
pytest.importorskip("cryptography")


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFECADENCE_HOME", str(tmp_path))
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
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


def test_full_connect_sync_surfaces_wiring(client, monkeypatch):
    """The headline integration test for v9.34. Mirrors what an
    operator does on first run after credentials are in hand."""
    from safecadence.platform.adapters import identity_adapters as IA

    # Stub Okta's two network methods. Real adapter, real pipeline,
    # only the wire is faked.
    monkeypatch.setattr(IA.OktaAdapter, "test_connection",
                          lambda self: {"ok": True, "error": ""})
    fake_raw = {
        "users": [{"id": "alice", "status": "ACTIVE"},
                   {"id": "bob",   "status": "ACTIVE"},
                   {"id": "carol", "status": "DEPROVISIONED"}],
        "groups": [{"id": "g1", "profile": {"name": "Admins"}},
                    {"id": "g2", "profile": {"name": "Engineers"}}],
        "policies": [],
    }
    monkeypatch.setattr(IA.OktaAdapter, "collect",
                          lambda self, aid: fake_raw)

    # 1. Connect with mode=save (which test+saves).
    r = client.post("/api/identity/connect", headers=auth(client),
                     json={"system": "okta", "target": "acme.okta.com",
                            "credentials": {"api_token": "tok-INT"},
                            "mode": "save"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True and body["saved"] is True

    # 2. Sync. Endpoint loads from vault, calls collect+normalize+save.
    r = client.post("/api/identity/sync/okta", headers=auth(client))
    assert r.status_code == 200, r.text
    sync = r.json()
    assert sync["ok"] is True
    assert sync["counts"]["users"] == 3
    assert sync["counts"]["groups"] == 2
    assert sync["asset_id"] == "okta:acme.okta.com"

    # 3. Connector status reflects the vault state.
    r = client.get("/api/identity/connectors-status",
                    headers=auth(client))
    assert r.status_code == 200
    okta = next(s for s in r.json()["systems"] if s["system"] == "okta")
    assert okta["configured"] is True
    assert okta["source"] == "vault"
    assert okta["target"] == "acme.okta.com"
    assert okta["last_test_at"]
    assert okta["last_synced_at"], (
        "After sync, last_synced_at must be populated so the connector "
        "strip shows 'last synced 2s ago'"
    )

    # 4. The asset is in list_assets — every downstream surface reads
    # from there. Asserting count > 0 proves the wire from sync to the
    # surfaces is connected.
    from safecadence.server.platform_api import list_assets
    assets = list_assets()
    matching = [a for a in assets
                 if (a.get("identity") or {}).get("asset_id")
                     == "okta:acme.okta.com"]
    assert len(matching) == 1

    # 5. Downstream surfaces respond 200 against the synced data.
    # We don't assert exact contents because each surface has its own
    # contract test elsewhere — what we assert here is "the wiring
    # didn't break".
    for path in ("/api/identity/findings",
                  "/api/identity/attack-paths"):
        r = client.get(path, headers=auth(client))
        assert r.status_code == 200, f"{path} broke: {r.text[:200]}"

    # /api/identity/who-can needs query params — exercise the wire.
    r = client.get("/api/identity/who-can", headers=auth(client),
                    params={"action": "ssh",
                            "resource": "prod-db",
                            "principal": "alice"})
    assert r.status_code == 200
    body = r.json()
    # Shape pin only — the resolver may say allowed=false because we
    # didn't seed any rules, that's fine.
    assert "allowed" in body
    assert "systems_consulted" in body


def test_disconnect_breaks_status_back_to_unconfigured(client, monkeypatch):
    """Connecting then disconnecting should flip the strip back to
    "not configured". Defends against a stale read on the status row
    after a disconnect."""
    from safecadence.platform.adapters import identity_adapters as IA
    monkeypatch.setattr(IA.OktaAdapter, "test_connection",
                          lambda self: {"ok": True, "error": ""})
    client.post("/api/identity/connect", headers=auth(client),
                 json={"system": "okta", "target": "acme.okta.com",
                        "credentials": {"api_token": "x"},
                        "mode": "save"})
    client.post("/api/identity/disconnect/okta", headers=auth(client))

    r = client.get("/api/identity/connectors-status",
                    headers=auth(client))
    okta = next(s for s in r.json()["systems"] if s["system"] == "okta")
    assert okta["configured"] is False, (
        "After disconnect, status must report not-configured even if "
        "env-var fallback isn't set"
    )
    assert okta["source"] in ("env", "none")
