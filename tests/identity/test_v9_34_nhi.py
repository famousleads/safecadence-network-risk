"""
v9.34 #5 — NHI store + lifecycle + HTTP endpoints.

Pinned trust + lifecycle properties:
  * Stale-finder fires for NHIs unused beyond stale_unused_days.
  * Rotation-overdue fires when last_rotated_at + rotation_policy_days
    is in the past.
  * Deprecated NHIs are excluded from findings (operator already
    flagged them for removal).
  * Endpoints are writer-gated for state-changing actions.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
import yaml

pytest.importorskip("fastapi")
pytest.importorskip("cryptography")


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SAFECADENCE_HOME", str(tmp_path))
    yield


# --------------------------------------------------------- module tests


def test_register_and_list_round_trip():
    from safecadence.identity import nhi_store
    rec = nhi_store.register(name="payroll-svc", provider="aws",
                                owner="alice@acme.com",
                                rotation_policy_days=90)
    assert rec.nhi_id.startswith("nhi-")
    assert rec.name == "payroll-svc"
    listed = nhi_store.list_all()
    assert len(listed) == 1
    assert listed[0].nhi_id == rec.nhi_id


def test_register_rejects_empty_name():
    from safecadence.identity import nhi_store
    with pytest.raises(ValueError, match="name is required"):
        nhi_store.register(name="")


def test_attest_and_rotate_update_timestamps():
    from safecadence.identity import nhi_store
    rec = nhi_store.register(name="ci-deploy", provider="github")
    a = nhi_store.attest(rec.nhi_id, by="alice@acme.com")
    assert a.attested_at and a.attested_by == "alice@acme.com"
    r = nhi_store.rotate(rec.nhi_id)
    assert r.last_rotated_at


def test_attest_unknown_id_raises():
    from safecadence.identity import nhi_store
    with pytest.raises(KeyError):
        nhi_store.attest("nhi-doesnotexist", by="alice")


def test_stale_finder_emits_for_unused_nhi():
    from safecadence.identity import nhi_store
    rec = nhi_store.register(name="legacy-importer")
    # Backdate created_at so the "never used" path fires.
    saved = nhi_store.get(rec.nhi_id)
    saved.created_at = (
        datetime.now(timezone.utc) - timedelta(days=181)
    ).isoformat()
    nhi_store._save(saved)

    findings = nhi_store.stale_findings(stale_unused_days=90)
    matching = [f for f in findings
                 if f["principal"] == rec.nhi_id
                 and f["kind"] == "nhi_stale"]
    assert len(matching) == 1
    assert matching[0]["severity"] == "high"   # 181 days > 180


def test_stale_finder_skips_deprecated():
    from safecadence.identity import nhi_store
    rec = nhi_store.register(name="x")
    saved = nhi_store.get(rec.nhi_id)
    saved.created_at = (
        datetime.now(timezone.utc) - timedelta(days=200)
    ).isoformat()
    nhi_store._save(saved)
    nhi_store.deprecate(rec.nhi_id)

    findings = nhi_store.stale_findings(stale_unused_days=90)
    assert all(f["principal"] != rec.nhi_id for f in findings), (
        "deprecated NHIs must NOT appear in stale findings"
    )


def test_rotation_overdue_emits_finding():
    from safecadence.identity import nhi_store
    rec = nhi_store.register(name="api-key", rotation_policy_days=30)
    # Mark as rotated 60 days ago (30 days overdue).
    saved = nhi_store.get(rec.nhi_id)
    saved.last_rotated_at = (
        datetime.now(timezone.utc) - timedelta(days=60)
    ).isoformat()
    saved.last_used_at = datetime.now(timezone.utc).isoformat()
    nhi_store._save(saved)

    findings = nhi_store.stale_findings(stale_unused_days=90)
    rotation = [f for f in findings
                 if f["kind"] == "nhi_rotation_overdue"
                 and f["principal"] == rec.nhi_id]
    assert len(rotation) == 1
    assert rotation[0]["evidence"]["overdue_days"] >= 29


# ---------------------------------------------------------- HTTP tests


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SAFECADENCE_HOME", str(tmp_path))
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
    c._sc_hdr = {"Authorization": f"Bearer {r.json()['access_token']}"}
    return c


def auth(c):
    return c._sc_hdr


def test_nhi_create_and_list(client):
    r = client.post("/api/identity/nhi", headers=auth(client),
                     json={"name": "payroll-svc",
                            "owner": "alice@acme.com",
                            "rotation_policy_days": 90})
    assert r.status_code == 200
    nhi_id = r.json()["nhi_id"]
    assert nhi_id.startswith("nhi-")

    r = client.get("/api/identity/nhi", headers=auth(client))
    assert r.status_code == 200
    assert any(n["nhi_id"] == nhi_id for n in r.json()["nhis"])


def test_nhi_lifecycle_endpoints(client):
    nhi_id = client.post("/api/identity/nhi", headers=auth(client),
                          json={"name": "ci-deploy"}).json()["nhi_id"]

    r = client.post(f"/api/identity/nhi/{nhi_id}/attest",
                     headers=auth(client))
    assert r.status_code == 200
    assert r.json()["attested_by"] == "alice"

    r = client.post(f"/api/identity/nhi/{nhi_id}/rotate",
                     headers=auth(client))
    assert r.status_code == 200
    assert r.json()["last_rotated_at"]

    r = client.post(f"/api/identity/nhi/{nhi_id}/deprecate",
                     headers=auth(client))
    assert r.status_code == 200
    assert r.json()["deprecated"] is True


def test_nhi_create_requires_writer(client):
    r = client.post("/api/identity/nhi", json={"name": "x"})
    assert r.status_code in (401, 403)


def test_nhi_findings_endpoint(client):
    """Wire-up test: the endpoint exists and returns the shape the
    UI expects, even when nothing's stale."""
    r = client.get("/api/identity/nhi/findings", headers=auth(client))
    assert r.status_code == 200
    assert "findings" in r.json()
