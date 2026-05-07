"""
v9.35.1 — End-to-end smoke test.

One test that walks the full v9.34/v9.35 product loop. If anything in
the chain regresses, this test fails before users notice. The flow:

  1. Connect a fake identity system (test_only)
  2. Connect again with mode=save (vault writes)
  3. Sync — collect+normalize+save_asset
  4. /access — verdict against the synced data
  5. /findings — surfaces are reachable
  6. NHI — register + attest + rotate + list
  7. Builder — pack-driven plan resolution
  8. Workflow — submit → review → approve (rollback plan persisted)
  9. Rollback plan — fetched + contains expected commands

Stubbed: adapter.test_connection and adapter.collect (we don't have
a real Okta tenant). Everything else uses the real code path.
"""

from __future__ import annotations

import pytest
import yaml

pytest.importorskip("fastapi")
pytest.importorskip("cryptography")


@pytest.fixture
def client(tmp_path, monkeypatch):
    """Boot a clean FastAPI app under a fresh tenant + isolated stores."""
    monkeypatch.setenv("SAFECADENCE_HOME", str(tmp_path))
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_PLATFORM_STORE",
                        str(tmp_path / "platform_assets"))
    monkeypatch.setenv("SC_USERS_FILE", str(tmp_path / "users.yaml"))
    monkeypatch.setenv("SC_JIT_STORE", str(tmp_path / "jit.json"))
    monkeypatch.setenv("SC_INTEL_HOME", str(tmp_path / "intel"))
    monkeypatch.setenv("SC_JWT_SECRET",
                        "test-secret-do-not-use-in-prod")
    monkeypatch.setenv("SC_AI_DISABLED", "1")
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


def test_e2e_full_product_loop(client, monkeypatch):
    """The headline integration test for v9.35.1.

    Walks every stage operators touch on a fresh install. Each
    assertion below pins one stage of the chain.
    """
    # ---- Stage 1: stub Okta adapter ---------------------------------
    from safecadence.platform.adapters import identity_adapters as IA
    monkeypatch.setattr(IA.OktaAdapter, "test_connection",
                          lambda self: {"ok": True, "error": ""})
    fake_raw = {
        "users": [{"id": "alice", "status": "ACTIVE"},
                   {"id": "bob",   "status": "ACTIVE"}],
        "groups": [{"id": "g-admins", "profile": {"name": "Admins"}}],
        "policies": [],
    }
    monkeypatch.setattr(IA.OktaAdapter, "collect",
                          lambda self, aid: fake_raw)

    # ---- Stage 2: connect (test_only first, then save) --------------
    r = client.post("/api/identity/connect", headers=auth(client),
                     json={"system": "okta", "target": "e2e.okta.com",
                            "credentials": {"api_token": "tok-e2e"},
                            "mode": "test_only"})
    assert r.status_code == 200 and r.json()["ok"] is True
    assert r.json()["saved"] is False, "test_only must not persist"

    r = client.post("/api/identity/connect", headers=auth(client),
                     json={"system": "okta", "target": "e2e.okta.com",
                            "credentials": {"api_token": "tok-e2e"},
                            "mode": "save"})
    assert r.status_code == 200 and r.json()["saved"] is True

    # ---- Stage 3: sync ----------------------------------------------
    r = client.post("/api/identity/sync/okta", headers=auth(client))
    assert r.status_code == 200 and r.json()["ok"] is True
    assert r.json()["counts"]["users"] == 2

    # Vault status reflects the vault record (not env fallback).
    r = client.get("/api/identity/connectors-status",
                    headers=auth(client))
    okta = next(s for s in r.json()["systems"] if s["system"] == "okta")
    assert okta["configured"] is True
    assert okta["source"] == "vault"
    assert okta["last_synced_at"]

    # ---- Stage 4: /access query -------------------------------------
    r = client.get("/api/identity/who-can", headers=auth(client),
                    params={"action": "ssh",
                            "resource": "prod-db",
                            "principal": "alice"})
    assert r.status_code == 200
    assert "allowed" in r.json()
    assert "systems_consulted" in r.json()

    # ---- Stage 5: surface endpoints respond -------------------------
    for path in ("/api/identity/findings",
                  "/api/identity/attack-paths"):
        assert client.get(path, headers=auth(client)).status_code == 200

    # ---- Stage 6: NHI lifecycle -------------------------------------
    nhi_id = client.post("/api/identity/nhi", headers=auth(client),
                          json={"name": "e2e-bot",
                                 "owner": "alice@acme",
                                 "rotation_policy_days": 90}
                         ).json()["nhi_id"]
    assert nhi_id.startswith("nhi-")
    assert client.post(f"/api/identity/nhi/{nhi_id}/attest",
                        headers=auth(client)).status_code == 200
    assert client.post(f"/api/identity/nhi/{nhi_id}/rotate",
                        headers=auth(client)).status_code == 200
    listed = client.get("/api/identity/nhi", headers=auth(client)).json()
    assert any(n["nhi_id"] == nhi_id for n in listed["nhis"])

    # ---- Stage 7: builder resolves a known intent -------------------
    from safecadence.execution.builder import build_plan
    plan = build_plan("check version on cisco devices")
    assert plan.matched_packs, (
        "builder must match a pack for a well-known intent — if this "
        "fails the offline pack table regressed"
    )

    # ---- Stage 8: workflow — submit, review, approve ----------------
    from safecadence.execution import store as exec_store, workflow
    from safecadence.execution.schema import (
        CommandJob, CommandMode, JobStatus, RiskLevel,
    )
    job = CommandJob(
        job_id="e2e-job-001", name="E2E test job",
        description="End-to-end smoke",
        mode=CommandMode.CONFIG, risk=RiskLevel.MEDIUM,
        status=JobStatus.DRAFT, target_asset_ids=["e2e-asset-1"],
        inline_commands={
            "cisco_ios": ["ip route 10.99.0.0 255.255.0.0 1.2.3.4",
                            "logging host 10.0.0.5"],
        },
    )
    exec_store.save_job(job)
    # Submit for review.
    job.status = JobStatus.REVIEW
    exec_store.save_job(job)
    workflow.request_approval(job.job_id, requested_by="alice")
    # Approve — generates rollback plan. Use SUPER_ADMIN since the
    # MEDIUM-risk approval requires the higher tier and we want to
    # exercise the role gate as a real operator would.
    workflow.approve(job.job_id, approver="bob",
                       role="super_admin")
    job_after = exec_store.get_job(job.job_id)
    assert job_after.status == JobStatus.APPROVED
    assert job_after.rollback_plan_id, (
        "approve() must persist a rollback plan id on the job"
    )

    # ---- Stage 9: rollback plan content -----------------------------
    plan = exec_store.get_rollback(job_after.rollback_plan_id)
    assert plan is not None
    rb = plan.asset_rollbacks.get("cisco_ios", [])
    # Inverse of "ip route 10.99.0.0 255.255.0.0 1.2.3.4" must be
    # "no ip route 10.99.0.0 255.255.0.0 1.2.3.4" (preserving the
    # remainder of the line — the v9.35 #2 fix).
    assert any("no ip route 10.99.0.0" in c for c in rb), (
        f"rollback plan must invert ip route preserving the remainder; "
        f"got {rb!r}"
    )
    assert any("no logging host" in c for c in rb), (
        "rollback plan must invert logging host"
    )

    # API surface for rollback plan.
    r = client.get(f"/api/execute/jobs/{job.job_id}/rollback-plan",
                    headers=auth(client))
    assert r.status_code == 200
    assert r.json()["plan_id"] == plan.plan_id
    assert "cisco_ios" in r.json()["asset_rollbacks"]


def test_e2e_demo_seed_populates_every_surface(client, monkeypatch):
    """v9.35.1 #1 sanity check: after `safecadence demo` runs, every
    surface has content. Without this, a buyer evaluating the product
    sees empty cards everywhere on first run."""
    from safecadence import demo
    out = demo.load_demo_fleet()
    # Identity vault — 3 connectors saved.
    assert sum(1 for v in out["identity_seeded"].values() if v) >= 2
    # NHIs — at least 6 demo records.
    assert out["nhi_seeded"]["created"] >= 6
    # Execution jobs — at least 6 in the lifecycle.
    assert out["execution_seeded"]["jobs"] >= 6
    # Compliance — risk register / exceptions populated.
    assert out["compliance_seeded"]

    # Now hit the surfaces and confirm they return non-empty.
    r = client.get("/api/identity/connectors-status", headers=auth(client))
    configured = sum(1 for s in r.json()["systems"] if s["configured"])
    assert configured >= 2

    r = client.get("/api/identity/nhi", headers=auth(client))
    assert len(r.json()["nhis"]) >= 6

    r = client.get("/api/identity/nhi/findings", headers=auth(client))
    findings = r.json()["findings"]
    # Demo includes at least one stale NHI (220 days unused) so the
    # finder should produce at least one finding.
    assert findings, "demo should seed at least one stale-NHI finding"
