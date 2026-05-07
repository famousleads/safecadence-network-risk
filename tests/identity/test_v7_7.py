"""
v7.7 — REST API + transactional apply + findings + remediation +
evidence pack + UI page render.

The REST endpoint tests use FastAPI's TestClient. The transactional
test injects failure on the second target to verify rollback.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict

import pytest

from safecadence.identity.findings import scan_findings, remediate_path
from safecadence.identity.transactional import apply_all
from safecadence.identity.evidence_pack import build_pack
from safecadence.identity.ir import validate_ir


# ---------------------------------------------------------------- findings


def test_findings_detect_stale_nhi():
    assets = [{
        "nhi": {
            "nhi_id": "build-bot",
            "subtype": "service_account",
            "provider": "okta",
            "last_used_at": "2025-01-01T00:00:00+00:00",
        },
    }]
    fs = scan_findings(assets, stale_days=90,
                        now=time.time())
    stale = [f for f in fs if f.kind == "stale_nhi"]
    assert stale, "expected stale_nhi finding"
    assert stale[0].principal == "build-bot"
    assert "stale" in stale[0].suggested_ir["intent"].lower() or \
           "deactivate" in stale[0].suggested_ir["intent"].lower()


def test_findings_detect_no_mfa_tenant():
    assets = [{
        "identity_block": {
            "provider": "okta", "tenant_id": "acme",
            "user_count": 50, "mfa_enrolled": False,
        },
    }]
    fs = scan_findings(assets)
    no_mfa = [f for f in fs if f.kind == "no_mfa"]
    assert no_mfa
    assert no_mfa[0].severity == "high"


def test_findings_detect_over_privileged():
    assets = [{
        "identity_block": {
            "provider": "okta",
            "group_memberships": {"alice@x": ["g1", "g2", "g3", "g4", "g5", "g6"]},
        },
    }]
    fs = scan_findings(assets, over_priv_threshold=5)
    op = [f for f in fs if f.kind == "over_privileged"]
    assert op
    assert "alice@x" in op[0].principal


def test_findings_detect_orphan_service_account():
    assets = [{
        "nhi": {
            "nhi_id": "old-sa",
            "subtype": "service_account",
            "owner_principal": "departed@x",
            "provider": "okta",
        },
    }]
    fs = scan_findings(assets)
    orph = [f for f in fs if f.kind == "orphan_service_account"]
    assert orph
    assert orph[0].severity == "critical"


# ---------------------------------------------------------------- remediation


def test_remediate_path_from_chain_summary():
    ir = remediate_path({
        "chain_summary": "alice@x → BuildEngineers → build-bot → AdminRole → prod-db"
    })
    assert ir.effect == "deny"
    assert "alice@x" in ir.subjects.principals
    assert "prod-db" in ir.resources.asset_ids


def test_remediate_path_from_edges():
    ir = remediate_path({
        "edges": [
            {"src": "alice", "dst": "Admins", "kind": "member_of"},
            {"src": "Admins", "dst": "prod-db", "kind": "has_credential_to"},
        ]
    })
    assert ir.effect == "deny"
    assert "alice" in ir.subjects.principals
    assert "prod-db" in ir.resources.asset_ids


def test_remediate_path_rejects_short_input():
    with pytest.raises(ValueError):
        remediate_path({"chain_summary": "alice"})
    with pytest.raises(ValueError):
        remediate_path({})


# ---------------------------------------------------------------- transactional


class _FakeAdapter:
    """Adapter stub for testing apply_all without touching real systems."""
    def __init__(self, name, *, fail=False):
        self.name = name
        self.fail = fail
        self.committed = []
        self.rolled_back = False

    def apply_policy(self, ir, *, dry_run=True, **_):
        if self.fail and not dry_run:
            return {"target": self.name, "dry_run": dry_run,
                     "operations": [], "diff": "",
                     "committed_ids": [], "warnings": [],
                     "error": "synthetic failure"}
        ids = [f"{self.name}-001"] if not dry_run else []
        self.committed = ids
        return {"target": self.name, "dry_run": dry_run,
                 "operations": [{"op_kind": "x", "summary": self.name}],
                 "diff": f"# {self.name}",
                 "committed_ids": ids, "warnings": [], "error": None}

    def _rollback(self, committed_ids):
        self.rolled_back = True
        return {"ok": True, "rolled_back_ids": list(committed_ids)}


def _ir():
    return validate_ir({
        "intent": "x", "effect": "deny", "actions": ["ssh"],
        "subjects": {"groups": ["g"]}, "targets": ["okta", "ise"],
    })


def test_apply_all_dry_run_returns_preview_ok():
    adapters = {"okta": _FakeAdapter("okta"), "ise": _FakeAdapter("ise")}
    r = apply_all(_ir(), adapters, dry_run=True)
    assert r["status"] == "preview_ok"
    assert r["per_target"]["okta"]["error"] is None
    assert r["per_target"]["ise"]["error"] is None


def _commit_token_for(targets):
    """Helper: dry-run the transactional layer to mint the multi-target
    confirm_token v9.33 #2 requires for the commit path."""
    fake = {t: _FakeAdapter(t) for t in targets}
    return apply_all(_ir(), fake, dry_run=True,
                       actor="t")["confirm_token"]


def test_apply_all_commit_all_succeed():
    adapters = {"okta": _FakeAdapter("okta"), "ise": _FakeAdapter("ise")}
    token = _commit_token_for(["okta", "ise"])
    r = apply_all(_ir(), adapters, dry_run=False,
                   actor="t", confirm_token=token)
    assert r["status"] == "all_committed"
    assert r["per_target"]["okta"]["committed_ids"] == ["okta-001"]
    assert r["per_target"]["ise"]["committed_ids"] == ["ise-001"]


def test_apply_all_rollback_on_second_failure():
    okta = _FakeAdapter("okta")
    ise = _FakeAdapter("ise", fail=True)
    token = _commit_token_for(["okta", "ise"])
    r = apply_all(_ir(), {"okta": okta, "ise": ise},
                   dry_run=False, actor="t", confirm_token=token,
                   on_failure="rollback")
    assert r["status"] == "rolled_back"
    assert r["failure"]["target"] == "ise"
    assert okta.rolled_back is True       # first target was rolled back


def test_apply_all_continue_on_failure_keeps_going():
    okta = _FakeAdapter("okta", fail=True)
    ise = _FakeAdapter("ise")
    token = _commit_token_for(["okta", "ise"])
    r = apply_all(_ir(), {"okta": okta, "ise": ise},
                   dry_run=False, actor="t", confirm_token=token,
                   on_failure="continue")
    assert r["status"] == "partial"
    assert r["per_target"]["okta"]["error"] == "synthetic failure"
    assert r["per_target"]["ise"]["committed_ids"] == ["ise-001"]


# ---------------------------------------------------------------- evidence


def test_evidence_pack_emits_all_three_formats():
    assets = [
        {"identity_block": {"provider": "okta", "tenant_id": "acme",
                              "user_count": 50, "mfa_enrolled": True}},
        {"identity": {"asset_id": "prod-db", "criticality": "crown-jewel"}},
    ]
    pack = build_pack(assets, requested_by="test")
    assert "summary" in pack["json"]
    assert "providers_connected" in pack["json"]["summary"]
    assert isinstance(pack["csv_text"], str)
    assert pack["csv_text"].startswith("section,id,severity,")
    assert isinstance(pack["pdf_bytes"], bytes)
    assert pack["pdf_bytes"].startswith(b"%PDF")


def test_evidence_pack_summary_counts_match():
    assets = [{
        "identity_block": {"provider": "okta", "user_count": 1,
                            "mfa_enrolled": False},
    }]
    pack = build_pack(assets, requested_by="t")
    assert pack["json"]["summary"]["mfa_noncompliant_tenants"] == 1
    soc = pack["json"]["frameworks"]["soc2_cc6"]
    assert soc["CC6.1 — Logical access provisioned per role"]["status"] != "compliant"


# ---------------------------------------------------------------- REST API


@pytest.fixture
def client(tmp_path, monkeypatch):
    """Boot a fresh FastAPI app with a clean tenant. Returns TestClient
    + a function that yields an authed bearer token."""
    monkeypatch.setenv("SC_USERS_FILE", str(tmp_path / "users.yaml"))
    monkeypatch.setenv("SC_JIT_STORE", str(tmp_path / "jit.json"))
    # Isolate the platform store
    monkeypatch.setenv("SAFECADENCE_HOME", str(tmp_path / ".safecadence"))

    from fastapi.testclient import TestClient
    from safecadence.server import create_app
    app = create_app(users_file=str(tmp_path / "users.yaml"),
                       db_url=f"sqlite:///{tmp_path}/sc.db",
                       jwt_secret="test-secret-do-not-use-in-prod")
    return TestClient(app)


def _auth(client):
    """Bootstrap admin user is created on first /api/login. Returns token."""
    # The default users file gets bootstrapped by load_users(); first login
    # is admin / a generated default we can read out.
    import yaml
    from pathlib import Path
    users_path = Path(os.environ["SC_USERS_FILE"])
    if users_path.exists():
        # Find admin password from the bootstrap. If it's hashed we have to
        # reset; for tests, use the admin reset path.
        pass

    # Reset admin password to a known value
    from safecadence.server.auth import hash_password
    users_path.parent.mkdir(parents=True, exist_ok=True)
    users_path.write_text(yaml.safe_dump({
        "tenants": {"default": {"users": [
            {"username": "admin",
              "password_hash": hash_password("test-pw"),
              "roles": ["admin"]}
        ]}}
    }), encoding="utf-8")
    r = client.post("/api/login",
                     data={"username": "admin", "password": "test-pw"})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def test_identity_translate_form_endpoint(client):
    token = _auth(client)
    r = client.post("/api/identity/translate",
                     headers={"Authorization": f"Bearer {token}"},
                     json={"form": True, "intent": "x",
                           "groups": ["G"], "actions": ["ssh"],
                           "environments": ["prod"], "effect": "deny",
                           "require_mfa": True})
    assert r.status_code == 200, r.text
    ir = r.json()["ir"]
    assert ir["effect"] == "deny"
    assert ir["subjects"]["groups"] == ["G"]


def test_identity_preview_endpoint(client):
    token = _auth(client)
    h = {"Authorization": f"Bearer {token}"}
    ir = client.post("/api/identity/translate", headers=h,
                      json={"form": True, "intent": "x",
                            "groups": ["G"], "actions": ["ssh"],
                            "environments": ["prod"], "effect": "deny"}
                      ).json()["ir"]
    r = client.post("/api/identity/preview", headers=h, json={"ir": ir})
    assert r.status_code == 200
    assert "operations" in r.json()
    assert any(o["target"] == "okta" for o in r.json()["operations"])


def test_identity_apply_dry_run_endpoint(client):
    token = _auth(client)
    h = {"Authorization": f"Bearer {token}"}
    ir = client.post("/api/identity/translate", headers=h,
                      json={"form": True, "intent": "x",
                            "groups": ["G"], "actions": ["ssh"],
                            "environments": ["prod"], "effect": "deny"}
                      ).json()["ir"]
    r = client.post("/api/identity/apply", headers=h,
                     json={"ir": ir, "target": "okta", "dry_run": True})
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["dry_run"] is True
    assert j["error"] is None


def test_identity_jit_endpoints(client):
    token = _auth(client)
    h = {"Authorization": f"Bearer {token}"}
    g = client.post("/api/identity/jit/grant", headers=h, json={
        "principal": "alice@x", "action": "ssh", "resource": "srv-1",
        "duration_seconds": 60, "target": "okta",
    })
    assert g.status_code == 200, g.text
    grant_id = g.json()["grant_id"]

    listed = client.get("/api/identity/jit/list", headers=h)
    assert listed.status_code == 200
    assert any(g["grant_id"] == grant_id for g in listed.json()["grants"])

    rev = client.post(f"/api/identity/jit/revoke/{grant_id}", headers=h)
    assert rev.status_code == 200
    assert rev.json()["status"] == "revoked"


def test_identity_findings_endpoint(client):
    token = _auth(client)
    h = {"Authorization": f"Bearer {token}"}
    r = client.get("/api/identity/findings", headers=h)
    assert r.status_code == 200
    assert "findings" in r.json()


def test_identity_evidence_pack_endpoint_json(client):
    token = _auth(client)
    h = {"Authorization": f"Bearer {token}"}
    r = client.get("/api/identity/evidence-pack?format=json", headers=h)
    assert r.status_code == 200
    j = r.json()
    assert "summary" in j
    assert "frameworks" in j


def test_identity_ui_page_renders(client):
    token = _auth(client)
    r = client.get("/identity")
    assert r.status_code == 200
    assert "SafeCadence" in r.text
    assert "/api/identity/translate" in r.text  # JS calls it
    assert "/api/identity/jit/grant" in r.text
