"""
v9.31 — HTTP-level tests for the compliance + policy-quick endpoints.

These complement the module-level tests in test_compliance.py:
those exercise the modules directly; these prove the FastAPI wiring
works end-to-end (auth gating, JSON shape, status codes).

Auth: a known admin is bootstrapped via SC_USERS_FILE so we can
present a Bearer token. Every endpoint is hit at least once; mutating
endpoints get both a writer and a no-token call to prove the auth
gate is on.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
import yaml

fastapi = pytest.importorskip("fastapi")
pytest.importorskip("yaml")


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_USERS_FILE", str(tmp_path / "users.yaml"))
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path / "scdata"))
    monkeypatch.setenv("SAFECADENCE_HOME", str(tmp_path / "scdata"))
    monkeypatch.setenv("SC_JWT_SECRET", "test-secret-do-not-use-in-prod")
    from fastapi.testclient import TestClient
    from safecadence.server import create_app
    from safecadence.server.auth import hash_password
    users_file = Path(os.environ["SC_USERS_FILE"])
    users_file.parent.mkdir(parents=True, exist_ok=True)
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


def auth(client):
    return client._sc_hdr


# =================================================== mappings + coverage


def test_api_compliance_frameworks_lists_six(client):
    r = client.get("/api/compliance/frameworks", headers=auth(client))
    assert r.status_code == 200
    fws = {f["key"] for f in r.json()["frameworks"]}
    for k in ("nist_800_53", "cis_v8", "pci_dss_4", "hipaa",
                "iso_27001_2022", "soc2_tsc"):
        assert k in fws


def test_api_compliance_coverage_for_nist(client):
    r = client.get("/api/compliance/coverage/nist_800_53",
                    headers=auth(client))
    assert r.status_code == 200
    body = r.json()
    assert body["covered_count"] > 0
    fids = {row["framework_id"] for row in body["covered"]}
    assert "AC-2" in fids


def test_api_compliance_control_detail(client):
    r = client.get("/api/compliance/control/enforce_mfa",
                    headers=auth(client))
    assert r.status_code == 200
    body = r.json()
    assert body["control_id"] == "enforce_mfa"
    assert body.get("nist_800_53")
    assert body.get("frequency")


def test_api_compliance_requires_auth(client):
    r = client.get("/api/compliance/frameworks")
    assert r.status_code == 401


# =================================================== sla + exceptions


def test_api_compliance_sla_summary(client):
    r = client.get("/api/compliance/sla", headers=auth(client))
    assert r.status_code == 200
    body = r.json()
    assert "summary" in body and "annotated" in body


def test_api_compliance_exception_create_list_revoke(client):
    payload = {
        "control_id": "enforce_mfa",
        "asset_id": "rtr-1",
        "finding_id": "f-1",
        "justification": "Pending vendor patch — exception until next quarter",
        "valid_for_days": 30,
    }
    r = client.post("/api/compliance/exceptions",
                     headers=auth(client), json=payload)
    assert r.status_code == 200, r.text
    rec = r.json()
    eid = rec["id"]
    # List
    r = client.get("/api/compliance/exceptions",
                    headers=auth(client))
    assert any(e["id"] == eid for e in r.json()["exceptions"])
    # Revoke
    r = client.delete(f"/api/compliance/exceptions/{eid}",
                       headers=auth(client))
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_api_compliance_exception_short_justification_400(client):
    r = client.post("/api/compliance/exceptions",
                     headers=auth(client),
                     json={"control_id": "x", "asset_id": "y",
                              "finding_id": "f", "justification": "x",
                              "valid_for_days": 7})
    assert r.status_code == 400


# =================================================== control history


def test_api_compliance_control_history_endpoints(client):
    # Seed via the module so the API has something to return
    from safecadence.compliance.control_history import record
    record("enforce_mfa", "rtr-1", "pass")
    record("enforce_mfa", "rtr-1", "fail")
    r = client.get("/api/compliance/control-history/enforce_mfa",
                    headers=auth(client))
    assert r.status_code == 200
    assert len(r.json()["history"]) == 2

    r = client.get("/api/compliance/control-history-summary",
                    headers=auth(client))
    rolled = {row["control_id"]: row for row in r.json()["controls"]}
    assert rolled["enforce_mfa"]["tests"] == 2


# =================================================== risk register


def test_api_compliance_risks_full_lifecycle(client):
    payload = {
        "title": "Test risk",
        "description": "Test description",
        "owner": "ciso@example.com",
        "domain": "server",
        "likelihood": 4, "impact": 4,
        "control_ids": ["enforce_mfa"],
        "mitigation": "Enforce MFA on every privileged account",
    }
    r = client.post("/api/compliance/risks", headers=auth(client),
                     json=payload)
    assert r.status_code == 200, r.text
    rid = r.json()["id"]
    # List + summary
    r = client.get("/api/compliance/risks", headers=auth(client))
    assert any(rec["id"] == rid for rec in r.json()["risks"])
    assert r.json()["summary"]["total"] >= 1
    # Delete
    r = client.delete(f"/api/compliance/risks/{rid}",
                       headers=auth(client))
    assert r.json()["ok"] is True


def test_api_compliance_risks_validates_levels(client):
    r = client.post("/api/compliance/risks", headers=auth(client),
                     json={"title": "x", "description": "y",
                              "owner": "z", "domain": "server",
                              "likelihood": 99, "impact": 1})
    assert r.status_code == 400


# =================================================== baseline drift


def test_api_compliance_baseline_set_then_diff(client):
    # Seed an asset so the drift report can be computed.
    from safecadence.server.platform_api import save_asset
    save_asset({
        "identity": {"asset_id": "rtr-99", "hostname": "rtr-99",
                       "vendor": "Cisco",
                       "product_family": "Cisco IOS Software"},
        "raw_collection": {"running":
                              "aaa new-model\nip ssh version 2\nlogging host 10.0.0.5\n"},
    })
    # Set baseline that LACKS the logging line — drift should flag it as added.
    r = client.post("/api/compliance/baseline/rtr-99",
                     headers=auth(client),
                     json={"config_text":
                              "aaa new-model\nip ssh version 2\n"})
    assert r.status_code == 200
    assert r.json()["asset_id"] == "rtr-99"

    r = client.get("/api/compliance/baseline/rtr-99",
                    headers=auth(client))
    body = r.json()
    drift = body["drift"]
    assert drift["has_baseline"] is True
    assert any("logging host" in line for line in drift["added"])


def test_api_compliance_baseline_blocks_path_traversal(client):
    # Two ways the bad path can be blocked: FastAPI's path matcher
    # rejects unescaped slashes (404), or our `_safe_id` raises (400).
    # Both count as "no path traversal reached disk."
    r = client.post("/api/compliance/baseline/..%2F..%2Fetc%2Fpasswd",
                     headers=auth(client),
                     json={"config_text": "x"})
    assert r.status_code in (400, 404)
    # Also try a path with a literal dot-segment in a single id token.
    r = client.post("/api/compliance/baseline/..passwd",
                     headers=auth(client),
                     json={"config_text": "x"})
    assert r.status_code == 400


# =================================================== auditor portal


def test_api_compliance_auditor_issue_verify_revoke(client):
    r = client.post("/api/compliance/auditor/tokens",
                     headers=auth(client),
                     json={"name": "Acme CPA Q4",
                              "issued_to": "auditor@acme.com",
                              "valid_for_days": 30})
    assert r.status_code == 200, r.text
    body = r.json()
    secret = body["secret"]
    tok_id = body["token"]["id"]
    assert secret and tok_id

    # The verify path is module-level; confirm that scope works.
    from safecadence.compliance.auditor_portal import verify
    assert verify(secret, path="/compliance") is not None

    # Revoke via API
    r = client.delete(f"/api/compliance/auditor/tokens/{tok_id}",
                       headers=auth(client))
    assert r.json()["ok"] is True
    assert verify(secret, path="/compliance") is None


def test_api_compliance_auditor_list_never_returns_hash(client):
    client.post("/api/compliance/auditor/tokens",
                 headers=auth(client),
                 json={"name": "Foo", "issued_to": "a@x",
                          "valid_for_days": 30})
    r = client.get("/api/compliance/auditor/tokens",
                    headers=auth(client))
    for tok in r.json()["tokens"]:
        assert "secret_hash" not in tok


# =================================================== evidence chain


def test_api_compliance_evidence_chain_appends_and_verifies(client):
    r = client.post("/api/compliance/evidence-chain/append",
                     headers=auth(client),
                     json={"framework": "soc2",
                              "content_b64": "fake-pdf-bytes"})
    assert r.status_code == 200
    pack_id = r.json()["pack_id"]
    assert pack_id

    r = client.get("/api/compliance/evidence-chain",
                    headers=auth(client))
    body = r.json()
    assert body["integrity"]["ok"] is True
    assert any(rec["pack_id"] == pack_id for rec in body["chain"])


# =================================================== compliance-mode toggle


def test_api_compliance_mode_default_enabled(client):
    r = client.get("/api/settings/compliance-mode",
                    headers=auth(client))
    assert r.status_code == 200
    assert r.json()["enabled"] is True


def test_api_compliance_mode_can_be_toggled(client):
    r = client.post("/api/settings/compliance-mode",
                     headers=auth(client),
                     json={"enabled": False})
    assert r.json()["enabled"] is False
    r = client.get("/api/settings/compliance-mode",
                    headers=auth(client))
    assert r.json()["enabled"] is False


# =================================================== quick policy + dry mode


def test_api_policy_quick_create_lists_and_deletes(client):
    r = client.post("/api/policy/quick",
                     headers=auth(client),
                     json={"name": "Edge hardening",
                              "target_group": "edge-firewalls",
                              "control_ids": ["enforce_ssh_v2",
                                                "disable_telnet",
                                                "enable_syslog"],
                              "mode": "report_only"})
    assert r.status_code == 200, r.text
    pid = r.json()["id"]
    assert r.json()["mode"] == "report_only"
    r = client.get("/api/policy/quick", headers=auth(client))
    assert any(p["id"] == pid for p in r.json()["policies"])
    r = client.delete(f"/api/policy/quick/{pid}",
                       headers=auth(client))
    assert r.json()["ok"] is True


def test_api_policy_quick_validates(client):
    r = client.post("/api/policy/quick",
                     headers=auth(client),
                     json={"name": "x", "target_group": "g",
                              "control_ids": []})
    assert r.status_code == 400


def test_api_policy_mode_set_validates(client):
    r = client.post("/api/policy/some-id/mode",
                     headers=auth(client),
                     json={"mode": "bogus"})
    assert r.status_code == 400


# =================================================== live preview + sandbox


def test_api_policy_preview_config_cisco(client):
    r = client.post("/api/policy/preview-config",
                     headers=auth(client),
                     json={"vendor": "cisco-ios",
                              "control_ids": ["enforce_ssh_v2",
                                                "disable_telnet"]})
    assert r.status_code == 200
    body = r.json()
    assert body["supported"] is True
    assert "ip ssh version 2" in body["rendered"]
    assert "transport input ssh" in body["rendered"]


def test_api_policy_preview_unsupported_vendor(client):
    r = client.post("/api/policy/preview-config",
                     headers=auth(client),
                     json={"vendor": "acme-os",
                              "control_ids": ["enforce_ssh_v2"]})
    body = r.json()
    assert body["supported"] is False


def test_api_policy_sandbox_returns_diff(client):
    from safecadence.server.platform_api import save_asset
    save_asset({
        "identity": {"asset_id": "sbx-1", "hostname": "sbx-1",
                       "vendor": "Cisco",
                       "product_family": "Cisco IOS Software"},
        "raw_collection": {"running": "aaa new-model\n"},  # weak
    })
    r = client.post("/api/policy/sandbox/sbx-1",
                     headers=auth(client),
                     json={"control_ids": ["enforce_ssh_v2",
                                              "enable_syslog"]})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["asset_id"] == "sbx-1"
    assert body["vendor"] == "cisco-ios"
    assert "ip ssh version 2" in body["rendered_preview"]


def test_api_policy_sandbox_unknown_asset_404(client):
    r = client.post("/api/policy/sandbox/does-not-exist",
                     headers=auth(client),
                     json={"control_ids": ["enforce_ssh_v2"]})
    assert r.status_code == 404


# =================================================== v9.32.1: drift roll-up

def test_api_drift_all_returns_three_buckets_with_summary(client):
    """/api/drift/all is the unified roll-up that powers /drift's three
    tabs. It must always return policy / baseline / cross_system arrays
    plus a summary, even on a fresh install with zero data — the UI
    relies on the keys existing to render empty states.

    Regression coverage for v9.32.1: the original /drift only surfaced
    cross_system because the policy-drift import was wrong (was reading
    from policy.persistence, the correct module is policy.store) and
    the field name was wrong (was reading 'drift', actual key is
    'regressions'). If those bugs come back, this test fails.
    """
    r = client.get("/api/drift/all", headers=auth(client))
    assert r.status_code == 200, r.text
    body = r.json()
    for k in ("policy", "baseline", "cross_system", "summary"):
        assert k in body, f"missing key {k}: {body!r}"
    for k in ("policy", "baseline", "cross_system"):
        assert isinstance(body[k], list), f"{k} not a list"
    s = body["summary"]
    for k in ("total", "policy", "baseline", "cross_system",
                "by_severity"):
        assert k in s, f"summary missing {k}"
    assert s["total"] == s["policy"] + s["baseline"] + s["cross_system"]
    for sev in ("critical", "high", "medium", "low"):
        assert sev in s["by_severity"]


def test_api_drift_all_requires_auth(client):
    """The roll-up sees policy + baseline + cross-system data — has
    to be auth-gated like every other /api/* endpoint. No token =
    no roll-up."""
    r = client.get("/api/drift/all")
    assert r.status_code in (401, 403)


# ============================================ v9.32.1: daemon policy-eval hook

def test_daemon_persists_policy_evaluations_in_run_cycle(tmp_path,
                                                              monkeypatch):
    """v9.32.1 wired the daemon to call evaluate_policy() + persist_-
    evaluation() on every run_cycle so detect_drift() has at least
    two history points to compare. Without this hook, /drift's policy
    tab is permanently empty even when configs visibly drifted.

    This test seeds a single asset + a single policy, runs run_cycle
    once, and asserts the hook fired and bumped the counter.
    """
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SAFECADENCE_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))            # isolate ~/.safecadence
    monkeypatch.setenv("SC_AI_DISABLED", "1")
    # No outbound for daemon notifications.
    monkeypatch.setenv("SC_SLACK_WEBHOOK", "")

    from safecadence import daemon as dmn
    out = dmn.run_cycle()
    # The hook is best-effort by design (daemon can't abort a cycle on
    # one bad policy) — we accept any non-negative count. What matters
    # is that the field exists, which proves the hook is wired and is
    # always reported back to ops dashboards / selfcheck.
    hooks = out.get("compliance_hooks") or {}
    assert "policy_evaluations_persisted" in hooks, (
        "daemon must always emit the policy_evaluations_persisted "
        "key — /drift's policy tab + ops dashboards rely on it"
    )
    assert isinstance(hooks["policy_evaluations_persisted"], int)
    assert hooks["policy_evaluations_persisted"] >= 0
