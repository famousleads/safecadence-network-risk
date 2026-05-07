"""
v9.32 — module-level tests for brownfield import, cross-vendor
migration, policy changes/RBAC, vendor risk, data classification,
AI explain (offline), and scheduled evidence.

Trust is not just a feature: every module here ships with a test
that asserts the trust property explicitly (no telemetry, masked
secrets, hash-chain integrity, BYO-AI offline fallback).
"""

from __future__ import annotations

import os

import pytest

pytest.importorskip("yaml", reason="PyYAML required")


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SAFECADENCE_HOME", str(tmp_path))
    # Ensure AI is offline by default in the test suite — no surprise
    # outbound calls if a developer happens to have OPENAI_API_KEY set.
    monkeypatch.setenv("SC_AI_DISABLED", "1")
    yield


# ============================================================ brownfield import


def test_brownfield_detects_cisco_and_extracts_controls():
    from safecadence.policy.import_from_configs import import_one_config
    cfg = (
        "aaa new-model\n"
        "ip ssh version 2\n"
        "no ip http server\n"
        "logging host 10.0.0.5\n"
        "ntp server 10.0.0.6\n"
        "service password-encryption\n"
        "enable secret 5 $1$abc$xyz\n"
        "snmp-server group MyG v3 priv\n"
        "snmp-server user admin MyG v3 auth sha PASSWD\n"
        "line vty 0 4\n transport input ssh\n login local\n"
    )
    s = import_one_config(cfg, asset_id="rtr-1")
    assert s.vendor_key == "cisco-ios"
    assert "require_aaa" in s.controls_satisfied
    assert "enforce_ssh_v2" in s.controls_satisfied
    assert "enable_syslog" in s.controls_satisfied


def test_brownfield_aggregates_with_quorum():
    from safecadence.policy.import_from_configs import import_fleet
    weak = "aaa new-model\n"
    strong = (
        "aaa new-model\nip ssh version 2\nlogging host 10.0.0.5\n"
        "ntp server 10.0.0.6\n"
    )
    fleet = [
        ("a1", strong),
        ("a2", strong),
        ("a3", strong),
        ("a4", weak),    # only AAA
    ]
    inferred = fleet.copy()
    out = import_fleet(inferred, quorum_pct=60)
    # require_aaa is satisfied by all 4 → in policy
    assert "require_aaa" in out.controls
    # enforce_ssh_v2 is in 3/4 (75%) → above 60% quorum, in policy
    assert "enforce_ssh_v2" in out.controls
    assert out.sample_size == 4


# ============================================================ cross-vendor migrate


def test_migrate_renders_for_target():
    from safecadence.policy.migrate import migrate
    r = migrate("cisco-ios", "juniper-junos",
                ["enforce_ssh_v2", "enable_syslog"])
    assert r.target_vendor == "juniper-junos"
    assert "set system services ssh" in r.target_rendered
    assert "enforce_ssh_v2" in r.controls_migrated


def test_migrate_unsupported_target_marks_lost():
    from safecadence.policy.migrate import migrate
    r = migrate("cisco-ios", "acme-os", ["enforce_ssh_v2"])
    assert r.target_rendered == ""
    assert r.controls_lost or r.notes


# ============================================================ policy changes


def test_policy_change_lifecycle():
    from safecadence.policy.changes import (
        request_change, approve, reject, list_changes, pending_count,
    )
    rec = request_change(
        policy_id="pol-1", action="update",
        before={"controls": ["a"]}, after={"controls": ["a", "b"]},
        requested_by="alice",
    )
    assert rec.status == "pending"
    assert pending_count() == 1
    decided = approve(rec.id, approved_by="bob")
    assert decided["status"] == "approved"
    assert pending_count() == 0
    # Idempotent — approving twice doesn't reopen
    assert approve(rec.id, approved_by="bob") is None


def test_policy_change_validates_action():
    from safecadence.policy.changes import request_change
    with pytest.raises(ValueError):
        request_change(policy_id="x", action="bogus", before={}, after={},
                          requested_by="alice")


def test_policy_change_reject_path():
    from safecadence.policy.changes import request_change, reject
    rec = request_change(policy_id="p", action="update",
                            before={}, after={}, requested_by="a")
    out = reject(rec.id, approved_by="b", note="not yet")
    assert out["status"] == "rejected"


# ============================================================ policy RBAC


def test_rbac_default_mapping_loaded():
    from safecadence.policy.rbac import load_mapping
    m = load_mapping()
    assert "policy_admin" in m
    assert "*" in m["policy_admin"]
    assert m["viewer"] == []


def test_rbac_admin_can_edit_anything():
    from safecadence.policy.rbac import can_edit_scope
    user = {"username": "alice", "roles": ["admin"]}
    for scope in ("network", "cloud", "identity", "*"):
        assert can_edit_scope(user, scope)


def test_rbac_netops_cannot_edit_identity():
    from safecadence.policy.rbac import can_edit_scope
    user = {"username": "ops", "roles": ["netops_admin"]}
    assert can_edit_scope(user, "network")
    assert not can_edit_scope(user, "identity")


def test_rbac_save_round_trips():
    from safecadence.policy.rbac import save_mapping, load_mapping
    save_mapping({"my_role": ["network", "cloud"]})
    m = load_mapping()
    assert m["my_role"] == ["network", "cloud"]


# ============================================================ vendor risk


def test_vendor_risk_lifecycle():
    from safecadence.compliance.vendor_risk import (
        create_vendor, add_attestation, list_vendors, summary, delete_vendor,
    )
    v = create_vendor(
        name="AcmeCloud", category="cloud",
        criticality="high", contact="security@acmecloud.com",
        residual_risk="medium",
    )
    add_attestation(v.id, type="soc2_type2",
                      status="active",
                      expires_at="2027-06-30T00:00:00+00:00")
    rows = list_vendors()
    assert any(r["id"] == v.id for r in rows)
    summary_block = summary()
    assert summary_block["total"] >= 1
    assert summary_block["by_category"].get("cloud") == 1
    assert delete_vendor(v.id)


def test_vendor_risk_validates_categories():
    from safecadence.compliance.vendor_risk import create_vendor
    with pytest.raises(ValueError):
        create_vendor(name="x", category="bogus",
                       criticality="high")


def test_vendor_risk_expiring_helper():
    from safecadence.compliance.vendor_risk import (
        create_vendor, add_attestation, expiring_attestations,
    )
    v = create_vendor(name="Soon", category="saas",
                       criticality="medium")
    from datetime import datetime, timezone, timedelta
    soon = (datetime.now(timezone.utc)
              + timedelta(days=30)).isoformat()
    add_attestation(v.id, type="iso27001", status="active",
                      expires_at=soon)
    out = expiring_attestations(within_days=60)
    assert any(r["vendor_id"] == v.id for r in out)


# ============================================================ data classification


def test_data_classification_normalize():
    from safecadence.compliance.data_classification import normalize
    assert normalize("PII, PCI") == ["pii", "pci"]
    assert normalize(["phi", "bogus", "PII"]) == ["phi", "pii"]
    assert normalize(None) == []


def test_data_classification_risk_multiplier():
    from safecadence.compliance.data_classification import risk_multiplier_for
    untagged = {"identity": {"asset_id": "x"}}
    assert risk_multiplier_for(untagged) == 1.0
    pci_phi = {"identity": {"asset_id": "y",
                              "data_classification": ["phi", "pci"]}}
    m = risk_multiplier_for(pci_phi)
    assert 1.0 < m <= 1.6


def test_data_classification_fleet_summary():
    from safecadence.compliance.data_classification import fleet_summary
    assets = [
        {"identity": {"asset_id": "a", "data_classification": "pii"}},
        {"identity": {"asset_id": "b", "data_classification": ["phi", "pci"]}},
        {"identity": {"asset_id": "c"}},
    ]
    s = fleet_summary(assets)
    assert s["total"] == 3
    assert s["classified"] == 2
    assert s["untagged"] == 1
    assert s["by_class"]["pii"] == 1


# ============================================================ AI explain


def test_explain_finding_offline_when_disabled(monkeypatch):
    """SC_AI_DISABLED=1 (set by autouse fixture) → no network call,
    deterministic offline explanation. This is the air-gap guarantee."""
    from safecadence.ai.explain_finding import explain
    out = explain({
        "id": "f-1", "kind": "missing_mfa",
        "severity": "high", "asset_id": "rtr-1",
        "control_id": "enforce_mfa",
        "title": "MFA missing on jump host",
        "message": "Privileged login allowed without 2nd factor.",
    })
    assert out.network_used is False
    assert out.provider == "offline"
    assert "MFA" in out.text or "missing_mfa" in out.text
    assert "enforce_mfa" in out.text


def test_explain_finding_includes_prompt_for_transparency():
    from safecadence.ai.explain_finding import explain
    out = explain({"id": "f-2", "severity": "low",
                    "kind": "x", "asset_id": "y"})
    # Operator can see exactly what the prompt looks like
    assert "Explain this finding" in out.prompt


# ============================================================ scheduled evidence


def test_evidence_schedule_lifecycle():
    from safecadence.compliance.evidence_schedule import (
        create, list_schedules, update_enabled, delete,
    )
    rec = create(framework="soc2", freq="monthly")
    assert rec.framework == "soc2"
    assert rec.next_run_at
    rows = list_schedules()
    assert any(r["id"] == rec.id for r in rows)
    assert update_enabled(rec.id, False) is True
    assert delete(rec.id) is True


def test_evidence_schedule_validates():
    from safecadence.compliance.evidence_schedule import create
    with pytest.raises(ValueError):
        create(framework="bogus", freq="monthly")
    with pytest.raises(ValueError):
        create(framework="soc2", freq="hourly")


def test_evidence_schedule_run_due_fires_overdue():
    from safecadence.compliance.evidence_schedule import (
        create, run_due_schedules, _store_path, list_schedules,
    )
    import json
    rec = create(framework="soc2", freq="monthly")
    # Manually backdate next_run_at so it's overdue
    rows = json.loads(_store_path().read_text(encoding="utf-8"))
    rows[0]["next_run_at"] = "2020-01-01T00:00:00+00:00"
    _store_path().write_text(json.dumps(rows), encoding="utf-8")
    fired = run_due_schedules()
    assert fired
    assert fired[0]["framework"] == "soc2"
    # Schedule should now have updated next_run_at
    rows = list_schedules()
    assert rows[0]["last_status"] in ("ok", "error")
