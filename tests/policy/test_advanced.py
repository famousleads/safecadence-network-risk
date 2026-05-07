"""Phase-5 advanced features: store/workflow/exceptions/variants/audit/cve/attestation/shadow IT."""

from __future__ import annotations

import json

from safecadence.policy import audit, exceptions, store, variants
from safecadence.policy.attestation import attestation_markdown, build_attestation
from safecadence.policy.cve_policies import policy_from_cves
from safecadence.policy.evaluator import evaluate
from safecadence.policy.schema import PolicyState, Severity
from safecadence.policy.shadow_it import find_shadow_assets
from safecadence.policy.templates import load_template
from safecadence.policy.workflow import WorkflowError, transition


def test_store_save_get_list_delete():
    p = load_template("tmpl_network_hardening")
    store.save(p, actor="t")
    listed = store.list_policies()
    assert any(m["policy_id"] == p.policy_id for m in listed)
    got = store.get(p.policy_id)
    assert got is not None
    assert got.policy_name == p.policy_name
    assert store.delete(p.policy_id, actor="t") is True
    assert store.get(p.policy_id) is None


def test_workflow_legal_and_illegal_transitions():
    p = load_template("tmpl_network_hardening")
    p.severity = Severity.LOW          # not critical → single approver allowed
    store.save(p, actor="t")
    transition(p.policy_id, PolicyState.REVIEW, actor="t")
    p2 = transition(p.policy_id, PolicyState.APPROVED, actor="t", approvers=["a"])
    assert p2.state == PolicyState.APPROVED
    # illegal: APPROVED → DRAFT
    try:
        transition(p.policy_id, PolicyState.DRAFT, actor="t")
        assert False, "should have raised"
    except WorkflowError:
        pass


def test_critical_policy_requires_two_approvers():
    p = load_template("tmpl_zero_trust")
    p.severity = Severity.CRITICAL
    store.save(p, actor="t")
    transition(p.policy_id, PolicyState.REVIEW, actor="t")
    try:
        transition(p.policy_id, PolicyState.APPROVED, actor="t", approvers=["only_one"])
        assert False, "should have required 2 approvers"
    except WorkflowError:
        pass
    # 2 approvers is fine
    transition(p.policy_id, PolicyState.APPROVED, actor="t",
               approvers=["a", "b"])


def test_exception_lifecycle(cisco_router_messy):
    p = load_template("tmpl_network_hardening")
    store.save(p, actor="t")
    ex = exceptions.add_exception(p.policy_id, asset_id="r2",
                                   control_id="disable_telnet",
                                   justification="legacy", approved_by="ciso",
                                   actor="t")
    assert ex.exception_id
    listed = exceptions.list_exceptions(p.policy_id)
    assert any(e["exception_id"] == ex.exception_id and e["status"] == "active"
               for e in listed)
    # evaluator should now skip the control for that asset
    p2 = store.get(p.policy_id)
    ev = evaluate(p2, [cisco_router_messy])
    assert all(v.control_id != "disable_telnet" for v in ev.violations)
    assert exceptions.revoke_exception(p.policy_id, ex.exception_id, actor="t") is True


def test_variant_overrides_parameters():
    p = load_template("tmpl_logging_monitoring")
    store.save(p, actor="t")
    variants.set_variant(p.policy_id, environment="dev",
                         control_id="enable_syslog",
                         parameters={"syslog_target": "10.99.99.99"},
                         actor="t")
    p2 = store.get(p.policy_id)
    asset_dev = {"identity": {"asset_type": "network", "environment": "dev"}}
    eff = p2.control_for_asset("enable_syslog", asset_dev)
    assert eff.parameters.get("syslog_target") == "10.99.99.99"


def test_cve_policy_generation():
    p = policy_from_cves([{"cve_id": "CVE-2025-9999", "severity": "critical",
                            "kev": True, "affected_vendors": ["cisco"]}])
    assert p.severity == Severity.CRITICAL
    assert p.controls and p.controls[0].control_id == "enforce_patch_level"
    assert p.source == "cve"
    assert "cisco" in (p.scope.get("vendor") or [])


def test_attestation_report_renders(cisco_router_clean):
    p = load_template("tmpl_network_hardening")
    att = build_attestation(p, [cisco_router_clean])
    assert att["compliance_summary"]["pass_count"] >= 1
    md = attestation_markdown(att)
    assert "Compliance Attestation Report" in md


def test_shadow_it_when_no_policies():
    sh = find_shadow_assets([
        {"identity": {"asset_id": "x", "asset_type": "server", "vendor": "ubuntu"}},
        {"identity": {"asset_id": "y", "asset_type": "network", "vendor": "cisco"}},
    ])
    assert len(sh) == 2
    assert {a["asset_id"] for a in sh} == {"x", "y"}


def test_audit_logging_round_trip():
    audit.log("test_event", actor="tester", policy_id="x",
              detail={"a": 1})
    recent = audit.read_recent(limit=10)
    assert any(e["action"] == "test_event" for e in recent)
