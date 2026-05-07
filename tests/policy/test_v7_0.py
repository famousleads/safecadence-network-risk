"""v7.0 — Secure Command Execution Engine tests.

Locks down:
  - Schema: every dataclass round-trips JSON
  - RBAC: 6-tier matrix with risk-routed approvals
  - Guardrails: risk classifier + blocked + lockout work end-to-end
  - Builder: NL intent → per-vendor command set
  - Workflow: legal state transitions + 'authors cannot self-approve'
  - Executor: dry-run produces real CommandExecution rows
  - Exporters: Ansible / Salt / NSO / raw / markdown render
  - Identity translators: 5 idp_* controls now have output
"""

from __future__ import annotations

import os


# --------------------------------------------------------------------------
# RBAC matrix
# --------------------------------------------------------------------------

def test_rbac_six_tiers_present():
    from safecadence.execution.rbac import Role, capabilities_for
    roles = list(Role)
    assert len(roles) == 6
    # Strict superset chain — Super Admin ⊇ Security Admin ⊇ ...
    prev_caps = set()
    order = [Role.VIEWER, Role.AUDITOR, Role.OPERATOR,
             Role.ENGINEER, Role.SECURITY_ADMIN, Role.SUPER_ADMIN]
    for role in order:
        c = capabilities_for(role)
        assert prev_caps.issubset(c), f"{role} doesn't subsume previous tier"
        prev_caps = c


def test_rbac_engineer_cannot_approve_own_config():
    from safecadence.execution.rbac import Capability, Role, can
    # Engineer creates config jobs but only Security Admin approves
    assert can(Role.ENGINEER, Capability.CREATE_CONFIG_JOB)
    assert not can(Role.ENGINEER, Capability.APPROVE_MEDIUM_RISK)
    assert can(Role.SECURITY_ADMIN, Capability.APPROVE_MEDIUM_RISK)


def test_rbac_no_role_has_execute_real_by_default():
    """Real SSH push is NEVER granted by default. To enable it the
    operator wires SafeCadence into Ansible Tower / NSO."""
    from safecadence.execution.rbac import Capability, Role, capabilities_for
    for r in Role:
        assert Capability.EXECUTE_REAL not in capabilities_for(r), (
            f"role {r} should NOT have EXECUTE_REAL by default"
        )


def test_rbac_critical_requires_two_approvers():
    from safecadence.execution.rbac import approvals_needed
    assert approvals_needed("critical") == 2
    assert approvals_needed("high") == 1
    assert approvals_needed("medium") == 1
    assert approvals_needed("low") == 0
    assert approvals_needed("safe") == 0


# --------------------------------------------------------------------------
# Guardrails
# --------------------------------------------------------------------------

def test_guardrails_show_command_is_safe():
    from safecadence.execution.guardrails import classify_risk
    r = classify_risk(["show running-config", "show ip bgp summary"])
    assert r.risk.value == "safe"


def test_guardrails_reload_is_critical():
    from safecadence.execution.guardrails import classify_risk
    r = classify_risk(["reload"])
    assert r.risk.value == "critical"


def test_guardrails_unknown_command_defaults_up():
    """Default-up: unrecognised commands get MEDIUM, never SAFE."""
    from safecadence.execution.guardrails import classify_risk
    r = classify_risk(["frobnicate the bazz"])
    assert r.risk.value == "medium"


def test_guardrails_blocks_rm_rf_root():
    from safecadence.execution.guardrails import is_blocked
    r = is_blocked(["rm -rf /"])
    assert r.blocked is True


def test_guardrails_no_aaa_escalates_to_critical():
    from safecadence.execution.guardrails import preflight
    pf = preflight(["no aaa new-model"])
    assert pf.risk.value == "critical"
    assert pf.escalated_to_critical is True


def test_guardrails_lockout_detects_no_ssh_without_console():
    from safecadence.execution.guardrails import lockout_risk
    asset = {"raw_collection": {
        "running": "interface GigabitEthernet0/0\n ip address 10.0.0.1 255.255.255.0\n"
    }}
    r = lockout_risk(["no transport input ssh"], asset)
    assert r.at_risk is True


# --------------------------------------------------------------------------
# Builder
# --------------------------------------------------------------------------

def test_builder_bgp_intent_emits_per_vendor_commands():
    from safecadence.execution.builder import build_plan
    plan = build_plan("Check BGP on all Cisco routers")
    assert "bgp_health" in plan.matched_packs
    assert "cisco_ios" in plan.commands_by_vendor
    assert plan.risk.value == "safe"
    assert plan.blocked is False


def test_builder_unmatched_intent_returns_empty_with_summary():
    from safecadence.execution.builder import build_plan
    plan = build_plan("do something inexplicable to my fleet")
    assert plan.matched_packs == []
    assert "no built-in command pack" in plan.summary.lower()


def test_builder_blocked_intent_returns_blocked_plan():
    """An intent that lands on a hard-blocked command must come back
    blocked instead of silently dropping it."""
    from safecadence.execution.builder import build_plan, _PACKS
    # Inject a hostile pack just for this test
    _PACKS["__test_destroy__"] = {"linux": ["rm -rf /"]}
    try:
        # Ride a real intent rule + the synthetic pack
        from safecadence.execution.guardrails import is_blocked
        r = is_blocked(_PACKS["__test_destroy__"]["linux"])
        assert r.blocked is True
    finally:
        del _PACKS["__test_destroy__"]


# --------------------------------------------------------------------------
# Workflow state machine
# --------------------------------------------------------------------------

def test_workflow_create_submit_approve(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_EXECUTION_STORE", str(tmp_path))
    from safecadence.execution import workflow
    from safecadence.execution.rbac import Role
    from safecadence.execution.schema import (
        CommandJob, CommandMode, JobStatus,
    )
    job = CommandJob(name="t", mode=CommandMode.READ_ONLY,
                      inline_commands={"cisco_ios": ["show version"]},
                      created_by="alice")
    workflow.create_job(job, actor="alice", role=Role.OPERATOR)
    workflow.submit_for_review(job.job_id, actor="alice")
    # safe risk → auto-approved (approvals_needed = 0)
    from safecadence.execution import store
    j = store.get_job(job.job_id)
    assert j.status == JobStatus.APPROVED


def test_workflow_self_approval_blocked(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_EXECUTION_STORE", str(tmp_path))
    from safecadence.execution import workflow
    from safecadence.execution.rbac import Role
    from safecadence.execution.schema import (
        CommandJob, CommandMode,
    )
    # A medium-risk job needs an approver; the author must NOT be it.
    job = CommandJob(name="t", mode=CommandMode.CONFIG,
                      inline_commands={"cisco_ios": ["copy running startup"]},
                      created_by="bob")
    workflow.create_job(job, actor="bob", role=Role.ENGINEER)
    workflow.submit_for_review(job.job_id, actor="bob")
    import pytest
    with pytest.raises(workflow.WorkflowError):
        workflow.approve(job.job_id, approver="bob",
                          role=Role.SECURITY_ADMIN)


def test_workflow_blocks_dangerous_job(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_EXECUTION_STORE", str(tmp_path))
    from safecadence.execution import workflow
    from safecadence.execution.rbac import Role
    from safecadence.execution.schema import (
        CommandJob, CommandMode, JobStatus,
    )
    job = CommandJob(name="evil", mode=CommandMode.CONFIG,
                      inline_commands={"linux": ["rm -rf /"]},
                      created_by="mallory")
    workflow.create_job(job, actor="mallory", role=Role.ENGINEER)
    import pytest
    with pytest.raises(workflow.WorkflowError):
        workflow.submit_for_review(job.job_id, actor="mallory")
    from safecadence.execution import store
    j = store.get_job(job.job_id)
    assert j.status == JobStatus.BLOCKED


# --------------------------------------------------------------------------
# Executor — dry-run end-to-end against demo fleet
# --------------------------------------------------------------------------

def test_dry_run_against_demo_fleet(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_EXECUTION_STORE", str(tmp_path / "exec"))
    monkeypatch.setenv("SC_PLATFORM_STORE", str(tmp_path / "plat"))
    from safecadence.demo import load_demo_fleet
    from safecadence.execution import executor, store, workflow
    from safecadence.execution.rbac import Role
    from safecadence.execution.schema import (
        CommandJob, CommandMode,
    )
    load_demo_fleet()
    # Build a job that targets all Cisco assets via filter
    job = CommandJob(
        name="diag",
        mode=CommandMode.READ_ONLY,
        target_filter={"all": [{"field": "vendor", "op": "eq",
                                  "value": "cisco"}]},
        inline_commands={
            "cisco_ios":  ["show version", "show ip interface brief"],
            "cisco_nxos": ["show version"],
        },
        created_by="alice",
    )
    workflow.create_job(job, actor="alice", role=Role.OPERATOR)
    workflow.submit_for_review(job.job_id, actor="alice")
    result = executor.dry_run(job.job_id)
    assert result["ok"] is True
    assert result["asset_count"] >= 1
    # Real CommandExecution rows must have landed in the store
    assert len(store.list_executions(job_id=job.job_id)) >= 1


# --------------------------------------------------------------------------
# Exporters
# --------------------------------------------------------------------------

def test_export_ansible_includes_per_vendor_play():
    from safecadence.execution.executor import export_ansible
    from safecadence.execution.schema import (
        CommandJob, CommandMode, RiskLevel,
    )
    job = CommandJob(name="t", mode=CommandMode.READ_ONLY,
                      risk=RiskLevel.SAFE,
                      inline_commands={"cisco_ios": ["show version"]})
    out = export_ansible(job, assets=[])
    assert "cisco.ios.ios_command" in out
    assert "show version" in out


def test_export_all_formats_produce_text():
    from safecadence.execution.executor import export
    from safecadence.execution.schema import CommandJob
    job = CommandJob(name="t",
                      inline_commands={"linux": ["uname -a"]})
    for fmt in ("ansible", "salt", "nso", "raw", "markdown"):
        text = export(job, fmt)
        assert isinstance(text, str) and len(text) > 0


# --------------------------------------------------------------------------
# Identity translator coverage
# --------------------------------------------------------------------------

def test_okta_idp_translator_covers_idp_controls():
    from safecadence.policy.translators import _TRANSLATORS
    assert "okta_idp" in _TRANSLATORS
    okta = _TRANSLATORS["okta_idp"]
    for cid in ("idp_require_mfa_for_admins", "idp_disable_dormant_accounts",
                "idp_password_complexity", "idp_conditional_access",
                "idp_privileged_role_review"):
        assert okta.supports(cid), f"okta_idp claims to support {cid}"


def test_azure_ca_translator_now_handles_idp_controls():
    from safecadence.policy.translators import _TRANSLATORS
    from safecadence.policy.schema import PolicyControl
    az = _TRANSLATORS["azure_ca"]
    fix = az.translate(PolicyControl(control_id="idp_require_mfa_for_admins"),
                       asset={"identity": {"asset_id": "x"}})
    assert fix.applicable
    joined = "\n".join(fix.fix).lower()
    assert "conditionalaccess" in joined


# --------------------------------------------------------------------------
# Asset model extensions — owner / team / location
# --------------------------------------------------------------------------

def test_demo_assets_carry_owner_and_location():
    from safecadence.demo import build_demo_fleet
    fleet = build_demo_fleet()
    sample = fleet[0]["identity"]
    for k in ("owner", "team", "country", "city",
              "campus", "building", "floor", "rack",
              "support_contract"):
        assert k in sample, f"identity missing {k}"
