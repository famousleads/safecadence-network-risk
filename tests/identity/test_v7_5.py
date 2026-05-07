"""
v7.5 — Identity Intelligence engine tests.

Coverage targets per spec §10:
  * NHI schema round-trip via dataclasses + JSON
  * AdapterCapabilities still loads without supports_write
  * IR validation: rejects malformed input, accepts well-formed
  * AI translator with mock client: produces valid IR, validates schema
  * Effective-permission resolver: deny wins, conditions enforce step-up
  * Compiler: deterministic per-system preview, Okta op shape
  * Okta apply_policy: dry-run does no HTTP; commit calls injected stubs
"""

from __future__ import annotations

import json
from dataclasses import asdict

import pytest

from safecadence.identity.ir import (
    Condition, IRValidationError, PrincipalSelector, ResourceSelector,
    UnifiedPolicyIR, validate_ir,
)
from safecadence.identity.effective_permissions import (
    _DeclaredRule, decide, rules_from_assets,
)
from safecadence.identity.compiler import compile_plan
from safecadence.identity.ai_translator import (
    from_form, translate, _clean_json,
)


# ---------------------------------------------------------------- schema


def test_nhi_schema_roundtrip():
    from safecadence.platform.schema import NonHumanIdentity, UnifiedAsset
    nhi = NonHumanIdentity(
        nhi_id="aws-iam:role/build-bot",
        subtype="iam_role",
        provider="aws",
        effective_scopes=["s3:Get*", "s3:List*"],
        risk_findings=["never_rotated"],
    )
    d = asdict(nhi)
    assert d["nhi_id"] == "aws-iam:role/build-bot"
    assert d["subtype"] == "iam_role"
    # round-trip via JSON
    parsed = json.loads(json.dumps(d))
    nhi2 = NonHumanIdentity(**parsed)
    assert nhi2 == nhi
    # UnifiedAsset has the field
    a = UnifiedAsset()
    assert a.nhi.nhi_id == ""


def test_adapter_capabilities_supports_write_default():
    from safecadence.platform.adapter_base import AdapterCapabilities
    caps = AdapterCapabilities(name="test")
    assert caps.supports_write is False
    assert caps.write_capabilities == []


# ---------------------------------------------------------------- IR validation


def test_validate_ir_rejects_missing_actions():
    with pytest.raises(IRValidationError):
        validate_ir({"effect": "deny", "subjects": {"groups": ["x"]}})


def test_validate_ir_rejects_unknown_effect():
    with pytest.raises(IRValidationError):
        validate_ir({"effect": "maybe", "actions": ["ssh"],
                      "subjects": {"groups": ["x"]}})


def test_validate_ir_rejects_empty_subjects():
    with pytest.raises(IRValidationError):
        validate_ir({"effect": "deny", "actions": ["ssh"], "subjects": {}})


def test_validate_ir_accepts_well_formed():
    ir = validate_ir({
        "intent": "no SSH for contractors without MFA",
        "effect": "deny",
        "actions": ["ssh"],
        "subjects": {"groups": ["Contractors"]},
        "resources": {"environments": ["prod"]},
        "conditions": [{"kind": "mfa_required", "value": True}],
        "targets": ["okta", "ise"],
    })
    assert ir.effect == "deny"
    assert ir.subjects.groups == ["Contractors"]
    assert ir.conditions[0].kind == "mfa_required"


# ---------------------------------------------------------------- AI translator


def test_ai_translator_with_stub():
    """We stub the AI call so unit tests never open a socket."""
    fake_response = json.dumps({
        "intent": "engineers can RDP staging with MFA",
        "subjects": {"groups": ["Engineers"]},
        "resources": {"environments": ["staging"]},
        "actions": ["rdp"],
        "conditions": [{"kind": "mfa_required", "value": True}],
        "effect": "allow",
        "targets": ["entra"],
    })

    def stub_ai(system, user, model):
        return fake_response

    from safecadence.ai.client import AIProvider
    result = translate("engineers can RDP staging with MFA",
                        provider=AIProvider.OPENAI,
                        model="gpt-test",
                        ai_call=stub_ai)
    assert result.ir.effect == "allow"
    assert result.ir.author == "ai"
    assert result.ir.ai_model == "gpt-test"
    assert "Engineers" in result.ir.subjects.groups


def test_ai_translator_strips_code_fences():
    raw = "```json\n" + json.dumps({
        "intent": "x",
        "subjects": {"groups": ["g"]},
        "actions": ["ssh"],
        "effect": "deny",
    }) + "\n```"

    def stub_ai(system, user, model):
        return raw

    from safecadence.ai.client import AIProvider
    result = translate("x", provider=AIProvider.OPENAI, model="m",
                        ai_call=stub_ai)
    assert result.ir.intent == "x"


def test_ai_translator_rejects_garbage():
    def stub_ai(system, user, model):
        return "this is not JSON, sorry"

    from safecadence.ai.client import AIProvider
    with pytest.raises(IRValidationError):
        translate("x", provider=AIProvider.OPENAI, model="m", ai_call=stub_ai)


def test_clean_json_handles_prefixes():
    assert _clean_json("Output: {\"a\": 1}") == '{"a": 1}'
    assert _clean_json("```{\"a\":1}```") == '{"a":1}'


def test_form_fallback_produces_valid_ir():
    ir = from_form(intent="test", groups=["Contractors"],
                    actions=["ssh"], environments=["prod"])
    assert ir.effect == "deny"
    assert ir.subjects.groups == ["Contractors"]
    assert any(c.kind == "mfa_required" for c in ir.conditions)


# ---------------------------------------------------------------- effective perms


def test_decide_default_deny_with_no_rules():
    d = decide("alice@x", "ssh", "srv-1")
    assert d.allowed is False
    assert "default deny" in " ".join(d.reasons).lower()


def test_decide_explicit_allow():
    rules = [_DeclaredRule(
        system="okta", rule_id="r1", rule_name="allow-eng-ssh",
        effect="allow", principals=["group:Engineers"],
        resources=["env:staging"], actions=["ssh"], conditions=[],
        priority=10,
    )]
    d = decide("alice@x", "ssh", "srv-staging-01",
                principal_groups=["Engineers"],
                resource_attrs={"env": "staging"},
                rules=rules)
    assert d.allowed is True
    assert d.chain[0].rule_name == "allow-eng-ssh"


def test_decide_deny_wins_over_allow():
    rules = [
        _DeclaredRule(system="okta", rule_id="r1", rule_name="allow-eng",
                       effect="allow", principals=["group:Engineers"],
                       resources=["*"], actions=["ssh"], conditions=[],
                       priority=100),
        _DeclaredRule(system="ise", rule_id="r2", rule_name="deny-no-mfa",
                       effect="deny", principals=["group:Engineers"],
                       resources=["*"], actions=["ssh"], conditions=[],
                       priority=50),
    ]
    d = decide("alice@x", "ssh", "srv-1",
                principal_groups=["Engineers"], rules=rules)
    assert d.allowed is False
    assert d.chain[0].rule_name == "deny-no-mfa"


def test_decide_step_up_when_condition_unmet():
    rules = [_DeclaredRule(
        system="okta", rule_id="r1", rule_name="allow-with-mfa",
        effect="allow", principals=["*"], resources=["*"],
        actions=["ssh"], conditions=["mfa_required"],
        priority=10,
    )]
    d = decide("alice", "ssh", "srv", rules=rules,
                context={"mfa": False})
    assert d.allowed is False
    assert d.requires_step_up is True


def test_rules_from_assets_synthesizes_v6_data():
    assets = [{
        "identity_block": {
            "provider": "okta",
            "active_authz_rule": "AllowAccess",
            "mfa_enrolled": True,
        },
    }]
    rules = rules_from_assets(assets)
    assert len(rules) == 1
    assert rules[0].system == "okta"
    assert rules[0].effect == "allow"


# ---------------------------------------------------------------- compiler


def test_compile_plan_emits_okta_op():
    ir = validate_ir({
        "intent": "no SSH for contractors without MFA",
        "effect": "deny",
        "actions": ["ssh"],
        "subjects": {"groups": ["Contractors"]},
        "resources": {"environments": ["prod"]},
        "conditions": [{"kind": "mfa_required", "value": True}],
        "targets": ["okta"],
    })
    plan = compile_plan(ir)
    assert len(plan.operations) == 1
    op = plan.operations[0]
    assert op.target == "okta"
    assert op.deferred is False
    assert "rule_name" in op.payload
    assert "Quarantine" in op.payload["target_group"]


def test_compile_plan_emits_real_op_for_all_targets():
    """v7.6 generalized the Okta pattern — every target now emits a
    real operation. The 'deferred' flag is reserved for true future
    work (none in v7.6)."""
    ir = validate_ir({
        "intent": "broad policy",
        "effect": "deny", "actions": ["ssh"],
        "subjects": {"groups": ["g"]},
        "targets": ["all"],
    })
    plan = compile_plan(ir)
    assert {o.target for o in plan.operations} == {
        "okta", "ise", "ad", "entra", "clearpass"}
    assert all(o.deferred is False for o in plan.operations)


def test_compile_plan_diff_is_human_readable():
    ir = validate_ir({
        "intent": "test policy",
        "effect": "deny", "actions": ["ssh"],
        "subjects": {"groups": ["X"]},
        "targets": ["okta"],
    })
    diff = compile_plan(ir).diff()
    assert "test policy" in diff
    assert "[okta]" in diff


# ---------------------------------------------------------------- Okta write-back


def test_okta_apply_policy_dry_run_makes_no_http_calls():
    from safecadence.platform.adapters.identity_adapters import OktaAdapter
    ir = validate_ir({
        "intent": "x", "effect": "deny", "actions": ["ssh"],
        "subjects": {"groups": ["g"]}, "targets": ["okta"],
    })
    a = OktaAdapter(target="acme.okta.com",
                     credentials={"api_token": "x"})
    calls: list = []

    def fail_post(*args, **kwargs):
        calls.append(("POST", args))
        raise RuntimeError("dry-run must not POST")

    def fail_put(*args, **kwargs):
        calls.append(("PUT", args))
        raise RuntimeError("dry-run must not PUT")

    result = a.apply_policy(ir, dry_run=True,
                             http_post=fail_post, http_put=fail_put)
    assert result["dry_run"] is True
    assert result["error"] is None
    assert calls == []
    assert "diff" in result and "[okta]" in result["diff"]


def test_okta_apply_policy_commit_calls_post_and_activate_put():
    from safecadence.platform.adapters.identity_adapters import OktaAdapter
    ir = validate_ir({
        "intent": "no contractors", "effect": "deny", "actions": ["ssh"],
        "subjects": {"groups": ["Contractors"]}, "targets": ["okta"],
    })
    a = OktaAdapter(target="acme.okta.com",
                     credentials={"api_token": "x"})

    def stub_post(url, headers, body):
        assert "/groups/rules" in url
        assert body["type"] == "group_rule"
        return {"id": "rul_TESTID", "status": "INACTIVE"}

    def stub_put(url, headers, body):
        assert "/groups/rules/rul_TESTID/lifecycle/activate" in url
        return {"status": "ACTIVE"}

    # v9.33 #2 — commit requires a confirm_token from a prior dry-run.
    dry = a.apply_policy(ir, dry_run=True, actor="alice")
    token = dry["confirm_token"]
    result = a.apply_policy(ir, dry_run=False, actor="alice",
                             confirm_token=token,
                             http_post=stub_post, http_put=stub_put)
    assert result["dry_run"] is False
    assert result["error"] is None
    assert result["committed_ids"] == ["rul_TESTID"]


def test_okta_capabilities_declare_write_support():
    from safecadence.platform.adapters.identity_adapters import OktaAdapter
    assert OktaAdapter.capabilities.supports_write is True
    assert "group_rule" in OktaAdapter.capabilities.write_capabilities
