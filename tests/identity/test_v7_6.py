"""
v7.6 — write-back for ISE/AD/Entra/ClearPass + identity attack-path
edges + JIT + conflict resolution.

All HTTP / LDAP stubbed via the test seams baked into the mixin.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from safecadence.identity.ir import validate_ir
from safecadence.identity.compiler import compile_plan
from safecadence.identity.attack_paths import compute_identity_paths
from safecadence.identity.jit import (
    expire_due, grant, grant_to_ir, list_grants, revoke,
)
from safecadence.identity.conflict_resolution import (
    ConflictPolicy, PrecedenceRule, load_policy, resolve_conflict,
    _default_policy,
)
from safecadence.identity.ir import Decision, Rule


# ---------------------------------------------------------------- helpers


def _ir_deny_ssh_for(group: str, target_list: list[str]) -> object:
    return validate_ir({
        "intent": f"deny ssh for {group}",
        "effect": "deny", "actions": ["ssh"],
        "subjects": {"groups": [group]},
        "resources": {"environments": ["prod"]},
        "targets": target_list,
        "conditions": [{"kind": "mfa_required", "value": True}],
    })


# ---------------------------------------------------------------- compiler


def test_compile_plan_emits_real_ops_for_all_5_targets():
    ir = _ir_deny_ssh_for("Contractors", ["all"])
    plan = compile_plan(ir)
    targets = sorted(o.target for o in plan.operations)
    assert targets == ["ad", "clearpass", "entra", "ise", "okta"]
    assert all(o.deferred is False for o in plan.operations)


def test_ise_op_has_ers_body_with_authz_rule():
    ir = _ir_deny_ssh_for("Contractors", ["ise"])
    plan = compile_plan(ir)
    ise_op = next(o for o in plan.operations if o.target == "ise")
    body = ise_op.payload["ers_body"]
    assert "AuthorizationRule" in body
    assert body["AuthorizationRule"]["profileName"] == "DenyAccess"
    assert ise_op.payload["rule_name"].startswith("sc-")


def test_entra_op_has_ca_policy_with_block_grant_control():
    ir = _ir_deny_ssh_for("Contractors", ["entra"])
    plan = compile_plan(ir)
    op = next(o for o in plan.operations if o.target == "entra")
    body = op.payload["ca_body"]
    assert body["state"] == "enabled"
    assert "block" in body["grantControls"]["builtInControls"]


def test_ad_op_targets_quarantine_group_when_deny():
    ir = _ir_deny_ssh_for("Contractors", ["ad"])
    plan = compile_plan(ir)
    op = next(o for o in plan.operations if o.target == "ad")
    assert op.payload["target_group"] == "SafeCadence-Quarantined"
    assert op.payload["action_kind"] == "quarantine"


def test_clearpass_op_has_profile_and_policy_bodies():
    ir = _ir_deny_ssh_for("Contractors", ["clearpass"])
    plan = compile_plan(ir)
    op = next(o for o in plan.operations if o.target == "clearpass")
    assert "profile_body" in op.payload
    assert "policy_body" in op.payload
    assert op.payload["profile_body"]["action"] == "RADIUS:Reject"


# ---------------------------------------------------------------- write-back


def test_ise_apply_dry_run_makes_no_http_calls():
    from safecadence.platform.adapters.identity_adapters import CiscoISEAdapter
    a = CiscoISEAdapter(target="ise.example", credentials={"username": "x", "password": "y"})
    calls: list = []

    def fail_post(*args, **kwargs):
        calls.append(args); raise RuntimeError("no")

    r = a.apply_policy(_ir_deny_ssh_for("Contractors", ["ise"]),
                        dry_run=True, http_post=fail_post)
    assert r["dry_run"] is True
    assert r["error"] is None
    assert calls == []


def test_ise_apply_commit_calls_http_post():
    from safecadence.platform.adapters.identity_adapters import CiscoISEAdapter
    a = CiscoISEAdapter(target="ise.example",
                         credentials={"username": "x", "password": "y"})

    def stub_post(url, headers, body):
        assert "/config/authorization" in url
        assert "AuthorizationRule" in body
        return {"id": "ise-rule-42"}

    ir = _ir_deny_ssh_for("Contractors", ["ise"])
    token = a.apply_policy(ir, dry_run=True, actor="t")["confirm_token"]
    r = a.apply_policy(ir, dry_run=False, actor="t",
                        confirm_token=token, http_post=stub_post)
    assert r["error"] is None
    assert r["committed_ids"] == ["ise-rule-42"]


def test_clearpass_apply_creates_profile_and_policy():
    from safecadence.platform.adapters.identity_adapters import HPEClearPassAdapter
    a = HPEClearPassAdapter(target="cp.example",
                             credentials={"client_id": "x", "client_secret": "y"})
    posts: list = []

    def stub_post(url, headers, body):
        posts.append(url)
        return {"id": "cp-" + str(len(posts))}

    ir = _ir_deny_ssh_for("Contractors", ["clearpass"])
    token = a.apply_policy(ir, dry_run=True, actor="t")["confirm_token"]
    r = a.apply_policy(ir, dry_run=False, actor="t",
                        confirm_token=token, http_post=stub_post)
    assert r["error"] is None
    assert len(r["committed_ids"]) == 2
    assert any("/enforcement-profile" in u for u in posts)
    assert any("/enforcement-policy" in u for u in posts)


def test_ad_apply_calls_ldap_modify_for_quarantine():
    from safecadence.platform.adapters.identity_adapters import ActiveDirectoryAdapter
    a = ActiveDirectoryAdapter(target="ldap://ad.example",
                                credentials={"bind_dn": "x", "bind_password": "y",
                                              "base_dn": "DC=corp,DC=local"})
    modifies: list = []

    def stub_modify(dn, changes):
        modifies.append((dn, changes))

    # We pass an explicit principal so the test doesn't depend on AD search
    ir = validate_ir({
        "intent": "deny ssh for one user",
        "effect": "deny", "actions": ["ssh"],
        "subjects": {"principals": ["CN=alice,OU=Contractors,DC=corp,DC=local"]},
        "targets": ["ad"],
    })
    token = a.apply_policy(ir, dry_run=True, actor="t")["confirm_token"]
    r = a.apply_policy(ir, dry_run=False, actor="t",
                        confirm_token=token, ldap_modify=stub_modify)
    assert r["error"] is None
    assert len(modifies) >= 1
    assert any("alice" in m[0] or "alice" in str(m[1]) for m in modifies)


def test_entra_apply_dry_run_skips_token_fetch():
    from safecadence.platform.adapters.identity_adapters import EntraIDAdapter
    # Missing creds — would fail token fetch on commit, but dry_run
    # should not even try.
    a = EntraIDAdapter(target="tenant.onmicrosoft.com",
                        credentials={"tenant_id": "", "client_id": "",
                                      "client_secret": ""})
    r = a.apply_policy(_ir_deny_ssh_for("Contractors", ["entra"]),
                        dry_run=True)
    assert r["dry_run"] is True
    assert r["error"] is None
    assert r["operations"][0]["op_kind"] == "upsert_ca_policy"


# ---------------------------------------------------------------- attack paths


def test_compute_identity_paths_finds_human_to_crown_jewel():
    assets = [
        {
            "identity": {"asset_id": "alice", "asset_type": "identity"},
            "identity_block": {
                "group_memberships": {"alice@x": ["BuildEngineers"]},
            },
        },
        {
            "identity": {"asset_id": "build-bot", "asset_type": "identity"},
            "nhi": {"nhi_id": "build-bot", "subtype": "service_account",
                    "owner_principal": "BuildEngineers",
                    "can_impersonate": ["AdminRole"]},
        },
        {
            "identity": {"asset_id": "prod-db",
                         "asset_type": "server", "criticality": "crown-jewel"},
            "identity_block": {"authorized_groups": ["AdminRole"]},
        },
    ]
    paths = compute_identity_paths(assets)
    assert paths, "expected at least one identity attack path"
    top = paths[0]
    assert "build-bot" in top.chain_summary()
    assert top.terminal_asset == "prod-db"
    assert top.risk_score > 0


def test_compute_identity_paths_returns_empty_on_no_edges():
    assert compute_identity_paths([]) == []


def test_compute_identity_paths_marks_crown_jewel_reason():
    assets = [
        {
            "identity": {"asset_id": "alice"},
            "identity_block": {
                "group_memberships": {"alice@x": ["Admins"]},
            },
        },
        {
            "identity": {"asset_id": "db",
                         "criticality": "crown-jewel"},
            "identity_block": {"authorized_groups": ["Admins"]},
        },
    ]
    paths = compute_identity_paths(assets)
    assert paths
    assert any("crown-jewel" in r for r in paths[0].reasons)


# ---------------------------------------------------------------- JIT


def test_jit_grant_persists_and_lists(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_JIT_STORE", str(tmp_path / "jit.json"))
    g = grant(principal="alice@x", action="ssh", resource="srv-1",
               duration_seconds=300, target="okta", created_by="test")
    assert g.grant_id.startswith("jit_")
    assert g.expires_at > time.time()
    assert g.status == "active"

    grants = list_grants()
    assert len(grants) == 1
    assert grants[0].grant_id == g.grant_id


def test_jit_grant_rejects_zero_duration(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_JIT_STORE", str(tmp_path / "jit.json"))
    with pytest.raises(ValueError):
        grant(principal="x", action="ssh", resource="r",
               duration_seconds=0, target="okta")


def test_jit_grant_rejects_too_long(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_JIT_STORE", str(tmp_path / "jit.json"))
    with pytest.raises(ValueError):
        grant(principal="x", action="ssh", resource="r",
               duration_seconds=86400 * 30, target="okta")


def test_jit_expire_due_marks_expired(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_JIT_STORE", str(tmp_path / "jit.json"))
    base = time.time()
    g1 = grant(principal="a", action="ssh", resource="r",
                duration_seconds=60, target="okta", now=base - 3600)
    g2 = grant(principal="b", action="ssh", resource="r",
                duration_seconds=86400, target="okta", now=base)
    expired = expire_due(now=base + 1)
    assert any(g.grant_id == g1.grant_id for g in expired)
    assert all(g.grant_id != g2.grant_id for g in expired)


def test_jit_grant_to_ir_produces_advisory_allow(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_JIT_STORE", str(tmp_path / "jit.json"))
    g = grant(principal="a@x", action="ssh", resource="srv-1",
               duration_seconds=60, target="okta")
    ir = grant_to_ir(g)
    assert ir.effect == "allow"
    assert ir.severity == "advisory"
    assert ir.subjects.principals == ["a@x"]


def test_jit_revoke_marks_revoked(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_JIT_STORE", str(tmp_path / "jit.json"))
    g = grant(principal="a", action="ssh", resource="r",
               duration_seconds=60, target="okta")
    rv = revoke(g.grant_id)
    assert rv is not None
    assert rv.status == "revoked"
    after = list_grants()
    assert after[0].status == "revoked"


# ---------------------------------------------------------------- conflict


def _decision(allowed: bool, system: str, rule_name: str = "r") -> Decision:
    return Decision(
        allowed=allowed,
        chain=[Rule(system=system, rule_id="x", rule_name=rule_name,
                     effect="allow" if allowed else "deny",
                     matched_on=[])],
        systems_consulted=[system],
        reasons=[f"{system} says {'allow' if allowed else 'deny'}"],
        principal="alice", action="ssh", resource="prod-db",
    )


def test_resolve_conflict_unanimous_collapses_cleanly():
    decs = {
        "okta": _decision(True, "okta"),
        "ad": _decision(True, "ad"),
    }
    out = resolve_conflict(decs, policy=_default_policy())
    assert out.allowed is True
    assert "unanimous" in " ".join(out.reasons).lower()


def test_resolve_conflict_disagreement_human_default_fails_closed():
    pol = ConflictPolicy(rules=[], default_winner="human")
    decs = {
        "okta": _decision(True, "okta"),
        "ad": _decision(False, "ad"),
    }
    out = resolve_conflict(decs, policy=pol)
    assert out.allowed is False
    assert any("human" in r for r in out.reasons)


def test_resolve_conflict_specific_winner_applied():
    pol = ConflictPolicy(rules=[
        PrecedenceRule(winner="ad", when_systems=["ad", "okta"]),
    ], default_winner="human")
    decs = {
        "okta": _decision(True, "okta"),
        "ad": _decision(False, "ad"),
    }
    out = resolve_conflict(decs, policy=pol)
    assert out.allowed is False  # AD wins, AD says deny
    assert any("ad" in r.lower() for r in out.reasons)


def test_resolve_conflict_winner_not_in_decisions_fails_closed():
    pol = ConflictPolicy(rules=[
        PrecedenceRule(winner="ise", when_systems=["okta", "ad"]),
    ], default_winner="human")
    decs = {
        "okta": _decision(True, "okta"),
        "ad": _decision(False, "ad"),
    }
    out = resolve_conflict(decs, policy=pol)
    assert out.allowed is False


def test_default_policy_has_safe_defaults():
    pol = _default_policy()
    assert pol.default_winner == "human"
    assert any(r.winner == "ad" for r in pol.rules)
