"""
v7.5 — IR → per-system change preview compiler.

Deterministic, no AI. Given a UnifiedPolicyIR, produce the list of
operations each connected identity system would need to perform to
enforce the intent. The Okta operations are real and used by the
write-back path; the other systems return a "deferred" stub so the
preview surface is consistent and the v7.6 work is just filling in
the per-system bodies.

Every operation is JSON-serializable so the preview can be diffed in
the UI, exported to ticket systems, and stored in the audit log
alongside the IR that produced it.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict

from safecadence.identity.ir import UnifiedPolicyIR


@dataclass
class Operation:
    """A single per-system change. UI renders these as a checklist."""
    target: str                                 # 'okta' | 'ise' | 'ad' | 'entra' | 'clearpass'
    op_kind: str                                # 'create_group_rule' | 'update_authz' | ...
    summary: str                                # human-readable one-liner
    payload: dict = field(default_factory=dict)
    deferred: bool = False                      # True until v7.6 ships that adapter
    risk: str = "medium"                        # advisory | low | medium | high | critical


@dataclass
class CompiledPlan:
    """Full preview returned by the compiler."""
    ir: UnifiedPolicyIR
    operations: list[Operation] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def diff(self) -> str:
        """Render a plain-text diff for the CLI / UI preview pane."""
        lines: list[str] = []
        lines.append(f"# Unified policy: {self.ir.intent or '(no intent)'}")
        lines.append(f"#   effect={self.ir.effect}  severity={self.ir.severity}  "
                     f"targets={','.join(self.ir.targets)}")
        if self.ir.subjects.groups:
            lines.append(f"#   groups: {', '.join(self.ir.subjects.groups)}")
        if self.ir.subjects.principals:
            lines.append(f"#   principals: {', '.join(self.ir.subjects.principals)}")
        if self.ir.actions:
            lines.append(f"#   actions: {', '.join(self.ir.actions)}")
        if self.ir.resources.environments:
            lines.append(f"#   environments: {', '.join(self.ir.resources.environments)}")
        if self.ir.conditions:
            lines.append("#   conditions: " + ", ".join(
                f"{'!' if c.negate else ''}{c.kind}" for c in self.ir.conditions))
        lines.append("")
        for op in self.operations:
            mark = "  [deferred]" if op.deferred else ""
            lines.append(f"  * [{op.target}] {op.op_kind}: {op.summary}{mark}")
        if self.warnings:
            lines.append("")
            lines.append("Warnings:")
            for w in self.warnings:
                lines.append(f"  ! {w}")
        return "\n".join(lines)


# ---------------------------------------------------------------- compile

def compile_plan(ir: UnifiedPolicyIR) -> CompiledPlan:
    """Turn an IR into per-system operations."""
    targets = set(ir.targets or ["all"])
    if "all" in targets:
        targets = {"okta", "ise", "ad", "entra", "clearpass"}

    plan = CompiledPlan(ir=ir)

    if "okta" in targets:
        plan.operations.append(_compile_okta(ir))

    if "ise" in targets:
        plan.operations.append(_compile_ise(ir))

    if "ad" in targets:
        plan.operations.append(_compile_ad(ir))

    if "entra" in targets:
        plan.operations.append(_compile_entra(ir))

    if "clearpass" in targets:
        plan.operations.append(_compile_clearpass(ir))

    # Cross-cutting warnings
    if ir.severity == "advisory":
        plan.warnings.append("severity=advisory: changes will not be enforced; "
                              "humans see the recommendation only.")
    if not ir.subjects.groups and not ir.subjects.principals:
        plan.warnings.append("no groups or principals selected — only "
                              "tag/role/nhi_subtype matchers will fire.")

    return plan


# ---------------------------------------------------------------- okta

def _compile_okta(ir: UnifiedPolicyIR) -> Operation:
    """Real Okta operation — used by OktaAdapter.apply_policy.

    For v7.5 we model the IR as an Okta group rule:
      - if effect=deny, the rule places matched users into a quarantine
        group (no app assignments)
      - if effect=allow, the rule places matched users into a group that
        has the relevant app assignment
      - if effect=require_step_up, we mark the rule as a pre-condition
        for an Okta sign-on policy that requires MFA

    The real PUT happens in OktaAdapter.apply_policy; here we just emit
    the operation payload that the adapter will consume.
    """
    rule_name = f"sc-{_slug(ir.intent or 'unified-policy')}"

    expression = _okta_expression(ir)

    if ir.effect == "deny":
        target_group = "SafeCadence-Quarantine"
        summary = (f"create/update Okta group rule '{rule_name}' → moves "
                    f"matched users to {target_group}")
    elif ir.effect == "allow":
        target_group = _okta_allow_group(ir)
        summary = (f"create/update Okta group rule '{rule_name}' → grants "
                    f"membership in {target_group}")
    else:  # require_step_up
        target_group = "SafeCadence-RequiresStepUp"
        summary = (f"create/update Okta group rule '{rule_name}' → requires "
                    f"MFA step-up via {target_group}")

    return Operation(
        target="okta",
        op_kind="upsert_group_rule",
        summary=summary,
        payload={
            "rule_name": rule_name,
            "expression": expression,
            "target_group": target_group,
            "actions": ir.actions,
            "intent": ir.intent,
        },
        deferred=False,
        risk="high" if ir.effect == "deny" else "medium",
    )


def _okta_expression(ir: UnifiedPolicyIR) -> str:
    """Build an Okta Expression Language expression from selectors.

    Okta group-rule expressions support `user.profile.*` matchers and
    `isMemberOfGroupName` / `isMemberOfAnyGroup`. We compose AND-of-OR.
    """
    parts: list[str] = []
    if ir.subjects.groups:
        names = " or ".join(
            f'isMemberOfGroupName("{g}")' for g in ir.subjects.groups)
        parts.append(f"({names})")
    if ir.subjects.principals:
        emails = " or ".join(
            f'user.profile.email == "{p}"' for p in ir.subjects.principals)
        parts.append(f"({emails})")
    if ir.subjects.tags:
        tags = " or ".join(
            f'String.contains(user.profile.tags, "{t}")'
            for t in ir.subjects.tags)
        parts.append(f"({tags})")
    # Conditions translate (where supported)
    for cond in ir.conditions:
        if cond.kind == "mfa_required":
            # Negate semantics: deny + require-MFA → "user has no MFA factor"
            if ir.effect == "deny" and (cond.value is True and not cond.negate):
                parts.append('(user.factor.totp == null and '
                              'user.factor.webauthn == null)')
            else:
                parts.append('(user.factor.totp != null or '
                              'user.factor.webauthn != null)')
    return " and ".join(parts) if parts else "true"


def _okta_allow_group(ir: UnifiedPolicyIR) -> str:
    """Choose the Okta group that grants the requested action."""
    if "ssh" in ir.actions:
        return "SafeCadence-SSH-Allowed"
    if "rdp" in ir.actions:
        return "SafeCadence-RDP-Allowed"
    if "admin" in ir.actions:
        return "SafeCadence-Admin"
    return "SafeCadence-AllowedAccess"


# ---------------------------------------------------------------- ise

def _compile_ise(ir: UnifiedPolicyIR) -> Operation:
    """Cisco ISE — emit ERS authorization rule.

    ISE expects an AuthorizationRule wrapping a condition tree and a
    profile reference. We keep the condition shallow (one AND-of-ORs)
    so v7.6 ships a working contract; richer conditions land in v7.7.
    """
    rule_name = f"sc-{_slug(ir.intent or 'unified-policy')}"
    profile = "DenyAccess" if ir.effect == "deny" else "PermitAccess"
    if ir.effect == "require_step_up":
        profile = "RequireMFA"

    children = []
    for grp in ir.subjects.groups:
        children.append({
            "name": "IdentityGroup",
            "operator": "equals",
            "value": grp,
        })
    for cond in ir.conditions:
        if cond.kind == "mfa_required":
            children.append({
                "name": "MFA-Posture-Compliant",
                "operator": "equals" if not (
                    ir.effect == "deny" and cond.value is True) else "not-equals",
                "value": "true",
            })
        elif cond.kind == "device_trusted":
            children.append({
                "name": "Cert-Issuer",
                "operator": "equals",
                "value": "Internal-CA",
            })

    payload = {
        "AuthorizationRule": {
            "name": rule_name,
            "rule": {
                "conditionType": "ConditionAndBlock",
                "isNegate": False,
                "children": children or [{
                    "name": "Default", "operator": "equals", "value": "*",
                }],
            },
            "profileName": profile,
        }
    }
    return Operation(
        target="ise",
        op_kind="upsert_authz_rule",
        summary=(f"upsert ISE authz rule '{rule_name}' → "
                 f"profile={profile}"),
        payload={"rule_name": rule_name, "profile": profile,
                  "ers_body": payload, "intent": ir.intent},
        deferred=False,
        risk="high" if ir.effect == "deny" else "medium",
    )


# ---------------------------------------------------------------- ad

def _compile_ad(ir: UnifiedPolicyIR) -> Operation:
    """Active Directory — group-membership change via LDAP modify.

    Approach for v7.6:
      * deny  → remove principals from groups in subjects.groups,
                add to a `SafeCadence-Quarantined` group
      * allow → add principals to a `SafeCadence-{Action}-Allowed` group
      * step_up → no-op (AD doesn't enforce step-up; emit a warning)

    AD doesn't natively model 'principal'. We rely on subjects.groups
    being AD groups; for principal-by-email we look up sAMAccountName
    at apply time (handled in the adapter, not the compiler).
    """
    rule_name = f"sc-{_slug(ir.intent or 'unified-policy')}"
    if ir.effect == "deny":
        action_kind = "quarantine"
        target_group = "SafeCadence-Quarantined"
        summary = (f"AD: remove members of "
                    f"{','.join(ir.subjects.groups) or '(none)'} from privileged "
                    f"groups; add to {target_group}")
    elif ir.effect == "allow":
        action_kind = "grant"
        target_group = _ad_allow_group(ir)
        summary = (f"AD: add members of "
                    f"{','.join(ir.subjects.groups) or '(none)'} to {target_group}")
    else:
        action_kind = "advise"
        target_group = ""
        summary = ("AD: step-up not enforceable in AD; emitting advisory "
                    "only — pair with Entra Conditional Access for MFA.")

    return Operation(
        target="ad",
        op_kind="modify_group_membership",
        summary=summary,
        payload={
            "rule_name": rule_name,
            "action_kind": action_kind,
            "source_groups": list(ir.subjects.groups),
            "principals": list(ir.subjects.principals),
            "target_group": target_group,
            "intent": ir.intent,
        },
        deferred=False,
        risk="high" if ir.effect == "deny" else "medium",
    )


def _ad_allow_group(ir: UnifiedPolicyIR) -> str:
    if "ssh" in ir.actions:
        return "SafeCadence-AD-SSH-Allowed"
    if "rdp" in ir.actions:
        return "SafeCadence-AD-RDP-Allowed"
    return "SafeCadence-AD-Allowed"


# ---------------------------------------------------------------- entra

def _compile_entra(ir: UnifiedPolicyIR) -> Operation:
    """Entra ID — Conditional Access policy via Microsoft Graph.

    Compiles the IR into a CA policy JSON body shaped for
    PATCH /v1.0/identity/conditionalAccess/policies/{id}
    (or POST to .../policies for create).
    """
    rule_name = f"sc-{_slug(ir.intent or 'unified-policy')}"
    state = "enabled" if ir.severity == "enforce" else "enabledForReportingButNotEnforced"

    grant_controls: dict
    if ir.effect == "deny":
        grant_controls = {"operator": "OR", "builtInControls": ["block"]}
    elif ir.effect == "require_step_up":
        grant_controls = {"operator": "AND",
                           "builtInControls": ["mfa", "compliantDevice"]}
    else:
        grant_controls = {"operator": "OR", "builtInControls": []}
        # Allow: model as exclusion in the deny side; here we just emit
        # a permissive policy.

    conditions: dict = {
        "users": {
            "includeGroups": list(ir.subjects.groups) or ["All"],
            "excludeUsers": list(ir.subjects.exclude_principals),
        },
        "applications": {"includeApplications": ["All"]},
    }
    if any(c.kind == "device_trusted" and not c.negate for c in ir.conditions):
        conditions["devices"] = {
            "deviceFilter": {"mode": "include",
                              "rule": "device.trustType -eq \"AzureAD\""},
        }

    payload = {
        "displayName": rule_name,
        "state": state,
        "conditions": conditions,
        "grantControls": grant_controls,
    }
    return Operation(
        target="entra",
        op_kind="upsert_ca_policy",
        summary=(f"upsert Entra CA policy '{rule_name}' "
                 f"(state={state}, effect={ir.effect})"),
        payload={"rule_name": rule_name, "ca_body": payload,
                  "intent": ir.intent},
        deferred=False,
        risk="high" if ir.effect == "deny" else "medium",
    )


# ---------------------------------------------------------------- clearpass

def _compile_clearpass(ir: UnifiedPolicyIR) -> Operation:
    """HPE Aruba ClearPass — enforcement-profile + enforcement-policy.

    ClearPass enforcement is two-tier: profiles describe what to do
    (e.g. assign VLAN, deny), policies describe when to apply which
    profile. We emit one of each; the adapter POSTs them in order.
    """
    rule_name = f"sc-{_slug(ir.intent or 'unified-policy')}"
    if ir.effect == "deny":
        profile_action = "RADIUS:Reject"
    elif ir.effect == "require_step_up":
        profile_action = "RADIUS:IETF-Filter:[Quarantine-VLAN]"
    else:
        profile_action = "RADIUS:IETF-Filter:[Production-VLAN]"

    profile_body = {
        "name": f"{rule_name}-profile",
        "description": ir.intent or "",
        "type": "RADIUS",
        "action": profile_action,
    }
    policy_body = {
        "name": rule_name,
        "description": ir.intent or "",
        "enforcement_type": "RADIUS",
        "default_enforcement_profile": f"{rule_name}-profile",
        "rules": [{
            "match_type": "ALL",
            "conditions": [
                {"type": "Tips:Role", "name": grp, "operator": "EQUALS",
                  "value": grp}
                for grp in ir.subjects.groups
            ] or [{"type": "Tips:Role", "name": "Any",
                    "operator": "EQUALS", "value": "Any"}],
            "enforcement_profile_names": [f"{rule_name}-profile"],
        }],
    }
    return Operation(
        target="clearpass",
        op_kind="upsert_enforcement",
        summary=(f"upsert ClearPass enforcement '{rule_name}' "
                 f"(action={profile_action})"),
        payload={
            "rule_name": rule_name,
            "profile_body": profile_body,
            "policy_body": policy_body,
            "intent": ir.intent,
        },
        deferred=False,
        risk="high" if ir.effect == "deny" else "medium",
    )


# ---------------------------------------------------------------- helpers

def _stub(target: str, op_kind: str, summary: str) -> Operation:
    return Operation(
        target=target, op_kind=op_kind, summary=summary,
        deferred=True, risk="medium",
    )


def _slug(text: str) -> str:
    """Stable, URL-safe slug from intent text. Caps length."""
    import re
    s = re.sub(r"[^a-zA-Z0-9]+", "-", (text or "").strip().lower()).strip("-")
    return (s or "policy")[:48]
