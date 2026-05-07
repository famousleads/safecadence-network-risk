"""
v7.5 — Effective-permission resolver.

Answers "given everything the connected identity systems declare,
can principal X do action Y on resource Z right now?" — and shows
its work, rule by rule.

Pure-Python. Operates on the existing platform store snapshot
(UnifiedAsset graph). No I/O. Order of precedence:

  1. Most-specific deny wins (highest-priority deny rule that matches)
  2. Most-specific allow next
  3. Default deny

Step-up (require_step_up) is treated like allow if the caller's
context already satisfies the step-up requirement, otherwise like
deny with `requires_step_up=True` so the UI can prompt for MFA.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from safecadence.identity.ir import Decision, Rule


# ---------------------------------------------------------------- types

@dataclass
class _DeclaredRule:
    """An adapter-emitted rule pulled from a UnifiedAsset's identity_block.

    Adapters that surface identity policy populate this when they collect.
    For v7.5 we work off the asset graph directly; in v7.6 we'll cache
    these in a dedicated table for sub-second resolver latency.
    """
    system: str
    rule_id: str
    rule_name: str
    effect: str                                 # allow | deny | step_up
    principals: list[str]                       # ['group:Contractors', 'user:alice@x']
    resources: list[str]                        # ['asset_type:server', 'env:prod']
    actions: list[str]                          # ['ssh', 'rdp', '*']
    conditions: list[str]                       # ['mfa_required']
    priority: int = 100                         # lower = more specific


# ---------------------------------------------------------------- public api

def decide(principal: str, action: str, resource: str, *,
           context: dict | None = None,
           rules: Iterable[_DeclaredRule] | None = None,
           principal_groups: list[str] | None = None,
           resource_attrs: dict | None = None,
           precedence_policy=None) -> Decision:
    """Compose declared rules across all connected identity systems.

    Inputs
    ------
    principal       e.g. 'alice@contractor.com' or 'nhi:build-bot-prod'
    action          e.g. 'ssh' / 'http' / 'admin'
    resource        e.g. asset_id 'srv-prod-db-01'
    context         dict with current MFA / posture / time. Optional.
                    keys: mfa, posture_compliant, device_trusted, risk_score,
                          session_age_seconds
    rules           iterable of _DeclaredRule. If not given, an empty list is
                    used (callers who haven't loaded rules get default-deny).
    principal_groups  groups the principal is in (transitive). Caller resolves.
    resource_attrs    {'asset_type': 'server', 'env': 'prod', 'criticality': ...}
    """
    ctx = context or {}
    pg = principal_groups or []
    ra = resource_attrs or {}
    rules_list = list(rules or [])

    matched: list[tuple[_DeclaredRule, list[str]]] = []
    for rule in rules_list:
        match_evidence = _match(rule, principal, pg, action, resource, ra)
        if match_evidence is not None:
            matched.append((rule, match_evidence))

    # Most-specific deny wins
    matched.sort(key=lambda r: (_effect_rank(r[0].effect), r[0].priority))

    chain: list[Rule] = []
    final_effect = "deny"
    requires_step_up = False
    reasons: list[str] = []

    for rule, evidence in matched:
        chain.append(Rule(
            system=rule.system, rule_id=rule.rule_id,
            rule_name=rule.rule_name, effect=rule.effect,
            matched_on=evidence,
        ))
        # First matched rule (after sort) decides — but keep the chain so
        # callers can show all rules that fired, not just the deciding one.
        if final_effect == "deny" and not chain[:-1]:
            final_effect = rule.effect
            reasons.append(f"{rule.system}/{rule.rule_name}: {rule.effect}")

    # Conditions on the deciding rule
    if matched:
        deciding = matched[0][0]
        for cond in deciding.conditions:
            satisfied = _condition_satisfied(cond, ctx)
            if not satisfied:
                if final_effect == "allow":
                    final_effect = "step_up"
                    requires_step_up = True
                    reasons.append(f"condition not met: {cond}")

    if final_effect == "deny" and not matched:
        reasons.append("default deny: no matching rule")
        systems_consulted = sorted({r.system for r in rules_list})
    else:
        systems_consulted = sorted({r.system for r in rules_list})

    base_decision = Decision(
        allowed=(final_effect == "allow"),
        chain=chain,
        systems_consulted=systems_consulted,
        reasons=reasons or [f"effective: {final_effect}"],
        requires_step_up=requires_step_up,
        principal=principal,
        action=action,
        resource=resource,
    )

    # v7.8 — if multiple systems were consulted AND the caller passed a
    # precedence policy AND systems disagree, hand off to the conflict
    # resolver so AD-wins-on-prod / human-escalation rules actually fire.
    if precedence_policy is not None and len(systems_consulted) > 1:
        per_sys = _split_chain_by_system(chain, principal, action, resource)
        # Only invoke conflict resolution if systems actually disagree
        if len({d.allowed for d in per_sys.values()}) > 1:
            from safecadence.identity.conflict_resolution import resolve_conflict
            return resolve_conflict(
                per_sys, policy=precedence_policy,
                action=action,
                environment=(resource_attrs or {}).get("env", ""),
            )

    return base_decision


def _split_chain_by_system(chain: list[Rule], principal: str,
                            action: str, resource: str) -> dict[str, Decision]:
    """Helper for conflict-resolution hand-off — group rules by system
    and synthesize a per-system Decision. Used so resolve_conflict()
    can apply the precedence policy."""
    by_sys: dict[str, list[Rule]] = {}
    for r in chain:
        by_sys.setdefault(r.system, []).append(r)
    out: dict[str, Decision] = {}
    for sys_, rules in by_sys.items():
        deciding = rules[0]   # first matched rule of that system
        out[sys_] = Decision(
            allowed=(deciding.effect == "allow"),
            chain=rules,
            systems_consulted=[sys_],
            reasons=[f"{sys_}/{deciding.rule_name}: {deciding.effect}"],
            requires_step_up=(deciding.effect == "step_up"),
            principal=principal, action=action, resource=resource,
        )
    return out


# ---------------------------------------------------------------- internals

def _effect_rank(effect: str) -> int:
    # deny first (lowest), then step_up, then allow
    return {"deny": 0, "step_up": 1, "allow": 2}.get(effect, 99)


def _match(rule: _DeclaredRule, principal: str, principal_groups: list[str],
           action: str, resource: str, resource_attrs: dict) -> list[str] | None:
    """Return list of match-evidence strings, or None if rule does not match."""
    evidence: list[str] = []

    # Principal: explicit user match OR group match OR wildcard
    p_matched = False
    for p in rule.principals:
        if p == "*":
            p_matched = True
            evidence.append("principal:*")
            break
        if p.startswith("user:") and p.split(":", 1)[1] == principal:
            p_matched = True
            evidence.append(p)
            break
        if p.startswith("group:") and p.split(":", 1)[1] in principal_groups:
            p_matched = True
            evidence.append(p)
            break
    if not p_matched:
        return None

    # Action: exact or wildcard
    if "*" not in rule.actions and action not in rule.actions:
        return None
    evidence.append(f"action:{action}")

    # Resource: explicit asset id, or attribute match (asset_type:server, env:prod, ...)
    r_matched = False
    for r in rule.resources:
        if r == "*" or r == resource:
            r_matched = True
            evidence.append(r)
            break
        if ":" in r:
            k, v = r.split(":", 1)
            if str(resource_attrs.get(k, "")) == v:
                r_matched = True
                evidence.append(r)
                break
    if not r_matched:
        return None

    return evidence


def _condition_satisfied(cond: str, ctx: dict) -> bool:
    """Tiny condition language for v7.5. Extend as needed.

    Recognized:
      mfa_required        ctx['mfa']                 must be truthy
      posture_compliant   ctx['posture_compliant']   must be truthy
      device_trusted      ctx['device_trusted']      must be truthy
    """
    if cond == "mfa_required":
        return bool(ctx.get("mfa"))
    if cond == "posture_compliant":
        return bool(ctx.get("posture_compliant"))
    if cond == "device_trusted":
        return bool(ctx.get("device_trusted"))
    # Unknown condition: be conservative — treat as not satisfied
    return False


# ---------------------------------------------------------------- bridge

def rules_from_assets(assets: Iterable[dict]) -> list[_DeclaredRule]:
    """Pull declared rules out of the platform store's UnifiedAsset dicts.

    For v7.5 we take a forgiving approach: each asset's identity_block can
    optionally carry a `declared_rules` list (the v6 adapters don't yet
    populate this — that's part of the v7.6 adapter retrofit). When absent,
    we synthesize a minimal rule from `active_authz_rule` so existing
    fixtures still produce a non-empty resolver chain.
    """
    out: list[_DeclaredRule] = []
    for a in assets:
        ib = (a.get("identity_block") or {}) if isinstance(a, dict) else {}
        provider = ib.get("provider") or "unknown"
        for r in (ib.get("declared_rules") or []):
            out.append(_DeclaredRule(
                system=r.get("system", provider),
                rule_id=str(r.get("rule_id", "")),
                rule_name=r.get("rule_name", ""),
                effect=r.get("effect", "deny"),
                principals=list(r.get("principals", [])),
                resources=list(r.get("resources", [])),
                actions=list(r.get("actions", [])),
                conditions=list(r.get("conditions", [])),
                priority=int(r.get("priority", 100)),
            ))
        # Backwards-compat synth from v6 fields
        if ib.get("active_authz_rule") and not (ib.get("declared_rules") or []):
            out.append(_DeclaredRule(
                system=provider,
                rule_id=ib.get("active_authz_rule", ""),
                rule_name=ib.get("active_authz_rule", ""),
                effect="allow" if ib.get("mfa_enrolled") else "step_up",
                principals=["*"],
                resources=["*"],
                actions=["*"],
                conditions=["mfa_required"] if not ib.get("mfa_enrolled") else [],
                priority=200,
            ))
    return out
