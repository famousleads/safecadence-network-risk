"""
Multi-environment policy variants — helpers for setting / removing
per-environment overrides on a policy.

Stored on SecurityPolicy.environment_variants as
    {env_name: {control_id: {param_overrides}}}

The evaluator + translators consume these via control_for_asset().
"""

from __future__ import annotations

from typing import Any

from safecadence.policy.audit import log as audit_log
from safecadence.policy.schema import SecurityPolicy
from safecadence.policy.store import get, save


def set_variant(policy_id: str, *, environment: str, control_id: str,
                parameters: dict[str, Any], actor: str = "system") -> SecurityPolicy:
    p = get(policy_id)
    if not p:
        raise KeyError(f"policy not found: {policy_id}")
    env = environment.lower()
    p.environment_variants = dict(p.environment_variants or {})
    p.environment_variants.setdefault(env, {})[control_id] = parameters
    save(p, actor=actor)
    audit_log("variant_set", actor=actor, policy_id=policy_id,
              detail={"env": env, "control_id": control_id, "params": parameters})
    return p


def remove_variant(policy_id: str, *, environment: str, control_id: str,
                   actor: str = "system") -> bool:
    p = get(policy_id)
    if not p:
        return False
    env = environment.lower()
    if env in (p.environment_variants or {}) and control_id in p.environment_variants[env]:
        del p.environment_variants[env][control_id]
        if not p.environment_variants[env]:
            del p.environment_variants[env]
        save(p, actor=actor)
        audit_log("variant_removed", actor=actor, policy_id=policy_id,
                  detail={"env": env, "control_id": control_id})
        return True
    return False
