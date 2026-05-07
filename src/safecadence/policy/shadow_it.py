"""
Shadow IT detection — assets present in the platform inventory but
covered by no policy.

Reads the existing platform asset store (~/.safecadence/platform_assets/)
and the local policy store (~/.safecadence/policies/) and returns the
set of assets that no active policy targets.
"""

from __future__ import annotations

from typing import Any

from safecadence.policy.store import list_policies, get
from safecadence.policy.schema import SecurityPolicy, PolicyState


def _load_active_policies() -> list[SecurityPolicy]:
    out = []
    for meta in list_policies():
        # Only count Approved + Review + Draft policies — Deprecated are excluded
        if meta.get("state") == PolicyState.DEPRECATED.value:
            continue
        p = get(meta.get("policy_id"))
        if p:
            out.append(p)
    return out


def find_shadow_assets(assets: list[dict]) -> list[dict]:
    """Return every asset that NO active policy applies to."""
    policies = _load_active_policies()
    if not policies:
        # If there are no policies at all, every asset is shadow.
        return [_summary(a, reason="no_policies_defined") for a in assets]
    out: list[dict] = []
    for a in assets:
        if not any(p.applies_to(a) for p in policies):
            out.append(_summary(a, reason="no_policy_targets"))
    return out


def _summary(asset: dict, *, reason: str) -> dict[str, Any]:
    ident = asset.get("identity") or {}
    return {
        "asset_id": ident.get("asset_id"),
        "vendor": ident.get("vendor"),
        "asset_type": ident.get("asset_type"),
        "hostname": ident.get("hostname"),
        "environment": ident.get("environment"),
        "reason": reason,
    }
