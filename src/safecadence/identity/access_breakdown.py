"""
v9.40 — Per-principal asset breakdown for /access.

The v7.5 ``decide()`` resolver answers "can principal X do action Y on
resource Z right now?" — one decision at a time. That works for the
detail view but it's the wrong shape for the question a security
operator asks most:

    "Show me everything alice@acme can reach, and which systems grant
    each permission, so I can prove least-privilege at audit time."

This module composes per-asset chains by replaying ``decide()`` against
every (asset, action) pair in the fleet for a single principal, then
groups by asset and lists the systems that contributed each granted
action. The output is the JSON shape ``/api/identity/access`` returns.

Trust property: this is read-only. We never write back, never request
elevation, never call out to a real IdP. The breakdown reflects the
policies declared by the connected systems; nothing else.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from safecadence.identity.effective_permissions import (
    decide, rules_from_assets,
)


# Default actions to probe per asset. The "right" set is asset-type
# specific; we cover the security-relevant verbs that map to the
# multi-vendor translators we ship.
DEFAULT_ACTIONS = ("ssh", "rdp", "console", "https", "snmp", "api")

# Asset types we probe. Other types (printers, IoT, etc.) get the
# default action set but rarely have meaningful identity rules; skip
# the noise by default.
PROBE_TYPES = (
    "server", "network", "firewall", "loadbalancer",
    "database", "container_host", "endpoint",
)


@dataclass
class AssetGrant:
    """One asset, the actions a principal can perform on it, and the
    chain of declared rules + systems that contributed each grant."""
    asset_id: str
    hostname: str
    asset_type: str
    environment: str
    criticality: str
    site: str
    actions_allowed: list[str] = field(default_factory=list)
    actions_denied: list[str] = field(default_factory=list)
    actions_step_up: list[str] = field(default_factory=list)
    granted_by_systems: list[str] = field(default_factory=list)
    chain: list[dict] = field(default_factory=list)

    def to_json(self) -> dict:
        return {
            "asset_id": self.asset_id,
            "hostname": self.hostname,
            "asset_type": self.asset_type,
            "environment": self.environment,
            "criticality": self.criticality,
            "site": self.site,
            "actions_allowed": sorted(self.actions_allowed),
            "actions_denied": sorted(self.actions_denied),
            "actions_step_up": sorted(self.actions_step_up),
            "granted_by_systems": sorted(set(self.granted_by_systems)),
            "chain": self.chain,
        }


def breakdown_for_principal(
    *, principal: str,
    assets: Iterable[dict],
    principal_groups: list[str] | None = None,
    actions: tuple[str, ...] = DEFAULT_ACTIONS,
    context: dict | None = None,
    only_granted: bool = False,
    asset_types: tuple[str, ...] | None = PROBE_TYPES,
) -> dict:
    """Build the per-principal breakdown.

    Parameters
    ----------
    principal
        e.g. ``"alice@acme"`` or ``"svc-jenkins"``.
    assets
        The fleet snapshot — the same dicts ``decide()`` consumes.
    principal_groups
        Group memberships the IdP would tell us about, e.g.
        ``["group:Contractors"]``. Without this, group rules don't
        match — and most IdPs grant by group, so the operator should
        pass them in.
    actions
        Which verbs to probe per asset. Default set covers SSH/RDP/
        console/HTTPS/SNMP/API which spans the multi-vendor translator
        coverage.
    context
        Resolver context (mfa, posture_compliant, device_trusted).
        Defaults to all-False so step-up rules surface as ``step_up``
        rather than being hand-waved into ``allowed``.
    only_granted
        If True, the response excludes assets where the principal can
        do nothing. Defaults to False so the auditor can see "no
        access" assets too — that's the proof of least-privilege.
    asset_types
        Restrict the probe to these asset types. ``None`` means probe
        every asset.

    Returns
    -------
    {
      "principal": str,
      "groups": [str],
      "actions_probed": [str],
      "summary": {
        "assets_total": int,
        "assets_with_any_grant": int,
        "actions_granted": int,
        "systems_seen": [str],
      },
      "grants": [AssetGrant.to_json(), ...],
    }
    """
    assets_list = list(assets or [])
    rules = rules_from_assets(assets_list)
    ctx = dict(context or {})
    groups = list(principal_groups or [])
    actions = tuple(actions)

    grants: list[AssetGrant] = []
    systems_seen: set[str] = set()
    actions_granted = 0

    for a in assets_list:
        ident = (a.get("identity") or {}) if isinstance(a, dict) else {}
        atype = (ident.get("asset_type") or "").lower()
        if asset_types is not None and atype not in asset_types:
            continue
        aid = ident.get("asset_id") or ident.get("hostname") or ""
        if not aid:
            continue
        resource_attrs = {
            "asset_type": atype,
            "env": ident.get("environment", ""),
            "criticality": ident.get("criticality", ""),
            "site": ident.get("site", ""),
        }
        grant = AssetGrant(
            asset_id=str(aid),
            hostname=ident.get("hostname", "") or str(aid),
            asset_type=atype,
            environment=ident.get("environment", ""),
            criticality=ident.get("criticality", ""),
            site=ident.get("site", ""),
        )
        seen_chain: list[dict] = []
        for action in actions:
            d = decide(
                principal, action, str(aid),
                context=ctx, rules=rules,
                principal_groups=groups,
                resource_attrs=resource_attrs,
            )
            for sys in (d.systems_consulted or []):
                systems_seen.add(sys)
            if d.allowed and d.requires_step_up:
                grant.actions_step_up.append(action)
            elif d.allowed:
                grant.actions_allowed.append(action)
                actions_granted += 1
                for r in (d.chain or []):
                    if r.effect == "allow":
                        grant.granted_by_systems.append(r.system)
            else:
                grant.actions_denied.append(action)
            # Keep one chain per (action, effect) pair for the UI to
            # render — capped to avoid blowing up the response on
            # huge fleets.
            if len(seen_chain) < 24:
                for r in (d.chain or [])[:2]:
                    seen_chain.append({
                        "action": action,
                        "system": r.system,
                        "rule_name": r.rule_name,
                        "effect": r.effect,
                        "matched_on": r.matched_on,
                    })
        grant.chain = seen_chain

        if only_granted and not grant.actions_allowed and not grant.actions_step_up:
            continue
        grants.append(grant)

    grants_with_any = sum(
        1 for g in grants
        if g.actions_allowed or g.actions_step_up
    )
    return {
        "principal": principal,
        "groups": groups,
        "actions_probed": list(actions),
        "summary": {
            "assets_total": len(grants),
            "assets_with_any_grant": grants_with_any,
            "actions_granted": actions_granted,
            "systems_seen": sorted(systems_seen),
        },
        "grants": [g.to_json() for g in grants],
    }
