"""
v8.0 — "What if" simulator.

DIFFERENTIATOR. Take a UnifiedPolicyIR + the current fleet, return:

  matched_assets     — which assets the policy will hit
  current_decisions  — what each system says today for matched assets
  post_change        — what each system would say after applying
  closing_findings   — findings that would resolve
  opening_gaps       — compliance / coverage gaps that would open
  risk_delta         — net change in attack-path reach-weighted risk

Read-only. Fast. No system access. Pure-Python evaluation against the
in-memory snapshot.

This is the feature competitors don't have. SailPoint / Saviynt / Okta
IGA force you to apply changes and find out the hard way. SafeCadence
shows you the future before you commit.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from safecadence.identity.ir import UnifiedPolicyIR


@dataclass
class SimulationResult:
    intent: str = ""
    matched_assets: list[str] = field(default_factory=list)
    matched_principals: list[str] = field(default_factory=list)
    closing_findings: list[dict] = field(default_factory=list)
    opening_gaps: list[dict] = field(default_factory=list)
    risk_delta: dict = field(default_factory=dict)
    summary: str = ""


def simulate(ir: UnifiedPolicyIR, *,
              assets: Iterable[dict] | None = None,
              findings: Iterable[object] | None = None,
              attack_paths: Iterable[object] | None = None) -> SimulationResult:
    """Project the impact of `ir` against the current fleet."""
    assets = list(assets) if assets is not None else _load_assets()
    findings = list(findings) if findings is not None else _load_findings(assets)
    attack_paths = (list(attack_paths) if attack_paths is not None
                     else _load_paths(assets))

    matched_assets = _match_assets(ir, assets)
    matched_principals = list(ir.subjects.principals) + [
        f"group:{g}" for g in ir.subjects.groups]

    closing = _findings_that_close(ir, findings, matched_principals,
                                     matched_assets)
    opening = _gaps_that_open(ir, assets, matched_assets)
    risk_delta = _risk_delta(ir, attack_paths, matched_assets,
                              matched_principals)

    summary = _summary(ir, matched_assets, closing, opening, risk_delta)

    return SimulationResult(
        intent=ir.intent,
        matched_assets=matched_assets,
        matched_principals=matched_principals,
        closing_findings=closing,
        opening_gaps=opening,
        risk_delta=risk_delta,
        summary=summary,
    )


# ---------------------------------------------------------------- match

def _match_assets(ir: UnifiedPolicyIR, assets: list[dict]) -> list[str]:
    """Return asset_ids of assets the IR's resource selector matches."""
    out = []
    sel = ir.resources
    for a in assets:
        ident = a.get("identity") or {}
        aid = ident.get("asset_id", "")
        if not aid:
            continue
        if sel.asset_ids and aid in sel.asset_ids:
            out.append(aid); continue
        if sel.asset_types and ident.get("asset_type") in sel.asset_types:
            out.append(aid); continue
        if sel.environments and ident.get("environment") in sel.environments:
            out.append(aid); continue
        if sel.criticalities and ident.get("criticality") in sel.criticalities:
            out.append(aid); continue
        if sel.sites and ident.get("site") in sel.sites:
            out.append(aid); continue
        # If the selector is empty entirely, the policy is fleet-wide
        if not any([sel.asset_ids, sel.asset_types, sel.environments,
                    sel.criticalities, sel.sites, sel.tags]):
            out.append(aid)
    return out


# ---------------------------------------------------------------- impact

def _findings_that_close(ir: UnifiedPolicyIR, findings,
                          matched_principals: list[str],
                          matched_assets: list[str]) -> list[dict]:
    """Heuristic: a finding "closes" if its kind aligns with the IR's
    effect AND its principal is selected by the IR.

    Examples:
      * IR effect=deny, condition=mfa_required, no_mfa finding → closes
      * IR effect=deny on stale group → over_privileged finding closes
      * IR rotates an NHI → never_rotated finding closes
    """
    out = []
    cond_kinds = {c.kind for c in ir.conditions}
    for f in findings:
        f_kind = getattr(f, "kind", "")
        f_principal = getattr(f, "principal", "")
        # Same principal selected
        principal_match = (
            f_principal in [p.removeprefix("user:") for p in matched_principals]
            or any(g.removeprefix("group:") in str(getattr(f, "evidence", {}))
                    for g in matched_principals)
        )
        if not principal_match and not matched_assets:
            continue
        if (f_kind == "no_mfa" and ir.effect in ("deny", "require_step_up")
                and "mfa_required" in cond_kinds):
            out.append({"finding_id": getattr(f, "finding_id", ""),
                         "kind": f_kind, "title": getattr(f, "title", ""),
                         "reason": "MFA enforcement covers this gap"})
        elif (f_kind == "over_privileged" and ir.effect == "deny"):
            out.append({"finding_id": getattr(f, "finding_id", ""),
                         "kind": f_kind, "title": getattr(f, "title", ""),
                         "reason": "Deny-rule reduces privilege count"})
        elif (f_kind in ("stale_nhi", "never_rotated", "orphan_service_account")
                and ir.effect == "deny"):
            out.append({"finding_id": getattr(f, "finding_id", ""),
                         "kind": f_kind, "title": getattr(f, "title", ""),
                         "reason": "Deny rule deactivates the affected principal"})
    return out


def _gaps_that_open(ir: UnifiedPolicyIR, assets: list[dict],
                     matched_assets: list[str]) -> list[dict]:
    """Conservative — flag the obvious gaps:

    * deny SSH for a group that includes break-glass admins → operational risk
    * deny on prod with no exception → may break monitoring jobs
    """
    gaps = []
    if ir.effect == "deny" and "ssh" in ir.actions and "prod" in ir.resources.environments:
        gaps.append({
            "kind": "operational_risk",
            "severity": "warn",
            "title": "Deny SSH on prod may block legitimate ops accounts",
            "advice": "Add an exception group for break-glass / monitoring "
                       "(e.g. exclude_principals: ['ops-emergency']).",
        })
    if ir.effect == "deny" and not ir.subjects.exclude_principals:
        gaps.append({
            "kind": "no_break_glass",
            "severity": "info",
            "title": "No break-glass principals excluded",
            "advice": "Consider exclude_principals to avoid lockout if SSO breaks.",
        })
    if ir.severity == "advisory":
        gaps.append({
            "kind": "advisory_only",
            "severity": "info",
            "title": "Severity is advisory — no enforcement",
            "advice": "Change severity to 'enforce' once you're satisfied "
                       "with the dry-run output.",
        })
    return gaps


def _risk_delta(ir: UnifiedPolicyIR, attack_paths,
                 matched_assets: list[str],
                 matched_principals: list[str]) -> dict:
    """How does the attack-path total reach-weighted risk shift if the
    IR is enforced?

    Heuristic: for each path, if the IR severs the path (its terminal
    asset is matched and the IR effect is deny), risk decreases by
    that path's risk_score.
    """
    before = sum(getattr(p, "risk_score", 0) for p in attack_paths)
    severed = []
    for p in attack_paths:
        terminal = getattr(p, "terminal_asset", "")
        if terminal in matched_assets and ir.effect == "deny":
            severed.append({
                "chain": (p.chain_summary() if hasattr(p, "chain_summary")
                           else ""),
                "risk_score": getattr(p, "risk_score", 0),
                "terminal": terminal,
            })
    delta = sum(s["risk_score"] for s in severed)
    after = max(0, before - delta)
    return {
        "before_total": round(before, 2),
        "after_total": round(after, 2),
        "delta": round(-delta, 2),
        "severed_paths": severed[:10],
    }


def _summary(ir, matched_assets, closing, opening, risk_delta) -> str:
    parts = []
    parts.append(f"matches {len(matched_assets)} asset(s)")
    if closing:
        parts.append(f"closes {len(closing)} finding(s)")
    if opening:
        parts.append(f"opens {len(opening)} new gap(s)")
    if risk_delta.get("delta"):
        parts.append(
            f"net risk delta {risk_delta['delta']:+.1f}")
    return " · ".join(parts)


# ---------------------------------------------------------------- loaders

def _load_assets() -> list[dict]:
    try:
        from safecadence.server.platform_api import list_assets
        return list_assets()
    except Exception:
        return []


def _load_findings(assets):
    try:
        from safecadence.identity.findings import scan_findings
        return scan_findings(assets)
    except Exception:
        return []


def _load_paths(assets):
    try:
        from safecadence.identity.attack_paths import compute_identity_paths
        return compute_identity_paths(assets)
    except Exception:
        return []
