"""
v6.2 — Control suggestion engine.

Powers the Policy Builder wizard's "AI-suggested controls" step. Given:
  - asset_types (network/server/storage/cloud/...)
  - compliance frameworks (nist/cis/pci/hipaa/iso/zero-trust)
  - strictness (basic / standard / paranoid)

…returns a ranked list of controls with rationale. Pure-Python reasoner
(no external AI required) but the returned controls play nicely with the
existing AI interpreter for richer output.
"""

from __future__ import annotations

from typing import Any

from safecadence.policy.controls import all_controls
from safecadence.policy.frameworks import load_mappings


# Strictness band → severities to include
_STRICTNESS_SEV = {
    "basic":     {"critical"},
    "standard":  {"critical", "high"},
    "paranoid":  {"critical", "high", "medium", "low"},
}


def _matches_framework(control_frameworks: list[str], wanted: set[str]) -> bool:
    if not wanted:
        return True
    return any(any(w in fw.lower() for w in wanted) for fw in control_frameworks)


def suggest_controls(asset_types: list[str], frameworks: list[str],
                     strictness: str = "standard") -> dict[str, Any]:
    """Return suggested controls with rationale."""
    asset_types = [t.lower() for t in (asset_types or [])]
    wanted_fw = {f.lower().replace("-", "").replace("_", "")
                  for f in (frameworks or [])}
    sev_band = _STRICTNESS_SEV.get(strictness.lower(),
                                    _STRICTNESS_SEV["standard"])
    fw_map = load_mappings()

    suggested: list[dict] = []
    for spec in all_controls():
        # Asset-type filter — if user said "network" only, skip server-only controls
        if asset_types and not any(t in spec.applies_to for t in asset_types):
            continue
        # Severity filter
        if spec.severity.value not in sev_band:
            continue
        # Framework filter — control must satisfy at least one wanted framework
        # (substring match: "nist" matches "nist-800-53", "nist80053", etc.)
        ctrl_fws = []
        for fw, refs in (fw_map.get(spec.id) or {}).items():
            ctrl_fws.append(fw.lower().replace("-", "").replace("_", ""))
        if wanted_fw:
            framework_match = any(
                wanted in cf for wanted in wanted_fw for cf in ctrl_fws
            )
        else:
            framework_match = True
        if not framework_match:
            continue

        # Build a per-control rationale
        why_parts = [f"applies to {', '.join(spec.applies_to)}",
                      f"severity: {spec.severity.value}"]
        if wanted_fw:
            matching_fws = sorted(set(ctrl_fws) & wanted_fw) or ['—']
            why_parts.append(f"satisfies: {', '.join(matching_fws)}")

        suggested.append({
            "id": spec.id,
            "description": spec.description,
            "applies_to": spec.applies_to,
            "severity": spec.severity.value,
            "frameworks": spec.frameworks,
            "rationale": " · ".join(why_parts),
            "selected": True,    # default: enable everything we suggest
        })

    # Sort: critical first, then high, etc.
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    suggested.sort(key=lambda c: (sev_order.get(c["severity"], 9), c["id"]))

    return {
        "asset_types": asset_types,
        "frameworks": frameworks,
        "strictness": strictness,
        "control_count": len(suggested),
        "controls": suggested,
        "summary": (f"{len(suggested)} controls suggested for "
                    f"{len(asset_types) or 'all'} asset types matching "
                    f"{len(frameworks) or 'no'} frameworks at {strictness} strictness."),
    }


def preview_impact(control_ids: list[str], parameters: dict[str, dict],
                   assets: list[dict]) -> dict[str, Any]:
    """Live "what would this catch" preview.

    Builds a synthetic SecurityPolicy from the chosen controls + parameters,
    runs the evaluator against the current fleet, returns aggregate counts
    + the top 10 violations as a sample.
    """
    from safecadence.policy.controls import get_control
    from safecadence.policy.evaluator import evaluate
    from safecadence.policy.schema import (
        EnforcementMode, PolicyControl, SecurityPolicy, Severity,
    )

    controls: list[PolicyControl] = []
    asset_types_covered: set[str] = set()
    for cid in (control_ids or []):
        spec = get_control(cid)
        if not spec:
            continue
        asset_types_covered.update(spec.applies_to)
        controls.append(PolicyControl(
            control_id=cid,
            description=spec.description,
            parameters=(parameters or {}).get(cid, {}),
            severity=spec.severity,
            framework_refs=spec.frameworks,
        ))

    if not controls:
        return {"control_count": 0, "applicable_assets": 0,
                "would_pass": 0, "would_fail": 0, "would_be_na": 0,
                "by_severity": {}, "violations": [],
                "summary": "No controls selected — pick at least one."}

    syn = SecurityPolicy(
        policy_id="(preview)", policy_name="(preview)",
        controls=controls, severity=Severity.MEDIUM,
        enforcement_mode=EnforcementMode.OBSERVE,
        target_asset_types=sorted(asset_types_covered),
    )
    ev = evaluate(syn, assets)

    by_sev: dict[str, int] = {}
    for v in ev.violations:
        sev = v.severity.value if hasattr(v.severity, "value") else v.severity
        by_sev[sev] = by_sev.get(sev, 0) + 1

    sample = sorted(
        ev.violations,
        key=lambda v: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
            v.severity.value if hasattr(v.severity, "value") else v.severity, 9))[:10]

    return {
        "control_count": len(controls),
        "asset_count": len(assets),
        "applicable_assets": len(ev.asset_results),
        "would_pass": ev.pass_count,
        "would_fail": ev.fail_count,
        "would_be_na": ev.na_count,
        "by_severity": by_sev,
        "violations": [{
            "asset_id": v.asset_id, "control_id": v.control_id,
            "severity": v.severity.value if hasattr(v.severity, "value") else v.severity,
            "evidence": v.evidence,
        } for v in sample],
        "summary": (
            f"Against your {len(assets)} assets: "
            f"{ev.pass_count} would pass, "
            f"{ev.fail_count} would FAIL, "
            f"{ev.na_count} not applicable. "
            f"Top severities: {by_sev}."),
    }
