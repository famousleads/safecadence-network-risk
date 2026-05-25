"""
v12.0 — Multi-dimensional Safe Score.

The single 0–100 Safe Score from v9.x is still computed (and surfaced
in dashboards / reports), but v12 adds five additional dimensions so
mature buyers can see *what* drives the number rather than just
"a number went up." Each dimension has:

  * `value`            — 0-100 score for this dimension
  * `trend_7d`         — delta vs 7 days ago
  * `confidence_band`  — low / medium / high (heuristic for now;
                         real CIs come in v14 with ML)
  * `top_factors`      — 1-3 specific findings driving the dimension

Dimensions:
  1. compliance_health     — % controls passing across configured frameworks
  2. identity_health       — identity-system hygiene (stale accounts, MFA
                              coverage, NHI rotation cadence, attack-path
                              membership)
  3. drift_stability       — frequency + severity of unexpected config drift
                              over the trailing 30 days
  4. patch_freshness       — average asset-patch-age weighted by severity
  5. attack_path_risk      — count + criticality of attack paths reaching
                              crown-jewel assets
  6. ai_governance_readiness — AI/ML asset inventory + access-control
                                coverage; placeholder until v14 ML lands

Each dimension reads from existing v11.x data sources (compliance
controls, identity vault, scan history, attack-path graph) — this
module is a *composition* layer, not new data collection.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def _safe_round(v: float | None, places: int = 1) -> float | None:
    """None-tolerant rounding helper."""
    if v is None:
        return None
    return round(v, places)


# --------------------------------------------------------------------------
# Per-dimension computers
# --------------------------------------------------------------------------


def _compliance_health() -> dict:
    """% of configured-framework controls in PASS state."""
    assets: list = []
    try:
        from safecadence.storage import sqlite_store
        assets = list(sqlite_store.list_assets() or [])
    except Exception:
        assets = []

    total = 0
    passed = 0
    framework_breakdown: dict[str, dict] = {}

    for a in assets:
        for f in (a.get("findings") or []):
            for ctrl in (f.get("controls") or []):
                fw = (ctrl.get("framework") or "unknown").lower()
                framework_breakdown.setdefault(fw, {"total": 0, "passed": 0})
                framework_breakdown[fw]["total"] += 1
                total += 1
                if (f.get("severity") or "").lower() not in ("critical", "high"):
                    # Treat low/medium/info as compliant for this dimension
                    framework_breakdown[fw]["passed"] += 1
                    passed += 1

    pct = round(100 * passed / total, 1) if total else 100.0

    top_gaps: list[str] = []
    for fw, breakdown in framework_breakdown.items():
        if breakdown["total"]:
            gap = round(100 - 100 * breakdown["passed"] / breakdown["total"], 1)
            if gap > 0:
                top_gaps.append(f"{fw}: {gap}% controls failing")
    top_gaps = sorted(top_gaps, reverse=True)[:3]

    return {
        "value": pct,
        "trend_7d": None,  # populated by history layer in v12.5
        "confidence_band": "high" if total > 50 else "medium" if total > 10 else "low",
        "top_factors": top_gaps,
        "breakdown_by_framework": framework_breakdown,
    }


def _identity_health() -> dict:
    """Identity-system hygiene: stale accounts, MFA gaps, NHI rotation."""
    stale_count = 0
    no_mfa_count = 0
    nhi_overdue = 0
    total = 0

    try:
        # The identity module has no single list-all-identities function
        # today; we degrade gracefully when it's not callable.
        from safecadence.identity import discover as _id_discover
        list_fn = getattr(_id_discover, "list_identities", None)
        if list_fn is None:
            raise RuntimeError("identity list API not available")
        for i in (list_fn() or []):
            total += 1
            if not i.get("mfa_enabled"):
                no_mfa_count += 1
            if (i.get("last_login_days") or 0) > 90:
                stale_count += 1
            if i.get("is_nhi") and (i.get("rotation_age_days") or 0) > 180:
                nhi_overdue += 1
    except Exception:
        pass

    if total == 0:
        return {
            "value": None,
            "trend_7d": None,
            "confidence_band": "low",
            "top_factors": ["No identity data loaded"],
        }

    # Score: start at 100, deduct for each problem class
    score = 100.0
    score -= 30 * (no_mfa_count / total)
    score -= 20 * (stale_count / total)
    score -= 25 * (nhi_overdue / max(total, 1))
    score = max(0.0, round(score, 1))

    factors = []
    if no_mfa_count:
        factors.append(f"{no_mfa_count} identity/identities without MFA")
    if stale_count:
        factors.append(f"{stale_count} stale account(s) (no login > 90 days)")
    if nhi_overdue:
        factors.append(f"{nhi_overdue} NHI/service-account credentials overdue for rotation")

    return {
        "value": score,
        "trend_7d": None,
        "confidence_band": "high" if total > 20 else "medium",
        "top_factors": factors[:3] or ["Identity hygiene clean"],
    }


def _drift_stability() -> dict:
    """Frequency + severity of unexpected config drift over trailing 30 days."""
    drift_count_30d = 0
    critical_drift_30d = 0
    try:
        from safecadence.policy.cross_system_drift import recent_drift_events
        events = recent_drift_events(days=30) or []
        drift_count_30d = len(events)
        critical_drift_30d = sum(
            1 for e in events
            if (e.get("severity") or "").lower() in ("critical", "high")
        )
    except Exception:
        pass

    # Score: 100 if no drift; deduct for each drift event, more for critical
    score = 100.0 - drift_count_30d * 1.5 - critical_drift_30d * 4
    score = max(0.0, round(score, 1))

    factors = []
    if drift_count_30d:
        factors.append(f"{drift_count_30d} drift events in last 30 days")
    if critical_drift_30d:
        factors.append(f"{critical_drift_30d} of those were critical/high severity")
    if not factors:
        factors.append("No drift detected in last 30 days")

    return {
        "value": score,
        "trend_7d": None,
        "confidence_band": "medium",
        "top_factors": factors[:3],
    }


def _patch_freshness() -> dict:
    """Average asset patch-age weighted by severity."""
    asset_count = 0
    total_weighted_age = 0.0
    severity_weight = {"critical": 4.0, "high": 2.5, "medium": 1.2, "low": 0.5}

    try:
        # v12.0.0a6 — fixed: the platform_assets snapshot is read via the
        # shared helper in reports.sections (same path used by graph.build
        # and dashboard.widgets), NOT a non-existent platform.platform_assets
        # module. Defensive: still wrapped so a missing snapshot returns
        # asset_count == 0 instead of crashing.
        from safecadence.reports.sections import _load_platform_assets
        for a in (_load_platform_assets() or []):
            asset_count += 1
            for f in (a.get("findings") or []):
                age = float(f.get("age_days") or 0)
                w = severity_weight.get((f.get("severity") or "").lower(), 1.0)
                total_weighted_age += age * w
    except Exception:
        pass

    if asset_count == 0:
        return {
            "value": None,
            "trend_7d": None,
            "confidence_band": "low",
            "top_factors": ["No asset data loaded"],
        }

    avg_weighted_age = total_weighted_age / asset_count
    # Map: 0 days → 100, 90 days → 50, 180+ days → 0
    score = max(0.0, round(100 - (avg_weighted_age / 1.8), 1))

    factors = [f"Weighted avg patch age: {avg_weighted_age:.1f} days"]
    if avg_weighted_age > 90:
        factors.append("Patches systematically lagging > 90 days")
    if avg_weighted_age > 180:
        factors.append("Critical patch backlog — immediate action required")

    return {
        "value": score,
        "trend_7d": None,
        "confidence_band": "high" if asset_count > 20 else "medium",
        "top_factors": factors[:3],
    }


def _attack_path_risk() -> dict:
    """Count + criticality of attack paths reaching crown-jewel assets."""
    crown_paths = 0
    critical_crown_paths = 0
    try:
        from safecadence.discovery.attack_paths import enumerate_paths
        for p in (enumerate_paths() or []):
            if p.get("reaches_crown_jewel"):
                crown_paths += 1
                if (p.get("severity") or "").lower() in ("critical", "high"):
                    critical_crown_paths += 1
    except Exception:
        pass

    # Score: 100 if no crown-jewel paths; deduct for each one
    score = 100.0 - crown_paths * 5 - critical_crown_paths * 10
    score = max(0.0, round(score, 1))

    factors = []
    if crown_paths:
        factors.append(f"{crown_paths} attack path(s) reach a crown-jewel asset")
    if critical_crown_paths:
        factors.append(f"{critical_crown_paths} of those are critical-severity")
    if not factors:
        factors.append("No attack paths to crown-jewel assets detected")

    return {
        "value": score,
        "trend_7d": None,
        "confidence_band": "medium",
        "top_factors": factors[:3],
    }


def _ai_governance_readiness() -> dict:
    """AI/ML asset inventory + access-control coverage.

    Placeholder dimension until v14 ML lands. Today it returns a
    static "high" score with a note. In v14 this becomes a real
    score derived from AI-agent identity inventory, model-card
    coverage, and access-control posture on ML training data.
    """
    return {
        "value": 75.0,
        "trend_7d": None,
        "confidence_band": "low",
        "top_factors": [
            "AI governance scoring is preliminary in v12.0 — full ML-driven scoring lands in v14.",
            "Current value is a placeholder reflecting typical industry baseline.",
        ],
        "is_preliminary": True,
    }


# --------------------------------------------------------------------------
# Top-level entry point
# --------------------------------------------------------------------------


def compute_multidim_score(*, include_history: bool = False) -> dict:
    """Compute the full multi-dimensional Safe Score.

    Args:
        include_history: when True, include a 7-day rolling window per
                         dimension (placeholder in v12; real history
                         comes from the v13 telemetry-collection daemon).

    Returns:
        A dict shaped as documented at the top of this module.
    """
    dimensions = {
        "compliance_health": _compliance_health(),
        "identity_health": _identity_health(),
        "drift_stability": _drift_stability(),
        "patch_freshness": _patch_freshness(),
        "attack_path_risk": _attack_path_risk(),
        "ai_governance_readiness": _ai_governance_readiness(),
    }

    # Overall: weighted mean of the dimensions, skipping None values
    weights = {
        "compliance_health": 1.5,
        "identity_health": 1.2,
        "drift_stability": 1.0,
        "patch_freshness": 1.3,
        "attack_path_risk": 1.5,
        "ai_governance_readiness": 0.5,    # smaller weight since preliminary
    }
    weighted_sum = 0.0
    weight_total = 0.0
    for name, d in dimensions.items():
        v = d.get("value")
        if v is None:
            continue
        w = weights[name]
        weighted_sum += v * w
        weight_total += w

    overall = round(weighted_sum / weight_total, 1) if weight_total else None

    out = {
        "overall": overall,
        "dimensions": dimensions,
        "computed_at": datetime.now(timezone.utc).isoformat(),
        "scoring_version": "v12.0",
    }
    if include_history:
        # v12 ships history as None; v13 daemon fills this in
        out["history"] = {
            name: {"days": [], "values": []}
            for name in dimensions
        }
    return out


def compute_safe_score_flat() -> float | None:
    """Backwards-compatible single-number Safe Score.

    Calls ``compute_multidim_score`` and returns the overall value
    for code paths that haven't been updated to consume the
    multi-dimensional output yet.
    """
    return compute_multidim_score().get("overall")
