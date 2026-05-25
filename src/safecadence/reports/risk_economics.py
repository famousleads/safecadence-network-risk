"""
v12.0 — Risk Economics translation layer.

Every finding has a technical impact (severity, CVSS, attack path
membership). Risk Economics translates those into business-language
metrics that CISOs, CFOs, and boards budget against:

  * Estimated audit-failure exposure ($)
  * Estimated remediation cost ($)
  * Risk-reduction ROI per action (risk pts removed / hours of effort)
  * Technical debt score (cumulative weight of stale findings)
  * Operational risk velocity (rate of new findings per week)
  * Compliance burn-down rate (controls moving toward compliant)

All formulas use industry-standard rules of thumb (PCI/HIPAA fine
schedules, average breach-cost figures from Verizon DBIR / IBM Cost
of a Data Breach Report 2025), tuned for SafeCadence's typical
buyer profile (MSPs serving 5–500-person regulated customers).

The dollar figures are *order-of-magnitude estimates* — they're meant
to anchor business conversation, not to be quoted to insurance
adjusters. The report copy says so explicitly.
"""
from __future__ import annotations

from typing import Any


# --------------------------------------------------------------------------
# Industry constants (sourced from public IBM / Verizon / regulator data)
# --------------------------------------------------------------------------

# Average per-finding fine exposure by regulator (USD, 2025 figures)
REGULATOR_FINE_PER_FINDING = {
    "pci-dss-v4":   2500,    # PCI fines $5k-$100k/month for non-compliance
    "hipaa":        7500,    # HIPAA Tier 2 = $1k-$50k per violation
    "soc2":         0,       # SOC 2 doesn't have direct fines but blocks deals
    "nist-800-53":  0,       # internal compliance, no direct fine
    "cis-v8":       0,       # framework, no direct fine
    "cmmc-l2":     12000,    # DoD contract loss; using avg deal-loss estimate
    "gdpr":        45000,    # GDPR Article 32 — up to 2% of annual revenue
    "fedramp":     30000,    # contract-pause cost average
}

# Average deal-loss cost when SOC 2 readiness blocks a customer deal
SOC2_DEAL_BLOCK_COST = 75000

# Per-severity remediation cost (USD, includes engineer time + change-mgmt overhead)
REMEDIATION_COST_PER_SEVERITY = {
    "critical":  4500,
    "high":      2000,
    "medium":     800,
    "low":        200,
}

# Per-severity remediation effort in hours (single engineer)
REMEDIATION_HOURS_PER_SEVERITY = {
    "critical":  16,
    "high":       6,
    "medium":     2.5,
    "low":        0.5,
}

# Risk-point weight per severity. Bias toward critical/high so the ROI
# ranking (points / hours) doesn't degenerate into "the easiest finding
# wins" — what mature buyers actually want is "fix the critical stuff
# first even when it costs more hours." Scaled to make critical > high >
# medium > low *after* dividing by their per-severity remediation hours.
RISK_POINTS_PER_SEVERITY = {
    "critical": 100,
    "high":      35,
    "medium":     8,
    "low":        1,
}


# --------------------------------------------------------------------------
# Per-metric computers
# --------------------------------------------------------------------------


def estimated_audit_exposure(findings: list[dict], frameworks: list[str]) -> dict:
    """Estimate cumulative $ audit-failure exposure across configured frameworks.

    Args:
        findings: list of finding dicts (with `severity` + `controls`).
        frameworks: list of framework slugs the customer is being audited
                    against (e.g. ["soc2", "pci-dss-v4"]).

    Returns:
        {
            "total_exposure_usd": int,
            "by_framework": {"<fw>": {"finding_count": int, "exposure_usd": int}, ...},
            "deal_block_risk_usd": int,
        }
    """
    by_framework: dict[str, dict] = {}
    total = 0

    for f in findings or []:
        sev = (f.get("severity") or "").lower()
        if sev not in ("critical", "high"):
            continue  # only counted findings escalate audit risk
        for ctrl in (f.get("controls") or []):
            fw = (ctrl.get("framework") or "").lower()
            if frameworks and fw not in frameworks:
                continue
            fine = REGULATOR_FINE_PER_FINDING.get(fw, 0)
            if fine == 0:
                continue
            by_framework.setdefault(fw, {"finding_count": 0, "exposure_usd": 0})
            by_framework[fw]["finding_count"] += 1
            by_framework[fw]["exposure_usd"] += fine
            total += fine

    # SOC 2 doesn't have direct fines but blocks deals — surface separately
    deal_block = 0
    if "soc2" in [f.lower() for f in (frameworks or [])]:
        crit_high = sum(
            1 for f in (findings or [])
            if (f.get("severity") or "").lower() in ("critical", "high")
        )
        if crit_high > 5:
            # Estimate one deal-block per ~5 unresolved critical/high findings
            deal_block = (crit_high // 5) * SOC2_DEAL_BLOCK_COST

    return {
        "total_exposure_usd": total,
        "by_framework": by_framework,
        "deal_block_risk_usd": deal_block,
        "combined_exposure_usd": total + deal_block,
    }


def estimated_remediation_cost(findings: list[dict]) -> dict:
    """Estimate cumulative remediation cost in dollars + engineer-hours."""
    cost_usd = 0
    hours = 0.0
    by_severity: dict[str, dict] = {}

    for f in findings or []:
        sev = (f.get("severity") or "").lower()
        if sev not in REMEDIATION_COST_PER_SEVERITY:
            continue
        cost_usd += REMEDIATION_COST_PER_SEVERITY[sev]
        hours += REMEDIATION_HOURS_PER_SEVERITY[sev]
        by_severity.setdefault(sev, {"count": 0, "cost_usd": 0, "hours": 0.0})
        by_severity[sev]["count"] += 1
        by_severity[sev]["cost_usd"] += REMEDIATION_COST_PER_SEVERITY[sev]
        by_severity[sev]["hours"] += REMEDIATION_HOURS_PER_SEVERITY[sev]

    return {
        "total_cost_usd": cost_usd,
        "total_hours": round(hours, 1),
        "by_severity": by_severity,
    }


def risk_reduction_roi(findings: list[dict], top_n: int = 10) -> list[dict]:
    """Rank findings by (risk_points_removed / hours_of_effort).

    Returns the top N highest-ROI remediation actions for the action plan.
    """
    scored: list[dict] = []

    for f in findings or []:
        sev = (f.get("severity") or "").lower()
        if sev not in RISK_POINTS_PER_SEVERITY:
            continue
        risk_pts = RISK_POINTS_PER_SEVERITY[sev]
        hours = REMEDIATION_HOURS_PER_SEVERITY[sev]
        if hours <= 0:
            continue
        roi = round(risk_pts / hours, 2)
        scored.append({
            "finding_id": f.get("id") or f.get("rule_id"),
            "title": f.get("title"),
            "host": f.get("host") or f.get("hostname"),
            "severity": sev,
            "risk_points_removed": risk_pts,
            "estimated_hours": hours,
            "roi": roi,
            "cost_usd": REMEDIATION_COST_PER_SEVERITY[sev],
        })

    scored.sort(key=lambda x: x["roi"], reverse=True)
    return scored[:top_n]


def technical_debt_score(findings: list[dict]) -> dict:
    """Cumulative weight of stale findings (age > 90 days).

    Returns a 0-100 score where 100 = no stale findings, 0 = massive
    pile of unresolved age. Also returns absolute counts so the report
    can show "47 findings older than 90 days, 12 older than 180 days."
    """
    total = 0
    stale_90 = 0
    stale_180 = 0
    weighted_debt = 0.0

    for f in findings or []:
        total += 1
        age = float(f.get("age_days") or 0)
        sev = (f.get("severity") or "").lower()
        w = RISK_POINTS_PER_SEVERITY.get(sev, 1)
        if age > 90:
            stale_90 += 1
            weighted_debt += w
        if age > 180:
            stale_180 += 1
            weighted_debt += w  # doubles up for very stale items

    # Score: 100 - weighted_debt scaled to 0-100
    score = max(0.0, round(100 - weighted_debt / 5, 1))
    return {
        "score": score,
        "total_findings": total,
        "stale_over_90d": stale_90,
        "stale_over_180d": stale_180,
        "weighted_debt_points": round(weighted_debt, 1),
    }


def operational_risk_velocity(scan_history: list[dict]) -> dict:
    """Rate of new findings per week over the trailing 4 weeks.

    Args:
        scan_history: list of scan-result dicts with `timestamp` and
                      `findings_count`.

    Returns:
        {
            "current_week_new": int,
            "trailing_4wk_avg": float,
            "trend": "increasing" | "decreasing" | "stable",
        }
    """
    if not scan_history or len(scan_history) < 2:
        return {
            "current_week_new": None,
            "trailing_4wk_avg": None,
            "trend": "insufficient-data",
        }

    # Sort by timestamp ascending
    sorted_history = sorted(
        scan_history, key=lambda s: s.get("timestamp") or ""
    )
    deltas = []
    for i in range(1, len(sorted_history)):
        prev = sorted_history[i - 1].get("findings_count") or 0
        curr = sorted_history[i].get("findings_count") or 0
        deltas.append(max(0, curr - prev))  # only count new findings

    current = deltas[-1] if deltas else 0
    avg = round(sum(deltas) / len(deltas), 1) if deltas else 0

    if current > avg * 1.3:
        trend = "increasing"
    elif current < avg * 0.7:
        trend = "decreasing"
    else:
        trend = "stable"

    return {
        "current_week_new": current,
        "trailing_4wk_avg": avg,
        "trend": trend,
    }


def compliance_burn_down(framework_status: dict) -> dict:
    """Estimate weeks until 95% compliance at current remediation rate.

    Args:
        framework_status: per-framework dict with `passed`, `failed`,
                          and optionally `passed_this_week` keys.

    Returns:
        Per-framework projection of weeks-to-95%.
    """
    out: dict[str, dict] = {}
    for fw, status in (framework_status or {}).items():
        passed = status.get("passed") or 0
        failed = status.get("failed") or 0
        total = passed + failed
        if total == 0:
            out[fw] = {"weeks_to_95_pct": None, "current_pct": None}
            continue
        current_pct = round(100 * passed / total, 1)
        target_count = int(0.95 * total)
        need_to_pass = max(0, target_count - passed)

        weekly_rate = status.get("passed_this_week") or 0
        if need_to_pass == 0:
            weeks = 0
        elif weekly_rate <= 0:
            weeks = None  # insufficient data; show as ⏳
        else:
            weeks = round(need_to_pass / weekly_rate, 1)

        out[fw] = {
            "current_pct": current_pct,
            "target_pct": 95.0,
            "weeks_to_target": weeks,
        }
    return out


# --------------------------------------------------------------------------
# Top-level entry for the reports module
# --------------------------------------------------------------------------


def compute_risk_economics(
    findings: list[dict],
    *,
    frameworks: list[str] | None = None,
    scan_history: list[dict] | None = None,
    framework_status: dict | None = None,
) -> dict:
    """Compute the full Risk Economics block for inclusion in a report.

    All inputs are optional — missing inputs degrade gracefully to
    "Insufficient data" placeholders rather than zeros (zeros would
    falsely imply "everything is fine").
    """
    out: dict = {
        "estimated_audit_exposure": estimated_audit_exposure(
            findings or [], frameworks or []
        ),
        "estimated_remediation_cost": estimated_remediation_cost(findings or []),
        "risk_reduction_roi_top10": risk_reduction_roi(findings or [], top_n=10),
        "technical_debt_score": technical_debt_score(findings or []),
        "disclaimer": (
            "Dollar figures are order-of-magnitude business estimates "
            "based on published 2025 industry data (IBM Cost of a Data "
            "Breach Report; Verizon DBIR; HIPAA Tier 2 schedules; PCI "
            "non-compliance fines). They are NOT a substitute for "
            "professional risk-quantification or insurance underwriting."
        ),
    }
    if scan_history is not None:
        out["operational_risk_velocity"] = operational_risk_velocity(scan_history)
    if framework_status is not None:
        out["compliance_burn_down"] = compliance_burn_down(framework_status)
    return out
