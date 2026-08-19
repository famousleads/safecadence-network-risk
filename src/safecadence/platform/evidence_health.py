"""
Evidence Infrastructure Health (DESAT) — the one question that matters
to a public-safety agency's evidence chain:

    Is the infrastructure needed to CAPTURE, TRANSFER, STORE, ACCESS and
    PRESERVE digital evidence operational, secure and healthy?

This module is deliberately an ASSEMBLY of signals NetRisk already
collects — asset health scores, storage capacity + replication, backup
RPO staleness + immutability, CVE/KEV exposure, weak protocols — grouped
by evidence-chain stage. It monitors the infrastructure UNDER evidence
platforms; it does not touch, ingest, or store evidentiary content.

Pure functions over stored-asset dicts (the ``asdict(UnifiedAsset)``
shape) so it is testable without a store and honest when data is absent:
a stage with no participating assets reports "unknown", never "healthy".
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

# Evidence-chain stages, in chain order.
STAGES: tuple[str, ...] = ("capture", "transfer", "store", "access", "preserve")

# Thresholds — conservative, explainable.
_CAPACITY_WARN_PCT = 85.0
_CAPACITY_CRIT_PCT = 95.0
_HEALTH_WARN_SCORE = 70


def _g(d: dict | None, *path: str, default: Any = None) -> Any:
    cur: Any = d or {}
    for key in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(key)
    return default if cur is None else cur


def _asset_stages(asset: dict) -> list[str]:
    """Which evidence-chain stages this asset participates in.

    Sources, in order:
      1. ``public_safety.evidence_roles`` (set by classification)
      2. operator tags — ``evidence`` (= all stages) or ``evidence:store``
    """
    roles = list(_g(asset, "public_safety", "evidence_roles", default=[]) or [])
    tags = [str(t).lower() for t in (_g(asset, "identity", "tags", default=[]) or [])]
    for t in tags:
        if t == "evidence":
            return list(STAGES)
        if t.startswith("evidence:"):
            stage = t.split(":", 1)[1].strip()
            if stage in STAGES and stage not in roles:
                roles.append(stage)
    return [r for r in roles if r in STAGES]


def _asset_issues(asset: dict, stage: str) -> list[tuple[str, str]]:
    """(severity, message) issues this asset contributes to a stage.
    severity: 'critical' | 'warning'."""
    issues: list[tuple[str, str]] = []
    host = _g(asset, "identity", "hostname", default="") or \
        _g(asset, "identity", "asset_id", default="?")

    # -- universal: operational health + security exposure
    score = _g(asset, "health", "overall_score", default=100)
    band = str(_g(asset, "health", "risk_band", default="safe")).lower()
    if band == "critical":
        issues.append(("critical", f"{host}: health risk band is critical"))
    elif isinstance(score, (int, float)) and score < _HEALTH_WARN_SCORE:
        issues.append(("warning", f"{host}: health score {int(score)}/100"))

    kev = _g(asset, "security", "kev_cves", default=0) or 0
    crit_cves = _g(asset, "security", "critical_cves", default=0) or 0
    if kev:
        issues.append(("critical",
                        f"{host}: {kev} actively-exploited (KEV) CVE(s) on "
                        f"evidence-chain infrastructure"))
    elif crit_cves:
        issues.append(("warning", f"{host}: {crit_cves} critical CVE(s)"))

    weak = _g(asset, "security", "weak_protocols", default=[]) or []
    if weak:
        issues.append(("warning",
                        f"{host}: weak protocol(s) exposed: {', '.join(map(str, weak))}"))

    # -- store: capacity + replication
    if stage == "store":
        total = float(_g(asset, "storage", "total_capacity_tb", default=0) or 0)
        used = float(_g(asset, "storage", "used_capacity_tb", default=0) or 0)
        if total > 0:
            pct = used / total * 100.0
            if pct >= _CAPACITY_CRIT_PCT:
                issues.append(("critical",
                                f"{host}: evidence storage {pct:.0f}% full"))
            elif pct >= _CAPACITY_WARN_PCT:
                issues.append(("warning",
                                f"{host}: evidence storage {pct:.0f}% full"))
        repl = str(_g(asset, "storage", "replication_status", default="")).lower()
        if repl in ("degraded", "broken"):
            issues.append(("critical", f"{host}: replication {repl}"))

    # -- preserve: backup recency + immutability
    if stage == "preserve":
        status = str(_g(asset, "backup", "last_backup_status", default="")).lower()
        if status == "failed":
            issues.append(("critical", f"{host}: last backup FAILED"))
        elif status == "never":
            issues.append(("critical", f"{host}: never backed up"))
        target = float(_g(asset, "backup", "rpo_target_hours", default=0) or 0)
        actual = float(_g(asset, "backup", "actual_rpo_hours", default=0) or 0)
        if target > 0 and actual > target:
            issues.append(("warning",
                            f"{host}: backup is {actual:.0f}h old "
                            f"(target {target:.0f}h)"))
        if _g(asset, "backup", "platform", default="") and \
                not _g(asset, "backup", "immutability_enabled", default=False):
            issues.append(("warning",
                            f"{host}: backup immutability not enabled"))

    return issues


def evidence_infrastructure_summary(assets: list[dict]) -> dict:
    """Roll the fleet up into per-stage + overall evidence-chain health.

    Honest by construction: a stage with zero participating assets is
    ``unknown`` (with guidance), and overall is only ``healthy`` when
    every POPULATED stage is healthy — absence of data never upgrades
    the verdict.
    """
    stages: dict[str, dict] = {}
    for stage in STAGES:
        participating = [a for a in assets if stage in _asset_stages(a)]
        all_issues: list[tuple[str, str]] = []
        for a in participating:
            all_issues.extend(_asset_issues(a, stage))
        if not participating:
            status = "unknown"
        elif any(sev == "critical" for sev, _ in all_issues):
            status = "critical"
        elif all_issues:
            status = "warning"
        else:
            status = "healthy"
        stages[stage] = {
            "status": status,
            "asset_count": len(participating),
            "assets": sorted(
                (_g(a, "identity", "hostname", default="") or
                 _g(a, "identity", "asset_id", default="?"))
                for a in participating),
            "issues": [{"severity": sev, "message": msg}
                        for sev, msg in all_issues],
        }

    populated = [s for s in STAGES if stages[s]["asset_count"] > 0]
    statuses = {stages[s]["status"] for s in populated}
    if not populated:
        overall = "unknown"
    elif "critical" in statuses:
        overall = "critical"
    elif "warning" in statuses:
        overall = "warning"
    else:
        overall = "healthy"

    covered = len(populated)
    if overall == "unknown":
        headline = ("Evidence-chain visibility not established — no assets "
                     "are classified or tagged as evidence infrastructure yet.")
        guidance = ("Run discovery (cameras, docks, VMS auto-classify), or "
                     "tag assets with 'evidence' / 'evidence:<stage>' "
                     "(stages: capture, transfer, store, access, preserve).")
    else:
        total_issues = sum(len(stages[s]["issues"]) for s in STAGES)
        headline = (f"Evidence infrastructure is {overall.upper()} — "
                     f"{covered}/{len(STAGES)} chain stages have monitored "
                     f"assets, {total_issues} open issue(s).")
        missing = [s for s in STAGES if stages[s]["asset_count"] == 0]
        guidance = (f"No monitored assets for stage(s): {', '.join(missing)} "
                     "— coverage gap, not a clean bill of health."
                     if missing else "")

    return {
        "headline": headline,
        "overall_status": overall,
        "stages": stages,
        "stages_covered": covered,
        "stages_total": len(STAGES),
        "guidance": guidance,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "disclaimer": ("Monitors the infrastructure evidence depends on; "
                        "does not access or verify evidentiary content, and "
                        "is not a chain-of-custody attestation."),
    }
