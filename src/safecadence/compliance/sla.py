"""
v9.28 — Findings SLA tracking + breach detection.

Each finding gets a `due_at` timestamp computed from its severity
plus the SLA defined on the related control (or the platform default
if the finding isn't tied to a control). When a finding's `due_at`
passes without resolution, the daemon emits an SLA-breach finding.

Design choices:
  * Pure functions over a finding dict — no DB writes here. The
    caller (daemon, policy engine, evidence pack generator) decides
    what to do with the result.
  * SLA is a per-control table keyed by severity. Defaults shipped
    in compliance/mappings.py via `all_metadata_for_control`.
  * "Resolved" detection is conservative: status == 'resolved' OR
    'closed' OR 'mitigated'. Anything else counts as open.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional


# Platform-wide fallback when a finding doesn't cite a known control.
_DEFAULT_SLA = {"critical": 7, "high": 30, "medium": 90, "low": 180,
                  "info": 365}


@dataclass
class FindingSLA:
    finding_id: str
    severity: str
    control_id: str
    sla_days: int
    opened_at: str
    due_at: str
    breached: bool
    breach_age_days: int

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def _parse_ts(s: str) -> Optional[datetime]:
    if not s:
        return None
    try:
        ts = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts
    except Exception:
        return None


def _resolved(finding: dict) -> bool:
    status = (finding.get("status") or "").lower()
    return status in ("resolved", "closed", "mitigated", "fixed")


def _sla_days_for(control_id: str, severity: str) -> int:
    """Look up SLA days from the control mapping pack; fall back to
    the platform default if the control isn't mapped."""
    sev = (severity or "medium").lower()
    if sev == "critical-high":  # alias seen in some adapters
        sev = "critical"
    try:
        from safecadence.compliance.mappings import all_metadata_for_control
        meta = all_metadata_for_control(control_id) if control_id else {}
        table = meta.get("sla_severity_days") or _DEFAULT_SLA
    except Exception:
        table = _DEFAULT_SLA
    return int(table.get(sev, _DEFAULT_SLA.get(sev, 90)))


def annotate_finding(finding: dict, *, now: Optional[datetime] = None) -> FindingSLA:
    """Compute the SLA snapshot for one finding."""
    now = now or datetime.now(timezone.utc)
    severity = (finding.get("severity") or "medium").lower()
    control_id = (finding.get("control_id") or finding.get("control")
                    or "")
    fid = (finding.get("id") or finding.get("finding_id") or
            finding.get("uid") or "")

    opened = _parse_ts(finding.get("opened_at") or
                        finding.get("first_seen") or
                        finding.get("created_at"))
    if opened is None:
        opened = now    # treat unknown as "today" so we don't backdate
    sla_days = _sla_days_for(control_id, severity)
    due = opened + timedelta(days=sla_days)

    breached = (not _resolved(finding)) and (now > due)
    breach_age = max(0, (now - due).days) if breached else 0

    return FindingSLA(
        finding_id=str(fid),
        severity=severity,
        control_id=str(control_id),
        sla_days=sla_days,
        opened_at=opened.isoformat(),
        due_at=due.isoformat(),
        breached=breached,
        breach_age_days=breach_age,
    )


def annotate_findings(findings: Iterable[dict],
                        *, now: Optional[datetime] = None) -> list[FindingSLA]:
    return [annotate_finding(f, now=now) for f in findings]


def breach_summary(findings: Iterable[dict]) -> dict:
    """Roll up SLA breaches by severity for the home/inventory cards."""
    annots = annotate_findings(findings)
    by_sev: dict[str, int] = {}
    open_count = 0
    breached = 0
    for a in annots:
        by_sev.setdefault(a.severity, 0)
        if a.breached:
            by_sev[a.severity] += 1
            breached += 1
        if a.breach_age_days >= 0:
            open_count += 1
    return {
        "total_findings": len(annots),
        "breached": breached,
        "by_severity": by_sev,
    }


def sla_breaches_as_findings(findings: Iterable[dict]) -> list[dict]:
    """Emit synthetic 'sla_breach' findings for everything past due.

    These get persisted alongside real findings so the existing UI,
    SLA notifiers, and Splunk firehose all see them — no special
    casing required.
    """
    out: list[dict] = []
    for a in annotate_findings(findings):
        if not a.breached:
            continue
        out.append({
            "id": f"sla-breach::{a.finding_id}",
            "kind": "sla_breach",
            "severity": "high" if a.severity in ("medium", "low")
                          else "critical",
            "asset_id": "",   # parent finding's asset, filled by caller
            "title": f"SLA breach: finding {a.finding_id}",
            "message": (f"Finding {a.finding_id} has been open for "
                          f"{a.breach_age_days} days past its "
                          f"{a.sla_days}-day {a.severity} SLA."),
            "control_id": a.control_id,
            "parent_finding_id": a.finding_id,
        })
    return out
