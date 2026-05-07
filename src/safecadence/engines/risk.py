"""
Deterministic risk scoring (0-100).

Risk is driven by findings + business criticality. Each finding contributes
its severity weight; the total is normalized into a 0-100 band so that
"100" means "essentially every critical control failing".
"""

from __future__ import annotations

from safecadence.core.schema import Finding, Severity


RISK_BANDS = (
    (81, "critical"),
    (61, "high"),
    (31, "medium"),
    (0,  "low"),
)

# A risk "ceiling" of 200 weight points => 100. Past that, clamps.
_RISK_CEILING = 200


def risk_band(score: int) -> str:
    for threshold, label in RISK_BANDS:
        if score >= threshold:
            return label
    return "low"


def compute_risk(findings: list[Finding], *, business_criticality: str = "medium") -> int:
    """
    Deterministic 0-100 risk score.

    business_criticality multiplier:
        low      => 0.85
        medium   => 1.00
        high     => 1.15
        critical => 1.30
    """
    raw = 0
    for f in findings:
        raw += f.severity.weight

    multiplier = {
        "low":      0.85,
        "medium":   1.00,
        "high":     1.15,
        "critical": 1.30,
    }.get((business_criticality or "medium").lower(), 1.0)

    weighted = raw * multiplier
    score = int(round((weighted / _RISK_CEILING) * 100))
    return max(0, min(100, score))


def summarize(findings: list[Finding]) -> str:
    """One-line counts summary used in CLI + reports."""
    counts = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1
    parts = [
        f"{counts[Severity.CRITICAL]} critical",
        f"{counts[Severity.HIGH]} high",
        f"{counts[Severity.MEDIUM]} medium",
        f"{counts[Severity.LOW]} low",
        f"{counts[Severity.INFO]} info",
    ]
    return " · ".join(parts)
