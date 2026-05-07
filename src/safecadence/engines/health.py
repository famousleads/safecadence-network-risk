"""
Deterministic device health scoring (0-100).

Health is the *operational* signal: are interfaces up, is the device admin-ok,
do we have basic logging/NTP/AAA, is the OS recent, etc. Risk (engines/risk.py)
is the *security* signal driven by findings.
"""

from __future__ import annotations

from safecadence.core.schema import Finding, ParsedConfig, Severity


HEALTH_BANDS = (
    (90, "excellent"),
    (75, "good"),
    (60, "warning"),
    (40, "poor"),
    (0,  "critical"),
)


def health_band(score: int) -> str:
    for threshold, label in HEALTH_BANDS:
        if score >= threshold:
            return label
    return "critical"


def compute_health(parsed: ParsedConfig, findings: list[Finding]) -> int:
    """
    Start at 100, deduct points based on operational and hygiene signals.
    Returns an int in [0, 100].
    """
    score = 100

    # ---- Findings impact (capped per severity) ----
    sev_counts = {s: 0 for s in Severity}
    for f in findings:
        sev_counts[f.severity] += 1
    # Health cares about HIGH/CRITICAL more than security-only weights
    score -= min(40, sev_counts[Severity.CRITICAL] * 10)
    score -= min(25, sev_counts[Severity.HIGH] * 4)
    score -= min(15, sev_counts[Severity.MEDIUM] * 2)
    score -= min(5,  sev_counts[Severity.LOW] * 1)

    # ---- Interface state ----
    ifaces = parsed.interfaces or []
    if ifaces:
        admin_down = sum(1 for i in ifaces if not i.admin_up)
        # >40% interfaces shut indicates a half-decommissioned device
        if admin_down / max(len(ifaces), 1) > 0.4:
            score -= 5

    # ---- Basic hygiene indicators (presence in raw_config) ----
    text = (parsed.raw_config or "").lower()
    hygiene_checks = (
        ("ntp server",        4, "no NTP server configured"),
        ("logging ",          3, "no syslog/logging configured"),
        ("aaa new-model",     3, "AAA not enabled"),
        ("snmp-server",       1, "no SNMP monitoring"),
    )
    for needle, penalty, _ in hygiene_checks:
        if needle not in text:
            score -= penalty

    # ---- OS metadata signals ----
    if not parsed.version:
        score -= 2
    if not parsed.hostname:
        score -= 2

    return max(0, min(100, score))
