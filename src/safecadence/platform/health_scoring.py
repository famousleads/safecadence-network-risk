"""
Multi-dimensional health scoring engine.

Each asset gets 4 separate health scores (0-100, higher = better):
  - hardware_health     — power supplies, fans, temps, RAID, disk health
  - security_health     — vulnerabilities, exposed services, weak protocols
  - lifecycle_health    — EOL/EOS proximity, warranty status
  - operational_health  — uptime, errors, load

Plus an overall composite (weighted average) and a letter grade A/B/C/D/F.

Designed to be deterministic + transparent — every score deduction has
a documented reason that can be shown in the UI / report.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Tuple

from safecadence.platform.schema import UnifiedAsset, HealthScores


# Weights for composite — sum should be 100
_WEIGHTS = {
    "hardware": 25,
    "security": 40,        # security weighted highest — it's why people install us
    "lifecycle": 20,
    "operational": 15,
}


def _deduct(score: int, points: int) -> int:
    return max(0, score - points)


def score_hardware(asset: UnifiedAsset) -> Tuple[int, list[str]]:
    """Score hardware health from power, fans, temps, RAID."""
    score = 100
    reasons = []
    h = asset.hardware

    # Power supplies
    for ps in h.power_supplies:
        status = (ps.get("status") or "").lower()
        if status not in ("ok", "present", "normal", ""):
            score = _deduct(score, 15)
            reasons.append(f"Power supply slot {ps.get('slot','?')} status: {status}")

    # Fans
    for fan in h.fans:
        status = (fan.get("status") or "").lower()
        if status not in ("ok", "present", "normal", ""):
            score = _deduct(score, 10)
            reasons.append(f"Fan slot {fan.get('slot','?')} status: {status}")

    # Temperatures — anything > 75°C = warning, > 90°C = critical
    for t in h.temperatures:
        c = t.get("celsius", 0)
        if c >= 90:
            score = _deduct(score, 25)
            reasons.append(f"Temperature sensor {t.get('sensor','?')}: {c}°C (critical)")
        elif c >= 75:
            score = _deduct(score, 10)
            reasons.append(f"Temperature sensor {t.get('sensor','?')}: {c}°C (high)")

    # RAID status
    if h.raid_status and h.raid_status.lower() not in ("ok", "optimal", ""):
        score = _deduct(score, 30)
        reasons.append(f"RAID status: {h.raid_status}")

    # Memory utilization
    if h.memory_total_mb and h.memory_used_mb:
        pct = (h.memory_used_mb / h.memory_total_mb) * 100
        if pct > 95:
            score = _deduct(score, 15)
            reasons.append(f"Memory utilization: {pct:.0f}%")
        elif pct > 85:
            score = _deduct(score, 5)
            reasons.append(f"Memory utilization elevated: {pct:.0f}%")

    return score, reasons


def score_security(asset: UnifiedAsset) -> Tuple[int, list[str]]:
    """Score security from CVEs + exposed services + weak protocols."""
    score = 100
    reasons = []
    s = asset.security

    # KEV CVEs are catastrophic
    if s.kev_cves > 0:
        deduction = min(60, s.kev_cves * 25)
        score = _deduct(score, deduction)
        reasons.append(f"{s.kev_cves} CISA KEV CVE(s) — actively exploited in the wild")

    # Critical CVEs
    if s.critical_cves > 0:
        deduction = min(30, s.critical_cves * 10)
        score = _deduct(score, deduction)
        reasons.append(f"{s.critical_cves} critical CVE(s)")

    # High CVEs
    if s.high_cves > 0:
        deduction = min(20, s.high_cves * 5)
        score = _deduct(score, deduction)
        reasons.append(f"{s.high_cves} high-severity CVE(s)")

    # Weak protocols
    weak = set(p.lower() for p in s.weak_protocols)
    if "telnet" in weak or "ftp" in weak:
        score = _deduct(score, 20)
        reasons.append("Cleartext protocol(s) enabled (telnet/ftp)")
    if "smb1" in weak or "smbv1" in weak:
        score = _deduct(score, 25)
        reasons.append("SMB1 enabled — major ransomware vector")
    if "sslv3" in weak or "tls1.0" in weak or "tls1.1" in weak:
        score = _deduct(score, 10)
        reasons.append("Deprecated TLS/SSL versions enabled")

    # Public exposure of sensitive services
    for es in s.exposed_services:
        if es.get("public") and es.get("port") in (22, 23, 3389, 5900, 445, 161):
            score = _deduct(score, 15)
            reasons.append(f"Sensitive port {es.get('port')} publicly exposed")

    # Each missing patch
    if s.missing_patches:
        deduction = min(15, len(s.missing_patches) * 3)
        score = _deduct(score, deduction)
        reasons.append(f"{len(s.missing_patches)} missing patch(es)")

    # Toxic combinations apply on top
    for combo in s.toxic_combinations:
        boost = combo.get("score_boost", 0)
        score = _deduct(score, min(40, boost))
        reasons.append(f"Toxic combo: {combo.get('name', '?')}")

    return score, reasons


def score_lifecycle(asset: UnifiedAsset) -> Tuple[int, list[str]]:
    """Score based on EOL/EOS proximity + warranty."""
    score = 100
    reasons = []
    lc = asset.lifecycle

    # EOS status
    eos = (lc.eol_status or "").lower()
    if eos in ("end-of-support", "eos", "ended"):
        score = _deduct(score, 50)
        reasons.append("Past end-of-support — no more security patches")
    elif eos in ("end-of-software", "end-of-software-maintenance"):
        score = _deduct(score, 30)
        reasons.append("Past end-of-software — feature/bug patches stopped")
    elif eos in ("last-day-of-support",):
        score = _deduct(score, 20)
        reasons.append("Last-day-of-support announced")

    # Days until EOS
    if lc.days_until_eos:
        days = lc.days_until_eos
        if 0 < days < 90:
            score = _deduct(score, 20)
            reasons.append(f"EOS in {days} days")
        elif 0 < days < 365:
            score = _deduct(score, 10)
            reasons.append(f"EOS in {days} days — plan replacement")

    # Warranty
    if lc.warranty_status and lc.warranty_status.lower() == "expired":
        score = _deduct(score, 15)
        reasons.append("Hardware warranty expired")

    return score, reasons


def score_operational(asset: UnifiedAsset) -> Tuple[int, list[str]]:
    """Score based on uptime + interface errors + general health signals."""
    score = 100
    reasons = []

    # Uptime — too short = recent reboot (may be normal); too long = uncrashed but unpatched
    uptime = asset.os.uptime_seconds
    if 0 < uptime < 3600:
        score = _deduct(score, 5)
        reasons.append("Recent reboot (< 1 hour uptime)")
    elif uptime > 365 * 24 * 3600:
        score = _deduct(score, 15)
        reasons.append("Uptime > 1 year — almost certainly unpatched")
    elif uptime > 180 * 24 * 3600:
        score = _deduct(score, 5)
        reasons.append("Uptime > 6 months — verify patch status")

    # Interface errors
    total_errors = 0
    for iface in asset.interfaces:
        total_errors += (iface.errors_in or 0) + (iface.errors_out or 0)
        if (iface.crc_errors or 0) > 1000:
            score = _deduct(score, 10)
            reasons.append(f"Interface {iface.name}: {iface.crc_errors} CRC errors (cable issue?)")

    if total_errors > 100000:
        score = _deduct(score, 10)
        reasons.append(f"High interface error count: {total_errors}")

    # Backup status
    if asset.backup.platform:
        bs = (asset.backup.last_backup_status or "").lower()
        if bs == "failed":
            score = _deduct(score, 25)
            reasons.append("Last backup failed")
        elif bs == "warning":
            score = _deduct(score, 10)
            reasons.append("Last backup completed with warnings")
        elif bs == "never":
            score = _deduct(score, 30)
            reasons.append("No backup ever recorded")

    return score, reasons


def score_asset_health(asset: UnifiedAsset) -> HealthScores:
    """Compute all 4 scores + composite + grade. Returns HealthScores object."""
    hw_score, hw_reasons = score_hardware(asset)
    sec_score, sec_reasons = score_security(asset)
    lc_score, lc_reasons = score_lifecycle(asset)
    op_score, op_reasons = score_operational(asset)

    composite = (
        hw_score * _WEIGHTS["hardware"]
        + sec_score * _WEIGHTS["security"]
        + lc_score * _WEIGHTS["lifecycle"]
        + op_score * _WEIGHTS["operational"]
    ) // 100

    if composite >= 90:
        grade, band = "A", "safe"
    elif composite >= 80:
        grade, band = "B", "low"
    elif composite >= 70:
        grade, band = "C", "medium"
    elif composite >= 60:
        grade, band = "D", "high"
    else:
        grade, band = "F", "critical"

    return HealthScores(
        hardware_health=hw_score,
        security_health=sec_score,
        lifecycle_health=lc_score,
        operational_health=op_score,
        overall_score=composite,
        grade=grade,
        risk_band=band,
    )
