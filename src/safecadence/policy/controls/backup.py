"""Backup controls: retention, immutability, air-gap, RPO."""

from __future__ import annotations

from safecadence.policy.controls import ControlSpec, register_control
from safecadence.policy.schema import EvaluationResult, Severity


def _check_enforce_backup_retention(asset: dict, params: dict) -> tuple[EvaluationResult, str]:
    b = asset.get("backup") or {}
    required = int(params.get("min_retention_days", 30))
    # v6.4.3 — accept either retention_days or immutability_days as a
    # fallback. Real backup adapters use different field names; we'd
    # rather PASS on a real signal than UNKNOWN forever.
    actual = b.get("retention_days")
    if actual is None:
        actual = b.get("immutability_days")
    if actual is None:
        return EvaluationResult.UNKNOWN, "neither retention_days nor immutability_days collected"
    actual = int(actual)
    if actual >= required:
        return EvaluationResult.PASS, f"retention {actual}d >= {required}d"
    return EvaluationResult.FAIL, f"retention {actual}d < required {required}d"


register_control(ControlSpec(
    id="enforce_backup_retention",
    description="Backups retained for at least N days (default 30)",
    applies_to=["backup"],
    severity=Severity.HIGH,
    frameworks=["nist:CP-9", "cis:backup-1.1", "pci:9.5"],
    check_fn=_check_enforce_backup_retention,
))


def _check_enforce_immutability(asset: dict, params: dict) -> tuple[EvaluationResult, str]:
    b = asset.get("backup") or {}
    # Explicit boolean wins
    if b.get("immutability_enabled") is True:
        return EvaluationResult.PASS, "backup immutability enabled"
    if b.get("immutability_enabled") is False:
        return EvaluationResult.FAIL, "backup immutability disabled"
    # v6.4.3 — infer from common adapter fields. Veeam reports
    # immutability_days; AWS Backup reports vault_locked; Azure reports
    # has_locked_immutability_policy.
    days = b.get("immutability_days")
    if isinstance(days, (int, float)) and days > 0:
        return EvaluationResult.PASS, f"immutability set to {int(days)} days"
    if isinstance(days, (int, float)) and days == 0:
        return EvaluationResult.FAIL, "immutability_days = 0 (no protection)"
    if b.get("vault_locked") is True:
        return EvaluationResult.PASS, "AWS Backup vault locked"
    if b.get("has_locked_immutability_policy") is True:
        return EvaluationResult.PASS, "Azure Blob immutability policy locked"
    return EvaluationResult.UNKNOWN, "immutability state not collected"


register_control(ControlSpec(
    id="enforce_immutability",
    description="Backups must be immutable (object-lock / WORM)",
    applies_to=["backup"],
    severity=Severity.CRITICAL,
    frameworks=["nist:CP-9(8)", "cis:backup-1.3"],
    check_fn=_check_enforce_immutability,
))


def _check_enforce_air_gap(asset: dict, params: dict) -> tuple[EvaluationResult, str]:
    b = asset.get("backup") or {}
    if b.get("air_gapped") is True:
        return EvaluationResult.PASS, "air-gapped backup target"
    if b.get("air_gapped") is False:
        return EvaluationResult.FAIL, "no air-gap detected"
    # v6.4.3 — infer from common patterns. Tape jobs, cross-region/
    # cross-account replication, and offline media all count.
    if b.get("offsite_copies") and b.get("offsite_copies") > 0:
        return EvaluationResult.PASS, f"{b['offsite_copies']} off-site copies"
    if b.get("tape_jobs") and b.get("tape_jobs") > 0:
        return EvaluationResult.PASS, f"{b['tape_jobs']} tape jobs configured"
    if b.get("cross_account_copy") is True or b.get("cross_region_copy") is True:
        return EvaluationResult.PASS, "cross-account/region copy enabled"
    return EvaluationResult.UNKNOWN, "air-gap state not collected"


register_control(ControlSpec(
    id="enforce_air_gap",
    description="At least one backup copy is air-gapped or offline",
    applies_to=["backup"],
    severity=Severity.HIGH,
    frameworks=["nist:CP-9", "cis:backup-1.4"],
    check_fn=_check_enforce_air_gap,
))
