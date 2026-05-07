"""Storage controls: replication, snapshot retention, dedup-aware capacity guardrails."""

from __future__ import annotations

from safecadence.policy.controls import ControlSpec, register_control
from safecadence.policy.schema import EvaluationResult, Severity


def _check_replication_enabled(asset: dict, params: dict) -> tuple[EvaluationResult, str]:
    s = asset.get("storage") or {}
    status = (s.get("replication_status") or "").lower()
    if status in ("ok", "synchronized", "in-sync"):
        return EvaluationResult.PASS, f"replication: {status}"
    if status in ("none", ""):
        return EvaluationResult.FAIL, "no replication partner configured"
    return EvaluationResult.FAIL, f"replication degraded/broken: {status}"


register_control(ControlSpec(
    id="replication_enabled",
    description="Production storage arrays must replicate to a secondary",
    applies_to=["storage"],
    severity=Severity.HIGH,
    frameworks=["nist:CP-9", "cis:storage-2.1"],
    check_fn=_check_replication_enabled,
))
