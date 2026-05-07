"""
Compliance evaluator — runs a SecurityPolicy against the asset store.

For each (asset, control) pair it:
  1. Resolves the per-asset effective control (env variants).
  2. Checks for an active exception → mark NA + record exception_id.
  3. Calls the control's check_fn → PASS / FAIL / NA / UNKNOWN.
  4. On FAIL, builds a PolicyViolation with framework refs.

Returns a PolicyEvaluation summarising counts + the violation list.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Iterable

from safecadence.policy.controls import get_control
from safecadence.policy.schema import (
    EvaluationResult, PolicyControl, PolicyEvaluation, PolicyViolation,
    SecurityPolicy, Severity,
)


def _exception_for(policy: SecurityPolicy, asset: dict, control_id: str) -> str:
    """Return active exception_id (if any) covering this asset+control."""
    aid = (asset.get("identity") or {}).get("asset_id")
    now = datetime.now(timezone.utc).isoformat()
    for ex in (policy.exceptions or []):
        if ex.status != "active":
            continue
        if ex.asset_id != aid or ex.control_id != control_id:
            continue
        if ex.expires_at and ex.expires_at < now:
            continue
        return ex.exception_id
    return ""


def evaluate(policy: SecurityPolicy, assets: Iterable[dict]) -> PolicyEvaluation:
    asset_results: list[dict] = []
    violations: list[PolicyViolation] = []
    pass_count = fail_count = na_count = 0
    applicable_assets = 0

    # v6.4 — pre-resolve asset-group membership once, before iterating
    # the fleet. Without this we'd re-read every group's filter for
    # every asset; for a 2,000-device shop with five groups that's
    # 10,000 filter evaluations per policy per cycle.
    asset_list = list(assets)
    group_member_cache: set[str] | None = None
    if policy.applies_to_groups:
        from safecadence.policy.asset_groups import asset_ids_in_groups
        group_member_cache = asset_ids_in_groups(
            policy.applies_to_groups, asset_list)

    for asset in asset_list:
        if not policy.applies_to(asset, group_member_cache=group_member_cache):
            continue
        applicable_assets += 1
        ident = asset.get("identity") or {}
        aid = ident.get("asset_id", "")
        per_control: dict[str, str] = {}

        for control in policy.controls:
            spec = get_control(control.control_id)
            if not spec:
                per_control[control.control_id] = EvaluationResult.UNKNOWN.value
                continue

            # Asset-type applicability — control may not apply to this asset
            atype = ident.get("asset_type", "")
            if spec.applies_to and atype not in spec.applies_to:
                per_control[control.control_id] = EvaluationResult.NOT_APPLICABLE.value
                na_count += 1
                continue

            # Exception coverage
            ex_id = _exception_for(policy, asset, control.control_id)
            if ex_id:
                per_control[control.control_id] = EvaluationResult.NOT_APPLICABLE.value
                na_count += 1
                continue

            # Resolve env-variant parameters
            effective = policy.control_for_asset(control.control_id, asset) or control
            try:
                result, evidence = spec.check_fn(asset, effective.parameters or {})
            except Exception as e:
                result, evidence = EvaluationResult.UNKNOWN, f"check error: {e}"

            per_control[control.control_id] = result.value
            if result == EvaluationResult.PASS:
                pass_count += 1
            elif result == EvaluationResult.FAIL:
                fail_count += 1
                violations.append(PolicyViolation(
                    violation_id=f"vio_{uuid.uuid4().hex[:8]}",
                    policy_id=policy.policy_id,
                    control_id=control.control_id,
                    asset_id=aid,
                    severity=effective.severity or spec.severity,
                    message=spec.description,
                    evidence=evidence,
                    framework_refs=effective.framework_refs or spec.frameworks,
                ))
            else:
                na_count += 1

        asset_results.append({
            "asset_id": aid,
            "controls": per_control,
            "fail_count": sum(1 for r in per_control.values() if r == EvaluationResult.FAIL.value),
        })

    total_checks = pass_count + fail_count + na_count
    coverage = (pass_count + fail_count) / total_checks * 100 if total_checks else 0.0

    return PolicyEvaluation(
        evaluation_id=f"eval_{uuid.uuid4().hex[:8]}",
        policy_id=policy.policy_id,
        asset_results=asset_results,
        violations=violations,
        pass_count=pass_count,
        fail_count=fail_count,
        na_count=na_count,
        coverage_pct=round(coverage, 1),
    )
