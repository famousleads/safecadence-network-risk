"""
Remediation engine — turns violations into concrete fix plans.

For each PolicyViolation it picks the best translator for the asset
and produces a RemediationStep with fix / rollback / verify commands.
"""

from __future__ import annotations

import uuid

from safecadence.policy.schema import (
    PolicyEvaluation, PolicyViolation, RemediationPlan, RemediationStep,
    SecurityPolicy, Severity,
)
from safecadence.policy.translators import (
    BaseTranslator, get_translator, pick_translator_for_asset,
)


def generate_plan(policy: SecurityPolicy, evaluation: PolicyEvaluation,
                  assets_by_id: dict[str, dict],
                  vendor_target: str | None = None) -> RemediationPlan:
    """Build a RemediationPlan covering every violation in the evaluation."""
    steps: list[RemediationStep] = []
    counts = {"total": 0, "translated": 0, "untranslated": 0}

    for v in evaluation.violations:
        counts["total"] += 1
        asset = assets_by_id.get(v.asset_id) or {}
        translator: BaseTranslator | None = None
        if vendor_target:
            translator = get_translator(vendor_target)
        if not translator:
            translator = pick_translator_for_asset(asset)
        if not translator:
            counts["untranslated"] += 1
            steps.append(RemediationStep(
                asset_id=v.asset_id, control_id=v.control_id,
                vendor_target="unknown",
                notes=f"no translator matched asset; vendor='{(asset.get('identity') or {}).get('vendor')}'",
                severity=v.severity if isinstance(v.severity, Severity) else Severity(v.severity),
            ))
            continue

        control = next((c for c in policy.controls if c.control_id == v.control_id), None)
        if not control:
            continue
        # Apply env variant if applicable
        effective = policy.control_for_asset(control.control_id, asset) or control
        fix = translator.translate(effective, asset)
        if not fix.applicable:
            counts["untranslated"] += 1
            steps.append(RemediationStep(
                asset_id=v.asset_id, control_id=v.control_id,
                vendor_target=translator.vendor_target,
                notes=fix.notes or "translator marked not-applicable",
                severity=v.severity if isinstance(v.severity, Severity) else Severity(v.severity),
            ))
            continue
        counts["translated"] += 1
        steps.append(RemediationStep(
            asset_id=v.asset_id, control_id=v.control_id,
            vendor_target=translator.vendor_target,
            fix_commands=fix.fix, rollback_commands=fix.rollback,
            verify_commands=fix.verify, notes=fix.notes,
            severity=v.severity if isinstance(v.severity, Severity) else Severity(v.severity),
        ))

    return RemediationPlan(
        plan_id=f"plan_{uuid.uuid4().hex[:8]}",
        policy_id=policy.policy_id,
        steps=steps,
        summary=counts,
    )
