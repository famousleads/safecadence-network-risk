"""
What-if simulator — evaluate a policy against the fleet WITHOUT
saving the evaluation. Returns the same shape as evaluator + a
breakdown of what-would-fail-if-enforced.

Use case: before adopting a new policy, see "if I enforced this today,
47 assets become non-compliant — 12 critical."
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from safecadence.policy.evaluator import evaluate
from safecadence.policy.schema import SecurityPolicy, Severity


def simulate(policy: SecurityPolicy, assets: list[dict]) -> dict[str, Any]:
    ev = evaluate(policy, assets)
    by_severity: Counter = Counter()
    by_control: Counter = Counter()
    affected_assets = set()
    for v in ev.violations:
        sev = v.severity.value if isinstance(v.severity, Severity) else v.severity
        by_severity[sev] += 1
        by_control[v.control_id] += 1
        affected_assets.add(v.asset_id)
    return {
        "policy_id": policy.policy_id,
        "policy_name": policy.policy_name,
        "asset_count": len(assets),
        "applicable_assets": len(ev.asset_results),
        "would_pass": ev.pass_count,
        "would_fail": ev.fail_count,
        "would_be_na": ev.na_count,
        "coverage_pct": ev.coverage_pct,
        "affected_asset_count": len(affected_assets),
        "by_severity": dict(by_severity),
        "by_control": dict(by_control.most_common()),
        "summary": (
            f"If enforced today: {len(affected_assets)} assets would have "
            f"{ev.fail_count} violations across {len(by_control)} controls "
            f"({by_severity.get('critical', 0)} critical, "
            f"{by_severity.get('high', 0)} high)."
        ),
    }
