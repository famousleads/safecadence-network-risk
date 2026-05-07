"""Raw exporter — concatenated per-asset config snippets."""

from __future__ import annotations

from safecadence.policy.exporters import register_exporter
from safecadence.policy.schema import RemediationPlan, SecurityPolicy


@register_exporter("raw")
def export_raw(policy: SecurityPolicy, plan: RemediationPlan) -> str:
    out: list[str] = []
    out.append(f"! SafeCadence Remediation — policy: {policy.policy_name} ({policy.policy_id})")
    out.append(f"! plan: {plan.plan_id}   generated_at: {plan.generated_at}")
    out.append(f"! steps: {plan.summary.get('translated', 0)} translated, "
               f"{plan.summary.get('untranslated', 0)} untranslated")
    out.append("")
    by_asset: dict[str, list] = {}
    for s in plan.steps:
        by_asset.setdefault(s.asset_id, []).append(s)
    for aid, steps in by_asset.items():
        out.append(f"!{'=' * 70}")
        out.append(f"! ASSET: {aid}")
        out.append(f"!{'=' * 70}")
        for s in steps:
            out.append(f"! --- {s.control_id} ({s.vendor_target}, severity={s.severity.value}) ---")
            for line in s.fix_commands:
                out.append(line)
            if s.rollback_commands:
                out.append("! ROLLBACK:")
                for line in s.rollback_commands:
                    out.append(f"!   {line}")
            if s.verify_commands:
                out.append("! VERIFY:")
                for line in s.verify_commands:
                    out.append(f"!   {line}")
            if s.notes:
                out.append(f"! NOTE: {s.notes}")
            out.append("")
    return "\n".join(out)
