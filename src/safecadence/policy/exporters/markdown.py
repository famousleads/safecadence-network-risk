"""Markdown exporter — human-readable change runbook."""

from __future__ import annotations

from safecadence.policy.exporters import register_exporter
from safecadence.policy.schema import RemediationPlan, SecurityPolicy


@register_exporter("markdown")
def export_markdown(policy: SecurityPolicy, plan: RemediationPlan) -> str:
    out: list[str] = []
    out.append(f"# {policy.policy_name} — Remediation Runbook")
    out.append("")
    out.append(f"**Policy ID:** `{policy.policy_id}`  ")
    out.append(f"**Plan ID:** `{plan.plan_id}`  ")
    out.append(f"**Generated:** {plan.generated_at}  ")
    out.append(f"**Severity:** {policy.severity.value}  ")
    out.append(f"**Frameworks:** {', '.join(policy.compliance_frameworks) or 'none'}  ")
    out.append("")
    out.append(f"**Summary:** {plan.summary.get('translated',0)} steps translated, "
               f"{plan.summary.get('untranslated',0)} untranslated, "
               f"{plan.summary.get('total',0)} total.")
    out.append("")
    if policy.description:
        out.append("## Description")
        out.append("")
        out.append(policy.description.strip())
        out.append("")

    by_asset: dict[str, list] = {}
    for s in plan.steps:
        by_asset.setdefault(s.asset_id, []).append(s)

    out.append("## Per-asset changes")
    out.append("")
    for aid, steps in by_asset.items():
        out.append(f"### Asset `{aid}`")
        out.append("")
        for s in steps:
            out.append(f"#### {s.control_id} ({s.vendor_target}, severity={s.severity.value})")
            out.append("")
            if s.fix_commands:
                out.append("**Fix:**")
                out.append("")
                out.append("```")
                for line in s.fix_commands:
                    out.append(line)
                out.append("```")
                out.append("")
            if s.rollback_commands:
                out.append("**Rollback:**")
                out.append("")
                out.append("```")
                for line in s.rollback_commands:
                    out.append(line)
                out.append("```")
                out.append("")
            if s.verify_commands:
                out.append("**Verify:**")
                out.append("")
                out.append("```")
                for line in s.verify_commands:
                    out.append(line)
                out.append("```")
                out.append("")
            if s.notes:
                out.append(f"> Note: {s.notes}")
                out.append("")
    return "\n".join(out)
