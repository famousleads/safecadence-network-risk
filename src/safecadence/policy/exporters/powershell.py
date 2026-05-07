"""PowerShell exporter — Windows + Azure remediation script."""

from __future__ import annotations

from safecadence.policy.exporters import register_exporter
from safecadence.policy.schema import RemediationPlan, SecurityPolicy


@register_exporter("powershell")
def export_powershell(policy: SecurityPolicy, plan: RemediationPlan) -> str:
    lines: list[str] = []
    lines.append("<#")
    lines.append(f"  SafeCadence Remediation Script")
    lines.append(f"  Policy: {policy.policy_name} ({policy.policy_id})")
    lines.append(f"  Plan:   {plan.plan_id}    Generated: {plan.generated_at}")
    lines.append(f"  REVIEW BEFORE RUNNING. Run in an elevated PowerShell session.")
    lines.append("#>")
    lines.append("")
    lines.append("$ErrorActionPreference = 'Continue'")
    lines.append("Write-Host 'SafeCadence remediation starting...' -ForegroundColor Cyan")
    lines.append("")

    ps_steps = [s for s in plan.steps if s.vendor_target in ("windows", "azure")]
    for s in ps_steps:
        lines.append(f"# === {s.asset_id} : {s.control_id} ({s.vendor_target}) ===")
        lines.append(f"Write-Host '--> {s.control_id} on {s.asset_id}' -ForegroundColor Yellow")
        for cmd in s.fix_commands:
            lines.append(cmd)
        if s.notes:
            lines.append(f"# NOTE: {s.notes}")
        lines.append("")

    lines.append("Write-Host 'SafeCadence remediation complete.' -ForegroundColor Green")
    return "\n".join(lines)
