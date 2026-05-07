"""Bash exporter — Linux + AWS/GCP CLI remediation script."""

from __future__ import annotations

from safecadence.policy.exporters import register_exporter
from safecadence.policy.schema import RemediationPlan, SecurityPolicy


@register_exporter("bash")
def export_bash(policy: SecurityPolicy, plan: RemediationPlan) -> str:
    lines: list[str] = []
    lines.append("#!/usr/bin/env bash")
    lines.append("#")
    lines.append(f"# SafeCadence Remediation Script")
    lines.append(f"# Policy: {policy.policy_name} ({policy.policy_id})")
    lines.append(f"# Plan:   {plan.plan_id}    Generated: {plan.generated_at}")
    lines.append(f"# REVIEW BEFORE RUNNING.")
    lines.append("set -e")
    lines.append("")

    sh_steps = [s for s in plan.steps if s.vendor_target in ("linux", "aws_iam", "gcp")]
    for s in sh_steps:
        lines.append(f"# === {s.asset_id} : {s.control_id} ({s.vendor_target}) ===")
        lines.append(f"echo '--> {s.control_id} on {s.asset_id}'")
        for cmd in s.fix_commands:
            lines.append(cmd)
        if s.notes:
            lines.append(f"# NOTE: {s.notes}")
        lines.append("")

    lines.append("echo 'SafeCadence remediation complete.'")
    return "\n".join(lines)
