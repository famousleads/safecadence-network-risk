"""Terraform exporter — HCL fragments for cloud controls."""

from __future__ import annotations

from safecadence.policy.exporters import register_exporter
from safecadence.policy.schema import RemediationPlan, SecurityPolicy


@register_exporter("terraform")
def export_terraform(policy: SecurityPolicy, plan: RemediationPlan) -> str:
    lines: list[str] = []
    lines.append(f"# SafeCadence Remediation — Terraform HCL fragments")
    lines.append(f"# policy: {policy.policy_name} ({policy.policy_id})")
    lines.append(f"# plan:   {plan.plan_id}    generated: {plan.generated_at}")
    lines.append(f"# Apply only the resources you actually need; review before terraform apply.")
    lines.append("")

    cloud_steps = [s for s in plan.steps if s.vendor_target in ("aws_iam", "azure", "gcp")]
    if not cloud_steps:
        lines.append("# (No cloud-targeted remediation steps in this plan.)")
        return "\n".join(lines)

    for s in cloud_steps:
        lines.append(f"# --- {s.asset_id} : {s.control_id} ({s.vendor_target}) ---")
        if s.vendor_target == "aws_iam":
            if s.control_id == "block_public_exposure":
                lines.append(f'resource "aws_s3_account_public_access_block" "sc_{s.asset_id}" {{')
                lines.append('  block_public_acls       = true')
                lines.append('  block_public_policy     = true')
                lines.append('  ignore_public_acls      = true')
                lines.append('  restrict_public_buckets = true')
                lines.append("}")
            elif s.control_id == "enforce_logging":
                lines.append(f'resource "aws_cloudtrail" "sc_{s.asset_id}" {{')
                lines.append(f'  name                          = "safecadence-{s.asset_id}"')
                lines.append('  s3_bucket_name                = var.cloudtrail_bucket')
                lines.append('  is_multi_region_trail         = true')
                lines.append('  is_organization_trail         = true')
                lines.append('  enable_log_file_validation    = true')
                lines.append("}")
            elif s.control_id == "enforce_encryption_at_rest":
                lines.append(f'resource "aws_ebs_encryption_by_default" "sc_{s.asset_id}" {{ enabled = true }}')
            else:
                lines.append("# raw shell-equivalent commands (no direct Terraform resource):")
                for cmd in s.fix_commands:
                    lines.append(f"#   {cmd}")
        elif s.vendor_target == "azure":
            lines.append("# Azure remediation as az CLI commands; convert to azurerm_* resources as needed.")
            for cmd in s.fix_commands:
                lines.append(f"#   {cmd}")
        elif s.vendor_target == "gcp":
            lines.append("# GCP remediation as gcloud commands; convert to google_* resources as needed.")
            for cmd in s.fix_commands:
                lines.append(f"#   {cmd}")
        if s.notes:
            lines.append(f"# NOTE: {s.notes}")
        lines.append("")
    return "\n".join(lines)
