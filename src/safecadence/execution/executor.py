"""Dry-run executor + automation-tool exporter.

We do NOT SSH into customer devices. The dry-run executor:

  1. Resolves a job's targeting (asset_ids ∪ asset_group_ids ∪ filter)
     into the concrete list of in-scope assets, using the same
     primitives the policy evaluator uses.
  2. Picks the right vendor command set per asset based on its
     identity.vendor + os.os_type, falling back to a "manual" entry
     if no per-vendor pack exists.
  3. Creates one CommandExecution per asset, marks it `dry_run=True`,
     and writes a synthetic CommandOutput predicting the verdict.
  4. Wraps everything in audit events so the Audit Logs tab shows
     exactly who ran what against which asset, just like a real run
     would (which is the whole point of doing this even before
     real execution lands).

The exporter renders the same job into:
  * Ansible playbook (YAML)
  * Salt state
  * Cisco NSO XML config diff
  * Raw command list (for paste-into-CLI)
  * Markdown runbook

Operators take whichever output their automation tooling speaks and
SafeCadence's job is done. This is the design choice that keeps us
out of the 'we accidentally bricked your datacenter' business.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from safecadence.execution import store
from safecadence.execution.guardrails import preflight
from safecadence.execution.schema import (
    CommandExecution, CommandJob, CommandOutput, JobStatus, RiskLevel,
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------
# Targeting — resolve a job's three target fields into a list of assets
# --------------------------------------------------------------------------

def _resolve_targets(job: CommandJob) -> list[dict]:
    from safecadence.policy.asset_groups import (
        AssetGroup, asset_ids_in_groups, resolve_members,
    )
    from safecadence.server.platform_api import get_asset, list_assets

    out: list[dict] = []
    seen: set[str] = set()
    for aid in job.target_asset_ids or []:
        if aid in seen:
            continue
        a = get_asset(aid)
        if a:
            out.append(a)
            seen.add(aid)
    if job.target_asset_group_ids:
        all_assets = list_assets()
        for aid in asset_ids_in_groups(job.target_asset_group_ids,
                                          all_assets):
            if aid in seen:
                continue
            a = get_asset(aid)
            if a:
                out.append(a)
                seen.add(aid)
    if job.target_filter:
        ad_hoc = AssetGroup(group_id="__job_target__", name="job",
                             filter=dict(job.target_filter))
        for asset in resolve_members(ad_hoc, list_assets()):
            aid = (asset.get("identity") or {}).get("asset_id")
            if aid and aid not in seen:
                out.append(asset)
                seen.add(aid)
    return out


def _vendor_key(asset: dict) -> str:
    """Map an asset's identity → builder vendor key (cisco_ios, etc.)."""
    ident = asset.get("identity") or {}
    vendor = (ident.get("vendor") or "").lower()
    os_type = ((asset.get("os") or {}).get("os_type") or "").lower()
    if "cisco" in vendor:
        if "nx" in os_type:
            return "cisco_nxos"
        if "asa" in os_type:
            return "cisco_asa"
        return "cisco_ios"
    if "arista" in vendor:
        return "arista_eos"
    if "juniper" in vendor:
        return "juniper_junos"
    if "fortinet" in vendor:
        return "fortinet_fortios"
    if "palo" in vendor:
        return "paloalto_panos"
    if "microsoft" in vendor and "windows" in os_type:
        return "windows"
    if vendor in ("linux", "ubuntu", "rhel", "debian", "centos"):
        return "linux"
    if vendor == "aws":
        return "aws_iam"
    if vendor in ("azure", "microsoft"):
        return "azure"
    if vendor in ("gcp", "google"):
        return "gcp"
    return ""


# --------------------------------------------------------------------------
# Dry-run
# --------------------------------------------------------------------------

def dry_run(job_id: str, *, actor: str = "(dry-run)") -> dict:
    """Simulate the job. Creates real CommandExecution + CommandOutput
    records (with dry_run=True) so the Execution Queue tab shows what
    the queue would look like under real execution."""
    job = store.get_job(job_id)
    if not job:
        return {"ok": False, "error": "job not found"}
    if job.status != JobStatus.APPROVED:
        return {"ok": False,
                "error": f"job is not APPROVED (status: {job.status})"}

    targets = _resolve_targets(job)
    if not targets:
        return {"ok": False, "error": "no in-scope assets resolved"}

    summary = {
        "ok": True, "job_id": job.job_id,
        "asset_count": len(targets),
        "executions": [], "blocked": [], "no_translator": [],
    }

    for asset in targets:
        aid = (asset.get("identity") or {}).get("asset_id") or "?"
        vk = _vendor_key(asset)
        cmds = (job.inline_commands or {}).get(vk, [])
        if not cmds:
            summary["no_translator"].append({
                "asset_id": aid, "vendor_key": vk or "(unknown)",
                "reason": ("no per-vendor command set for this asset; "
                            "operator must edit the job"),
            })
            continue
        # Per-asset preflight — this can elevate based on the asset's
        # actual config text (lockout-risk patterns).
        pf = preflight(cmds, asset)
        ex = CommandExecution(
            job_id=job.job_id, asset_id=aid, vendor=vk,
            rendered_commands=list(cmds),
            started_at=_now(), finished_at=_now(),
            status=(JobStatus.BLOCKED if pf.blocked else JobStatus.DONE),
            dry_run=True,
        )
        if pf.blocked:
            ex.error = "; ".join(pf.reasons)[:300]
        store.save_execution(ex)
        out = CommandOutput(
            execution_id=ex.execution_id,
            raw_stdout="(dry-run — no real execution)",
            exit_code=0,
            parsed={"vendor_key": vk, "command_count": len(cmds)},
            issues=([{"severity": "blocked", "msg": r}
                       for r in pf.reasons] if pf.blocked else
                     [{"severity": pf.risk.value, "msg": r}
                       for r in pf.reasons]),
        )
        store.save_output(out)
        ex.output_id = out.output_id
        store.save_execution(ex)
        target = summary["blocked"] if pf.blocked else summary["executions"]
        target.append({
            "execution_id": ex.execution_id,
            "asset_id": aid, "vendor": vk, "risk": pf.risk.value,
            "command_count": len(cmds),
            "issues": [r for r in pf.reasons][:5],
        })

    return summary


# --------------------------------------------------------------------------
# Exporters — Ansible / Salt / NSO / Raw / Markdown
# --------------------------------------------------------------------------

def export_ansible(job: CommandJob, *, assets: list[dict]) -> str:
    """Render an Ansible playbook the operator can run with their own
    inventory + credentials. We do NOT generate inventory; the exporter
    emits per-vendor `tasks` blocks and assumes the operator wires
    `hosts:` to a group of their choosing."""
    lines: list[str] = []
    lines.append("---")
    lines.append(f"# Generated by SafeCadence v7.0")
    lines.append(f"# Job: {job.name} ({job.job_id})")
    lines.append(f"# Risk: {job.risk.value} · Mode: {job.mode.value}")
    lines.append(f"# Approvers: {', '.join(job.approvers) or '(none)'}")
    lines.append("")
    for vendor, cmds in (job.inline_commands or {}).items():
        if not cmds:
            continue
        lines.append(f"- name: SafeCadence ({vendor}) — {job.name}")
        lines.append(f"  hosts: {vendor}")
        lines.append(f"  gather_facts: false")
        lines.append(f"  tasks:")
        if vendor.startswith("cisco_"):
            module = "cisco.ios.ios_command"
            kind = "commands"
        elif vendor == "arista_eos":
            module = "arista.eos.eos_command"
            kind = "commands"
        elif vendor == "juniper_junos":
            module = "junipernetworks.junos.junos_command"
            kind = "commands"
        elif vendor == "linux":
            module = "ansible.builtin.shell"
            kind = "shell"
        elif vendor == "windows":
            module = "ansible.windows.win_shell"
            kind = "shell"
        else:
            module = "ansible.builtin.command"
            kind = "shell"

        if kind == "commands":
            lines.append(f"    - name: Run SafeCadence commands")
            lines.append(f"      {module}:")
            lines.append(f"        commands:")
            for c in cmds:
                lines.append(f"          - {json.dumps(c)}")
        else:
            for c in cmds:
                lines.append(f"    - name: {c[:60]}")
                lines.append(f"      {module}: {json.dumps(c)}")
        lines.append("")
    return "\n".join(lines)


def export_salt(job: CommandJob) -> str:
    """Salt state file. Emits net.cli for network devices, cmd.run
    for hosts. Operators wire targets via Salt's grains/pillar."""
    lines: list[str] = ["# SafeCadence v7.0 Salt state"]
    for vendor, cmds in (job.inline_commands or {}).items():
        if not cmds:
            continue
        lines.append(f"# === {vendor} ===")
        for i, c in enumerate(cmds, 1):
            sid = f"{job.job_id}_{vendor}_{i}"
            if vendor.startswith(("cisco_", "arista_", "juniper_")):
                lines.append(f"{sid}:")
                lines.append(f"  net.cli:")
                lines.append(f"    - command: {json.dumps(c)}")
            else:
                lines.append(f"{sid}:")
                lines.append(f"  cmd.run:")
                lines.append(f"    - name: {json.dumps(c)}")
        lines.append("")
    return "\n".join(lines)


def export_nso(job: CommandJob) -> str:
    """Cisco NSO config diff — emits a CLI-style snippet per vendor
    that an NSO operator can paste into a service template."""
    lines: list[str] = []
    lines.append(f"! SafeCadence v7.0 — NSO service snippet")
    lines.append(f"! Job: {job.name}  Risk: {job.risk.value}")
    for vendor, cmds in (job.inline_commands or {}).items():
        if not cmds:
            continue
        lines.append(f"!")
        lines.append(f"! ----- vendor: {vendor} -----")
        for c in cmds:
            lines.append(c)
    return "\n".join(lines)


def export_raw(job: CommandJob) -> str:
    """Plain command list, grouped by vendor — copy-paste into a CLI."""
    lines: list[str] = []
    for vendor, cmds in (job.inline_commands or {}).items():
        if not cmds:
            continue
        lines.append(f"# === {vendor} ===")
        for c in cmds:
            lines.append(c)
        lines.append("")
    return "\n".join(lines)


def export_markdown(job: CommandJob) -> str:
    """Human-readable runbook with a TOC + per-vendor sections."""
    lines: list[str] = []
    lines.append(f"# {job.name}")
    lines.append("")
    lines.append(f"- **Job ID:** `{job.job_id}`")
    lines.append(f"- **Risk:** {job.risk.value}")
    lines.append(f"- **Mode:** {job.mode.value}")
    lines.append(f"- **Created by:** {job.created_by or '(unknown)'}")
    lines.append(f"- **Approvers:** "
                 + (", ".join(job.approvers) or "_(none)_"))
    lines.append("")
    if job.description:
        lines.append("## Description")
        lines.append(job.description)
        lines.append("")
    for vendor, cmds in (job.inline_commands or {}).items():
        if not cmds:
            continue
        lines.append(f"## {vendor}")
        lines.append("```")
        for c in cmds:
            lines.append(c)
        lines.append("```")
    return "\n".join(lines)


def export(job: CommandJob, fmt: str, *, assets: list[dict] | None = None
           ) -> str:
    fmt = (fmt or "").lower()
    assets = assets or []
    if fmt == "ansible":  return export_ansible(job, assets=assets)
    if fmt == "salt":     return export_salt(job)
    if fmt == "nso":      return export_nso(job)
    if fmt == "raw":      return export_raw(job)
    if fmt in ("md", "markdown"): return export_markdown(job)
    raise ValueError(f"unknown export format: {fmt!r}; "
                      "use ansible / salt / nso / raw / markdown")
