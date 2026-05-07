"""Ansible exporter — vendor-aware playbook.

Maps SafeCadence vendor_target → the appropriate Ansible collection
module so the generated playbook runs against real gear via Ansible's
own connection layer (we don't ship our own SSH executor).
"""

from __future__ import annotations

from safecadence.policy.exporters import register_exporter
from safecadence.policy.schema import RemediationPlan, SecurityPolicy


# vendor_target → (collection module, connection)
_VENDOR_MODULES = {
    "cisco_ios":         ("cisco.ios.ios_config",        "network_cli"),
    "cisco_nxos":        ("cisco.nxos.nxos_config",      "network_cli"),
    "cisco_asa":         ("cisco.asa.asa_config",        "network_cli"),
    "arista_eos":        ("arista.eos.eos_config",       "network_cli"),
    "juniper_junos":     ("junipernetworks.junos.junos_config", "netconf"),
    "fortinet_fortios":  ("fortinet.fortios.fortios_configuration_fact", "httpapi"),
    "paloalto_panos":    ("paloaltonetworks.panos.panos_op", "local"),
    "linux":             ("ansible.builtin.shell",       "ssh"),
    "windows":           ("ansible.windows.win_powershell", "winrm"),
    "aws_iam":           ("ansible.builtin.shell",       "local"),
    "azure":             ("ansible.builtin.shell",       "local"),
    "gcp":               ("ansible.builtin.shell",       "local"),
}


def _yaml_escape(s: str) -> str:
    return s.replace('"', '\\"')


@register_exporter("ansible")
def export_ansible(policy: SecurityPolicy, plan: RemediationPlan) -> str:
    lines: list[str] = []
    lines.append("---")
    lines.append(f"# SafeCadence Remediation Playbook")
    lines.append(f"# policy: {policy.policy_name} ({policy.policy_id})")
    lines.append(f"# plan:   {plan.plan_id}")
    lines.append(f"# generated: {plan.generated_at}")
    lines.append("# REVIEW BEFORE RUNNING — these tasks change device configuration.")
    lines.append("")

    # Group steps by vendor_target so we build one play per vendor.
    by_vendor: dict[str, list] = {}
    for s in plan.steps:
        by_vendor.setdefault(s.vendor_target, []).append(s)

    for vendor, steps in by_vendor.items():
        module, conn = _VENDOR_MODULES.get(vendor, ("ansible.builtin.debug", "local"))
        # Hosts pattern is the asset_ids in this group joined into a host list
        host_list = sorted({s.asset_id for s in steps})
        lines.append(f"- name: SafeCadence remediation for {vendor}")
        lines.append(f"  hosts: " + " ".join(host_list))
        lines.append(f"  connection: {conn}")
        lines.append("  gather_facts: false")
        lines.append("  tasks:")
        for s in steps:
            lines.append(f"    - name: \"{_yaml_escape(s.control_id)} on {s.asset_id}\"")
            if module.endswith("_config"):
                lines.append(f"      {module}:")
                lines.append("        lines:")
                for cmd in s.fix_commands:
                    lines.append(f"          - \"{_yaml_escape(cmd)}\"")
            elif module == "ansible.builtin.shell":
                lines.append("      ansible.builtin.shell: |")
                for cmd in s.fix_commands:
                    lines.append(f"        {cmd}")
            elif module == "ansible.windows.win_powershell":
                lines.append("      ansible.windows.win_powershell:")
                lines.append("        script: |")
                for cmd in s.fix_commands:
                    lines.append(f"          {cmd}")
            else:
                lines.append(f"      {module}: {{}}")
                lines.append(f"      # commands to run manually:")
                for cmd in s.fix_commands:
                    lines.append(f"      #   {cmd}")
            if s.notes:
                lines.append(f"      tags: [\"{s.severity.value}\", \"{s.control_id}\"]")
                lines.append(f"      # NOTE: {_yaml_escape(s.notes)}")
            lines.append("")
        lines.append("")
    return "\n".join(lines)
