"""Cisco NX-OS translator. Grounded in NX-OS Configuration Guide."""

from __future__ import annotations

from safecadence.policy.schema import PolicyControl
from safecadence.policy.translators import BaseTranslator, TranslatedFix, register_translator


@register_translator("cisco_nxos")
class CiscoNXOSTranslator(BaseTranslator):
    asset_match = ["network"]

    def translate(self, control: PolicyControl, asset: dict) -> TranslatedFix:
        cid = control.control_id
        p = control.parameters or {}
        if cid == "disable_telnet":
            return TranslatedFix(
                fix=["no feature telnet"],
                rollback=["feature telnet"],
                verify=["show running-config | include telnet"],
            )
        if cid == "enforce_ssh_v2":
            return TranslatedFix(
                fix=["feature ssh", "ssh key rsa 2048 force"],
                rollback=["no feature ssh"],
                verify=["show ssh server"],
            )
        if cid == "require_aaa":
            tacacs_host = p.get("tacacs_host", "10.10.10.5")
            tacacs_key = p.get("tacacs_key", "REPLACE_ME")
            return TranslatedFix(
                fix=[
                    "feature tacacs+",
                    f"tacacs-server host {tacacs_host} key {tacacs_key}",
                    "aaa group server tacacs+ TACACS",
                    f" server {tacacs_host}",
                    "aaa authentication login default group TACACS local",
                    "aaa authorization commands default group TACACS local",
                    "aaa accounting default group TACACS",
                ],
                rollback=["no feature tacacs+"],
                verify=["show tacacs+ server", "show aaa authentication"],
            )
        if cid == "enforce_snmpv3":
            return TranslatedFix(
                fix=["no snmp-server community public",
                     "snmp-server user snmpv3user network-operator auth sha REPLACE_AUTH priv aes-128 REPLACE_PRIV"],
                rollback=["no snmp-server user snmpv3user network-operator"],
                verify=["show snmp user"],
            )
        if cid == "enable_syslog":
            target = p.get("syslog_target", "10.10.10.50")
            return TranslatedFix(
                fix=[f"logging server {target} 6", "logging level local7 6"],
                rollback=[f"no logging server {target}"],
                verify=["show logging server"],
            )
        if cid == "enable_ntp":
            srv = p.get("ntp_server", "pool.ntp.org")
            return TranslatedFix(
                fix=[f"ntp server {srv}"],
                rollback=[f"no ntp server {srv}"],
                verify=["show ntp peer-status"],
            )
        if cid == "restrict_management_access":
            cidrs = p.get("allowed_cidrs", ["10.10.10.0/24"])
            cmds = ["ip access-list MGMT-IN"]
            for i, c in enumerate(cidrs, 1):
                cmds.append(f" {i*10} permit ip {c} any")
            cmds += ["mgmt0", " ip access-group MGMT-IN in"]
            return TranslatedFix(
                fix=cmds,
                rollback=["no ip access-list MGMT-IN"],
                verify=["show access-lists MGMT-IN"],
            )
        return TranslatedFix(applicable=False, notes=f"cisco_nxos: no translation for {cid}")
