"""Arista EOS translator. Grounded in EOS User Manual."""

from __future__ import annotations

from safecadence.policy.schema import PolicyControl
from safecadence.policy.translators import BaseTranslator, TranslatedFix, register_translator


@register_translator("arista_eos")
class AristaEOSTranslator(BaseTranslator):
    asset_match = ["network"]

    def translate(self, control: PolicyControl, asset: dict) -> TranslatedFix:
        cid = control.control_id
        p = control.parameters or {}
        if cid == "disable_telnet":
            return TranslatedFix(
                fix=["management telnet", " shutdown"],
                rollback=["management telnet", " no shutdown"],
                verify=["show management telnet"],
            )
        if cid == "enforce_ssh_v2":
            return TranslatedFix(
                fix=["management ssh", " idle-timeout 15", " server-port 22"],
                rollback=["no management ssh"],
                verify=["show management ssh"],
            )
        if cid == "require_aaa":
            tacacs_host = p.get("tacacs_host", "10.10.10.5")
            tacacs_key = p.get("tacacs_key", "REPLACE_ME")
            return TranslatedFix(
                fix=[
                    f"tacacs-server host {tacacs_host} key 7 {tacacs_key}",
                    "aaa group server tacacs+ TACACS",
                    f" server {tacacs_host}",
                    "aaa authentication login default group TACACS local",
                    "aaa authorization commands all default group TACACS local",
                    "aaa accounting commands all default start-stop group TACACS",
                ],
                rollback=["no tacacs-server host"],
                verify=["show tacacs"],
            )
        if cid == "enforce_snmpv3":
            return TranslatedFix(
                fix=["no snmp-server community public ro",
                     "snmp-server view ALL iso included",
                     "snmp-server group SC-RO v3 priv read ALL",
                     "snmp-server user snmpv3user SC-RO v3 auth sha REPLACE_AUTH priv aes 128 REPLACE_PRIV"],
                rollback=["no snmp-server user snmpv3user SC-RO v3"],
                verify=["show snmp user"],
            )
        if cid == "enable_syslog":
            target = p.get("syslog_target", "10.10.10.50")
            return TranslatedFix(
                fix=[f"logging host {target}", "logging trap informational",
                     "logging facility local7"],
                rollback=[f"no logging host {target}"],
                verify=["show logging"],
            )
        if cid == "enable_ntp":
            srv = p.get("ntp_server", "pool.ntp.org")
            return TranslatedFix(
                fix=[f"ntp server {srv} prefer"],
                rollback=[f"no ntp server {srv}"],
                verify=["show ntp associations"],
            )
        if cid == "restrict_management_access":
            cidrs = p.get("allowed_cidrs", ["10.10.10.0/24"])
            cmds = ["ip access-list standard MGMT-IN"]
            for c in cidrs:
                cmds.append(f" permit {c}")
            cmds += [" deny any",
                     "management ssh", " ip access-group MGMT-IN in"]
            return TranslatedFix(
                fix=cmds,
                rollback=["no ip access-list standard MGMT-IN"],
                verify=["show ip access-lists MGMT-IN"],
            )
        return TranslatedFix(applicable=False, notes=f"arista_eos: no translation for {cid}")
