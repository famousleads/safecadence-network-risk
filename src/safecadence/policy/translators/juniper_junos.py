"""Juniper Junos translator. Grounded in Junos OS CLI User Guide.
Outputs Junos `set` commands; rollback uses `delete`."""

from __future__ import annotations

from safecadence.policy.schema import PolicyControl
from safecadence.policy.translators import BaseTranslator, TranslatedFix, register_translator


@register_translator("juniper_junos")
class JuniperJunosTranslator(BaseTranslator):
    asset_match = ["network"]

    def translate(self, control: PolicyControl, asset: dict) -> TranslatedFix:
        cid = control.control_id
        p = control.parameters or {}
        if cid == "disable_telnet":
            return TranslatedFix(
                fix=["delete system services telnet"],
                rollback=["set system services telnet"],
                verify=["show configuration system services | display set"],
            )
        if cid == "enforce_ssh_v2":
            return TranslatedFix(
                fix=["set system services ssh protocol-version v2",
                     "set system services ssh ciphers aes256-ctr",
                     "set system services ssh ciphers aes128-ctr"],
                rollback=["delete system services ssh protocol-version"],
                verify=["show configuration system services ssh | display set"],
            )
        if cid == "require_aaa":
            tacacs_host = p.get("tacacs_host", "10.10.10.5")
            tacacs_key = p.get("tacacs_key", "REPLACE_ME")
            return TranslatedFix(
                fix=[
                    f"set system tacplus-server {tacacs_host} secret \"{tacacs_key}\"",
                    "set system authentication-order [ tacplus password ]",
                    "set system accounting events login",
                    "set system accounting destination tacplus",
                ],
                rollback=[f"delete system tacplus-server {tacacs_host}"],
                verify=["show configuration system tacplus-server | display set"],
            )
        if cid == "enforce_snmpv3":
            return TranslatedFix(
                fix=["delete snmp community public",
                     "set snmp v3 usm local-engine user snmpv3user authentication-sha "
                     "authentication-password REPLACE_AUTH",
                     "set snmp v3 usm local-engine user snmpv3user privacy-aes128 "
                     "privacy-password REPLACE_PRIV"],
                rollback=["delete snmp v3 usm local-engine user snmpv3user"],
                verify=["show snmp v3 user"],
            )
        if cid == "enable_syslog":
            target = p.get("syslog_target", "10.10.10.50")
            return TranslatedFix(
                fix=[f"set system syslog host {target} any info",
                     f"set system syslog host {target} authorization info"],
                rollback=[f"delete system syslog host {target}"],
                verify=["show configuration system syslog | display set"],
            )
        if cid == "enable_ntp":
            srv = p.get("ntp_server", "pool.ntp.org")
            return TranslatedFix(
                fix=[f"set system ntp server {srv} prefer"],
                rollback=[f"delete system ntp server {srv}"],
                verify=["show ntp associations"],
            )
        if cid == "restrict_management_access":
            cidrs = p.get("allowed_cidrs", ["10.10.10.0/24"])
            cmds = ["set firewall family inet filter MGMT-IN term ALLOW from "
                    "source-address " + cidrs[0]]
            for c in cidrs[1:]:
                cmds.append(f"set firewall family inet filter MGMT-IN term ALLOW "
                            f"from source-address {c}")
            cmds += ["set firewall family inet filter MGMT-IN term ALLOW then accept",
                     "set firewall family inet filter MGMT-IN term DENY then discard",
                     "set interfaces lo0 unit 0 family inet filter input MGMT-IN"]
            return TranslatedFix(
                fix=cmds,
                rollback=["delete firewall family inet filter MGMT-IN"],
                verify=["show configuration firewall filter MGMT-IN | display set"],
            )
        return TranslatedFix(applicable=False, notes=f"juniper_junos: no translation for {cid}")
