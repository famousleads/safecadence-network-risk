"""Cisco IOS / IOS-XE translator. Grounded in Cisco IOS Configuration Guide."""

from __future__ import annotations

from safecadence.policy.schema import PolicyControl
from safecadence.policy.translators import BaseTranslator, TranslatedFix, register_translator


@register_translator("cisco_ios")
class CiscoIOSTranslator(BaseTranslator):
    asset_match = ["network"]

    def translate(self, control: PolicyControl, asset: dict) -> TranslatedFix:
        cid = control.control_id
        p = control.parameters or {}
        if cid == "disable_telnet":
            return TranslatedFix(
                fix=["line vty 0 15", " transport input ssh", " no transport input telnet", "exit"],
                rollback=["line vty 0 15", " transport input ssh telnet", "exit"],
                verify=["show running-config | include transport input"],
            )
        if cid == "enforce_ssh_v2":
            return TranslatedFix(
                fix=["ip ssh version 2", "ip ssh server algorithm mac hmac-sha2-256",
                     "ip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr"],
                rollback=["no ip ssh version 2"],
                verify=["show ip ssh"],
            )
        if cid == "require_aaa":
            tacacs_host = p.get("tacacs_host", "10.10.10.5")
            tacacs_key = p.get("tacacs_key", "REPLACE_ME")
            return TranslatedFix(
                fix=[
                    "aaa new-model",
                    f"tacacs server PRIMARY",
                    f" address ipv4 {tacacs_host}",
                    f" key {tacacs_key}",
                    "aaa group server tacacs+ TACACS_SRV",
                    " server name PRIMARY",
                    "aaa authentication login default group TACACS_SRV local",
                    "aaa authorization exec default group TACACS_SRV local",
                    "aaa accounting exec default start-stop group TACACS_SRV",
                ],
                rollback=["no aaa new-model", f"no tacacs server PRIMARY"],
                verify=["show aaa servers", "show aaa method-lists"],
                notes="Replace TACACS key before applying.",
            )
        if cid == "enforce_snmpv3":
            user = p.get("snmp_user", "snmpv3user")
            return TranslatedFix(
                fix=[
                    "no snmp-server community public",
                    "no snmp-server community private",
                    "snmp-server group SC-RO v3 priv read v1default",
                    f"snmp-server user {user} SC-RO v3 auth sha REPLACE_AUTH priv aes 256 REPLACE_PRIV",
                ],
                rollback=[f"no snmp-server user {user} SC-RO v3"],
                verify=["show snmp user", "show snmp group"],
                notes="Replace REPLACE_AUTH and REPLACE_PRIV before applying.",
            )
        if cid == "enable_syslog":
            target = p.get("syslog_target", "10.10.10.50")
            return TranslatedFix(
                fix=[f"logging host {target}", "logging trap informational",
                     "logging buffered 65536 informational", "service timestamps log datetime msec"],
                rollback=[f"no logging host {target}"],
                verify=["show logging"],
            )
        if cid == "enable_ntp":
            srv = p.get("ntp_server", "pool.ntp.org")
            return TranslatedFix(
                fix=[f"ntp server {srv}", "ntp authenticate"],
                rollback=[f"no ntp server {srv}"],
                verify=["show ntp associations", "show ntp status"],
            )
        if cid == "block_insecure_crypto":
            return TranslatedFix(
                fix=["no ip http server", "ip http secure-server",
                     "ip http secure-ciphersuite aes-128-cbc-sha aes-256-cbc-sha"],
                rollback=["ip http server"],
                verify=["show ip http server status"],
            )
        if cid == "restrict_management_access":
            cidrs = p.get("allowed_cidrs", ["10.10.10.0/24"])
            acl = ["ip access-list standard MGMT-IN"]
            for c in cidrs:
                ip, mask_bits = c.split("/")
                wildcard = ".".join(str(255 - int(o)) for o in
                                     _expand_mask(int(mask_bits)).split("."))
                acl.append(f" permit {ip} {wildcard}")
            acl += [" deny any log",
                    "line vty 0 15", " access-class MGMT-IN in", "exit"]
            return TranslatedFix(
                fix=acl,
                rollback=["line vty 0 15", " no access-class MGMT-IN in", "exit",
                          "no ip access-list standard MGMT-IN"],
                verify=["show access-lists MGMT-IN", "show line vty 0 15 | include access"],
            )
        return TranslatedFix(applicable=False, notes=f"cisco_ios: no translation for {cid}")


def _expand_mask(bits: int) -> str:
    val = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
    return ".".join(str((val >> (8 * i)) & 0xFF) for i in (3, 2, 1, 0))
