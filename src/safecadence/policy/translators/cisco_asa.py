"""Cisco ASA translator. Grounded in ASA Configuration Guide."""

from __future__ import annotations

from safecadence.policy.schema import PolicyControl
from safecadence.policy.translators import BaseTranslator, TranslatedFix, register_translator


@register_translator("cisco_asa")
class CiscoASATranslator(BaseTranslator):
    asset_match = ["network"]

    def translate(self, control: PolicyControl, asset: dict) -> TranslatedFix:
        cid = control.control_id
        p = control.parameters or {}
        if cid == "disable_telnet":
            return TranslatedFix(
                fix=["no telnet 0.0.0.0 0.0.0.0 outside",
                     "no telnet 0.0.0.0 0.0.0.0 inside"],
                rollback=["telnet 10.10.10.0 255.255.255.0 inside"],
                verify=["show running-config telnet"],
            )
        if cid == "enforce_ssh_v2":
            return TranslatedFix(
                fix=["ssh version 2", "ssh key-exchange group dh-group14-sha1"],
                rollback=["no ssh version 2"],
                verify=["show ssh"],
            )
        if cid == "require_aaa":
            tacacs_host = p.get("tacacs_host", "10.10.10.5")
            tacacs_key = p.get("tacacs_key", "REPLACE_ME")
            return TranslatedFix(
                fix=[
                    "aaa-server TACACS protocol tacacs+",
                    f"aaa-server TACACS (inside) host {tacacs_host}",
                    f" key {tacacs_key}",
                    "aaa authentication ssh console TACACS LOCAL",
                    "aaa accounting command TACACS",
                ],
                rollback=["no aaa-server TACACS protocol tacacs+"],
                verify=["show aaa-server TACACS"],
            )
        if cid == "block_insecure_crypto":
            return TranslatedFix(
                fix=["ssl encryption aes256-sha1 aes128-sha1",
                     "no ssl encryption rc4-md5"],
                rollback=["clear configure ssl"],
                verify=["show ssl"],
            )
        if cid == "enable_syslog":
            target = p.get("syslog_target", "10.10.10.50")
            return TranslatedFix(
                fix=["logging enable",
                     f"logging host inside {target}",
                     "logging trap informational"],
                rollback=[f"no logging host inside {target}"],
                verify=["show logging"],
            )
        if cid == "enable_ntp":
            srv = p.get("ntp_server", "pool.ntp.org")
            return TranslatedFix(
                fix=[f"ntp server {srv}"],
                rollback=[f"no ntp server {srv}"],
                verify=["show ntp associations"],
            )
        return TranslatedFix(applicable=False, notes=f"cisco_asa: no translation for {cid}")
