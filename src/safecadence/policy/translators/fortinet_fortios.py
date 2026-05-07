"""Fortinet FortiOS translator. Grounded in FortiOS CLI Reference."""

from __future__ import annotations

from safecadence.policy.schema import PolicyControl
from safecadence.policy.translators import BaseTranslator, TranslatedFix, register_translator


@register_translator("fortinet_fortios")
class FortinetFortiOSTranslator(BaseTranslator):
    asset_match = ["network"]

    def translate(self, control: PolicyControl, asset: dict) -> TranslatedFix:
        cid = control.control_id
        p = control.parameters or {}
        if cid == "disable_telnet":
            return TranslatedFix(
                fix=["config system global", " set admin-telnet disable", "end"],
                rollback=["config system global", " set admin-telnet enable", "end"],
                verify=["get system global | grep telnet"],
            )
        if cid == "enforce_ssh_v2":
            return TranslatedFix(
                fix=["config system global", " set admin-ssh-v1 disable", "end"],
                rollback=["config system global", " set admin-ssh-v1 enable", "end"],
                verify=["get system global | grep ssh"],
            )
        if cid == "block_insecure_crypto":
            return TranslatedFix(
                fix=["config system global",
                     " set strong-crypto enable",
                     " set ssl-min-proto-version TLSv1-2",
                     "end"],
                rollback=["config system global", " set strong-crypto disable", "end"],
                verify=["get system global | grep crypto"],
            )
        if cid == "enable_syslog":
            target = p.get("syslog_target", "10.10.10.50")
            return TranslatedFix(
                fix=[
                    "config log syslogd setting",
                    " set status enable",
                    f" set server \"{target}\"",
                    " set facility local7",
                    " set source-ip 0.0.0.0",
                    "end",
                ],
                rollback=["config log syslogd setting", " set status disable", "end"],
                verify=["get log syslogd setting"],
            )
        if cid == "enable_ntp":
            srv = p.get("ntp_server", "pool.ntp.org")
            return TranslatedFix(
                fix=[
                    "config system ntp",
                    " set ntpsync enable",
                    " set type custom",
                    " config ntpserver",
                    "  edit 1",
                    f"   set server \"{srv}\"",
                    "  next",
                    " end",
                    "end",
                ],
                rollback=["config system ntp", " set ntpsync disable", "end"],
                verify=["get system ntp"],
            )
        if cid == "restrict_management_access":
            cidrs = p.get("allowed_cidrs", ["10.10.10.0/24"])
            cmds = ["config system trusted-host"]
            for i, c in enumerate(cidrs, 1):
                ip, mask = c.split("/")
                cmds += [f" edit {i}", f"  set ip {ip}/{mask}", " next"]
            cmds += ["end"]
            return TranslatedFix(
                fix=cmds,
                rollback=["config system trusted-host", " purge", "end"],
                verify=["get system trusted-host"],
            )
        if cid == "restrict_default_creds":
            return TranslatedFix(
                fix=["config system admin", " edit admin",
                     "  set password REPLACE_STRONG_PASSWORD", " next", "end"],
                rollback=[],
                verify=["get system admin admin"],
                notes="Replace REPLACE_STRONG_PASSWORD with a strong password before applying.",
            )
        return TranslatedFix(applicable=False, notes=f"fortinet_fortios: no translation for {cid}")
