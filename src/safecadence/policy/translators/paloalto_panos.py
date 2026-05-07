"""Palo Alto PAN-OS translator. Grounded in PAN-OS CLI Reference."""

from __future__ import annotations

from safecadence.policy.schema import PolicyControl
from safecadence.policy.translators import BaseTranslator, TranslatedFix, register_translator


@register_translator("paloalto_panos")
class PaloAltoPANOSTranslator(BaseTranslator):
    asset_match = ["network"]

    def translate(self, control: PolicyControl, asset: dict) -> TranslatedFix:
        cid = control.control_id
        p = control.parameters or {}
        if cid == "disable_telnet":
            return TranslatedFix(
                fix=["set deviceconfig system service disable-telnet yes"],
                rollback=["set deviceconfig system service disable-telnet no"],
                verify=["show config running deviceconfig system service"],
            )
        if cid == "enforce_ssh_v2":
            return TranslatedFix(
                fix=["set deviceconfig system service ssh-version 2"],
                rollback=["delete deviceconfig system service ssh-version"],
                verify=["show config running deviceconfig system service"],
            )
        if cid == "block_insecure_crypto":
            return TranslatedFix(
                fix=["set shared ssl-tls-service-profile WEBADMIN protocol-settings min-version tls1-2",
                     "set shared ssl-tls-service-profile WEBADMIN protocol-settings max-version max"],
                rollback=["delete shared ssl-tls-service-profile WEBADMIN"],
                verify=["show shared ssl-tls-service-profile WEBADMIN"],
            )
        if cid == "enable_syslog":
            target = p.get("syslog_target", "10.10.10.50")
            return TranslatedFix(
                fix=[
                    f"set shared log-settings syslog SC-SYSLOG server SC server {target}",
                    "set shared log-settings syslog SC-SYSLOG server SC transport UDP",
                    "set shared log-settings syslog SC-SYSLOG server SC port 514",
                    "set shared log-settings syslog SC-SYSLOG server SC format BSD",
                    "set shared log-settings syslog SC-SYSLOG server SC facility LOG_USER",
                ],
                rollback=["delete shared log-settings syslog SC-SYSLOG"],
                verify=["show shared log-settings syslog"],
            )
        if cid == "enable_ntp":
            srv = p.get("ntp_server", "pool.ntp.org")
            return TranslatedFix(
                fix=[f"set deviceconfig system ntp-servers primary-ntp-server ntp-server-address {srv}"],
                rollback=["delete deviceconfig system ntp-servers"],
                verify=["show config running deviceconfig system ntp-servers"],
            )
        if cid == "restrict_management_access":
            cidrs = p.get("allowed_cidrs", ["10.10.10.0/24"])
            cmds = []
            for c in cidrs:
                cmds.append(f"set deviceconfig system permitted-ip {c}")
            return TranslatedFix(
                fix=cmds,
                rollback=["delete deviceconfig system permitted-ip"],
                verify=["show config running deviceconfig system permitted-ip"],
            )
        return TranslatedFix(applicable=False, notes=f"paloalto_panos: no translation for {cid}")
