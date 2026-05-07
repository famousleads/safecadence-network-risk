"""Windows translator. Outputs PowerShell + GPO snippets.

PowerShell snippets are text — they're not executed by SafeCadence.
The user pastes them into an elevated PowerShell prompt, an Ansible
win_powershell task, or a GPO Computer Startup script.
"""

from __future__ import annotations

from safecadence.policy.schema import PolicyControl
from safecadence.policy.translators import BaseTranslator, TranslatedFix, register_translator


@register_translator("windows")
class WindowsTranslator(BaseTranslator):
    asset_match = ["server"]

    def translate(self, control: PolicyControl, asset: dict) -> TranslatedFix:
        cid = control.control_id
        p = control.parameters or {}
        if cid == "enforce_password_policy":
            min_len = int(p.get("min_length", 14))
            return TranslatedFix(
                fix=["# Local Security Policy via secedit:",
                     "secedit /export /cfg C:\\Windows\\Temp\\sec.cfg",
                     f"(Get-Content C:\\Windows\\Temp\\sec.cfg) -replace 'MinimumPasswordLength = .*','MinimumPasswordLength = {min_len}' | "
                     "Set-Content C:\\Windows\\Temp\\sec.cfg",
                     "secedit /configure /db secedit.sdb /cfg C:\\Windows\\Temp\\sec.cfg /areas SECURITYPOLICY"],
                rollback=["# revert from prior backup of sec.cfg"],
                verify=["net accounts"],
            )
        if cid == "enforce_mfa":
            return TranslatedFix(
                fix=["# Enable Windows Hello / Smart Card via GPO:",
                     "# Computer Configuration > Administrative Templates > Windows Components > Windows Hello for Business",
                     "# OR via Azure AD MFA — configured at the tenant level, not per host"],
                rollback=["# Disable Windows Hello via the same GPO setting"],
                verify=["Get-ADDomain | Select-Object NetBIOSName"],
                notes="MFA is typically managed at the identity-provider level (Azure AD / Entra ID).",
            )
        if cid == "enforce_encryption_in_transit":
            return TranslatedFix(
                fix=["# Disable SMBv1:",
                     "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
                     "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart",
                     "# Disable insecure cipher suites:",
                     "Disable-TlsCipherSuite -Name 'TLS_RSA_WITH_RC4_128_SHA'",
                     "Disable-TlsCipherSuite -Name 'TLS_RSA_WITH_RC4_128_MD5'"],
                rollback=["Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force"],
                verify=["Get-SmbServerConfiguration | Select EnableSMB1Protocol",
                        "Get-TlsCipherSuite | Where-Object Name -like '*RC4*'"],
            )
        if cid == "enable_syslog":
            target = p.get("syslog_target", "10.10.10.50")
            return TranslatedFix(
                fix=[
                    "# Use NXLog or winlogbeat to forward Windows Event Log to syslog.",
                    "# NXLog config sample:",
                    "<Output out_safecadence>",
                    "  Module om_udp",
                    f"  Host {target}",
                    "  Port 514",
                    "</Output>",
                ],
                rollback=["# Remove the <Output> block from nxlog.conf and restart NXLog"],
                verify=["Get-Service NXLog"],
            )
        if cid == "enforce_patch_level":
            return TranslatedFix(
                fix=["Get-WindowsUpdate -AcceptAll -AutoReboot -Install",
                     "# Or: Install-WindowsUpdate -AcceptAll -AutoReboot",
                     "# Requires PSWindowsUpdate module: Install-Module PSWindowsUpdate -Force"],
                rollback=["# Roll back via 'Get-WUUninstall -KBArticleID KBxxxxxxx'"],
                verify=["Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10"],
            )
        if cid == "restrict_default_creds":
            return TranslatedFix(
                fix=["Disable-LocalUser -Name Administrator",
                     "Disable-LocalUser -Name Guest",
                     "# Optionally rename the admin account:",
                     "Rename-LocalUser -Name Administrator -NewName admin_rotated"],
                rollback=["Enable-LocalUser -Name Administrator"],
                verify=["Get-LocalUser | Select Name, Enabled"],
            )
        return TranslatedFix(applicable=False, notes=f"windows: no translation for {cid}")
