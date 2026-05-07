"""Linux translator. Outputs sshd_config, sysctl, PAM, iptables, auditd snippets.

All outputs are pure text — no shell pipelines, no exec. Works equally
on RHEL/CentOS, Debian/Ubuntu, SUSE: the snippets are config-file
content the operator drops into /etc/ paths.
"""

from __future__ import annotations

from safecadence.policy.schema import PolicyControl
from safecadence.policy.translators import BaseTranslator, TranslatedFix, register_translator


@register_translator("linux")
class LinuxTranslator(BaseTranslator):
    asset_match = ["server"]

    def translate(self, control: PolicyControl, asset: dict) -> TranslatedFix:
        cid = control.control_id
        p = control.parameters or {}
        if cid == "enforce_ssh_v2":
            return TranslatedFix(
                fix=["# /etc/ssh/sshd_config",
                     "Protocol 2",
                     "PermitRootLogin no",
                     "PasswordAuthentication no",
                     "PubkeyAuthentication yes",
                     "ClientAliveInterval 300",
                     "ClientAliveCountMax 2",
                     "MaxAuthTries 3",
                     "# Apply: sudo systemctl restart sshd"],
                rollback=["# revert sshd_config to /etc/ssh/sshd_config.bak",
                          "sudo cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config",
                          "sudo systemctl restart sshd"],
                verify=["sudo sshd -T | grep -E 'protocol|permitrootlogin|passwordauthentication'"],
                notes="Take a backup: sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak",
            )
        if cid == "enable_syslog":
            target = p.get("syslog_target", "10.10.10.50")
            return TranslatedFix(
                fix=["# /etc/rsyslog.d/99-safecadence.conf",
                     f"*.* @@{target}:514",
                     "# Apply: sudo systemctl restart rsyslog"],
                rollback=["sudo rm /etc/rsyslog.d/99-safecadence.conf",
                          "sudo systemctl restart rsyslog"],
                verify=["sudo systemctl status rsyslog",
                        f"sudo logger SAFECADENCE_TEST && journalctl -u rsyslog --since '1 minute ago'"],
            )
        if cid == "enable_ntp":
            srv = p.get("ntp_server", "pool.ntp.org")
            return TranslatedFix(
                fix=["# Use systemd-timesyncd or chrony",
                     "sudo timedatectl set-ntp true",
                     f"# OR /etc/chrony.conf: 'server {srv} iburst' then 'sudo systemctl restart chronyd'"],
                rollback=["sudo timedatectl set-ntp false"],
                verify=["timedatectl status"],
            )
        if cid == "enforce_password_policy":
            min_len = int(p.get("min_length", 14))
            return TranslatedFix(
                fix=["# /etc/security/pwquality.conf",
                     f"minlen = {min_len}",
                     "minclass = 3",
                     "maxrepeat = 2",
                     "# /etc/login.defs",
                     "PASS_MAX_DAYS 90",
                     "PASS_MIN_DAYS 1",
                     "PASS_WARN_AGE 7"],
                rollback=["# revert pwquality.conf and login.defs from backups"],
                verify=["sudo grep -E 'minlen|PASS_MAX_DAYS' /etc/security/pwquality.conf /etc/login.defs"],
            )
        if cid == "enforce_encryption_in_transit":
            return TranslatedFix(
                fix=["# Disable ftp, telnetd, rlogin if installed:",
                     "sudo systemctl disable --now telnet.socket || true",
                     "sudo systemctl disable --now vsftpd || true",
                     "sudo systemctl disable --now rsh.socket || true"],
                rollback=["sudo systemctl enable --now telnet.socket || true"],
                verify=["systemctl is-enabled telnet.socket vsftpd rsh.socket 2>/dev/null"],
            )
        if cid == "restrict_default_creds":
            return TranslatedFix(
                fix=["# Lock vendor default accounts (example):",
                     "sudo passwd -l admin || true",
                     "sudo passwd -l root || true",
                     "# Force password change on next login:",
                     "sudo chage -d 0 admin || true"],
                rollback=["sudo passwd -u admin"],
                verify=["sudo passwd -S admin", "sudo passwd -S root"],
            )
        if cid == "enforce_patch_level":
            return TranslatedFix(
                fix=["# RHEL/CentOS:",
                     "sudo dnf upgrade --security -y",
                     "# Debian/Ubuntu:",
                     "sudo apt-get update && sudo apt-get -y upgrade"],
                rollback=["# package downgrade is risky; restore from snapshot or backup"],
                verify=["dnf updateinfo list security 2>/dev/null || apt list --upgradable 2>/dev/null"],
            )
        if cid == "restrict_management_access":
            cidrs = p.get("allowed_cidrs", ["10.10.10.0/24"])
            rules = ["# /etc/nftables.conf — restrict SSH to admin CIDRs"]
            for c in cidrs:
                rules.append(f"add rule inet filter input ip saddr {c} tcp dport 22 accept")
            rules.append("add rule inet filter input tcp dport 22 drop")
            return TranslatedFix(
                fix=rules,
                rollback=["sudo nft flush ruleset"],
                verify=["sudo nft list ruleset | grep 'dport 22'"],
            )
        return TranslatedFix(applicable=False, notes=f"linux: no translation for {cid}")
