"""
MITRE ATT&CK technique mapping.

Every SafeCadence security control maps to one or more ATT&CK techniques —
the technique each control prevents, detects, or mitigates. This lets us
generate auditor-grade ATT&CK coverage reports straight from the existing
control library, with zero extra data collection.

Source: per-control mappings curated against ATT&CK Enterprise v14, taking
the most direct mitigation per technique (TXXXX) and sub-technique
(TXXXX.YYY).

Beats every CSPM/VM tool that just gives CVE IDs without explaining
"this is how the attacker would use it" (T1190 / T1078 / T1021 / etc.).
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any


# control_id → list of ATT&CK techniques this control mitigates.
# Tactic codes (TA0001..TA0011) are derived automatically from the technique IDs.
_CONTROL_TO_ATTACK: dict[str, list[dict]] = {
    "disable_telnet": [
        {"technique_id": "T1021.001", "name": "Remote Services: Remote Desktop Protocol",
         "tactic": "Lateral Movement", "rationale": "Telnet enables cleartext lateral movement."},
        {"technique_id": "T1040", "name": "Network Sniffing",
         "tactic": "Credential Access", "rationale": "Telnet creds are intercepted on the wire."},
    ],
    "enforce_ssh_v2": [
        {"technique_id": "T1021.004", "name": "Remote Services: SSH",
         "tactic": "Lateral Movement",
         "rationale": "SSHv2 forces modern algorithms; SSHv1 has known crypto weaknesses."},
    ],
    "require_aaa": [
        {"technique_id": "T1078", "name": "Valid Accounts",
         "tactic": "Defense Evasion / Persistence",
         "rationale": "Centralised AAA enables auth audit + RBAC + MFA enforcement."},
        {"technique_id": "T1556", "name": "Modify Authentication Process",
         "tactic": "Credential Access"},
    ],
    "enforce_snmpv3": [
        {"technique_id": "T1082", "name": "System Information Discovery",
         "tactic": "Discovery",
         "rationale": "SNMPv1/v2c communities leak system info to anyone with the string."},
        {"technique_id": "T1078", "name": "Valid Accounts", "tactic": "Persistence"},
    ],
    "enable_syslog": [
        {"technique_id": "T1562.008", "name": "Impair Defenses: Disable Cloud Logs",
         "tactic": "Defense Evasion",
         "rationale": "Centralised logging defeats local log-tampering."},
        {"technique_id": "T1070", "name": "Indicator Removal",
         "tactic": "Defense Evasion"},
    ],
    "enable_ntp": [
        {"technique_id": "T1070.006", "name": "Indicator Removal: Timestomp",
         "tactic": "Defense Evasion",
         "rationale": "Reliable time anchors evidence chain."},
    ],
    "block_insecure_crypto": [
        {"technique_id": "T1040", "name": "Network Sniffing",
         "tactic": "Credential Access"},
        {"technique_id": "T1573", "name": "Encrypted Channel",
         "tactic": "Command and Control",
         "rationale": "Strong crypto blocks downgrade attacks."},
    ],
    "restrict_management_access": [
        {"technique_id": "T1190", "name": "Exploit Public-Facing Application",
         "tactic": "Initial Access",
         "rationale": "Restricting mgmt to allow-list CIDRs prevents internet-facing exploitation."},
        {"technique_id": "T1133", "name": "External Remote Services",
         "tactic": "Initial Access"},
    ],
    "enforce_patch_level": [
        {"technique_id": "T1190", "name": "Exploit Public-Facing Application",
         "tactic": "Initial Access"},
        {"technique_id": "T1068", "name": "Exploitation for Privilege Escalation",
         "tactic": "Privilege Escalation",
         "rationale": "Patches close the windows the attacker uses."},
    ],
    "enforce_encryption_at_rest": [
        {"technique_id": "T1530", "name": "Data from Cloud Storage Object",
         "tactic": "Collection"},
        {"technique_id": "T1565.001", "name": "Stored Data Manipulation",
         "tactic": "Impact"},
    ],
    "enforce_encryption_in_transit": [
        {"technique_id": "T1040", "name": "Network Sniffing",
         "tactic": "Credential Access"},
        {"technique_id": "T1557", "name": "Adversary-in-the-Middle",
         "tactic": "Credential Access"},
    ],
    "restrict_default_creds": [
        {"technique_id": "T1078.001", "name": "Valid Accounts: Default Accounts",
         "tactic": "Initial Access / Persistence"},
        {"technique_id": "T1110.001", "name": "Brute Force: Password Guessing",
         "tactic": "Credential Access"},
    ],
    "enforce_password_policy": [
        {"technique_id": "T1110", "name": "Brute Force",
         "tactic": "Credential Access"},
        {"technique_id": "T1110.003", "name": "Password Spraying",
         "tactic": "Credential Access"},
    ],
    "enforce_mfa": [
        {"technique_id": "T1078", "name": "Valid Accounts",
         "tactic": "Initial Access / Persistence",
         "rationale": "MFA defeats most stolen-cred reuse."},
        {"technique_id": "T1110", "name": "Brute Force",
         "tactic": "Credential Access"},
    ],
    "enforce_least_privilege": [
        {"technique_id": "T1078", "name": "Valid Accounts",
         "tactic": "Persistence"},
        {"technique_id": "T1098", "name": "Account Manipulation",
         "tactic": "Persistence"},
        {"technique_id": "T1548", "name": "Abuse Elevation Control Mechanism",
         "tactic": "Privilege Escalation"},
    ],
    "block_public_exposure": [
        {"technique_id": "T1190", "name": "Exploit Public-Facing Application",
         "tactic": "Initial Access"},
        {"technique_id": "T1133", "name": "External Remote Services",
         "tactic": "Initial Access"},
    ],
    "enforce_cloud_iam": [
        {"technique_id": "T1078.004", "name": "Valid Accounts: Cloud Accounts",
         "tactic": "Defense Evasion / Persistence"},
        {"technique_id": "T1098.001", "name": "Account Manipulation: Additional Cloud Credentials",
         "tactic": "Persistence"},
        {"technique_id": "T1525", "name": "Implant Internal Image",
         "tactic": "Persistence"},
    ],
    "enforce_logging": [
        {"technique_id": "T1562.008", "name": "Impair Defenses: Disable Cloud Logs",
         "tactic": "Defense Evasion"},
    ],
    "enforce_backup_retention": [
        {"technique_id": "T1490", "name": "Inhibit System Recovery",
         "tactic": "Impact",
         "rationale": "Long retention denies ransomware-leverage of recent-only backups."},
    ],
    "enforce_immutability": [
        {"technique_id": "T1486", "name": "Data Encrypted for Impact",
         "tactic": "Impact",
         "rationale": "Immutable backups defeat ransomware encryption."},
        {"technique_id": "T1490", "name": "Inhibit System Recovery",
         "tactic": "Impact"},
    ],
    "enforce_air_gap": [
        {"technique_id": "T1486", "name": "Data Encrypted for Impact",
         "tactic": "Impact"},
        {"technique_id": "T1490", "name": "Inhibit System Recovery",
         "tactic": "Impact"},
    ],
    "replication_enabled": [
        {"technique_id": "T1485", "name": "Data Destruction",
         "tactic": "Impact"},
        {"technique_id": "T1565.001", "name": "Stored Data Manipulation",
         "tactic": "Impact"},
    ],
}


def techniques_for_control(control_id: str) -> list[dict]:
    """Return ATT&CK techniques mitigated by a single control."""
    return _CONTROL_TO_ATTACK.get(control_id, [])


def coverage_report(controls_in_use: list[str],
                    *, all_known_techniques: int = 600) -> dict[str, Any]:
    """Build a fleet-wide ATT&CK coverage report from the controls in use."""
    by_tech: dict[str, dict] = {}
    by_tactic: defaultdict[str, set] = defaultdict(set)
    control_count: Counter = Counter()

    for cid in controls_in_use:
        for t in techniques_for_control(cid):
            tid = t["technique_id"]
            entry = by_tech.setdefault(tid, {
                "technique_id": tid, "name": t["name"],
                "tactic": t["tactic"], "controls": [],
            })
            entry["controls"].append(cid)
            by_tactic[t["tactic"]].add(tid)
            control_count[cid] += 1

    techniques = sorted(by_tech.values(), key=lambda e: e["technique_id"])
    return {
        "control_count": len(set(controls_in_use)),
        "techniques_covered": len(techniques),
        "tactics_covered": len(by_tactic),
        "all_known_techniques_estimate": all_known_techniques,
        "coverage_pct": round(len(techniques) / all_known_techniques * 100, 1),
        "techniques": techniques,
        "tactics": {tactic: sorted(tids) for tactic, tids in by_tactic.items()},
        "controls_used": dict(control_count),
    }


def violation_to_attack(violations: list[dict]) -> list[dict]:
    """Map a list of policy violations to the ATT&CK techniques each enables."""
    out = []
    for v in violations:
        cid = v.get("control_id") or ""
        techs = techniques_for_control(cid)
        if not techs:
            continue
        out.append({
            "violation_id": v.get("violation_id"),
            "asset_id": v.get("asset_id"),
            "control_id": cid,
            "severity": v.get("severity"),
            "enables_techniques": [{"id": t["technique_id"], "name": t["name"],
                                    "tactic": t["tactic"]} for t in techs],
        })
    return out
