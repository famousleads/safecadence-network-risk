"""
Toxic Combinations Engine — finds dangerous *combinations* of findings.

Individual findings are useful. The combinations are where breaches happen:
  * Telnet open + default credentials → owned in seconds
  * SMB1 + outdated OS + KEV CVE → ransomware target
  * Public-facing + admin port + no MFA → account takeover

Each combination has:
  - severity (compound, often higher than its parts)
  - a "story" explaining the attack scenario
  - a single break-the-chain action that defuses it

Pure heuristic — no AI. Adds to the per-device findings list.
"""

from __future__ import annotations

from typing import Any


# Each combo: name, predicate (dict → bool), severity_boost, story, single_fix
_COMBINATIONS = [
    {
        "name": "Cleartext-admin",
        "predicate": lambda d: 23 in (d.get("open_ports") or []) and any(p in (d.get("open_ports") or []) for p in (80, 8080)),
        "severity": "critical",
        "score_boost": 35,
        "story": "Telnet (port 23) AND HTTP admin (port 80/8080) both open without TLS. Anyone on this network can sniff admin credentials in cleartext from either channel.",
        "fix": "Disable telnet + force HTTPS for the admin UI. This single change closes both attack vectors.",
    },
    {
        "name": "Default-SNMP-with-Telnet",
        "predicate": lambda d: 23 in (d.get("open_ports") or []) and 161 in (d.get("open_ports") or []),
        "severity": "critical",
        "score_boost": 30,
        "story": "Telnet AND SNMP both exposed. If SNMP is using default community ('public'/'private'), an attacker can dump the device's full configuration via SNMP, then use telnet to apply changes — all without credentials.",
        "fix": "Disable telnet, change SNMP community from default, restrict SNMP to a management host via ACL.",
    },
    {
        "name": "SMB-fileshare-on-IoT",
        "predicate": lambda d: 445 in (d.get("open_ports") or []) and (d.get("category", "") in ("iot", "camera", "printer")),
        "severity": "high",
        "score_boost": 25,
        "story": "An IoT/camera/printer device should never expose SMB. This is a classic ransomware lateral-movement target — devices that don't get patched + open file shares = perfect pivot point.",
        "fix": "Disable SMB on this device entirely. If file sharing is required, segment it onto a dedicated VLAN behind a firewall.",
    },
    {
        "name": "RDP-on-LAN",
        "predicate": lambda d: 3389 in (d.get("open_ports") or []),
        "severity": "high",
        "score_boost": 20,
        "story": "RDP exposed on the LAN. Even when not internet-facing, RDP is the #1 lateral-movement vector once an attacker gets a foothold. Without NLA + MFA, a single compromised credential gives full desktop access.",
        "fix": "Enforce Network Level Authentication (NLA), require MFA for all RDP logons, restrict RDP source IPs via Windows Firewall.",
    },
    {
        "name": "KEV-on-edge-device",
        "predicate": lambda d: any(c.get("kev") for c in (d.get("cves") or [])) and (d.get("category", "") in ("router", "firewall", "wireless-ap")),
        "severity": "critical",
        "score_boost": 40,
        "story": "This device is a network edge device (router/firewall/AP) AND has a CISA-KEV-listed vulnerability. KEV-listed means the CVE is being actively exploited in the wild RIGHT NOW. Edge devices are the #1 entry point for breaches.",
        "fix": "Patch the KEV-listed CVE within 48 hours per CISA Binding Operational Directive 22-01.",
    },
    {
        "name": "EOL-with-network-services",
        "predicate": lambda d: ("eol" in str(d.get("os", "")).lower() or "deprecated" in str(d.get("os", "")).lower()) and len(d.get("open_ports") or []) >= 3,
        "severity": "high",
        "score_boost": 25,
        "story": "OS is past end-of-life AND device exposes 3+ network services. EOL means no more security patches. New CVEs WILL be discovered and WILL go unfixed. Each open port is a future zero-day surface.",
        "fix": "Plan replacement within the current quarter. In the meantime, segment this device onto an isolated VLAN with strict egress filtering.",
    },
    {
        "name": "Multiple-cleartext-protocols",
        "predicate": lambda d: sum(1 for p in (d.get("open_ports") or []) if p in (21, 23, 80, 8080, 5060)) >= 2,
        "severity": "medium",
        "score_boost": 15,
        "story": "Two or more cleartext protocols (FTP/Telnet/HTTP/SIP) are exposed. Any attacker on the LAN can passively sniff credentials AND content from this device.",
        "fix": "Replace each cleartext protocol with its TLS equivalent (FTPS, SSH, HTTPS, SIPS).",
    },
    {
        "name": "SNMP-and-management-protocols",
        "predicate": lambda d: 161 in (d.get("open_ports") or []) and any(p in (d.get("open_ports") or []) for p in (22, 23, 80, 443)) and not d.get("snmp_sysdescr"),
        "severity": "medium",
        "score_boost": 12,
        "story": "Device exposes SNMP and admin protocols, but SNMP didn't respond to the safecadence probe — meaning the community string is non-default OR SNMP is properly ACL'd. Verify which.",
        "fix": "Confirm SNMP ACL is in place. If running SNMPv2c, upgrade to SNMPv3 with authentication + encryption.",
    },
    {
        "name": "Unidentified-device-with-many-services",
        "predicate": lambda d: not d.get("vendor") and len(d.get("open_ports") or []) >= 4,
        "severity": "medium",
        "score_boost": 18,
        "story": "Device exposes 4+ services but vendor/model could not be identified. Unknown devices on a LAN are a baseline anomaly. Could be: rogue device, BYOD endpoint, neglected legacy box, or attacker pivot point.",
        "fix": "Physically locate the device. Determine if authorized. If yes, identify the model and add to the asset inventory. If no, disconnect.",
    },
    {
        "name": "Multiple-CVEs-stacking",
        "predicate": lambda d: len(d.get("cves") or []) >= 3,
        "severity": "high",
        "score_boost": 20,
        "story": "Device matches 3+ CVEs. Even if individual CVEs are medium-severity, the combination significantly raises the chance of successful exploitation — attackers chain low-severity bugs to bypass mitigations.",
        "fix": "Update to the latest stable firmware/OS. Most multi-CVE-exposed devices are 1-2 versions behind.",
    },
]


def find_toxic_combinations(device: dict) -> list[dict]:
    """
    Evaluate all toxic-combination predicates against a device.
    Returns list of triggered combinations with details.
    """
    matches = []
    for combo in _COMBINATIONS:
        try:
            if combo["predicate"](device):
                matches.append({
                    "name": combo["name"],
                    "severity": combo["severity"],
                    "score_boost": combo["score_boost"],
                    "story": combo["story"],
                    "fix": combo["fix"],
                })
        except Exception:
            continue
    return matches


def enrich_device_with_toxic_combos(device: dict) -> dict:
    """
    Add toxic_combinations field, push compound findings into findings list,
    and boost the risk score (capped at 100).
    """
    combos = find_toxic_combinations(device)
    device["toxic_combinations"] = combos

    if combos:
        # Boost risk score by sum of boosts (capped at 100)
        boost = sum(c["score_boost"] for c in combos)
        device["risk_score"] = min(100, device.get("risk_score", 0) + boost)

        # Re-band based on new score
        score = device["risk_score"]
        if score >= 75:
            device["risk_band"] = "critical"
        elif score >= 50:
            device["risk_band"] = "high"
        elif score >= 25:
            device["risk_band"] = "medium"

        # Add compound findings to the findings list
        for c in combos:
            device.setdefault("findings", []).insert(0,
                f"⚠️ TOXIC COMBO ({c['severity']}): {c['story']}"
            )
            device.setdefault("recommended_actions", []).insert(0,
                f"[Compound fix] {c['fix']}"
            )

    return device


def fleet_toxic_summary(results: list[dict]) -> dict:
    """Summary of toxic combinations across the fleet."""
    by_combo: dict[str, int] = {}
    devices_with_combos = 0
    total = 0
    for d in results:
        combos = d.get("toxic_combinations", [])
        if combos:
            devices_with_combos += 1
            for c in combos:
                total += 1
                by_combo[c["name"]] = by_combo.get(c["name"], 0) + 1
    top = sorted(by_combo.items(), key=lambda kv: -kv[1])[:5]
    return {
        "total_combinations": total,
        "devices_with_combinations": devices_with_combos,
        "top_combinations": [{"name": n, "device_count": c} for n, c in top],
    }
