"""
Device categorization + per-device risk scoring.

Given a DiscoveredHost (with MAC, open ports, banners, mDNS services), assign:
  - category: router | switch | firewall | wireless-ap | printer | camera |
              nas | iot | media | voip | server-linux | server-windows |
              workstation-mac | workstation-windows | mobile-ios |
              mobile-android | unknown
  - risk_score: 0-100 (higher = worse)
  - risk_band: safe | low | medium | high | critical
  - findings: list of strings, one per security concern
  - recommended_actions: list of strings, prioritized
"""

from __future__ import annotations

from typing import Any


# ---------------------------------------------------------------- categorization
def categorize_device(host: Any, sysdescr_parsed: dict | None = None) -> str:
    """
    Heuristic classifier. Reads:
      host.mac, host.vendor_guess, host.open_ports, host.banners,
      host.device_type_guess (already set by mDNS), and the parsed sysDescr
    Returns a single category string.
    """
    mac = (host.mac or "").lower()
    vendor = (host.vendor_guess or "").lower()
    ports = set(host.open_ports or [])
    banners_text = " ".join(str(v).lower() for v in (host.banners or {}).values())
    existing = (host.device_type_guess or "").lower()
    sysd = (sysdescr_parsed or {}).get("os", "").lower()
    sysd_vendor = (sysdescr_parsed or {}).get("vendor", "").lower()

    # Existing mDNS classification beats heuristics
    if existing in ("printer", "camera", "media", "smart-home", "server"):
        if existing == "smart-home":
            return "iot"
        return existing

    # SNMP-derived OS gives the strongest signal
    if sysd in ("ios", "ios-xe", "nxos", "eos", "junos", "aos-cx", "aos", "routeros"):
        if "firewall" in banners_text or "asa" in sysd or "fortios" in sysd or "pan-os" in sysd:
            return "firewall"
        if 23 in ports or 22 in ports:
            # Common to all network gear; further differentiate by vendor lines
            return "switch" if "switch" in banners_text or "c3" in banners_text or "c4" in banners_text or "c9" in banners_text else "router"
        return "router"
    if sysd == "esxi" or "vmware" in vendor:
        return "server-linux"
    if sysd == "linux":
        return "server-linux"
    if sysd == "windows":
        return "server-windows"

    # Port-pattern heuristics
    if 9100 in ports or 631 in ports or "cups" in banners_text or "ipp" in banners_text:
        return "printer"
    if 554 in ports or "rtsp" in banners_text or "hikvision" in vendor or "dahua" in vendor:
        return "camera"
    if 5060 in ports or 5061 in ports:
        return "voip"
    if 445 in ports and 139 in ports:
        return "server-windows"
    if 3389 in ports:
        return "server-windows"
    if 22 in ports and 445 not in ports and 80 not in ports:
        return "server-linux"
    if 5000 in ports or "synology" in banners_text or "qnap" in banners_text:
        return "nas"
    if 1900 in ports:  # SSDP / UPnP
        return "iot"
    if 8009 in ports or "chromecast" in banners_text:
        return "media"

    # MAC OUI-based hints
    if any(s in vendor for s in ("apple", "nintendo", "sony")):
        if 22 in ports:
            return "workstation-mac"
        return "media"  # AppleTV / iPad / etc
    if "raspberry" in vendor:
        return "iot"
    if any(s in vendor for s in ("samsung", "lg ")):
        return "media"
    if "tp-link" in vendor or "netgear" in vendor or "asus" in vendor or "linksys" in vendor:
        return "wireless-ap"
    if any(s in vendor for s in ("hewlett", "epson", "brother", "canon", "lexmark", "ricoh", "xerox")):
        return "printer"
    if "cisco" in vendor or "arista" in vendor or "juniper" in vendor:
        return "switch"
    if any(s in vendor for s in ("amazon", "google", "ring", "ecobee", "nest", "philips", "wyze")):
        return "iot"

    # HTTP-only with no banner: probably IoT
    if 80 in ports and 22 not in ports and 23 not in ports:
        return "iot"

    return "unknown"


# ---------------------------------------------------------------- risk scoring
# (port, points, finding, action)
_RISK_PORT_RULES: list[tuple[int, int, str, str]] = [
    (23, 30, "Telnet (port 23) is open — credentials sent in cleartext.",
        "Disable telnet and use SSH (port 22) instead."),
    (21, 25, "FTP (port 21) is open — credentials sent in cleartext.",
        "Disable FTP and use SFTP (port 22) or HTTPS file transfer."),
    (445, 20, "SMB (port 445) is open — verify SMB1 is disabled and patches are current.",
        "Confirm SMB version >= 3.0, disable SMB1, restrict to known clients."),
    (139, 15, "NetBIOS (port 139) is open — legacy Windows file sharing.",
        "Disable if not required; confirm SMB1 disabled."),
    (135, 10, "RPC endpoint mapper (port 135) is open.",
        "Restrict via firewall to known management hosts."),
    (1900, 10, "UPnP (port 1900) is open — common attack vector for IoT.",
        "Disable UPnP on perimeter devices and segment IoT."),
    (5900, 25, "VNC (port 5900) is open — verify password + encryption.",
        "Use VNC with TLS or replace with SSH+X11/RDP."),
    (3389, 15, "RDP (port 3389) is open — verify NLA enabled, MFA on accounts.",
        "Restrict RDP access via NLA + MFA + IP allowlist."),
    (3306, 15, "MySQL (port 3306) is open — verify it is not internet-facing.",
        "Bind MySQL to internal interface only."),
    (5432, 15, "PostgreSQL (port 5432) is open — verify it is not internet-facing.",
        "Bind to internal interface; restrict pg_hba.conf."),
    (6379, 25, "Redis (port 6379) is open — frequent target if no auth.",
        "Enable AUTH, bind to internal interface, enable TLS."),
    (27017, 25, "MongoDB (port 27017) is open — frequent target if no auth.",
        "Require authentication, bind internal, enable TLS."),
    (8080, 5, "HTTP admin (port 8080) is open without TLS.",
        "Move admin UI behind HTTPS only."),
]


def score_device_risk(host: Any, sysdescr_result: dict | None = None) -> dict:
    """
    Compute risk score 0-100 + findings list for a discovered host.
    Returns dict: {score, band, findings, recommended_actions}
    """
    score = 0
    findings: list[str] = []
    actions: list[str] = []
    ports = set(host.open_ports or [])
    banners_text = " ".join(str(v).lower() for v in (host.banners or {}).values())

    # Port-based findings
    for port, pts, desc, action in _RISK_PORT_RULES:
        if port in ports:
            score += pts
            findings.append(desc)
            actions.append(action)

    # SNMP default community working = critical
    if sysdescr_result and sysdescr_result.get("ok"):
        community = sysdescr_result.get("community", "")
        if community.lower() in ("public", "private", "community"):
            score += 40
            findings.append(f"SNMP default community '{community}' is configured — anyone on this LAN can read device state.")
            actions.append("Change SNMP community string to a non-default value, restrict via SNMP ACLs, or disable SNMPv2c entirely.")

    # HTTP without HTTPS for admin-looking devices
    if 80 in ports and 443 not in ports and "router" in (host.device_type_guess or "").lower():
        score += 15
        findings.append("Admin UI on HTTP without HTTPS counterpart — credentials transmitted in cleartext.")
        actions.append("Enable HTTPS on the device and disable HTTP.")

    # Unknown vendor on a sensitive port
    if not host.vendor_guess and any(p in ports for p in (22, 23, 161, 80, 443)):
        score += 10
        findings.append("Device serves management ports but vendor/model could not be identified — investigate.")
        actions.append("Identify the device manually and confirm it belongs on this network.")

    # Self-signed or expired-looking TLS (heuristic from banner)
    if "issuer_cn=" in banners_text and "subject_cn=" in banners_text:
        if "issuer_cn= " in banners_text or "subject_cn= " in banners_text:
            # Empty CN = self-signed bare cert
            score += 5
            findings.append("TLS certificate has empty subject/issuer — likely self-signed.")
            actions.append("Replace with a CA-signed certificate or document self-signed exception.")

    score = min(100, score)
    if score == 0:
        band = "safe"
    elif score < 20:
        band = "low"
    elif score < 50:
        band = "medium"
    elif score < 75:
        band = "high"
    else:
        band = "critical"

    return {
        "score": score,
        "band": band,
        "findings": findings,
        "recommended_actions": actions,
    }
