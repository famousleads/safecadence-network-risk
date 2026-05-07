"""
Match discovered devices against the bundled CVE database.

Uses safecadence.enrichment.cve.find_cves() but normalizes the inputs from
discovery results (which may have looser version info than a parsed config).

Returns a per-device list of CVEs sorted by severity/KEV.
"""

from __future__ import annotations

import re
from typing import Any

from safecadence.enrichment.cve import find_cves


def _normalize_vendor(v: str) -> str:
    if not v:
        return ""
    vl = v.lower()
    if "cisco" in vl:
        return "cisco"
    if "aruba" in vl or "hpe" in vl:
        return "aruba"
    if "arista" in vl:
        return "arista"
    if "juniper" in vl:
        return "juniper"
    if "fortinet" in vl or "fortios" in vl:
        return "fortinet"
    if "palo alto" in vl or "pan-os" in vl:
        return "paloalto"
    if "mikrotik" in vl:
        return "mikrotik"
    if "synology" in vl:
        return "synology"
    if "qnap" in vl:
        return "qnap"
    if "vmware" in vl or "esxi" in vl:
        return "vmware"
    return vl.split()[0]


def _extract_version(s: str) -> str:
    """
    Pull the first version-like token out of a sysDescr string.
    Handles forms like 'Version 12.2(55)SE9', '15.0(2)SE12', '7.4.1', 'PAN-OS 11.0.4'.
    """
    if not s:
        return ""
    # Pattern A: 'Version X.Y(Z)...'
    m = re.search(r"version[:\s]+([0-9]+\.[0-9]+(?:\([0-9a-zA-Z]+\))?(?:[A-Za-z0-9\-.]+)?)", s, re.IGNORECASE)
    if m:
        return m.group(1)
    # Pattern B: bare semantic version
    m = re.search(r"\b([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[A-Za-z0-9\-.]+)?)\b", s)
    if m:
        return m.group(1)
    return ""


def cves_for_device(host_dict: dict) -> list[dict]:
    """
    Match a discovered device dict against the bundled CVE DB.
    Returns list of CVE dicts with: cve_id, severity, cvss, title, kev, fixed_in,
    description (truncated), references, workaround.
    Sorted: KEV first, then by CVSS desc.
    """
    vendor = _normalize_vendor(host_dict.get("vendor", ""))
    if not vendor:
        return []

    os_name = (host_dict.get("os", "") or "").lower()
    sysdescr = host_dict.get("snmp_sysdescr", "") or ""

    # Try to extract version from os_version, sysdescr, or banners
    version = (host_dict.get("os_version", "") or "").strip()
    if not version and sysdescr:
        version = _extract_version(sysdescr)
    if not version:
        # Try banners (e.g. SSH-2.0-OpenSSH_8.4 has version in protocol)
        for b in (host_dict.get("banners", {}) or {}).values():
            v = _extract_version(str(b))
            if v:
                version = v
                break

    try:
        matches = find_cves(vendor=vendor, os=os_name, version=version)
    except Exception:
        matches = []

    out = []
    for c in matches:
        d = c.to_dict() if hasattr(c, "to_dict") else dict(c)
        # Truncate description for UI
        if d.get("description"):
            d["description"] = d["description"][:300] + ("…" if len(d["description"]) > 300 else "")
        out.append(d)

    # Sort: KEV first, then CVSS desc, then severity rank
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    out.sort(key=lambda c: (
        not c.get("kev", False),
        -(c.get("cvss", 0) or 0),
        -sev_rank.get((c.get("severity") or "").lower(), 0),
    ))
    return out


def cve_summary_for_fleet(results: list[dict]) -> dict:
    """
    Aggregate fleet-wide CVE statistics from a discover result list.
    """
    total_cves = 0
    kev_cves = 0
    devices_with_cves = 0
    devices_with_kev = 0
    top_cves: dict[str, dict] = {}  # cve_id → record + affected_count

    for r in results:
        cves = r.get("cves", []) or []
        if cves:
            devices_with_cves += 1
            if any(c.get("kev") for c in cves):
                devices_with_kev += 1
        for c in cves:
            total_cves += 1
            if c.get("kev"):
                kev_cves += 1
            cid = c.get("cve_id", "")
            if cid:
                if cid not in top_cves:
                    top_cves[cid] = {**c, "_affected_devices": 0, "_affected_ips": []}
                top_cves[cid]["_affected_devices"] += 1
                if r.get("ip"):
                    top_cves[cid]["_affected_ips"].append(r["ip"])

    # Top 10 most-recurring critical CVEs
    cve_list = sorted(
        top_cves.values(),
        key=lambda c: (not c.get("kev", False), -(c.get("cvss", 0) or 0), -c.get("_affected_devices", 0)),
    )[:10]

    return {
        "total_cves": total_cves,
        "kev_cves": kev_cves,
        "devices_with_cves": devices_with_cves,
        "devices_with_kev": devices_with_kev,
        "top_cves": cve_list,
    }
