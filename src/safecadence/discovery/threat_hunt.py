"""
Threat hunting feed — pulls fresh CISA KEV catalog and matches against fleet.

Provides "you match these recently-active threat actor TTPs" intelligence
beyond the bundled CVE database.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any


CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _import_httpx():
    try:
        import httpx
        return httpx
    except ImportError:
        return None


def fetch_recent_kev(*, days: int = 30, timeout: int = 15) -> dict:
    """
    Fetch CISA KEV catalog and filter to entries added in the last N days.
    Returns {fetched_at, total_kev, recent_count, recent: [...]}.
    """
    httpx = _import_httpx()
    if not httpx:
        return {"error": "httpx required for threat-hunt"}

    try:
        with httpx.Client(timeout=timeout) as c:
            r = c.get(CISA_KEV_URL)
            if r.status_code != 200:
                return {"error": f"CISA returned {r.status_code}"}
            data = r.json()
    except Exception as e:
        return {"error": f"fetch failed: {e}"}

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    cutoff_str = cutoff.strftime("%Y-%m-%d")
    vulns = data.get("vulnerabilities", [])

    recent = []
    for v in vulns:
        added = v.get("dateAdded", "")
        if added >= cutoff_str:
            recent.append({
                "cve_id": v.get("cveID"),
                "vendor": v.get("vendorProject"),
                "product": v.get("product"),
                "vulnerability_name": v.get("vulnerabilityName", ""),
                "date_added": added,
                "due_date": v.get("dueDate", ""),
                "required_action": v.get("requiredAction", ""),
                "short_description": v.get("shortDescription", "")[:300],
                "ransomware": v.get("knownRansomwareCampaignUse", "Unknown"),
            })

    # Sort newest first
    recent.sort(key=lambda x: x.get("date_added", ""), reverse=True)

    return {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "total_kev": len(vulns),
        "recent_count": len(recent),
        "days_window": days,
        "recent": recent,
    }


def hunt_fleet(fleet: dict, *, days: int = 30) -> dict:
    """
    Match recent KEV entries against the fleet's identified vendors/products.
    Returns devices that match recent threat-actor TTPs.
    """
    feed = fetch_recent_kev(days=days)
    if "error" in feed:
        return feed

    recent = feed.get("recent", [])
    fleet_results = fleet.get("results", [])

    matches = []
    for rk in recent:
        rk_vendor = (rk.get("vendor") or "").lower()
        rk_product = (rk.get("product") or "").lower()
        affected_devices = []

        for d in fleet_results:
            d_vendor = (d.get("vendor") or "").lower()
            d_os = (d.get("os") or "").lower()
            d_sysd = (d.get("snmp_sysdescr") or "").lower()
            # Match if KEV vendor name appears in device vendor or sysDescr
            if rk_vendor and (rk_vendor in d_vendor or rk_vendor in d_sysd):
                # Bonus: also check product
                if not rk_product or rk_product in d_os or rk_product in d_sysd:
                    affected_devices.append({
                        "ip": d.get("ip"),
                        "hostname": d.get("hostname", ""),
                        "vendor": d.get("vendor", ""),
                        "snmp_sysdescr": (d.get("snmp_sysdescr") or "")[:200],
                    })

        if affected_devices:
            matches.append({
                **rk,
                "affected_devices": affected_devices,
                "affected_count": len(affected_devices),
            })

    return {
        "fetched_at": feed["fetched_at"],
        "days_window": days,
        "feed_total_recent": feed["recent_count"],
        "matches_in_fleet": len(matches),
        "matches": matches,
    }
