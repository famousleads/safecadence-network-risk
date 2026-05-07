"""
Discovery → Platform bridge.

Converts v2 discovery output (DiscoveryResult / DiscoveredHost) into v4
UnifiedAsset records and persists them to the platform asset store
(~/.safecadence/platform_assets/), so v2/v4/v5 share one fleet.

Design choices:
  * No new schema. UnifiedAsset already has everything we need.
  * Idempotent — re-running adopt() merges into existing records by ip/mac.
  * Best-effort vendor detection from existing OUI/banner/SNMP data.
  * Discovery findings (open ports, weak protocols) become Security entries.
  * Cross-platform: pure Python, no shell, all I/O via pathlib + utf-8.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from safecadence.platform.health_scoring import score_asset_health
from safecadence.platform.schema import (
    AssetIdentity, Hardware, OperatingSystem, Security, UnifiedAsset,
)


# Map discovery's loose vendor/os tags into the platform's normalized values.
_VENDOR_NORMALIZE = {
    "cisco systems": "cisco", "cisco":  "cisco", "ciscosys": "cisco",
    "arista":         "arista",
    "juniper":        "juniper", "juniper networks": "juniper",
    "fortinet":       "fortinet",
    "palo alto":      "palo-alto", "paloalto": "palo-alto", "palo-alto": "palo-alto",
    "aruba":          "aruba", "hewlett packard enterprise": "hpe", "hpe": "hpe",
    "dell":           "dell", "dell inc": "dell",
    "vmware":         "vmware",
    "microsoft":      "microsoft",
    "ubiquiti":       "ubiquiti",
    "mikrotik":       "mikrotik",
    "synology":       "synology",
    "netapp":         "netapp",
    "pure storage":   "pure",
    "qnap":           "qnap",
}

_DEVICE_TYPE_TO_ASSET_TYPE = {
    "router": "network", "switch": "network", "firewall": "network",
    "wireless-ap": "network", "wireless ap": "network", "ap": "network",
    "server": "server", "server-linux": "server", "server-windows": "server",
    "workstation": "server", "workstation-mac": "server",
    "workstation-windows": "server",
    "printer": "iot", "camera": "iot", "iot": "iot",
    "nas": "storage", "storage": "storage",
    "hypervisor": "hypervisor",
    "voip": "voip", "media": "media",
    "mobile": "mobile", "mobile-ios": "mobile", "mobile-android": "mobile",
    "unknown": "unknown",
}

# Cleartext / management ports that signal a hardening problem.
_WEAK_PROTO_BY_PORT = {
    23: "telnet", 21: "ftp", 80: "http", 110: "pop3", 143: "imap",
    111: "rpc", 135: "rpc", 137: "netbios", 139: "smb1", 445: "smb",
    513: "rlogin", 514: "rsh", 515: "lpr", 873: "rsync",
}


def _normalize_vendor(v: str) -> str:
    if not v:
        return "unknown"
    key = v.strip().lower()
    return _VENDOR_NORMALIZE.get(key, key.split()[0] if key else "unknown")


def discovered_to_asset(host) -> UnifiedAsset:
    """Build a UnifiedAsset from a DiscoveredHost (or its dict form)."""
    if isinstance(host, dict):
        h = host
    else:
        h = host.to_dict()

    ip = h.get("ip", "")
    hostname = h.get("hostname") or ip
    mac = h.get("mac", "")
    vendor = _normalize_vendor(h.get("vendor_guess", ""))
    os_type = (h.get("os_guess") or "unknown").lower()
    dev_type = (h.get("device_type_guess") or "unknown").lower()
    asset_type = _DEVICE_TYPE_TO_ASSET_TYPE.get(dev_type, "unknown")

    # Stable asset_id — prefer MAC (L2-adjacent), fall back to IP.
    aid = (mac or ip).lower().replace(":", "")

    identity = AssetIdentity(
        asset_id=aid, hostname=hostname, vendor=vendor,
        product_family=os_type, model=h.get("vendor_guess", "")[:60],
        asset_type=asset_type,
        last_collected_at=datetime.now(timezone.utc).isoformat(),
    )

    asset = UnifiedAsset(identity=identity, raw_collection={
        "discover": {
            "ip": ip, "mac": mac,
            "open_ports": h.get("open_ports") or [],
            "banners": h.get("banners") or {},
            "snmp_sysdescr": h.get("snmp_sysdescr", ""),
            "response_time_ms": h.get("response_time_ms", 0),
            "detected_at": h.get("detected_at", ""),
        }
    })

    sysdescr = h.get("snmp_sysdescr") or ""
    if sysdescr:
        asset.os = OperatingSystem(os_type=os_type, os_version=sysdescr[:120])

    open_ports = h.get("open_ports") or []
    weak = sorted({_WEAK_PROTO_BY_PORT[p] for p in open_ports
                   if p in _WEAK_PROTO_BY_PORT})
    asset.security = Security(
        weak_protocols=weak,
        exposed_services=[{"port": p, "banner": (h.get("banners") or {}).get(str(p), "")[:80]}
                          for p in open_ports],
        findings=([f"weak protocol exposed: {w}" for w in weak] if weak else []),
    )

    asset.health = score_asset_health(asset)
    return asset


def adopt_discovered(discovery_result, *, save: bool = True) -> dict[str, Any]:
    """
    Convert every DiscoveredHost in a DiscoveryResult into a UnifiedAsset
    and (optionally) persist it to the platform asset store.

    Returns {adopted: int, skipped: int, asset_ids: [...]}
    """
    if isinstance(discovery_result, dict):
        hosts = discovery_result.get("hosts") or []
    elif hasattr(discovery_result, "hosts"):
        hosts = discovery_result.hosts
    else:
        hosts = list(discovery_result)

    adopted: list[str] = []
    skipped = 0
    for h in hosts:
        try:
            asset = discovered_to_asset(h)
            if not (asset.identity.asset_id):
                skipped += 1
                continue
            if save:
                from safecadence.server.platform_api import save_asset
                save_asset(asset)
            adopted.append(asset.identity.asset_id)
        except Exception:
            skipped += 1
    return {"adopted": len(adopted), "skipped": skipped, "asset_ids": adopted}
