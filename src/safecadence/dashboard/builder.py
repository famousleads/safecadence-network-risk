"""
Dashboard data aggregator.

Reads a directory of scan-result JSON files (each produced by
`safecadence scan --json out.json`) and computes fleet-level statistics.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class DashboardData:
    """Aggregated state ready for the SPA renderer to embed."""
    devices: list[dict[str, Any]] = field(default_factory=list)
    overview: dict[str, Any] = field(default_factory=dict)
    cves_by_id: list[dict[str, Any]] = field(default_factory=list)
    eol_summary: list[dict[str, Any]] = field(default_factory=list)
    topology: dict[str, Any] | None = None
    generated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "devices": self.devices,
            "overview": self.overview,
            "cves_by_id": self.cves_by_id,
            "eol_summary": self.eol_summary,
            "topology": self.topology,
            "generated_at": self.generated_at,
        }


def load_scan_dir(scans_dir: Path | str) -> list[dict[str, Any]]:
    """Read every *.json under `scans_dir` and return parsed scan dicts."""
    root = Path(scans_dir)
    if not root.is_dir():
        return []
    out: list[dict[str, Any]] = []
    for f in sorted(root.iterdir()):
        if f.suffix.lower() != ".json" or not f.is_file():
            continue
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if "vendor" in d and "asset" in d:        # looks like a ScanResult dict
            d["_source_file"] = f.name
            out.append(d)
    return out


def _severity_count(scans: list[dict], sev: str) -> int:
    return sum(
        1
        for s in scans
        for f in s.get("findings", [])
        if f.get("severity") == sev
    )


def build_dashboard_data(
    scans: list[dict],
    *,
    topology: dict | None = None,
) -> DashboardData:
    """Aggregate fleet-level statistics from scan dicts."""
    from datetime import datetime, timezone

    # ----- Devices (one row per scan) ----------------------------- #
    devices: list[dict[str, Any]] = []
    for s in scans:
        ps = s.get("parsed_summary", {})
        asset = s.get("asset", {})
        devices.append({
            "name":          asset.get("hostname") or ps.get("hostname") or s.get("source", "?"),
            "vendor":        s.get("vendor", ""),
            "os":            ps.get("os", ""),
            "version":       ps.get("version", ""),
            "model":         ps.get("model", ""),
            "ip":            asset.get("ip", ""),
            "device_type":   asset.get("device_type", ""),
            "health_score":  s.get("health_score", 0),
            "risk_score":    s.get("risk_score", 0),
            "health_band":   s.get("health_band", ""),
            "risk_band":     s.get("risk_band", ""),
            "findings_count": len(s.get("findings", [])),
            "cves_count":    len(s.get("cves", [])),
            "eol_status":    (s.get("eol") or {}).get("status_today", "unknown"),
            "scan":          s,                     # full payload for drill-down
        })

    # ----- Overview KPIs ------------------------------------------ #
    n = len(scans)
    avg_health = int(sum(d["health_score"] for d in devices) / n) if n else 0
    avg_risk   = int(sum(d["risk_score"]   for d in devices) / n) if n else 0
    overview = {
        "device_count":        n,
        "avg_health":          avg_health,
        "avg_risk":            avg_risk,
        "critical_devices":    sum(1 for d in devices if d["risk_score"] >= 81 or d["risk_band"] == "critical"),
        "eol_devices":         sum(1 for d in devices if d["eol_status"] == "end-of-support"),
        "eos_software_devices": sum(1 for d in devices if d["eol_status"] == "end-of-software"),
        "kev_devices":         sum(
            1 for s in scans if any(c.get("kev") for c in s.get("cves", []))
        ),
        "findings_critical":   _severity_count(scans, "critical"),
        "findings_high":       _severity_count(scans, "high"),
        "findings_medium":     _severity_count(scans, "medium"),
        "findings_low":        _severity_count(scans, "low"),
        "findings_info":       _severity_count(scans, "info"),
        "vendor_breakdown":    {},
    }
    # Vendor breakdown
    for d in devices:
        v = d["vendor"] or "unknown"
        overview["vendor_breakdown"][v] = overview["vendor_breakdown"].get(v, 0) + 1

    # ----- CVE summary across fleet (dedup, who-is-affected) ------ #
    cve_index: dict[str, dict[str, Any]] = {}
    for d in devices:
        for c in d["scan"].get("cves", []):
            cid = c.get("cve_id")
            if not cid:
                continue
            entry = cve_index.setdefault(cid, {
                "cve_id":   cid,
                "severity": c.get("severity", "medium"),
                "cvss":     c.get("cvss", 0),
                "title":    c.get("title", ""),
                "kev":      c.get("kev", False),
                "affected_devices": [],
            })
            entry["affected_devices"].append(d["name"])
    cves_by_id = sorted(
        cve_index.values(),
        key=lambda c: (-int(c["kev"]), -float(c.get("cvss") or 0)),
    )

    # ----- EOL summary -------------------------------------------- #
    eol_index: dict[str, dict[str, Any]] = {}
    for d in devices:
        eol = d["scan"].get("eol")
        if not eol:
            continue
        key = f'{eol.get("vendor")}-{eol.get("os")}-{eol.get("version_prefix")}'
        entry = eol_index.setdefault(key, {
            "vendor":         eol.get("vendor"),
            "os":             eol.get("os"),
            "version_prefix": eol.get("version_prefix"),
            "end_of_software": eol.get("end_of_software", ""),
            "end_of_support":  eol.get("end_of_support", ""),
            "status_today":    eol.get("status_today", "unknown"),
            "affected_devices": [],
        })
        entry["affected_devices"].append(d["name"])
    eol_summary = sorted(
        eol_index.values(),
        key=lambda r: (
            0 if r["status_today"] == "end-of-support"
            else 1 if r["status_today"] == "end-of-software"
            else 2
        ),
    )

    return DashboardData(
        devices=devices,
        overview=overview,
        cves_by_id=cves_by_id,
        eol_summary=eol_summary,
        topology=topology,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )
