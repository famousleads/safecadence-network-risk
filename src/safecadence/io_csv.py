"""
CSV import / export for inventory + assets.

Inventory CSV format (for `safecadence collect --inventory inventory.csv`):

    host,name,vendor,username,password_env,key_file,port,site,owner,criticality
    10.10.10.1,DC-CORE-01,cisco-ios,netops,NETOPS_PW,,22,DC-NYC,netops,high
    10.10.10.2,SPINE-01,arista-eos,netops,,~/.ssh/id_rsa,22,DC-NYC,netops,critical

Asset CSV (for bulk import — produced by external CMDBs):

    hostname,ip,vendor,os,version,site,building,floor,rack,owner,criticality,tags
"""


from __future__ import annotations

import csv
import io
from pathlib import Path
from typing import Iterable, Iterator


_INVENTORY_FIELDS = (
    "host", "name", "vendor", "username", "password_env",
    "key_file", "port", "site", "owner", "criticality",
)


def read_inventory_csv(path: str | Path) -> list[dict]:
    """Read an inventory CSV and return device dicts compatible with the
    SSH `collect` command (same shape as the YAML format)."""
    out: list[dict] = []
    with open(path, "r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            row = {k.strip(): (v or "").strip() for k, v in row.items() if k}
            if not row.get("host"):
                continue
            d: dict = {
                "host": row["host"],
                "name": row.get("name") or row["host"],
                "vendor": row.get("vendor", ""),
                "username": row.get("username", ""),
            }
            if row.get("password_env"):
                d["password"] = f"env:{row['password_env']}"
            if row.get("key_file"):
                d["key_file"] = row["key_file"]
            if row.get("port"):
                try:
                    d["port"] = int(row["port"])
                except ValueError:
                    pass
            for k in ("site", "owner", "criticality"):
                if row.get(k):
                    d[k] = row[k]
            out.append(d)
    return out


def write_inventory_csv(devices: Iterable[dict], path: str | Path) -> int:
    """Inverse of read_inventory_csv. Returns count written."""
    n = 0
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(_INVENTORY_FIELDS))
        w.writeheader()
        for d in devices:
            row = {
                "host":         d.get("host", ""),
                "name":         d.get("name", ""),
                "vendor":       d.get("vendor", ""),
                "username":     d.get("username", ""),
                "password_env": d.get("password", "")[4:] if (d.get("password","").startswith("env:")) else "",
                "key_file":     d.get("key_file", ""),
                "port":         d.get("port", ""),
                "site":         d.get("site", ""),
                "owner":        d.get("owner", ""),
                "criticality":  d.get("criticality", ""),
            }
            w.writerow(row)
            n += 1
    return n


_ASSET_EXPORT_FIELDS = (
    "hostname", "ip", "vendor", "os", "version", "model", "device_type",
    "site", "building", "floor", "rack", "owner", "criticality",
    "health_score", "risk_score", "health_band", "risk_band",
    "findings_count", "cves_count", "kev_count", "eol_status",
)


def write_assets_csv(scans: Iterable[dict], path: str | Path) -> int:
    """Export a fleet of scan-result dicts to a flat CSV."""
    n = 0
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(_ASSET_EXPORT_FIELDS))
        w.writeheader()
        for s in scans:
            asset = s.get("asset", {}) or {}
            ps = s.get("parsed_summary", {}) or {}
            loc = asset.get("location", {}) or {}
            cves = s.get("cves", []) or []
            row = {
                "hostname":      asset.get("hostname") or ps.get("hostname", ""),
                "ip":            asset.get("ip", ""),
                "vendor":        s.get("vendor", ""),
                "os":            ps.get("os", ""),
                "version":       ps.get("version", ""),
                "model":         ps.get("model", ""),
                "device_type":   asset.get("device_type", ""),
                "site":          loc.get("site", ""),
                "building":      loc.get("building", ""),
                "floor":         loc.get("floor", ""),
                "rack":          loc.get("rack", ""),
                "owner":         asset.get("owner", ""),
                "criticality":   asset.get("business_criticality", ""),
                "health_score":  s.get("health_score", 0),
                "risk_score":    s.get("risk_score", 0),
                "health_band":   s.get("health_band", ""),
                "risk_band":     s.get("risk_band", ""),
                "findings_count": len(s.get("findings", [])),
                "cves_count":    len(cves),
                "kev_count":     sum(1 for c in cves if c.get("kev")),
                "eol_status":    (s.get("eol") or {}).get("status_today", ""),
            }
            w.writerow(row)
            n += 1
    return n


def read_assets_csv(path: str | Path) -> Iterator[dict]:
    """Read an asset CSV — useful when importing inventory from a CMDB."""
    with open(path, "r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            yield {k.strip(): (v or "").strip() for k, v in row.items() if k}
