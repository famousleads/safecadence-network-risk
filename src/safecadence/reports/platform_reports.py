"""
Platform-wide report types — operate on the cross-vendor UnifiedAsset
inventory rather than on individual scans.

Each report is a pure function: takes a list of asset dicts, returns a
serializable dict. The /api/platform/reports/{id} endpoint exposes
them; the platform UI renders them as cards.

Available reports:
  1.  lifecycle             EOL/EOS exposure across the fleet
  2.  security_posture      CVE counts, KEV exposure, weak protocols
  3.  capacity              Storage / compute capacity & headroom
  4.  backup_compliance     RPO adherence, immutability, air-gap
  5.  vendor_inventory      Asset counts grouped by vendor & domain
  6.  eol_eos               Hardware past or approaching EOS
  7.  health_summary        Composite health-score histogram
  8.  risk_register         Toxic-combo + high-severity findings
  9.  cloud_exposure        Public-facing cloud assets with CVEs
 10.  executive_overview    Single-page leadership summary
"""

from __future__ import annotations

from collections import Counter
from typing import Any


def _ident(a: dict) -> dict:
    return a.get("identity") or {}


# --------------------------------------------------------------------------
# 1. Lifecycle exposure
# --------------------------------------------------------------------------

def report_lifecycle(assets: list[dict]) -> dict:
    expired, soon, ok = [], [], []
    for a in assets:
        lc = a.get("lifecycle") or {}
        days = lc.get("days_until_eos")
        rec = {
            "asset_id": _ident(a).get("asset_id"),
            "vendor": _ident(a).get("vendor"),
            "model": _ident(a).get("model"),
            "asset_type": _ident(a).get("asset_type"),
            "days_until_eos": days,
            "eos_date": lc.get("eos_date", ""),
        }
        if days is None:
            ok.append(rec)
        elif days < 0:
            expired.append(rec)
        elif days <= 365:
            soon.append(rec)
        else:
            ok.append(rec)
    return {
        "title": "Lifecycle exposure",
        "summary": {"expired": len(expired), "within_12_months": len(soon),
                    "supported": len(ok), "total": len(assets)},
        "expired": sorted(expired, key=lambda x: x.get("days_until_eos") or 0),
        "within_12_months": sorted(soon, key=lambda x: x.get("days_until_eos") or 0),
    }


# --------------------------------------------------------------------------
# 2. Security posture
# --------------------------------------------------------------------------

def report_security_posture(assets: list[dict]) -> dict:
    crit = high = kev = weak = 0
    weak_protos: Counter = Counter()
    top_vulnerable = []
    for a in assets:
        sec = a.get("security") or {}
        crit += sec.get("critical_cves", 0)
        high += sec.get("high_cves", 0)
        kev  += sec.get("kev_cves", 0)
        for wp in sec.get("weak_protocols") or []:
            weak_protos[wp] += 1
            weak += 1
        score = (a.get("health") or {}).get("security_score")
        if isinstance(score, (int, float)) and score < 70:
            top_vulnerable.append({
                "asset_id": _ident(a).get("asset_id"),
                "vendor": _ident(a).get("vendor"),
                "security_score": score,
                "critical_cves": sec.get("critical_cves", 0),
                "kev_cves": sec.get("kev_cves", 0),
            })
    top_vulnerable.sort(key=lambda x: x["security_score"])
    return {
        "title": "Security posture",
        "summary": {"critical_cves": crit, "high_cves": high, "kev_cves": kev,
                    "weak_protocol_findings": weak},
        "weak_protocols": dict(weak_protos.most_common()),
        "top_vulnerable_assets": top_vulnerable[:25],
    }


# --------------------------------------------------------------------------
# 3. Capacity
# --------------------------------------------------------------------------

def report_capacity(assets: list[dict]) -> dict:
    total_tb = used_tb = 0.0
    per_array = []
    for a in assets:
        if _ident(a).get("asset_type") != "storage":
            continue
        s = a.get("storage") or {}
        t = s.get("total_capacity_tb", 0) or 0
        u = s.get("used_capacity_tb", 0) or 0
        total_tb += t
        used_tb += u
        if t:
            per_array.append({
                "asset_id": _ident(a).get("asset_id"),
                "vendor": _ident(a).get("vendor"),
                "total_tb": round(t, 2),
                "used_tb": round(u, 2),
                "pct_used": round((u / t) * 100, 1) if t else 0,
            })
    pct = round((used_tb / total_tb) * 100, 1) if total_tb else 0
    per_array.sort(key=lambda x: x["pct_used"], reverse=True)
    return {
        "title": "Capacity",
        "summary": {
            "total_tb": round(total_tb, 2),
            "used_tb": round(used_tb, 2),
            "free_tb": round(total_tb - used_tb, 2),
            "pct_used": pct,
        },
        "per_array": per_array,
    }


# --------------------------------------------------------------------------
# 4. Backup compliance
# --------------------------------------------------------------------------

def report_backup_compliance(assets: list[dict]) -> dict:
    in_rpo = out_rpo = no_data = 0
    immutable = air_gapped = 0
    rows = []
    for a in assets:
        if _ident(a).get("asset_type") != "backup":
            continue
        b = a.get("backup") or {}
        rpo_target = b.get("rpo_target_hours") or 0
        actual = b.get("actual_rpo_hours") or 0
        if rpo_target == 0 and actual == 0:
            no_data += 1
        elif actual <= rpo_target:
            in_rpo += 1
        else:
            out_rpo += 1
        if b.get("immutability_enabled"):
            immutable += 1
        if b.get("air_gapped"):
            air_gapped += 1
        rows.append({
            "asset_id": _ident(a).get("asset_id"),
            "platform": b.get("platform"),
            "rpo_target_hours": rpo_target,
            "actual_rpo_hours": actual,
            "in_compliance": rpo_target > 0 and actual <= rpo_target,
            "immutability_enabled": b.get("immutability_enabled", False),
            "air_gapped": b.get("air_gapped", False),
        })
    return {
        "title": "Backup compliance",
        "summary": {"in_rpo": in_rpo, "out_of_rpo": out_rpo, "no_data": no_data,
                    "immutable_count": immutable, "air_gapped_count": air_gapped},
        "rows": rows,
    }


# --------------------------------------------------------------------------
# 5. Vendor inventory
# --------------------------------------------------------------------------

def report_vendor_inventory(assets: list[dict]) -> dict:
    by_vendor: Counter = Counter()
    by_domain: Counter = Counter()
    matrix: dict[str, dict[str, int]] = {}
    for a in assets:
        v = (_ident(a).get("vendor") or "unknown").lower()
        d = _ident(a).get("asset_type") or "unknown"
        by_vendor[v] += 1
        by_domain[d] += 1
        matrix.setdefault(v, {})[d] = matrix.setdefault(v, {}).get(d, 0) + 1
    return {
        "title": "Vendor inventory",
        "summary": {"vendor_count": len(by_vendor), "asset_count": len(assets)},
        "by_vendor": dict(by_vendor.most_common()),
        "by_domain": dict(by_domain.most_common()),
        "vendor_x_domain": matrix,
    }


# --------------------------------------------------------------------------
# 6. EOL / EOS detail
# --------------------------------------------------------------------------

def report_eol_eos(assets: list[dict]) -> dict:
    rows = []
    for a in assets:
        lc = a.get("lifecycle") or {}
        if not lc.get("eos_date") and lc.get("days_until_eos") is None:
            continue
        rows.append({
            "asset_id": _ident(a).get("asset_id"),
            "vendor": _ident(a).get("vendor"),
            "model": _ident(a).get("model"),
            "asset_type": _ident(a).get("asset_type"),
            "eol_status": lc.get("eol_status", ""),
            "eol_date": lc.get("eol_date", ""),
            "eos_date": lc.get("eos_date", ""),
            "days_until_eos": lc.get("days_until_eos"),
            "warranty_status": lc.get("warranty_status", ""),
            "replacement_recommended": lc.get("replacement_recommended", False),
        })
    rows.sort(key=lambda x: x.get("days_until_eos") or 99999)
    return {"title": "EOL / EOS detail",
            "summary": {"count_with_lifecycle_data": len(rows)},
            "rows": rows}


# --------------------------------------------------------------------------
# 7. Health summary
# --------------------------------------------------------------------------

def report_health_summary(assets: list[dict]) -> dict:
    grades: Counter = Counter()
    composite_buckets = {"90-100": 0, "75-89": 0, "60-74": 0, "<60": 0, "n/a": 0}
    weakest = []
    for a in assets:
        h = a.get("health") or {}
        grades[h.get("grade") or "?"] += 1
        c = h.get("composite_score")
        if isinstance(c, (int, float)):
            if c >= 90: composite_buckets["90-100"] += 1
            elif c >= 75: composite_buckets["75-89"] += 1
            elif c >= 60: composite_buckets["60-74"] += 1
            else: composite_buckets["<60"] += 1
            if c < 70:
                weakest.append({
                    "asset_id": _ident(a).get("asset_id"),
                    "vendor": _ident(a).get("vendor"),
                    "asset_type": _ident(a).get("asset_type"),
                    "composite_score": c,
                    "grade": h.get("grade"),
                })
        else:
            composite_buckets["n/a"] += 1
    weakest.sort(key=lambda x: x["composite_score"])
    return {"title": "Health summary",
            "summary": {"by_grade": dict(grades), "buckets": composite_buckets},
            "weakest_assets": weakest[:25]}


# --------------------------------------------------------------------------
# 8. Risk register (toxic combos + critical findings)
# --------------------------------------------------------------------------

def report_risk_register(assets: list[dict]) -> dict:
    from safecadence.platform.correlation import find_toxic_combinations, find_orphans
    toxic = find_toxic_combinations(assets)
    orphans = find_orphans(assets)
    severities: Counter = Counter()
    for f in toxic:
        severities[f.get("severity", "unknown")] += 1
    return {"title": "Risk register",
            "summary": {"toxic_combos": len(toxic), "orphans": len(orphans),
                        "by_severity": dict(severities)},
            "toxic_combinations": toxic,
            "orphans": orphans}


# --------------------------------------------------------------------------
# 9. Cloud exposure
# --------------------------------------------------------------------------

def report_cloud_exposure(assets: list[dict]) -> dict:
    public_with_cves = []
    public_total = 0
    for a in assets:
        if _ident(a).get("asset_type") != "cloud":
            continue
        c = a.get("cloud") or {}
        if c.get("public_exposure"):
            public_total += 1
            sec = a.get("security") or {}
            if sec.get("critical_cves", 0) > 0 or sec.get("kev_cves", 0) > 0:
                public_with_cves.append({
                    "asset_id": _ident(a).get("asset_id"),
                    "provider": c.get("provider"),
                    "instance_id": c.get("instance_id"),
                    "public_ip": c.get("public_ip"),
                    "critical_cves": sec.get("critical_cves", 0),
                    "kev_cves": sec.get("kev_cves", 0),
                })
    return {"title": "Cloud exposure",
            "summary": {"public_assets": public_total,
                        "public_assets_with_critical_cves": len(public_with_cves)},
            "rows": public_with_cves}


# --------------------------------------------------------------------------
# 10. Executive overview
# --------------------------------------------------------------------------

def report_executive_overview(assets: list[dict]) -> dict:
    inv = report_vendor_inventory(assets)
    sec = report_security_posture(assets)
    lifecycle = report_lifecycle(assets)
    health = report_health_summary(assets)
    risk = report_risk_register(assets)
    return {
        "title": "Executive overview",
        "snapshot": {
            "asset_count": len(assets),
            "vendor_count": inv["summary"]["vendor_count"],
            "critical_cves": sec["summary"]["critical_cves"],
            "kev_cves": sec["summary"]["kev_cves"],
            "lifecycle_at_risk_12mo": lifecycle["summary"]["within_12_months"],
            "lifecycle_expired": lifecycle["summary"]["expired"],
            "toxic_combos": risk["summary"]["toxic_combos"],
            "orphans": risk["summary"]["orphans"],
        },
        "health_grades": health["summary"]["by_grade"],
        "domain_breakdown": inv["by_domain"],
        "top_vendors": dict(list(inv["by_vendor"].items())[:10]),
    }


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------

REPORT_REGISTRY: dict[str, dict] = {
    "lifecycle": {
        "title": "Lifecycle exposure",
        "description": "Hardware/software past or approaching end-of-support across the fleet.",
        "fn": report_lifecycle,
    },
    "security_posture": {
        "title": "Security posture",
        "description": "CVE counts (critical/high/KEV), weak protocols, and the most vulnerable assets.",
        "fn": report_security_posture,
    },
    "capacity": {
        "title": "Capacity",
        "description": "Storage capacity used / free across all arrays, sorted by pressure.",
        "fn": report_capacity,
    },
    "backup_compliance": {
        "title": "Backup compliance",
        "description": "RPO compliance, immutability, and air-gap status across backup platforms.",
        "fn": report_backup_compliance,
    },
    "vendor_inventory": {
        "title": "Vendor inventory",
        "description": "Asset counts grouped by vendor and domain (vendor × domain matrix).",
        "fn": report_vendor_inventory,
    },
    "eol_eos": {
        "title": "EOL / EOS detail",
        "description": "Per-asset EOL/EOS dates, warranty status, and replacement recommendations.",
        "fn": report_eol_eos,
    },
    "health_summary": {
        "title": "Health summary",
        "description": "Composite health-score histogram and the weakest assets in the fleet.",
        "fn": report_health_summary,
    },
    "risk_register": {
        "title": "Risk register",
        "description": "Cross-domain toxic combinations and orphaned-asset findings.",
        "fn": report_risk_register,
    },
    "cloud_exposure": {
        "title": "Cloud exposure",
        "description": "Public-facing cloud assets carrying critical or KEV-listed CVEs.",
        "fn": report_cloud_exposure,
    },
    "executive_overview": {
        "title": "Executive overview",
        "description": "One-page leadership snapshot: assets, vendors, CVEs, lifecycle, risks.",
        "fn": report_executive_overview,
    },
}
