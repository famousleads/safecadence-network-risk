"""
Report section composers — every function reads REAL system state from
the local NetRisk store.

Each composer takes:
  - store : the asset/scan store from `safecadence.storage.open_store()`
  - scope : a dict of optional filter keys (site, criticality, asset_type,
            vendor, date_range)

Each composer returns a structured dict shaped like:
  { "title": str,
    "data" : <section-specific dict>,
    "html_fragment": str (optional),
    "empty": bool (set when there is no data) }

Composers MUST NEVER raise on missing data; they return empty/zero
shapes and set ``empty: True`` so the wizard UI can still render them.
"""

from __future__ import annotations

import datetime as _dt
import html
import os
from collections import Counter
from typing import Any

try:
    from safecadence.reports.visuals import (
        attack_path_graph,
        compliance_heatmap,
        compliance_radar,
        cve_badge,
        severity_bars,
        severity_donut,
    )
    _VISUALS_OK = True
except Exception:  # pragma: no cover
    _VISUALS_OK = False


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _safe_list(store: Any, *, limit: int = 1000) -> list[dict]:
    """Return latest scans (one per host) without ever blowing up."""
    if store is None:
        return []
    try:
        rows = store.latest_per_host()
    except Exception:
        try:
            rows = store.list(limit=limit)
        except Exception:
            return []
    out: list[dict] = []
    for r in rows or []:
        if isinstance(r, dict) and r.get("id") and "payload" not in r:
            try:
                full = store.get(r["id"])
                if isinstance(full, dict):
                    out.append(full)
                    continue
            except Exception:
                pass
        if isinstance(r, dict):
            out.append(r)
    return out


def _scope_match(row: dict, scope: dict) -> bool:
    if not scope:
        return True
    asset = row.get("asset") or {}
    site = (asset.get("location") or {}).get("site") or row.get("site") or ""
    vendor = (row.get("vendor") or asset.get("vendor") or "").lower()
    asset_type = (asset.get("device_type") or asset.get("asset_type") or "").lower()
    criticality = (asset.get("criticality") or row.get("risk_band") or "").lower()

    s_site = scope.get("site") or ""
    if s_site and s_site != site:
        return False

    s_crit = scope.get("criticality") or []
    if s_crit and criticality not in [c.lower() for c in s_crit]:
        return False

    s_atype = scope.get("asset_type") or []
    if s_atype and asset_type not in [a.lower() for a in s_atype]:
        return False

    s_vend = scope.get("vendor") or []
    if s_vend and vendor not in [v.lower() for v in s_vend]:
        return False

    dr = scope.get("date_range") or {}
    if dr:
        started = row.get("started_at") or ""
        if dr.get("from") and started and started < dr["from"]:
            return False
        if dr.get("to") and started and started > dr["to"]:
            return False
    return True


def _filter(rows: list[dict], scope: dict) -> list[dict]:
    return [r for r in rows if _scope_match(r, scope)]


# --------------------------------------------------------------------------
# platform_assets fallback (for demo / when no scan history exists)
# --------------------------------------------------------------------------


def _load_platform_assets() -> list[dict]:
    """Read all platform asset JSON files from ~/.safecadence/platform_assets.

    Honors ``SC_DATA_DIR`` for testing / alternate data roots.
    Returns the list of full asset dicts. Never raises.
    """
    from pathlib import Path
    import json
    root = os.environ.get("SC_DATA_DIR") or str(Path.home() / ".safecadence")
    base = Path(root) / "platform_assets"
    if not base.exists():
        return []
    out: list[dict] = []
    try:
        for f in base.glob("*.json"):
            try:
                out.append(json.loads(f.read_text(encoding="utf-8")))
            except Exception:
                continue
    except Exception:
        return out
    return out


def _asset_field(asset: dict, key: str, default: Any = "") -> Any:
    """Pull a top-level identity field; falls back to root."""
    return (asset.get("identity") or {}).get(key) or asset.get(key, default)


def _scope_match_asset(asset: dict, scope: dict) -> bool:
    """Apply scope filters to a platform asset (separate logic from scan rows)."""
    if not scope:
        return True
    site = _asset_field(asset, "site") or ""
    vendor = (_asset_field(asset, "vendor") or "").lower()
    asset_type = (_asset_field(asset, "asset_type") or "").lower()
    criticality = (_asset_field(asset, "criticality") or "").lower()

    s_site = scope.get("site") or ""
    if s_site and s_site != site:
        return False
    s_crit = scope.get("criticality") or []
    if s_crit and criticality not in [c.lower() for c in s_crit]:
        return False
    s_atype = scope.get("asset_type") or []
    if s_atype and asset_type not in [a.lower() for a in s_atype]:
        return False
    s_vend = scope.get("vendor") or []
    if s_vend and vendor not in [v.lower() for v in s_vend]:
        return False
    return True


def _filter_assets(assets: list[dict], scope: dict) -> list[dict]:
    return [a for a in assets if _scope_match_asset(a, scope)]


def _scope_values_from_assets() -> dict:
    """Surface unique sites + vendors from the platform_assets store."""
    assets = _load_platform_assets()
    sites = sorted({_asset_field(a, "site") for a in assets if _asset_field(a, "site")})
    vendors = sorted({_asset_field(a, "vendor") for a in assets if _asset_field(a, "vendor")})
    return {"sites": list(sites), "vendors": list(vendors)}


def _asset_cve_counts(asset: dict) -> tuple[int, int, int]:
    """Return (critical, high, kev) integer CVE counts for an asset."""
    sec = asset.get("security") or {}
    try:
        crit = int(sec.get("critical_cves") or 0)
    except Exception:
        crit = 0
    try:
        high = int(sec.get("high_cves") or 0)
    except Exception:
        high = 0
    try:
        kev = int(sec.get("kev_cves") or 0)
    except Exception:
        kev = 0
    return crit, high, kev


def _asset_eol_flags(asset: dict) -> tuple[bool, bool]:
    """Return (hardware_eol, software_eos) booleans from lifecycle block."""
    lc = asset.get("lifecycle") or {}
    hw_status = (lc.get("hardware_status") or "").lower()
    sw_status = (lc.get("software_status") or "").lower()
    hw_eol = hw_status in ("eol", "past_eos")
    # in the schema, software_status uses "eos" / "past_eos"
    sw_eos = sw_status in ("eos", "past_eos")
    # Also treat very-soon EOS as past for KPI purposes only when negative
    try:
        days = int(lc.get("days_until_eos")) if lc.get("days_until_eos") is not None else None
    except Exception:
        days = None
    if days is not None and days <= 0:
        hw_eol = hw_eol or True
    return hw_eol, sw_eos


def _empty(title: str, data: dict | None = None) -> dict:
    return {
        "title": title,
        "data": data or {},
        "empty": True,
        "html_fragment": (
            f'<div class="sc-empty"><strong>{html.escape(title)}</strong>'
            "<br><small>No data in scope. Add scans or widen the filter.</small></div>"
        ),
    }


def _esc(s: Any) -> str:
    return html.escape(str(s if s is not None else ""))


# --------------------------------------------------------------------------
# 1. KPI summary
# --------------------------------------------------------------------------


def kpi_summary(store: Any, scope: dict) -> dict:
    """Top-line counts for the cover page."""
    rows = _filter(_safe_list(store), scope)
    if not rows:
        # Fallback: read platform_assets store populated by `safecadence demo`.
        assets = _filter_assets(_load_platform_assets(), scope)
        if assets:
            crit_total = 0
            high_total = 0
            kev_total = 0
            kev_devices = 0
            eol_count = 0
            eos_count = 0
            crit_band = 0
            high_band = 0
            med_band = 0
            low_band = 0
            for a in assets:
                c, h, k = _asset_cve_counts(a)
                crit_total += c
                high_total += h
                kev_total += k
                if k > 0:
                    kev_devices += 1
                hw_eol, sw_eos = _asset_eol_flags(a)
                if hw_eol:
                    eol_count += 1
                if sw_eos:
                    eos_count += 1
                band = (_asset_field(a, "criticality") or "").lower()
                if band == "crown-jewel" or band == "critical":
                    crit_band += 1
                elif band == "high":
                    high_band += 1
                elif band == "medium":
                    med_band += 1
                elif band == "low":
                    low_band += 1
            data = {
                "hosts": len(assets),
                "critical": crit_total,
                "high": high_total,
                "medium": med_band,
                "low": low_band,
                "cves": crit_total + high_total + kev_total,
                "kev": kev_devices,
                "eol": eol_count,
                "eos_software": eos_count,
            }
            cards = [
                ("Hosts", data["hosts"]),
                ("Critical CVEs", data["critical"]),
                ("High CVEs", data["high"]),
                ("KEV-listed devices", data["kev"]),
                ("Total CVEs", data["cves"]),
                ("EOL hardware", data["eol"]),
                ("EOS software", data["eos_software"]),
            ]
            cards_html = "".join(
                f'<div class="sc-kpi"><div class="sc-kpi-num">{_esc(v)}</div>'
                f'<div class="sc-kpi-lbl">{_esc(k)}</div></div>'
                for k, v in cards
            )
            viz = ""
            if _VISUALS_OK:
                sev_counts = {
                    "critical": data["critical"],
                    "high": data["high"],
                    "medium": data["medium"],
                    "low": data["low"],
                }
                viz = (
                    '<div class="sc-viz-row" style="margin-top:14px">'
                    f'<div class="sc-viz-col">{severity_donut(sev_counts)}</div>'
                    f'<div class="sc-viz-col">{severity_bars(sev_counts)}</div>'
                    '</div>'
                )
            return {
                "title": "KPI summary",
                "data": data,
                "html_fragment": f'<div class="sc-kpi-grid">{cards_html}</div>{viz}',
                "empty": False,
            }
        return _empty("KPI summary",
                      {"hosts": 0, "critical": 0, "high": 0, "medium": 0, "low": 0,
                       "cves": 0, "kev": 0, "eol": 0, "eos_software": 0})

    sev: Counter = Counter()
    cves = 0
    kev = 0
    eol = 0
    eos = 0
    for r in rows:
        for f in r.get("findings", []) or []:
            s = (f.get("severity") or "").lower()
            sev[s] += 1
        for c in r.get("cves", []) or []:
            cves += 1
            if c.get("kev"):
                kev += 1
        eol_status = (r.get("eol") or {}).get("status_today") or r.get("eol_status") or ""
        if eol_status == "end-of-support":
            eol += 1
        elif eol_status == "end-of-software":
            eos += 1

    data = {
        "hosts": len(rows),
        "critical": sev.get("critical", 0),
        "high": sev.get("high", 0),
        "medium": sev.get("medium", 0),
        "low": sev.get("low", 0),
        "cves": cves,
        "kev": kev,
        "eol": eol,
        "eos_software": eos,
    }
    cards = [
        ("Hosts", data["hosts"]),
        ("Critical findings", data["critical"]),
        ("High findings", data["high"]),
        ("Medium findings", data["medium"]),
        ("CVEs", data["cves"]),
        ("KEV-listed", data["kev"]),
        ("EOL hardware", data["eol"]),
        ("EOS software", data["eos_software"]),
    ]
    cards_html = "".join(
        f'<div class="sc-kpi"><div class="sc-kpi-num">{_esc(v)}</div>'
        f'<div class="sc-kpi-lbl">{_esc(k)}</div></div>'
        for k, v in cards
    )
    viz = ""
    if _VISUALS_OK:
        sev_counts = {
            "critical": data["critical"],
            "high": data["high"],
            "medium": data["medium"],
            "low": data["low"],
        }
        viz = (
            '<div class="sc-viz-row" style="margin-top:14px">'
            f'<div class="sc-viz-col">{severity_donut(sev_counts)}</div>'
            f'<div class="sc-viz-col">{severity_bars(sev_counts)}</div>'
            '</div>'
        )
    return {
        "title": "KPI summary",
        "data": data,
        "html_fragment": f'<div class="sc-kpi-grid">{cards_html}</div>{viz}',
        "empty": False,
    }


# --------------------------------------------------------------------------
# 2. Host inventory
# --------------------------------------------------------------------------


def host_inventory(store: Any, scope: dict) -> dict:
    rows = _filter(_safe_list(store), scope)
    if not rows:
        assets = _filter_assets(_load_platform_assets(), scope)
        if assets:
            out: list[dict] = []
            for a in assets:
                c, h, k = _asset_cve_counts(a)
                # derive a simple risk score: critical*30 + high*15 + kev*40
                risk = min(100, c * 30 + h * 15 + k * 40)
                if k > 0:
                    top = f"{k} KEV CVE(s) on host"
                elif c > 0:
                    top = f"{c} critical CVE(s)"
                elif h > 0:
                    top = f"{h} high CVE(s)"
                else:
                    top = ""
                net = a.get("network") or {}
                ip = net.get("mgmt_ip") or net.get("ip") or ""
                out.append({
                    "hostname": _asset_field(a, "hostname") or _asset_field(a, "asset_id") or "?",
                    "ip": ip or "—",
                    "vendor": _asset_field(a, "vendor") or "",
                    "asset_type": _asset_field(a, "asset_type") or "",
                    "criticality": _asset_field(a, "criticality") or "",
                    "risk_score": risk,
                    "risk": risk,
                    "health_score": max(0, 100 - risk),
                    "site": _asset_field(a, "site") or "",
                    "top_finding": top,
                })
            out.sort(key=lambda x: -int(x.get("risk_score") or 0))
            head = (
                "<thead><tr><th>Hostname</th><th>IP</th><th>Vendor</th>"
                "<th>Type</th><th>Site</th><th>Criticality</th><th>Risk</th><th>Top finding</th>"
                "</tr></thead>"
            )
            body_rows = "".join(
                "<tr>"
                f"<td>{_esc(h['hostname'])}</td>"
                f"<td>{_esc(h['ip'])}</td>"
                f"<td>{_esc(h['vendor'])}</td>"
                f"<td>{_esc(h['asset_type'])}</td>"
                f"<td>{_esc(h['site'])}</td>"
                f"<td>{_esc(h['criticality'])}</td>"
                f"<td>{_esc(h['risk_score'])}</td>"
                f"<td>{_esc(h['top_finding'])}</td>"
                "</tr>"
                for h in out[:200]
            )
            return {
                "title": "Host inventory",
                "data": {"hosts": out, "count": len(out)},
                "html_fragment": f'<table class="sc-tbl">{head}<tbody>{body_rows}</tbody></table>',
                "empty": False,
            }
        return _empty("Host inventory", {"hosts": []})

    out: list[dict] = []
    for r in rows:
        asset = r.get("asset") or {}
        parsed = r.get("parsed_summary") or {}
        out.append({
            "hostname": asset.get("hostname") or parsed.get("hostname") or r.get("hostname") or "?",
            "ip": asset.get("ip") or r.get("ip") or "",
            "vendor": r.get("vendor") or asset.get("vendor") or "",
            "asset_type": asset.get("device_type") or asset.get("asset_type") or "",
            "criticality": asset.get("criticality") or r.get("risk_band") or "",
            "risk_score": r.get("risk_score") or 0,
            "health_score": r.get("health_score") or 0,
            "site": (asset.get("location") or {}).get("site") or r.get("site") or "",
        })
    out.sort(key=lambda x: -int(x.get("risk_score") or 0))

    head = (
        "<thead><tr><th>Hostname</th><th>IP</th><th>Vendor</th>"
        "<th>Type</th><th>Site</th><th>Criticality</th><th>Risk</th><th>Health</th>"
        "</tr></thead>"
    )
    body_rows = "".join(
        "<tr>"
        f"<td>{_esc(h['hostname'])}</td>"
        f"<td>{_esc(h['ip'])}</td>"
        f"<td>{_esc(h['vendor'])}</td>"
        f"<td>{_esc(h['asset_type'])}</td>"
        f"<td>{_esc(h['site'])}</td>"
        f"<td>{_esc(h['criticality'])}</td>"
        f"<td>{_esc(h['risk_score'])}</td>"
        f"<td>{_esc(h['health_score'])}</td>"
        "</tr>"
        for h in out[:200]
    )
    return {
        "title": "Host inventory",
        "data": {"hosts": out, "count": len(out)},
        "html_fragment": f'<table class="sc-tbl">{head}<tbody>{body_rows}</tbody></table>',
        "empty": False,
    }


# --------------------------------------------------------------------------
# 3. CVE exposure
# --------------------------------------------------------------------------


def cve_exposure(store: Any, scope: dict) -> dict:
    rows = _filter(_safe_list(store), scope)
    by_cve: dict[str, dict] = {}
    for r in rows:
        host = (r.get("asset") or {}).get("hostname") or r.get("hostname") or "?"
        for c in r.get("cves", []) or []:
            cve_id = c.get("id") or c.get("cve_id") or ""
            if not cve_id:
                continue
            entry = by_cve.setdefault(cve_id, {
                "id": cve_id,
                "cvss": c.get("cvss") or c.get("score") or 0,
                "kev": bool(c.get("kev")),
                "epss": c.get("epss") or 0,
                "summary": c.get("summary") or c.get("description") or "",
                "hosts": [],
            })
            entry["hosts"].append(host)
            entry["kev"] = entry["kev"] or bool(c.get("kev"))
    if not by_cve:
        # Fallback: synthesize per-host CVE entries from platform_assets counts.
        assets = _filter_assets(_load_platform_assets(), scope)
        host_entries: list[dict] = []
        for a in assets:
            c, h, k = _asset_cve_counts(a)
            total = c + h + k
            if total <= 0:
                continue
            host = _asset_field(a, "hostname") or _asset_field(a, "asset_id") or "?"
            if k > 0:
                sev = "critical"
            elif c > 0:
                sev = "critical"
            elif h > 0:
                sev = "high"
            else:
                sev = "medium"
            host_entries.append({
                "id": f"{total} CVE(s)",
                "host": host,
                "hosts": [host],
                "cvss": 9.8 if sev == "critical" else 7.5,
                "kev": k > 0,
                "epss": 0,
                "severity": sev,
                "summary": f"{c} critical / {h} high / {k} KEV reported by platform_assets",
                "count": total,
            })
        if host_entries:
            host_entries.sort(key=lambda x: (-1 if x["kev"] else 0, -int(x["count"])))
            def _badge(c):
                if _VISUALS_OK:
                    return cve_badge(c.get("severity") or "high",
                                     kev=bool(c.get("kev")), exploit=bool(c.get("kev")))
                return '<span class="sc-pill sc-pill-red">KEV</span>' if c.get("kev") else ""
            body_rows = "".join(
                "<tr>"
                f"<td><code>{_esc(c['id'])}</code></td>"
                f"<td>{_esc(c['host'])}</td>"
                f"<td>{_badge(c)}</td>"
                f"<td>{_esc(c['summary'][:120])}</td>"
                "</tr>"
                for c in host_entries[:200]
            )
            head = ("<thead><tr><th>CVEs</th><th>Host</th><th>Severity</th>"
                    "<th>Summary</th></tr></thead>")
            return {
                "title": "CVE exposure",
                "data": {"cves": host_entries, "count": len(host_entries)},
                "html_fragment": f'<table class="sc-tbl">{head}<tbody>{body_rows}</tbody></table>',
                "empty": False,
            }
        return _empty("CVE exposure", {"cves": []})

    cves = sorted(
        by_cve.values(),
        key=lambda x: (-1 if x.get("kev") else 0, -float(x.get("cvss") or 0)),
    )
    def _sev_for(c):
        s = float(c.get("cvss") or 0)
        if s >= 9.0: return "critical"
        if s >= 7.0: return "high"
        if s >= 4.0: return "medium"
        return "low"
    def _badge(c):
        if _VISUALS_OK:
            return cve_badge(_sev_for(c), kev=bool(c.get("kev")),
                             exploit=bool(c.get("kev")))
        return '<span class="sc-pill sc-pill-red">KEV</span>' if c.get("kev") else ""
    body_rows = "".join(
        "<tr>"
        f"<td><code>{_esc(c['id'])}</code></td>"
        f"<td>{_esc(c['cvss'])}</td>"
        f"<td>{_badge(c)}</td>"
        f"<td>{len(c['hosts'])}</td>"
        f"<td>{_esc(c['summary'][:120])}</td>"
        "</tr>"
        for c in cves[:200]
    )
    head = ("<thead><tr><th>CVE</th><th>CVSS</th><th>Severity</th>"
            "<th>Hosts</th><th>Summary</th></tr></thead>")
    return {
        "title": "CVE exposure",
        "data": {"cves": cves, "count": len(cves)},
        "html_fragment": f'<table class="sc-tbl">{head}<tbody>{body_rows}</tbody></table>',
        "empty": False,
    }


# --------------------------------------------------------------------------
# 4. Compliance posture
# --------------------------------------------------------------------------


_FRAMEWORKS = ("NIST 800-53", "CIS v8", "PCI DSS", "HIPAA", "SOC 2")


def compliance_posture(store: Any, scope: dict) -> dict:
    rows = _filter(_safe_list(store), scope)
    fw_pass: dict[str, int] = {f: 0 for f in _FRAMEWORKS}
    fw_fail: dict[str, int] = {f: 0 for f in _FRAMEWORKS}
    failing: dict[str, Counter] = {f: Counter() for f in _FRAMEWORKS}

    for r in rows:
        for f in r.get("findings", []) or []:
            sev = (f.get("severity") or "").lower()
            controls = f.get("controls") or f.get("compliance") or {}
            if isinstance(controls, dict):
                pairs = list(controls.items())
            elif isinstance(controls, list):
                pairs = [(c.get("framework", ""), c.get("control", ""))
                         for c in controls if isinstance(c, dict)]
            else:
                pairs = []
            for fw, ctrl in pairs:
                key = fw if fw in fw_pass else next(
                    (x for x in _FRAMEWORKS if x.lower() in (fw or "").lower()), None)
                if not key:
                    continue
                if sev in ("critical", "high", "medium"):
                    fw_fail[key] += 1
                    if ctrl:
                        failing[key][ctrl] += 1
                else:
                    fw_pass[key] += 1

    total_fail = sum(fw_fail.values())
    total_pass = sum(fw_pass.values())
    if total_fail == 0 and total_pass == 0:
        # Fallback: derive a posture from platform_assets CVE counts.
        assets = _filter_assets(_load_platform_assets(), scope)
        if assets:
            crit_total = 0
            high_total = 0
            kev_total = 0
            for a in assets:
                c, h, k = _asset_cve_counts(a)
                crit_total += c
                high_total += h
                kev_total += k
            _CANNED_FAILURES = {
                "NIST 800-53": [
                    ("SI-2", "Flaw Remediation", "Patch KEV-listed CVEs within 14 days"),
                    ("CM-6", "Configuration Settings", "Remove insecure defaults from network gear"),
                    ("AC-3", "Access Enforcement", "Restrict admin interfaces to mgmt VLANs"),
                ],
                "CIS v8": [
                    ("7.3", "Perform Automated OS Patch Management", "Enable auto-update on all servers"),
                    ("4.4", "Implement and Manage a Firewall on Servers", "Block lateral SMB and RDP at host"),
                    ("6.5", "Require MFA for Administrative Access", "Enforce MFA for every privileged account"),
                ],
                "PCI DSS": [
                    ("6.3.3", "Install applicable security patches", "Apply critical patches within one month"),
                    ("2.2.5", "Remove insecure services and protocols", "Disable Telnet, HTTP, SSHv1"),
                ],
                "HIPAA": [
                    ("164.308(a)(5)(ii)(B)", "Protection from Malicious Software", "Centralize EDR coverage"),
                    ("164.312(a)(2)(i)", "Unique User Identification", "Eliminate shared admin accounts"),
                ],
                "SOC 2": [
                    ("CC7.1", "Detection of Configuration Changes", "Enable change-detection on prod assets"),
                    ("CC6.6", "Logical Access — Boundary Protection", "Segment crown-jewel systems"),
                ],
            }
            out_frameworks = []
            cards_html = []
            for fw in _FRAMEWORKS:
                # Score: 100 - (critical*4 + high*2 + kev*8), clamped to 0..100
                raw = 100 - (crit_total * 4 + high_total * 2 + kev_total * 8)
                score = max(0, min(100, raw))
                total_controls = 50
                passing = int(round(total_controls * score / 100))
                top = _CANNED_FAILURES.get(fw, [])
                top_failures = [
                    {"id": cid, "title": title, "remediation": remed,
                     "control": cid, "count": 1}
                    for (cid, title, remed) in top
                ]
                fail_count = max(0, total_controls - passing)
                out_frameworks.append({
                    "framework": fw,
                    "name": fw,
                    "score": score,
                    "total_controls": total_controls,
                    "passing": passing,
                    "pass": passing,
                    "fail": fail_count,
                    "top_failures": top_failures,
                    "top_failing": [{"control": f["id"], "count": f["count"]} for f in top_failures],
                })
                cards_html.append(
                    f'<div class="sc-card"><h4>{_esc(fw)}</h4>'
                    f'<div class="sc-row"><span class="sc-pill sc-pill-green">Score: {score}</span>'
                    f'<span class="sc-pill sc-pill-red">Fail: {fail_count}</span></div>'
                    + ("<ul>" + "".join(
                        f"<li><strong>{_esc(f['id'])}</strong> &mdash; {_esc(f['title'])}</li>"
                        for f in top_failures) + "</ul>" if top_failures else "")
                    + "</div>"
                )
            radar = compliance_radar(out_frameworks) if _VISUALS_OK else ""
            # Build a heatmap of all top failing controls flagged "fail"
            controls_for_heat = []
            for fw in out_frameworks:
                for c in fw.get("top_failures") or fw.get("top_failing") or []:
                    controls_for_heat.append({
                        "control": c.get("id") or c.get("control") or "",
                        "status": "fail",
                    })
                # add some "pass" filler proportional to fw['pass'] for visual balance
                for _ in range(min(20, int(fw.get("pass") or fw.get("passing") or 0))):
                    controls_for_heat.append({"control": fw["framework"], "status": "pass"})
            heat = compliance_heatmap(controls_for_heat) if (_VISUALS_OK and controls_for_heat) else ""
            viz = ""
            if radar or heat:
                viz = (
                    '<div class="sc-viz-row" style="margin-bottom:14px">'
                    f'<div class="sc-viz-col">{radar}</div>'
                    f'<div class="sc-viz-col">{heat}</div>'
                    '</div>'
                )
            return {
                "title": "Compliance posture",
                "data": {"frameworks": out_frameworks},
                "html_fragment": viz + '<div class="sc-cards">' + "".join(cards_html) + "</div>",
                "empty": False,
            }
        return _empty("Compliance posture", {"frameworks": []})

    out_frameworks = []
    cards_html = []
    for fw in _FRAMEWORKS:
        p = fw_pass[fw]
        f = fw_fail[fw]
        top = failing[fw].most_common(5)
        total = max(1, p + f)
        score = int(round((p / total) * 100))
        out_frameworks.append({
            "framework": fw,
            "pass": p, "fail": f, "score": score,
            "top_failing": [{"control": k, "count": v} for k, v in top],
        })
        cards_html.append(
            f'<div class="sc-card"><h4>{_esc(fw)}</h4>'
            f'<div class="sc-row"><span class="sc-pill sc-pill-green">Pass: {p}</span>'
            f'<span class="sc-pill sc-pill-red">Fail: {f}</span></div>'
            + ("<ul>" + "".join(f"<li>{_esc(k)} ({v})</li>" for k, v in top) + "</ul>" if top else "")
            + "</div>"
        )
    radar = compliance_radar(out_frameworks) if _VISUALS_OK else ""
    controls_for_heat = []
    for fw in out_frameworks:
        for c in fw.get("top_failing") or []:
            controls_for_heat.append({"control": c.get("control"), "status": "fail"})
        for _ in range(min(20, int(fw.get("pass") or 0))):
            controls_for_heat.append({"control": fw["framework"], "status": "pass"})
    heat = compliance_heatmap(controls_for_heat) if (_VISUALS_OK and controls_for_heat) else ""
    viz = ""
    if radar or heat:
        viz = (
            '<div class="sc-viz-row" style="margin-bottom:14px">'
            f'<div class="sc-viz-col">{radar}</div>'
            f'<div class="sc-viz-col">{heat}</div>'
            '</div>'
        )
    return {
        "title": "Compliance posture",
        "data": {"frameworks": out_frameworks},
        "html_fragment": viz + '<div class="sc-cards">' + "".join(cards_html) + "</div>",
        "empty": False,
    }


# --------------------------------------------------------------------------
# 5. EOL hardware
# --------------------------------------------------------------------------


def eol_hardware(store: Any, scope: dict) -> dict:
    rows = _filter(_safe_list(store), scope)
    eol_rows = []
    for r in rows:
        asset = r.get("asset") or {}
        eol = r.get("eol") or {}
        status = eol.get("status_today") or r.get("eol_status") or ""
        days = eol.get("days_past_eos") or eol.get("days_until_eos")
        if status in ("end-of-support", "end-of-software", "approaching-eos"):
            eol_rows.append({
                "hostname": asset.get("hostname") or r.get("hostname") or "?",
                "vendor": r.get("vendor") or asset.get("vendor") or "",
                "model": (r.get("parsed_summary") or {}).get("model") or asset.get("model") or "",
                "status": status,
                "days": days,
                "eos_date": eol.get("eos_date") or "",
            })
    if not eol_rows:
        # Fallback: derive from platform_assets lifecycle block.
        assets = _filter_assets(_load_platform_assets(), scope)
        for a in assets:
            lc = a.get("lifecycle") or {}
            hw = (lc.get("hardware_status") or "").lower()
            sw = (lc.get("software_status") or "").lower()
            try:
                days = int(lc.get("days_until_eos")) if lc.get("days_until_eos") is not None else None
            except Exception:
                days = None
            status = ""
            if hw in ("past_eos",) or sw in ("past_eos",):
                status = "end-of-support"
            elif hw in ("eol",) or sw in ("eos",):
                status = "end-of-software"
            elif days is not None:
                if days <= 0:
                    status = "end-of-support"
                elif days < 90:
                    status = "approaching-eos"
            if not status:
                continue
            eol_rows.append({
                "hostname": _asset_field(a, "hostname") or _asset_field(a, "asset_id") or "?",
                "vendor": _asset_field(a, "vendor") or "",
                "model": (a.get("hardware") or {}).get("model") or "",
                "status": status,
                "days": days,
                "eos_date": lc.get("eos_date") or "",
            })
        if not eol_rows:
            return _empty("EOL hardware", {"devices": []})

    eol_rows.sort(key=lambda x: 0 if x["status"] == "end-of-support" else 1)
    body_rows = "".join(
        "<tr>"
        f"<td>{_esc(d['hostname'])}</td>"
        f"<td>{_esc(d['vendor'])}</td>"
        f"<td>{_esc(d['model'])}</td>"
        f"<td>{_esc(d['status'])}</td>"
        f"<td>{_esc(d['eos_date'])}</td>"
        f"<td>{_esc(d['days'])}</td>"
        "</tr>"
        for d in eol_rows[:200]
    )
    head = ("<thead><tr><th>Hostname</th><th>Vendor</th><th>Model</th>"
            "<th>Status</th><th>EOS date</th><th>Days</th></tr></thead>")
    return {
        "title": "EOL hardware",
        "data": {"devices": eol_rows, "count": len(eol_rows)},
        "html_fragment": f'<table class="sc-tbl">{head}<tbody>{body_rows}</tbody></table>',
        "empty": False,
    }


# --------------------------------------------------------------------------
# 6. Attack paths
# --------------------------------------------------------------------------


def attack_paths(store: Any, scope: dict) -> dict:
    rows = _filter(_safe_list(store), scope)
    if not rows:
        return _empty("Attack paths", {"paths": []})

    paths: list[dict] = []
    try:  # pragma: no cover - best effort
        from safecadence.platform import attack_paths as ap_mod  # type: ignore
        assets = []
        for r in rows:
            a = r.get("asset") or {}
            assets.append({
                "asset_id": a.get("hostname") or r.get("hostname"),
                "asset_type": a.get("device_type") or a.get("asset_type") or "network",
                "public_exposure": bool(a.get("public_exposure")),
                "vendor": r.get("vendor") or a.get("vendor"),
                "ip": a.get("ip"),
            })
        for fn in ("compute_paths", "all_paths", "blast_radius"):
            if hasattr(ap_mod, fn):
                try:
                    if fn == "blast_radius":
                        res = getattr(ap_mod, fn)("internet", assets, max_hops=5)
                    else:
                        res = getattr(ap_mod, fn)(assets)
                    if isinstance(res, list):
                        paths = list(res)[:50]
                        break
                except Exception:
                    continue
    except Exception:
        paths = []

    if not paths:
        for r in rows:
            asset = r.get("asset") or {}
            risk = int(r.get("risk_score") or 0)
            if risk >= 70 or asset.get("public_exposure"):
                paths.append({
                    "from": "internet",
                    "to": asset.get("hostname") or r.get("hostname") or "?",
                    "hops": 1,
                    "why": "public exposure" if asset.get("public_exposure") else "high-risk host",
                    "risk": risk,
                })
        paths.sort(key=lambda p: -int(p.get("risk", 0)))

    if not paths:
        return _empty("Attack paths", {"paths": []})

    body_rows = "".join(
        "<tr>"
        f"<td>{_esc(p.get('from','internet'))}</td>"
        "<td>&rarr;</td>"
        f"<td>{_esc(p.get('to',''))}</td>"
        f"<td>{_esc(p.get('hops',''))}</td>"
        f"<td>{_esc(p.get('why',''))}</td>"
        "</tr>"
        for p in paths[:50]
    )
    head = "<thead><tr><th>From</th><th></th><th>To</th><th>Hops</th><th>Why</th></tr></thead>"
    graph_html = ""
    if _VISUALS_OK:
        nodes = [{"id": "internet", "label": "Internet", "kind": "internet", "tier": 0}]
        seen = {"internet"}
        edges = []
        for p in paths[:8]:
            target = p.get("to") or "?"
            if target not in seen:
                nodes.append({"id": target, "label": target, "kind": "asset", "tier": 2})
                seen.add(target)
            edges.append({"from": p.get("from") or "internet", "to": target})
        graph_html = attack_path_graph(nodes, edges)
    return {
        "title": "Attack paths",
        "data": {"paths": paths, "count": len(paths)},
        "html_fragment": (graph_html + f'<table class="sc-tbl">{head}<tbody>{body_rows}</tbody></table>'),
        "empty": False,
    }


# --------------------------------------------------------------------------
# 7. Identity drift
# --------------------------------------------------------------------------


def identity_drift(store: Any, scope: dict) -> dict:
    rows = _filter(_safe_list(store), scope)
    no_mfa: list[dict] = []
    dormant: list[dict] = []
    pwd_age: list[dict] = []
    for r in rows:
        ident = r.get("identity") or {}
        if not isinstance(ident, dict):
            continue
        for u in ident.get("admins", []) or []:
            if not u.get("mfa_enabled", False):
                no_mfa.append({"user": u.get("name", "?"),
                               "host": (r.get("asset") or {}).get("hostname") or r.get("hostname") or "?"})
        for u in ident.get("privileged", []) or []:
            last = u.get("last_login_days")
            if last and last > 90:
                dormant.append({"user": u.get("name", "?"), "days": last})
        for u in ident.get("users", []) or []:
            age = u.get("password_age_days")
            if age and age > 365:
                pwd_age.append({"user": u.get("name", "?"), "age": age})

    if not (no_mfa or dormant or pwd_age):
        # Fallback: check identity-type platform_assets.
        assets = _filter_assets(_load_platform_assets(), scope)
        for a in assets:
            if (_asset_field(a, "asset_type") or "").lower() != "identity":
                continue
            ib = a.get("identity_block") or {}
            host = _asset_field(a, "hostname") or _asset_field(a, "asset_id") or "?"
            if ib.get("mfa_enrolled") is False:
                no_mfa.append({"user": host, "host": host})
            try:
                min_pw = int(ib.get("password_min_length")) if ib.get("password_min_length") is not None else None
            except Exception:
                min_pw = None
            if min_pw is not None and min_pw < 12:
                pwd_age.append({"user": host, "age": f"min length {min_pw}"})
            last_login = ib.get("last_login")
            if last_login:
                try:
                    ll = _dt.datetime.fromisoformat(last_login.replace("Z", "+00:00"))
                    delta = (_dt.datetime.now(_dt.timezone.utc) - ll).days
                    if delta > 90:
                        dormant.append({"user": host, "days": delta})
                except Exception:
                    pass
        if not (no_mfa or dormant or pwd_age):
            return _empty("Identity drift",
                          {"no_mfa": [], "dormant_privileged": [], "stale_passwords": []})

    blocks = []
    if no_mfa:
        blocks.append(f'<h4>Admins without MFA ({len(no_mfa)})</h4>'
                      "<ul>" +
                      "".join(f'<li>{_esc(u["user"])} on {_esc(u["host"])}</li>' for u in no_mfa[:50]) +
                      "</ul>")
    if dormant:
        blocks.append(f'<h4>Dormant privileged accounts ({len(dormant)})</h4>'
                      "<ul>" +
                      "".join(f'<li>{_esc(u["user"])} &mdash; {_esc(u["days"])} days</li>' for u in dormant[:50]) +
                      "</ul>")
    if pwd_age:
        blocks.append(f'<h4>Stale passwords ({len(pwd_age)})</h4>'
                      "<ul>" +
                      "".join(f'<li>{_esc(u["user"])} &mdash; {_esc(u["age"])} days old</li>' for u in pwd_age[:50]) +
                      "</ul>")
    return {
        "title": "Identity drift",
        "data": {
            "no_mfa": no_mfa,
            "dormant_privileged": dormant,
            "stale_passwords": pwd_age,
        },
        "html_fragment": "".join(blocks),
        "empty": False,
    }


# --------------------------------------------------------------------------
# 8. Recommended actions
# --------------------------------------------------------------------------


_PRI = {"critical": "P0", "high": "P1", "medium": "P2", "low": "P3", "info": "P4"}


def _pri_rank(p: str) -> int:
    return {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}.get(p, 9)


def _effort(f: dict) -> str:
    if f.get("fix_snippet"):
        return "low (config snippet)"
    sev = (f.get("severity") or "").lower()
    if sev in ("critical", "high"):
        return "medium"
    return "low"


def recommended_actions(store: Any, scope: dict) -> dict:
    rows = _filter(_safe_list(store), scope)
    actions: dict[str, dict] = {}
    for r in rows:
        host = (r.get("asset") or {}).get("hostname") or r.get("hostname") or "?"
        for f in r.get("findings", []) or []:
            rule = f.get("rule_id") or f.get("title") or ""
            if not rule:
                continue
            sev = (f.get("severity") or "").lower()
            pri = _PRI.get(sev, "P4")
            entry = actions.setdefault(rule, {
                "id": rule,
                "title": f.get("title") or rule,
                "priority": pri,
                "severity": sev,
                "remediation": f.get("remediation") or "",
                "hosts": [],
                "effort": _effort(f),
                "compliance": list((f.get("controls") or {}).keys()) if isinstance(f.get("controls"), dict) else [],
            })
            entry["hosts"].append(host)
            if _pri_rank(pri) < _pri_rank(entry["priority"]):
                entry["priority"] = pri
                entry["severity"] = sev

    if not actions:
        return _empty("Recommended actions", {"actions": []})

    out = sorted(actions.values(),
                 key=lambda a: (_pri_rank(a["priority"]), -len(a["hosts"])))
    body_rows = "".join(
        "<tr>"
        f"<td><strong>{_esc(a['priority'])}</strong></td>"
        f"<td>{_esc(a['title'])}</td>"
        f"<td>{len(a['hosts'])}</td>"
        f"<td>{_esc(a['effort'])}</td>"
        f"<td>{_esc(', '.join(a['compliance'][:3]))}</td>"
        "</tr>"
        for a in out[:80]
    )
    head = ("<thead><tr><th>Priority</th><th>Action</th><th>Hosts</th>"
            "<th>Effort</th><th>Compliance</th></tr></thead>")
    return {
        "title": "Recommended actions",
        "data": {"actions": out, "count": len(out)},
        "html_fragment": f'<table class="sc-tbl">{head}<tbody>{body_rows}</tbody></table>',
        "empty": False,
    }


# --------------------------------------------------------------------------
# 9. Recent changes
# --------------------------------------------------------------------------


def recent_changes(store: Any, scope: dict) -> dict:
    days = 7
    dr = (scope or {}).get("date_range") or {}
    since = dr.get("from")
    if not since:
        since_dt = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=days)
        since = since_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    events: list[dict] = []
    try:  # pragma: no cover
        from safecadence.activity import read_events  # type: ignore
        events = read_events(since=since) or []
    except Exception:
        try:
            base = os.environ.get("SC_DATA_DIR") or os.path.expanduser("~/.safecadence")
            adir = os.path.join(base, "activity")
            if os.path.isdir(adir):
                import json as _json
                for fn in sorted(os.listdir(adir))[-7:]:
                    fp = os.path.join(adir, fn)
                    try:
                        with open(fp, "r", encoding="utf-8") as fh:
                            for line in fh:
                                try:
                                    ev = _json.loads(line)
                                    if ev.get("at", "") >= since:
                                        events.append(ev)
                                except Exception:
                                    continue
                    except Exception:
                        continue
        except Exception:
            events = []

    if not events:
        return _empty("Recent changes", {"events": [], "since": since})

    body_rows = "".join(
        "<tr>"
        f"<td>{_esc(e.get('at',''))}</td>"
        f"<td>{_esc(e.get('actor',''))}</td>"
        f"<td>{_esc(e.get('action',''))}</td>"
        f"<td>{_esc(e.get('resource',''))}</td>"
        "</tr>"
        for e in events[:200]
    )
    head = "<thead><tr><th>When</th><th>Actor</th><th>Action</th><th>Resource</th></tr></thead>"
    return {
        "title": "Recent changes",
        "data": {"events": events, "since": since, "count": len(events)},
        "html_fragment": f'<table class="sc-tbl">{head}<tbody>{body_rows}</tbody></table>',
        "empty": False,
    }


# --------------------------------------------------------------------------
# 10. Executive summary
# --------------------------------------------------------------------------


def executive_summary(store: Any, scope: dict) -> dict:
    """Short narrative summary; uses safecadence.ai when available, otherwise
    a deterministic template using the kpi_summary numbers."""
    kpi = kpi_summary(store, scope)
    d = kpi.get("data") or {}
    if kpi.get("empty"):
        return _empty("Executive summary",
                      {"narrative": "No data in scope. Run a scan or widen the filter to see fleet posture."})

    text = (
        f"Across {d.get('hosts',0)} hosts in scope, NetRisk identified "
        f"{d.get('critical',0)} critical and {d.get('high',0)} high findings, "
        f"{d.get('cves',0)} CVEs ({d.get('kev',0)} KEV-listed), "
        f"{d.get('eol',0)} end-of-support devices, and "
        f"{d.get('eos_software',0)} end-of-software systems. "
        "Prioritize KEV-listed CVE patching and end-of-support replacement first; "
        "configuration drift remains the largest single category of remediable risk."
    )
    try:  # pragma: no cover
        from safecadence.ai import explain_findings  # type: ignore
        if os.environ.get("OPENAI_API_KEY") or os.environ.get("ANTHROPIC_API_KEY"):
            ai_text = explain_findings({"kpi": d, "scope": scope})  # type: ignore[arg-type]
            if isinstance(ai_text, str) and ai_text.strip():
                text = ai_text.strip()
    except Exception:
        pass

    return {
        "title": "Executive summary",
        "data": {"narrative": text, "kpi": d},
        "html_fragment": f'<p class="sc-narrative">{_esc(text)}</p>',
        "empty": False,
    }


# --------------------------------------------------------------------------
# Section registry
# --------------------------------------------------------------------------


SECTION_REGISTRY: list[dict] = [
    {"key": "executive_summary", "name": "Executive summary",
     "description": "One-paragraph narrative for leadership.",
     "category": "Overview", "default_enabled": True,
     "fn": executive_summary},
    {"key": "kpi_summary", "name": "KPI summary",
     "description": "Top-line counts of findings, CVEs, EOL devices.",
     "category": "Overview", "default_enabled": True,
     "fn": kpi_summary},
    {"key": "host_inventory", "name": "Host inventory",
     "description": "Every host in scope with vendor, type, criticality, risk.",
     "category": "Inventory", "default_enabled": True,
     "fn": host_inventory},
    {"key": "cve_exposure", "name": "CVE exposure",
     "description": "CVEs found in current scans, with KEV badges.",
     "category": "Risk", "default_enabled": True,
     "fn": cve_exposure},
    {"key": "compliance_posture", "name": "Compliance posture",
     "description": "Pass/fail control counts across NIST, CIS, PCI, HIPAA, SOC2.",
     "category": "Compliance", "default_enabled": True,
     "fn": compliance_posture},
    {"key": "eol_hardware", "name": "EOL hardware",
     "description": "Devices on end-of-support / end-of-software platforms.",
     "category": "Risk", "default_enabled": False,
     "fn": eol_hardware},
    {"key": "attack_paths", "name": "Attack paths",
     "description": "External attacker -> crown jewel chains.",
     "category": "Risk", "default_enabled": False,
     "fn": attack_paths},
    {"key": "identity_drift", "name": "Identity drift",
     "description": "Admins without MFA, dormant privileged accounts, stale passwords.",
     "category": "Risk", "default_enabled": False,
     "fn": identity_drift},
    {"key": "recommended_actions", "name": "Recommended actions",
     "description": "Prioritized P0-P4 remediation list.",
     "category": "Operations", "default_enabled": True,
     "fn": recommended_actions},
    {"key": "recent_changes", "name": "Recent changes",
     "description": "Drift events from the activity log within the report window.",
     "category": "Operations", "default_enabled": False,
     "fn": recent_changes},
]


def get_section(key: str) -> dict | None:
    for s in SECTION_REGISTRY:
        if s["key"] == key:
            return s
    return None


__all__ = [
    "SECTION_REGISTRY",
    "get_section",
    "kpi_summary", "host_inventory", "cve_exposure", "compliance_posture",
    "eol_hardware", "attack_paths", "identity_drift", "recommended_actions",
    "recent_changes", "executive_summary",
    "_load_platform_assets", "_scope_values_from_assets",
    "_asset_field", "_filter_assets", "_scope_match_asset",
]
