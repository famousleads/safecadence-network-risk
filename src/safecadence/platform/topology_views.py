"""Topology map views — emit Cytoscape.js JSON for the 9 named views.

The frontend loads Cytoscape from a CDN and renders whichever view
the operator picks. The backend's job is to project the asset
inventory into the right shape for each view: nodes + edges with
`data` payloads carrying the asset id, vendor, criticality, health,
risk, and view-specific metadata.

The 9 views from the spec:

  1. global       — country / region / site grouping
  2. campus       — buildings / floors / closets
  3. subnet       — VLANs / IP ranges
  4. security_zone — firewall zones (DMZ / trust / untrust / mgmt)
  5. cloud        — VPC / VNET / subnets / cloud resources
  6. risk_heat    — coloured by risk level (low/med/high/critical)
  7. lifecycle    — coloured by EOL / EOS proximity
  8. health       — coloured by health grade (A–F)
  9. vulnerability — coloured by KEV / critical-CVE counts

Cytoscape format:
    {
      "elements": {
        "nodes": [{"data": {"id": "...", "label": "...", ...}}, ...],
        "edges": [{"data": {"source": "...", "target": "...", ...}}, ...],
      },
      "layout": { "name": "...", "padding": 20 },
      "style": [...],
    }
"""

from __future__ import annotations

from typing import Any

from safecadence.server.platform_api import list_assets


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _ident(a: dict) -> dict:
    return a.get("identity") or {}


def _label(a: dict) -> str:
    ident = _ident(a)
    return (ident.get("hostname") or ident.get("asset_id")
            or "(unnamed)")


def _risk_color(a: dict) -> str:
    sec = a.get("security") or {}
    if sec.get("kev_cves", 0) > 0:
        return "#ef4444"   # red
    if sec.get("critical_cves", 0) > 0:
        return "#f59e0b"   # amber
    if sec.get("high_cves", 0) > 0:
        return "#eab308"   # yellow
    return "#10b981"       # green


def _lifecycle_color(a: dict) -> str:
    days = (a.get("lifecycle") or {}).get("days_until_eos")
    if days is None:
        return "#9ca3af"   # gray — unknown
    if days <= 0:
        return "#ef4444"
    if days <= 180:
        return "#f59e0b"
    if days <= 365:
        return "#eab308"
    return "#10b981"


def _health_color(a: dict) -> str:
    grade = (a.get("health") or {}).get("grade") or "?"
    return {"A": "#10b981", "B": "#22c55e", "C": "#eab308",
            "D": "#f59e0b", "F": "#ef4444"}.get(grade, "#9ca3af")


def _kev_color(a: dict) -> str:
    sec = a.get("security") or {}
    n = (sec.get("kev_cves") or 0)
    if n >= 3: return "#dc2626"
    if n >= 1: return "#ef4444"
    if (sec.get("critical_cves") or 0) > 0: return "#f59e0b"
    return "#9ca3af"


def _node(asset_id: str, label: str, *, parent: str = "",
           color: str = "#3b82f6", shape: str = "round-rectangle",
           extra: dict | None = None) -> dict:
    data = {"id": asset_id, "label": label, "color": color, "shape": shape}
    if parent:
        data["parent"] = parent
    if extra:
        data.update(extra)
    return {"data": data}


def _edge(src: str, dst: str, *, label: str = "",
           color: str = "#9ca3af") -> dict:
    return {"data": {"id": f"{src}--{dst}",
                       "source": src, "target": dst,
                       "label": label, "color": color}}


_LAYOUTS = {
    "global":        {"name": "concentric", "padding": 30},
    "campus":        {"name": "breadthfirst", "padding": 30, "directed": True},
    "subnet":        {"name": "cose", "padding": 30, "fit": True},
    "security_zone": {"name": "cose", "padding": 30, "fit": True},
    "cloud":         {"name": "concentric", "padding": 30},
    "risk_heat":     {"name": "cose", "padding": 30, "fit": True},
    "lifecycle":     {"name": "cose", "padding": 30, "fit": True},
    "health":        {"name": "cose", "padding": 30, "fit": True},
    "vulnerability": {"name": "cose", "padding": 30, "fit": True},
}


_BASE_STYLE = [
    {"selector": "node", "style": {
        "label": "data(label)", "background-color": "data(color)",
        "shape": "data(shape)", "text-valign": "bottom",
        "text-halign": "center", "color": "#cbd5e1",
        "font-size": "10px", "padding": "6px",
        "border-color": "rgba(255,255,255,0.18)", "border-width": 1,
    }},
    {"selector": "node[parent]", "style": {"text-valign": "top"}},
    {"selector": "$node > node", "style": {
        "label": "data(label)", "padding": 12,
        "background-color": "rgba(99,102,241,0.10)",
        "border-color": "rgba(99,102,241,0.40)", "border-width": 1,
        "shape": "round-rectangle", "color": "#a5b4fc",
        "font-size": "11px", "font-weight": "bold",
    }},
    {"selector": "edge", "style": {
        "width": 1.4, "line-color": "data(color)",
        "target-arrow-color": "data(color)",
        "target-arrow-shape": "triangle",
        "curve-style": "bezier", "label": "data(label)",
        "font-size": "9px", "color": "#94a3b8",
    }},
]


def _envelope(view: str, nodes: list[dict],
               edges: list[dict], stats: dict) -> dict:
    return {
        "view": view,
        "elements": {"nodes": nodes, "edges": edges},
        "layout": _LAYOUTS.get(view, {"name": "cose", "padding": 30}),
        "style": _BASE_STYLE,
        "stats": stats,
    }


# --------------------------------------------------------------------------
# 1. Global — country / region / site
# --------------------------------------------------------------------------

def view_global(assets: list[dict] | None = None) -> dict:
    assets = assets or list_assets()
    nodes: list[dict] = []
    edges: list[dict] = []
    seen: set[str] = set()
    for a in assets:
        ident = _ident(a)
        country = ident.get("country") or "unknown"
        site = ident.get("site") or "unknown"
        country_id = f"country:{country}"
        site_id = f"site:{country}:{site}"
        if country_id not in seen:
            nodes.append(_node(country_id, country, color="#3b82f6"))
            seen.add(country_id)
        if site_id not in seen:
            nodes.append(_node(site_id, site, parent=country_id,
                                color="#1e3a8a"))
            seen.add(site_id)
        aid = ident.get("asset_id") or ""
        if aid:
            nodes.append(_node(aid, _label(a), parent=site_id,
                                color=_risk_color(a)))
    return _envelope("global", nodes, edges,
                       {"asset_count": len(assets),
                        "country_count": sum(1 for n in nodes
                                              if n["data"]["id"].startswith("country:"))})


# --------------------------------------------------------------------------
# 2. Campus — building / floor / rack
# --------------------------------------------------------------------------

def view_campus(assets: list[dict] | None = None) -> dict:
    assets = assets or list_assets()
    nodes: list[dict] = []
    seen: set[str] = set()
    for a in assets:
        ident = _ident(a)
        campus = ident.get("campus") or "unknown"
        building = ident.get("building") or "unknown"
        floor = ident.get("floor") or "?"
        rack = ident.get("rack") or "?"
        c_id = f"campus:{campus}"
        b_id = f"building:{campus}:{building}"
        f_id = f"floor:{campus}:{building}:{floor}"
        r_id = f"rack:{campus}:{building}:{floor}:{rack}"
        for nid, lbl, parent, color in [
            (c_id, campus, "", "#0ea5e9"),
            (b_id, f"Bldg {building}", c_id, "#0369a1"),
            (f_id, f"Floor {floor}", b_id, "#075985"),
            (r_id, f"Rack {rack}", f_id, "#0c4a6e"),
        ]:
            if nid not in seen:
                nodes.append(_node(nid, lbl, parent=parent, color=color))
                seen.add(nid)
        aid = ident.get("asset_id") or ""
        if aid:
            nodes.append(_node(aid, _label(a), parent=r_id,
                                color=_health_color(a)))
    return _envelope("campus", nodes, [], {"asset_count": len(assets)})


# --------------------------------------------------------------------------
# 3. Subnet — VLANs / IP ranges
# --------------------------------------------------------------------------

def view_subnet(assets: list[dict] | None = None) -> dict:
    assets = assets or list_assets()
    nodes: list[dict] = []
    seen: set[str] = set()
    for a in assets:
        ident = _ident(a)
        net = a.get("network") or {}
        vlan = net.get("vlan") or "no-vlan"
        subnet = net.get("subnet") or net.get("cidr") or "no-subnet"
        v_id = f"vlan:{vlan}"
        s_id = f"subnet:{vlan}:{subnet}"
        if v_id not in seen:
            nodes.append(_node(v_id, f"VLAN {vlan}", color="#8b5cf6"))
            seen.add(v_id)
        if s_id not in seen:
            nodes.append(_node(s_id, str(subnet), parent=v_id,
                                color="#6d28d9"))
            seen.add(s_id)
        aid = ident.get("asset_id") or ""
        if aid:
            nodes.append(_node(aid, _label(a), parent=s_id,
                                color=_risk_color(a)))
    return _envelope("subnet", nodes, [], {"asset_count": len(assets)})


# --------------------------------------------------------------------------
# 4. Security zone — firewall trust zones
# --------------------------------------------------------------------------

def view_security_zone(assets: list[dict] | None = None) -> dict:
    assets = assets or list_assets()
    nodes: list[dict] = []
    seen: set[str] = set()
    for a in assets:
        ident = _ident(a)
        net = a.get("network") or {}
        zone = (net.get("zone") or "trust").lower()
        z_id = f"zone:{zone}"
        if z_id not in seen:
            color = {"dmz": "#f59e0b", "edge": "#ef4444",
                       "trust": "#10b981", "untrust": "#dc2626",
                       "mgmt": "#3b82f6"}.get(zone, "#6b7280")
            nodes.append(_node(z_id, zone.upper(), color=color))
            seen.add(z_id)
        aid = ident.get("asset_id") or ""
        if aid:
            nodes.append(_node(aid, _label(a), parent=z_id,
                                color=_risk_color(a)))
    return _envelope("security_zone", nodes, [], {"asset_count": len(assets)})


# --------------------------------------------------------------------------
# 5. Cloud — accounts / VPC / subnets / resources
# --------------------------------------------------------------------------

def view_cloud(assets: list[dict] | None = None) -> dict:
    assets = assets or list_assets()
    nodes: list[dict] = []
    seen: set[str] = set()
    for a in assets:
        if _ident(a).get("asset_type") not in ("cloud", "backup"):
            continue
        cloud = a.get("cloud") or {}
        account = (cloud.get("account_id")
                    or cloud.get("subscription_id")
                    or cloud.get("project_id") or "unknown-account")
        region = cloud.get("region") or "no-region"
        a_id = f"acct:{account}"
        r_id = f"region:{account}:{region}"
        if a_id not in seen:
            nodes.append(_node(a_id, f"Acct {account[:20]}",
                                color="#22d3ee"))
            seen.add(a_id)
        if r_id not in seen:
            nodes.append(_node(r_id, region, parent=a_id,
                                color="#0e7490"))
            seen.add(r_id)
        aid = (a.get("identity") or {}).get("asset_id") or ""
        if aid:
            color = "#ef4444" if cloud.get("public_exposure") else _risk_color(a)
            nodes.append(_node(aid, _label(a), parent=r_id, color=color))
    return _envelope("cloud", nodes, [],
                       {"asset_count": sum(1 for a in assets
                                            if _ident(a).get("asset_type")
                                            in ("cloud", "backup"))})


# --------------------------------------------------------------------------
# 6. Risk heat
# --------------------------------------------------------------------------

def view_risk_heat(assets: list[dict] | None = None) -> dict:
    assets = assets or list_assets()
    nodes: list[dict] = []
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for a in assets:
        aid = _ident(a).get("asset_id") or ""
        if not aid:
            continue
        sec = a.get("security") or {}
        if sec.get("kev_cves", 0) > 0:
            band = "critical"
        elif sec.get("critical_cves", 0) > 0:
            band = "high"
        elif sec.get("high_cves", 0) > 0:
            band = "medium"
        else:
            band = "low"
        counts[band] += 1
        size = 60 if band == "critical" else 50 if band == "high" \
                else 40 if band == "medium" else 30
        nodes.append(_node(aid, _label(a), color=_risk_color(a),
                            extra={"size": size, "band": band}))
    return _envelope("risk_heat", nodes, [], counts)


# --------------------------------------------------------------------------
# 7. Lifecycle (EOL proximity)
# --------------------------------------------------------------------------

def view_lifecycle(assets: list[dict] | None = None) -> dict:
    assets = assets or list_assets()
    nodes: list[dict] = []
    counts = {"past_eos": 0, "within_180d": 0,
              "within_year": 0, "ok": 0, "unknown": 0}
    for a in assets:
        aid = _ident(a).get("asset_id") or ""
        if not aid:
            continue
        days = (a.get("lifecycle") or {}).get("days_until_eos")
        if days is None: counts["unknown"] += 1
        elif days <= 0: counts["past_eos"] += 1
        elif days <= 180: counts["within_180d"] += 1
        elif days <= 365: counts["within_year"] += 1
        else: counts["ok"] += 1
        nodes.append(_node(aid, _label(a), color=_lifecycle_color(a),
                            extra={"days_until_eos": days}))
    return _envelope("lifecycle", nodes, [], counts)


# --------------------------------------------------------------------------
# 8. Health
# --------------------------------------------------------------------------

def view_health(assets: list[dict] | None = None) -> dict:
    assets = assets or list_assets()
    nodes: list[dict] = []
    counts = {"A": 0, "B": 0, "C": 0, "D": 0, "F": 0, "?": 0}
    for a in assets:
        aid = _ident(a).get("asset_id") or ""
        if not aid:
            continue
        grade = (a.get("health") or {}).get("grade") or "?"
        counts[grade if grade in counts else "?"] += 1
        nodes.append(_node(aid, _label(a), color=_health_color(a),
                            extra={"grade": grade}))
    return _envelope("health", nodes, [], counts)


# --------------------------------------------------------------------------
# 9. Vulnerability
# --------------------------------------------------------------------------

def view_vulnerability(assets: list[dict] | None = None) -> dict:
    assets = assets or list_assets()
    nodes: list[dict] = []
    counts = {"kev": 0, "critical": 0, "high": 0, "clean": 0}
    for a in assets:
        aid = _ident(a).get("asset_id") or ""
        if not aid:
            continue
        sec = a.get("security") or {}
        if sec.get("kev_cves", 0) > 0: counts["kev"] += 1
        elif sec.get("critical_cves", 0) > 0: counts["critical"] += 1
        elif sec.get("high_cves", 0) > 0: counts["high"] += 1
        else: counts["clean"] += 1
        nodes.append(_node(aid, _label(a), color=_kev_color(a),
                            extra={
                                "kev": sec.get("kev_cves", 0),
                                "critical_cves": sec.get("critical_cves", 0),
                                "high_cves": sec.get("high_cves", 0),
                            }))
    return _envelope("vulnerability", nodes, [], counts)


# --------------------------------------------------------------------------
# Dispatch
# --------------------------------------------------------------------------

VIEWS = {
    "global":        view_global,
    "campus":        view_campus,
    "subnet":        view_subnet,
    "security_zone": view_security_zone,
    "cloud":         view_cloud,
    "risk_heat":     view_risk_heat,
    "lifecycle":     view_lifecycle,
    "health":        view_health,
    "vulnerability": view_vulnerability,
}


def render(view: str, assets: list[dict] | None = None) -> dict:
    fn = VIEWS.get(view)
    if not fn:
        return {"error": f"unknown view {view!r}",
                "available": list(VIEWS.keys())}
    return fn(assets)
