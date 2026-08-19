"""
GIS-lite — /api/v1/geo/assets (GeoJSON) + /map (Leaflet page).

Assets with coordinates (``public_safety.latitude/longitude``, set by
import/adapter/manual edit) become a GeoJSON FeatureCollection, styled
by risk band, ready for Leaflet/ArcGIS/QGIS — GeoJSON is the
vendor-neutral contract.

Local-first note: the /map page loads Leaflet + OpenStreetMap tiles
from the internet WHEN available and degrades to a plain feature list
when offline/air-gapped. The GeoJSON endpoint itself never needs the
internet — agencies can pull it into their own ArcGIS.
"""

from __future__ import annotations

from typing import Any


def asset_feature(asset: dict) -> dict | None:
    """One stored asset → GeoJSON Feature, or None without coordinates."""
    ps = asset.get("public_safety") or {}
    try:
        lat = float(ps.get("latitude") or 0.0)
        lon = float(ps.get("longitude") or 0.0)
    except (TypeError, ValueError):
        return None
    if lat == 0.0 and lon == 0.0:
        return None
    if not (-90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0):
        return None
    ident = asset.get("identity") or {}
    health = asset.get("health") or {}
    return {
        "type": "Feature",
        "geometry": {"type": "Point", "coordinates": [lon, lat]},
        "properties": {
            "asset_id": ident.get("asset_id", ""),
            "hostname": ident.get("hostname", ""),
            "vendor": ident.get("vendor", ""),
            "asset_type": ident.get("asset_type", ""),
            "ps_category": ps.get("ps_category", ""),
            "mission_function": ps.get("mission_function", ""),
            "site": ident.get("site", ""),
            "agency": ps.get("agency", ""),
            "criticality": ident.get("criticality", ""),
            "risk_band": health.get("risk_band", "safe"),
            "overall_score": health.get("overall_score", 100),
        },
    }


def assets_geojson(assets: list[dict], *, site: str = "",
                    ps_category: str = "", risk_band: str = "") -> dict:
    """FeatureCollection over assets that carry coordinates."""
    feats = []
    for a in assets:
        f = asset_feature(a)
        if f is None:
            continue
        p = f["properties"]
        if site and p["site"] != site:
            continue
        if ps_category and p["ps_category"] != ps_category:
            continue
        if risk_band and p["risk_band"] != risk_band:
            continue
        feats.append(f)
    return {"type": "FeatureCollection", "features": feats,
             "properties": {"count": len(feats),
                             "assets_without_geo":
                                 sum(1 for a in assets if asset_feature(a) is None)}}


_MAP_HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SafeCadence — asset map</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
<style>
 body{margin:0;font:14px/1.5 system-ui,sans-serif;background:#0b1220;color:#e2e8f0}
 #map{height:100vh}
 .fallback{padding:24px;max-width:760px;margin:0 auto}
 .fallback table{width:100%;border-collapse:collapse;font-size:13px}
 .fallback td,.fallback th{border-bottom:1px solid #1e293b;padding:6px;text-align:left}
 .legend{position:absolute;bottom:18px;left:12px;z-index:1000;background:#0b1220cc;
   padding:8px 12px;border-radius:8px;font-size:12px}
 .dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:5px}
</style></head><body>
<div id="map"></div>
<div class="legend" id="legend" style="display:none">
  <span class="dot" style="background:#16a34a"></span>safe/low&nbsp;
  <span class="dot" style="background:#d97706"></span>medium/high&nbsp;
  <span class="dot" style="background:#dc2626"></span>critical
</div>
<div class="fallback" id="fallback" style="display:none">
  <h2>Asset map (offline mode)</h2>
  <p>Map tiles need internet access. GeoJSON is available at
     <code>/api/v1/geo/assets</code> for ArcGIS/QGIS import. Assets with
     coordinates:</p>
  <table id="tbl"><thead><tr><th>Host</th><th>Category</th><th>Site</th>
    <th>Risk</th><th>Lat</th><th>Lon</th></tr></thead><tbody></tbody></table>
</div>
<script>
const BAND={critical:"#dc2626",high:"#d97706",medium:"#d97706",
             low:"#16a34a",safe:"#16a34a"};
async function boot(){
  const r=await fetch("/api/v1/geo/assets",{headers:authHeaders()});
  if(!r.ok){showFallback([]);return;}
  const gj=await r.json();
  let leafletOk=false;
  try{
    await import("https://unpkg.com/leaflet@1.9.4/dist/leaflet-src.esm.js");
    leafletOk=typeof L!=="undefined"||true;
  }catch(e){leafletOk=false;}
  if(!leafletOk||typeof L==="undefined"){
    const s=document.createElement("script");
    s.src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js";
    s.onload=()=>draw(gj); s.onerror=()=>showFallback(gj.features||[]);
    document.head.appendChild(s); return;
  }
  draw(gj);
}
function authHeaders(){
  const t=localStorage.getItem("sc_token");
  return t?{Authorization:"Bearer "+t}:{}; }
function draw(gj){
  const feats=gj.features||[];
  if(!feats.length){showFallback(feats);return;}
  const map=L.map("map");
  L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png",
    {maxZoom:19,attribution:"&copy; OpenStreetMap"}).addTo(map);
  const pts=[];
  for(const f of feats){
    const [lon,lat]=f.geometry.coordinates;
    const p=f.properties;
    pts.push([lat,lon]);
    L.circleMarker([lat,lon],{radius:8,color:BAND[p.risk_band]||"#64748b",
      fillOpacity:.75}).addTo(map)
     .bindPopup(`<b>${p.hostname||p.asset_id}</b><br>${p.ps_category||p.asset_type}`+
        `<br>site: ${p.site||"?"} · risk: ${p.risk_band}`+
        `<br>score: ${p.overall_score}/100`);
  }
  map.fitBounds(pts,{padding:[30,30]});
  document.getElementById("legend").style.display="block";
}
function showFallback(feats){
  document.getElementById("map").style.display="none";
  const fb=document.getElementById("fallback");
  fb.style.display="block";
  const tb=fb.querySelector("tbody");
  for(const f of feats){
    const p=f.properties,[lon,lat]=f.geometry.coordinates;
    const tr=document.createElement("tr");
    tr.innerHTML=`<td>${p.hostname||p.asset_id}</td><td>${p.ps_category||p.asset_type}</td>`+
      `<td>${p.site||""}</td><td>${p.risk_band}</td>`+
      `<td>${lat.toFixed(5)}</td><td>${lon.toFixed(5)}</td>`;
    tb.appendChild(tr);
  }
}
boot();
</script></body></html>"""


def build_router():
    try:
        from fastapi import APIRouter, Depends
        from fastapi.responses import HTMLResponse
    except Exception:                                  # pragma: no cover
        return None

    try:
        from safecadence.auth.rbac import UserRole, require_role
        _viewer_dep = require_role(UserRole.VIEWER)
    except Exception:                                  # pragma: no cover
        def _viewer_dep():
            return None

    router = APIRouter(tags=["geo"])

    @router.get("/api/v1/geo/assets")
    def geo_assets(site: str = "", ps_category: str = "",
                    risk_band: str = "", _: Any = Depends(_viewer_dep)):
        from safecadence.server.platform_api import list_assets
        return assets_geojson(list_assets(), site=site,
                                ps_category=ps_category, risk_band=risk_band)

    @router.get("/map", response_class=HTMLResponse, include_in_schema=False)
    def map_page():
        return HTMLResponse(_MAP_HTML)

    return router
