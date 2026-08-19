"""
DESAT (public-safety) UI pages — wrapped in the v9 chrome like every
other page:

* ``GET /map``                       — GIS asset map (Leaflet, offline fallback)
* ``GET /evidence-infrastructure``   — evidence-chain health dashboard
* ``GET /incidents``                 — native incident queue + timelines

Plus the page-local JSON they consume (namespaced under
``/api/v1/desat/*`` so they never collide with the headless server's
routers):

* ``GET /api/v1/desat/geo``              — GeoJSON FeatureCollection
* ``GET /api/v1/desat/evidence-health``  — evidence-chain summary
* ``GET /api/v1/desat/incidents``        — incident list (+detail via ?id=)
"""

from __future__ import annotations

try:
    from fastapi.responses import HTMLResponse
    _FASTAPI_OK = True
except Exception:                                       # pragma: no cover
    _FASTAPI_OK = False

from safecadence.ui._chrome import wrap


# ============================================================ /map

_MAP_BODY = """
<div style="display:flex;align-items:center;gap:12px;margin-bottom:8px">
  <h1 style="margin:0">🗺️ Asset map</h1>
  <span class="muted" id="map-stats" style="font-size:12px"></span>
  <span style="flex:1"></span>
  <select id="map-band" onchange="mapLoad()" style="width:auto;padding:6px 10px;font-size:12px">
    <option value="">All risk bands</option>
    <option value="critical">Critical</option>
    <option value="high">High</option>
    <option value="medium">Medium</option>
    <option value="low">Low</option>
    <option value="safe">Safe</option>
  </select>
  <button class="alt" style="width:auto;padding:6px 10px;font-size:12px"
          onclick="mapLoad()">⟳ Reload</button>
</div>
<p class="muted" style="margin-top:0;font-size:12px">
  Assets with GPS coordinates (set by import, adapter, or the asset
  editor). Color = risk band. The GeoJSON behind this page
  (<code>/api/v1/desat/geo</code>) imports straight into ArcGIS/QGIS.
  Tiles need internet — offline deployments get the table below.
</p>
<div class="card" style="padding:0;overflow:hidden">
  <div id="sc-map" style="height:560px"></div>
</div>
<div class="card" id="map-fallback" style="display:none;margin-top:12px">
  <h2 style="font-size:14px;margin:0 0 6px">Assets with coordinates</h2>
  <table><thead><tr><th>Host</th><th>Category</th><th>Site</th>
    <th>Risk</th><th>Lat</th><th>Lon</th></tr></thead>
    <tbody id="map-tbody"></tbody></table>
</div>
"""

_MAP_SCRIPT = r"""
const MAP_BAND = {critical:"#ef4444", high:"#f59e0b", medium:"#f59e0b",
                    low:"#10b981", safe:"#10b981"};
let scMap = null, scLayer = null;
async function mapLoad() {
  const band = document.getElementById("map-band").value;
  const r = await fetch("/api/v1/desat/geo" + (band ? "?risk_band="+band : ""));
  if (!r.ok) { mapFallback([]); return; }
  const gj = await r.json();
  const stats = document.getElementById("map-stats");
  stats.textContent = gj.features.length + " on map · " +
    (gj.properties && gj.properties.assets_without_geo || 0) + " without coordinates";
  if (typeof L === "undefined") { mapLeafletLoad(gj); return; }
  mapDraw(gj);
}
function mapLeafletLoad(gj) {
  const css = document.createElement("link");
  css.rel = "stylesheet";
  css.href = "https://unpkg.com/leaflet@1.9.4/dist/leaflet.css";
  document.head.appendChild(css);
  const s = document.createElement("script");
  s.src = "https://unpkg.com/leaflet@1.9.4/dist/leaflet.js";
  s.onload = () => mapDraw(gj);
  s.onerror = () => mapFallback(gj.features || []);
  document.head.appendChild(s);
}
function mapDraw(gj) {
  const feats = gj.features || [];
  if (!feats.length) { mapFallback(feats); return; }
  if (!scMap) {
    scMap = L.map("sc-map");
    L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png",
      {maxZoom: 19, attribution: "&copy; OpenStreetMap"}).addTo(scMap);
  }
  if (scLayer) scLayer.remove();
  scLayer = L.layerGroup().addTo(scMap);
  const pts = [];
  for (const f of feats) {
    const [lon, lat] = f.geometry.coordinates, p = f.properties;
    pts.push([lat, lon]);
    L.circleMarker([lat, lon], {radius: 8,
        color: MAP_BAND[p.risk_band] || "#8b95b1", fillOpacity: .75})
      .addTo(scLayer)
      .bindPopup(`<b>${p.hostname || p.asset_id}</b><br>` +
        `${p.ps_category || p.asset_type} · ${p.site || "?"}<br>` +
        `risk: ${p.risk_band} · score ${p.overall_score}/100<br>` +
        `<a href="/asset/${encodeURIComponent(p.asset_id)}">open asset →</a>`);
  }
  scMap.fitBounds(pts, {padding: [30, 30]});
}
function mapFallback(feats) {
  document.getElementById("sc-map").style.display = "none";
  const fb = document.getElementById("map-fallback");
  fb.style.display = "block";
  const tb = document.getElementById("map-tbody");
  tb.innerHTML = "";
  for (const f of feats) {
    const p = f.properties, [lon, lat] = f.geometry.coordinates;
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${p.hostname || p.asset_id}</td>` +
      `<td>${p.ps_category || p.asset_type}</td><td>${p.site || ""}</td>` +
      `<td>${p.risk_band}</td><td>${lat.toFixed(5)}</td><td>${lon.toFixed(5)}</td>`;
    tb.appendChild(tr);
  }
}
mapLoad();
"""


# ============================================================ /evidence-infrastructure

_EIH_BODY = """
<div style="display:flex;align-items:center;gap:12px;margin-bottom:8px">
  <h1 style="margin:0">🎥 Evidence infrastructure</h1>
  <span class="muted" id="eih-stats" style="font-size:12px"></span>
  <span style="flex:1"></span>
  <button class="alt" style="width:auto;padding:6px 10px;font-size:12px"
          onclick="eihLoad()">⟳ Reload</button>
</div>
<p class="muted" style="margin-top:0;font-size:12px">
  Is the infrastructure needed to <b>capture → transfer → store → access
  → preserve</b> digital evidence operational, secure, and healthy?
  Assembled from asset health, storage capacity + replication, backup
  RPO + immutability, and CVE/KEV exposure. Infrastructure only — this
  page never touches evidentiary content.
</p>
<div class="card" id="eih-headline"><div class="muted">Loading…</div></div>
<div id="eih-stages"
     style="display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));
            margin-top:12px"></div>
"""

_EIH_SCRIPT = r"""
const EIH_COLOR = {healthy:"var(--ok)", warning:"var(--warn)",
                     critical:"var(--bad)", unknown:"var(--muted)"};
async function eihLoad() {
  const r = await fetch("/api/v1/desat/evidence-health");
  if (!r.ok) return;
  const s = await r.json();
  document.getElementById("eih-stats").textContent =
    s.stages_covered + "/" + s.stages_total + " chain stages monitored";
  const head = document.getElementById("eih-headline");
  head.innerHTML =
    `<div style="font-size:16px;font-weight:700;color:${EIH_COLOR[s.overall_status]}">` +
    `${s.headline}</div>` +
    (s.guidance ? `<div class="muted" style="margin-top:6px;font-size:12px">${s.guidance}</div>` : "") +
    `<div class="muted" style="margin-top:8px;font-size:11px">${s.disclaimer}</div>`;
  const host = document.getElementById("eih-stages");
  host.innerHTML = "";
  for (const stage of ["capture","transfer","store","access","preserve"]) {
    const st = s.stages[stage];
    const card = document.createElement("div");
    card.className = "card";
    let issues = "";
    for (const i of st.issues.slice(0, 5)) {
      issues += `<div style="font-size:12px;margin-top:4px;color:` +
        `${i.severity === "critical" ? "var(--bad)" : "var(--warn)"}">` +
        `${i.severity === "critical" ? "❗" : "⚠️"} ${i.message}</div>`;
    }
    card.innerHTML =
      `<div style="display:flex;align-items:center;gap:8px">` +
      `<span style="text-transform:capitalize;font-weight:700">${stage}</span>` +
      `<span style="flex:1"></span>` +
      `<span style="color:${EIH_COLOR[st.status]};font-weight:700;font-size:12px;` +
      `text-transform:uppercase">${st.status}</span></div>` +
      `<div class="muted" style="font-size:12px;margin-top:4px">` +
      `${st.asset_count} asset${st.asset_count === 1 ? "" : "s"}` +
      (st.assets.length ? " — " + st.assets.slice(0, 4).join(", ") +
        (st.assets.length > 4 ? "…" : "") : "") + `</div>` +
      (issues || `<div class="muted" style="font-size:12px;margin-top:4px">` +
        (st.asset_count ? "No open issues." :
          "No assets tagged for this stage.") + `</div>`);
    host.appendChild(card);
  }
}
eihLoad();
"""


# ============================================================ /incidents

_INC_BODY = """
<div style="display:flex;align-items:center;gap:12px;margin-bottom:8px">
  <h1 style="margin:0">🚨 Incidents</h1>
  <span class="muted" id="inc-stats" style="font-size:12px"></span>
  <span style="flex:1"></span>
  <select id="inc-status" onchange="incLoad()" style="width:auto;padding:6px 10px;font-size:12px">
    <option value="">All statuses</option>
    <option value="open">Open</option>
    <option value="acknowledged">Acknowledged</option>
    <option value="investigating">Investigating</option>
    <option value="resolved">Resolved</option>
    <option value="closed">Closed</option>
  </select>
  <button class="alt" style="width:auto;padding:6px 10px;font-size:12px"
          onclick="incLoad()">⟳ Reload</button>
</div>
<p class="muted" style="margin-top:0;font-size:12px">
  Native incidents: event → correlate → incident → impact → investigate
  → resolve. Critical/high events on known assets open incidents
  automatically when <code>SC_EVENTS_AUTO_INCIDENT=1</code>.
</p>
<div class="card" style="padding:0">
  <table><thead><tr><th>Severity</th><th>Title</th><th>Status</th>
    <th>Site</th><th>Assets</th><th>Opened</th></tr></thead>
    <tbody id="inc-tbody"><tr><td colspan="6" class="muted"
      style="padding:14px">Loading…</td></tr></tbody></table>
</div>
<div class="card" id="inc-detail" style="display:none;margin-top:12px"></div>
"""

_INC_SCRIPT = r"""
const INC_SEV = {critical:"var(--bad)", high:"var(--warn)",
                   medium:"var(--med)", low:"var(--ok)", info:"var(--muted)"};
async function incLoad() {
  const st = document.getElementById("inc-status").value;
  const r = await fetch("/api/v1/desat/incidents" + (st ? "?status="+st : ""));
  if (!r.ok) return;
  const d = await r.json();
  const rows = d.incidents || [];
  const openish = rows.filter(x =>
    !["resolved","closed"].includes(x.status)).length;
  document.getElementById("inc-stats").textContent =
    rows.length + " shown · " + openish + " active";
  const tb = document.getElementById("inc-tbody");
  tb.innerHTML = rows.length ? "" :
    `<tr><td colspan="6" class="muted" style="padding:14px">No incidents` +
    ` — events with SC_EVENTS_AUTO_INCIDENT=1 open them automatically,` +
    ` or seed the sheriff demo: <code>safecadence demo --sheriff</code></td></tr>`;
  for (const i of rows) {
    const tr = document.createElement("tr");
    tr.style.cursor = "pointer";
    tr.onclick = () => incDetail(i.incident_id);
    tr.innerHTML =
      `<td><span style="color:${INC_SEV[i.severity] || "var(--muted)"};` +
      `font-weight:700;text-transform:uppercase;font-size:11px">${i.severity}</span></td>` +
      `<td>${i.title}</td>` +
      `<td><span style="font-size:12px;text-transform:capitalize">${i.status}</span></td>` +
      `<td>${i.site || ""}</td>` +
      `<td class="muted" style="font-size:12px">${(i.affected_assets || []).join(", ")}</td>` +
      `<td class="muted" style="font-size:12px">${(i.opened_at || "").slice(0, 16).replace("T", " ")}</td>`;
    tb.appendChild(tr);
  }
}
async function incDetail(id) {
  const r = await fetch("/api/v1/desat/incidents?id=" + encodeURIComponent(id));
  if (!r.ok) return;
  const i = await r.json();
  const el = document.getElementById("inc-detail");
  el.style.display = "block";
  let tl = "";
  for (const t of (i.timeline || [])) {
    tl += `<tr><td class="muted" style="white-space:nowrap;font-size:12px">` +
      `${(t.at || "").slice(0, 16).replace("T", " ")}</td>` +
      `<td style="font-size:12px">${t.kind}</td>` +
      `<td style="font-size:12px">${t.detail}` +
      (t.actor ? ` <span class="muted">— ${t.actor}</span>` : "") + `</td></tr>`;
  }
  el.innerHTML =
    `<div style="display:flex;gap:10px;align-items:center">` +
    `<h2 style="font-size:15px;margin:0">${i.title}</h2><span style="flex:1"></span>` +
    `<span class="muted" style="font-size:12px">${i.incident_id}</span></div>` +
    (i.mission_impact ? `<p style="margin:8px 0 0;font-size:13px">` +
      `<b>Mission impact:</b> ${i.mission_impact}</p>` : "") +
    (i.resolution ? `<p style="margin:6px 0 0;font-size:13px;color:var(--ok)">` +
      `<b>Resolution:</b> ${i.resolution}</p>` : "") +
    `<h2 style="font-size:13px;margin:12px 0 4px">Timeline</h2>` +
    `<table><tbody>${tl}</tbody></table>`;
  el.scrollIntoView({behavior: "smooth"});
}
incLoad();
"""


# ============================================================ register

def register(app) -> None:                              # pragma: no cover
    if not _FASTAPI_OK:
        return

    # ---- page-local JSON (namespaced; no collision with the headless
    # server's /api/v1/events|incidents|geo routers) ------------------
    @app.get("/api/v1/desat/geo")
    def desat_geo(risk_band: str = "", site: str = "", ps_category: str = ""):
        from safecadence.platform.geo_api import assets_geojson
        from safecadence.server.platform_api import list_assets
        return assets_geojson(list_assets(), site=site,
                                ps_category=ps_category, risk_band=risk_band)

    @app.get("/api/v1/desat/evidence-health")
    def desat_evidence_health():
        from safecadence.platform.evidence_health import (
            evidence_infrastructure_summary,
        )
        from safecadence.server.platform_api import list_assets
        return evidence_infrastructure_summary(list_assets())

    @app.get("/api/v1/desat/incidents")
    def desat_incidents(status: str = "", id: str = ""):
        from safecadence.incidents.store import get_incident, list_incidents
        if id:
            inc = get_incident(id)
            return inc.to_dict() if inc else {"error": "not found"}
        return {"incidents": list_incidents(status=status)}

    # ---- pages -------------------------------------------------------
    @app.get("/map", response_class=HTMLResponse)
    def map_page():
        return HTMLResponse(wrap("Asset map", _MAP_BODY, _MAP_SCRIPT))

    @app.get("/evidence-infrastructure", response_class=HTMLResponse)
    def evidence_infrastructure_page():
        return HTMLResponse(wrap("Evidence infrastructure",
                                    _EIH_BODY, _EIH_SCRIPT))

    @app.get("/incidents", response_class=HTMLResponse)
    def incidents_page():
        return HTMLResponse(wrap("Incidents", _INC_BODY, _INC_SCRIPT))
