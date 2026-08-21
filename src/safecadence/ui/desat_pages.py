"""
DESAT (public-safety) UI pages — wrapped in the v9 chrome like every
other page:

* ``GET /map``                       — GIS asset map (Leaflet, offline fallback)
* ``GET /evidence-infrastructure``   — evidence-chain health dashboard
* ``GET /incidents``                 — incident queue + timelines + ACTIONS
                                        (ack / investigate / resolve / close /
                                        reopen, with notes)
* ``GET /events``                    — live inbound-event stream (syslog /
                                        traps / webhooks) with filters

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
function esc(s){return String(s==null?"":s).replace(/[&<>"']/g,function(c){
  return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c];});}
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
      .bindPopup(`<b>${esc(p.hostname || p.asset_id)}</b><br>` +
        `${esc(p.ps_category || p.asset_type)} · ${esc(p.site || "?")}<br>` +
        `risk: ${esc(p.risk_band)} · score ${p.overall_score}/100<br>` +
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
    tr.innerHTML = `<td>${esc(p.hostname || p.asset_id)}</td>` +
      `<td>${esc(p.ps_category || p.asset_type)}</td><td>${esc(p.site || "")}</td>` +
      `<td>${esc(p.risk_band)}</td><td>${lat.toFixed(5)}</td><td>${lon.toFixed(5)}</td>`;
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
// Issue messages + asset names embed hostnames sourced from device
// telemetry — escape everything server-derived.
function esc(s){return String(s==null?"":s).replace(/[&<>"']/g,function(c){
  return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c];});}
async function eihLoad() {
  const r = await fetch("/api/v1/desat/evidence-health");
  if (!r.ok) return;
  const s = await r.json();
  document.getElementById("eih-stats").textContent =
    s.stages_covered + "/" + s.stages_total + " chain stages monitored";
  const head = document.getElementById("eih-headline");
  head.innerHTML =
    `<div style="font-size:16px;font-weight:700;color:${EIH_COLOR[s.overall_status]}">` +
    `${esc(s.headline)}</div>` +
    (s.guidance ? `<div class="muted" style="margin-top:6px;font-size:12px">${esc(s.guidance)}</div>` : "") +
    `<div class="muted" style="margin-top:8px;font-size:11px">${esc(s.disclaimer)}</div>`;
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
        `${i.severity === "critical" ? "❗" : "⚠️"} ${esc(i.message)}</div>`;
    }
    card.innerHTML =
      `<div style="display:flex;align-items:center;gap:8px">` +
      `<span style="text-transform:capitalize;font-weight:700">${esc(stage)}</span>` +
      `<span style="flex:1"></span>` +
      `<span style="color:${EIH_COLOR[st.status]};font-weight:700;font-size:12px;` +
      `text-transform:uppercase">${esc(st.status)}</span></div>` +
      `<div class="muted" style="font-size:12px;margin-top:4px">` +
      `${st.asset_count} asset${st.asset_count === 1 ? "" : "s"}` +
      (st.assets.length ? " — " + esc(st.assets.slice(0, 4).join(", ")) +
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
// XSS defense: incident/event data originates from unauthenticated syslog
// and SNMP-trap datagrams, so EVERY server-derived value interpolated into
// innerHTML must be escaped (covers ' for single-quoted onclick attrs too).
function esc(s){return String(s==null?"":s).replace(/[&<>"']/g,function(c){
  return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c];});}
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
      `font-weight:700;text-transform:uppercase;font-size:11px">${esc(i.severity)}</span></td>` +
      `<td>${esc(i.title)}</td>` +
      `<td><span style="font-size:12px;text-transform:capitalize">${esc(i.status)}</span></td>` +
      `<td>${esc(i.site || "")}</td>` +
      `<td class="muted" style="font-size:12px">${esc((i.affected_assets || []).join(", "))}</td>` +
      `<td class="muted" style="font-size:12px">${esc((i.opened_at || "").slice(0, 16).replace("T", " "))}</td>`;
    tb.appendChild(tr);
  }
}
// Legal next steps per status — mirrors incidents/store.py _TRANSITIONS.
const INC_NEXT = {
  open:            [["acknowledged","Acknowledge"],["investigating","Start investigating"],
                     ["resolved","Resolve"],["closed","Close"]],
  acknowledged:    [["investigating","Start investigating"],["resolved","Resolve"],
                     ["closed","Close"]],
  investigating:   [["resolved","Resolve"],["closed","Close"]],
  resolved:        [["closed","Close"],["investigating","Reopen investigation"]],
  closed:          [["open","Reopen"]],
};
async function incDetail(id) {
  const r = await fetch("/api/v1/desat/incidents?id=" + encodeURIComponent(id));
  if (!r.ok) return;
  const i = await r.json();
  const el = document.getElementById("inc-detail");
  el.style.display = "block";
  let tl = "";
  for (const t of (i.timeline || [])) {
    tl += `<tr><td class="muted" style="white-space:nowrap;font-size:12px">` +
      `${esc((t.at || "").slice(0, 16).replace("T", " "))}</td>` +
      `<td style="font-size:12px">${esc(t.kind)}</td>` +
      `<td style="font-size:12px">${esc(t.detail)}` +
      (t.actor ? ` <span class="muted">— ${esc(t.actor)}</span>` : "") + `</td></tr>`;
  }
  let actions = "";
  const iid = esc(i.incident_id);
  for (const [to, label] of (INC_NEXT[i.status] || [])) {
    actions += `<button class="alt" style="width:auto;padding:6px 12px;` +
      `font-size:12px" onclick="incAct('${iid}','${esc(to)}')">${esc(label)}</button>`;
  }
  el.innerHTML =
    `<div style="display:flex;gap:10px;align-items:center">` +
    `<h2 style="font-size:15px;margin:0">${esc(i.title)}</h2><span style="flex:1"></span>` +
    `<span class="muted" style="font-size:12px">${iid} · ` +
    `<span style="text-transform:capitalize">${esc(i.status)}</span></span></div>` +
    (i.mission_impact ? `<p style="margin:8px 0 0;font-size:13px">` +
      `<b>Mission impact:</b> ${esc(i.mission_impact)}</p>` : "") +
    (i.resolution ? `<p style="margin:6px 0 0;font-size:13px;color:var(--ok)">` +
      `<b>Resolution:</b> ${esc(i.resolution)}</p>` : "") +
    `<div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:12px">` +
    actions +
    `<input id="inc-note" placeholder="Add a note (optional — required to resolve)"` +
    ` style="flex:1;min-width:220px;padding:6px 10px;font-size:12px">` +
    `<button class="alt" style="width:auto;padding:6px 12px;font-size:12px"` +
    ` onclick="incNote('${iid}')">＋ Note</button></div>` +
    `<div class="muted" id="inc-msg" style="font-size:12px;margin-top:6px"></div>` +
    `<h2 style="font-size:13px;margin:12px 0 4px">Timeline</h2>` +
    `<table><tbody>${tl}</tbody></table>`;
  el.scrollIntoView({behavior: "smooth"});
}
async function incAct(id, to) {
  const note = (document.getElementById("inc-note") || {}).value || "";
  const body = {incident_id: id, status: to, note: note, actor: "operator"};
  if (to === "resolved") body.resolution = note || "Resolved via UI";
  const r = await fetch("/api/v1/desat/incidents/transition", {
    method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify(body)});
  const d = await r.json().catch(() => ({}));
  const msg = document.getElementById("inc-msg");
  if (!r.ok) { if (msg) msg.textContent = d.detail || d.error || "transition failed"; return; }
  await incLoad();
  await incDetail(id);
}
async function incNote(id) {
  const note = (document.getElementById("inc-note") || {}).value || "";
  if (!note.trim()) return;
  const r = await fetch("/api/v1/desat/incidents/note", {
    method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({incident_id: id, note: note, actor: "operator"})});
  if (r.ok) await incDetail(id);
}
incLoad();
"""


# ============================================================ /events

_EVT_BODY = """
<div style="display:flex;align-items:center;gap:12px;margin-bottom:8px">
  <h1 style="margin:0">📡 Events</h1>
  <span class="muted" id="evt-stats" style="font-size:12px"></span>
  <span style="flex:1"></span>
  <select id="evt-sev" onchange="evtLoad()" style="width:auto;padding:6px 10px;font-size:12px">
    <option value="">All severities</option>
    <option value="critical">Critical</option>
    <option value="high">High</option>
    <option value="medium">Medium</option>
    <option value="low">Low</option>
    <option value="info">Info</option>
  </select>
  <select id="evt-src" onchange="evtLoad()" style="width:auto;padding:6px 10px;font-size:12px">
    <option value="">All sources</option>
    <option value="syslog">Syslog</option>
    <option value="snmp_trap">SNMP trap</option>
    <option value="webhook">Webhook</option>
  </select>
  <button class="alt" style="width:auto;padding:6px 10px;font-size:12px"
          onclick="evtLoad()">⟳ Reload</button>
</div>
<p class="muted" style="margin-top:0;font-size:12px">
  Inbound telemetry: syslog, SNMP traps, and webhooks — deduplicated,
  linked to assets by sender IP. Enable listeners with
  <code>SC_EVENTS_LISTENERS=1</code> (syslog :5514, traps :5162 by
  default, loopback-bound). Critical/high events on known assets can
  auto-open incidents (<code>SC_EVENTS_AUTO_INCIDENT=1</code>).
</p>
<div class="card" style="padding:0">
  <table><thead><tr><th>Received</th><th>Severity</th><th>Source</th>
    <th>Type</th><th>Asset</th><th>Description</th></tr></thead>
    <tbody id="evt-tbody"><tr><td colspan="6" class="muted"
      style="padding:14px">Loading…</td></tr></tbody></table>
</div>
"""

_EVT_SCRIPT = r"""
const EVT_SEV = {critical:"var(--bad)", high:"var(--warn)",
                   medium:"var(--med)", low:"var(--ok)", info:"var(--muted)"};
// Events carry raw syslog/trap text from unauthenticated senders — escape all.
function esc(s){return String(s==null?"":s).replace(/[&<>"']/g,function(c){
  return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c];});}
async function evtLoad() {
  const sev = document.getElementById("evt-sev").value;
  const src = document.getElementById("evt-src").value;
  const qs = new URLSearchParams();
  if (sev) qs.set("severity", sev);
  if (src) qs.set("source", src);
  const r = await fetch("/api/v1/desat/events?" + qs.toString());
  if (!r.ok) return;
  const d = await r.json();
  const rows = d.events || [];
  document.getElementById("evt-stats").textContent =
    rows.length + " event" + (rows.length === 1 ? "" : "s") + " (last " +
    (d.days || 7) + " days)";
  const tb = document.getElementById("evt-tbody");
  tb.innerHTML = rows.length ? "" :
    `<tr><td colspan="6" class="muted" style="padding:14px">No events yet.` +
    ` Point device syslog/traps at the listeners, POST to the webhook, or` +
    ` seed the demo: <code>safecadence demo --sheriff</code></td></tr>`;
  for (const e of rows) {
    const tr = document.createElement("tr");
    tr.innerHTML =
      `<td class="muted" style="white-space:nowrap;font-size:12px">` +
      `${esc((e.received_at || "").slice(0, 16).replace("T", " "))}</td>` +
      `<td><span style="color:${EVT_SEV[e.severity] || "var(--muted)"};` +
      `font-weight:700;font-size:11px;text-transform:uppercase">${esc(e.severity)}</span></td>` +
      `<td style="font-size:12px">${esc(e.source)}</td>` +
      `<td style="font-size:12px">${esc(e.event_type)}</td>` +
      `<td style="font-size:12px">` +
      (e.asset_id ? `<a href="/asset/${encodeURIComponent(e.asset_id)}">` +
        `${esc(e.hostname || e.asset_id)}</a>` : esc(e.source_ip || "—")) + `</td>` +
      `<td style="font-size:12px">${esc(e.description)}</td>`;
    tb.appendChild(tr);
  }
}
evtLoad();
"""


# ============================================================ licensing gate

_UPSELL_BODY = """
<div class="card" style="max-width:640px;margin:40px auto;text-align:center;padding:34px">
  <div style="font-size:38px">🛡️</div>
  <h1 style="margin:8px 0 4px">SafeCadence Public Safety</h1>
  <p class="muted" style="font-size:13px;margin:0 0 14px">
    The evidence-infrastructure assurance layer for law-enforcement
    agencies: asset map, evidence-chain health, incidents, event
    ingestion, CJIS control mapping.
  </p>
  <p style="font-size:13px;margin:0 0 6px">
    This capability requires a <b>Public Safety license</b> — priced per
    agency by monitored assets, with deployment support and an SLA.
  </p>
  <p style="font-size:13px;margin:0 0 18px">
    Evaluate it right now, free, with the built-in synthetic agency:<br>
    <code style="font-size:12px">safecadence demo --sheriff</code>
  </p>
  <a href="mailto:hello@safecadence.com?subject=Public%20Safety%20license"
     style="display:inline-block;background:var(--accent);color:#fff;border-radius:8px;
            padding:10px 18px;font-weight:700;text-decoration:none">
    Talk to us about licensing</a>
  <p class="muted" style="font-size:11px;margin-top:14px">
    A real person replies within 24h — no automated sales sequence.
  </p>
</div>
"""

_EVAL_BANNER = (
    '<div style="background:rgba(245,158,11,.12);border:1px solid var(--warn);'
    'border-radius:8px;padding:8px 14px;margin-bottom:12px;font-size:12.5px">'
    '⚠️ <b>Evaluation mode</b> — synthetic demo data, not licensed for '
    'production use. <a href="mailto:hello@safecadence.com?subject='
    'Public%20Safety%20license">Get a Public Safety license</a> for live '
    'agency deployment.</div>')


def _ps_access() -> str:
    """'licensed' | 'evaluation' | 'locked'.

    Licensed: the signed license file carries the ``public_safety``
    feature. Evaluation: sheriff demo data is loaded (free, synthetic,
    banner-marked). Locked: neither — pages show the upsell, APIs 402.
    """
    try:
        from safecadence.license import feature_enabled
        if feature_enabled("public_safety"):
            return "licensed"
    except Exception:
        pass
    try:
        from safecadence.server.platform_api import list_assets
        for a in list_assets():
            if "demo:sheriff" in ((a.get("identity") or {}).get("tags") or []):
                return "evaluation"
    except Exception:
        pass
    return "locked"


# ============================================================ register

def register(app) -> None:                              # pragma: no cover
    if not _FASTAPI_OK:
        return
    from fastapi import Body, HTTPException

    def _api_gate() -> None:
        if _ps_access() == "locked":
            raise HTTPException(
                402, "Public Safety license required (or load the "
                       "evaluation tenant: safecadence demo --sheriff)")

    def _page(title: str, body: str, script: str) -> "HTMLResponse":
        access = _ps_access()
        if access == "locked":
            return HTMLResponse(wrap(title, _UPSELL_BODY, ""))
        if access == "evaluation":
            body = _EVAL_BANNER + body
        return HTMLResponse(wrap(title, body, script))

    # ---- page-local JSON (namespaced; no collision with the headless
    # server's /api/v1/events|incidents|geo routers) ------------------
    @app.get("/api/v1/desat/geo")
    def desat_geo(risk_band: str = "", site: str = "", ps_category: str = ""):
        _api_gate()
        from safecadence.platform.geo_api import assets_geojson
        from safecadence.server.platform_api import list_assets
        return assets_geojson(list_assets(), site=site,
                                ps_category=ps_category, risk_band=risk_band)

    @app.get("/api/v1/desat/evidence-health")
    def desat_evidence_health():
        _api_gate()
        from safecadence.platform.evidence_health import (
            evidence_infrastructure_summary,
        )
        from safecadence.server.platform_api import list_assets
        return evidence_infrastructure_summary(list_assets())

    @app.get("/api/v1/desat/incidents")
    def desat_incidents(status: str = "", id: str = ""):
        _api_gate()
        from safecadence.incidents.store import get_incident, list_incidents
        if id:
            inc = get_incident(id)
            return inc.to_dict() if inc else {"error": "not found"}
        return {"incidents": list_incidents(status=status)}

    @app.post("/api/v1/desat/incidents/transition")
    def desat_incident_transition(payload: dict = Body(...)):
        _api_gate()
        from safecadence.incidents.store import transition_incident
        try:
            inc = transition_incident(
                str(payload.get("incident_id", "")),
                str(payload.get("status", "")),
                actor=str(payload.get("actor", "ui")),
                note=str(payload.get("note", "")),
                resolution=str(payload.get("resolution", "")))
        except KeyError as exc:
            raise HTTPException(404, "incident not found") from exc
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        return inc.to_dict()

    @app.post("/api/v1/desat/incidents/note")
    def desat_incident_note(payload: dict = Body(...)):
        _api_gate()
        from safecadence.incidents.store import add_note
        try:
            inc = add_note(str(payload.get("incident_id", "")),
                            str(payload.get("note", "")),
                            actor=str(payload.get("actor", "ui")))
        except KeyError as exc:
            raise HTTPException(404, "incident not found") from exc
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        return inc.to_dict()

    @app.get("/api/v1/desat/events")
    def desat_events(severity: str = "", source: str = "",
                      asset_id: str = "", days: int = 7, limit: int = 300):
        _api_gate()
        from safecadence.events.store import query_events
        days = max(1, min(int(days), 30))
        return {"days": days,
                 "events": query_events(limit=max(1, min(int(limit), 1000)),
                                          severity=severity, source=source,
                                          asset_id=asset_id, days=days)}

    # ---- pages -------------------------------------------------------
    @app.get("/map", response_class=HTMLResponse)
    def map_page():
        return _page("Asset map", _MAP_BODY, _MAP_SCRIPT)

    @app.get("/evidence-infrastructure", response_class=HTMLResponse)
    def evidence_infrastructure_page():
        return _page("Evidence infrastructure", _EIH_BODY, _EIH_SCRIPT)

    @app.get("/incidents", response_class=HTMLResponse)
    def incidents_page():
        return _page("Incidents", _INC_BODY, _INC_SCRIPT)

    @app.get("/events", response_class=HTMLResponse)
    def events_page():
        return _page("Events", _EVT_BODY, _EVT_SCRIPT)
