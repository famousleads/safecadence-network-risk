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
<style>
#sc-tac{position:relative;height:560px;background:#0e1a15;overflow:hidden}
#sc-tac svg.base{position:absolute;inset:0;width:100%;height:100%}
.sc-pin{position:absolute;transform:translate(-50%,-50%);z-index:3;cursor:pointer;
  display:flex;align-items:center;gap:5px;background:rgba(10,25,20,.88);
  border:1px solid rgba(127,174,154,.45);border-radius:999px;padding:3px 9px 3px 5px;
  font-size:11px;color:#d7ece3;text-decoration:none;white-space:nowrap}
.sc-pin i{width:9px;height:9px;border-radius:50%;display:inline-block}
.sc-pin:hover{border-color:#5fd3b8;z-index:5}
.sc-unit{position:absolute;transform:translate(-50%,-50%);z-index:4;
  transition:left 1.9s linear,top 1.9s linear;display:flex;align-items:center;gap:5px;
  background:rgba(14,40,44,.92);border:1px solid rgba(45,212,191,.55);
  border-left:4px solid #2dd4bf;border-radius:999px;padding:3px 9px;
  font-size:11px;font-weight:700;color:#bff2e7;cursor:default}
.sc-unit small{font-weight:600;color:#7fae9a;text-transform:uppercase;font-size:8.5px;letter-spacing:.05em}
.sc-com{position:absolute;transform:translate(-50%,-50%);z-index:2;font-size:11px;
  opacity:.85;cursor:default;filter:drop-shadow(0 0 3px rgba(0,0,0,.7))}
.sc-chip{position:absolute;left:10px;top:10px;z-index:6;font-size:9.5px;font-weight:800;
  letter-spacing:.07em;color:#9fe8dc;background:rgba(10,25,28,.85);
  border:1px solid rgba(45,212,191,.35);border-radius:20px;padding:3px 9px}
#sc-posture{position:absolute;top:10px;right:10px;z-index:6;width:212px;
  background:rgba(10,22,18,.93);border:1px solid rgba(127,174,154,.4);border-radius:10px;
  padding:12px;color:#d7ece3;font-size:12px;display:grid;gap:7px}
#sc-posture .t{font-size:10px;font-weight:800;letter-spacing:.08em;text-transform:uppercase;color:#7fae9a}
#sc-posture .n{font-size:26px;font-weight:800;line-height:1;color:#fff}
#sc-posture .row{display:flex;justify-content:space-between;gap:8px}
#sc-posture .row b{color:#fff}
.sc-strip{margin-top:12px}
.sc-strip .hd{display:flex;justify-content:space-between;align-items:center;margin:0 0 6px}
.sc-strip .hd h2{font-size:14px;margin:0}
.sc-strip .hd span{font-size:10.5px;color:var(--muted,#8b95b1);font-weight:700;
  text-transform:uppercase;letter-spacing:.06em}
.sc-row{display:grid;grid-template-columns:86px minmax(0,1fr) auto auto;gap:10px;
  align-items:center;padding:8px 12px;border:1px solid var(--line,rgba(255,255,255,.08));
  border-radius:8px;margin-bottom:6px;text-decoration:none;color:inherit;
  border-left-width:4px}
.sc-row:hover{background:rgba(255,255,255,.03)}
.sc-row.critical,.sc-row.high{border-left-color:#ef4444}
.sc-row.medium,.sc-row.warning{border-left-color:#f59e0b}
.sc-row.watch,.sc-row.low,.sc-row.info{border-left-color:#334155}
.sc-sev{font-size:10px;font-weight:800;text-transform:uppercase;letter-spacing:.05em}
.sc-sev.critical,.sc-sev.high{color:#ef4444}.sc-sev.medium,.sc-sev.warning{color:#f59e0b}
.sc-sev.watch,.sc-sev.low,.sc-sev.info{color:#8b95b1}
.sc-row .ti{font-size:12.5px;font-weight:650;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.sc-row .me,.sc-row .st{font-size:11px;color:var(--muted,#8b95b1);white-space:nowrap}
</style>
<div style="display:flex;align-items:center;gap:12px;margin-bottom:8px">
  <h1 style="margin:0">🗺️ Command overview</h1>
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
  Your county on one screen: facilities and assets by risk, patrol units in
  motion, posture at a glance — and everything that's burning, ranked, below.
  The basemap renders on-device (no external tiles). The GeoJSON behind it
  (<code>/api/v1/desat/geo</code>) imports straight into ArcGIS/QGIS.
</p>
<div class="card" style="padding:0;overflow:hidden">
  <div id="sc-tac">
    <span class="sc-chip">● SIMULATED AVL — connect CAD/AVL for live tracking</span>
    <div id="sc-posture"><span class="t">Command posture</span>
      <span class="n" id="scp-n">—</span><span id="scp-s" class="muted" style="font-size:11px">loading…</span>
      <div class="row"><span>Critical / high</span><b id="scp-c">—</b></div>
      <div class="row"><span>Evidence chain</span><b id="scp-e">—</b></div>
    </div>
  </div>
</div>
<p class="muted" style="margin:6px 2px 0;font-size:11.5px">
  🤝 Community layer: <span id="sc-com-line">—</span> ·
  <a href="/community" style="color:inherit">manage</a></p>
<div class="sc-strip">
  <div class="hd"><h2>Open incidents &amp; alerts</h2><span>highest severity first</span></div>
  <div id="sc-strip-rows"><span class="muted" style="font-size:12px">loading…</span></div>
</div>
<details class="card" style="margin-top:12px">
  <summary style="cursor:pointer;font-size:13px">Assets with coordinates (table)</summary>
  <table style="margin-top:8px"><thead><tr><th>Host</th><th>Category</th><th>Site</th>
    <th>Risk</th><th>Lat</th><th>Lon</th></tr></thead>
    <tbody id="map-tbody"></tbody></table>
</details>
"""

_MAP_SCRIPT = r"""
/* Command overview: on-device tactical basemap (zero external tiles),
   real assets projected by lat/lon, simulated patrol units (honest
   chip; real CAD/AVL replaces them when connected), posture overlay,
   and incidents+alerts ranked hot-to-cold below. */
const MAP_BAND = {critical:"#ef4444", high:"#f59e0b", medium:"#f59e0b",
                    low:"#10b981", safe:"#10b981"};
function esc(s){return String(s==null?"":s).replace(/[&<>"']/g,function(c){
  return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c];});}
function rng(seed){let h=2166136261>>>0;
  for(let i=0;i<seed.length;i++){h=Math.imul(h^seed.charCodeAt(i),16777619)>>>0;}
  return function(){h=Math.imul(h^(h>>>15),2246822519)>>>0;
    h=Math.imul(h^(h>>>13),3266489917)>>>0;return((h^=h>>>16)>>>0)/4294967296;};}
function baseSVG(seed){
  const r=rng(seed);let s='<rect width="600" height="400" fill="#0e1a15"/>';
  for(let bx=0;bx<10;bx++)for(let by=0;by<7;by++){if(r()<.3)continue;
    s+=`<rect x="${(bx*60+6+r()*6).toFixed(1)}" y="${(by*57+6+r()*6).toFixed(1)}"
        width="${(44+r()*10).toFixed(1)}" height="${(41+r()*10).toFixed(1)}" rx="3"
        fill="${r()<.25?"#12251d":"#101f19"}"/>`;}
  const wy=40+r()*60;
  s+=`<path d="M0 ${wy} C150 ${wy-24},300 ${wy+30},600 ${wy-8} L600 0 L0 0 Z" fill="#0c2027" opacity=".8"/>`;
  const v1=(120+r()*90)|0,v2=(370+r()*120)|0,h1=(110+r()*60)|0,h2=(250+r()*80)|0;
  for(const d of [`M ${v1} 0 V400`,`M ${v2} 0 V400`,`M 0 ${h1} H600`,`M 0 ${h2} H600`])
    s+=`<path d="${d}" stroke="#1c3428" stroke-width="10" fill="none"/><path d="${d}" stroke="#27473a" stroke-width="6" fill="none"/>`;
  for(let g=0;g<=600;g+=60)s+=`<line x1="${g}" y1="0" x2="${g}" y2="400" stroke="#2c5340" stroke-width=".4" opacity=".3"/>`;
  for(let g=0;g<=400;g+=57)s+=`<line x1="0" y1="${g}" x2="600" y2="${g}" stroke="#2c5340" stroke-width=".4" opacity=".3"/>`;
  s+='<g transform="translate(566,372)"><circle r="13" fill="rgba(10,25,20,.9)" stroke="#2c5340"/><path d="M0 -8 L3.5 4 L0 1.5 L-3.5 4 Z" fill="#5fd3b8"/><text y="-17" text-anchor="middle" font-size="9" fill="#7fae9a">N</text></g>';
  return `<svg class="base" viewBox="0 0 600 400" preserveAspectRatio="xMidYMid slice">${s}</svg>`;
}
function project(feats){
  let lats=[],lons=[];
  for(const f of feats){lons.push(f.geometry.coordinates[0]);lats.push(f.geometry.coordinates[1]);}
  const la=Math.min(...lats),lb=Math.max(...lats),oa=Math.min(...lons),ob=Math.max(...lons);
  return function(lon,lat){
    const x=(ob-oa)<1e-9?50:8+84*(lon-oa)/(ob-oa);
    const y=(lb-la)<1e-9?50:12+76*(1-(lat-la)/(lb-la));
    return [x,y];
  };
}
let UNITS=null, unitTimer=null;
function ensureUnits(spots){
  if(UNITS)return;
  const ids=[["U-12","patrol"],["M-07","medical"],["CR-5","patrol"],["E-9","fire"]];
  UNITS=ids.map(function(pair,i){
    const rr=rng(pair[0]);
    const home=spots.length?spots[i%spots.length]:[20+rr()*60,20+rr()*60];
    return {id:pair[0],kind:pair[1],r:rr,x:home[0],y:home[1],
             st:["available","enroute","on_scene"][i%3],t:null,dwell:0,el:null};
  });
  unitTimer=setInterval(tickUnits,2000);
}
function tickUnits(){
  if(document.visibilityState==="hidden"||!UNITS)return;
  const hot=[...document.querySelectorAll(".sc-pin[data-hot]")]
    .map(function(p){return [parseFloat(p.style.left),parseFloat(p.style.top)];});
  for(const u of UNITS){
    if(!u.el||!u.el.isConnected)continue;
    if(u.st==="on_scene"){if(--u.dwell<=0){u.st="available";u.t=null;setUnit(u);}continue;}
    if(!u.t||Math.hypot(u.x-u.t[0],u.y-u.t[1])<1.6){
      if(u.st==="enroute"){u.st="on_scene";u.dwell=5+(u.r()*4|0);setUnit(u);continue;}
      if(hot.length&&u.r()<.15){u.t=hot[(u.r()*hot.length)|0];u.st="enroute";setUnit(u);}
      else{u.t=[10+u.r()*80,14+u.r()*72];}
    }
    const dx=u.t[0]-u.x,dy=u.t[1]-u.y,d=Math.hypot(dx,dy)||1,
          sp=u.st==="enroute"?2.3:1.1,step=Math.min(sp,d);
    u.x=Math.max(3,Math.min(97,u.x+dx/d*step+(u.r()-.5)*.3));
    u.y=Math.max(4,Math.min(94,u.y+dy/d*step+(u.r()-.5)*.3));
    u.el.style.left=u.x.toFixed(2)+"%";u.el.style.top=u.y.toFixed(2)+"%";
  }
}
function setUnit(u){if(u.el)u.el.innerHTML=esc(u.id)+" <small>"+esc(u.st.replace("_"," "))+"</small>";}
async function mapLoad(){
  const band=document.getElementById("map-band").value;
  const r=await fetch("/api/v1/desat/geo"+(band?"?risk_band="+band:""));
  const tac=document.getElementById("sc-tac");
  const keep=[...tac.querySelectorAll(".sc-chip,#sc-posture")];
  if(!r.ok){return;}
  const gj=await r.json(),feats=gj.features||[];
  document.getElementById("map-stats").textContent=feats.length+" on map · "+
    ((gj.properties&&gj.properties.assets_without_geo)||0)+" without coordinates";
  tac.innerHTML=baseSVG("county:"+feats.length);
  keep.forEach(function(k){tac.appendChild(k);});
  const pr=project(feats.length?feats:[{geometry:{coordinates:[0,0]}}]);
  const tb=document.getElementById("map-tbody");tb.innerHTML="";
  const spots=[];
  for(const f of feats){
    const [lon,lat]=f.geometry.coordinates,p=f.properties,[x,y]=pr(lon,lat);
    const hot=(p.risk_band==="critical"||p.risk_band==="high");
    const a=document.createElement("a");
    a.className="sc-pin";a.style.left=x.toFixed(2)+"%";a.style.top=y.toFixed(2)+"%";
    if(hot){a.setAttribute("data-hot","1");}
    a.href="/asset/"+encodeURIComponent(p.asset_id);
    a.title=(p.ps_category||p.asset_type||"")+" · "+(p.site||"")+" · risk "+(p.risk_band||"?");
    a.innerHTML='<i style="background:'+(MAP_BAND[p.risk_band]||"#8b95b1")+'"></i>'+esc(p.hostname||p.asset_id);
    tac.appendChild(a);
    if(spots.length<6){spots.push([x,y]);}
    const tr=document.createElement("tr");
    tr.innerHTML="<td>"+esc(p.hostname||p.asset_id)+"</td><td>"+esc(p.ps_category||p.asset_type)+
      "</td><td>"+esc(p.site||"")+"</td><td>"+esc(p.risk_band)+"</td><td>"+lat.toFixed(5)+
      "</td><td>"+lon.toFixed(5)+"</td>";
    tb.appendChild(tr);
  }
  ensureUnits(spots);
  for(const u of UNITS){
    const el=document.createElement("span");
    el.className="sc-unit";el.style.left=u.x.toFixed(2)+"%";el.style.top=u.y.toFixed(2)+"%";
    u.el=el;setUnit(u);tac.appendChild(el);
  }
  /* community layer: consent-based registry cameras + active watches */
  try{
    const cr=await fetch("/api/v1/desat/community");
    if(cr.ok){
      const com=await cr.json();
      for(const pt of (com.map_points||[]).slice(0,60)){
        let [cx,cy]=pr(pt.lon,pt.lat);
        cx=Math.max(2,Math.min(97,cx));cy=Math.max(3,Math.min(95,cy));
        const el=document.createElement("span");
        el.className="sc-com";el.style.left=cx.toFixed(2)+"%";el.style.top=cy.toFixed(2)+"%";
        el.title=(pt.kind==="watch"?"Watch request: ":"Registered camera: ")+
          (pt.label||"")+" · "+(pt.meta||"");
        el.textContent=pt.kind==="watch"?"🏠":"📷";
        tac.appendChild(el);
      }
      const cs=document.getElementById("sc-com-line");
      if(cs)cs.textContent=(com.registered_cameras||0)+" registered cameras · "+
        (com.active_watches||0)+" active watch requests";
    }
  }catch(e){}
  const crit=feats.filter(function(f){return f.properties.risk_band==="critical"||f.properties.risk_band==="high";}).length;
  document.getElementById("scp-n").textContent=feats.length;
  document.getElementById("scp-s").textContent="assets on the county map";
  document.getElementById("scp-c").textContent=crit;
}
function sevRank(s){s=String(s||"watch").toLowerCase();
  if(s.indexOf("crit")===0)return 0;if(s==="high"||s==="urgent")return 1;
  if(s==="medium"||s==="warning"||s==="elevated")return 2;
  if(s==="watch"||s==="open")return 3;if(s==="low")return 4;return 5;}
async function stripLoad(){
  const rows=[];
  try{const r=await fetch("/api/v1/desat/incidents");
    if(r.ok){for(const i of ((await r.json()).incidents||[]))
      rows.push({sev:i.severity,ti:i.title,me:i.site||i.incident_type||"incident",
                  st:i.status,href:"/incidents"});}}catch(e){}
  try{const r=await fetch("/api/v1/desat/events?days=7&limit=100");
    if(r.ok){for(const ev of ((await r.json()).events||[]))
      rows.push({sev:ev.severity,ti:ev.description||ev.event_type,
                  me:ev.hostname||ev.source||"event",st:ev.event_type||"alert",
                  href:"/events"});}}catch(e){}
  rows.sort(function(a,b){return sevRank(a.sev)-sevRank(b.sev);});
  const box=document.getElementById("sc-strip-rows");
  box.innerHTML=rows.slice(0,10).map(function(q){
    const s=String(q.sev||"watch").toLowerCase().replace(/[^a-z0-9]/g,"");
    return '<a class="sc-row '+esc(s)+'" href="'+esc(q.href)+'">'+
      '<span class="sc-sev '+esc(s)+'">'+esc(q.sev||"watch")+'</span>'+
      '<span class="ti">'+esc(q.ti||"Review item")+'</span>'+
      '<span class="me">'+esc(q.me||"")+'</span>'+
      '<span class="st">'+esc(String(q.st||"open").replace(/[_-]+/g," "))+'</span></a>';
  }).join("")||'<span class="muted" style="font-size:12px">All clear — no open incidents or recent alerts.</span>';
}
async function postureLoad(){
  try{const r=await fetch("/api/v1/desat/evidence-health");
    if(r.ok){const s=await r.json();
      document.getElementById("scp-e").textContent=String(s.overall_status||"unknown").replace(/[_-]+/g," ");}}catch(e){}
}
mapLoad();stripLoad();postureLoad();
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


# ============================================================ community page

_COMMUNITY_BODY = """
<h1 style="margin:0 0 4px">🤝 Community</h1>
<p class="muted" style="margin:0 0 14px;font-size:12.5px">
  Consent-based programs, agency-controlled. The Camera Registry lists
  residents who <b>volunteered</b> to be contacted — no feeds, no access,
  no monitoring. Watch Requests digitize vacation/business checks.
  No social feeds, no public reporting, nothing leaves your network.
</p>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px" class="cm-grid">
 <div class="card">
  <h2 style="font-size:15px;margin:0 0 4px">📷 Camera Registry <span class="muted" id="cm-cam-count" style="font-size:11px"></span></h2>
  <div id="cm-cams" style="font-size:12.5px"></div>
  <details style="margin-top:10px"><summary style="cursor:pointer;font-size:12.5px">Register a camera (staff entry)</summary>
   <div style="display:grid;gap:6px;margin-top:8px;font-size:12px">
    <input id="cm-owner" placeholder="Owner name">
    <input id="cm-contact" placeholder="Contact (phone or email)">
    <input id="cm-address" placeholder="Address">
    <div style="display:flex;gap:6px"><input id="cm-lat" placeholder="Latitude"><input id="cm-lon" placeholder="Longitude"></div>
    <select id="cm-kind"><option>residential</option><option>doorbell</option><option>business</option><option>hoa</option><option>other</option></select>
    <label style="font-size:12px"><input type="checkbox" id="cm-consent">
      Owner has explicitly consented to be listed and contacted. <b>Required.</b></label>
    <button onclick="cmAddCam()">Add to registry</button>
   </div>
  </details>
 </div>
 <div class="card">
  <h2 style="font-size:15px;margin:0 0 4px">🏠 Watch Requests <span class="muted" id="cm-watch-count" style="font-size:11px"></span></h2>
  <div id="cm-watches" style="font-size:12.5px"></div>
  <details style="margin-top:10px"><summary style="cursor:pointer;font-size:12.5px">New watch request (staff entry)</summary>
   <div style="display:grid;gap:6px;margin-top:8px;font-size:12px">
    <input id="wr-name" placeholder="Requester name">
    <input id="wr-contact" placeholder="Contact">
    <input id="wr-address" placeholder="Address">
    <div style="display:flex;gap:6px"><input id="wr-lat" placeholder="Latitude"><input id="wr-lon" placeholder="Longitude"></div>
    <div style="display:flex;gap:6px"><input id="wr-start" type="date"><input id="wr-end" type="date"></div>
    <button onclick="cmAddWatch()">Create watch</button>
   </div>
  </details>
 </div>
</div>
"""

_COMMUNITY_SCRIPT = r"""
function esc(s){return String(s==null?"":s).replace(/[&<>"']/g,function(c){
  return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c];});}
async function cmLoad(){
  try{
    const r=await fetch("/api/v1/desat/community/cameras");
    if(r.ok){const cams=(await r.json()).cameras;
      document.getElementById("cm-cam-count").textContent=cams.length+" registered";
      document.getElementById("cm-cams").innerHTML=cams.slice(0,25).map(c=>
        `<div style="padding:6px 0;border-bottom:1px solid var(--line,rgba(255,255,255,.08))">
          <b>${esc(c.owner_name)}</b> · ${esc(c.camera_kind)} · ${esc(c.address)}
          <span class="muted" style="font-size:11px">· ${esc(c.contact)}</span></div>`).join("")
        ||'<span class="muted">No cameras registered yet.</span>';}
  }catch(e){}
  try{
    const r=await fetch("/api/v1/desat/community/watches");
    if(r.ok){const ws=(await r.json()).watches;
      const act=ws.filter(w=>w.status==="active");
      document.getElementById("cm-watch-count").textContent=act.length+" active";
      document.getElementById("cm-watches").innerHTML=ws.slice(0,25).map(w=>
        `<div style="padding:6px 0;border-bottom:1px solid var(--line,rgba(255,255,255,.08))">
          <b>${esc(w.requester_name)}</b> · ${esc(w.address)}
          <span class="muted" style="font-size:11px">· ${esc(w.start_date)} → ${esc(w.end_date)}
          · ${esc(w.status)} · ${(w.checks||[]).length} check(s)</span>
          ${w.status==="active"?`<button style="width:auto;padding:2px 8px;font-size:11px;margin-left:6px"
            onclick="cmCheck('${esc(w.id)}')">Log check</button>`:""}</div>`).join("")
        ||'<span class="muted">No watch requests.</span>';}
  }catch(e){}
}
async function cmAddCam(){
  const v=id=>document.getElementById(id).value;
  const r=await fetch("/api/v1/desat/community/cameras",{method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({owner_name:v("cm-owner"),contact:v("cm-contact"),
      address:v("cm-address"),latitude:parseFloat(v("cm-lat")),
      longitude:parseFloat(v("cm-lon")),camera_kind:v("cm-kind"),
      consent_confirmed:document.getElementById("cm-consent").checked})});
  if(!r.ok){alert((await r.json()).detail||"failed");return;}
  cmLoad();
}
async function cmAddWatch(){
  const v=id=>document.getElementById(id).value;
  const r=await fetch("/api/v1/desat/community/watches",{method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({requester_name:v("wr-name"),contact:v("wr-contact"),
      address:v("wr-address"),latitude:parseFloat(v("wr-lat")),
      longitude:parseFloat(v("wr-lon")),start_date:v("wr-start"),end_date:v("wr-end")})});
  if(!r.ok){alert((await r.json()).detail||"failed");return;}
  cmLoad();
}
async function cmCheck(id){
  const officer=prompt("Officer name for this check:");
  if(!officer)return;
  await fetch("/api/v1/desat/community/watches/check",{method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({id:id,officer:officer})});
  cmLoad();
}
cmLoad();
"""

# ============================================================ situations page

_SITUATION_BODY = """
<h1 style="margin:0 0 4px">🧿 Situation Analytics</h1>
<p class="muted" style="margin:0 0 10px;font-size:12.5px">
  Your cameras and detection systems already raise events — person,
  vehicle, door forced, weapon, crowd, tamper. SafeCadence connects
  them across cameras, doors, and time into <b>situations</b> a
  dispatcher can act on. Detection stays with your certified vendors;
  we never watch video, never identify faces, never act on our own.
</p>
<div id="st-note" class="card" style="font-size:13px;margin-bottom:12px">Loading…</div>
<div id="st-cards" style="display:grid;gap:10px"></div>
<details class="card" style="margin-top:14px">
  <summary style="cursor:pointer;font-size:13px">Recent analytics events + AI use policy</summary>
  <div id="st-summary" class="muted" style="font-size:12px;margin-top:8px"></div>
  <p id="st-policy" class="muted" style="font-size:11.5px;margin-top:8px"></p>
</details>
"""

_SITUATION_SCRIPT = r"""
function esc(s){return String(s==null?"":s).replace(/[&<>"']/g,function(c){
  return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c];});}
var ST_SEV={critical:"#d93b3b",high:"#b87513",medium:"#0e7c86",low:"#647386"};
async function stLoad(){
  try{
    const j=await (await fetch("/api/v1/desat/situations?window=45")).json();
    document.getElementById("st-note").innerHTML=
      "<b>Watch note"+(j.note.ai_generated?" (AI, grounded)":"")+":</b> "+esc(j.note.note);
    document.getElementById("st-cards").innerHTML=(j.situations||[]).map(c=>
      `<div class="card" style="border-left:5px solid ${ST_SEV[c.severity]||"#647386"};border-radius:0">
        <div style="font-size:14px;font-weight:700">${esc(c.headline)}
          <span class="muted" style="font-size:11px">· confidence ${esc(c.confidence)}</span></div>
        <div class="muted" style="font-size:12px;margin:4px 0">${(c.evidence||[]).map(e=>"• "+esc(e)).join("<br>")}</div>
        <div style="font-size:12.5px;color:#0e7c86;font-weight:600">→ ${esc(c.recommended_action)}</div>
      </div>`).join("")
      ||'<div class="card" style="font-size:13px">No correlated situations in the window — quiet is the goal. ✅</div>';
    const s=j.summary;
    document.getElementById("st-summary").textContent=
      s.events_in_window+" analytics event(s) in the last "+s.window_minutes+
      " min ("+(s.event_types||[]).join(", ")+") from your cameras, VMS, and detection vendors.";
    document.getElementById("st-policy").textContent=s.ai_use_policy;
  }catch(e){
    document.getElementById("st-note").textContent="Could not load situations.";
  }
}
stLoad();
setInterval(stLoad, 20000);
"""

# ============================================================ notify page

_NOTIFY_BODY = """
<h1 style="margin:0 0 4px">📢 Mass Notification</h1>
<p class="muted" style="margin:0 0 6px;font-size:12.5px">
  Trigger, approve, deliver, <b>prove</b>. Alerts ride the systems you
  already own — your email relay, carrier SMS gateways, your own phone
  system (Asterisk/FreePBX, Cisco via InformaCast), and your existing
  community alerting platform (Everbridge, Rave, OnSolve). Every send
  requires a <b>named human approver</b> and lands in a tamper-evident
  audit log.
</p>
<p id="nf-mode" style="margin:0 0 14px;font-size:12px;font-weight:700"></p>
<div style="display:grid;grid-template-columns:1.15fr 1fr;gap:14px">
 <div class="card">
  <h2 style="font-size:15px;margin:0 0 8px">Send an alert</h2>
  <div style="display:grid;gap:6px;font-size:12.5px">
   <select id="nf-group"></select>
   <select id="nf-template">
     <option value="">Custom message...</option>
     <option value="lockdown">Lockdown</option>
     <option value="evacuation">Evacuation</option>
     <option value="shelter">Shelter in place</option>
     <option value="all_clear">All clear</option>
   </select>
   <input id="nf-site" placeholder="Site / building (for templates)">
   <input id="nf-subject" placeholder="Subject (custom messages)">
   <textarea id="nf-body" rows="3" placeholder="Message (custom)"></textarea>
   <input id="nf-by" placeholder="Your name (initiated by)">
   <input id="nf-approved" placeholder="Approver name - REQUIRED">
   <button onclick="nfSend()">Send (test mode unless live is enabled)</button>
   <div id="nf-result" class="muted" style="font-size:12px"></div>
  </div>
 </div>
 <div style="display:grid;gap:14px;align-content:start">
  <div class="card">
   <h2 style="font-size:15px;margin:0 0 6px">Groups <span id="nf-gcount" class="muted" style="font-size:11px"></span></h2>
   <div id="nf-groups" style="font-size:12.5px"></div>
  </div>
  <div class="card">
   <h2 style="font-size:15px;margin:0 0 6px">Alert log <span id="nf-chain" style="font-size:11px"></span></h2>
   <div id="nf-log" style="font-size:12px"></div>
  </div>
 </div>
</div>
"""

_NOTIFY_SCRIPT = r"""
function esc(s){return String(s==null?"":s).replace(/[&<>"']/g,function(c){
  return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c];});}
async function nfLoad(){
  try{
    const s=await (await fetch("/api/v1/desat/notify")).json();
    document.getElementById("nf-mode").textContent = s.live_mode
      ? "LIVE MODE - alerts will really deliver."
      : "TEST MODE - full pipeline runs, nothing is delivered (set SC_NOTIFY_LIVE=1 to go live).";
    document.getElementById("nf-mode").style.color = s.live_mode ? "#d93b3b" : "#0e7c86";
  }catch(e){}
  try{
    const g=(await (await fetch("/api/v1/desat/notify/groups")).json()).groups;
    document.getElementById("nf-gcount").textContent=g.length+" group(s)";
    document.getElementById("nf-group").innerHTML =
      g.map(x=>`<option>${esc(x.name)}</option>`).join("")||"<option value=''>No groups yet</option>";
    document.getElementById("nf-groups").innerHTML =
      g.map(x=>`<div style="padding:5px 0;border-bottom:1px solid rgba(255,255,255,.08)">
        <b>${esc(x.name)}</b> · ${x.members.length} member(s) · ${esc((x.channels||[]).join(", "))}
        ${x.community?'<span style="color:#0e7c86"> · community (consent recorded)</span>':""}</div>`).join("")
      ||'<span class="muted">No groups yet - create them via the API or CLI.</span>';
  }catch(e){}
  try{
    const l=await (await fetch("/api/v1/desat/notify/log")).json();
    document.getElementById("nf-chain").textContent =
      l.verify.ok?"chain verified ("+l.verify.entries+")":"CHAIN BROKEN";
    document.getElementById("nf-chain").style.color=l.verify.ok?"#0e7c86":"#d93b3b";
    document.getElementById("nf-log").innerHTML =
      (l.log||[]).slice(0,8).map(e=>`<div style="padding:4px 0;border-bottom:1px solid rgba(255,255,255,.08)">
        <b>${esc(e.subject)}</b> · ${esc(e.group)} · ${esc(e.mode)}
        <span class="muted">· approved by ${esc(e.approved_by)} · ${esc((e.at||"").slice(0,16))}</span></div>`).join("")
      ||'<span class="muted">No alerts sent yet.</span>';
  }catch(e){}
}
async function nfSend(){
  const v=id=>document.getElementById(id).value;
  const r=await fetch("/api/v1/desat/notify/send",{method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({group:v("nf-group"),template:v("nf-template"),
      site:v("nf-site"),subject:v("nf-subject"),body:v("nf-body"),
      initiated_by:v("nf-by"),approved_by:v("nf-approved")})});
  const j=await r.json();
  document.getElementById("nf-result").textContent = r.ok
    ? "Sent ("+j.mode+") - logged as "+j.id
    : (j.detail||"failed");
  nfLoad();
}
nfLoad();
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
    """'licensed' | 'trial' | 'evaluation' | 'locked'.

    Licensed: the license file carries the ``public_safety`` feature.
    Trial: the built-in free 90-day evaluation (auto-starts on first
    use; real data, banner shows days remaining). Evaluation: sheriff
    demo data loaded after trial expiry (synthetic, banner-marked).
    Locked: none of the above — pages show the upsell, APIs 402.
    """
    try:
        from safecadence.license import feature_access
        acc = feature_access("public_safety")
        if acc["mode"] == "licensed":
            return "licensed"
        if acc["mode"] == "trial":
            return "trial"
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


def _trial_banner() -> str:
    days = 0
    try:
        from safecadence.license import trial_status
        days = trial_status("public_safety").get("days_remaining", 0)
    except Exception:
        pass
    return (
        '<div style="background:rgba(14,124,134,.10);border:1px solid var(--accent);'
        'border-radius:8px;padding:8px 14px;margin-bottom:12px;font-size:12.5px">'
        f'⏳ <b>Free 90-day Public Safety trial</b> — {days} days '
        'remaining. Full features, your data, runs entirely on this device. '
        '<a href="mailto:hello@safecadence.com?subject=Public%20Safety%20license">'
        'Get an agency license</a> to keep it after the trial.</div>')


# ============================================================ register

def register(app) -> None:                              # pragma: no cover
    if not _FASTAPI_OK:
        return
    from fastapi import Body, HTTPException

    def _api_gate() -> None:
        if _ps_access() == "locked":
            raise HTTPException(
                402, "Public Safety license required — your free 90-day "
                       "trial has ended. Email hello@safecadence.com for an "
                       "agency license, or load the synthetic evaluation "
                       "tenant: safecadence demo --sheriff")

    def _page(title: str, body: str, script: str) -> "HTMLResponse":
        access = _ps_access()
        if access == "locked":
            return HTMLResponse(wrap(title, _UPSELL_BODY, ""))
        if access == "trial":
            body = _trial_banner() + body
        elif access == "evaluation":
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

    # ---- EvidenceWatch (the wedge: one-pager + audit pack) -----------
    @app.get("/evidencewatch", response_class=HTMLResponse)
    def evidencewatch_page(agency: str = ""):
        _api_gate()
        from safecadence import evidencewatch as ew
        return HTMLResponse(ew.render_report_html(agency=agency))

    @app.get("/evidencewatch/audit", response_class=HTMLResponse)
    def evidencewatch_audit(agency: str = ""):
        _api_gate()
        from safecadence import evidencewatch as ew
        return HTMLResponse(ew.audit_export(agency=agency))

    @app.get("/api/v1/desat/evidencewatch")
    def evidencewatch_api():
        _api_gate()
        from safecadence import evidencewatch as ew
        return ew.build_report()

    @app.get("/campuswatch", response_class=HTMLResponse)
    def campuswatch_page(district: str = "", demo: int = 0):
        _api_gate()
        from safecadence import evidencewatch as ew
        assets = None
        if demo:
            from safecadence.demo_campus import build_campus_fleet
            assets = build_campus_fleet()
        r = ew.build_report(assets, profile="campus")
        return HTMLResponse(ew.render_report_html(r, agency=district,
                                                    profile="campus"))

    @app.get("/campuswatch/audit", response_class=HTMLResponse)
    def campuswatch_audit(district: str = ""):
        _api_gate()
        from safecadence import evidencewatch as ew
        return HTMLResponse(ew.audit_export(agency=district, profile="campus"))

    @app.get("/api/v1/desat/campuswatch")
    def campuswatch_api():
        _api_gate()
        from safecadence import evidencewatch as ew
        return ew.build_report(profile="campus")

    # ---- Situation Analytics (events in, situations out) -------------
    @app.get("/api/v1/desat/situations")
    def situations_get(window: int = 30):
        _api_gate()
        from safecadence import situation
        cards = situation.assess(window)
        return {"summary": situation.summary(window), "situations": cards,
                 "note": situation.situation_note(cards)}

    @app.post("/api/v1/desat/video-event")
    def video_event_ingest(payload: dict = Body(...)):
        _api_gate()
        from safecadence import situation
        try:
            return situation.ingest_video_event(payload)
        except (ValueError, TypeError) as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.post("/api/v1/desat/situations/demo")
    def situations_demo():
        _api_gate()
        from safecadence import situation
        return situation.seed_demo()

    @app.get("/situations", response_class=HTMLResponse)
    def situations_page():
        return _page("Situation Analytics", _SITUATION_BODY,
                      _SITUATION_SCRIPT)

    # ---- Mass Notification (trigger + approve + prove) ---------------
    @app.get("/api/v1/desat/notify")
    def notify_summary():
        _api_gate()
        from safecadence import mass_notify
        return mass_notify.summary()

    @app.get("/api/v1/desat/notify/groups")
    def notify_groups():
        _api_gate()
        from safecadence import mass_notify
        return {"groups": mass_notify.list_groups()}

    @app.post("/api/v1/desat/notify/groups")
    def notify_group_save(payload: dict = Body(...)):
        _api_gate()
        from safecadence import mass_notify
        try:
            return mass_notify.save_group(
                name=str(payload.get("name", "")),
                members=payload.get("members") or [],
                community=bool(payload.get("community")),
                channels=payload.get("channels") or ["email"])
        except (ValueError, TypeError) as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.get("/api/v1/desat/notify/log")
    def notify_log():
        _api_gate()
        from safecadence import mass_notify
        return {"log": mass_notify.alert_log(50),
                 "verify": mass_notify.verify_log()}

    @app.post("/api/v1/desat/notify/send")
    def notify_send(payload: dict = Body(...)):
        _api_gate()
        from safecadence import mass_notify
        try:
            return mass_notify.send_notification(
                group=str(payload.get("group", "")),
                subject=str(payload.get("subject", "")),
                body=str(payload.get("body", "")),
                template=str(payload.get("template", "")),
                site=str(payload.get("site", "")),
                channels=payload.get("channels"),
                initiated_by=str(payload.get("initiated_by", "")),
                approved_by=str(payload.get("approved_by", "")),
                incident_id=str(payload.get("incident_id", "")),
                live=bool(payload.get("live")) or None)
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc
        except (ValueError, TypeError) as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.get("/notify", response_class=HTMLResponse)
    def notify_page():
        return _page("Mass Notification", _NOTIFY_BODY, _NOTIFY_SCRIPT)

    @app.get("/facilitywatch", response_class=HTMLResponse)
    def facilitywatch_page(name: str = ""):
        _api_gate()
        from safecadence import evidencewatch as ew
        r = ew.build_report(None, profile="facility")
        return HTMLResponse(ew.render_report_html(r, agency=name,
                                                    profile="facility"))

    @app.get("/facilitywatch/audit", response_class=HTMLResponse)
    def facilitywatch_audit(name: str = ""):
        _api_gate()
        from safecadence import evidencewatch as ew
        return HTMLResponse(ew.audit_export(agency=name,
                                              profile="facility"))

    @app.get("/api/v1/desat/facilitywatch")
    def facilitywatch_api():
        _api_gate()
        from safecadence import evidencewatch as ew
        return ew.build_report(profile="facility")

    # ---- Community layer (consent-based; agency-entered) -------------
    @app.get("/api/v1/desat/community")
    def community_summary():
        _api_gate()
        from safecadence import community
        return community.summary()

    @app.get("/api/v1/desat/community/cameras")
    def community_cameras(status: str = "active"):
        _api_gate()
        from safecadence import community
        return {"cameras": community.list_cameras(status)}

    @app.get("/api/v1/desat/community/cameras/near")
    def community_cameras_near(lat: float, lon: float, radius_m: float = 500):
        _api_gate()
        from safecadence import community
        return {"radius_m": radius_m,
                 "cameras": community.cameras_near(lat, lon, radius_m)}

    @app.post("/api/v1/desat/community/cameras")
    def community_camera_add(payload: dict = Body(...)):
        _api_gate()
        from safecadence import community
        try:
            return community.register_camera(
                owner_name=str(payload.get("owner_name", "")),
                contact=str(payload.get("contact", "")),
                address=str(payload.get("address", "")),
                latitude=float(payload.get("latitude", 999)),
                longitude=float(payload.get("longitude", 999)),
                camera_kind=str(payload.get("camera_kind", "residential")),
                notes=str(payload.get("notes", "")),
                consent_confirmed=bool(payload.get("consent_confirmed")),
                entered_by=str(payload.get("entered_by", "staff")))
        except (ValueError, TypeError) as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.post("/api/v1/desat/community/cameras/remove")
    def community_camera_remove(payload: dict = Body(...)):
        _api_gate()
        from safecadence import community
        try:
            return community.remove_camera(
                str(payload.get("id", "")),
                reason=str(payload.get("reason", "owner request")))
        except KeyError as exc:
            raise HTTPException(404, "not found") from exc

    @app.get("/api/v1/desat/community/watches")
    def community_watches(status: str = ""):
        _api_gate()
        from safecadence import community
        return {"watches": community.list_watches(status)}

    @app.post("/api/v1/desat/community/watches")
    def community_watch_add(payload: dict = Body(...)):
        _api_gate()
        from safecadence import community
        try:
            return community.request_watch(
                requester_name=str(payload.get("requester_name", "")),
                contact=str(payload.get("contact", "")),
                address=str(payload.get("address", "")),
                latitude=float(payload.get("latitude", 999)),
                longitude=float(payload.get("longitude", 999)),
                start_date=str(payload.get("start_date", "")),
                end_date=str(payload.get("end_date", "")),
                notes=str(payload.get("notes", "")),
                entered_by=str(payload.get("entered_by", "staff")))
        except (ValueError, TypeError) as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.post("/api/v1/desat/community/watches/check")
    def community_watch_check(payload: dict = Body(...)):
        _api_gate()
        from safecadence import community
        try:
            return community.log_check(
                str(payload.get("id", "")),
                officer=str(payload.get("officer", "")),
                note=str(payload.get("note", "")))
        except KeyError as exc:
            raise HTTPException(404, "not found") from exc
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.get("/community", response_class=HTMLResponse)
    def community_page():
        return _page("Community", _COMMUNITY_BODY, _COMMUNITY_SCRIPT)

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
