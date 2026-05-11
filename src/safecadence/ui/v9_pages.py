"""
v9.0 — All sidebar pages.

Real list pages backed by existing APIs:
  /inventory   — every asset
  /findings    — identity findings
  /jit         — active + recent JIT grants
  /paths       — identity attack paths
  /watchlists  — pinned entities

Stub pages (coming in v9.1) that don't 404 — they render the v9 chrome
+ a friendly "we're working on this view, meanwhile see X" card:
  /policies, /drift, /evidence, /per-device-diff,
  /builder, /approvals, /queue, /rollback,
  /topology

Every page uses the universal chrome so the sidebar / palette / theme
toggle / notifications work consistently.
"""

from __future__ import annotations

# v9.53 — module-level import so FastAPI's get_type_hints() can resolve
# `request: Request` annotations on routes that need the raw request
# object. Imports inside register() are local and invisible to FastAPI
# under PEP 563 string-deferred annotations.
try:
    from fastapi import Request, Body as _FastApiBody
except ImportError:                                     # pragma: no cover
    Request = None  # type: ignore[assignment,misc]
    _FastApiBody = None  # type: ignore[assignment,misc]

from safecadence.ui._chrome import wrap


# ---------------------------------------------------------------- inventory


_INVENTORY_BODY = """
<h1>Inventory <span class="sc-help" data-help="inventory-sources"></span></h1>
<p class="muted" id="subtitle">Loading…</p>

<!-- Ways to populate -->
<div style="display:grid;gap:10px;
     grid-template-columns:repeat(auto-fit,minmax(220px,1fr));
     margin-bottom:16px">
  <div class="card" style="border-left:4px solid #7c5cff;padding:14px 16px;
       cursor:pointer" onclick="openDiscover()">
    <div style="font-size:11px;text-transform:uppercase;letter-spacing:0.5px;
                color:var(--muted)">🛰️  LAN scan</div>
    <div style="font-size:14px;font-weight:700;margin-top:4px">
      Probe a CIDR range</div>
    <div style="font-size:12px;color:var(--muted);margin-top:4px">
      ARP + mDNS + TLS + HTTP fingerprint. Sees the local broadcast domain.</div>
    <button class="primary" style="margin-top:8px;width:auto;padding:6px 12px;
            font-size:12px">🛰  Run scan</button>
  </div>
  <div class="card" style="border-left:4px solid #06b6d4;padding:14px 16px;
       cursor:pointer" onclick="openSnmpHarvest()">
    <div style="font-size:11px;text-transform:uppercase;letter-spacing:0.5px;
                color:var(--muted)">📡  Network gear</div>
    <div style="font-size:14px;font-weight:700;margin-top:4px">
      Harvest from a router</div>
    <div style="font-size:12px;color:var(--muted);margin-top:4px">
      LLDP + CDP + MAC table via SNMP. One router → 50–500 devices.</div>
    <button class="primary" style="margin-top:8px;width:auto;padding:6px 12px;
            font-size:12px;background:#06b6d4">📡  SNMP harvest</button>
  </div>
  <div class="card" style="border-left:4px solid #10b981;padding:14px 16px;
       cursor:pointer" onclick="openUpload()">
    <div style="font-size:11px;text-transform:uppercase;letter-spacing:0.5px;
                color:var(--muted)">📥  Upload</div>
    <div style="font-size:14px;font-weight:700;margin-top:4px">
      Import from CSV</div>
    <div style="font-size:12px;color:var(--muted);margin-top:4px">
      CMDB export or asset list. Template included — drag, drop, preview, commit.</div>
    <button class="primary" style="margin-top:8px;width:auto;padding:6px 12px;
            font-size:12px;background:#10b981">📥  Upload CSV</button>
  </div>
  <div class="card" style="border-left:4px solid #f59e0b;padding:14px 16px;
       cursor:pointer" onclick="openManualAdd()">
    <div style="font-size:11px;text-transform:uppercase;letter-spacing:0.5px;
                color:var(--muted)">✏️  Manual</div>
    <div style="font-size:14px;font-weight:700;margin-top:4px">
      Add one device by hand</div>
    <div style="font-size:12px;color:var(--muted);margin-top:4px">
      Useful for crown-jewels you want SafeCadence to track immediately.</div>
    <button class="primary" style="margin-top:8px;width:auto;padding:6px 12px;
            font-size:12px;background:#f59e0b">+ Add device</button>
  </div>

  <div class="card" style="border-left:4px solid #2563eb;padding:14px 16px;
       cursor:pointer" onclick="openAd()">
    <div style="font-size:11px;text-transform:uppercase;letter-spacing:0.5px;
                color:var(--muted)">🪪  AD / LDAP</div>
    <div style="font-size:14px;font-weight:700;margin-top:4px">
      Pull from Active Directory</div>
    <div style="font-size:12px;color:var(--muted);margin-top:4px">
      Every domain-joined endpoint, with OS, OU, last-logon. Biggest
      single source.</div>
    <button class="primary" style="margin-top:8px;width:auto;padding:6px 12px;
            font-size:12px;background:#2563eb">🪪  Bind to DC</button>
  </div>

  <div class="card" style="border-left:4px solid #0ea5e9;padding:14px 16px;
       cursor:pointer" onclick="openEntra()">
    <div style="font-size:11px;text-transform:uppercase;letter-spacing:0.5px;
                color:var(--muted)">☁️  Entra ID</div>
    <div style="font-size:14px;font-weight:700;margin-top:4px">
      Pull from Microsoft Graph</div>
    <div style="font-size:12px;color:var(--muted);margin-top:4px">
      Intune-enrolled phones, Macs, BYOD laptops. What AD on-prem misses.</div>
    <button class="primary" style="margin-top:8px;width:auto;padding:6px 12px;
            font-size:12px;background:#0ea5e9">☁️  Connect tenant</button>
  </div>

  <div class="card" style="border-left:4px solid #ef4444;padding:14px 16px;
       cursor:pointer" onclick="openDhcp()">
    <div style="font-size:11px;text-transform:uppercase;letter-spacing:0.5px;
                color:var(--muted)">📋  DHCP leases</div>
    <div style="font-size:14px;font-weight:700;margin-top:4px">
      Pull DHCP server leases</div>
    <div style="font-size:12px;color:var(--muted);margin-top:4px">
      ISC dhcpd file or Windows DHCP CSV. Catches sleeping laptops + IoT.</div>
    <button class="primary" style="margin-top:8px;width:auto;padding:6px 12px;
            font-size:12px;background:#ef4444">📋  Import leases</button>
  </div>

  <div class="card" style="border-left:4px solid #f97316;padding:14px 16px;
       cursor:pointer" onclick="openCloud()">
    <div style="font-size:11px;text-transform:uppercase;letter-spacing:0.5px;
                color:var(--muted)">🌩️  Cloud</div>
    <div style="font-size:14px;font-weight:700;margin-top:4px">
      AWS / Azure / GCP</div>
    <div style="font-size:12px;color:var(--muted);margin-top:4px">
      EC2 + Azure VMs + GCE — invisible to LAN scans.</div>
    <button class="primary" style="margin-top:8px;width:auto;padding:6px 12px;
            font-size:12px;background:#f97316">🌩️  Pull cloud assets</button>
  </div>
</div>

<!-- Bulk action bar (v9.12) — shown only when rows are selected -->
<div id="inv-bulk" class="card" style="display:none;align-items:center;
     gap:10px;padding:8px 14px;margin-bottom:8px;
     background:var(--accent-soft);border-left:4px solid var(--accent)">
  <strong id="inv-bulk-count" style="font-size:13px"></strong>
  <span style="flex:1"></span>
  <button class="alt" style="width:auto;padding:6px 12px;font-size:12px"
          onclick="invBulkAddToGroup()">📦 Add to group</button>
  <button class="alt" style="width:auto;padding:6px 12px;font-size:12px"
          onclick="invBulkDelete()"
          style="background:#fef3c7;color:#92400e">🗑 Delete</button>
  <button class="alt" style="width:auto;padding:6px 12px;font-size:12px"
          onclick="invToggleAll(false)">✗ Clear</button>
</div>

<!-- Filters -->
<div style="display:flex;gap:8px;margin-bottom:8px;flex-wrap:wrap;align-items:center" id="filters">
  <button class="alt" style="width:auto;padding:6px 12px;font-size:12px" data-f="all">All</button>
  <button class="alt" style="width:auto;padding:6px 12px;font-size:12px" data-f="network">Network</button>
  <button class="alt" style="width:auto;padding:6px 12px;font-size:12px" data-f="server">Servers</button>
  <button class="alt" style="width:auto;padding:6px 12px;font-size:12px" data-f="identity">Identity</button>
  <button class="alt" style="width:auto;padding:6px 12px;font-size:12px" data-f="cloud">Cloud</button>
  <button class="alt" style="width:auto;padding:6px 12px;font-size:12px" data-f="backup">Backup</button>
  <button class="alt" style="width:auto;padding:6px 12px;font-size:12px" data-f="crown">Crown jewels</button>
  <span style="flex:1"></span>
  <button class="alt" style="width:auto;padding:6px 12px;font-size:12px"
          onclick="invToggleDensity()" title="Toggle row density"
          id="density-btn">↕ Density</button>
  <button class="alt" style="width:auto;padding:6px 12px;font-size:12px"
          onclick="invResetWidths()" title="Reset column widths">↺ Widths</button>
  <button class="alt" style="width:auto;padding:6px 12px;font-size:12px"
          onclick="toggleColumnPicker()">⚙ Columns</button>
</div>

<!-- Column picker (hidden by default) -->
<div class="card" id="col-picker" style="display:none;padding:14px 16px">
  <div style="font-size:13px;font-weight:600;margin-bottom:8px">
    Show columns
    <span class="sc-help" data-help="inventory-columns"></span>
  </div>
  <div id="col-checks" style="display:grid;gap:6px;
       grid-template-columns:repeat(auto-fill,minmax(180px,1fr));font-size:12px">
  </div>
</div>

<style>
  /* Resizable column handles for the inventory table */
  #tbl { table-layout: fixed; width: 100%; border-collapse: collapse; }
  #tbl th { position: relative; overflow: hidden; text-overflow: ellipsis;
            white-space: nowrap; }
  #tbl td { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  #tbl .col-resizer {
    position: absolute; top: 0; right: 0; bottom: 0; width: 6px;
    cursor: col-resize; user-select: none;
    background: transparent; z-index: 5;
  }
  #tbl .col-resizer::after {
    content: ""; position: absolute; top: 25%; right: 2px; bottom: 25%;
    width: 1px; background: var(--border, #26315b);
  }
  #tbl .col-resizer:hover, #tbl .col-resizer.dragging {
    background: rgba(124, 92, 255, 0.18);
  }
  /* Body cell density variants */
  #tbl.density-compact td, #tbl.density-compact th { padding: 4px 8px; font-size: 12px; }
  #tbl.density-comfortable td, #tbl.density-comfortable th { padding: 14px 12px; }
  /* Allow content to be revealed on hover when text is clipped */
  #tbl tbody tr:hover td { white-space: normal; }
</style>

<div class="card" style="padding:0;overflow-x:auto" id="tbl-wrap">
  <table id="tbl" class="density-normal">
    <thead id="tbl-head"></thead>
    <tbody><tr><td colspan="9" class="muted" style="padding:36px;text-align:center">Loading…</td></tr></tbody>
  </table>
</div>
"""

_INVENTORY_SCRIPT = r"""
let ALL_ASSETS = [];
let CUR_FILTER = "all";

// Column registry — each entry knows how to render its cell from an asset dict.
function pickIp(a) {
  // Prefer explicit mgmt_ip → first interface ip → identity.ip → custom_fields.mgmt_ip
  const id = a.identity || {};
  if (id.mgmt_ip) return id.mgmt_ip;
  const cf = id.custom_fields || {};
  if (cf.mgmt_ip) return cf.mgmt_ip;
  if (id.ip) return id.ip;
  const ifaces = a.interfaces || [];
  for (const i of ifaces) {
    if (i && (i.ip_address || i.ip)) return i.ip_address || i.ip;
  }
  return "";
}
function pickMac(a) {
  const id = a.identity || {};
  if (id.mac_address) return id.mac_address;
  if (id.mac) return id.mac;
  const ifaces = a.interfaces || [];
  for (const i of ifaces) {
    if (i && (i.mac_address || i.mac)) return i.mac_address || i.mac;
  }
  return "";
}
function fmtDate(v) {
  if (!v) return "";
  try { return String(v).slice(0, 10); } catch (e) { return String(v); }
}

// v9.24: Safe Score map populated alongside the asset list. Empty
// until /api/scores/safe responds; rows render '—' in the meantime.
let SAFE_SCORES = {};
function safeScorePill(aid) {
  const s = SAFE_SCORES[aid];
  if (s == null) return "";
  const cls = s >= 80 ? "pill-ok" : s >= 60 ? "pill-warn" : "pill-crit";
  return `<span class="pill ${cls}" title="Safe Score: composite of findings, CVEs, attack paths, drift">${s}</span>`;
}

const COLS = [
  // ----- identity & criticality -----
  { k:"crit",      l:"⚠",         on:true,  fn:a => (a.identity||{}).criticality === "crown-jewel"
                                                   ? '<span class="pill pill-crit">crown</span>' : "" },
  { k:"safe",      l:"Safe",       on:true,  fn:a => safeScorePill((a.identity||{}).asset_id || "") },
  { k:"name",      l:"Hostname",   on:true,  fn:a => `<strong>${(a.identity||{}).hostname || (a.identity||{}).asset_id || ''}</strong>` },
  { k:"mgmt_ip",   l:"Mgmt IP",    on:true,  fn:a => { const ip = pickIp(a); return ip ? `<code>${ip}</code>` : ""; } },
  { k:"mgmt_url",  l:"Mgmt URL",   on:false, fn:a => { const u = (a.identity||{}).mgmt_url || ((a.identity||{}).custom_fields||{}).mgmt_url || ""; return u ? `<a href="${u}" target="_blank" rel="noopener">open ↗</a>` : ""; } },
  { k:"mac",       l:"MAC",        on:false, fn:a => { const m = pickMac(a); return m ? `<code>${m}</code>` : ""; } },
  { k:"vlan",      l:"VLAN",       on:false, fn:a => { const v = ((a.identity||{}).custom_fields||{}).vlan; const vs = (a.interfaces||[]).map(i => i && i.vlan).filter(Boolean); return v || vs[0] || ""; } },
  { k:"vendor",    l:"Vendor",     on:true,  fn:a => (a.identity||{}).vendor || "" },
  { k:"model",     l:"Model",      on:false, fn:a => (a.hardware||{}).model || (a.identity||{}).model || "" },
  { k:"family",    l:"Family",     on:false, fn:a => (a.identity||{}).product_family || "" },
  { k:"serial",    l:"Serial",     on:false, fn:a => `<code>${(a.identity||{}).serial_number || ""}</code>` },
  { k:"type",      l:"Type",       on:true,  fn:a => (a.identity||{}).asset_type || "" },
  { k:"env",       l:"Env",        on:true,  fn:a => (a.identity||{}).environment || "" },
  { k:"site",      l:"Site",       on:true,  fn:a => (a.identity||{}).site || "" },
  { k:"datacenter",l:"DC",         on:false, fn:a => ((a.identity||{}).custom_fields||{}).datacenter || (a.identity||{}).datacenter || "" },
  { k:"rack",      l:"Rack",       on:false, fn:a => ((a.identity||{}).custom_fields||{}).rack || "" },
  { k:"criticality",l:"Crit",      on:false, fn:a => { const c = (a.identity||{}).criticality || ""; return c ? `<span class="pill ${c==='crown-jewel'?'pill-crit':c==='high'?'pill-high':'pill-info'}">${c}</span>` : ""; } },
  { k:"owner",     l:"Owner",      on:true,  fn:a => (a.identity||{}).owner || "" },
  { k:"team",      l:"Team",       on:false, fn:a => (a.identity||{}).team || "" },
  { k:"biz_owner", l:"Biz owner",  on:false, fn:a => ((a.identity||{}).custom_fields||{}).business_owner || "" },
  { k:"tags",      l:"Tags",       on:false, fn:a => ((a.identity||{}).tags || []).slice(0, 4).map(t => `<span class="pill pill-info" style="margin-right:2px">${t}</span>`).join("") },

  // ----- OS / lifecycle -----
  { k:"os",        l:"OS",         on:false, fn:a => `${(a.os||{}).os_type || ""} ${(a.os||{}).version || (a.os||{}).os_version || ""}` },
  { k:"firmware",  l:"Firmware",   on:false, fn:a => (a.os||{}).firmware_version || (a.hardware||{}).firmware_version || "" },
  { k:"uptime",    l:"Uptime",     on:false, fn:a => fmtUptime((a.os||{}).uptime_seconds || 0) },
  { k:"eol",       l:"EOL",        on:false, fn:a => { const e = (a.lifecycle||{}).eol_status || ""; return e ? `<span class="pill ${e==='end-of-life'?'pill-crit':e==='end-of-sale'?'pill-high':'pill-info'}">${e}</span>` : ""; } },

  // ----- license / support -----
  { k:"license",   l:"License",    on:false, fn:a => (a.license||{}).license_level || "" },
  { k:"lic_expiry",l:"Lic expiry", on:false, fn:a => fmtDate((a.license||{}).license_expiry) },
  { k:"support",   l:"Support exp",on:false, fn:a => fmtDate((a.license||{}).support_contract_expiry || ((a.identity||{}).custom_fields||{}).support_expiry) },

  // ----- system / health -----
  { k:"cpu",       l:"CPU%",       on:false, fn:a => fmtPct((a.system_resources||{}).cpu_utilization_percent) },
  { k:"mem",       l:"Mem%",       on:false, fn:a => fmtPct((a.system_resources||{}).memory_utilization_percent) },

  // ----- interfaces / network -----
  { k:"ifaces",    l:"Iface",      on:false, fn:a => String((a.interfaces||[]).length) },
  { k:"ifaces_up", l:"Up/Total",   on:false, fn:a => { const ifs = a.interfaces||[]; const up = ifs.filter(i => i && (i.status === 'up' || i.admin_status === 'up')).length; return ifs.length ? `${up}/${ifs.length}` : ""; } },
  { k:"default_gw",l:"Default GW", on:false, fn:a => (a.routing||{}).default_gateway || "" },
  { k:"uplink",    l:"Uplink",     on:false, fn:a => ((a.identity||{}).custom_fields||{}).uplink || "" },

  // ----- routing -----
  { k:"ospf_n",    l:"OSPF nbr",   on:false, fn:a => String((a.routing_protocols||{}).ospf_neighbor_count || 0) },
  { k:"bgp_n",     l:"BGP nbr",    on:false, fn:a => String((a.routing_protocols||{}).bgp_neighbor_count || 0) },

  // ----- security -----
  { k:"ports",     l:"Open ports", on:false, fn:a => ((a.network_security||{}).open_ports || []).join(", ") },
  { k:"telnet",    l:"Telnet",     on:false, fn:a => (a.network_security||{}).telnet_enabled ? '<span class="pill pill-crit">on</span>' : '<span class="muted">off</span>' },
  { k:"snmp_ins",  l:"SNMP weak",  on:false, fn:a => { const ns = a.network_security||{}; const weak = ns.snmp_v1_v2_enabled || (ns.snmp_communities||[]).some(c => ['public','private'].includes(c)); return weak ? '<span class="pill pill-crit">yes</span>' : '<span class="muted">no</span>'; } },
  { k:"aaa",       l:"AAA",        on:false, fn:a => (a.network_security||{}).aaa_enabled ? '<span class="pill pill-ok">on</span>' : '<span class="muted">off</span>' },
  { k:"cves",      l:"KEV",        on:true,  fn:a => { const k = (a.security||{}).kev_cves || 0; return `<span class="${k>0?'pill pill-crit':'muted'}">${k}</span>`; } },
  { k:"crit_cve",  l:"CritCVE",    on:false, fn:a => String((a.security||{}).critical_cves || 0) },

  // ----- ops health signals -----
  { k:"ntp_ok",    l:"NTP",        on:false, fn:a => { const sl = a.system_logging||{}; const ok = sl.ntp_synced; return ok === true ? '<span class="pill pill-ok">ok</span>' : ok === false ? '<span class="pill pill-crit">drift</span>' : ""; } },
  { k:"syslog",    l:"Syslog",     on:false, fn:a => { const sl = a.system_logging||{}; return (sl.syslog_servers||[]).length ? '<span class="pill pill-ok">ok</span>' : '<span class="pill pill-high">none</span>'; } },
  { k:"last_seen", l:"Last seen",  on:false, fn:a => fmtDate((a.identity||{}).last_seen || (a.identity||{}).last_collected_at) },
  { k:"last_cfg",  l:"Last cfg △", on:false, fn:a => fmtDate((a.raw_collection||{}).last_config_change || ((a.identity||{}).custom_fields||{}).last_config_change) },
  { k:"last_bkp",  l:"Last backup",on:false, fn:a => fmtDate(((a.identity||{}).custom_fields||{}).last_backup) },

  // ----- compliance & risk -----
  { k:"compliance",l:"Compliance", on:false, fn:a => ((a.identity||{}).tags||[]).filter(t => t.startsWith('compliance:')).map(t => `<span class="pill pill-info">${t.replace('compliance:','')}</span>`).join(" ") },
  { k:"risk",      l:"Risk",       on:false, fn:a => { const r = (a.compliance_signals||{}).risk_score_0_100 || 0; return r ? `<span class="pill ${r>=70?'pill-crit':r>=40?'pill-high':'pill-ok'}">${r}</span>` : ""; } },
  { k:"health",    l:"Grade",      on:true,  fn:a => { const g = (a.health||{}).grade || "—"; const cls = g==="A"||g==="B" ? "pill-ok" : g==="C"?"pill-high":"pill-crit"; return `<span class="pill ${cls}">${g}</span>`; } },
  { k:"policies",  l:"Policies",   on:false, fn:a => String((a.compliance_signals||{}).policies_applied_count || 0) },
  { k:"findings",  l:"Findings",   on:false, fn:a => { const n = (a.compliance_signals||{}).open_findings_count || 0; return n ? `<span class="pill pill-high">${n}</span>` : '<span class="muted">0</span>'; } },
  { k:"discovered",l:"Source",     on:false, fn:a => (a.identity||{}).discovery_source || "" },
];

function fmtPct(v) { v = Number(v) || 0; return v ? v.toFixed(0) + "%" : ""; }
function fmtUptime(s) {
  s = Number(s) || 0;
  if (!s) return "";
  const d = Math.floor(s / 86400);
  if (d) return d + "d";
  const h = Math.floor(s / 3600);
  return h + "h";
}

function loadColPrefs() {
  const saved = JSON.parse(localStorage.getItem("SC_INV_COLS") || "null");
  if (saved && Array.isArray(saved)) {
    for (const c of COLS) c.on = saved.includes(c.k);
  }
}
function saveColPrefs() {
  localStorage.setItem("SC_INV_COLS",
    JSON.stringify(COLS.filter(c => c.on).map(c => c.k)));
}

// ---- Column resize + density (v9.41) -------------------------------------
function loadColWidths() {
  try {
    return JSON.parse(localStorage.getItem("SC_INV_WIDTHS") || "{}") || {};
  } catch (e) { return {}; }
}
function saveColWidth(key, px) {
  const w = loadColWidths();
  w[key] = Math.max(48, Math.round(px));
  localStorage.setItem("SC_INV_WIDTHS", JSON.stringify(w));
}
function invResetWidths() {
  localStorage.removeItem("SC_INV_WIDTHS");
  renderTable();
}
function attachResizers() {
  document.querySelectorAll("#tbl th .col-resizer").forEach(handle => {
    handle.addEventListener("mousedown", evt => {
      evt.preventDefault(); evt.stopPropagation();
      const th = handle.parentElement;
      const key = handle.dataset.colkey;
      const startX = evt.pageX;
      const startW = th.getBoundingClientRect().width;
      handle.classList.add("dragging");
      document.body.style.cursor = "col-resize";
      function onMove(e) {
        const dx = e.pageX - startX;
        const newW = Math.max(48, startW + dx);
        th.style.width = newW + "px";
      }
      function onUp() {
        document.removeEventListener("mousemove", onMove);
        document.removeEventListener("mouseup", onUp);
        handle.classList.remove("dragging");
        document.body.style.cursor = "";
        const finalW = th.getBoundingClientRect().width;
        saveColWidth(key, finalW);
      }
      document.addEventListener("mousemove", onMove);
      document.addEventListener("mouseup", onUp);
    });
  });
}

const _DENSITY_LIST = ["compact", "normal", "comfortable"];
function _loadDensity() {
  return localStorage.getItem("SC_INV_DENSITY") || "normal";
}
function _applyDensity() {
  const tbl = document.getElementById("tbl");
  if (!tbl) return;
  const d = _loadDensity();
  _DENSITY_LIST.forEach(k => tbl.classList.remove("density-" + k));
  tbl.classList.add("density-" + d);
  const btn = document.getElementById("density-btn");
  if (btn) btn.textContent = "↕ " + d.charAt(0).toUpperCase() + d.slice(1);
}
function invToggleDensity() {
  const cur = _loadDensity();
  const idx = (_DENSITY_LIST.indexOf(cur) + 1) % _DENSITY_LIST.length;
  localStorage.setItem("SC_INV_DENSITY", _DENSITY_LIST[idx]);
  _applyDensity();
}
document.addEventListener("DOMContentLoaded", _applyDensity);

function renderColPicker() {
  const host = document.getElementById("col-checks");
  host.innerHTML = COLS.map(c => `
    <label style="display:flex;align-items:center;gap:6px;cursor:pointer">
      <input type="checkbox" data-col="${c.k}" ${c.on ? "checked" : ""}
             style="width:auto" />
      ${c.l}
    </label>
  `).join("");
  host.querySelectorAll("input").forEach(inp => {
    inp.addEventListener("change", e => {
      const col = COLS.find(c => c.k === e.target.dataset.col);
      if (col) col.on = e.target.checked;
      saveColPrefs();
      renderTable();
    });
  });
}
function toggleColumnPicker() {
  const p = document.getElementById("col-picker");
  if (p.style.display === "none") {
    renderColPicker();
    p.style.display = "block";
  } else {
    p.style.display = "none";
  }
}

async function loadInventory() {
  try {
    const r = await scApi("/api/platform/inventory");
    ALL_ASSETS = r.assets || [];
    document.getElementById("subtitle").textContent =
      `${ALL_ASSETS.length} assets monitored · click any row for the full device fact sheet`;
    // v9.24: kick off Safe Score fetch in parallel; merge by asset_id when it arrives.
    scApi("/api/scores/safe").then(s => {
      SAFE_SCORES = {};
      for (const row of (s?.per_asset || [])) {
        if (row.asset_id) SAFE_SCORES[row.asset_id] = row.score;
      }
      renderTable();
    }).catch(() => { /* score endpoint not reachable — render without */ });
    renderTable();
  } catch (e) {
    document.querySelector("#tbl tbody").innerHTML =
      `<tr><td colspan="9" class="muted">Failed to load: ${e.message}. ` +
      `<a href="/onboarding">Run onboarding</a> or <a href="/legacy">use legacy UI</a>.</td></tr>`;
  }
}

function renderTable() {
  let assets = ALL_ASSETS;
  if (CUR_FILTER === "crown") {
    assets = assets.filter(a => (a.identity || {}).criticality === "crown-jewel");
  } else if (CUR_FILTER !== "all") {
    assets = assets.filter(a => (a.identity || {}).asset_type === CUR_FILTER);
  }
  const visible = COLS.filter(c => c.on);
  const savedWidths = loadColWidths();
  document.getElementById("tbl-head").innerHTML =
    "<tr>" +
    `<th style="width:24px"><input type="checkbox" id="inv-all"
       onclick="invToggleAll(this.checked)" style="width:auto"/></th>` +
    visible.map(c => {
      const w = savedWidths[c.k];
      const wattr = w ? ` style="width:${w}px"` : "";
      return `<th data-colkey="${c.k}"${wattr}>${c.l}` +
             `<span class="col-resizer" data-colkey="${c.k}"></span></th>`;
    }).join("") +
    `<th style="width:40px"></th>` +
    "</tr>";
  attachResizers();
  _applyDensity();
  const tbody = document.querySelector("#tbl tbody");
  if (!assets.length) {
    tbody.innerHTML = `<tr><td colspan="${visible.length+2}" class="muted" style="padding:24px">
      No assets in this view. <a href="/onboarding">Load demo data</a></td></tr>`;
    return;
  }
  tbody.innerHTML = assets.map(a => {
    const aid = (a.identity || {}).asset_id || "";
    const click = `location.href='/asset/${encodeURIComponent(aid)}'`;
    // One <td> per visible column, each with the row-click handler. The
    // previous implementation nested <td>s inside a colspan="0" wrapper,
    // which produced invalid HTML and visible header/data mis-alignment.
    const cells = visible.map(c =>
      `<td style="cursor:pointer" onclick="${click}">${c.fn(a) || ""}</td>`
    ).join("");
    return `<tr data-aid="${aid}">
      <td onclick="event.stopPropagation()">
        <input type="checkbox" class="inv-pick" value="${aid}"
               style="width:auto" onclick="invSelChange()"/>
      </td>${cells}<td style="text-align:right">
        <span style="cursor:pointer;font-size:18px;color:var(--muted);
              padding:4px 8px" onclick="invKebab(event,'${aid}')">⋯</span>
      </td>
    </tr>`;
  }).join("");
  invSelChange();
}

// ---- v9.12 — bulk-select & row actions -----------------------
function invToggleAll(on) {
  document.querySelectorAll(".inv-pick").forEach(c => c.checked = on);
  invSelChange();
}
function invSelected() {
  return Array.from(document.querySelectorAll(".inv-pick:checked"))
              .map(c => c.value);
}
function invSelChange() {
  const n = invSelected().length;
  const bar = document.getElementById("inv-bulk");
  if (!bar) return;
  if (n === 0) { bar.style.display = "none"; return; }
  bar.style.display = "flex";
  document.getElementById("inv-bulk-count").textContent =
    `${n} selected`;
}
function invKebab(evt, aid) {
  evt.stopPropagation();
  scOpenSlide("Actions for " + aid, `
    <div style="display:grid;gap:8px">
      <button class="primary" onclick="invEdit('${aid}')">✏️  Edit device</button>
      <button class="alt" onclick="invAddToGroupOne('${aid}')">📦  Add to group</button>
      <button class="alt" onclick="location.href='/execute?asset_id=${encodeURIComponent(aid)}'">
        ⚡  Run command</button>
      <button class="alt" onclick="location.href='/asset/${encodeURIComponent(aid)}'">
        🔍  Open cockpit</button>
      <hr style="border:0;border-top:1px solid var(--border);margin:6px 0"/>
      <button onclick="invDelete('${aid}')"
              style="background:#fef3c7;color:#92400e">🗑  Delete device</button>
    </div>
  `);
}

async function invEdit(aid) {
  // Fetch the asset, open the manual-add slide-over pre-filled
  let a;
  try { a = await scApi(`/api/platform/asset/${encodeURIComponent(aid)}`); }
  catch(e) { alert(e.message); return; }
  const id = a.identity || {};
  scOpenSlide("Edit " + aid, _MANUAL_FORM_HTML);
  setTimeout(() => {
    document.getElementById("ma-hostname").value = id.hostname || "";
    document.getElementById("ma-hostname").disabled = true;
    document.getElementById("ma-type").value = id.asset_type || "network";
    document.getElementById("ma-vendor").value = id.vendor || "";
    document.getElementById("ma-model").value = id.model || "";
    document.getElementById("ma-ip").value = id.mgmt_ip || "";
    document.getElementById("ma-url").value = id.mgmt_url || "";
    document.getElementById("ma-site").value = id.site || "";
    document.getElementById("ma-env").value = id.environment || "";
    document.getElementById("ma-owner").value = id.owner || "";
    document.getElementById("ma-team").value = id.team || "";
    document.getElementById("ma-crit").value = id.criticality || "";
    document.getElementById("ma-serial").value = id.serial_number || "";
    // Wire submit to PUT instead of POST
    window._EDIT_AID = aid;
  }, 30);
}

async function invDelete(aid) {
  if (!confirm(`Delete ${aid}?\n\nThis removes the asset from inventory but does not touch the actual device.`))
    return;
  try {
    await scApi(`/api/platform/asset/${encodeURIComponent(aid)}`,
                {method:"DELETE"});
    scCloseSlide(); loadInventory();
  } catch(e) { alert("Delete failed: " + e.message); }
}

async function invAddToGroupOne(aid) {
  const groups = await scApi("/api/platform/asset-groups").catch(() => ({groups:[]}));
  const opts = (groups.groups || []).map(g =>
    `<option value="${g.group_id}">${g.name || g.group_id}</option>`).join("");
  scOpenSlide("Add to group", `
    <p class="muted">Pick an existing group or
       <a href="/groups">create a new one</a> first.</p>
    <select id="atg-id" style="width:100%;padding:8px">${opts}</select>
    <button class="primary" style="margin-top:10px"
            onclick="invAddToGroupCommit(['${aid}'])">Add</button>
  `);
}
function invBulkAddToGroup() {
  const aids = invSelected();
  if (!aids.length) return;
  invAddToGroupOne(""); // open picker; commit will use bulk-selected
  setTimeout(() => {
    const btn = document.querySelector("#scSlideBody button.primary");
    if (btn) btn.setAttribute("onclick",
       `invAddToGroupCommit(${JSON.stringify(aids)})`);
  }, 50);
}
async function invAddToGroupCommit(aids) {
  const gid = document.getElementById("atg-id").value;
  if (!gid) { alert("Pick a group"); return; }
  try {
    const r = await scApi(`/api/platform/asset-groups/${encodeURIComponent(gid)}/members`,
                          {method:"POST", body: JSON.stringify({asset_ids: aids})});
    alert(`Added ${(r.added || []).length} to ${gid}`);
    scCloseSlide();
  } catch(e) { alert(e.message); }
}
async function invBulkDelete() {
  const aids = invSelected();
  if (!aids.length) return;
  if (!confirm(`Delete ${aids.length} asset${aids.length===1?'':'s'}? Cannot be undone.`)) return;
  let ok = 0, failed = [];
  for (const aid of aids) {
    try {
      await scApi(`/api/platform/asset/${encodeURIComponent(aid)}`,
                  {method:"DELETE"});
      ok++;
    } catch(e) { failed.push(aid); }
  }
  alert(`Deleted ${ok}.${failed.length ? " Failed: " + failed.join(", ") : ""}`);
  loadInventory();
}

document.querySelectorAll("#filters button[data-f]").forEach(b => {
  b.addEventListener("click", () => {
    CUR_FILTER = b.dataset.f;
    document.querySelectorAll("#filters button[data-f]").forEach(x =>
      x.style.background = "var(--panel-2)");
    b.style.background = "var(--accent-soft)";
    renderTable();
  });
});

// =============================================================
//  AUTO-DISCOVER  (slide-over)
// =============================================================
function openDiscover() {
  const html = `
    <p class="muted">Probe a CIDR range with ARP + mDNS + TLS/HTTP fingerprint.
       Found devices appear here; tick what you want and click Adopt.</p>

    <label style="font-size:12px;font-weight:600">CIDR range</label>
    <input id="dsc-cidr" type="text" placeholder="10.0.0.0/24"
           value="${(localStorage.getItem('SC_LAST_CIDR')||'')}"
           style="width:100%;padding:8px;border-radius:6px;
                  border:1px solid var(--border);background:var(--bg);
                  color:var(--text);margin-bottom:8px"/>

    <label style="font-size:12px;font-weight:600">Mode</label>
    <select id="dsc-mode" style="width:100%;padding:8px;border-radius:6px;
                  border:1px solid var(--border);background:var(--bg);
                  color:var(--text);margin-bottom:12px">
      <option value="lan_deep">Deep (ARP + mDNS + SNMP) — recommended</option>
      <option value="extended">Extended port scan</option>
      <option value="quick">Quick (default ports)</option>
    </select>

    <button class="primary" id="dsc-run" onclick="runDiscover()">
      🛰  Run discovery</button>

    <div id="dsc-status" class="muted"
         style="margin-top:12px;font-size:12px"></div>
    <div id="dsc-results" style="margin-top:12px"></div>
  `;
  scOpenSlide("Auto-discover devices", html);
}

// v9.3 — streaming discovery via Server-Sent Events.
// Devices appear in the table as soon as they're identified, with a live
// progress bar. EventSource keeps the connection open until the server
// emits a 'done' event.
let _DSC_ES = null;

function runDiscover() {
  const cidr = document.getElementById("dsc-cidr").value.trim();
  const mode = document.getElementById("dsc-mode").value;
  if (!cidr) { alert("CIDR required"); return; }
  localStorage.setItem("SC_LAST_CIDR", cidr);
  const btn  = document.getElementById("dsc-run");
  const stat = document.getElementById("dsc-status");
  const res  = document.getElementById("dsc-results");
  btn.disabled = true; btn.textContent = "Scanning…";
  stat.innerHTML = `<span class="muted">Probing ${cidr} (${mode})…</span>`;
  res.innerHTML = `
    <div style="margin:8px 0">
      <div id="dsc-bar-wrap" style="height:6px;background:var(--panel-2);
           border-radius:3px;overflow:hidden">
        <div id="dsc-bar" style="height:6px;width:0%;
             background:linear-gradient(90deg,#7c5cff,#10b981);
             transition:width 200ms ease"></div>
      </div>
      <div id="dsc-meta" class="muted"
           style="font-size:11px;margin-top:4px">0 / ? scanned</div>
    </div>
    <div style="display:flex;gap:8px;align-items:center;margin:8px 0">
      <button class="alt" style="width:auto;padding:4px 10px;font-size:12px"
              onclick="dscToggleAll(true)">Select all</button>
      <button class="alt" style="width:auto;padding:4px 10px;font-size:12px"
              onclick="dscToggleAll(false)">None</button>
      <span style="flex:1"></span>
      <button class="alt" style="width:auto;padding:4px 10px;font-size:12px"
              onclick="dscCancel()">Cancel</button>
      <button class="primary" style="width:auto;padding:6px 14px;font-size:12px"
              onclick="adoptDiscovered()">📥  Adopt selected</button>
    </div>
    <div class="card" style="padding:0;max-height:340px;overflow:auto">
      <table style="font-size:12px">
        <thead><tr><th></th><th>IP</th><th>Hostname</th><th>Vendor</th>
                   <th>Type</th><th>Risk</th></tr></thead>
        <tbody id="dsc-rows">
          <tr><td colspan="6" class="muted" style="padding:18px;text-align:center">
            Waiting for first device…</td></tr>
        </tbody>
      </table>
    </div>`;

  window._DSC_HOSTS = [];
  const url = `/api/discover/stream?cidr=${encodeURIComponent(cidr)}` +
              `&mode=${encodeURIComponent(mode)}`;
  _DSC_ES = new EventSource(url);

  _DSC_ES.addEventListener("progress", (e) => {
    try {
      const d = JSON.parse(e.data);
      const bar = document.getElementById("dsc-bar");
      const meta = document.getElementById("dsc-meta");
      if (bar) bar.style.width = d.percent + "%";
      if (meta) meta.textContent =
        `${d.scanned} / ${d.total} IPs scanned · ${d.percent}%`;
    } catch (_) {}
  });

  _DSC_ES.addEventListener("host", (e) => {
    try {
      const h = JSON.parse(e.data);
      window._DSC_HOSTS.push(h);
      dscAppendRow(h, window._DSC_HOSTS.length - 1);
    } catch (_) {}
  });

  _DSC_ES.addEventListener("done", (e) => {
    let info = {};
    try { info = JSON.parse(e.data); } catch (_) {}
    stat.innerHTML =
      `<span style="color:#10b981">✓</span> Found ${
         window._DSC_HOSTS.length} device${
         window._DSC_HOSTS.length === 1 ? "" : "s"} in ${
         info.duration_ms || 0}ms (${info.scanned || 0} IPs scanned).`;
    dscClose();
  });

  _DSC_ES.addEventListener("error", (e) => {
    let msg = "stream interrupted";
    try { msg = JSON.parse(e.data).message || msg; } catch (_) {}
    if (e.target && e.target.readyState === 2) msg = "connection closed";
    stat.innerHTML = `<span style="color:#f97373">${msg}</span>`;
    dscClose();
  });
}

function dscAppendRow(h, idx) {
  const tbody = document.getElementById("dsc-rows");
  if (!tbody) return;
  // Drop the placeholder row on first append
  if (tbody.firstElementChild?.querySelector("td.muted")) {
    tbody.innerHTML = "";
  }
  const tr = document.createElement("tr");
  tr.innerHTML = `
    <td><input type="checkbox" data-idx="${idx}" checked class="dsc-pick"/></td>
    <td><code>${h.ip || ""}</code></td>
    <td>${h.hostname || ""}</td>
    <td>${h.vendor || ""}</td>
    <td>${h.device_type || h.category || ""}</td>
    <td>${h.risk_band ? `<span class="pill ${
      h.risk_band === 'critical' ? 'pill-crit' :
      h.risk_band === 'high'     ? 'pill-high' : 'pill-info'}">${
      h.risk_band}</span>` : ''}</td>`;
  // Briefly highlight the new row.
  tr.style.background = "rgba(124,92,255,.10)";
  tbody.appendChild(tr);
  setTimeout(() => { tr.style.transition = "background 600ms";
                     tr.style.background = ""; }, 60);
}

function dscClose() {
  if (_DSC_ES) { _DSC_ES.close(); _DSC_ES = null; }
  const btn = document.getElementById("dsc-run");
  if (btn) { btn.disabled = false; btn.textContent = "🛰  Run discovery"; }
}

function dscCancel() {
  dscClose();
  const stat = document.getElementById("dsc-status");
  if (stat) stat.innerHTML = `<span class="muted">Cancelled.</span>`;
}

function dscToggleAll(on) {
  document.querySelectorAll(".dsc-pick").forEach(c => c.checked = on);
}

async function adoptDiscovered() {
  const picks = Array.from(document.querySelectorAll(".dsc-pick:checked"))
                     .map(c => Number(c.dataset.idx));
  const selected = picks.map(i => window._DSC_HOSTS[i]).filter(Boolean);
  if (!selected.length) { alert("Pick at least one device"); return; }
  // Map UI keys back to bridge.discovered_to_asset's expected dict shape.
  const hosts = selected.map(h => ({
    ip: h.ip, hostname: h.hostname || h.ip, mac: h.mac || "",
    vendor_guess: h.vendor || "", os_guess: h.os || "",
    device_type_guess: h.device_type || h.category || "unknown",
    snmp_sysdescr: h.snmp_sysdescr || "",
    open_ports: h.open_ports || [],
    banners: h.banners || {},
  }));
  try {
    const r = await scApi("/api/platform/adopt-discovered", {
      method: "POST", body: JSON.stringify({ hosts })
    });
    alert(`Adopted ${r.adopted} device${r.adopted === 1 ? "" : "s"}` +
          (r.skipped ? ` (skipped ${r.skipped})` : "."));
    scCloseSlide();
    loadInventory();
  } catch (e) { alert("Adopt failed: " + e.message); }
}

// =============================================================
//  SNMP HARVEST  (LLDP/CDP/MAC table from a router/switch)
// =============================================================
function openSnmpHarvest() {
  const html = `
    <p class="muted">Point at one router or switch with an SNMP community.
       SafeCadence will pull LLDP + CDP neighbors and the bridge forwarding
       table. Single highest-impact source for network gear — one core
       switch routinely yields 50–500 devices.</p>

    <label style="font-size:12px;font-weight:600">Router / switch IP</label>
    <input id="sh-host" type="text" placeholder="10.0.0.1"
           value="${(localStorage.getItem('SC_LAST_SNMP_HOST')||'')}"
           style="width:100%;padding:8px;border-radius:6px;
                  border:1px solid var(--border);background:var(--bg);
                  color:var(--text);margin-bottom:8px"/>

    <div style="display:grid;gap:8px;grid-template-columns:2fr 1fr;margin-bottom:12px">
      <div>
        <label style="font-size:12px;font-weight:600">SNMP community</label>
        <input id="sh-community" type="password"
               placeholder="public (use a real read-only community in prod)"
               style="width:100%;padding:8px;border-radius:6px;
                      border:1px solid var(--border);background:var(--bg);
                      color:var(--text)"/>
      </div>
      <div>
        <label style="font-size:12px;font-weight:600">Version</label>
        <select id="sh-version" style="width:100%;padding:8px;
                border-radius:6px;border:1px solid var(--border);
                background:var(--bg);color:var(--text)">
          <option value="2c">v2c (recommended)</option>
          <option value="1">v1 (legacy)</option>
        </select>
      </div>
    </div>

    <button class="primary" id="sh-run" onclick="runSnmpHarvest()"
            style="background:#06b6d4">📡  Harvest</button>

    <div id="sh-status" class="muted" style="margin-top:12px;font-size:12px"></div>
    <div id="sh-results" style="margin-top:8px"></div>

    <div class="muted" style="margin-top:14px;font-size:11px">
      Requires <code>net-snmp</code> on the SafeCadence host (macOS:
      <code>brew install net-snmp</code>; Debian: <code>apt-get install snmp</code>).
      Use a read-only community — SafeCadence never writes via SNMP.
    </div>
  `;
  scOpenSlide("Harvest from network gear", html);
}

async function runSnmpHarvest() {
  const host = document.getElementById("sh-host").value.trim();
  const community = document.getElementById("sh-community").value.trim() || "public";
  const version = document.getElementById("sh-version").value;
  if (!host) { alert("Router IP required"); return; }
  localStorage.setItem("SC_LAST_SNMP_HOST", host);
  const btn = document.getElementById("sh-run");
  const stat = document.getElementById("sh-status");
  const out  = document.getElementById("sh-results");
  btn.disabled = true; btn.textContent = "Walking…";
  stat.innerHTML = `<span class="muted">Walking ${host} via SNMPv${version}…
                    LLDP, CDP, BRIDGE-MIB. This usually takes 5–30s.</span>`;
  out.innerHTML = "";

  try {
    const r = await scApi("/api/discover/snmp-harvest", {
      method: "POST",
      body: JSON.stringify({ host, community, version }),
    });
    const note = r.error ? `<div style="color:#f9a73e;font-size:11px;margin-top:4px">${r.error}</div>` : "";
    stat.innerHTML = `
      <strong>${r.sys_name || host}</strong>
      <div class="muted" style="font-size:11px;margin-top:2px">
        ${r.sys_descr ? r.sys_descr.slice(0, 120) + (r.sys_descr.length > 120 ? '…' : '') : ''}
      </div>
      <div style="margin-top:6px">
        <span class="pill pill-info">${r.neighbor_count} neighbors</span>
        <span class="pill pill-info">${r.mac_count} MAC entries</span>
      </div>
      ${note}
    `;

    const hosts = r.hosts || [];
    if (!hosts.length) {
      out.innerHTML = `<p class="muted" style="margin-top:12px">
        No LLDP/CDP neighbors. Try checking that LLDP/CDP is enabled on the
        device, or look at the MAC table below for raw L2 visibility.</p>`;
    } else {
      out.innerHTML = `
        <div style="display:flex;gap:8px;align-items:center;margin:12px 0 6px">
          <button class="alt" style="width:auto;padding:4px 10px;font-size:12px"
                  onclick="shToggleAll(true)">Select all</button>
          <button class="alt" style="width:auto;padding:4px 10px;font-size:12px"
                  onclick="shToggleAll(false)">None</button>
          <span style="flex:1"></span>
          <button class="primary" style="width:auto;padding:6px 14px;font-size:12px"
                  onclick="adoptHarvested()">📥  Adopt selected</button>
        </div>
        <div class="card" style="padding:0;max-height:300px;overflow:auto">
          <table style="font-size:12px">
            <thead><tr><th></th><th>Neighbor</th><th>IP</th>
                       <th>via</th><th>Port</th><th>Platform</th></tr></thead>
            <tbody>${hosts.map((h, i) => `
              <tr>
                <td><input type="checkbox" data-idx="${i}" checked
                           class="sh-pick"/></td>
                <td>${h.hostname || h.mac || ""}</td>
                <td><code>${h.ip || ""}</code></td>
                <td>${(h.banners||{})._via || ""}</td>
                <td class="muted" style="font-size:11px">${(h.banners||{})._remote_port || ""}</td>
                <td class="muted" style="font-size:11px">${(h.banners||{})._platform || ""}</td>
              </tr>`).join("")}
            </tbody>
          </table>
        </div>`;
      window._SH_HOSTS = hosts;
    }

    // MAC table summary
    if (r.macs && r.macs.length) {
      const macHtml = `
        <details style="margin-top:14px">
          <summary class="muted" style="cursor:pointer;font-size:12px">
            ${r.macs.length} MAC addresses in bridge forwarding table</summary>
          <div class="card" style="padding:0;max-height:240px;overflow:auto;margin-top:6px">
            <table style="font-size:11px">
              <thead><tr><th>MAC</th><th>Port</th></tr></thead>
              <tbody>${r.macs.slice(0, 200).map(m => `
                <tr><td><code>${m.mac}</code></td><td>${m.port}</td></tr>
              `).join("")}</tbody>
            </table>
          </div>
        </details>`;
      out.innerHTML += macHtml;
    }
  } catch (e) {
    stat.innerHTML = `<span style="color:#f97373">${e.message}</span>`;
  } finally {
    btn.disabled = false; btn.textContent = "📡  Harvest";
  }
}

function shToggleAll(on) {
  document.querySelectorAll(".sh-pick").forEach(c => c.checked = on);
}

async function adoptHarvested() {
  const picks = Array.from(document.querySelectorAll(".sh-pick:checked"))
                     .map(c => Number(c.dataset.idx));
  const selected = picks.map(i => window._SH_HOSTS[i]).filter(Boolean);
  if (!selected.length) { alert("Pick at least one neighbor"); return; }
  try {
    const r = await scApi("/api/platform/adopt-discovered", {
      method: "POST", body: JSON.stringify({ hosts: selected })
    });
    alert(`Adopted ${r.adopted} device${r.adopted === 1 ? "" : "s"}` +
          (r.skipped ? ` (skipped ${r.skipped})` : "."));
    scCloseSlide();
    loadInventory();
  } catch (e) { alert("Adopt failed: " + e.message); }
}

// =============================================================
//  v9.5 — AD / LDAP harvest
// =============================================================
function openAd() {
  scOpenSlide("Pull computers from AD", `
    <p class="muted">Bind to a domain controller and pull every computer
       object. Use a read-only service account.</p>
    <label class="ml">DC server *</label>
    <input id="ad-server" placeholder="dc01.acme.local" />
    <label class="ml">Bind DN *</label>
    <input id="ad-bind" placeholder="CN=svc_safecadence,OU=Service,DC=acme,DC=com" />
    <label class="ml">Password *</label>
    <input id="ad-pass" type="password" />
    <label class="ml">Search base *</label>
    <input id="ad-base" placeholder="DC=acme,DC=com" />
    <label class="ml">LDAP filter</label>
    <input id="ad-filter" placeholder="(objectClass=computer)" />
    <label style="display:flex;gap:6px;font-size:12px;margin-top:8px">
      <input id="ad-ssl" type="checkbox" checked style="width:auto"/> Use LDAPS (recommended)
    </label>
    <button class="primary" style="margin-top:10px;background:#2563eb"
            onclick="runAd()">🪪  Connect & pull</button>
    <div id="ad-status" class="muted" style="margin-top:12px;font-size:12px"></div>
    <div id="ad-out"></div>
    <style>#scSlideBody label.ml{display:block;font-size:11px;font-weight:600;
      margin:6px 0 3px;color:var(--muted)}
      #scSlideBody input,#scSlideBody select{width:100%;padding:7px;
      border-radius:6px;border:1px solid var(--border);background:var(--bg);
      color:var(--text);font-size:12px}</style>
  `);
}
async function runAd() {
  const v = id => (document.getElementById('ad-' + id)?.value || "").trim();
  const body = {
    server: v("server"), bind_dn: v("bind"), password: v("pass"),
    base_dn: v("base"), ldap_filter: v("filter") || "(objectClass=computer)",
    use_ssl: document.getElementById("ad-ssl").checked,
  };
  if (!(body.server && body.bind_dn && body.password && body.base_dn)) {
    alert("Server, bind DN, password, and base DN are all required."); return;
  }
  const stat = document.getElementById("ad-status");
  const out  = document.getElementById("ad-out");
  stat.textContent = "Binding to " + body.server + "…"; out.innerHTML = "";
  try {
    const r = await scApi("/api/discover/ad-harvest",
                          {method:"POST", body: JSON.stringify(body)});
    if (r.error) { stat.innerHTML = `<span style="color:#f97373">${r.error}</span>`; return; }
    stat.innerHTML = `<span style="color:#10b981">✓</span> ${r.count} computer object${r.count===1?'':'s'}`;
    renderHarvested(out, r.hosts || [], "ad");
  } catch (e) { stat.innerHTML = `<span style="color:#f97373">${e.message}</span>`; }
}

// =============================================================
//  v9.5 — Entra ID harvest
// =============================================================
function openEntra() {
  scOpenSlide("Pull devices from Entra ID", `
    <p class="muted">Client-credentials flow. App registration needs
       <code>Device.Read.All</code> with admin consent.</p>
    <label class="ml">Tenant ID *</label>
    <input id="en-tenant" placeholder="00000000-0000-0000-0000-000000000000" />
    <label class="ml">Client ID *</label>
    <input id="en-client" />
    <label class="ml">Client secret *</label>
    <input id="en-secret" type="password" />
    <button class="primary" style="margin-top:10px;background:#0ea5e9"
            onclick="runEntra()">☁️  Connect tenant</button>
    <div id="en-status" class="muted" style="margin-top:12px;font-size:12px"></div>
    <div id="en-out"></div>
  `);
}
async function runEntra() {
  const v = id => (document.getElementById('en-' + id)?.value || "").trim();
  const body = {tenant_id: v("tenant"), client_id: v("client"), client_secret: v("secret")};
  if (!(body.tenant_id && body.client_id && body.client_secret)) {
    alert("All three creds are required."); return;
  }
  const stat = document.getElementById("en-status");
  const out  = document.getElementById("en-out");
  stat.textContent = "Authenticating against login.microsoftonline.com…";
  try {
    const r = await scApi("/api/discover/entra-harvest",
                          {method:"POST", body: JSON.stringify(body)});
    if (r.error) { stat.innerHTML = `<span style="color:#f97373">${r.error}</span>`; return; }
    stat.innerHTML = `<span style="color:#10b981">✓</span> ${r.count} device${r.count===1?'':'s'}`;
    renderHarvested(out, r.hosts || [], "entra");
  } catch (e) { stat.innerHTML = `<span style="color:#f97373">${e.message}</span>`; }
}

// =============================================================
//  v9.5 — DHCP leases
// =============================================================
function openDhcp() {
  scOpenSlide("Import DHCP leases", `
    <p class="muted">Three input modes: read an ISC dhcpd lease file,
       paste it, or paste Windows DHCP CSV.</p>
    <label class="ml">Mode</label>
    <select id="dh-kind" onchange="dhKindChanged()">
      <option value="paste">Paste ISC lease text</option>
      <option value="isc">Read ISC file (server-side)</option>
      <option value="windows">Paste Windows DHCP CSV</option>
    </select>
    <div id="dh-isc-row" style="display:none">
      <label class="ml">Lease file path</label>
      <input id="dh-file" placeholder="/var/lib/dhcp/dhcpd.leases" />
    </div>
    <div id="dh-paste-row">
      <label class="ml">Paste content</label>
      <textarea id="dh-text" style="width:100%;height:140px;padding:7px;
        font-family:monospace;font-size:11px;border-radius:6px;
        border:1px solid var(--border);background:var(--bg);color:var(--text)"
        placeholder='lease 10.0.0.42 { hardware ethernet 00:11:22:33:44:55; ...'></textarea>
    </div>
    <button class="primary" style="margin-top:10px;background:#ef4444"
            onclick="runDhcp()">📋  Import</button>
    <div id="dh-status" class="muted" style="margin-top:12px;font-size:12px"></div>
    <div id="dh-out"></div>
  `);
}
function dhKindChanged() {
  const kind = document.getElementById("dh-kind").value;
  document.getElementById("dh-isc-row").style.display = (kind === "isc") ? "block" : "none";
  document.getElementById("dh-paste-row").style.display = (kind === "isc") ? "none" : "block";
}
async function runDhcp() {
  const kind = document.getElementById("dh-kind").value;
  const body = {kind};
  if (kind === "isc") body.lease_file = document.getElementById("dh-file").value.trim() ||
                                          "/var/lib/dhcp/dhcpd.leases";
  else if (kind === "windows") body.kind = "windows", body.csv_text = document.getElementById("dh-text").value;
  else /* paste */              body.text = document.getElementById("dh-text").value;
  const stat = document.getElementById("dh-status");
  const out  = document.getElementById("dh-out");
  stat.textContent = "Parsing…";
  try {
    const r = await scApi("/api/discover/dhcp-harvest",
                          {method:"POST", body: JSON.stringify(body)});
    if (r.error) { stat.innerHTML = `<span style="color:#f97373">${r.error}</span>`; return; }
    stat.innerHTML = `<span style="color:#10b981">✓</span> ${r.count} lease${r.count===1?'':'s'}`;
    renderHarvested(out, r.hosts || [], "dhcp");
  } catch (e) { stat.innerHTML = `<span style="color:#f97373">${e.message}</span>`; }
}

// =============================================================
//  v9.6 — Cloud (AWS / Azure / GCP)
// =============================================================
function openCloud() {
  scOpenSlide("Pull cloud assets", `
    <p class="muted">Uses your local <code>aws</code>/<code>az</code>/<code>gcloud</code>
       CLI auth chain — SafeCadence never holds cloud creds. If the CLI
       isn't on this host, use paste-mode below.</p>

    <label class="ml">Provider</label>
    <select id="cl-cloud" onchange="clCloudChanged()">
      <option value="aws">AWS — describe-instances</option>
      <option value="azure">Azure — vm list</option>
      <option value="gcp">GCP — compute instances list</option>
    </select>

    <!-- live CLI status + setup help (filled by clRefreshStatus) -->
    <div id="cl-cli-status" class="card"
         style="padding:12px 14px;margin-top:8px;
                background:var(--panel-2);font-size:12px">
      <div class="muted">Probing CLI status…</div>
    </div>

    <div id="cl-aws-row">
      <label class="ml">Profile (optional)</label>
      <input id="cl-profile" placeholder="default" />
      <label class="ml">Region (optional)</label>
      <input id="cl-region" placeholder="us-east-1" />
    </div>
    <div id="cl-az-row" style="display:none">
      <label class="ml">Subscription (optional)</label>
      <input id="cl-sub" />
    </div>
    <div id="cl-gcp-row" style="display:none">
      <label class="ml">Project (optional)</label>
      <input id="cl-project" />
    </div>

    <details id="cl-paste-details" style="margin-top:10px">
      <summary class="muted" style="cursor:pointer;font-size:12px">
        📋  Paste-mode (off-host) — no CLI needed</summary>
      <p class="muted" style="font-size:11px;margin:6px 0">
        Run the command on a machine that has the CLI configured, then
        paste the JSON output here.</p>
      <pre id="cl-paste-cmd" class="muted"
           style="background:var(--bg);padding:6px 8px;border-radius:4px;
                  font-size:11px;margin:6px 0"></pre>
      <textarea id="cl-json" placeholder="paste JSON output here…"
        style="width:100%;height:120px;padding:7px;font-family:monospace;
        font-size:11px;border-radius:6px;border:1px solid var(--border);
        background:var(--bg);color:var(--text)"></textarea>
    </details>

    <button class="primary" style="margin-top:10px;background:#f97316"
            onclick="runCloud()">🌩️  Pull</button>
    <div id="cl-status" class="muted" style="margin-top:12px;font-size:12px"></div>
    <div id="cl-out"></div>
  `);
  clRefreshStatus();
}

// Probe /api/discover/cloud-status once and re-render whenever the
// provider picker changes. Cache results so flipping providers doesn't
// re-probe.
let _CL_STATUS = null;
async function clRefreshStatus() {
  try {
    if (!_CL_STATUS) {
      _CL_STATUS = await scApi("/api/discover/cloud-status");
    }
  } catch (e) {
    _CL_STATUS = {};
  }
  clRenderStatus();
}

function clRenderStatus() {
  const cloud = document.getElementById("cl-cloud").value;
  const key = (cloud === "azure") ? "azure" : cloud;
  const s = (_CL_STATUS || {})[key] || {};
  const card = document.getElementById("cl-cli-status");
  const pasteCmd = document.getElementById("cl-paste-cmd");

  // Update the paste-mode hint command per-provider
  const pasteHint = {
    aws:   "aws ec2 describe-instances --output json",
    azure: "az vm list -d -o json",
    gcp:   "gcloud compute instances list --format=json",
  }[cloud] || "";
  if (pasteCmd) pasteCmd.textContent = "$ " + pasteHint;

  const installed = !!s.installed;
  const authed    = !!s.authed;
  const installCmd  = s.install_hint || "";
  const authCmd     = s.auth_hint || "";
  const minIam      = s.min_iam || "";
  const ident       = s.identity || "";

  let badgeColor, badgeText;
  if (installed && authed) {
    badgeColor = "#10b981"; badgeText = "READY";
  } else if (installed) {
    badgeColor = "#f59e0b"; badgeText = "CLI installed, not authenticated";
  } else {
    badgeColor = "#f97373"; badgeText = "CLI not installed on this host";
  }

  card.innerHTML = `
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
      <span style="display:inline-block;width:8px;height:8px;border-radius:50%;
                   background:${badgeColor}"></span>
      <strong>${badgeText}</strong>
      ${ident ? `<span class="muted" style="margin-left:auto;font-size:11px">
                   as <code>${ident}</code></span>` : ""}
    </div>

    ${(!installed) ? `
      <div style="margin-top:6px">
        <div class="muted" style="margin-bottom:3px">Install:</div>
        <pre style="background:var(--bg);padding:6px 8px;border-radius:4px;
                    font-size:11px;margin:0;white-space:pre-wrap">${installCmd}</pre>
      </div>
      <div style="margin-top:8px">
        <div class="muted" style="margin-bottom:3px">Then authenticate:</div>
        <pre style="background:var(--bg);padding:6px 8px;border-radius:4px;
                    font-size:11px;margin:0">${authCmd}</pre>
      </div>` : ""}

    ${(installed && !authed) ? `
      <div style="margin-top:6px">
        <div class="muted" style="margin-bottom:3px">Authenticate:</div>
        <pre style="background:var(--bg);padding:6px 8px;border-radius:4px;
                    font-size:11px;margin:0">${authCmd}</pre>
        ${s.authed_error ? `<div class="muted" style="font-size:11px;margin-top:4px">
          <em>error: ${s.authed_error}</em></div>` : ""}
      </div>` : ""}

    ${minIam ? `<div class="muted" style="margin-top:8px;font-size:11px">
      <strong>Min permission:</strong> <code>${minIam}</code></div>` : ""}

    ${(!installed || !authed) ? `
      <div style="margin-top:8px;padding:6px 8px;border-left:3px solid #06b6d4;
                  background:var(--bg);font-size:11px">
        ⓘ  Or skip the CLI entirely — use <strong>paste-mode</strong>
        below to paste output from another machine.
      </div>` : ""}

    <div style="margin-top:8px">
      <button class="alt" style="width:auto;padding:3px 8px;font-size:11px"
              onclick="_CL_STATUS=null;clRefreshStatus()">⟳ Re-check</button>
    </div>
  `;

  // If installed+authed and the user hasn't pasted JSON, collapse paste-mode
  const det = document.getElementById("cl-paste-details");
  if (installed && authed) det.removeAttribute("open");
  else                     det.setAttribute("open", "");
}
function clCloudChanged() {
  const c = document.getElementById("cl-cloud").value;
  document.getElementById("cl-aws-row").style.display = (c === "aws") ? "block" : "none";
  document.getElementById("cl-az-row").style.display = (c === "azure") ? "block" : "none";
  document.getElementById("cl-gcp-row").style.display = (c === "gcp") ? "block" : "none";
  clRenderStatus();
}
async function runCloud() {
  const cloud = document.getElementById("cl-cloud").value;
  const body = {cloud};
  if (cloud === "aws") {
    body.profile = (document.getElementById("cl-profile").value || "").trim();
    body.region = (document.getElementById("cl-region").value || "").trim();
  } else if (cloud === "azure") {
    body.subscription = (document.getElementById("cl-sub").value || "").trim();
  } else {
    body.project = (document.getElementById("cl-project").value || "").trim();
  }
  const json = (document.getElementById("cl-json").value || "").trim();
  if (json) body.json_text = json;
  const stat = document.getElementById("cl-status");
  const out  = document.getElementById("cl-out");
  stat.textContent = `Querying ${cloud}…`;
  try {
    const r = await scApi("/api/discover/cloud-harvest",
                          {method:"POST", body: JSON.stringify(body)});
    if (r.error) {
      stat.innerHTML = clFormatError(r.error, cloud);
      return;
    }
    stat.innerHTML = `<span style="color:#10b981">✓</span> ${r.count} instance${r.count===1?'':'s'}`;
    renderHarvested(out, r.hosts || [], cloud);
  } catch (e) {
    stat.innerHTML = clFormatError(e.message || String(e), cloud);
  }
}

// Make the most common errors actionable inline.
function clFormatError(msg, cloud) {
  msg = String(msg || "");
  const lower = msg.toLowerCase();
  // CLI missing → big install/paste-mode CTA
  if (lower.includes("cli not found") || lower.includes("not installed")) {
    return `
      <div style="border-left:3px solid #f97373;padding:8px 12px;
                  background:var(--bg);border-radius:4px">
        <strong style="color:#f97373">${cloud} CLI not found on this host.</strong>
        <div style="margin-top:6px;font-size:12px">Two options:</div>
        <ol style="font-size:12px;margin:4px 0 4px 20px">
          <li>Install + auth the CLI (see status panel above for commands), then
              press Pull again.</li>
          <li>Or skip it: expand <strong>Paste-mode</strong> above, run the
              command on a machine that has the CLI, and paste the JSON.</li>
        </ol>
      </div>`;
  }
  // Auth errors → point to login command
  if (lower.includes("credentials") || lower.includes("not logged in") ||
      lower.includes("expired") || lower.includes("unauthorized")) {
    return `
      <div style="border-left:3px solid #f59e0b;padding:8px 12px;
                  background:var(--bg);border-radius:4px">
        <strong style="color:#f59e0b">Auth failed</strong> — ${msg.slice(0, 200)}
        <div class="muted" style="margin-top:4px;font-size:11px">
          Re-authenticate the CLI then press ⟳ Re-check above.
        </div>
      </div>`;
  }
  return `<span style="color:#f97373">${msg}</span>`;
}

// =============================================================
//  Shared: render + adopt harvested rows
// =============================================================
function renderHarvested(container, hosts, sourceLabel) {
  if (!hosts.length) {
    container.innerHTML = `<p class="muted" style="margin-top:12px">
      No records returned.</p>`;
    return;
  }
  window._HARV_HOSTS = hosts;
  window._HARV_SOURCE = sourceLabel;
  container.innerHTML = `
    <div style="display:flex;gap:8px;align-items:center;margin:10px 0 6px">
      <button class="alt" style="width:auto;padding:4px 10px;font-size:12px"
              onclick="harvToggleAll(true)">Select all</button>
      <button class="alt" style="width:auto;padding:4px 10px;font-size:12px"
              onclick="harvToggleAll(false)">None</button>
      <span style="flex:1"></span>
      <button class="primary" style="width:auto;padding:6px 14px;font-size:12px"
              onclick="adoptHarvestedRows()">📥  Adopt selected</button>
    </div>
    <div class="card" style="padding:0;max-height:300px;overflow:auto">
      <table style="font-size:12px">
        <thead><tr><th></th><th>Hostname</th><th>IP</th><th>Vendor</th>
                   <th>OS</th><th>via</th></tr></thead>
        <tbody>${hosts.map((h, i) => `
          <tr>
            <td><input type="checkbox" data-idx="${i}" checked class="harv-pick"/></td>
            <td>${h.hostname || h.mac || ""}</td>
            <td><code>${h.ip || ""}</code></td>
            <td>${h.vendor_guess || ""}</td>
            <td>${h.os_guess || ""}</td>
            <td class="muted" style="font-size:11px">${(h.banners||{})._via || sourceLabel}</td>
          </tr>`).join("")}
        </tbody>
      </table>
    </div>`;
}
function harvToggleAll(on) {
  document.querySelectorAll(".harv-pick").forEach(c => c.checked = on);
}
async function adoptHarvestedRows() {
  const picks = Array.from(document.querySelectorAll(".harv-pick:checked"))
                     .map(c => Number(c.dataset.idx));
  const selected = picks.map(i => window._HARV_HOSTS[i]).filter(Boolean);
  if (!selected.length) { alert("Pick at least one"); return; }
  try {
    const r = await scApi("/api/platform/adopt-discovered",
                          {method:"POST", body: JSON.stringify({hosts: selected})});
    alert(`Adopted ${r.adopted} record${r.adopted === 1 ? "" : "s"}` +
          (r.skipped ? ` (skipped ${r.skipped})` : "."));
    scCloseSlide(); loadInventory();
  } catch (e) { alert("Adopt failed: " + e.message); }
}

// =============================================================
//  UPLOAD CSV  (slide-over)
// =============================================================
function openUpload() {
  const html = `
    <p class="muted">Bulk-import assets from CSV. Drag a file, paste content,
       or download the template to see the supported columns.</p>

    <a href="/api/platform/import/csv-template" class="alt"
       style="display:inline-block;padding:6px 12px;border-radius:6px;
              background:var(--panel-2);text-decoration:none;color:var(--text);
              font-size:12px;margin-bottom:12px">
      ⬇  Download template CSV
    </a>

    <div id="up-drop" style="border:2px dashed var(--border);
         border-radius:10px;padding:24px;text-align:center;cursor:pointer;
         margin-bottom:8px" onclick="document.getElementById('up-file').click()">
      <div style="font-size:30px">📁</div>
      <div style="font-size:13px;font-weight:600">Drop CSV here or click to choose</div>
      <div class="muted" style="font-size:11px;margin-top:4px">
        Or paste contents below.</div>
    </div>
    <input id="up-file" type="file" accept=".csv,text/csv" style="display:none"/>

    <textarea id="up-paste" placeholder="…or paste CSV here"
              style="width:100%;height:100px;padding:8px;border-radius:6px;
                     border:1px solid var(--border);background:var(--bg);
                     color:var(--text);font-family:monospace;font-size:11px;
                     margin-top:6px"></textarea>

    <button class="primary" id="up-preview" style="margin-top:8px"
            onclick="csvPreview()">Preview</button>

    <div id="up-status" class="muted" style="margin-top:12px;font-size:12px"></div>
    <div id="up-out"></div>
  `;
  scOpenSlide("Upload CSV", html);
  setTimeout(() => {
    const drop = document.getElementById("up-drop");
    const file = document.getElementById("up-file");
    const paste = document.getElementById("up-paste");
    file.addEventListener("change", () => {
      if (!file.files[0]) return;
      const fr = new FileReader();
      fr.onload = e => { paste.value = e.target.result;
                         document.getElementById("up-status").textContent =
                          `Loaded ${file.files[0].name} (${e.target.result.length} bytes)`; };
      fr.readAsText(file.files[0]);
    });
    drop.addEventListener("dragover", e => { e.preventDefault();
                          drop.style.borderColor = "var(--accent)"; });
    drop.addEventListener("dragleave", () => drop.style.borderColor = "var(--border)");
    drop.addEventListener("drop", e => {
      e.preventDefault(); drop.style.borderColor = "var(--border)";
      const f = e.dataTransfer.files[0];
      if (!f) return;
      const fr = new FileReader();
      fr.onload = ev => { paste.value = ev.target.result;
                          document.getElementById("up-status").textContent =
                            `Loaded ${f.name} (${ev.target.result.length} bytes)`; };
      fr.readAsText(f);
    });
  }, 50);
}

async function csvPreview() {
  const csv = document.getElementById("up-paste").value;
  if (!csv.trim()) { alert("Paste or drop a CSV first"); return; }
  const stat = document.getElementById("up-status");
  const out  = document.getElementById("up-out");
  stat.textContent = "Validating…"; out.innerHTML = "";
  try {
    const r = await scApi("/api/platform/import/csv-preview", {
      method: "POST", body: JSON.stringify({ csv })
    });
    stat.innerHTML = `<strong>${r.valid_count}</strong> valid · ` +
                     `<strong style="color:${r.error_count?'#f97373':'inherit'}">` +
                     `${r.error_count}</strong> error${r.error_count===1?'':'s'}`;
    const rows = (r.rows || []).slice(0, 25);
    const hdrs = r.headers || [];
    out.innerHTML = `
      <div class="card" style="padding:0;max-height:280px;overflow:auto;margin-top:8px">
        <table style="font-size:11px">
          <thead><tr>${hdrs.map(h => `<th>${h}</th>`).join('')}<th>status</th></tr></thead>
          <tbody>${rows.map(row => {
            const ok = !row.errors || !row.errors.length;
            return `<tr>${hdrs.map(h => `<td>${(row.values||{})[h]||''}</td>`).join('')}
              <td>${ok ? '<span class="pill pill-ok">ok</span>' :
                         `<span class="pill pill-crit" title="${row.errors.join(', ')}">err</span>`}</td>
            </tr>`;
          }).join('')}</tbody>
        </table>
      </div>
      <button class="primary" style="margin-top:10px"
              onclick="csvCommit()">📥  Commit ${r.valid_count} asset${r.valid_count===1?'':'s'}</button>
      <label style="display:inline-block;margin-left:12px;font-size:12px">
        <input type="checkbox" id="up-overwrite" style="width:auto"/> Overwrite existing
      </label>
    `;
    window._CSV = csv;
  } catch (e) { stat.innerHTML = `<span style="color:#f97373">Failed: ${e.message}</span>`; }
}

async function csvCommit() {
  const csv = window._CSV;
  const overwrite = document.getElementById("up-overwrite")?.checked || false;
  try {
    const r = await scApi("/api/platform/import/csv-commit", {
      method: "POST", body: JSON.stringify({ csv, overwrite })
    });
    alert(`Imported ${r.created || r.imported || 0} asset(s).` +
          (r.skipped ? ` Skipped ${r.skipped}.` : ""));
    scCloseSlide(); loadInventory();
  } catch (e) { alert("Commit failed: " + e.message); }
}

// =============================================================
//  MANUAL ADD DEVICE  (slide-over)
// =============================================================
// Reusable form HTML — used by both Add (POST) and Edit (PUT) flows.
const _MANUAL_FORM_HTML = `
    <p class="muted">Fields marked * are required. AI will auto-derive role,
       criticality, environment, and tags from the hostname after save.</p>

    <div style="display:grid;gap:10px;grid-template-columns:1fr 1fr">
      <div><label class="ml">Hostname *</label>
        <input id="ma-hostname" placeholder="edge-rtr-01.acme.local"/></div>
      <div><label class="ml">Asset type *</label>
        <select id="ma-type">
          <option value="network">network</option>
          <option value="server">server</option>
          <option value="identity">identity</option>
          <option value="cloud">cloud</option>
          <option value="storage">storage</option>
          <option value="backup">backup</option>
          <option value="iot">iot</option>
        </select></div>
      <div><label class="ml">Vendor *</label>
        <input id="ma-vendor" placeholder="cisco"/></div>
      <div><label class="ml">Model</label>
        <input id="ma-model" placeholder="ISR4451-X"/></div>
      <div><label class="ml">Mgmt IP</label>
        <input id="ma-ip" placeholder="10.10.0.1"/></div>
      <div><label class="ml">Mgmt URL</label>
        <input id="ma-url" placeholder="https://10.10.0.1"/></div>
      <div><label class="ml">Site</label>
        <input id="ma-site" placeholder="dc1"/></div>
      <div><label class="ml">Environment</label>
        <select id="ma-env">
          <option value="">(auto)</option><option value="prod">prod</option>
          <option value="staging">staging</option><option value="dev">dev</option>
        </select></div>
      <div><label class="ml">Owner</label>
        <input id="ma-owner" placeholder="Faz Karim"/></div>
      <div><label class="ml">Team</label>
        <input id="ma-team" placeholder="network-eng"/></div>
      <div><label class="ml">Criticality</label>
        <select id="ma-crit">
          <option value="">(auto)</option><option value="crown-jewel">crown-jewel</option>
          <option value="high">high</option><option value="medium">medium</option>
          <option value="low">low</option>
        </select></div>
      <div><label class="ml">Serial</label>
        <input id="ma-serial" placeholder="FXS1929Q3VR"/></div>
    </div>

    <label class="ml" style="margin-top:10px">Notes / business owner</label>
    <textarea id="ma-notes" placeholder="optional"
              style="width:100%;height:50px"></textarea>

    <div style="display:flex;gap:8px;margin-top:14px">
      <button class="primary" onclick="manualSubmit(false)">Save</button>
      <button class="primary" style="background:#7c5cff"
              onclick="manualSubmit(true)">Save + AI enrich</button>
    </div>
    <div id="ma-status" class="muted" style="margin-top:10px;font-size:12px"></div>

    <style>
      #scSlideBody label.ml { display:block;font-size:11px;font-weight:600;
                              margin-bottom:3px;color:var(--muted) }
      #scSlideBody input, #scSlideBody select, #scSlideBody textarea {
        width:100%;padding:7px;border-radius:6px;border:1px solid var(--border);
        background:var(--bg);color:var(--text);font-size:12px;
      }
    </style>
  `;

function openManualAdd() {
  window._EDIT_AID = null;
  scOpenSlide("Add device", _MANUAL_FORM_HTML);
}

async function manualSubmit(enrich) {
  const v = id => (document.getElementById("ma-" + id)?.value || "").trim();
  const payload = {
    hostname: v("hostname"), asset_type: v("type"), vendor: v("vendor"),
    model: v("model"), mgmt_ip: v("ip"), mgmt_url: v("url"),
    site: v("site"), environment: v("env"), owner: v("owner"),
    team: v("team"), criticality: v("crit"), serial_number: v("serial"),
    notes: v("notes"), enrich_ai: !!enrich,
  };
  if (!payload.hostname || !payload.asset_type || !payload.vendor) {
    alert("Hostname, type, and vendor are required."); return;
  }
  const stat = document.getElementById("ma-status");
  stat.textContent = "Saving…";
  // v9.12 — if _EDIT_AID is set, PUT instead of POST
  const editing = !!window._EDIT_AID;
  const url = editing
    ? `/api/platform/asset/${encodeURIComponent(window._EDIT_AID)}`
    : "/api/platform/asset";
  const method = editing ? "PUT" : "POST";
  try {
    const r = await scApi(url, {method, body: JSON.stringify(payload)});
    stat.innerHTML = `<span style="color:#10b981">✓</span> ` +
      (editing ? `Updated <code>${window._EDIT_AID}</code>`
               : `Saved as <code>${r.asset_id}</code>` +
                 (r.enriched ? ` · enriched (${r.enriched_role||'?'})` : ""));
    setTimeout(() => { scCloseSlide(); window._EDIT_AID = null; loadInventory(); }, 700);
  } catch (e) { stat.innerHTML = `<span style="color:#f97373">${e.message}</span>`; }
}

// v9.20.1 — auto-open a hero card from ?open=<source> query param.
// Lets /coverage and other pages deep-link to the right slide-over.
(function() {
  const q = new URLSearchParams(location.search);
  const open = (q.get("open") || "").toLowerCase();
  const map = {
    "lan-scan": "openDiscover", "discover": "openDiscover",
    "snmp": "openSnmpHarvest",
    "ad": "openAd", "ldap": "openAd",
    "entra": "openEntra",
    "dhcp": "openDhcp",
    "cloud": "openCloud", "aws": "openCloud",
    "azure": "openCloud", "gcp": "openCloud",
    "upload": "openUpload", "csv": "openUpload",
    "manual": "openManualAdd", "add": "openManualAdd",
  };
  const fn = map[open];
  if (fn && typeof window[fn] === "function") {
    setTimeout(() => {
      window[fn]();
      // For cloud, pre-pick the right provider after the slide-over renders
      if (fn === "openCloud" && ["aws","azure","gcp"].includes(open)) {
        setTimeout(() => {
          const sel = document.getElementById("cl-cloud");
          if (sel) { sel.value = open; if (window.clCloudChanged) clCloudChanged(); }
        }, 80);
      }
    }, 250);
  }
})();

loadColPrefs();
loadInventory();
"""


# ---------------------------------------------------------------- findings


_FINDINGS_BODY = """
<h1>Findings <span class="sc-help" data-help="finding-kind"></span></h1>
<p class="muted" id="subtitle">Loading…</p>

<div class="card" style="padding:0">
  <table id="tbl">
    <thead><tr>
      <th>Severity</th><th>Kind</th><th>Title</th>
      <th>Principal</th><th></th>
    </tr></thead>
    <tbody><tr><td colspan="5" class="muted" style="padding:36px;text-align:center">Loading…</td></tr></tbody>
  </table>
</div>
"""

_FINDINGS_SCRIPT = r"""
async function loadFindings() {
  try {
    const r = await scApi("/api/identity/findings");
    const fs = r.findings || [];
    document.getElementById("subtitle").textContent =
      `${fs.length} open · ${fs.filter(f => f.severity === 'critical').length} critical`;
    const tbody = document.querySelector("#tbl tbody");
    if (!fs.length) {
      tbody.innerHTML = `<tr><td colspan="5" class="muted" style="padding:48px;text-align:center">
        🎉 No findings. Your fleet looks healthy. <a href="/automation">Set up automation</a>
        to alert when one appears.</td></tr>`;
      return;
    }
    tbody.innerHTML = fs.map(f => {
      const sev = f.severity === "critical" || f.severity === "high" ? "pill-crit"
                : f.severity === "medium" ? "pill-high" : "pill-info";
      const ir = JSON.stringify(JSON.stringify(f.suggested_ir || {}));
      return `<tr>
        <td><span class="pill ${sev}">${(f.severity || '').toUpperCase()}</span></td>
        <td>${f.kind}</td>
        <td>${f.title}</td>
        <td class="muted">${f.principal || ''}</td>
        <td><button class="alt" style="width:auto;padding:4px 12px;font-size:12px"
                    onclick='showIR(${ir}, "${f.finding_id}")'>View IR</button></td>
      </tr>`;
    }).join("");
  } catch (e) {
    document.querySelector("#tbl tbody").innerHTML =
      `<tr><td colspan="5" class="muted">Failed: ${e.message}</td></tr>`;
  }
}

function showIR(irStr, fid) {
  let ir;
  try { ir = JSON.parse(irStr); } catch(e) { ir = {}; }
  const html = `
    <p class="muted">Suggested remediation IR for <code>${fid}</code></p>
    <pre>${JSON.stringify(ir, null, 2)}</pre>
    <button class="primary" style="margin-top:12px"
            onclick='applyAutoFix("${fid}")'>Auto-fix (dry-run)</button>
  `;
  scOpenSlide("Finding " + fid, html);
}

// v9.33 #3 — auto-fix now renders a real per-system diff card and
// only commits after the operator clicks through. Trust property:
// no external write happens without a visible diff + a click.
async function applyAutoFix(fid) {
  try {
    const r = await scApi(`/api/identity/auto-fix/${fid}?dry_run=true`,
                          { method: "POST" });
    renderDiffCard(fid, r.result || {});
  } catch (e) { alert(e.message); }
}

// Reusable diff card. Takes the dry-run ApplyResult and renders it
// per-system with an "I've reviewed this — commit" CTA.
function renderDiffCard(fid, result) {
  const target = result.target || "?";
  const ops = (result.operations || []);
  const warns = (result.warnings || []);
  const tok = result.confirm_token || "";
  const sevPill = ops[0]?.risk === "critical" ? "pill-crit"
                : ops[0]?.risk === "high" ? "pill-high" : "pill-info";

  const opsHTML = ops.length ? ops.map(o => `
    <div class="card" style="padding:12px;margin-top:8px">
      <div style="display:flex;align-items:center;gap:8px">
        <span class="pill ${sevPill}">${(o.risk || 'info').toUpperCase()}</span>
        <strong>${o.op_kind || '?'}</strong>
        <span class="muted" style="margin-left:auto">${o.summary || ''}</span>
      </div>
      <details style="margin-top:8px"><summary class="muted" style="cursor:pointer;font-size:12px">payload</summary>
        <pre style="font-size:11px;margin-top:6px">${JSON.stringify(o.payload || {}, null, 2)}</pre>
      </details>
    </div>`).join("") : `<p class="muted">No operations — nothing would change.</p>`;

  const warnHTML = warns.length ? `
    <div class="card" style="padding:12px;margin-top:12px;border-left:3px solid #f5a623">
      <strong>Warnings</strong>
      <ul style="margin:6px 0 0 20px">${warns.map(w => `<li>${w}</li>`).join("")}</ul>
    </div>` : "";

  const errHTML = result.error ? `
    <div class="card" style="padding:12px;margin-top:12px;border-left:3px solid #d04646">
      <strong>Error</strong><div>${result.error}</div>
    </div>` : "";

  const commitBtn = (tok && !result.error) ? `
    <button class="primary" style="margin-top:16px;width:100%"
            id="diff-commit-btn"
            onclick='commitFromDiff("${fid}", "${tok}")'>
      I've reviewed this — commit to ${target}
    </button>
    <p class="muted" style="font-size:11px;margin-top:8px">
      Commit posts to /api/identity/auto-fix/${fid}?dry_run=false with this
      confirm_token. The token is bound to the IR + target + your username
      and expires in 10 minutes.
    </p>` : `
    <p class="muted" style="margin-top:12px">
      No commit available — this is a preview only. Fix the error above
      and re-run the dry-run.
    </p>`;

  const html = `
    <p class="muted">Auto-fix preview for <code>${fid}</code></p>
    <div style="display:flex;align-items:center;gap:8px;margin:12px 0">
      <span class="pill pill-info">target: ${target}</span>
      <span class="pill pill-info">dry-run</span>
      <span class="muted" style="margin-left:auto;font-size:11px">
        no external write has happened yet
      </span>
    </div>
    ${opsHTML}
    ${warnHTML}
    ${errHTML}
    <div id="diff-result"></div>
    ${commitBtn}
  `;
  scOpenSlide("Diff — " + target, html);
}

async function commitFromDiff(fid, token) {
  const btn = document.getElementById("diff-commit-btn");
  if (btn) { btn.disabled = true; btn.textContent = "Committing…"; }
  const out = document.getElementById("diff-result");
  try {
    const url = `/api/identity/auto-fix/${fid}?dry_run=false`
              + `&confirm_token=${encodeURIComponent(token)}`;
    const r = await scApi(url, { method: "POST" });
    const res = r.result || {};
    if (res.error) {
      out.innerHTML = `<div class="card" style="padding:12px;margin-top:12px;border-left:3px solid #d04646">
        <strong>Commit failed:</strong> ${res.error}</div>`;
      if (btn) { btn.disabled = false; btn.textContent = "Try again"; }
    } else {
      out.innerHTML = `<div class="card" style="padding:12px;margin-top:12px;border-left:3px solid #2ea44f">
        <strong>✓ Committed</strong>
        <div class="muted" style="margin-top:4px">
          ${(res.committed_ids || []).length} change(s) applied to ${res.target}.
        </div>
      </div>`;
      if (btn) { btn.style.display = "none"; }
    }
  } catch (e) {
    // 409 conflict = stale dry-run, the most common failure mode.
    out.innerHTML = `<div class="card" style="padding:12px;margin-top:12px;border-left:3px solid #d04646">
      <strong>Preview is stale.</strong>
      <div class="muted" style="margin-top:4px">${e.message}</div>
      <button class="alt" style="margin-top:8px;width:auto;padding:4px 12px"
              onclick='applyAutoFix("${fid}")'>Re-run dry-run</button>
    </div>`;
    if (btn) { btn.style.display = "none"; }
  }
}

loadFindings();
"""


# ---------------------------------------------------------------- jit


_JIT_BODY = """
<h1>Just-in-Time grants</h1>
<p class="muted" id="subtitle">Loading…</p>

<!-- v9.33 #7 — JIT hero band -->
<div class="grid-3" style="margin-top:8px">
  <div class="card" style="padding:14px">
    <div class="muted" style="font-size:11px">ACTIVE</div>
    <div id="jit-active" style="font-size:24px;font-weight:600">…</div>
    <div class="muted" style="font-size:11px">currently granted</div>
  </div>
  <div class="card" style="padding:14px">
    <div class="muted" style="font-size:11px">EXPIRING</div>
    <div id="jit-expiring" style="font-size:24px;font-weight:600">…</div>
    <div class="muted" style="font-size:11px">in next 24 hours</div>
  </div>
  <div class="card" style="padding:14px">
    <div class="muted" style="font-size:11px">EXPIRED — TO REVOKE</div>
    <div id="jit-stale" style="font-size:24px;font-weight:600">…</div>
    <div class="muted" style="font-size:11px">awaiting commit to target</div>
  </div>
</div>

<div class="card" style="padding:0;margin-top:16px">
  <table id="tbl">
    <thead><tr>
      <th>Status</th><th>Principal</th><th>Action</th><th>Resource</th>
      <th>Target</th><th>Expires</th>
    </tr></thead>
    <tbody><tr><td colspan="6" class="muted" style="padding:36px;text-align:center">Loading…</td></tr></tbody>
  </table>
</div>

<div style="margin-top:16px">
  <a href="/identity#jit-tbl" class="alt"
     style="display:inline-block;padding:8px 16px;border-radius:8px;
            background:var(--panel-2);text-decoration:none;color:var(--text)">
    + Grant new JIT access
  </a>
</div>
"""

_JIT_SCRIPT = r"""
async function loadJIT() {
  try {
    const r = await scApi("/api/identity/jit/list");
    const grants = r.grants || [];
    const active = grants.filter(g => g.status === 'active');
    const now = Date.now() / 1000;
    const expiring = active.filter(g => g.expires_at - now < 86400);
    const stale = grants.filter(g => g.status === 'expired');
    // v9.33 #7 — surface counts in the hero band.
    const set = (id, v) => { const e = document.getElementById(id); if (e) e.textContent = v; };
    set("jit-active", active.length);
    set("jit-expiring", expiring.length);
    set("jit-stale", stale.length);
    document.getElementById("subtitle").textContent =
      `${grants.length} total · ${active.length} active`;
    const tbody = document.querySelector("#tbl tbody");
    if (!grants.length) {
      tbody.innerHTML = `<tr><td colspan="6" class="muted" style="padding:48px;text-align:center">
        No JIT grants yet. <a href="/identity#jit-tbl">Issue your first one</a> for
        time-bounded access (auto-revokes when expired).</td></tr>`;
      return;
    }
    tbody.innerHTML = grants.map(g => {
      const sev = g.status === "active" ? "pill-ok"
                : g.status === "expired" ? "pill-info" : "pill-high";
      const exp = new Date(g.expires_at * 1000);
      return `<tr>
        <td><span class="pill ${sev}">${g.status}</span></td>
        <td>${g.principal}</td>
        <td>${g.action}</td>
        <td>${g.resource}</td>
        <td>${g.target}</td>
        <td>${exp.toLocaleString()}</td>
      </tr>`;
    }).join("");
  } catch (e) {
    document.querySelector("#tbl tbody").innerHTML =
      `<tr><td colspan="6" class="muted">Failed: ${e.message}</td></tr>`;
  }
}
loadJIT();
"""


# ---------------------------------------------------------------- attack paths


_PATHS_BODY = """
<h1>Identity attack paths <span class="sc-help" data-help="path-chain"></span></h1>
<p class="muted" id="subtitle">Loading…</p>

<!-- v9.33 #8 — paths hero band -->
<div class="grid-3" style="margin-top:8px">
  <div class="card" style="padding:14px">
    <div class="muted" style="font-size:11px">TOTAL PATHS</div>
    <div id="paths-total" style="font-size:24px;font-weight:600">…</div>
  </div>
  <div class="card" style="padding:14px">
    <div class="muted" style="font-size:11px">CRITICAL (risk ≥ 7)</div>
    <div id="paths-crit" style="font-size:24px;font-weight:600;color:#fda4af">…</div>
  </div>
  <div class="card" style="padding:14px">
    <div class="muted" style="font-size:11px">BLAST-RADIUS p95</div>
    <div id="paths-p95" style="font-size:24px;font-weight:600">…</div>
    <div class="muted" style="font-size:11px">assets reachable from worst path</div>
  </div>
</div>

<div class="card" style="padding:0;margin-top:16px">
  <table id="tbl">
    <thead><tr>
      <th>Risk <span class="sc-help" data-help="path-risk"></span></th>
      <th>Chain</th><th>Terminal asset</th><th></th>
    </tr></thead>
    <tbody><tr><td colspan="4" class="muted" style="padding:36px;text-align:center">Loading…</td></tr></tbody>
  </table>
</div>
"""

_PATHS_SCRIPT = r"""
async function loadPaths() {
  try {
    const r = await scApi("/api/identity/attack-paths");
    const paths = r.paths || [];
    // v9.33 #8 — feed the hero band.
    const set = (id, v) => { const e = document.getElementById(id); if (e) e.textContent = v; };
    set("paths-total", paths.length);
    set("paths-crit",  paths.filter(p => (p.risk_score || 0) >= 7).length);
    const worst = paths[0];
    set("paths-p95", worst ? (worst.terminal_asset || "—") : "—");
    document.getElementById("subtitle").textContent =
      `${paths.length} paths detected · ranked by risk`;
    const tbody = document.querySelector("#tbl tbody");
    if (!paths.length) {
      tbody.innerHTML = `<tr><td colspan="4" class="muted" style="padding:48px;text-align:center">
        🎉 No identity attack paths detected. <a href="/automation">Set up an
        automation rule</a> to alert if one appears.</td></tr>`;
      return;
    }
    tbody.innerHTML = paths.map(p => {
      const risk = p.risk_score >= 7 ? "pill-crit"
                 : p.risk_score >= 4 ? "pill-high" : "pill-info";
      const chain = JSON.stringify(p.chain_summary);
      return `<tr>
        <td><span class="pill ${risk}">${p.risk_score.toFixed(1)}</span></td>
        <td>${p.chain_summary}</td>
        <td>${p.terminal_asset}</td>
        <td><button class="alt" style="width:auto;padding:4px 12px;font-size:12px"
                    onclick='remediatePath(${chain})'>Remediate</button></td>
      </tr>`;
    }).join("");
  } catch (e) {
    document.querySelector("#tbl tbody").innerHTML =
      `<tr><td colspan="4" class="muted">Failed: ${e.message}</td></tr>`;
  }
}

async function remediatePath(chain) {
  try {
    const r = await scApi("/api/identity/remediate-path", {
      method: "POST",
      body: JSON.stringify({ chain_summary: chain }),
    });
    scOpenSlide("Severing IR", `
      <p class="muted">This IR severs the attack path. Review and apply via
      the identity translator.</p>
      <pre>${JSON.stringify(r.ir, null, 2)}</pre>
      <a href="/identity" class="primary"
         style="display:inline-block;padding:8px 16px;border-radius:8px;
                background:var(--accent);color:#fff;text-decoration:none;
                margin-top:12px">Open identity translator →</a>
    `);
  } catch (e) { alert(e.message); }
}
loadPaths();
"""


# ---------------------------------------------------------------- watchlists


_WATCHLISTS_BODY = """
<h1>Watchlists</h1>
<p class="muted">Pin assets, NHIs, principals, or findings.
Daemon flags any change in your morning briefing.</p>

<div class="card" style="padding:0">
  <table id="tbl">
    <thead><tr>
      <th>Watching</th><th>Kind</th><th>Last change</th><th></th>
    </tr></thead>
    <tbody><tr><td colspan="4" class="muted" style="padding:36px;text-align:center">Loading…</td></tr></tbody>
  </table>
</div>

<div style="margin-top:16px" class="muted">
  Tip: open any asset (e.g. <a href="/inventory">/inventory</a> →
  click a row) and use the "+ Watchlist" button.
</div>
"""

_WATCHLISTS_SCRIPT = r"""
async function loadWatchlists() {
  try {
    const r = await scApi("/api/intel/watchlists");
    const ws = r.watches || [];
    const tbody = document.querySelector("#tbl tbody");
    if (!ws.length) {
      tbody.innerHTML = `<tr><td colspan="4" class="muted" style="padding:48px;text-align:center">
        No watchlist entries yet.<br/>Open <a href="/inventory">Inventory</a>
        and click "+ Watchlist" on any asset.</td></tr>`;
      return;
    }
    tbody.innerHTML = ws.map(w => {
      const lastChange = w.last_change_at
        ? new Date(w.last_change_at * 1000).toLocaleString() : "—";
      return `<tr>
        <td>${w.label}</td>
        <td><span class="pill">${w.entity_kind}</span></td>
        <td class="muted">${lastChange}<br/><small>${w.last_change_summary || ''}</small></td>
        <td><button class="alt" style="width:auto;padding:4px 12px;font-size:12px;background:#7f1d1d;color:#fff;border:0"
                    onclick='removeWatch("${w.watch_id}")'>Remove</button></td>
      </tr>`;
    }).join("");
  } catch (e) {
    document.querySelector("#tbl tbody").innerHTML =
      `<tr><td colspan="4" class="muted">Failed: ${e.message}</td></tr>`;
  }
}
async function removeWatch(id) {
  try {
    await scApi(`/api/intel/watchlists/${id}`, { method: "DELETE" });
    loadWatchlists();
  } catch (e) { alert(e.message); }
}
loadWatchlists();
"""


# ---------------------------------------------------------------- policies


_POLICIES_BODY = """
<h1>Policies <span class="sc-help" data-help="policy-targeting"></span></h1>
<p class="muted" id="subtitle">Loading…</p>

<!-- How policies work — collapsible primer -->
<details class="card" style="padding:14px 16px;margin-bottom:16px">
  <summary style="cursor:pointer;font-weight:600">
    📐 How policies apply across mixed fleets
    <span class="sc-help" data-help="policies-mixed-fleets"></span>
  </summary>
  <div style="margin-top:12px;font-size:13px;line-height:1.6">
    <p><strong>Four targeting layers</strong> (use the highest one that fits):</p>
    <ol style="margin:8px 0 12px 24px">
      <li><strong>Tag</strong> — <code>env:prod AND compliance:pci</code> →
          cross-cuts vendors and asset types. Most durable.</li>
      <li><strong>Asset group</strong> — saved query like <em>"DC1 crown jewels"</em>.</li>
      <li><strong>Asset type / vendor</strong> — when the syntax matters
          (e.g. only Cisco IOS).</li>
      <li><strong>Individual asset</strong> — escape hatch for one-offs.</li>
    </ol>
    <p><strong>Same intent, different vendors → automatic.</strong> One Unified
    Policy IR fans out via per-vendor translators (Cisco IOS, NX-OS, Arista,
    Palo Alto, Juniper, Aruba…) so you author once, SafeCadence emits the
    right CLI per device.</p>
    <p><strong>Asset can't comply?</strong> Add an
    <span class="sc-help" data-help="policies-exception"></span>
    exception with reason + expiry + compensating control instead of
    weakening the policy.</p>
  </div>
</details>

<div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap">
  <button class="primary" style="width:auto;padding:8px 16px"
          onclick="location.href='/identity'">+ New identity policy</button>
  <button class="alt" style="width:auto;padding:8px 16px"
          onclick="alert('Compliance policy builder — legacy at /legacy until v9.2')">
    + New compliance policy</button>
  <span style="flex:1"></span>
  <button class="alt" style="width:auto;padding:8px 16px"
          onclick="location.href='/simulate'">🔮 Simulate policy</button>
</div>

<div class="card" style="padding:0">
  <table id="tbl">
    <thead><tr>
      <th>Policy</th><th>Targeting</th><th>Matched</th>
      <th>Last eval</th><th>Status</th>
    </tr></thead>
    <tbody><tr><td colspan="5" class="muted" style="padding:36px;text-align:center">Loading…</td></tr></tbody>
  </table>
</div>
"""

_POLICIES_SCRIPT = r"""
async function loadPolicies() {
  let policies = [];
  try {
    const r = await scApi("/api/policy/");
    policies = r.policies || [];
  } catch (e) {
    document.querySelector("#tbl tbody").innerHTML =
      `<tr><td colspan="5" class="muted">No policies endpoint reachable: ${e.message}.</td></tr>`;
    document.getElementById("subtitle").textContent = "Endpoint unavailable";
    return;
  }
  document.getElementById("subtitle").textContent =
    `${policies.length} policies defined · click any row to see targeting + per-vendor preview`;
  if (!policies.length) {
    document.querySelector("#tbl tbody").innerHTML = `
      <tr><td colspan="5" class="muted" style="padding:48px;text-align:center">
        🌱 No policies yet. <a href="/identity">Author your first identity policy</a>
        with the AI translator, or <a href="/legacy">use the compliance builder</a>.
      </td></tr>`;
    return;
  }
  document.querySelector("#tbl tbody").innerHTML = policies.map(p => {
    const t = p.targeting || p.target || {};
    const targetParts = [];
    if ((t.tags||[]).length)         targetParts.push(`<code>tags:${t.tags.join(",")}</code>`);
    if ((t.asset_types||[]).length)  targetParts.push(`<code>type:${t.asset_types.join(",")}</code>`);
    if ((t.vendors||[]).length)      targetParts.push(`<code>vendor:${t.vendors.join(",")}</code>`);
    if ((t.environments||[]).length) targetParts.push(`<code>env:${t.environments.join(",")}</code>`);
    if ((t.criticalities||[]).length)targetParts.push(`<code>crit:${t.criticalities.join(",")}</code>`);
    if ((t.asset_ids||[]).length)    targetParts.push(`${t.asset_ids.length} explicit`);
    if (!targetParts.length)         targetParts.push('<em class="muted">fleet-wide</em>');
    const matched = p.matched_count !== undefined ? p.matched_count : (p.target_count || "—");
    const last = p.last_evaluated_at || p.last_run || "never";
    const passing = p.compliance_pct !== undefined ? p.compliance_pct + "%" : "—";
    const cls = (passing === "—") ? "" :
                Number(p.compliance_pct) >= 80 ? "pill-ok" :
                Number(p.compliance_pct) >= 60 ? "pill-high" : "pill-crit";
    return `<tr style="cursor:pointer" onclick='showPolicy(${JSON.stringify(JSON.stringify(p))})'>
      <td><strong>${p.policy_name || p.name || p.policy_id}</strong>
          <div class="muted" style="font-size:11px">${p.policy_id || ""}</div></td>
      <td>${targetParts.join(" · ")}</td>
      <td>${matched}</td>
      <td class="muted">${last}</td>
      <td>${cls ? `<span class="pill ${cls}">${passing}</span>` : passing}</td>
    </tr>`;
  }).join("");
}

function showPolicy(jsonStr) {
  let p;
  try { p = JSON.parse(JSON.parse(jsonStr)); } catch (e) {
    try { p = JSON.parse(jsonStr); } catch { p = {}; }
  }
  const t = p.targeting || p.target || {};
  const html = `
    <div class="muted" style="margin-bottom:8px">${p.policy_id || ""}</div>
    <h3 style="margin:0 0 8px">${p.policy_name || p.name || "(unnamed)"}</h3>
    <div style="margin-top:12px"><strong>Targeting</strong>
      <pre style="margin-top:6px">${JSON.stringify(t, null, 2)}</pre></div>
    <div style="margin-top:12px"><strong>Controls</strong>
      <pre style="margin-top:6px">${JSON.stringify(p.controls || p.control_ids || [], null, 2)}</pre></div>
    <div style="margin-top:12px"><strong>Full record</strong>
      <pre style="margin-top:6px;max-height:200px;overflow:auto">${JSON.stringify(p, null, 2)}</pre></div>
    <div style="display:flex;gap:8px;margin-top:14px">
      <button class="primary" style="width:auto;padding:8px 16px"
              onclick='policyPreviewVendor(${JSON.stringify(p)})'>
        Preview per-vendor</button>
      <button class="alt" style="width:auto;padding:8px 16px"
              onclick='policyAddException(${JSON.stringify(p.policy_id || p.id || "")})'>
        Add exception</button>
    </div>
    <div id="pol-preview-out" style="margin-top:14px"></div>
  `;
  scOpenSlide(p.policy_name || "Policy", html);
}

// v9.37 — wire previously-stub buttons to the real APIs that shipped
// in v9.31 (preview-config) and v9.32 (policy changes / exceptions).
async function policyPreviewVendor(policy) {
  const out = document.getElementById("pol-preview-out");
  if (!out) return;
  out.innerHTML = '<div class="muted">Rendering vendor preview…</div>';
  try {
    const r = await scApi("/api/policy/preview-config", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({policy: policy, vendor: "cisco_ios"}),
    });
    const cfg = (r && (r.config || r.preview)) || "";
    out.innerHTML =
      '<div><strong>cisco_ios preview (shape-only)</strong>' +
      '<pre style="max-height:240px;overflow:auto;margin-top:6px">' +
      (cfg || "// no config rendered").replace(/[<>&]/g, c =>
        ({"<":"&lt;",">":"&gt;","&":"&amp;"}[c])) +
      "</pre></div>";
  } catch (e) {
    out.innerHTML =
      '<div class="muted">Preview failed: ' + (e.message || e) + '</div>';
  }
}

async function policyAddException(policyId) {
  if (!policyId) {
    alert("This policy has no policy_id; can't attach an exception.");
    return;
  }
  const reason = prompt(
    "Exception reason (one line, will be stored in the audit trail):");
  if (!reason) return;
  try {
    await scApi("/api/policy/changes", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        policy_id: policyId,
        kind: "exception",
        reason: reason,
      }),
    });
    alert("Exception submitted for review.");
  } catch (e) {
    alert("Failed to submit exception: " + (e.message || e));
  }
}

loadPolicies();
"""


# ---------------------------------------------------------------- stub maker


def _stub_body(title: str, blurb: str, related: list[tuple[str, str]]) -> str:
    """Generic 'this view is coming' page with helpful redirects."""
    rel_html = "".join(
        f'<li><a href="{href}">{label}</a></li>' for label, href in related
    )
    return f"""
<h1>{title}</h1>
<p class="muted">{blurb}</p>

<div class="card" style="text-align:center;padding:48px">
  <div style="font-size:36px">🚧</div>
  <h3 style="margin:12px 0 4px">This view ships in v9.1</h3>
  <p class="muted">The data + engine already work. We're polishing the v9
  surface for it next. In the meantime:</p>
  <ul style="display:inline-block;text-align:left;margin-top:12px">{rel_html}</ul>
  <p class="muted" style="margin-top:16px">
    <a href="/legacy">Or use the legacy UI</a> for the full feature set.
  </p>
</div>
"""


# ---------------------------------------------------------------- shadow-IT


_SHADOW_BODY = """
<h1>Shadow IT</h1>
<p class="muted">Devices SafeCadence has seen via active probes (LAN scan,
   SNMP, DHCP, cloud) but that are <strong>missing from declarative
   sources</strong> — Active Directory, Entra, CMDB, manual additions.
   Every row is a candidate worth investigating.</p>

<div class="card" id="summary-card" style="margin-bottom:14px">
  <div class="muted">Loading…</div>
</div>

<div style="display:flex;gap:8px;margin-bottom:8px;align-items:center">
  <h2 style="margin:0;font-size:18px">Candidates</h2>
  <span style="flex:1"></span>
  <button class="alt" style="width:auto;padding:6px 12px;font-size:12px"
          onclick="location.reload()">⟳ Refresh</button>
</div>

<div class="card" style="padding:0">
  <table id="shadow-tbl">
    <thead><tr>
      <th>Hostname</th><th>IP</th><th>Type</th><th>Vendor</th><th>Sources</th>
    </tr></thead>
    <tbody><tr><td colspan="5" class="muted" style="padding:36px;text-align:center">
      Loading…</td></tr></tbody>
  </table>
</div>

<p class="muted" style="margin-top:16px;font-size:12px">
  💡 Once you have AD or CMDB connected, this list is your weekly
  triage. Each device is either rogue (and should be removed) or
  legitimate (and should be added to the CMDB so it stops appearing here).
</p>
"""

_SHADOW_SCRIPT = r"""
async function loadShadow() {
  try {
    const r = await scApi("/api/platform/shadow-it");
    const items = r.shadow_it || [];
    const counts = r.counts_by_source || {};
    const sources = Object.keys(counts).sort();

    const summary = document.getElementById("summary-card");
    summary.innerHTML = `
      <div style="display:flex;gap:14px;align-items:baseline;flex-wrap:wrap">
        <div><strong style="font-size:24px">${r.shadow_it_count}</strong>
             <span class="muted">shadow-IT candidates</span></div>
        <span class="muted">·</span>
        <div class="muted" style="font-size:12px">
          ${sources.length} source${sources.length===1?'':'s'}:
          ${sources.map(s => `<span class="pill pill-info">${s}=${counts[s]}</span>`).join(" ")}
        </div>
      </div>
      <div class="muted" style="margin-top:8px;font-size:12px">${r.summary || ""}</div>
    `;

    const tbody = document.querySelector("#shadow-tbl tbody");
    if (!items.length) {
      tbody.innerHTML = `<tr><td colspan="5" class="muted" style="padding:48px;text-align:center">
        🎉 No shadow IT detected. Every device seen by an active probe
        also appears in a declarative source.</td></tr>`;
      return;
    }
    tbody.innerHTML = items.map(s => `
      <tr style="cursor:pointer" onclick="location.href='/asset/${encodeURIComponent(s.asset_id)}'">
        <td><strong>${s.hostname || s.asset_id}</strong></td>
        <td><code>${s.primary_ip || ''}</code></td>
        <td>${s.asset_type || '?'}</td>
        <td>${s.vendor || ''}</td>
        <td>${(s.sources||[]).map(x => `<span class="pill pill-high">${x}</span>`).join(" ")}</td>
      </tr>`).join("");
  } catch (e) {
    document.querySelector("#shadow-tbl tbody").innerHTML =
      `<tr><td colspan="5" class="muted">Failed: ${e.message}</td></tr>`;
  }
}
loadShadow();
"""


# ---------------------------------------------------------------- topology

_TOPOLOGY_BODY = """
<div style="display:flex;align-items:center;gap:12px;margin-bottom:8px">
  <h1 style="margin:0">Topology</h1>
  <span class="muted" id="topo-stats" style="font-size:12px"></span>
  <span style="flex:1"></span>
  <select id="topo-view" onchange="topoChangeView()"
          style="padding:6px 10px;border-radius:6px;
                 border:1px solid var(--border);
                 background:var(--bg);color:var(--text);font-size:12px">
    <option value="sites">🌎 Sites map (default)</option>
    <option value="xmas">🎄 Network hierarchy (Visio-style)</option>
    <option value="unified">Unified (all layers)</option>
    <optgroup label="Logical (v7.1 views)">
      <option value="global">Global</option>
      <option value="campus">Campus</option>
      <option value="subnet">Subnet</option>
      <option value="security_zone">Security zone</option>
      <option value="cloud">Cloud</option>
      <option value="risk_heat">Risk heat</option>
      <option value="lifecycle">Lifecycle</option>
      <option value="health">Health</option>
      <option value="vulnerability">Vulnerability</option>
    </optgroup>
  </select>
  <select id="topo-layout" onchange="topoChangeLayout()"
          style="padding:6px 10px;border-radius:6px;
                 border:1px solid var(--border);
                 background:var(--bg);color:var(--text);font-size:12px">
    <option value="breadthfirst">Hierarchical (Meraki-style)</option>
    <option value="cose">Force-directed</option>
    <option value="concentric">Concentric (by criticality)</option>
    <option value="circle">Circle</option>
    <option value="grid">Grid</option>
  </select>
  <input id="topo-search" placeholder="🔍 search hostname / IP…"
         oninput="topoSearch()"
         style="padding:6px 10px;border-radius:6px;width:200px;
                border:1px solid var(--border);
                background:var(--bg);color:var(--text);font-size:12px"/>
  <button class="alt" style="width:auto;padding:6px 10px;font-size:12px"
          onclick="topoLoad()">⟳ Reload</button>
</div>

<div id="topo-wrap" style="display:grid;
     grid-template-columns:200px 1fr 240px;gap:10px;
     height:calc(100vh - 230px);min-height:500px">

  <!-- LEFT: layer toggles + filters -->
  <div class="card" style="padding:12px;overflow:auto;font-size:12px">
    <div style="font-weight:600;text-transform:uppercase;font-size:11px;
                color:var(--muted);margin-bottom:6px">Layers</div>
    <div id="topo-layers"></div>

    <div style="font-weight:600;text-transform:uppercase;font-size:11px;
                color:var(--muted);margin:14px 0 6px">Filters</div>
    <label class="ml">Environment</label>
    <select id="f-env" onchange="topoApplyFilters()">
      <option value="">all</option><option value="prod">prod</option>
      <option value="staging">staging</option><option value="dev">dev</option>
    </select>
    <label class="ml">Site</label>
    <input id="f-site" placeholder="any" oninput="topoApplyFilters()"/>
    <label class="ml">Min criticality</label>
    <select id="f-crit" onchange="topoApplyFilters()">
      <option value="">any</option>
      <option value="medium">medium+</option>
      <option value="high">high+</option>
      <option value="crown-jewel">crown-jewel only</option>
    </select>
    <label style="display:flex;gap:6px;margin-top:8px">
      <input type="checkbox" id="f-hide-ghosts" style="width:auto"
             onchange="topoApplyFilters()"/>
      Hide ghost nodes
    </label>

    <div style="font-weight:600;text-transform:uppercase;font-size:11px;
                color:var(--muted);margin:14px 0 6px">Legend</div>
    <div style="font-size:11px;line-height:1.7">
      <div><span style="display:inline-block;width:10px;height:10px;
        background:#7c5cff;border-radius:50%;margin-right:6px"></span>network</div>
      <div><span style="display:inline-block;width:10px;height:10px;
        background:#10b981;border-radius:50%;margin-right:6px"></span>server</div>
      <div><span style="display:inline-block;width:10px;height:10px;
        background:#06b6d4;border-radius:50%;margin-right:6px"></span>identity</div>
      <div><span style="display:inline-block;width:10px;height:10px;
        background:#f97316;border-radius:50%;margin-right:6px"></span>cloud</div>
      <div><span style="display:inline-block;width:10px;height:10px;
        background:#9ca3af;border-radius:50%;margin-right:6px;opacity:0.5"></span>ghost (unmatched)</div>
      <div style="margin-top:6px"><strong>⭐</strong> = crown-jewel</div>
    </div>

    <style>
      #topo-wrap label.ml{display:block;font-size:11px;font-weight:600;
        margin:8px 0 3px;color:var(--muted)}
      #topo-wrap input,#topo-wrap select{width:100%;padding:5px;
        border-radius:4px;border:1px solid var(--border);background:var(--bg);
        color:var(--text);font-size:11px}
    </style>
  </div>

  <!-- CENTER: cytoscape canvas (Meraki-style light background) -->
  <div class="card" style="padding:0;position:relative;overflow:hidden">
    <div id="topo-cy" style="width:100%;height:100%;
         background:radial-gradient(circle at 50% 30%,#ffffff 0%,#f1f5f9 70%,#e2e8f0 100%)">
    </div>
    <div id="topo-empty" style="display:none;position:absolute;inset:0;
         display:flex;flex-direction:column;align-items:center;
         justify-content:center;text-align:center;padding:30px;
         background:var(--panel)">
      <div style="font-size:46px;margin-bottom:12px">🗺️</div>
      <h3 style="margin:0">No topology data yet</h3>
      <p class="muted" style="max-width:340px;margin:8px 0 16px">
        Run <strong>📡 SNMP harvest</strong> from /inventory against any
        router/switch to populate the physical layer. Or load demo data —
        the logical layers will populate from any inventory.
      </p>
      <a class="primary" href="/inventory"
         style="display:inline-block;padding:8px 16px;border-radius:8px;
                background:var(--accent);color:#fff;text-decoration:none">
        Go to Inventory →</a>
    </div>
  </div>

  <!-- RIGHT: selection panel -->
  <div class="card" id="topo-sel" style="padding:14px;overflow:auto;
       font-size:12px">
    <div class="muted">Click a node to inspect.</div>
  </div>
</div>
"""

_TOPOLOGY_SCRIPT = r"""
let CY = null;
let LAST_PAYLOAD = null;
let LAST_VIEW = "unified";

// Lazy-load Cytoscape from CDN (already allowed: cdnjs in chrome).
function ensureCytoscape() {
  return new Promise((resolve, reject) => {
    if (window.cytoscape) return resolve(window.cytoscape);
    const s = document.createElement("script");
    s.src = "https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.26.0/cytoscape.min.js";
    s.onload = () => resolve(window.cytoscape);
    s.onerror = () => reject(new Error("Failed to load Cytoscape from CDN."));
    document.head.appendChild(s);
  });
}

async function topoLoad() {
  const view = document.getElementById("topo-view").value;
  LAST_VIEW = view;
  document.getElementById("topo-stats").textContent = "Loading…";
  let url;
  if (view === "sites")        url = "/api/platform/topology-sites";
  else if (view === "xmas")    url = "/api/platform/topology-xmas";
  else if (view === "unified") url = "/api/platform/topology-unified";
  else                          url = `/api/platform/topology/${encodeURIComponent(view)}`;

  let payload;
  try {
    payload = await scApi(url);
  } catch (e) {
    document.getElementById("topo-stats").textContent = "Error: " + e.message;
    return;
  }
  LAST_PAYLOAD = payload;

  // Build the layer toggle UI from the payload's `layers` map (unified view)
  // or hide it for the single-layer v7.1 views.
  topoRenderLayerToggles(payload);

  const elems = (payload.elements && (payload.elements.nodes ||
                                       payload.elements.edges))
                ? [...(payload.elements.nodes || []),
                    ...(payload.elements.edges || [])]
                : Array.isArray(payload.elements) ? payload.elements : [];

  const stats = payload.stats || {};
  const nNodes = stats.node_count ?? (payload.elements?.nodes?.length || 0);
  const nEdges = stats.edge_count ?? (payload.elements?.edges?.length || 0);
  document.getElementById("topo-stats").textContent =
    `${nNodes} nodes · ${nEdges} edges` +
    (stats.router_count ? ` · ${stats.router_count} routers harvested` : "") +
    (stats.ghost_count ? ` · ${stats.ghost_count} ghosts` : "");

  const empty = document.getElementById("topo-empty");
  if (!nNodes) { empty.style.display = "flex"; if (CY) CY.destroy(); CY=null; return; }
  empty.style.display = "none";

  await ensureCytoscape();
  if (CY) CY.destroy();
  // Both sites map AND xmas tree use preset positions from the backend.
  const isPreset = (view === "sites" || view === "xmas");
  const layoutCfg = isPreset
    ? { name: "preset", fit: true, padding: 60 }
    : topoLayoutOpts();
  const styleFn = (view === "sites") ? topoSiteStyles
                 : (view === "xmas") ? topoXmasStyles
                 : topoStyles;
  CY = cytoscape({
    container: document.getElementById("topo-cy"),
    elements: elems,
    style: styleFn(),
    layout: layoutCfg,
    wheelSensitivity: 0.2,
    boxSelectionEnabled: false,
    minZoom: 0.3, maxZoom: 3,
  });
  // For xmas: draw faint horizontal tier bands underneath
  if (view === "xmas" && payload.bands) {
    setTimeout(() => topoDrawXmasBands(payload.bands), 60);
  }
  CY.on("tap", "node", e => {
    const d = e.target.data();
    if (d.is_site_card) topoDrillIntoSite(d);
    else topoSelectNode(e.target);
  });
  // Empty-canvas tap clears selection panel
  CY.on("tap", e => {
    if (e.target === CY) {
      document.getElementById("topo-sel").innerHTML =
        '<div class="muted">Click a node to inspect.</div>';
    }
  });
  topoApplyFilters();
}

// Pick layout options in a way that looks Meraki-like for hierarchical
// (uplink at top → access switches → end-hosts).
function topoLayoutOpts() {
  const name = document.getElementById("topo-layout").value;
  if (name === "breadthfirst") {
    return {
      name: "breadthfirst",
      directed: true,
      spacingFactor: 1.4,
      padding: 40,
      animate: false, fit: true,
      // Pick roots = network devices with the highest neighbor count
      // (the core/edge router naturally floats to the top).
      roots: () => {
        if (!CY) return undefined;
        const networkNodes = CY.nodes().filter(n =>
          n.data("asset_type") === "network" && !n.isParent());
        if (!networkNodes.length) return undefined;
        let best = null, bestDeg = -1;
        networkNodes.forEach(n => {
          if (n.degree() > bestDeg) { bestDeg = n.degree(); best = n; }
        });
        return best ? best.id() : undefined;
      },
    };
  }
  if (name === "concentric") {
    return {
      name: "concentric",
      animate: false, fit: true, padding: 40,
      concentric: n =>
        ({"crown-jewel": 4, "high": 3, "medium": 2, "low": 1}[
          n.data("criticality")] || 0),
      levelWidth: () => 1, minNodeSpacing: 30,
    };
  }
  return { name, animate: false, fit: true, padding: 40 };
}

function topoRenderLayerToggles(payload) {
  const host = document.getElementById("topo-layers");
  const layers = payload.layers || {};
  const keys = Object.keys(layers);
  if (!keys.length) {
    host.innerHTML = `<div class="muted" style="font-size:11px">
      Single-layer view — no toggles.</div>`;
    return;
  }
  // Persist toggle state across reloads via localStorage
  const saved = JSON.parse(localStorage.getItem("SC_TOPO_LAYERS") || "{}");
  host.innerHTML = keys.map(L => {
    const on = (L in saved) ? saved[L] : true;
    return `<label style="display:flex;gap:6px;margin:4px 0;cursor:pointer">
      <input type="checkbox" data-layer="${L}" ${on ? "checked" : ""}
             style="width:auto" onchange="topoApplyFilters()"/>
      <span>${L.replace("-", " ")}</span>
    </label>`;
  }).join("");
}

function topoApplyFilters() {
  if (!CY) return;
  const layers = {};
  document.querySelectorAll("#topo-layers input").forEach(c =>
    layers[c.dataset.layer] = c.checked);
  localStorage.setItem("SC_TOPO_LAYERS", JSON.stringify(layers));

  const env = document.getElementById("f-env").value;
  const site = (document.getElementById("f-site").value || "").trim().toLowerCase();
  const minCrit = document.getElementById("f-crit").value;
  const hideGhosts = document.getElementById("f-hide-ghosts").checked;
  const critRank = {"crown-jewel": 3, "high": 2, "medium": 1, "low": 0, "": 0};
  const minRank = critRank[minCrit] ?? 0;

  CY.batch(() => {
    CY.nodes().forEach(n => {
      const d = n.data();
      const visible =
        (!env || d.env === env) &&
        (!site || (d.site || "").toLowerCase().includes(site)) &&
        (critRank[d.criticality] ?? 0) >= minRank &&
        (!hideGhosts || !d.ghost);
      n.style("display", visible ? "element" : "none");
    });
    CY.edges().forEach(e => {
      const eLayers = e.data("layers") || ["physical"];
      const layerOk = eLayers.some(L => layers[L] !== false);
      const endpointsVisible =
        e.source().style("display") !== "none" &&
        e.target().style("display") !== "none";
      e.style("display", (layerOk && endpointsVisible) ? "element" : "none");
    });
  });
}

function topoChangeView() { topoLoad(); }
function topoChangeLayout() {
  if (!CY) return;
  CY.layout(topoLayoutOpts()).run();
}

function topoSelectNode(node) {
  const d = node.data();
  const sel = document.getElementById("topo-sel");

  // Meraki-style header: icon + status dot + hostname + IP
  const statusDot = `<span style="display:inline-block;width:10px;height:10px;
    border-radius:50%;background:${d.health_color || '#9ca3af'};
    box-shadow:0 0 0 2px rgba(255,255,255,.6);margin-right:6px"></span>`;
  const header = `
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
      <div style="font-size:28px;line-height:1">${d.icon || '❓'}</div>
      <div style="flex:1;min-width:0">
        <div style="font-size:14px;font-weight:700;
                    overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
             title="${d.label || d.id}">${d.label || d.id}</div>
        <div class="muted" style="font-size:11px">
          ${statusDot}<code>${d.mgmt_ip || d.id}</code></div>
      </div>
    </div>`;

  // Adjacent neighbors panel — Meraki-style port list
  const adjacent = node.connectedEdges().map(e => {
    const other = e.source().id() === node.id() ? e.target() : e.source();
    const od = other.data();
    const port = e.source().id() === node.id()
      ? e.data("local_port") : e.data("remote_port");
    return `<tr>
      <td>${od.icon || ''}</td>
      <td><a href="#" onclick="topoFocus('${od.id}');return false"
             style="color:#3b82f6">${od.label || od.id}</a></td>
      <td class="muted">${port || ''}</td>
    </tr>`;
  }).join("");

  const ghostNote = d.ghost
    ? `<div style="margin-top:8px;padding:8px;border-radius:4px;
                    background:#fef3c7;color:#92400e;font-size:11px">
        ⓘ Ghost neighbor — seen via LLDP/CDP but not yet in inventory.
        ${d.hint ? `<br/><em>${d.hint}</em>` : ""}</div>`
    : "";

  const cockpitLink = !d.ghost ?
    `<a class="primary" href="/asset/${encodeURIComponent(d.id)}"
        style="display:block;text-align:center;margin-top:10px;
               padding:8px;border-radius:6px;background:var(--accent);
               color:#fff;text-decoration:none;font-size:12px">
       Open in cockpit →</a>` : "";

  sel.innerHTML = `
    ${header}
    <table style="font-size:11px;width:100%;margin-top:6px">
      <tr><td class="muted">Type</td>
          <td><strong>${d.asset_type || '—'}</strong></td></tr>
      <tr><td class="muted">Vendor</td><td>${d.vendor || '—'}</td></tr>
      <tr><td class="muted">Site</td><td>${d.site || '—'}</td></tr>
      <tr><td class="muted">Env</td><td>${d.env || '—'}</td></tr>
      <tr><td class="muted">Criticality</td>
          <td>${d.criticality === 'crown-jewel'
                ? '<span style="color:#f59e0b">⭐ crown-jewel</span>'
                : (d.criticality || '—')}</td></tr>
    </table>
    ${ghostNote}${cockpitLink}
    ${adjacent ? `
      <div style="margin-top:14px;font-weight:600;font-size:11px;
                  text-transform:uppercase;color:var(--muted)">
        Adjacent (${node.connectedEdges().length})</div>
      <table style="font-size:11px;width:100%;margin-top:4px">
        ${adjacent}
      </table>` : ""}
  `;
}

function topoFocus(id) {
  if (!CY) return;
  const n = CY.getElementById(id);
  if (!n.length) return;
  CY.elements().unselect();
  n.select();
  CY.center(n); CY.zoom({ level: 1.4, position: n.position() });
  topoSelectNode(n);
}

function topoStyles() {
  // Meraki-style: rounded white tiles with the device pictogram + label,
  // a colored status ring (green/yellow/red), and port labels on edges.
  return [
    // Compound parent nodes (one per site) — Meraki "by network" boxes
    { selector: "node[?is_site_group]",
      style: {
        "shape": "round-rectangle",
        "background-color": "#f8fafc",
        "background-opacity": 0.6,
        "border-width": 1.5,
        "border-color": "#cbd5e1",
        "border-style": "dashed",
        "label": "data(label)",
        "color": "#475569",
        "font-size": 13,
        "font-weight": 700,
        "text-valign": "top",
        "text-halign": "center",
        "text-margin-y": -8,
        "padding": "24px",
      }},

    // Default device tile
    { selector: "node",
      style: {
        "shape": "round-rectangle",
        "label": ele => {
          const icon = ele.data("icon") || "❓";
          const lbl = ele.data("label") || ele.data("id") || "";
          return icon + "\n" + (lbl.length > 22 ? lbl.slice(0, 21) + "…" : lbl);
        },
        "text-wrap": "wrap",
        "text-valign": "center",
        "text-halign": "center",
        "color": "#1f2937",
        "font-size": 10,
        "line-height": 1.25,
        "min-zoomed-font-size": 8,
        "background-color": ele => ele.data("ghost") ? "#f1f5f9" : "#ffffff",
        "background-opacity": 1,
        // Status ring color from health
        "border-width": 3,
        "border-color": ele => ele.data("health_color") || "#9ca3af",
        "width": ele => {
          const c = ele.data("criticality");
          return c === "crown-jewel" ? 86 : c === "high" ? 76 : 68;
        },
        "height": ele => {
          const c = ele.data("criticality");
          return c === "crown-jewel" ? 64 : c === "high" ? 58 : 52;
        },
        "opacity": ele => ele.data("ghost") ? 0.65 : 1,
      }},

    // Crown-jewel highlight: gold pill outline on top of status ring
    { selector: "node[criticality = 'crown-jewel']",
      style: {
        "border-width": 4,
        "border-color": "#f59e0b",
      }},

    // Edge styling — Meraki uses curved cables with port labels at each end
    { selector: "edge",
      style: {
        "width": ele => ele.data("edge_kind") === "neighbor" ? 2.4 : 1.2,
        "curve-style": "unbundled-bezier",
        "control-point-distances": 30,
        "control-point-weights": 0.5,
        "line-color": ele => {
          const layers = ele.data("layers") || ["physical"];
          if (layers.includes("identity-attack-path")) return "#ef4444";
          if (layers.includes("physical")) return "#475569";       // dark gray cable
          if (layers.includes("physical-l2")) return "#10b981";
          if (layers.includes("logical-subnet")) return "#94a3b8";
          if (layers.includes("logical-site")) return "#cbd5e1";
          if (layers.includes("cloud")) return "#f97316";
          return "#9ca3af";
        },
        "line-style": ele => {
          const layers = ele.data("layers") || [];
          if (layers.includes("logical-subnet") || layers.includes("logical-site")
              || layers.includes("cloud")) return "dashed";
          return "solid";
        },
        "opacity": 0.8,
        "target-arrow-shape": "none",

        // Port labels at each end (only for LLDP/CDP edges)
        "source-label": ele => ele.data("local_port") || "",
        "target-label": ele => ele.data("remote_port") || "",
        "source-text-offset": 24,
        "target-text-offset": 24,
        "source-text-rotation": "autorotate",
        "target-text-rotation": "autorotate",
        "font-size": 8,
        "color": "#475569",
        "text-background-color": "#ffffff",
        "text-background-opacity": 0.85,
        "text-background-padding": "1px",
        "text-background-shape": "round-rectangle",
      }},

    // Identity attack-path edges get an arrow + brighter color
    { selector: "edge[edge_kind = 'attack-path']",
      style: {
        "target-arrow-shape": "triangle",
        "target-arrow-color": "#ef4444",
        "width": 2.2,
      }},

    // Selected node + search highlight
    { selector: "node:selected",
      style: {
        "border-width": 5,
        "border-color": "#3b82f6",
        "box-shadow": "0 0 0 3px rgba(59,130,246,0.25)",
      }},
    { selector: ".search-hit",
      style: {
        "border-color": "#3b82f6",
        "border-width": 5,
      }},
    { selector: ".search-fade",
      style: { "opacity": 0.18 }},
  ];
}

// v9.14 — Christmas tree (Visio-style network hierarchy) stylesheet.
function topoXmasStyles() {
  return [
    { selector: "node[?is_anchor]",   // Internet anchor at the top
      style: {
        "shape": "round-rectangle",
        "background-color": "#dbeafe",
        "border-width": 2,
        "border-color": "#0ea5e9",
        "width": 130, "height": 60,
        "label": ele => `${ele.data("icon")||"🌐"}  ${ele.data("label")||"Internet"}`,
        "text-valign": "center", "text-halign": "center",
        "color": "#075985", "font-size": 13, "font-weight": 700,
      }},
    // Devices: standard Meraki-style tile, but width/height proportional
    { selector: "node",
      style: {
        "shape": "round-rectangle",
        "background-color": ele => ele.data("ghost") ? "#f1f5f9" : "#ffffff",
        "border-width": 3,
        "border-color": ele => ele.data("health_color") || "#9ca3af",
        "width": 80, "height": 56,
        "label": ele => {
          const icon = ele.data("icon") || "❓";
          const lbl = (ele.data("label") || "").slice(0, 18);
          return icon + "\n" + lbl;
        },
        "text-wrap": "wrap",
        "text-valign": "center", "text-halign": "center",
        "color": "#1f2937",
        "font-size": 9,
        "line-height": 1.25,
      }},
    // Crown jewels — gold border on top
    { selector: "node[criticality = 'crown-jewel']",
      style: { "border-width": 4, "border-color": "#f59e0b" }},
    // Side-rail nodes (identity, cloud) — slightly different tone
    { selector: "node[?is_side]",
      style: {
        "background-color": ele =>
          ele.data("asset_type") === "cloud" ? "#fff7ed" : "#f0fdf4",
        "border-color": ele =>
          ele.data("asset_type") === "cloud" ? "#f97316" : "#10b981",
      }},
    // Hierarchy edges: clean dark cables
    { selector: "edge",
      style: {
        "width": 1.4,
        "curve-style": "bezier",
        "line-color": ele => {
          const k = ele.data("edge_kind") || "";
          if (k === "identity") return "#10b981";
          if (k === "wan")      return "#f97316";
          return "#334155";   // hierarchy
        },
        "line-style": ele =>
          (ele.data("edge_kind") || "") === "identity" ? "dashed" : "solid",
        "opacity": 0.7,
        "target-arrow-shape": "none",
      }},
    { selector: "node:selected",
      style: { "border-width": 5, "border-color": "#3b82f6" }},
  ];
}

// Faint horizontal tier-band labels underneath the Christmas tree.
// Cytoscape doesn't have a clean "background band" primitive, so we
// inject SVG into the canvas wrapper. Cleared on view-change.
function topoDrawXmasBands(bands) {
  if (!CY) return;
  const wrap = document.getElementById("topo-cy");
  // Remove any previous overlay
  const old = wrap.querySelector("svg.xmas-bands");
  if (old) old.remove();
  const svgNs = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(svgNs, "svg");
  svg.setAttribute("class", "xmas-bands");
  svg.style.cssText = "position:absolute;left:0;top:0;width:100%;" +
                      "height:100%;pointer-events:none;z-index:0";
  for (const b of bands) {
    const g = document.createElementNS(svgNs, "g");
    const text = document.createElementNS(svgNs, "text");
    text.textContent = b.label;
    text.setAttribute("x", "12");
    text.setAttribute("y", b.y - 30);
    text.setAttribute("fill", b.color);
    text.setAttribute("font-size", "11");
    text.setAttribute("font-weight", "600");
    text.setAttribute("opacity", "0.45");
    g.appendChild(text);
    const line = document.createElementNS(svgNs, "line");
    line.setAttribute("x1", 100); line.setAttribute("x2", "100%");
    line.setAttribute("y1", b.y - 30); line.setAttribute("y2", b.y - 30);
    line.setAttribute("stroke", b.color);
    line.setAttribute("stroke-opacity", "0.15");
    line.setAttribute("stroke-dasharray", "4 6");
    g.appendChild(line);
    svg.appendChild(g);
  }
  // Add SVG behind the Cytoscape canvas
  wrap.style.position = "relative";
  wrap.insertBefore(svg, wrap.firstChild);
}

// v9.13 — Site card stylesheet for the geographic map. Each site is a
// large rounded rectangle showing icon + name + asset-count + health pills.
function topoSiteStyles() {
  return [
    { selector: "node[?is_site_card]",
      style: {
        "shape": "round-rectangle",
        "background-color": ele => ele.data("is_cloud") ? "#fff7ed" : "#ffffff",
        "border-width": 2,
        "border-color": ele => ele.data("is_cloud") ? "#f97316" : "#3b82f6",
        "width": 200, "height": 100,
        "label": ele => {
          const d = ele.data();
          const totalAssets = d.asset_count || 0;
          const types = d.type_summary || "";
          const health =
            (d.red    > 0 ? `🔴 ${d.red}  ` : "") +
            (d.yellow > 0 ? `🟡 ${d.yellow}  ` : "") +
            (d.green  > 0 ? `🟢 ${d.green}  ` : "");
          const crown = d.crown_jewels > 0 ? `  ⭐${d.crown_jewels}` : "";
          return `${d.icon || '🏢'}  ${d.label}${crown}\n` +
                 `${totalAssets} asset${totalAssets===1?'':'s'} · ${types}\n` +
                 `${health.trim() || 'no health data'}`;
        },
        "text-wrap": "wrap",
        "text-valign": "center",
        "text-halign": "center",
        "color": "#0f172a",
        "font-size": 11,
        "line-height": 1.45,
        "padding": "10px",
      }},
    { selector: "node[?is_site_card]:selected",
      style: {
        "border-width": 4,
        "border-color": "#3b82f6",
      }},
    // WAN edges between sites
    { selector: "edge",
      style: {
        "width": 3,
        "curve-style": "bezier",
        "control-point-step-size": 60,
        "line-color": ele => {
          const k = ele.data("kind") || "";
          if (k === "direct-connect") return "#f97316";
          if (k === "wan")            return "#1e40af";
          if (k.startsWith("inferred")) return "#94a3b8";
          return "#64748b";
        },
        "line-style": ele =>
          (ele.data("kind") || "").startsWith("inferred") ? "dashed" : "solid",
        "label": "data(label)",
        "font-size": 10,
        "color": "#475569",
        "text-background-color": "#ffffff",
        "text-background-opacity": 0.85,
        "text-background-padding": "2px",
        "text-background-shape": "round-rectangle",
        "target-arrow-shape": "none",
      }},
    { selector: "node[?is_site_card]:active, node[?is_site_card]:hover",
      style: { "border-color": "#3b82f6" }},
  ];
}

// v9.13 — drill from a site card into that site's L2 view.
async function topoDrillIntoSite(siteData) {
  // Build a sub-graph of just this site's assets using the existing
  // unified endpoint, then filter client-side by site_id.
  document.getElementById("topo-stats").textContent =
    `Loading ${siteData.label}…`;
  let payload;
  try {
    payload = await scApi("/api/platform/topology-unified");
  } catch(e) {
    document.getElementById("topo-stats").textContent =
      "Failed: " + e.message;
    return;
  }
  const allNodes = payload.elements?.nodes || [];
  const allEdges = payload.elements?.edges || [];
  const keepIds = new Set(allNodes
    .filter(n => (n.data?.site || "").toLowerCase()
                  === (siteData.site_id || "").toLowerCase())
    .map(n => n.data.id));
  const nodes = allNodes.filter(n => keepIds.has(n.data.id));
  const edges = allEdges.filter(e =>
    keepIds.has(e.data.source) && keepIds.has(e.data.target));

  // Render with the regular Meraki-style stylesheet
  if (!window.cytoscape) await ensureCytoscape();
  if (CY) CY.destroy();
  CY = cytoscape({
    container: document.getElementById("topo-cy"),
    elements: [...nodes, ...edges],
    style: topoStyles(),
    layout: {name: "breadthfirst", directed: true, fit: true,
             padding: 40, spacingFactor: 1.4},
    wheelSensitivity: 0.2,
  });
  CY.on("tap", "node", e => topoSelectNode(e.target));

  // Stats + breadcrumb-style "back" hint
  document.getElementById("topo-stats").innerHTML =
    `<a href="#" onclick="topoChangeView();return false"
        style="color:#3b82f6">← Back to sites map</a>
     · <strong>${siteData.label}</strong>
     · ${nodes.length} device${nodes.length===1?'':'s'}, ${edges.length} link${edges.length===1?'':'s'}`;
}

// Meraki-style search: filter to matches, center, zoom
function topoSearch() {
  if (!CY) return;
  const q = (document.getElementById("topo-search").value || "").trim().toLowerCase();
  if (!q) {
    CY.elements().removeClass("search-hit search-fade");
    CY.fit(undefined, 30); return;
  }
  let hits = CY.collection();
  CY.nodes().forEach(n => {
    const d = n.data();
    const hay = [d.label, d.id, d.mgmt_ip, d.vendor, d.asset_type, d.site]
                .filter(Boolean).join(" ").toLowerCase();
    if (hay.includes(q)) hits = hits.union(n);
  });
  CY.elements().removeClass("search-hit search-fade");
  if (hits.length === 0) return;
  CY.elements().not(hits).addClass("search-fade");
  hits.addClass("search-hit");
  CY.fit(hits, 60);
}

topoLoad();
"""


# ---------------------------------------------------------------- execute (Command Center)


_EXEC_BODY = """
<div style="display:flex;align-items:center;gap:12px;margin-bottom:8px">
  <h1 style="margin:0">⚡ Command Center</h1>
  <span class="muted" id="exec-totp" style="font-size:12px"></span>
  <span style="flex:1"></span>
  <a href="#queue" class="alt" style="padding:6px 10px;border-radius:6px;
     background:var(--panel-2);color:var(--text);text-decoration:none;
     font-size:12px">Queue</a>
  <a href="#audit" class="alt" style="padding:6px 10px;border-radius:6px;
     background:var(--panel-2);color:var(--text);text-decoration:none;
     font-size:12px">Audit</a>
</div>

<p class="muted" style="margin-top:0">
  Build, dry-run, approve, execute, and roll back commands across your
  fleet. Tier 1 = read-only (no approval). Tier 2 = config change
  (approval required). Tier 3 = reboot/risky (TOTP MFA + admin approval).
</p>

<div style="display:grid;gap:12px;grid-template-columns:1fr 320px">

  <!-- LEFT: builder + plan + actions -->
  <div>
    <div class="card">
      <div style="font-weight:600;text-transform:uppercase;font-size:11px;
                  color:var(--muted);margin-bottom:8px">1. Pick targets</div>
      <input id="ex-targets" placeholder="comma-separated asset IDs (e.g. edge-rtr-01.acme.local)"
             style="width:100%;padding:8px;border-radius:6px;
                    border:1px solid var(--border);background:var(--bg);
                    color:var(--text);font-size:12px"/>
      <div class="muted" style="font-size:11px;margin-top:4px">
        Also accepts asset-group IDs prefixed with <code>group:</code>.
        Leave empty to plan against the full fleet.
      </div>
    </div>

    <div class="card" style="margin-top:10px">
      <div style="font-weight:600;text-transform:uppercase;font-size:11px;
                  color:var(--muted);margin-bottom:8px">2. State intent (plain English)</div>
      <textarea id="ex-intent" placeholder="e.g. Disable Telnet on this device. Or: Set NTP server to 10.0.0.1. Or: Show running config."
        style="width:100%;height:80px;padding:8px;border-radius:6px;
        border:1px solid var(--border);background:var(--bg);color:var(--text);
        font-size:13px"></textarea>
      <div style="display:flex;gap:8px;margin-top:8px">
        <button class="primary" onclick="execPlan()">🧠  Plan with AI</button>
        <button class="alt" style="width:auto;padding:8px 14px"
                onclick="execClear()">Clear</button>
      </div>
    </div>

    <div id="exec-plan-card" class="card" style="margin-top:10px;display:none">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
        <div style="font-weight:600;text-transform:uppercase;font-size:11px;
                    color:var(--muted)">3. Review plan</div>
        <span style="flex:1"></span>
        <span id="exec-tier-badge"></span>
      </div>
      <div id="exec-plan-summary" class="muted" style="font-size:12px;margin-bottom:8px"></div>
      <div id="exec-plan-blocks"></div>

      <div style="display:flex;gap:8px;margin-top:14px;flex-wrap:wrap"
           id="exec-actions">
        <button class="alt" style="width:auto;padding:8px 14px"
                onclick="execDryRun()">🔍  Dry-run</button>
        <button class="primary" style="width:auto;padding:8px 14px"
                onclick="execSubmit()">📤  Submit for approval</button>
      </div>
    </div>

    <div id="exec-job-card" class="card" style="margin-top:10px;display:none">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
        <div style="font-weight:600;text-transform:uppercase;font-size:11px;
                    color:var(--muted)">4. Job</div>
        <span id="exec-job-id" class="muted"
              style="font-family:monospace;font-size:11px"></span>
        <span style="flex:1"></span>
        <span id="exec-job-status"></span>
      </div>
      <pre id="exec-job-output" style="max-height:300px;overflow:auto;
        font-size:11px;line-height:1.45;background:var(--bg);
        padding:10px;border-radius:4px;margin:0"></pre>
      <div id="exec-job-actions" style="display:flex;gap:8px;margin-top:10px;
            flex-wrap:wrap"></div>
    </div>
  </div>

  <!-- RIGHT: queue + audit -->
  <div>
    <div class="card" id="queue">
      <div style="display:flex;align-items:center;margin-bottom:6px">
        <strong style="font-size:12px;text-transform:uppercase;
                       color:var(--muted)">Active queue</strong>
        <span style="flex:1"></span>
        <button class="alt" style="width:auto;padding:3px 8px;font-size:11px"
                onclick="execLoadQueue()">⟳</button>
      </div>
      <div id="exec-queue" class="muted" style="font-size:12px">Loading…</div>
    </div>

    <div class="card" id="audit" style="margin-top:10px">
      <div style="font-size:12px;text-transform:uppercase;
                  color:var(--muted);font-weight:600;margin-bottom:6px">
        Recent audit</div>
      <div id="exec-audit" class="muted" style="font-size:11px;
            max-height:380px;overflow:auto">Loading…</div>
    </div>
  </div>
</div>
"""


_EXEC_SCRIPT = r"""
let LAST_PLAN = null;
let LAST_JOB = null;

// Pre-fill targets from ?asset_id= query param
(function() {
  const q = new URLSearchParams(location.search);
  const aid = q.get("asset_id");
  if (aid) {
    setTimeout(() => {
      document.getElementById("ex-targets").value = aid;
      const intent = document.getElementById("ex-intent");
      intent.placeholder = `e.g. Show running config on ${aid}. Or: Disable Telnet.`;
    }, 30);
  }
})();

async function execLoadTotp() {
  try {
    const r = await scApi("/api/execute/totp/status");
    const el = document.getElementById("exec-totp");
    if (r.enrolled) {
      el.innerHTML = '<span style="color:#10b981">✓</span> TOTP enrolled';
    } else {
      el.innerHTML = `<span style="color:#f59e0b">⚠ TOTP not enrolled</span>
        <a href="#" onclick="execEnrollTotp();return false"
           style="margin-left:6px">Enroll →</a>`;
    }
  } catch(e) { /* ignore */ }
}
async function execEnrollTotp() {
  try {
    const r = await scApi("/api/execute/totp/enroll", {method:"POST"});
    scOpenSlide("Enroll TOTP", `
      <p class="muted">Scan this URI in Google Authenticator / 1Password / Authy.
         You'll need a code from this app for every Tier 3 (reboot/risky)
         job approval.</p>
      <pre style="background:var(--bg);padding:8px;border-radius:4px;
                  font-size:11px;word-break:break-all">${r.otpauth_uri}</pre>
      <div class="muted" style="font-size:11px;margin-top:8px">
        Secret (manual entry): <code>${r.secret}</code></div>
    `);
    execLoadTotp();
  } catch(e) { alert(e.message); }
}

function execClear() {
  document.getElementById("ex-intent").value = "";
  document.getElementById("exec-plan-card").style.display = "none";
  document.getElementById("exec-job-card").style.display = "none";
  LAST_PLAN = null; LAST_JOB = null;
}

async function execPlan() {
  const intent = document.getElementById("ex-intent").value.trim();
  if (!intent) { alert("Describe what you want to do."); return; }
  const tgt = document.getElementById("ex-targets").value.trim();
  const asset_ids = [], group_ids = [];
  for (const t of tgt.split(",").map(s=>s.trim()).filter(Boolean)) {
    if (t.startsWith("group:")) group_ids.push(t.slice(6));
    else asset_ids.push(t);
  }
  document.getElementById("exec-plan-summary").textContent = "Planning…";
  document.getElementById("exec-plan-card").style.display = "block";
  document.getElementById("exec-plan-blocks").innerHTML = "";
  try {
    const plan = await scApi("/api/execute/builder/plan", {
      method: "POST",
      body: JSON.stringify({intent, asset_ids, asset_group_ids: group_ids}),
    });
    LAST_PLAN = plan;
    execRenderPlan(plan);
  } catch(e) {
    document.getElementById("exec-plan-summary").innerHTML =
      `<span style="color:#f97373">${e.message}</span>`;
  }
}

function execRenderPlan(plan) {
  const tier = plan.risk_tier || plan.tier || "tier1";
  const tierColor = {tier1:"#10b981", tier2:"#f59e0b", tier3:"#ef4444"}[tier] || "#9ca3af";
  document.getElementById("exec-tier-badge").innerHTML =
    `<span class="pill" style="background:${tierColor};color:#fff">
       ${tier.toUpperCase()} ${tier==="tier1"?"· read-only" :
                                tier==="tier2"?"· config change" :
                                "· reboot/risky"}</span>`;

  let summary = plan.summary || `${(plan.matched_packs||[]).length} packs matched`;
  if (plan.blocked) {
    summary = `<span style="color:#f97373">🚫 BLOCKED:</span> ` +
              (plan.block_reasons||[]).join("; ");
  }
  document.getElementById("exec-plan-summary").innerHTML = summary;

  const packs = plan.matched_packs || [];
  if (!packs.length) {
    document.getElementById("exec-plan-blocks").innerHTML =
      `<p class="muted">No control packs matched. Try a more specific
       intent or check that the targets exist.</p>`;
    document.getElementById("exec-actions").style.display =
      plan.blocked ? "none" : "flex";
    return;
  }
  document.getElementById("exec-plan-blocks").innerHTML = packs.map(p => `
    <details open style="margin-bottom:6px">
      <summary style="cursor:pointer;font-size:12px;font-weight:600">
        ${p.name || p.pack_id || "pack"}
        <span class="muted" style="font-weight:400;margin-left:6px">
          ${(p.targets||[]).length} target${(p.targets||[]).length===1?'':'s'}</span>
      </summary>
      <pre style="background:var(--bg);padding:8px;border-radius:4px;
                  font-size:11px;margin:6px 0;max-height:200px;overflow:auto">
${(p.commands||[]).join("\n") || "(no commands)"}</pre>
    </details>
  `).join("");
  document.getElementById("exec-actions").style.display =
    plan.blocked ? "none" : "flex";
}

async function execSubmit() {
  if (!LAST_PLAN) return;
  const intent = document.getElementById("ex-intent").value.trim();
  const tgt = document.getElementById("ex-targets").value.trim();
  const asset_ids = [], group_ids = [];
  for (const t of tgt.split(",").map(s=>s.trim()).filter(Boolean)) {
    if (t.startsWith("group:")) group_ids.push(t.slice(6));
    else asset_ids.push(t);
  }
  try {
    const r = await scApi("/api/execute/builder/plan-and-save", {
      method:"POST",
      body: JSON.stringify({
        intent, asset_ids, asset_group_ids: group_ids,
        name: intent.slice(0,60),
      }),
    });
    LAST_JOB = r.job;
    execShowJob(r.job, "submitted");
    // Move job into REVIEW so an approver can act
    try {
      await scApi(`/api/execute/jobs/${r.job.job_id}/submit`, {method:"POST"});
      LAST_JOB.status = "review";
      execShowJob(LAST_JOB, "in review");
    } catch(_) {}
    execLoadQueue();
    execLoadAudit();
  } catch(e) { alert("Submit failed: " + e.message); }
}

async function execDryRun() {
  if (!LAST_PLAN) return;
  // First save the job, then dry-run it
  await execSubmit();
  if (!LAST_JOB) return;
  try {
    const r = await scApi(`/api/execute/jobs/${LAST_JOB.job_id}/dry-run`,
                          {method:"POST"});
    document.getElementById("exec-job-output").textContent =
      JSON.stringify(r, null, 2);
    document.getElementById("exec-job-status").innerHTML =
      '<span class="pill pill-info">DRY-RUN</span>';
  } catch(e) { alert("Dry-run failed: " + e.message); }
}

function execShowJob(job, statusText) {
  document.getElementById("exec-job-card").style.display = "block";
  document.getElementById("exec-job-id").textContent = job.job_id;
  document.getElementById("exec-job-status").innerHTML =
    `<span class="pill ${job.tier==="tier3"?"pill-crit":job.tier==="tier2"?"pill-high":"pill-info"}">
       ${job.tier?.toUpperCase() || ""} · ${statusText}</span>`;
  document.getElementById("exec-job-output").textContent =
    `Created at ${job.created_at || "now"}.\n` +
    `Targets: ${(job.targets||[]).map(t=>t.asset_id).join(", ") || "—"}\n` +
    `Commands: ${(job.commands||job.command_strings||[]).length}`;
  document.getElementById("exec-job-actions").innerHTML = execJobActions(job);
}

function execJobActions(job) {
  const id = job.job_id;
  const status = (job.status || "").toLowerCase();
  const tier = (job.tier || job.risk_tier || "tier1").toLowerCase();
  const btns = [];
  if (status === "review" || status === "draft") {
    btns.push(`<button class="alt" onclick="execApprove('${id}')">✅ Approve</button>`);
    btns.push(`<button class="alt" onclick="execReject('${id}')"
               style="background:#fef3c7;color:#92400e">✗ Reject</button>`);
  }
  if (status === "approved") {
    if (tier === "tier3") {
      btns.push(`<button class="primary" onclick="execRunTier3('${id}')">
                  🚀 Execute (TOTP)</button>`);
    } else {
      btns.push(`<button class="primary" onclick="execRun('${id}')">🚀 Execute</button>`);
    }
  }
  if (status === "executed" || status === "running") {
    btns.push(`<button class="alt" onclick="execRollback('${id}')"
               style="background:#fef3c7;color:#92400e">↺ Rollback</button>`);
  }
  if (status === "review" || status === "approved") {
    btns.push(`<button class="alt" onclick="execCancel('${id}')">Cancel</button>`);
  }
  return btns.join("") || '<span class="muted">no actions available in this state</span>';
}

async function execApprove(id) {
  try {
    await scApi(`/api/execute/jobs/${id}/approve`, {method:"POST"});
    alert("Approved.");
    execRefresh(id);
  } catch(e) { alert(e.message); }
}
async function execReject(id) {
  const reason = prompt("Reason for rejection?");
  if (reason === null) return;
  try {
    await scApi(`/api/execute/jobs/${id}/reject`,
                {method:"POST", body:JSON.stringify({reason})});
    execRefresh(id);
  } catch(e) { alert(e.message); }
}
async function execRun(id) {
  if (!confirm("Execute this job for real? This will run commands against the targets.")) return;
  try {
    const r = await scApi(`/api/execute/jobs/${id}/run-real`,
                          {method:"POST", body:JSON.stringify({})});
    document.getElementById("exec-job-output").textContent =
      JSON.stringify(r, null, 2);
    execRefresh(id);
  } catch(e) { alert(e.message); }
}
async function execRunTier3(id) {
  const code = prompt("Tier 3 — enter your TOTP code:");
  if (!code) return;
  try {
    const r = await scApi(`/api/execute/jobs/${id}/run-real`,
                          {method:"POST", body:JSON.stringify({totp: code.trim()})});
    document.getElementById("exec-job-output").textContent =
      JSON.stringify(r, null, 2);
    execRefresh(id);
  } catch(e) { alert("TOTP rejected or job failed: " + e.message); }
}
async function execRollback(id) {
  if (!confirm("Roll back this job to the saved pre-execution state?")) return;
  try {
    await scApi(`/api/execute/jobs/${id}/rollback`, {method:"POST"});
    execRefresh(id);
  } catch(e) { alert(e.message); }
}
async function execCancel(id) {
  try {
    await scApi(`/api/execute/jobs/${id}/cancel`, {method:"POST"});
    execRefresh(id);
  } catch(e) { alert(e.message); }
}
async function execRefresh(id) {
  try {
    const j = await scApi(`/api/execute/jobs/${id}`);
    LAST_JOB = j;
    execShowJob(j, j.status || "");
    execLoadQueue();
    execLoadAudit();
  } catch(e) {}
}

async function execLoadQueue() {
  try {
    const r = await scApi("/api/execute/queue");
    const items = r.queue || [];
    const host = document.getElementById("exec-queue");
    if (!items.length) {
      host.innerHTML = "No active jobs.";
      return;
    }
    host.innerHTML = items.slice(0, 12).map(j => {
      const sev = j.tier==="tier3"?"pill-crit":j.tier==="tier2"?"pill-high":"pill-info";
      return `<div onclick="execRefresh('${j.job_id}')"
        style="padding:6px 8px;margin:3px 0;border-radius:4px;
               background:var(--panel-2);cursor:pointer;font-size:11px">
        <div style="display:flex;gap:6px;align-items:center">
          <span class="pill ${sev}">${(j.tier||'?').toUpperCase()}</span>
          <span style="flex:1;overflow:hidden;text-overflow:ellipsis;
                white-space:nowrap">${j.name || j.job_id}</span>
          <span class="muted">${j.status}</span>
        </div>
      </div>`;
    }).join("");
  } catch(e) {
    document.getElementById("exec-queue").innerHTML =
      `<span style="color:#f97373">${e.message}</span>`;
  }
}

async function execLoadAudit() {
  try {
    const r = await scApi("/api/execute/audit?limit=30");
    const entries = r.entries || [];
    const host = document.getElementById("exec-audit");
    if (!entries.length) { host.innerHTML = "No audit entries yet."; return; }
    host.innerHTML = entries.map(e => {
      const ts = (e.timestamp || e.ts || "").slice(0, 19).replace("T", " ");
      return `<div style="padding:3px 0;border-bottom:1px solid var(--border)">
        <code style="color:var(--muted)">${ts}</code>
        <strong>${e.action || e.event || "?"}</strong>
        <span class="muted">${e.actor || e.user || ""}</span>
        <span class="muted">${(e.job_id || "").slice(0,12)}</span>
      </div>`;
    }).join("");
  } catch(e) {
    document.getElementById("exec-audit").innerHTML =
      `<span style="color:#f97373">${e.message}</span>`;
  }
}

execLoadTotp();
execLoadQueue();
execLoadAudit();
"""


# ---------------------------------------------------------------- groups


_GROUPS_BODY = """
<div style="display:flex;align-items:center;gap:12px;margin-bottom:8px">
  <h1 style="margin:0">📦 Asset groups</h1>
  <span class="muted" id="grp-stats" style="font-size:12px"></span>
  <span style="flex:1"></span>
  <button class="primary" onclick="openCreateGroup()"
          style="width:auto;padding:8px 14px">+ New group</button>
</div>

<p class="muted" style="margin-top:0">
  Groups are how you target many devices at once. A device can belong to
  many groups (a switch is in <code>site:dc1</code>, <code>vendor:cisco</code>,
  and <code>role:access</code>). Policies can target a group by ID — the
  same intent fans out across vendors and types via per-vendor translators.
</p>

<div style="display:grid;gap:12px;grid-template-columns:340px 1fr">
  <!-- LEFT: groups list -->
  <div class="card" style="padding:0;overflow:hidden">
    <div style="padding:8px 12px;border-bottom:1px solid var(--border);
                font-size:11px;text-transform:uppercase;color:var(--muted);
                font-weight:600">All groups</div>
    <div id="grp-list" style="max-height:calc(100vh - 280px);overflow:auto">
      <div class="muted" style="padding:30px;text-align:center">Loading…</div>
    </div>
  </div>

  <!-- RIGHT: selected group detail -->
  <div id="grp-detail" class="card" style="padding:18px">
    <div class="muted">Pick a group on the left, or click + New group to
      create one.</div>
  </div>
</div>
"""


_GROUPS_SCRIPT = r"""
let GROUPS = [];
let CUR_GROUP = null;

async function grpLoad() {
  try {
    const r = await scApi("/api/platform/asset-groups");
    GROUPS = r.groups || [];
    document.getElementById("grp-stats").textContent =
      `${GROUPS.length} group${GROUPS.length === 1 ? "" : "s"}`;
    grpRenderList();
    if (GROUPS.length && !CUR_GROUP) grpSelect(GROUPS[0].group_id);
    else if (CUR_GROUP) grpSelect(CUR_GROUP);
  } catch(e) {
    document.getElementById("grp-list").innerHTML =
      `<div class="muted" style="padding:18px">${e.message}</div>`;
  }
}

function grpRenderList() {
  const host = document.getElementById("grp-list");
  if (!GROUPS.length) {
    host.innerHTML = `<div class="muted" style="padding:30px;text-align:center">
      No groups yet.<br/><a href="#" onclick="openCreateGroup();return false">
      Create your first one →</a></div>`;
    return;
  }
  host.innerHTML = GROUPS.map(g => `
    <div onclick="grpSelect('${g.group_id}')"
         class="grp-row ${CUR_GROUP === g.group_id ? 'sel' : ''}"
         style="padding:10px 14px;border-bottom:1px solid var(--border);
                cursor:pointer">
      <div style="font-size:13px;font-weight:600">${g.name || g.group_id}</div>
      <div class="muted" style="font-size:11px;margin-top:2px">
        ${g.description || g.group_id}</div>
      <div style="display:flex;gap:6px;margin-top:6px;font-size:11px">
        <span class="pill pill-info">${g.member_count || 0} members</span>
        ${(g.asset_ids || []).length ? `<span class="pill">static</span>` : ''}
        ${(g.filter && Object.keys(g.filter).length) ? `<span class="pill">filter</span>` : ''}
      </div>
    </div>
  `).join("");
  // Highlight current
  document.querySelectorAll(".grp-row.sel").forEach(el =>
    el.style.background = "var(--panel-2)");
}

async function grpSelect(gid) {
  CUR_GROUP = gid;
  grpRenderList();
  const host = document.getElementById("grp-detail");
  host.innerHTML = `<div class="muted">Loading…</div>`;
  try {
    const g = await scApi(`/api/platform/asset-groups/${encodeURIComponent(gid)}`);
    grpRenderDetail(g);
  } catch(e) {
    host.innerHTML = `<div class="muted">${e.message}</div>`;
  }
}

function grpRenderDetail(g) {
  const filterChips = Object.entries(g.filter || {}).map(([k, v]) =>
    `<span class="pill pill-info">${k}=${Array.isArray(v) ? v.join("|") : v}</span>`
  ).join(" ");
  const members = (g.members || []).slice(0, 200);
  document.getElementById("grp-detail").innerHTML = `
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px">
      <h2 style="margin:0;font-size:18px">${g.name || g.group_id}</h2>
      <span style="flex:1"></span>
      <button class="alt" style="width:auto;padding:6px 12px;font-size:12px"
              onclick="openApplyPolicy('${g.group_id}')">📐 Apply policy</button>
      <button class="alt" style="width:auto;padding:6px 12px;font-size:12px"
              onclick="grpDelete('${g.group_id}')"
              style="background:#fef3c7;color:#92400e">🗑 Delete</button>
    </div>
    <p class="muted" style="font-size:12px;margin:0 0 10px">
      ${g.description || ""}</p>
    <div><code>${g.group_id}</code> · ${g.member_count} members ·
        tenant <code>${g.tenant || "local"}</code></div>

    ${filterChips ? `
      <div style="margin-top:12px">
        <div class="muted" style="font-size:11px;font-weight:600;text-transform:uppercase">
          Filter (dynamic membership)</div>
        <div style="margin-top:4px">${filterChips}</div>
      </div>` : ""}

    <div style="margin-top:14px">
      <div class="muted" style="font-size:11px;font-weight:600;text-transform:uppercase">
        Members (${g.member_count})</div>
      <div class="card" style="padding:0;margin-top:6px;max-height:340px;overflow:auto">
        <table style="font-size:12px;width:100%">
          <thead><tr><th>Asset</th><th></th></tr></thead>
          <tbody>${members.length ? members.map(aid => `
            <tr>
              <td><a href="/asset/${encodeURIComponent(aid)}">${aid}</a></td>
              <td style="text-align:right">
                ${(g.asset_ids || []).includes(aid)
                   ? `<button class="alt" style="width:auto;padding:3px 8px;font-size:11px"
                       onclick="grpRemoveMember('${g.group_id}','${aid}')">remove</button>`
                   : '<span class="muted" style="font-size:11px">via filter</span>'}
              </td>
            </tr>
          `).join("") : `<tr><td colspan="2" class="muted"
              style="padding:18px;text-align:center">No members yet.</td></tr>`}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

async function grpRemoveMember(gid, aid) {
  if (!confirm(`Remove ${aid} from this group?`)) return;
  try {
    await scApi(`/api/platform/asset-groups/${encodeURIComponent(gid)}/members/${encodeURIComponent(aid)}`,
                {method:"DELETE"});
    grpSelect(gid);
  } catch(e) { alert(e.message); }
}

async function grpDelete(gid) {
  if (!confirm(`Delete group ${gid}? Members are NOT deleted, just unlinked.`)) return;
  try {
    await scApi(`/api/platform/asset-groups/${encodeURIComponent(gid)}`,
                {method:"DELETE"});
    CUR_GROUP = null;
    grpLoad();
  } catch(e) { alert(e.message); }
}

function openCreateGroup() {
  scOpenSlide("Create asset group", `
    <p class="muted">A group can be a static list of asset IDs, a dynamic
       filter, or both. Filters re-evaluate as inventory changes — useful
       for "all prod Cisco gear", "all crown-jewel servers", etc.</p>
    <label class="ml">Group ID *</label>
    <input id="ng-id" placeholder="prod-network-gear (lowercase, hyphens)" />
    <label class="ml">Name *</label>
    <input id="ng-name" placeholder="Production network gear" />
    <label class="ml">Description</label>
    <input id="ng-desc" placeholder="optional" />
    <label class="ml">Filter (one per line: <code>key:value</code>)</label>
    <textarea id="ng-filter" placeholder="env:prod
asset_type:network
vendor:cisco" style="height:80px;font-family:monospace;font-size:11px"></textarea>
    <div class="muted" style="font-size:11px;margin-top:4px">
      Example keys: <code>env</code>, <code>site</code>, <code>vendor</code>,
      <code>asset_type</code>, <code>criticality</code>, <code>tag</code>.
    </div>
    <button class="primary" style="margin-top:10px" onclick="grpCreate()">
      Create group</button>
    <div id="ng-status" class="muted" style="margin-top:8px;font-size:12px"></div>
    <style>#scSlideBody label.ml{display:block;font-size:11px;font-weight:600;
      margin:8px 0 3px;color:var(--muted)}
      #scSlideBody input,#scSlideBody textarea{width:100%;padding:7px;
      border-radius:6px;border:1px solid var(--border);background:var(--bg);
      color:var(--text);font-size:12px}</style>
  `);
}

async function grpCreate() {
  const id = (document.getElementById("ng-id").value || "").trim();
  const name = (document.getElementById("ng-name").value || "").trim();
  if (!id || !name) { alert("Group ID and name are required."); return; }
  // Parse "field:value" lines into v6.4 AND-of-clauses filter shape:
  //   {AND: [{field, op:"eq", value}, ...]}
  const clauses = [];
  for (const line of (document.getElementById("ng-filter").value || "").split("\n")) {
    const [k, v] = line.split(":").map(s => (s||"").trim());
    if (k && v) clauses.push({field: k, op: "eq", value: v});
  }
  const filter = clauses.length === 0 ? {}
                 : clauses.length === 1 ? clauses[0]
                 : {all: clauses};
  try {
    await scApi("/api/platform/asset-groups", {
      method:"POST",
      body: JSON.stringify({
        group_id: id, name,
        description: document.getElementById("ng-desc").value || "",
        filter, asset_ids: [],
      }),
    });
    scCloseSlide();
    CUR_GROUP = id;
    grpLoad();
  } catch(e) {
    document.getElementById("ng-status").innerHTML =
      `<span style="color:#f97373">${e.message}</span>`;
  }
}

function openApplyPolicy(gid) {
  scOpenSlide("Apply policy to " + gid, `
    <p class="muted">Send the group ID to the policy translator. The
       translator turns plain English into a per-vendor IR — every
       device in this group gets the right command for its vendor and OS.</p>
    <a class="primary" href="/identity?focus_group=${encodeURIComponent(gid)}"
       style="display:inline-block;padding:10px 16px;border-radius:8px;
              background:var(--accent);color:#fff;text-decoration:none">
      Open policy translator →</a>
    <p class="muted" style="margin-top:14px;font-size:12px">
      Or jump to <a href="/policies?group=${encodeURIComponent(gid)}">existing
      policies that target this group</a>.
    </p>
    <p class="muted" style="font-size:12px">
      Or run a one-off command across the group:
      <a href="/execute?group=${encodeURIComponent(gid)}">open Command Center →</a>
    </p>
  `);
}

grpLoad();
"""


# ---------------------------------------------------------------- changes

_CHANGES_BODY = """
<div style="display:flex;align-items:center;gap:12px;margin-bottom:8px">
  <h1 style="margin:0">📈 Fleet changes</h1>
  <span class="muted" id="ch-stats" style="font-size:12px"></span>
  <span style="flex:1"></span>
  <select id="ch-window" onchange="chLoad()"
          style="padding:6px 10px;border-radius:6px;border:1px solid var(--border);
                 background:var(--bg);color:var(--text);font-size:12px">
    <option value="1">last 24h</option>
    <option value="7" selected>last 7 days</option>
    <option value="30">last 30 days</option>
  </select>
  <button class="alt" style="width:auto;padding:6px 10px;font-size:12px"
          onclick="chLoad()">⟳ Reload</button>
</div>
<p class="muted" style="margin-top:0">
  What changed in your fleet vs. the snapshot from <strong id="ch-baseline">…</strong>?
  Snapshots are written daily; the first run on a new system has no
  baseline yet.
</p>

<div id="ch-summary" style="display:grid;gap:10px;
     grid-template-columns:repeat(auto-fit,minmax(180px,1fr));margin-bottom:14px">
  <div class="card" style="padding:14px;border-left:3px solid #10b981">
    <div class="muted" style="font-size:11px;text-transform:uppercase;font-weight:600">
      Added</div>
    <div id="ch-added-n" style="font-size:30px;font-weight:700;
         color:#10b981;line-height:1">—</div>
  </div>
  <div class="card" style="padding:14px;border-left:3px solid #ef4444">
    <div class="muted" style="font-size:11px;text-transform:uppercase;font-weight:600">
      Removed</div>
    <div id="ch-removed-n" style="font-size:30px;font-weight:700;
         color:#ef4444;line-height:1">—</div>
  </div>
  <div class="card" style="padding:14px;border-left:3px solid #f59e0b">
    <div class="muted" style="font-size:11px;text-transform:uppercase;font-weight:600">
      Modified</div>
    <div id="ch-modified-n" style="font-size:30px;font-weight:700;
         color:#f59e0b;line-height:1">—</div>
  </div>
</div>

<div style="display:grid;gap:12px;grid-template-columns:1fr 1fr 1fr">
  <div class="card" id="ch-added-card">
    <strong style="font-size:12px;text-transform:uppercase;color:#10b981">Added</strong>
    <div id="ch-added-list" class="muted">—</div>
  </div>
  <div class="card" id="ch-removed-card">
    <strong style="font-size:12px;text-transform:uppercase;color:#ef4444">Removed</strong>
    <div id="ch-removed-list" class="muted">—</div>
  </div>
  <div class="card" id="ch-modified-card">
    <strong style="font-size:12px;text-transform:uppercase;color:#f59e0b">Modified</strong>
    <div id="ch-modified-list" class="muted">—</div>
  </div>
</div>
"""

_CHANGES_SCRIPT = r"""
async function chLoad() {
  const days = document.getElementById("ch-window").value;
  document.getElementById("ch-stats").textContent = "Loading…";
  try {
    const d = await scApi(`/api/platform/changes?since_days=${days}`);
    chRender(d);
  } catch(e) {
    document.getElementById("ch-stats").textContent = "Failed: " + e.message;
  }
}
function chRender(d) {
  if (d.no_baseline) {
    document.getElementById("ch-stats").innerHTML =
      `<span style="color:#f59e0b">📸 First snapshot taken just now</span>`;
    // v9.20.2 — friendly cold-start explainer instead of three zeros
    document.querySelector('#ch-summary').insertAdjacentHTML('beforebegin', `
      <div id="ch-coldstart" class="card" style="padding:18px;
           margin-bottom:14px;border-left:4px solid #f59e0b;
           background:#fef3c7;color:#78350f">
        <strong style="font-size:14px">First-run — there's no baseline to compare against yet.</strong>
        <p style="margin:6px 0 0;font-size:13px;line-height:1.5">
          SafeCadence just wrote today's inventory snapshot to
          <code style="background:rgba(255,255,255,.5);padding:1px 4px">
          ~/.safecadence/inventory_snapshots/${d.current_date}.json</code>.
          Come back tomorrow (or after any device add/remove/edit) and
          this page will show:
        </p>
        <ul style="margin:8px 0 0 20px;font-size:13px;line-height:1.7">
          <li><strong>Added</strong> — new devices that appeared since the snapshot</li>
          <li><strong>Removed</strong> — devices that vanished from inventory</li>
          <li><strong>Modified</strong> — devices whose hostname / vendor / site / criticality / tags changed</li>
        </ul>
      </div>`);
  } else {
    // Clean up cold-start banner if present from a previous render
    document.getElementById("ch-coldstart")?.remove();
    document.getElementById("ch-stats").textContent =
      `Comparing ${d.current_date} to ${d.baseline_date}`;
  }
  document.getElementById("ch-baseline").textContent =
    d.baseline_date || "(no baseline)";
  const c = d.counts || {};
  document.getElementById("ch-added-n").textContent = c.added || 0;
  document.getElementById("ch-removed-n").textContent = c.removed || 0;
  document.getElementById("ch-modified-n").textContent = c.modified || 0;
  function row(items, kind) {
    if (!items.length) return '<p class="muted" style="margin-top:6px">none</p>';
    return items.slice(0, 50).map(x => {
      const fields = (x.fields_changed || []).join(", ");
      const extra = kind === "modified" && fields
        ? `<div class="muted" style="font-size:11px">${fields}</div>` : "";
      return `<div style="padding:6px 8px;margin:4px 0;border-radius:4px;
        background:var(--panel-2);font-size:12px;cursor:pointer"
        onclick="location.href='/asset/${encodeURIComponent(x.asset_id)}'">
        <strong>${x.hostname || x.asset_id}</strong>
        <span class="muted" style="font-size:11px;margin-left:6px">
          ${x.type || ''} · ${x.vendor || ''} · ${x.site || ''}</span>
        ${extra}
      </div>`;
    }).join("");
  }
  document.getElementById("ch-added-list").innerHTML = row(d.added || [], "added");
  document.getElementById("ch-removed-list").innerHTML = row(d.removed || [], "removed");
  document.getElementById("ch-modified-list").innerHTML = row(d.modified || [], "modified");
}
chLoad();
"""


# ---------------------------------------------------------------- discovery jobs

_JOBS_BODY = """
<div style="display:flex;align-items:center;gap:12px;margin-bottom:8px">
  <h1 style="margin:0">⏱ Discovery jobs</h1>
  <span class="muted" id="jobs-stats" style="font-size:12px"></span>
  <span style="flex:1"></span>
  <button class="primary" onclick="openJobCreate()"
          style="width:auto;padding:8px 14px">+ Schedule new job</button>
</div>
<p class="muted" style="margin-top:0">
  Schedule recurring discovery — SNMP harvests against your routers, AD
  pulls every morning, cloud refreshes every few hours. The
  <code>safecadence daemon</code> picks up these jobs and fires them on
  schedule. You can also <strong>Run now</strong> any job manually.
</p>

<div class="card" style="padding:0">
  <table id="jobs-tbl">
    <thead><tr>
      <th>Name</th><th>Source</th><th>Interval</th><th>Last run</th>
      <th>Next run</th><th>Status</th><th></th>
    </tr></thead>
    <tbody><tr><td colspan="7" class="muted" style="padding:32px;text-align:center">Loading…</td></tr></tbody>
  </table>
</div>
"""

_JOBS_SCRIPT = r"""
async function jobsLoad() {
  try {
    const r = await scApi("/api/platform/discovery-jobs");
    const jobs = r.jobs || [];
    document.getElementById("jobs-stats").textContent =
      `${jobs.length} job${jobs.length===1?'':'s'} scheduled`;
    const tbody = document.querySelector("#jobs-tbl tbody");
    if (!jobs.length) {
      tbody.innerHTML = `<tr><td colspan="7" class="muted"
        style="padding:48px;text-align:center">
        No scheduled jobs yet.
        <a href="#" onclick="openJobCreate();return false">Schedule your first one →</a>
        </td></tr>`;
      return;
    }
    tbody.innerHTML = jobs.map(j => {
      const status = j.last_status || "pending";
      const sev = status==="ok" ? "pill-ok" : status==="error" ? "pill-crit" : "pill-info";
      // v9.23: surface last_error as a tooltip on failed jobs so the
      // daemon hook's failures are visible without digging into ~/.safecadence.
      const err = (j.last_error || "").replace(/"/g, "&quot;");
      const statusBadge = status === "error" && err
        ? `<span class="pill ${sev}" title="${err}" style="cursor:help">${status} ⓘ</span>`
        : `<span class="pill ${sev}">${status}</span>`;
      return `<tr>
        <td><strong>${j.name}</strong>
          <div class="muted" style="font-size:11px">${j.job_id}</div></td>
        <td>${j.source}</td>
        <td>every ${j.interval_hours}h</td>
        <td class="muted" style="font-size:11px">${(j.last_run_at||'').slice(0,16) || '—'}</td>
        <td class="muted" style="font-size:11px">${(j.next_run_at||'').slice(0,16) || '—'}</td>
        <td>${statusBadge}</td>
        <td style="text-align:right">
          <button class="alt" style="width:auto;padding:4px 10px;font-size:11px"
                  onclick="jobRun('${j.job_id}')">▶ Run now</button>
          <button class="alt" style="width:auto;padding:4px 10px;font-size:11px;
                  background:#fef3c7;color:#92400e"
                  onclick="jobDelete('${j.job_id}')">🗑</button>
        </td>
      </tr>`;
    }).join("");
  } catch(e) {
    document.querySelector("#jobs-tbl tbody").innerHTML =
      `<tr><td colspan="7" class="muted">${e.message}</td></tr>`;
  }
}
function openJobCreate() {
  scOpenSlide("Schedule discovery job", `
    <p class="muted">Choose a source and how often to run it. The
       daemon will pick up the schedule.</p>
    <label class="ml">Job name *</label>
    <input id="nj-name" placeholder="Pull AD computers daily" />
    <label class="ml">Source *</label>
    <select id="nj-source">
      <option value="lan-scan">LAN scan</option>
      <option value="snmp">SNMP harvest</option>
      <option value="ad">Active Directory</option>
      <option value="entra">Entra ID</option>
      <option value="dhcp">DHCP leases</option>
      <option value="aws">AWS</option>
      <option value="azure">Azure</option>
      <option value="gcp">GCP</option>
    </select>
    <label class="ml">Interval (hours) *</label>
    <input id="nj-int" type="number" min="1" value="24" />
    <label class="ml">Params (one per line: <code>key=value</code>)</label>
    <textarea id="nj-params" placeholder="cidr=10.0.0.0/24
community=public
host=10.0.0.1" style="font-family:monospace;font-size:11px;height:80px"></textarea>
    <button class="primary" style="margin-top:10px"
            onclick="jobCreate()">Schedule</button>
    <div id="nj-status" class="muted" style="margin-top:8px;font-size:12px"></div>
    <style>#scSlideBody label.ml{display:block;font-size:11px;font-weight:600;
      margin:8px 0 3px;color:var(--muted)}
      #scSlideBody input,#scSlideBody select,#scSlideBody textarea{width:100%;
      padding:7px;border-radius:6px;border:1px solid var(--border);
      background:var(--bg);color:var(--text);font-size:12px}</style>
  `);
}
async function jobCreate() {
  const params = {};
  for (const line of (document.getElementById("nj-params").value || "").split("\n")) {
    const [k, v] = line.split("=").map(s => (s||"").trim());
    if (k && v) params[k] = v;
  }
  try {
    await scApi("/api/platform/discovery-jobs", {
      method: "POST",
      body: JSON.stringify({
        name: document.getElementById("nj-name").value,
        source: document.getElementById("nj-source").value,
        interval_hours: Number(document.getElementById("nj-int").value),
        params,
      }),
    });
    scCloseSlide(); jobsLoad();
  } catch(e) {
    document.getElementById("nj-status").innerHTML =
      `<span style="color:#f97373">${e.message}</span>`;
  }
}
async function jobRun(id) {
  try {
    const r = await scApi(`/api/platform/discovery-jobs/${id}/run-now`,
                          {method: "POST"});
    if (r.redirect) {
      alert(r.hint + "\n\nRedirecting to inventory…");
      location.href = r.redirect;
    } else { jobsLoad(); }
  } catch(e) { alert(e.message); }
}
async function jobDelete(id) {
  if (!confirm(`Delete this scheduled job?`)) return;
  try {
    await scApi(`/api/platform/discovery-jobs/${id}`, {method:"DELETE"});
    jobsLoad();
  } catch(e) { alert(e.message); }
}
jobsLoad();
"""


# ---------------------------------------------------------------- tags

_TAGS_BODY = """
<div style="display:flex;align-items:center;gap:12px;margin-bottom:8px">
  <h1 style="margin:0">🏷 Tags</h1>
  <span class="muted" id="tags-stats" style="font-size:12px"></span>
  <span style="flex:1"></span>
  <input id="tags-search" placeholder="🔍 filter…"
         oninput="tagsRender()"
         style="padding:6px 10px;border-radius:6px;width:240px;
                border:1px solid var(--border);background:var(--bg);
                color:var(--text);font-size:12px"/>
</div>

<!-- v9.20.2 — what tags do + cheatsheet -->
<div class="card" style="padding:14px 16px;margin-bottom:14px;
     background:linear-gradient(135deg,var(--panel),var(--panel-2))">
  <strong style="font-size:13px">What tags do — the short version</strong>
  <p style="margin:6px 0;font-size:12px;line-height:1.5">
    Tags are how SafeCadence ties everything together. They drive:
  </p>
  <ul style="margin:0 0 8px 20px;font-size:12px;line-height:1.6">
    <li><strong>Groups</strong> — <code>{filter:{field:'env',op:'eq',value:'prod'}}</code> resolves to every asset tagged <code>env:prod</code></li>
    <li><strong>Policies</strong> — "All prod Cisco gear" targets <code>env:prod</code> + <code>vendor:cisco</code></li>
    <li><strong>AI enrichment</strong> — auto-sets <code>role:</code>, <code>env:</code>, <code>criticality:</code> from hostname/config</li>
    <li><strong>Compliance scope</strong> — <code>compliance:pci</code> tags drive the <a href="/scope">/scope</a> page</li>
  </ul>
  <strong style="font-size:11px;text-transform:uppercase;color:var(--muted)">Common tag families</strong>
  <div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:6px">
    <span class="pill pill-info">env:prod / staging / dev</span>
    <span class="pill pill-info">site:dc1 / branch-nyc</span>
    <span class="pill pill-info">role:edge-router / core / access / db-server</span>
    <span class="pill pill-info">vendor:cisco / arista / palo-alto</span>
    <span class="pill pill-info">criticality:crown-jewel / high / medium</span>
    <span class="pill pill-info">compliance:pci / soc2 / hipaa</span>
    <span class="pill pill-info">team:network-eng / data-eng</span>
  </div>
  <p style="margin:10px 0 0;font-size:11.5px;color:var(--muted)">
    Tags are added 3 ways: (1) AI enrichment when a device is discovered,
    (2) manually on any <a href="/inventory">asset cockpit</a> →
    Custom fields, (3) by editing a CSV on import.
  </p>
</div>

<div class="card" style="padding:0">
  <table id="tags-tbl">
    <thead><tr><th>Tag</th><th>Usage</th><th></th></tr></thead>
    <tbody><tr><td colspan="3" class="muted" style="padding:30px;text-align:center">Loading…</td></tr></tbody>
  </table>
</div>

<p class="muted" style="margin-top:14px;font-size:11px">
  ✎ rename = applies the new name to every asset that had the old tag.
  🗑 delete = strips the tag from every asset (the assets stay).
</p>
"""

_TAGS_SCRIPT = r"""
let TAG_DATA = [];
async function tagsLoad() {
  try {
    const r = await scApi("/api/platform/tags");
    TAG_DATA = r.tags || [];
    document.getElementById("tags-stats").textContent =
      `${TAG_DATA.length} unique tag${TAG_DATA.length===1?'':'s'}`;
    tagsRender();
  } catch(e) {
    document.querySelector("#tags-tbl tbody").innerHTML =
      `<tr><td colspan="3" class="muted">${e.message}</td></tr>`;
  }
}
function tagsRender() {
  const q = (document.getElementById("tags-search").value || "").toLowerCase();
  const items = TAG_DATA.filter(t => !q || t.tag.toLowerCase().includes(q));
  const tbody = document.querySelector("#tags-tbl tbody");
  if (!items.length) {
    tbody.innerHTML = `<tr><td colspan="3" class="muted"
       style="padding:30px;text-align:center">No tags${q?' match':''}.</td></tr>`;
    return;
  }
  tbody.innerHTML = items.map(t => `<tr>
    <td><code>${t.tag}</code></td>
    <td>${t.count}</td>
    <td style="text-align:right">
      <button class="alt" style="width:auto;padding:4px 10px;font-size:11px"
              onclick="tagRename('${t.tag}')">✎ rename</button>
      <button class="alt" style="width:auto;padding:4px 10px;font-size:11px;
              background:#fef3c7;color:#92400e"
              onclick="tagDelete('${t.tag}')">🗑</button>
    </td>
  </tr>`).join("");
}
async function tagRename(old) {
  const next = prompt(`Rename "${old}" to:`, old);
  if (next === null || next === old) return;
  try {
    const r = await scApi("/api/platform/tags/rename",
                          {method: "POST",
                           body: JSON.stringify({old_tag: old, new_tag: next})});
    alert(`Renamed across ${r.renamed} asset${r.renamed===1?'':'s'}.`);
    tagsLoad();
  } catch(e) { alert(e.message); }
}
async function tagDelete(old) {
  if (!confirm(`Delete "${old}" from every asset?`)) return;
  try {
    const r = await scApi("/api/platform/tags/rename",
                          {method: "POST",
                           body: JSON.stringify({old_tag: old, new_tag: ""})});
    alert(`Removed from ${r.renamed} asset${r.renamed===1?'':'s'}.`);
    tagsLoad();
  } catch(e) { alert(e.message); }
}
tagsLoad();
"""


# ---------------------------------------------------------------- scope

_SCOPE_BODY = """
<div style="display:flex;align-items:center;gap:12px;margin-bottom:8px">
  <h1 style="margin:0">📑 Compliance scope</h1>
  <span class="muted" id="sc-stats" style="font-size:12px"></span>
</div>
<p class="muted" style="margin-top:0">
  Which assets fall under which compliance framework? Driven by
  <code>compliance:&lt;framework&gt;</code> tags (e.g.
  <code>compliance:pci</code>, <code>compliance:soc2</code>,
  <code>compliance:hipaa</code>). Tag any asset on its cockpit page or
  via the <a href="/tags">/tags</a> page.
</p>

<div id="scope-frameworks"></div>
"""

_SCOPE_SCRIPT = r"""
async function scopeLoad() {
  try {
    const r = await scApi("/api/platform/scope");
    const frameworks = r.frameworks || [];
    document.getElementById("sc-stats").textContent =
      `${frameworks.length} framework${frameworks.length===1?'':'s'} in use`;
    const host = document.getElementById("scope-frameworks");
    if (!frameworks.length) {
      // v9.20.2 — actionable empty state with one-click tag wizard
      host.innerHTML = `
        <div class="card" style="padding:24px;margin-top:14px">
          <h3 style="margin:0">No compliance scope tags yet</h3>
          <p class="muted" style="margin-top:8px;font-size:13px;line-height:1.55">
            This page groups assets by <code>compliance:&lt;framework&gt;</code>
            tag — once any asset is tagged, it appears here under its
            framework card.</p>
          <p class="muted" style="font-size:13px;line-height:1.55">
            <strong>Three frameworks the wizard knows about:</strong>
          </p>
          <div style="display:grid;gap:10px;
               grid-template-columns:repeat(auto-fit,minmax(220px,1fr));
               margin-top:8px">
            <button class="alt" onclick="scopeWizard('pci')"
              style="text-align:left;padding:12px"><b>💳 PCI DSS</b><br/>
              <span class="muted" style="font-size:11px">
                Cardholder-data systems (DBs, payment apps, key mgmt)
              </span></button>
            <button class="alt" onclick="scopeWizard('soc2')"
              style="text-align:left;padding:12px"><b>📋 SOC 2</b><br/>
              <span class="muted" style="font-size:11px">
                Customer-data + production access (most prod servers)
              </span></button>
            <button class="alt" onclick="scopeWizard('hipaa')"
              style="text-align:left;padding:12px"><b>🏥 HIPAA</b><br/>
              <span class="muted" style="font-size:11px">
                Anything that touches PHI
              </span></button>
          </div>
          <p class="muted" style="font-size:11.5px;margin-top:14px">
            Or tag assets manually: open any
            <a href="/inventory">asset cockpit</a> → Custom fields → add tag
            <code>compliance:pci</code>. The tag is then renamable and
            deletable from <a href="/tags">/tags</a> like any other.
          </p>
        </div>`;
      return;
    }
    host.innerHTML = frameworks.map(f => `
      <details open class="card" style="padding:14px;margin-top:10px">
        <summary style="cursor:pointer;font-size:14px;font-weight:600">
          ${f.framework.toUpperCase()}
          <span class="muted" style="font-weight:400;margin-left:8px">
            ${f.count} asset${f.count===1?'':'s'} in scope</span>
        </summary>
        <div style="display:grid;gap:6px;margin-top:10px;
             grid-template-columns:repeat(auto-fit,minmax(220px,1fr))">
          ${f.members.map(m => `<div onclick="location.href='/asset/${encodeURIComponent(m.asset_id)}'"
            style="padding:6px 10px;border-radius:4px;background:var(--panel-2);
              cursor:pointer;font-size:12px">
            <strong>${m.hostname || m.asset_id}</strong>
            <div class="muted" style="font-size:11px">
              ${m.asset_type || ''} · ${m.site || ''} · ${m.criticality || ''}</div>
          </div>`).join("")}
        </div>
      </details>
    `).join("");
  } catch(e) {
    document.getElementById("sc-stats").textContent = "Failed: " + e.message;
  }
}
// v9.20.2 — wizard: pick assets, bulk-tag with compliance:<framework>
async function scopeWizard(framework) {
  let inv;
  try { inv = await scApi("/api/platform/inventory"); }
  catch(e) { alert("Couldn't load inventory: " + e.message); return; }
  const assets = (inv.assets || []).slice(0, 200).map(a => {
    const i = a.identity || {};
    return {id: i.asset_id, label: i.hostname || i.asset_id,
            type: i.asset_type, crit: i.criticality, site: i.site};
  });
  scOpenSlide(`Tag assets as compliance:${framework}`, `
    <p class="muted">Pick the assets that fall in <strong>${framework.toUpperCase()}</strong>
       scope. They'll get the tag <code>compliance:${framework}</code>
       added — and immediately appear under that framework's card on
       this page.</p>
    <div style="display:flex;gap:6px;align-items:center;margin:8px 0">
      <input id="sw-search" placeholder="🔍 filter…"
             oninput="scopeWizardFilter()"
             style="flex:1;padding:6px 8px;border-radius:4px;
                    border:1px solid var(--border);background:var(--bg);
                    color:var(--text);font-size:12px"/>
      <button class="alt" style="width:auto;padding:4px 10px;font-size:11px"
              onclick="scopeWizardSelectAll(true)">all</button>
      <button class="alt" style="width:auto;padding:4px 10px;font-size:11px"
              onclick="scopeWizardSelectAll(false)">none</button>
    </div>
    <div id="sw-list" class="card" style="padding:0;max-height:340px;
         overflow:auto"></div>
    <button class="primary" style="margin-top:10px"
            onclick="scopeWizardCommit('${framework}')">
      Tag selected as compliance:${framework}</button>
    <div id="sw-status" class="muted" style="margin-top:8px;font-size:12px"></div>
  `);
  window._SW_ASSETS = assets;
  scopeWizardFilter();
}

function scopeWizardFilter() {
  const q = (document.getElementById("sw-search")?.value || "").toLowerCase();
  const items = (window._SW_ASSETS || []).filter(a =>
    !q || (a.label + " " + (a.type||"") + " " + (a.crit||"") +
           " " + (a.site||"")).toLowerCase().includes(q));
  document.getElementById("sw-list").innerHTML = items.map(a => `
    <label style="display:flex;align-items:center;gap:8px;padding:6px 10px;
      border-bottom:1px solid var(--border);font-size:12px;cursor:pointer">
      <input type="checkbox" class="sw-pick" value="${a.id}" style="width:auto"/>
      <strong style="flex:1">${a.label}</strong>
      <span class="muted">${a.type||''} · ${a.site||''} · ${a.crit||''}</span>
    </label>`).join("");
}
function scopeWizardSelectAll(on) {
  document.querySelectorAll(".sw-pick").forEach(c => c.checked = on);
}
async function scopeWizardCommit(framework) {
  const ids = Array.from(document.querySelectorAll(".sw-pick:checked"))
                   .map(c => c.value);
  if (!ids.length) { alert("Pick at least one asset"); return; }
  const stat = document.getElementById("sw-status");
  stat.textContent = `Tagging ${ids.length} asset(s)…`;
  let ok = 0, fail = 0;
  for (const id of ids) {
    try {
      // Read existing tags, append the new one, PUT
      const a = await scApi(`/api/platform/asset/${encodeURIComponent(id)}`);
      const tags = (a.identity || {}).tags || [];
      const tag = `compliance:${framework}`;
      if (!tags.includes(tag)) tags.push(tag);
      await scApi(`/api/platform/asset/${encodeURIComponent(id)}`,
                  {method: "PUT", body: JSON.stringify({tags})});
      ok++;
    } catch(e) { fail++; }
  }
  stat.innerHTML = `<span style="color:#10b981">✓</span> Tagged ${ok}` +
                   (fail ? ` (${fail} failed)` : "");
  setTimeout(() => { scCloseSlide(); scopeLoad(); }, 700);
}

scopeLoad();
"""


# ---------------------------------------------------------------- per-device diff

_PDD_BODY = """
<div style="display:flex;align-items:center;gap:12px;margin-bottom:8px">
  <h1 style="margin:0">⇆ Per-device diff</h1>
  <span class="muted" id="pdd-stats" style="font-size:12px"></span>
</div>
<p class="muted" style="margin-top:0">
  Two modes: compare any two devices (A vs B) for drift detection, OR
  pass <code>?job=&lt;job_id&gt;</code> to see what each device's running
  config looked like before vs after that job ran.
</p>

<!-- v9.35 #3 — job-scoped diff. Hidden until the URL has ?job=… -->
<div id="pdd-job-mode" class="card" style="padding:14px;display:none;margin-bottom:14px">
  <div style="display:flex;align-items:center;gap:8px">
    <strong>Job</strong>
    <code id="pdd-job-id" style="font-size:12px"></code>
    <span class="muted" id="pdd-job-summary" style="margin-left:auto;font-size:11px"></span>
  </div>
  <div id="pdd-job-execs" style="margin-top:10px"></div>
</div>

<div style="display:grid;gap:10px;grid-template-columns:1fr 1fr;
            margin-bottom:12px">
  <div class="card" style="padding:10px">
    <label style="font-size:11px;font-weight:600;text-transform:uppercase;
                  color:var(--muted)">Device A</label>
    <input id="pdd-a" placeholder="asset_id (e.g. core-sw-01)"
           style="width:100%;padding:7px;border-radius:6px;border:1px solid var(--border);
                  background:var(--bg);color:var(--text);font-size:12px;margin-top:4px"/>
  </div>
  <div class="card" style="padding:10px">
    <label style="font-size:11px;font-weight:600;text-transform:uppercase;
                  color:var(--muted)">Device B</label>
    <input id="pdd-b" placeholder="asset_id (e.g. core-sw-02)"
           style="width:100%;padding:7px;border-radius:6px;border:1px solid var(--border);
                  background:var(--bg);color:var(--text);font-size:12px;margin-top:4px"/>
  </div>
</div>
<div style="display:flex;gap:8px;margin-bottom:14px;align-items:center">
  <button class="primary" onclick="pddRun()"
          style="width:auto;padding:8px 14px">⇆  Compare</button>
  <button class="alt" onclick="pddSwap()"
          style="width:auto;padding:8px 14px;font-size:12px">⇌ Swap</button>
  <span class="muted" id="pdd-meta" style="font-size:11px;margin-left:8px"></span>
</div>

<div id="pdd-empty" class="card" style="padding:24px;text-align:center">
  <p class="muted">Pick two assets above to compare their running configs.
     Both must have <code>raw_collection.running</code> populated — run
     <strong>📡 SNMP harvest</strong> from /inventory if either is missing
     config data.</p>
</div>
<div id="pdd-result" style="display:none">
  <div style="display:grid;gap:10px;grid-template-columns:1fr 1fr;
              margin-bottom:10px">
    <div class="card" style="padding:8px 12px">
      <strong id="pdd-a-name">A</strong>
      <div class="muted" style="font-size:11px" id="pdd-a-meta"></div>
    </div>
    <div class="card" style="padding:8px 12px">
      <strong id="pdd-b-name">B</strong>
      <div class="muted" style="font-size:11px" id="pdd-b-meta"></div>
    </div>
  </div>
  <div class="card" style="padding:0;overflow:hidden">
    <div style="padding:8px 14px;border-bottom:1px solid var(--border);
                font-size:12px">
      <span id="pdd-summary"></span>
    </div>
    <div id="pdd-diff" style="font-family:ui-monospace,Menlo,monospace;
         font-size:11.5px;line-height:1.45;max-height:60vh;overflow:auto"></div>
  </div>
</div>
"""

_PDD_SCRIPT = r"""
(function() {
  // Pre-fill from URL: ?a=foo&b=bar
  const q = new URLSearchParams(location.search);
  const a = q.get("a") || q.get("asset_id");
  const b = q.get("b");
  const jobId = q.get("job");
  if (a) setTimeout(()=>{document.getElementById("pdd-a").value = a;}, 30);
  if (b) setTimeout(()=>{document.getElementById("pdd-b").value = b;}, 30);
  if (a && b) setTimeout(pddRun, 100);
  // v9.35 #3 — job mode pulls from /api/execute/jobs/{id}/config-diff.
  if (jobId) setTimeout(() => pddLoadJobDiff(jobId), 50);
})();

// v9.35 #3 — render before/after diff for every execution under a job.
async function pddLoadJobDiff(jobId) {
  const jobBox = document.getElementById("pdd-job-mode");
  jobBox.style.display = "block";
  document.getElementById("pdd-job-id").textContent = jobId;
  const summary = document.getElementById("pdd-job-summary");
  const execsDiv = document.getElementById("pdd-job-execs");
  execsDiv.innerHTML = '<p class="muted">Loading…</p>';
  try {
    const r = await fetch(`/api/execute/jobs/${encodeURIComponent(jobId)}/config-diff`,
                            { credentials: 'include' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const data = await r.json();
    const execs = data.executions || [];
    summary.textContent = execs.length + ' execution(s)';
    if (!execs.length) {
      execsDiv.innerHTML = `<p class="muted">No executions for this job yet.</p>`;
      return;
    }
    execsDiv.innerHTML = execs.map(e => {
      const dryRunBadge = e.dry_run
        ? '<span class="pill pill-info">dry-run</span>' : '';
      if (!e.has_snapshots) {
        return `<div class="card" style="padding:10px;margin-top:8px">
          <strong>${pddEsc(e.asset_id)}</strong>
          <span class="muted" style="margin-left:6px">${pddEsc(e.vendor || '')}</span>
          ${dryRunBadge}
          <div class="muted" style="font-size:11px;margin-top:4px">
            No pre/post config snapshots captured for this execution.
            Snapshots are captured by Tier-3 SSH; dry-run + manual-execution
            modes don't fetch them.
          </div>
        </div>`;
      }
      const diffHTML = (e.unified_diff || []).map(line => {
        let cls = '';
        if (line.startsWith('+++') || line.startsWith('---')) cls = 'muted';
        else if (line.startsWith('+')) cls = 'diff-add';
        else if (line.startsWith('-')) cls = 'diff-del';
        else if (line.startsWith('@@')) cls = 'diff-hunk';
        return `<span class="${cls}">${pddEsc(line)}</span>`;
      }).join('\n');
      return `<div class="card" style="padding:10px;margin-top:8px">
        <div style="display:flex;align-items:center;gap:8px">
          <strong>${pddEsc(e.asset_id)}</strong>
          <span class="muted" style="font-size:11px">${pddEsc(e.vendor || '')}</span>
          ${dryRunBadge}
          <span class="muted" style="margin-left:auto;font-size:11px">
            <span style="color:#2ea44f">+${e.added_lines || 0}</span>
            <span style="color:#d04646;margin-left:6px">-${e.removed_lines || 0}</span>
          </span>
        </div>
        <pre style="font-family:ui-monospace,Menlo,monospace;font-size:11px;
                    line-height:1.45;margin-top:8px;max-height:50vh;
                    overflow:auto;white-space:pre-wrap">${diffHTML}</pre>
      </div>`;
    }).join('');
  } catch (err) {
    execsDiv.innerHTML = `<p class="muted">Failed to load: ${pddEsc(err.message)}</p>`;
  }
}

function pddEsc(s) {
  const d = document.createElement('div');
  d.textContent = String(s == null ? '' : s);
  return d.innerHTML;
}

function pddSwap() {
  const a = document.getElementById("pdd-a");
  const b = document.getElementById("pdd-b");
  [a.value, b.value] = [b.value, a.value];
}

async function pddRun() {
  const a = document.getElementById("pdd-a").value.trim();
  const b = document.getElementById("pdd-b").value.trim();
  if (!a || !b) { alert("Pick both A and B"); return; }
  if (a === b)  { alert("A and B are the same"); return; }
  document.getElementById("pdd-meta").textContent = "Loading…";
  let assetA, assetB;
  try {
    [assetA, assetB] = await Promise.all([
      scApi(`/api/platform/asset/${encodeURIComponent(a)}`),
      scApi(`/api/platform/asset/${encodeURIComponent(b)}`),
    ]);
  } catch(e) {
    document.getElementById("pdd-meta").innerHTML =
      `<span style="color:#f97373">${e.message}</span>`;
    return;
  }
  const cfgA = pddCfg(assetA);
  const cfgB = pddCfg(assetB);
  if (!cfgA || !cfgB) {
    document.getElementById("pdd-meta").innerHTML =
      `<span style="color:#f59e0b">⚠ Missing running config on ` +
      `${!cfgA ? a : b}. Run SNMP harvest from /inventory to populate it.</span>`;
    return;
  }
  pddRender(assetA, assetB, cfgA, cfgB);
}

function pddCfg(asset) {
  const raw = asset && asset.raw_collection;
  if (!raw || typeof raw !== "object") return null;
  return raw.running || raw.config || raw.startup || raw.text || null;
}

function pddRender(aA, aB, cA, cB) {
  document.getElementById("pdd-empty").style.display = "none";
  document.getElementById("pdd-result").style.display = "block";
  const idA = aA.identity || {}; const idB = aB.identity || {};
  document.getElementById("pdd-a-name").textContent = idA.hostname || idA.asset_id || "A";
  document.getElementById("pdd-b-name").textContent = idB.hostname || idB.asset_id || "B";
  document.getElementById("pdd-a-meta").textContent =
    `${idA.vendor||''} · ${idA.asset_type||''} · ${idA.site||''}`;
  document.getElementById("pdd-b-meta").textContent =
    `${idB.vendor||''} · ${idB.asset_type||''} · ${idB.site||''}`;

  const linesA = (cA || "").split("\n");
  const linesB = (cB || "").split("\n");
  const diff = pddLineDiff(linesA, linesB);

  const adds = diff.filter(d => d.kind === "+").length;
  const dels = diff.filter(d => d.kind === "-").length;
  const same = diff.filter(d => d.kind === " ").length;
  document.getElementById("pdd-summary").innerHTML =
    `<strong>${adds}</strong> added · <strong>${dels}</strong> removed · ` +
    `<strong>${same}</strong> unchanged · ${diff.length} total`;
  document.getElementById("pdd-meta").innerHTML =
    adds + dels === 0
      ? `<span style="color:#10b981">✓ Configs identical</span>`
      : `<span style="color:#f59e0b">${adds + dels} differences</span>`;

  // Render unified diff with color coding
  const esc = s => (s||"").replace(/[<>&]/g, c =>
                    ({"<":"&lt;",">":"&gt;","&":"&amp;"}[c]));
  const rows = diff.map(d => {
    const bg = d.kind === "+" ? "rgba(16,185,129,.16)"
             : d.kind === "-" ? "rgba(239,68,68,.16)" : "transparent";
    const sig = d.kind === "+" ? '<span style="color:#10b981">+</span>'
              : d.kind === "-" ? '<span style="color:#ef4444">−</span>'
              : ' ';
    return `<div style="background:${bg};padding:1px 12px;display:flex;gap:8px">
      <span style="color:var(--muted);width:14px">${sig}</span>
      <span style="white-space:pre">${esc(d.line)}</span>
    </div>`;
  }).join("");
  document.getElementById("pdd-diff").innerHTML = rows;
}

// O(N+M) approximate diff — group consecutive removals + additions.
// Good enough for human eyeballing; matches what `diff -u` shows for
// most config-file changes. Not LCS-perfect on heavy reorderings.
function pddLineDiff(a, b) {
  const setA = new Set(a);
  const setB = new Set(b);
  const out = [];
  let i = 0, j = 0;
  while (i < a.length || j < b.length) {
    const lA = a[i], lB = b[j];
    if (i >= a.length) { out.push({kind:"+", line: lB}); j++; continue; }
    if (j >= b.length) { out.push({kind:"-", line: lA}); i++; continue; }
    if (lA === lB) { out.push({kind:" ", line: lA}); i++; j++; continue; }
    // Heuristic: if A's current line shows up later in B, treat current B
    // line as added; else treat A's as removed.
    if (setB.has(lA) && !setA.has(lB)) {
      out.push({kind:"+", line: lB}); j++;
    } else {
      out.push({kind:"-", line: lA}); i++;
    }
  }
  return out;
}
"""


# ---------------------------------------------------------------- coverage


_COVERAGE_BODY = """
<div style="display:flex;align-items:center;gap:12px;margin-bottom:8px">
  <h1 style="margin:0">📊 Discovery coverage</h1>
  <span class="muted" id="cov-stats" style="font-size:12px"></span>
  <span style="flex:1"></span>
  <button class="alt" style="width:auto;padding:6px 10px;font-size:12px"
          onclick="covLoad()">⟳ Reload</button>
</div>
<p class="muted" style="margin-top:0">
  Are we even seeing what we should be? Each card below is a discovery
  source. Green = fresh, yellow = stale, red = very stale, gray = never
  connected. The recommendations on the right are ordered by visibility
  multiplier.
</p>

<div style="display:grid;gap:12px;grid-template-columns:1fr 320px">
  <!-- LEFT: source cards + score -->
  <div>
    <div class="card" id="cov-score" style="padding:18px;
         background:linear-gradient(135deg,var(--panel),var(--panel-2))">
      <div class="muted">Loading…</div>
    </div>
    <div id="cov-sources"
         style="display:grid;gap:10px;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));
                margin-top:12px"></div>

    <!-- v9.20.1 — recent discovery activity strip -->
    <h2 style="font-size:14px;margin:18px 0 6px">Recent discovery activity</h2>
    <p class="muted" style="margin:0 0 6px;font-size:12px">
      Last 10 LAN scans persisted by SafeCadence. SNMP/AD/Entra/DHCP/cloud
      runs aren't logged here yet — they show up via the asset's
      <code>discovery_source</code> + <code>last_seen</code>.
    </p>
    <div id="cov-activity" class="card" style="padding:0">
      <div class="muted" style="padding:14px">Loading…</div>
    </div>
  </div>

  <!-- RIGHT: recommendations -->
  <div class="card" style="padding:14px;overflow:auto">
    <div style="font-size:11px;text-transform:uppercase;color:var(--muted);
                font-weight:600;margin-bottom:8px">Recommendations</div>
    <div id="cov-recs" class="muted">Loading…</div>
  </div>
</div>
"""

_COVERAGE_SCRIPT = r"""
async function covLoad() {
  document.getElementById("cov-score").innerHTML = '<div class="muted">Loading…</div>';
  document.getElementById("cov-sources").innerHTML = '';
  document.getElementById("cov-recs").innerHTML = '<div class="muted">Loading…</div>';
  try {
    const data = await scApi("/api/platform/coverage");
    covRender(data);
  } catch(e) {
    document.getElementById("cov-score").innerHTML =
      `<span style="color:#f97373">Failed: ${e.message}</span>`;
  }
}

function covRender(d) {
  const t = d.totals || {};
  const score = d.score || 0;
  const ringColor = score >= 80 ? "#10b981"
                  : score >= 50 ? "#f59e0b" : "#ef4444";
  document.getElementById("cov-stats").textContent =
    `${t.fleet_size || 0} assets · ${t.distinct_sources || 0} source${
      (t.distinct_sources===1)?'':'s'} connected` +
    (t.hours_since_freshest_source != null
       ? ` · freshest ${t.hours_since_freshest_source.toFixed(1)}h ago`
       : '');

  document.getElementById("cov-score").innerHTML = `
    <div style="display:flex;align-items:center;gap:18px">
      <div style="width:90px;height:90px;border-radius:50%;
        background:conic-gradient(${ringColor} ${score*3.6}deg,
                                  rgba(255,255,255,.06) 0);
        display:flex;align-items:center;justify-content:center">
        <div style="width:74px;height:74px;border-radius:50%;
          background:var(--panel);display:flex;align-items:center;
          justify-content:center;font-size:22px;font-weight:700;
          color:${ringColor}">${score}</div>
      </div>
      <div>
        <div style="font-size:13px;font-weight:600;text-transform:uppercase;
                    color:var(--muted)">Coverage score</div>
        <div style="font-size:14px;margin-top:4px">
          ${score >= 80 ? '✅ Healthy — most sources connected and fresh.'
            : score >= 50 ? '⚠ Partial — some big sources missing or stale.'
            : '🚨 Limited visibility — large parts of the fleet probably invisible.'}
        </div>
        <div class="muted" style="font-size:11px;margin-top:6px">
          Heuristic. Real coverage depends on which sources are right for
          your environment — not all orgs need every connector.
        </div>
      </div>
    </div>
  `;

  // Source cards (v9.20.1 — added inline Run / Reconnect button per card)
  const host = document.getElementById("cov-sources");
  host.innerHTML = (d.sources || []).map(s => {
    const ageStr = s.last_seen_at
      ? `${s.hours_since.toFixed(1)}h ago`
      : (s.connected ? 'no timestamp' : 'never connected');
    const gapPill = {
      "fresh":           '<span class="pill pill-ok">fresh</span>',
      "stale":           '<span class="pill pill-high">stale</span>',
      "very-stale":      '<span class="pill pill-crit">very stale</span>',
      "no-timestamp":    '<span class="pill pill-info">no ts</span>',
      "never-connected": '<span class="pill" style="background:#9ca3af;color:#fff">offline</span>',
    }[s.estimated_gap] || '';
    // Only sources that have a hero card on /inventory get an inline button
    const RUN_KEYS = {"lan-scan":1,"snmp":1,"ad":1,"entra":1,"dhcp":1,
                     "aws":1,"azure":1,"gcp":1,"manual":1,"import":1};
    const btn = RUN_KEYS[s.key]
      ? `<a href="/inventory?open=${s.key}"
            style="display:block;margin-top:8px;padding:5px 8px;font-size:11px;
                   text-align:center;border-radius:4px;text-decoration:none;
                   background:${s.connected ? 'var(--panel)' : 'var(--accent)'};
                   color:${s.connected ? 'var(--text)' : '#fff'};
                   border:1px solid ${s.connected ? 'var(--border)' : 'var(--accent)'}">
            ${s.connected ? '↻  Run again' : '+  Connect'}
         </a>` : "";
    return `<div class="card" style="padding:12px;border-left:3px solid ${s.status_color}">
      <div style="display:flex;align-items:center;gap:8px">
        <span style="display:inline-block;width:10px;height:10px;
          border-radius:50%;background:${s.status_color}"></span>
        <strong>${s.label}</strong>
        <span style="flex:1"></span>
        ${gapPill}
      </div>
      <div class="muted" style="font-size:11px;margin-top:4px">${s.hint}</div>
      <div style="margin-top:8px;display:flex;justify-content:space-between;
                  font-size:12px">
        <span><strong>${s.asset_count}</strong>
          asset${s.asset_count===1?'':'s'}</span>
        <span class="muted">${ageStr}</span>
      </div>
      ${btn}
    </div>`;
  }).join("");

  // Recommendations (deep-linked CTAs — each opens the right hero card)
  const recHost = document.getElementById("cov-recs");
  if (!d.recommendations || !d.recommendations.length) {
    recHost.innerHTML =
      `<p class="muted">All known sources connected and fresh. 🎉</p>`;
  } else {
    recHost.innerHTML = d.recommendations.map(r => {
      const sev = r.priority === "high"   ? "pill-crit"
                : r.priority === "medium" ? "pill-high" : "pill-info";
      return `<div style="padding:10px;border-radius:6px;margin-bottom:8px;
                background:var(--panel-2)">
        <div style="display:flex;align-items:center;gap:6px;margin-bottom:4px">
          <span class="pill ${sev}">${r.priority}</span>
          <strong>${r.title}</strong>
        </div>
        <div class="muted" style="font-size:11.5px;line-height:1.45">${r.body}</div>
        <a href="${r.cta_url}" class="primary"
           style="display:inline-block;margin-top:8px;padding:5px 10px;
                  font-size:11px;border-radius:4px;background:var(--accent);
                  color:#fff;text-decoration:none">${r.cta_label} →</a>
      </div>`;
    }).join("");
  }

  covLoadActivity();
}

// v9.20.1 — pull the last N LAN-scan runs (the only persisted history we
// have so far) and render them as an activity strip.
async function covLoadActivity() {
  const host = document.getElementById("cov-activity");
  try {
    const runs = await scApi("/api/discover/saved?limit=10");
    const items = Array.isArray(runs) ? runs : (runs.runs || runs || []);
    if (!items.length) {
      host.innerHTML = `<div class="muted" style="padding:14px">
        No discovery runs persisted yet. Once you run a LAN scan from
        /inventory, the last 10 runs will appear here.</div>`;
      return;
    }
    host.innerHTML = `<table style="width:100%;font-size:12px;margin:0">
      <thead><tr><th style="padding:8px 12px">When</th>
        <th>CIDR / target</th>
        <th>Devices found</th>
        <th>Duration</th>
        <th></th></tr></thead>
      <tbody>${items.slice(0,10).map(run => {
        const ts = (run.started_at || run.finished_at || '').slice(0,19).replace('T',' ');
        const cidr = run.cidr || run.subnet || '—';
        const count = run.count ?? run.hosts_responding ?? '—';
        const dur = run.duration_ms ? `${(run.duration_ms/1000).toFixed(1)}s` : '—';
        const id = run.run_id ?? run.id;
        return `<tr>
          <td style="padding:6px 12px"><code>${ts || '—'}</code></td>
          <td><code>${cidr}</code></td>
          <td>${count}</td>
          <td class="muted">${dur}</td>
          <td>${id ? `<a href="/api/discover/saved/${id}"
              style="font-size:11px">view JSON →</a>` : ''}</td>
        </tr>`;
      }).join('')}</tbody>
    </table>`;
  } catch (e) {
    host.innerHTML = `<div class="muted" style="padding:14px">
      Couldn't load run history: ${e.message}</div>`;
  }
}

covLoad();
"""


# ---------------------------------------------------------------- blast radius

_BLAST_BODY = """
<div style="display:flex;align-items:center;gap:12px;margin-bottom:8px">
  <h1 style="margin:0">🎯 Blast radius</h1>
  <span class="muted" id="br-stats" style="font-size:12px"></span>
  <span style="flex:1"></span>
  <input id="br-asset" placeholder="🔍 asset_id…"
         oninput="brSearch()"
         style="padding:6px 10px;border-radius:6px;width:280px;
                border:1px solid var(--border);
                background:var(--bg);color:var(--text);font-size:12px"/>
  <button class="alt" style="width:auto;padding:6px 10px;font-size:12px"
          onclick="brLoad()">⟳ Reload</button>
</div>

<p class="muted" style="margin-top:0">
  <strong>If this asset is compromised, what else can the attacker reach?</strong>
  Each node = a downstream asset, each edge = an attack path
  (network adjacency, identity grant, or trust relationship).
  Distance from center = number of hops.
</p>

<div style="display:grid;gap:12px;grid-template-columns:1fr 280px;
     height:calc(100vh - 230px);min-height:500px">

  <!-- LEFT: graph or empty state -->
  <div class="card" style="padding:0;position:relative;overflow:hidden">
    <div id="br-cy" style="width:100%;height:100%;
         background:radial-gradient(circle at 50% 30%,#ffffff 0%,
                                     #f1f5f9 70%,#e2e8f0 100%)"></div>
    <div id="br-empty" style="display:none;position:absolute;inset:0;
         flex-direction:column;align-items:center;justify-content:center;
         text-align:center;padding:30px;background:var(--panel)">
      <div style="font-size:46px;margin-bottom:10px">🌫</div>
      <h3 style="margin:0">No reachable assets from here</h3>
      <p class="muted" style="max-width:480px;margin:8px 0 14px">
        The attack-path engine couldn't find any downstream assets from
        this device. That usually means one of these data sources isn't
        connected yet:</p>
      <ul style="text-align:left;font-size:13px;max-width:480px;
                  list-style:none;padding:0">
        <li style="margin:6px 0">
          <strong>📡 SNMP harvest</strong> — for network adjacency
          (LLDP/CDP).
          <a href="/inventory">Run from /inventory →</a></li>
        <li style="margin:6px 0">
          <strong>🪪 AD / Entra connector</strong> — for identity grants
          (who can log in here).
          <a href="/inventory">Connect from /inventory →</a></li>
        <li style="margin:6px 0">
          <strong>☁ Cloud connector</strong> — for IAM trust + AssumeRole
          edges.
          <a href="/inventory">Connect from /inventory →</a></li>
        <li style="margin:6px 0">
          <strong>Asset tags</strong> — <code>role:</code>,
          <code>criticality:crown-jewel</code> drive the engine's prioritization.
          <a href="/asset/${(window.brStartId||'')}">Edit asset →</a></li>
      </ul>
      <div class="muted" style="font-size:11px;margin-top:14px">
        Once any of these are populated, this page lights up automatically.
      </div>
    </div>
  </div>

  <!-- RIGHT: paths list + summary -->
  <div class="card" style="padding:14px;overflow:auto">
    <div id="br-summary" class="muted" style="font-size:12px;
         margin-bottom:10px">Loading…</div>
    <div style="font-size:11px;text-transform:uppercase;color:var(--muted);
                font-weight:600;margin-bottom:6px">Reached assets</div>
    <div id="br-paths"></div>
  </div>
</div>
"""

_BLAST_SCRIPT = r"""
let BR_CY = null;
let BR_DATA = null;
window.brStartId = "";

(function() {
  // Pre-fill from URL: /blast-radius/<asset_id>
  const m = location.pathname.match(/^\/blast-radius\/(.+)$/);
  if (m) {
    window.brStartId = decodeURIComponent(m[1]);
    setTimeout(() => {
      const el = document.getElementById("br-asset");
      if (el) el.value = window.brStartId;
      brLoad();
    }, 30);
  }
})();

async function brLoad() {
  const aid = (document.getElementById("br-asset").value || "").trim();
  if (!aid) { brShowPickPrompt(); return; }
  window.brStartId = aid;
  document.getElementById("br-stats").textContent = "Loading…";
  let data;
  try {
    data = await scApi(`/api/platform/blast-radius/${encodeURIComponent(aid)}`);
  } catch(e) {
    document.getElementById("br-stats").textContent = "Failed: " + e.message;
    brRenderEmpty(true, e.message);
    return;
  }
  BR_DATA = data;
  brRender(data);
}

function brShowPickPrompt() {
  document.getElementById("br-stats").textContent = "Pick an asset above";
  document.getElementById("br-summary").innerHTML =
    `<p class="muted">Type any asset's ID into the search box (try
       <code>edge-rtr-01.acme.local</code>, <code>okta-acme</code>,
       <code>jump-host</code>) — or open this page from the
       <strong>🎯 Attack-path graph</strong> action on any asset cockpit.</p>`;
  document.getElementById("br-paths").innerHTML = "";
  brRenderEmpty(false, "");
}

function brRenderEmpty(failed, errMsg) {
  if (BR_CY) { BR_CY.destroy(); BR_CY = null; }
  const e = document.getElementById("br-empty");
  e.style.display = "flex";
  if (failed) {
    e.querySelector("h3").textContent = "Couldn't load blast radius";
    e.querySelector("p").textContent = errMsg || "API request failed.";
  }
}

async function brRender(d) {
  document.getElementById("br-stats").innerHTML =
    `<strong>${d.start}</strong> · ${d.reached} reachable ·
     ${d.crown_jewels_reached || 0} crown-jewels · ${d.max_hops_walked} hops`;

  const sumHtml = `
    <div style="font-size:13px">${d.summary || ''}</div>
    ${d.by_hop ? `<div style="margin-top:8px"><strong>By hop:</strong>
      ${Object.entries(d.by_hop).map(([h,n]) =>
        `<span class="pill pill-info" style="margin-right:4px">hop ${h}: ${n}</span>`
      ).join('')}</div>` : ''}
    ${d.by_type ? `<div style="margin-top:6px"><strong>By type:</strong>
      ${Object.entries(d.by_type).map(([t,n]) =>
        `<span class="pill" style="margin-right:4px">${t}: ${n}</span>`
      ).join('')}</div>` : ''}`;
  document.getElementById("br-summary").innerHTML = sumHtml;

  const paths = d.paths || [];
  document.getElementById("br-paths").innerHTML = paths.length === 0
    ? `<p class="muted">No reachable assets.</p>`
    : paths.map(p => {
        const crown = p.criticality === "crown-jewel" ? '⭐ ' : '';
        const sev = p.criticality === "crown-jewel" ? "pill-crit"
                   : p.hops <= 1 ? "pill-high" : "pill-info";
        return `<div onclick="location.href='/asset/${encodeURIComponent(p.asset_id)}'"
          style="padding:8px 10px;margin:4px 0;border-radius:4px;
                 background:var(--panel-2);cursor:pointer;font-size:12px">
          <div><span class="pill ${sev}">hop ${p.hops}</span>
            ${crown}<strong>${p.asset_id}</strong></div>
          <div class="muted" style="font-size:11px;margin-top:2px">
            ${p.asset_type || ''} · ${p.vendor || ''}</div>
        </div>`;
      }).join("");

  if (paths.length === 0) {
    brRenderEmpty(false, "");
    return;
  }
  document.getElementById("br-empty").style.display = "none";

  // Build Cytoscape graph: center = start asset, others fanned out by hop
  await ensureCytoscape();
  if (BR_CY) BR_CY.destroy();
  const nodes = [{
    data: {id: d.start, label: d.start, hops: 0,
           criticality: "start", asset_type: ""}
  }];
  const edges = [];
  for (const p of paths) {
    nodes.push({
      data: {id: p.asset_id, label: p.asset_id, hops: p.hops,
             criticality: p.criticality || "",
             asset_type: p.asset_type || "",
             vendor: p.vendor || ""}
    });
    edges.push({
      data: {source: d.start, target: p.asset_id, hops: p.hops}
    });
  }
  BR_CY = cytoscape({
    container: document.getElementById("br-cy"),
    elements: [...nodes, ...edges],
    style: brStyles(),
    layout: {name: "concentric", concentric: n =>
                10 - (n.data("hops") || 0),
             levelWidth: () => 1, minNodeSpacing: 35,
             animate: false, fit: true, padding: 40},
    wheelSensitivity: 0.2,
  });
  BR_CY.on("tap", "node", e => {
    const id = e.target.data("id");
    if (id !== d.start) location.href = `/asset/${encodeURIComponent(id)}`;
  });
}

function brStyles() {
  return [
    { selector: "node", style: {
      "shape": "ellipse",
      "background-color": ele => {
        if (ele.data("criticality") === "start")        return "#3b82f6";
        if (ele.data("criticality") === "crown-jewel")  return "#ef4444";
        if ((ele.data("hops") || 0) === 1)              return "#f59e0b";
        return "#94a3b8";
      },
      "label": "data(label)",
      "color": "#1f2937",
      "font-size": 9,
      "text-valign": "bottom",
      "text-margin-y": 4,
      "text-outline-color": "#fff",
      "text-outline-width": 2,
      "width": ele => ele.data("criticality") === "start" ? 32 : 18,
      "height": ele => ele.data("criticality") === "start" ? 32 : 18,
      "border-width": ele => ele.data("criticality") === "crown-jewel" ? 2 : 0,
      "border-color": "#fbbf24",
    }},
    { selector: "edge", style: {
      "width": 1.2, "curve-style": "bezier",
      "line-color": ele => (ele.data("hops") || 1) === 1 ? "#f59e0b" : "#94a3b8",
      "opacity": 0.5,
      "target-arrow-shape": "triangle",
      "target-arrow-color": ele => (ele.data("hops") || 1) === 1 ? "#f59e0b" : "#94a3b8",
      "arrow-scale": 0.8,
    }},
  ];
}

function ensureCytoscape() {
  return new Promise((resolve, reject) => {
    if (window.cytoscape) return resolve();
    const s = document.createElement("script");
    s.src = "https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.26.0/cytoscape.min.js";
    s.onload = () => resolve();
    s.onerror = () => reject(new Error("CDN load failed"));
    document.head.appendChild(s);
  });
}

let _BR_TMR;
function brSearch() {
  clearTimeout(_BR_TMR);
  _BR_TMR = setTimeout(brLoad, 600);
}

// Initial render: if no asset_id in URL, show pick-prompt
if (!window.brStartId) brShowPickPrompt();
"""


# --------------------------------------------------------- v9.32.1 /vendors page

_VENDORS_BODY = """
<h1>Vendor risk</h1>
<p class="muted">Track third-party vendors (cloud providers, SaaS, hardware
   suppliers, MSPs) and their security attestations. Auditors care about
   fourth-party risk; SOC 2 CC9 and ISO 27001 A.5.19 / A.5.20 / A.5.22
   ask for it explicitly.</p>

<div id="vr-summary" style="display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin:14px 0">
  <div class="card"><div class="muted" style="font-size:11px">Total vendors</div>
    <div id="vr-total" style="font-size:24px;font-weight:700">—</div></div>
  <div class="card"><div class="muted" style="font-size:11px">High residual</div>
    <div id="vr-high" style="font-size:24px;font-weight:700;color:var(--warn,#ca8a04)">—</div></div>
  <div class="card"><div class="muted" style="font-size:11px">Critical residual</div>
    <div id="vr-crit" style="font-size:24px;font-weight:700;color:var(--bad,#dc2626)">—</div></div>
  <div class="card"><div class="muted" style="font-size:11px">Expiring &lt; 60d</div>
    <div id="vr-exp" style="font-size:24px;font-weight:700">—</div></div>
</div>

<div style="display:flex;gap:8px;margin-bottom:8px">
  <button onclick="vrOpenCreate()">+ New vendor</button>
  <span style="flex:1"></span>
  <button class="alt" style="width:auto;padding:6px 12px;font-size:12px"
          onclick="vrLoad()">&#x21BB; Refresh</button>
</div>

<div class="card" style="padding:0">
  <table id="vr-tbl">
    <thead><tr>
      <th>Vendor</th><th>Category</th><th>Criticality</th>
      <th>Residual</th><th>Attestations</th><th></th>
    </tr></thead>
    <tbody><tr><td colspan="6" class="muted" style="padding:36px;text-align:center">
      Loading...</td></tr></tbody>
  </table>
</div>

<p class="muted" style="margin-top:14px;font-size:12px">
  Trust note: vendor records live in <code>$SC_DATA_DIR/vendor_risk.json</code> &mdash; local file, never transmitted.
</p>
"""

_VENDORS_SCRIPT = r"""
async function vrLoad() {
  try {
    const r = await fetch('/api/compliance/vendors',
                            {credentials:'include'});
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const d = await r.json();
    const s = d.summary || {};
    document.getElementById('vr-total').textContent = s.total || 0;
    document.getElementById('vr-high').textContent  = (s.by_residual_risk||{}).high || 0;
    document.getElementById('vr-crit').textContent  = (s.by_residual_risk||{}).critical || 0;
    document.getElementById('vr-exp').textContent   = s.expiring_60d || 0;
    vrRender(d.vendors || []);
  } catch (e) {
    document.querySelector('#vr-tbl tbody').innerHTML =
      `<tr><td colspan="6" class="muted" style="padding:36px;text-align:center">
        Failed to load: ${esc(e.message)}</td></tr>`;
  }
}

function vrRender(rows) {
  const tbody = document.querySelector('#vr-tbl tbody');
  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="6" class="muted" style="padding:36px;text-align:center">
      No vendors tracked yet.
      <a href="#" onclick="vrOpenCreate();return false">Add your first vendor &rarr;</a>
    </td></tr>`;
    return;
  }
  tbody.innerHTML = rows.map(v => {
    const r = v.residual_risk || 'medium';
    const cls = r === 'critical' || r === 'high' ? 'tag-red' :
                r === 'low' ? 'tag-green' : 'tag-yellow';
    const atts = (v.attestations || []).map(a =>
      `<span class="tag tag-info" style="margin-right:4px;font-size:11px"
             title="${esc(a.expires_at || 'no expiry')}">${esc(a.type)}</span>`
    ).join('') || '<span class="muted" style="font-size:11px">none</span>';
    return `<tr>
      <td><strong>${esc(v.name)}</strong>
        <div class="muted" style="font-size:11px">${esc(v.contact || '')}</div></td>
      <td>${esc(v.category)}</td>
      <td>${esc(v.criticality)}</td>
      <td><span class="tag ${cls}">${esc(r)}</span></td>
      <td>${atts}</td>
      <td style="text-align:right">
        <button class="alt" style="padding:3px 8px;font-size:11px"
                onclick="vrAddAtt('${esc(v.id)}','${esc(v.name)}')">+ Attest</button>
        <button class="alt" style="padding:3px 8px;font-size:11px;margin-left:4px"
                onclick="vrDelete('${esc(v.id)}')">Delete</button>
      </td>
    </tr>`;
  }).join('');
}

function vrOpenCreate() {
  if (typeof scOpenSlide !== 'function') {
    alert('Slide-over not available; create via POST /api/compliance/vendors.');
    return;
  }
  scOpenSlide('New vendor', `
    <label>Name *</label><input id="vr-name" placeholder="e.g. AcmeCloud" />
    <label class="ml">Category *</label>
    <select id="vr-cat">
      <option value="cloud">Cloud provider</option>
      <option value="saas">SaaS</option>
      <option value="hardware">Hardware supplier</option>
      <option value="msp">MSP</option>
      <option value="data_processor">Data processor</option>
      <option value="other">Other</option>
    </select>
    <label class="ml">Criticality</label>
    <select id="vr-crit">
      <option value="low">Low</option>
      <option value="medium" selected>Medium</option>
      <option value="high">High</option>
      <option value="critical">Critical</option>
    </select>
    <label class="ml">Residual risk</label>
    <select id="vr-res">
      <option value="low">Low</option>
      <option value="medium" selected>Medium</option>
      <option value="high">High</option>
      <option value="critical">Critical</option>
    </select>
    <label class="ml">Contact</label>
    <input id="vr-contact" placeholder="security@vendor.com" />
    <label class="ml">Notes</label>
    <textarea id="vr-notes" rows="2"></textarea>
    <button style="margin-top:12px" onclick="vrCreate()">Add vendor</button>
  `);
}

async function vrCreate() {
  const body = {
    name: document.getElementById('vr-name').value,
    category: document.getElementById('vr-cat').value,
    criticality: document.getElementById('vr-crit').value,
    residual_risk: document.getElementById('vr-res').value,
    contact: document.getElementById('vr-contact').value,
    notes: document.getElementById('vr-notes').value,
  };
  const r = await fetch('/api/compliance/vendors', {
    method:'POST', credentials:'include',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify(body),
  });
  if (!r.ok) { alert('Failed: ' + (await r.text())); return; }
  if (typeof scCloseSlide === 'function') scCloseSlide();
  vrLoad();
}

function vrAddAtt(vid, vname) {
  if (typeof scOpenSlide !== 'function') return;
  scOpenSlide('Add attestation: ' + vname, `
    <label>Type *</label>
    <select id="va-type">
      <option value="soc2_type2">SOC 2 Type 2</option>
      <option value="soc2_type1">SOC 2 Type 1</option>
      <option value="iso27001">ISO 27001</option>
      <option value="pci_dss">PCI-DSS</option>
      <option value="hipaa">HIPAA</option>
      <option value="fedramp_moderate">FedRAMP Moderate</option>
      <option value="fedramp_high">FedRAMP High</option>
      <option value="hitrust">HITRUST</option>
      <option value="iso27017">ISO 27017</option>
      <option value="iso27018">ISO 27018</option>
      <option value="csa_star">CSA STAR</option>
      <option value="other">Other</option>
    </select>
    <label class="ml">Status</label>
    <select id="va-status">
      <option value="active" selected>Active</option>
      <option value="expired">Expired</option>
      <option value="in_progress">In progress</option>
      <option value="not_attested">Not attested</option>
    </select>
    <label class="ml">Expires (ISO date, optional)</label>
    <input id="va-exp" placeholder="2027-06-30" />
    <label class="ml">Doc URL</label>
    <input id="va-url" placeholder="https://trust.vendor.com/..." />
    <button style="margin-top:12px" onclick="vrSubmitAtt('${esc(vid)}')">Add</button>
  `);
}

async function vrSubmitAtt(vid) {
  const exp = document.getElementById('va-exp').value;
  const body = {
    type: document.getElementById('va-type').value,
    status: document.getElementById('va-status').value,
    expires_at: exp ? exp + 'T00:00:00+00:00' : null,
    doc_url: document.getElementById('va-url').value,
  };
  const r = await fetch(`/api/compliance/vendors/${encodeURIComponent(vid)}/attestations`,
    {method:'POST', credentials:'include',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify(body)});
  if (!r.ok) { alert('Failed: ' + (await r.text())); return; }
  if (typeof scCloseSlide === 'function') scCloseSlide();
  vrLoad();
}

async function vrDelete(vid) {
  if (!confirm('Delete vendor ' + vid + '?')) return;
  await fetch(`/api/compliance/vendors/${encodeURIComponent(vid)}`,
    {method:'DELETE', credentials:'include'});
  vrLoad();
}

function esc(s){const d=document.createElement('div');d.textContent=String(s||'');return d.innerHTML;}
vrLoad();
"""


# --------------------------------------------------------- v9.32.1 manual YAML policy editor

_POLICY_NEW_BODY = """
<h1>Author policy (raw YAML)</h1>
<p class="muted">Direct YAML editor for operators who want full control.
   The wizard on <a href="/policies">/policies</a> covers 80% of cases —
   this surface is for the other 20%. Live validation; live vendor
   render preview on the right; never written until you click <strong>Save</strong>.</p>

<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:14px">
  <div class="card" style="padding:14px">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
      <strong style="font-size:13px">policy.yaml</strong>
      <span style="flex:1"></span>
      <span id="pn-status" class="muted" style="font-size:11px">—</span>
    </div>
    <textarea id="pn-yaml" rows="22" spellcheck="false"
      style="width:100%;font-family:ui-monospace,Menlo,monospace;font-size:12px;
             padding:10px;border:1px solid var(--border);border-radius:6px;
             background:var(--input-bg, var(--panel-2, #f8f9fa));
             color:var(--fg)"></textarea>
    <div style="display:flex;gap:8px;margin-top:10px;flex-wrap:wrap">
      <button onclick="pnSave()">Save policy</button>
      <button class="alt" onclick="pnLoadTemplate()">Load template</button>
      <button class="alt" onclick="pnImportFromConfig()"
              title="Paste a running config; SafeCadence infers a starter policy">
        Import from config…</button>
      <span style="flex:1"></span>
      <select id="pn-vendor" onchange="pnPreview()" style="padding:6px">
        <option value="cisco-ios">cisco-ios</option>
        <option value="juniper-junos">juniper-junos</option>
        <option value="paloalto-panos">paloalto-panos</option>
        <option value="fortinet-fortios">fortinet-fortios</option>
        <option value="arista-eos">arista-eos</option>
      </select>
    </div>
  </div>

  <div class="card" style="padding:14px">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
      <strong style="font-size:13px">Vendor preview</strong>
      <span class="muted" style="font-size:11px"
            id="pn-preview-status">live</span>
    </div>
    <pre id="pn-preview" style="font-family:ui-monospace,Menlo,monospace;
         font-size:12px;background:var(--panel-2,#f8f9fa);padding:10px;
         border-radius:6px;min-height:480px;overflow:auto;margin:0">
Type a policy on the left. Vendor preview renders here as you type.</pre>
  </div>
</div>

<p class="muted" style="margin-top:14px;font-size:12px">
  Trust note: this preview is the v9.31 shape-preview pack — it shows
  the <em>shape</em> of the change, not the production-ready translator
  output. The real translators run at enforce-time after approval.
  Defaults: every quick-authored policy starts in
  <code>mode: report_only</code> so it emits findings without enforcing
  for a soak period.
</p>
"""

_POLICY_NEW_SCRIPT = r"""
const PN_TEMPLATE = `# SafeCadence policy — manual YAML
name: Edge firewall hardening
description: Baseline hardening for our edge firewalls.
target_group: edge-firewalls
mode: report_only       # report_only | enforce | disabled
control_ids:
  - enforce_ssh_v2
  - disable_telnet
  - require_aaa
  - enable_syslog
  - enable_ntp
  - block_insecure_crypto
  - restrict_management_access
`;

let _pnTimer = null;
function pnPreview() {
  clearTimeout(_pnTimer);
  _pnTimer = setTimeout(_pnPreviewNow, 250);
}

async function _pnPreviewNow() {
  const yaml = document.getElementById('pn-yaml').value;
  const vendor = document.getElementById('pn-vendor').value;
  const status = document.getElementById('pn-status');
  const out = document.getElementById('pn-preview');
  // Cheap client-side YAML key scrape — extract control_ids: lines
  // that start with "- " under control_ids:.
  let cids = [];
  let inBlock = false;
  for (const raw of yaml.split('\n')) {
    const line = raw.replace(/\s+$/,'');
    if (/^control_ids\s*:/.test(line)) { inBlock = true; continue; }
    if (inBlock) {
      const m = line.match(/^\s*-\s*([a-z0-9_]+)/);
      if (m) cids.push(m[1]);
      else if (line && !/^\s/.test(line)) inBlock = false;
    }
  }
  if (!cids.length) {
    status.textContent = 'no control_ids parsed';
    out.textContent = '(no controls listed yet)';
    return;
  }
  status.textContent = `${cids.length} control(s)`;
  try {
    const r = await fetch('/api/policy/preview-config', {
      method:'POST', credentials:'include',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({vendor, control_ids: cids}),
    });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const data = await r.json();
    if (!data.supported) {
      out.textContent = '! ' + (data.note || 'unsupported vendor');
    } else {
      out.textContent = data.rendered ||
        '(no preview snippet for these controls — translator runs at enforce-time)';
    }
  } catch (e) {
    out.textContent = 'preview failed: ' + e.message;
  }
}

async function pnSave() {
  const yaml = document.getElementById('pn-yaml').value;
  // Quick parse to extract minimal fields for the quick-author endpoint.
  const get = k => {
    const m = yaml.match(new RegExp('^' + k + '\\\\s*:\\\\s*(.+)$', 'm'));
    return m ? m[1].trim() : '';
  };
  const name = get('name');
  const target = get('target_group');
  const mode = get('mode') || 'report_only';
  let cids = [];
  let inBlock = false;
  for (const raw of yaml.split('\n')) {
    const line = raw.replace(/\s+$/,'');
    if (/^control_ids\s*:/.test(line)) { inBlock = true; continue; }
    if (inBlock) {
      const m = line.match(/^\s*-\s*([a-z0-9_]+)/);
      if (m) cids.push(m[1]);
      else if (line && !/^\s/.test(line)) inBlock = false;
    }
  }
  if (!name || !cids.length) {
    alert('name + at least one control_id are required');
    return;
  }
  const r = await fetch('/api/policy/quick', {
    method:'POST', credentials:'include',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({
      name, target_group: target, control_ids: cids, mode,
    }),
  });
  if (!r.ok) { alert('Save failed: ' + (await r.text())); return; }
  const data = await r.json();
  document.getElementById('pn-status').textContent =
    `saved as ${data.id}`;
}

function pnLoadTemplate() {
  document.getElementById('pn-yaml').value = PN_TEMPLATE;
  pnPreview();
}

// v9.37 — surface the brownfield import that's been in the API since
// v9.32 #1 but was only reachable via curl. Paste a running config,
// SafeCadence infers a starter policy YAML you can edit before saving.
async function pnImportFromConfig() {
  const cfg = prompt(
    "Paste a running config (Cisco IOS, Junos, Palo, Fortinet, EOS).\n" +
    "SafeCadence will infer a starter policy you can edit before Save.");
  if (!cfg || !cfg.trim()) return;
  const status = document.getElementById('pn-status');
  status.textContent = 'inferring policy from config…';
  try {
    const r = await fetch('/api/policy/import-from-config', {
      method: 'POST', credentials: 'include',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({config: cfg}),
    });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const data = await r.json();
    const yaml = data.yaml || data.policy_yaml || '';
    if (!yaml) {
      status.textContent = 'import returned no policy';
      alert(
        "Import returned no policy. The parser couldn't find any " +
        "control patterns in this config. Try a different vendor or " +
        "start from a template.");
      return;
    }
    document.getElementById('pn-yaml').value = yaml;
    status.textContent = 'imported — review before saving';
    pnPreview();
  } catch (e) {
    status.textContent = 'import failed';
    alert('Import failed: ' + (e.message || e));
  }
}

document.getElementById('pn-yaml').addEventListener('input', pnPreview);
pnLoadTemplate();
"""


# --------------------------------------------------------- v9.27 Compliance coverage page

_COMPLIANCE_BODY = """
<h1>Compliance coverage</h1>
<p class="muted">Every SafeCadence control mapped to its NIST 800-53,
   CIS v8, PCI-DSS 4.0, HIPAA, ISO 27001:2022, and SOC 2 TSC equivalents.
   Pick a framework on the left to see what's covered, what isn't,
   and which SafeCadence controls satisfy each requirement.</p>

<div style="display:grid;grid-template-columns:280px 1fr;gap:14px;margin-top:14px">
  <div class="card" style="padding:0">
    <div style="padding:12px 14px;border-bottom:1px solid var(--border);
                font-weight:600">Frameworks</div>
    <div id="cmp-fw-list">
      <div class="muted" style="padding:14px">Loading...</div>
    </div>
  </div>
  <div class="card" id="cmp-detail">
    <div class="muted">Pick a framework to view its coverage matrix.</div>
  </div>
</div>

<p class="muted" style="margin-top:14px;font-size:12px">
  Mappings ship in <code>data/control_mappings.yaml</code>. Add a row
  there when you author a new control.
</p>
"""

_COMPLIANCE_SCRIPT = r"""
let _CMP_FRAMEWORKS = [];

async function cmpLoad() {
  try {
    const r = await fetch('/api/compliance/frameworks',
                            {credentials:'include'});
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const d = await r.json();
    _CMP_FRAMEWORKS = d.frameworks || [];
    cmpRenderList();
  } catch (e) {
    document.getElementById('cmp-fw-list').innerHTML =
      `<div class="muted" style="padding:14px">Failed: ${e.message}</div>`;
  }
}

function cmpRenderList() {
  const host = document.getElementById('cmp-fw-list');
  host.innerHTML = _CMP_FRAMEWORKS.map(f => `
    <a href="#" onclick="cmpPick('${f.key}');return false"
       style="display:block;padding:11px 14px;border-bottom:1px solid var(--border);
              text-decoration:none;color:var(--fg)">
      <div style="font-weight:600">${esc(f.label)}</div>
      <div class="muted" style="font-size:12px;margin-top:2px">
        Covers ${f.covered_count} requirements via ${f.safecadence_count} SafeCadence controls
      </div>
    </a>`).join('');
}

async function cmpPick(key) {
  const detail = document.getElementById('cmp-detail');
  detail.innerHTML = '<div class="muted">Loading coverage...</div>';
  try {
    const r = await fetch(`/api/compliance/coverage/${encodeURIComponent(key)}`,
                            {credentials:'include'});
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const d = await r.json();
    const rows = (d.covered || []).map(row => `
      <tr>
        <td style="font-family:ui-monospace,Menlo,monospace;font-size:12px">${esc(row.framework_id)}</td>
        <td>${(row.safecadence_controls||[]).map(c =>
          `<a href="#" onclick="cmpControl('${esc(c)}');return false"
              class="tag tag-info" style="margin-right:4px">${esc(c)}</a>`
          ).join('')}</td>
      </tr>`).join('');
    detail.innerHTML = `
      <h2 style="margin:0 0 4px">${esc(d.framework)}</h2>
      <div class="muted" style="font-size:12px;margin-bottom:12px">
        ${d.covered_count} requirements covered by SafeCadence controls
      </div>
      <table>
        <thead><tr><th style="width:140px">Framework ID</th>
                   <th>Covered by SafeCadence control(s)</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="2" class="muted" style="padding:24px;text-align:center">No coverage yet — add mappings to data/control_mappings.yaml.</td></tr>'}</tbody>
      </table>`;
  } catch (e) {
    detail.innerHTML = `<div class="muted">Failed: ${e.message}</div>`;
  }
}

async function cmpControl(cid) {
  const detail = document.getElementById('cmp-detail');
  try {
    const r = await fetch(`/api/compliance/control/${encodeURIComponent(cid)}`,
                            {credentials:'include'});
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const d = await r.json();
    if (d.error) throw new Error(d.error);
    const sla = d.sla_severity_days || {};
    const slaTbl = ['critical','high','medium','low'].map(k =>
      `<span class="tag tag-${k==='critical'||k==='high'?'red':k==='medium'?'yellow':'green'}"
             style="margin-right:4px">${k}: ${sla[k] != null ? sla[k]+'d' : '—'}</span>`).join('');
    const fw = (key, label) => {
      const ids = d[key] || [];
      if (!ids.length) return '';
      return `<div style="margin-top:8px"><strong>${label}</strong>: ${
        ids.map(id => `<code style="font-size:12px;margin-right:4px">${esc(id)}</code>`).join('')
      }</div>`;
    };
    detail.innerHTML = `
      <div style="margin-bottom:8px"><a href="#" onclick="cmpPick('${esc(_lastFw)}');return false">&larr; Back</a></div>
      <h2 style="margin:0 0 4px"><code>${esc(cid)}</code></h2>
      <div class="muted" style="margin-bottom:12px">${esc(d.description||'')} &middot; ${esc(d.domain||'')}</div>
      <div><strong>Owner</strong>: ${esc(d.owner_default||'—')} &middot;
           <strong>Frequency</strong>: ${esc(d.frequency||'—')} &middot;
           <strong>Evidence</strong>: ${esc(d.evidence_type||'—')}</div>
      <div style="margin-top:6px"><strong>SLA by severity</strong>: ${slaTbl}</div>
      ${fw('nist_800_53','NIST 800-53 r5')}
      ${fw('cis_v8','CIS Controls v8')}
      ${fw('pci_dss_4','PCI-DSS 4.0')}
      ${fw('hipaa','HIPAA')}
      ${fw('iso_27001_2022','ISO 27001:2022')}
      ${fw('soc2_tsc','SOC 2 TSC')}
    `;
  } catch (e) {
    detail.innerHTML = `<div class="muted">Failed: ${e.message}</div>`;
  }
}

let _lastFw = '';
const _origPick = cmpPick;
cmpPick = async function(k) { _lastFw = k; return _origPick(k); };

function esc(s){const d=document.createElement('div');d.textContent=String(s||'');return d.innerHTML;}
cmpLoad();
"""


# --------------------------------------------------------- v9.29 Risk register

_RISKS_BODY = """
<h1>Risk register</h1>
<p class="muted">Identified risks with likelihood &times; impact = inherent score,
   reduced by linked-control effectiveness to a residual score. The kind
   of artifact ISO 27001 / NIST RMF auditors expect to see maintained.</p>

<div id="rr-summary" style="display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin:14px 0">
  <div class="card"><div class="muted" style="font-size:11px">Total</div>
    <div id="rr-total" style="font-size:24px;font-weight:700">—</div></div>
  <div class="card"><div class="muted" style="font-size:11px">Critical residual</div>
    <div id="rr-crit" style="font-size:24px;font-weight:700;color:var(--bad,#dc2626)">—</div></div>
  <div class="card"><div class="muted" style="font-size:11px">High residual</div>
    <div id="rr-high" style="font-size:24px;font-weight:700;color:var(--warn,#ca8a04)">—</div></div>
  <div class="card"><div class="muted" style="font-size:11px">Open</div>
    <div id="rr-open" style="font-size:24px;font-weight:700">—</div></div>
</div>

<div style="display:flex;gap:8px;margin-bottom:8px">
  <button onclick="rrOpenCreate()">+ New risk</button>
  <span style="flex:1"></span>
  <button class="alt" style="width:auto;padding:6px 12px;font-size:12px"
          onclick="rrLoad()">&#x21BB; Refresh</button>
</div>

<div class="card" style="padding:0">
  <table id="rr-tbl">
    <thead><tr>
      <th>Title</th><th>Owner</th><th>Domain</th>
      <th>L &times; I</th><th>Inherent</th><th>Residual</th>
      <th>Status</th><th></th>
    </tr></thead>
    <tbody><tr><td colspan="8" class="muted" style="padding:36px;text-align:center">Loading...</td></tr></tbody>
  </table>
</div>
"""

_RISKS_SCRIPT = r"""
async function rrLoad() {
  try {
    const r = await fetch('/api/compliance/risks', {credentials:'include'});
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const d = await r.json();
    const summary = d.summary || {};
    document.getElementById('rr-total').textContent = summary.total || 0;
    document.getElementById('rr-crit').textContent = (summary.by_band||{})['critical'] || 0;
    document.getElementById('rr-high').textContent = (summary.by_band||{})['high'] || 0;
    document.getElementById('rr-open').textContent = (summary.by_status||{})['open'] || 0;
    rrRender(d.risks || []);
  } catch (e) {
    document.querySelector('#rr-tbl tbody').innerHTML =
      `<tr><td colspan="8" class="muted" style="padding:36px;text-align:center">Failed: ${e.message}</td></tr>`;
  }
}

function rrRender(rows) {
  const tbody = document.querySelector('#rr-tbl tbody');
  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="8" class="muted" style="padding:36px;text-align:center">
      No risks yet. <a href="#" onclick="rrOpenCreate();return false">Add the first one &rarr;</a>
    </td></tr>`;
    return;
  }
  tbody.innerHTML = rows.map(r => {
    const tag = b => b === 'critical' ? 'tag-red' :
                      b === 'high' ? 'tag-red' :
                      b === 'medium' ? 'tag-yellow' :
                      b === 'low' ? 'tag-green' : 'tag-info';
    return `<tr>
      <td><strong>${esc(r.title)}</strong>
          <div class="muted" style="font-size:11px">${esc(r.description||'').slice(0,80)}</div></td>
      <td>${esc(r.owner||'—')}</td>
      <td>${esc(r.domain||'—')}</td>
      <td>${r.likelihood} &times; ${r.impact}</td>
      <td><span class="tag ${tag(r.band_inherent)}">${r.inherent_score} ${r.band_inherent}</span></td>
      <td><span class="tag ${tag(r.band_residual)}">${r.residual_score} ${r.band_residual}</span>
          <small class="muted" style="margin-left:4px">ctl ${Math.round((r.control_strength||0)*100)}%</small></td>
      <td>${esc(r.status)}</td>
      <td><button class="alt" style="padding:3px 8px;font-size:11px"
                  onclick="rrDelete('${esc(r.id)}')">Delete</button></td>
    </tr>`;
  }).join('');
}

function rrOpenCreate() {
  if (typeof scOpenSlide !== 'function') {
    alert('Slide-over not available; create via /api/compliance/risks POST.');
    return;
  }
  scOpenSlide('New risk', `
    <label>Title *</label>
    <input id="rr-title" placeholder="e.g. Ransomware via misconfigured RDP" />
    <label class="ml">Description</label>
    <textarea id="rr-desc" rows="3" placeholder="What goes wrong, where, why."></textarea>
    <label class="ml">Owner *</label>
    <input id="rr-owner" placeholder="e.g. ciso@acme.com" />
    <label class="ml">Domain</label>
    <select id="rr-domain">
      <option>network</option><option>server</option>
      <option>identity</option><option>cloud</option>
      <option>backup</option><option>storage</option>
      <option>business</option>
    </select>
    <div style="display:flex;gap:8px;margin-top:8px">
      <div style="flex:1"><label>Likelihood (1-5) *</label>
        <input id="rr-lik" type="number" min="1" max="5" value="3" /></div>
      <div style="flex:1"><label>Impact (1-5) *</label>
        <input id="rr-imp" type="number" min="1" max="5" value="3" /></div>
    </div>
    <label class="ml">Linked control IDs (comma-sep)</label>
    <input id="rr-ctrl" placeholder="enforce_mfa, enforce_logging" />
    <label class="ml">Mitigation</label>
    <textarea id="rr-mit" rows="2"></textarea>
    <button style="margin-top:12px" onclick="rrCreate()">Create risk</button>
  `);
}

async function rrCreate() {
  const body = {
    title: document.getElementById('rr-title').value,
    description: document.getElementById('rr-desc').value,
    owner: document.getElementById('rr-owner').value,
    domain: document.getElementById('rr-domain').value,
    likelihood: parseInt(document.getElementById('rr-lik').value, 10),
    impact: parseInt(document.getElementById('rr-imp').value, 10),
    control_ids: document.getElementById('rr-ctrl').value.split(',').map(s=>s.trim()).filter(Boolean),
    mitigation: document.getElementById('rr-mit').value,
  };
  const r = await fetch('/api/compliance/risks', {
    method:'POST', credentials:'include',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify(body)
  });
  if (!r.ok) { alert('Failed: ' + await r.text()); return; }
  if (typeof scCloseSlide === 'function') scCloseSlide();
  rrLoad();
}

async function rrDelete(id) {
  if (!confirm('Delete risk ' + id + '?')) return;
  await fetch('/api/compliance/risks/' + encodeURIComponent(id),
                {method:'DELETE', credentials:'include'});
  rrLoad();
}

function esc(s){const d=document.createElement('div');d.textContent=String(s||'');return d.innerHTML;}
rrLoad();
"""


# --------------------------------------------------------- v9.25 Safe Score leaderboard

_SCORES_BODY = """
<h1>Safe Score leaderboard</h1>
<p class="muted">0-100 per asset, higher is safer. The number composes
   open findings, KEV/EPSS/CVSS-prioritized CVEs, attack-path
   membership, drift, and missing controls. The fleet number on the
   left is criticality-weighted — one bad critical box drags the fleet
   number more than five bad low-criticality boxes.</p>

<div style="display:grid;grid-template-columns:280px 1fr;gap:14px;margin:14px 0">
  <div class="card" style="padding:18px;text-align:center">
    <div class="muted" style="font-size:11px;text-transform:uppercase;letter-spacing:.5px">Fleet</div>
    <div id="sc-fleet" style="font-size:48px;font-weight:800;line-height:1;margin-top:6px">—</div>
    <div id="sc-band" class="muted" style="font-size:13px;margin-top:4px">—</div>
    <div id="sc-trend" class="muted" style="font-size:12px;margin-top:8px">—</div>
  </div>
  <div class="card">
    <div style="display:flex;align-items:baseline;gap:8px">
      <strong>30-day fleet trend</strong>
      <span class="muted" style="font-size:11px">(one point per daemon cycle)</span>
    </div>
    <div id="sc-chart" style="height:120px;margin-top:8px"></div>
    <div id="sc-chart-empty" class="muted" style="font-size:12px;display:none">
      No history yet. The daemon writes a snapshot every cycle —
      <a href="#" onclick="scForceSnap();return false">snapshot now</a>.
    </div>
  </div>
</div>

<h2 style="font-size:18px;margin-top:18px">Per-asset leaderboard</h2>
<div class="card" style="padding:0">
  <table id="sc-tbl">
    <thead><tr>
      <th style="cursor:pointer" onclick="scSort('score')">Safe ▾</th>
      <th>Asset</th>
      <th>Vendor</th>
      <th>Criticality</th>
      <th>Top reason</th>
    </tr></thead>
    <tbody><tr><td colspan="5" class="muted"
         style="padding:36px;text-align:center">Loading...</td></tr></tbody>
  </table>
</div>
"""

_SCORES_SCRIPT = r"""
let _SC_ROWS = [];
let _SC_DIR = 1;  // 1 = ascending (worst first), -1 = descending

async function scLoad() {
  // Headline + per-asset
  try {
    const r = await fetch('/api/scores/safe', {credentials:'include'});
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const d = await r.json();
    document.getElementById('sc-fleet').textContent = d.fleet_score;
    document.getElementById('sc-band').textContent = `Grade ${d.fleet_band} · ${d.asset_count} assets`;
    _SC_ROWS = d.per_asset || [];
    scRender();
  } catch (e) {
    document.querySelector('#sc-tbl tbody').innerHTML =
      `<tr><td colspan="5" class="muted" style="padding:36px;text-align:center">Score endpoint not reachable (${e.message}).</td></tr>`;
  }
  // Trend + chart
  try {
    const h = await fetch('/api/scores/safe/history?days=30',
                            {credentials:'include'});
    if (!h.ok) throw new Error('HTTP ' + h.status);
    const data = await h.json();
    const tr = data.trend || {};
    const tEl = document.getElementById('sc-trend');
    if (tr.samples > 1 && tr.delta !== 0) {
      const arrow = tr.direction === 'up' ? '↑' : tr.direction === 'down' ? '↓' : '→';
      tEl.textContent = `${arrow} ${tr.delta > 0 ? '+' : ''}${tr.delta} over the last 7 days (${tr.samples} samples)`;
    } else if (tr.samples >= 1) {
      tEl.textContent = `${tr.samples} sample${tr.samples===1?'':'s'} in last 30 days · trend stable`;
    }
    scDrawChart(data.history || []);
  } catch (e) {
    document.getElementById('sc-chart-empty').style.display = 'block';
  }
}

function scRender() {
  const rows = [..._SC_ROWS].sort((a,b) => (a.score - b.score) * _SC_DIR);
  const tbody = document.querySelector('#sc-tbl tbody');
  if (!rows.length) {
    tbody.innerHTML =
      `<tr><td colspan="5" class="muted" style="padding:36px;text-align:center">
        No assets yet. <a href="/onboarding">Onboard a fleet</a> to populate.
      </td></tr>`;
    return;
  }
  tbody.innerHTML = rows.slice(0, 200).map(r => {
    const sev = r.score >= 80 ? 'tag-green' : r.score >= 60 ? 'tag-yellow' : 'tag-red';
    const top = (r.reasons && r.reasons[0])
      ? `<span class="muted" style="font-size:11px">${esc(r.reasons[0].message)}</span>`
      : '<span class="muted" style="font-size:11px">no signals — clean</span>';
    return `<tr>
      <td><span class="tag ${sev}" style="font-weight:600">${r.score}</span>
          <small class="muted" style="margin-left:4px">${r.band}</small></td>
      <td><a href="/asset/${encodeURIComponent(r.asset_id)}">${esc(r.asset_id)}</a></td>
      <td>—</td>
      <td>—</td>
      <td>${top}</td>
    </tr>`;
  }).join('');
}

function scSort(_field) {
  _SC_DIR = -_SC_DIR;
  scRender();
}

function scDrawChart(history) {
  const host = document.getElementById('sc-chart');
  if (!history || history.length < 2) {
    document.getElementById('sc-chart-empty').style.display = 'block';
    return;
  }
  const w = host.clientWidth || 600;
  const h = 120, padX = 6, padY = 8;
  const xs = history.map((_, i) =>
    padX + (i * (w - 2*padX)) / (history.length - 1));
  const ys = history.map(p => {
    const v = Math.max(0, Math.min(100, Number(p.fleet_score) || 0));
    return h - padY - (v / 100) * (h - 2*padY);
  });
  const d = xs.map((x, i) =>
    `${i ? 'L' : 'M'}${x.toFixed(1)} ${ys[i].toFixed(1)}`).join(' ');
  // Y-axis grid at 50 + 80 (typical band thresholds)
  const grid50 = h - padY - 0.50 * (h - 2*padY);
  const grid80 = h - padY - 0.80 * (h - 2*padY);
  host.innerHTML =
    `<svg width="100%" height="${h}" viewBox="0 0 ${w} ${h}"
          xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="none">
       <line x1="0" x2="${w}" y1="${grid50}" y2="${grid50}"
             stroke="var(--border)" stroke-dasharray="3 3"/>
       <line x1="0" x2="${w}" y1="${grid80}" y2="${grid80}"
             stroke="var(--border)" stroke-dasharray="3 3"/>
       <path d="${d}" fill="none" stroke="var(--accent)" stroke-width="2"/>
     </svg>`;
}

async function scForceSnap() {
  try {
    await fetch('/api/scores/safe/snapshot',
                  {method:'POST', credentials:'include'});
    scLoad();
  } catch(e) { alert('Snapshot failed: ' + e.message); }
}

function esc(s){const d=document.createElement('div');d.textContent=String(s||'');return d.innerHTML;}
scLoad();
"""


# --------------------------------------------------------- v9.23 graduated pages
#
# Each replaces the old _stub_body with a real, v9-chromed page that
# fetches data from an existing API endpoint and renders it. Empty
# states are explicit and link to the right adjacent feature.


_DRIFT_BODY = """
<h1>Drift</h1>
<p class="muted">Three flavors, one page. <strong>Policy drift</strong>
   is when running config diverges from the policy you authored.
   <strong>Baseline drift</strong> is when running config diverges from
   the snapshot you declared as your "good" state.
   <strong>Cross-system drift</strong> is when two identity systems
   disagree about the same principal (Okta says yes, AD says no).</p>

<!-- Summary cards -->
<div style="display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin:14px 0">
  <div class="card"><div class="muted" style="font-size:11px">Total</div>
    <div id="dr-total" style="font-size:24px;font-weight:700">—</div></div>
  <div class="card"><div class="muted" style="font-size:11px">Critical</div>
    <div id="dr-crit" style="font-size:24px;font-weight:700;color:var(--bad,#dc2626)">—</div></div>
  <div class="card"><div class="muted" style="font-size:11px">High</div>
    <div id="dr-high" style="font-size:24px;font-weight:700;color:var(--warn,#ca8a04)">—</div></div>
  <div class="card"><div class="muted" style="font-size:11px">Medium / low</div>
    <div id="dr-med" style="font-size:24px;font-weight:700">—</div></div>
</div>

<!-- Tabs -->
<div style="display:flex;gap:8px;border-bottom:1px solid var(--border);margin-bottom:12px">
  <button class="dr-tab dr-tab-active" data-tab="policy" onclick="drPick('policy')">
    Policy drift <span class="muted" id="dr-cnt-policy">—</span>
  </button>
  <button class="dr-tab" data-tab="baseline" onclick="drPick('baseline')">
    Baseline drift <span class="muted" id="dr-cnt-baseline">—</span>
  </button>
  <button class="dr-tab" data-tab="cross_system" onclick="drPick('cross_system')">
    Cross-system <span class="muted" id="dr-cnt-cross_system">—</span>
  </button>
  <span style="flex:1"></span>
  <button class="alt" style="width:auto;padding:6px 12px;font-size:12px"
          onclick="drLoad()">&#x21BB; Refresh</button>
</div>

<style>
.dr-tab { background:transparent; border:0; padding:10px 14px; cursor:pointer;
          font-size:13px; color:var(--muted); border-bottom:2px solid transparent; }
.dr-tab:hover { color:var(--fg); }
.dr-tab-active { color:var(--fg); border-bottom-color:var(--accent,#2563eb); font-weight:600; }
</style>

<div class="card" style="padding:0">
  <table id="dr-tbl">
    <thead id="dr-thead"><tr><th>Loading…</th></tr></thead>
    <tbody><tr><td class="muted" style="padding:36px;text-align:center">Loading drift report...</td></tr></tbody>
  </table>
</div>

<p class="muted" style="margin-top:16px;font-size:12px">
  Drift is computed by the daemon every cycle. Empty tabs mean either
  no drift, or no source for that drift type yet — set a baseline on
  <a href="/inventory">/inventory</a> for baseline drift, author policies
  on <a href="/policies">/policies</a> for policy drift, or connect a
  second identity system on <a href="/onboarding">/onboarding</a> for
  cross-system drift.
</p>
"""

_DRIFT_SCRIPT = r"""
let DR_DATA = null;
let DR_CURRENT = 'policy';

async function drLoad() {
  const tbody = document.querySelector('#dr-tbl tbody');
  tbody.innerHTML = `<tr><td class="muted" style="padding:36px;text-align:center">Loading...</td></tr>`;
  try {
    const r = await fetch('/api/drift/all', {credentials:'include'});
    if (!r.ok) throw new Error('HTTP ' + r.status);
    DR_DATA = await r.json();
    const s = DR_DATA.summary || {};
    document.getElementById('dr-total').textContent = s.total ?? 0;
    document.getElementById('dr-crit').textContent  = (s.by_severity||{}).critical ?? 0;
    document.getElementById('dr-high').textContent  = (s.by_severity||{}).high ?? 0;
    document.getElementById('dr-med').textContent   =
      ((s.by_severity||{}).medium ?? 0) + ((s.by_severity||{}).low ?? 0);
    document.getElementById('dr-cnt-policy').textContent       = `(${s.policy ?? 0})`;
    document.getElementById('dr-cnt-baseline').textContent     = `(${s.baseline ?? 0})`;
    document.getElementById('dr-cnt-cross_system').textContent = `(${s.cross_system ?? 0})`;
    drRender();
  } catch (e) {
    tbody.innerHTML = `<tr><td class="muted" style="padding:36px;text-align:center">
      Drift roll-up not reachable: ${esc(e.message)}.
      <a href="/onboarding">Run onboarding</a> if you haven't yet.</td></tr>`;
  }
}

function drPick(tab) {
  DR_CURRENT = tab;
  document.querySelectorAll('.dr-tab').forEach(b => {
    b.classList.toggle('dr-tab-active', b.dataset.tab === tab);
  });
  drRender();
}

function drRender() {
  if (!DR_DATA) return;
  const rows = DR_DATA[DR_CURRENT] || [];
  const thead = document.getElementById('dr-thead');
  const tbody = document.querySelector('#dr-tbl tbody');

  if (DR_CURRENT === 'policy') {
    thead.innerHTML = `<tr><th>Asset</th><th>Policy</th><th>Control</th>
      <th>Severity</th><th>Detail</th><th></th></tr>`;
    if (!rows.length) {
      tbody.innerHTML = `<tr><td colspan="6" class="muted" style="padding:36px;text-align:center">
        No policy drift. Either every asset matches its declared policy, or you haven't authored any policies yet —
        <a href="/policies">go author one →</a></td></tr>`;
      return;
    }
    tbody.innerHTML = rows.slice(0, 500).map(r => `
      <tr>
        <td>${assetCell(r.asset_id)}</td>
        <td><a href="/policies#${esc(r.policy_id||'')}">${esc(r.policy_id||'-')}</a></td>
        <td><code style="font-size:11px">${esc(r.control_id||'-')}</code></td>
        <td>${sevTag(r.severity)}</td>
        <td class="muted" style="font-size:12px">${esc(r.message||'-').slice(0,140)}</td>
        <td style="text-align:right;white-space:nowrap">
          ${r.asset_id ? actionBtns(r.asset_id, r.policy_id) : ''}
        </td>
      </tr>`).join('');
  } else if (DR_CURRENT === 'baseline') {
    thead.innerHTML = `<tr><th>Asset</th><th>Severity</th>
      <th>What drifted</th><th></th></tr>`;
    if (!rows.length) {
      tbody.innerHTML = `<tr><td colspan="4" class="muted" style="padding:36px;text-align:center">
        No baseline drift. Either nothing has changed since the baseline was set, or no asset has a baseline yet —
        set one from <a href="/inventory">/inventory</a> per device.</td></tr>`;
      return;
    }
    tbody.innerHTML = rows.slice(0, 500).map(r => `
      <tr>
        <td>${assetCell(r.asset_id)}</td>
        <td>${sevTag(r.severity)}</td>
        <td class="muted" style="font-size:12px">${esc(r.message||'-').slice(0,200)}</td>
        <td style="text-align:right;white-space:nowrap">
          ${r.asset_id ? actionBtns(r.asset_id) : ''}
        </td>
      </tr>`).join('');
  } else {
    thead.innerHTML = `<tr><th>Principal</th><th>Resource</th>
      <th>System A</th><th>System B</th><th>Severity</th></tr>`;
    if (!rows.length) {
      tbody.innerHTML = `<tr><td colspan="5" class="muted" style="padding:36px;text-align:center">
        No cross-system drift. Either every connected identity system agrees, or only one is wired up —
        <a href="/onboarding">connect another →</a></td></tr>`;
      return;
    }
    tbody.innerHTML = rows.slice(0, 500).map(r => `
      <tr>
        <td><strong>${esc(r.principal||'-')}</strong></td>
        <td>${esc(r.resource||'-')}</td>
        <td>${esc(String(r.system_a||'-'))}</td>
        <td>${esc(String(r.system_b||'-'))}</td>
        <td>${sevTag(r.severity)}</td>
      </tr>`).join('');
  }
}

function assetCell(aid) {
  if (!aid) return '-';
  return `<a href="/asset/${encodeURIComponent(aid)}">${esc(aid)}</a>`;
}

function actionBtns(aid, pid) {
  const a = encodeURIComponent(aid);
  const diffHref = `/per-device-diff?a=${a}` + (pid ? `&policy=${encodeURIComponent(pid)}` : '');
  const fixHref  = `/builder?asset_id=${a}` + (pid ? `&policy=${encodeURIComponent(pid)}` : '');
  return `
    <a href="${diffHref}" class="alt" style="padding:3px 8px;font-size:11px;
       text-decoration:none;border-radius:4px;margin-right:4px">Diff</a>
    <a href="${fixHref}" class="alt" style="padding:3px 8px;font-size:11px;
       text-decoration:none;border-radius:4px;background:var(--accent-bg,#e0f2fe)">Remediate</a>`;
}

function sevTag(sev) {
  sev = (sev || 'medium').toLowerCase();
  const cls = (sev === 'critical' || sev === 'high') ? 'tag-red' :
              sev === 'low' ? 'tag-green' : 'tag-yellow';
  return `<span class="tag ${cls}">${esc(sev)}</span>`;
}

function esc(s){const d=document.createElement('div');d.textContent=String(s||'');return d.innerHTML;}
drLoad();
"""


_EVIDENCE_BODY = """
<h1>Evidence packs</h1>
<p class="muted">One-click compliance bundles for SOC 2, ISO 27001, and
   NIST 800-53. Each pack assembles control-mapped findings, asset
   inventory, JIT grants, and approvals into a single auditor-ready
   archive.</p>

<div class="grid" style="display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin-top:16px">
  <div class="card">
    <h3 style="margin:0 0 6px">SOC 2</h3>
    <p class="muted" style="font-size:13px">Trust services criteria -
       security, availability, confidentiality.</p>
    <button class="alt" style="margin-top:8px" onclick="evGen('soc2')">Generate pack</button>
  </div>
  <div class="card">
    <h3 style="margin:0 0 6px">ISO 27001</h3>
    <p class="muted" style="font-size:13px">Annex A controls and ISMS
       evidence aligned to your inventory.</p>
    <button class="alt" style="margin-top:8px" onclick="evGen('iso27001')">Generate pack</button>
  </div>
  <div class="card">
    <h3 style="margin:0 0 6px">NIST 800-53</h3>
    <p class="muted" style="font-size:13px">Federal control families:
       AC, AU, CM, IA, SC.</p>
    <button class="alt" style="margin-top:8px" onclick="evGen('nist-800-53')">Generate pack</button>
  </div>
</div>

<h2 style="margin-top:24px;font-size:18px">Recent packs</h2>
<div class="card" style="padding:0;margin-top:8px">
  <table id="ev-tbl">
    <thead><tr><th>Generated</th><th>Framework</th><th>Status</th><th></th></tr></thead>
    <tbody><tr><td colspan="4" class="muted" style="padding:36px;text-align:center">
      No packs yet -- generate one above.</td></tr></tbody>
  </table>
</div>

<p class="muted" style="margin-top:16px;font-size:12px">
  The identity evidence pack lives on
  <a href="/identity">/identity</a> -- that one ships PDF + CSV + JSON
  for the full identity surface.
</p>
"""

_EVIDENCE_SCRIPT = r"""
async function evGen(framework) {
  const tbody = document.querySelector('#ev-tbl tbody');
  const row = document.createElement('tr');
  row.innerHTML = `<td>${new Date().toLocaleString()}</td>` +
    `<td>${framework}</td><td><span class="tag tag-yellow">generating...</span></td><td></td>`;
  if (tbody.querySelector('.muted')) tbody.innerHTML = '';
  tbody.prepend(row);
  try {
    const r = await fetch('/api/platform/evidence-pack?framework=' + encodeURIComponent(framework),
                          {credentials:'include'});
    if (!r.ok) throw new Error('HTTP ' + r.status);
    row.children[2].innerHTML = '<span class="tag tag-green">ready</span>';
    row.children[3].innerHTML = '<a href="/api/platform/evidence-pack?framework=' +
      encodeURIComponent(framework) + '&download=1">Download</a>';
  } catch (e) {
    row.children[2].innerHTML = '<span class="tag tag-red">error</span>';
    row.children[3].textContent = String(e.message);
  }
}
"""


_BUILDER_BODY = """
<h1>Command builder</h1>
<p class="muted">Describe a change in plain English &middot; pick which
   assets it should run on &middot; SafeCadence translates to per-vendor
   commands, classifies the risk, and stages the job for approval.
   Nothing executes from this page.</p>

<!-- ============================================================
     STEP 1 — Intent
     ============================================================ -->
<div class="card" style="margin-top:14px">
  <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px">
    <span style="display:inline-flex;align-items:center;justify-content:center;
                 width:22px;height:22px;border-radius:50%;background:var(--sc-accent,#2563eb);
                 color:white;font-size:12px;font-weight:700">1</span>
    <strong style="font-size:14px">What do you want to do?</strong>
  </div>

  <div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px"
       id="bld-intent-pills">
    <!-- pills filled in by JS so the canonical list lives in one place -->
  </div>

  <textarea id="bld-intent" rows="3"
            placeholder="e.g. Block SMB inbound on edge firewalls except from /24 management subnet."
            style="width:100%;font-family:inherit;font-size:13px;padding:10px;
                   border:1px solid var(--sc-border);border-radius:6px;
                   background:var(--sc-input-bg);color:var(--sc-fg)"></textarea>
  <p class="muted" style="font-size:11px;margin-top:6px">
    Click a starter above to fill the box, or type your own. The
    builder matches against ~30 offline intent packs first; for
    anything else it asks the configured BYO-AI translator.
  </p>
</div>

<!-- ============================================================
     STEP 2 — Target
     ============================================================ -->
<div class="card" style="margin-top:14px">
  <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px">
    <span style="display:inline-flex;align-items:center;justify-content:center;
                 width:22px;height:22px;border-radius:50%;background:var(--sc-accent,#2563eb);
                 color:white;font-size:12px;font-weight:700">2</span>
    <strong style="font-size:14px">Where should it run?</strong>
  </div>

  <div style="display:flex;gap:10px;align-items:flex-start;flex-wrap:wrap">
    <div style="flex:1;min-width:260px">
      <label class="muted" style="font-size:11px;display:block;margin-bottom:4px">
        Asset group</label>
      <select id="bld-group" onchange="bldOnGroupChange()"
              style="width:100%;padding:8px;border:1px solid var(--sc-border);
                     border-radius:6px;background:var(--sc-input-bg);color:var(--sc-fg)">
        <option value="">Loading groups…</option>
      </select>
    </div>
    <div style="flex:1;min-width:260px">
      <label class="muted" style="font-size:11px;display:block;margin-bottom:4px">
        Resolved devices</label>
      <div id="bld-target-preview"
           style="padding:8px;border:1px solid var(--sc-border);
                  border-radius:6px;background:var(--sc-panel-2,#f8f9fa);
                  min-height:36px;font-size:12px;color:var(--sc-fg)">
        <span class="muted">Pick a group to see the device list.</span>
      </div>
    </div>
  </div>

  <p class="muted" style="font-size:11px;margin-top:8px">
    Don't see your group? Author it on
    <a href="/groups">/groups</a> first &mdash; the dropdown reflects
    the same list. Selecting <em>(All matching assets)</em> targets
    every device the intent's vendor pack applies to; use it
    deliberately.
  </p>
</div>

<!-- ============================================================
     STEP 2.5 — Invite specific approvers (optional, v9.42)
     ============================================================ -->
<div class="card" style="margin-top:14px">
  <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px">
    <span style="display:inline-flex;align-items:center;justify-content:center;
                 width:22px;height:22px;border-radius:50%;background:#94a3b8;
                 color:white;font-size:12px;font-weight:700">·</span>
    <strong style="font-size:14px">Invite specific approvers
      <span class="muted" style="font-weight:400;font-size:12px">(optional)</span>
    </strong>
  </div>
  <div id="bld-invitees" style="display:flex;gap:6px;flex-wrap:wrap;
       padding:8px;border:1px solid var(--sc-border);border-radius:6px;
       min-height:38px;background:var(--sc-input-bg)">
    <span class="muted" id="bld-invitees-empty"
          style="font-size:12px;align-self:center">
      No specific invites — defaults to "any qualified approver"
    </span>
  </div>
  <div style="margin-top:8px">
    <select id="bld-invitee-pick" onchange="bldAddInvitee()"
            style="width:auto;padding:6px;border:1px solid var(--sc-border);
                   border-radius:6px;background:var(--sc-input-bg);color:var(--sc-fg)">
      <option value="">+ Add approver…</option>
    </select>
  </div>
  <p class="muted" style="font-size:11px;margin-top:8px">
    Trust note: invitation &ne; authorization. The role gate still
    enforces who can actually approve. Inviting someone without the
    required role is harmless &mdash; they get the email and see the
    queue page; clicking Approve returns 403. Invitees get an email
    DM (when SMTP is configured on
    <a href="/settings#email">/settings</a>); the channel webhook
    still fires regardless so backups can see the request too.
  </p>
</div>

<!-- ============================================================
     ACTIONS
     ============================================================ -->
<div style="display:flex;gap:8px;margin-top:14px;flex-wrap:wrap">
  <button onclick="bldPreview()" id="bld-preview-btn">Preview plan</button>
  <button class="alt" onclick="bldClear()">Clear</button>
  <span style="flex:1"></span>
  <a class="alt" href="/approvals" style="display:inline-block;padding:8px 14px;
     border-radius:6px;text-decoration:none;text-align:center">
    View approvals queue &rarr;</a>
</div>

<!-- ============================================================
     STEP 3 — Plan (hidden until preview)
     ============================================================ -->
<div id="bld-plan" style="margin-top:18px;display:none">
  <div class="card" id="bld-plan-card" style="margin-bottom:12px"></div>

  <div class="card" style="margin-bottom:12px">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
      <strong style="font-size:13px">Per-vendor commands</strong>
      <span class="muted" id="bld-cmd-summary" style="font-size:11px"></span>
    </div>
    <div id="bld-vendors"></div>
  </div>

  <div class="card" id="bld-rollback-card" style="margin-bottom:12px">
    <div style="display:flex;align-items:center;gap:8px">
      <span id="bld-rollback-icon" style="font-size:18px">&#x21A9;&#xFE0F;</span>
      <div>
        <strong style="font-size:13px">Rollback plan</strong>
        <div class="muted" style="font-size:12px" id="bld-rollback-text">
          Will be generated automatically when this job is approved.
        </div>
      </div>
    </div>
  </div>

  <div style="display:flex;gap:8px;flex-wrap:wrap">
    <button class="alt" onclick="bldSaveDraft()">Save as draft</button>
    <button onclick="bldSubmit()">Submit for approval &rarr;</button>
    <span style="flex:1"></span>
    <a class="alt" href="/queue" style="display:inline-block;padding:8px 14px;
       border-radius:6px;text-decoration:none;text-align:center">
      Execution queue</a>
  </div>
</div>
"""

_BUILDER_SCRIPT = r"""
// v9.41 — Builder redesign. The core mental model is three steps:
//   (1) intent — what    (2) target — where    (3) plan — how
// We keep the API surface identical to v9.35; the redesign is purely
// the UX shell. The plan response shape (commands_by_vendor, risk,
// risk_reasons, mode, blocked) drives the render.

// Keep the canonical list of starter intents in one place. Adding a
// pack? Add the matching pill so operators discover the new intent.
const BLD_INTENT_PILLS = [
  ["Block service inbound",
    "Block SMB inbound on edge firewalls except from /24 management subnet."],
  ["Add log destination",
    "Send all syslog messages to log host 10.0.0.5 on UDP/514."],
  ["Disable insecure protocol",
    "Disable telnet on every edge router; allow ssh v2 only."],
  ["Update NTP server",
    "Replace the current NTP server with time.acme.local on every router."],
  ["Tighten management ACL",
    "Permit SSH to management interfaces only from the 10.0.0.0/24 jump network."],
  ["Rotate SNMP community",
    "Replace the read-only SNMP community on every router with a fresh value."],
];

let BLD_GROUPS = [];          // [{group_id, name, member_count}]
let BLD_LAST_PLAN = null;
let BLD_LAST_TARGET = null;   // {asset_group_ids, asset_ids} for save calls
let BLD_USERS = [];           // v9.42 — directory of invitable approvers
let BLD_INVITEES = [];        // v9.42 — usernames the operator picked

function _esc(s) {
  return String(s ?? "").replace(/[<>&"']/g, c =>
    ({"<":"&lt;",">":"&gt;","&":"&amp;",'"':"&quot;","'":"&#39;"}[c]));
}

// ---------------- bootstrap ----------------

(function bldInit() {
  const wrap = document.getElementById('bld-intent-pills');
  wrap.innerHTML = BLD_INTENT_PILLS.map(([label, intent], i) =>
    `<button class="alt" type="button" onclick="bldPickPill(${i})"
       style="padding:4px 10px;font-size:11px;border-radius:14px;
              width:auto;font-weight:500" title="${_esc(intent)}">
       ${_esc(label)}</button>`).join('');
  bldLoadGroups();
  bldLoadUsers();
})();

// v9.42 — directory of invitable approvers ----------------------

async function bldLoadUsers() {
  const sel = document.getElementById('bld-invitee-pick');
  if (!sel) return;
  try {
    const r = await fetch('/api/users', {credentials:'include'});
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const data = await r.json();
    BLD_USERS = (data.users || []).filter(u => u && u.username);
  } catch (e) {
    sel.innerHTML = '<option value="">(no directory available)</option>';
    return;
  }
  bldRenderInviteeOptions();
}

function bldRenderInviteeOptions() {
  const sel = document.getElementById('bld-invitee-pick');
  const taken = new Set(BLD_INVITEES);
  sel.innerHTML =
    '<option value="">+ Add approver…</option>' +
    BLD_USERS.filter(u => !taken.has(u.username)).map(u => {
      const label = u.display_name || u.username;
      const email = u.email ? ` · ${u.email}` : '';
      const roles = (u.roles || []).join(',');
      return `<option value="${_esc(u.username)}">${_esc(label)}${_esc(email)}` +
             (roles ? ` (${_esc(roles)})` : '') + '</option>';
    }).join('');
}

function bldAddInvitee() {
  const sel = document.getElementById('bld-invitee-pick');
  const v = sel.value;
  if (!v) return;
  if (BLD_INVITEES.includes(v)) return;
  BLD_INVITEES.push(v);
  sel.value = '';
  bldRenderInvitees();
  bldRenderInviteeOptions();
}

function bldRemoveInvitee(username) {
  BLD_INVITEES = BLD_INVITEES.filter(u => u !== username);
  bldRenderInvitees();
  bldRenderInviteeOptions();
}

function bldRenderInvitees() {
  const wrap = document.getElementById('bld-invitees');
  const empty = document.getElementById('bld-invitees-empty');
  if (!BLD_INVITEES.length) {
    if (empty) empty.style.display = '';
    wrap.innerHTML =
      '<span class="muted" id="bld-invitees-empty" ' +
      'style="font-size:12px;align-self:center">' +
      'No specific invites — defaults to "any qualified approver"</span>';
    return;
  }
  const byName = Object.fromEntries(BLD_USERS.map(u => [u.username, u]));
  wrap.innerHTML = BLD_INVITEES.map(name => {
    const u = byName[name] || {username: name};
    const label = u.display_name || u.username;
    const noEmail = u.email ? '' :
      ' <span title="No email on file — they will not receive a DM"' +
      ' style="color:#b91c1c">⚠</span>';
    return `<span style="display:inline-flex;align-items:center;gap:4px;
              padding:4px 4px 4px 10px;border-radius:14px;
              background:var(--sc-panel-2,#f1f5f9);font-size:12px">
              <strong>${_esc(label)}</strong>${noEmail}
              <button onclick="bldRemoveInvitee('${_esc(name)}')"
                      style="background:none;border:none;cursor:pointer;
                             padding:0 6px;font-size:14px;line-height:1;color:#64748b"
                      title="Remove">&times;</button>
            </span>`;
  }).join('');
}

function bldPickPill(i) {
  const [_, intent] = BLD_INTENT_PILLS[i] || [];
  if (!intent) return;
  document.getElementById('bld-intent').value = intent;
  document.getElementById('bld-intent').focus();
}

// ---------------- step 2: groups ----------------

async function bldLoadGroups() {
  const sel = document.getElementById('bld-group');
  try {
    const r = await fetch('/api/platform/asset-groups',
                            {credentials:'include'});
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const data = await r.json();
    BLD_GROUPS = (data.groups || data || []).filter(g => g && g.group_id);
  } catch (e) {
    sel.innerHTML = '<option value="">(failed to load groups)</option>';
    return;
  }
  sel.innerHTML =
    '<option value="">— pick a group —</option>' +
    '<option value="__all__">(All matching assets)</option>' +
    BLD_GROUPS.map(g => {
      const n = g.member_count !== undefined
                  ? ` · ${g.member_count} device${g.member_count === 1 ? '' : 's'}`
                  : '';
      return `<option value="${_esc(g.group_id)}">${_esc(g.name || g.group_id)}${n}</option>`;
    }).join('');
}

async function bldOnGroupChange() {
  const sel = document.getElementById('bld-group');
  const out = document.getElementById('bld-target-preview');
  const v = sel.value;
  if (!v) {
    out.innerHTML = '<span class="muted">Pick a group to see the device list.</span>';
    return;
  }
  if (v === '__all__') {
    out.innerHTML =
      '<strong style="color:#b91c1c">All matching assets</strong>' +
      ' &mdash; final scope is decided by the intent&apos;s vendor ' +
      'pack at preview time. Use deliberately.';
    return;
  }
  out.innerHTML = '<span class="muted">Resolving…</span>';
  try {
    const r = await fetch('/api/platform/asset-groups/' +
                          encodeURIComponent(v),
                          {credentials:'include'});
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const data = await r.json();
    const ids = data.members || [];
    const n = data.member_count ?? ids.length;
    if (!n) {
      out.innerHTML = '<span class="muted">0 devices match this group right now.</span>';
      return;
    }
    const preview = ids.slice(0, 4).map(_esc).join(', ');
    const more = n > 4 ? ` and ${n - 4} more` : '';
    out.innerHTML = `<strong>${n} device${n === 1 ? '' : 's'}</strong> ` +
                    `&middot; ${preview}${more}`;
  } catch (e) {
    out.innerHTML = '<span class="muted">Resolve failed: ' +
                    _esc(e.message || e) + '</span>';
  }
}

// ---------------- step 3: preview + render ----------------

function _bldCurrentTarget() {
  const v = document.getElementById('bld-group').value;
  if (!v || v === '__all__') {
    return {asset_group_ids: [], asset_ids: []};
  }
  return {asset_group_ids: [v], asset_ids: []};
}

async function bldPreview() {
  const intent = document.getElementById('bld-intent').value.trim();
  if (!intent) { alert('Type or pick a starter intent first.'); return; }
  const target = _bldCurrentTarget();
  BLD_LAST_TARGET = target;

  const btn = document.getElementById('bld-preview-btn');
  const orig = btn.textContent;
  btn.disabled = true;
  btn.textContent = 'Previewing…';
  try {
    const r = await fetch('/api/execute/builder/plan', {
      method:'POST', credentials:'include',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({intent, approvers_invited: BLD_INVITEES, ...target}),
    });
    if (!r.ok) {
      const text = await r.text();
      _bldRenderError(`Preview failed: HTTP ${r.status}`, text);
      return;
    }
    const plan = await r.json();
    BLD_LAST_PLAN = plan;
    _bldRenderPlan(plan);
  } finally {
    btn.disabled = false;
    btn.textContent = orig;
  }
}

function _bldRenderError(title, body) {
  const wrap = document.getElementById('bld-plan');
  wrap.style.display = 'block';
  document.getElementById('bld-plan-card').innerHTML =
    `<div style="background:#fee2e2;border-left:4px solid #b91c1c;
         padding:10px 14px;border-radius:4px">
       <strong>${_esc(title)}</strong>
       <pre style="margin:6px 0 0;font-size:11px;white-space:pre-wrap">${_esc(body)}</pre>
     </div>`;
  document.getElementById('bld-vendors').innerHTML = '';
  document.getElementById('bld-cmd-summary').textContent = '';
  document.getElementById('bld-rollback-card').style.display = 'none';
}

function _bldRiskBadge(risk) {
  const r = String(risk || 'safe').toLowerCase();
  const colors = {
    safe:    {bg:'#dcfce7', fg:'#166534', label:'SAFE'},
    low:     {bg:'#dcfce7', fg:'#166534', label:'LOW'},
    medium:  {bg:'#fef9c3', fg:'#854d0e', label:'MEDIUM'},
    high:    {bg:'#fed7aa', fg:'#9a3412', label:'HIGH'},
    critical:{bg:'#fecaca', fg:'#991b1b', label:'CRITICAL'},
  };
  const c = colors[r] || colors.medium;
  return `<span style="background:${c.bg};color:${c.fg};padding:3px 10px;
            border-radius:12px;font-size:11px;font-weight:700;
            letter-spacing:0.5px">${c.label}</span>`;
}

function _bldApproverFor(risk) {
  const r = String(risk || 'safe').toLowerCase();
  if (r === 'safe' || r === 'low') return 'OPERATOR';
  if (r === 'medium')              return 'SUPER_ADMIN';
  return 'SUPER_ADMIN + 1 additional approver';   // high / critical
}

function _bldRenderPlan(plan) {
  const wrap = document.getElementById('bld-plan');
  wrap.style.display = 'block';

  // ---------- header card ----------
  const card = document.getElementById('bld-plan-card');

  if (plan.blocked) {
    card.innerHTML =
      `<div style="background:#fecaca;border-left:4px solid #991b1b;
           padding:10px 14px;border-radius:4px">
         <strong>Blocked by guardrails</strong>
         <ul style="margin:6px 0 0 18px;font-size:12px">
           ${(plan.block_reasons || []).map(r =>
              `<li>${_esc(r)}</li>`).join('')}
         </ul>
       </div>`;
    document.getElementById('bld-vendors').innerHTML = '';
    document.getElementById('bld-cmd-summary').textContent = '';
    document.getElementById('bld-rollback-card').style.display = 'none';
    return;
  }

  if (!(plan.matched_packs || []).length) {
    card.innerHTML =
      `<div style="background:#fef9c3;border-left:4px solid #ca8a04;
           padding:10px 14px;border-radius:4px">
         <strong>No matching pack &mdash; couldn&apos;t translate this intent.</strong>
         <div class="muted" style="font-size:12px;margin-top:4px">
           ${_esc(plan.summary || 'Try rephrasing or check the BYO-AI translator is configured.')}
         </div>
       </div>`;
    document.getElementById('bld-vendors').innerHTML = '';
    document.getElementById('bld-cmd-summary').textContent = '';
    document.getElementById('bld-rollback-card').style.display = 'none';
    return;
  }

  const cmdsByVendor = plan.commands_by_vendor || {};
  const vendors = Object.keys(cmdsByVendor);
  const totalCmds = vendors.reduce(
    (a, v) => a + (cmdsByVendor[v] || []).length, 0);
  const groupTargets = (plan.target_asset_group_ids || []).length;
  const idTargets = (plan.target_asset_ids || []).length;
  const targetSummary = idTargets
    ? `${idTargets} explicit asset${idTargets === 1 ? '' : 's'}`
    : groupTargets
    ? `${groupTargets} asset group${groupTargets === 1 ? '' : 's'}`
    : 'all matching assets (no group selected)';

  const reasons = (plan.risk_reasons || []).slice(0, 3);
  const reasonsHtml = reasons.length
    ? `<ul style="margin:6px 0 0 18px;font-size:11px;color:var(--sc-fg)">
         ${reasons.map(r => `<li>${_esc(r)}</li>`).join('')}
       </ul>`
    : '';

  card.innerHTML =
    `<div style="display:flex;gap:14px;align-items:center;flex-wrap:wrap">
       ${_bldRiskBadge(plan.risk)}
       <div style="flex:1;min-width:240px">
         <strong style="font-size:14px">${_esc(plan.summary || 'Plan ready')}</strong>
         <div class="muted" style="font-size:12px;margin-top:2px">
           Mode: <code>${_esc(plan.mode || 'config')}</code> &middot;
           Method: <code>${_esc(plan.method || 'manual')}</code> &middot;
           Approval: <code>${_bldApproverFor(plan.risk)}</code>
         </div>
       </div>
     </div>
     <div style="margin-top:10px;display:flex;gap:18px;flex-wrap:wrap;font-size:12px">
       <div><strong>${vendors.length}</strong>
            <span class="muted">vendor${vendors.length === 1 ? '' : 's'}</span></div>
       <div><strong>${totalCmds}</strong>
            <span class="muted">command${totalCmds === 1 ? '' : 's'} total</span></div>
       <div><span class="muted">Targets:</span> <strong>${_esc(targetSummary)}</strong></div>
       <div><span class="muted">Matched packs:</span>
            <code style="font-size:11px">${(plan.matched_packs || []).map(_esc).join(', ')}</code></div>
     </div>
     ${reasonsHtml}`;

  // ---------- per-vendor commands ----------
  const ven = document.getElementById('bld-vendors');
  document.getElementById('bld-cmd-summary').textContent =
    vendors.length ? `${vendors.length} vendor${vendors.length === 1 ? '' : 's'} · ${totalCmds} commands` : '';

  if (!vendors.length) {
    ven.innerHTML = '<span class="muted">No commands generated. Plan blocked or empty.</span>';
  } else {
    ven.innerHTML = vendors.map((v, idx) => {
      const cmds = cmdsByVendor[v] || [];
      // Auto-expand the first vendor; rest collapsed for tidiness.
      const open = idx === 0 ? ' open' : '';
      return `<details${open} style="border:1px solid var(--sc-border);
              border-radius:6px;padding:8px 12px;margin-bottom:6px">
                <summary style="cursor:pointer;font-size:13px">
                  <code style="font-weight:600">${_esc(v)}</code>
                  <span class="muted" style="font-size:11px;margin-left:6px">
                    ${cmds.length} command${cmds.length === 1 ? '' : 's'}</span>
                </summary>
                <pre style="margin:8px 0 0;font-family:ui-monospace,Menlo,monospace;
                     font-size:12px;background:var(--sc-panel-2,#f8f9fa);
                     padding:10px;border-radius:4px;overflow:auto;
                     white-space:pre-wrap">${cmds.map(_esc).join('\n')}</pre>
              </details>`;
    }).join('');
  }

  // ---------- rollback indicator ----------
  const rbCard = document.getElementById('bld-rollback-card');
  rbCard.style.display = '';
  const isConfig = String(plan.mode || '').toLowerCase().includes('config');
  document.getElementById('bld-rollback-text').innerHTML = isConfig
    ? `Will be generated automatically when this job is approved. ` +
      `<a href="/rollback">/rollback</a> shows the inverse commands ` +
      `per vendor before commit.`
    : `Read-only plan &mdash; no rollback needed.`;
}

// ---------------- save paths ----------------

async function bldSaveDraft() {
  if (!BLD_LAST_PLAN) { alert('Preview a plan first.'); return; }
  if (BLD_LAST_PLAN.blocked) {
    alert('This plan is blocked by guardrails. Adjust the intent before saving.');
    return;
  }
  const intent = document.getElementById('bld-intent').value.trim();
  const target = BLD_LAST_TARGET || _bldCurrentTarget();
  const r = await fetch('/api/execute/builder/save-draft', {
    method:'POST', credentials:'include',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({intent, approvers_invited: BLD_INVITEES, ...target}),
  });
  if (!r.ok) {
    alert('Save failed: HTTP ' + r.status + '\n' + (await r.text()));
    return;
  }
  const j = await r.json();
  const id = (j.job && j.job.job_id) || '';
  alert('Saved as draft' + (id ? `: ${id}` : '') +
        '. The job stays in DRAFT — no approver pinged. ' +
        'Find it on /queue under the DRAFT filter when you\'re ready.');
}

async function bldSubmit() {
  if (!BLD_LAST_PLAN) { alert('Preview a plan first.'); return; }
  if (BLD_LAST_PLAN.blocked) {
    alert('This plan is blocked by guardrails. Adjust the intent before submitting.');
    return;
  }
  const intent = document.getElementById('bld-intent').value.trim();
  const target = BLD_LAST_TARGET || _bldCurrentTarget();
  if (!confirm('Submit for approval? Approvers will be notified.')) return;
  const r = await fetch('/api/execute/builder/plan-and-save', {
    method:'POST', credentials:'include',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({intent, approvers_invited: BLD_INVITEES, ...target}),
  });
  if (!r.ok) {
    alert('Submit failed: HTTP ' + r.status + '\n' + (await r.text()));
    return;
  }
  const j = await r.json();
  const id = (j.job && j.job.job_id) || '';
  location.href = '/approvals' + (id ? `?focus=${encodeURIComponent(id)}` : '');
}

function bldClear() {
  document.getElementById('bld-intent').value = '';
  document.getElementById('bld-group').value = '';
  document.getElementById('bld-target-preview').innerHTML =
    '<span class="muted">Pick a group to see the device list.</span>';
  document.getElementById('bld-plan').style.display = 'none';
  BLD_INVITEES = [];
  bldRenderInvitees();
  bldRenderInviteeOptions();
  BLD_LAST_PLAN = null;
  BLD_LAST_TARGET = null;
}
"""


_APPROVALS_BODY = """
<h1>Approvals queue</h1>
<p class="muted">Risk-tiered approval flow. Every job from the
   <a href="/builder">command builder</a> or any IaC pipeline lands
   here with a pre-computed rollback plan.</p>

<div class="card" style="margin-bottom:14px">
  <div style="display:flex;gap:16px;align-items:center;flex-wrap:wrap">
    <div><strong id="apv-pending">-</strong> <span class="muted">pending</span></div>
    <div><strong id="apv-approved">-</strong> <span class="muted">approved</span></div>
    <div><strong id="apv-rejected">-</strong> <span class="muted">rejected</span></div>
    <span style="flex:1"></span>
    <button class="alt" style="width:auto;padding:6px 12px;font-size:12px"
            onclick="apvRefresh()">&#x21BB; Refresh</button>
  </div>
</div>

<div class="card" style="padding:0">
  <table id="apv-tbl">
    <thead><tr>
      <th>Job</th><th>Intent</th><th>Risk</th><th>Status</th><th>Actions</th>
    </tr></thead>
    <tbody><tr><td colspan="5" class="muted"
         style="padding:36px;text-align:center">Loading...</td></tr></tbody>
  </table>
</div>

<p class="muted" style="margin-top:16px;font-size:12px">
  Approving here doesn't execute -- execution still lives on
  <a href="/queue">/queue</a> and requires Tier 3 SSH + TOTP for real
  changes.
</p>
"""

_APPROVALS_SCRIPT = r"""
async function apvRefresh() {
  const tbody = document.querySelector('#apv-tbl tbody');
  tbody.innerHTML = '<tr><td colspan="5" class="muted" style="padding:36px;text-align:center">Loading...</td></tr>';
  try {
    const r = await fetch('/api/execute/jobs', {credentials:'include'});
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const data = await r.json();
    const jobs = data.jobs || data || [];
    const counts = {pending:0, approved:0, rejected:0};
    for (const j of jobs) {
      const s = (j.status || '').toLowerCase();
      if (s.includes('pending') || s === 'submitted') counts.pending++;
      else if (s.includes('approved')) counts.approved++;
      else if (s.includes('rejected')) counts.rejected++;
    }
    document.getElementById('apv-pending').textContent = counts.pending;
    document.getElementById('apv-approved').textContent = counts.approved;
    document.getElementById('apv-rejected').textContent = counts.rejected;
    if (!jobs.length) {
      tbody.innerHTML = '<tr><td colspan="5" class="muted" style="padding:36px;text-align:center">' +
        'No jobs yet. <a href="/builder">Use the command builder</a> to plan one.</td></tr>';
      return;
    }
    tbody.innerHTML = jobs.slice(0, 200).map(j => {
      const id = j.job_id || j.id || '-';
      const intent = j.intent || j.description || '-';
      const risk = (j.risk_tier || j.risk || 'medium').toLowerCase();
      const tag = risk === 'high' || risk === 'critical' ? 'tag tag-red' :
                  risk === 'low' ? 'tag tag-green' : 'tag tag-yellow';
      const status = j.status || '-';
      const actions = (status === 'pending' || status === 'submitted')
        ? `<button class="alt" style="padding:3px 8px;font-size:11px"
            onclick="apvApprove('${esc(String(id))}')">Approve</button>
          <button class="alt" style="padding:3px 8px;font-size:11px;margin-left:4px"
            onclick="apvReject('${esc(String(id))}')">Reject</button>`
        : `<a href="/queue#${esc(String(id))}" style="font-size:12px">Open &rarr;</a>`;
      return `<tr><td><code style="font-size:11px">${esc(String(id))}</code></td>` +
             `<td>${esc(String(intent)).slice(0,80)}</td>` +
             `<td><span class="${tag}">${esc(risk)}</span></td>` +
             `<td>${esc(String(status))}</td>` +
             `<td>${actions}</td></tr>`;
    }).join('');
  } catch (e) {
    document.getElementById('apv-pending').textContent = '-';
    tbody.innerHTML = '<tr><td colspan="5" class="muted" style="padding:36px;text-align:center">' +
      'Approvals API not reachable (' + esc(String(e.message)) + ').</td></tr>';
  }
}
async function apvApprove(id) {
  const r = await fetch('/api/execute/jobs/' + encodeURIComponent(id) + '/approve',
    {method:'POST', credentials:'include'});
  if (!r.ok) { alert('Approve failed: HTTP ' + r.status); return; }
  apvRefresh();
}
async function apvReject(id) {
  const r = await fetch('/api/execute/jobs/' + encodeURIComponent(id) + '/reject',
    {method:'POST', credentials:'include'});
  if (!r.ok) { alert('Reject failed: HTTP ' + r.status); return; }
  apvRefresh();
}
function esc(s){const d=document.createElement('div');d.textContent=String(s);return d.innerHTML;}
apvRefresh();
"""


_QUEUE_BODY = """
<h1>Execution queue</h1>
<p class="muted">Active jobs by stage. Dry-run results, real-execution
   progress, and final state -- all in one place.</p>

<div class="card" style="margin-bottom:14px">
  <div style="display:flex;gap:16px;align-items:center;flex-wrap:wrap">
    <div><strong id="q-running">-</strong> <span class="muted">running</span></div>
    <div><strong id="q-queued">-</strong> <span class="muted">queued</span></div>
    <div><strong id="q-done">-</strong> <span class="muted">completed</span></div>
    <div><strong id="q-error">-</strong> <span class="muted">errored</span></div>
    <span style="flex:1"></span>
    <button class="alt" style="width:auto;padding:6px 12px;font-size:12px"
            onclick="qRefresh()">&#x21BB; Refresh</button>
  </div>
</div>

<div class="card" style="padding:0">
  <table id="q-tbl">
    <thead><tr>
      <th>Job</th><th>Stage</th><th>Started</th><th>Duration</th><th></th>
    </tr></thead>
    <tbody><tr><td colspan="5" class="muted"
         style="padding:36px;text-align:center">Loading...</td></tr></tbody>
  </table>
</div>

<p class="muted" style="margin-top:16px;font-size:12px">
  Anything that fails here drops a rollback candidate on
  <a href="/rollback">/rollback</a>.
</p>
"""

_QUEUE_SCRIPT = r"""
async function qRefresh() {
  const tbody = document.querySelector('#q-tbl tbody');
  tbody.innerHTML = '<tr><td colspan="5" class="muted" style="padding:36px;text-align:center">Loading...</td></tr>';
  try {
    const r = await fetch('/api/execute/queue', {credentials:'include'});
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const data = await r.json();
    const jobs = data.queue || data.jobs || data || [];
    const c = {running:0, queued:0, done:0, error:0};
    for (const j of jobs) {
      const s = (j.stage || j.status || '').toLowerCase();
      if (s.includes('run')) c.running++;
      else if (s.includes('queue') || s.includes('approved') || s === 'submitted') c.queued++;
      else if (s.includes('error') || s.includes('fail')) c.error++;
      else if (s.includes('done') || s.includes('complete')) c.done++;
    }
    document.getElementById('q-running').textContent = c.running;
    document.getElementById('q-queued').textContent = c.queued;
    document.getElementById('q-done').textContent = c.done;
    document.getElementById('q-error').textContent = c.error;
    if (!jobs.length) {
      tbody.innerHTML = '<tr><td colspan="5" class="muted" style="padding:36px;text-align:center">' +
        'Queue empty. <a href="/approvals">Approve a job</a> to put work here.</td></tr>';
      return;
    }
    tbody.innerHTML = jobs.slice(0, 200).map(j => {
      const id = j.job_id || j.id || '-';
      const stage = j.stage || j.status || '-';
      const started = j.started_at || j.created_at || '-';
      const dur = j.duration_seconds != null ? j.duration_seconds + 's' : '-';
      const tagCls = stage.toLowerCase().includes('error') || stage.toLowerCase().includes('fail')
        ? 'tag tag-red'
        : stage.toLowerCase().includes('done') || stage.toLowerCase().includes('complete')
          ? 'tag tag-green' : 'tag tag-yellow';
      return `<tr><td><code style="font-size:11px">${esc(String(id))}</code></td>` +
             `<td><span class="${tagCls}">${esc(String(stage))}</span></td>` +
             `<td>${esc(String(started))}</td>` +
             `<td>${esc(String(dur))}</td>` +
             `<td><a href="/approvals#${esc(String(id))}" style="font-size:12px">Detail &rarr;</a></td></tr>`;
    }).join('');
  } catch (e) {
    tbody.innerHTML = '<tr><td colspan="5" class="muted" style="padding:36px;text-align:center">' +
      'Queue not reachable (' + esc(String(e.message)) + ').</td></tr>';
  }
}
function esc(s){const d=document.createElement('div');d.textContent=String(s);return d.innerHTML;}
qRefresh();
setInterval(qRefresh, 15000); // live refresh every 15s
"""


_ROLLBACK_BODY = """
<h1>Rollback manager</h1>
<p class="muted">Every approved job comes with a rollback plan
   generated <em>before</em> execution. If something breaks, you don't
   guess -- you click. Plans are persisted with the job for the lifetime
   of the audit window.</p>

<div class="card" style="padding:0">
  <table id="rb-tbl">
    <thead><tr>
      <th>Job</th><th>Original intent</th><th>Status</th><th></th>
    </tr></thead>
    <tbody><tr><td colspan="4" class="muted"
         style="padding:36px;text-align:center">Loading...</td></tr></tbody>
  </table>
</div>

<p class="muted" style="margin-top:16px;font-size:12px">
  Rollbacks themselves go through approvals + the same execution
  guardrails -- they're just another job, with the diff inverted.
</p>
"""

_ROLLBACK_SCRIPT = r"""
async function rbRefresh() {
  const tbody = document.querySelector('#rb-tbl tbody');
  tbody.innerHTML = '<tr><td colspan="4" class="muted" style="padding:36px;text-align:center">Loading...</td></tr>';
  try {
    const r = await fetch('/api/execute/jobs', {credentials:'include'});
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const data = await r.json();
    const jobs = (data.jobs || data || []).filter(j =>
      j.has_rollback || j.rollback_plan || (j.status||'').toLowerCase() === 'completed' ||
      (j.status||'').toLowerCase() === 'errored' || (j.status||'').toLowerCase() === 'failed');
    if (!jobs.length) {
      tbody.innerHTML = '<tr><td colspan="4" class="muted" style="padding:36px;text-align:center">' +
        'No rollback candidates. They will appear here once jobs run from the ' +
        '<a href="/queue">queue</a>.</td></tr>';
      return;
    }
    tbody.innerHTML = jobs.slice(0, 200).map(j => {
      const id = j.job_id || j.id || '-';
      const intent = j.intent || j.description || '-';
      const status = j.status || '-';
      const tag = (status.toLowerCase().includes('error') || status.toLowerCase().includes('fail'))
        ? 'tag tag-red' : 'tag tag-green';
      return `<tr><td><code style="font-size:11px">${esc(String(id))}</code></td>` +
             `<td>${esc(String(intent)).slice(0,80)}</td>` +
             `<td><span class="${tag}">${esc(String(status))}</span></td>` +
             `<td><button class="alt" style="padding:3px 8px;font-size:11px"
                  onclick="rbDoRollback('${esc(String(id))}')">Roll back</button></td></tr>`;
    }).join('');
  } catch (e) {
    tbody.innerHTML = '<tr><td colspan="4" class="muted" style="padding:36px;text-align:center">' +
      'Rollback list not reachable (' + esc(String(e.message)) + ').</td></tr>';
  }
}
// v9.35 #2 — show the persisted rollback plan BEFORE the operator
// commits. They see the inverted commands per device + a count of
// "REVIEW" lines that need manual edits. No commit without explicit
// click in the slide-over.
async function rbDoRollback(id) {
  let plan = null;
  try {
    const r = await fetch('/api/execute/jobs/' + encodeURIComponent(id)
                          + '/rollback-plan', {credentials: 'include'});
    if (r.ok) plan = await r.json();
  } catch (e) {
    // Fall through to the plan-less branch below.
  }
  const rollbacks = (plan && plan.asset_rollbacks) || {};
  const targets = Object.keys(rollbacks);
  const reviewCount = (plan && plan.review_count) || 0;
  const planHTML = targets.length ? targets.map(vendor => `
    <div class="card" style="padding:10px;margin-top:8px">
      <strong>${esc(vendor)}</strong>
      <span class="muted" style="margin-left:6px">${rollbacks[vendor].length} command(s)</span>
      <pre style="font-size:11px;margin-top:6px;white-space:pre-wrap">${
        rollbacks[vendor].map(c => esc(c)).join('\n')
      }</pre>
    </div>`).join('') : `<p class="muted">
      No rollback plan persisted for this job. (Plans are generated
      when a job transitions to APPROVED.) Submitting a rollback
      anyway will mark the job ROLLED_BACK in the audit log without
      executing inverse commands. Most operators want to author a
      manual rollback job instead.
    </p>`;

  const reviewBanner = reviewCount > 0 ? `
    <div class="card" style="padding:10px;margin-top:8px;border-left:3px solid #f5a623">
      <strong>${reviewCount} command(s) need manual review</strong>
      <div class="muted" style="font-size:11px;margin-top:4px">
        Lines starting with <code># REVIEW</code> couldn't be auto-inverted.
        Hand-edit those before submitting the rollback.
      </div>
    </div>` : '';

  scOpenSlide('Rollback plan — ' + id, `
    <p class="muted">
      The plan below was generated at approval time and persisted with
      the job. Submitting a rollback enqueues these inverse commands
      as a NEW job that goes through the same approval + execution
      gates as the original.
    </p>
    ${reviewBanner}
    ${planHTML}
    <div style="display:flex;gap:8px;margin-top:14px">
      <button class="alt" onclick='scCloseSlide()'>Cancel</button>
      <button class="primary" onclick='rbConfirmRollback("${esc(id)}")'>
        Submit rollback &rarr; /approvals
      </button>
    </div>
  `);
}

async function rbConfirmRollback(id) {
  const r = await fetch('/api/execute/jobs/' + encodeURIComponent(id)
                        + '/rollback', {method:'POST', credentials:'include'});
  if (!r.ok) { alert('Rollback submit failed: HTTP ' + r.status); return; }
  scCloseSlide();
  alert('Rollback submitted. Track it on /approvals.');
  rbRefresh();
}
function esc(s){const d=document.createElement('div');d.textContent=String(s);return d.innerHTML;}
rbRefresh();
"""


# ---------------------------------------------------------------- register


# --------------------------------------------------------- v9.33 #9 /access

# Who-can-reach-X surface. Type a resource + an action, get every principal
# the EffectivePermissionResolver says is allowed (across Okta+AD+Entra+
# ISE+ClearPass) plus the rule chain that grants it. Per-row "revoke" goes
# through the diff-card flow from #3.

_ACCESS_BODY = """
<h1>Who can reach…</h1>
<p class="muted">
  Cross-system access query. Powered by the EffectivePermissionResolver
  (composes Okta + AD + Entra + ISE + ClearPass declared rules).
</p>

<div class="card" style="padding:16px;margin-top:8px">
  <div class="row" style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px">
    <div>
      <label>Resource (asset_id, hostname, or app)</label>
      <input id="ax-resource" placeholder="prod-db" />
    </div>
    <div>
      <label>Action</label>
      <input id="ax-action" placeholder="ssh" value="ssh" />
    </div>
    <div>
      <label>Principal hint (optional, narrows query)</label>
      <input id="ax-principal" placeholder="alice@acme.com" />
    </div>
  </div>
  <div style="margin-top:12px">
    <button class="primary" onclick="runAccessQuery()">Search</button>
  </div>
</div>

<div id="ax-result" style="margin-top:16px"></div>
"""

_ACCESS_SCRIPT = r"""
async function runAccessQuery() {
  const res  = (document.getElementById("ax-resource").value || "").trim();
  const act  = (document.getElementById("ax-action").value || "").trim();
  const pri  = (document.getElementById("ax-principal").value || "").trim()
              || "*";
  const out  = document.getElementById("ax-result");
  if (!res || !act) {
    out.innerHTML = `<p class="muted">Enter resource + action to search.</p>`;
    return;
  }
  out.innerHTML = `<p class="muted">Searching…</p>`;
  try {
    const url = `/api/identity/who-can?action=${encodeURIComponent(act)}`
              + `&resource=${encodeURIComponent(res)}`
              + `&principal=${encodeURIComponent(pri)}`;
    const r = await scApi(url);
    const allowed = r.allowed;
    const stepup  = r.requires_step_up;
    const sysList = (r.systems_consulted || []).join(", ") || "(none)";
    const reasons = (r.reasons || []).map(s => `<li>${s}</li>`).join("");
    const chain   = (r.chain || []).map(c => `
      <div class="card" style="padding:10px;margin-top:6px">
        <span class="pill pill-info">${c.system}</span>
        <strong>${c.rule_name}</strong>
        <span class="muted" style="margin-left:6px">→ ${c.effect}</span>
        <div class="muted" style="font-size:12px;margin-top:4px">
          matched on: ${(c.matched_on || []).join(", ")}
        </div>
      </div>`).join("");
    const verdictPill = allowed
      ? `<span class="pill pill-crit">ALLOW</span>`
      : `<span class="pill pill-info">DENY</span>`;
    out.innerHTML = `
      <div class="card" style="padding:16px">
        <div style="display:flex;align-items:center;gap:8px">
          ${verdictPill}
          <strong>${pri}</strong>
          <span class="muted">→ ${act} →</span>
          <strong>${res}</strong>
          ${stepup ? `<span class="pill pill-high" style="margin-left:auto">step-up MFA</span>` : ''}
        </div>
        <div class="muted" style="font-size:12px;margin-top:6px">
          systems consulted: ${sysList}
        </div>
        ${reasons ? `<details style="margin-top:8px"><summary class="muted">reasons</summary>
          <ul style="margin:6px 0 0 20px">${reasons}</ul></details>` : ''}
        <div style="margin-top:12px"><strong>Rule chain</strong></div>
        ${chain || `<p class="muted">No rules matched.</p>`}
        ${allowed ? `<button class="alt" style="margin-top:12px;width:auto;padding:6px 14px"
                      onclick="alert('Revoke flow uses the diff-card from /findings — wire-up arrives in v9.33.1')">
                      Revoke this access &rarr;
                    </button>` : ''}
      </div>`;
  } catch (e) {
    out.innerHTML = `<p class="muted">Query failed: ${e.message}</p>`;
  }
}
"""


# --------------------------------------------------------- v9.33 #4–6 /identity

# Action-first identity page. Hero band (Auto-detect / Connect / Manual NHI),
# per-system connector status strip, "next 3 actions" panel pulling from
# /api/identity/findings, and the existing translator + JIT widgets so we
# don't drop functionality. Slide-over forms are surfaced via shared chrome.

_IDENTITY_BODY = """
<h1>Identity</h1>
<p class="muted" id="ident-subtitle">
  Cross-system policy intelligence over Okta, Entra, ISE, ClearPass, and AD.
</p>

<!-- v9.33 #4 — onboarding hero band -->
<div class="grid-3" style="margin-top:16px">
  <div class="card hero-card" id="hero-discover">
    <div class="muted" style="font-size:11px">1</div>
    <h3 style="margin:4px 0">Auto-detect</h3>
    <p class="muted" style="font-size:13px">
      Scan email DNS, LAN, and Graph to find Okta / Entra / ISE / ClearPass / AD
      reachable from this host. Read-only.
    </p>
    <button class="primary" onclick="openDiscoverSlide()">Run discovery</button>
  </div>
  <div class="card hero-card" id="hero-connect">
    <div class="muted" style="font-size:11px">2</div>
    <h3 style="margin:4px 0">Connect a system</h3>
    <p class="muted" style="font-size:13px">
      Add credentials for one of the 5 supported identity systems.
      Stored in the encrypted vault, never sent off this host.
    </p>
    <button class="alt" onclick="openConnectSlide()">Connect…</button>
  </div>
  <div class="card hero-card" id="hero-nhi">
    <div class="muted" style="font-size:11px">3</div>
    <h3 style="margin:4px 0">Add an NHI manually</h3>
    <p class="muted" style="font-size:13px">
      Service accounts, API keys, IAM roles. Track owner + rotation
      cadence even before adapters are connected.
    </p>
    <button class="alt" onclick="openManualNHISlide()">Add NHI…</button>
  </div>
</div>

<!-- v9.33 #4 — connector status strip -->
<div class="card" style="margin-top:16px;padding:12px">
  <div style="display:flex;align-items:center;gap:8px">
    <strong>Connectors</strong>
    <span class="muted" id="conn-summary">checking…</span>
    <a class="muted" style="margin-left:auto;font-size:12px" href="/onboarding">
      Setup help &rarr;
    </a>
  </div>
  <div id="conn-strip" style="display:flex;gap:8px;margin-top:8px;flex-wrap:wrap">
  </div>
</div>

<!-- v9.33 #6 — next 3 actions panel -->
<div class="card" style="margin-top:16px;padding:16px">
  <div style="display:flex;align-items:center;gap:8px">
    <strong>Next 3 actions</strong>
    <span class="muted" style="font-size:12px">
      identity-scoped — top stale NHI, top over-privileged human, top conflict
    </span>
    <a class="muted" style="margin-left:auto;font-size:12px" href="/findings">
      All findings &rarr;
    </a>
  </div>
  <div id="next-actions" style="margin-top:8px"></div>
</div>

<!-- v9.34 #5 — Non-human identities -->
<h2 style="margin-top:24px">Non-human identities</h2>
<p class="muted" style="font-size:13px">
  Service accounts, API keys, IAM roles. Owner + rotation cadence drive
  the stale-NHI finder and rotation-overdue alerts.
</p>
<div class="card" style="padding:16px;margin-top:8px">
  <div id="nhi-list">Loading…</div>
  <div style="margin-top:12px">
    <button class="alt" onclick="openManualNHISlide()">+ Add NHI</button>
  </div>
</div>

<!-- Translator (existing v7.5 functionality, preserved) -->
<h2 style="margin-top:24px">Translate intent &rarr; per-system change</h2>
<p class="muted" style="font-size:13px">
  Plain English in, unified policy IR out, per-system change preview at the
  bottom. Submitting calls <code>/api/identity/translate</code>; nothing
  is committed without an explicit dry-run + confirm-token review.
</p>
<div class="card" style="padding:16px;margin-top:8px">
  <textarea id="ident-intent" rows="3"
    placeholder="e.g. Block contractors from production SSH unless MFA"></textarea>
  <div class="row" style="margin-top:8px;display:flex;gap:8px">
    <button class="primary" id="ident-translate-btn"
            onclick="translateIntent()">Translate</button>
    <button class="alt" onclick="previewIR()">Preview against connected systems</button>
  </div>
  <pre id="ident-ir" class="muted"
       style="margin-top:12px;display:none;font-size:12px"></pre>
</div>

<!-- JIT widget (existing v7.6 functionality, preserved) -->
<h2 style="margin-top:24px">Just-in-Time access</h2>
<p class="muted" style="font-size:13px">
  Time-boxed grants. Issued through <code>/api/identity/jit/grant</code>,
  auto-expired by the daemon. Apply step still requires confirm-token.
</p>
<div class="card" style="padding:16px;margin-top:8px">
  <div class="row" style="display:flex;gap:8px;flex-wrap:wrap">
    <input id="jit-principal" placeholder="principal (alice@acme.com)" />
    <input id="jit-action"    placeholder="action (ssh)" />
    <input id="jit-resource"  placeholder="resource (prod-db)" />
    <input id="jit-duration"  placeholder="seconds (14400)" />
  </div>
  <div style="margin-top:8px">
    <button class="primary" onclick="issueJIT()">Issue JIT grant</button>
  </div>
  <p class="muted" style="font-size:11px;margin-top:6px">
    A JIT record is persisted locally; pushing the grant to the target system
    requires a separate dry-run + confirm-token from /findings.
  </p>
</div>
"""


_IDENTITY_SCRIPT = r"""
async function loadConnectorStatus() {
  try {
    const r = await scApi("/api/identity/connectors-status");
    const cs = r.systems || [];
    const sum = document.getElementById("conn-summary");
    sum.textContent = `${r.configured || 0} of ${r.total || 5} connected`;
    const strip = document.getElementById("conn-strip");
    strip.innerHTML = cs.map(s => {
      const cls = s.configured ? "pill-info" : "pill-high";
      const label = s.configured
        ? "configured"
        : `missing ${s.need - s.have}/${s.need} env`;
      return `<span class="pill ${cls}" title="${(s.missing || []).join(', ')}">
        ${s.system} · ${label}
      </span>`;
    }).join("");
  } catch (e) {
    document.getElementById("conn-summary").textContent =
      "could not load (auth?)";
  }
}

async function loadNextActions() {
  const div = document.getElementById("next-actions");
  try {
    const r = await scApi("/api/identity/findings");
    const fs = (r.findings || []).slice().sort((a, b) => {
      const o = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      return (o[a.severity] || 9) - (o[b.severity] || 9);
    });
    if (!fs.length) {
      div.innerHTML = `<p class="muted">
        🎉 Nothing pressing. Connect a system to start producing findings.
      </p>`;
      return;
    }
    div.innerHTML = fs.slice(0, 3).map(f => {
      const sev = f.severity === "critical" || f.severity === "high"
                ? "pill-crit"
                : f.severity === "medium" ? "pill-high" : "pill-info";
      return `<div style="display:flex;align-items:center;gap:10px;
                            padding:8px 0;border-bottom:1px solid var(--line)">
        <span class="pill ${sev}">${(f.severity || '').toUpperCase()}</span>
        <div style="flex:1">
          <div>${f.title || f.kind}</div>
          <div class="muted" style="font-size:11px">${f.principal || ''}</div>
        </div>
        <a class="alt" style="padding:4px 10px;text-decoration:none;font-size:12px"
           href="/findings#${f.finding_id}">Resolve &rarr;</a>
      </div>`;
    }).join("");
  } catch (e) {
    div.innerHTML = `<p class="muted">Could not load findings: ${e.message}</p>`;
  }
}

// v9.33 #4 — Discover slide-over.
function openDiscoverSlide() {
  scOpenSlide("Auto-detect identity systems", `
    <p class="muted">
      Probes Okta (DNS), Entra (Graph discovery), ISE/ClearPass (LAN TCP),
      and AD (DNS SRV). Read-only — no credentials required.
    </p>
    <label>Email domain (optional)</label>
    <input id="dd-email" placeholder="acme.com" />
    <label style="margin-top:8px">Entra tenant (optional)</label>
    <input id="dd-entra" placeholder="acme.onmicrosoft.com" />
    <label style="margin-top:8px">AD domain (optional)</label>
    <input id="dd-ad" placeholder="corp.local" />
    <button class="primary" style="margin-top:12px;width:100%"
            onclick="runDiscovery()">Run discovery</button>
    <div id="dd-result" style="margin-top:12px"></div>
  `);
}

async function runDiscovery() {
  const out = document.getElementById("dd-result");
  out.innerHTML = `<p class="muted">Probing… (≤10s)</p>`;
  try {
    const body = {
      email_domain: (document.getElementById("dd-email").value || "").trim() || null,
      entra_tenant: (document.getElementById("dd-entra").value || "").trim() || null,
      ad_domain:    (document.getElementById("dd-ad").value || "").trim() || null,
    };
    const r = await scApi("/api/identity/discover", {
      method: "POST", body: JSON.stringify(body),
    });
    const fs = r.findings || [];
    if (!fs.length) {
      out.innerHTML = `<p class="muted">
        No identity systems detected. Try a different domain hint or use
        Connect to add credentials directly.
      </p>`;
      return;
    }
    out.innerHTML = fs.map(f => `
      <div class="card" style="padding:10px;margin-top:8px">
        <strong>${f.system}</strong>
        <span class="pill pill-info" style="margin-left:6px">
          ${Math.round((f.confidence || 0) * 100)}% confidence
        </span>
        <div class="muted" style="margin-top:4px">${f.evidence}</div>
        <div style="margin-top:6px"><strong>Next:</strong> ${f.next_step}</div>
        ${Object.keys(f.env_vars || {}).length ? `
          <details style="margin-top:6px"><summary class="muted">env-var recipe</summary>
            <pre style="font-size:11px;margin-top:4px">${
              Object.entries(f.env_vars).map(([k,v]) =>
                `export ${k}='${v}'`).join('\n')
            }</pre>
          </details>` : ''}
      </div>`).join("");
  } catch (e) {
    out.innerHTML = `<p class="muted">Discovery failed: ${e.message}</p>`;
  }
}

// v9.34 #1 — Connect form (real). Posts to /api/identity/connect.
// v9.34.2 — operator-friendly help and aggressive autofill defense.
//
// Trust property: "Save & sync" only runs after Test Connection
// returns ok. The server-side handler enforces this independently
// (vault refuses test_passed=False); the UI mirror just keeps the
// human in the loop.
//
// Each schema entry now carries:
//   target_help: prose explaining WHAT the target is (not IP/hostname
//                vocabulary — concrete "look in this admin URL" text)
//   target_examples: array of 2-3 real-shaped examples
//   field-level `help` for each credential
const CONNECT_SCHEMAS = {
  okta: {
    label: "Okta",
    target_label: "Okta domain",
    target_placeholder: "your-org.okta.com",
    target_help: "This is the URL you visit when you log into Okta admin — without the https:// prefix. It is NOT an IP address. Most Okta tenants look like company-name.okta.com; sandbox/preview tenants look like company-name.oktapreview.com.",
    target_examples: [
      "acme.okta.com",
      "acme.oktapreview.com",
      "auth.acme.com  (custom domain)",
    ],
    fields: [{
      k: "api_token", l: "API token", secret: true,
      help: "Okta admin → Security → API → Tokens → Create Token. A read-only-scope token is enough for sync; write-back needs admin scope.",
    }],
    help: "Okta REST API. Read-only token works for sync; write-back needs admin scope.",
  },
  entra: {
    label: "Entra ID (Azure AD)",
    target_label: "Tenant",
    target_placeholder: "your-org.onmicrosoft.com",
    target_help: "Your Microsoft Entra tenant. NOT an IP — it's a domain name ending in .onmicrosoft.com (or your custom verified domain). Find it in the Entra admin center under Overview → Primary domain.",
    target_examples: [
      "acme.onmicrosoft.com",
      "<tenant-id-uuid>",
      "acme.com  (verified custom domain)",
    ],
    fields: [
      { k: "tenant_id",     l: "Tenant ID",
        help: "Directory (tenant) ID GUID from Entra admin → Overview." },
      { k: "client_id",     l: "Client ID",
        help: "Application (client) ID from your app registration." },
      { k: "client_secret", l: "Client secret", secret: true,
        help: "Generate under app registration → Certificates & secrets." },
    ],
    help: "App registration with Directory.Read.All for sync. Conditional Access write-back needs Policy.ReadWrite.ConditionalAccess.",
  },
  ise: {
    label: "Cisco ISE",
    target_label: "ISE host",
    target_placeholder: "ise.example.com",
    target_help: "Hostname or IP of your ISE primary admin node (the one you log into for the GUI). HTTPS port 443 must be reachable from this host. ISE-specific port 9060 (ERS API) is also used.",
    target_examples: [
      "ise01.lab.acme.com",
      "10.10.20.5",
    ],
    fields: [
      { k: "username", l: "ERS API username",
        help: "A dedicated ERS API user — separate from your GUI admin account." },
      { k: "password", l: "ERS API password", secret: true,
        help: "Set when you created the ERS user." },
    ],
    help: "Enable ERS in Admin → Settings → ERS Settings. Use a dedicated ERS user, not the GUI admin.",
  },
  clearpass: {
    label: "HPE Aruba ClearPass",
    target_label: "ClearPass host",
    target_placeholder: "cp.example.com",
    target_help: "Hostname or IP of your ClearPass Policy Manager publisher.",
    target_examples: [
      "cp01.lab.acme.com",
      "10.20.30.40",
    ],
    fields: [
      { k: "client_id",     l: "OAuth client ID",
        help: "Create in Admin → API Clients with Read scope (Read+Write for enforcement)." },
      { k: "client_secret", l: "OAuth client secret", secret: true },
    ],
    help: "Create an API client in Admin → API Clients with Read scope (Read+Write for enforcement).",
  },
  ad: {
    label: "Active Directory (LDAP)",
    target_label: "LDAP URL",
    target_placeholder: "ldaps://ad.example.com",
    target_help: "Full LDAP URL to your Domain Controller. Use ldaps:// (port 636) wherever possible — plain ldap:// sends the bind password in clear.",
    target_examples: [
      "ldaps://dc01.corp.acme.local",
      "ldap://10.0.0.10  (NOT recommended; cleartext bind)",
    ],
    fields: [
      { k: "bind_dn",       l: "Bind DN",
        help: "Distinguished Name of the read-only service account, e.g. CN=svc-safecadence,OU=Service,DC=corp,DC=local" },
      { k: "bind_password", l: "Bind password", secret: true },
      { k: "base_dn",       l: "Base DN",
        help: "Top of the directory subtree to read, e.g. DC=corp,DC=local" },
    ],
    help: "Read-only service account is enough for sync. Write-back (group membership) needs delegated group write.",
  },
};

function openConnectSlide() {
  const picker = Object.entries(CONNECT_SCHEMAS).map(([k, s]) => `
    <button class="alt" style="padding:10px;text-align:left"
            onclick='showConnectForm("${k}")'>
      <strong>${s.label}</strong>
      <div class="muted" style="font-size:11px;margin-top:2px">${s.help}</div>
    </button>`).join("");
  scOpenSlide("Connect a system", `
    <p class="muted">
      Pick a system. We make exactly one outbound call (the Test
      Connection probe). Credentials are stored encrypted at rest in
      the local vault — never sent off this host.
    </p>
    <div style="display:flex;flex-direction:column;gap:8px;margin-top:12px">
      ${picker}
    </div>
  `);
}

function showConnectForm(system) {
  const s = CONNECT_SCHEMAS[system];
  if (!s) return;
  // v9.34.2 — Chrome ignores autocomplete="off" routinely, so we use
  // the established defensive cocktail: (a) randomize each field's
  // `name` so Chrome can't pattern-match against its memory, (b) add a
  // hidden honeypot username+password pair that Chrome fills FIRST,
  // (c) start every real input as readonly and only remove it on
  // focus, (d) keep all the autocomplete/lpignore attributes.
  const salt = Math.random().toString(36).slice(2, 9);
  const examplesHTML = s.target_examples ? `
    <div class="muted" style="font-size:11px;margin-top:4px">
      Examples:
      ${s.target_examples.map(e => `<code style="margin-right:8px">${e}</code>`).join("")}
    </div>` : "";
  const targetHelpHTML = s.target_help ? `
    <div class="muted" style="font-size:12px;margin-top:4px">${s.target_help}</div>
  ` : "";

  const fieldHTML = s.fields.map(f => `
    <label style="margin-top:10px">${f.l}</label>
    <input id="cf-${f.k}" name="cf_${f.k}_${salt}"
           type="${f.secret ? 'password' : 'text'}"
           readonly onfocus="this.removeAttribute('readonly')"
           autocomplete="off" autocorrect="off" autocapitalize="off"
           spellcheck="false" data-lpignore="true" data-1p-ignore />
    ${f.help ? `<div class="muted" style="font-size:11px;margin-top:2px">${f.help}</div>` : ''}
  `).join("");

  scOpenSlide("Connect — " + s.label, `
    <p class="muted">${s.help}</p>

    <!-- v9.34.2: honeypot fields. Chrome fills the FIRST username +
         password pair it finds; we make sure those are these throwaway
         hidden ones, not the real target/credential below. -->
    <div style="position:absolute;left:-9999px;top:-9999px;height:0;overflow:hidden"
         aria-hidden="true">
      <input type="text"     name="username" autocomplete="username" tabindex="-1" />
      <input type="password" name="password" autocomplete="current-password" tabindex="-1" />
    </div>

    <label>${s.target_label}</label>
    <input id="cf-target" name="cf_target_${salt}"
           placeholder="${s.target_placeholder}"
           readonly onfocus="this.removeAttribute('readonly')"
           autocomplete="off" autocorrect="off" autocapitalize="off"
           spellcheck="false" data-lpignore="true" data-1p-ignore />
    ${targetHelpHTML}
    ${examplesHTML}

    ${fieldHTML}

    <div class="row" style="display:flex;gap:8px;margin-top:14px">
      <button class="alt" onclick='runConnect("${system}", "test_only")'>
        Test connection
      </button>
      <button class="primary" id="cf-save-btn" disabled
              style="opacity:0.5;cursor:not-allowed"
              onclick='runConnect("${system}", "save")'>
        Save &amp; sync
      </button>
    </div>
    <p class="muted" style="font-size:11px;margin-top:8px">
      Save is locked until Test Connection succeeds. Trust property: a
      credential blob never reaches the vault on a failing test.
    </p>
    <div id="cf-result" style="margin-top:12px"></div>
  `);
  // v9.34.2 — also clear any value Chrome managed to push into the
  // target field before our readonly attribute took effect (some
  // versions race here). Run after the slide-over DOM lands.
  setTimeout(() => {
    const t = document.getElementById("cf-target");
    if (t && t.value && t.value.length < 4) t.value = "";
    for (const f of s.fields) {
      const el = document.getElementById("cf-" + f.k);
      if (el) el.value = "";
    }
  }, 50);
}

// v9.34.2 — visual disabled state helpers. The disabled HTML attribute
// prevents click; this just makes the button LOOK disabled too.
function _setSaveBtnEnabled(enabled) {
  const btn = document.getElementById("cf-save-btn");
  if (!btn) return;
  btn.disabled = !enabled;
  btn.style.opacity = enabled ? "1" : "0.5";
  btn.style.cursor = enabled ? "pointer" : "not-allowed";
}

// v9.34.2 — validate target shape client-side. Catches the autofill-of-
// "admin" footgun before we even make a network call.
function _validateTarget(system, target) {
  if (!target) return "is required";
  if (system === "ad") {
    // ldap:// or ldaps://, or a bare host/IP that has at least a dot.
    if (target.startsWith("ldap://") || target.startsWith("ldaps://")) return null;
    if (!target.includes(".")) {
      return "should be ldap://host or ldaps://host with a fully-qualified hostname (got " + JSON.stringify(target) + ")";
    }
    return null;
  }
  // Okta/Entra/ISE/ClearPass — must look like a hostname. Reject single
  // words like "admin" that browser autofill happily produces.
  if (!target.includes(".") || target.length < 4) {
    return "should be a fully-qualified hostname (got " + JSON.stringify(target) + ")";
  }
  // Reject obvious garbage characters.
  if (/\s/.test(target)) {
    return "should not contain whitespace";
  }
  return null;
}

async function runConnect(system, mode) {
  const s = CONNECT_SCHEMAS[system];
  const target = (document.getElementById("cf-target").value || "").trim();
  const creds = {};
  for (const f of s.fields) {
    const v = (document.getElementById("cf-" + f.k).value || "").trim();
    if (v) creds[f.k] = v;
  }
  const out = document.getElementById("cf-result");

  // v9.34.2 — client-side validation BEFORE any network call.
  const targetErr = _validateTarget(system, target);
  if (targetErr) {
    out.innerHTML = `<div class="card" style="padding:12px;border-left:3px solid #d04646">
      <strong>${s.target_label} ${targetErr}.</strong>
      <div class="muted" style="margin-top:4px">
        Expected format: <code>${s.target_placeholder}</code>
      </div>
    </div>`;
    _setSaveBtnEnabled(false);
    return;
  }
  if (Object.keys(creds).length < s.fields.length) {
    out.innerHTML = `<p class="muted">Fill every credential field before testing.</p>`;
    _setSaveBtnEnabled(false);
    return;
  }
  out.innerHTML = `<p class="muted">Calling test_connection… (one outbound HTTP/LDAP call to ${target})</p>`;
  try {
    const r = await scApi("/api/identity/connect", {
      method: "POST",
      body: JSON.stringify({ system, target, credentials: creds, mode }),
    });
    if (!r.ok) {
      // v9.34.2 — server may include a translated `hint` for common
      // failure modes. Surface it prominently above the raw error.
      const hintHTML = r.hint ? `
        <div style="margin-top:6px"><strong>${r.hint}</strong></div>
      ` : '';
      out.innerHTML = `<div class="card" style="padding:12px;border-left:3px solid #d04646">
        <strong>Test failed.</strong>
        ${hintHTML}
        <details style="margin-top:6px"><summary class="muted" style="cursor:pointer;font-size:11px">raw error</summary>
          <pre style="font-size:11px;margin-top:4px">${r.error || 'unknown error'}</pre>
        </details>
        <div class="muted" style="margin-top:6px;font-size:11px">
          Nothing was saved. Fix the credentials and try again.
        </div>
      </div>`;
      _setSaveBtnEnabled(false);
      return;
    }
    // v9.52.1 — render the v9.51 groups_probe inline. Operators
    // see "Groups: 14 found" or "Groups: 403 — missing scope" so
    // they know whether the IdP-groups cache will populate before
    // they save.
    const probe = r.groups_probe || {};
    let probeHTML = "";
    if (probe.ok === true) {
      probeHTML = `<div class="muted" style="margin-top:4px;font-size:12px">
        <strong>Groups:</strong> ${probe.count} found
        — IdP-groups cache will populate. <a href="/idp-groups">View cache →</a>
      </div>`;
    } else if (probe.ok === false) {
      probeHTML = `<div class="muted" style="margin-top:4px;font-size:12px;
          color:#a35c00">
        <strong>Groups:</strong> ${probe.reason || "could not enumerate"}
        — auth + sync still works, but <code>@group:NAME</code> invitee
        expansion will resolve to nothing for this system.
      </div>`;
    }
    if (mode === "test_only") {
      out.innerHTML = `<div class="card" style="padding:12px;border-left:3px solid #2ea44f">
        <strong>✓ Connection ok.</strong>
        <div class="muted" style="margin-top:4px">
          Click <em>Save &amp; sync</em> to persist these credentials and trigger
          the initial sync.
        </div>
        ${probeHTML}
      </div>`;
      _setSaveBtnEnabled(true);
      return;
    }
    // mode === "save"
    out.innerHTML = `<div class="card" style="padding:12px;border-left:3px solid #2ea44f">
      <strong>✓ Saved.</strong>
      <div class="muted" style="margin-top:4px">
        Triggering initial sync…
      </div>
      ${probeHTML}
    </div>`;
    // v9.34 #3 — kick off the sync; UI surface ships in #3.
    try {
      await scApi("/api/identity/sync/" + encodeURIComponent(system),
                    { method: "POST" });
      out.innerHTML += `<div class="card" style="padding:12px;margin-top:8px">
        <strong>✓ Sync complete.</strong>
        <div class="muted" style="margin-top:4px">
          Refresh /identity to see the connector strip update.
        </div>
      </div>`;
    } catch (e) {
      out.innerHTML += `<div class="card" style="padding:12px;margin-top:8px;border-left:3px solid #f5a623">
        Saved successfully, but sync failed: ${e.message}.
        Re-run from the connector strip when you're ready.
      </div>`;
    }
  } catch (e) {
    out.innerHTML = `<div class="card" style="padding:12px;border-left:3px solid #d04646">
      <strong>Request failed.</strong>
      <div class="muted" style="margin-top:4px">${e.message}</div>
    </div>`;
  }
}

// v9.34 #5 — Manual NHI add. Posts to /api/identity/nhi.
function openManualNHISlide() {
  scOpenSlide("Add a non-human identity", `
    <p class="muted">
      Track an NHI even before adapters are connected. Owner + rotation
      cadence make stale finder + rotation-overdue checks meaningful.
    </p>
    <label>NHI name</label>
    <input id="nhi-name" placeholder="payroll-prod-svc" />
    <label style="margin-top:8px">Subtype</label>
    <select id="nhi-subtype">
      <option value="service_account">service_account</option>
      <option value="api_key">api_key</option>
      <option value="iam_role">iam_role</option>
      <option value="managed_identity">managed_identity</option>
      <option value="k8s_sa">k8s_sa</option>
      <option value="oauth_client">oauth_client</option>
      <option value="machine_cert">machine_cert</option>
    </select>
    <label style="margin-top:8px">Owner (email)</label>
    <input id="nhi-owner" placeholder="alice@acme.com" />
    <label style="margin-top:8px">Provider</label>
    <input id="nhi-provider" placeholder="aws / okta / github / …" />
    <label style="margin-top:8px">Rotation cadence (days, 0 = none)</label>
    <input id="nhi-rot" type="number" value="90" />
    <button class="primary" style="margin-top:12px;width:100%"
            onclick="saveNHI()">Add NHI</button>
    <div id="nhi-result" style="margin-top:8px"></div>
  `);
}

async function saveNHI() {
  const out = document.getElementById("nhi-result");
  const name = (document.getElementById("nhi-name").value || "").trim();
  if (!name) { out.innerHTML = `<p class="muted">Name is required.</p>`; return; }
  try {
    const body = {
      name,
      subtype:  document.getElementById("nhi-subtype").value,
      owner:    document.getElementById("nhi-owner").value,
      provider: document.getElementById("nhi-provider").value,
      rotation_policy_days: parseInt(
        document.getElementById("nhi-rot").value || "0", 10),
    };
    const r = await scApi("/api/identity/nhi", {
      method: "POST", body: JSON.stringify(body),
    });
    out.innerHTML = `<div class="card" style="padding:10px;border-left:3px solid #2ea44f">
      ✓ Created <code>${r.nhi_id}</code>. Refresh /identity to see it in
      the NHI list.
    </div>`;
    loadNHIList();
  } catch (e) {
    out.innerHTML = `<p class="muted">Failed: ${e.message}</p>`;
  }
}

async function loadNHIList() {
  const div = document.getElementById("nhi-list");
  if (!div) return;
  try {
    const r = await scApi("/api/identity/nhi");
    const ns = r.nhis || [];
    if (!ns.length) {
      div.innerHTML = `<p class="muted">
        No non-human identities tracked yet. Click <em>Add NHI</em> above
        or sync a connected system to populate this list.
      </p>`;
      return;
    }
    div.innerHTML = `
      <table style="width:100%;font-size:13px">
        <thead><tr>
          <th style="text-align:left">Name</th>
          <th style="text-align:left">Subtype</th>
          <th style="text-align:left">Owner</th>
          <th style="text-align:left">Last rotated</th>
          <th style="text-align:left">Attested</th>
          <th></th>
        </tr></thead>
        <tbody>
          ${ns.map(n => `<tr>
            <td>${n.name}${n.deprecated ? ' <span class="pill pill-info">deprecated</span>' : ''}</td>
            <td class="muted">${n.subtype}</td>
            <td class="muted">${n.owner || '—'}</td>
            <td class="muted">${n.last_rotated_at ? n.last_rotated_at.slice(0,10) : 'never'}</td>
            <td class="muted">${n.attested_at ? n.attested_at.slice(0,10) : '—'}</td>
            <td>
              <button class="alt" style="padding:2px 8px;font-size:11px"
                      onclick='nhiAction("${n.nhi_id}", "attest")'>Attest</button>
              <button class="alt" style="padding:2px 8px;font-size:11px"
                      onclick='nhiAction("${n.nhi_id}", "rotate")'>Rotated</button>
            </td>
          </tr>`).join("")}
        </tbody>
      </table>`;
  } catch (e) {
    div.innerHTML = `<p class="muted">Could not load NHIs: ${e.message}</p>`;
  }
}

async function nhiAction(nhi_id, kind) {
  try {
    await scApi(`/api/identity/nhi/${encodeURIComponent(nhi_id)}/${kind}`,
                  { method: "POST" });
    loadNHIList();
  } catch (e) { alert("Failed: " + e.message); }
}

// Translator — calls the existing /api/identity/translate.
async function translateIntent() {
  const intent = (document.getElementById("ident-intent").value || "").trim();
  const out = document.getElementById("ident-ir");
  if (!intent) { out.style.display = "none"; return; }
  out.style.display = "block";
  out.textContent = "Translating…";
  try {
    const r = await scApi("/api/identity/translate", {
      method: "POST",
      body: JSON.stringify({ intent }),
    });
    out.textContent = JSON.stringify(r, null, 2);
  } catch (e) { out.textContent = "Failed: " + e.message; }
}

async function previewIR() {
  const intent = (document.getElementById("ident-intent").value || "").trim();
  const out = document.getElementById("ident-ir");
  if (!intent) return;
  out.style.display = "block";
  out.textContent = "Previewing…";
  try {
    const r = await scApi("/api/identity/preview", {
      method: "POST",
      body: JSON.stringify({ intent }),
    });
    out.textContent = JSON.stringify(r, null, 2);
  } catch (e) { out.textContent = "Failed: " + e.message; }
}

// JIT — calls /api/identity/jit/grant. Apply happens elsewhere.
async function issueJIT() {
  const principal = (document.getElementById("jit-principal").value || "").trim();
  const action    = (document.getElementById("jit-action").value || "").trim();
  const resource  = (document.getElementById("jit-resource").value || "").trim();
  const duration  = parseInt(
    (document.getElementById("jit-duration").value || "14400").trim(), 10);
  if (!principal || !action || !resource) {
    alert("principal + action + resource are required"); return;
  }
  try {
    const r = await scApi("/api/identity/jit/grant", {
      method: "POST",
      body: JSON.stringify({ principal, action, resource,
                              duration_seconds: duration }),
    });
    alert("JIT grant " + (r.grant_id || "issued") +
          " — push to target via /findings auto-fix.");
  } catch (e) { alert("Failed: " + e.message); }
}

loadConnectorStatus();
loadNextActions();
loadNHIList();
"""


# ============================================================================
# v9.43 — /users admin page + /settings hub (email + notification prefs)
# ============================================================================

_USERS_BODY = """
<h1>Users</h1>
<p class="muted">Directory used for approval invitations + targeted
notifications. Admin-only writes; everyone can see the list. Add
<code>email</code> here so a user gets approval-invite DMs; add
<code>slack_user_id</code> / <code>teams_user_id</code> to be
@-mentioned in the channel webhook.</p>

<div class="card" style="padding:0">
  <table id="ux-tbl">
    <thead><tr>
      <th>Username</th><th>Display name</th><th>Email</th><th>Roles</th>
      <th>Channels</th><th></th>
    </tr></thead>
    <tbody><tr><td colspan="6" class="muted"
       style="padding:36px;text-align:center">Loading...</td></tr></tbody>
  </table>
</div>

<div style="margin-top:14px">
  <button onclick="uxOpenAdd()">+ Add user</button>
</div>

<div id="ux-edit" class="card" style="margin-top:14px;display:none"></div>

<p class="muted" style="font-size:12px;margin-top:14px">
  Trust note: editing contact info doesn't grant or revoke any role.
  The role gate in <code>workflow.approve()</code> is the authority
  boundary; this page is only about <em>where</em> notifications land.
</p>
"""

_USERS_SCRIPT = r"""
let UX_USERS = [];

async function uxLoad() {
  const tbody = document.querySelector('#ux-tbl tbody');
  try {
    const r = await fetch('/api/users', {credentials:'include'});
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const data = await r.json();
    UX_USERS = data.users || [];
  } catch (e) {
    tbody.innerHTML = '<tr><td colspan="6" class="bad">' +
      'Failed to load: ' + uxEsc(e.message) + '</td></tr>';
    return;
  }
  if (!UX_USERS.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="muted" ' +
      'style="padding:36px;text-align:center">No users yet.</td></tr>';
    return;
  }
  tbody.innerHTML = UX_USERS.map(u => {
    const channels = [];
    if (u.email) channels.push('email');
    if (u.notify && u.notify.slack_user_id) channels.push('slack');
    if (u.notify && u.notify.teams_user_id) channels.push('teams');
    if (u.notify && u.notify.pagerduty_user_id) channels.push('pagerduty');
    return `<tr>
      <td><strong>${uxEsc(u.username)}</strong></td>
      <td>${uxEsc(u.display_name || '')}</td>
      <td>${uxEsc(u.email || '')}</td>
      <td><code style="font-size:11px">${uxEsc((u.roles || []).join(','))}</code></td>
      <td>${channels.length ? channels.map(c =>
            `<span class="pill">${uxEsc(c)}</span>`).join(' ') :
            '<span class="muted">none</span>'}</td>
      <td>
        <button class="alt" style="padding:3px 8px;font-size:11px"
                onclick="uxOpenEdit('${uxEsc(u.username)}')">Edit</button>
        <button class="alt" style="padding:3px 8px;font-size:11px;margin-left:4px"
                onclick="uxOpenCaps('${uxEsc(u.username)}')">Caps</button>
        <button class="alt" style="padding:3px 8px;font-size:11px;margin-left:4px"
                onclick="uxDelete('${uxEsc(u.username)}')">Delete</button>
      </td>
    </tr>`;
  }).join('');
}

function uxEsc(s) {
  return String(s ?? '').replace(/[<>&"']/g, c =>
    ({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;',"'":'&#39;'}[c]));
}

function uxOpenAdd() { _uxRenderForm(null); }
function uxOpenEdit(name) {
  const u = UX_USERS.find(x => x.username === name) || {username:name};
  _uxRenderForm(u);
}

function _uxRenderForm(u) {
  const isNew = !u || !UX_USERS.find(x => x.username === u.username);
  const wrap = document.getElementById('ux-edit');
  const e = u || {username:'', display_name:'', email:'', roles:['viewer'],
                    notify:{}, external_id:''};
  wrap.style.display = '';
  wrap.innerHTML = `
    <h3 style="margin:0 0 10px">${isNew ? 'Add' : 'Edit'} user</h3>
    <div style="display:grid;grid-template-columns:140px 1fr;gap:8px;font-size:13px">
      <label>Username</label>
        <input id="uxf-username" value="${uxEsc(e.username)}"
               ${isNew ? '' : 'readonly'} />
      <label>Display name</label>
        <input id="uxf-display" value="${uxEsc(e.display_name || '')}" />
      <label>Email</label>
        <input id="uxf-email" type="email"
               value="${uxEsc(e.email || '')}" />
      <label>Roles (CSV)</label>
        <input id="uxf-roles" value="${uxEsc((e.roles || []).join(','))}"
               placeholder="admin,analyst,viewer" />
      <label>Slack user id</label>
        <input id="uxf-slack" value="${uxEsc((e.notify || {}).slack_user_id || '')}"
               placeholder="U03ABCDEF" />
      <label>Teams user id</label>
        <input id="uxf-teams" value="${uxEsc((e.notify || {}).teams_user_id || '')}"
               placeholder="8:orgid:guid" />
      <label>PagerDuty user id</label>
        <input id="uxf-pd" value="${uxEsc((e.notify || {}).pagerduty_user_id || '')}"
               placeholder="PD0123" />
      <label>External id</label>
        <input id="uxf-ext" value="${uxEsc(e.external_id || '')}"
               placeholder="okta:00u3xyz" />
    </div>
    <div style="margin-top:14px">
      <button onclick="uxSave()">Save</button>
      <button class="alt" onclick="document.getElementById('ux-edit').style.display='none'">Cancel</button>
    </div>`;
}

async function uxSave() {
  const body = {
    username: document.getElementById('uxf-username').value.trim(),
    display_name: document.getElementById('uxf-display').value.trim(),
    email: document.getElementById('uxf-email').value.trim(),
    roles: document.getElementById('uxf-roles').value.split(',')
            .map(s => s.trim()).filter(Boolean),
    notify: {
      slack_user_id: document.getElementById('uxf-slack').value.trim(),
      teams_user_id: document.getElementById('uxf-teams').value.trim(),
      pagerduty_user_id: document.getElementById('uxf-pd').value.trim(),
    },
    external_id: document.getElementById('uxf-ext').value.trim(),
  };
  // Strip blank notify entries
  Object.keys(body.notify).forEach(k => {
    if (!body.notify[k]) delete body.notify[k];
  });
  try {
    const r = await fetch('/api/users', {
      method:'POST', credentials:'include',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify(body),
    });
    if (!r.ok) {
      const t = await r.text();
      alert('Save failed: ' + t);
      return;
    }
    document.getElementById('ux-edit').style.display = 'none';
    uxLoad();
  } catch (e) {
    alert('Save failed: ' + e.message);
  }
}

async function uxDelete(name) {
  if (!confirm('Delete user ' + name + '?')) return;
  const r = await fetch('/api/users/' + encodeURIComponent(name),
                          {method:'DELETE', credentials:'include'});
  if (!r.ok) { alert('Delete failed: ' + (await r.text())); return; }
  uxLoad();
}

// v9.48 — capability slide-over.
async function uxOpenCaps(name) {
  const wrap = document.getElementById('ux-edit');
  wrap.style.display = '';
  wrap.innerHTML = '<p class="muted">Loading capabilities for ' +
    uxEsc(name) + '…</p>';
  let data;
  try {
    const r = await fetch('/api/capabilities/' +
                            encodeURIComponent(name),
                            {credentials:'include'});
    if (!r.ok) throw new Error('HTTP ' + r.status);
    data = await r.json();
  } catch (e) {
    wrap.innerHTML = '<p class="bad">Failed: ' + uxEsc(e.message) +
      '</p>';
    return;
  }
  // Build the matrix: each capability row shows a tri-state
  // (granted / role-floor / denied) with a button to grant or revoke.
  const grantSet = new Set(data.grant || []);
  const denySet = new Set(data.deny || []);
  const effSet = new Set(data.effective || []);
  const allCaps = (data.descriptions && Object.keys(data.descriptions))
    || [];
  const rows = allCaps.map(cap => {
    const desc = data.descriptions[cap] || '';
    let state, action, btnLabel;
    if (denySet.has(cap)) {
      state = '<span class="pill pill-bad">denied</span>';
      action = 'clearDeny';
      btnLabel = 'Clear deny';
    } else if (grantSet.has(cap)) {
      state = '<span class="pill pill-ok">granted</span>';
      action = 'revoke';
      btnLabel = 'Revoke';
    } else if (effSet.has(cap)) {
      state = '<span class="pill">via role</span>';
      action = 'revoke';
      btnLabel = 'Revoke';
    } else {
      state = '<span class="muted">—</span>';
      action = 'grant';
      btnLabel = 'Grant';
    }
    return `<tr>
      <td><code style="font-size:11px">${uxEsc(cap)}</code></td>
      <td class="muted" style="font-size:12px">${uxEsc(desc)}</td>
      <td>${state}</td>
      <td><button class="alt" style="padding:3px 8px;font-size:11px"
                  onclick="uxCapsAction('${uxEsc(name)}','${cap}','${action}')">
            ${btnLabel}</button></td>
    </tr>`;
  }).join('');
  const history = (data.history || []).slice().reverse().map(h =>
    `<tr><td><code style="font-size:11px">${uxEsc(h.ts)}</code></td>` +
    `<td>${uxEsc(h.actor)}</td>` +
    `<td><code style="font-size:11px">${uxEsc(h.action)}</code></td>` +
    `<td><code style="font-size:11px">${uxEsc(h.capability)}</code></td>` +
    `<td class="muted" style="font-size:12px">${uxEsc(h.reason || '')}</td></tr>`
  ).join('') || '<tr><td colspan="5" class="muted">No grants yet.</td></tr>';
  wrap.innerHTML = `
    <h3 style="margin:0 0 6px">Capabilities — ${uxEsc(name)}</h3>
    <p class="muted" style="font-size:12px">
      Roles: <code>${uxEsc((data.roles || []).join(',') || '—')}</code> ·
      ${effSet.size} effective capabilities.
      Per-user grants override the role floor; per-user denies override
      both.
    </p>
    <div class="card" style="padding:0">
      <table>
        <thead><tr><th>Capability</th><th>What it lets the user do</th>
          <th>State</th><th></th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
    <h4 style="margin:18px 0 6px">Recent history</h4>
    <div class="card" style="padding:0">
      <table>
        <thead><tr><th>When (UTC)</th><th>By</th><th>Action</th>
          <th>Capability</th><th>Reason</th></tr></thead>
        <tbody>${history}</tbody>
      </table>
    </div>
    <div style="margin-top:14px">
      <button class="alt" onclick="document.getElementById('ux-edit').style.display='none'">Close</button>
    </div>
    <p class="muted" style="font-size:11px;margin-top:10px">
      Trust note: every grant/revoke also lands in the v9.47 activity
      log (<a href="/audit">/audit</a>) so the full provenance chain is
      visible there.
    </p>`;
}

async function uxCapsAction(name, capability, action) {
  const reason = prompt('Reason (logged):') || '';
  const url = '/api/capabilities/' + encodeURIComponent(name) + '/' +
    (action === 'clearDeny' ? 'clear-deny' : action);
  const r = await fetch(url, {
    method:'POST', credentials:'include',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({capability: capability, reason: reason}),
  });
  if (!r.ok) { alert('Failed: ' + (await r.text())); return; }
  uxOpenCaps(name);
}

uxLoad();
"""

# --------------------------- /settings hub ---------------------------

_SETTINGS_BODY = """
<h1>Settings</h1>
<p class="muted">Customer SMTP for email DMs &middot; tenant default
notification routing &middot; per-user notification preferences (this
account).</p>

<!-- Tabs -->
<div style="display:flex;gap:6px;margin-top:14px;border-bottom:1px solid var(--sc-border)">
  <button class="alt" id="st-tab-email"      onclick="stShow('email')"
          style="padding:6px 14px;border-radius:6px 6px 0 0;width:auto">
    Email (SMTP)</button>
  <button class="alt" id="st-tab-defaults"   onclick="stShow('defaults')"
          style="padding:6px 14px;border-radius:6px 6px 0 0;width:auto">
    Tenant defaults</button>
  <button class="alt" id="st-tab-prefs"      onclick="stShow('prefs')"
          style="padding:6px 14px;border-radius:6px 6px 0 0;width:auto">
    My notifications</button>
  <button class="alt" id="st-tab-webhooks"   onclick="stShow('webhooks')"
          style="padding:6px 14px;border-radius:6px 6px 0 0;width:auto">
    Webhooks</button>
  <button class="alt" id="st-tab-sso"        onclick="stShow('sso')"
          style="padding:6px 14px;border-radius:6px 6px 0 0;width:auto">
    SSO (OIDC)</button>
</div>

<!-- Email tab -->
<div id="st-pane-email" class="card" style="margin-top:0;border-radius:0 6px 6px 6px">
  <h3 style="margin:0 0 10px">Email (customer SMTP)</h3>
  <p class="muted" style="font-size:12px">SafeCadence is an SMTP
  <em>client</em>: you point us at your own server (Exchange / Postfix
  / corporate relay / Gmail SMTP / SendGrid). Mail stays in your
  estate's logs. Empty config = email DMs disabled, channel webhooks
  still fire as a fallback.</p>
  <div style="display:grid;grid-template-columns:160px 1fr;gap:8px;font-size:13px;margin-top:10px">
    <label>Enabled</label>
      <input id="st-em-enabled" type="checkbox" />
    <label>SMTP host</label>
      <input id="st-em-host" placeholder="smtp.acme.local" />
    <label>SMTP port</label>
      <input id="st-em-port" type="number" value="587" />
    <label>STARTTLS</label>
      <input id="st-em-tls" type="checkbox" checked />
    <label>Implicit TLS (port 465)</label>
      <input id="st-em-ssl" type="checkbox" />
    <label>Username</label>
      <input id="st-em-user" placeholder="noreply@acme.com" />
    <label>Password</label>
      <input id="st-em-pw" type="password"
             placeholder="(leave blank to keep current)" />
    <label>From address</label>
      <input id="st-em-from" placeholder="SafeCadence <noreply@acme.com>" />
  </div>
  <p class="muted" style="font-size:11px;margin-top:8px">
    <span id="st-em-state">Loading current config…</span>
  </p>
  <div style="display:flex;gap:8px;margin-top:10px">
    <button onclick="stSaveEmail()">Save</button>
    <button class="alt" onclick="stTestEmail()">Send test email</button>
  </div>
  <div id="st-em-result" style="margin-top:8px"></div>
</div>

<!-- Tenant defaults -->
<div id="st-pane-defaults" class="card" style="margin-top:0;border-radius:0 6px 6px 6px;display:none">
  <h3 style="margin:0 0 10px">Tenant default notification routing</h3>
  <p class="muted" style="font-size:12px">Used when a user has no
  override for a category. Each user can change their own settings
  on the "My notifications" tab. Admin-only.</p>
  <div id="st-def-matrix"
       style="overflow-x:auto;margin-top:10px"></div>
  <div style="margin-top:14px">
    <button onclick="stSaveDefaults()">Save defaults</button>
  </div>
</div>

<!-- My prefs -->
<div id="st-pane-prefs" class="card" style="margin-top:0;border-radius:0 6px 6px 6px;display:none">
  <h3 style="margin:0 0 10px">My notification preferences</h3>
  <p class="muted" style="font-size:12px">
    Toggle on the channels you want to receive each event kind on.
    Channels you can't enable are grayed out — they require the
    matching contact field on your user record (admin sets via
    <a href="/users">/users</a>).
  </p>
  <div id="st-pf-matrix" style="overflow-x:auto;margin-top:10px"></div>
  <div style="margin-top:14px">
    <button onclick="stSavePrefs()">Save my preferences</button>
  </div>
  <p class="muted" style="font-size:11px;margin-top:10px">
    Trust note: the channel webhook (Slack / Teams / PagerDuty channel)
    fires regardless of these toggles — backups still see every event.
    These toggles control only the per-user direct delivery (email
    DM, channel @-mention).
  </p>
</div>

<!-- Webhooks tab (v9.44) -->
<div id="st-pane-webhooks" class="card" style="margin-top:0;border-radius:0 6px 6px 6px;display:none">
  <h3 style="margin:0 0 10px">Webhooks</h3>
  <p class="muted" style="font-size:12px">
    Send events to Slack / Teams / Discord / PagerDuty / Opsgenie /
    ServiceNow / Google Chat / Webex / Mattermost / Rocket.Chat / any
    JSON endpoint. Each webhook can filter by category (specific event
    kinds) AND minimum severity. URLs are Fernet-encrypted at rest;
    this page never displays the full URL once saved.
  </p>

  <div class="card" style="padding:0;margin-top:12px">
    <table id="wh-tbl">
      <thead><tr>
        <th>ID</th><th>Provider</th><th>URL preview</th>
        <th>Categories</th><th>Min severity</th><th>State</th><th></th>
      </tr></thead>
      <tbody><tr><td colspan="7" class="muted"
        style="padding:36px;text-align:center">Loading…</td></tr></tbody>
    </table>
  </div>

  <div style="margin-top:12px">
    <button onclick="whOpenAdd()">+ Add webhook</button>
  </div>

  <div id="wh-edit" class="card" style="margin-top:14px;display:none"></div>

  <p class="muted" style="font-size:11px;margin-top:14px">
    Each webhook fires independently — one dead Discord doesn't block
    the Slack one. Failures are recorded in the audit log with the
    provider name and reason.
  </p>
</div>

<!-- SSO tab (v9.55.1 — capability_map editor) -->
<div id="st-pane-sso" class="card" style="margin-top:0;border-radius:0 6px 6px 6px;display:none">
  <h3 style="margin:0 0 10px">OIDC SSO + capability auto-grant</h3>
  <p class="muted" style="font-size:12px">
    SafeCadence's OIDC SSO (v7.4) federates auth to your IdP
    (Okta, Entra, Auth0, Keycloak, Google). v9.54 added
    capability auto-grant: every successful login reconciles
    the user's IdP group claims against the
    <code>capability_map</code> below and grants/revokes
    capabilities to match. Manual grants made via /users#caps
    are never touched.
  </p>

  <div style="display:grid;grid-template-columns:160px 1fr;gap:8px;font-size:13px;margin-top:14px">
    <label>SSO enabled</label>
      <input id="st-sso-enabled" type="checkbox" disabled />
    <label>Flow</label>
      <input id="st-sso-flow" disabled />
    <label>Issuer</label>
      <input id="st-sso-issuer" disabled />
    <label>Client ID</label>
      <input id="st-sso-client-id" disabled />
    <label>Default role</label>
      <input id="st-sso-default-role" disabled />
  </div>
  <p class="muted" style="font-size:11px;margin-top:8px">
    Above fields are read-only here — edit them in
    <code>~/.safecadence/sso.json</code> (file is mode 0600,
    owned by the SafeCadence service user).
  </p>

  <h4 style="margin-top:24px">capability_map (group → capabilities)</h4>
  <p class="muted" style="font-size:12px">
    One row per IdP group claim value (the literal string the IdP
    emits in <code>groups</code>, <code>roles</code>, or
    <code>memberOf</code>). The right column is a comma-separated
    list of capability names from the
    <a href="/capabilities">capabilities matrix</a>. Save validates
    that every capability is real — typos won't silently grant
    nothing.
  </p>

  <div class="card" style="padding:0;margin-top:12px">
    <table id="st-sso-cm-tbl" style="width:100%;font-size:12px">
      <thead><tr>
        <th style="padding:8px 12px">IdP group claim</th>
        <th style="padding:8px 12px">Capabilities (comma-separated)</th>
        <th style="padding:8px 12px;width:60px"></th>
      </tr></thead>
      <tbody><tr><td colspan="3" class="muted"
        style="padding:36px;text-align:center">Loading…</td></tr></tbody>
    </table>
  </div>

  <div style="display:flex;gap:8px;margin-top:12px">
    <button onclick="ssoCmAddRow()">+ Add row</button>
    <button onclick="ssoCmSave()">Save capability_map</button>
  </div>
  <div id="st-sso-cm-result" style="margin-top:8px"></div>
</div>
"""

_SETTINGS_SCRIPT = r"""
let ST_CATEGORIES = [];
let ST_CHANNELS = [];
let ST_DEFAULTS = {};
let ST_MY = null;        // {available_channels, overrides, tenant_defaults}

function stEsc(s) {
  return String(s ?? '').replace(/[<>&"']/g, c =>
    ({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;',"'":'&#39;'}[c]));
}

function stShow(name) {
  for (const n of ['email', 'defaults', 'prefs', 'webhooks', 'sso']) {
    const pane = document.getElementById('st-pane-' + n);
    if (pane) pane.style.display = (n === name) ? '' : 'none';
  }
  if (name === 'email') stLoadEmail();
  else if (name === 'defaults') stLoadDefaults();
  else if (name === 'prefs') stLoadPrefs();
  else if (name === 'sso') ssoLoad();
  else if (name === 'webhooks') whLoad();
  if ((location.hash || '').slice(1) !== name && name !== 'email')
    history.replaceState(null, '', '#' + name);
}

// ---- Email tab ----

async function stLoadEmail() {
  document.getElementById('st-em-state').textContent = 'Loading…';
  try {
    const r = await fetch('/api/settings/email', {credentials:'include'});
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const c = await r.json();
    document.getElementById('st-em-enabled').checked = !!c.enabled;
    document.getElementById('st-em-host').value = c.host || '';
    document.getElementById('st-em-port').value = c.port || 587;
    document.getElementById('st-em-tls').checked = !!c.use_tls;
    document.getElementById('st-em-ssl').checked = !!c.use_ssl;
    document.getElementById('st-em-user').value = c.username || '';
    document.getElementById('st-em-from').value = c.from_addr || '';
    document.getElementById('st-em-pw').placeholder =
      c.has_password ? '(saved — leave blank to keep)' : '(none configured)';
    document.getElementById('st-em-state').textContent =
      c.enabled ? 'Email DMs enabled.' :
      'Email DMs disabled — channel webhook still fires as a fallback.';
  } catch (e) {
    document.getElementById('st-em-state').textContent =
      'Failed to load: ' + e.message;
  }
}

async function stSaveEmail() {
  const body = {
    enabled: document.getElementById('st-em-enabled').checked,
    host: document.getElementById('st-em-host').value.trim(),
    port: parseInt(document.getElementById('st-em-port').value || '587'),
    use_tls: document.getElementById('st-em-tls').checked,
    use_ssl: document.getElementById('st-em-ssl').checked,
    username: document.getElementById('st-em-user').value.trim(),
    password: document.getElementById('st-em-pw').value,
    from_addr: document.getElementById('st-em-from').value.trim(),
  };
  if (!body.password) delete body.password;
  const r = await fetch('/api/settings/email', {
    method:'POST', credentials:'include',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify(body),
  });
  const out = document.getElementById('st-em-result');
  if (!r.ok) { out.innerHTML =
    '<span class="bad">Save failed: ' + stEsc(await r.text()) + '</span>';
    return;
  }
  out.innerHTML = '<span class="ok">Saved.</span>';
  stLoadEmail();
}

async function stTestEmail() {
  const out = document.getElementById('st-em-result');
  out.textContent = 'Sending test email…';
  const r = await fetch('/api/settings/email/test', {
    method:'POST', credentials:'include',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({}),
  });
  if (!r.ok) {
    out.innerHTML = '<span class="bad">Test failed: ' +
      stEsc(await r.text()) + '</span>';
    return;
  }
  const j = await r.json();
  out.innerHTML = '<span class="ok">Test email sent to ' +
    stEsc(j.to) + '.</span>';
}

// ---- Tenant defaults ----

async function stEnsureCategories() {
  if (ST_CATEGORIES.length) return;
  const r = await fetch('/api/notify/categories',
                          {credentials:'include'});
  if (!r.ok) throw new Error('HTTP ' + r.status);
  const data = await r.json();
  ST_CATEGORIES = data.categories || [];
  ST_CHANNELS = data.channels || [];
}

async function stLoadDefaults() {
  await stEnsureCategories();
  const r = await fetch('/api/settings/notify-defaults',
                          {credentials:'include'});
  if (!r.ok) {
    document.getElementById('st-def-matrix').innerHTML =
      '<span class="bad">Failed: ' + stEsc(await r.text()) + '</span>';
    return;
  }
  ST_DEFAULTS = (await r.json()).defaults || {};
  document.getElementById('st-def-matrix').innerHTML =
    _stRenderMatrix(ST_DEFAULTS, /*editable=*/true,
                       /*available=*/null, 'def');
}

async function stSaveDefaults() {
  const updated = _stCollectMatrix('def');
  const r = await fetch('/api/settings/notify-defaults', {
    method:'POST', credentials:'include',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({defaults: updated}),
  });
  if (!r.ok) { alert('Save failed: ' + (await r.text())); return; }
  alert('Saved.');
}

// ---- My prefs ----

async function stLoadPrefs() {
  await stEnsureCategories();
  const r = await fetch('/api/users/me/notify-prefs',
                          {credentials:'include'});
  if (!r.ok) {
    document.getElementById('st-pf-matrix').innerHTML =
      '<span class="bad">Failed: ' + stEsc(await r.text()) + '</span>';
    return;
  }
  ST_MY = await r.json();
  // Effective view: my override OR fall back to tenant default
  const effective = {};
  for (const c of ST_CATEGORIES) {
    const k = c.key;
    effective[k] = (ST_MY.overrides || {})[k] !== undefined
                    ? ST_MY.overrides[k]
                    : (ST_MY.tenant_defaults || {})[k] || [];
  }
  document.getElementById('st-pf-matrix').innerHTML =
    _stRenderMatrix(effective, /*editable=*/true,
                       /*available=*/ST_MY.available_channels, 'pf');
}

async function stSavePrefs() {
  const updated = _stCollectMatrix('pf');
  const r = await fetch('/api/users/me/notify-prefs', {
    method:'POST', credentials:'include',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({notify_prefs: updated}),
  });
  if (!r.ok) { alert('Save failed: ' + (await r.text())); return; }
  alert('Saved.');
}

// ---- shared matrix helpers ----

function _stRenderMatrix(prefs, editable, available, prefix) {
  // available = null  -> all channels enabled (admin defaults view)
  // available = list  -> only those channels enabled (user view)
  let h = '<table style="border-collapse:collapse;font-size:13px;width:100%">';
  h += '<thead><tr><th style="text-align:left;padding:6px 8px">Event kind</th>';
  for (const ch of ST_CHANNELS) {
    h += '<th style="padding:6px 8px">' + stEsc(ch.label) + '</th>';
  }
  h += '</tr></thead><tbody>';
  for (const cat of ST_CATEGORIES) {
    h += '<tr><td style="padding:6px 8px;border-top:1px solid var(--sc-border)">';
    h += '<strong>' + stEsc(cat.label) + '</strong>';
    h += '<div class="muted" style="font-size:11px">' +
         stEsc(cat.description) + '</div>';
    h += '</td>';
    const enabled = new Set(prefs[cat.key] || []);
    for (const ch of ST_CHANNELS) {
      const id = prefix + '-' + cat.key + '-' + ch.key;
      const isAvail = (available === null) ||
                        (available || []).indexOf(ch.key) >= 0;
      const dis = (!editable || !isAvail) ? 'disabled' : '';
      const title = isAvail ? '' :
        ' title="No ' + stEsc(ch.user_field) +
        ' on your record — admin can add one on /users"';
      h += '<td style="padding:6px 8px;text-align:center;border-top:1px solid var(--sc-border)">';
      h += `<input type="checkbox" id="${id}"${dis}${title} ` +
           `data-cat="${stEsc(cat.key)}" data-ch="${stEsc(ch.key)}" ` +
           (enabled.has(ch.key) ? 'checked' : '') + '>';
      h += '</td>';
    }
    h += '</tr>';
  }
  h += '</tbody></table>';
  return h;
}

function _stCollectMatrix(prefix) {
  const out = {};
  for (const cat of ST_CATEGORIES) {
    const chans = [];
    for (const ch of ST_CHANNELS) {
      const id = prefix + '-' + cat.key + '-' + ch.key;
      const el = document.getElementById(id);
      if (el && el.checked && !el.disabled) {
        chans.push(ch.key);
      }
    }
    out[cat.key] = chans;
  }
  return out;
}

// ---- Webhooks tab (v9.44) ----

let WH_PROVIDERS = [];
let WH_LIST = [];

async function whLoad() {
  const tbody = document.querySelector('#wh-tbl tbody');
  try {
    const r = await fetch('/api/webhooks', {credentials:'include'});
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const data = await r.json();
    WH_LIST = data.webhooks || [];
    WH_PROVIDERS = data.providers || [];
  } catch (e) {
    tbody.innerHTML = '<tr><td colspan="7" class="bad">' +
      'Failed to load: ' + stEsc(e.message) + '</td></tr>';
    return;
  }
  await stEnsureCategories();
  if (!WH_LIST.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="muted" ' +
      'style="padding:36px;text-align:center">' +
      'No webhooks yet. Add one to start routing events to Slack / ' +
      'Discord / your ITSM / etc.</td></tr>';
    return;
  }
  tbody.innerHTML = WH_LIST.map(w => {
    const cats = (w.categories || []).map(c =>
      `<code style="font-size:11px">${stEsc(c)}</code>`).join(' ') ||
      '<span class="muted">any</span>';
    const sev = w.min_severity ?
      `<code>${stEsc(w.min_severity)}</code>` :
      '<span class="muted">any</span>';
    const state = w.enabled ?
      '<span class="pill pill-ok">on</span>' :
      '<span class="pill">off</span>';
    return `<tr>
      <td><strong>${stEsc(w.id)}</strong></td>
      <td>${stEsc(w.provider)}</td>
      <td><code style="font-size:11px">${stEsc(w.url_preview || '—')}</code></td>
      <td>${cats}</td>
      <td>${sev}</td>
      <td>${state}</td>
      <td>
        <button class="alt" style="padding:3px 8px;font-size:11px"
                onclick="whTest('${stEsc(w.id)}')">Test</button>
        <button class="alt" style="padding:3px 8px;font-size:11px;margin-left:4px"
                onclick="whEdit('${stEsc(w.id)}')">Edit</button>
        <button class="alt" style="padding:3px 8px;font-size:11px;margin-left:4px"
                onclick="whDelete('${stEsc(w.id)}')">Delete</button>
      </td>
    </tr>`;
  }).join('');
}

function whOpenAdd() { _whRenderForm(null); }
function whEdit(id) {
  const w = WH_LIST.find(x => x.id === id) || {id};
  _whRenderForm(w);
}

// v9.45 — which providers actually use the API token vs the
// signing secret. Anything else is hidden so the form doesn't
// look like a kitchen-sink with five fields you must ignore.
const WH_TOKEN_PROVIDERS = new Set([
  'pagerduty', 'opsgenie', 'webex', 'servicenow',
]);
const WH_SIG_PROVIDERS = new Set(['generic_hmac']);

function _whSyncFields() {
  const prov = document.getElementById('whf-provider').value;
  const showTok = !prov || WH_TOKEN_PROVIDERS.has(prov);
  const showSig = !prov || WH_SIG_PROVIDERS.has(prov);
  const tokRow = document.getElementById('whf-row-token');
  const sigRow = document.getElementById('whf-row-sig');
  if (tokRow) {
    tokRow.style.display = showTok ? '' : 'none';
    if (tokRow.previousElementSibling)
      tokRow.previousElementSibling.style.display = showTok ? '' : 'none';
  }
  if (sigRow) {
    sigRow.style.display = showSig ? '' : 'none';
    if (sigRow.previousElementSibling)
      sigRow.previousElementSibling.style.display = showSig ? '' : 'none';
  }
}

function _whRenderForm(w) {
  const isNew = !w || !WH_LIST.find(x => x.id === w.id);
  const wrap = document.getElementById('wh-edit');
  const e = w || {};
  const provOpts = WH_PROVIDERS.map(p =>
    `<option value="${stEsc(p)}"${e.provider===p?' selected':''}>${stEsc(p)}</option>`
  ).join('');
  const sevOpts = ['', 'info', 'low', 'medium', 'high', 'critical']
    .map(s => `<option value="${s}"${e.min_severity===s?' selected':''}>${s||'(any)'}</option>`)
    .join('');
  const catBoxes = ST_CATEGORIES.map(c => {
    const checked = (e.categories || []).includes(c.key) ? 'checked' : '';
    return `<label style="display:inline-block;margin:2px 8px 2px 0;font-size:12px">
      <input type="checkbox" data-cat-key="${stEsc(c.key)}" ${checked}>
      ${stEsc(c.label)}</label>`;
  }).join('');
  wrap.style.display = '';
  wrap.innerHTML = `
    <h3 style="margin:0 0 10px">${isNew ? 'Add' : 'Edit'} webhook</h3>
    <div style="display:grid;grid-template-columns:160px 1fr;gap:8px;font-size:13px">
      <label>ID</label>
        <input id="whf-id" value="${stEsc(e.id || '')}"
               ${isNew ? '' : 'readonly'}
               placeholder="security-team-slack" />
      <label>Provider</label>
        <select id="whf-provider" onchange="_whSyncFields()">
          <option value="">(auto-detect from URL)</option>
          ${provOpts}
        </select>
      <label>Webhook URL</label>
        <input id="whf-url" type="url"
               placeholder="${e.has_url ? '(saved — leave blank to keep)'
                                          : 'https://hooks.slack.com/services/…'}" />
      <label>API token</label>
        <input id="whf-row-token" type="password"
               placeholder="${e.has_token ? '(saved — leave blank to keep)'
                                            : 'Required for Opsgenie / Webex / ServiceNow / PagerDuty'}" />
      <label>HMAC signing secret</label>
        <input id="whf-row-sig" type="password"
               placeholder="${e.has_signing_secret ? '(saved — leave blank to keep)'
                                                     : 'Required only for generic_hmac'}" />
      <label>Min severity</label>
        <select id="whf-sev">${sevOpts}</select>
      <label style="vertical-align:top">Categories</label>
        <div id="whf-cats">${catBoxes}
          <p class="muted" style="font-size:11px;margin-top:6px">
            Filters are AND'd: this webhook fires only when BOTH
            categories AND min severity match. Leave both blank to
            fire for every event kind.
          </p>
        </div>
      <label>Enabled</label>
        <input id="whf-enabled" type="checkbox"
               ${e.enabled === false ? '' : 'checked'} />
      <label>Notes</label>
        <input id="whf-notes" value="${stEsc(e.notes || '')}"
               placeholder="Security team channel" />
    </div>
    <div style="margin-top:14px">
      <button onclick="whSave()">Save</button>
      <button class="alt" onclick="document.getElementById('wh-edit').style.display='none'">Cancel</button>
    </div>
    <p class="muted" style="font-size:11px;margin-top:8px">
      Trust note: URLs and tokens are Fernet-encrypted at rest. The
      table above shows only a redacted preview so an admin can
      recognise the row without exposing the secret. Use the Test
      button after saving to verify the wire end-to-end.
    </p>`;
  _whSyncFields();
}

async function whSave() {
  const cats = Array.from(document.querySelectorAll('#whf-cats input[type=checkbox]'))
    .filter(el => el.checked)
    .map(el => el.dataset.catKey);
  const body = {
    id: document.getElementById('whf-id').value.trim(),
    provider: document.getElementById('whf-provider').value,
    url: document.getElementById('whf-url').value.trim(),
    api_token: document.getElementById('whf-row-token').value,
    signing_secret: document.getElementById('whf-row-sig').value,
    min_severity: document.getElementById('whf-sev').value,
    categories: cats,
    enabled: document.getElementById('whf-enabled').checked,
    notes: document.getElementById('whf-notes').value.trim(),
  };
  if (!body.url) delete body.url;
  if (!body.api_token) delete body.api_token;
  if (!body.signing_secret) delete body.signing_secret;
  const r = await fetch('/api/webhooks', {
    method:'POST', credentials:'include',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify(body),
  });
  if (!r.ok) { alert('Save failed: ' + (await r.text())); return; }
  document.getElementById('wh-edit').style.display = 'none';
  whLoad();
}

async function whDelete(id) {
  if (!confirm('Delete webhook ' + id + '?')) return;
  const r = await fetch('/api/webhooks/' + encodeURIComponent(id),
                          {method:'DELETE', credentials:'include'});
  if (!r.ok) { alert('Delete failed: ' + (await r.text())); return; }
  whLoad();
}

async function whTest(id) {
  const r = await fetch('/api/webhooks/' + encodeURIComponent(id) + '/test',
                          {method:'POST', credentials:'include'});
  if (!r.ok) {
    alert('Test failed: ' + (await r.text()));
    return;
  }
  const j = await r.json();
  alert('Test event sent via ' + j.provider + '. Check the destination.');
}

// Default open via URL hash
const _initial = (location.hash || '#email').slice(1);
stShow(['email','defaults','prefs','webhooks','sso'].includes(_initial) ? _initial : 'email');

// ===== v9.55.1 — SSO capability_map editor =====================
async function ssoLoad() {
  const tbody = document.querySelector('#st-sso-cm-tbl tbody');
  const result = document.getElementById('st-sso-cm-result');
  result.innerHTML = '';
  let cfg;
  try {
    const r = await fetch('/api/settings/sso', {credentials:'include'});
    if (!r.ok) {
      tbody.innerHTML = '<tr><td colspan="3" class="bad" style="padding:24px;text-align:center">' +
        'Failed (HTTP ' + r.status + ')</td></tr>';
      return;
    }
    cfg = await r.json();
  } catch (e) {
    tbody.innerHTML = '<tr><td colspan="3" class="bad" style="padding:24px;text-align:center">' +
      'Failed: ' + stEsc(e.message) + '</td></tr>';
    return;
  }
  document.getElementById('st-sso-enabled').checked = !!cfg.enabled;
  document.getElementById('st-sso-flow').value = cfg.flow || '';
  document.getElementById('st-sso-issuer').value = cfg.oidc_issuer || '';
  document.getElementById('st-sso-client-id').value = cfg.oidc_client_id || '';
  document.getElementById('st-sso-default-role').value = cfg.default_role || '';
  const cm = cfg.capability_map || {};
  const rows = Object.keys(cm).sort().map(k => ssoCmRowHtml(k, cm[k]));
  tbody.innerHTML = rows.length ? rows.join('') :
    '<tr><td colspan="3" class="muted" style="padding:24px;text-align:center">' +
    'No mappings yet. Click "+ Add row" to start.</td></tr>';
}

function ssoCmRowHtml(group, caps) {
  const capsStr = Array.isArray(caps) ? caps.join(', ') : String(caps || '');
  return `<tr>
    <td style="padding:6px 12px"><input type="text" class="sso-cm-group" value="${stEsc(group)}" placeholder="okta-secops" /></td>
    <td style="padding:6px 12px"><input type="text" class="sso-cm-caps" value="${stEsc(capsStr)}" placeholder="read.audit, admin.capabilities" /></td>
    <td style="padding:6px 12px;text-align:center">
      <button class="alt" style="padding:4px 10px;width:auto;font-size:11px"
              onclick="ssoCmRemoveRow(this)">Remove</button>
    </td>
  </tr>`;
}

function ssoCmAddRow() {
  const tbody = document.querySelector('#st-sso-cm-tbl tbody');
  // Drop any "no mappings yet" placeholder.
  if (tbody.children.length === 1 && tbody.children[0].children.length === 1) {
    tbody.innerHTML = '';
  }
  tbody.insertAdjacentHTML('beforeend', ssoCmRowHtml('', ''));
}

function ssoCmRemoveRow(btn) {
  const tr = btn.closest('tr');
  if (tr) tr.remove();
}

async function ssoCmSave() {
  const result = document.getElementById('st-sso-cm-result');
  result.innerHTML = '<span class="muted">Saving…</span>';
  const tbody = document.querySelector('#st-sso-cm-tbl tbody');
  const map = {};
  for (const tr of tbody.children) {
    const groupEl = tr.querySelector('.sso-cm-group');
    const capsEl = tr.querySelector('.sso-cm-caps');
    if (!groupEl || !capsEl) continue;
    const g = (groupEl.value || '').trim();
    const caps = (capsEl.value || '').split(',')
      .map(s => s.trim()).filter(s => s);
    if (!g) continue;
    map[g] = caps;
  }
  try {
    const r = await fetch('/api/settings/sso/capability-map', {
      method: 'POST', credentials: 'include',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({capability_map: map}),
    });
    const body = await r.json().catch(() => ({}));
    if (!r.ok) {
      result.innerHTML = '<span class="bad">Save failed: ' +
        stEsc(body.detail || ('HTTP ' + r.status)) + '</span>';
      return;
    }
    const ct = Object.keys(map).length;
    result.innerHTML = '<span class="ok">Saved — ' + ct +
      ' group mapping(s). Active on next OIDC login.</span>';
  } catch (e) {
    result.innerHTML = '<span class="bad">Save failed: ' +
      stEsc(e.message) + '</span>';
  }
}
"""


# v9.47 — /audit page that surfaces the JSONL activity log
_AUDIT_BODY = """
<h1>Activity log</h1>
<p class="muted">Every authenticated mutation that lands on the
SafeCadence API. Reads (GET) are skipped by default to keep the
log readable; set <code>SC_ACTIVITY_LOG_READS=1</code> for
forensic mode. Files live under
<code>$SC_DATA_DIR/activity/YYYY-MM-DD.jsonl</code> — one per day,
chmod 600.</p>

<div class="card" style="display:flex;gap:12px;align-items:end;flex-wrap:wrap">
  <div>
    <label class="muted" style="font-size:11px">Window</label><br>
    <select id="auDays" onchange="auLoad()">
      <option value="1">last 24h</option>
      <option value="7" selected>last 7 days</option>
      <option value="30">last 30 days</option>
      <option value="90">last 90 days</option>
    </select>
  </div>
  <div>
    <label class="muted" style="font-size:11px">Actor contains</label><br>
    <input id="auActor" placeholder="alice or @example.com"
           autocomplete="off" onchange="auLoad()" style="width:160px" />
  </div>
  <div>
    <label class="muted" style="font-size:11px">Method</label><br>
    <select id="auMethod" onchange="auLoad()">
      <option value="">any</option>
      <option value="POST">POST</option>
      <option value="PUT">PUT</option>
      <option value="PATCH">PATCH</option>
      <option value="DELETE">DELETE</option>
    </select>
  </div>
  <div>
    <label class="muted" style="font-size:11px">Path contains</label><br>
    <input id="auPath" placeholder="/api/users" autocomplete="off"
           onchange="auLoad()" style="width:200px" />
  </div>
  <div>
    <label class="muted" style="font-size:11px">Quick filter</label><br>
    <button class="alt" id="au-chip-caps" style="padding:6px 10px;font-size:12px"
            onclick="auQuick('caps')">Capability changes only</button>
    <button class="alt" id="au-chip-mine" style="padding:6px 10px;font-size:12px;margin-left:4px"
            onclick="auQuick('mine')">My actions only</button>
    <button class="alt" id="au-chip-clear" style="padding:6px 10px;font-size:12px;margin-left:4px"
            onclick="auQuick('clear')">Clear</button>
  </div>
  <div>
    <button onclick="auLoad()">Refresh</button>
  </div>
  <div>
    <button class="alt" onclick="auDownloadCsv()"
            style="padding:6px 12px;font-size:12px">Download CSV</button>
  </div>
</div>

<div class="card" style="margin-top:14px;padding:0">
  <table id="au-tbl">
    <thead><tr>
      <th style="width:160px">When (UTC)</th>
      <th style="width:100px">Actor</th>
      <th style="width:60px">Method</th>
      <th>Path</th>
      <th>Detail</th>
      <th style="width:60px">Status</th>
      <th style="width:80px">Duration</th>
      <th style="width:120px">IP</th>
      <th style="width:120px">Request ID</th>
    </tr></thead>
    <tbody><tr><td colspan="9" class="muted"
       style="padding:36px;text-align:center">Loading...</td></tr></tbody>
  </table>
</div>

<p class="muted" style="font-size:12px;margin-top:8px" id="au-tz-note">
  <!-- populated by JS at auLoad time -->
</p>

<p class="muted" style="font-size:12px;margin-top:14px">
  Trust note: this view is read-only. The log itself is append-only
  on disk — there's no &quot;delete row&quot; button on purpose. Retention runs
  three ways (pick whichever fits):
  <code>logrotate</code> drop-in (see <code>docs/examples/safecadence-activity.logrotate</code>),
  systemd <code>.service</code> + <code>.timer</code> for containers
  (<code>docs/examples/safecadence-activity-prune.{service,timer}</code>),
  or the daemon hook controlled by <code>SC_ACTIVITY_RETENTION_DAYS</code>
  (default 90, set to 0 to disable). One-shot manual prune via
  <code>safecadence activity prune --retention N</code>.
  CSV exports of this view also write a row to the log so downloads
  show up in the next refresh.
</p>
"""

_AUDIT_SCRIPT = r"""
async function auLoad() {
  const tbody = document.querySelector('#au-tbl tbody');
  tbody.innerHTML = '<tr><td colspan="8" class="muted"' +
    ' style="padding:24px;text-align:center">Loading...</td></tr>';
  // v9.57.1 — surface the operator's browser timezone so they can
  // sanity-check the hover tooltips. UTC is what the JSONL stores;
  // the tooltip shows local. The footer reminds you which is which.
  try {
    const tz = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
    const note = document.getElementById('au-tz-note');
    if (note) {
      note.innerHTML = 'Timestamps are stored as UTC. Hover any row to ' +
        'see your local time (' + auEsc(tz) + ').';
    }
  } catch (e) { /* old browser, skip */ }
  const params = new URLSearchParams();
  params.set('days', document.getElementById('auDays').value);
  const actor = document.getElementById('auActor').value.trim();
  if (actor) params.set('actor', actor);
  const method = document.getElementById('auMethod').value;
  if (method) params.set('method', method);
  const path = document.getElementById('auPath').value.trim();
  if (path) params.set('path', path);
  let data;
  try {
    const r = await fetch('/api/activity?' + params.toString(),
                            {credentials:'include'});
    if (!r.ok) throw new Error('HTTP ' + r.status);
    data = await r.json();
  } catch (e) {
    tbody.innerHTML = '<tr><td colspan="8" class="bad">Failed: ' +
      auEsc(e.message) + '</td></tr>';
    return;
  }
  if (!data.rows || !data.rows.length) {
    tbody.innerHTML = '<tr><td colspan="9" class="muted"' +
      ' style="padding:36px;text-align:center">' +
      'No activity in this window. Try widening the time range or' +
      ' clearing the filters.</td></tr>';
    return;
  }
  tbody.innerHTML = data.rows.map(row => `<tr>
      <td><code style="font-size:11px">${auFormatTs(row.ts || '')}</code></td>
      <td><strong>${auEsc(row.actor || '')}</strong></td>
      <td><code style="font-size:11px">${auEsc(row.method || '')}</code></td>
      <td><code style="font-size:11px">${auEsc(row.path || '')}</code></td>
      <td>${auDetail(row)}</td>
      <td>${auStatus(row.status)}</td>
      <td>${row.duration_ms || 0} ms</td>
      <td><code style="font-size:11px">${auEsc(row.ip || '')}</code></td>
      <td><code style="font-size:11px">${auEsc(row.request_id || '')}</code></td>
    </tr>`).join('');
}

// v9.50 — surface the extra dict for capability changes etc.
// Capability rows include {action, capability, reason}; show them
// inline so the auditor doesn't have to dig into the JSONL file.
//
// v9.50.1 — filter out keys that already have their own column or
// are uninteresting noise (request_id is in its own column;
// duration_ms is in its own column; etc.).
const _AU_NOISE_KEYS = new Set([
  'request_id', 'duration_ms', 'ip', 'tenant', 'status',
]);

function auDetail(row) {
  const ex = row.extra || {};
  if (ex.action && ex.capability) {
    const reason = ex.reason
      ? ' <span class="muted" style="font-size:11px">— ' +
        auEsc(ex.reason) + '</span>'
      : '';
    return '<code style="font-size:11px">' + auEsc(ex.action) + '</code> ' +
           '<code style="font-size:11px">' + auEsc(ex.capability) +
           '</code>' + reason;
  }
  // Other event types: render the meaningful keys compactly.
  const keys = Object.keys(ex).filter(k => !_AU_NOISE_KEYS.has(k));
  if (!keys.length) return '<span class="muted">—</span>';
  return '<code style="font-size:11px">' +
         auEsc(keys.slice(0, 3).map(k => k + '=' + ex[k]).join(' ')) +
         '</code>';
}

function auQuick(kind) {
  const path = document.getElementById('auPath');
  const method = document.getElementById('auMethod');
  const actor = document.getElementById('auActor');
  if (kind === 'caps') {
    path.value = '/api/capabilities/';
    method.value = 'POST';
  } else if (kind === 'mine') {
    // v9.57.1 — populate the actor box with the caller's username so
    // "what did I do this week?" is one click. Pulled from the
    // /api/me endpoint (multi-user) or falls back to local-admin
    // (single-user / synthetic admin mode). The actor field is
    // substring-match (v9.57) so the populated value works for
    // alice@example.com just as well as alice.
    actor.value = ''; // optimistic clear so we don't double-filter
    fetch('/api/me', {credentials: 'include'}).then(r => {
      if (r.ok) return r.json();
      return null;
    }).then(me => {
      if (me && me.username) {
        actor.value = me.username;
      } else {
        // Single-user mode — synth admin caller is `local-admin`.
        actor.value = 'local-admin';
      }
      auLoad();
    }).catch(() => {
      actor.value = 'local-admin';
      auLoad();
    });
    return;
  } else {
    path.value = '';
    method.value = '';
    actor.value = '';
  }
  auLoad();
}

// v9.57.1 — render UTC timestamp with browser-local tooltip on hover
// so an auditor in PST can read "2026-05-07T14:23:11Z" as "9:23 AM
// her time" without doing tz math. Falls back to the raw UTC string
// if Intl is unavailable (browser too old).
function auFormatTs(ts) {
  if (!ts) return '';
  const escaped = auEsc(ts);
  try {
    const d = new Date(ts);
    if (isNaN(d.getTime())) return escaped;
    const local = d.toLocaleString(undefined, {
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
      timeZoneName: 'short',
    });
    return '<span title="' + auEsc(local) + '">' + escaped + '</span>';
  } catch (e) {
    return escaped;
  }
}

// v9.53 — Download the current filter view as CSV. Reuses the
// same /api/activity endpoint with format=csv so the file matches
// exactly what the page is showing.
function auDownloadCsv() {
  const params = new URLSearchParams();
  params.set('days', document.getElementById('auDays').value);
  const actor = document.getElementById('auActor').value.trim();
  if (actor) params.set('actor', actor);
  const method = document.getElementById('auMethod').value;
  if (method) params.set('method', method);
  const path = document.getElementById('auPath').value.trim();
  if (path) params.set('path', path);
  params.set('format', 'csv');
  window.location.href = '/api/activity?' + params.toString();
}

function auStatus(s) {
  s = parseInt(s || 0);
  if (s >= 500) return '<span class="pill pill-bad">' + s + '</span>';
  if (s >= 400) return '<span class="pill" style="background:#fef3c7">' + s + '</span>';
  if (s >= 200) return '<span class="pill pill-ok">' + s + '</span>';
  return '<span class="muted">' + s + '</span>';
}

function auEsc(s) {
  return String(s ?? '').replace(/[<>&"']/g, c =>
    ({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;',"'":'&#39;'}[c]));
}

auLoad();
"""


# v9.50.1 — /capabilities tenant-wide overview matrix
_CAPS_BODY = """
<h1>Capabilities <span class="muted" style="font-size:14px">— org grant matrix</span></h1>
<p class="muted">Tenant-wide view of who has what. Each row is a
user; each column is a capability. Cells:
<span class="pill pill-ok">G</span> explicit grant,
<span class="pill">R</span> via role floor,
<span class="pill pill-bad">D</span> explicit deny,
<span class="muted">—</span> not granted. Click a user's name to
edit their grants in the /users slide-over.</p>

<div class="card" style="display:flex;gap:12px;align-items:center">
  <span id="cm-stats" class="muted" style="font-size:12px">Loading…</span>
  <a href="/users" class="alt" style="margin-left:auto;padding:6px 12px;
      text-decoration:none;border-radius:6px;border:1px solid var(--sc-border);
      font-size:12px">Open /users to edit</a>
</div>

<div class="card" style="margin-top:14px;padding:0;overflow-x:auto">
  <table id="cm-tbl" style="font-size:11px">
    <thead><tr><th>User</th><th>Roles</th><th id="cm-headers"></th></tr></thead>
    <tbody><tr><td colspan="3" class="muted"
       style="padding:36px;text-align:center">Loading…</td></tr></tbody>
  </table>
</div>

<p class="muted" style="font-size:12px;margin-top:14px">
  Trust note: this view is read-only. All grant/revoke happens via
  /users#caps (audit-logged) or `safecadence capabilities grant`
  (also audit-logged). Hover any cell for the role + history detail.
</p>
"""

_CAPS_SCRIPT = r"""
async function cmLoad() {
  const tbody = document.querySelector('#cm-tbl tbody');
  const headers = document.getElementById('cm-headers');
  const stats = document.getElementById('cm-stats');
  let data, allCaps, roleFloor;
  try {
    const r = await fetch('/api/capabilities', {credentials:'include'});
    if (!r.ok) throw new Error('HTTP ' + r.status);
    data = await r.json();
    allCaps = data.all_capabilities || [];
    roleFloor = data.role_floor || {};
  } catch (e) {
    tbody.innerHTML = '<tr><td colspan="3" class="bad">Failed: ' +
      cmEsc(e.message) + '</td></tr>';
    return;
  }
  // Pull users for role context
  let users = [];
  try {
    const r = await fetch('/api/users', {credentials:'include'});
    if (r.ok) users = (await r.json()).users || [];
  } catch (e) { /* keep going */ }
  // Index users by username for quick lookup
  const userMap = {};
  for (const u of users) { userMap[u.username] = u; }
  const grantMap = {};
  for (const g of (data.grants || [])) { grantMap[g.username] = g; }
  // Header row of capability keys (rotated 30deg via short labels)
  const capCells = allCaps.map(c => {
    const desc = (data.descriptions || {})[c] || '';
    return `<th title="${cmEsc(desc)}" style="writing-mode:vertical-rl;
            transform:rotate(180deg);padding:8px 4px;font-weight:normal;
            font-size:10px"><code>${cmEsc(c)}</code></th>`;
  }).join('');
  // Replace the placeholder header cell with the real columns
  document.querySelector('#cm-tbl thead tr').innerHTML =
    '<th style="width:120px">User</th>' +
    '<th style="width:140px">Roles</th>' + capCells;
  // Rows: every user that exists, plus users that have grants but
  // aren't in the directory (pending, deleted, etc.)
  const allUsernames = Array.from(new Set([
    ...Object.keys(userMap),
    ...Object.keys(grantMap),
  ])).sort();
  if (!allUsernames.length) {
    tbody.innerHTML = '<tr><td colspan="' + (allCaps.length + 2) +
      '" class="muted" style="padding:36px;text-align:center">' +
      'No users yet. Add some via /users or `safecadence users add`.' +
      '</td></tr>';
    stats.textContent = '0 users · 0 grants';
    return;
  }
  let totalGrants = 0, totalDenies = 0;
  tbody.innerHTML = allUsernames.map(uname => {
    const u = userMap[uname] || {username: uname, roles: []};
    const rec = grantMap[uname] || {grant:[], deny:[]};
    const grantSet = new Set(rec.grant || []);
    const denySet = new Set(rec.deny || []);
    totalGrants += grantSet.size;
    totalDenies += denySet.size;
    // Compute the role-floor union for this user
    const floorSet = new Set();
    if ((u.roles || []).includes('admin')) {
      // Admin short-circuits to ALL
      for (const c of allCaps) floorSet.add(c);
    } else {
      for (const r of (u.roles || [])) {
        for (const c of (roleFloor[r] || [])) floorSet.add(c);
      }
    }
    const cells = allCaps.map(c => {
      let badge, title;
      if (denySet.has(c)) {
        badge = '<span class="pill pill-bad">D</span>';
        title = 'Explicit deny';
      } else if (grantSet.has(c)) {
        badge = '<span class="pill pill-ok">G</span>';
        title = 'Explicit grant';
      } else if (floorSet.has(c)) {
        badge = '<span class="pill">R</span>';
        title = 'Via role floor';
      } else {
        badge = '<span class="muted">—</span>';
        title = 'Not granted';
      }
      return `<td title="${cmEsc(c)}: ${title}"
                style="text-align:center;padding:4px">${badge}</td>`;
    }).join('');
    const rolesText = (u.roles || []).join(',') || '—';
    return `<tr>
      <td><a href="/users" style="color:var(--sc-fg)">
            <strong>${cmEsc(uname)}</strong></a></td>
      <td><code style="font-size:10px">${cmEsc(rolesText)}</code></td>
      ${cells}
    </tr>`;
  }).join('');
  stats.textContent = `${allUsernames.length} user(s) · ` +
    `${totalGrants} explicit grant(s) · ${totalDenies} deny rule(s)`;
}

function cmEsc(s) {
  return String(s ?? '').replace(/[<>&"']/g, c =>
    ({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;',"'":'&#39;'}[c]));
}

cmLoad();
"""


# v9.55.1 — /capabilities/all-tenants cross-tenant view
# Consumes /api/capabilities/all-tenants (built in v9.54). Read-only;
# the gate is enforced server-side (admin.capabilities on at least one
# tenant or single-user synthetic admin).
_CAPS_ALL_TENANTS_BODY = """
<h1>Cross-tenant capabilities <span class="muted" style="font-size:14px">— MSP view</span></h1>
<p class="muted">Every grant across every tenant in one place.
Useful for answering &quot;who has <code>admin.capabilities</code>
anywhere on this install?&quot; without N round trips. Read-only;
edit grants in <a href="/capabilities">/capabilities</a> for the
tenant matrix or <a href="/users">/users</a> for per-user.</p>

<div class="card" style="display:flex;gap:12px;align-items:center">
  <span id="cmt-stats" class="muted" style="font-size:12px">Loading…</span>
  <a href="/capabilities" class="alt" style="margin-left:auto;padding:6px 12px;
      text-decoration:none;border-radius:6px;border:1px solid var(--sc-border);
      font-size:12px">Single-tenant matrix</a>
</div>

<div id="cmt-tenants" style="margin-top:14px"></div>

<p class="muted" style="font-size:12px;margin-top:14px">
  Trust note: the gate is server-side — you need
  <code>admin.capabilities</code> on at least one tenant, or
  the synthetic admin role in single-user mode. Otherwise the API
  returns 403 and this page shows an error banner.
</p>
"""

_CAPS_ALL_TENANTS_SCRIPT = r"""
async function cmtLoad() {
  const stats = document.getElementById('cmt-stats');
  const wrap = document.getElementById('cmt-tenants');
  let data;
  try {
    const r = await fetch('/api/capabilities/all-tenants',
                            {credentials:'include'});
    if (!r.ok) {
      const t = await r.text();
      wrap.innerHTML = '<div class="card bad">' +
        'Failed (HTTP ' + r.status + '): ' + cmtEsc(t) + '</div>';
      stats.textContent = 'Access denied or store empty.';
      return;
    }
    data = await r.json();
  } catch (e) {
    wrap.innerHTML = '<div class="card bad">Failed: ' +
      cmtEsc(e.message) + '</div>';
    return;
  }
  const tenants = data.tenants || [];
  const byTenant = data.by_tenant || {};
  if (!tenants.length) {
    wrap.innerHTML = '<div class="card muted" style="text-align:center;padding:36px">' +
      'No grants in any tenant yet.</div>';
    stats.textContent = '0 tenant(s) · 0 grant(s).';
    return;
  }
  let totalRows = 0;
  let totalGrants = 0;
  let totalDenies = 0;
  const sections = tenants.map(t => {
    const rows = (byTenant[t] || []);
    totalRows += rows.length;
    rows.forEach(r => {
      totalGrants += (r.grant || []).length;
      totalDenies += (r.deny || []).length;
    });
    if (!rows.length) {
      return `<div class="card" style="margin-bottom:14px">
        <h3 style="margin-top:0">${cmtEsc(t)}</h3>
        <p class="muted" style="margin:0">No grants in this tenant.</p>
      </div>`;
    }
    const tbody = rows.map(r => {
      const grants = (r.grant || []).map(c =>
        `<span class="pill pill-ok" style="margin:1px">${cmtEsc(c)}</span>`
      ).join(' ') || '<span class="muted">—</span>';
      const denies = (r.deny || []).map(c =>
        `<span class="pill pill-bad" style="margin:1px">${cmtEsc(c)}</span>`
      ).join(' ') || '<span class="muted">—</span>';
      return `<tr>
        <td><strong>${cmtEsc(r.username)}</strong></td>
        <td>${grants}</td>
        <td>${denies}</td>
      </tr>`;
    }).join('');
    return `<div class="card" style="margin-bottom:14px;padding:0;overflow-x:auto">
      <h3 style="margin:14px 16px 6px 16px">${cmtEsc(t)}
        <span class="muted" style="font-size:12px;font-weight:400">
          (${rows.length} user(s))</span></h3>
      <table style="font-size:12px;width:100%">
        <thead><tr>
          <th style="padding:8px 16px">User</th>
          <th style="padding:8px 16px">Explicit grants</th>
          <th style="padding:8px 16px">Explicit denies</th>
        </tr></thead>
        <tbody>${tbody}</tbody>
      </table>
    </div>`;
  });
  wrap.innerHTML = sections.join('');
  stats.textContent = `${tenants.length} tenant(s) · ${totalRows} ` +
    `user record(s) · ${totalGrants} explicit grant(s) · ` +
    `${totalDenies} explicit deny rule(s).`;
}

function cmtEsc(s) {
  return String(s ?? '').replace(/[<>&"']/g, c =>
    ({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;',"'":'&#39;'}[c]));
}

cmtLoad();
"""


# v9.50 — IdP-sourced approver groups admin page (cache view + force refresh)
_IDP_GROUPS_BODY = """
<h1>IdP groups <span class="muted" style="font-size:14px">— approver cache</span></h1>
<p class="muted">Cached snapshot of group memberships pulled from
connected IdPs (Okta / Entra / AD / ISE / ClearPass). The notification
registry expands <code>@group:NAME</code> entries against this cache
when fanning out approval invites. Refreshed once per daemon cycle.
Groups not synced in the last 24 h are flagged <span class="pill"
style="background:#fef3c7">stale</span>.</p>

<div class="card" style="display:flex;gap:12px;align-items:center">
  <button onclick="igRefresh()">Force refresh now</button>
  <span id="ig-refresh-status" class="muted" style="font-size:12px"></span>
</div>

<div class="card" style="margin-top:14px;padding:0">
  <table id="ig-tbl">
    <thead><tr>
      <th>System</th><th>Name</th><th style="width:80px">Members</th>
      <th>Sample members</th>
      <th style="width:160px">Last synced</th>
      <th style="width:80px">Status</th>
    </tr></thead>
    <tbody><tr><td colspan="6" class="muted"
       style="padding:36px;text-align:center">Loading…</td></tr></tbody>
  </table>
</div>

<p class="muted" style="font-size:12px;margin-top:14px">
  Trust note: the cache is read-only at notification dispatch time —
  the daemon refresh and the manual button above are the only paths
  that update it. ISE and ClearPass groups appear here without
  members because their REST APIs don't expose membership in a
  single call (per-user iteration would be expensive); use AD or
  Okta for human approver groups.
</p>
"""

_IDP_GROUPS_SCRIPT = r"""
async function igLoad() {
  const tbody = document.querySelector('#ig-tbl tbody');
  tbody.innerHTML = '<tr><td colspan="6" class="muted"' +
    ' style="padding:24px;text-align:center">Loading…</td></tr>';
  let data;
  try {
    const r = await fetch('/api/idp-groups', {credentials:'include'});
    if (!r.ok) throw new Error('HTTP ' + r.status);
    data = await r.json();
  } catch (e) {
    tbody.innerHTML = '<tr><td colspan="6" class="bad">Failed: ' +
      igEsc(e.message) + '</td></tr>';
    return;
  }
  const rows = data.groups || [];
  if (!rows.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="muted"' +
      ' style="padding:36px;text-align:center">' +
      'No groups cached yet. Connect an identity system in /identity ' +
      'and click the refresh button above to populate the cache.' +
      '</td></tr>';
    return;
  }
  tbody.innerHTML = rows.map(g => {
    const sample = (g.members || []).slice(0, 3).join(', ');
    const more = (g.members || []).length > 3 ?
      ' <span class="muted">+' + ((g.members || []).length - 3) +
      ' more</span>' : '';
    const stale = g.stale ?
      '<span class="pill" style="background:#fef3c7">stale</span>' :
      '<span class="pill pill-ok">fresh</span>';
    return `<tr>
      <td><code style="font-size:11px">${igEsc(g.system)}</code></td>
      <td><strong>${igEsc(g.name)}</strong></td>
      <td>${(g.members || []).length}</td>
      <td class="muted" style="font-size:12px">${igEsc(sample)}${more}</td>
      <td><code style="font-size:11px">${igEsc(g.synced_at || '—')}</code></td>
      <td>${stale}</td>
    </tr>`;
  }).join('');
}

async function igRefresh() {
  const status = document.getElementById('ig-refresh-status');
  status.textContent = 'Refreshing… (depends on IdP latency)';
  let summary;
  try {
    const r = await fetch('/api/idp-groups/refresh', {
      method:'POST', credentials:'include',
    });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    summary = await r.json();
  } catch (e) {
    status.textContent = 'Refresh failed: ' + e.message;
    return;
  }
  const parts = [];
  for (const [sys, info] of Object.entries(summary || {})) {
    if (sys === 'error') continue;
    parts.push(`${sys}: ${info.ok ? info.count + ' groups' : 'error'}`);
  }
  status.textContent = parts.length ? parts.join(' · ') :
    'No connected systems exposed a list_groups() endpoint.';
  igLoad();
}

function igEsc(s) {
  return String(s ?? '').replace(/[<>&"']/g, c =>
    ({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;',"'":'&#39;'}[c]));
}

igLoad();
"""


def register(app):
    from fastapi.responses import HTMLResponse
    from fastapi import Depends

    # Real list pages
    @app.get("/inventory", response_class=HTMLResponse)
    def inv():
        return HTMLResponse(wrap("Inventory", _INVENTORY_BODY, _INVENTORY_SCRIPT))

    @app.get("/findings", response_class=HTMLResponse)
    def findings():
        return HTMLResponse(wrap("Findings", _FINDINGS_BODY, _FINDINGS_SCRIPT))

    # v9.33 #4–6 — action-first /identity (supersedes identity_ui.py)
    @app.get("/identity", response_class=HTMLResponse)
    def identity_v9():
        return HTMLResponse(wrap("Identity", _IDENTITY_BODY, _IDENTITY_SCRIPT))

    # v9.33 #9 — Who-can-reach-X query surface
    @app.get("/access", response_class=HTMLResponse)
    def access_query():
        return HTMLResponse(wrap("Who can reach", _ACCESS_BODY, _ACCESS_SCRIPT))

    @app.get("/jit", response_class=HTMLResponse)
    def jit():
        return HTMLResponse(wrap("JIT grants", _JIT_BODY, _JIT_SCRIPT))

    @app.get("/paths", response_class=HTMLResponse)
    def paths():
        return HTMLResponse(wrap("Attack paths", _PATHS_BODY, _PATHS_SCRIPT))

    @app.get("/watchlists", response_class=HTMLResponse)
    def watchlists():
        return HTMLResponse(wrap("Watchlists", _WATCHLISTS_BODY, _WATCHLISTS_SCRIPT))

    # /policies — real page (replaces stub)
    @app.get("/policies", response_class=HTMLResponse)
    def policies():
        return HTMLResponse(wrap("Policies", _POLICIES_BODY, _POLICIES_SCRIPT))

    # v9.8 — shadow-IT page (real, calls /api/platform/shadow-it)
    @app.get("/shadow-it", response_class=HTMLResponse)
    def shadow_it_page():
        return HTMLResponse(wrap("Shadow IT", _SHADOW_BODY, _SHADOW_SCRIPT))

    # v9.9 — real topology page with Cytoscape + layer toggles
    @app.get("/topology", response_class=HTMLResponse)
    def topology_page():
        return HTMLResponse(wrap("Topology", _TOPOLOGY_BODY, _TOPOLOGY_SCRIPT))

    # v9.11 — real Command Center (replaces broken /execute link)
    @app.get("/execute", response_class=HTMLResponse)
    def execute_page():
        return HTMLResponse(wrap("Command Center", _EXEC_BODY, _EXEC_SCRIPT))

    # v9.12 — asset groups management page
    @app.get("/groups", response_class=HTMLResponse)
    def groups_page():
        return HTMLResponse(wrap("Asset groups", _GROUPS_BODY, _GROUPS_SCRIPT))

    # v9.16 — blast-radius page wrapped in v9 chrome with empty-state explainer
    @app.get("/blast-radius", response_class=HTMLResponse)
    @app.get("/blast-radius/{asset_id}", response_class=HTMLResponse)
    def blast_radius_page(asset_id: str = ""):
        return HTMLResponse(wrap("Blast radius", _BLAST_BODY, _BLAST_SCRIPT))

    # v9.17 — discovery coverage health
    @app.get("/coverage", response_class=HTMLResponse)
    def coverage_page():
        return HTMLResponse(wrap("Coverage", _COVERAGE_BODY, _COVERAGE_SCRIPT))

    # v9.18 — fleet change report
    @app.get("/changes", response_class=HTMLResponse)
    def changes_page():
        return HTMLResponse(wrap("Fleet changes", _CHANGES_BODY, _CHANGES_SCRIPT))

    # v9.19 — discovery scheduling
    @app.get("/discovery-jobs", response_class=HTMLResponse)
    def discovery_jobs_page():
        return HTMLResponse(wrap("Discovery jobs", _JOBS_BODY, _JOBS_SCRIPT))

    # v9.22 — real per-device diff page (replaces stub)
    @app.get("/per-device-diff", response_class=HTMLResponse)
    def per_device_diff_page():
        return HTMLResponse(wrap("Per-device diff", _PDD_BODY, _PDD_SCRIPT))

    # v9.20 — tag management + scope visualizer
    @app.get("/tags", response_class=HTMLResponse)
    def tags_page():
        return HTMLResponse(wrap("Tags", _TAGS_BODY, _TAGS_SCRIPT))

    @app.get("/scope", response_class=HTMLResponse)
    def scope_page():
        return HTMLResponse(wrap("Compliance scope", _SCOPE_BODY, _SCOPE_SCRIPT))

    @app.get("/scores", response_class=HTMLResponse)
    def scores_page():
        return HTMLResponse(wrap("Safe Score leaderboard",
                                  _SCORES_BODY, _SCORES_SCRIPT))

    @app.get("/compliance", response_class=HTMLResponse)
    def compliance_page():
        return HTMLResponse(wrap("Compliance coverage",
                                  _COMPLIANCE_BODY, _COMPLIANCE_SCRIPT))

    @app.get("/risks", response_class=HTMLResponse)
    def risks_page():
        return HTMLResponse(wrap("Risk register",
                                  _RISKS_BODY, _RISKS_SCRIPT))

    @app.get("/vendors", response_class=HTMLResponse)
    def vendors_page():
        return HTMLResponse(wrap("Vendor risk",
                                  _VENDORS_BODY, _VENDORS_SCRIPT))

    @app.get("/policies/new", response_class=HTMLResponse)
    def policies_new_page():
        return HTMLResponse(wrap("Author policy (raw YAML)",
                                  _POLICY_NEW_BODY, _POLICY_NEW_SCRIPT))

    # v9.30 — /legacy was the v2.x fleet/scan workflow. Every page is
    # now a v9 surface, but old bookmarks + error-fallback strings still
    # reference it. Redirect to /home so nothing 404s.
    @app.get("/legacy")
    def legacy_redirect():
        from fastapi.responses import RedirectResponse
        return RedirectResponse("/home", status_code=302)

    # v9.23 — graduated 6 stubs to real v9-chromed pages backed by APIs.
    @app.get("/drift", response_class=HTMLResponse)
    def drift_page():
        return HTMLResponse(wrap("Cross-system drift",
                                  _DRIFT_BODY, _DRIFT_SCRIPT))

    @app.get("/evidence", response_class=HTMLResponse)
    def evidence_page():
        return HTMLResponse(wrap("Evidence packs",
                                  _EVIDENCE_BODY, _EVIDENCE_SCRIPT))

    @app.get("/builder", response_class=HTMLResponse)
    def builder_page():
        return HTMLResponse(wrap("Command builder",
                                  _BUILDER_BODY, _BUILDER_SCRIPT))

    @app.get("/approvals", response_class=HTMLResponse)
    def approvals_page():
        return HTMLResponse(wrap("Approvals queue",
                                  _APPROVALS_BODY, _APPROVALS_SCRIPT))

    @app.get("/queue", response_class=HTMLResponse)
    def queue_page():
        return HTMLResponse(wrap("Execution queue",
                                  _QUEUE_BODY, _QUEUE_SCRIPT))

    @app.get("/rollback", response_class=HTMLResponse)
    def rollback_page():
        return HTMLResponse(wrap("Rollback manager",
                                  _ROLLBACK_BODY, _ROLLBACK_SCRIPT))

    # v9.43 — admin UI for the user directory + per-user notify prefs
    @app.get("/users", response_class=HTMLResponse)
    def users_page():
        return HTMLResponse(wrap("Users", _USERS_BODY, _USERS_SCRIPT))

    # v9.43 — settings hub: SMTP, notification defaults, the Splunk panel
    @app.get("/settings", response_class=HTMLResponse)
    def settings_page():
        return HTMLResponse(wrap("Settings",
                                  _SETTINGS_BODY, _SETTINGS_SCRIPT))

    # v9.47 — activity log (who did what, when?). The middleware
    # writes one JSONL row per authenticated mutation; this page +
    # API surface them filterable by actor / method / path / day.
    @app.get("/audit", response_class=HTMLResponse)
    def audit_page():
        return HTMLResponse(wrap("Activity log",
                                  _AUDIT_BODY, _AUDIT_SCRIPT))

    # v9.50 — IdP-sourced approver groups admin page.
    # The /api/idp-groups endpoints live further down so they can use
    # the _require_caps helper that's defined in the activity log
    # block. The page route can stay here.
    @app.get("/idp-groups", response_class=HTMLResponse)
    def idp_groups_page():
        return HTMLResponse(wrap("IdP groups (approver cache)",
                                  _IDP_GROUPS_BODY, _IDP_GROUPS_SCRIPT))

    # v9.50.1 — tenant-wide capability matrix (read-only overview).
    @app.get("/capabilities", response_class=HTMLResponse)
    def capabilities_page():
        return HTMLResponse(wrap("Capabilities (org matrix)",
                                  _CAPS_BODY, _CAPS_SCRIPT))

    # v9.55.1 — cross-tenant view (consumes /api/capabilities/all-tenants
    # which v9.54 already shipped). Server-side gate handles auth; this
    # route just renders the page shell.
    @app.get("/capabilities/all-tenants", response_class=HTMLResponse)
    def capabilities_all_tenants_page():
        return HTMLResponse(wrap("Capabilities (cross-tenant)",
                                  _CAPS_ALL_TENANTS_BODY,
                                  _CAPS_ALL_TENANTS_SCRIPT))

    # v9.55.1 — /settings#sso tab support: GET returns a redacted
    # config view (no client_secret); POST capability-map persists
    # the new mapping after validating every capability name.
    @app.get("/api/settings/sso")
    def api_settings_sso(request: Request):
        # Self-only or admin.capabilities. Read-only view returns
        # truthy fields except secrets.
        from safecadence.ui._caller import caller_user
        from safecadence.capabilities import has_capability
        caller = caller_user(request)
        ok = "admin" in (caller.roles or []) or has_capability(
            username=caller.username, roles=caller.roles,
            capability="admin.capabilities", tenant=caller.tenant,
        )
        if not ok:
            raise _FastApiHTTPException(
                status_code=403,
                detail=("/settings#sso requires admin.capabilities "
                        "or the synthetic admin role."),
            )
        from safecadence.sso import load_config
        cfg = load_config()
        return {
            "enabled": cfg.enabled,
            "flow": cfg.flow,
            "oidc_issuer": cfg.oidc_issuer,
            "oidc_client_id": cfg.oidc_client_id,
            # Never echo the secret back to the browser.
            "oidc_redirect_uri": cfg.oidc_redirect_uri,
            "oidc_scopes": list(cfg.oidc_scopes or []),
            "default_role": cfg.default_role,
            "default_tenant": cfg.default_tenant,
            "tenant_claim": cfg.tenant_claim,
            "role_map": dict(cfg.role_map or {}),
            "capability_map": {k: list(v) for k, v
                                  in (cfg.capability_map or {}).items()},
        }

    @app.post("/api/settings/sso/capability-map")
    def api_settings_sso_capmap(request: Request,
                                  body: dict = _FastApiBody(...)):
        from safecadence.ui._caller import caller_user
        from safecadence.capabilities import (
            has_capability, ALL_CAPABILITIES,
        )
        caller = caller_user(request)
        ok = "admin" in (caller.roles or []) or has_capability(
            username=caller.username, roles=caller.roles,
            capability="admin.capabilities", tenant=caller.tenant,
        )
        if not ok:
            raise _FastApiHTTPException(
                status_code=403,
                detail=("Editing OIDC capability_map requires "
                        "admin.capabilities."),
            )
        new_map = body.get("capability_map") or {}
        if not isinstance(new_map, dict):
            raise _FastApiHTTPException(
                status_code=400,
                detail="capability_map must be an object.",
            )
        # Validate every capability name. Failure-loud per the v9.54
        # design: a typo in capability_map should never silently grant
        # nothing on the next login.
        invalid: list[str] = []
        cleaned: dict[str, list[str]] = {}
        for group, caps in new_map.items():
            if not isinstance(group, str) or not group.strip():
                continue
            if not isinstance(caps, list):
                raise _FastApiHTTPException(
                    status_code=400,
                    detail=(f"capability_map[{group!r}] must be a "
                            "list of capability names."),
                )
            for c in caps:
                if not isinstance(c, str):
                    invalid.append(repr(c))
                elif c not in ALL_CAPABILITIES:
                    invalid.append(c)
            cleaned[group.strip()] = [c for c in caps
                                         if c in ALL_CAPABILITIES]
        if invalid:
            raise _FastApiHTTPException(
                status_code=400,
                detail=(f"Unknown capabilities: {sorted(set(invalid))!r}. "
                        "See /capabilities for the full list."),
            )
        from safecadence.sso import load_config, save_config
        cfg = load_config()
        cfg.capability_map = cleaned
        save_config(cfg)
        return {"ok": True, "groups": len(cleaned),
                 "total_caps": sum(len(v) for v in cleaned.values())}

    # v9.49.1 — capability-gated read of the activity log.
    # Single-user installs short-circuit (synthetic admin); multi-user
    # JWT path actually checks the user has READ_ACTIVITY.
    from fastapi import Request as _FastApiRequest
    from fastapi import HTTPException as _FastApiHTTPException

    def _require_caps(cap: str):
        from safecadence.ui._caller import caller_user
        from safecadence.capabilities import has_capability

        def _dep(request: _FastApiRequest):
            user = caller_user(request)
            if not has_capability(username=user.username,
                                    roles=user.roles,
                                    capability=cap,
                                    tenant=user.tenant):
                raise _FastApiHTTPException(
                    status_code=403,
                    detail=(f"Missing capability: {cap}. "
                            "An admin can grant it via /users#caps."),
                )
            return user
        # Make sure FastAPI treats the parameter as Request, not query
        _dep.__annotations__ = {"request": _FastApiRequest, "return": object}
        return _dep

    # v9.57.2 — token-bucket rate limit on /api/activity. Same shape
    # as the v9.56 /ask limiter. Default 60 calls / 60s per
    # (username, client_ip). Overridable via SC_AUDIT_RATE_LIMIT and
    # SC_AUDIT_RATE_WINDOW_SEC. Pre-v9.57.2 a viewer-tier user with
    # read.activity could hammer this endpoint in a tight loop to
    # exfiltrate the whole log without tripping any alarm.
    _AUDIT_BUCKET: dict = {}        # (user, ip) -> [timestamps]

    @app.get("/api/activity")
    def api_activity(request: Request,
                       days: int = 7, actor: str = "",
                       method: str = "", path: str = "",
                       limit: int = 500, format: str = "json",
                       from_ts: str = "", to_ts: str = "",
                       extra_filter: str = "",
                       tenant: str = "",
                       _user=Depends(_require_caps("read.activity"))):
        # v9.57 — substring actor + date range + extra-dict filter.
        # Pre-v9.57 the only filters were exact-actor, method,
        # path-contains, and last-N-days. Compliance auditors and
        # operators kept hitting the wall.
        from safecadence.activity import read_range
        import os as _os
        import time as _time

        # --- v9.57.2 #2: token-bucket rate limit ----------------
        try:
            _r_window = int(_os.environ.get(
                "SC_AUDIT_RATE_WINDOW_SEC", "60") or "60")
            _r_limit = int(_os.environ.get(
                "SC_AUDIT_RATE_LIMIT", "60") or "60")
        except ValueError:
            _r_window, _r_limit = 60, 60
        _ip = (request.client.host if request and request.client
                  else "unknown")
        _user_name = getattr(_user, "username", "") or "anonymous"
        _key = (_user_name, _ip)
        _now = _time.time()
        _stamps = [t for t in _AUDIT_BUCKET.get(_key, [])
                     if _now - t < _r_window]
        if len(_stamps) >= _r_limit:
            _retry = int(_r_window - (_now - _stamps[0]))
            raise _FastApiHTTPException(
                status_code=429,
                detail=(f"rate limit ({_r_limit}/{_r_window}s) — "
                        f"retry in {max(1, _retry)}s"),
            )
        _stamps.append(_now)
        _AUDIT_BUCKET[_key] = _stamps

        # --- v9.57.2 #1: tenant scoping --------------------------
        # If the caller doesn't pass a `tenant` query arg, scope to
        # their own tenant. MSP-style operators with admin role
        # (`role=admin` short-circuits the cap check) can pass
        # tenant="*" to see across tenants — but only after they've
        # explicitly asked for it.
        caller_tenant = getattr(_user, "tenant", "default") or "default"
        is_admin = "admin" in (getattr(_user, "roles", []) or [])
        if tenant == "*" and is_admin:
            scoped_tenant = None    # cross-tenant read, admin-only
        elif tenant:
            # Operator asked for a specific tenant; allow only if
            # admin OR the operator's own tenant.
            if not is_admin and tenant != caller_tenant:
                raise _FastApiHTTPException(
                    status_code=403,
                    detail=("Cross-tenant audit read requires "
                            "role=admin or tenant matching caller."),
                )
            scoped_tenant = tenant
        else:
            scoped_tenant = caller_tenant
        try:
            d = max(1, min(int(days), 90))
        except (TypeError, ValueError):
            d = 7
        try:
            lim = max(1, min(int(limit), 5000))
        except (TypeError, ValueError):
            lim = 500
        # Parse extra_filter — repeated key=value separated by ';' or
        # ','. Skips malformed entries silently rather than 400ing
        # so a typo in one key doesn't lose the whole query.
        extra_dict: dict = {}
        for kv in (extra_filter.replace(";", ",").split(",")):
            kv = kv.strip()
            if not kv or "=" not in kv:
                continue
            k, _, v = kv.partition("=")
            k = k.strip()
            v = v.strip()
            if k:
                extra_dict[k] = v
        recs = read_range(
            days=d,
            # actor input is treated as substring — the historical
            # exact-match behaviour was surprising for emails and
            # SSO usernames.
            actor_contains=(actor or None),
            tenant=scoped_tenant,
            method=(method.upper() or None) if method else None,
            path_contains=(path or None),
            extra_filter=extra_dict or None,
            from_ts=(from_ts or None),
            to_ts=(to_ts or None),
            limit=lim,
        )
        # v9.53 — CSV export so auditors can take the log offline.
        # v9.57 — exporting the log is itself an audit-worthy event;
        # we write a row BEFORE responding so the export shows up in
        # the next /audit view (same log being exported).
        if (format or "").lower() == "csv":
            import csv
            import io
            from fastapi.responses import Response
            from datetime import datetime as _dt, timezone as _tz

            # Audit row for the export itself.
            try:
                from safecadence.activity import (
                    append as _append,
                    ActivityRecord as _AR,
                )
                actor_name = getattr(_user, "username", "") or "anonymous"
                tenant_name = getattr(_user, "tenant", "default") or "default"
                ip = (request.client.host if request and request.client
                        else "unknown")
                _append(_AR(
                    ts=_dt.now(_tz.utc).isoformat(
                        timespec="seconds").replace("+00:00", "Z"),
                    actor=actor_name,
                    tenant=tenant_name,
                    method="GET", path="/api/activity",
                    status=200, ip=ip, duration_ms=0,
                    request_id=getattr(request.state, "request_id", "") or
                                 f"export_{int(_dt.now(_tz.utc).timestamp() * 1000)}",
                    extra={
                        "export": "csv",
                        "row_count": len(recs),
                        "filter_days": d,
                        "filter_actor": actor or "",
                        "filter_path": path or "",
                        "filter_method": method or "",
                        "filter_from_ts": from_ts or "",
                        "filter_to_ts": to_ts or "",
                        "filter_extra": extra_filter or "",
                    },
                ))
            except Exception:                               # pragma: no cover
                # Audit best-effort — never block the export.
                pass

            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(["ts", "actor", "tenant", "method", "path",
                              "status", "ip", "duration_ms", "request_id",
                              "extra"])
            import json as _json
            for r in recs:
                writer.writerow([
                    r.ts, r.actor, r.tenant, r.method, r.path,
                    r.status, r.ip, r.duration_ms, r.request_id,
                    _json.dumps(r.extra, separators=(",", ":")) if r.extra else "",
                ])
            csv_bytes = buf.getvalue().encode("utf-8")
            stamp = _dt.now(_tz.utc).strftime("%Y%m%d-%H%M%S")

            # v9.57.2 #3 — embed filter context in the filename so
            # an auditor downloading three slices on the same day
            # ends up with three distinguishable files instead of
            # safecadence-activity-{stamp}.csv x3.
            #
            # Filename shape:
            #   safecadence-activity-{stamp}-{filter-segments}.csv
            # Each segment is sanitized to [a-zA-Z0-9_-] and capped
            # at ~32 chars so a path filter like /api/capabilities/
            # doesn't blow the filename length budget.
            import re as _re

            def _safe_seg(label: str, value: str, max_len: int = 32) -> str:
                if not value:
                    return ""
                # Slashes and special chars become underscores so
                # `/api/capabilities/` becomes `_api_capabilities_`.
                cleaned = _re.sub(r"[^a-zA-Z0-9._-]+", "_", value)
                cleaned = cleaned.strip("_")
                if not cleaned:
                    return ""
                cleaned = cleaned[:max_len]
                return f"{label}-{cleaned}"

            segs = []
            if scoped_tenant and scoped_tenant != "default":
                segs.append(_safe_seg("tenant", scoped_tenant, 24))
            if actor:
                segs.append(_safe_seg("actor", actor, 24))
            if path:
                segs.append(_safe_seg("path", path, 32))
            if method:
                segs.append(_safe_seg("method", method, 8))
            if from_ts or to_ts:
                # Use just the date portion (YYYY-MM-DD) so range
                # downloads stay readable.
                fmt_range = (
                    (from_ts or "")[:10] + ".." + (to_ts or "")[:10]
                ).strip(".")
                segs.append(_safe_seg("range", fmt_range, 24))
            else:
                segs.append(_safe_seg("days", str(d), 4))

            suffix = "-".join(s for s in segs if s)
            fname = (f"safecadence-activity-{stamp}"
                       + (f"-{suffix}" if suffix else "")
                       + ".csv")
            return Response(
                content=csv_bytes,
                media_type="text/csv",
                headers={"Content-Disposition":
                          f'attachment; filename="{fname}"'},
            )
        return {"days": d, "count": len(recs),
                 "rows": [r.__dict__ for r in recs]}

    # v9.48 — capability-based RBAC: list / grant / revoke.
    # Local UI uses single-user "admin" actor; the multi-user JWT
    # API in server/app.py applies the require_capability gate.
    @app.get("/api/capabilities")
    def api_caps_list(tenant: str = "default"):
        from safecadence.capabilities import (
            list_grants, ALL_CAPABILITIES,
        )
        from safecadence.capabilities.constants import (
            DESCRIPTIONS, ROLE_FLOOR,
        )
        return {
            "tenant": tenant,
            "all_capabilities": ALL_CAPABILITIES,
            "descriptions": DESCRIPTIONS,
            "role_floor": {k: sorted(v) for k, v in ROLE_FLOOR.items()},
            "grants": [
                {"username": r.username,
                  "grant": r.grant, "deny": r.deny,
                  "history": r.history[-25:]}
                for r in list_grants(tenant=tenant)
            ],
        }

    # v9.54 — cross-tenant capability admin view. MSP / multi-customer
    # deployments need one place to see every grant across every tenant
    # so the security team can answer "who has admin.capabilities
    # anywhere on this install?" without N round trips.
    #
    # Gate: caller must hold admin.capabilities on at least one tenant
    # OR be the synthetic admin (single-user mode). The response always
    # carries every tenant's full record — there is no per-tenant
    # filtering at this level because the whole point is global view.
    @app.get("/api/capabilities/all-tenants")
    def api_caps_all_tenants(request: Request):
        from safecadence.ui._caller import caller_user
        from safecadence.capabilities import (
            list_all_grants, list_tenants, has_capability,
            ALL_CAPABILITIES,
        )
        from safecadence.capabilities.constants import (
            DESCRIPTIONS, ROLE_FLOOR,
        )
        caller = caller_user(request)
        # Synthetic admin (single-user mode) sails through. For
        # multi-user deployments, ANY tenant where the caller holds
        # admin.capabilities counts — they're an MSP operator with
        # at least one customer.
        ok = "admin" in (caller.roles or [])
        if not ok:
            for t in list_tenants():
                if has_capability(username=caller.username,
                                    roles=caller.roles,
                                    capability="admin.capabilities",
                                    tenant=t):
                    ok = True
                    break
        if not ok:
            raise _FastApiHTTPException(
                status_code=403,
                detail=("Cross-tenant capability view requires "
                        "admin.capabilities on at least one tenant."),
            )
        rows = list_all_grants()
        # Group by tenant for an easy front-end render
        by_tenant: dict = {}
        for r in rows:
            by_tenant.setdefault(r.tenant, []).append({
                "username": r.username,
                "grant": r.grant,
                "deny": r.deny,
                "history": r.history[-10:],
            })
        return {
            "tenants": list_tenants(),
            "all_capabilities": ALL_CAPABILITIES,
            "descriptions": DESCRIPTIONS,
            "role_floor": {k: sorted(v) for k, v in ROLE_FLOOR.items()},
            "by_tenant": by_tenant,
            "row_count": len(rows),
        }

    def _caps_self_or_admin_check(request, target_username: str) -> None:
        """v9.53 helper for /api/capabilities/{username}. Self-read is
        free; viewing another user's grants requires READ_AUDIT or
        MANAGE_CAPABILITIES."""
        from safecadence.ui._caller import caller_user
        from safecadence.capabilities import has_capability
        caller = caller_user(request)
        if target_username == caller.username:
            return
        if has_capability(username=caller.username, roles=caller.roles,
                            capability="read.audit",
                            tenant=caller.tenant):
            return
        if has_capability(username=caller.username, roles=caller.roles,
                            capability="admin.capabilities",
                            tenant=caller.tenant):
            return
        raise _FastApiHTTPException(
            status_code=403,
            detail=("Viewing another user's capability grants "
                    "requires READ_AUDIT or MANAGE_CAPABILITIES."),
        )

    # Request type is imported at module scope (top of file) so PEP 563
    # string-deferred annotations resolve correctly for FastAPI.
    @app.get("/api/capabilities/{username}")
    def api_caps_user(username: str, request: Request,
                        tenant: str = "default"):
        _caps_self_or_admin_check(request, username)
        from safecadence.capabilities.store import (
            get_grant, user_capabilities,
        )
        from safecadence.capabilities.constants import (
            ROLE_FLOOR, DESCRIPTIONS,
        )
        # Resolve the user's roles from the directory so the response
        # includes the *effective* capability set, not just the
        # explicit grants/denies.
        from safecadence.users import directory as _dir
        rec = next(
            (u for u in _dir.list_users(tenant=tenant)
              if u.username == username), None,
        )
        roles = list(rec.roles) if rec else []
        eff = sorted(user_capabilities(username=username,
                                          roles=roles, tenant=tenant))
        cap_rec = get_grant(username, tenant=tenant)
        return {
            "username": username,
            "tenant": tenant,
            "roles": roles,
            "effective": eff,
            "grant": cap_rec.grant,
            "deny": cap_rec.deny,
            "history": cap_rec.history[-50:],
            "descriptions": DESCRIPTIONS,
            "role_floor": {k: sorted(v) for k, v in ROLE_FLOOR.items()},
        }

    @app.post("/api/capabilities/{username}/grant")
    def api_caps_grant(username: str, body: dict,
                         user=Depends(_require_caps("admin.capabilities"))):
        from safecadence.capabilities.store import grant, mark_http_in_flight
        capability = str(body.get("capability") or "").strip()
        # v9.49.1 — actor is now derived from the resolved caller, not
        # the request body. Lets us trust the audit trail attribution.
        actor = body.get("actor") or user.username
        reason = str(body.get("reason") or "").strip()
        tenant = str(body.get("tenant") or "default").strip() or "default"
        # v9.50.1 — skip the store-side synthetic activity emit; the
        # v9.47 middleware already logs this request with richer detail.
        mark_http_in_flight(True)
        try:
            rec = grant(username, capability,
                         tenant=tenant, actor=actor, reason=reason)
        except ValueError as exc:
            from fastapi import HTTPException
            raise HTTPException(status_code=400, detail=str(exc))
        return {"username": rec.username,
                 "grant": rec.grant, "deny": rec.deny}

    @app.post("/api/capabilities/{username}/revoke")
    def api_caps_revoke(username: str, body: dict,
                          user=Depends(_require_caps("admin.capabilities"))):
        from safecadence.capabilities.store import revoke, mark_http_in_flight
        capability = str(body.get("capability") or "").strip()
        actor = body.get("actor") or user.username
        reason = str(body.get("reason") or "").strip()
        tenant = str(body.get("tenant") or "default").strip() or "default"
        mark_http_in_flight(True)
        try:
            rec = revoke(username, capability,
                          tenant=tenant, actor=actor, reason=reason)
        except ValueError as exc:
            from fastapi import HTTPException
            raise HTTPException(status_code=400, detail=str(exc))
        return {"username": rec.username,
                 "grant": rec.grant, "deny": rec.deny}

    @app.post("/api/capabilities/{username}/clear-deny")
    def api_caps_clear_deny(username: str, body: dict,
                              user=Depends(_require_caps("admin.capabilities"))):
        from safecadence.capabilities.store import (
            clear_deny, mark_http_in_flight,
        )
        capability = str(body.get("capability") or "").strip()
        actor = body.get("actor") or user.username
        reason = str(body.get("reason") or "").strip()
        tenant = str(body.get("tenant") or "default").strip() or "default"
        mark_http_in_flight(True)
        try:
            rec = clear_deny(username, capability,
                              tenant=tenant, actor=actor, reason=reason)
        except ValueError as exc:
            from fastapi import HTTPException
            raise HTTPException(status_code=400, detail=str(exc))
        return {"username": rec.username,
                 "grant": rec.grant, "deny": rec.deny}

    # v9.50 — IdP-groups API endpoints (defined here so _require_caps
    # is in scope; the page route /idp-groups is declared earlier).
    @app.get("/api/idp-groups")
    def api_idp_groups_list(_user=Depends(_require_caps("read.identity"))):
        from safecadence.identity.groups import list_groups, stale_groups
        all_groups = list_groups()
        stale_set = {(g.system, g.id) for g in stale_groups()}
        return {
            "groups": [
                {"system": g.system, "id": g.id, "name": g.name,
                  "members": g.members,
                  "synced_at": g.synced_at,
                  "stale": (g.system, g.id) in stale_set}
                for g in all_groups
            ],
            "count": len(all_groups),
        }

    @app.post("/api/idp-groups/refresh")
    def api_idp_groups_refresh(_user=Depends(_require_caps("identity.vault"))):
        from safecadence.identity.groups import refresh_from_adapters
        return refresh_from_adapters()

    # Remaining stubs — kept for any future routes that appear in the
    # sidebar before they have a real page yet.
    _STUBS: list[tuple[str, str, str, list[tuple[str, str]]]] = []
    for path, title, blurb, related in _STUBS:
        def _make(t, b, r):
            def _h():
                return HTMLResponse(wrap(t, _stub_body(t, b, r), ""))
            return _h
        app.add_api_route(path, _make(title, blurb, related),
                            response_class=HTMLResponse)
