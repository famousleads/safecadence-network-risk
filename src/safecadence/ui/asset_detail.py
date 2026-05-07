"""
v8.0 — Per-asset detail page at /asset/{asset_id}.

Single URL = the whole story of one asset. Surfaces:

  identity       — hostname, vendor, env, criticality, owner
  security       — KEV CVE count, critical CVE count, findings by severity
  lifecycle      — EOL/EOS, warranty
  policies       — every policy that targets this asset + current pass/fail
  attack-paths   — every chain that terminates at this asset
  jit            — active + recent JIT grants on this asset
  comments       — team notes
  watchlist      — toggle to pin this asset

Pulls from existing endpoints; no new platform store fields needed.
"""

from __future__ import annotations

from safecadence.ui._chrome import wrap


_BODY = """
<h1 id="title">Asset</h1>
<p class="muted" id="subtitle">Loading…</p>

<!-- Identity strip -->
<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:8px;margin:12px 0">
  <div class="card"><div class="muted">Safe Score
    <span title="0-100, higher is safer. Composes findings, CVEs, attack paths, drift, missing controls.">ⓘ</span>
    </div><div id="kv-safe">—</div></div>
  <div class="card"><div class="muted">Vendor</div><div id="kv-vendor">—</div></div>
  <div class="card"><div class="muted">Model</div><div id="kv-model">—</div></div>
  <div class="card"><div class="muted">Type</div><div id="kv-type">—</div></div>
  <div class="card"><div class="muted">Env</div><div id="kv-env">—</div></div>
  <div class="card"><div class="muted">Criticality</div><div id="kv-crit">—</div></div>
  <div class="card"><div class="muted">Owner</div><div id="kv-owner">—</div></div>
  <div class="card"><div class="muted">Source</div><div id="kv-source">—</div></div>
</div>

<!-- v9.26 cockpit: Safe Score 2.0 breakdown (posture + best-practice + software currency) -->
<div class="card" id="ss2-card" style="margin:10px 0;padding:14px 16px;display:none">
  <div style="font-size:12px;text-transform:uppercase;letter-spacing:.5px;
              color:var(--muted);margin-bottom:8px">Safe Score breakdown</div>
  <div id="ss2-host" style="display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;font-size:13px"></div>
</div>

<!-- v9.15 cockpit: actions filtered by device + vendor type -->
<div class="card" id="actions-card" style="margin:10px 0;padding:14px 16px;
     background:linear-gradient(135deg,var(--panel),var(--panel-2))">
  <div style="font-size:12px;text-transform:uppercase;letter-spacing:.5px;
              color:var(--muted);margin-bottom:8px"
       id="actions-title">What I can do here</div>
  <div id="actions-host" class="muted" style="padding:14px">
    Loading…</div>
</div>

<!-- 13 category sections — only render when populated -->

<div id="sec-identity" class="sec card" style="display:none">
  <h2 style="margin-top:0">🔹 Device Identity</h2>
  <div class="kv-grid"></div>
</div>

<div id="sec-hardware" class="sec card" style="display:none">
  <h2 style="margin-top:0">🔹 Hardware Inventory</h2>
  <div class="kv-grid"></div>
  <div class="modules"></div>
</div>

<div id="sec-os" class="sec card" style="display:none">
  <h2 style="margin-top:0">🔹 Operating System</h2>
  <div class="kv-grid"></div>
</div>

<div id="sec-license" class="sec card" style="display:none">
  <h2 style="margin-top:0">🔹 Licensing</h2>
  <div class="kv-grid"></div>
</div>

<div id="sec-resources" class="sec card" style="display:none">
  <h2 style="margin-top:0">🔹 System Resources (CPU / Memory)</h2>
  <div class="kv-grid"></div>
</div>

<div id="sec-interfaces" class="sec card" style="display:none">
  <h2 style="margin-top:0">🔹 Interfaces</h2>
  <table class="iface-tbl">
    <thead><tr><th>Name</th><th>Status</th><th>IP</th><th>MAC</th>
                <th>Speed</th><th>Errors</th></tr></thead>
    <tbody></tbody>
  </table>
</div>

<div id="sec-routing" class="sec card" style="display:none">
  <h2 style="margin-top:0">🔹 Routing Table</h2>
  <div class="kv-grid"></div>
</div>

<div id="sec-l2" class="sec card" style="display:none">
  <h2 style="margin-top:0">🔹 ARP / MAC Tables</h2>
  <div class="kv-grid"></div>
</div>

<div id="sec-netsec" class="sec card" style="display:none">
  <h2 style="margin-top:0">🔹 Security & Access (control plane)</h2>
  <div class="kv-grid"></div>
</div>

<div id="sec-routprot" class="sec card" style="display:none">
  <h2 style="margin-top:0">🔹 Routing Protocols</h2>
  <div class="kv-grid"></div>
</div>

<div id="sec-logs" class="sec card" style="display:none">
  <h2 style="margin-top:0">🔹 Logs & Time</h2>
  <div class="kv-grid"></div>
</div>

<div id="sec-voice" class="sec card" style="display:none">
  <h2 style="margin-top:0">🔹 Voice / UC</h2>
  <div class="kv-grid"></div>
</div>

<div id="sec-health" class="sec card" style="display:none">
  <h2 style="margin-top:0">🔹 Device Health Scores</h2>
  <div class="kv-grid"></div>
</div>

<div id="sec-compliance" class="sec card" style="display:none">
  <h2 style="margin-top:0">🔹 Compliance / Risk Signals (AI)</h2>
  <div class="kv-grid"></div>
  <div id="comp-extras"></div>
</div>

<!-- Configuration -->
<h2 id="sec-config-h" style="display:none">📜 Running configuration</h2>
<div id="sec-config" class="card" style="display:none;padding:0">
  <div style="display:flex;justify-content:space-between;align-items:center;
              padding:10px 14px;border-bottom:1px solid var(--border)">
    <div class="muted" id="config-meta" style="font-size:12px"></div>
    <div style="display:flex;gap:6px">
      <button class="alt" style="width:auto;padding:4px 10px;font-size:12px"
              onclick="copyConfig()">Copy</button>
      <button class="alt" style="width:auto;padding:4px 10px;font-size:12px"
              onclick="downloadConfig()">Download</button>
    </div>
  </div>
  <pre id="config-pre" style="max-height:480px;margin:0;border-radius:0;
       border:0;font-family:ui-monospace,Menlo,monospace;font-size:12px;
       line-height:1.5;padding:14px"></pre>
</div>

<!-- Policies targeting this asset -->
<h2>📐 Policies that apply to this asset
  <span class="sc-help" data-help="policies-on-asset"></span>
</h2>
<div class="card" id="policies-card">
  <div class="muted">Loading…</div>
</div>

<!-- Custom fields editor -->
<h2>🏷 Custom fields</h2>
<div class="card">
  <div id="custom-fields"><div class="muted">No custom fields yet.</div></div>
  <div style="display:flex;gap:8px;margin-top:8px">
    <input id="cf-key" placeholder="key (e.g. business_owner)" style="flex:1" />
    <input id="cf-val" placeholder="value" style="flex:2" />
    <button class="primary" style="width:auto;padding:8px 16px"
            onclick="addCustomField()">Add</button>
  </div>
  <div class="muted" style="font-size:11px;margin-top:4px">
    Custom fields persist with the asset. Use them for business-specific
    context: business_owner, change_window, criticality_reason, etc.
  </div>
</div>

<h2>🚩 Findings about this asset</h2>
<div class="card"><table id="findings-tbl">
  <thead><tr><th>severity</th><th>kind</th><th>title</th></tr></thead>
  <tbody><tr><td colspan="3" class="muted">none</td></tr></tbody>
</table></div>

<h2>🎯 Attack paths terminating here</h2>
<div class="card"><table id="paths-tbl">
  <thead><tr><th>risk</th><th>chain</th></tr></thead>
  <tbody><tr><td colspan="2" class="muted">none</td></tr></tbody>
</table></div>

<h2>⏱️ JIT grants on this asset</h2>
<div class="card"><table id="jit-tbl">
  <thead><tr><th>principal</th><th>action</th><th>status</th><th>expires</th></tr></thead>
  <tbody><tr><td colspan="4" class="muted">none</td></tr></tbody>
</table></div>

<h2>💬 Comments</h2>
<div class="card">
  <div id="comments-list" class="muted">Loading…</div>
  <textarea id="new-comment" rows="2" placeholder="Add a comment…" style="margin-top:8px"></textarea>
  <button onclick="addComment()" style="margin-top:6px">Post</button>
</div>

<!-- v9.2: Vendor raw collection — every cached `show *` output -->
<h2 id="sec-vendor-raw">🔎 Vendor raw collection</h2>
<p class="muted" style="margin-top:-6px">
  Cached output of every command SafeCadence's collector ran against this
  device. Click a section to expand. Use this when you need to verify
  what the box actually said vs. what we parsed.
</p>
<div class="card" id="vendor-raw-card" style="padding:0">
  <div class="muted" style="padding:14px">Loading…</div>
</div>

<h2 id="raw-block">📜 Raw asset JSON</h2>
<details class="card">
  <summary class="muted">show / hide complete asset record</summary>
  <pre id="raw">—</pre>
</details>

<style>
.kv-grid { display:grid; gap:6px 18px;
           grid-template-columns:repeat(auto-fit,minmax(220px,1fr));
           font-size:13px; }
.kv-grid .kv { display:flex; gap:8px; padding:4px 0;
               border-bottom:1px solid var(--border); }
.kv-grid .kv .k { color:var(--muted); min-width:140px; }
.kv-grid .kv .v { color:var(--text); word-break:break-all; }
.kv-grid .kv .v code { background:var(--bg); padding:1px 4px;
                       border-radius:3px; font-size:11px; }
.iface-tbl { width:100%; }
.modules { margin-top:10px; }
.modules .module {
  background:var(--bg); padding:8px 10px; border-radius:6px;
  margin-bottom:4px; font-size:12px; font-family:ui-monospace,Menlo,monospace;
}
</style>
"""

_SCRIPT = r"""
const ASSET_ID = decodeURIComponent(location.pathname.split('/').pop() || "");
let WATCHED = false;
let WATCH_ID = null;
let CURRENT_ASSET = null;

function fmtBytes(b) {
  b = Number(b) || 0;
  if (!b) return "—";
  if (b > 1e9) return (b / 1e9).toFixed(1) + " GB";
  if (b > 1e6) return (b / 1e6).toFixed(1) + " MB";
  if (b > 1e3) return (b / 1e3).toFixed(1) + " KB";
  return b + " B";
}
function fmtUptime(s) {
  s = Number(s) || 0;
  if (!s) return "—";
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  return `${d}d ${h}h`;
}
function bool(v) { return v === true ? "✓ enabled" : v === false ? "✗ disabled" : "—"; }
function listOr(v) {
  if (!v || !Array.isArray(v) || !v.length) return "—";
  return v.join(", ");
}
function notEmpty(d) {
  if (!d || typeof d !== "object") return false;
  return Object.values(d).some(v => v !== "" && v !== 0 && v !== false &&
                                     v !== null && v !== undefined &&
                                     !(Array.isArray(v) && !v.length));
}

function renderKV(sectionId, pairs) {
  const sec = document.getElementById(sectionId);
  const grid = sec.querySelector(".kv-grid");
  const filtered = pairs.filter(p => p[1] !== undefined && p[1] !== null
                                       && p[1] !== "" && p[1] !== "—");
  if (!filtered.length) { sec.style.display = "none"; return; }
  sec.style.display = "block";
  grid.innerHTML = filtered.map(p =>
    `<div class="kv"><div class="k">${p[0]}</div><div class="v">${p[1]}</div></div>`
  ).join("");
}

async function load() {
  if (!ASSET_ID) return;
  document.getElementById("title").textContent = ASSET_ID;
  try {
    // v9.15.1 — was hitting /api/platform/{id} (404) which left
    // CURRENT_ASSET null and stuck the actions panel at "Loading…".
    const asset = await scApi(`/api/platform/asset/${encodeURIComponent(ASSET_ID)}`);
    CURRENT_ASSET = asset;
    if (!asset) {
      document.getElementById("subtitle").textContent =
        "Asset not found in store. (Was demo data loaded?)";
      renderActionsPanel(null);
      return;
    }
    renderAsset(asset);
    document.getElementById("raw").textContent = JSON.stringify(asset, null, 2);
  } catch (e) {
    document.getElementById("subtitle").textContent = e.message;
    renderActionsPanel(null);  // remove "Loading…" placeholder on error
    return;
  }

  loadFindings();
  loadPaths();
  loadJIT();
  loadComments();
  loadWatchState();
  loadConfig();
  loadPoliciesTargetingMe();
  loadVendorRaw();
  // v9.15 — render device-aware action panel after asset is loaded.
  renderActionsPanel(CURRENT_ASSET);
}

// =============================================================
//  v9.2 — Vendor raw collection (every cached `show *` output)
// =============================================================
function loadVendorRaw() {
  const card = document.getElementById("vendor-raw-card");
  const a = CURRENT_ASSET || {};
  const raw = a.raw_collection || {};
  const meta = a.collector || {};
  const keys = Object.keys(raw).filter(k => k && raw[k] != null);
  if (!keys.length) {
    card.innerHTML = `<div class="muted" style="padding:14px">
      No raw collector output cached for this device yet.
      ${(a.identity||{}).discovery_source === "manual"
        ? "Manually-added devices have no collector output until SafeCadence runs <code>safecadence collect</code> against them."
        : "Run <code>safecadence collect --asset " + (a.identity||{}).asset_id + "</code> to populate."}
    </div>`;
    return;
  }
  // Sort: running config first, version next, then alphabetical.
  const order = ["running", "config", "startup", "version", "inventory",
                 "interfaces", "ip_route", "ip_arp", "mac_address_table",
                 "vlan", "ip_protocols", "processes_cpu", "memory",
                 "logging", "license", "environment", "redundancy",
                 "ip_dhcp_binding", "spanning_tree", "lldp_neighbors",
                 "cdp_neighbors"];
  keys.sort((a, b) => {
    const ai = order.indexOf(a); const bi = order.indexOf(b);
    if (ai === -1 && bi === -1) return a.localeCompare(b);
    if (ai === -1) return 1;
    if (bi === -1) return -1;
    return ai - bi;
  });
  const lastCol = meta.last_collected_at || (a.identity||{}).last_collected_at || "—";
  card.innerHTML = `
    <div style="padding:10px 14px;border-bottom:1px solid var(--border);
                display:flex;justify-content:space-between;align-items:center">
      <div class="muted" style="font-size:12px">
        ${keys.length} sections · last collected ${lastCol}</div>
      <input id="vraw-filter" placeholder="filter sections…"
             style="width:200px;padding:4px 8px;border-radius:4px;
                    border:1px solid var(--border);background:var(--bg);
                    color:var(--text);font-size:12px"
             oninput="vrawFilter()" />
    </div>
    <div id="vraw-list">
      ${keys.map(k => {
        const v = raw[k];
        const txt = (typeof v === "string") ? v : JSON.stringify(v, null, 2);
        const lines = (txt || "").split("\n").length;
        return `
          <details data-section="${k}" style="border-bottom:1px solid var(--border)">
            <summary style="padding:10px 14px;cursor:pointer;
                            font-family:ui-monospace,Menlo,monospace;font-size:12px">
              <strong>show ${k.replace(/_/g, ' ')}</strong>
              <span class="muted" style="margin-left:10px">${lines} lines</span>
            </summary>
            <pre style="margin:0;padding:12px 16px;font-size:11.5px;
                        line-height:1.5;max-height:380px;overflow:auto;
                        font-family:ui-monospace,Menlo,monospace">${
              (txt || "").replace(/[<>&]/g, c =>
                ({"<":"&lt;",">":"&gt;","&":"&amp;"}[c]))
            }</pre>
          </details>`;
      }).join("")}
    </div>
  `;
}

function vrawFilter() {
  const q = (document.getElementById("vraw-filter").value || "").toLowerCase();
  document.querySelectorAll("#vraw-list details").forEach(d => {
    const k = (d.dataset.section || "").toLowerCase();
    const t = (d.querySelector("pre")?.textContent || "").toLowerCase();
    d.style.display = (!q || k.includes(q) || t.includes(q)) ? "block" : "none";
  });
}

// =============================================================
//  v9.15 — Device-aware action panel
// =============================================================
//
// Each descriptor: {label, hint, icon, onclick, applies(asset),
//                    section: "Operate"|"Investigate"|"Configure"|"Audit"}
// Render only the ones whose `applies()` returns true. Sections shown
// in fixed order; empty sections hidden.

const _SECTIONS = ["Operate", "Investigate", "Configure", "Audit"];

function _at(a)     { return ((a.identity || {}).asset_type || "").toLowerCase(); }
function _vendor(a) { return ((a.identity || {}).vendor || "").toLowerCase(); }
function _isNet(a)  { return _at(a) === "network"; }
function _isSrv(a)  { return _at(a) === "server"; }
function _isIdp(a)  { return _at(a) === "identity"; }
function _isCloud(a){ return _at(a) === "cloud"; }
function _hasRunningCfg(a) {
  const r = a.raw_collection || {};
  return !!(r.running || r.config || r.startup);
}
function _hasSnapshots(a) {
  return ((a.raw_collection || {}).snapshots || []).length > 0;
}

const _ACTIONS = [
  // ---------- OPERATE ----------
  { id:"run-cmd", section:"Operate", icon:"⚡",
    label:"Run command", hint:"Tier 1/2/3 with approval",
    applies: a => _isNet(a) || _isSrv(a),
    onclick: () => location.href = `/execute?asset_id=${aid()}` },

  { id:"snapshot", section:"Operate", icon:"📸",
    label:"Take config snapshot", hint:"Save running-config now",
    applies: a => _isNet(a) && _hasRunningCfg(a),
    onclick: () => actSnapshot() },

  { id:"compare", section:"Operate", icon:"🔁",
    label:"Compare to last snapshot", hint:"Per-device diff",
    applies: a => _isNet(a) && _hasSnapshots(a),
    onclick: () => actCompareSnapshot() },

  { id:"backup", section:"Operate", icon:"💾",
    label:"Backup config now", hint:"Push to git / archive",
    applies: a => _isNet(a) && _hasRunningCfg(a),
    onclick: () => actBackupConfig() },

  { id:"reboot", section:"Operate", icon:"🔄",
    label:"Schedule reboot",
    hint:"Tier 3 — TOTP MFA required",
    applies: a => _isNet(a) || _isSrv(a),
    onclick: () => location.href = `/execute?asset_id=${aid()}&intent=reload+device` },

  { id:"jit-network", section:"Operate", icon:"⏱",
    label:"Grant JIT access", hint:"Time-bounded SSH/RDP",
    applies: a => _isNet(a) || _isSrv(a),
    onclick: () => actGrantJIT() },

  { id:"jit-idp", section:"Operate", icon:"⏱",
    label:"Issue JIT grant",
    hint:"This IDP issues time-bounded role/group",
    applies: a => _isIdp(a),
    onclick: () => location.href = `/identity#jit-tbl?provider=${aid()}` },

  { id:"cloud-console", section:"Operate", icon:"🪟",
    label:"Open cloud console",
    hint:"Jump to the AWS / Azure / GCP web UI",
    applies: a => _isCloud(a),
    onclick: () => actOpenCloudConsole() },

  { id:"decommission", section:"Operate", icon:"🗑",
    label:"Mark decommissioned", hint:"Sets discovery_source=removed",
    applies: a => true,
    onclick: () => actDecommission() },

  // ---------- INVESTIGATE ----------
  { id:"watch", section:"Investigate", icon:"📌",
    label:"Add to watchlist", hint:"Alert on any change",
    applies: a => true,
    onclick: () => toggleWatch() },

  { id:"attack-path", section:"Investigate", icon:"🎯",
    label:"Attack-path graph", hint:"Blast radius from this asset",
    applies: a => true,
    onclick: () => actAttackPath() },

  { id:"effective-perm", section:"Investigate", icon:"🔓",
    label:"Effective permissions",
    hint:"Who can access what through this IDP",
    applies: a => _isIdp(a),
    onclick: () => location.href = `/identity?focus_idp=${aid()}` },

  { id:"topology", section:"Investigate", icon:"🗺",
    label:"Open in topology", hint:"Place this device on the map",
    applies: a => true,
    onclick: () => actTopology() },

  { id:"timeline", section:"Investigate", icon:"⏰",
    label:"Timeline (90d)", hint:"Every change here",
    applies: a => true,
    onclick: () => actTimeline() },

  { id:"compare-peer", section:"Investigate", icon:"⇆",
    label:"Compare to peer", hint:"Pick another switch, diff configs",
    applies: a => _isNet(a),
    onclick: () => actComparePeer() },

  { id:"vendor-raw", section:"Investigate", icon:"🔎",
    label:"Vendor raw collection",
    hint:"Every cached `show` output",
    applies: a => Object.keys(a.raw_collection || {}).length > 0,
    onclick: () => document.getElementById("sec-vendor-raw")
                            .scrollIntoView({behavior:"smooth"}) },

  // v9.16.1 — MITRE was pointing at a non-existent /api/intel/mitre.
  // The legacy console at /legacy has the existing report; until we ship
  // a v9 MITRE page, route there instead of a 404.
  { id:"mitre", section:"Investigate", icon:"🛡",
    label:"MITRE ATT&CK mapping", hint:"Open in legacy console",
    applies: a => _isNet(a) || _isSrv(a),
    onclick: () => location.href = `/legacy#mitre` },

  // ---------- CONFIGURE ----------
  { id:"apply-policy", section:"Configure", icon:"📐",
    label:"Apply policy",
    hint:"Author intent → per-vendor preview",
    applies: a => true,
    onclick: () => actApplyPolicy() },

  { id:"add-exception", section:"Configure", icon:"🛡",
    label:"Add policy exception",
    hint:"Document reason + expiry + comp control",
    applies: a => true,
    onclick: () => actAddException() },

  { id:"fix-playbook", section:"Configure", icon:"🩹",
    label:"AI fix playbook",
    hint:"Top risks here → prioritized fixes",
    applies: a => true,
    onclick: () => actFixPlaybook() },

  { id:"runbook", section:"Configure", icon:"📖",
    label:"AI operational notes",
    hint:"Read-only AI suggestions — verify against vendor docs",
    applies: a => _isNet(a) || _isSrv(a),
    onclick: () => actGenRunbook() },

  { id:"enrich", section:"Configure", icon:"🤖",
    label:"Re-run AI enrichment",
    hint:"Refresh role/criticality/tags",
    applies: a => true,
    onclick: () => actEnrich() },

  // ---------- AUDIT ----------
  { id:"evidence", section:"Audit", icon:"📑",
    label:"Evidence pack",
    hint:"SOC 2 / PCI / NIST PDF for this asset",
    applies: a => true,
    onclick: () => actEvidencePack() },

  { id:"findings", section:"Audit", icon:"🚩",
    label:"Open findings",
    hint:"All open findings on this asset",
    applies: a => true,
    onclick: () => document.getElementById("findings-tbl")
                            ?.scrollIntoView({behavior:"smooth"}) },

  // v9.16.1 — was pointing at the JSON API endpoint, which dumped raw
  // JSON in the browser. Point at the v9 timeline page that exists.
  { id:"audit-log", section:"Audit", icon:"📜",
    label:"Audit log",
    hint:"Every action taken on this asset",
    applies: a => true,
    onclick: () => location.href = `/timeline?asset_id=${aid()}` },
];

// Render only the applicable actions, grouped by section.
function renderActionsPanel(asset) {
  const host = document.getElementById("actions-host");
  const titleEl = document.getElementById("actions-title");
  if (!asset) {
    host.textContent = "Asset not loaded.";
    return;
  }
  const ident = asset.identity || {};
  const subtitle = `for ${ident.asset_type || '?'} · vendor ${ident.vendor || '?'}` +
                   (ident.criticality ? ` · ${ident.criticality}` : "");
  titleEl.innerHTML = `What I can do here ` +
    `<span class="muted" style="font-size:11px;text-transform:none;
            letter-spacing:0;font-weight:400;margin-left:8px">${subtitle}</span>`;

  const applicable = _ACTIONS.filter(a => {
    try { return !!a.applies(asset); }
    catch (e) { return false; }
  });
  if (!applicable.length) {
    host.innerHTML =
      `<p class="muted">No actions surfaced for this asset type.</p>`;
    return;
  }
  // Group by section
  const groups = {};
  for (const s of _SECTIONS) groups[s] = [];
  for (const a of applicable) (groups[a.section] || groups.Operate).push(a);

  let html = "";
  for (const s of _SECTIONS) {
    const items = groups[s];
    if (!items.length) continue;
    html += `<div style="margin-top:8px;font-size:11px;text-transform:uppercase;
                letter-spacing:.5px;color:var(--muted);font-weight:600">${s}</div>
       <div style="display:grid;gap:6px;margin-top:4px;
            grid-template-columns:repeat(auto-fit,minmax(190px,1fr))">`;
    for (const a of items) {
      html += `<button class="alt" id="actbtn-${a.id}"
                style="text-align:left;padding:8px 10px"
                onclick='(${a.onclick})()'>
        <b>${a.icon} ${a.label}</b><br/>
        <span class="muted" style="font-size:11px">${a.hint}</span>
      </button>`;
    }
    html += `</div>`;
  }
  host.innerHTML = html;
}

function aid() { return encodeURIComponent(ASSET_ID); }

function actRunCommand() {
  // v9.11 — /execute is now a real page, navigate directly.
  location.href = `/execute?asset_id=${aid()}`;
}

function actApplyPolicy() {
  // Send to the identity translator, which does plain-English → IR → preview.
  // For non-identity assets the same flow still works — translator picks the
  // right per-vendor implementation based on asset_type/vendor.
  scOpenSlide("Apply policy on " + ASSET_ID, `
    <p class="muted">Author policy intent. The translator turns it into a
       per-vendor preview before anything is applied.</p>
    <a class="primary" href="/identity?focus_asset=${aid()}"
       style="display:inline-block;padding:10px 16px;border-radius:8px;
              background:var(--accent);color:#fff;text-decoration:none">
      Open policy translator →</a>
    <p class="muted" style="margin-top:14px">
      Or pick from existing policies:
      <a href="/policies?asset=${aid()}">view policies that target this asset</a>.
    </p>
  `);
}

async function actSnapshot() {
  if (!confirm(`Take a config snapshot of ${ASSET_ID} now?`)) return;
  try {
    const r = await scApi(`/api/platform/asset/${aid()}/snapshot`,
                           { method: "POST" });
    alert(`✓ Snapshot saved (${r.bytes||0} bytes). Compare in /per-device-diff.`);
  } catch (e) { alert("Snapshot failed: " + e.message); }
}

function actCompareSnapshot() {
  location.href = `/per-device-diff?asset_id=${aid()}`;
}

function actGrantJIT() {
  location.href = `/identity#jit-tbl?resource=${aid()}`;
}

function actEvidencePack() {
  // Server-side endpoint streams a PDF.
  window.open(`/api/platform/evidence-pack?framework=pci&asset_id=${aid()}`, "_blank");
}

async function actFixPlaybook() {
  scOpenSlide("AI fix playbook for " + ASSET_ID, `
    <div class="muted">Generating top-risks playbook…</div>
  `);
  try {
    const r = await scApi(`/api/policy/fix-top-risks?asset_id=${aid()}`);
    const fixes = r.fixes || r.playbook || [];
    const html = fixes.length
      ? `<p class="muted">${fixes.length} prioritized fixes for this asset:</p>
         <ol style="font-size:13px">${fixes.map(f =>
            `<li><strong>${f.title || f.kind || ''}</strong> — ${f.summary || f.description || ''}</li>`
         ).join("")}</ol>`
      : `<p class="muted">No outstanding risks detected for this asset. 🎉</p>`;
    scOpenSlide("AI fix playbook for " + ASSET_ID, html);
  } catch (e) {
    scOpenSlide("AI fix playbook for " + ASSET_ID,
      `<p class="muted">Failed: ${e.message}</p>`);
  }
}

function actAttackPath() {
  // v9.16 — navigate to the v9-chrome blast-radius page (was opening the
  // legacy standalone viz in a new tab).
  location.href = `/blast-radius/${aid()}`;
}

function actTopology() {
  location.href = `/topology?focus=${aid()}`;
}

function actTimeline() {
  location.href = `/timeline?asset_id=${aid()}`;
}

function actAddException() {
  scOpenSlide("Add policy exception for " + ASSET_ID, `
    <p class="muted">Pick the policy this asset legitimately can't satisfy,
       state the reason, set an expiry, document the compensating control.</p>
    <a class="primary" href="/policies?exception_for=${aid()}"
       style="display:inline-block;padding:10px 16px;border-radius:8px;
              background:var(--accent);color:#fff;text-decoration:none">
      Open exceptions UI →</a>
    <p class="muted" style="margin-top:14px;font-size:12px">
      Exceptions show up as a yellow pill on this asset and auto-expire on
      the date you set. The pill ages you into reviewing it — that's the point.
    </p>
  `);
}

async function actEnrich() {
  if (!confirm(`Re-run AI enrichment on ${ASSET_ID}? This will refresh role, criticality, and tags.`)) return;
  try {
    const r = await scApi(`/api/intel/enrich/${aid()}`, { method: "POST" });
    alert(`✓ Enriched. Role=${r.inferred_role||'?'} criticality=${r.inferred_criticality||'?'}`);
    location.reload();
  } catch (e) { alert("Enrich failed: " + e.message); }
}

// =============================================================
//  v9.15 — additional device-aware actions
// =============================================================

async function actBackupConfig() {
  // Re-uses the snapshot endpoint; difference is intent: a backup goes
  // to the snapshot history with a "backup" label so it shows up in a
  // separate timeline strand later.
  if (!confirm(`Take a backup snapshot of ${ASSET_ID}?`)) return;
  try {
    const r = await scApi(`/api/platform/asset/${aid()}/snapshot`,
                           { method: "POST" });
    alert(`✓ Backup saved (${r.bytes||0} bytes, ${r.total_snapshots} total).`);
  } catch (e) { alert("Backup failed: " + e.message); }
}

function actOpenCloudConsole() {
  const a = CURRENT_ASSET || {};
  const ident = a.identity || {};
  const cf = ident.custom_fields || {};
  const vendor = (ident.vendor || "").toLowerCase();
  const region = ident.site || cf.region || "";
  let url = "";
  if (vendor === "aws" || vendor.includes("aws")) {
    const id = cf.instance_id || ident.asset_id;
    url = `https://${region || 'us-east-1'}.console.aws.amazon.com/ec2/home?region=${region || 'us-east-1'}#InstanceDetails:instanceId=${id}`;
  } else if (vendor === "azure" || vendor.includes("azure")) {
    const sub = cf.subscription_id || "";
    const rg = cf.resource_group || "";
    const name = ident.hostname || ident.asset_id;
    url = `https://portal.azure.com/#@${sub}/resource/subscriptions/${sub}/resourceGroups/${rg}/providers/Microsoft.Compute/virtualMachines/${name}/overview`;
  } else if (vendor === "gcp" || vendor.includes("google")) {
    const project = cf.project_id || "";
    const name = ident.hostname || ident.asset_id;
    const zone = cf.zone || region;
    url = `https://console.cloud.google.com/compute/instancesDetail/zones/${zone}/instances/${name}?project=${project}`;
  }
  if (!url) {
    alert("Couldn't compose a console URL — check the asset's vendor + " +
          "custom_fields (region, instance_id, subscription_id, project_id).");
    return;
  }
  window.open(url, "_blank");
}

async function actDecommission() {
  if (!confirm(`Mark ${ASSET_ID} as decommissioned?\n\nKeeps the record for audit but removes from active fleet views and policy targets.`))
    return;
  try {
    await scApi(`/api/platform/asset/${aid()}`, {
      method: "PUT",
      body: JSON.stringify({
        discovery_source: "decommissioned",
        criticality: "low",
      }),
    });
    alert("✓ Marked decommissioned. Use Inventory → Edit to fully delete.");
    location.reload();
  } catch (e) { alert("Failed: " + e.message); }
}

function actComparePeer() {
  // Pop a slide-over with a search box; user picks another asset and
  // we route to /per-device-diff with both IDs.
  scOpenSlide("Compare " + ASSET_ID + " to a peer", `
    <p class="muted">Pick another switch/router to diff its running
       config against this one. Useful for spotting drift across
       supposedly-identical access switches.</p>
    <input id="peer-search" placeholder="hostname or IP"
       style="width:100%;padding:8px;border-radius:6px;
              border:1px solid var(--border);background:var(--bg);
              color:var(--text);font-size:12px"
       oninput="peerSearch()" />
    <div id="peer-results" style="margin-top:10px;
         max-height:280px;overflow:auto"></div>
  `);
}
async function peerSearch() {
  const q = (document.getElementById("peer-search").value || "").trim().toLowerCase();
  const host = document.getElementById("peer-results");
  if (!q) { host.innerHTML = '<div class="muted">Type to search…</div>'; return; }
  try {
    const r = await scApi("/api/platform/inventory");
    const matches = (r.assets || []).filter(a => {
      const id = a.identity || {};
      if (id.asset_id === ASSET_ID) return false;
      if ((id.asset_type || "").toLowerCase() !== "network") return false;
      const hay = [id.asset_id, id.hostname, id.mgmt_ip, id.vendor]
                    .filter(Boolean).join(" ").toLowerCase();
      return hay.includes(q);
    }).slice(0, 25);
    if (!matches.length) {
      host.innerHTML = '<div class="muted">No matches.</div>';
      return;
    }
    host.innerHTML = matches.map(m => {
      const id = m.identity || {};
      return `<div style="padding:6px 10px;border-radius:4px;cursor:pointer;
        background:var(--panel-2);margin:4px 0"
        onclick="location.href='/per-device-diff?a=${aid()}&b=${encodeURIComponent(id.asset_id)}'">
        <strong>${id.hostname || id.asset_id}</strong>
        <span class="muted" style="font-size:11px;margin-left:8px">
          ${id.vendor||''} · ${id.mgmt_ip||''}</span>
      </div>`;
    }).join("");
  } catch(e) { host.innerHTML = `<div class="muted">${e.message}</div>`; }
}

async function actGenRunbook() {
  // v9.56 — reframe this surface honestly. Pre-v9.56 it called
  // /api/intel/ask (a read-only Q&A endpoint whose system prompt
  // explicitly forbids proposing write actions) and called the
  // result a "runbook." That's a lie: it's an AI-generated text
  // suggestion that you'd be wise to verify against vendor docs
  // before running anything. The label "operational notes" is
  // honest about what we're actually returning.
  scOpenSlide("AI operational notes for " + ASSET_ID, `
    <p class="muted">Read-only AI suggestion for common operational
       tasks on this device — health check, safe config backup,
       reload procedure, troubleshooting starting points.</p>
    <p class="muted" style="font-size:11px;
       padding:8px;background:var(--bg);border-radius:4px;
       border-left:3px solid #f59e0b">
       <strong>Verify before executing.</strong> SafeCadence's
       /ask path is intentionally read-only — these are
       suggestions the model produced from your fleet snapshot
       plus its training data, not a vendor-validated runbook.
       Cross-check vendor documentation before running any
       command on production.
    </p>
    <div id="rb-out" class="muted">Generating…</div>
  `);
  try {
    const a = CURRENT_ASSET || {};
    const ident = a.identity || {};
    // v9.56 — prompt is explicit that we want SUGGESTIONS, not a
    // runbook. The read-only system prompt enforces this on the
    // model side; this comment makes the intent obvious to the
    // next reader of this file.
    const prompt =
      `Suggest operational tasks an operator might want to run on ` +
      `${ident.hostname || ASSET_ID} ` +
      `(${ident.vendor || 'unknown vendor'} ${ident.asset_type || 'device'}). ` +
      `Cover: 1) read-only daily health check commands, ` +
      `2) safe (non-disruptive) config backup commands, ` +
      `3) reload procedure considerations (do NOT issue 'reload' yourself), ` +
      `4) top 3 read-only troubleshooting starters. ` +
      `Use vendor-appropriate CLI syntax. Mark every command read-only or write. ` +
      `Keep it under 25 lines.`;
    const r = await scApi("/api/intel/ask", {
      method: "POST",
      body: JSON.stringify({question: prompt}),
    });
    const out = document.getElementById("rb-out");
    if (out) out.innerHTML =
      `<pre style="white-space:pre-wrap;font-size:12px;line-height:1.5;
        background:var(--bg);padding:10px;border-radius:4px">${
          (r.answer || r.text || "(no response)").replace(/[<>&]/g, c =>
            ({"<":"&lt;",">":"&gt;","&":"&amp;"}[c]))
        }</pre>` +
      (r.fallback_reason ? `<p class="muted" style="font-size:11px;
         margin-top:8px">↻ deterministic fallback — ${
           r.fallback_reason.replace(/[<>&]/g, c =>
             ({"<":"&lt;",">":"&gt;","&":"&amp;"}[c]))
         }</p>` : '');
  } catch(e) {
    const out = document.getElementById("rb-out");
    if (out) out.innerHTML =
      `<p class="muted">AI request failed: ${(e.message || '').replace(/[<>&]/g, c =>
        ({"<":"&lt;",">":"&gt;","&":"&amp;"}[c]))}.
       Configure BYO-AI under Settings,
       or use the static runbook templates in the legacy UI.</p>`;
  }
}

function loadConfig() {
  const a = CURRENT_ASSET || {};
  const raw = a.raw_collection || {};
  const cfg = raw.running || raw.config || raw.startup || raw.text || "";
  if (!cfg) {
    return;  // Section stays hidden if no config available.
  }
  document.getElementById("sec-config-h").style.display = "block";
  document.getElementById("sec-config").style.display = "block";
  document.getElementById("config-pre").textContent = cfg;
  const lines = cfg.split("\n").length;
  document.getElementById("config-meta").textContent =
    `${lines} lines · ${cfg.length.toLocaleString()} bytes · last collected ` +
    ((a.identity || {}).last_collected_at || "—");
}

function copyConfig() {
  const text = document.getElementById("config-pre").textContent;
  navigator.clipboard.writeText(text).then(
    () => { document.getElementById("config-meta").textContent = "✓ Copied to clipboard"; },
    () => alert("Copy failed. Browser may block clipboard access."),
  );
}

function downloadConfig() {
  const text = document.getElementById("config-pre").textContent;
  const blob = new Blob([text], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${ASSET_ID}-running-config.txt`;
  a.click();
  URL.revokeObjectURL(url);
}

async function loadPoliciesTargetingMe() {
  const host = document.getElementById("policies-card");
  // Pull every saved policy and filter client-side by asset match
  let policies = [];
  try {
    const r = await scApi("/api/policy/");
    policies = r.policies || [];
  } catch (e) {
    host.innerHTML = `<div class="muted">No policies endpoint reachable.
      <a href="/policies">Open policies tool →</a></div>`;
    return;
  }
  if (!policies.length) {
    host.innerHTML = `<div class="muted">
      No policies defined yet. <a href="/policies">Build your first one →</a>
    </div>`;
    return;
  }
  // Filter by targeting — match on asset_type, vendor, env, criticality, tags, asset_id
  const a = CURRENT_ASSET || {};
  const id = a.identity || {};
  const tags = id.tags || [];
  const matching = policies.filter(p => {
    const t = p.targeting || p.target || {};
    if ((t.asset_ids || []).includes(id.asset_id)) return true;
    if ((t.asset_types || []).includes(id.asset_type)) return true;
    if ((t.vendors || []).includes(id.vendor)) return true;
    if ((t.environments || []).includes(id.environment)) return true;
    if ((t.criticalities || []).includes(id.criticality)) return true;
    for (const tag of (t.tags || [])) {
      if (tags.includes(tag)) return true;
    }
    // Empty targeting → fleet-wide → applies to everyone
    if (!t.asset_ids && !t.asset_types && !t.vendors && !t.environments
        && !t.criticalities && !t.tags) return true;
    return false;
  });
  if (!matching.length) {
    host.innerHTML = `<div class="muted">
      No policies currently target this asset.
      <a href="/policies">Build a policy →</a></div>`;
    return;
  }
  host.innerHTML = `
    <div class="muted" style="margin-bottom:8px">
      ${matching.length} of ${policies.length} policies target this asset.
    </div>
    <table style="width:100%">
      <thead><tr><th>Policy</th><th>Targeting</th><th>Last eval</th><th></th></tr></thead>
      <tbody>${matching.map(p => `
        <tr>
          <td><strong>${p.policy_name || p.name || p.policy_id}</strong></td>
          <td class="muted" style="font-size:12px">${describeTargeting(p)}</td>
          <td class="muted" style="font-size:12px">${p.last_evaluated_at || "—"}</td>
          <td><a href="/policies#${p.policy_id || ''}" style="font-size:12px">View →</a></td>
        </tr>
      `).join("")}</tbody>
    </table>
  `;
}

function describeTargeting(p) {
  const t = p.targeting || p.target || {};
  const parts = [];
  if ((t.tags || []).length)         parts.push("tags=" + t.tags.join(","));
  if ((t.asset_types || []).length)  parts.push("type=" + t.asset_types.join(","));
  if ((t.vendors || []).length)      parts.push("vendor=" + t.vendors.join(","));
  if ((t.environments || []).length) parts.push("env=" + t.environments.join(","));
  if ((t.criticalities || []).length) parts.push("crit=" + t.criticalities.join(","));
  if ((t.asset_ids || []).length)    parts.push(t.asset_ids.length + " explicit");
  return parts.join(" · ") || "fleet-wide";
}

function renderAsset(a) {
  const id = a.identity || {};
  const hw = a.hardware || {};
  const os = a.os || {};
  const lic = a.license || {};
  const sr = a.system_resources || {};
  const rt = a.routing || {};
  const l2 = a.l2_tables || {};
  const ns = a.network_security || {};
  const rp = a.routing_protocols || {};
  const lg = a.system_logging || {};
  const vc = a.voice_uc || {};
  const cs = a.compliance_signals || {};
  const h = a.health || {};
  const sec = a.security || {};

  // Header strip
  document.getElementById("title").textContent =
    id.hostname || id.asset_id || ASSET_ID;
  document.getElementById("subtitle").textContent =
    `${id.asset_id || ""}${id.site ? " · " + id.site : ""}`;
  document.getElementById("kv-vendor").textContent = id.vendor || "—";
  document.getElementById("kv-model").textContent = hw.model || id.model || "—";
  document.getElementById("kv-type").textContent = id.asset_type || "—";
  document.getElementById("kv-env").textContent = id.environment || "—";
  document.getElementById("kv-crit").innerHTML =
    `<span class="pill ${id.criticality === 'crown-jewel' ? 'pill-crit' : ''}">${id.criticality || '—'}</span>`;
  document.getElementById("kv-owner").textContent = id.owner || "—";
  document.getElementById("kv-source").textContent = id.discovery_source || "—";

  // v9.24/9.26: Safe Score (per-asset). Async — element starts as "—".
  scApi(`/api/scores/safe/${encodeURIComponent(ASSET_ID)}`).then(s => {
    if (!s || typeof s.score !== "number") return;
    const el = document.getElementById("kv-safe");
    if (!el) return;
    const conf = typeof s.confidence === "number" ? s.confidence : 1;
    if (conf < 0.3) {
      // v9.26: low confidence — show "—" with explainer.
      el.innerHTML = `<span class="muted" title="Insufficient data — scan first.\n${(s.confidence_reasons||[]).join('\\n')}">— <small>(low confidence)</small></span>`;
    } else {
      const cls = s.score >= 80 ? "pill-ok"
                 : s.score >= 60 ? "pill-high" : "pill-crit";
      const conftag = conf < 0.7
        ? ` <small style="color:var(--muted)">(±)</small>` : "";
      el.innerHTML = `<span class="pill ${cls}" title="Grade ${s.band} · confidence ${Math.round(conf*100)}%">${s.score}${conftag}</span>`;
    }
  }).catch(() => {});

  // v9.26: posture + best-practice + software-currency breakdown card
  Promise.all([
    scApi(`/api/scores/posture/${encodeURIComponent(ASSET_ID)}`).catch(() => null),
    scApi(`/api/scores/best-practice/${encodeURIComponent(ASSET_ID)}`).catch(() => null),
    scApi(`/api/scores/software-currency/${encodeURIComponent(ASSET_ID)}`).catch(() => null),
  ]).then(([post, bp, sc]) => {
    const card = document.getElementById("ss2-card");
    const host = document.getElementById("ss2-host");
    if (!card || !host) return;
    if (!post && !bp && !sc) return;
    card.style.display = "block";
    const safeText = s => (s == null) ? "—" : String(s);
    const postureHtml = post ? `
      <div>
        <div class="muted" style="font-size:11px">Posture credit</div>
        <div style="font-size:18px;font-weight:700">+${post.credit}<small style="color:var(--muted);font-weight:400"> / ${post.cap}</small></div>
        <div class="muted" style="font-size:11px;margin-top:4px">${(post.earned||[]).length} earned · ${(post.not_satisfied||[]).length} missing</div>
      </div>` : '';
    const bpHtml = (bp && bp.vendor_key) ? `
      <div>
        <div class="muted" style="font-size:11px">Vendor hardening (${bp.vendor_key})</div>
        <div style="font-size:18px;font-weight:700">${bp.credit}<small style="color:var(--muted);font-weight:400"> / ${bp.max_credit}</small></div>
        <div class="muted" style="font-size:11px;margin-top:4px">${bp.passed.length} pass · ${bp.failed.length} fail · ${bp.compliance_pct}%</div>
      </div>` : `
      <div>
        <div class="muted" style="font-size:11px">Vendor hardening</div>
        <div style="font-size:14px;color:var(--muted)">no pack for this vendor</div>
      </div>`;
    const scStatusColor = sc ? ({
      current: 'var(--ok,#16a34a)', supported: 'var(--ok,#16a34a)',
      behind: 'var(--warn,#ca8a04)', eol: 'var(--bad,#dc2626)',
      kev_vulnerable: 'var(--bad,#dc2626)', unknown: 'var(--muted)'
    }[sc.status] || 'var(--muted)') : 'var(--muted)';
    const scHtml = sc ? `
      <div>
        <div class="muted" style="font-size:11px">Software currency</div>
        <div style="font-size:14px;font-weight:700;color:${scStatusColor}">${sc.status.replace('_',' ')}</div>
        <div class="muted" style="font-size:11px;margin-top:4px">${safeText(sc.running_version)}${sc.recommended ? ' · rec ' + sc.recommended : ''}</div>
      </div>` : '';
    host.innerHTML = postureHtml + bpHtml + scHtml;
  });

  // Section 1 — Identity
  renderKV("sec-identity", [
    ["hostname", id.hostname], ["asset_id", `<code>${id.asset_id || ""}</code>`],
    ["vendor", id.vendor], ["product_family", id.product_family],
    ["model", hw.model || id.model],
    ["serial_number", id.serial_number],
    ["chassis_serial", id.chassis_serial_number],
    ["asset_type", id.asset_type], ["environment", id.environment],
    ["site", id.site], ["rack", id.rack], ["datacenter", id.datacenter],
    ["criticality", id.criticality], ["owner", id.owner], ["team", id.team],
    ["tags", listOr(id.tags)],
    ["discovery_source", id.discovery_source],
    ["discovered_at", id.discovered_at],
    ["last_collected_at", id.last_collected_at],
  ]);

  // Section 2 — Hardware
  renderKV("sec-hardware", [
    ["chassis_pid", hw.chassis_pid], ["chassis_vid", hw.chassis_vid],
    ["cpu_model", hw.cpu_model], ["cpu_count", hw.cpu_count],
    ["memory_total_mb", hw.memory_total_mb && (hw.memory_total_mb + " MB")],
    ["memory_used_mb", hw.memory_used_mb && (hw.memory_used_mb + " MB")],
    ["disk_count", hw.disk_count], ["disk_total_gb", hw.disk_total_gb && (hw.disk_total_gb + " GB")],
    ["firmware_version", hw.firmware_version], ["bios_version", hw.bios_version],
    ["bmc_version", hw.bmc_version],
  ]);
  // Modules + transceivers + PSUs as small lists
  const modulesEl = document.querySelector("#sec-hardware .modules");
  if (modulesEl) {
    const parts = [];
    for (const mod of (hw.modules || [])) {
      parts.push(`<div class="module">slot ${mod.slot}: ${mod.pid} (${mod.serial})</div>`);
    }
    for (const t of (hw.transceivers || [])) {
      parts.push(`<div class="module">${t.port}: ${t.type} (${t.serial})</div>`);
    }
    for (const ps of (hw.power_supplies || [])) {
      parts.push(`<div class="module">${ps.slot}: ${ps.status} ${ps.watts ? "(" + ps.watts + "W)" : ""}</div>`);
    }
    for (const f of (hw.fans || [])) {
      parts.push(`<div class="module">${f.slot}: ${f.status} ${f.rpm ? "(" + f.rpm + " RPM)" : ""}</div>`);
    }
    modulesEl.innerHTML = parts.join("");
  }

  // Section 3 — OS
  renderKV("sec-os", [
    ["os_type", os.os_type],
    ["os_version", os.os_version || os.version],
    ["kernel_version", os.kernel_version],
    ["boot_image", os.boot_image && `<code>${os.boot_image}</code>`],
    ["config_register", os.config_register && `<code>${os.config_register}</code>`],
    ["uptime", fmtUptime(os.uptime_seconds)],
    ["last_reboot", os.last_reboot],
    ["patch_level", os.patch_level],
  ]);

  // Section 4 — License
  renderKV("sec-license", [
    ["license_type", lic.license_type], ["license_level", lic.license_level],
    ["license_status", lic.license_status],
    ["smart_license_enabled", bool(lic.smart_license_enabled)],
    ["license_expiry_date", lic.license_expiry_date],
    ["seats", lic.seats_total ? `${lic.seats_used} / ${lic.seats_total}` : ""],
    ["licensed_features", listOr(lic.licensed_features)],
  ]);

  // Section 5 — System resources
  renderKV("sec-resources", [
    ["cpu_5sec", sr.cpu_5sec && (sr.cpu_5sec + "%")],
    ["cpu_1min", sr.cpu_1min && (sr.cpu_1min + "%")],
    ["cpu_5min", sr.cpu_5min && (sr.cpu_5min + "%")],
    ["cpu_utilization", sr.cpu_utilization_percent && (sr.cpu_utilization_percent + "%")],
    ["memory_total", fmtBytes(sr.memory_total_bytes)],
    ["memory_used", fmtBytes(sr.memory_used_bytes)],
    ["memory_free", fmtBytes(sr.memory_free_bytes)],
    ["memory_utilization", sr.memory_utilization_percent && (sr.memory_utilization_percent + "%")],
  ]);

  // Section 6 — Interfaces
  const ifaces = a.interfaces || [];
  if (ifaces.length) {
    document.getElementById("sec-interfaces").style.display = "block";
    document.querySelector(".iface-tbl tbody").innerHTML = ifaces.map(i => `
      <tr>
        <td><strong>${i.name || ""}</strong></td>
        <td><span class="pill ${i.status === 'up' ? 'pill-ok' : 'pill-crit'}">${i.status || "?"}</span></td>
        <td>${i.ip_address || ""}${i.netmask ? "/" + i.netmask : ""}</td>
        <td><code>${i.mac_address || ""}</code></td>
        <td>${i.speed_mbps ? i.speed_mbps + " Mbps" : ""}</td>
        <td>${(i.errors_in || 0) + (i.errors_out || 0)}</td>
      </tr>
    `).join("");
  }

  // Section 7 — Routing
  renderKV("sec-routing", [
    ["routing_table_size", rt.routing_table_size],
    ["default_gateway", rt.default_gateway],
    ["static_routes", rt.static_routes_count],
    ["connected_routes", rt.connected_routes_count],
    ["ospf_routes", rt.ospf_routes_count],
    ["bgp_routes", rt.bgp_routes_count],
    ["eigrp_routes", rt.eigrp_routes_count],
    ["rip_routes", rt.rip_routes_count],
  ]);

  // Section 8 — L2 tables
  renderKV("sec-l2", [
    ["arp_entries_count", l2.arp_entries_count],
    ["mac_table_entries_count", l2.mac_table_entries_count],
    ["sample MAC entries", (l2.sample_mac_entries || []).length
      ? "<br>" + (l2.sample_mac_entries || []).map(m => `<code>${m.mac}</code> vlan ${m.vlan_id} → ${m.interface}`).join("<br>")
      : ""],
  ]);

  // Section 9 — Network security
  renderKV("sec-netsec", [
    ["aaa_enabled", bool(ns.aaa_enabled)],
    ["ssh_enabled", bool(ns.ssh_enabled)],
    ["telnet_enabled", ns.telnet_enabled === undefined ? "" : (ns.telnet_enabled
      ? '<span class="pill pill-crit">✗ enabled (insecure)</span>'
      : "✓ disabled")],
    ["http_server_enabled", ns.http_server_enabled === undefined ? "" : (ns.http_server_enabled
      ? '<span class="pill pill-high">✗ enabled (use HTTPS)</span>'
      : "✓ disabled")],
    ["https_server_enabled", bool(ns.https_server_enabled)],
    ["snmp_v1_enabled", bool(ns.snmp_v1_enabled)],
    ["snmp_v2c_enabled", bool(ns.snmp_v2c_enabled)],
    ["snmp_v3_enabled", bool(ns.snmp_v3_enabled)],
    ["password_encryption_enabled", bool(ns.password_encryption_enabled)],
    ["weak_default_creds_present", ns.weak_default_creds_present === undefined ? "" : (ns.weak_default_creds_present
      ? '<span class="pill pill-crit">YES — fix immediately</span>'
      : "✓ none detected")],
    ["number_of_local_users", ns.number_of_local_users],
    ["acl_count", ns.acl_count],
    ["open_ports", listOr(ns.open_ports)],
    ["vpn_tunnels_active", ns.vpn_tunnels_active],
  ]);

  // Section 10 — Routing protocols
  renderKV("sec-routprot", [
    ["ospf_enabled", bool(rp.ospf_enabled)],
    ["ospf_neighbor_count", rp.ospf_neighbor_count],
    ["ospf_areas", listOr(rp.ospf_areas)],
    ["bgp_enabled", bool(rp.bgp_enabled)],
    ["bgp_neighbor_count", rp.bgp_neighbor_count],
    ["bgp_asn", rp.bgp_asn],
    ["eigrp_enabled", bool(rp.eigrp_enabled)],
    ["eigrp_neighbor_count", rp.eigrp_neighbor_count],
    ["routing_protocols_configured", listOr(rp.routing_protocols_configured)],
  ]);

  // Section 11 — Logs
  renderKV("sec-logs", [
    ["system_time", lg.system_time],
    ["timezone", lg.timezone],
    ["ntp_status", lg.ntp_status],
    ["ntp_servers", listOr(lg.ntp_servers)],
    ["syslog_servers", listOr(lg.syslog_servers)],
    ["log_buffer_size_bytes", fmtBytes(lg.log_buffer_size_bytes)],
    ["critical_log_count", lg.critical_log_count],
    ["error_log_count", lg.error_log_count],
    ["warning_log_count", lg.warning_log_count],
    ["last_log_message", lg.last_log_message && `<code>${lg.last_log_message}</code>`],
  ]);

  // Section 12 — Voice/UC
  renderKV("sec-voice", [
    ["active_calls", vc.active_calls],
    ["sip_status", vc.sip_status],
    ["registered_endpoints", vc.registered_endpoints],
    ["dial_peers_count", vc.dial_peers_count],
    ["rtp_sessions", vc.rtp_sessions],
    ["sip_trunk_count", vc.sip_trunk_count],
    ["codec_usage", vc.codec_usage && Object.keys(vc.codec_usage).length
      ? Object.entries(vc.codec_usage).map(([k, v]) => `${k}=${v}`).join(", ")
      : ""],
  ]);

  // Section 13 — Health scores
  renderKV("sec-health", [
    ["overall_score", h.overall_score && `<strong>${h.overall_score}/100</strong>`],
    ["grade", h.grade],
    ["risk_band", h.risk_band],
    ["hardware_health", h.hardware_health && (h.hardware_health + "/100")],
    ["security_health", h.security_health && (h.security_health + "/100")],
    ["lifecycle_health", h.lifecycle_health && (h.lifecycle_health + "/100")],
    ["operational_health", h.operational_health && (h.operational_health + "/100")],
  ]);

  // Section 14 — Compliance signals
  renderKV("sec-compliance", [
    ["risk_score_0_100", cs.risk_score_0_100 && `<strong class="${cs.risk_score_0_100 >= 70 ? '' : ''}">${cs.risk_score_0_100}/100</strong>`],
    ["eos_status", cs.eos_status],
    ["eol_status", cs.eol_status],
    ["weak_config_detected", cs.weak_config_detected === undefined ? "" : (cs.weak_config_detected
      ? '<span class="pill pill-crit">YES</span>' : "✓ none")],
    ["config_drift_detected", cs.config_drift_detected === undefined ? "" : (cs.config_drift_detected
      ? '<span class="pill pill-high">YES — review</span>' : "✓ in sync")],
    ["drift_summary", cs.drift_summary],
    ["known_cves", listOr(cs.known_cves)],
  ]);
  // Compliance extras — bullet lists for findings + best practices
  const compExtras = document.getElementById("comp-extras");
  let extras = "";
  if ((cs.weak_config_findings || []).length) {
    extras += `<div style="margin-top:10px"><strong>Weak config findings</strong><ul>`
      + cs.weak_config_findings.map(f => `<li>${f}</li>`).join("")
      + "</ul></div>";
  }
  if ((cs.missing_best_practices || []).length) {
    extras += `<div style="margin-top:10px"><strong>Missing best practices</strong><ul>`
      + cs.missing_best_practices.map(f => `<li>${f}</li>`).join("")
      + "</ul></div>";
  }
  compExtras.innerHTML = extras;

  // Custom fields
  renderCustomFields(id.custom_fields || {});
}

function renderCustomFields(cf) {
  const host = document.getElementById("custom-fields");
  const keys = Object.keys(cf);
  if (!keys.length) {
    host.innerHTML = '<div class="muted">No custom fields yet.</div>';
    return;
  }
  host.innerHTML = keys.map(k => `
    <div class="kv" style="display:flex;gap:8px;padding:6px 0;border-bottom:1px solid var(--border)">
      <div class="muted" style="min-width:160px">${k}</div>
      <div style="flex:1">${cf[k]}</div>
      <button class="alt" style="width:auto;padding:2px 8px;font-size:11px;background:#7f1d1d;color:#fff;border:0"
              onclick="removeCustomField('${k.replace(/'/g, "\\'")}')">✕</button>
    </div>
  `).join("");
}

async function addCustomField() {
  const k = document.getElementById("cf-key").value.trim();
  const v = document.getElementById("cf-val").value.trim();
  if (!k) { alert("Key is required"); return; }
  // Persist via PATCH on the platform asset endpoint. The backend
  // merges the incoming custom_fields with the existing ones.
  if (!CURRENT_ASSET) return;
  const cf = (CURRENT_ASSET.identity || {}).custom_fields || {};
  cf[k] = v;
  CURRENT_ASSET.identity = CURRENT_ASSET.identity || {};
  CURRENT_ASSET.identity.custom_fields = cf;
  try {
    await scApi(`/api/platform/${encodeURIComponent(ASSET_ID)}`, {
      method: "PUT",
      body: JSON.stringify(CURRENT_ASSET),
    });
    document.getElementById("cf-key").value = "";
    document.getElementById("cf-val").value = "";
    renderCustomFields(cf);
  } catch (e) {
    // Fallback: persist to localStorage so the user still has *something*
    const lsKey = "SC_CF_" + ASSET_ID;
    localStorage.setItem(lsKey, JSON.stringify(cf));
    document.getElementById("cf-key").value = "";
    document.getElementById("cf-val").value = "";
    renderCustomFields(cf);
  }
}

function removeCustomField(k) {
  if (!CURRENT_ASSET) return;
  const cf = (CURRENT_ASSET.identity || {}).custom_fields || {};
  delete cf[k];
  CURRENT_ASSET.identity.custom_fields = cf;
  scApi(`/api/platform/${encodeURIComponent(ASSET_ID)}`, {
    method: "PUT",
    body: JSON.stringify(CURRENT_ASSET),
  }).catch(() => {});
  renderCustomFields(cf);
}

async function loadFindings() {
  try {
    const r = await scApi("/api/identity/findings");
    const matching = (r.findings || []).filter(f =>
      (f.principal === ASSET_ID) ||
      JSON.stringify(f.evidence || {}).includes(ASSET_ID));
    if (matching.length) {
      document.querySelector("#findings-tbl tbody").innerHTML =
        matching.map(f => `<tr>
          <td><span class="pill ${f.severity === 'critical' || f.severity === 'high' ? 'pill-crit' : 'pill-high'}">${f.severity}</span></td>
          <td>${f.kind}</td><td>${f.title}</td>
        </tr>`).join("");
    }
  } catch (e) {}
}

async function loadPaths() {
  try {
    const r = await scApi("/api/identity/attack-paths");
    const matching = (r.paths || []).filter(p => p.terminal_asset === ASSET_ID);
    if (matching.length) {
      document.querySelector("#paths-tbl tbody").innerHTML =
        matching.map(p => `<tr><td>${p.risk_score.toFixed(1)}</td><td>${p.chain_summary}</td></tr>`).join("");
    }
  } catch (e) {}
}

async function loadJIT() {
  try {
    const r = await scApi("/api/identity/jit/list");
    const matching = (r.grants || []).filter(g => g.resource === ASSET_ID);
    if (matching.length) {
      document.querySelector("#jit-tbl tbody").innerHTML =
        matching.map(g => `<tr>
          <td>${g.principal}</td><td>${g.action}</td>
          <td>${g.status}</td>
          <td>${new Date(g.expires_at*1000).toLocaleString()}</td>
        </tr>`).join("");
    }
  } catch (e) {}
}

async function loadWatchState() {
  try {
    const r = await scApi("/api/intel/watchlists");
    for (const w of (r.watches || [])) {
      if (w.entity_kind === "asset" && w.entity_id === ASSET_ID) {
        WATCHED = true;
        WATCH_ID = w.watch_id;
        document.getElementById("watch-btn").textContent = "✓ Watching";
        break;
      }
    }
  } catch (e) {}
}

async function toggleWatch() {
  if (WATCHED && WATCH_ID) {
    await scApi(`/api/intel/watchlists/${WATCH_ID}`, { method: "DELETE" });
    WATCHED = false; WATCH_ID = null;
    document.getElementById("watch-btn").textContent = "+ Watchlist";
  } else {
    const r = await scApi("/api/intel/watchlists", {
      method: "POST",
      body: JSON.stringify({ entity_kind: "asset", entity_id: ASSET_ID }),
    });
    WATCHED = true; WATCH_ID = r.watch_id;
    document.getElementById("watch-btn").textContent = "✓ Watching";
  }
}

async function loadComments() {
  try {
    const r = await scApi(`/api/intel/comments?entity_kind=asset&entity_id=${ASSET_ID}`);
    const list = document.getElementById("comments-list");
    if (!r.comments.length) {
      list.innerHTML = '<div class="muted">No comments yet — be the first.</div>';
      return;
    }
    list.innerHTML = r.comments.map(c => {
      const when = new Date(c.created_at * 1000).toLocaleString();
      return `<div style="padding:6px 0;border-bottom:1px solid var(--border)">
        <strong>${c.user}</strong> <span class="muted">${when}</span><br/>
        ${c.text}
      </div>`;
    }).join("");
  } catch (e) {}
}

async function addComment() {
  const text = document.getElementById("new-comment").value.trim();
  if (!text) return;
  try {
    await scApi("/api/intel/comments", {
      method: "POST",
      body: JSON.stringify({
        entity_kind: "asset", entity_id: ASSET_ID, text
      }),
    });
    document.getElementById("new-comment").value = "";
    loadComments();
  } catch (e) { alert(e.message); }
}

load();
"""


def register(app):
    from fastapi.responses import HTMLResponse

    @app.get("/asset/{asset_id}", response_class=HTMLResponse)
    def asset_page(asset_id: str):
        return HTMLResponse(wrap(f"Asset · {asset_id}", _BODY, _SCRIPT))
