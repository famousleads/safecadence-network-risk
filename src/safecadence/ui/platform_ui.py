"""
Platform UI — single self-contained HTML page rendering the 6 domain
dashboards (Inventory / Servers / Storage / Virtualization / Cloud /
Backup) plus a Reports tab that calls the /api/platform/reports/*
endpoints.

The page is server-rendered as one big HTML string with vanilla JS that
calls the JSON API. Auth uses the same JWT bearer token the rest of
the app issues — the user logs in via /api/login first, then opens
/api/platform/ui in a browser tab and pastes the token (or the local
helper writes it to localStorage).
"""

from __future__ import annotations


_HTML_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>SafeCadence — Device Intelligence Platform</title>
<meta name="viewport" content="width=device-width,initial-scale=1" />
<style>
  :root {
    --bg:#0b1020; --panel:#121a33; --ink:#e7ecf5; --muted:#8b95b1;
    --accent:#5ad1ff; --good:#36d399; --warn:#f6c04d; --bad:#ef4f4f;
    --border:#26315b;
  }
  * { box-sizing:border-box; }
  html,body { margin:0; padding:0; background:var(--bg); color:var(--ink);
              font:14px/1.45 -apple-system,BlinkMacSystemFont,Segoe UI,Inter,Roboto,sans-serif; }
  header { padding:14px 22px; border-bottom:1px solid var(--border);
           display:flex; align-items:center; gap:18px; background:#0a1029; }
  header h1 { font-size:16px; margin:0; font-weight:600; letter-spacing:.4px; }
  header .badge { font-size:11px; padding:2px 8px; border:1px solid var(--border);
                  border-radius:999px; color:var(--muted); }
  nav { display:flex; gap:4px; padding:0 22px; border-bottom:1px solid var(--border);
        overflow-x:auto; background:#0a1029; }
  nav button { background:transparent; color:var(--muted); border:0; padding:12px 16px;
               cursor:pointer; border-bottom:2px solid transparent; font:inherit; }
  nav button.active { color:var(--ink); border-bottom-color:var(--accent); }
  nav button:hover { color:var(--ink); }
  main { padding:22px; max-width:1480px; margin:0 auto; }
  .row { display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr));
         gap:14px; margin-bottom:18px; }
  .card { background:var(--panel); border:1px solid var(--border); border-radius:12px;
          padding:14px 16px; }
  .card h3 { margin:0 0 6px; font-size:12px; color:var(--muted); text-transform:uppercase;
             letter-spacing:.6px; font-weight:600; }
  .card .v { font-size:28px; font-weight:600; }
  .card .sub { color:var(--muted); font-size:12px; margin-top:4px; }
  table { width:100%; border-collapse:collapse; background:var(--panel);
          border:1px solid var(--border); border-radius:12px; overflow:hidden; }
  th,td { padding:10px 12px; text-align:left; border-bottom:1px solid var(--border);
          font-size:13px; }
  th { color:var(--muted); font-weight:600; text-transform:uppercase;
       font-size:11px; letter-spacing:.5px; background:#101733; }
  tr:last-child td { border-bottom:0; }
  .pill { font-size:11px; padding:2px 8px; border-radius:999px; border:1px solid var(--border); }
  .pill.good { color:var(--good); border-color:#1f4d3a; background:#0f2620; }
  .pill.warn { color:var(--warn); border-color:#5a4519; background:#2a2110; }
  .pill.bad  { color:var(--bad);  border-color:#5a1f1f; background:#2a1010; }
  .empty { color:var(--muted); padding:30px; text-align:center; font-style:italic; }
  .toolbar { display:flex; gap:10px; align-items:center; margin-bottom:14px; }
  input,select,button.btn { background:#0a1029; color:var(--ink); border:1px solid var(--border);
                            border-radius:8px; padding:8px 12px; font:inherit; }
  button.btn { cursor:pointer; }
  button.btn:hover { border-color:var(--accent); }
  pre { background:#0a1029; border:1px solid var(--border); border-radius:8px;
        padding:12px; overflow:auto; font-size:12px; max-height:520px; }
  .grid2 { display:grid; grid-template-columns:1fr 1fr; gap:18px; }
  @media (max-width:900px) { .grid2 { grid-template-columns:1fr; } }
  .auth-banner { background:#2a1010; border:1px solid #5a1f1f; padding:10px 14px;
                 border-radius:8px; margin-bottom:14px; color:var(--bad); display:none; }
</style>
</head>
<body>
<header>
  <h1>SafeCadence Device Intelligence Platform</h1>
  <span class="badge">tenant: __TENANT__</span>
  <span class="badge">v4.0</span>
  <span style="margin-left:auto" class="badge">/api/platform</span>
</header>
<nav>
  <button data-tab="overview" class="active">Overview</button>
  <button data-tab="inventory">Inventory</button>
  <button data-tab="servers">Servers</button>
  <button data-tab="storage">Storage</button>
  <button data-tab="virt">Virtualization</button>
  <button data-tab="network">Network</button>
  <button data-tab="cloud">Cloud</button>
  <button data-tab="backup">Backup</button>
  <button data-tab="reports">Reports</button>
</nav>
<main>
  <div id="auth" class="auth-banner">
    Bearer token required. Run <code>safecadence ui</code> to log in, or set <code>localStorage.SC_TOKEN</code> in this tab.
  </div>
  <section id="tab-overview" class="tab"></section>
  <section id="tab-inventory" class="tab" hidden></section>
  <section id="tab-servers" class="tab" hidden></section>
  <section id="tab-storage" class="tab" hidden></section>
  <section id="tab-virt" class="tab" hidden></section>
  <section id="tab-network" class="tab" hidden></section>
  <section id="tab-cloud" class="tab" hidden></section>
  <section id="tab-backup" class="tab" hidden></section>
  <section id="tab-reports" class="tab" hidden></section>
</main>
<script>
const $ = (s, r=document) => r.querySelector(s);
const $$ = (s, r=document) => Array.from(r.querySelectorAll(s));
const TOKEN = () => localStorage.getItem("SC_TOKEN") || "";

async function api(path) {
  const tok = TOKEN();
  const headers = tok ? { Authorization: "Bearer " + tok } : {};
  const r = await fetch(path, { headers });
  if (r.status === 401) { $("#auth").style.display = "block"; return null; }
  return r.json();
}

const grade = g => `<span class="pill ${g==='A'||g==='B'?'good':g==='C'?'warn':g==='?'?'':'bad'}">${g||'?'}</span>`;

function statCards(s) {
  return `
    <div class="row">
      <div class="card"><h3>Assets</h3><div class="v">${s.count||0}</div></div>
      <div class="card"><h3>EOS &lt; 12mo</h3><div class="v">${s.eos_at_risk_12mo||0}</div></div>
      <div class="card"><h3>Critical CVEs</h3><div class="v">${s.critical_cves_total||0}</div></div>
      <div class="card"><h3>Top vendor</h3><div class="v">${Object.keys(s.by_vendor||{})[0]||'—'}</div>
        <div class="sub">${(Object.values(s.by_vendor||{})[0]||0)} assets</div></div>
    </div>
    <div class="row">
      <div class="card"><h3>Grade A</h3><div class="v">${(s.by_grade||{}).A||0}</div></div>
      <div class="card"><h3>Grade B</h3><div class="v">${(s.by_grade||{}).B||0}</div></div>
      <div class="card"><h3>Grade C</h3><div class="v">${(s.by_grade||{}).C||0}</div></div>
      <div class="card"><h3>Grade D/F</h3><div class="v">${((s.by_grade||{}).D||0)+((s.by_grade||{}).F||0)}</div></div>
    </div>`;
}

function assetTable(assets) {
  if (!assets || !assets.length) return '<div class="empty">No assets collected yet for this domain.</div>';
  const rows = assets.slice(0, 200).map(a => {
    const i = a.identity||{}, h = a.health||{};
    return `<tr>
      <td><code>${i.asset_id||''}</code></td>
      <td>${i.vendor||''}</td>
      <td>${i.model||i.product_family||''}</td>
      <td>${i.hostname||''}</td>
      <td>${i.environment||''}</td>
      <td>${grade(h.grade)}</td>
      <td>${h.composite_score!=null?h.composite_score:'—'}</td>
    </tr>`;
  }).join("");
  return `<table>
    <thead><tr><th>Asset ID</th><th>Vendor</th><th>Model</th><th>Hostname</th>
                <th>Env</th><th>Grade</th><th>Score</th></tr></thead>
    <tbody>${rows}</tbody></table>`;
}

async function renderDomain(tabId, apiPath) {
  const el = $("#tab-" + tabId);
  el.innerHTML = '<div class="empty">Loading…</div>';
  const j = await api(apiPath);
  if (!j) { el.innerHTML = ''; return; }
  el.innerHTML = statCards(j.summary||{}) + assetTable(j.assets||[]);
}

// v6.3 — first-run onboarding panel.
// When the asset store is empty, evaluators see a welcoming "load demo
// data / connect AWS / upload config" card instead of an empty grid.
function onboardingHtml() {
  return `<div class="card" style="padding:24px;margin-bottom:18px;
            border:1px solid var(--accent,#3b82f6);background:rgba(59,130,246,0.04)">
    <h2 style="margin:0 0 8px">Welcome — your fleet is empty</h2>
    <p style="margin:0 0 16px;color:var(--muted)">
      Pick the fastest way to see what SafeCadence does. Demo data is
      the recommended first step — it loads in under a second and
      shows every detector firing against a realistic 30-asset shop.
    </p>
    <div style="display:flex;gap:10px;flex-wrap:wrap">
      <button class="btn" onclick="loadDemoFleet()" style="font-weight:600">
        Load demo data (30 assets)
      </button>
      <button class="btn secondary" onclick="document.location='/api/platform/inventory'">
        Connect AWS / Azure / on-prem (docs)
      </button>
      <button class="btn ghost" onclick="document.location='/'">
        Upload a config file
      </button>
    </div>
    <p style="margin:14px 0 0;color:var(--muted);font-size:12px">
      Demo assets carry the prefix shown in <code>safecadence list-adapters</code>.
      Run <code>safecadence demo --clear</code> from the CLI to remove them
      when you're ready to wire up real sources.
    </p>
  </div>`;
}

async function loadDemoFleet() {
  const tok = TOKEN();
  const r = await fetch("/api/platform/load-demo?overwrite=false", {
    method: "POST",
    headers: tok ? { Authorization: "Bearer " + tok } : {},
  });
  const j = await r.json();
  alert((j.summary || ("Loaded " + (j.written || 0) + " demo assets"))
        + "\\n\\nReloading…");
  document.location.reload();
}

async function renderOverview() {
  const el = $("#tab-overview");
  el.innerHTML = '<div class="empty">Loading…</div>';
  const h = await api("/api/platform/health");
  if (!h) { el.innerHTML = ''; return; }
  let html = "";
  // Empty fleet → onboarding panel BEFORE the dashboard.
  if (!h.total || h.total === 0) {
    html += onboardingHtml();
  }
  html += `<div class="row">
    <div class="card"><h3>Total assets</h3><div class="v">${h.total||0}</div></div>`;
  for (const [d, s] of Object.entries(h.domains||{})) {
    html += `<div class="card"><h3>${d}</h3><div class="v">${s.count||0}</div>
      <div class="sub">${s.critical_cves_total||0} crit CVEs · ${s.eos_at_risk_12mo||0} near-EOS</div></div>`;
  }
  html += `</div>`;
  // toxic combos preview
  const r = await api("/api/platform/reports/risk_register");
  if (r) {
    html += `<h2 style="margin:24px 0 10px">Risk register</h2>`;
    const toxic = r.toxic_combinations || [];
    if (!toxic.length) html += '<div class="empty">No toxic combinations detected.</div>';
    else {
      const rows = toxic.slice(0, 25).map(t => `<tr>
        <td><code>${t.asset_id||''}</code></td>
        <td><span class="pill ${t.severity==='critical'?'bad':t.severity==='high'?'warn':''}">${t.severity}</span></td>
        <td>${t.type}</td><td>${t.msg}</td></tr>`).join('');
      html += `<table><thead><tr><th>Asset</th><th>Severity</th><th>Type</th><th>Detail</th></tr></thead>
              <tbody>${rows}</tbody></table>`;
    }
  }
  el.innerHTML = html;
}

async function renderInventory() {
  const el = $("#tab-inventory");
  el.innerHTML = `<div class="toolbar">
    <input id="invFilter" placeholder="Filter by vendor or hostname…" style="flex:1" />
    <select id="invType">
      <option value="">All types</option>
      <option value="server">server</option>
      <option value="storage">storage</option>
      <option value="hypervisor">hypervisor</option>
      <option value="network">network</option>
      <option value="cloud">cloud</option>
      <option value="backup">backup</option>
    </select>
    <button class="btn" id="invGo">Refresh</button>
  </div><div id="invBody"></div>`;
  async function load() {
    const t = $("#invType").value;
    const q = $("#invFilter").value.toLowerCase();
    const j = await api("/api/platform/inventory" + (t ? "?asset_type=" + t : ""));
    if (!j) { $("#invBody").innerHTML=''; return; }
    let assets = j.assets || [];
    if (q) assets = assets.filter(a => JSON.stringify(a).toLowerCase().includes(q));
    $("#invBody").innerHTML = assetTable(assets);
  }
  $("#invGo").onclick = load; $("#invType").onchange = load;
  $("#invFilter").addEventListener("input", () => { clearTimeout(window._t); window._t = setTimeout(load, 200); });
  load();
}

async function renderReports() {
  const el = $("#tab-reports");
  el.innerHTML = '<div class="empty">Loading reports…</div>';
  const j = await api("/api/platform/reports");
  if (!j) { el.innerHTML = ''; return; }
  let html = `<div class="row">`;
  for (const r of (j.reports||[])) {
    html += `<div class="card"><h3>${r.id}</h3>
       <div style="font-weight:600">${r.title}</div>
       <div class="sub">${r.description}</div>
       <button class="btn" data-rid="${r.id}" style="margin-top:8px">Run</button></div>`;
  }
  html += `</div><div id="reportOut"></div>`;
  el.innerHTML = html;
  $$("[data-rid]", el).forEach(b => b.onclick = async () => {
    const id = b.dataset.rid;
    $("#reportOut").innerHTML = '<div class="empty">Running…</div>';
    const out = await api("/api/platform/reports/" + id);
    $("#reportOut").innerHTML = `<h2 style="margin:18px 0 8px">${out.title||id}</h2>
       <pre>${JSON.stringify(out, null, 2)}</pre>`;
  });
}

const RENDERERS = {
  overview: renderOverview,
  inventory: renderInventory,
  servers:  () => renderDomain("servers",  "/api/platform/servers"),
  storage:  () => renderDomain("storage",  "/api/platform/storage"),
  virt:     () => renderDomain("virt",     "/api/platform/virtualization"),
  network:  () => renderDomain("network",  "/api/platform/network"),
  cloud:    () => renderDomain("cloud",    "/api/platform/cloud"),
  backup:   () => renderDomain("backup",   "/api/platform/backup"),
  reports:  renderReports,
};

function _activate(tabName) {
  $$("nav button").forEach(x => x.classList.toggle("active", x.dataset.tab === tabName));
  $$(".tab").forEach(s => s.hidden = (s.id !== "tab-" + tabName));
  if (RENDERERS[tabName]) RENDERERS[tabName]();
}
$$("nav button").forEach(b => b.onclick = () => _activate(b.dataset.tab));

const _initial = (location.hash || "").replace(/^#/, "");
_activate(_initial && RENDERERS[_initial] ? _initial : "overview");
window.addEventListener("hashchange", () => {
  const t = (location.hash || "").replace(/^#/, "");
  if (RENDERERS[t]) _activate(t);
});
</script>
</body>
</html>
"""


def render_platform_ui(tenant: str = "default") -> str:
    return _HTML_TEMPLATE.replace("__TENANT__", tenant)
