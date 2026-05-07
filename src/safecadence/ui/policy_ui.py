"""
Policy UI — v6.2 redesign.

A guided, AI-first single-page app. Replaces the v5 template-grid UX with:
  - 5-step Builder wizard (protect what → frameworks → strictness → AI-suggested
    controls → live impact preview against your fleet)
  - Rich Interpreter chat with suggested-prompt chips and inline policy preview
  - Action-oriented Compliance dashboard with Top-3 actions widget
  - Drift, Remediation, Exceptions, Audit tabs that actually do something

Pure vanilla JS, no build step, no CDN. Works in both server-mode (JWT auth)
and local-UI mode (no auth — same code skips the Authorization header when
no token is in localStorage).
"""

from __future__ import annotations


_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>SafeCadence — Policy Intelligence</title>
<meta name="viewport" content="width=device-width,initial-scale=1" />
<style>
  :root {
    --bg:#0b1020; --panel:#121a33; --panel2:#0e1530; --ink:#e7ecf5;
    --muted:#8b95b1; --accent:#7c5cff; --accent2:#5ad1ff;
    --good:#36d399; --warn:#f6c04d; --bad:#ef4f4f; --crit:#ff3b3b;
    --border:#26315b; --hover:#1a2447;
  }
  * { box-sizing:border-box; }
  html,body { margin:0; padding:0; background:var(--bg); color:var(--ink);
              font:14px/1.5 -apple-system,BlinkMacSystemFont,Segoe UI,Inter,Roboto,sans-serif; }
  a { color:var(--accent2); text-decoration:none; }
  a:hover { text-decoration:underline; }
  header { padding:14px 22px; border-bottom:1px solid var(--border);
           display:flex; align-items:center; gap:18px; background:#0a1029;
           position:sticky; top:0; z-index:50; }
  header h1 { font-size:16px; margin:0; font-weight:600; letter-spacing:.4px; }
  header .badge { font-size:11px; padding:2px 8px; border:1px solid var(--border);
                  border-radius:999px; color:var(--muted); }
  header .ask {
    flex:1; max-width:560px; margin-left:auto;
    background:#0a1029; border:1px solid var(--border); border-radius:999px;
    padding:8px 14px; display:flex; gap:8px; align-items:center;
  }
  header .ask input { flex:1; background:transparent; color:var(--ink);
                       border:0; outline:none; font:inherit; }
  header .ask kbd { font-family:ui-monospace,Menlo,monospace; font-size:10px;
                     padding:1px 5px; border:1px solid var(--border);
                     border-radius:3px; color:var(--muted); }

  nav.tabs { display:flex; gap:4px; padding:0 22px; border-bottom:1px solid var(--border);
             overflow-x:auto; background:#0a1029; }
  nav.tabs button { background:transparent; color:var(--muted); border:0; padding:12px 16px;
                    cursor:pointer; border-bottom:2px solid transparent; font:inherit; }
  nav.tabs button.active { color:var(--ink); border-bottom-color:var(--accent); }
  nav.tabs button:hover { color:var(--ink); }
  main { padding:22px; max-width:1480px; margin:0 auto; }

  .card { background:var(--panel); border:1px solid var(--border); border-radius:12px;
          padding:18px 20px; margin-bottom:14px; }
  .card h2 { font-size:14px; margin:0 0 8px; color:var(--muted);
             text-transform:uppercase; letter-spacing:.5px; font-weight:600; }
  .card h3 { font-size:16px; margin:0 0 8px; color:var(--ink); }

  .row { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr));
         gap:12px; margin-bottom:18px; }
  .stat { background:var(--panel); border:1px solid var(--border); border-radius:12px;
          padding:14px 16px; }
  .stat h3 { margin:0 0 4px; font-size:11px; color:var(--muted);
             text-transform:uppercase; letter-spacing:.6px; font-weight:600; }
  .stat .v { font-size:28px; font-weight:700; }
  .stat .sub { color:var(--muted); font-size:12px; margin-top:2px; }

  table { width:100%; border-collapse:collapse; background:var(--panel);
          border:1px solid var(--border); border-radius:12px; overflow:hidden; }
  th,td { padding:10px 12px; text-align:left; border-bottom:1px solid var(--border);
          font-size:13px; vertical-align:top; }
  th { color:var(--muted); font-weight:600; text-transform:uppercase;
       font-size:11px; letter-spacing:.5px; background:#101733; }
  tr:last-child td { border-bottom:0; }
  tr:hover td { background:rgba(124,92,255,.04); }

  .pill { font-size:10px; padding:2px 8px; border-radius:999px;
          border:1px solid var(--border); color:var(--muted); display:inline-block; }
  .pill.crit { color:#fff; background:var(--crit); border-color:var(--crit); }
  .pill.high { color:#fff; background:var(--bad); border-color:var(--bad); }
  .pill.medium { color:#000; background:var(--warn); border-color:var(--warn); }
  .pill.low { color:var(--good); border-color:#1f4d3a; background:#0f2620; }
  .pill.info { color:var(--muted); }
  .pill.good { color:var(--good); border-color:#1f4d3a; background:#0f2620; }

  button.btn { background:var(--accent); color:#fff; border:0; padding:9px 16px;
               border-radius:8px; font:inherit; font-weight:600; cursor:pointer;
               transition:.15s; }
  button.btn:hover { transform:translateY(-1px);
                      box-shadow:0 4px 12px rgba(124,92,255,.4); }
  button.btn.secondary { background:transparent; color:var(--ink);
                          border:1px solid var(--border); }
  button.btn.secondary:hover { border-color:var(--accent); background:var(--hover); }
  button.btn.ghost { background:transparent; color:var(--muted); border:0; }
  button.btn.ghost:hover { color:var(--ink); }

  input,select,textarea { background:#0a1029; color:var(--ink);
                           border:1px solid var(--border); border-radius:8px;
                           padding:9px 12px; font:inherit; }
  textarea { width:100%; min-height:120px;
              font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }

  pre { background:#0a1029; border:1px solid var(--border); border-radius:8px;
        padding:12px; overflow:auto; font-size:12px; max-height:480px; }

  .empty { color:var(--muted); padding:30px; text-align:center; font-style:italic; }
  .auth-banner { background:#2a1010; border:1px solid #5a1f1f; padding:10px 14px;
                  border-radius:8px; margin-bottom:14px; color:var(--bad); display:none; }

  /* === Wizard === */
  .wizard { background:var(--panel); border:1px solid var(--border);
            border-radius:14px; padding:26px 30px; }
  .wiz-step { display:none; }
  .wiz-step.active { display:block; }
  .wiz-progress { display:flex; gap:10px; margin-bottom:24px; }
  .wiz-progress .dot { flex:1; height:5px; background:var(--border);
                        border-radius:3px; position:relative; overflow:hidden; }
  .wiz-progress .dot.done { background:var(--accent); }
  .wiz-progress .dot.active { background:linear-gradient(90deg,var(--accent),var(--accent2)); }
  .wiz-step h2 { font-size:11px; margin:0 0 4px; color:var(--accent2);
                  text-transform:uppercase; letter-spacing:.6px; }
  .wiz-step h3 { font-size:22px; margin:0 0 6px; }
  .wiz-step .lede { color:var(--muted); margin:0 0 24px; font-size:14px; }
  .pick-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr));
                gap:12px; margin-bottom:18px; }
  .pick {
    background:var(--panel2); border:2px solid var(--border); border-radius:12px;
    padding:18px 16px; text-align:center; cursor:pointer; user-select:none;
    transition:.15s; position:relative;
  }
  .pick:hover { border-color:var(--accent2); transform:translateY(-2px); }
  .pick.selected { border-color:var(--accent); background:rgba(124,92,255,.08); }
  .pick .icon { font-size:28px; margin-bottom:6px; }
  .pick .label { font-weight:600; }
  .pick .desc { font-size:11px; color:var(--muted); margin-top:4px; }
  .pick.selected::after { content:"✓"; position:absolute; top:8px; right:10px;
                            color:var(--accent); font-weight:700; font-size:16px; }
  .wiz-actions { display:flex; gap:10px; margin-top:26px; align-items:center; }
  .wiz-actions .spacer { flex:1; }

  .checklist { max-height:400px; overflow-y:auto; padding-right:6px; }
  .checklist .ctrl-row {
    display:grid; grid-template-columns:24px 1fr auto auto; gap:10px;
    padding:10px 0; border-bottom:1px solid var(--border); align-items:center;
  }
  .checklist .ctrl-row:last-child { border-bottom:0; }
  .checklist .name { font-weight:600; }
  .checklist .why { font-size:11px; color:var(--muted); margin-top:2px; }

  /* === Interpreter chat === */
  .chat-msgs { background:var(--panel2); border:1px solid var(--border);
               border-radius:12px; padding:14px 18px; min-height:240px;
               max-height:480px; overflow-y:auto; margin-bottom:14px; }
  .chat-msg { margin-bottom:14px; }
  .chat-msg .who { font-size:11px; color:var(--muted); text-transform:uppercase;
                    letter-spacing:.6px; margin-bottom:4px; }
  .chat-msg.user .who { color:var(--accent2); }
  .chat-msg.ai .who { color:var(--accent); }
  .chat-msg .body { background:rgba(255,255,255,.02); border:1px solid var(--border);
                     border-radius:10px; padding:12px 14px; }
  .prompt-chips { display:flex; flex-wrap:wrap; gap:8px; margin:10px 0 14px; }
  .prompt-chips button { background:rgba(124,92,255,.08); border:1px solid var(--accent);
                          color:var(--ink); padding:6px 12px; border-radius:999px;
                          font-size:12px; cursor:pointer; }
  .prompt-chips button:hover { background:rgba(124,92,255,.18); }

  /* === Compliance dashboard top-3 === */
  .top3 .item { background:var(--panel2); border:1px solid var(--border);
                border-radius:12px; padding:14px 18px; margin-bottom:10px;
                display:grid; grid-template-columns:30px 1fr auto; gap:14px;
                align-items:center; }
  .top3 .item .num { font-size:20px; font-weight:700; color:var(--accent2); }
  .top3 .item .why { color:var(--muted); font-size:12px; margin-top:2px; }

  /* === Compliance bar === */
  .compliance-bar { display:flex; height:24px; border-radius:12px;
                     overflow:hidden; background:var(--border); margin:8px 0; }
  .compliance-bar .pass { background:var(--good); }
  .compliance-bar .fail { background:var(--bad); }
  .compliance-bar .na { background:var(--muted); opacity:.4; }
</style>
</head>
<body>
<header>
  <h1>SafeCadence Policy Intelligence</h1>
  <span class="badge">tenant: __TENANT__</span>
  <span class="badge">v6.4</span>
  <div class="ask">
    <span style="color:var(--muted)">🔎</span>
    <input id="askBar" placeholder="Ask: 'Lock down all my Cisco routers' or 'How many crown-jewels lack MFA?'" />
    <kbd>Enter</kbd>
  </div>
</header>
<nav class="tabs">
  <button data-tab="builder" class="active">🛠 Builder</button>
  <button data-tab="interpreter">🤖 AI Interpreter</button>
  <button data-tab="compliance">✓ Compliance</button>
  <button data-tab="drift">📉 Drift</button>
  <button data-tab="remediation">🩹 Remediation</button>
  <button data-tab="command">⚡ Command Center</button>
  <button data-tab="approvals">📝 Approvals</button>
  <button data-tab="execqueue">📋 Execution Queue</button>
  <button data-tab="rollback">⏮ Rollback</button>
  <button data-tab="exceptions">⚖ Exceptions</button>
  <button data-tab="audit">📜 Audit</button>
  <button data-tab="settings">⚙ Settings</button>
</nav>
<main>
  <div id="auth" class="auth-banner">
    Bearer token required. Set <code>localStorage.SC_TOKEN</code> via the v2 sidebar's Settings tab, or run with <code>--password</code>.
  </div>
  <section id="tab-builder" class="tab"></section>
  <section id="tab-interpreter" class="tab" hidden></section>
  <section id="tab-compliance" class="tab" hidden></section>
  <section id="tab-drift" class="tab" hidden></section>
  <section id="tab-remediation" class="tab" hidden></section>
  <section id="tab-command" class="tab" hidden></section>
  <section id="tab-approvals" class="tab" hidden></section>
  <section id="tab-execqueue" class="tab" hidden></section>
  <section id="tab-rollback" class="tab" hidden></section>
  <section id="tab-exceptions" class="tab" hidden></section>
  <section id="tab-audit" class="tab" hidden></section>
  <section id="tab-settings" class="tab" hidden></section>
</main>
<script>
const $ = (s, r=document) => r.querySelector(s);
const $$ = (s, r=document) => Array.from(r.querySelectorAll(s));
const TOKEN = () => localStorage.getItem("SC_TOKEN") || "";
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, m =>
  ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));

async function api(path, opts={}) {
  const tok = TOKEN();
  opts.headers = { ...(opts.headers||{}) };
  if (tok) opts.headers.Authorization = "Bearer " + tok;
  const r = await fetch(path, opts);
  if (r.status === 401) { $("#auth").style.display = "block"; return null; }
  const ct = r.headers.get("content-type") || "";
  return ct.includes("application/json") ? r.json() : r.text();
}

const sevPill = (s) => `<span class="pill ${esc(s||"info")}">${esc(s||"?")}</span>`;

// =====================================================================
// Tab: BUILDER (5-step wizard)
// =====================================================================

// v6.4 — wizard expanded to 6 steps. The new step 2 ("Apply to which
// devices?") was the killer missing primitive: without it every policy
// implicitly targeted the whole fleet, which is fine for an audit tool
// and useless for a real operator who wants "this policy on my 17 PCI
// scope devices and nothing else."
const BUILDER = {
  step: 1,
  asset_types: new Set(),
  asset_group_ids: new Set(),  // empty == fleet-wide (legacy default)
  available_groups: [],         // populated when step 2 first opens
  frameworks: new Set(),
  strictness: "standard",
  controls: [],     // [{id, severity, selected, parameters:{...}, ...}]
  policy_name: "",
  preview: null,
};

function renderBuilder() {
  const el = $("#tab-builder");
  const totalSteps = 6;
  el.innerHTML = `
    <div class="wizard">
      <div class="wiz-progress">
        ${[1,2,3,4,5,6].map(n => `<div class="dot ${
          n < BUILDER.step ? 'done' : n === BUILDER.step ? 'active' : ''
        }"></div>`).join('')}
      </div>
      <div id="wizBody"></div>
    </div>
  `;
  if (BUILDER.step === 1) renderStep1();
  if (BUILDER.step === 2) renderStep2Groups();
  if (BUILDER.step === 3) renderStep3Frameworks();
  if (BUILDER.step === 4) renderStep4Strictness();
  if (BUILDER.step === 5) renderStep5Controls();
  if (BUILDER.step === 6) renderStep6Preview();
}

function nav(prev, nextLabel, nextFn, nextDisabled=false) {
  return `<div class="wiz-actions">
    ${prev ? `<button class="btn secondary" onclick="BUILDER.step=${prev}; renderBuilder()">← Back</button>` : ''}
    <span class="spacer"></span>
    <button class="btn" id="wizNext" ${nextDisabled?'disabled style="opacity:.4;cursor:not-allowed"':''}>${nextLabel}</button>
  </div>`;
}

function renderStep1() {
  const types = [
    {id:"network", icon:"🌐", label:"Network gear", desc:"Routers, switches, firewalls, APs"},
    {id:"server", icon:"🖥", label:"Servers", desc:"Linux, Windows, BMCs"},
    {id:"storage", icon:"💾", label:"Storage", desc:"NetApp, Pure, Dell EMC, HPE"},
    {id:"hypervisor", icon:"🪄", label:"Virtualization", desc:"vCenter, Nutanix, Proxmox"},
    {id:"cloud", icon:"☁", label:"Cloud", desc:"AWS, Azure, GCP, K8s, OCI"},
    {id:"backup", icon:"🗄", label:"Backup", desc:"Veeam, Rubrik, Cohesity"},
    {id:"identity", icon:"🔐", label:"Identity / NAC", desc:"ISE, ClearPass, AD, Entra, Okta"},
  ];
  $("#wizBody").innerHTML = `
    <div class="wiz-step active">
      <h2>Step 1 of 6</h2>
      <h3>What do you want to protect?</h3>
      <p class="lede">Pick one or more asset types this policy should govern.
        SafeCadence will only suggest controls that apply to what you select.</p>
      <div class="pick-grid">
        ${types.map(t => `<div class="pick ${BUILDER.asset_types.has(t.id)?'selected':''}"
          onclick="toggleAssetType('${t.id}')">
          <div class="icon">${t.icon}</div>
          <div class="label">${t.label}</div>
          <div class="desc">${t.desc}</div>
        </div>`).join('')}
      </div>
      ${nav(null, "Next →", () => { BUILDER.step = 2; renderBuilder(); }, BUILDER.asset_types.size === 0)}
    </div>
  `;
  if (BUILDER.asset_types.size > 0) {
    $("#wizNext").onclick = () => { BUILDER.step = 2; renderBuilder(); };
  }
}

// ---- v6.4 — STEP 2: which devices? ----
async function renderStep2Groups() {
  // Fetch groups lazily — first time the user lands here.
  if (!BUILDER.available_groups || BUILDER.available_groups.length === 0) {
    $("#wizBody").innerHTML = `<div class="empty">⏳ Loading asset groups…</div>`;
    const r = await api("/api/platform/asset-groups");
    BUILDER.available_groups = (r && r.groups) ? r.groups : [];
  }
  const groups = BUILDER.available_groups;
  const selected = BUILDER.asset_group_ids;
  const fleetWide = selected.size === 0;
  const groupCards = groups.length === 0
    ? `<div class="empty">No asset groups defined yet. Create one with
         <code>safecadence groups create</code> or via
         <code>POST /api/platform/asset-groups</code>, then come back —
         or skip this step to apply fleet-wide.</div>`
    : groups.map(g => `<div class="pick ${selected.has(g.group_id)?'selected':''}"
        onclick="toggleAssetGroup('${esc(g.group_id)}')">
        <div class="label">${esc(g.name || g.group_id)}</div>
        <div class="desc">${esc(g.description || '')}</div>
        <div style="color:var(--muted);font-size:11px;margin-top:6px">
          ${g.member_count || 0} members
          ${g.asset_ids && g.asset_ids.length ? ' · static' : ''}
          ${g.filter && Object.keys(g.filter).length ? ' · dynamic' : ''}
        </div>
      </div>`).join('');
  $("#wizBody").innerHTML = `
    <div class="wiz-step active">
      <h2>Step 2 of 6</h2>
      <h3>Apply to which devices?</h3>
      <p class="lede">Pick one or more asset groups, or leave empty to evaluate
        every asset of the types you selected (fleet-wide). Groups let you say
        "this policy on these specific devices and nothing else."</p>
      <div class="pick ${fleetWide ? 'selected' : ''}"
           onclick="BUILDER.asset_group_ids = new Set(); renderStep2Groups()"
           style="margin-bottom:12px">
        <div class="label">All assets of those types (fleet-wide)</div>
        <div class="desc">Original behavior — evaluate every asset matching
          the asset types from step 1.</div>
      </div>
      <div class="pick-grid">${groupCards}</div>
      ${nav(1, "Next →")}
    </div>
  `;
  $("#wizNext").onclick = () => { BUILDER.step = 3; renderBuilder(); };
}
window.toggleAssetGroup = (gid) => {
  if (BUILDER.asset_group_ids.has(gid)) BUILDER.asset_group_ids.delete(gid);
  else BUILDER.asset_group_ids.add(gid);
  renderStep2Groups();
};
window.toggleAssetType = (id) => {
  BUILDER.asset_types.has(id) ? BUILDER.asset_types.delete(id) : BUILDER.asset_types.add(id);
  renderStep1();
};

function renderStep3Frameworks() {
  const frameworks = [
    {id:"nist", label:"NIST 800-53 Rev 5", desc:"US federal baseline. Required for FedRAMP."},
    {id:"cis", label:"CIS Controls v8", desc:"Center for Internet Security baseline."},
    {id:"pci", label:"PCI-DSS v4", desc:"Required if you store/process payment cards."},
    {id:"hipaa", label:"HIPAA Security Rule", desc:"Required for US healthcare PHI."},
    {id:"iso", label:"ISO 27001", desc:"International infosec management standard."},
    {id:"zerotrust", label:"NIST 800-207 Zero Trust", desc:"Identity-centric architecture."},
  ];
  $("#wizBody").innerHTML = `
    <div class="wiz-step active">
      <h2>Step 3 of 6</h2>
      <h3>Which compliance frameworks must you satisfy?</h3>
      <p class="lede">Selecting frameworks will tag every generated control with the
        specific framework references it satisfies — auditor-ready evidence.</p>
      <div class="pick-grid">
        ${frameworks.map(f => `<div class="pick ${BUILDER.frameworks.has(f.id)?'selected':''}"
          onclick="toggleFramework('${f.id}')">
          <div class="label">${f.label}</div>
          <div class="desc">${f.desc}</div>
        </div>`).join('')}
      </div>
      <p style="color:var(--muted);font-size:12px">You can pick none — controls will still be suggested
        based on asset types alone.</p>
      ${nav(2, "Next →")}
    </div>
  `;
  $("#wizNext").onclick = () => { BUILDER.step = 4; renderBuilder(); };
}
window.toggleFramework = (id) => {
  BUILDER.frameworks.has(id) ? BUILDER.frameworks.delete(id) : BUILDER.frameworks.add(id);
  renderStep3Frameworks();
};

function renderStep4Strictness() {
  const opts = [
    {id:"basic", label:"Basic baseline", desc:"Critical-only. Bare minimum to not get owned. Fast to roll out."},
    {id:"standard", label:"Industry standard", desc:"Critical + high. What most orgs run. Recommended."},
    {id:"paranoid", label:"High security", desc:"All severities including medium + low. For regulated environments."},
  ];
  $("#wizBody").innerHTML = `
    <div class="wiz-step active">
      <h2>Step 4 of 6</h2>
      <h3>How strict should this policy be?</h3>
      <p class="lede">Stricter = more controls. Pick what you can realistically operationalize.</p>
      <div class="pick-grid">
        ${opts.map(o => `<div class="pick ${BUILDER.strictness===o.id?'selected':''}"
          onclick="BUILDER.strictness='${o.id}'; renderStep4Strictness()">
          <div class="label">${o.label}</div>
          <div class="desc">${o.desc}</div>
        </div>`).join('')}
      </div>
      ${nav(3, "Suggest controls →")}
    </div>
  `;
  $("#wizNext").onclick = async () => { await loadSuggestions(); };
}

async function loadSuggestions() {
  $("#wizBody").innerHTML = `<div class="empty">⏳ Asking SafeCadence to suggest controls based on your selections…</div>`;
  const at = [...BUILDER.asset_types].join(",");
  const fw = [...BUILDER.frameworks].join(",");
  const r = await api(`/api/policy/suggest-controls?asset_types=${at}&frameworks=${fw}&strictness=${BUILDER.strictness}`);
  if (!r) return;
  BUILDER.controls = r.controls || [];
  BUILDER.step = 5;
  renderBuilder();
}

function renderStep5Controls() {
  const list = BUILDER.controls;
  $("#wizBody").innerHTML = `
    <div class="wiz-step active">
      <h2>Step 5 of 6</h2>
      <h3>Suggested controls (${list.filter(c=>c.selected).length} of ${list.length} selected)</h3>
      <p class="lede">Untick any you don't want. Severity is shown so you can drop optional ones.
        These were suggested based on: <strong>${[...BUILDER.asset_types].join(", ") || "all asset types"}</strong>
        · <strong>${[...BUILDER.frameworks].join(", ") || "no frameworks"}</strong>
        · <strong>${BUILDER.strictness}</strong> strictness.</p>
      <div class="card" style="margin:0">
        <div class="checklist">
          ${list.length === 0
            ? '<div class="empty">No controls match these filters. Try adding asset types or relaxing strictness.</div>'
            : list.map((c,i) => `<div class="ctrl-row">
              <input type="checkbox" ${c.selected?'checked':''}
                     onchange="BUILDER.controls[${i}].selected=this.checked; renderStep5Controls()" />
              <div>
                <div class="name">${esc(c.id)}</div>
                <div class="why">${esc(c.description)} · ${esc(c.rationale)}</div>
              </div>
              <div>${sevPill(c.severity)}</div>
              <div style="color:var(--muted);font-size:11px">${(c.applies_to||[]).join(", ")}</div>
            </div>`).join('')}
        </div>
      </div>
      ${nav(4, "Preview impact on my fleet →")}
    </div>
  `;
  $("#wizNext").onclick = async () => { await runPreview(); };
}

async function runPreview() {
  const ids = BUILDER.controls.filter(c=>c.selected).map(c=>c.id);
  if (ids.length === 0) { alert("Pick at least one control."); return; }
  $("#wizBody").innerHTML = `<div class="empty">⏳ Running the policy against your current fleet…</div>`;
  const r = await api("/api/policy/preview", {
    method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({
      control_ids: ids, parameters: {},
      applies_to_groups: [...BUILDER.asset_group_ids],
      target_asset_types: [...BUILDER.asset_types],
    }),
  });
  if (!r) return;
  BUILDER.preview = r;
  BUILDER.step = 6;
  renderBuilder();
}

function renderStep6Preview() {
  const p = BUILDER.preview || {};
  const sev = p.by_severity || {};
  const total = (p.would_pass||0) + (p.would_fail||0) + (p.would_be_na||0);
  const pct = (n) => total ? `${Math.round(n/total*100)}%` : '0%';
  const groupsLabel = BUILDER.asset_group_ids.size === 0
    ? 'fleet-wide (all assets of selected types)'
    : [...BUILDER.asset_group_ids].join(', ');
  $("#wizBody").innerHTML = `
    <div class="wiz-step active">
      <h2>Step 6 of 6</h2>
      <h3>Impact preview</h3>
      <p style="color:var(--muted);font-size:13px;margin-bottom:12px">
        <strong>Targeting:</strong> ${esc(groupsLabel)}
      </p>
      <p class="lede">${esc(p.summary || '')}</p>

      <div class="row">
        <div class="stat"><h3>Assets in scope</h3><div class="v">${p.applicable_assets||0}</div>
          <div class="sub">of ${p.asset_count||0} total</div></div>
        <div class="stat"><h3>Would pass</h3><div class="v" style="color:var(--good)">${p.would_pass||0}</div></div>
        <div class="stat"><h3>Would FAIL</h3><div class="v" style="color:var(--bad)">${p.would_fail||0}</div></div>
        <div class="stat"><h3>Not applicable</h3><div class="v" style="color:var(--muted)">${p.would_be_na||0}</div></div>
      </div>

      <div class="card">
        <h2>Pass / fail / NA breakdown</h2>
        <div class="compliance-bar">
          <div class="pass" style="width:${pct(p.would_pass||0)}"></div>
          <div class="fail" style="width:${pct(p.would_fail||0)}"></div>
          <div class="na" style="width:${pct(p.would_be_na||0)}"></div>
        </div>
        <div style="display:flex;gap:18px;font-size:12px;color:var(--muted);margin-top:6px">
          <span><span class="pill good">●</span> Pass</span>
          <span><span class="pill high">●</span> Fail</span>
          <span><span class="pill info">●</span> N/A</span>
        </div>
      </div>

      ${(p.violations||[]).length ? `<div class="card">
        <h2>Top violations that would be caught</h2>
        <table>
          <thead><tr><th>Asset</th><th>Control</th><th>Severity</th><th>Evidence</th></tr></thead>
          <tbody>
            ${p.violations.map(v => `<tr>
              <td><code>${esc(v.asset_id)}</code></td>
              <td><code>${esc(v.control_id)}</code></td>
              <td>${sevPill(v.severity)}</td>
              <td style="color:var(--muted);font-size:12px">${esc(v.evidence)}</td>
            </tr>`).join('')}
          </tbody>
        </table>
      </div>` : ''}

      <div class="card">
        <h2>Policy name</h2>
        <input id="policyName" placeholder="e.g. ACME Network Hardening Q2 2026"
               style="width:100%" value="${esc(BUILDER.policy_name || autoName())}" />
        <p style="color:var(--muted);font-size:12px;margin-top:8px">
          Tip: include the team or quarter — easier to find later.
        </p>
      </div>

      ${nav(5, "💾 Save policy")}
    </div>
  `;
  $("#wizNext").onclick = async () => { await savePolicy(); };
}

function autoName() {
  const at = [...BUILDER.asset_types].join("/");
  const fw = [...BUILDER.frameworks].join("/");
  const d = new Date().toISOString().split('T')[0];
  return `${at || "All"} ${fw ? "(" + fw + ") " : ""}— ${d}`;
}

async function savePolicy() {
  const name = ($("#policyName")?.value || autoName()).trim();
  // Build the body shape /api/policy/ POST expects
  const body = {
    policy_name: name,
    target_asset_types: [...BUILDER.asset_types],
    // v6.4 — empty list = fleet-wide (legacy behaviour preserved).
    applies_to_groups: [...BUILDER.asset_group_ids],
    compliance_frameworks: [...BUILDER.frameworks],
    severity: "high",
    controls: BUILDER.controls.filter(c=>c.selected).map(c => ({
      control_id: c.id, severity: c.severity, parameters: c.parameters || {},
      framework_refs: c.frameworks || [],
    })),
  };
  const r = await api("/api/policy/", {
    method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify(body),
  });
  if (!r) return;
  const tgt = BUILDER.asset_group_ids.size === 0
    ? 'fleet-wide'
    : `${BUILDER.asset_group_ids.size} group(s): ${[...BUILDER.asset_group_ids].join(', ')}`;
  alert(`✓ Policy '${name}' saved (id: ${r.policy_id}, targeting ${tgt}). `
        + `Switching to Compliance tab…`);
  // Reset wizard
  BUILDER.step = 1;
  BUILDER.asset_types.clear();
  BUILDER.asset_group_ids.clear();
  BUILDER.available_groups = [];
  BUILDER.frameworks.clear();
  BUILDER.strictness = "standard";
  BUILDER.controls = [];
  BUILDER.policy_name = "";
  switchTab("compliance");
}

// =====================================================================
// Tab: INTERPRETER (rich chat)
// =====================================================================

// CHAT history persists across page reloads via sessionStorage so an
// accidental F5 doesn't lose the user's exploration. Survives until the
// browser tab is closed; an explicit Clear button below empties both
// in-memory and persisted state.
const CHAT_STORAGE_KEY = "safecadence.policy.chat.v1";
const CHAT = { history: [] };
try {
  const raw = sessionStorage.getItem(CHAT_STORAGE_KEY);
  if (raw) {
    const restored = JSON.parse(raw);
    if (Array.isArray(restored)) CHAT.history = restored;
  }
} catch (e) { /* sessionStorage unavailable in some contexts */ }
function chatPersist() {
  try { sessionStorage.setItem(CHAT_STORAGE_KEY, JSON.stringify(CHAT.history)); }
  catch (e) { /* quota or disabled — no-op */ }
}
function chatClear() {
  CHAT.history = [];
  try { sessionStorage.removeItem(CHAT_STORAGE_KEY); } catch (e) {}
  renderInterpreter();
}

function renderInterpreter() {
  const el = $("#tab-interpreter");
  el.innerHTML = `
    <div class="card">
      <h2>Plain-English → Policy</h2>
      <p style="color:var(--muted);margin:0 0 14px">
        Type what you want to enforce. The interpreter extracts controls + parameters
        with the offline matcher (always works). Add <strong>--ai</strong> for richer extraction.
      </p>
      <div class="prompt-chips">
        <button onclick="chatSubmit(this.textContent)">Disable Telnet, enforce SSHv2, require AAA/TACACS</button>
        <button onclick="chatSubmit(this.textContent)">Lock down all my Cisco routers to NIST 800-53</button>
        <button onclick="chatSubmit(this.textContent)">Make sure no admin works without MFA</button>
        <button onclick="chatSubmit(this.textContent)">Just got a SOC 2 audit, what should I enforce?</button>
        <button onclick="chatSubmit(this.textContent)">Block public exposure on every cloud asset</button>
        <button onclick="chatSubmit(this.textContent)">Send all logs to 10.10.10.50</button>
      </div>
      <div class="chat-msgs" id="chatMsgs">
        ${CHAT.history.length === 0
          ? `<div class="empty" style="padding:18px;border:1px dashed var(--border);border-radius:8px;color:var(--muted)">
               <strong>Start by clicking a suggestion above</strong> — or describe in your own words what you want enforced
               (for example: <em>"Require MFA for all admins"</em> or <em>"Disable telnet on every router"</em>).<br><br>
               Conversation is kept in this browser tab until you hit <em>Clear</em>.
             </div>`
          : CHAT.history.map(renderChatMsg).join('')}
      </div>
      <div style="display:flex;gap:8px">
        <textarea id="chatInput" placeholder="Type your security intent..."
                  style="flex:1;min-height:60px"></textarea>
      </div>
      <div style="display:flex;gap:8px;margin-top:8px;align-items:center">
        <label style="color:var(--muted);font-size:12px">
          <input type="checkbox" id="useAI" /> Use BYO-AI (set $OPENAI_API_KEY first)
        </label>
        <span class="spacer" style="flex:1"></span>
        <button class="btn ghost" onclick="chatClear()">Clear</button>
        <button class="btn" id="chatGo">Interpret →</button>
      </div>
    </div>
  `;
  $("#chatGo").onclick = () => chatSubmit($("#chatInput").value);
  $("#chatInput").addEventListener("keydown", (e) => {
    if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) chatSubmit(e.target.value);
  });
}

function renderChatMsg(m) {
  if (m.role === "user") {
    return `<div class="chat-msg user"><div class="who">You</div>
      <div class="body">${esc(m.text)}</div></div>`;
  }
  if (m.role === "ai") {
    const p = m.policy || {};
    return `<div class="chat-msg ai"><div class="who">SafeCadence (${esc(p.source||"offline")})</div>
      <div class="body">
        <strong>Extracted ${(p.controls||[]).length} controls:</strong>
        <ul style="margin:8px 0;padding-left:20px">
          ${(p.controls||[]).map(c => `<li>
            <code>${esc(c.control_id)}</code>
            ${c.parameters && Object.keys(c.parameters).length
              ? '<span style="color:var(--muted);font-size:11px"> · params: ' + esc(JSON.stringify(c.parameters)) + '</span>'
              : ''}
          </li>`).join('')}
        </ul>
        <div style="display:flex;gap:8px;margin-top:10px">
          <button class="btn" onclick="saveInterpretedPolicy('${esc(p.policy_id||"")}', '${esc(p.policy_name||"")}', ${m.idx})">Save as policy</button>
          <button class="btn secondary" onclick="editInterpretedPolicy(${m.idx})">Edit before save</button>
        </div>
      </div></div>`;
  }
  return '';
}

window.chatSubmit = async (text) => {
  text = (text || "").trim();
  if (!text) return;
  CHAT.history.push({role: "user", text});
  chatPersist();
  renderInterpreter();
  const ai = !!$("#useAI")?.checked;
  const r = await api("/api/policy/interpret", {
    method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({text, ai, save: false}),
  });
  if (!r) return;
  CHAT.history.push({role: "ai", policy: r, idx: CHAT.history.length});
  chatPersist();
  renderInterpreter();
};

window.saveInterpretedPolicy = async (pid, pname, idx) => {
  const msg = CHAT.history[idx];
  if (!msg) return;
  const p = msg.policy;
  const body = {
    policy_name: pname || p.policy_name,
    target_asset_types: p.target_asset_types || [],
    compliance_frameworks: p.compliance_frameworks || [],
    severity: p.severity || "medium",
    controls: (p.controls || []).map(c => ({
      control_id: c.control_id, severity: c.severity,
      parameters: c.parameters || {},
      framework_refs: c.framework_refs || [],
    })),
  };
  const r = await api("/api/policy/", {
    method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify(body),
  });
  if (r) alert(`✓ Saved as policy ${r.policy_id}.`);
};

// =====================================================================
// Tab: COMPLIANCE (action-oriented dashboard)
// =====================================================================

async function renderCompliance() {
  const el = $("#tab-compliance");
  el.innerHTML = '<div class="empty">⏳ Loading fleet compliance…</div>';
  const j = await api("/api/policy/compliance");
  if (!j) return;
  const tot_pass = (j.policies||[]).reduce((a,p) => a + (p.pass||0), 0);
  const tot_fail = (j.policies||[]).reduce((a,p) => a + (p.fail||0), 0);
  const tot_na = (j.policies||[]).reduce((a,p) => a + (p.na||0), 0);
  const pct = tot_pass + tot_fail ? Math.round(tot_pass / (tot_pass+tot_fail) * 100) : 0;

  // Top-3 actions: pull from cross-drift + briefing
  const briefing = await api("/api/policy/executive-briefing");
  const top3 = (briefing?.top_risks || []).slice(0, 3);

  el.innerHTML = `
    <div class="card">
      <h2>Fleet compliance</h2>
      <div style="display:flex;align-items:baseline;gap:10px">
        <div style="font-size:42px;font-weight:700">${pct}%</div>
        <div style="color:var(--muted)">${tot_pass} pass · ${tot_fail} fail · ${tot_na} N/A across ${(j.policies||[]).length} policies</div>
      </div>
      <div class="compliance-bar">
        <div class="pass" style="width:${pct}%"></div>
        <div class="fail" style="width:${tot_pass+tot_fail ? Math.round(tot_fail/(tot_pass+tot_fail)*100) : 0}%"></div>
      </div>
    </div>

    <div class="card top3">
      <h2>Top 3 actions this week</h2>
      ${top3.length ? top3.map((r, i) => `<div class="item">
        <div class="num">${i+1}</div>
        <div>
          <div style="font-weight:600">${esc(r.title)}</div>
          <div class="why">${esc(r.why)}</div>
          <div style="color:var(--accent2);font-size:12px;margin-top:4px"><strong>Action:</strong> ${esc(r.action)}</div>
        </div>
        <div>${sevPill(r.severity)}</div>
      </div>`).join('') : '<div class="empty">No top-priority risks detected. Continue periodic drift evaluation.</div>'}
      <div style="margin-top:14px;display:flex;gap:8px">
        <button class="btn" onclick="switchTab('remediation')">→ Open Remediation</button>
        <button class="btn secondary" onclick="downloadFixTopRisks()">⬇ Download top-5 fix playbook</button>
      </div>
    </div>

    <div class="card">
      <h2>Per-policy compliance</h2>
      ${(j.policies||[]).length ? `<table>
        <thead><tr><th>Policy</th><th>State</th><th>Pass</th><th>Fail</th><th>Coverage</th><th>Action</th></tr></thead>
        <tbody>
          ${j.policies.map(p => `<tr>
            <td><strong>${esc(p.policy_name)}</strong><div style="color:var(--muted);font-size:11px"><code>${esc(p.policy_id)}</code></div></td>
            <td>${sevPill(p.state==='approved'?'good':p.state==='draft'?'medium':'info')} ${esc(p.state)}</td>
            <td style="color:var(--good)">${p.pass}</td>
            <td style="color:${p.fail>0?'var(--bad)':'var(--muted)'}">${p.fail}</td>
            <td>${p.coverage_pct}%</td>
            <td>
              <button class="btn secondary" onclick="evaluatePolicy('${esc(p.policy_id)}')">Re-evaluate</button>
              <button class="btn ghost" onclick="showDeviceDiff('${esc(p.policy_id)}')">Show device diff →</button>
            </td>
          </tr>`).join('')}
        </tbody>
      </table>` : '<div class="empty">No policies yet — create one in the Builder tab.</div>'}
    </div>
  `;
}

window.evaluatePolicy = async (pid) => {
  const r = await api(`/api/policy/${encodeURIComponent(pid)}/evaluate`, {method: "POST"});
  if (r) {
    alert(`Re-evaluated. Pass=${r.pass_count}, Fail=${r.fail_count}, Coverage=${r.coverage_pct}%`);
    renderCompliance();
  }
};

// v6.5 — Per-device diff modal. Pick a failing asset for this policy
// and render the line-by-line config delta in the device's syntax.
window.showDeviceDiff = async (pid) => {
  // Pull the latest evaluation rows so we can offer a smart asset pick.
  const ev = await api(`/api/policy/${encodeURIComponent(pid)}`);
  if (!ev) return;
  // Fetch fleet to enumerate possible asset_ids — start with assets
  // whose asset_type matches the policy's targets.
  const inv = await api("/api/platform/inventory");
  const assets = (inv && inv.assets) || [];
  const targets = ev.target_asset_types || [];
  const candidates = targets.length
    ? assets.filter(a => targets.includes((a.identity||{}).asset_type))
    : assets;
  if (!candidates.length) {
    alert("No assets in scope for this policy. Build the inventory first or load demo data.");
    return;
  }
  const choices = candidates.map(a => (a.identity||{}).asset_id).filter(Boolean);
  const aid = window.prompt(
    `Show device diff for which asset?\\n\\nIn-scope assets:\\n  ${choices.slice(0, 20).join('\\n  ')}` +
    (choices.length > 20 ? `\\n  ... +${choices.length - 20} more` : ''),
    choices[0] || ""
  );
  if (!aid) return;
  const diff = await api(
    `/api/policy/${encodeURIComponent(pid)}/diff/${encodeURIComponent(aid)}`
  );
  if (!diff) return;
  renderDiffModal(diff);
};

function renderDiffModal(diff) {
  const container = document.getElementById("diffModal") || (() => {
    const d = document.createElement("div");
    d.id = "diffModal";
    d.style.cssText = "position:fixed;top:0;left:0;right:0;bottom:0;"
      + "background:rgba(0,0,0,0.6);z-index:9999;display:flex;"
      + "align-items:center;justify-content:center;padding:20px";
    document.body.appendChild(d);
    return d;
  })();
  const failing = (diff.controls || []).filter(c =>
    c.status === "fail" || c.status === "unknown");
  const ok = (diff.controls || []).filter(c => c.status === "pass");
  container.innerHTML = `
    <div style="background:var(--panel);max-width:1200px;max-height:90vh;
                width:100%;overflow:auto;border-radius:10px;
                border:1px solid var(--border);padding:24px">
      <div style="display:flex;justify-content:space-between;align-items:start;
                  margin-bottom:14px">
        <div>
          <h2 style="margin:0">${esc(diff.asset_id)}
            <span style="color:var(--muted);font-size:13px">
              (${esc(diff.asset_vendor || 'unknown')})
            </span>
          </h2>
          <div style="color:var(--muted);font-size:13px;margin-top:4px">
            Policy: <strong>${esc(diff.policy_name)}</strong> ·
            Translator: <code>${esc(diff.translator || 'none — manual review')}</code>
          </div>
        </div>
        <button class="btn ghost" onclick="document.getElementById('diffModal').remove()">
          Close ✕
        </button>
      </div>

      <div class="card" style="margin:0 0 12px 0">
        <strong>${esc(diff.summary || '')}</strong>
        <div style="color:var(--muted);font-size:12px;margin-top:6px">
          ${diff.evaluation.fail_count} fail ·
          ${diff.evaluation.pass_count} pass ·
          ${diff.evaluation.na_count} N/A across
          ${diff.evaluation.control_count} controls.
        </div>
      </div>

      ${failing.length ? failing.map(c => `
        <div class="card" style="margin:0 0 10px 0;
                                  border-left:4px solid ${
            c.severity==='critical'?'var(--bad)':c.severity==='high'?'#f59e0b':'var(--muted)'
          }">
          <div style="display:flex;justify-content:space-between;
                      align-items:baseline;margin-bottom:6px">
            <div><code><strong>${esc(c.control_id)}</strong></code>
              ${sevPill(c.severity)}
              <span style="color:var(--muted);font-size:12px">
                · status: ${esc(c.status)}</span>
            </div>
            <div style="color:var(--muted);font-size:12px">
              ${c.lines_already_satisfied} satisfied · ${c.lines_to_add} to add
            </div>
          </div>
          ${c.evidence ? `<div style="color:var(--muted);font-size:12px;
                                       margin-bottom:6px">
              ${esc(c.evidence)}</div>` : ''}
          ${c.translator_notes ? `<div style="color:var(--muted);
                                                font-size:11px;margin-bottom:6px;
                                                font-style:italic">
              ${esc(c.translator_notes)}</div>` : ''}
          ${c.fix && c.fix.length ? `
            <pre style="background:var(--bg);padding:10px;border-radius:6px;
                        overflow-x:auto;font-size:12px;margin:6px 0">${
              c.fix.map(ann => {
                const mark = ann.already_present ? '✓' : '+';
                const color = ann.already_present
                  ? 'color:var(--good)' : 'color:var(--accent)';
                return `<span style="${color}">${mark}</span> ${esc(ann.line)}`;
              }).join('\\n')
            }</pre>` : '<div class="empty" style="padding:8px">No translator output for this control on this vendor.</div>'}
          ${c.verify && c.verify.length ? `
            <div style="color:var(--muted);font-size:11px;margin-top:6px">
              <strong>Verify:</strong> ${c.verify.slice(0,2).map(v=>'<code>'+esc(v)+'</code>').join(' · ')}
            </div>` : ''}
        </div>
      `).join('') : '<div class="empty">No failing controls — this asset already satisfies the policy.</div>'}

      ${diff.unified_diff ? `
        <details style="margin-top:14px">
          <summary style="cursor:pointer;color:var(--muted);font-size:12px">
            Show unified diff (paste into git apply / change-management)
          </summary>
          <pre style="background:var(--bg);padding:10px;border-radius:6px;
                      overflow-x:auto;font-size:11px;margin-top:6px;
                      white-space:pre-wrap">${esc(diff.unified_diff)}</pre>
        </details>` : ''}

      <div style="margin-top:14px;display:flex;gap:8px">
        <button class="btn" onclick="copyDiffToClipboard()">Copy fix commands</button>
        <button class="btn ghost" onclick="document.getElementById('diffModal').remove()">
          Close
        </button>
      </div>
    </div>
  `;
  // Stash the payload so the copy button can grab it without a re-fetch.
  window._lastDiff = diff;
}

window.copyDiffToClipboard = () => {
  const d = window._lastDiff;
  if (!d) return;
  const lines = [];
  lines.push(`# ${d.asset_id} — ${d.policy_name}`);
  for (const c of (d.controls || [])) {
    if (c.status !== "fail" && c.status !== "unknown") continue;
    lines.push(`# ----- ${c.control_id} (${c.severity}) -----`);
    for (const ann of (c.fix || [])) {
      if (!ann.already_present && ann.line.trim()) {
        lines.push(ann.line);
      }
    }
    lines.push("");
  }
  navigator.clipboard.writeText(lines.join("\\n")).then(
    () => alert("Fix commands copied to clipboard."),
    () => alert("Copy failed — paste from the visible block instead.")
  );
};

window.downloadFixTopRisks = async () => {
  const r = await fetch("/api/policy/fix-top-risks?top=5&format=ansible", {
    headers: TOKEN() ? {Authorization: "Bearer " + TOKEN()} : {},
  });
  const txt = await r.text();
  const blob = new Blob([txt], {type: "text/yaml"});
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `safecadence-top5-fix-${new Date().toISOString().split("T")[0]}.yml`;
  a.click();
};

// =====================================================================
// Tab: DRIFT
// =====================================================================

async function renderDrift() {
  const el = $("#tab-drift");
  const policies = (await api("/api/policy/")) ?? {policies: []};
  el.innerHTML = `
    <div class="card">
      <h2>Drift detection</h2>
      <p style="color:var(--muted)">Compares the most recent two evaluations of a policy and surfaces controls that regressed (PASS → FAIL) or improved.</p>
      <div style="display:flex;gap:8px;margin-top:14px">
        <select id="driftPid" style="flex:1;max-width:400px">
          <option value="">Pick a policy...</option>
          ${(policies.policies||[]).map(p => `<option value="${esc(p.policy_id)}">${esc(p.policy_name)} (${esc(p.policy_id)})</option>`).join('')}
        </select>
        <button class="btn" onclick="loadDrift()">Show drift</button>
      </div>
      <div id="driftOut" style="margin-top:14px"></div>
    </div>
  `;
}

window.loadDrift = async () => {
  const pid = $("#driftPid").value;
  if (!pid) return;
  $("#driftOut").innerHTML = '<div class="empty">⏳</div>';
  const r = await api(`/api/policy/${encodeURIComponent(pid)}/drift`);
  if (!r) return;
  const regs = r.regressions || [];
  const imps = r.improvements || [];
  const hist = r.history_size || 0;

  // v6.5.1 — actionable empty-state. Drift requires ≥2 evaluations to
  // produce anything meaningful; explain that to the user and give them
  // a one-click way to take a snapshot now.
  let empty = '';
  if (hist < 2) {
    empty = `<div class="card" style="border:1px dashed var(--border);
              background:rgba(59,130,246,0.04);margin-top:14px">
      <h3 style="margin:0 0 8px">⚠ Not enough history yet</h3>
      <p style="color:var(--muted);margin:0 0 12px">
        Drift compares the <strong>two most recent evaluations</strong> of this policy.
        You currently have <strong>${hist}</strong> snapshot${hist === 1 ? '' : 's'}
        for this policy — drift needs at least 2 to compute regressions.
      </p>
      <p style="color:var(--muted);margin:0 0 12px;font-size:12px">
        How to populate it:
        <br>• Click <strong>Evaluate now</strong> below to take a snapshot, then
        click it again later (after a config change) to see what changed.
        <br>• Or run <code>safecadence daemon</code> in a terminal — every cycle
        persists a fresh snapshot automatically.
      </p>
      <button class="btn" onclick="evaluateAndReloadDrift('${esc(pid)}')">
        📸 Evaluate now (take snapshot)
      </button>
    </div>`;
  }

  $("#driftOut").innerHTML = `
    <div class="row">
      <div class="stat"><h3>History</h3><div class="v">${hist}</div><div class="sub">evaluations</div></div>
      <div class="stat"><h3>Regressions</h3><div class="v" style="color:var(--bad)">${regs.length}</div></div>
      <div class="stat"><h3>Improvements</h3><div class="v" style="color:var(--good)">${imps.length}</div></div>
      ${r.trend ? `<div class="stat"><h3>Pass-rate Δ</h3>
        <div class="v" style="color:${r.trend.delta>=0?'var(--good)':'var(--bad)'}">${r.trend.delta>=0?'+':''}${r.trend.delta}%</div>
        <div class="sub">${r.trend.previous_pass_pct}% → ${r.trend.current_pass_pct}%</div></div>` : ''}
    </div>
    ${empty}
    ${regs.length ? `<div class="card"><h2>Regressions</h2><table>
      <thead><tr><th>Asset</th><th>Control</th><th>From</th><th>To</th></tr></thead>
      <tbody>${regs.map(r => `<tr>
        <td><code>${esc(r.asset_id)}</code></td>
        <td><code>${esc(r.control_id)}</code></td>
        <td>${sevPill('good')} ${esc(r.from)}</td>
        <td>${sevPill('high')} ${esc(r.to)}</td>
      </tr>`).join('')}</tbody></table></div>` : ''}
    ${imps.length ? `<div class="card"><h2>Improvements</h2><table>
      <thead><tr><th>Asset</th><th>Control</th><th>From</th><th>To</th></tr></thead>
      <tbody>${imps.map(r => `<tr>
        <td><code>${esc(r.asset_id)}</code></td>
        <td><code>${esc(r.control_id)}</code></td>
        <td>${sevPill('high')} ${esc(r.from)}</td>
        <td>${sevPill('good')} ${esc(r.to)}</td>
      </tr>`).join('')}</tbody></table></div>` : ''}
  `;
};

window.evaluateAndReloadDrift = async (pid) => {
  $("#driftOut").innerHTML = '<div class="empty">⏳ Taking snapshot…</div>';
  const r = await api(`/api/policy/${encodeURIComponent(pid)}/evaluate`,
    {method: "POST"});
  if (!r) return;
  // Re-load drift — should now show history+1.
  loadDrift();
};

// =====================================================================
// Tab: REMEDIATION
// =====================================================================

async function renderRemediation() {
  const el = $("#tab-remediation");
  const policies = (await api("/api/policy/")) ?? {policies: []};
  el.innerHTML = `
    <div class="card">
      <h2>Generate remediation</h2>
      <p style="color:var(--muted)">Pick a policy and a target format. SafeCadence generates the fix
        commands, rollback steps, and verification commands per asset — never executes.</p>
      <div style="display:grid;grid-template-columns:2fr 1fr 1fr auto;gap:10px;margin-top:14px;align-items:end">
        <div>
          <label style="color:var(--muted);font-size:12px;display:block;margin-bottom:4px">Policy</label>
          <select id="remPid" style="width:100%">
            <option value="(top-5)">⚡ Top 5 highest-priority across ALL policies</option>
            ${(policies.policies||[]).map(p => `<option value="${esc(p.policy_id)}">${esc(p.policy_name)}</option>`).join('')}
          </select>
        </div>
        <div>
          <label style="color:var(--muted);font-size:12px;display:block;margin-bottom:4px">Format</label>
          <select id="remFmt" style="width:100%">
            <option value="ansible">Ansible playbook</option>
            <option value="terraform">Terraform HCL</option>
            <option value="powershell">PowerShell</option>
            <option value="bash">Bash</option>
            <option value="markdown">Markdown runbook</option>
            <option value="raw">Raw configs</option>
          </select>
        </div>
        <div>
          <label style="color:var(--muted);font-size:12px;display:block;margin-bottom:4px">Vendor (optional)</label>
          <select id="remVendor" style="width:100%">
            <option value="">(auto)</option>
            <option>cisco_ios</option><option>cisco_nxos</option><option>cisco_asa</option>
            <option>arista_eos</option><option>juniper_junos</option>
            <option>fortinet_fortios</option><option>paloalto_panos</option>
            <option>linux</option><option>windows</option>
            <option>aws_iam</option><option>azure</option><option>gcp</option>
            <option>cisco_ise</option><option>clearpass_role</option>
            <option>ad_gpo</option><option>azure_ca</option>
          </select>
        </div>
        <button class="btn" onclick="loadRemediation()">Generate</button>
      </div>
      <pre id="remOut" style="margin-top:14px;display:none"></pre>
    </div>
  `;
}

window.loadRemediation = async () => {
  const pid = $("#remPid").value;
  const fmt = $("#remFmt").value;
  const v = $("#remVendor").value;
  $("#remOut").style.display = "block";
  $("#remOut").textContent = "⏳ Generating...";
  let url;
  if (pid === "(top-5)") {
    url = `/api/policy/fix-top-risks?top=5&format=${fmt}`;
  } else {
    url = `/api/policy/${encodeURIComponent(pid)}/export?format=${fmt}${v?'&vendor='+v:''}`;
  }
  const r = await fetch(url, {
    headers: TOKEN() ? {Authorization: "Bearer " + TOKEN()} : {},
  });
  const txt = await r.text();
  $("#remOut").textContent = txt;
};

// =====================================================================
// Tab: EXCEPTIONS
// =====================================================================

async function renderExceptions() {
  const el = $("#tab-exceptions");
  const policies = (await api("/api/policy/")) ?? {policies: []};
  el.innerHTML = `
    <div class="card">
      <h2>Risk-acceptance exceptions</h2>
      <p style="color:var(--muted)">Sometimes you can't fix a violation right now. Document it formally —
        with justification, approver, and an expiry date. Auditors love this.</p>
      <div style="display:flex;gap:8px;margin-top:14px">
        <select id="exPid" style="flex:1;max-width:400px">
          <option value="">Pick a policy...</option>
          ${(policies.policies||[]).map(p => `<option value="${esc(p.policy_id)}">${esc(p.policy_name)}</option>`).join('')}
        </select>
        <button class="btn secondary" onclick="loadExceptions()">List exceptions</button>
      </div>
      <pre id="exOut" style="margin-top:14px;display:none"></pre>
    </div>
  `;
}

window.loadExceptions = async () => {
  const pid = $("#exPid").value;
  if (!pid) return;
  $("#exOut").style.display = "block";
  $("#exOut").textContent = "⏳";
  const r = await api(`/api/policy/${encodeURIComponent(pid)}/exceptions`);
  $("#exOut").textContent = JSON.stringify(r, null, 2);
};

// =====================================================================
// Tab: AUDIT
// =====================================================================

async function renderAudit() {
  const el = $("#tab-audit");
  el.innerHTML = '<div class="empty">⏳ Loading audit log…</div>';
  // Pull both the policy audit and the v7.0 execution audit so the
  // operator sees a unified timeline. They're written to two different
  // files but the operator doesn't care.
  const [policyAudit, execAudit] = await Promise.all([
    api("/api/policy/audit?limit=200"),
    api("/api/execute/audit?limit=200").catch(() => ({entries: []})),
  ]);
  const events = (policyAudit?.events || []).map(e => ({
    timestamp: e.ts || e.timestamp || "",
    actor: e.actor || "",
    action: e.action || "",
    job_id: "", policy_id: e.policy_id || "",
    detail: typeof e.detail === "string" ? e.detail
              : JSON.stringify(e.detail || {}),
    source: "policy",
  })).concat((execAudit?.entries || []).map(e => ({
    timestamp: e.timestamp || "",
    actor: e.actor || "",
    action: e.action || "",
    job_id: e.job_id || "",
    policy_id: "",
    detail: e.detail || "",
    source: "execution",
  })));
  events.sort((a, b) => (b.timestamp || "").localeCompare(a.timestamp || ""));

  el.innerHTML = `
    <div class="card">
      <h2>Audit log</h2>
      <p style="color:var(--muted)">Append-only record of every policy + execution action.
        Combines <code>~/.safecadence/policy_audit-*.jsonl</code> and
        <code>~/.safecadence/execution/audit/audit.log</code>.</p>
      <div style="display:flex;gap:8px;margin:10px 0;flex-wrap:wrap">
        <input id="auditFilter" placeholder="Filter (actor / action / policy / job)..." style="flex:1;min-width:240px" />
        <select id="auditSource">
          <option value="">all sources</option>
          <option value="policy">policy</option>
          <option value="execution">execution</option>
        </select>
        <button class="btn secondary" onclick="exportAuditCsv()">⬇ CSV</button>
      </div>
      <div id="auditOut">${renderAuditTable(events)}</div>
    </div>
  `;
  // Stash for the filter handler + CSV exporter
  window._auditEvents = events;
  $("#auditFilter").addEventListener("input", filterAudit);
  $("#auditSource").addEventListener("change", filterAudit);
}

function renderAuditTable(events) {
  if (!events.length) {
    return '<div class="empty">No events yet. Create a policy, evaluate, or submit a job to populate.</div>';
  }
  return `<table>
    <thead><tr><th>Time</th><th>Source</th><th>Actor</th><th>Action</th><th>Subject</th><th>Detail</th></tr></thead>
    <tbody>${events.slice(0, 500).map(e => `<tr>
      <td style="white-space:nowrap;font-size:11px;color:var(--muted)">${esc((e.timestamp || '').slice(0, 19))}</td>
      <td><span class="pill ${e.source === 'execution' ? 'warn' : 'good'}">${esc(e.source)}</span></td>
      <td>${esc(e.actor || '')}</td>
      <td><code>${esc(e.action || '')}</code></td>
      <td style="font-size:11px"><code>${esc(e.job_id || e.policy_id || '')}</code></td>
      <td style="font-size:11px;color:var(--muted)">${esc((e.detail || '').slice(0, 120))}</td>
    </tr>`).join('')}</tbody>
  </table>`;
}

window.filterAudit = () => {
  const f = ($("#auditFilter").value || "").toLowerCase();
  const src = $("#auditSource").value;
  const filtered = (window._auditEvents || []).filter(e => {
    if (src && e.source !== src) return false;
    if (!f) return true;
    return [e.actor, e.action, e.policy_id, e.job_id, e.detail]
      .some(v => (v || "").toLowerCase().includes(f));
  });
  $("#auditOut").innerHTML = renderAuditTable(filtered);
};

window.exportAuditCsv = () => {
  const rows = window._auditEvents || [];
  const cols = ["timestamp", "source", "actor", "action",
                 "policy_id", "job_id", "detail"];
  const csv = [cols.join(",")].concat(rows.map(r =>
    cols.map(c => '"' + String(r[c] || "").replace(/"/g, '""') + '"').join(",")
  )).join("\\n");
  const blob = new Blob([csv], {type: "text/csv"});
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `safecadence-audit-${new Date().toISOString().split("T")[0]}.csv`;
  a.click();
};

// =====================================================================
// Tab: SETTINGS
// =====================================================================

async function renderSettings() {
  const el = $("#tab-settings");
  el.innerHTML = '<div class="empty">⏳ Loading settings…</div>';
  // v9.25: hydrate Splunk fields once the markup is in the DOM. The
  // existing per-card await chain below populates lic/rbac/totp; we
  // run loadSplunk() on the next tick so $("#splUrl") exists.
  setTimeout(() => { try { window.loadSplunk && window.loadSplunk(); } catch(e){} }, 50);
  // Pull live state for the cards that depend on the server.
  const [lic, rbacInfo, totp] = await Promise.all([
    api("/api/platform/license").catch(() => null),
    api("/api/execute/rbac").catch(() => null),
    api("/api/execute/totp/status").catch(() => null),
  ]);
  el.innerHTML = `
    <div class="card">
      <h2>Bearer token</h2>
      <p style="color:var(--muted)">Paste your JWT here if you're hitting a server-mode SafeCadence.</p>
      <input id="tokInput" placeholder="Bearer token..." style="width:100%;font-family:ui-monospace,Menlo,monospace" value="${esc(TOKEN())}" />
      <div style="display:flex;gap:8px;margin-top:10px">
        <button class="btn" onclick="localStorage.setItem('SC_TOKEN', $('#tokInput').value); alert('Saved.')">Save</button>
        <button class="btn secondary" onclick="localStorage.removeItem('SC_TOKEN'); $('#tokInput').value=''; alert('Cleared.')">Clear</button>
      </div>
    </div>

    <div class="card">
      <h2>License</h2>
      ${lic ? `
        <div style="display:grid;grid-template-columns:auto 1fr;gap:8px 18px;font-size:13px">
          <div style="color:var(--muted)">Licensee</div><div><strong>${esc(lic.licensee || '—')}</strong></div>
          <div style="color:var(--muted)">Assets</div>
          <div>${lic.asset_count} of ${lic.max_assets || '∞'}
            ${lic.over_limit ? '<span class="pill bad">OVER LIMIT</span>' : ''}</div>
          <div style="color:var(--muted)">Signature</div>
          <div>${esc(lic.signature_state || '—')}</div>
          <div style="color:var(--muted)">Expires</div>
          <div>${esc(lic.expires_at || '(no expiry)')}</div>
          <div style="color:var(--muted)">Features</div>
          <div>${(lic.features || []).map(f=>'<span class="pill">'+esc(f)+'</span>').join(' ')}</div>
        </div>` : '<div class="empty">License endpoint unavailable.</div>'}
    </div>

    <div class="card">
      <h2>Your role + capabilities</h2>
      ${rbacInfo ? `
        <div>Role: <strong>${esc(rbacInfo.role)}</strong> — ${(rbacInfo.capabilities||[]).length} capabilities</div>
        <details style="margin-top:8px">
          <summary style="cursor:pointer;color:var(--muted);font-size:12px">List capabilities</summary>
          <pre style="font-size:11px">${(rbacInfo.capabilities||[]).join('\\n')}</pre>
        </details>` : '<div class="empty">RBAC endpoint unavailable.</div>'}
    </div>

    <div class="card">
      <h2>TOTP enrollment (Tier3 SSH)</h2>
      <p style="color:var(--muted)">Required before you can fire real SSH execution from the API.</p>
      <div>Status:
        <strong style="color:${totp?.enrolled ? 'var(--good)' : 'var(--warn)'}">
          ${totp?.enrolled ? 'enrolled' : 'NOT enrolled'}
        </strong>
      </div>
      <div style="margin-top:10px">
        <button class="btn" onclick="enrollTotp()">${totp?.enrolled ? 'Re-enroll' : 'Enroll TOTP'}</button>
      </div>
    </div>

    <div class="card">
      <h2>BYO-AI provider</h2>
      <p style="color:var(--muted)">SafeCadence calls the AI provider directly from your machine — no key ever touches a SafeCadence server. Set one of these env vars before you launch <code>safecadence ui</code>:</p>
      <pre>export OPENAI_API_KEY=sk-...
export ANTHROPIC_API_KEY=sk-ant-...
export OLLAMA_HOST=http://127.0.0.1:11434   # local LLM, air-gap friendly</pre>
    </div>

    <div class="card">
      <h2>Notifications</h2>
      <p style="color:var(--muted)">Outbound channels for the daemon's critical-finding alerts.
        Set per-channel webhook URLs as env vars (server-side):</p>
      <pre>export SC_SLACK_WEBHOOK="https://hooks.slack.com/services/..."
export SC_TEAMS_WEBHOOK="https://acme.webhook.office.com/..."
export SC_PAGERDUTY_URL="https://events.pagerduty.com/v2/enqueue?routing_key=..."
export SC_WEBHOOK_SIGNING_SECRET="your-shared-secret"   # HMAC-SHA256
export SC_SMTP_HOST="smtp.acme.com"
export SC_DIGEST_RECIPIENTS="security@acme.com,netops@acme.com"</pre>
      <div style="display:flex;gap:8px;margin-top:10px">
        <button class="btn secondary" onclick="previewDigest()">Preview digest</button>
        <button class="btn secondary" onclick="sendDigest()">Send digest now</button>
      </div>
      <pre id="digestOut" style="margin-top:10px;display:none;max-height:300px;overflow:auto;font-size:11px"></pre>
    </div>

    <!-- v9.25: Splunk HEC panel -->
    <div class="card" id="splunkCard">
      <h2>Splunk (HEC outbound)</h2>
      <p style="color:var(--muted)">
        Push every finding, score change, and weak-link alert into Splunk
        as a stream of events. Searchable as <code>source=safecadence</code>.
        Token field is masked once saved; leave it as-is to keep the
        existing token, or paste a new one to overwrite.
      </p>
      <div style="display:grid;grid-template-columns:auto 1fr;gap:8px 12px;margin-top:8px;font-size:13px;align-items:center">
        <label>HEC URL</label>
        <input id="splUrl" placeholder="https://splunk.example.com:8088/services/collector"
               style="width:100%;font-family:ui-monospace,Menlo,monospace" />
        <label>HEC token</label>
        <input id="splTok" type="password"
               placeholder="paste token, or leave masked to keep existing"
               style="width:100%;font-family:ui-monospace,Menlo,monospace" />
        <label>Index</label>
        <input id="splIdx" placeholder="(optional — token's default if blank)"
               style="width:100%;font-family:ui-monospace,Menlo,monospace" />
        <label>Source</label>
        <input id="splSrc" placeholder="safecadence"
               style="width:100%;font-family:ui-monospace,Menlo,monospace" />
        <label>Sourcetype</label>
        <input id="splST"  placeholder="safecadence:event"
               style="width:100%;font-family:ui-monospace,Menlo,monospace" />
        <label><input type="checkbox" id="splOn" /> Enabled</label>
        <span></span>
      </div>
      <div style="display:flex;gap:8px;margin-top:10px;flex-wrap:wrap">
        <button class="btn" onclick="saveSplunk()">Save</button>
        <button class="btn secondary" onclick="testSplunk()">Send test event</button>
        <span id="splOut" style="font-size:12px;color:var(--muted);align-self:center"></span>
      </div>
    </div>

    <div class="card">
      <h2>Compliance evidence pack</h2>
      <p style="color:var(--muted)">Auditor-ready PDF, one per framework.</p>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        ${["nist","cis","pci","hipaa","iso","zerotrust"].map(f =>
          `<a class="btn ghost" href="/api/platform/evidence-pack?framework=${f}" target="_blank">${f.toUpperCase()}.pdf</a>`).join('')}
      </div>
    </div>

    <div class="card">
      <h2>Storage backend</h2>
      <p style="color:var(--muted)">Set <code>DATABASE_URL</code> to switch from file-backed JSON
        to Postgres. Both work; file-backed JSON is the air-gap-friendly default.</p>
    </div>

    <div class="card">
      <h2>Useful links</h2>
      <ul>
        <li><a href="/api/docs" target="_blank">OpenAPI / Swagger UI</a></li>
        <li><a href="/api/platform/ui" target="_blank">Platform UI (v4 inventory)</a></li>
        <li><a href="https://github.com/famousleads/safecadence-network-risk" target="_blank">GitHub repo</a></li>
        <li><a href="https://pypi.org/project/safecadence-netrisk/" target="_blank">PyPI</a></li>
      </ul>
    </div>
  `;
}

window.enrollTotp = async () => {
  const r = await api("/api/execute/totp/enroll", {method: "POST"});
  if (!r) return;
  alert(`TOTP secret:\\n\\n${r.secret}\\n\\nAdd to your authenticator app.\\nOr scan: ${r.otpauth_uri}`);
  renderSettings();
};

window.previewDigest = async () => {
  const r = await api("/api/platform/digest/preview");
  if (!r) return;
  $("#digestOut").style.display = "block";
  $("#digestOut").textContent = r.text;
};

window.sendDigest = async () => {
  const r = await api("/api/platform/digest/send", {method: "POST"});
  if (!r) return;
  alert(r.sent ? "Sent: " + (r.recipients || []).join(", ")
                : "Failed: " + (r.reason || "unknown"));
};

// v9.25 — Splunk HEC settings panel handlers
window.loadSplunk = async () => {
  const c = await api("/api/settings/splunk");
  if (!c) return;
  $("#splUrl").value = c.hec_url || "";
  $("#splTok").value = c.hec_token || "";   // already masked server-side
  $("#splIdx").value = c.index || "";
  $("#splSrc").value = c.source || "safecadence";
  $("#splST").value  = c.sourcetype || "safecadence:event";
  $("#splOn").checked = !!c.enabled;
};

window.saveSplunk = async () => {
  const out = $("#splOut");
  out.textContent = "Saving…";
  const r = await api("/api/settings/splunk", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({
      hec_url:    $("#splUrl").value,
      hec_token:  $("#splTok").value,
      index:      $("#splIdx").value,
      source:     $("#splSrc").value,
      sourcetype: $("#splST").value,
      enabled:    $("#splOn").checked,
    }),
  });
  if (!r) { out.textContent = "Save failed."; return; }
  // Refresh masked token + flash confirmation.
  $("#splTok").value = r.hec_token || "";
  out.textContent = "Saved.";
  setTimeout(() => { out.textContent = ""; }, 2500);
};

window.testSplunk = async () => {
  const out = $("#splOut");
  out.textContent = "Sending test event…";
  const r = await api("/api/settings/splunk/test", {method: "POST"});
  if (!r) { out.textContent = "Test failed (no response)."; return; }
  out.textContent = r.sent
    ? `OK — Splunk responded ${r.status || ""}.`
    : `Failed: ${r.reason || "unknown"}`;
};

// =====================================================================
// Global "Ask" bar — routes to the right tab
// =====================================================================

$("#askBar").addEventListener("keydown", async (e) => {
  if (e.key !== "Enter") return;
  const q = e.target.value.trim();
  if (!q) return;
  e.target.value = "";
  // Heuristic routing: question? → chat; intent statement? → interpreter
  const isChat = /^(how|how many|what|which|show|list|where|who|why|when)\b/i.test(q);
  if (isChat) {
    switchTab("interpreter");
    // Use the chat-with-fleet endpoint
    const r = await api("/api/policy/chat", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({question: q, ai: !!$("#useAI")?.checked}),
    });
    CHAT.history.push({role: "user", text: q});
    CHAT.history.push({role: "ai", policy: {source: r.source||"offline",
      controls: [], policy_name: "(answered via fleet chat)"},
      answer: r.answer, idx: CHAT.history.length});
    chatPersist();
    renderInterpreter();
    // Append the answer text after the standard chat msg
    setTimeout(() => {
      const last = $$("#chatMsgs .chat-msg").pop();
      if (last) last.querySelector(".body").innerHTML +=
        `<div style="margin-top:10px;padding-top:10px;border-top:1px solid var(--border);white-space:pre-wrap">${esc(r.answer||"")}</div>`;
    }, 50);
  } else {
    switchTab("interpreter");
    setTimeout(() => chatSubmit(q), 200);
  }
});

// =====================================================================
// Tab switcher
// =====================================================================

const RENDERERS = {
  builder: renderBuilder,
  interpreter: renderInterpreter,
  compliance: renderCompliance,
  drift: renderDrift,
  remediation: renderRemediation,
  command:    renderCommandCenter,
  approvals:  renderApprovals,
  execqueue:  renderExecutionQueue,
  rollback:   renderRollbackManager,
  exceptions: renderExceptions,
  audit: renderAudit,
  settings: renderSettings,
};

// =====================================================================
// v7.0 — Command Center (AI Command Builder + draft jobs)
// =====================================================================

async function renderCommandCenter() {
  const el = $("#tab-command");
  const rbac = await api("/api/execute/rbac") || {role:"viewer", capabilities:[]};
  el.innerHTML = `
    <div class="card">
      <h2>⚡ Command Center</h2>
      <p style="color:var(--muted)">
        Plan and submit command jobs across your fleet. Type natural language —
        SafeCadence picks the right vendor commands, classifies the risk, runs
        guardrails, and routes for approval. Real execution happens via your
        existing Ansible/Salt/NSO pipeline.
      </p>
      <div style="display:flex;gap:8px;margin-top:14px">
        <input id="cmdIntent" placeholder="e.g. Check BGP and interface errors on all Cisco routers"
               style="flex:1;font-size:14px" />
        <button class="btn" onclick="cmdPlanIntent()">Plan</button>
        <button class="btn secondary" onclick="cmdPlanAndSubmit()">Plan + Submit for review</button>
      </div>
      <div id="cmdPlanOut" style="margin-top:14px"></div>
      <div style="color:var(--muted);font-size:12px;margin-top:14px">
        You are: <code>${esc(rbac.role)}</code> — ${(rbac.capabilities||[]).length} capabilities.
      </div>
    </div>

    <div class="card" style="margin-top:14px">
      <h2>Recent draft jobs</h2>
      <div id="cmdRecent"><div class="empty">⏳</div></div>
    </div>
  `;
  cmdLoadRecent();
}

window.cmdPlanIntent = async () => {
  const intent = $("#cmdIntent").value.trim();
  if (!intent) return;
  const r = await api("/api/execute/builder/plan", {
    method:"POST", headers:{"Content-Type":"application/json"},
    body: JSON.stringify({intent}),
  });
  $("#cmdPlanOut").innerHTML = renderPlan(r);
};

window.cmdPlanAndSubmit = async () => {
  const intent = $("#cmdIntent").value.trim();
  if (!intent) return;
  const r = await fetch("/api/execute/builder/plan-and-save", {
    method:"POST",
    headers:{
      "Content-Type":"application/json",
      ...(TOKEN()?{Authorization:"Bearer "+TOKEN()}:{}),
    },
    body: JSON.stringify({intent, name: intent.slice(0,60)}),
  });
  if (!r.ok) {
    alert("Planner refused: " + (await r.text()));
    return;
  }
  const j = await r.json();
  // Submit for review now
  await api(`/api/execute/jobs/${encodeURIComponent(j.job.job_id)}/submit`,
            {method:"POST"});
  alert("Job created + submitted for review: " + j.job.job_id);
  cmdLoadRecent();
};

function renderPlan(p) {
  if (!p) return '<div class="empty">No plan returned.</div>';
  if (p.blocked) {
    return `<div class="card" style="border-left:4px solid var(--bad)">
      <h3>🚫 BLOCKED</h3>
      ${(p.block_reasons||[]).map(r=>`<div>${esc(r)}</div>`).join('')}
    </div>`;
  }
  if (!(p.matched_packs||[]).length) {
    return `<div class="empty">${esc(p.summary||'No match.')}</div>`;
  }
  return `<div class="card">
    <strong>${esc(p.summary||'')}</strong>
    <div style="margin-top:6px">
      ${(p.matched_packs||[]).map(x=>'<span class="pill">'+esc(x)+'</span>').join(' ')}
      ${sevPill(p.risk||'safe')}
    </div>
    ${(p.risk_reasons||[]).length ? `<details style="margin-top:8px;color:var(--muted);font-size:12px">
      <summary>Risk reasoning (${p.risk_reasons.length})</summary>
      <pre>${esc(p.risk_reasons.join('\\n'))}</pre>
    </details>` : ''}
    <h4 style="margin:10px 0 6px">Commands by vendor</h4>
    ${Object.entries(p.commands_by_vendor||{}).map(([v,cs])=>`
      <div style="margin-bottom:8px">
        <code><strong>${esc(v)}</strong></code>
        <pre style="background:var(--bg);padding:8px;border-radius:6px;font-size:12px">${esc(cs.join('\\n'))}</pre>
      </div>
    `).join('')}
  </div>`;
}

async function cmdLoadRecent() {
  const j = await api("/api/execute/jobs") || {jobs:[]};
  const html = (j.jobs||[]).slice(0,20).map(j=>`
    <tr>
      <td><code>${esc(j.job_id)}</code></td>
      <td>${esc(j.name||'')}</td>
      <td>${sevPill(j.risk)}</td>
      <td>${esc(j.status)}</td>
      <td>${esc(j.mode)}</td>
      <td>${(j.approvers||[]).length} / ${j.approvals_required}</td>
      <td>
        <button class="btn ghost" onclick="cmdShowJob('${esc(j.job_id)}')">Detail</button>
        ${j.status==='approved' ? `<button class="btn" onclick="cmdDryRun('${esc(j.job_id)}')">Dry-run</button>` : ''}
        ${j.status==='approved' ? `<button class="btn ghost" onclick="cmdExport('${esc(j.job_id)}')">Export Ansible</button>` : ''}
      </td>
    </tr>
  `).join('');
  $("#cmdRecent").innerHTML = (j.jobs||[]).length ? `<table>
    <thead><tr><th>ID</th><th>Name</th><th>Risk</th><th>Status</th><th>Mode</th><th>Approvals</th><th>Actions</th></tr></thead>
    <tbody>${html}</tbody></table>`
    : '<div class="empty">No jobs yet — type an intent above.</div>';
}

window.cmdShowJob = async (jid) => {
  const j = await api("/api/execute/jobs/"+encodeURIComponent(jid));
  if (!j) return;
  alert(JSON.stringify(j, null, 2));
};

window.cmdDryRun = async (jid) => {
  const r = await api("/api/execute/jobs/"+encodeURIComponent(jid)+"/dry-run",
                       {method:"POST"});
  if (r) alert("Dry-run completed against " + r.asset_count
                + " assets. Executions: " + (r.executions||[]).length
                + "  Blocked: " + (r.blocked||[]).length);
  cmdLoadRecent();
};

window.cmdExport = async (jid) => {
  const r = await fetch("/api/execute/jobs/"+encodeURIComponent(jid)+"/export?fmt=ansible",
    {headers: TOKEN() ? {Authorization:"Bearer "+TOKEN()} : {}});
  const txt = await r.text();
  const blob = new Blob([txt], {type:"text/yaml"});
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = jid + ".yml";
  a.click();
};

// =====================================================================
// v7.0 — Approval Queue
// =====================================================================

async function renderApprovals() {
  const el = $("#tab-approvals");
  const j = await api("/api/execute/jobs?status=review") || {jobs:[]};
  el.innerHTML = `
    <div class="card">
      <h2>📝 Approval Queue</h2>
      <p style="color:var(--muted)">Jobs awaiting review. Authors cannot approve their own jobs.
        Critical-risk jobs require 2 distinct approvers.</p>
      ${(j.jobs||[]).length ? `<table>
        <thead><tr><th>Job</th><th>Risk</th><th>Approvals</th><th>Author</th><th>Created</th><th>Action</th></tr></thead>
        <tbody>${j.jobs.map(jb=>`<tr>
          <td><strong>${esc(jb.name||jb.job_id)}</strong>
              <div style="color:var(--muted);font-size:11px"><code>${esc(jb.job_id)}</code></div></td>
          <td>${sevPill(jb.risk)}</td>
          <td>${(jb.approvers||[]).length} / ${jb.approvals_required}</td>
          <td>${esc(jb.created_by||'?')}</td>
          <td style="color:var(--muted);font-size:12px">${esc((jb.created_at||'').slice(0,16))}</td>
          <td>
            <button class="btn" onclick="approveJob('${esc(jb.job_id)}')">Approve</button>
            <button class="btn secondary" onclick="rejectJob('${esc(jb.job_id)}')">Reject</button>
          </td>
        </tr>`).join('')}</tbody></table>` : '<div class="empty">No jobs awaiting review.</div>'}
    </div>`;
}

window.approveJob = async (jid) => {
  const note = prompt("Optional note:");
  const r = await fetch("/api/execute/jobs/"+encodeURIComponent(jid)+"/approve", {
    method:"POST",
    headers:{"Content-Type":"application/json",
      ...(TOKEN()?{Authorization:"Bearer "+TOKEN()}:{})},
    body: JSON.stringify({note: note||""}),
  });
  if (!r.ok) { alert("Approve failed: " + (await r.text())); return; }
  alert("Approved.");
  renderApprovals();
};

window.rejectJob = async (jid) => {
  const reason = prompt("Reason for rejection:");
  if (!reason) return;
  const r = await fetch("/api/execute/jobs/"+encodeURIComponent(jid)+"/reject", {
    method:"POST",
    headers:{"Content-Type":"application/json",
      ...(TOKEN()?{Authorization:"Bearer "+TOKEN()}:{})},
    body: JSON.stringify({reason}),
  });
  if (!r.ok) { alert("Reject failed: " + (await r.text())); return; }
  alert("Rejected.");
  renderApprovals();
};

// =====================================================================
// v7.0 — Execution Queue + Rollback Manager
// =====================================================================

async function renderExecutionQueue() {
  const el = $("#tab-execqueue");
  const q = await api("/api/execute/queue") || {queue:[]};
  el.innerHTML = `
    <div class="card">
      <h2>📋 Execution Queue</h2>
      <p style="color:var(--muted)">Jobs in REVIEW / APPROVED / SCHEDULED / RUNNING.
        Approved jobs export to Ansible / Salt / NSO; SafeCadence does not push.</p>
      ${(q.queue||[]).length ? `<table>
        <thead><tr><th>Job</th><th>Status</th><th>Risk</th><th>Targets</th><th>Action</th></tr></thead>
        <tbody>${q.queue.map(jb=>`<tr>
          <td><code>${esc(jb.job_id)}</code> ${esc(jb.name||'')}</td>
          <td>${sevPill(jb.status==='approved'?'good':jb.status==='running'?'warn':'info')} ${esc(jb.status)}</td>
          <td>${sevPill(jb.risk)}</td>
          <td style="color:var(--muted);font-size:12px">${(jb.target_asset_ids||[]).length}+
              ${(jb.target_asset_group_ids||[]).length} groups</td>
          <td>
            ${jb.status==='approved' ? `<button class="btn" onclick="cmdDryRun('${esc(jb.job_id)}')">Dry-run</button>` : ''}
            <button class="btn ghost" onclick="cmdExport('${esc(jb.job_id)}')">Export</button>
          </td>
        </tr>`).join('')}</tbody></table>` : '<div class="empty">Queue is empty.</div>'}
    </div>`;
}

async function renderRollbackManager() {
  const el = $("#tab-rollback");
  const j = await api("/api/execute/jobs") || {jobs:[]};
  const eligible = (j.jobs||[]).filter(jb =>
    jb.rollback_plan_id && (jb.status==='done' || jb.status==='failed'));
  el.innerHTML = `
    <div class="card">
      <h2>⏮ Rollback Manager</h2>
      <p style="color:var(--muted)">Jobs whose rollback plan was generated at approval.
        Rolling back marks the job ROLLED_BACK and writes an immutable audit row.</p>
      ${eligible.length ? `<table>
        <thead><tr><th>Job</th><th>Status</th><th>Plan</th><th>Action</th></tr></thead>
        <tbody>${eligible.map(jb=>`<tr>
          <td>${esc(jb.name||jb.job_id)}<div style="color:var(--muted);font-size:11px"><code>${esc(jb.job_id)}</code></div></td>
          <td>${esc(jb.status)}</td>
          <td><code>${esc(jb.rollback_plan_id||'-')}</code></td>
          <td><button class="btn secondary" onclick="rollbackJob('${esc(jb.job_id)}')">Rollback</button></td>
        </tr>`).join('')}</tbody></table>` : '<div class="empty">No jobs are eligible for rollback yet.</div>'}
    </div>`;
}

window.rollbackJob = async (jid) => {
  if (!confirm("Roll back this job? An audit entry will be created.")) return;
  const r = await api("/api/execute/jobs/"+encodeURIComponent(jid)+"/rollback",
                       {method:"POST"});
  if (r) alert("Rolled back: " + r.status);
  renderRollbackManager();
};

function switchTab(name) {
  $$("nav.tabs button").forEach(b => b.classList.toggle("active", b.dataset.tab === name));
  $$(".tab").forEach(s => s.hidden = (s.id !== "tab-" + name));
  if (RENDERERS[name]) RENDERERS[name]();
}

$$("nav.tabs button").forEach(b => b.onclick = () => switchTab(b.dataset.tab));

// Honor the URL hash on first load + on hashchange (so the parent v2 sidebar can deep-link)
const _init = (location.hash || "").replace(/^#/, "");
switchTab(RENDERERS[_init] ? _init : "builder");
window.addEventListener("hashchange", () => {
  const t = (location.hash || "").replace(/^#/, "");
  if (RENDERERS[t]) switchTab(t);
});
</script>
</body>
</html>
"""


def render_policy_ui(tenant: str = "default") -> str:
    return _HTML.replace("__TENANT__", tenant)
