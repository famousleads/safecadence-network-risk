"""
v7.7 — Server-rendered Identity UI.

Single self-contained HTML page mounted at /identity. Vanilla JS, calls
the v7.7 /api/identity/* endpoints. Designed to be linked from the
existing safecadence ui's nav and to work standalone for operators
who only need the identity workflow.

Auth: same JWT bearer the rest of the app uses; the page reads
localStorage.SC_TOKEN on load (matching the existing UI conventions).
"""

from __future__ import annotations


_PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>SafeCadence — Identity</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 24px;
    font: 14px/1.5 -apple-system, "Segoe UI", Inter, sans-serif;
    background: #0b1020; color: #e7ecf5;
  }
  h1 { font-size: 22px; margin: 0 0 4px; }
  h2 { font-size: 16px; margin: 24px 0 8px; color: #b6bfd9; }
  .grid { display: grid; gap: 12px; grid-template-columns: 1fr 1fr; }
  .card {
    background: #121a33; border: 1px solid #26315b; border-radius: 10px;
    padding: 16px;
  }
  textarea, input, select, button {
    width: 100%; padding: 10px 12px; border-radius: 8px;
    background: #0a1029; color: #e7ecf5; border: 1px solid #26315b;
    font: inherit; margin-top: 6px;
  }
  textarea { font-family: ui-monospace, Menlo, monospace; min-height: 140px; }
  button {
    background: #7c5cff; border: 0; cursor: pointer; font-weight: 600;
  }
  button.alt { background: #1f2a4a; border: 1px solid #26315b; }
  button:disabled { opacity: 0.5; cursor: not-allowed; }
  .row { display: flex; gap: 8px; }
  .row > * { flex: 1; }
  pre {
    background: #07091a; padding: 12px; border-radius: 8px;
    overflow: auto; max-height: 360px; white-space: pre-wrap; word-break: break-word;
    color: #d6deef; font-size: 12px;
  }
  .pill { display: inline-block; padding: 2px 8px; border-radius: 999px;
    background: #1f2a4a; font-size: 11px; margin-right: 4px; }
  .pill.bad { background: #5a1320; color: #fecaca; }
  .pill.warn { background: #4d3a08; color: #fde68a; }
  .pill.ok  { background: #0e3a25; color: #a7f3d0; }
  .muted { color: #8b95b1; font-size: 12px; }
  .err { color: #fecaca; background: #2d0a13; padding: 8px 12px;
    border-radius: 8px; margin-top: 8px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 6px 8px;
    border-bottom: 1px solid #1f2a4a; }
  th { color: #8b95b1; font-weight: 500; }
  .signin {
    background: #121a33; border: 1px solid #26315b; border-radius: 10px;
    padding: 24px; max-width: 480px;
  }
</style>
</head>
<body>

<h1>🔐 SafeCadence Identity</h1>
<p class="muted">v7.7 — read & write across Cisco ISE, ClearPass, AD,
Entra, Okta. AI-assisted authoring. Effective-permission lookup.
JIT grants. Evidence pack export.</p>
<p class="muted" style="margin-top:0">
Quick links:
<a href="/hub" style="color:#aab7ff">🧰 Tool Hub</a>
&nbsp;·&nbsp; <a href="/" style="color:#aab7ff">📊 Dashboard</a>
&nbsp;·&nbsp; <a href="/#inventory" style="color:#aab7ff">📋 Inventory</a>
&nbsp;·&nbsp; <a href="/#topology" style="color:#aab7ff">🗺️ Topology</a>
&nbsp;·&nbsp; <a href="/#compliance" style="color:#aab7ff">✅ Compliance</a>
&nbsp;·&nbsp; <a href="/#command" style="color:#aab7ff">⚙️ Command Center</a>
&nbsp;·&nbsp; <a href="/#audit" style="color:#aab7ff">📜 Audit</a>
</p>

<div id="signin" class="signin" style="display:none">
  <h2 style="margin-top:0">Sign in required</h2>
  <p class="muted">Set your bearer token to use this page. The token
  is stored in your browser's localStorage and never leaves your
  machine.</p>
  <input id="token" type="password" placeholder="Bearer token (JWT)" />
  <button onclick="saveToken()">Save & continue</button>
</div>

<div id="app" style="display:none">

<div class="grid">

<!-- ============================ Translate ====================== -->
<div class="card">
  <h2>1. Translate intent → IR</h2>
  <textarea id="intent" placeholder="e.g. contractors without MFA cannot SSH to prod"></textarea>
  <div class="row">
    <button onclick="translateAI()">AI translate</button>
    <button class="alt" onclick="showForm()">Guided form</button>
  </div>
  <div id="form" style="display:none; margin-top:8px">
    <input id="form-groups" placeholder="groups (comma-sep)" />
    <input id="form-actions" placeholder="actions (comma-sep)" value="ssh" />
    <input id="form-envs" placeholder="environments" value="prod" />
    <select id="form-effect">
      <option value="deny">deny</option>
      <option value="allow">allow</option>
      <option value="require_step_up">require_step_up</option>
    </select>
    <button onclick="translateForm()">Build IR from form</button>
  </div>
</div>

<!-- ============================ IR + preview =================== -->
<div class="card">
  <h2>2. IR JSON</h2>
  <textarea id="ir" placeholder="(translate something on the left first)"></textarea>
  <div class="row">
    <button onclick="preview()">Preview per-system diff</button>
  </div>
  <pre id="preview-out"></pre>
</div>

<!-- ============================ Apply ========================== -->
<div class="card">
  <h2>3. Apply</h2>
  <div class="row">
    <select id="target">
      <option value="okta">okta</option>
      <option value="ise">ise</option>
      <option value="ad">ad</option>
      <option value="entra">entra</option>
      <option value="clearpass">clearpass</option>
    </select>
    <button onclick="applyOne(true)">Dry-run</button>
    <button onclick="applyOne(false)">Commit (Tier-3)</button>
  </div>
  <div class="row" style="margin-top:8px">
    <button onclick="applyAll(true)">Apply-all dry-run</button>
    <button onclick="applyAll(false)">Apply-all commit (atomic)</button>
  </div>
  <pre id="apply-out"></pre>
</div>

<!-- ============================ Who-can ======================== -->
<div class="card">
  <h2>4. Who-can lookup</h2>
  <input id="wc-principal" placeholder="alice@yourcorp.com" />
  <div class="row">
    <input id="wc-action"   placeholder="ssh" />
    <input id="wc-resource" placeholder="prod-db-01" />
  </div>
  <input id="wc-groups" placeholder="comma-separated groups" />
  <div class="row">
    <label class="muted">
      <input type="checkbox" id="wc-mfa" /> MFA satisfied
    </label>
    <button onclick="whoCan()">Evaluate</button>
  </div>
  <pre id="wc-out"></pre>
</div>

</div><!-- /grid -->

<!-- ============================ Findings ====================== -->
<h2>Findings <button onclick="loadFindings()" class="alt"
       style="width:auto; padding: 4px 12px;">Refresh</button></h2>
<div class="card">
  <table id="findings-tbl">
    <thead><tr><th>severity</th><th>kind</th><th>title</th><th>actions</th></tr></thead>
    <tbody><tr><td colspan="4" class="muted">click Refresh</td></tr></tbody>
  </table>
</div>

<!-- ============================ Attack paths ================== -->
<h2>Identity attack paths
  <button onclick="loadPaths()" class="alt" style="width:auto; padding: 4px 12px;">Refresh</button>
</h2>
<div class="card">
  <table id="paths-tbl">
    <thead><tr><th>risk</th><th>chain</th><th>actions</th></tr></thead>
    <tbody><tr><td colspan="3" class="muted">click Refresh</td></tr></tbody>
  </table>
</div>

<!-- ============================ JIT =========================== -->
<h2>Just-In-Time grants
  <button onclick="loadJIT()" class="alt" style="width:auto; padding: 4px 12px;">Refresh</button>
</h2>
<div class="card">
  <div class="row" style="margin-bottom:8px">
    <input id="jit-principal" placeholder="alice@x" />
    <input id="jit-action"    placeholder="ssh" />
    <input id="jit-resource"  placeholder="prod-db-01" />
    <input id="jit-duration"  placeholder="duration seconds" value="14400" />
    <button onclick="jitGrant()">Grant</button>
  </div>
  <table id="jit-tbl">
    <thead><tr><th>id</th><th>status</th><th>principal</th><th>action</th>
                <th>resource</th><th>target</th><th>expires</th></tr></thead>
    <tbody><tr><td colspan="7" class="muted">click Refresh</td></tr></tbody>
  </table>
</div>

<!-- ============================ Evidence ===================== -->
<h2>Evidence pack</h2>
<div class="card">
  <p class="muted">Snapshot of your identity posture mapped to SOC 2,
  ISO 27001, NIST 800-53. Three formats: JSON (programmatic), CSV
  (spreadsheet), PDF (auditor).</p>
  <div class="row">
    <button onclick="downloadPack('json')">Download JSON</button>
    <button onclick="downloadPack('csv')">Download CSV</button>
    <button onclick="downloadPack('pdf')">Download PDF</button>
  </div>
</div>

<h2>↪ Related tools</h2>
<div class="card">
  <p class="muted" style="margin-top:0">
    Once you've authored an identity policy, the next step usually
    lives in another tool. Here's where to go for the common follow-ups:
  </p>
  <table>
    <thead><tr><th>If you want to…</th><th>Open</th></tr></thead>
    <tbody>
      <tr><td>See which assets the policy will hit</td>
          <td><a href="/#inventory">Inventory</a></td></tr>
      <tr><td>Visualize the affected slice of the network</td>
          <td><a href="/#topology">Topology</a></td></tr>
      <tr><td>Check current policy violations on the same fleet</td>
          <td><a href="/#compliance">Compliance</a></td></tr>
      <tr><td>Build a network-side change job (router/switch/firewall)</td>
          <td><a href="/#command">Command Center</a></td></tr>
      <tr><td>Send the change for approval</td>
          <td><a href="/#approvals">Approvals queue</a></td></tr>
      <tr><td>Roll back a previously committed change</td>
          <td><a href="/#rollback">Rollback manager</a></td></tr>
      <tr><td>Review what's already changed in the last week</td>
          <td><a href="/#audit">Audit trail</a></td></tr>
      <tr><td>See a single index of every SafeCadence tool</td>
          <td><a href="/hub">🧰 Tool Hub</a></td></tr>
    </tbody>
  </table>
</div>

</div><!-- /app -->

<script>
const TOKEN_KEY = "SC_TOKEN";
let token = localStorage.getItem(TOKEN_KEY) || "";

function init() {
  if (token) { document.getElementById("app").style.display = "block"; }
  else { document.getElementById("signin").style.display = "block"; }
}
function saveToken() {
  const v = document.getElementById("token").value.trim();
  if (!v) return;
  localStorage.setItem(TOKEN_KEY, v); token = v;
  document.getElementById("signin").style.display = "none";
  document.getElementById("app").style.display = "block";
}

async function api(path, opts = {}) {
  const r = await fetch(path, {
    ...opts,
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer " + token,
      ...(opts.headers || {}),
    },
  });
  if (!r.ok) {
    const t = await r.text();
    throw new Error(`HTTP ${r.status}: ${t}`);
  }
  return r.json();
}

function setOut(id, obj) {
  document.getElementById(id).textContent =
      typeof obj === "string" ? obj : JSON.stringify(obj, null, 2);
}

async function translateAI() {
  const intent = document.getElementById("intent").value.trim();
  if (!intent) return;
  try {
    const j = await api("/api/identity/translate",
                         { method: "POST", body: JSON.stringify({ intent }) });
    document.getElementById("ir").value = JSON.stringify(j.ir, null, 2);
  } catch (e) { setOut("preview-out", e.message); }
}

function showForm() { document.getElementById("form").style.display = "block"; }

async function translateForm() {
  const body = {
    form: true,
    intent: document.getElementById("intent").value.trim() || "guided form",
    groups: document.getElementById("form-groups").value.split(",").map(s=>s.trim()).filter(Boolean),
    actions: document.getElementById("form-actions").value.split(",").map(s=>s.trim()).filter(Boolean),
    environments: document.getElementById("form-envs").value.split(",").map(s=>s.trim()).filter(Boolean),
    effect: document.getElementById("form-effect").value,
    require_mfa: true,
  };
  try {
    const j = await api("/api/identity/translate",
                         { method: "POST", body: JSON.stringify(body) });
    document.getElementById("ir").value = JSON.stringify(j.ir, null, 2);
  } catch (e) { setOut("preview-out", e.message); }
}

function _readIR() {
  try { return JSON.parse(document.getElementById("ir").value); }
  catch { throw new Error("IR JSON is invalid — translate or fix it first"); }
}

async function preview() {
  try {
    const ir = _readIR();
    const j = await api("/api/identity/preview",
                         { method: "POST", body: JSON.stringify({ ir }) });
    setOut("preview-out", j.diff || JSON.stringify(j, null, 2));
  } catch (e) { setOut("preview-out", e.message); }
}

async function applyOne(dry) {
  try {
    const ir = _readIR();
    const target = document.getElementById("target").value;
    const j = await api("/api/identity/apply", {
      method: "POST",
      body: JSON.stringify({ ir, target, dry_run: dry }),
    });
    setOut("apply-out", j);
  } catch (e) { setOut("apply-out", e.message); }
}

async function applyAll(dry) {
  try {
    const ir = _readIR();
    const j = await api("/api/identity/apply-all", {
      method: "POST",
      body: JSON.stringify({ ir, targets: ir.targets || ["all"],
                              dry_run: dry, on_failure: "rollback" }),
    });
    setOut("apply-out", j);
  } catch (e) { setOut("apply-out", e.message); }
}

async function whoCan() {
  const p = document.getElementById("wc-principal").value.trim();
  const a = document.getElementById("wc-action").value.trim();
  const r = document.getElementById("wc-resource").value.trim();
  const g = document.getElementById("wc-groups").value.trim();
  const mfa = document.getElementById("wc-mfa").checked;
  if (!p || !a || !r) return;
  try {
    const q = new URLSearchParams({
      principal: p, action: a, resource: r,
      groups: g, mfa: String(mfa),
    });
    const j = await api("/api/identity/who-can?" + q.toString());
    setOut("wc-out", j);
  } catch (e) { setOut("wc-out", e.message); }
}

async function loadFindings() {
  try {
    const j = await api("/api/identity/findings");
    const tbody = document.querySelector("#findings-tbl tbody");
    tbody.innerHTML = "";
    if (!j.findings.length) {
      tbody.innerHTML = '<tr><td colspan="4" class="muted">No findings.</td></tr>';
      return;
    }
    for (const f of j.findings) {
      const cls = (f.severity === "critical" || f.severity === "high") ? "bad"
                  : f.severity === "medium" ? "warn" : "ok";
      const tr = document.createElement("tr");
      tr.innerHTML = `<td><span class="pill ${cls}">${f.severity}</span></td>
        <td>${f.kind}</td><td>${f.title}</td>
        <td><button class="alt" style="width:auto; padding:4px 8px"
              onclick='loadIR(${JSON.stringify(JSON.stringify(f.suggested_ir))})'>Use IR</button></td>`;
      tbody.appendChild(tr);
    }
  } catch (e) { alert(e.message); }
}

function loadIR(s) {
  document.getElementById("ir").value = JSON.stringify(JSON.parse(s), null, 2);
  window.scrollTo({ top: 0, behavior: "smooth" });
}

async function loadPaths() {
  try {
    const j = await api("/api/identity/attack-paths");
    const tbody = document.querySelector("#paths-tbl tbody");
    tbody.innerHTML = "";
    if (!j.paths.length) {
      tbody.innerHTML = '<tr><td colspan="3" class="muted">No identity attack paths.</td></tr>';
      return;
    }
    for (const p of j.paths) {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td>${p.risk_score.toFixed(1)}</td>
        <td>${p.chain_summary}</td>
        <td><button class="alt" style="width:auto; padding:4px 8px"
              onclick='remediatePath(${JSON.stringify(p.chain_summary)})'>Remediate</button></td>`;
      tbody.appendChild(tr);
    }
  } catch (e) { alert(e.message); }
}

async function remediatePath(chain) {
  try {
    const j = await api("/api/identity/remediate-path", {
      method: "POST", body: JSON.stringify({ chain_summary: chain }),
    });
    document.getElementById("ir").value = JSON.stringify(j.ir, null, 2);
    window.scrollTo({ top: 0, behavior: "smooth" });
  } catch (e) { alert(e.message); }
}

async function loadJIT() {
  try {
    const j = await api("/api/identity/jit/list");
    const tbody = document.querySelector("#jit-tbl tbody");
    tbody.innerHTML = "";
    if (!j.grants.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="muted">No JIT grants.</td></tr>';
      return;
    }
    for (const g of j.grants) {
      const tr = document.createElement("tr");
      const expires = new Date(g.expires_at * 1000).toISOString().slice(0,19);
      tr.innerHTML = `<td>${g.grant_id}</td><td>${g.status}</td>
        <td>${g.principal}</td><td>${g.action}</td><td>${g.resource}</td>
        <td>${g.target}</td><td>${expires}</td>`;
      tbody.appendChild(tr);
    }
  } catch (e) { alert(e.message); }
}

async function jitGrant() {
  const body = {
    principal: document.getElementById("jit-principal").value.trim(),
    action:    document.getElementById("jit-action").value.trim(),
    resource:  document.getElementById("jit-resource").value.trim(),
    duration_seconds: parseInt(document.getElementById("jit-duration").value, 10),
    target: "okta",
    reason: "via UI",
  };
  if (!body.principal || !body.action || !body.resource) return;
  try {
    await api("/api/identity/jit/grant",
               { method: "POST", body: JSON.stringify(body) });
    loadJIT();
  } catch (e) { alert(e.message); }
}

async function downloadPack(fmt) {
  // The auth headers preclude a plain <a> download, so fetch+blob it
  try {
    const r = await fetch(`/api/identity/evidence-pack?format=${fmt}`, {
      headers: { Authorization: "Bearer " + token },
    });
    if (!r.ok) throw new Error("HTTP " + r.status);
    const blob = await r.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `identity-evidence.${fmt}`;
    a.click();
    URL.revokeObjectURL(url);
  } catch (e) { alert(e.message); }
}

init();
</script>
</body>
</html>
"""


def register(app):
    """v7.7 — used to register /identity. v9.33 #4 superseded this with
    the action-first version in ``v9_pages.py``. Kept as a no-op so the
    server.app import chain doesn't break; the standalone _PAGE template
    is preserved for anyone embedding the legacy translator UX directly.
    """
    return  # no-op
