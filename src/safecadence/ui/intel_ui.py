"""
v7.9 — UI pages for the intel features.

  /ask         AI assistant chat
  /timeline    chronological event view
  /onboarding  first-run setup wizard
  /briefing    morning briefing preview
  /automation  rules editor

Single self-contained page per feature, vanilla JS, calls the
/api/intel/* endpoints.
"""

from __future__ import annotations


def _wrap(title: str, body: str, page_script: str = "") -> str:
    """v9: delegate to the universal chrome (sidebar + topbar + palette).
    The intel_ui pages used to ship their own mini-shell; v9 unifies on
    one design system. Page scripts get a small `api()` shim for
    backward-compat — equivalent to the chrome's `scApi`."""
    from safecadence.ui._chrome import wrap
    shim = """
const api = scApi;
""" + page_script
    return wrap(title, body, shim)


_ASK_BODY = """
<h1>💬 Ask SafeCadence</h1>
<p class="muted">Natural-language questions over your entire fleet.
Read-only. If no AI key is configured, the assistant falls back to a
deterministic answer for common questions.</p>

<div class="card">
  <textarea id="q" rows="3"
    placeholder="e.g. how many crown-jewel assets have failing policies right now?"></textarea>
  <button onclick="ask()">Ask</button>
</div>

<div class="card" id="answer-card" style="display:none">
  <h2>Answer</h2>
  <pre id="answer"></pre>
  <div class="muted" id="meta"></div>
</div>

<div class="card">
  <h2>Try asking</h2>
  <ul class="muted">
    <li>How many critical findings are open?</li>
    <li>Which contractors are over-privileged?</li>
    <li>What NHIs haven't been rotated in 90 days?</li>
    <li>Summarize identity risk in plain English.</li>
    <li>Which assets are crown-jewels?</li>
  </ul>
</div>
"""

_ASK_SCRIPT = """
async function ask() {
  const q = document.getElementById("q").value.trim();
  if (!q) return;
  document.getElementById("answer-card").style.display = "block";
  document.getElementById("answer").textContent = "Thinking…";
  document.getElementById("meta").textContent = "";
  try {
    const r = await api("/api/intel/ask", {
      method: "POST", body: JSON.stringify({ question: q })
    });
    document.getElementById("answer").textContent = r.answer;
    document.getElementById("meta").textContent =
      (r.used_ai ? "✓ answered via AI" : "↻ deterministic fallback")
      + (r.fallback_reason ? " — " + r.fallback_reason : "");
  } catch (e) {
    document.getElementById("answer").textContent = e.message;
  }
}
"""

_TIMELINE_BODY = """
<h1>⏱️ Timeline</h1>
<p class="muted">Everything that has changed in your fleet in the
selected window. Audit, JIT, comments, assignments, watchlist, automation.</p>

<div class="card">
  <div style="display:flex; gap:8px; align-items:center">
    <label class="muted">Window:</label>
    <select id="since" style="width:auto" onchange="load()">
      <option value="86400">last 24h</option>
      <option value="604800" selected>last 7 days</option>
      <option value="2592000">last 30 days</option>
      <option value="7776000">last 90 days</option>
    </select>
    <label class="muted">Kinds:</label>
    <input id="kinds" style="width:auto" placeholder="audit,jit,comment…"
           list="timeline-kinds" autocomplete="off" onchange="load()" />
    <datalist id="timeline-kinds">
      <option value="audit">
      <option value="jit">
      <option value="comment">
      <option value="assignment">
      <option value="watchlist">
      <option value="automation">
      <!-- v9.45 — NOTIFY_CATEGORIES (dispatch_event) -->
      <option value="approval_requested">
      <option value="finding_critical">
      <option value="watchlist_change">
      <option value="drift_detected">
      <option value="automation_fired">
      <option value="jit_granted">
      <option value="digest_daily">
    </datalist>
  </div>
  <p class="muted" style="font-size:11px;margin-top:6px">
    Comma-separated. Pick from the suggestions or leave blank for all kinds.
  </p>
</div>

<div class="card">
  <table id="tbl">
    <thead><tr><th>when</th><th>kind</th><th>summary</th><th>actor</th>
                <th>entity</th></tr></thead>
    <tbody><tr><td colspan="5" class="muted">loading…</td></tr></tbody>
  </table>
</div>
"""

_TIMELINE_SCRIPT = """
async function load() {
  const since = document.getElementById("since").value;
  const kinds = document.getElementById("kinds").value;
  try {
    const r = await api(`/api/intel/timeline?since_seconds=${since}&kinds=${kinds}`);
    const tbody = document.querySelector("#tbl tbody");
    if (!r.events.length) {
      tbody.innerHTML = '<tr><td colspan="5" class="muted">No events.</td></tr>';
      return;
    }
    tbody.innerHTML = r.events.map(e => {
      const when = new Date(e.timestamp * 1000).toLocaleString();
      const sev = e.severity === "critical" || e.severity === "high" ? "bad"
                 : e.severity === "medium" ? "warn" : "ok";
      return `<tr>
        <td>${when}</td>
        <td><span class="pill">${e.kind}</span></td>
        <td>${e.summary}</td>
        <td>${e.actor || ""}</td>
        <td>${e.entity_kind ? e.entity_kind + ":" + (e.entity_id||"") : ""}</td>
      </tr>`;
    }).join("");
  } catch (e) {
    document.querySelector("#tbl tbody").innerHTML =
      `<tr><td colspan="5" class="bad">${e.message}</td></tr>`;
  }
}
load();
"""

_BRIEFING_BODY = """
<h1>📰 Morning briefing</h1>
<p class="muted">A daily digest tailored for your account.
The same content can be emailed via <code>safecadence schedule</code>.</p>

<div class="card">
  <button onclick="generate()">Generate briefing now</button>
</div>

<div id="out" class="card" style="display:none">
  <pre id="text"></pre>
</div>
"""

_BRIEFING_SCRIPT = """
async function generate() {
  document.getElementById("out").style.display = "block";
  document.getElementById("text").textContent = "Generating…";
  try {
    const r = await api("/api/intel/briefing", { method: "POST",
      body: JSON.stringify({}) });
    document.getElementById("text").textContent = r.text;
  } catch (e) {
    document.getElementById("text").textContent = e.message;
  }
}
"""

_AUTO_BODY = """
<h1>🤖 Automation rules</h1>
<p class="muted">IF a finding matches THEN run actions.
Rate-limited so a noisy finding doesn't fire 100x.</p>

<div class="card">
  <h2>New rule</h2>
  <input id="r-name" placeholder="rule name (e.g. auto-fix stale NHIs)" />
  <div style="display:flex; gap:8px; margin-top:6px">
    <select id="r-kind" style="width:50%">
      <option value="">any kind</option>
      <option>stale_nhi</option>
      <option>no_mfa</option>
      <option>over_privileged</option>
      <option>never_rotated</option>
      <option>orphan_service_account</option>
    </select>
    <select id="r-sev" style="width:50%">
      <option value="">any severity</option>
      <option value="low">low+</option>
      <option value="medium">medium+</option>
      <option value="high">high+</option>
      <option value="critical">critical only</option>
    </select>
  </div>
  <select id="r-action" style="margin-top:6px">
    <option value="auto_fix">auto_fix (dry-run)</option>
    <option value="assign">assign</option>
    <option value="notify_log">notify_log</option>
    <option value="notify_slack">notify_slack</option>
  </select>
  <input id="r-action-arg" placeholder="(if assign: assignee email; if slack: channel)"
         style="margin-top:6px" />
  <button style="margin-top:6px" onclick="saveRule()">Save rule</button>
</div>

<div class="card">
  <h2>Rules</h2>
  <table id="rules-tbl">
    <thead><tr><th>name</th><th>when</th><th>then</th><th>last fired</th>
                <th></th></tr></thead>
    <tbody><tr><td colspan="5" class="muted">loading…</td></tr></tbody>
  </table>
  <button class="alt" style="margin-top:8px; background:#1f2a4a"
          onclick="preview()">Preview what would fire now</button>
  <pre id="preview" style="display:none; margin-top:8px"></pre>
</div>
"""

_AUTO_SCRIPT = """
async function loadRules() {
  const r = await api("/api/intel/automation/rules");
  const tbody = document.querySelector("#rules-tbl tbody");
  if (!r.rules.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="muted">No rules yet.</td></tr>';
    return;
  }
  tbody.innerHTML = r.rules.map(rule => `
    <tr>
      <td>${rule.name}</td>
      <td>${JSON.stringify(rule.when)}</td>
      <td>${rule.then.map(t=>t.action).join(", ")}</td>
      <td>${rule.last_fired_at ?
            new Date(rule.last_fired_at*1000).toLocaleString() : "(never)"}</td>
      <td><button style="background:#7f1d1d; width:auto; padding:2px 8px"
                  onclick="del('${rule.rule_id}')">Delete</button></td>
    </tr>`).join("");
}
async function saveRule() {
  const action = { action: document.getElementById("r-action").value };
  const arg = document.getElementById("r-action-arg").value.trim();
  if (action.action === "assign" && arg) action.to = arg;
  if (action.action === "notify_slack" && arg) action.channel = arg;
  const body = {
    name: document.getElementById("r-name").value || "unnamed rule",
    when: { kind: document.getElementById("r-kind").value || undefined,
            severity_at_least: document.getElementById("r-sev").value || undefined },
    then: [action],
  };
  // strip undefined
  Object.keys(body.when).forEach(k => body.when[k] === undefined && delete body.when[k]);
  await api("/api/intel/automation/rules",
            { method: "POST", body: JSON.stringify(body) });
  loadRules();
}
async function del(id) {
  await api(`/api/intel/automation/rules/${id}`, { method: "DELETE" });
  loadRules();
}
async function preview() {
  const r = await api("/api/intel/automation/preview", { method: "POST" });
  const out = document.getElementById("preview");
  out.style.display = "block";
  // v9.38 — make the dry-run nature of preview impossible to miss.
  // Before this, the JSON dump alone could be misread as "actions
  // already fired". Now the banner spells it out.
  const wouldFire = (r.would_fire || r.matches || []).length;
  out.innerHTML =
    '<div style="background:#fef9c3;border-left:4px solid #ca8a04;' +
    'padding:10px 14px;margin-bottom:8px;border-radius:4px">' +
    '<strong>🔮 Preview only — no actions taken.</strong> ' +
    'These are the rules that <em>would</em> fire against current ' +
    'findings. Click <em>Add rule</em> to make them real.' +
    (wouldFire ? ' (' + wouldFire + ' rule match' +
      (wouldFire === 1 ? '' : 'es') + ')' : '') +
    '</div>' +
    '<pre style="margin:0">' +
    JSON.stringify(r, null, 2).replace(/[<>&]/g, c =>
      ({"<":"&lt;",">":"&gt;","&":"&amp;"}[c])) +
    '</pre>';
}
loadRules();
"""

_ONBOARD_BODY = """
<h1>🧭 SafeCadence — first-run setup</h1>
<p class="muted">Five steps to value. Most users finish in under 5 minutes.</p>

<div class="card">
  <div class="step" id="s1"><div class="num">1</div><div>
    <strong>Load data</strong><br/>
    <span class="muted">Either run the demo fleet or import real CSV.</span><br/>
    <button style="width:auto; padding:4px 12px; margin-top:4px"
            onclick="runDemo()">Load demo data (31 assets + 3 NHIs)</button>
    <a class="muted" href="/#inventory" style="margin-left:12px">…or import CSV</a>
  </div></div>
  <div class="step" id="s2"><div class="num">2</div><div>
    <strong>Discover identity systems</strong><br/>
    <span class="muted">Auto-detect Okta, Entra, ISE, ClearPass, AD reachable
    from this host. Run <code>safecadence identity discover --email-domain
    yourcorp.com</code>.</span>
  </div></div>
  <div class="step" id="s3"><div class="num">3</div><div>
    <strong>Author your first policy</strong><br/>
    <span class="muted">Plain-English intent → IR → preview → apply.</span><br/>
    <a href="/identity" class="muted" style="text-decoration:underline">
      Open identity translator →</a>
  </div></div>
  <div class="step" id="s4"><div class="num">4</div><div>
    <strong>Pin a watchlist</strong><br/>
    <span class="muted">Pick 3-5 assets/NHIs to follow. Daemon flags
    overnight changes in your morning briefing.</span><br/>
    <a href="/timeline" class="muted">Open timeline →</a>
  </div></div>
  <div class="step" id="s5"><div class="num">5</div><div>
    <strong>Set up an automation rule</strong><br/>
    <span class="muted">"WHEN stale_nhi finding appears THEN auto-fix dry-run".
    Once a few rules run, SafeCadence becomes a daily habit.</span><br/>
    <a href="/automation" class="muted">Open automation →</a>
  </div></div>
</div>
"""

_ONBOARD_SCRIPT = """
async function runDemo() {
  try {
    await api("/api/platform/load-demo?overwrite=false", { method: "POST" });
    alert("Demo loaded! Refreshing…");
    location.href = "/home";
  } catch (e) { alert(e.message); }
}
"""


def register(app):
    from fastapi.responses import HTMLResponse

    @app.get("/ask", response_class=HTMLResponse)
    def page_ask():
        return HTMLResponse(_wrap("Ask", _ASK_BODY, _ASK_SCRIPT))

    @app.get("/timeline", response_class=HTMLResponse)
    def page_timeline():
        return HTMLResponse(_wrap("Timeline", _TIMELINE_BODY, _TIMELINE_SCRIPT))

    @app.get("/briefing", response_class=HTMLResponse)
    def page_briefing():
        return HTMLResponse(_wrap("Briefing", _BRIEFING_BODY, _BRIEFING_SCRIPT))

    @app.get("/automation", response_class=HTMLResponse)
    def page_automation():
        return HTMLResponse(_wrap("Automation", _AUTO_BODY, _AUTO_SCRIPT))

    @app.get("/onboarding", response_class=HTMLResponse)
    def page_onboarding():
        return HTMLResponse(_wrap("Onboarding", _ONBOARD_BODY, _ONBOARD_SCRIPT))
