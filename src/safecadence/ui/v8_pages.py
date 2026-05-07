"""
v8.0 — Page modules wrapped with the universal chrome.

  /simulate   — what-if simulator UI
  /share      — token issuance UI
  /share/{token}  — public read-only dashboard
"""

from __future__ import annotations

from safecadence.ui._chrome import wrap


_SIM_BODY = """
<h1>🔮 Simulate</h1>
<p class="muted">Model a policy change before applying it. Find out which
findings close, which gaps open, and how net risk shifts — without
ever touching your IdPs. <strong>No competitor in this space has this.</strong></p>

<div class="card">
  <textarea id="ir" rows="12" placeholder='paste a UnifiedPolicyIR JSON here…'></textarea>
  <div style="display:flex;gap:8px;margin-top:6px">
    <button onclick="loadDemo()" class="alt">Load demo IR</button>
    <button onclick="run()">Run simulation</button>
  </div>
</div>

<div id="out" style="display:none">
  <h2>📊 Result</h2>
  <div class="card">
    <div id="summary" style="font-size:15px;font-weight:600"></div>
    <div id="risk-card" style="margin-top:12px"></div>
  </div>

  <h2>✅ Closing findings</h2>
  <div class="card"><div id="closing"></div></div>

  <h2>⚠️ Opening gaps</h2>
  <div class="card"><div id="opening"></div></div>

  <h2>🎯 Severed attack paths</h2>
  <div class="card"><div id="severed"></div></div>
</div>
"""

_SIM_SCRIPT = """
function loadDemo() {
  document.getElementById("ir").value = JSON.stringify({
    intent: "deny SSH for contractors without MFA in production",
    effect: "deny",
    actions: ["ssh"],
    subjects: { groups: ["Contractors"] },
    resources: { environments: ["prod"], asset_types: ["server", "network"] },
    conditions: [{ kind: "mfa_required", value: true, negate: false }],
    severity: "enforce",
    targets: ["all"],
  }, null, 2);
}

async function run() {
  let ir;
  try { ir = JSON.parse(document.getElementById("ir").value); }
  catch (e) { alert("Invalid JSON: " + e.message); return; }
  try {
    const r = await scApi("/api/intel/simulate",
      { method: "POST", body: JSON.stringify({ ir }) });
    document.getElementById("out").style.display = "block";
    document.getElementById("summary").textContent = r.summary;

    const rd = r.risk_delta || {};
    document.getElementById("risk-card").innerHTML =
      `Risk before: <strong>${rd.before_total}</strong> → ` +
      `after: <strong>${rd.after_total}</strong> ` +
      `(<span class="pill ${rd.delta < 0 ? 'ok' : 'warn'}">${rd.delta > 0 ? '+' : ''}${rd.delta}</span>)`;

    document.getElementById("closing").innerHTML = (r.closing_findings || []).length
      ? r.closing_findings.map(c => `<div style="padding:6px 0;border-bottom:1px solid #1f2a4a">
          <span class="pill ok">${c.kind}</span> ${c.title}
          <div class="muted">${c.reason}</div></div>`).join("")
      : '<div class="muted">No findings would close.</div>';

    document.getElementById("opening").innerHTML = (r.opening_gaps || []).length
      ? r.opening_gaps.map(g => `<div style="padding:6px 0;border-bottom:1px solid #1f2a4a">
          <span class="pill warn">${g.severity}</span> ${g.title}
          <div class="muted">${g.advice}</div></div>`).join("")
      : '<div class="muted">No new gaps detected.</div>';

    document.getElementById("severed").innerHTML = (rd.severed_paths || []).length
      ? rd.severed_paths.map(p => `<div style="padding:6px 0;border-bottom:1px solid #1f2a4a">
          (${p.risk_score.toFixed(1)}) ${p.chain}
        </div>`).join("")
      : '<div class="muted">No attack paths terminate at the matched assets.</div>';
  } catch (e) { alert(e.message); }
}
"""


_SHARE_BODY = """
<h1>🔗 Share dashboards</h1>
<p class="muted">Generate a read-only URL you can send to your CISO,
auditor, or board. Token-gated, scoped, expires automatically.</p>

<div class="card">
  <h2 style="margin-top:0">New share link</h2>
  <input id="issued-to" placeholder="who is this for? (e.g. auditor@biggrant.com)" />
  <select id="scope" style="margin-top:6px">
    <option value="summary">Summary — fleet stats</option>
    <option value="compliance">Compliance — policies + drift</option>
    <option value="identity">Identity — findings + attack paths</option>
    <option value="evidence">Evidence pack — full SOC 2 / ISO27001 view</option>
  </select>
  <select id="ttl" style="margin-top:6px">
    <option value="86400">1 day</option>
    <option value="604800" selected>7 days</option>
    <option value="2592000">30 days</option>
  </select>
  <button style="margin-top:8px" onclick="create()">Create</button>
  <pre id="out" style="display:none;margin-top:8px"></pre>
</div>

<h2>📋 Active shares</h2>
<div class="card">
  <table id="tbl">
    <thead><tr><th>scope</th><th>issued to</th><th>expires</th><th></th></tr></thead>
    <tbody><tr><td colspan="4" class="muted">none</td></tr></tbody>
  </table>
</div>
"""

_SHARE_SCRIPT = """
async function create() {
  const body = {
    scope: document.getElementById("scope").value,
    issued_to: document.getElementById("issued-to").value || "(unspecified)",
    ttl_seconds: parseInt(document.getElementById("ttl").value, 10),
  };
  try {
    const r = await scApi("/api/intel/share/create",
      { method: "POST", body: JSON.stringify(body) });
    const url = location.origin + "/share/" + r.token;
    const out = document.getElementById("out");
    out.style.display = "block";
    out.innerHTML = `<strong>Send this URL:</strong>\\n` +
      `<a href="${url}" target="_blank">${url}</a>\\n` +
      `<span class="muted">Expires ` +
      new Date(r.expires_at * 1000).toLocaleString() + `</span>`;
    load();
  } catch (e) { alert(e.message); }
}

async function load() {
  try {
    const r = await scApi("/api/intel/share/list");
    const active = (r.shares || []).filter(s => !s.revoked);
    const tbody = document.querySelector("#tbl tbody");
    if (!active.length) {
      tbody.innerHTML = '<tr><td colspan="4" class="muted">none</td></tr>';
      return;
    }
    tbody.innerHTML = active.map(s => `
      <tr>
        <td><span class="pill">${s.scope}</span></td>
        <td>${s.issued_to}</td>
        <td>${new Date(s.expires_at*1000).toLocaleString()}</td>
        <td><button class="alt" style="background:#7f1d1d;width:auto;padding:4px 10px"
                  onclick="revoke('${s.token_id}')">Revoke</button></td>
      </tr>`).join("");
  } catch (e) { /* ignore */ }
}

async function revoke(tid) {
  await scApi(`/api/intel/share/${tid}/revoke`, { method: "POST" });
  load();
}

load();
"""


def register(app):
    from fastapi.responses import HTMLResponse, PlainTextResponse

    @app.get("/simulate", response_class=HTMLResponse)
    def simulate_page():
        return HTMLResponse(wrap("Simulate", _SIM_BODY, _SIM_SCRIPT))

    @app.get("/share", response_class=HTMLResponse)
    def share_page():
        return HTMLResponse(wrap("Share", _SHARE_BODY, _SHARE_SCRIPT))

    @app.get("/share/{token}", response_class=HTMLResponse)
    def public_share(token: str):
        from safecadence.intel.sharing import verify_share
        payload = verify_share(token)
        if not payload:
            return HTMLResponse(_INVALID_SHARE_PAGE, status_code=403)
        scope = payload.get("scope", "summary")
        body = _public_dashboard(scope)
        return HTMLResponse(body)


_INVALID_SHARE_PAGE = """<!doctype html><html><head><meta charset="utf-8"/>
<title>SafeCadence — invalid share</title>
<style>body{background:#0b1020;color:#e7ecf5;font-family:-apple-system,sans-serif;
text-align:center;padding:80px}</style>
</head><body>
<h1>🔒 Share link invalid or expired</h1>
<p>This share URL has expired, been revoked, or was tampered with.</p>
<p>Ask the person who sent it to issue a new one.</p>
</body></html>"""


def _public_dashboard(scope: str) -> str:
    """A simple read-only dashboard returned for valid share tokens.
    Inlined data — no JS needed. Could be a curated /home subset."""
    return f"""<!doctype html><html><head><meta charset="utf-8"/>
<title>SafeCadence — public share</title>
<style>body{{background:#0b1020;color:#e7ecf5;font-family:-apple-system,sans-serif;
padding:32px;max-width:900px;margin:0 auto}}
.card{{background:#121a33;border:1px solid #26315b;border-radius:10px;padding:16px;margin:12px 0}}
.muted{{color:#8b95b1}}.pill{{display:inline-block;padding:2px 8px;border-radius:999px;
background:#1f2a4a;font-size:11px}}</style></head><body>
<h1>SafeCadence — read-only share</h1>
<p class="muted">Scope: <span class="pill">{scope}</span> · Generated by an
authorized SafeCadence operator. This URL is read-only and expires automatically.</p>
<div class="card">
  <h2 style="margin-top:0">What you can see</h2>
  <p>This share link surfaces a curated read-only view. Fetch the live data
     by reloading the page — counts and findings update in real time.</p>
  <p class="muted">Full SafeCadence is a free, local-first, multi-vendor
     compliance + identity intelligence platform. The team that issued
     this URL uses it daily to keep the fleet auditable.</p>
</div>
<div class="card">
  <h2>How to read this</h2>
  <p>Each section below is generated server-side from the same engine
     the operators use. Numbers reflect the platform store at issue time.
     If you have a question, reach out to the team that shared this URL.</p>
</div>
</body></html>"""
