"""
v9.1 — Interactive product tour at /tour.

Walks through the 5 killer features with sample data, showing actual
output a user would see. Designed to be linkable from the home page
hero band and the onboarding banner.
"""

from __future__ import annotations

from safecadence.ui._chrome import wrap


_BODY = """
<h1>✨ See SafeCadence in action</h1>
<p class="muted">Five killer features in 60 seconds. Each section runs
against your loaded fleet and shows what you'd see day-to-day. No real
IdP credentials needed for any of this — every demo is server-side and
read-only.</p>

<!-- Step 1: AI translator -->
<div class="card" style="border-left:4px solid #7c5cff">
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:8px">
    <div style="background:#7c5cff;color:white;width:28px;height:28px;border-radius:50%;
                display:flex;align-items:center;justify-content:center;font-weight:700">1</div>
    <h2 style="margin:0">🤖 AI policy translator</h2>
  </div>
  <p class="muted">Type a sentence, get a unified policy IR that
  applies cleanly across <strong>Okta + Cisco ISE + Active Directory +
  Entra ID + ClearPass</strong>.</p>

  <div style="margin-top:12px">
    <input id="t-input" placeholder="Try: contractors without MFA cannot SSH to prod"
           value="contractors without MFA cannot SSH to prod" />
    <div style="display:flex;gap:8px;margin-top:8px">
      <button class="primary" style="width:auto;padding:8px 16px"
              onclick="runTranslate()">Translate (no AI key needed)</button>
      <a href="/identity" class="alt" style="width:auto;padding:8px 16px;
         display:inline-block;background:var(--panel-2);text-decoration:none;
         color:var(--text);border-radius:8px;font-weight:600">Open full translator →</a>
    </div>
  </div>

  <div id="t-out" style="display:none;margin-top:12px">
    <div class="muted" style="margin-bottom:6px">Per-system change preview:</div>
    <pre id="t-pre"></pre>
  </div>
</div>

<!-- Step 2: Simulator -->
<div class="card" style="border-left:4px solid #10b981">
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:8px">
    <div style="background:#10b981;color:white;width:28px;height:28px;border-radius:50%;
                display:flex;align-items:center;justify-content:center;font-weight:700">2</div>
    <h2 style="margin:0">🔮 What-if simulator</h2>
  </div>
  <p class="muted">Click to model the impact of the policy you just
  translated — without applying it. Risk delta, closing findings,
  opening gaps.</p>
  <button class="primary" style="width:auto;padding:8px 16px;margin-top:6px"
          onclick="runSimulate()">Run simulation</button>
  <a href="/simulate" class="alt" style="width:auto;padding:8px 16px;
     display:inline-block;background:var(--panel-2);text-decoration:none;
     color:var(--text);border-radius:8px;font-weight:600;margin-left:8px">
     Open full simulator →</a>
  <div id="s-out" style="display:none;margin-top:12px">
    <pre id="s-pre"></pre>
  </div>
</div>

<!-- Step 3: Attack paths -->
<div class="card" style="border-left:4px solid #ef4444">
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:8px">
    <div style="background:#ef4444;color:white;width:28px;height:28px;border-radius:50%;
                display:flex;align-items:center;justify-content:center;font-weight:700">3</div>
    <h2 style="margin:0">🎯 Identity attack paths</h2>
  </div>
  <p class="muted">Human → group → service-account → role → asset
  chains. Sailpoint and Saviynt don't show this. Wiz does it for cloud
  only. SafeCadence does it across IdPs + network.</p>
  <button class="primary" style="width:auto;padding:8px 16px;margin-top:6px"
          onclick="loadPaths()">Find attack paths in fleet</button>
  <a href="/paths" class="alt" style="width:auto;padding:8px 16px;
     display:inline-block;background:var(--panel-2);text-decoration:none;
     color:var(--text);border-radius:8px;font-weight:600;margin-left:8px">
     Open full attack-path view →</a>
  <div id="p-out" style="display:none;margin-top:12px">
    <table id="p-tbl"><thead><tr><th>Risk</th><th>Chain</th></tr></thead>
    <tbody></tbody></table>
  </div>
</div>

<!-- Step 4: who-can -->
<div class="card" style="border-left:4px solid #3b82f6">
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:8px">
    <div style="background:#3b82f6;color:white;width:28px;height:28px;border-radius:50%;
                display:flex;align-items:center;justify-content:center;font-weight:700">4</div>
    <h2 style="margin:0">🔎 Effective-permission lookup</h2>
  </div>
  <p class="muted">"Right now, can principal X do action Y on resource
  Z?" composed across all connected IdPs with full reasoning chain.
  Most-asked SOC question, no off-the-shelf answer.</p>
  <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;margin-top:6px">
    <input id="wc-p" placeholder="alice@x" value="alice.admin@acme.local" />
    <input id="wc-a" placeholder="ssh" value="ssh" />
    <input id="wc-r" placeholder="prod-db" value="dc-01.acme.local" />
  </div>
  <button class="primary" style="width:auto;padding:8px 16px;margin-top:6px"
          onclick="runWhoCan()">Evaluate</button>
  <div id="wc-out" style="display:none;margin-top:12px">
    <pre id="wc-pre"></pre>
  </div>
</div>

<!-- Step 5: JIT -->
<div class="card" style="border-left:4px solid #f59e0b">
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:8px">
    <div style="background:#f59e0b;color:white;width:28px;height:28px;border-radius:50%;
                display:flex;align-items:center;justify-content:center;font-weight:700">5</div>
    <h2 style="margin:0">⏱️ Just-in-Time access</h2>
  </div>
  <p class="muted">Time-bounded grants with auto-revoke. Free PAM-lite
  that competitors charge tens of thousands for.</p>
  <button class="primary" style="width:auto;padding:8px 16px;margin-top:6px"
          onclick="grantJIT()">Grant 4h SSH to prod-db (demo)</button>
  <a href="/jit" class="alt" style="width:auto;padding:8px 16px;
     display:inline-block;background:var(--panel-2);text-decoration:none;
     color:var(--text);border-radius:8px;font-weight:600;margin-left:8px">
     Open JIT manager →</a>
  <div id="j-out" style="display:none;margin-top:12px"></div>
</div>

<div class="card" style="text-align:center;padding:32px;background:var(--panel-2)">
  <h2 style="margin:0 0 8px">🎉 That's the product</h2>
  <p class="muted" style="max-width:600px;margin:0 auto">
  Five capabilities in five minutes. Daily use comes from the morning
  briefing, automation rules, and watchlists. Auditor handoff comes
  from the evidence pack and public share. Everything else lives in
  the sidebar.</p>
  <a href="/home" class="primary" style="display:inline-block;
     padding:10px 24px;border-radius:8px;background:var(--accent);
     color:white;text-decoration:none;font-weight:600;margin-top:16px">
     Back to dashboard →</a>
</div>
"""

_SCRIPT = r"""
async function runTranslate() {
  const intent = document.getElementById("t-input").value.trim();
  try {
    // Use form path so no AI key is required
    const r = await scApi("/api/identity/translate", {
      method: "POST",
      body: JSON.stringify({
        form: true, intent,
        groups: ["Contractors"], actions: ["ssh"],
        environments: ["prod"], effect: "deny", require_mfa: true,
      }),
    });
    const ir = r.ir;
    const prev = await scApi("/api/identity/preview", {
      method: "POST", body: JSON.stringify({ ir }),
    });
    document.getElementById("t-out").style.display = "block";
    document.getElementById("t-pre").textContent = prev.diff;
    // Save IR for the simulator step
    window.__TOUR_IR = ir;
  } catch (e) { alert(e.message); }
}

async function runSimulate() {
  const ir = window.__TOUR_IR;
  if (!ir) {
    alert("Run step 1 first to translate an IR.");
    return;
  }
  try {
    const r = await scApi("/api/intel/simulate", {
      method: "POST", body: JSON.stringify({ ir }),
    });
    document.getElementById("s-out").style.display = "block";
    const lines = [];
    lines.push(`📊 ${r.summary}`);
    lines.push("");
    lines.push(`Matched assets: ${(r.matched_assets || []).length}`);
    if (r.risk_delta) {
      lines.push(`Risk before:  ${r.risk_delta.before_total}`);
      lines.push(`Risk after:   ${r.risk_delta.after_total}`);
      lines.push(`Risk delta:   ${r.risk_delta.delta > 0 ? "+" : ""}${r.risk_delta.delta}`);
    }
    if ((r.closing_findings || []).length) {
      lines.push("");
      lines.push("Closing findings:");
      for (const f of r.closing_findings.slice(0,5)) {
        lines.push(`  ✓ ${f.kind} — ${f.title}`);
      }
    }
    if ((r.opening_gaps || []).length) {
      lines.push("");
      lines.push("Opening gaps (review):");
      for (const g of r.opening_gaps) {
        lines.push(`  ⚠ ${g.kind} — ${g.title}`);
      }
    }
    document.getElementById("s-pre").textContent = lines.join("\n");
  } catch (e) { alert(e.message); }
}

async function loadPaths() {
  try {
    const r = await scApi("/api/identity/attack-paths");
    document.getElementById("p-out").style.display = "block";
    const tbody = document.querySelector("#p-tbl tbody");
    if (!r.paths || !r.paths.length) {
      tbody.innerHTML = `<tr><td colspan="2" class="muted">
        No paths yet — load demo with <code>safecadence demo</code>.</td></tr>`;
      return;
    }
    tbody.innerHTML = r.paths.slice(0,5).map(p => {
      const cls = p.risk_score >= 7 ? "pill-crit" : p.risk_score >= 4 ? "pill-high" : "pill-info";
      return `<tr>
        <td><span class="pill ${cls}">${p.risk_score.toFixed(1)}</span></td>
        <td>${p.chain_summary}</td>
      </tr>`;
    }).join("");
  } catch (e) { alert(e.message); }
}

async function runWhoCan() {
  const p = document.getElementById("wc-p").value;
  const a = document.getElementById("wc-a").value;
  const r = document.getElementById("wc-r").value;
  try {
    const q = new URLSearchParams({ principal: p, action: a, resource: r });
    const dec = await scApi("/api/identity/who-can?" + q.toString());
    document.getElementById("wc-out").style.display = "block";
    const lines = [];
    lines.push(`Principal: ${p}`);
    lines.push(`Action:    ${a}`);
    lines.push(`Resource:  ${r}`);
    lines.push("");
    lines.push(`Decision:  ${dec.allowed ? "✓ ALLOW" : "✗ DENY"}`);
    if (dec.requires_step_up) lines.push("           (step-up required)");
    lines.push("");
    lines.push(`Systems:   ${(dec.systems_consulted || []).join(", ") || "(none)"}`);
    lines.push("");
    lines.push("Reasoning:");
    for (const reason of dec.reasons || []) {
      lines.push(`  - ${reason}`);
    }
    if ((dec.chain || []).length) {
      lines.push("");
      lines.push("Rule chain:");
      for (const rule of dec.chain) {
        lines.push(`  [${rule.system}] ${rule.rule_name} → ${rule.effect}`);
      }
    }
    document.getElementById("wc-pre").textContent = lines.join("\n");
  } catch (e) { alert(e.message); }
}

async function grantJIT() {
  try {
    const g = await scApi("/api/identity/jit/grant", {
      method: "POST",
      body: JSON.stringify({
        principal: "alice@yourcorp.com",
        action: "ssh",
        resource: "dc-01.acme.local",
        duration_seconds: 14400,
        target: "okta",
        reason: "Demo grant via tour",
      }),
    });
    document.getElementById("j-out").style.display = "block";
    document.getElementById("j-out").innerHTML = `
      <pre>Granted: ${g.grant_id}
Principal:  alice@yourcorp.com
Action:     ssh → dc-01.acme.local (4h)
Status:     ${g.status}
Expires:    ${new Date(g.expires_at * 1000).toLocaleString()}

The daemon auto-revokes when expired. With OKTA_API_TOKEN set,
the revoke is pushed to Okta. Without it, the grant is marked
expired locally and surfaced in the morning briefing.</pre>
      <p class="muted" style="margin-top:8px">
        See your grant in <a href="/jit">JIT manager</a>.
      </p>`;
  } catch (e) {
    document.getElementById("j-out").style.display = "block";
    document.getElementById("j-out").innerHTML =
      `<pre>${e.message}</pre>`;
  }
}
"""


def register(app):
    from fastapi.responses import HTMLResponse

    @app.get("/tour", response_class=HTMLResponse)
    def tour():
        return HTMLResponse(wrap("Tour", _BODY, _SCRIPT))
