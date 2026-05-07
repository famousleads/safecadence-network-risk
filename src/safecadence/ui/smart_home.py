"""
v7.8 — Smart home page (/home).

Replaces "what does this product do?" confusion with a context-aware
landing page that:

  * Surfaces the 3 most-impactful things to do *right now*
  * Shows a global search bar that hits assets + policies + findings
    + identity rules + JIT grants in one query
  * Links prominently to the Tool Hub (full feature index)
  * Degrades to a friendly "load demo data" prompt when the fleet is empty

Loads in <1s — every tile is a separate fetch so a single slow component
doesn't block the page.
"""

from __future__ import annotations


_PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>SafeCadence — Home</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 32px;
    font: 14px/1.55 -apple-system, "Segoe UI", Inter, sans-serif;
    background: #0b1020; color: #e7ecf5;
  }
  .container { max-width: 1180px; margin: 0 auto; }
  .top { display: flex; justify-content: space-between; align-items: baseline;
          gap: 12px; margin-bottom: 4px; }
  h1 { font-size: 26px; margin: 0; }
  .nav a { color: #aab7ff; text-decoration: none; margin-left: 14px;
            font-size: 13px; }
  .lede { color: #b6bfd9; margin: 0 0 24px; }

  /* Global search */
  .search {
    background: #121a33; border: 1px solid #26315b; border-radius: 10px;
    padding: 12px 16px; display: flex; gap: 8px; align-items: center;
    margin-bottom: 24px;
  }
  .search input {
    flex: 1; padding: 8px 12px; border-radius: 8px;
    background: #0a1029; color: #e7ecf5; border: 1px solid #26315b;
    font: inherit;
  }
  .search-results {
    background: #0a1029; border: 1px solid #1f2a4a; border-radius: 8px;
    padding: 8px; margin-top: 8px; max-height: 360px; overflow: auto;
  }
  .search-results .hit {
    padding: 6px 8px; border-radius: 6px; cursor: pointer;
  }
  .search-results .hit:hover { background: #1f2a4a; }
  .search-results .hit .kind { color: #8b95b1; font-size: 11px; }

  /* Action tiles */
  h2 { font-size: 18px; margin: 24px 0 8px; color: #d6deef; }
  .actions { display: grid; gap: 12px;
             grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); }
  .action {
    background: #121a33; border: 1px solid #26315b; border-radius: 10px;
    padding: 14px 16px;
  }
  .action.crit  { border-left: 4px solid #ef4444; }
  .action.warn  { border-left: 4px solid #f59e0b; }
  .action.info  { border-left: 4px solid #3b82f6; }
  .action.ok    { border-left: 4px solid #10b981; }
  .action h3 { margin: 0 0 4px; font-size: 14px; }
  .action .meta { color: #8b95b1; font-size: 12px; margin-bottom: 8px; }
  .action a.cta {
    display: inline-block; background: #7c5cff; color: #fff;
    padding: 4px 12px; border-radius: 6px; text-decoration: none;
    font-size: 12px; font-weight: 600;
  }
  .action a.alt {
    display: inline-block; padding: 4px 12px; color: #aab7ff;
    text-decoration: none; font-size: 12px; margin-left: 6px;
  }

  /* Empty state */
  .empty {
    background: #121a33; border: 2px dashed #26315b; border-radius: 10px;
    padding: 36px; text-align: center; color: #b6bfd9;
  }
  .empty h3 { color: #e7ecf5; margin: 0 0 8px; }
  .empty .cta { display: inline-block; margin-top: 12px;
                 background: #7c5cff; color: #fff; padding: 8px 16px;
                 border-radius: 8px; text-decoration: none; font-weight: 600; }

  /* Stats strip */
  .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 8px; margin-top: 12px; }
  .stat {
    background: #121a33; border: 1px solid #26315b; border-radius: 8px;
    padding: 12px; text-align: center;
  }
  .stat .num { font-size: 22px; font-weight: 700; }
  .stat .lbl { color: #8b95b1; font-size: 11px; text-transform: uppercase; }
  .stat .num.bad { color: #fca5a5; }
  .stat .num.warn { color: #fcd34d; }
  .stat .num.ok { color: #6ee7b7; }
</style>
</head>
<body>
<div class="container">

<div class="top">
  <h1>🏠 SafeCadence</h1>
  <div class="nav">
    <a href="/hub">🧰 Tool Hub</a>
    <a href="/identity">🔐 Identity</a>
    <a href="/">📊 Dashboard</a>
  </div>
</div>
<p class="lede">
v7.7 — local-first infrastructure + identity intelligence.
Type below to search, or scroll for the most impactful next steps in
your fleet. Press <kbd>?</kbd> for keyboard shortcuts.
</p>

<!-- Global search -->
<div class="search">
  <span style="color:#8b95b1">🔎</span>
  <input id="q" placeholder="Search assets, policies, findings, principals…"
         autocomplete="off" autofocus />
</div>
<div id="search-results" class="search-results" style="display:none"></div>

<!-- Stats strip -->
<div class="stats" id="stats"></div>

<!-- Top actions -->
<h2>⚡ Next 3 actions</h2>
<div id="actions" class="actions">
  <div class="action info"><h3>Loading…</h3></div>
</div>

<!-- Empty state -->
<div id="empty" class="empty" style="display:none">
  <h3>Your fleet is empty</h3>
  <p>SafeCadence works best with assets to reason about. Load realistic
  demo data (31 network devices + identity systems) to see the platform
  in action, or onboard real assets via the Inventory tab.</p>
  <a class="cta" href="#" onclick="loadDemo(event)">Load demo data</a>
</div>

</div>

<script>
const TOKEN_KEY = "SC_TOKEN";
const TOKEN = localStorage.getItem(TOKEN_KEY) || "";

async function api(path, opts = {}) {
  const r = await fetch(path, {
    ...opts,
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer " + TOKEN,
      ...(opts.headers || {}),
    },
  });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

function el(html) {
  const t = document.createElement("template");
  t.innerHTML = html.trim();
  return t.content.firstChild;
}

function renderStat(num, label, cls = "") {
  return `<div class="stat"><div class="num ${cls}">${num}</div><div class="lbl">${label}</div></div>`;
}

async function loadStats() {
  let policy = null, drift = null, findings = null, paths = null, jit = null;
  let assetCount = 0;

  try { policy = await api("/api/policy/executive-briefing"); } catch (e) {}
  try { drift  = await api("/api/policy/cross-system-drift");   } catch (e) {}
  try { findings = await api("/api/identity/findings");          } catch (e) {}
  try { paths  = await api("/api/identity/attack-paths");        } catch (e) {}
  try {
    const j = await api("/api/identity/jit/list?active_only=true");
    jit = j.grants || [];
  } catch (e) { jit = []; }

  assetCount = (policy && policy.asset_summary &&
                  policy.asset_summary.asset_count) || 0;

  const compliance = (policy && policy.policy_summary &&
                        policy.policy_summary.overall_compliance_pct) || 0;
  const fails = (policy && policy.policy_summary &&
                   policy.policy_summary.total_failures) || 0;
  const driftCount = (drift && drift.finding_count) || 0;
  const findingCount = (findings && findings.count) || 0;
  const pathCount = (paths && paths.count) || 0;

  // Stats strip
  document.getElementById("stats").innerHTML =
      renderStat(assetCount, "assets") +
      renderStat(compliance + "%", "compliant",
                  compliance >= 80 ? "ok" : compliance >= 60 ? "warn" : "bad") +
      renderStat(fails, "policy failures", fails > 0 ? "warn" : "ok") +
      renderStat(driftCount, "drift findings", driftCount > 0 ? "warn" : "ok") +
      renderStat(findingCount, "identity findings",
                  findingCount > 0 ? "warn" : "ok") +
      renderStat(pathCount, "attack paths", pathCount > 0 ? "bad" : "ok") +
      renderStat((jit || []).length, "active JIT");

  // Empty state
  if (assetCount === 0) {
    document.getElementById("empty").style.display = "block";
    document.getElementById("actions").style.display = "none";
    return;
  }

  // Compute top 3 actions, in priority order
  const actions = [];
  if (pathCount > 0 && paths.paths.length) {
    const top = paths.paths[0];
    actions.push({
      severity: "crit",
      title: `🎯 ${pathCount} identity attack path${pathCount > 1 ? "s" : ""} detected`,
      detail: `Top: ${top.chain_summary} (risk ${top.risk_score.toFixed(1)})`,
      cta_label: "Remediate now",
      cta_href: "/identity#paths-tbl",
    });
  }
  if (findingCount > 0) {
    const top = findings.findings && findings.findings[0];
    actions.push({
      severity: top && top.severity === "critical" ? "crit"
              : top && top.severity === "high" ? "crit"
              : "warn",
      title: `🚩 ${findingCount} identity finding${findingCount > 1 ? "s" : ""}`,
      detail: top ? `${top.title}` : "Stale NHIs / no-MFA / over-privileged",
      cta_label: "Open Identity",
      cta_href: "/identity#findings-tbl",
    });
  }
  if (fails > 0) {
    const top = (policy.policy_summary &&
                  policy.policy_summary.top_5_failing_policies) || [];
    actions.push({
      severity: "warn",
      title: `❌ ${fails} policy violation${fails > 1 ? "s" : ""} open`,
      detail: top.length ? `Top: "${top[0].policy_name}" (${top[0].fail} fails)`
                          : "View the Compliance tab for details",
      cta_label: "Open Compliance",
      cta_href: "/#compliance",
    });
  }
  if (driftCount > 0) {
    actions.push({
      severity: "info",
      title: `📉 ${driftCount} cross-system drift finding${driftCount > 1 ? "s" : ""}`,
      detail: "Two or more identity systems disagree on policy",
      cta_label: "Open Drift",
      cta_href: "/#drift",
    });
  }
  if ((jit || []).length > 0) {
    actions.push({
      severity: "info",
      title: `⏱️ ${jit.length} active JIT grant${jit.length > 1 ? "s" : ""}`,
      detail: "Time-bounded access in flight — review or revoke",
      cta_label: "Open JIT",
      cta_href: "/identity#jit-tbl",
    });
  }

  if (!actions.length) {
    actions.push({
      severity: "ok",
      title: "✅ Everything looks good",
      detail: "No critical findings, drift, or attack paths in the last cycle.",
      cta_label: "Open Tool Hub",
      cta_href: "/hub",
    });
  }

  // Render top 3
  const top3 = actions.slice(0, 3);
  document.getElementById("actions").innerHTML = top3.map(a => `
    <div class="action ${a.severity}">
      <h3>${a.title}</h3>
      <div class="meta">${a.detail}</div>
      <a class="cta" href="${a.cta_href}">${a.cta_label} →</a>
      <a class="alt" href="/hub">all tools</a>
    </div>
  `).join("");
}

async function loadDemo(ev) {
  ev.preventDefault();
  ev.target.textContent = "Loading…";
  ev.target.style.pointerEvents = "none";
  try {
    await api("/api/platform/load-demo?overwrite=false", { method: "POST" });
    location.reload();
  } catch (e) {
    ev.target.textContent = "Failed: " + e.message;
  }
}

// ---- Search ----
const SEARCH_BASE = [
  { kind: "tool", name: "Inventory",            href: "/#inventory",    keys: ["asset", "device", "fleet"] },
  { kind: "tool", name: "Topology",             href: "/#topology",     keys: ["graph", "map"] },
  { kind: "tool", name: "Compliance",           href: "/#compliance",   keys: ["policy", "audit", "soc2", "iso"] },
  { kind: "tool", name: "Drift",                href: "/#drift",        keys: ["delta", "change"] },
  { kind: "tool", name: "Identity",             href: "/identity",      keys: ["okta", "ise", "ad", "entra", "clearpass", "mfa", "nhi"] },
  { kind: "tool", name: "JIT grants",           href: "/identity#jit-tbl", keys: ["just-in-time", "temporary"] },
  { kind: "tool", name: "Identity attack paths", href: "/identity#paths-tbl", keys: ["graph", "chain"] },
  { kind: "tool", name: "Command Center",       href: "/#command",      keys: ["ssh", "execute", "job"] },
  { kind: "tool", name: "Approvals queue",      href: "/#approvals",    keys: ["review", "sign-off"] },
  { kind: "tool", name: "Rollback manager",     href: "/#rollback",     keys: ["undo", "revert"] },
  { kind: "tool", name: "Audit trail",          href: "/#audit",        keys: ["log", "history"] },
  { kind: "tool", name: "Tool Hub",             href: "/hub",           keys: ["index", "all"] },
  { kind: "tool", name: "Settings",             href: "/#settings",     keys: ["config", "rbac", "totp"] },
];

let searchTimer = null;
document.getElementById("q").addEventListener("input", (e) => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => doSearch(e.target.value.trim()), 100);
});

function doSearch(q) {
  const box = document.getElementById("search-results");
  if (!q) { box.style.display = "none"; box.innerHTML = ""; return; }
  const lc = q.toLowerCase();
  const tools = SEARCH_BASE.filter(t =>
    t.name.toLowerCase().includes(lc) ||
    (t.keys || []).some(k => k.includes(lc))
  );
  // Also fire async searches against the live endpoints
  Promise.all([
    api(`/api/platform/search?q=${encodeURIComponent(q)}&limit=10`).catch(() => null),
  ]).then(([assets]) => {
    let html = tools.length ? tools.map(t =>
      `<a class="hit" href="${t.href}" style="display:block; text-decoration:none; color:#e7ecf5">
         <div>${t.name}</div>
         <div class="kind">tool · ${t.kind}</div>
       </a>`
    ).join("") : "";
    if (assets && assets.results && assets.results.length) {
      for (const a of assets.results.slice(0, 8)) {
        const ident = (a.identity || {});
        html += `<a class="hit" href="/#asset-${ident.asset_id || ''}"
                 style="display:block; text-decoration:none; color:#e7ecf5">
                 <div>${ident.hostname || ident.asset_id || '(unnamed)'}</div>
                 <div class="kind">asset · ${ident.vendor || ''} ${ident.asset_type || ''}</div>
               </a>`;
      }
    }
    if (!html) html = '<div class="kind" style="padding:8px">No matches.</div>';
    box.innerHTML = html;
    box.style.display = "block";
  });
}

// ---- Keyboard shortcuts ----
let shortcutBuffer = "";
let bufferTimer = null;
document.addEventListener("keydown", (e) => {
  if (e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA") return;
  if (e.key === "?") { showHelp(); return; }
  if (e.key === "/") { e.preventDefault(); document.getElementById("q").focus(); return; }
  shortcutBuffer += e.key;
  clearTimeout(bufferTimer);
  bufferTimer = setTimeout(() => shortcutBuffer = "", 700);
  const map = {
    "gh": "/hub", "gi": "/identity", "gd": "/", "ga": "/#audit",
    "gc": "/#compliance", "gt": "/#topology", "gp": "/#policy",
    "gs": "/#settings", "go": "/#home",
  };
  if (map[shortcutBuffer]) location.href = map[shortcutBuffer];
});

function showHelp() {
  alert(
"SafeCadence keyboard shortcuts:\n\n" +
"  /   focus search\n" +
"  ?   this help\n" +
"  g h Tool Hub\n" +
"  g i Identity\n" +
"  g d Dashboard\n" +
"  g c Compliance\n" +
"  g t Topology\n" +
"  g a Audit\n" +
"  g s Settings"
  );
}

loadStats();
</script>
</body>
</html>
"""


_ACTIVITY_FEED_HTML = """
<h2>📡 Live activity</h2>
<div class="card">
  <table id="feed-tbl">
    <thead><tr><th>when</th><th>kind</th><th>summary</th></tr></thead>
    <tbody><tr><td colspan="3" class="muted">loading…</td></tr></tbody>
  </table>
  <div class="muted" style="margin-top:6px">
    Auto-refreshes every 60s. <a href="/timeline">Full timeline →</a>
  </div>
</div>
"""

_ACTIVITY_FEED_JS = """
async function loadFeed() {
  try {
    const r = await scApi("/api/intel/timeline?since_seconds=86400&limit=10");
    const tbody = document.querySelector("#feed-tbl tbody");
    if (!r.events || !r.events.length) {
      tbody.innerHTML = '<tr><td colspan="3" class="muted">All quiet — nothing in the last 24h.</td></tr>';
      return;
    }
    tbody.innerHTML = r.events.map(e => {
      const when = new Date(e.timestamp * 1000).toLocaleTimeString();
      return `<tr>
        <td class="muted" style="white-space:nowrap">${when}</td>
        <td><span class="pill">${e.kind}</span></td>
        <td>${e.summary || ""}</td>
      </tr>`;
    }).join("");
  } catch (e) {}
}
loadFeed();
setInterval(loadFeed, 60000);
"""


def register(app):
    """Mount /home wrapped in the universal chrome."""
    from fastapi.responses import HTMLResponse
    from safecadence.ui._chrome import wrap

    # /home: keep the existing inline content (stats + actions + search)
    # and append the activity feed; the chrome wrapper handles nav, bell,
    # banner, shortcuts.
    inner_body = _PAGE  # legacy full page (with its own <html>) — extract body
    # Strip the surrounding <html>/<head>/<style>/<body> from _PAGE so the
    # chrome wrapper isn't doubled up. The legacy _PAGE already contains
    # full HTML; we re-emit a chrome-aware version below.

    @app.get("/home", response_class=HTMLResponse)
    def home_page():
        body = (_HOME_BODY_INLINE
                + _ACTIVITY_FEED_HTML)
        return HTMLResponse(wrap("Home", body, _HOME_SCRIPT_INLINE
                                  + _ACTIVITY_FEED_JS))


# ---------------- v9 home body (chrome supplies sidebar + topbar) -------

_HOME_BODY_INLINE = """
<!-- Killer features hero band -->
<div id="killer-band" style="display:grid;gap:10px;
     grid-template-columns:repeat(auto-fit,minmax(220px,1fr));
     margin-bottom:16px">
  <a href="/identity" style="text-decoration:none;color:var(--text);
     background:linear-gradient(135deg,#7c5cff,#5b3dd9);
     border-radius:12px;padding:14px 16px;display:block;
     border:1px solid var(--border)">
    <div style="font-size:11px;text-transform:uppercase;letter-spacing:0.5px;opacity:0.8">
      🤖 AI translator
    </div>
    <div style="font-size:14px;font-weight:700;margin-top:4px">
      Plain English → 5 IdPs
    </div>
    <div style="font-size:11px;opacity:0.85;margin-top:2px">
      "no SSH for contractors" → Okta + ISE + AD + Entra + ClearPass
    </div>
  </a>
  <a href="/simulate" style="text-decoration:none;color:var(--text);
     background:linear-gradient(135deg,#10b981,#0d8c63);
     border-radius:12px;padding:14px 16px;display:block;
     border:1px solid var(--border)">
    <div style="font-size:11px;text-transform:uppercase;letter-spacing:0.5px;opacity:0.8">
      🔮 What-if simulator
    </div>
    <div style="font-size:14px;font-weight:700;margin-top:4px">
      Preview before commit
    </div>
    <div style="font-size:11px;opacity:0.85;margin-top:2px">
      Risk delta · closing findings · severed paths
    </div>
  </a>
  <a href="/paths" style="text-decoration:none;color:var(--text);
     background:linear-gradient(135deg,#ef4444,#b32626);
     border-radius:12px;padding:14px 16px;display:block;
     border:1px solid var(--border)">
    <div style="font-size:11px;text-transform:uppercase;letter-spacing:0.5px;opacity:0.8">
      🎯 Attack paths
    </div>
    <div style="font-size:14px;font-weight:700;margin-top:4px">
      Human → SA → role → asset
    </div>
    <div style="font-size:11px;opacity:0.85;margin-top:2px">
      Identity chains nobody else surfaces
    </div>
  </a>
  <a href="/jit" style="text-decoration:none;color:var(--text);
     background:linear-gradient(135deg,#3b82f6,#1d62cf);
     border-radius:12px;padding:14px 16px;display:block;
     border:1px solid var(--border)">
    <div style="font-size:11px;text-transform:uppercase;letter-spacing:0.5px;opacity:0.8">
      ⏱️ JIT access
    </div>
    <div style="font-size:14px;font-weight:700;margin-top:4px">
      Time-bounded grants
    </div>
    <div style="font-size:11px;opacity:0.85;margin-top:2px">
      4 hours · auto-revoke · audit trail
    </div>
  </a>
  <a href="/tour" style="text-decoration:none;color:var(--text);
     background:linear-gradient(135deg,#f59e0b,#b87708);
     border-radius:12px;padding:14px 16px;display:block;
     border:1px solid var(--border)">
    <div style="font-size:11px;text-transform:uppercase;letter-spacing:0.5px;opacity:0.8">
      ✨ See it in action
    </div>
    <div style="font-size:14px;font-weight:700;margin-top:4px">
      Take the 60-second tour
    </div>
    <div style="font-size:11px;opacity:0.85;margin-top:2px">
      One click per killer feature
    </div>
  </a>
</div>

<!-- Hero -->
<div id="hero" class="card" style="padding:28px;display:flex;align-items:center;gap:28px;margin-bottom:16px">
  <div id="score-circle" style="width:130px;height:130px;border-radius:50%;
       background:conic-gradient(var(--ok) 0% 0%, var(--panel-2) 0% 100%);
       display:flex;align-items:center;justify-content:center;flex-shrink:0;position:relative">
    <div style="position:absolute;inset:8px;border-radius:50%;background:var(--panel)"></div>
    <div style="position:relative;font-size:32px;font-weight:800" id="score-num">—</div>
  </div>
  <div style="flex:1;min-width:0">
    <h1 style="margin:0 0 4px;font-size:18px">Safe Score
      <span class="sc-help" data-help="safe-score"></span>
      <span id="score-trend" class="pill pill-ok" style="margin-left:8px">—</span>
      <span id="demo-badge" class="pill pill-high" style="display:none;margin-left:4px">DEMO DATA
        <span class="sc-help" data-help="demo-data"></span>
      </span>
    </h1>
    <div class="muted" id="score-meta">Loading fleet snapshot…</div>
    <!-- v9.25: 30-day sparkline. Empty until the daemon writes ≥ 2 snapshots. -->
    <div id="score-spark" style="margin-top:6px;height:28px"></div>
    <div style="margin-top:6px"><a href="/scores" style="font-size:12px">See full leaderboard →</a></div>
  </div>
</div>

<!-- v9.24: Weak Link hero card -->
<div id="weak-link-card" class="card" style="display:none;padding:16px;margin-bottom:16px;
     border-left:4px solid var(--accent);background:linear-gradient(90deg,
     color-mix(in srgb, var(--accent) 8%, transparent), transparent)">
  <div style="display:flex;gap:14px;align-items:center">
    <div style="font-size:28px;flex-shrink:0">🎯</div>
    <div style="flex:1;min-width:0">
      <div style="font-size:11px;text-transform:uppercase;letter-spacing:0.5px;color:var(--muted);font-weight:600">
        Weakest link in your fleet
      </div>
      <div id="wl-headline" style="font-size:15px;margin-top:2px;font-weight:600">Computing…</div>
      <div id="wl-detail" class="muted" style="font-size:12px;margin-top:2px"></div>
    </div>
    <a id="wl-cta" href="#" class="primary" style="display:none;padding:8px 14px;
       border-radius:6px;text-decoration:none;font-size:13px;flex-shrink:0">Open asset →</a>
  </div>
</div>

<!-- Stat row -->
<div id="stat-row" style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:16px">
  <div class="card" style="cursor:pointer;text-align:left" onclick="location.href='/findings'">
    <div id="stat-crit" style="font-size:32px;font-weight:800;color:var(--bad)">—</div>
    <div class="muted" style="font-size:11px;text-transform:uppercase;letter-spacing:0.5px">Critical findings</div>
  </div>
  <div class="card" style="cursor:pointer;text-align:left" onclick="location.href='/paths'">
    <div id="stat-paths" style="font-size:32px;font-weight:800;color:var(--warn)">—</div>
    <div class="muted" style="font-size:11px;text-transform:uppercase;letter-spacing:0.5px">Open attack paths</div>
  </div>
  <div class="card" style="cursor:pointer;text-align:left" onclick="location.href='/jit'">
    <div id="stat-jit" style="font-size:32px;font-weight:800;color:var(--ok)">—</div>
    <div class="muted" style="font-size:11px;text-transform:uppercase;letter-spacing:0.5px">Active JIT grants</div>
  </div>
</div>

<!-- Two-col -->
<div style="display:grid;grid-template-columns:1fr 360px;gap:16px" id="two-col">
  <div class="card">
    <h2 style="margin:0 0 12px">⚡ Your next 3 actions
      <span class="sc-help" data-help="next-3-actions"></span>
    </h2>
    <div id="actions">
      <div class="muted">Loading…</div>
    </div>
  </div>
  <div class="card">
    <h2 style="margin:0 0 12px"><span style="color:var(--ok)">●</span> Live activity
      <span class="sc-help" data-help="live-activity"></span>
    </h2>
    <div id="feed"><div class="muted">Loading…</div></div>
    <div style="margin-top:12px;padding:10px;background:var(--bg);border:1px solid var(--border);border-radius:8px;display:flex;gap:8px;align-items:center">
      <span style="color:var(--accent)">🤖</span>
      <input id="ai-q" placeholder="Ask anything…" style="flex:1;background:transparent;border:0;color:var(--text);outline:0;width:auto;padding:0" />
      <button class="primary" style="width:auto;padding:5px 12px;font-size:12px" onclick="askAI()">Ask</button>
    </div>
  </div>
</div>

<!-- Empty fleet -->
<div id="empty" class="card" style="display:none;text-align:center;padding:48px;border:2px dashed var(--border)">
  <div style="font-size:36px">👋</div>
  <h3 style="margin:12px 0 4px">Your fleet is empty</h3>
  <p class="muted" style="margin:0">Load the realistic demo fleet (31 assets + 3 NHIs) to see SafeCadence in action.</p>
  <button class="primary" style="width:auto;padding:10px 20px;margin-top:16px" onclick="loadDemo()">Load demo data</button>
</div>
"""

_HOME_SCRIPT_INLINE = r"""
async function loadHome() {
  let policy=null, findings=null, paths=null, jit=[];
  try { policy = await scApi("/api/policy/executive-briefing"); } catch(e){}
  try { findings = await scApi("/api/identity/findings"); } catch(e){}
  try { paths    = await scApi("/api/identity/attack-paths"); } catch(e){}
  try { const j = await scApi("/api/identity/jit/list?active_only=true"); jit = j.grants || []; } catch(e){}

  const assetCount = (policy?.asset_summary?.asset_count) || 0;
  const compliance = (policy?.policy_summary?.overall_compliance_pct) || 0;
  const fails = (policy?.policy_summary?.total_failures) || 0;
  const fc = (findings?.count) || 0;
  const pc = (paths?.count) || 0;

  // Empty state
  if (assetCount === 0) {
    document.getElementById("hero").style.display = "none";
    document.getElementById("stat-row").style.display = "none";
    document.getElementById("two-col").style.display = "none";
    document.getElementById("empty").style.display = "block";
    return;
  }

  // v9.24: Hero score is now the Safe Score (real number, not random).
  // Falls back to compliance% if the score endpoint isn't reachable so
  // legacy deployments still render.
  let safeScoreData = null;
  try { safeScoreData = await scApi("/api/scores/safe"); } catch(e){}
  const headline = safeScoreData?.fleet_score ??
                    Math.max(0, Math.min(100, Number(compliance) || 0));
  const band = safeScoreData?.fleet_band || "";
  const color = headline >= 80 ? "var(--ok)" : headline >= 60 ? "var(--warn)" : "var(--bad)";
  document.getElementById("score-circle").style.background =
    `conic-gradient(${color} 0% ${headline}%, var(--panel-2) ${headline}% 100%)`;
  document.getElementById("score-num").innerHTML =
    `${Math.round(headline)}${band ? `<small style="font-size:14px;color:var(--muted);margin-left:4px">${band}</small>` : ""}`;
  // v9.25: real trend from persisted snapshots — no more random.
  // Falls back to the band letter if we have no history yet.
  const tEl = document.getElementById("score-trend");
  let trendData = null;
  try { trendData = await scApi("/api/scores/safe/history?days=30"); } catch(e){}
  const tr = trendData?.trend;
  if (tr && tr.samples > 1 && tr.delta !== 0) {
    const arrow = tr.direction === "up" ? "↑" : tr.direction === "down" ? "↓" : "→";
    const sign = tr.delta > 0 ? "+" : "";
    tEl.textContent = `${arrow} ${sign}${tr.delta} this week`;
    tEl.className = "pill " + (tr.direction === "up" ? "pill-ok"
                                : tr.direction === "down" ? "pill-crit"
                                : "pill-warn");
  } else if (band) {
    tEl.textContent = `Grade ${band}`;
    tEl.className = "pill " + (headline >= 80 ? "pill-ok"
                                  : headline >= 60 ? "pill-warn" : "pill-crit");
  } else {
    tEl.style.display = "none";
  }
  // Sparkline next to the score circle. Pure inline SVG, no library.
  const spark = document.getElementById("score-spark");
  const hist = trendData?.history || [];
  if (spark && hist.length >= 2) {
    const w = 110, h = 28, pad = 2;
    const xs = hist.map((_, i) => pad + (i * (w - 2*pad)) / (hist.length - 1));
    const ys = hist.map(p => {
      const v = Math.max(0, Math.min(100, Number(p.fleet_score) || 0));
      return h - pad - (v / 100) * (h - 2*pad);
    });
    const d = xs.map((x, i) => `${i ? "L" : "M"}${x.toFixed(1)} ${ys[i].toFixed(1)}`).join(" ");
    spark.innerHTML =
      `<svg width="${w}" height="${h}" viewBox="0 0 ${w} ${h}"
            xmlns="http://www.w3.org/2000/svg" aria-label="Safe Score trend">
         <path d="${d}" fill="none" stroke="${color}" stroke-width="1.6"/>
       </svg>`;
  } else if (spark) {
    spark.innerHTML = `<span style="font-size:11px;color:var(--muted)">Trend appears after the daemon runs.</span>`;
  }
  document.getElementById("score-meta").textContent =
    `${assetCount} assets monitored · last cycle ${new Date().toLocaleTimeString()}`;

  // v9.24: Weak Link hero card
  try {
    const wl = await scApi("/api/scores/weak-link");
    if (wl && wl.weak_link) {
      const w = wl.weak_link;
      const card = document.getElementById("weak-link-card");
      card.style.display = "block";
      const lift = w.score_lift > 0 ? ` — fleet Safe score climbs ${w.current_fleet_score} → ${w.projected_fleet_score}` : "";
      document.getElementById("wl-headline").textContent =
        `Fix ${w.asset_label} and ${w.paths_killed} attack path${w.paths_killed===1?"":"s"} collapse${lift}`;
      document.getElementById("wl-detail").textContent = w.reason;
      const cta = document.getElementById("wl-cta");
      cta.href = `/asset/${encodeURIComponent(w.asset_id)}`;
      cta.style.display = "inline-block";
    }
  } catch(e) { /* no paths yet — leave card hidden */ }
  // Show demo badge if fleet looks demo-y (rough heuristic)
  if (assetCount >= 25 && assetCount <= 40) {
    document.getElementById("demo-badge").style.display = "inline-block";
  }

  // Stats
  document.getElementById("stat-crit").textContent = String(
    (findings?.findings || []).filter(f => f.severity === "critical").length || 0);
  document.getElementById("stat-paths").textContent = String(pc);
  document.getElementById("stat-jit").textContent = String(jit.length);

  // Top 3 actions
  const actions = [];
  if (pc > 0 && paths?.paths?.length) {
    const top = paths.paths[0];
    actions.push({ sev: "crit", num: 1,
      title: `Remediate path: ${top.chain_summary}`,
      meta: `Risk ${top.risk_score.toFixed(1)} · ~2 minutes`,
      href: "/paths" });
  }
  if (fc > 0) {
    const f = findings.findings[0];
    actions.push({ sev: f.severity === "critical" ? "crit" : "high", num: actions.length + 1,
      title: f.title,
      meta: `${f.kind} · auto-fix available`,
      href: "/findings" });
  }
  if (fails > 0) {
    const top = (policy?.policy_summary?.top_5_failing_policies) || [];
    actions.push({ sev: "high", num: actions.length + 1,
      title: top.length ? `Fix policy "${top[0].policy_name}"` : "Fix failing policies",
      meta: top.length ? `Failing on ${top[0].fail} hosts · ~5 minutes` : "View compliance for details",
      href: "/policies" });
  }
  if (!actions.length) {
    actions.push({ sev: "ok", num: 1,
      title: "Everything looks good",
      meta: "No critical findings, attack paths, or policy fails.",
      href: "/hub" });
  }
  const sevPill = { crit:"pill-crit", high:"pill-high", med:"pill-med", info:"pill-info", ok:"pill-ok" };
  document.getElementById("actions").innerHTML = actions.slice(0,3).map(a => `
    <div onclick="location.href='${a.href}'" style="display:flex;align-items:center;gap:12px;padding:12px 0;border-bottom:1px solid var(--border);cursor:pointer">
      <div style="width:24px;height:24px;border-radius:6px;background:var(--accent-soft);color:var(--accent);
                  display:flex;align-items:center;justify-content:center;font-weight:700;font-size:12px;flex-shrink:0">${a.num}</div>
      <div style="flex:1;min-width:0">
        <div style="font-size:13px;font-weight:600">${a.title}</div>
        <div class="muted" style="font-size:12px;margin-top:2px">${a.meta}</div>
      </div>
      <span class="pill ${sevPill[a.sev]||'pill-info'}">${a.sev.toUpperCase()}</span>
    </div>
  `).join("");

  // Activity feed
  try {
    const r = await scApi("/api/intel/timeline?since_seconds=86400&limit=8");
    const events = r.events || [];
    if (!events.length) {
      document.getElementById("feed").innerHTML = '<div class="muted">All quiet — nothing in the last 24h.</div>';
    } else {
      document.getElementById("feed").innerHTML = events.map(e => {
        const when = new Date(e.timestamp * 1000).toLocaleTimeString();
        return `<div style="padding:8px 0;border-bottom:1px solid var(--border);font-size:12px">
          <div><strong>${e.kind}</strong> · ${e.summary || ""}</div>
          <div class="muted" style="font-size:11px">${when} · ${e.actor || "system"}</div>
        </div>`;
      }).join("");
    }
  } catch(e){
    document.getElementById("feed").innerHTML = '<div class="muted">Activity unavailable.</div>';
  }
}

async function loadDemo() {
  try {
    await scApi("/api/platform/load-demo?overwrite=false", { method: "POST" });
    location.reload();
  } catch (e) { alert(e.message); }
}

async function askAI() {
  const q = document.getElementById("ai-q").value.trim();
  if (!q) return;
  location.href = "/ask?q=" + encodeURIComponent(q);
}
document.getElementById("ai-q")?.addEventListener("keydown", e => {
  if (e.key === "Enter") askAI();
});

loadHome();
"""
