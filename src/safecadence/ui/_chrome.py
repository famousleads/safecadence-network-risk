"""
v9.0 — Universal app chrome.

ONE shell that wraps every page in SafeCadence:

  * Left sidebar with 7 navigation groups (collapsible)
  * Top bar with breadcrumb + action buttons
  * Cmd+K command palette modal with fuzzy search
  * Right-side slide-over for entity details
  * Light + dark theme toggle
  * Mobile responsive — sidebar collapses to bottom-tab nav < 720px
  * Severity-coded pills, status dots, sparklines
  * Inline AI-everywhere via the existing /api/intel/ask
  * Live notifications bell

Every page calls `wrap(title, body, page_script)` and gets the full
v9 experience automatically.
"""

from __future__ import annotations


_HEAD = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<meta name="theme-color" content="#1F6F6A" />
<title>SafeCadence — %TITLE%</title>
<link rel="manifest" href="/manifest.webmanifest" />
<link rel="stylesheet" href="/static/responsive.css" />
<style>
:root {
  --bg: #0b1020; --panel: #121a33; --panel-2: #1a2447;
  --border: #26315b; --text: #e7ecf5; --muted: #8b95b1;
  --accent: #7c5cff; --accent-soft: rgba(124, 92, 255, 0.15);
  --bad: #ef4444; --warn: #f59e0b; --med: #fde68a;
  --info: #3b82f6; --ok: #10b981;
}
body[data-theme="light"] {
  --bg: #f8fafc; --panel: #ffffff; --panel-2: #f1f5f9;
  --border: #e2e8f0; --text: #0f172a; --muted: #64748b;
  --accent: #6d28d9; --accent-soft: rgba(109, 40, 217, 0.1);
}
* { box-sizing: border-box; }
body {
  margin: 0; font: 14px/1.55 -apple-system, "Segoe UI", Inter, sans-serif;
  background: var(--bg); color: var(--text); display: flex; min-height: 100vh;
}
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }

/* ============ SIDEBAR ============ */
aside.sc-sidebar {
  width: 240px; background: var(--panel);
  border-right: 1px solid var(--border);
  padding: 14px 12px; flex-shrink: 0; display: flex; flex-direction: column;
  height: 100vh; position: sticky; top: 0; overflow-y: auto;
}
aside.sc-sidebar .sc-logo {
  font-weight: 800; font-size: 15px; padding: 4px 8px; margin-bottom: 12px;
  cursor: pointer;
}
aside.sc-sidebar .sc-logo .dot { color: var(--accent); }
aside.sc-sidebar .sc-search {
  background: var(--panel-2); border: 1px solid var(--border);
  border-radius: 8px; padding: 6px 10px; margin-bottom: 14px;
  display: flex; align-items: center; gap: 8px; cursor: pointer;
}
aside.sc-sidebar .sc-search input {
  background: transparent; border: 0; color: var(--text); font: inherit;
  flex: 1; outline: 0; cursor: pointer; pointer-events: none;
}
aside.sc-sidebar .sc-search kbd {
  background: var(--bg); padding: 2px 6px; border-radius: 4px;
  font-size: 11px; color: var(--muted); border: 1px solid var(--border);
}
aside.sc-sidebar .group { margin-top: 10px; }
aside.sc-sidebar .group-title {
  font-size: 11px; color: var(--muted); text-transform: uppercase;
  letter-spacing: 0.5px; padding: 4px 8px;
}
aside.sc-sidebar .nav-item, aside.sc-sidebar .sub {
  display: flex; align-items: center; gap: 8px; padding: 6px 8px;
  border-radius: 6px; cursor: pointer; font-size: 13px; color: var(--text);
  text-decoration: none;
}
aside.sc-sidebar .sub { font-size: 12px; padding-left: 28px; color: var(--muted); }
aside.sc-sidebar .nav-item:hover, aside.sc-sidebar .sub:hover {
  background: var(--panel-2); color: var(--text);
}
aside.sc-sidebar .nav-item.active, aside.sc-sidebar .sub.active {
  background: var(--accent-soft); color: var(--accent); font-weight: 600;
}
aside.sc-sidebar .nav-item .icon { width: 18px; text-align: center; }
aside.sc-sidebar .footer {
  margin-top: auto; padding: 10px 8px; border-top: 1px solid var(--border);
  font-size: 12px; color: var(--muted); display: flex;
  align-items: center; justify-content: space-between;
}
aside.sc-sidebar .footer button {
  background: transparent; border: 0; color: var(--muted); cursor: pointer; font-size: 14px;
}
aside.sc-sidebar .footer button:hover { color: var(--text); }

/* ============ MAIN ============ */
main.sc-main { flex: 1; min-width: 0; display: flex; flex-direction: column; }
.sc-topbar {
  background: var(--panel); border-bottom: 1px solid var(--border);
  padding: 10px 24px; display: flex; align-items: center; gap: 12px;
  position: sticky; top: 0; z-index: 5;
}
.sc-breadcrumb { font-size: 13px; color: var(--muted); flex: 1;
                  white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.sc-breadcrumb strong { color: var(--text); }
.sc-iconbtn {
  background: var(--panel-2); border: 1px solid var(--border);
  border-radius: 8px; padding: 6px 10px; cursor: pointer; font-size: 14px;
  color: var(--text); position: relative; display: inline-flex; align-items: center; gap: 6px;
}
.sc-iconbtn:hover { border-color: var(--accent); }
.sc-iconbtn .badge {
  position: absolute; top: -4px; right: -4px; background: var(--bad);
  color: white; font-size: 10px; padding: 1px 5px; border-radius: 8px;
  font-weight: 700; display: none;
}
.sc-iconbtn.has-events .badge { display: inline-block; }

/* v12.1 — HA / cluster status badge in the topbar. */
.sc-cluster-badge {
  display: inline-block; padding: 3px 8px; margin-left: 6px;
  border-radius: 999px; font-size: 11px; font-weight: 700;
  letter-spacing: 0.04em; text-transform: uppercase;
  border: 1px solid transparent; cursor: help;
}
.sc-cluster-badge-hidden  { display: none; }
.sc-cluster-badge-active  { background: rgba(16,185,129,.16);
                            color: #10b981; border-color: rgba(16,185,129,.4); }
.sc-cluster-badge-standby { background: rgba(245,158,11,.16);
                            color: #f59e0b; border-color: rgba(245,158,11,.4); }
.sc-cluster-badge-error   { background: rgba(220,38,38,.16);
                            color: #dc2626; border-color: rgba(220,38,38,.4); }

.sc-page { padding: 24px 28px; max-width: 1280px; }

/* ============ ONBOARDING BANNER ============ */
.sc-banner {
  background: linear-gradient(90deg, #2a1c5e, #4c2c8c);
  padding: 10px 24px; display: none; align-items: center; gap: 14px;
  border-bottom: 1px solid var(--border); color: white;
}
.sc-banner.show { display: flex; }
.sc-banner .text { flex: 1; font-size: 13px; }
.sc-banner a {
  background: white; color: #2a1c5e; padding: 4px 12px; border-radius: 6px;
  font-weight: 600; font-size: 12px; text-decoration: none;
}
.sc-banner button.dismiss {
  background: transparent; border: 0; color: rgba(255,255,255,0.7);
  cursor: pointer; font-size: 18px;
}

/* ============ COMMAND PALETTE ============ */
.sc-palette-bg {
  display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.55);
  z-index: 200; backdrop-filter: blur(2px);
  align-items: flex-start; justify-content: center; padding-top: 12vh;
}
.sc-palette-bg.open { display: flex; }
.sc-palette {
  background: var(--panel); border: 1px solid var(--border);
  border-radius: 12px; width: 560px; max-width: 90vw;
  box-shadow: 0 20px 60px rgba(0,0,0,0.5);
}
.sc-palette input {
  width: 100%; padding: 14px 18px; background: transparent; border: 0;
  border-bottom: 1px solid var(--border); color: var(--text);
  font: inherit; outline: 0; font-size: 15px;
}
.sc-palette .results { padding: 6px 0; max-height: 60vh; overflow: auto; }
.sc-palette .pgroup-title {
  font-size: 11px; color: var(--muted); padding: 6px 18px;
  text-transform: uppercase; letter-spacing: 0.5px;
}
.sc-palette .presult {
  padding: 9px 18px; cursor: pointer; font-size: 13px;
  display: flex; align-items: center; gap: 10px; color: var(--text);
}
.sc-palette .presult:hover, .sc-palette .presult.selected {
  background: var(--accent-soft);
}
.sc-palette .presult .icon { width: 18px; }
.sc-palette .presult .meta { color: var(--muted); font-size: 11px; margin-left: auto; }

/* ============ SLIDE-OVER ============ */
.sc-slideover-bg {
  display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.4); z-index: 100;
}
.sc-slideover-bg.open { display: block; }
.sc-slideover {
  display: none; position: fixed; top: 0; right: 0; bottom: 0;
  width: 480px; max-width: 90vw;
  background: var(--panel); border-left: 1px solid var(--border);
  z-index: 101; padding: 20px 24px; overflow: auto;
  animation: slidein 0.18s ease-out;
}
.sc-slideover.open { display: block; }
@keyframes slidein {
  from { transform: translateX(20px); opacity: 0; }
  to   { transform: translateX(0); opacity: 1; }
}
.sc-slideover .so-head {
  display: flex; align-items: center; justify-content: space-between;
  margin-bottom: 12px;
}
.sc-slideover h2 { margin: 0; font-size: 16px; }
.sc-slideover .so-close {
  background: transparent; border: 0; color: var(--muted); cursor: pointer; font-size: 18px;
}

/* ============ NOTIFICATIONS DRAWER ============ */
.sc-drawer {
  position: fixed; top: 60px; right: 12px; width: 380px;
  max-height: 70vh; overflow: auto;
  background: var(--panel); border: 1px solid var(--border);
  border-radius: 12px; box-shadow: 0 8px 32px rgba(0,0,0,0.4);
  padding: 12px 14px; z-index: 200; display: none;
}
.sc-drawer.open { display: block; }
.sc-drawer h3 { margin: 0 0 8px; font-size: 14px; }
.sc-drawer .item {
  padding: 8px 4px; border-bottom: 1px solid var(--border);
  font-size: 12px; cursor: pointer;
}
.sc-drawer .item:hover { background: var(--panel-2); }
.sc-drawer .item .meta { color: var(--muted); font-size: 11px; margin-top: 2px; }

/* ============ COMMON WIDGETS ============ */
h1 { font-size: 22px; margin: 0 0 4px; }
h2 { font-size: 16px; margin: 24px 0 8px; }
.muted { color: var(--muted); font-size: 12px; }
.card {
  background: var(--panel); border: 1px solid var(--border);
  border-radius: 12px; padding: 18px 20px; margin-bottom: 12px;
}
input, textarea, select, button {
  width: 100%; padding: 10px 12px; border-radius: 8px;
  background: var(--bg); color: var(--text); border: 1px solid var(--border);
  font: inherit;
}
button.primary {
  background: var(--accent); color: white; border: 0;
  cursor: pointer; font-weight: 600;
}
button.primary:hover { opacity: 0.9; }
button.alt {
  background: var(--panel-2); border: 1px solid var(--border);
  color: var(--text); cursor: pointer; font-weight: 600;
}
pre { background: var(--bg); padding: 12px; border-radius: 8px;
      white-space: pre-wrap; word-break: break-word;
      max-height: 480px; overflow: auto; font-size: 12px; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--border); }
th { color: var(--muted); font-weight: 500; }

.pill {
  display: inline-block; padding: 2px 8px; border-radius: 999px;
  font-size: 11px; font-weight: 600; background: var(--panel-2); color: var(--text);
}
.pill-crit { background: rgba(239,68,68,0.15); color: var(--bad); }
.pill-high { background: rgba(245,158,11,0.15); color: var(--warn); }
.pill-med  { background: rgba(253,230,138,0.15); color: var(--med); }
.pill-info { background: rgba(59,130,246,0.15); color: var(--info); }
.pill-ok   { background: rgba(16,185,129,0.15); color: var(--ok); }

/* ============ HELP TOOLTIP ============ */
.sc-help {
  display: inline-flex; align-items: center; justify-content: center;
  width: 16px; height: 16px; border-radius: 50%;
  background: var(--panel-2); color: var(--muted);
  font-size: 11px; font-weight: 700; cursor: help;
  border: 1px solid var(--border); margin-left: 4px;
  vertical-align: middle; text-decoration: none;
  transition: all 0.15s;
}
.sc-help:hover { background: var(--accent); color: white; border-color: var(--accent); }
.sc-help::before { content: "?"; }
.sc-help-popover {
  position: fixed; z-index: 250; max-width: 360px;
  background: var(--panel); border: 1px solid var(--border);
  border-radius: 10px; padding: 14px 16px;
  box-shadow: 0 10px 40px rgba(0,0,0,0.5);
  font-size: 13px; line-height: 1.5;
  display: none;
}
.sc-help-popover.open { display: block; }
.sc-help-popover h4 {
  margin: 0 0 6px; font-size: 13px; font-weight: 700;
  color: var(--accent);
}
.sc-help-popover .body { color: var(--text); }
.sc-help-popover .values, .sc-help-popover .example, .sc-help-popover .docs {
  margin-top: 8px; font-size: 12px;
}
.sc-help-popover .values strong, .sc-help-popover .example strong {
  display: block; color: var(--muted); text-transform: uppercase;
  letter-spacing: 0.5px; font-size: 10px; margin-bottom: 2px;
}
.sc-help-popover .values ul {
  margin: 0; padding-left: 18px; font-size: 12px;
}
.sc-help-popover .example code {
  background: var(--bg); padding: 2px 6px; border-radius: 4px;
  font-family: ui-monospace, Menlo, monospace;
}
.sc-help-popover .docs a { font-size: 11px; }

/* Pulse animation used by the first-time nudge so users learn that
   the ? icon is interactive. Plays twice on first visit, never again. */
@keyframes scNudge {
  0%, 100% { box-shadow: 0 0 0 0 rgba(124, 92, 255, 0); transform: scale(1); }
  50%      { box-shadow: 0 0 0 6px rgba(124, 92, 255, 0.35); transform: scale(1.2); }
}

/* ============ MOBILE ============ */
@media (max-width: 720px) {
  body { flex-direction: column; }
  aside.sc-sidebar {
    position: fixed; bottom: 0; top: auto; width: 100%; height: 64px;
    flex-direction: row; padding: 6px; border-right: 0;
    border-top: 1px solid var(--border); z-index: 50; overflow-x: auto;
  }
  aside.sc-sidebar .sc-logo, aside.sc-sidebar .sc-search,
  aside.sc-sidebar .group-title, aside.sc-sidebar .footer { display: none; }
  aside.sc-sidebar .group { display: flex; flex: 1; }
  aside.sc-sidebar .nav-item {
    flex: 1; flex-direction: column; gap: 2px; font-size: 10px; padding: 4px; text-align: center;
  }
  aside.sc-sidebar .sub { display: none; }
  main.sc-main { padding-bottom: 70px; width: 100%; }
  .sc-topbar { padding: 10px 12px; flex-wrap: wrap; }
  .sc-page { padding: 14px; }
  .sc-slideover { width: 100%; }
}
</style>
</head>
<body data-theme="dark">

<!-- ============ A11Y: skip-to-content ============ -->
<a class="skip-to-content" href="#sc-main-content">Skip to main content</a>

<!-- ============ SIDEBAR ============ -->
<aside class="sc-sidebar" id="sc-sidebar" aria-label="Primary navigation">
  <div class="sc-logo" onclick="location.href='/home'" role="link" tabindex="0"
       aria-label="SafeCadence home">
    SafeCadence<span class="dot">.</span>
  </div>
  <div class="sc-search" onclick="scOpenPalette()">
    <span style="color:var(--muted)">🔎</span>
    <input placeholder="Search…" readonly />
    <kbd>⌘K</kbd>
  </div>

  <a class="nav-item" id="nav-home" href="/home">
    <span class="icon">🏠</span> Home
  </a>

  <div class="group">
    <div class="group-title">Discover</div>
    <a class="sub" id="nav-inventory" href="/inventory">Inventory</a>
    <a class="sub" id="nav-groups" href="/groups">Groups</a>
    <a class="sub" id="nav-topology" href="/topology">Topology</a>
    <a class="sub" id="nav-shadow-it" href="/shadow-it">Shadow IT</a>
    <a class="sub" id="nav-coverage" href="/coverage">Coverage</a>
    <a class="sub" id="nav-changes" href="/changes">Changes</a>
    <a class="sub" id="nav-discovery-jobs" href="/discovery-jobs">Schedule</a>
    <a class="sub" id="nav-tags" href="/tags">Tags</a>
    <a class="sub" id="nav-scope" href="/scope">Compliance scope</a>
  </div>

  <div class="group">
    <div class="group-title">Compliance</div>
    <a class="sub" id="nav-policies" href="/policies">Policies</a>
    <a class="sub" id="nav-findings" href="/findings">Findings</a>
    <a class="sub" id="nav-drift" href="/drift">Drift</a>
    <a class="sub" id="nav-evidence" href="/evidence">Evidence</a>
    <a class="sub" id="nav-compliance" href="/compliance">Compliance</a>
    <a class="sub" id="nav-risks" href="/risks">Risk register</a>
    <a class="sub" id="nav-vendors" href="/vendors">Vendor risk</a>
  </div>

  <div class="group">
    <div class="group-title">Identity</div>
    <a class="sub" id="nav-identity" href="/identity">Translator</a>
    <a class="sub" id="nav-jit" href="/jit">JIT grants</a>
    <a class="sub" id="nav-paths" href="/paths">Attack paths</a>
    <a class="sub" id="nav-simulate" href="/simulate">Simulate</a>
  </div>

  <div class="group">
    <div class="group-title">Execute</div>
    <a class="sub" id="nav-builder" href="/builder">Builder</a>
    <a class="sub" id="nav-approvals" href="/approvals">Approvals</a>
    <a class="sub" id="nav-queue" href="/queue">Queue</a>
    <a class="sub" id="nav-rollback" href="/rollback">Rollback</a>
  </div>

  <div class="group">
    <div class="group-title">Automation</div>
    <a class="sub" id="nav-automation" href="/automation">Rules</a>
    <a class="sub" id="nav-watchlists" href="/watchlists">Watchlists</a>
    <a class="sub" id="nav-briefing" href="/briefing">Briefings</a>
  </div>

  <div class="group">
    <div class="group-title">Audit</div>
    <a class="sub" id="nav-timeline" href="/timeline">Timeline</a>
    <a class="sub" id="nav-audit" href="/audit">Activity log</a>
    <a class="sub" id="nav-idp-groups" href="/idp-groups">IdP groups</a>
    <a class="sub" id="nav-share" href="/share">Public shares</a>
  </div>

  <div class="group">
    <div class="group-title">Reports</div>
    <a class="sub" id="nav-reports" href="/reports">📊 Builder</a>
  </div>

  <!-- v12.0.0a6 — Cluster & AI nav. Shows v12+ surfaces in one place. -->
  <div class="group">
    <div class="group-title">Cluster &amp; AI</div>
    <a class="sub" id="nav-cluster" href="/cluster-status">🗄️ Cluster status</a>
    <a class="sub" id="nav-customer" href="/customer">🤝 Customer portal</a>
    <a class="sub" id="nav-ai-agents" href="/ai-agents">🤖 AI agents</a>
    <a class="sub" id="nav-api-keys" href="/api-keys">🔐 Identity &amp; API key governance</a>
  </div>

  <div class="group">
    <div class="group-title">Settings</div>
    <a class="sub" id="nav-settings" href="/settings">⚙️ Settings</a>
    <a class="sub" id="nav-users" href="/users">👥 Users</a>
    <a class="sub" id="nav-capabilities" href="/capabilities">🔑 Capabilities</a>
    <a class="sub" id="nav-onboarding" href="/onboarding">Onboarding</a>
    <a class="sub" id="nav-hub" href="/hub">All tools</a>
    <a class="sub" id="nav-help" href="/help">📖 Help</a>
    <a class="sub" id="nav-help-topics" href="/help/topics">🔍 All help topics</a>
  </div>

  <div class="footer">
    <div id="sc-user">👤 admin</div>
    <div>
      <button onclick="scToggleTheme()" title="toggle light/dark">🌗</button>
      <button onclick="scShowHelp()" title="keyboard shortcuts">⌨</button>
    </div>
  </div>
</aside>

<!-- ============ MAIN ============ -->
<main class="sc-main" id="sc-main-content" role="main">

  <!-- Top bar -->
  <div class="sc-topbar" role="banner">
    <button class="sc-hamburger" aria-label="Toggle navigation menu"
            aria-controls="sc-sidebar" aria-expanded="false"
            onclick="scToggleSidebar()">&#9776;</button>
    <div class="sc-breadcrumb" id="sc-breadcrumb" aria-label="Breadcrumb">
      <strong>%TITLE%</strong>
    </div>
    <button class="sc-iconbtn" onclick="scOpenPalette()" title="Cmd+K"
            aria-label="Open command palette (Cmd+K)">⌘K</button>
    <button class="sc-iconbtn" onclick="location.href='/ask'"
            aria-label="Open Ask AI">🤖 Ask AI</button>
    <button class="sc-iconbtn" id="sc-bell" onclick="scToggleDrawer()"
            aria-label="Notifications" aria-haspopup="true">
      🔔<span class="badge" aria-hidden="true">0</span>
    </button>
    <!-- v12.1 — HA / cluster status badge.
         Hidden by default; the cluster.js fetch turns it on only when
         /api/v1/cluster/status returns a real cluster view. -->
    <span id="sc-cluster-badge" class="sc-cluster-badge sc-cluster-badge-hidden"
          title="Cluster role"></span>
  </div>

  <!-- a11y live region for dynamic status messages (report preview etc) -->
  <div id="sc-live" class="sr-only" aria-live="polite" aria-atomic="true"></div>

  <!-- Onboarding banner -->
  <div class="sc-banner" id="sc-banner">
    <div class="text">👋 New here? Take the 5-step tour — fleet to live findings in under 5 min.</div>
    <a href="/onboarding">Start tour</a>
    <button class="dismiss" onclick="scDismissBanner()">✕</button>
  </div>

  <!-- Notifications drawer (shown on bell click) -->
  <div class="sc-drawer" id="sc-drawer">
    <h3>🔔 Recent activity</h3>
    <div id="sc-drawer-list"><div class="muted">Loading…</div></div>
  </div>

  <!-- Page body -->
  <div class="sc-page">
"""


_FOOT = """
  </div>
</main>

<!-- ============ COMMAND PALETTE ============ -->
<div class="sc-palette-bg" id="sc-palette-bg" onclick="scClosePaletteBg(event)">
  <div class="sc-palette" onclick="event.stopPropagation()">
    <input id="sc-palette-input" placeholder="Search assets, tools, findings…" autocomplete="off" />
    <div class="results" id="sc-palette-results"></div>
  </div>
</div>

<!-- ============ HELP POPOVER ============ -->
<div class="sc-help-popover" id="sc-help-popover"></div>

<!-- ============ SLIDE-OVER ============ -->
<div class="sc-slideover-bg" onclick="scCloseSlide()"></div>
<div class="sc-slideover" id="sc-slideover">
  <div class="so-head">
    <h2 id="sc-so-title">—</h2>
    <button class="so-close" onclick="scCloseSlide()">✕</button>
  </div>
  <div id="sc-so-body"></div>
</div>

<script>
// ============================================================
//  SafeCadence v9 universal app chrome.
// ============================================================

const SC_TOKEN = localStorage.getItem("SC_TOKEN") || "";

// v12.1 — Cluster status poller. Pings /api/v1/cluster/status every 30s.
// Shows the topbar badge only when this install is actually clustered
// (peers configured) — single-node installs see nothing extra.
async function scUpdateClusterBadge() {
  try {
    const r = await fetch("/api/v1/cluster/status", {cache: "no-store"});
    if (!r.ok) return;
    const d = await r.json();
    const badge = document.getElementById("sc-cluster-badge");
    if (!badge) return;
    const peerCount = d.peer_count || 0;
    if (peerCount === 0) { badge.classList.add("sc-cluster-badge-hidden"); return; }
    const active = (d.local && d.local.is_active_node);
    const reachable = d.reachable_peers || 0;
    const lag = (d.replication_lag && d.replication_lag.lag_seconds);
    badge.classList.remove("sc-cluster-badge-hidden",
                            "sc-cluster-badge-active",
                            "sc-cluster-badge-standby",
                            "sc-cluster-badge-error");
    badge.classList.add(active ? "sc-cluster-badge-active"
                                : "sc-cluster-badge-standby");
    badge.textContent = active ? "ACTIVE" : "STANDBY";
    let tip = (active ? "This node is the active cluster leader."
                       : "This node is on standby; reads only.");
    tip += " Peers reachable: " + reachable + "/" + peerCount + ".";
    if (lag != null) tip += " Replication lag: " + lag + "s.";
    badge.title = tip;
  } catch (e) { /* no-op; cluster polling is best-effort */ }
}
scUpdateClusterBadge();
setInterval(scUpdateClusterBadge, 30000);

// Help registry — injected by the chrome from help_registry.py
window.SC_HELP = %SC_HELP_JSON%;

// ---- Hover state machine ----
// mouseenter on ? icon → 400ms delay → open popover
// mouseleave from icon AND popover → 200ms delay → close
// Mouse over popover keeps it open so users can read multi-line content.
let scHoverOpenTimer = null;
let scHoverCloseTimer = null;
let scActiveHelpId = null;

function scInitHelp() {
  // Convert every <span class="sc-help" data-help="X"></span> into an
  // accessible ? icon that opens the popover on click, hover, or
  // keyboard.
  document.querySelectorAll(".sc-help").forEach(el => {
    if (el.dataset.scHelpInit) return;
    el.dataset.scHelpInit = "1";
    el.setAttribute("tabindex", "0");
    const id = el.dataset.help;
    el.setAttribute("title", "Help — " + id);
    // Click — pin the popover open until the user dismisses it
    el.addEventListener("click", e => {
      e.preventDefault(); e.stopPropagation();
      clearTimeout(scHoverCloseTimer);
      scShowHelp(id, el);
    });
    // Keyboard — Enter / Space
    el.addEventListener("keydown", e => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        scShowHelp(id, el);
      }
    });
    // Hover — open after 400ms; close 200ms after both icon AND popover unhovered
    el.addEventListener("mouseenter", () => {
      clearTimeout(scHoverCloseTimer);
      clearTimeout(scHoverOpenTimer);
      scHoverOpenTimer = setTimeout(() => scShowHelp(id, el), 400);
    });
    el.addEventListener("mouseleave", () => {
      clearTimeout(scHoverOpenTimer);
      scHoverCloseTimer = setTimeout(() => scClosePopover(), 200);
    });
    // Focus opens too (keyboard-only users)
    el.addEventListener("focus", () => scShowHelp(id, el));
  });

  // Wire popover hover so moving INTO it keeps it open
  const pop = document.getElementById("sc-help-popover");
  if (pop && !pop.dataset.scHoverInit) {
    pop.dataset.scHoverInit = "1";
    pop.addEventListener("mouseenter", () => {
      clearTimeout(scHoverCloseTimer);
    });
    pop.addEventListener("mouseleave", () => {
      scHoverCloseTimer = setTimeout(() => scClosePopover(), 200);
    });
  }
}

// ---- First-time per-page nudge ----
// On each page's first visit, auto-open the most-important help icon
// once. Persists "seen" in localStorage so it never nags again.
const SC_NUDGE_BY_PATH = {
  "/home":         "next-3-actions",
  "/findings":     "finding-kind",
  "/paths":        "path-risk",
  "/jit":          null,             // self-explanatory
  "/identity":     "translator-intent",
  "/simulate":     "simulator-input",
  "/automation":   "automation-action",
  "/watchlists":   "watchlist-entity-kind",
  "/share":        "share-scope",
  "/tour":         null,             // tour itself IS the nudge
  "/onboarding":   null,
  "/help":         null,
};

function scMaybeNudge() {
  const id = SC_NUDGE_BY_PATH[location.pathname];
  if (!id) return;
  const key = "SC_NUDGED_" + location.pathname;
  if (localStorage.getItem(key)) return;
  // Find the matching ? icon on this page
  const el = document.querySelector(`.sc-help[data-help="${id}"]`);
  if (!el) return;
  // Wait for the page to settle so the popover lands on a stable layout
  setTimeout(() => {
    scShowHelp(id, el);
    localStorage.setItem(key, "1");
    // Subtle pulse on the icon so the user understands the popover is
    // tied to the ? — they'll know to look for it next time.
    el.style.animation = "scNudge 1.6s ease-in-out 2";
  }, 800);
}

function scShowHelp(id, anchor) {
  const entry = (window.SC_HELP || {})[id];
  const pop = document.getElementById("sc-help-popover");
  if (!entry) {
    pop.innerHTML = `<h4>Help: ${id}</h4>
      <div class="body muted">No help text registered for this field.
      Add an entry in <code>ui/help_registry.py</code>.</div>`;
  } else {
    let html = `<h4>${entry.title || id}</h4>`;
    if (entry.body) html += `<div class="body">${entry.body}</div>`;
    if (entry.values && entry.values.length) {
      html += `<div class="values"><strong>Accepted values</strong>
                <ul>${entry.values.map(v => `<li>${v}</li>`).join("")}</ul>
              </div>`;
    }
    if (entry.example) {
      html += `<div class="example"><strong>Example</strong>
                <code>${entry.example}</code></div>`;
    }
    if (entry.docs_href) {
      html += `<div class="docs"><a href="${entry.docs_href}">Open the full tool →</a></div>`;
    }
    pop.innerHTML = html;
  }
  // Position next to anchor
  const rect = anchor.getBoundingClientRect();
  let top = rect.bottom + 8;
  let left = rect.left;
  // Keep on screen
  pop.classList.add("open");
  const popRect = pop.getBoundingClientRect();
  if (left + popRect.width > window.innerWidth - 12) {
    left = window.innerWidth - popRect.width - 12;
  }
  if (top + popRect.height > window.innerHeight - 12) {
    top = rect.top - popRect.height - 8;
  }
  pop.style.left = Math.max(12, left) + "px";
  pop.style.top = top + "px";
}

function scClosePopover() {
  document.getElementById("sc-help-popover")?.classList.remove("open");
}

document.addEventListener("click", e => {
  const pop = document.getElementById("sc-help-popover");
  if (pop && pop.classList.contains("open") &&
      !pop.contains(e.target) &&
      !e.target.classList.contains("sc-help")) {
    pop.classList.remove("open");
  }
});

async function scApi(path, opts = {}) {
  const r = await fetch(path, {
    ...opts,
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer " + SC_TOKEN,
      ...(opts.headers || {}),
    },
  });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

// ---- Active nav highlighting ----
function scHighlightNav() {
  const path = location.pathname;
  const map = {
    "/home": "nav-home",
    "/inventory": "nav-inventory",
    "/groups": "nav-groups",
    "/topology": "nav-topology",
    "/shadow-it": "nav-shadow-it",
    "/coverage": "nav-coverage",
    "/changes": "nav-changes",
    "/discovery-jobs": "nav-discovery-jobs",
    "/tags": "nav-tags",
    "/scope": "nav-scope",
    "/policies": "nav-policies",
    "/findings": "nav-findings",
    "/drift": "nav-drift",
    "/evidence": "nav-evidence",
    "/identity": "nav-identity",
    "/jit": "nav-jit",
    "/paths": "nav-paths",
    "/simulate": "nav-simulate",
    "/builder": "nav-builder",
    "/approvals": "nav-approvals",
    "/queue": "nav-queue",
    "/rollback": "nav-rollback",
    "/automation": "nav-automation",
    "/watchlists": "nav-watchlists",
    "/briefing": "nav-briefing",
    "/timeline": "nav-timeline",
    "/audit": "nav-audit",
    "/idp-groups": "nav-idp-groups",
    "/share": "nav-share",
    "/settings": "nav-settings",
    "/users": "nav-users",
    "/capabilities": "nav-capabilities",
    "/onboarding": "nav-onboarding",
    "/hub": "nav-hub",
    "/help": "nav-help",
  };
  const id = map[path];
  if (id) {
    const el = document.getElementById(id);
    if (el) el.classList.add("active");
  }
}

// ---- Theme ----
function scToggleTheme() {
  const cur = document.body.getAttribute("data-theme");
  const next = cur === "dark" ? "light" : "dark";
  document.body.setAttribute("data-theme", next);
  localStorage.setItem("SC_THEME", next);
}
(function () {
  const saved = localStorage.getItem("SC_THEME");
  if (saved) document.body.setAttribute("data-theme", saved);
})();

// v9.31 — Compliance-off mode. When disabled, hide the Compliance group's
// auditor-facing entries (/compliance, /risks, /evidence) so shops that
// don't sell to regulated customers don't see the audit chrome. Policies +
// Findings + Drift remain — they're security hygiene, not compliance.
(async function () {
  try {
    const r = await fetch("/api/settings/compliance-mode",
                            {credentials: "include"});
    if (!r.ok) return;
    const cfg = await r.json();
    if (cfg && cfg.enabled === false) {
      ["nav-compliance", "nav-risks", "nav-evidence", "nav-vendors"].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.style.display = "none";
      });
    }
  } catch (e) { /* mode flag unreachable — leave default UI */ }
})();

// ---- Notifications drawer ----
async function scLoadNotifs() {
  try {
    const r = await scApi("/api/intel/timeline?since_seconds=86400&limit=15");
    const events = r.events || [];
    const bell = document.getElementById("sc-bell");
    const badge = bell.querySelector(".badge");
    if (events.length) {
      bell.classList.add("has-events");
      badge.textContent = String(events.length);
    } else {
      bell.classList.remove("has-events");
    }
    const list = document.getElementById("sc-drawer-list");
    if (!events.length) {
      list.innerHTML = '<div class="muted">All quiet — nothing in the last 24h.</div>';
      return;
    }
    list.innerHTML = events.map(e => {
      const when = new Date(e.timestamp * 1000).toLocaleString();
      const cls = (e.severity === "critical" || e.severity === "high") ? "pill-crit"
                  : e.severity === "medium" ? "pill-high" : "pill-info";
      return `<div class="item">
        <span class="pill ${cls}">${e.kind}</span>
        ${e.summary || ""}
        <div class="meta">${when} · ${e.actor || "system"}</div>
      </div>`;
    }).join("");
  } catch (e) { /* silent */ }
}
function scToggleDrawer() {
  document.getElementById("sc-drawer").classList.toggle("open");
}
document.addEventListener("click", (e) => {
  const drawer = document.getElementById("sc-drawer");
  const bell = document.getElementById("sc-bell");
  if (drawer && drawer.classList.contains("open") &&
      !drawer.contains(e.target) && !bell.contains(e.target)) {
    drawer.classList.remove("open");
  }
});

// ---- Onboarding banner ----
async function scMaybeShowBanner() {
  if (localStorage.getItem("SC_ONBOARDING_DISMISSED")) return;
  try {
    const r = await scApi("/api/identity/findings");
    if (r.count === 0) {
      document.getElementById("sc-banner").classList.add("show");
    }
  } catch (e) { /* ignore */ }
}
function scDismissBanner() {
  document.getElementById("sc-banner").classList.remove("show");
  localStorage.setItem("SC_ONBOARDING_DISMISSED", "1");
}

// ---- Command palette ----
const SC_TOOLS = [
  { kind: "tool", icon: "🏠", name: "Home", href: "/home" },
  { kind: "tool", icon: "📋", name: "Inventory", href: "/inventory" },
  { kind: "tool", icon: "🗺️", name: "Topology", href: "/topology" },
  { kind: "tool", icon: "✅", name: "Policies", href: "/policies" },
  { kind: "tool", icon: "🚩", name: "Findings", href: "/findings" },
  { kind: "tool", icon: "📉", name: "Drift", href: "/drift" },
  { kind: "tool", icon: "📑", name: "Evidence packs", href: "/evidence" },
  { kind: "tool", icon: "🔐", name: "Identity translator", href: "/identity" },
  { kind: "tool", icon: "⏱️", name: "JIT grants", href: "/jit" },
  { kind: "tool", icon: "🎯", name: "Attack paths", href: "/paths" },
  { kind: "tool", icon: "🔮", name: "Simulate", href: "/simulate" },
  { kind: "tool", icon: "⚙️", name: "Command builder", href: "/builder" },
  { kind: "tool", icon: "🛡️", name: "Approvals", href: "/approvals" },
  { kind: "tool", icon: "🤖", name: "Automation rules", href: "/automation" },
  { kind: "tool", icon: "📌", name: "Watchlists", href: "/watchlists" },
  { kind: "tool", icon: "📰", name: "Morning briefing", href: "/briefing" },
  { kind: "tool", icon: "📜", name: "Audit timeline", href: "/timeline" },
  { kind: "tool", icon: "🔗", name: "Public shares", href: "/share" },
  { kind: "tool", icon: "🧭", name: "Onboarding", href: "/onboarding" },
  { kind: "tool", icon: "🧰", name: "All tools", href: "/hub" },
  { kind: "tool", icon: "💬", name: "Ask AI", href: "/ask" },
];

let scPaletteSelected = 0;

function scOpenPalette() {
  document.getElementById("sc-palette-bg").classList.add("open");
  setTimeout(() => {
    const i = document.getElementById("sc-palette-input");
    i.value = "";
    i.focus();
    scRenderPalette("");
  }, 50);
}
function scClosePalette() {
  document.getElementById("sc-palette-bg").classList.remove("open");
}
function scClosePaletteBg(e) {
  if (e.target.id === "sc-palette-bg") scClosePalette();
}
function scRenderPalette(q) {
  q = (q || "").toLowerCase();
  const results = q
    ? SC_TOOLS.filter(t => t.name.toLowerCase().includes(q))
    : SC_TOOLS.slice(0, 8);
  const out = document.getElementById("sc-palette-results");
  let html = '<div class="pgroup-title">' + (q ? "Tools" : "Tools (recent)") + '</div>';
  results.forEach((t, i) => {
    const sel = i === scPaletteSelected ? "selected" : "";
    html += `<div class="presult ${sel}" data-href="${t.href}" data-i="${i}">
      <span class="icon">${t.icon}</span>${t.name}<span class="meta">${t.kind}</span>
    </div>`;
  });
  if (q) {
    html += '<div class="pgroup-title">Live search</div>';
    html += `<div class="presult" data-q="${q}">
      <span class="icon">🔎</span>Search "${q}" across assets &amp; findings…<span class="meta">⏎</span>
    </div>`;
    html += '<div class="pgroup-title">AI</div>';
    html += `<div class="presult" data-ai="${q}">
      <span class="icon">🤖</span>Ask AI: "${q}"<span class="meta">⏎</span>
    </div>`;
  }
  out.innerHTML = html;
  out.querySelectorAll(".presult").forEach(el => {
    el.addEventListener("click", () => {
      const href = el.dataset.href;
      const ai = el.dataset.ai;
      const q = el.dataset.q;
      if (href) location.href = href;
      else if (ai) location.href = "/ask?q=" + encodeURIComponent(ai);
      else if (q) location.href = "/home?q=" + encodeURIComponent(q);
    });
  });
}

const scPaletteInput = document.getElementById("sc-palette-input");
if (scPaletteInput) {
  scPaletteInput.addEventListener("input", e => {
    scPaletteSelected = 0;
    scRenderPalette(e.target.value);
  });
  scPaletteInput.addEventListener("keydown", e => {
    const items = document.querySelectorAll("#sc-palette-results .presult");
    if (e.key === "ArrowDown") {
      e.preventDefault();
      scPaletteSelected = Math.min(items.length - 1, scPaletteSelected + 1);
      items.forEach((it, i) => it.classList.toggle("selected", i === scPaletteSelected));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      scPaletteSelected = Math.max(0, scPaletteSelected - 1);
      items.forEach((it, i) => it.classList.toggle("selected", i === scPaletteSelected));
    } else if (e.key === "Enter") {
      e.preventDefault();
      const sel = items[scPaletteSelected];
      if (sel) sel.click();
    }
  });
}

// ---- Slide-over ----
function scOpenSlide(title, html) {
  document.getElementById("sc-so-title").textContent = title;
  document.getElementById("sc-so-body").innerHTML = html;
  document.getElementById("sc-slideover").classList.add("open");
  document.querySelector(".sc-slideover-bg").classList.add("open");
}
function scCloseSlide() {
  document.getElementById("sc-slideover").classList.remove("open");
  document.querySelector(".sc-slideover-bg").classList.remove("open");
}

// ---- Keyboard shortcuts ----
let scShortBuf = "";
let scShortTimer = null;
document.addEventListener("keydown", (e) => {
  if ((e.metaKey || e.ctrlKey) && e.key === "k") {
    e.preventDefault();
    scOpenPalette();
    return;
  }
  if (e.key === "Escape") {
    scClosePalette();
    scCloseSlide();
    document.getElementById("sc-drawer")?.classList.remove("open");
    return;
  }
  if (e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA") return;
  if (e.key === "/") { e.preventDefault(); scOpenPalette(); return; }
  if (e.key === "?") { scShowHelp(); return; }
  scShortBuf += e.key;
  clearTimeout(scShortTimer);
  scShortTimer = setTimeout(() => scShortBuf = "", 700);
  const map = {
    "gh": "/home", "gi": "/inventory", "gf": "/findings",
    "gd": "/drift", "gt": "/timeline", "gp": "/policies",
    "gj": "/jit", "ga": "/automation", "gs": "/simulate",
    "gk": "/ask", "gx": "/hub", "gb": "/briefing",
  };
  if (map[scShortBuf]) location.href = map[scShortBuf];
});

function scShowHelp() {
  alert(
"SafeCadence keyboard shortcuts:\\n\\n" +
"  ⌘ K   command palette\\n" +
"  /     command palette\\n" +
"  ?     this help\\n" +
"  Esc   close any open panel\\n\\n" +
"  g h   Home\\n" +
"  g i   Inventory\\n" +
"  g f   Findings\\n" +
"  g j   JIT grants\\n" +
"  g a   Automation\\n" +
"  g s   Simulate\\n" +
"  g k   Ask AI\\n" +
"  g t   Timeline\\n" +
"  g p   Policies\\n" +
"  g d   Drift\\n" +
"  g x   All tools (Hub)"
  );
}

// ---- v11.1 PWA: register the service worker ---------
// Best-effort. Service workers are an enhancement, not a requirement.
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js', { scope: '/' })
      .catch(() => {/* ignore – PWA is opt-in */});
  });
}

// ---- v11.1 a11y helpers -----------------------------
// Announce a message into the polite live region so assistive tech reads it.
window.scAnnounce = function(msg) {
  const live = document.getElementById('sc-live');
  if (!live) return;
  // Clear then set so duplicate text still re-announces.
  live.textContent = '';
  setTimeout(() => { live.textContent = msg; }, 30);
};

// Toggle the sidebar on mobile/tablet (hamburger button).
window.scToggleSidebar = function() {
  const aside = document.getElementById('sc-sidebar');
  if (!aside) return;
  const btn = document.querySelector('.sc-hamburger');
  const open = aside.classList.toggle('open');
  aside.style.display = open ? 'flex' : '';
  if (btn) btn.setAttribute('aria-expanded', open ? 'true' : 'false');
};

// ---- Boot ----
scHighlightNav();
scLoadNotifs();
setInterval(scLoadNotifs, 60000);
scMaybeShowBanner();
scInitHelp();
// Re-scan for sc-help elements after the page script runs (in case it
// injects more).
setTimeout(scInitHelp, 100);

%PAGE_SCRIPT%

// Re-init help one more time after the page script is done, then nudge
// first-time visitors.
setTimeout(() => { scInitHelp(); scMaybeNudge(); }, 250);

// Close popover on Escape (in addition to existing handlers)
document.addEventListener("keydown", e => {
  if (e.key === "Escape") scClosePopover();
});
</script>

</body>
</html>
"""


def wrap(title: str, body: str, page_script: str = "") -> str:
    """Wrap any page body in the v9 universal chrome."""
    from safecadence.ui.help_registry import help_json
    foot = (_FOOT
            .replace("%PAGE_SCRIPT%", page_script)
            .replace("%SC_HELP_JSON%", help_json()))
    return _HEAD.replace("%TITLE%", title) + body + foot
