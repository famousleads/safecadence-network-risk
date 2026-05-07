// SafeCadence Quick Console — popup script
//
// Stores host + token in chrome.storage.local (sync would push them to
// other Chrome profiles, which is the wrong default for a credential).
// All requests go to the user-configured host; no calls home.

const $ = (s) => document.querySelector(s);
const setupView = $("#setup");
const quickView = $("#quick");

async function getCfg() {
  const o = await chrome.storage.local.get(["host", "token"]);
  return {host: o.host || "", token: o.token || ""};
}

async function setCfg(host, token) {
  await chrome.storage.local.set({host, token});
}

async function api(path, init = {}) {
  const {host, token} = await getCfg();
  if (!host || !token) throw new Error("not configured");
  const url = host.replace(/\/$/, "") + path;
  const headers = init.headers || {};
  headers["Authorization"] = "Bearer " + token;
  const r = await fetch(url, {...init, headers});
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

async function showQuickView() {
  setupView.classList.add("hidden");
  quickView.classList.remove("hidden");
  await renderStatus();
}

async function renderStatus() {
  const card = $("#card-status");
  card.innerHTML = '<div class="empty">⏳ Loading…</div>';
  try {
    const [briefing, drift, license] = await Promise.all([
      api("/api/policy/executive-briefing").catch(() => null),
      api("/api/policy/cross-system-drift").catch(() => null),
      api("/api/platform/license").catch(() => null),
    ]);
    const kev = briefing?.asset_summary?.kev_cves_total ?? 0;
    const fails = briefing?.policy_summary?.total_failures ?? 0;
    const compliance = briefing?.policy_summary?.overall_compliance_pct ?? 0;
    const findings = drift?.finding_count ?? 0;
    card.innerHTML = `
      <div class="stat ${kev > 0 ? 'bad' : 'good'}">
        <div class="v">${kev}</div>
        <div class="l">KEV CVEs in active fleet</div>
      </div>
      <div class="stat ${fails > 0 ? 'warn' : 'good'}">
        <div class="v">${fails}</div>
        <div class="l">policy failures across ${briefing?.policy_summary?.policy_count || 0} policies</div>
      </div>
      <div class="stat">
        <div class="v">${compliance}%</div>
        <div class="l">overall compliance</div>
      </div>
      <div class="stat ${findings > 0 ? 'warn' : 'good'}">
        <div class="v">${findings}</div>
        <div class="l">cross-system drift findings</div>
      </div>
      <div style="border-top:1px solid var(--border);margin-top:8px;padding-top:8px;color:var(--muted);font-size:10px">
        License: <strong>${license?.licensee || 'open-source'}</strong>
        · ${license?.asset_count || 0} of ${license?.max_assets || '∞'} assets
        ${license?.signature_state === 'invalid'
          ? '<span style="color:var(--bad)">· INVALID SIG</span>'
          : license?.signature_state === 'unsigned'
          ? '<span style="color:var(--warn)">· unsigned</span>'
          : ''}
      </div>
    `;
  } catch (e) {
    card.innerHTML = `<div class="empty" style="color:var(--bad)">${e.message}</div>`;
  }
}

// ----- setup actions -----

$("#connect").onclick = async () => {
  const host = $("#host").value.trim();
  const token = $("#token").value.trim();
  if (!host || !token) {
    alert("Need host + token");
    return;
  }
  await setCfg(host, token);
  // Quick health probe
  try {
    const r = await fetch(host.replace(/\/$/, "") + "/api/health");
    if (!r.ok) throw new Error("health: HTTP " + r.status);
    await showQuickView();
  } catch (e) {
    alert("Could not reach SafeCadence: " + e.message);
  }
};

$("#testHealth").onclick = async () => {
  const host = $("#host").value.trim();
  if (!host) return alert("Enter a host first");
  try {
    const r = await fetch(host.replace(/\/$/, "") + "/api/health");
    const j = await r.json();
    alert("OK: " + JSON.stringify(j));
  } catch (e) {
    alert("Failed: " + e.message);
  }
};

// ----- quick-view actions -----

document.addEventListener("click", async (e) => {
  const action = e.target.dataset?.action;
  if (!action) return;
  const {host} = await getCfg();
  if (!host) return;
  if (action === "open-ui") {
    chrome.tabs.create({url: host.replace(/\/$/, "") + "/api/policy/ui"});
  } else if (action === "briefing") {
    chrome.tabs.create({url: host.replace(/\/$/, "") + "/api/policy/ui#interpreter"});
  } else if (action === "drift") {
    chrome.tabs.create({url: host.replace(/\/$/, "") + "/api/policy/ui#drift"});
  } else if (action === "audit") {
    chrome.tabs.create({url: host.replace(/\/$/, "") + "/api/policy/ui#audit"});
  }
});

$("#planBtn").onclick = async () => {
  const intent = $("#intent").value.trim();
  if (!intent) return;
  const out = $("#planOut");
  out.classList.remove("hidden");
  out.textContent = "⏳";
  try {
    const r = await api("/api/execute/builder/plan", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({intent}),
    });
    out.textContent = JSON.stringify({
      summary: r.summary,
      risk: r.risk,
      matched_packs: r.matched_packs,
      blocked: r.blocked,
    }, null, 2);
  } catch (e) {
    out.textContent = "Error: " + e.message;
  }
};

$("#forgetBtn").onclick = async () => {
  await chrome.storage.local.remove(["host", "token"]);
  setupView.classList.remove("hidden");
  quickView.classList.add("hidden");
  $("#token").value = "";
};

// ----- boot -----

(async () => {
  const cfg = await getCfg();
  if (cfg.host && cfg.token) {
    await showQuickView();
  }
})();
