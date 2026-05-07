"""Single-file HTML dashboard renderer."""

from __future__ import annotations

import html as html_lib
import json

from safecadence.dashboard.builder import DashboardData


def render_dashboard(data: DashboardData, *, title: str = "SafeCadence Fleet Dashboard") -> str:
    payload = json.dumps(data.to_dict(), indent=2, default=str)
    title_esc = html_lib.escape(title)
    return _DASHBOARD_TEMPLATE.replace("__TITLE__", title_esc).replace("__DATA__", payload)


_DASHBOARD_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>__TITLE__</title>
<style>
  *,*::before,*::after { box-sizing: border-box; }
  body { margin: 0; font-family: -apple-system, "Segoe UI", Roboto, sans-serif;
         background: #f8fafc; color: #0f172a; }
  a { color: #1d4ed8; text-decoration: none; } a:hover { text-decoration: underline; }
  /* Layout */
  .app { display: grid; grid-template-columns: 220px 1fr; min-height: 100vh; }
  nav { background: #0f172a; color: #cbd5e1; padding: 18px 0; }
  nav .brand { padding: 0 18px 12px; border-bottom: 1px solid #1e293b; margin-bottom: 14px; }
  nav .brand-name { color: #fff; font-weight: 700; font-size: 14px; letter-spacing: -.01em; }
  nav .brand-sub { color: #64748b; font-size: 11px; }
  nav a { display: block; padding: 9px 18px; color: #cbd5e1; font-size: 13px; border-left: 3px solid transparent; }
  nav a:hover { background: #1e293b; color: #fff; text-decoration: none; }
  nav a.active { background: #1e293b; color: #fff; border-left-color: #38bdf8; }
  nav a .badge { float: right; font-size: 10px; background: #334155; color: #cbd5e1;
                  padding: 1px 7px; border-radius: 999px; margin-top: 1px; }
  nav a.active .badge { background: #38bdf8; color: #0f172a; }
  main { padding: 26px 32px; max-width: 1400px; }
  h1 { margin: 0 0 4px; font-size: 22px; }
  .subtitle { color: #64748b; font-size: 13px; margin-bottom: 24px; }
  /* KPI cards */
  .kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 14px; margin-bottom: 26px; }
  .kpi { background: #fff; border: 1px solid #e2e8f0; border-radius: 12px;
         padding: 16px 18px; }
  .kpi .lbl { font-size: 11px; text-transform: uppercase; color: #64748b; letter-spacing: .06em; }
  .kpi .v { font-size: 28px; font-weight: 700; margin: 4px 0 2px; }
  .kpi .sub { font-size: 12px; color: #64748b; }
  .kpi.crit  .v { color: #dc2626; }
  .kpi.warn  .v { color: #d97706; }
  .kpi.ok    .v { color: #16a34a; }
  /* Cards */
  .card { background: #fff; border: 1px solid #e2e8f0; border-radius: 12px;
          padding: 20px 24px; margin-bottom: 20px; }
  .card h2 { margin: 0 0 14px; font-size: 16px; }
  /* Tables */
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; font-weight: 600; color: #64748b; font-size: 11px;
       text-transform: uppercase; letter-spacing: .04em; padding: 8px 10px;
       border-bottom: 1px solid #e2e8f0; cursor: pointer; user-select: none; }
  th:hover { background: #f8fafc; }
  td { padding: 9px 10px; border-bottom: 1px solid #f1f5f9; }
  tbody tr:hover { background: #f8fafc; cursor: pointer; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 600; }
  .badge-green   { background:#dcfce7; color:#14532d; }
  .badge-yellow  { background:#fef3c7; color:#854d0e; }
  .badge-red     { background:#fee2e2; color:#7f1d1d; }
  .badge-orange  { background:#ffedd5; color:#9a3412; }
  .badge-blue    { background:#dbeafe; color:#1e40af; }
  .badge-gray    { background:#f1f5f9; color:#475569; }
  .kev { background:#fee2e2; color:#7f1d1d; padding:1px 6px; border-radius:3px;
          font-size:9px; font-weight:700; margin-left:4px; }
  /* Search/filter */
  .toolbar { display: flex; gap: 10px; margin-bottom: 14px; flex-wrap: wrap; }
  .toolbar input, .toolbar select {
    border: 1px solid #cbd5e1; border-radius: 6px; padding: 6px 10px;
    font-size: 13px; background: #fff; min-width: 180px;
  }
  .toolbar input:focus, .toolbar select:focus { outline: 2px solid #38bdf8; outline-offset: -1px; }
  /* Detail view */
  .detail-back { display: inline-block; margin-bottom: 14px; color: #64748b; font-size: 13px; }
  .detail-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 18px; }
  .detail-grid .card { margin-bottom: 0; }
  pre { background: #0f172a; color: #f1f5f9; padding: 12px 14px; border-radius: 6px;
        font-family: ui-monospace, Menlo, monospace; font-size: 12px; line-height: 1.5;
        max-height: 460px; overflow: auto; white-space: pre; }
  details { margin-top: 12px; }
  details > summary { cursor: pointer; font-size: 13px; font-weight: 600; color: #475569; padding: 4px 0; }
  details[open] > summary { color: #0f172a; }
  .severity-bar { display: flex; height: 8px; border-radius: 4px; overflow: hidden;
                  background: #f1f5f9; margin: 6px 0 14px; }
  .severity-bar > div { height: 100%; }
  /* Empty state */
  .empty { text-align: center; padding: 60px 20px; color: #94a3b8; }
  .empty h2 { color: #0f172a; margin-bottom: 8px; }
  /* Topology */
  #topology-network { width: 100%; height: 70vh; background: #fff; border: 1px solid #e2e8f0;
                       border-radius: 8px; }
  /* Chart */
  canvas { max-width: 100%; }
  /* Print */
  @media print { nav { display: none; } .app { grid-template-columns: 1fr; } main { max-width: none; } }
</style>
</head>
<body>
<div class="app">
  <nav>
    <div class="brand">
      <div class="brand-name">SafeCadence</div>
      <div class="brand-sub">Network Risk · v1.0</div>
    </div>
    <a href="#" data-route="overview">Overview <span class="badge" id="nav-overview"></span></a>
    <a href="#devices" data-route="devices">Devices <span class="badge" id="nav-devices"></span></a>
    <a href="#cves" data-route="cves">CVEs <span class="badge" id="nav-cves"></span></a>
    <a href="#eol" data-route="eol">EOL <span class="badge" id="nav-eol"></span></a>
    <a href="#topology" data-route="topology">Topology</a>
    <a href="#about" data-route="about">About</a>
  </nav>
  <main id="content"></main>
</div>

<script>
const DATA = __DATA__;

// ------------------------------------------------------------------- //
// Helpers                                                             //
// ------------------------------------------------------------------- //
function escapeHtml(s) {
  if (s === null || s === undefined) return '';
  return String(s).replace(/[&<>"']/g, c => ({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
  }[c]));
}

function bandClass(band) {
  if (!band) return 'badge-gray';
  if (band === 'critical' || band === 'end-of-support' || band === 'poor') return 'badge-red';
  if (band === 'high' || band === 'end-of-software' || band === 'warning') return 'badge-orange';
  if (band === 'medium')                                                    return 'badge-yellow';
  if (band === 'low' || band === 'good' || band === 'excellent' || band === 'supported') return 'badge-green';
  return 'badge-gray';
}

function sevClass(sev) {
  if (sev === 'critical') return 'badge-red';
  if (sev === 'high')     return 'badge-orange';
  if (sev === 'medium')   return 'badge-yellow';
  if (sev === 'low')      return 'badge-blue';
  return 'badge-gray';
}

function fmtScore(n, max) {
  return `${n|0}<span style="font-size:13px;color:#94a3b8">/${max||100}</span>`;
}

// ------------------------------------------------------------------- //
// Routing                                                             //
// ------------------------------------------------------------------- //
const routes = {
  overview: renderOverview,
  devices:  renderDevices,
  device:   renderDeviceDetail,
  cves:     renderCVEs,
  eol:      renderEOL,
  topology: renderTopology,
  about:    renderAbout,
};

function navigate() {
  const hash = location.hash.replace(/^#/, '') || 'overview';
  const [route, ...rest] = hash.split('/');
  document.querySelectorAll('nav a').forEach(a => a.classList.remove('active'));
  const navEl = document.querySelector(`nav a[data-route="${route}"]`);
  if (navEl) navEl.classList.add('active');
  const fn = routes[route] || routes.overview;
  fn(rest.join('/'));
  document.querySelector('main').scrollTop = 0;
}
window.addEventListener('hashchange', navigate);

// ------------------------------------------------------------------- //
// Pages                                                               //
// ------------------------------------------------------------------- //
function renderOverview() {
  const o = DATA.overview;
  const totalFindings = o.findings_critical + o.findings_high + o.findings_medium + o.findings_low + o.findings_info;
  let html = `
    <h1>Fleet overview</h1>
    <div class="subtitle">${o.device_count} device(s) scanned · generated ${escapeHtml(DATA.generated_at)}</div>

    <div class="kpis">
      <div class="kpi"><div class="lbl">Devices</div><div class="v">${o.device_count}</div></div>
      <div class="kpi ${o.avg_risk >= 60 ? 'warn' : 'ok'}"><div class="lbl">Avg risk</div><div class="v">${o.avg_risk}</div><div class="sub">/100</div></div>
      <div class="kpi ${o.avg_health < 60 ? 'warn' : 'ok'}"><div class="lbl">Avg health</div><div class="v">${o.avg_health}</div><div class="sub">/100</div></div>
      <div class="kpi crit"><div class="lbl">Critical risk</div><div class="v">${o.critical_devices}</div><div class="sub">device(s)</div></div>
      <div class="kpi crit"><div class="lbl">KEV exposed</div><div class="v">${o.kev_devices}</div><div class="sub">device(s)</div></div>
      <div class="kpi warn"><div class="lbl">End-of-support</div><div class="v">${o.eol_devices}</div><div class="sub">device(s)</div></div>
      <div class="kpi warn"><div class="lbl">End-of-software</div><div class="v">${o.eos_software_devices}</div><div class="sub">device(s)</div></div>
    </div>

    <div class="card">
      <h2>Findings by severity (${totalFindings} total)</h2>
      <div class="severity-bar">
        ${[
          ['#dc2626', o.findings_critical, 'critical'],
          ['#ea580c', o.findings_high, 'high'],
          ['#d97706', o.findings_medium, 'medium'],
          ['#0284c7', o.findings_low, 'low'],
          ['#94a3b8', o.findings_info, 'info'],
        ].map(([c,n]) => n ? `<div style="width:${(n/totalFindings*100).toFixed(1)}%;background:${c}" title="${n}"></div>` : '').join('')}
      </div>
      <div style="font-size:12px;color:#475569">
        <span class="badge badge-red">${o.findings_critical} critical</span>
        <span class="badge badge-orange">${o.findings_high} high</span>
        <span class="badge badge-yellow">${o.findings_medium} medium</span>
        <span class="badge badge-blue">${o.findings_low} low</span>
        <span class="badge badge-gray">${o.findings_info} info</span>
      </div>
    </div>

    <div class="detail-grid">
      <div class="card">
        <h2>Vendor breakdown</h2>
        <div id="vendor-chart"></div>
      </div>
      <div class="card">
        <h2>Top devices by risk</h2>
        <table>
          <thead><tr><th>Device</th><th>Vendor</th><th>Risk</th><th>Health</th></tr></thead>
          <tbody>
            ${[...DATA.devices].sort((a,b) => b.risk_score - a.risk_score).slice(0,8).map(d => `
              <tr onclick="location.hash='#device/${encodeURIComponent(d.name)}'">
                <td><strong>${escapeHtml(d.name)}</strong></td>
                <td>${escapeHtml(d.vendor)}</td>
                <td><span class="badge ${bandClass(d.risk_band)}">${d.risk_score}</span></td>
                <td><span class="badge ${bandClass(d.health_band)}">${d.health_score}</span></td>
              </tr>`).join('')}
          </tbody>
        </table>
      </div>
    </div>

    <div class="card">
      <h2>Top CVEs across fleet</h2>
      ${DATA.cves_by_id.length === 0
        ? '<div style="color:#16a34a;font-size:13px">No CVEs matched.</div>'
        : `<table>
            <thead><tr><th>CVE</th><th>Severity</th><th>CVSS</th><th>Affected</th><th>Title</th></tr></thead>
            <tbody>
              ${DATA.cves_by_id.slice(0,10).map(c => `
                <tr onclick="location.hash='#cves'">
                  <td><strong>${escapeHtml(c.cve_id)}</strong>${c.kev ? '<span class="kev">KEV</span>' : ''}</td>
                  <td><span class="badge ${sevClass(c.severity)}">${escapeHtml(c.severity.toUpperCase())}</span></td>
                  <td>${c.cvss || '—'}</td>
                  <td>${c.affected_devices.length}</td>
                  <td>${escapeHtml((c.title||'').slice(0,80))}</td>
                </tr>`).join('')}
            </tbody>
           </table>`}
    </div>
  `;
  document.getElementById('content').innerHTML = html;

  // Render vendor breakdown — pure inline SVG donut chart, no CDN
  const vendorChart = document.getElementById('vendor-chart');
  if (vendorChart) {
    const vb = o.vendor_breakdown || {};
    const palette = ['#1ba0d7','#ff6900','#0066cc','#84bd00','#ee2722','#5c2d91','#475569','#fa582d'];
    const entries = Object.entries(vb);
    const total = entries.reduce((s, [, n]) => s + n, 0) || 1;
    const cx = 100, cy = 100, r = 70, ir = 42;
    let acc = 0;
    let paths = '';
    entries.forEach(([, n], i) => {
      const start = acc / total * Math.PI * 2 - Math.PI / 2;
      acc += n;
      const end = acc / total * Math.PI * 2 - Math.PI / 2;
      const large = (end - start) > Math.PI ? 1 : 0;
      const x1 = cx + r * Math.cos(start),  y1 = cy + r * Math.sin(start);
      const x2 = cx + r * Math.cos(end),    y2 = cy + r * Math.sin(end);
      const x3 = cx + ir * Math.cos(end),   y3 = cy + ir * Math.sin(end);
      const x4 = cx + ir * Math.cos(start), y4 = cy + ir * Math.sin(start);
      const d = `M ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2} L ${x3} ${y3} A ${ir} ${ir} 0 ${large} 0 ${x4} ${y4} Z`;
      paths += `<path d="${d}" fill="${palette[i % palette.length]}" />`;
    });
    let legend = '<div style="margin-top:12px;font-size:12px">' +
      entries.map(([v, n], i) =>
        `<div style="display:flex;align-items:center;margin:2px 0">
          <span style="width:10px;height:10px;background:${palette[i % palette.length]};border-radius:2px;margin-right:6px"></span>
          ${escapeHtml(v)} <span style="color:#64748b;margin-left:6px">${n}</span>
        </div>`).join('') + '</div>';
    vendorChart.innerHTML = `
      <svg viewBox="0 0 200 200" width="200" height="200" style="display:block;margin:0 auto">${paths}
        <text x="100" y="100" text-anchor="middle" font-size="22" font-weight="700" fill="#0f172a">${total}</text>
        <text x="100" y="118" text-anchor="middle" font-size="10" fill="#64748b">DEVICES</text>
      </svg>${legend}`;
  }
}

let devicesSort = { col: 'risk_score', dir: 'desc' };
let devicesFilter = { q: '', vendor: '', band: '' };

function renderDevices() {
  let filtered = DATA.devices.filter(d => {
    if (devicesFilter.q) {
      const q = devicesFilter.q.toLowerCase();
      if (!(d.name||'').toLowerCase().includes(q) &&
          !(d.ip||'').includes(q) &&
          !(d.vendor||'').toLowerCase().includes(q) &&
          !(d.os||'').toLowerCase().includes(q)) return false;
    }
    if (devicesFilter.vendor && d.vendor !== devicesFilter.vendor) return false;
    if (devicesFilter.band && d.risk_band !== devicesFilter.band) return false;
    return true;
  });
  filtered.sort((a,b) => {
    const x = a[devicesSort.col], y = b[devicesSort.col];
    if (typeof x === 'number') return devicesSort.dir === 'asc' ? x - y : y - x;
    return devicesSort.dir === 'asc'
      ? String(x).localeCompare(String(y))
      : String(y).localeCompare(String(x));
  });

  const vendorOpts = [...new Set(DATA.devices.map(d => d.vendor))].sort();
  const bandOpts = ['critical', 'high', 'medium', 'low'];

  let html = `
    <h1>Devices</h1>
    <div class="subtitle">${filtered.length} of ${DATA.devices.length} shown · click any row for full detail</div>
    <div class="card">
      <div class="toolbar">
        <input type="search" placeholder="Search name / IP / vendor / OS…" id="dev-q" value="${escapeHtml(devicesFilter.q)}">
        <select id="dev-vendor">
          <option value="">All vendors</option>
          ${vendorOpts.map(v => `<option value="${escapeHtml(v)}" ${v===devicesFilter.vendor?'selected':''}>${escapeHtml(v)}</option>`).join('')}
        </select>
        <select id="dev-band">
          <option value="">All risk bands</option>
          ${bandOpts.map(b => `<option value="${b}" ${b===devicesFilter.band?'selected':''}>${b}</option>`).join('')}
        </select>
      </div>
      <table id="dev-table">
        <thead><tr>
          <th data-col="name">Device</th>
          <th data-col="vendor">Vendor</th>
          <th data-col="os">OS</th>
          <th data-col="version">Version</th>
          <th data-col="risk_score">Risk</th>
          <th data-col="health_score">Health</th>
          <th data-col="findings_count">Findings</th>
          <th data-col="cves_count">CVEs</th>
          <th data-col="eol_status">EOL</th>
        </tr></thead>
        <tbody>
          ${filtered.map(d => `
            <tr onclick="location.hash='#device/${encodeURIComponent(d.name)}'">
              <td><strong>${escapeHtml(d.name)}</strong>${d.ip ? `<div style="color:#64748b;font-size:11px">${escapeHtml(d.ip)}</div>`:''}</td>
              <td>${escapeHtml(d.vendor)}</td>
              <td>${escapeHtml(d.os)}</td>
              <td>${escapeHtml(d.version)}</td>
              <td><span class="badge ${bandClass(d.risk_band)}">${d.risk_score}</span></td>
              <td><span class="badge ${bandClass(d.health_band)}">${d.health_score}</span></td>
              <td>${d.findings_count}</td>
              <td>${d.cves_count}${d.scan.cves && d.scan.cves.some(c=>c.kev) ? '<span class="kev">KEV</span>':''}</td>
              <td><span class="badge ${bandClass(d.eol_status)}">${escapeHtml(d.eol_status)}</span></td>
            </tr>`).join('')}
        </tbody>
      </table>
    </div>
  `;
  document.getElementById('content').innerHTML = html;

  document.getElementById('dev-q').oninput = e => { devicesFilter.q = e.target.value; renderDevices(); };
  document.getElementById('dev-vendor').onchange = e => { devicesFilter.vendor = e.target.value; renderDevices(); };
  document.getElementById('dev-band').onchange = e => { devicesFilter.band = e.target.value; renderDevices(); };
  document.querySelectorAll('#dev-table th').forEach(th => {
    th.onclick = () => {
      const col = th.dataset.col;
      devicesSort = devicesSort.col === col
        ? { col, dir: devicesSort.dir === 'asc' ? 'desc' : 'asc' }
        : { col, dir: 'desc' };
      renderDevices();
    };
  });
}

function renderDeviceDetail(name) {
  const decoded = decodeURIComponent(name || '');
  const d = DATA.devices.find(x => x.name === decoded);
  if (!d) {
    document.getElementById('content').innerHTML = `
      <a class="detail-back" href="#devices">← Back to devices</a>
      <div class="empty"><h2>Device not found</h2><div>${escapeHtml(decoded)}</div></div>`;
    return;
  }
  const s = d.scan;
  const cfg = s.parsed_raw || '';

  const findingsByName = {};
  (s.findings || []).forEach(f => {
    findingsByName[f.severity] = (findingsByName[f.severity] || []);
    findingsByName[f.severity].push(f);
  });

  let html = `
    <a class="detail-back" href="#devices">← All devices</a>
    <h1>${escapeHtml(d.name)}</h1>
    <div class="subtitle">${escapeHtml([d.vendor, d.os, d.version, d.ip].filter(Boolean).join(' · '))}</div>

    <div class="kpis">
      <div class="kpi ${d.health_score < 50 ? 'warn' : 'ok'}"><div class="lbl">Health</div><div class="v">${d.health_score}</div><div class="sub">${escapeHtml(d.health_band)}</div></div>
      <div class="kpi ${d.risk_score >= 60 ? 'crit' : 'ok'}"><div class="lbl">Risk</div><div class="v">${d.risk_score}</div><div class="sub">${escapeHtml(d.risk_band)}</div></div>
      <div class="kpi"><div class="lbl">Findings</div><div class="v">${d.findings_count}</div></div>
      <div class="kpi ${d.cves_count > 0 ? 'crit' : 'ok'}"><div class="lbl">CVEs</div><div class="v">${d.cves_count}</div></div>
      <div class="kpi ${d.eol_status==='end-of-support' ? 'crit' : (d.eol_status==='end-of-software' ? 'warn' : 'ok')}">
        <div class="lbl">EOL status</div><div class="v" style="font-size:18px;line-height:1.4;margin-top:8px">${escapeHtml(d.eol_status)}</div></div>
    </div>

    <div class="detail-grid">
      <div class="card">
        <h2>Device info</h2>
        <table>
          ${[
            ['Hostname', d.name],
            ['IP', d.ip || '—'],
            ['Vendor', d.vendor],
            ['OS', d.os],
            ['Version', d.version || '—'],
            ['Model', d.model || '—'],
            ['Type', d.device_type || '—'],
          ].map(([k,v]) => `<tr><td style="color:#64748b">${k}</td><td>${escapeHtml(v)}</td></tr>`).join('')}
        </table>
      </div>
      <div class="card">
        <h2>EOL details</h2>
        ${s.eol ? `
          <table>
            <tr><td style="color:#64748b">Status</td><td><span class="badge ${bandClass(d.eol_status)}">${escapeHtml(d.eol_status)}</span></td></tr>
            <tr><td style="color:#64748b">End-of-software</td><td>${escapeHtml(s.eol.end_of_software || '—')}</td></tr>
            <tr><td style="color:#64748b">End-of-support</td><td>${escapeHtml(s.eol.end_of_support || '—')}</td></tr>
            ${s.eol.notes ? `<tr><td style="color:#64748b">Notes</td><td>${escapeHtml(s.eol.notes)}</td></tr>` : ''}
          </table>` : '<div style="color:#94a3b8;font-size:13px">No EOL data for this version.</div>'}
      </div>
    </div>

    <div class="card">
      <h2>CVEs (${(s.cves || []).length})</h2>
      ${(s.cves || []).length === 0 ? '<div style="color:#16a34a;font-size:13px">No CVEs matched for this version.</div>' : `
        <table>
          <thead><tr><th>CVE</th><th>Sev</th><th>CVSS</th><th>Title</th><th></th></tr></thead>
          <tbody>
            ${s.cves.map(c => `<tr>
              <td><strong>${escapeHtml(c.cve_id)}</strong>${c.kev ? '<span class="kev">KEV</span>':''}</td>
              <td><span class="badge ${sevClass(c.severity)}">${escapeHtml(c.severity)}</span></td>
              <td>${c.cvss || '—'}</td>
              <td>${escapeHtml(c.title || '')}</td>
              <td>${(c.references||[]).slice(0,2).map(r => `<a href="${escapeHtml(r)}" target="_blank">link</a>`).join(' ')}</td>
            </tr>`).join('')}
          </tbody>
        </table>`}
    </div>

    <div class="card">
      <h2>Findings (${d.findings_count})</h2>
      ${d.findings_count === 0 ? '<div style="color:#16a34a">No findings.</div>' : `
        <table>
          <thead><tr><th>Severity</th><th>Rule</th><th>Title</th></tr></thead>
          <tbody>
            ${(s.findings || []).map(f => `<tr>
              <td><span class="badge ${sevClass(f.severity)}">${escapeHtml(f.severity)}</span></td>
              <td style="font-family:ui-monospace,Menlo,monospace;font-size:11px">${escapeHtml(f.rule_id)}</td>
              <td>${escapeHtml(f.title)}</td>
            </tr>`).join('')}
          </tbody>
        </table>`}
    </div>

    ${cfg ? `
      <div class="card">
        <h2>Running config (${cfg.length.toLocaleString()} bytes)</h2>
        <details open><summary>Show / hide config</summary>
          <pre>${escapeHtml(cfg)}</pre>
        </details>
      </div>` : ''}
  `;
  document.getElementById('content').innerHTML = html;
}

function renderCVEs() {
  let html = `
    <h1>CVEs across fleet</h1>
    <div class="subtitle">${DATA.cves_by_id.length} unique CVE(s) detected · sorted by KEV first, then CVSS</div>
    <div class="card">
      ${DATA.cves_by_id.length === 0 ? '<div style="color:#16a34a">No CVEs matched.</div>' : `
        <table>
          <thead><tr><th>CVE</th><th>Sev</th><th>CVSS</th><th>Affected devices</th><th>Title</th></tr></thead>
          <tbody>
            ${DATA.cves_by_id.map(c => `<tr>
              <td><strong>${escapeHtml(c.cve_id)}</strong>${c.kev ? '<span class="kev">KEV</span>':''}</td>
              <td><span class="badge ${sevClass(c.severity)}">${escapeHtml(c.severity)}</span></td>
              <td>${c.cvss || '—'}</td>
              <td>${c.affected_devices.map(n => `<a href="#device/${encodeURIComponent(n)}">${escapeHtml(n)}</a>`).join(', ')}</td>
              <td>${escapeHtml(c.title||'')}</td>
            </tr>`).join('')}
          </tbody>
        </table>`}
    </div>`;
  document.getElementById('content').innerHTML = html;
}

function renderEOL() {
  let html = `
    <h1>End-of-life summary</h1>
    <div class="subtitle">${DATA.eol_summary.length} unique version-train(s) in your fleet</div>
    <div class="card">
      ${DATA.eol_summary.length === 0 ? '<div style="color:#94a3b8">No EOL data attached.</div>' : `
        <table>
          <thead><tr><th>Vendor</th><th>OS</th><th>Version</th><th>Status</th><th>End-of-software</th><th>End-of-support</th><th>Affected</th></tr></thead>
          <tbody>
            ${DATA.eol_summary.map(r => `<tr>
              <td>${escapeHtml(r.vendor)}</td>
              <td>${escapeHtml(r.os)}</td>
              <td>${escapeHtml(r.version_prefix)}.x</td>
              <td><span class="badge ${bandClass(r.status_today)}">${escapeHtml(r.status_today)}</span></td>
              <td>${escapeHtml(r.end_of_software || '—')}</td>
              <td>${escapeHtml(r.end_of_support || '—')}</td>
              <td>${r.affected_devices.map(n => `<a href="#device/${encodeURIComponent(n)}">${escapeHtml(n)}</a>`).join(', ')}</td>
            </tr>`).join('')}
          </tbody>
        </table>`}
    </div>`;
  document.getElementById('content').innerHTML = html;
}

function renderTopology() {
  if (!DATA.topology || !DATA.topology.nodes || !DATA.topology.nodes.length) {
    document.getElementById('content').innerHTML = `
      <h1>Topology</h1>
      <div class="empty">
        <h2>No topology attached</h2>
        <div>Run with <code>safecadence dashboard --topology lldp.txt</code> to embed an L2 graph.</div>
      </div>`;
    return;
  }
  document.getElementById('content').innerHTML = `
    <h1>Topology</h1>
    <div class="subtitle">${DATA.topology.nodes.length} nodes · ${DATA.topology.edges.length} links · drag any node to rearrange · click for detail</div>
    <div class="card" style="padding:0;height:70vh"><div id="topology-network" style="width:100%;height:100%;position:relative"></div></div>
  `;

  // Pure SVG force-directed layout — no CDN.
  const container = document.getElementById('topology-network');
  const W = container.clientWidth, H = container.clientHeight;
  const svgNS = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(svgNS, 'svg');
  svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
  svg.style.width = '100%'; svg.style.height = '100%'; svg.style.userSelect = 'none';
  container.appendChild(svg);

  const colors = {
    'Cisco':'#1ba0d7','Cisco Meraki':'#5c2d91','Aruba':'#ff6900','Arista':'#0066cc',
    'Juniper':'#84bd00','Fortinet':'#ee2722','Palo Alto Networks':'#fa582d',
    'MikroTik':'#f37021','Ubiquiti':'#0559c9',
  };
  const nodeMap = {};
  const cx = W/2, cy = H/2, R = Math.min(W, H) * 0.32;
  DATA.topology.nodes.forEach((n, i) => {
    const angle = (i / DATA.topology.nodes.length) * Math.PI * 2;
    nodeMap[n.name] = {
      ...n,
      x: cx + R * Math.cos(angle), y: cy + R * Math.sin(angle),
      vx: 0, vy: 0,
      color: colors[n.vendor] || '#e2e8f0',
    };
  });
  const nodeList = Object.values(nodeMap);
  const edges = DATA.topology.edges;

  // Force simulation
  const k = 200, kr = 24000;
  for (let it = 0; it < 220; it++) {
    for (let i=0; i<nodeList.length; i++) for (let j=i+1; j<nodeList.length; j++) {
      const a = nodeList[i], b = nodeList[j];
      let dx = a.x - b.x, dy = a.y - b.y, d2 = dx*dx + dy*dy + 0.01, d = Math.sqrt(d2);
      const f = kr / d2;
      a.vx += (dx/d)*f; a.vy += (dy/d)*f;
      b.vx -= (dx/d)*f; b.vy -= (dy/d)*f;
    }
    edges.forEach(e => {
      const a = nodeMap[e.local_device], b = nodeMap[e.remote_device];
      if (!a || !b) return;
      let dx = b.x-a.x, dy = b.y-a.y, d = Math.sqrt(dx*dx+dy*dy)+0.01;
      const f = (d - k) * 0.05;
      a.vx += (dx/d)*f; a.vy += (dy/d)*f;
      b.vx -= (dx/d)*f; b.vy -= (dy/d)*f;
    });
    nodeList.forEach(n => {
      n.x += n.vx*0.04; n.y += n.vy*0.04;
      n.vx *= 0.85; n.vy *= 0.85;
      n.x = Math.max(40, Math.min(W-40, n.x));
      n.y = Math.max(40, Math.min(H-40, n.y));
    });
  }

  // Draw edges
  const edgeEls = [];
  edges.forEach(e => {
    const a = nodeMap[e.local_device], b = nodeMap[e.remote_device];
    if (!a || !b) return;
    const line = document.createElementNS(svgNS, 'line');
    line.setAttribute('stroke', '#94a3b8'); line.setAttribute('stroke-width', '2');
    line.setAttribute('x1', a.x); line.setAttribute('y1', a.y);
    line.setAttribute('x2', b.x); line.setAttribute('y2', b.y);
    svg.appendChild(line);
    edgeEls.push({ line, a, b });
  });

  // Draw nodes
  const nodeEls = {};
  nodeList.forEach(n => {
    const g = document.createElementNS(svgNS, 'g');
    g.setAttribute('data-name', n.name);
    g.setAttribute('transform', `translate(${n.x},${n.y})`);
    g.style.cursor = 'pointer';
    let shape;
    if (n.role === 'router') {
      shape = document.createElementNS(svgNS, 'polygon');
      shape.setAttribute('points', '0,-22 22,0 0,22 -22,0');
    } else if (n.role === 'firewall') {
      shape = document.createElementNS(svgNS, 'polygon');
      const pts = [];
      for (let kk=0; kk<6; kk++) {
        const a = Math.PI/3 * kk - Math.PI/2;
        pts.push((22*Math.cos(a)).toFixed(1)+','+(22*Math.sin(a)).toFixed(1));
      }
      shape.setAttribute('points', pts.join(' '));
    } else if (n.role === 'wireless') {
      shape = document.createElementNS(svgNS, 'circle');
      shape.setAttribute('r', 18);
    } else {
      shape = document.createElementNS(svgNS, 'rect');
      shape.setAttribute('x', -28); shape.setAttribute('y', -18);
      shape.setAttribute('width', 56); shape.setAttribute('height', 36);
      shape.setAttribute('rx', 5);
    }
    shape.setAttribute('fill', n.color);
    shape.setAttribute('stroke', '#1e293b'); shape.setAttribute('stroke-width', '1.5');
    g.appendChild(shape);
    const lbl = document.createElementNS(svgNS, 'text');
    lbl.setAttribute('y', 36); lbl.setAttribute('text-anchor', 'middle');
    lbl.setAttribute('font-size', '11'); lbl.setAttribute('font-weight', '600');
    lbl.style.pointerEvents = 'none';
    lbl.textContent = n.name.length > 16 ? n.name.slice(0, 16) + '…' : n.name;
    g.appendChild(lbl);
    const tt = document.createElementNS(svgNS, 'title');
    tt.textContent = [n.name, n.vendor, n.role, n.ip].filter(Boolean).join(' · ');
    g.appendChild(tt);
    svg.appendChild(g);
    nodeEls[n.name] = g;
  });

  // Drag + click
  let dragging = null, dragOff = {x:0,y:0};
  function svgPoint(evt) {
    const r = svg.getBoundingClientRect();
    return { x: (evt.clientX - r.left)*W/r.width, y: (evt.clientY - r.top)*H/r.height };
  }
  function refresh() {
    Object.entries(nodeEls).forEach(([id, g]) => {
      const n = nodeMap[id]; g.setAttribute('transform', `translate(${n.x},${n.y})`);
    });
    edgeEls.forEach(({line, a, b}) => {
      line.setAttribute('x1', a.x); line.setAttribute('y1', a.y);
      line.setAttribute('x2', b.x); line.setAttribute('y2', b.y);
    });
  }
  svg.addEventListener('mousedown', e => {
    const g = e.target.closest('[data-name]');
    if (!g) return;
    e.preventDefault();
    dragging = nodeMap[g.dataset.name];
    const p = svgPoint(e);
    dragOff = { x: p.x - dragging.x, y: p.y - dragging.y };
    dragging._wasDrag = false;
  });
  window.addEventListener('mousemove', e => {
    if (!dragging) return;
    const p = svgPoint(e);
    dragging.x = p.x - dragOff.x; dragging.y = p.y - dragOff.y;
    dragging._wasDrag = true;
    refresh();
  });
  window.addEventListener('mouseup', e => {
    if (dragging && !dragging._wasDrag) {
      // simple click → drill into device detail
      location.hash = '#device/' + encodeURIComponent(dragging.name);
    }
    dragging = null;
  });
}

function renderAbout() {
  document.getElementById('content').innerHTML = `
    <h1>About this dashboard</h1>
    <div class="card">
      <p>This dashboard is a <strong>self-contained HTML file</strong> generated by the
      <a href="https://safecadence.com">SafeCadence Network Risk</a> open-source CLI.
      Everything you see was computed locally on your machine — no SaaS, no telemetry,
      no data uploaded anywhere.</p>
      <p>Rebuild it any time:</p>
      <pre>safecadence dashboard --scans dir-of-scan-jsons/ --topology lldp.txt -o dashboard.html</pre>
      <p>Need help running it across a fleet? <a href="mailto:hello@safecadence.com">hello@safecadence.com</a>.</p>
    </div>
    <div class="card">
      <h2>Stats</h2>
      <table>
        <tr><td style="color:#64748b">Generated</td><td>${escapeHtml(DATA.generated_at)}</td></tr>
        <tr><td style="color:#64748b">Devices</td><td>${DATA.overview.device_count}</td></tr>
        <tr><td style="color:#64748b">Unique CVEs</td><td>${DATA.cves_by_id.length}</td></tr>
        <tr><td style="color:#64748b">EOL trains</td><td>${DATA.eol_summary.length}</td></tr>
        <tr><td style="color:#64748b">Topology</td><td>${DATA.topology ? `${DATA.topology.nodes.length} nodes · ${DATA.topology.edges.length} links` : 'not attached'}</td></tr>
      </table>
    </div>`;
}

// ------------------------------------------------------------------- //
// Init                                                                //
// ------------------------------------------------------------------- //
document.getElementById('nav-overview').textContent = DATA.overview.device_count || '';
document.getElementById('nav-devices').textContent  = DATA.overview.device_count || '';
document.getElementById('nav-cves').textContent     = DATA.cves_by_id.length || '';
document.getElementById('nav-eol').textContent      = DATA.eol_summary.length || '';

navigate();
</script>
</body>
</html>"""
