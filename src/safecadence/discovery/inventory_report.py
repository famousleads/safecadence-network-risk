"""
Render a self-contained HTML inventory report from a discovery payload.

Output is a single .html file (no CDN dependencies) that can be:
  - emailed as an attachment
  - printed to PDF via Cmd+P / Save as PDF
  - opened by anyone with a browser, anywhere, with no network

Layout: cover → exec summary KPIs → risk distribution → by-category
breakdown → critical/high device list → full asset inventory table →
recommended actions appendix.
"""

from __future__ import annotations

import html as html_lib
import json
from datetime import datetime, timezone


def _esc(s) -> str:
    return html_lib.escape(str(s) if s is not None else "")


def render_inventory_report(data: dict, *, title: str = "Network Inventory & Risk Report") -> str:
    cidr = data.get("cidr", "?")
    mode = data.get("mode", "?")
    count = data.get("count", 0)
    scanned = data.get("scanned", 0)
    duration = data.get("duration_ms", 0)
    summary = data.get("summary", {})
    bands = summary.get("by_risk_band", {})
    cats = summary.get("by_category", {})
    results = data.get("results", [])
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Critical + high devices for the spotlight section
    spotlight = [r for r in results if r.get("risk_band") in ("critical", "high")]

    # Aggregate all unique recommended actions across the fleet
    all_actions: dict[str, int] = {}
    for r in results:
        for a in r.get("recommended_actions", []):
            all_actions[a] = all_actions.get(a, 0) + 1
    top_actions = sorted(all_actions.items(), key=lambda kv: -kv[1])[:15]

    # KPI bar
    kpi_html = f"""
    <div class="kpis">
      <div class="kpi info"><div class="lbl">Devices</div><div class="v">{count}</div><div class="sub">on {_esc(cidr)}</div></div>
      <div class="kpi crit"><div class="lbl">Critical risk</div><div class="v">{bands.get('critical', 0)}</div><div class="sub">requires immediate action</div></div>
      <div class="kpi warn"><div class="lbl">High risk</div><div class="v">{bands.get('high', 0)}</div><div class="sub">action this quarter</div></div>
      <div class="kpi"><div class="lbl">Medium risk</div><div class="v">{bands.get('medium', 0)}</div></div>
      <div class="kpi ok"><div class="lbl">Safe</div><div class="v">{bands.get('safe', 0) + bands.get('low', 0)}</div></div>
    </div>
    """

    # Category breakdown
    cat_rows = "".join(
        f"<tr><td>{_esc(cat)}</td><td style='text-align:right'>{n}</td></tr>"
        for cat, n in sorted(cats.items(), key=lambda kv: -kv[1])
    )

    # Spotlight (critical + high)
    spotlight_rows = ""
    for r in spotlight:
        findings_list = "".join(f"<li>{_esc(f)}</li>" for f in r.get("findings", [])[:5])
        actions_list = "".join(f"<li>{_esc(a)}</li>" for a in r.get("recommended_actions", [])[:3])
        spotlight_rows += f"""
        <div class="spotlight">
          <div class="spotlight-head">
            <div>
              <div class="spotlight-ip"><code>{_esc(r.get('ip', ''))}</code></div>
              <div class="spotlight-meta">{_esc(r.get('hostname') or '—')} · {_esc(r.get('vendor') or '?')} · {_esc(r.get('category', '?'))}</div>
            </div>
            <div class="spotlight-risk">
              <span class="band band-{_esc(r.get('risk_band', 'safe'))}">{_esc(r.get('risk_band', 'safe').upper())}</span>
              <div class="spotlight-score">{r.get('risk_score', 0)}/100</div>
            </div>
          </div>
          <div class="spotlight-body">
            <div><strong>Findings:</strong><ul>{findings_list or '<li>(none)</li>'}</ul></div>
            <div><strong>Recommended actions:</strong><ul>{actions_list or '<li>(none)</li>'}</ul></div>
          </div>
        </div>
        """

    # Full inventory table
    inventory_rows = ""
    for r in results:
        ports = " ".join(f'<span class="pill">{_esc(p)}</span>' for p in r.get("open_ports", []))
        sysd = r.get("snmp_sysdescr", "")
        sysd_html = f'<div class="sysd">{_esc(sysd[:200])}</div>' if sysd else ""
        inventory_rows += f"""
        <tr>
          <td><code>{_esc(r.get('ip', ''))}</code></td>
          <td>{_esc(r.get('hostname') or '—')}</td>
          <td><code class="mac">{_esc(r.get('mac') or '—')}</code></td>
          <td>{_esc(r.get('vendor') or '—')}</td>
          <td>{_esc(r.get('category') or '—')}</td>
          <td>{ports}{sysd_html}</td>
          <td><span class="band band-{_esc(r.get('risk_band', 'safe'))}">{r.get('risk_score', 0)}</span></td>
        </tr>
        """

    # Top recommended actions appendix
    actions_rows = "".join(
        f"<tr><td>{_esc(a)}</td><td style='text-align:right'>{n} device{'s' if n != 1 else ''}</td></tr>"
        for a, n in top_actions
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_esc(title)} — {_esc(cidr)}</title>
<style>
  *,*::before,*::after {{ box-sizing: border-box; }}
  body {{ margin:0; font-family:-apple-system,"Segoe UI",Roboto,sans-serif;
          background:#fff; color:#0f172a; font-size:14px; line-height:1.5;
          -webkit-print-color-adjust:exact; print-color-adjust:exact; }}
  .page {{ max-width:1100px; margin:0 auto; padding:40px 32px; }}
  h1 {{ font-size:30px; margin:0 0 6px; font-weight:800; letter-spacing:-.01em; }}
  h2 {{ font-size:18px; margin:32px 0 14px; font-weight:700; border-bottom:2px solid #0f172a; padding-bottom:6px; }}
  h3 {{ font-size:15px; margin:0 0 10px; font-weight:600; color:#1e293b; }}
  .meta {{ color:#64748b; font-size:13px; margin-bottom:24px; }}
  code {{ font-family:ui-monospace,Menlo,Consolas,monospace; font-size:13px; background:#f8fafc; padding:1px 5px; border-radius:3px; }}
  code.mac {{ font-size:11px; color:#475569; }}
  /* KPIs */
  .kpis {{ display:grid; grid-template-columns:repeat(5,1fr); gap:12px; margin:18px 0 28px; }}
  .kpi {{ background:#f8fafc; border:1px solid #e2e8f0; border-radius:10px; padding:14px 16px; }}
  .kpi .lbl {{ font-size:10px; text-transform:uppercase; color:#64748b; letter-spacing:.06em; font-weight:600; }}
  .kpi .v {{ font-size:26px; font-weight:800; margin:4px 0 2px; }}
  .kpi .sub {{ font-size:11px; color:#64748b; }}
  .kpi.crit .v {{ color:#dc2626; }}
  .kpi.warn .v {{ color:#d97706; }}
  .kpi.ok .v {{ color:#16a34a; }}
  .kpi.info .v {{ color:#1d4ed8; }}
  /* Tables */
  table {{ width:100%; border-collapse:collapse; font-size:12px; margin:8px 0; }}
  th {{ text-align:left; font-weight:600; color:#475569; font-size:10px; text-transform:uppercase;
       letter-spacing:.04em; padding:8px 10px; border-bottom:2px solid #cbd5e1; background:#f8fafc; }}
  td {{ padding:8px 10px; border-bottom:1px solid #f1f5f9; vertical-align:top; }}
  /* Risk band badges */
  .band {{ display:inline-block; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:700; min-width:32px; text-align:center; }}
  .band-safe {{ background:#dcfce7; color:#14532d; }}
  .band-low {{ background:#dbeafe; color:#1e3a8a; }}
  .band-medium {{ background:#fef3c7; color:#78350f; }}
  .band-high {{ background:#fee2e2; color:#7f1d1d; }}
  .band-critical {{ background:#0f172a; color:#fff; }}
  .pill {{ display:inline-block; padding:1px 6px; background:#f1f5f9; color:#334155; border-radius:3px; font-size:10px; margin:0 2px; }}
  /* Spotlight cards */
  .spotlight {{ background:#fff; border:1px solid #e2e8f0; border-radius:10px; padding:14px 18px; margin:10px 0; page-break-inside:avoid; }}
  .spotlight-head {{ display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:10px; }}
  .spotlight-ip {{ font-size:16px; font-weight:700; }}
  .spotlight-meta {{ font-size:12px; color:#64748b; margin-top:2px; }}
  .spotlight-risk {{ text-align:right; }}
  .spotlight-score {{ font-size:18px; font-weight:800; margin-top:4px; color:#0f172a; }}
  .spotlight-body {{ display:grid; grid-template-columns:1fr 1fr; gap:14px; font-size:12px; }}
  .spotlight-body ul {{ margin:4px 0 0; padding-left:18px; }}
  .spotlight-body li {{ margin:3px 0; }}
  .sysd {{ font-size:10px; color:#64748b; margin-top:4px; font-family:ui-monospace,monospace; max-width:380px; overflow-wrap:break-word; }}
  /* Print page breaks */
  @media print {{
    .page {{ padding:20px 28px; }}
    h2 {{ page-break-after:avoid; }}
    .spotlight {{ page-break-inside:avoid; }}
  }}
  /* Cover */
  .cover {{ border-bottom:3px solid #0f172a; padding-bottom:18px; margin-bottom:18px; }}
  .cover-brand {{ font-size:11px; letter-spacing:.12em; text-transform:uppercase; color:#1e3a8a; font-weight:700; }}
  /* Footer */
  .footer {{ margin-top:40px; padding-top:18px; border-top:1px solid #e2e8f0;
            font-size:11px; color:#64748b; text-align:center; }}
</style>
</head>
<body>
<div class="page">

  <div class="cover">
    <div class="cover-brand">SafeCadence Network Risk · Inventory & Risk Report</div>
    <h1>{_esc(title)}</h1>
    <div class="meta">
      Subnet <code>{_esc(cidr)}</code> · Scan mode <strong>{_esc(mode)}</strong> ·
      {scanned} targets probed in {duration/1000:.1f}s ·
      Generated {_esc(generated)}
    </div>
  </div>

  <h2>Executive Summary</h2>
  {kpi_html}

  <p>This report is the result of a single-pass network discovery and risk assessment of <code>{_esc(cidr)}</code>. {count} devices were enumerated using a combination of TCP probing, ARP cache reading, mDNS/Bonjour announcements, SNMP v2c sysDescr probes, TLS certificate inspection, and HTTP banner scraping. Each device received an automated risk score (0–100) based on its open ports, exposed services, and identified vendor/model.</p>

  <p><strong>Top-line finding:</strong> {bands.get('critical', 0)} device{'s require' if bands.get('critical', 0) != 1 else ' requires'} immediate remediation; {bands.get('high', 0)} additional device{'s' if bands.get('high', 0) != 1 else ''} warrant{'s' if bands.get('high', 0) == 1 else ''} attention this quarter. Recommended actions are listed per device in the spotlight section and aggregated across the fleet in the appendix.</p>

  <h2>Devices Requiring Immediate Action ({len(spotlight)})</h2>
  {spotlight_rows or '<p style="color:#16a34a"><strong>None.</strong> No devices in the critical or high-risk bands. Continue normal monitoring.</p>'}

  <h2>Asset Inventory ({count} devices)</h2>
  <table>
    <thead><tr><th>IP</th><th>Hostname</th><th>MAC</th><th>Vendor</th><th>Category</th><th>Open ports / Services</th><th>Risk</th></tr></thead>
    <tbody>{inventory_rows}</tbody>
  </table>

  <h2>Device Mix by Category</h2>
  <table style="max-width:380px">
    <thead><tr><th>Category</th><th style="text-align:right">Count</th></tr></thead>
    <tbody>{cat_rows}</tbody>
  </table>

  <h2>Top Recommended Actions</h2>
  <table>
    <thead><tr><th>Recommended action</th><th style="text-align:right">Affects</th></tr></thead>
    <tbody>{actions_rows or '<tr><td colspan="2" style="text-align:center; color:#64748b">No actions identified.</td></tr>'}</tbody>
  </table>

  <h2>Methodology</h2>
  <p style="font-size:12px; color:#475569">This report was generated by <code>safecadence-netrisk</code> v2.3.1+ running locally on a single workstation. No data was transmitted to any third party. The discovery used five concurrent identification techniques: (1) TCP port probing on 27 management ports, (2) local ARP cache reading for L2-adjacent devices, (3) mDNS/Bonjour multicast listener for self-announcing devices, (4) SNMP v2c sysDescr GET with common community strings (only when port 161 was already detected open or the device was suspected to be network gear), (5) TLS certificate subject extraction and HTTP page-title scraping. Risk scores combine port-based heuristics with default-credential checks and known-vulnerability matching where vendor/model could be identified.</p>

  <div class="footer">
    SafeCadence Network Risk · MIT licensed ·
    <a href="https://pypi.org/project/safecadence-netrisk/" style="color:#1d4ed8; text-decoration:none">pypi.org/project/safecadence-netrisk</a> ·
    Generated {_esc(generated)}
  </div>

</div>
</body>
</html>
"""
