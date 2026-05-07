"""
Management-grade network risk report.

Generates a single-file HTML document with:
  - Cover page with KPIs at a glance
  - Executive summary in plain English
  - Risk distribution donut chart (inline SVG)
  - Category breakdown bar chart (inline SVG)
  - Top vulnerabilities table (KEV-prioritized)
  - Per-device cards for critical/high-risk devices
  - Compliance coverage section (NIST / CIS / PCI / HIPAA)
  - Full asset inventory table
  - Top recommended actions appendix
  - Methodology footnote

Designed to be:
  - Exec-readable in 30 seconds
  - Print-perfect (Cmd+P → Save as PDF)
  - Zero CDN dependencies
  - Better than the equivalent output from Tenable / Qualys / Rapid7

The reader should walk away knowing exactly what to fix first, why it matters,
and what good looks like.
"""

from __future__ import annotations

import html as html_lib
import json
from datetime import datetime, timezone


def _esc(s) -> str:
    return html_lib.escape(str(s) if s is not None else "")


# ---------------------------------------------------------------- inline SVG charts

def _donut_chart(segments: list[tuple[str, int, str]], *, size: int = 180) -> str:
    """
    Generate a donut chart as inline SVG.
    segments: list of (label, value, color)
    """
    total = sum(v for _, v, _ in segments) or 1
    cx = cy = size / 2
    r_outer = size / 2 - 6
    r_inner = r_outer * 0.62
    paths = []
    cumulative = 0
    for label, value, color in segments:
        if value == 0:
            continue
        start_angle = cumulative / total * 360
        end_angle = (cumulative + value) / total * 360
        cumulative += value
        # Convert to radians starting at -90deg
        import math
        sa_rad = math.radians(start_angle - 90)
        ea_rad = math.radians(end_angle - 90)
        x1, y1 = cx + r_outer * math.cos(sa_rad), cy + r_outer * math.sin(sa_rad)
        x2, y2 = cx + r_outer * math.cos(ea_rad), cy + r_outer * math.sin(ea_rad)
        x3, y3 = cx + r_inner * math.cos(ea_rad), cy + r_inner * math.sin(ea_rad)
        x4, y4 = cx + r_inner * math.cos(sa_rad), cy + r_inner * math.sin(sa_rad)
        large_arc = 1 if (end_angle - start_angle) > 180 else 0
        d = (
            f"M {x1:.2f} {y1:.2f} "
            f"A {r_outer:.2f} {r_outer:.2f} 0 {large_arc} 1 {x2:.2f} {y2:.2f} "
            f"L {x3:.2f} {y3:.2f} "
            f"A {r_inner:.2f} {r_inner:.2f} 0 {large_arc} 0 {x4:.2f} {y4:.2f} "
            f"Z"
        )
        paths.append(f'<path d="{d}" fill="{color}" />')
    center_label = f'<text x="{cx}" y="{cy}" text-anchor="middle" dominant-baseline="central" font-size="22" font-weight="700" fill="#0f172a">{total}</text>'
    return (
        f'<svg viewBox="0 0 {size} {size}" width="{size}" height="{size}" xmlns="http://www.w3.org/2000/svg">'
        + "".join(paths)
        + center_label
        + '</svg>'
    )


def _bar_chart(items: list[tuple[str, int]], *, max_width: int = 360, color: str = "#1d4ed8") -> str:
    """Horizontal bar chart for category breakdown."""
    if not items:
        return ""
    max_val = max(v for _, v in items) or 1
    rows = []
    bar_h = 22
    y = 0
    width = max_width
    for label, value in items:
        bw = max(2, int(value / max_val * (width - 100)))
        rows.append(f'''
        <g transform="translate(0,{y})">
          <text x="0" y="14" font-size="12" fill="#475569">{_esc(label)}</text>
          <rect x="100" y="3" width="{bw}" height="{bar_h-6}" fill="{color}" rx="2" />
          <text x="{105+bw}" y="14" font-size="11" fill="#0f172a" font-weight="600">{value}</text>
        </g>''')
        y += bar_h
    return f'<svg viewBox="0 0 {width} {y}" width="{width}" height="{y}" xmlns="http://www.w3.org/2000/svg">{"".join(rows)}</svg>'


# ---------------------------------------------------------------- main render
def render_management_report(
    discover_data: dict,
    *,
    cve_summary: dict | None = None,
    organization: str = "Your Organization",
) -> str:
    cidr = discover_data.get("cidr", "?")
    mode = discover_data.get("mode", "?")
    count = discover_data.get("count", 0)
    scanned = discover_data.get("scanned", 0)
    duration = discover_data.get("duration_ms", 0)
    summary = discover_data.get("summary", {})
    bands = summary.get("by_risk_band", {})
    cats = summary.get("by_category", {})
    results = discover_data.get("results", [])

    crit = bands.get("critical", 0)
    high = bands.get("high", 0)
    medium = bands.get("medium", 0)
    low = bands.get("low", 0)
    safe = bands.get("safe", 0)

    cve_summary = cve_summary or {}
    total_cves = cve_summary.get("total_cves", 0)
    kev_cves = cve_summary.get("kev_cves", 0)
    devices_with_kev = cve_summary.get("devices_with_kev", 0)
    top_cves = cve_summary.get("top_cves", [])

    # Spotlight devices (critical + high)
    spotlight = [r for r in results if r.get("risk_band") in ("critical", "high")]

    # All recommended actions across the fleet, deduped + counted
    all_actions: dict[str, int] = {}
    for r in results:
        for a in r.get("recommended_actions", []):
            all_actions[a] = all_actions.get(a, 0) + 1
    top_actions = sorted(all_actions.items(), key=lambda kv: -kv[1])[:15]

    # Risk distribution donut
    donut_segments = [
        ("Critical", crit, "#0f172a"),
        ("High", high, "#dc2626"),
        ("Medium", medium, "#d97706"),
        ("Low", low, "#1d4ed8"),
        ("Safe", safe, "#16a34a"),
    ]
    donut_svg = _donut_chart(donut_segments, size=200)

    # Category bar chart (top 10)
    sorted_cats = sorted(cats.items(), key=lambda kv: -kv[1])[:10]
    cat_chart = _bar_chart(sorted_cats, max_width=440, color="#1e3a8a")

    # Compliance coverage (rough estimate from finding tags)
    compliance_data = _compute_compliance_coverage(results)

    # KPI cards
    kpis_html = f"""
    <div class="kpi-grid">
      <div class="kpi-card kpi-info">
        <div class="kpi-label">Devices in scope</div>
        <div class="kpi-value">{count}</div>
        <div class="kpi-sub">discovered on {_esc(cidr)}</div>
      </div>
      <div class="kpi-card kpi-critical">
        <div class="kpi-label">CRITICAL risk</div>
        <div class="kpi-value">{crit}</div>
        <div class="kpi-sub">remediate immediately</div>
      </div>
      <div class="kpi-card kpi-high">
        <div class="kpi-label">HIGH risk</div>
        <div class="kpi-value">{high}</div>
        <div class="kpi-sub">remediate this quarter</div>
      </div>
      <div class="kpi-card kpi-cve">
        <div class="kpi-label">Known CVEs matched</div>
        <div class="kpi-value">{total_cves}</div>
        <div class="kpi-sub">{kev_cves} on CISA KEV catalog</div>
      </div>
      <div class="kpi-card kpi-kev">
        <div class="kpi-label">Devices w/ KEV CVE</div>
        <div class="kpi-value">{devices_with_kev}</div>
        <div class="kpi-sub">actively exploited in the wild</div>
      </div>
    </div>
    """

    # Donut + category panels
    donut_panel = f"""
    <div class="grid-2">
      <div class="panel">
        <h3>Fleet risk distribution</h3>
        <div style="text-align:center; margin:14px 0">{donut_svg}</div>
        <div class="legend">
          <span><i style="background:#0f172a"></i> Critical {crit}</span>
          <span><i style="background:#dc2626"></i> High {high}</span>
          <span><i style="background:#d97706"></i> Medium {medium}</span>
          <span><i style="background:#1d4ed8"></i> Low {low}</span>
          <span><i style="background:#16a34a"></i> Safe {safe}</span>
        </div>
      </div>
      <div class="panel">
        <h3>Device mix</h3>
        <div style="margin-top:10px">{cat_chart}</div>
      </div>
    </div>
    """

    # Spotlight cards
    spotlight_html = ""
    for r in spotlight[:10]:  # cap at 10 for report length
        findings = r.get("findings", [])[:5]
        actions = r.get("recommended_actions", [])[:5]
        cves = r.get("cves", [])[:5]
        findings_html = "".join(f"<li>{_esc(f)}</li>" for f in findings) or "<li>(none)</li>"
        actions_html = "".join(f"<li>{_esc(a)}</li>" for a in actions) or "<li>(none)</li>"
        cves_html = ""
        if cves:
            cves_html = "<h4 style='margin-top:10px'>Known CVEs</h4><ul class='cve-list'>"
            for c in cves:
                kev_badge = ' <span class="kev-badge">KEV</span>' if c.get("kev") else ""
                cves_html += f"<li><strong>{_esc(c.get('cve_id',''))}</strong> CVSS {c.get('cvss','?')}{kev_badge} — {_esc(c.get('title','')[:80])}</li>"
            cves_html += "</ul>"
        spotlight_html += f"""
        <div class="device-card">
          <div class="device-head">
            <div>
              <div class="device-ip"><code>{_esc(r.get('ip',''))}</code></div>
              <div class="device-meta">
                {_esc(r.get('hostname') or 'unnamed')} ·
                {_esc(r.get('vendor') or 'unknown vendor')} ·
                <span class="cat-pill">{_esc(r.get('category','?'))}</span>
              </div>
              {f'<div class="sysd">{_esc(r.get("snmp_sysdescr","")[:200])}</div>' if r.get("snmp_sysdescr") else ""}
            </div>
            <div class="device-risk">
              <span class="band band-{_esc(r.get('risk_band','safe'))}">{_esc((r.get('risk_band','safe')).upper())}</span>
              <div class="device-score">{r.get('risk_score',0)}<small>/100</small></div>
            </div>
          </div>
          <div class="device-body">
            <div>
              <h4>Security findings</h4>
              <ul>{findings_html}</ul>
            </div>
            <div>
              <h4>Recommended actions</h4>
              <ul>{actions_html}</ul>
            </div>
          </div>
          {cves_html}
        </div>
        """

    # Top CVEs table (if any)
    top_cves_html = ""
    if top_cves:
        rows = ""
        for c in top_cves:
            kev_badge = ' <span class="kev-badge">KEV</span>' if c.get("kev") else ""
            ips = (c.get("_affected_ips") or [])[:3]
            ips_html = " ".join(f'<code class="mini">{_esc(ip)}</code>' for ip in ips)
            if c.get("_affected_devices", 0) > 3:
                ips_html += f' <span style="color:#64748b">+{c["_affected_devices"]-3} more</span>'
            rows += f"""<tr>
              <td><strong>{_esc(c.get('cve_id',''))}</strong>{kev_badge}</td>
              <td>{c.get('cvss','—')}</td>
              <td>{_esc((c.get('severity') or '').upper())}</td>
              <td style="font-size:12px">{_esc((c.get('title') or '')[:80])}</td>
              <td>{c.get('_affected_devices', 0)}</td>
              <td>{ips_html}</td>
            </tr>"""
        top_cves_html = f"""
        <h2>Top Vulnerabilities (KEV-prioritized)</h2>
        <table class="report-table">
          <thead><tr><th>CVE ID</th><th>CVSS</th><th>Severity</th><th>Title</th><th>Affected</th><th>Devices</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>"""

    # Top actions table
    top_actions_html = ""
    if top_actions:
        rows = "".join(
            f"<tr><td>{i+1}</td><td>{_esc(a)}</td><td style='text-align:right'>{n}</td></tr>"
            for i, (a, n) in enumerate(top_actions)
        )
        top_actions_html = f"""
        <h2>Top Recommended Actions (across fleet)</h2>
        <p>Acting on these in order will close the most findings with the least effort.</p>
        <table class="report-table">
          <thead><tr><th style="width:30px">#</th><th>Action</th><th style="text-align:right">Devices affected</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>"""

    # Compliance coverage section
    compliance_html = _render_compliance_section(compliance_data)

    # Full asset inventory
    inv_rows = ""
    for r in results:
        ports_html = " ".join(f'<span class="pill">{_esc(p)}</span>' for p in r.get("open_ports", []))
        cve_count = len(r.get("cves", []))
        cve_badge = f'<span class="cve-count">{cve_count} CVE</span>' if cve_count else ''
        inv_rows += f"""<tr>
          <td><span class="band band-{_esc(r.get('risk_band','safe'))}">{r.get('risk_score',0)}</span></td>
          <td><code>{_esc(r.get('ip',''))}</code></td>
          <td>{_esc(r.get('hostname') or '—')}</td>
          <td><code class="mac">{_esc(r.get('mac') or '—')}</code></td>
          <td>{_esc(r.get('vendor') or '—')}</td>
          <td>{_esc(r.get('category') or '—')}</td>
          <td>{ports_html}{cve_badge}</td>
        </tr>"""

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    org = _esc(organization)

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Network Risk Report — {_esc(cidr)} — {generated}</title>
<style>
  *,*::before,*::after {{ box-sizing: border-box; }}
  body {{ margin:0; font-family:-apple-system,"Segoe UI",Roboto,sans-serif; color:#0f172a; background:#fff; font-size:14px; line-height:1.5; -webkit-print-color-adjust:exact; print-color-adjust:exact; }}
  .page {{ max-width:1100px; margin:0 auto; padding:0 32px 50px; }}
  /* COVER */
  .cover {{ background:linear-gradient(135deg, #0f172a, #1e3a8a 60%, #1e40af);
           color:#fff; padding:60px 32px 50px; margin:0 -32px 30px; position:relative; }}
  .cover::after {{ content:""; position:absolute; bottom:0; left:0; right:0; height:6px; background:linear-gradient(90deg,#dc2626,#d97706,#eab308,#16a34a); }}
  .cover .brand {{ font-size:11px; letter-spacing:.16em; text-transform:uppercase; color:#94a3b8; font-weight:700; }}
  .cover h1 {{ font-size:38px; line-height:1.1; margin:14px 0 8px; font-weight:800; letter-spacing:-.01em; }}
  .cover .sub {{ font-size:16px; color:#cbd5e1; margin-bottom:20px; max-width:780px; }}
  .cover-meta {{ font-size:13px; color:#94a3b8; }}
  .cover-meta strong {{ color:#fff; }}
  /* KPI grid */
  .kpi-grid {{ display:grid; grid-template-columns:repeat(5,1fr); gap:14px; margin:24px 0 32px; }}
  .kpi-card {{ background:#fff; border:1px solid #e2e8f0; border-radius:12px; padding:18px 20px; box-shadow:0 1px 3px rgba(0,0,0,.04); }}
  .kpi-label {{ font-size:10px; text-transform:uppercase; color:#64748b; letter-spacing:.08em; font-weight:700; margin-bottom:4px; }}
  .kpi-value {{ font-size:32px; font-weight:800; line-height:1; margin-bottom:4px; }}
  .kpi-sub {{ font-size:11px; color:#64748b; }}
  .kpi-critical .kpi-value {{ color:#0f172a; }}
  .kpi-critical {{ background:linear-gradient(135deg, #fff, #fee2e2); border-color:#fecaca; }}
  .kpi-high .kpi-value {{ color:#dc2626; }}
  .kpi-high {{ background:linear-gradient(135deg, #fff, #fef3c7); border-color:#fde68a; }}
  .kpi-info .kpi-value {{ color:#1d4ed8; }}
  .kpi-cve .kpi-value {{ color:#7c3aed; }}
  .kpi-kev .kpi-value {{ color:#dc2626; }}
  .kpi-kev {{ background:linear-gradient(135deg, #fff, #fee2e2); border-color:#fecaca; }}
  /* Headings */
  h2 {{ font-size:20px; margin:36px 0 14px; font-weight:700; padding-bottom:6px; border-bottom:2px solid #0f172a; }}
  h3 {{ font-size:15px; margin:0 0 10px; font-weight:700; color:#1e293b; }}
  h4 {{ font-size:13px; margin:0 0 6px; font-weight:700; color:#475569; text-transform:uppercase; letter-spacing:.04em; }}
  /* Layout */
  .grid-2 {{ display:grid; grid-template-columns:1fr 1fr; gap:18px; }}
  .panel {{ background:#fff; border:1px solid #e2e8f0; border-radius:12px; padding:18px 20px; }}
  .legend {{ display:flex; flex-wrap:wrap; gap:12px; font-size:11px; color:#475569; justify-content:center; }}
  .legend i {{ display:inline-block; width:10px; height:10px; border-radius:2px; margin-right:4px; vertical-align:middle; }}
  /* Tables */
  table.report-table {{ width:100%; border-collapse:collapse; font-size:12px; margin:8px 0 18px; }}
  table.report-table th {{ text-align:left; padding:8px 10px; background:#0f172a; color:#cbd5e1; font-size:10px; font-weight:700; text-transform:uppercase; letter-spacing:.06em; }}
  table.report-table th:first-child {{ border-top-left-radius:6px; }}
  table.report-table th:last-child {{ border-top-right-radius:6px; }}
  table.report-table td {{ padding:8px 10px; border-bottom:1px solid #f1f5f9; vertical-align:top; }}
  /* Risk band badges */
  .band {{ display:inline-block; padding:3px 9px; border-radius:4px; font-size:11px; font-weight:700; min-width:36px; text-align:center; }}
  .band-safe {{ background:#dcfce7; color:#14532d; }}
  .band-low {{ background:#dbeafe; color:#1e3a8a; }}
  .band-medium {{ background:#fef3c7; color:#78350f; }}
  .band-high {{ background:#fee2e2; color:#7f1d1d; }}
  .band-critical {{ background:#0f172a; color:#fff; }}
  /* Pills */
  .pill {{ display:inline-block; padding:1px 6px; background:#f1f5f9; color:#334155; border-radius:3px; font-size:10px; margin:0 2px 0 0; }}
  .cat-pill {{ background:#eff6ff; color:#1d4ed8; padding:1px 7px; border-radius:3px; font-size:11px; font-weight:600; }}
  .kev-badge {{ background:#dc2626; color:#fff; padding:1px 5px; border-radius:3px; font-size:9px; font-weight:700; vertical-align:middle; }}
  .cve-count {{ background:#fef3c7; color:#78350f; padding:1px 6px; border-radius:3px; font-size:10px; font-weight:600; margin-left:4px; }}
  code {{ font-family:ui-monospace,Menlo,Consolas,monospace; font-size:12px; background:#f8fafc; padding:1px 5px; border-radius:3px; }}
  code.mac {{ font-size:10px; color:#475569; }}
  code.mini {{ font-size:10px; padding:0 4px; }}
  .sysd {{ font-size:10px; color:#64748b; margin-top:4px; font-family:ui-monospace,monospace; max-width:480px; }}
  /* Device cards */
  .device-card {{ background:#fff; border:1px solid #e2e8f0; border-radius:12px; padding:18px 22px; margin:12px 0; page-break-inside:avoid; }}
  .device-head {{ display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:14px; }}
  .device-ip {{ font-size:18px; font-weight:700; }}
  .device-meta {{ font-size:12px; color:#64748b; margin-top:3px; }}
  .device-risk {{ text-align:right; }}
  .device-score {{ font-size:24px; font-weight:800; margin-top:6px; color:#0f172a; }}
  .device-score small {{ font-size:11px; color:#94a3b8; font-weight:500; }}
  .device-body {{ display:grid; grid-template-columns:1fr 1fr; gap:18px; font-size:12px; padding-top:8px; border-top:1px solid #f1f5f9; }}
  .device-body ul {{ margin:4px 0 0; padding-left:18px; }}
  .device-body li {{ margin:3px 0; }}
  .cve-list {{ margin:4px 0 0; padding-left:18px; font-size:11px; }}
  .cve-list li {{ margin:3px 0; }}
  /* Compliance section */
  .compliance-grid {{ display:grid; grid-template-columns:repeat(auto-fit, minmax(220px, 1fr)); gap:14px; margin:14px 0; }}
  .compliance-card {{ background:#fff; border:1px solid #e2e8f0; border-radius:10px; padding:14px 16px; }}
  .compliance-card .name {{ font-weight:700; color:#1e3a8a; }}
  .compliance-card .gauge {{ height:8px; background:#e2e8f0; border-radius:4px; margin:8px 0; overflow:hidden; }}
  .compliance-card .gauge-fill {{ height:100%; background:linear-gradient(90deg,#dc2626,#d97706,#16a34a); }}
  .compliance-card .stat {{ font-size:11px; color:#64748b; }}
  /* Section dividers */
  .section-intro {{ background:#f8fafc; border-left:4px solid #1e3a8a; padding:14px 18px; border-radius:0 6px 6px 0; margin:8px 0 18px; font-size:13px; color:#334155; }}
  /* Print styles */
  @media print {{
    .cover {{ padding:40px 24px 32px; }}
    h2 {{ page-break-after:avoid; }}
    .device-card {{ page-break-inside:avoid; }}
    .panel {{ page-break-inside:avoid; }}
  }}
  /* Footer */
  .footer {{ margin-top:50px; padding:18px 0; border-top:1px solid #e2e8f0; font-size:11px; color:#64748b; text-align:center; }}
  .toc {{ background:#f8fafc; border-radius:8px; padding:14px 20px; margin:18px 0 28px; font-size:12px; }}
  .toc h3 {{ margin:0 0 8px; font-size:11px; text-transform:uppercase; letter-spacing:.06em; color:#64748b; }}
  .toc ol {{ margin:0; padding-left:20px; columns:2; }}
  .toc li {{ padding:1px 0; }}
  .toc a {{ color:#1d4ed8; text-decoration:none; }}
</style>
</head>
<body>
<div class="page">

<!-- COVER -->
<div class="cover">
  <div class="brand">SafeCadence Network Risk · Audit Report</div>
  <h1>Network Risk Assessment</h1>
  <div class="sub">Comprehensive identification, vulnerability mapping, and remediation prioritization for {_esc(cidr)}.</div>
  <div class="cover-meta">
    Prepared for <strong>{org}</strong> ·
    Subnet <strong>{_esc(cidr)}</strong> ·
    Scan mode <strong>{_esc(mode)}</strong> ·
    {scanned} hosts probed in {duration/1000:.1f}s ·
    Generated {generated}
  </div>
</div>

<!-- TOC -->
<div class="toc">
  <h3>Contents</h3>
  <ol>
    <li><a href="#exec">Executive Summary</a></li>
    <li><a href="#risk">Fleet Risk Distribution</a></li>
    <li><a href="#critical">Devices Requiring Immediate Action</a></li>
    <li><a href="#vulns">Top Vulnerabilities</a></li>
    <li><a href="#actions">Top Recommended Actions</a></li>
    <li><a href="#compliance">Compliance Coverage</a></li>
    <li><a href="#inventory">Full Asset Inventory</a></li>
    <li><a href="#methodology">Methodology</a></li>
  </ol>
</div>

<!-- EXEC SUMMARY -->
<h2 id="exec">Executive Summary</h2>
{kpis_html}

<div class="section-intro">
This assessment of <code>{_esc(cidr)}</code> identified <strong>{count} devices</strong>, of which
<strong>{crit + high} ({((crit+high)/max(count,1))*100:.0f}%)</strong> require remediation action.
{f"<strong>{kev_cves} known-exploited vulnerabilities (CISA KEV-listed)</strong> were matched across <strong>{devices_with_kev} devices</strong> — these have confirmed real-world exploitation and warrant immediate attention." if kev_cves else "No known-exploited vulnerabilities were matched, but the assessment is heuristic and additional CVEs may apply once devices are positively identified."}
The most impactful remediation priority is detailed in section 5; per-device action plans are in sections 3 and 7.
</div>

<!-- RISK -->
<h2 id="risk">Fleet Risk Distribution</h2>
{donut_panel}

<!-- SPOTLIGHT -->
<h2 id="critical">Devices Requiring Immediate Action ({len(spotlight)})</h2>
<p>The {len(spotlight)} device{"s" if len(spotlight) != 1 else ""} below carry the highest aggregated risk score across the fleet. Each entry includes findings, recommended remediation actions, and any CVEs matched against the device's identified vendor/version. Prioritize these in your next change window.</p>
{spotlight_html or '<div class="section-intro" style="border-color:#16a34a; background:#f0fdf4">No devices in the critical or high-risk bands. Continue normal monitoring cadence.</div>'}

<!-- VULNS -->
{top_cves_html}

<!-- ACTIONS -->
{top_actions_html}

<!-- COMPLIANCE -->
{compliance_html}

<!-- INVENTORY -->
<h2 id="inventory">Full Asset Inventory ({count} devices)</h2>
<table class="report-table">
  <thead><tr><th>Risk</th><th>IP</th><th>Hostname</th><th>MAC</th><th>Vendor</th><th>Category</th><th>Open ports / CVEs</th></tr></thead>
  <tbody>{inv_rows}</tbody>
</table>

<!-- METHODOLOGY -->
<h2 id="methodology">Methodology &amp; Disclosure</h2>
<p style="font-size:12px; color:#475569">
  This assessment was generated by <code>safecadence-netrisk</code> (open-source, MIT-licensed) running locally on the
  auditor's workstation. <strong>No data was transmitted to any third party.</strong> Discovery used five concurrent
  identification techniques: TCP port probing on 27 management ports, ARP cache reading for L2-adjacent devices,
  mDNS/Bonjour multicast listener for self-announcing devices, SNMP v2c sysDescr GET with common community strings
  (only when port 161 was already detected open), and TLS certificate subject extraction with HTTP page-title scraping.
  Risk scores combine port-based heuristics, default-credential detection, and known-vulnerability matching against
  the bundled CVE database (cross-referenced with the CISA Known Exploited Vulnerabilities catalog as of {generated}).
  CVE matching is best-effort; results may miss CVEs for devices not positively identified by vendor + version.
  This report should be reviewed by a qualified network security engineer before initiating remediation work.
</p>
<p style="font-size:11px; color:#94a3b8; margin-top:18px">
  Tool: <a href="https://pypi.org/project/safecadence-netrisk/" style="color:#1d4ed8">safecadence-netrisk</a> ·
  Source: <a href="https://github.com/famousleads/safecadence-network-risk" style="color:#1d4ed8">github.com/famousleads/safecadence-network-risk</a> ·
  Engagement support: <a href="mailto:hello@safecadence.com" style="color:#1d4ed8">hello@safecadence.com</a>
</p>

<div class="footer">
  Generated by SafeCadence Network Risk · {generated} · MIT licensed · 100% local · Bring-your-own-AI
</div>

</div>
</body>
</html>
"""


def _compute_compliance_coverage(results: list[dict]) -> dict:
    """Aggregate compliance framework coverage from finding tags."""
    frameworks = {
        "NIST 800-53": {"passed": 0, "failed": 0, "covered_controls": set()},
        "CIS Controls v8": {"passed": 0, "failed": 0, "covered_controls": set()},
        "PCI-DSS": {"passed": 0, "failed": 0, "covered_controls": set()},
        "HIPAA": {"passed": 0, "failed": 0, "covered_controls": set()},
    }
    # Map common keywords in finding text → framework controls
    keyword_map = [
        # (keywords, NIST, CIS, PCI, HIPAA)
        (["telnet", "cleartext"], "AC-17", "4.5", "2.3", "164.312(a)"),
        (["snmp default"], "IA-5", "5.4", "2.1", "164.308(a)(5)"),
        (["smb1", "smb"], "SC-8", "13.6", "4.1", "164.312(e)"),
        (["rdp"], "AC-17", "12.6", "8.3", "164.312(a)"),
        (["ftp"], "SC-8", "4.1", "2.3", "164.312(e)"),
        (["self-signed", "tls"], "SC-12", "3.10", "4.1", "164.312(e)"),
    ]
    for r in results:
        for f in r.get("findings", []):
            f_lower = f.lower()
            for kws, nist, cis, pci, hipaa in keyword_map:
                if any(k in f_lower for k in kws):
                    frameworks["NIST 800-53"]["failed"] += 1
                    frameworks["NIST 800-53"]["covered_controls"].add(nist)
                    frameworks["CIS Controls v8"]["failed"] += 1
                    frameworks["CIS Controls v8"]["covered_controls"].add(cis)
                    frameworks["PCI-DSS"]["failed"] += 1
                    frameworks["PCI-DSS"]["covered_controls"].add(pci)
                    frameworks["HIPAA"]["failed"] += 1
                    frameworks["HIPAA"]["covered_controls"].add(hipaa)
    # Convert sets to sorted lists for serialization
    for fw in frameworks.values():
        fw["covered_controls"] = sorted(fw["covered_controls"])
    return frameworks


def _render_compliance_section(compliance_data: dict) -> str:
    cards = []
    for name, fw in compliance_data.items():
        failed = fw["failed"]
        controls = fw["covered_controls"]
        # Coverage bar — 100% gap if any failures, else 0%
        gap_pct = min(100, failed * 5)  # rough
        ctrl_chips = " ".join(f'<span class="pill">{_esc(c)}</span>' for c in controls[:8])
        cards.append(f"""
        <div class="compliance-card">
          <div class="name">{_esc(name)}</div>
          <div class="gauge"><div class="gauge-fill" style="width:{gap_pct}%"></div></div>
          <div class="stat">{failed} finding{'s' if failed != 1 else ''} mapped · {len(controls)} controls touched</div>
          <div style="margin-top:8px">{ctrl_chips or '<span style="color:#16a34a; font-size:11px">No mapped findings</span>'}</div>
        </div>
        """)
    return f"""
    <h2 id="compliance">Compliance Coverage</h2>
    <p>Findings from this assessment have been auto-mapped to commonly-required compliance frameworks. The bar shows the relative gap (longer = more findings).</p>
    <div class="compliance-grid">{''.join(cards)}</div>
    <p style="font-size:11px; color:#64748b; margin-top:8px">
      Mappings are heuristic — verify against your specific compliance scope.
      Run <code>safecadence list-rules --vendor &lt;vendor&gt;</code> for the full per-rule
      compliance tag library.
    </p>
    """
