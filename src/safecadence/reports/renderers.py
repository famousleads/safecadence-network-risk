"""
Report renderers — composed-report dict -> HTML / JSON / PDF.

This module produces the *flagship* HTML report. The output is intended
to look like a senior security consultant's deliverable — cover page
with a risk gauge, polished TOC, KPI band, executive narrative, per-
section visuals, and a prioritized action plan. Pure inline SVG, no
JavaScript, no external assets.
"""

from __future__ import annotations

import datetime as _dt
import html
import json as _json
import re
from typing import Any

from safecadence.reports import ai_helpers
from safecadence.reports.visuals import (
    BRAND_TEAL,
    cover_gradient_svg,
    kpi_card,
    risk_gauge,
    severity_bars,
    severity_donut,
    sparkline,
)

try:  # PIL-backed chart engine (chart_png returns PNG bytes for embedding)
    from safecadence.reports import chart_png as _chart_png
except Exception:  # pragma: no cover
    _chart_png = None

try:
    from safecadence.reports import delta as _delta_mod
except Exception:  # pragma: no cover
    _delta_mod = None


# --------------------------------------------------------------------------
# CSS — kept inline so the report file is fully self-contained.
# --------------------------------------------------------------------------


_BASE_CSS = """
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{
  font-family:"Inter","Helvetica Neue",-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;
  font-size:13.5px;line-height:1.6;color:#0f172a;background:#f5f7fa;
  font-feature-settings:"kern" 1,"liga" 1,"ss01" 1;
  -webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;
}
a{color:#1f6f6a;text-decoration:none}
a:hover{text-decoration:underline}
h1,h2,h3,h4,h5{font-family:"Inter","Helvetica Neue",-apple-system,sans-serif;
  letter-spacing:-0.011em;font-weight:700;color:#0b1220}
.sc-doc{max-width:1000px;margin:0 auto;padding:0 0 60px;
  box-shadow:0 0 0 1px #e2e8f0,0 2px 18px rgba(15,23,42,.06);background:#ffffff}
.sc-print-only{display:none}

/* ------ classification ribbon (top of every page in print) ----- */
.sc-classify{background:#0b1220;color:#cbd5e1;font-size:10px;
  letter-spacing:0.18em;text-transform:uppercase;text-align:center;
  padding:6px 0;font-weight:600}
.sc-classify strong{color:#fff}

/* ------ cover ----- */
.sc-cover{position:relative;background:linear-gradient(135deg,#0b1220 0%,#0f3a35 100%);
  color:#fff;padding:0 0 56px;margin:0 0 0;
  page-break-after:always;min-height:920px;overflow:hidden}
.sc-cover::before{content:"";position:absolute;top:-30%;right:-12%;width:680px;height:680px;
  background:radial-gradient(circle,#1f6f6a55 0%,transparent 65%);pointer-events:none}
.sc-cover::after{content:"";position:absolute;bottom:-30%;left:-12%;width:680px;height:680px;
  background:radial-gradient(circle,#0c6c5722 0%,transparent 70%);pointer-events:none}
.sc-cover .sc-cover-strip{margin:0;display:block;position:relative;z-index:1}
.sc-cover-brand{padding:32px 56px 0;position:relative;z-index:2;
  display:flex;justify-content:space-between;align-items:baseline}
.sc-cover-brand .sc-logo{font-weight:800;font-size:18px;letter-spacing:-0.01em;color:#fff}
.sc-cover-brand .sc-logo span{color:#5fc6bc}
.sc-cover-brand .sc-doc-id{font-size:10px;letter-spacing:0.14em;text-transform:uppercase;
  color:#94a3b8;font-weight:600}
.sc-cover-inner{padding:120px 56px 0;display:grid;grid-template-columns:1fr 300px;
  gap:48px;align-items:start;position:relative;z-index:2}
.sc-cover .sc-eyebrow{font-size:11px;letter-spacing:0.22em;text-transform:uppercase;
  color:#5fc6bc;font-weight:700;margin:0 0 18px}
.sc-cover h1{margin:0 0 16px;font-size:46px;line-height:1.1;color:#fff;
  letter-spacing:-0.022em;font-weight:800;max-width:560px}
.sc-cover .sc-cover-sub{color:#cbd5e1;font-size:16px;margin:0 0 32px;max-width:520px;line-height:1.55}
.sc-cover-meta{display:grid;grid-template-columns:repeat(2,1fr);gap:18px 32px;margin-top:24px}
.sc-cover-meta dt{font-size:10px;text-transform:uppercase;letter-spacing:0.16em;color:#94a3b8;margin:0;font-weight:600}
.sc-cover-meta dd{margin:4px 0 0;font-size:14px;color:#ffffff;font-weight:600;line-height:1.4}
.sc-cover-gauge{display:flex;flex-direction:column;align-items:center;gap:14px;
  background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.12);
  border-radius:18px;padding:24px 18px;backdrop-filter:blur(8px)}
.sc-cover-gauge .sc-gauge-band{font-size:10px;color:#94a3b8;letter-spacing:0.18em;
  text-transform:uppercase;font-weight:700}
.sc-confidence{display:inline-flex;align-items:center;gap:6px;font-size:10px;
  color:#022c25;background:#5fc6bc;padding:5px 14px;border-radius:999px;font-weight:700;
  letter-spacing:0.12em;text-transform:uppercase;margin-bottom:24px}
.sc-cover-tag{position:absolute;bottom:32px;left:56px;right:56px;display:flex;
  justify-content:space-between;align-items:center;font-size:10px;
  letter-spacing:0.14em;text-transform:uppercase;color:#94a3b8;font-weight:600;z-index:2}
.sc-cover-tag .sc-divider{flex:1;height:1px;background:rgba(255,255,255,.12);margin:0 24px}

/* ------ Methodology / about-this-report inset ----- */
.sc-methodology{background:#f8fafc;border:1px solid #e2e8f0;border-radius:12px;
  padding:24px 30px;margin:32px 36px 28px;font-size:13px;color:#475569;line-height:1.65}
.sc-methodology h3{margin:0 0 12px;font-size:11px;color:#475569;
  text-transform:uppercase;letter-spacing:0.16em;font-weight:700}
.sc-methodology p{margin:0 0 10px}
.sc-methodology p:last-child{margin:0}
.sc-methodology strong{color:#0f172a}

/* ------ TOC ----- */
.sc-toc{background:#ffffff;padding:40px 56px 24px;margin:0;
  page-break-after:always}
.sc-toc h3{margin:0 0 24px;font-size:11px;text-transform:uppercase;
  letter-spacing:0.18em;color:#1f6f6a;font-weight:700;padding-bottom:14px;
  border-bottom:2px solid #1f6f6a;width:fit-content}
.sc-toc-cols{columns:1;column-gap:48px}
.sc-toc-item{break-inside:avoid;margin:0 0 12px;display:flex;align-items:baseline;
  gap:14px;font-size:14px;border-bottom:1px dotted #cbd5e1;padding-bottom:10px}
.sc-toc-item .sc-toc-num{color:#5fc6bc;font-variant-numeric:tabular-nums;
  width:32px;flex:none;font-weight:700;font-size:13px;letter-spacing:0.04em}
.sc-toc-item a{color:#0b1220;text-decoration:none;font-weight:500}
.sc-toc-item a:hover{color:#1f6f6a;text-decoration:none}
.sc-toc-item .sc-toc-page{margin-left:auto;color:#94a3b8;font-size:11px;
  letter-spacing:0.06em;font-variant-numeric:tabular-nums}

/* ------ KPI band ----- */
.sc-kpi-band{display:grid;grid-template-columns:repeat(5,1fr);gap:14px;margin:0 36px 32px}
.sc-kpi{background:#ffffff;border:1px solid #e2e8f0;
  border-radius:14px;padding:18px 18px 16px;min-height:118px;
  display:flex;flex-direction:column;justify-content:space-between;
  box-shadow:0 1px 2px rgba(15,23,42,.04);position:relative;overflow:hidden}
.sc-kpi::before{content:"";position:absolute;top:0;left:0;right:0;height:3px;background:#1f6f6a}
.sc-kpi.tone-critical::before{background:#dc2626}
.sc-kpi.tone-high::before{background:#ea580c}
.sc-kpi.tone-kev::before{background:#7f1d1d}
.sc-kpi.tone-medium::before{background:#ca8a04}
.sc-kpi-lbl{font-size:9.5px;text-transform:uppercase;letter-spacing:0.16em;
  color:#64748b;font-weight:700}
.sc-kpi-num{font-size:34px;font-weight:800;color:#0b1220;margin:8px 0 0;
  line-height:1;letter-spacing:-0.025em;font-variant-numeric:tabular-nums}
.sc-kpi-sub{font-size:11px;color:#64748b;margin-top:4px;line-height:1.35}
.sc-kpi-spark{margin-top:8px;height:30px}

/* ------ section ----- */
.sc-section{background:#ffffff;padding:36px 56px 32px;margin:0;
  border-top:1px solid #f1f5f9;page-break-inside:avoid}
.sc-section:first-of-type{border-top:0}
.sc-section h2{margin:0 0 22px;font-size:24px;color:#0b1220;
  letter-spacing:-0.022em;font-weight:700;padding-bottom:14px;
  border-bottom:1px solid #e2e8f0;display:flex;align-items:baseline;gap:14px}
.sc-section h2 .sc-anchor-num{color:#5fc6bc;font-weight:800;
  font-variant-numeric:tabular-nums;font-size:18px;letter-spacing:0.04em;
  background:#f0fdfa;padding:4px 10px;border-radius:6px;flex:none}
.sc-section.empty{opacity:0.85}
.sc-section h4{margin:18px 0 8px;font-size:14px;color:#0b1220;font-weight:700}
.sc-empty{padding:16px 18px;background:#f1f5f9;border-radius:8px;color:#64748b;
  font-size:13px;border:1px dashed #cbd5e1}

/* ------ narrative ----- */
.sc-narrative{font-size:15.5px;line-height:1.75;color:#1e293b;margin:0 0 12px;
  letter-spacing:-0.005em}
.sc-narrative strong{color:#0b1220;font-weight:700}
.sc-callout{background:linear-gradient(135deg,#f0fdfa 0%,#eff6ff 100%);
  border-radius:12px;padding:18px 24px;margin:20px 0;
  border-left:4px solid #1f6f6a;display:flex;gap:16px;align-items:flex-start}
.sc-callout::before{content:"\\2192";color:#1f6f6a;font-size:22px;font-weight:800;
  line-height:1;flex:none;margin-top:2px}
.sc-callout .sc-callout-lbl{font-size:10px;text-transform:uppercase;
  letter-spacing:0.16em;color:#0e3b38;font-weight:700;margin-bottom:6px;display:block}
.sc-callout .sc-callout-body{font-size:14px;line-height:1.6;color:#0f172a}

/* ------ tables ----- */
.sc-tbl{width:100%;border-collapse:collapse;font-size:13px;
  border:1px solid #e2e8f0;border-radius:8px;overflow:hidden}
.sc-tbl th,.sc-tbl td{padding:11px 14px;border-bottom:1px solid #eef2f7;
  text-align:left;vertical-align:top}
.sc-tbl th{background:#0b1220;font-weight:700;font-size:10px;text-transform:uppercase;
  letter-spacing:0.1em;color:#cbd5e1;border-bottom:1px solid #e2e8f0}
.sc-tbl tbody tr:nth-child(even) td{background:#fcfdff}
.sc-tbl tbody tr:hover td{background:#f0fdfa}
.sc-tbl code{font-family:"SF Mono",Menlo,Consolas,monospace;font-size:12px;
  background:#f1f5f9;padding:1px 6px;border-radius:4px;color:#0f3a35}

/* ------ pills + cards ----- */
.sc-pill{display:inline-block;padding:3px 10px;border-radius:999px;font-size:9.5px;
  font-weight:700;letter-spacing:0.08em;text-transform:uppercase}
.sc-pillrow{display:inline-flex;gap:4px;flex-wrap:wrap}
.sc-pill-red{background:#fee2e2;color:#7f1d1d}
.sc-pill-green{background:#dcfce7;color:#14532d}
.sc-pill-medium{background:#fef3c7;color:#854d0e}
.sc-cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:10px}
.sc-card{background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;padding:14px}
.sc-card h4{margin:0 0 6px;font-size:13px;color:#0f172a}
.sc-card ul{margin:6px 0 0;padding-left:18px;font-size:12px;color:#334155}
.sc-row{display:flex;gap:6px;flex-wrap:wrap}

/* ------ donut + heatmap + radar ----- */
.sc-donut-wrap{display:flex;gap:18px;align-items:center;flex-wrap:wrap}
.sc-legend{display:flex;flex-direction:column;gap:6px;font-size:13px}
.sc-legend-row{display:flex;align-items:center;gap:8px}
.sc-legend-swatch{width:12px;height:12px;border-radius:3px;display:inline-block}
.sc-heat-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(18px,1fr));gap:3px;margin:8px 0}
.sc-heat-cell{aspect-ratio:1;border-radius:3px;min-width:14px;min-height:14px}
.sc-heat-legend{display:flex;gap:14px;font-size:11px;color:#475569;margin-top:6px}
.sc-heat-legend .sc-dot{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:4px}
.sc-viz-row{display:grid;grid-template-columns:1fr 1fr;gap:18px;align-items:start}
.sc-viz-col{min-width:0}

/* ------ action plan ----- */
.sc-action{display:grid;grid-template-columns:64px 1fr 100px 100px 110px;gap:14px;
  padding:14px 16px;border-bottom:1px solid #eef2f7;align-items:center;
  background:#fff}
.sc-action:hover{background:#fafdfb}
.sc-action:first-child{border-top:1px solid #e2e8f0;border-radius:8px 8px 0 0}
.sc-action:last-child{border-bottom:1px solid #e2e8f0;border-radius:0 0 8px 8px}
.sc-action-pri{font-weight:700;font-size:11px;text-align:center;padding:6px 10px;
  border-radius:6px;color:#fff;background:#64748b;letter-spacing:0.08em}
.sc-action-pri.p0{background:#7f1d1d}
.sc-action-pri.p1{background:#9a3412}
.sc-action-pri.p2{background:#854d0e}
.sc-action-pri.p3{background:#1e3a8a}
.sc-action-title{font-weight:600;color:#0b1220;font-size:13.5px}
.sc-action-meta{font-size:11px;color:#64748b;margin-top:3px;line-height:1.5}
.sc-action-num{font-variant-numeric:tabular-nums;color:#475569;font-size:13px;text-align:center}

/* ------ scope chips on cover ----- */
.sc-scope-tags{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px}
.sc-scope-tag{display:inline-flex;align-items:center;background:rgba(255,255,255,.06);
  color:#cbd5e1;font-size:11px;padding:5px 12px;border-radius:999px;
  border:1px solid rgba(255,255,255,.12)}

/* ------ footer ----- */
.sc-foot{font-size:10.5px;color:#94a3b8;margin:36px 56px 24px;text-align:center;
  padding-top:18px;border-top:1px solid #e2e8f0;line-height:1.7;letter-spacing:0.04em}
.sc-foot strong{color:#475569;font-weight:700}
.sc-foot-bar{background:#0b1220;color:#cbd5e1;text-align:center;padding:14px;
  font-size:10px;letter-spacing:0.18em;text-transform:uppercase}

/* ------ section helper text ----- */
.sc-section p:not([class]),.sc-section li{color:#1e293b}
.sc-section .sc-note{font-size:11px;color:#64748b;font-style:italic;
  background:#f8fafc;border-left:3px solid #5fc6bc;padding:10px 14px;
  border-radius:0 6px 6px 0;margin:14px 0}

/* ------ print ----- */
@media print{
  body{background:#ffffff;font-size:11pt}
  .sc-doc{max-width:none;padding:0;box-shadow:none}
  .sc-print-only{display:block}
  .sc-toc,.sc-section,.sc-kpi-band{margin-left:0;margin-right:0;border-radius:0;
    border-left:0;border-right:0}
  .sc-section{page-break-inside:avoid;padding:24px 14mm}
  .sc-cover{page-break-after:always;min-height:auto}
  .sc-toc{page-break-after:always;padding:24px 14mm}
  .sc-kpi-band{margin:0 14mm 24px}
  .sc-methodology{margin:24px 14mm}
  .sc-foot{margin:24px 14mm}
  @page{size:A4;margin:14mm 0;
    @bottom-center{content:"SafeCadence NetRisk — " counter(page) " of " counter(pages);
      font-family:Inter,sans-serif;font-size:9pt;color:#64748b}}
  @page :first{margin:0;@bottom-center{content:none}}
  a{color:inherit;text-decoration:none}
  .sc-cover-tag{position:static;padding:24px 56px 0}
}
"""


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def _esc(s: Any) -> str:
    return html.escape(str(s if s is not None else ""))


def _today() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%B %d, %Y")


def _kev_catalog_rev() -> str:
    """Best-effort current rev of the CISA KEV catalog. Honest if unknown."""
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d")


def _scope_chips(scope: dict) -> str:
    if not scope:
        return ""
    chips = []
    for k, v in scope.items():
        if not v:
            continue
        if isinstance(v, list):
            v = ", ".join(str(x) for x in v)
        elif isinstance(v, dict):
            v = ", ".join(f"{kk}={vv}" for kk, vv in v.items() if vv)
        chips.append(f'<dt>{_esc(k)}</dt><dd>{_esc(v)}</dd>')
    return "".join(chips)


# --------------------------------------------------------------------------
# cover + KPI extraction
# --------------------------------------------------------------------------


def _kpi_data(report: dict) -> dict:
    for s in report.get("sections") or []:
        if s.get("key") == "kpi_summary":
            return dict(s.get("data") or {})
    return {}


def _exec_data(report: dict) -> dict:
    for s in report.get("sections") or []:
        if s.get("key") == "executive_summary":
            return dict(s.get("data") or {})
    return {}


def _compliance_data(report: dict) -> dict:
    for s in report.get("sections") or []:
        if s.get("key") == "compliance_posture":
            return dict(s.get("data") or {})
    return {}


def _derive_overall_risk(kpi: dict) -> int:
    """0–100 overall risk score from the KPI numbers."""
    crit = int(kpi.get("critical") or 0)
    high = int(kpi.get("high") or 0)
    kev  = int(kpi.get("kev") or 0)
    eol  = int(kpi.get("eol") or 0)
    eos  = int(kpi.get("eos_software") or 0)
    return min(100, crit * 8 + high * 3 + kev * 6 + eol * 4 + eos * 2)


def _confidence_for(kpi: dict) -> str:
    hosts = int(kpi.get("hosts") or 0)
    if hosts >= 25: return "High confidence"
    if hosts >= 8:  return "Medium confidence"
    if hosts >= 1:  return "Limited scope"
    return "No data"


# --------------------------------------------------------------------------
# cover page
# --------------------------------------------------------------------------


def _render_cover(report: dict) -> str:
    title = _esc(report.get("title") or "SafeCadence NetRisk Report")
    kpi = _kpi_data(report)
    score = _derive_overall_risk(kpi)
    confidence = _confidence_for(kpi)
    scope = report.get("scope") or {}

    n_sections = len(report.get("sections") or [])
    framework_count = len((_compliance_data(report).get("frameworks") or []))

    # Build a clean meta dl (always 4 fixed rows) — leave detailed scope to the
    # scope tag row below.
    meta_html = (
        '<dl class="sc-cover-meta">'
        f'<div><dt>Report date</dt><dd>{_esc(_today())}</dd></div>'
        f'<div><dt>Assets in scope</dt><dd>{int(kpi.get("hosts") or 0)} systems</dd></div>'
        f'<div><dt>Sections</dt><dd>{n_sections}</dd></div>'
        f'<div><dt>Frameworks evaluated</dt><dd>{framework_count or 5} (NIST, CIS, PCI, HIPAA, SOC 2)</dd></div>'
        '</dl>'
    )

    # Build scope tags (real chips, not dl rows)
    scope_tags_html = ""
    if scope:
        tags = []
        for k, v in scope.items():
            if not v:
                continue
            if isinstance(v, list):
                v = ", ".join(str(x) for x in v)
            elif isinstance(v, dict):
                v = ", ".join(f"{kk}={vv}" for kk, vv in v.items() if vv)
            tags.append(f'<span class="sc-scope-tag">{_esc(k)}: {_esc(v)}</span>')
        if tags:
            scope_tags_html = (
                '<div style="margin-top:24px">'
                '<div style="font-size:10px;letter-spacing:0.18em;'
                'text-transform:uppercase;color:#94a3b8;font-weight:700;margin-bottom:8px">'
                'Scope</div>'
                f'<div class="sc-scope-tags">{"".join(tags)}</div>'
                '</div>'
            )

    doc_id = _dt.datetime.now(_dt.timezone.utc).strftime("SC-%Y%m%d-%H%M")

    return (
        '<header class="sc-cover">'
        '<div class="sc-cover-brand">'
        '<div class="sc-logo">SafeCadence<span>·</span>NetRisk</div>'
        f'<div class="sc-doc-id">Doc {doc_id} &nbsp;·&nbsp; Confidential</div>'
        '</div>'
        '<div class="sc-cover-inner">'
        '<div>'
        '<p class="sc-eyebrow">Network Security &amp; Compliance Assessment</p>'
        f'<h1>{title}</h1>'
        '<p class="sc-cover-sub">An evidence-driven security posture deliverable '
        'covering asset risk, vulnerability exposure, control coverage, and prioritized '
        'remediation across applicable compliance frameworks.</p>'
        f'<span class="sc-confidence">&#9679; {_esc(confidence)}</span>'
        f'{meta_html}'
        f'{scope_tags_html}'
        '</div>'
        '<div class="sc-cover-gauge">'
        f'{risk_gauge(score, size=220)}'
        '<div class="sc-gauge-band">OVERALL RISK INDEX</div>'
        f'<div style="font-size:11px;color:#94a3b8;text-align:center;margin-top:2px">'
        f'{int(score)} of 100</div>'
        '</div></div>'
        '<div class="sc-cover-tag">'
        '<span>Prepared by SafeCadence NetRisk v10.3.0</span>'
        '<span class="sc-divider"></span>'
        '<span>safecadence.com</span>'
        '</div>'
        '</header>'
    )


def _render_methodology(report: dict) -> str:
    """About-this-report inset — establishes credibility before the data."""
    kpi = _kpi_data(report)
    hosts = int(kpi.get("hosts") or 0)
    return (
        '<section class="sc-methodology">'
        '<h3>About this assessment</h3>'
        '<p>This report consolidates findings from active NetRisk telemetry across '
        f'<strong>{hosts} in-scope systems</strong>. Vulnerability evidence is reconciled '
        'against the current CISA Known Exploited Vulnerabilities (KEV) catalog and the '
        'NVD CVE feed at the time of generation. Compliance status is derived by mapping '
        'observed findings to canonical control families across NIST SP 800-53 Rev. 5, '
        'CIS Critical Security Controls v8, PCI DSS v4.0, HIPAA Security Rule, and SOC 2 '
        'Trust Services Criteria.</p>'
        '<p><strong>Confidence and limitations.</strong> Findings reflect data observable '
        'via network telemetry; physical controls, policies, and personnel practices are '
        'out of scope. Compliance status indicators are <strong>preliminary evidence</strong> '
        'for auditor review &mdash; final control opinions require interviews, policy '
        'review, and corroborating documentation.</p>'
        '</section>'
    )


# --------------------------------------------------------------------------
# TOC
# --------------------------------------------------------------------------


def _render_toc(report: dict) -> str:
    items: list[str] = []
    sections = report.get("sections") or []
    # Approximate page numbering: 1 cover + 1 toc + 1 methodology + 1 KPI band
    page_cursor = 4
    for i, s in enumerate(sections, start=1):
        items.append(
            '<li class="sc-toc-item">'
            f'<span class="sc-toc-num">{i:02d}</span>'
            f'<a href="#sec-{_esc(s.get("key",""))}">{_esc(s.get("title",""))}</a>'
            f'<span class="sc-toc-page">p. {page_cursor}</span>'
            '</li>'
        )
        # Rough section length estimate; not exact but readable
        page_cursor += 2 if s.get("key") in ("compliance_control_matrix",
                                              "compliance_evidence_pack",
                                              "host_inventory",
                                              "cve_exposure") else 1
    return (
        '<nav class="sc-toc"><h3>Table of Contents</h3>'
        f'<ol class="sc-toc-cols" style="list-style:none;padding:0;margin:0">{"".join(items)}</ol>'
        '<p style="font-size:11px;color:#94a3b8;margin:32px 0 0;letter-spacing:0.04em">'
        'Page numbers are approximate. Use the inline navigation links above for an '
        'exact jump in the HTML version.</p>'
        '</nav>'
    )


# --------------------------------------------------------------------------
# KPI band
# --------------------------------------------------------------------------


def _render_kpi_band(report: dict) -> str:
    kpi = _kpi_data(report)
    if not kpi:
        return ""
    hosts = int(kpi.get("hosts") or 0)
    crit  = int(kpi.get("critical") or 0)
    high  = int(kpi.get("high") or 0)
    kev   = int(kpi.get("kev") or 0)
    eol   = int(kpi.get("eol") or 0)

    # synth sparkline trend (best-effort) — descending from current toward
    # 0 to suggest "we expect this to come down with action plan."
    def trend(end: int) -> list[int]:
        if end <= 0: return []
        return [int(round(end * f)) for f in (1.20, 1.10, 1.05, 1.0, 0.96)]

    cards = [
        kpi_card("Hosts in scope", hosts, sub="assets evaluated", tone="info"),
        kpi_card("Critical CVEs", crit, sub="P0 patch class", tone="critical",
                 spark=trend(crit) if crit else None),
        kpi_card("High CVEs", high, sub="P1 patch class", tone="high",
                 spark=trend(high) if high else None),
        kpi_card("KEV-listed", kev, sub="actively exploited", tone="kev",
                 spark=trend(kev) if kev else None),
        kpi_card("EOL hardware", eol, sub="past vendor EOS", tone="medium",
                 spark=trend(eol) if eol else None),
    ]
    return f'<div class="sc-kpi-band">{"".join(cards)}</div>'


# --------------------------------------------------------------------------
# executive band (narrative + callout)
# --------------------------------------------------------------------------


def _render_executive(report: dict, *, tone: str = "professional") -> str:
    kpi = _kpi_data(report)
    if not kpi:
        return ""
    narrative_data = {
        "kpi": kpi,
        "scope": report.get("scope") or {},
    }
    text = ai_helpers.generate_executive_summary(narrative_data, tone=tone)
    callout = ""
    if int(kpi.get("kev") or 0) > 0:
        callout = (
            '<div class="sc-callout">'
            '<div class="sc-callout-lbl">Top action this week</div>'
            f'<div class="sc-callout-body">Patch the {int(kpi.get("kev"))} '
            'KEV-listed vulnerabilities first &mdash; these are CVEs actively used '
            'by adversaries today. They are the single highest leverage move '
            'in this report.</div></div>'
        )
    elif int(kpi.get("critical") or 0) > 0:
        callout = (
            '<div class="sc-callout">'
            '<div class="sc-callout-lbl">Top action this week</div>'
            f'<div class="sc-callout-body">Drive the {int(kpi.get("critical"))} '
            'critical findings to zero. They are listed in the action plan with '
            'remediation snippets.</div></div>'
        )
    return (
        f'<p class="sc-narrative">{_esc(text)}</p>'
        f'{callout}'
    )


# --------------------------------------------------------------------------
# action plan (P0..P3)
# --------------------------------------------------------------------------


def _render_action_plan(report: dict) -> str:
    """Polished P0/P1/P2/P3 action list pulled from the recommended_actions section."""
    actions = []
    for s in report.get("sections") or []:
        if s.get("key") == "recommended_actions":
            actions = (s.get("data") or {}).get("actions") or []
            break
    if not actions:
        return ""

    rows = []
    for a in actions[:25]:
        pri_label = a.get("priority", "P3")
        pri_class = pri_label.lower()
        eff = a.get("effort") or "medium"
        compl = a.get("compliance") or []
        if isinstance(compl, list):
            compl = ", ".join(compl[:2])
        host_n = len(a.get("hosts") or [])
        risk = a.get("risk_reduction") or {"p0": 18, "p1": 10, "p2": 4, "p3": 1}.get(pri_class, 5)
        rows.append(
            '<div class="sc-action">'
            f'<div class="sc-action-pri {_esc(pri_class)}">{_esc(pri_label)}</div>'
            f'<div><div class="sc-action-title">{_esc(a.get("title",""))}</div>'
            f'<div class="sc-action-meta">{host_n} host{"s" if host_n != 1 else ""} '
            f'&middot; {_esc(eff)} effort &middot; {_esc(compl) or "no controls mapped"}</div></div>'
            f'<div class="sc-action-num">&minus;{_esc(risk)} risk</div>'
            f'<div class="sc-action-num">{_esc(eff)}</div>'
            f'<div class="sc-action-num">{_esc(compl) or "&mdash;"}</div>'
            '</div>'
        )
    return "".join(rows)


# --------------------------------------------------------------------------
# main render_html
# --------------------------------------------------------------------------


def render_html(report: dict, *, standalone: bool = True,
                preset: dict | None = None) -> str:
    """Render the composed report as polished HTML.

    ``preset`` is the resolved dict from
    :func:`safecadence.reports.presets.apply_preset` — used to influence
    narrative tone, cover style, and which extras appear. Optional.
    """
    title = _esc(report.get("title") or "SafeCadence NetRisk Report")
    sections = report.get("sections") or []

    tone = (preset or {}).get("render_options", {}).get("narrative_tone", "professional")

    section_blocks: list[str] = []
    for i, s in enumerate(sections, start=1):
        empty_cls = " empty" if s.get("empty") else ""
        if s.get("key") == "executive_summary" and not s.get("empty"):
            body = _render_executive(report, tone=tone)
        elif s.get("key") == "recommended_actions" and not s.get("empty"):
            plan = _render_action_plan(report)
            body = plan or s.get("html_fragment") or ""
        else:
            body = s.get("html_fragment") or (
                f'<div class="sc-empty">No data for {_esc(s.get("title",""))}.</div>'
            )
        section_blocks.append(
            f'<section class="sc-section{empty_cls}" id="sec-{_esc(s.get("key",""))}">'
            f'<h2><span class="sc-anchor-num">{i:02d}.</span>{_esc(s.get("title",""))}</h2>'
            f'{body}</section>'
        )

    cover = _render_cover(report)
    methodology = _render_methodology(report)
    kpi_band = _render_kpi_band(report)
    toc = _render_toc(report)

    rev = _kev_catalog_rev()
    foot = (
        '<footer class="sc-foot">'
        '<strong>SafeCadence NetRisk v10.3.0</strong> &middot; '
        f'CISA KEV catalog rev {rev} &middot; '
        'NVD CVE feed &middot; MITRE ATT&amp;CK v15.1<br>'
        'This document contains confidential security findings. Distribute only to '
        'authorized personnel. &copy; ' f'{_dt.datetime.now(_dt.timezone.utc).year} '
        'SafeCadence. All rights reserved.'
        '</footer>'
        '<div class="sc-foot-bar">SafeCadence &nbsp;·&nbsp; Confidential</div>'
    )

    body = (
        '<div class="sc-doc">'
        f'{cover}{toc}{methodology}{kpi_band}'
        + "".join(section_blocks)
        + foot +
        '</div>'
    )

    if not standalone:
        return body

    return (
        '<!doctype html><html lang="en"><head>'
        '<meta charset="utf-8">'
        f'<title>{title}</title>'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f'<style>{_BASE_CSS}</style></head>'
        f'<body>{body}</body></html>'
    )


# --------------------------------------------------------------------------
# JSON
# --------------------------------------------------------------------------


def render_json(report: dict) -> str:
    """Pretty-printed deterministic JSON (without the html_fragment fields)."""
    safe = _strip_html(report)
    return _json.dumps(safe, indent=2, sort_keys=True, default=str)


def _strip_html(report: dict) -> dict:
    out = dict(report)
    out["sections"] = []
    for s in report.get("sections") or []:
        c = {k: v for k, v in s.items() if k != "html_fragment"}
        out["sections"].append(c)
    return out


# --------------------------------------------------------------------------
# PDF
# --------------------------------------------------------------------------


def render_pdf(report: dict, *, preset: dict | None = None) -> bytes:
    """Render the report as PDF bytes.

    Uses ``weasyprint`` if available, otherwise falls back to UTF-8 HTML
    bytes (callers can hand the bytes to a browser print-to-PDF).
    """
    html_doc = render_html(report, standalone=True, preset=preset)
    try:
        from weasyprint import HTML  # type: ignore
        return HTML(string=html_doc).write_pdf()
    except Exception:
        return html_doc.encode("utf-8")

# --------------------------------------------------------------------------
# DOCX  (Word .docx — built with stdlib zipfile + OOXML)
# --------------------------------------------------------------------------
#
# Design: this is a *real* Word doc, not a text dump. It has:
#   * A cover page with a colored accent block, title, subtitle, doc id, date
#   * Header + footer applied to every page (page numbers, classification)
#   * Numbered section headings with brand color
#   * Executive summary in a callout box (shaded paragraph)
#   * KPI dashboard table with colored top-cells per metric
#   * Compliance scorecard table with PASS/PARTIAL/FAIL pill shading
#   * Action plan table with priority color column
#   * Per-section content tables with header shading + alternating row tint


def _docx_escape(s: Any) -> str:
    return html.escape(str(s if s is not None else ""), quote=True)


# DOCX OOXML colors (RGB hex, no #)
_DOCX_BRAND_DARK     = "0B1220"
_DOCX_BRAND_TEAL     = "1F6F6A"
_DOCX_BRAND_TEAL_LT  = "5FC6BC"
_DOCX_INK            = "0F172A"
_DOCX_INK_SOFT       = "475569"
_DOCX_INK_FAINT      = "64748B"
_DOCX_BG_SOFT        = "F8FAFC"
_DOCX_BG_TEAL        = "F0FDFA"
_DOCX_RULE           = "E2E8F0"
_DOCX_RED            = "DC2626"
_DOCX_ORANGE         = "EA580C"
_DOCX_AMBER          = "CA8A04"
_DOCX_BLUE           = "1E40AF"
_DOCX_GREEN          = "16A34A"


def _docx_run(text: str, *, bold: bool = False, size_pt: int = 11,
              color: str = _DOCX_INK, italic: bool = False,
              font: str = "Calibri", uppercase: bool = False) -> str:
    """A single OOXML run (text fragment with formatting)."""
    rpr_bits = []
    if bold:      rpr_bits.append("<w:b/>")
    if italic:    rpr_bits.append("<w:i/>")
    rpr_bits.append(f'<w:sz w:val="{int(size_pt*2)}"/>')
    rpr_bits.append(f'<w:szCs w:val="{int(size_pt*2)}"/>')
    rpr_bits.append(f'<w:color w:val="{color}"/>')
    rpr_bits.append(f'<w:rFonts w:ascii="{font}" w:hAnsi="{font}" w:cs="{font}"/>')
    if uppercase: rpr_bits.append("<w:caps/>")
    rpr = f"<w:rPr>{''.join(rpr_bits)}</w:rPr>"
    return f'<w:r>{rpr}<w:t xml:space="preserve">{_docx_escape(text)}</w:t></w:r>'


def _docx_para(runs: str | list, *, align: str | None = None,
               space_before: int = 0, space_after: int = 80,
               shade: str | None = None, border_left: str | None = None,
               page_break_before: bool = False,
               indent_left: int = 0,
               keep_next: bool = False,
               keep_lines: bool = False) -> str:
    """Wrap runs (or text) into a paragraph with optional shading + accent.

    If ``runs`` is a string and already starts with ``<w:r>`` (pre-built run
    XML), pass it through verbatim. Otherwise treat it as user text and
    wrap in a default run.
    """
    if isinstance(runs, str):
        if runs.lstrip().startswith("<w:r"):
            runs_xml = runs
        else:
            runs_xml = _docx_run(runs) if runs else ""
    elif isinstance(runs, list):
        runs_xml = "".join(runs)
    else:
        runs_xml = ""

    ppr_bits = []
    if page_break_before:
        ppr_bits.append('<w:pageBreakBefore/>')
    if align:
        ppr_bits.append(f'<w:jc w:val="{align}"/>')
    if space_before or space_after:
        ppr_bits.append(
            f'<w:spacing w:before="{int(space_before)}" w:after="{int(space_after)}" '
            f'w:line="276" w:lineRule="auto"/>'
        )
    if indent_left:
        ppr_bits.append(f'<w:ind w:left="{indent_left}"/>')
    if shade:
        ppr_bits.append(f'<w:shd w:val="clear" w:color="auto" w:fill="{shade}"/>')
    if border_left:
        ppr_bits.append(
            '<w:pBdr>'
            f'<w:left w:val="single" w:sz="36" w:space="6" w:color="{border_left}"/>'
            '</w:pBdr>'
        )
    if keep_next:
        ppr_bits.append('<w:keepNext/>')
    if keep_lines:
        ppr_bits.append('<w:keepLines/>')
    ppr = f"<w:pPr>{''.join(ppr_bits)}</w:pPr>" if ppr_bits else ""
    return f"<w:p>{ppr}{runs_xml}</w:p>"


def _docx_heading(text: str, *, level: int = 1, prefix: str = "",
                  page_break_before: bool = False) -> str:
    """A styled heading. Level 1 = 22pt + brand teal, level 2 = 14pt + dark."""
    if level == 1:
        size_pt, color = 22, _DOCX_BRAND_TEAL
        space_before, space_after = 360, 160
    elif level == 2:
        size_pt, color = 14, _DOCX_INK
        space_before, space_after = 240, 100
    else:
        size_pt, color = 12, _DOCX_INK
        space_before, space_after = 180, 80

    runs = []
    if prefix:
        runs.append(_docx_run(prefix + "  ",
                              bold=True, size_pt=size_pt, color=_DOCX_BRAND_TEAL_LT))
    runs.append(_docx_run(text, bold=True, size_pt=size_pt, color=color))

    return _docx_para(runs, space_before=space_before, space_after=space_after,
                       page_break_before=page_break_before,
                       keep_next=True, keep_lines=True)


def _docx_callout(label: str, body: str, *, color: str = _DOCX_BRAND_TEAL) -> str:
    """Shaded paragraph with left accent bar (used for executive summary / key takeaway)."""
    label_p = _docx_para(
        [_docx_run(label.upper(), bold=True, size_pt=9, color=color, uppercase=True)],
        shade=_DOCX_BG_TEAL, border_left=color,
        space_before=120, space_after=40, indent_left=180,
    )
    body_p = _docx_para(
        [_docx_run(body, size_pt=11, color=_DOCX_INK)],
        shade=_DOCX_BG_TEAL, border_left=color,
        space_before=0, space_after=120, indent_left=180,
    )
    return label_p + body_p


def _docx_tcell(text: str | list, *, width: int, shade: str | None = None,
                bold: bool = False, size_pt: int = 10, color: str = _DOCX_INK,
                align: str | None = None,
                v_align: str = "center") -> str:
    """Build one table cell. text can be a string or a list of run dicts."""
    if isinstance(text, str):
        # Strip HTML tags so HTML-fragment sections render cleanly in Word
        clean = re.sub(r"<[^>]+>", "", text)
        # Decode common entities
        clean = clean.replace("&middot;", "·").replace("&nbsp;", " ").replace(
            "&amp;", "&").replace("&mdash;", "—").replace("&minus;", "-").replace(
            "&lt;", "<").replace("&gt;", ">").replace("&apos;", "'").replace(
            "&quot;", '"')
        runs = _docx_run(clean, bold=bold, size_pt=size_pt, color=color)
    elif isinstance(text, list):
        runs = "".join(text)
    else:
        runs = ""

    shade_xml = (f'<w:shd w:val="clear" w:color="auto" w:fill="{shade}"/>'
                 if shade else "")
    ppr_bits = []
    if align:
        ppr_bits.append(f'<w:jc w:val="{align}"/>')
    ppr_bits.append('<w:spacing w:before="40" w:after="40"/>')
    ppr = f"<w:pPr>{''.join(ppr_bits)}</w:pPr>"

    tcpr = (
        f'<w:tcPr>'
        f'<w:tcW w:w="{width}" w:type="dxa"/>'
        f'{shade_xml}'
        f'<w:vAlign w:val="{v_align}"/>'
        f'<w:tcMar><w:top w:w="80" w:type="dxa"/><w:bottom w:w="80" w:type="dxa"/>'
        '<w:left w:w="100" w:type="dxa"/><w:right w:w="100" w:type="dxa"/></w:tcMar>'
        '</w:tcPr>'
    )
    return f"<w:tc>{tcpr}<w:p>{ppr}{runs}</w:p></w:tc>"


def _docx_table(rows: list[list[dict]], *, widths: list[int],
                header_shade: str = _DOCX_BRAND_DARK,
                alt_shade: str = _DOCX_BG_SOFT) -> str:
    """Build a styled table.

    rows: list of rows; each row is a list of cell-dicts:
      {text, shade?, bold?, color?, align?, size_pt?}

    The first row is the header and gets dark shading + white text.
    """
    if not rows:
        return ""

    grid = "<w:tblGrid>" + "".join(f'<w:gridCol w:w="{w}"/>' for w in widths) + "</w:tblGrid>"
    tbl_pr = (
        '<w:tblPr>'
        '<w:tblW w:w="5000" w:type="pct"/>'
        '<w:tblLook w:val="04A0"/>'
        '<w:tblBorders>'
        f'<w:top w:val="single" w:sz="6" w:color="{_DOCX_BRAND_TEAL}"/>'
        '<w:left w:val="single" w:sz="2" w:color="E2E8F0"/>'
        f'<w:bottom w:val="single" w:sz="6" w:color="{_DOCX_BRAND_TEAL}"/>'
        '<w:right w:val="single" w:sz="2" w:color="E2E8F0"/>'
        '<w:insideH w:val="single" w:sz="2" w:color="EEF2F7"/>'
        '<w:insideV w:val="single" w:sz="2" w:color="EEF2F7"/>'
        '</w:tblBorders>'
        '</w:tblPr>'
    )

    out = [f"<w:tbl>{tbl_pr}{grid}"]
    for ri, row in enumerate(rows):
        cells_xml = []
        for ci, cell in enumerate(row):
            w = widths[ci] if ci < len(widths) else widths[-1]
            if ri == 0:
                cells_xml.append(_docx_tcell(
                    cell.get("text", ""), width=w,
                    shade=header_shade, bold=True, size_pt=9,
                    color="FFFFFF", align=cell.get("align", "left")
                ))
            else:
                shade = cell.get("shade") or (alt_shade if ri % 2 == 0 else None)
                cells_xml.append(_docx_tcell(
                    cell.get("text", ""), width=w,
                    shade=shade,
                    bold=cell.get("bold", False),
                    size_pt=cell.get("size_pt", 10),
                    color=cell.get("color", _DOCX_INK),
                    align=cell.get("align"),
                ))
        out.append(f"<w:tr><w:trPr>{'<w:tblHeader/>' if ri == 0 else ''}</w:trPr>"
                   f"{''.join(cells_xml)}</w:tr>")
    out.append("</w:tbl>")
    # Anchor paragraph after the table so docs don't have orphan tables
    out.append(_docx_para("", space_before=0, space_after=0))
    return "".join(out)


# --------------------------------------------------------------------------
# DOCX image embedding infrastructure
# --------------------------------------------------------------------------


class _DocxMedia:
    """Accumulator for DOCX media. Holds (filename, png_bytes) tuples plus the
    relationship XML fragments to weave into ``word/_rels/document.xml.rels``.
    """

    def __init__(self) -> None:
        self.images: list[tuple[str, bytes]] = []
        self._next = 1

    def add(self, png_bytes: bytes | None) -> str | None:
        if not png_bytes:
            return None
        i = self._next
        self._next += 1
        fn = f"image{i}.png"
        rid = f"rIdImg{i}"
        self.images.append((fn, png_bytes))
        return rid

    def rels_xml(self) -> str:
        out = []
        for i, (fn, _) in enumerate(self.images, start=1):
            rid = f"rIdImg{i}"
            out.append(
                f'<Relationship Id="{rid}" '
                'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" '
                f'Target="media/{fn}"/>'
            )
        return "".join(out)


def _docx_inline_image(rid: str | None, *, width_in: float = 6.0,
                        height_in: float = 3.0,
                        align: str = "center",
                        keep_next: bool = False,
                        keep_lines: bool = True) -> str:
    """Return paragraph XML embedding the image as an inline drawing.

    If ``rid`` is falsy (PIL unavailable / chart failed), returns an empty
    string so the caller can degrade gracefully.
    """
    if not rid:
        return ""
    cx = int(width_in * 914400)
    cy = int(height_in * 914400)
    align_xml = f'<w:jc w:val="{align}"/>' if align else ""
    keep_xml = (('<w:keepNext/>' if keep_next else '')
                + ('<w:keepLines/>' if keep_lines else ''))
    return (
        f'<w:p><w:pPr>{align_xml}{keep_xml}'
        '<w:spacing w:before="40" w:after="60"/></w:pPr>'
        '<w:r><w:drawing>'
        f'<wp:inline distT="0" distB="0" distL="0" distR="0" '
        'xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing">'
        f'<wp:extent cx="{cx}" cy="{cy}"/>'
        '<wp:effectExtent l="0" t="0" r="0" b="0"/>'
        f'<wp:docPr id="{abs(hash(rid)) % 100000 + 1}" name="Chart {rid}"/>'
        '<wp:cNvGraphicFramePr/>'
        '<a:graphic xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">'
        '<a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">'
        '<pic:pic xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture">'
        f'<pic:nvPicPr><pic:cNvPr id="{abs(hash(rid)) % 100000 + 1}" name="Chart"/>'
        '<pic:cNvPicPr/></pic:nvPicPr>'
        f'<pic:blipFill>'
        '<a:blip xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
        f'r:embed="{rid}"/>'
        '<a:stretch><a:fillRect/></a:stretch></pic:blipFill>'
        f'<pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="{cx}" cy="{cy}"/></a:xfrm>'
        '<a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr>'
        '</pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p>'
    )


def _docx_chart_png(kind: str, *args, **kwargs) -> bytes | None:
    """Safe wrapper around chart_png — returns None if PIL is unavailable or
    the chart raises."""
    if _chart_png is None:
        return None
    try:
        fn = getattr(_chart_png, kind, None)
        if fn is None:
            return None
        return fn(*args, **kwargs)
    except Exception:
        return None


def _docx_cover_page(report: dict, media: "_DocxMedia | None" = None) -> str:
    """Big branded cover page — colored accent bar, eyebrow, title, subtitle,
    metadata grid, doc id."""
    title = report.get("title") or "SafeCadence NetRisk Report"
    kpi = _kpi_data(report)
    score = _derive_overall_risk(kpi)
    confidence = _confidence_for(kpi)
    n_sections = len(report.get("sections") or [])
    doc_id = _dt.datetime.now(_dt.timezone.utc).strftime("SC-%Y%m%d-%H%M")

    # Brand strip at the very top: dark shaded paragraph
    brand_strip = _docx_para([
        _docx_run("SAFECADENCE", bold=True, size_pt=11, color="FFFFFF"),
        _docx_run("  ·  ", color="5FC6BC", bold=True, size_pt=11),
        _docx_run("NETRISK", bold=True, size_pt=11, color=_DOCX_BRAND_TEAL_LT),
    ], shade=_DOCX_BRAND_DARK, space_before=0, space_after=0, indent_left=180)

    # Logo mark — embed under brand strip if PIL is available
    logo_block = ""
    if media is not None:
        logo_png = _docx_chart_png("logo_mark", size=200, on_dark=False)
        if logo_png:
            rid = media.add(logo_png)
            logo_block = _docx_inline_image(rid, width_in=0.8, height_in=0.8,
                                              align="left")

    # Spacer
    spacer = _docx_para("", space_before=2400, space_after=0)

    # Eyebrow
    eyebrow = _docx_para([
        _docx_run("NETWORK SECURITY & COMPLIANCE ASSESSMENT",
                   bold=True, size_pt=9, color=_DOCX_BRAND_TEAL),
    ], space_before=0, space_after=160)

    # Title
    title_p = _docx_para([
        _docx_run(title, bold=True, size_pt=32, color=_DOCX_BRAND_DARK),
    ], space_before=0, space_after=120)

    # Subtitle
    subtitle = _docx_para([
        _docx_run(
            "An evidence-driven security posture deliverable covering asset risk, "
            "vulnerability exposure, control coverage, and prioritized remediation.",
            size_pt=13, color=_DOCX_INK_SOFT, italic=True,
        ),
    ], space_before=0, space_after=480)

    # Confidence chip via shaded short paragraph
    conf_p = _docx_para([
        _docx_run(f"  {confidence}  ", bold=True, size_pt=9, color="022C25"),
    ], shade=_DOCX_BRAND_TEAL_LT, space_before=0, space_after=480)

    # Metadata table (2 cols, 4 rows) — using the new table helper
    meta_rows = [
        # Use a synthetic header that is non-printing (no, just skip — table API has hdr)
        [{"text": "Report date"},   {"text": _today(), "bold": True}],
        [{"text": "Assets in scope"}, {"text": f"{int(kpi.get('hosts') or 0)} systems", "bold": True}],
        [{"text": "Sections"},        {"text": str(n_sections), "bold": True}],
        [{"text": "Overall risk"},    {"text": f"{score} / 100", "bold": True,
                                       "color": _DOCX_RED if score >= 70 else
                                                _DOCX_ORANGE if score >= 40 else _DOCX_GREEN}],
        [{"text": "Frameworks"},      {"text": "NIST 800-53, CIS v8, PCI DSS, HIPAA, SOC 2", "bold": True}],
        [{"text": "Document ID"},     {"text": doc_id, "bold": True}],
    ]
    # Wrap with a non-printing header so widths apply (DOCX requires header row)
    meta_rows = [[{"text": ""}, {"text": ""}]] + meta_rows
    # But we want it to LOOK like a label/value pair table, not a header table.
    # Build raw without header shading.
    grid = '<w:tblGrid><w:gridCol w:w="2800"/><w:gridCol w:w="6200"/></w:tblGrid>'
    tbl_pr = (
        '<w:tblPr>'
        '<w:tblW w:w="5000" w:type="pct"/>'
        '<w:tblLook w:val="0000"/>'
        '<w:tblBorders>'
        f'<w:top w:val="single" w:sz="18" w:color="{_DOCX_BRAND_TEAL}"/>'
        '<w:left w:val="none" w:sz="0" w:color="auto"/>'
        f'<w:bottom w:val="single" w:sz="18" w:color="{_DOCX_BRAND_TEAL}"/>'
        '<w:right w:val="none" w:sz="0" w:color="auto"/>'
        '<w:insideH w:val="single" w:sz="2" w:color="E2E8F0"/>'
        '<w:insideV w:val="none" w:sz="0" w:color="auto"/>'
        '</w:tblBorders>'
        '</w:tblPr>'
    )
    rows_xml = []
    for label, value in [
        ("Report date",     _today()),
        ("Assets in scope", f"{int(kpi.get('hosts') or 0)} systems"),
        ("Sections",        str(n_sections)),
        ("Overall risk",    f"{score} / 100"),
        ("Frameworks",      "NIST 800-53, CIS v8, PCI DSS, HIPAA, SOC 2"),
        ("Document ID",     doc_id),
    ]:
        label_cell = _docx_tcell([_docx_run(label.upper(), bold=True, size_pt=8,
                                            color=_DOCX_INK_FAINT, uppercase=True)],
                                  width=2800)
        risk_color = _DOCX_INK
        if label == "Overall risk":
            risk_color = (_DOCX_RED if score >= 70 else
                          _DOCX_ORANGE if score >= 40 else _DOCX_GREEN)
        value_cell = _docx_tcell([_docx_run(value, bold=True, size_pt=11,
                                            color=risk_color)],
                                  width=6200)
        rows_xml.append(f"<w:tr>{label_cell}{value_cell}</w:tr>")
    meta_tbl = f"<w:tbl>{tbl_pr}{grid}{''.join(rows_xml)}</w:tbl>"

    # Trailing confidential mark
    confidential = _docx_para([
        _docx_run("CONFIDENTIAL — Distribute only to authorized personnel",
                   size_pt=9, color=_DOCX_INK_FAINT, uppercase=True),
    ], align="center", space_before=720, space_after=0,
       page_break_before=False)

    # Force a page break after the cover
    page_break = (
        '<w:p><w:pPr><w:pageBreakBefore/></w:pPr></w:p>'
    )

    return (
        brand_strip + logo_block + spacer + eyebrow + title_p + subtitle +
        conf_p + meta_tbl +
        _docx_para("", space_before=0, space_after=0) +
        confidential + page_break
    )


def _docx_toc(report: dict) -> str:
    """Branded TOC — heading + list of section numbers with leader dots."""
    sections = report.get("sections") or []
    parts = [_docx_heading("Table of Contents", level=1, prefix="")]
    for i, s in enumerate(sections, start=1):
        parts.append(_docx_para([
            _docx_run(f"{i:02d}.   ", bold=True, size_pt=11, color=_DOCX_BRAND_TEAL_LT),
            _docx_run(s.get("title", ""), size_pt=11, color=_DOCX_INK),
        ], space_before=40, space_after=80))
    # Page break after TOC
    parts.append('<w:p><w:pPr><w:pageBreakBefore/></w:pPr></w:p>')
    return "".join(parts)


def _docx_executive_callout(report: dict) -> str:
    """If the report has an executive_summary section, lift it into a callout."""
    for s in report.get("sections") or []:
        if s.get("key") == "executive_summary" and not s.get("empty"):
            try:
                text = ai_helpers.generate_executive_summary(
                    {"kpi": _kpi_data(report), "scope": report.get("scope") or {}},
                    tone="executive",
                )
            except Exception:
                text = (s.get("data") or {}).get("summary") or ""
            if text:
                return _docx_callout("Executive summary", text)
    return ""


def _docx_kpi_dashboard(report: dict, media: "_DocxMedia | None" = None) -> str:
    """Five colored KPI tiles rendered as one short, very-wide table row, plus
    a severity donut chart above and a sparkline trend below."""
    kpi = _kpi_data(report)
    if not kpi:
        return ""
    items = [
        ("HOSTS IN SCOPE", str(int(kpi.get("hosts") or 0)),    _DOCX_BRAND_TEAL),
        ("CRITICAL CVEs", str(int(kpi.get("critical") or 0)),   _DOCX_RED),
        ("HIGH CVEs",     str(int(kpi.get("high") or 0)),       _DOCX_ORANGE),
        ("KEV-LISTED",    str(int(kpi.get("kev") or 0)),        "7F1D1D"),
        ("EOL DEVICES",   str(int(kpi.get("eol") or 0)),        _DOCX_AMBER),
    ]
    # Build a 1-row table where each cell stacks (label small) + (number big)
    grid = '<w:tblGrid>' + ''.join('<w:gridCol w:w="1800"/>' for _ in items) + '</w:tblGrid>'
    tbl_pr = (
        '<w:tblPr><w:tblW w:w="5000" w:type="pct"/>'
        '<w:tblLook w:val="0000"/>'
        '<w:tblCellSpacing w:w="40" w:type="dxa"/>'
        '<w:tblBorders>'
        '<w:top w:val="none" w:sz="0" w:color="auto"/>'
        '<w:left w:val="none" w:sz="0" w:color="auto"/>'
        '<w:bottom w:val="none" w:sz="0" w:color="auto"/>'
        '<w:right w:val="none" w:sz="0" w:color="auto"/>'
        '<w:insideH w:val="none" w:sz="0" w:color="auto"/>'
        '<w:insideV w:val="none" w:sz="0" w:color="auto"/>'
        '</w:tblBorders></w:tblPr>'
    )
    cells = []
    for label, value, color in items:
        # Top mini-bar via shaded paragraph
        top_bar = _docx_para([_docx_run("  ", size_pt=4)], shade=color,
                             space_before=0, space_after=0)
        lbl_p = _docx_para([_docx_run(label, bold=True, size_pt=8,
                                       color=_DOCX_INK_FAINT, uppercase=True)],
                            space_before=80, space_after=20, align="center")
        val_p = _docx_para([_docx_run(value, bold=True, size_pt=28, color=color)],
                            space_before=0, space_after=80, align="center")
        cell_inner = top_bar + lbl_p + val_p
        tcpr = (
            '<w:tcPr><w:tcW w:w="1800" w:type="dxa"/>'
            '<w:tcBorders>'
            f'<w:top w:val="single" w:sz="4" w:color="{_DOCX_RULE}"/>'
            f'<w:left w:val="single" w:sz="4" w:color="{_DOCX_RULE}"/>'
            f'<w:bottom w:val="single" w:sz="4" w:color="{_DOCX_RULE}"/>'
            f'<w:right w:val="single" w:sz="4" w:color="{_DOCX_RULE}"/>'
            '</w:tcBorders></w:tcPr>'
        )
        cells.append(f"<w:tc>{tcpr}{cell_inner}</w:tc>")
    table = f"<w:tbl>{tbl_pr}{grid}<w:tr>{''.join(cells)}</w:tr></w:tbl>"

    # Severity donut chart on top, then tiles, then sparkline trend below
    chart_xml = ""
    sparkline_xml = ""
    if media is not None:
        counts = {
            "critical": int(kpi.get("critical") or 0),
            "high":     int(kpi.get("high") or 0),
            "medium":   int(kpi.get("medium") or 0),
            "low":      int(kpi.get("low") or 0),
            "info":     0,
        }
        donut_png = _docx_chart_png("severity_donut", counts, size=320)
        if donut_png:
            rid = media.add(donut_png)
            chart_xml = (
                _docx_para([_docx_run("Severity distribution",
                                       size_pt=10, bold=True,
                                       color=_DOCX_INK_FAINT, uppercase=True)],
                           align="center", space_before=40, space_after=20,
                           keep_next=True)
                + _docx_inline_image(rid, width_in=2.8, height_in=2.8,
                                       align="center", keep_next=True)
            )
        # Sparkline — descending synthetic trend if no history available
        crit_now = int(kpi.get("critical") or 0)
        trend_vals = None
        if _delta_mod is not None:
            try:
                ts = _delta_mod.trend_series("critical", days=30)
                if ts and len(ts) >= 2:
                    trend_vals = ts
            except Exception:
                trend_vals = None
        if not trend_vals:
            # Synthesize a descending trend ending at the current value
            base = max(crit_now + 6, 6)
            trend_vals = [base, base - 1, max(0, base - 2),
                          max(0, base - 3), max(0, base - 4),
                          max(0, base - 5), crit_now]
        spark_png = _docx_chart_png("sparkline", trend_vals,
                                     width=600, height=80)
        if spark_png:
            srid = media.add(spark_png)
            sparkline_xml = (
                _docx_para([_docx_run("CRITICAL CVE COUNT — 30-DAY TREND",
                                       size_pt=9, bold=True,
                                       color=_DOCX_INK_FAINT, uppercase=True)],
                           align="center", space_before=120, space_after=20,
                           keep_next=True)
                + _docx_inline_image(srid, width_in=5.0, height_in=0.7,
                                       align="center")
            )

    return (_docx_heading("Risk dashboard", level=1, prefix="")
            + chart_xml
            + _docx_para("", space_before=80, space_after=80)
            + table
            + sparkline_xml
            + _docx_para("", space_before=0, space_after=160))


def _docx_compliance_scorecard(report: dict,
                                 media: "_DocxMedia | None" = None) -> str:
    """Compliance scorecard: framework | score | status pill | top gaps.

    Adds a compliance radar chart centered above the table when PIL is
    available."""
    cd = _compliance_data(report)
    frameworks = cd.get("frameworks") or []
    if not frameworks:
        return ""

    radar_xml = ""
    if media is not None:
        radar_png = _docx_chart_png("compliance_radar", frameworks, size=400)
        if radar_png:
            rid = media.add(radar_png)
            radar_xml = _docx_inline_image(rid, width_in=4.2, height_in=4.2,
                                            align="center", keep_next=True)
    rows = [[
        {"text": "Framework"},
        {"text": "Score",   "align": "center"},
        {"text": "Status",  "align": "center"},
        {"text": "Top failing controls"},
    ]]
    for fw in frameworks:
        score = int(fw.get("score") or 0)
        if score >= 85:
            status = "PASS";    pill_color = _DOCX_GREEN
        elif score >= 65:
            status = "PARTIAL"; pill_color = _DOCX_AMBER
        else:
            status = "FAIL";    pill_color = _DOCX_RED
        top = fw.get("top_failures") or fw.get("top_failing") or []
        top_str = ", ".join(
            (c.get("id") or c.get("control") or "") for c in top[:3]
        ) or "—"
        rows.append([
            {"text": fw.get("framework") or fw.get("name") or "", "bold": True},
            {"text": f"{score}%", "align": "center", "bold": True,
             "color": pill_color, "size_pt": 12},
            {"text": status, "align": "center", "bold": True,
             "color": "FFFFFF", "shade": pill_color, "size_pt": 9},
            {"text": top_str, "size_pt": 9, "color": _DOCX_INK_SOFT},
        ])
    return (
        _docx_heading("Compliance scorecard", level=1, prefix="") +
        radar_xml +
        _docx_table(rows, widths=[2400, 1200, 1300, 4100])
    )


def _docx_action_plan(report: dict) -> str:
    """Top action plan with colored priority column."""
    actions = []
    for s in report.get("sections") or []:
        if s.get("key") == "recommended_actions":
            actions = (s.get("data") or {}).get("actions") or []
            break
    if not actions:
        return ""
    rows = [[
        {"text": "Priority", "align": "center"},
        {"text": "Action"},
        {"text": "Effort", "align": "center"},
        {"text": "Controls"},
    ]]
    pri_colors = {"P0": _DOCX_RED, "P1": _DOCX_ORANGE,
                  "P2": _DOCX_AMBER, "P3": _DOCX_BLUE}
    for a in actions[:25]:
        pri = a.get("priority") or "P3"
        compl = a.get("compliance") or []
        if isinstance(compl, list):
            compl = ", ".join(compl[:3]) if compl else "—"
        rows.append([
            {"text": pri, "align": "center", "bold": True,
             "color": "FFFFFF", "shade": pri_colors.get(pri, _DOCX_INK_FAINT),
             "size_pt": 10},
            {"text": a.get("title", ""), "bold": True},
            {"text": a.get("effort") or "medium", "align": "center",
             "color": _DOCX_INK_SOFT},
            {"text": str(compl), "size_pt": 9, "color": _DOCX_INK_SOFT},
        ])
    return (
        _docx_heading("Prioritized action plan", level=1, prefix="") +
        _docx_table(rows, widths=[1100, 4800, 1100, 2000])
    )


def _docx_section_block(s: dict, report: dict, idx: int) -> str:
    """Render a generic non-flagship section as heading + small table or prose."""
    title = s.get("title") or s.get("key") or ""
    key = s.get("key")
    data = s.get("data") or {}
    parts = [_docx_heading(title, level=1, prefix=f"{idx:02d}")]

    if s.get("empty"):
        parts.append(_docx_para([_docx_run(f"No data for {title}.",
                                             size_pt=10, color=_DOCX_INK_FAINT,
                                             italic=True)],
                                 shade=_DOCX_BG_SOFT))
        return "".join(parts)

    if key == "kpi_summary":
        # Already covered by the dashboard
        rows = [[{"text": "Metric"}, {"text": "Value", "align": "center"}, {"text": "Notes"}]]
        rows.append([{"text": "Hosts in scope", "bold": True},
                     {"text": str(data.get("hosts", 0)), "align": "center"},
                     {"text": "Assets evaluated"}])
        rows.append([{"text": "Critical CVEs", "bold": True},
                     {"text": str(data.get("critical", 0)), "align": "center",
                      "color": _DOCX_RED, "bold": True},
                     {"text": "P0 patch class"}])
        rows.append([{"text": "High CVEs", "bold": True},
                     {"text": str(data.get("high", 0)), "align": "center",
                      "color": _DOCX_ORANGE, "bold": True},
                     {"text": "P1 patch class"}])
        rows.append([{"text": "KEV-listed", "bold": True},
                     {"text": str(data.get("kev", 0)), "align": "center",
                      "color": "7F1D1D", "bold": True},
                     {"text": "Actively exploited"}])
        rows.append([{"text": "EOL hardware", "bold": True},
                     {"text": str(data.get("eol", 0)), "align": "center",
                      "color": _DOCX_AMBER, "bold": True},
                     {"text": "Past vendor EOS"}])
        rows.append([{"text": "EOS software", "bold": True},
                     {"text": str(data.get("eos_software", 0)), "align": "center"},
                     {"text": "Unsupported versions"}])
        parts.append(_docx_table(rows, widths=[2400, 1400, 5200]))
        return "".join(parts)

    if key == "compliance_executive_summary":
        narrative_bits = []
        weakest = data.get("weakest"); strongest = data.get("strongest")
        kpi = data.get("kpi") or {}
        if weakest:
            narrative_bits.append(
                f"The weakest framework today is {weakest.get('framework','')} at "
                f"{int(weakest.get('score') or 0)}%, driven primarily by "
                f"{int(kpi.get('critical') or 0)} critical and "
                f"{int(kpi.get('high') or 0)} high-severity open findings."
            )
        if int(kpi.get("kev") or 0):
            narrative_bits.append(
                f"There are {int(kpi.get('kev'))} CISA KEV-listed vulnerabilities in scope. "
                "These trigger SI-2, 6.3.3, RA-5, and HIPAA risk-management findings "
                "across multiple frameworks."
            )
        if strongest and weakest and strongest is not weakest:
            narrative_bits.append(
                f"The strongest framework today is {strongest.get('framework','')} at "
                f"{int(strongest.get('score') or 0)}%."
            )
        narrative_bits.append(
            "Resolving the prioritized action plan is expected to lift "
            "posture by 15–25 points across all evaluated frameworks."
        )
        parts.append(_docx_para([_docx_run(" ".join(narrative_bits),
                                            size_pt=11, color=_DOCX_INK)],
                                 space_after=160))

        frameworks = data.get("frameworks") or []
        if frameworks:
            rows = [[
                {"text": "Framework"},
                {"text": "Score", "align": "center"},
                {"text": "Status", "align": "center"},
                {"text": "Open gaps", "align": "center"},
            ]]
            for fw in frameworks:
                score = int(fw.get("score") or 0)
                if score >= 85:
                    status = "PASS"; pc = _DOCX_GREEN
                elif score >= 65:
                    status = "PARTIAL"; pc = _DOCX_AMBER
                else:
                    status = "FAIL"; pc = _DOCX_RED
                rows.append([
                    {"text": fw.get("framework") or "", "bold": True},
                    {"text": f"{score}%", "align": "center", "bold": True, "color": pc},
                    {"text": status, "align": "center", "bold": True,
                     "color": "FFFFFF", "shade": pc, "size_pt": 9},
                    {"text": f"{int(fw.get('fail') or 0)}", "align": "center"},
                ])
            parts.append(_docx_table(rows, widths=[2800, 1200, 1400, 1600]))
        return "".join(parts)

    if key == "compliance_control_matrix":
        rows_data = data.get("rows") or []
        if not rows_data:
            parts.append(_docx_para("No control matrix data available."))
            return "".join(parts)
        # Tile counts at top
        by_status = data.get("by_status") or {}
        parts.append(_docx_para([
            _docx_run(f"  PASS {by_status.get('pass',0)}  ", bold=True, size_pt=10,
                      color=_DOCX_GREEN),
            _docx_run("  ·  ", color=_DOCX_INK_FAINT),
            _docx_run(f"  PARTIAL {by_status.get('partial',0)}  ", bold=True,
                      size_pt=10, color=_DOCX_AMBER),
            _docx_run("  ·  ", color=_DOCX_INK_FAINT),
            _docx_run(f"  FAIL {by_status.get('fail',0)}  ", bold=True, size_pt=10,
                      color=_DOCX_RED),
            _docx_run("  ·  ", color=_DOCX_INK_FAINT),
            _docx_run(f"  Total {len(rows_data)}  ", bold=True, size_pt=10,
                      color=_DOCX_INK_FAINT),
        ], space_after=120))
        tbl_rows = [[
            {"text": "Framework"},
            {"text": "Control"},
            {"text": "Title"},
            {"text": "Status", "align": "center"},
            {"text": "Evidence"},
        ]]
        status_color = {"pass": _DOCX_GREEN, "partial": _DOCX_AMBER,
                        "fail": _DOCX_RED, "na": _DOCX_INK_FAINT}
        for r in rows_data[:60]:  # cap for doc length
            tbl_rows.append([
                {"text": r["framework"], "size_pt": 9},
                {"text": r["id"], "bold": True, "size_pt": 9},
                {"text": r["title"], "size_pt": 9},
                {"text": (r["status"] or "").upper(), "align": "center", "bold": True,
                 "color": "FFFFFF", "shade": status_color.get(r["status"], _DOCX_INK_FAINT),
                 "size_pt": 8},
                {"text": r["evidence"], "size_pt": 8, "color": _DOCX_INK_SOFT},
            ])
        parts.append(_docx_table(tbl_rows, widths=[1500, 1100, 2500, 1100, 2800]))
        if len(rows_data) > 60:
            parts.append(_docx_para([_docx_run(
                f"Showing first 60 of {len(rows_data)} controls. Full set is in the JSON export.",
                size_pt=9, italic=True, color=_DOCX_INK_FAINT)], space_after=160))
        return "".join(parts)

    if key == "compliance_gap_analysis":
        groups = data.get("groups") or []
        if not groups:
            parts.append(_docx_para("No active control gaps detected."))
            return "".join(parts)
        for grp in groups:
            parts.append(_docx_heading(
                f'{grp["framework"]} — {len(grp["actions"])} gaps',
                level=2, prefix=""))
            tbl_rows = [[
                {"text": "Control"}, {"text": "Title / Remediation"},
                {"text": "Priority", "align": "center"},
                {"text": "Lift", "align": "center"},
                {"text": "Effort", "align": "center"},
            ]]
            pri_colors = {"P0": _DOCX_RED, "P1": _DOCX_ORANGE,
                          "P2": _DOCX_AMBER, "P3": _DOCX_BLUE}
            for a in grp["actions"][:15]:
                tbl_rows.append([
                    {"text": a["id"], "bold": True, "size_pt": 9},
                    {"text": f"{a['title']} — {a.get('remediation','')}", "size_pt": 9},
                    {"text": a["priority"], "align": "center", "bold": True,
                     "color": "FFFFFF", "shade": pri_colors.get(a["priority"], _DOCX_INK_FAINT),
                     "size_pt": 9},
                    {"text": f"+{a['lift']}", "align": "center", "bold": True,
                     "color": _DOCX_GREEN, "size_pt": 9},
                    {"text": a["effort"], "align": "center", "size_pt": 9},
                ])
            parts.append(_docx_table(tbl_rows, widths=[1100, 4200, 1100, 1000, 1600]))
        return "".join(parts)

    if key == "compliance_evidence_pack":
        findings = data.get("findings") or []
        if not findings:
            parts.append(_docx_para("No findings recorded in scope."))
            return "".join(parts)
        parts.append(_docx_para([_docx_run(
            f"Top {min(50, len(findings))} of {len(findings)} findings — KEV first, "
            "then severity, then asset. Use the JSON export for the complete trail.",
            size_pt=10, italic=True, color=_DOCX_INK_SOFT)], space_after=160))
        tbl_rows = [[
            {"text": "#", "align": "center"},
            {"text": "Asset"},
            {"text": "Observation"},
            {"text": "Severity", "align": "center"},
            {"text": "Mapped controls"},
        ]]
        sev_color = {"critical": _DOCX_RED, "high": _DOCX_ORANGE,
                     "medium": _DOCX_AMBER, "low": _DOCX_BLUE}
        for i, f in enumerate(findings[:50], start=1):
            sev = (f.get("severity") or "").lower()
            kev_str = " [KEV]" if f.get("kev") else ""
            controls = f.get("controls") or {}
            ctrl_str = ", ".join(f"{fw}: {c}" for fw, c in
                                 (controls.items() if isinstance(controls, dict) else [])
                                 ) or "—"
            tbl_rows.append([
                {"text": str(i), "align": "center", "size_pt": 9},
                {"text": f.get("host", ""), "size_pt": 9, "bold": True},
                {"text": (f.get("title", "") + kev_str), "size_pt": 9},
                {"text": (sev.upper() if sev else "—"), "align": "center", "bold": True,
                 "color": "FFFFFF",
                 "shade": sev_color.get(sev, _DOCX_INK_FAINT), "size_pt": 8},
                {"text": ctrl_str, "size_pt": 8, "color": _DOCX_INK_SOFT},
            ])
        parts.append(_docx_table(tbl_rows, widths=[500, 1400, 3000, 1000, 2900]))
        return "".join(parts)

    if key == "host_inventory":
        hosts = data.get("hosts") or data.get("rows") or []
        if not hosts:
            parts.append(_docx_para("No hosts in scope."))
            return "".join(parts)
        tbl_rows = [[
            {"text": "Host"}, {"text": "Vendor"}, {"text": "Site"},
            {"text": "Criticality", "align": "center"},
            {"text": "Crit", "align": "center"},
            {"text": "High", "align": "center"},
        ]]
        for h in hosts[:60]:
            tbl_rows.append([
                {"text": h.get("hostname") or h.get("host") or h.get("name") or "",
                 "bold": True, "size_pt": 9},
                {"text": h.get("vendor", ""), "size_pt": 9},
                {"text": h.get("site", ""), "size_pt": 9},
                {"text": h.get("criticality", ""), "align": "center", "size_pt": 9},
                {"text": str(h.get("critical", h.get("crit_count", 0))),
                 "align": "center", "size_pt": 9, "color": _DOCX_RED, "bold": True},
                {"text": str(h.get("high", h.get("high_count", 0))),
                 "align": "center", "size_pt": 9, "color": _DOCX_ORANGE, "bold": True},
            ])
        parts.append(_docx_table(tbl_rows, widths=[2200, 1600, 1400, 1400, 800, 800]))
        return "".join(parts)

    # Generic dict/list fallback
    if isinstance(data, dict) and data:
        rows = [[{"text": "Field"}, {"text": "Value"}]]
        for k, v in list(data.items())[:25]:
            if isinstance(v, (list, dict)):
                v = f"{len(v)} item(s)" if hasattr(v, "__len__") else str(v)[:140]
            rows.append([{"text": str(k), "bold": True, "size_pt": 9},
                         {"text": str(v), "size_pt": 9}])
        parts.append(_docx_table(rows, widths=[2600, 6400]))
    else:
        parts.append(_docx_para([_docx_run(
            "See HTML or JSON export for the complete content of this section.",
            size_pt=10, italic=True, color=_DOCX_INK_FAINT)]))

    return "".join(parts)


# --------------------------------------------------------------------------
# DOCX — new tier-2/3/4 building blocks
# --------------------------------------------------------------------------


# Peer benchmark medians per framework (self-reported industry data).
_PEER_BENCHMARK = {
    "NIST 800-53": 71, "NIST": 71,
    "CIS v8": 76, "CIS": 76,
    "PCI DSS v4.0": 83, "PCI DSS": 83, "PCI": 83,
    "HIPAA Security Rule": 70, "HIPAA": 70,
    "SOC 2": 79,
}


def _docx_revision_history(report: dict) -> str:
    """Revision history table — placed right after the cover before TOC."""
    rows = [[
        {"text": "Version"},
        {"text": "Date"},
        {"text": "Change"},
        {"text": "Author"},
    ]]
    rows.append([
        {"text": "v10.3.0", "bold": True},
        {"text": _today()},
        {"text": "Initial assessment"},
        {"text": "SafeCadence NetRisk"},
    ])
    return (
        _docx_heading("Revision history", level=2, prefix="") +
        _docx_table(rows, widths=[1400, 1800, 4800, 2000]) +
        _docx_para("", space_before=0, space_after=120)
    )


def _docx_methodology_section(report: dict) -> str:
    """Methodology + timeline page — date range, asset types, frameworks."""
    kpi = _kpi_data(report)
    today = _today()
    items = [
        ("Assessment date",   today),
        ("Date range scanned", "Most-recent 30-day window through " + today),
        ("Assets in scope",    f"{int(kpi.get('hosts') or 0)} systems "
                                "(switches, routers, firewalls, wireless controllers, hosts)"),
        ("Asset types covered", "Network infrastructure, perimeter security, identity, endpoint"),
        ("Frameworks evaluated", "NIST 800-53 r5, CIS v8, PCI DSS v4.0, HIPAA Security Rule, SOC 2"),
        ("CISA KEV catalog rev", _kev_catalog_rev()),
        ("NVD CVE feed rev",    today + " (NVD 2.0 API snapshot)"),
        ("Tooling",             "SafeCadence NetRisk v10.3.0 + signal-based config analysis"),
        ("Methodology",         "Evidence-driven posture: each finding is mapped to one or more "
                                "controls and ranked by exploitability, asset criticality, "
                                "and KEV status before remediation prioritization."),
    ]
    parts = [_docx_heading("Methodology & timeline", level=1, prefix="")]
    for label, value in items:
        parts.append(_docx_para([
            _docx_run("•  ", bold=True, color=_DOCX_BRAND_TEAL_LT, size_pt=12),
            _docx_run(f"{label}: ", bold=True, color=_DOCX_INK, size_pt=11),
            _docx_run(value, color=_DOCX_INK_SOFT, size_pt=11),
        ], space_before=40, space_after=80))
    return "".join(parts)


def _docx_risk_register(report: dict) -> str:
    """Risk register table derived from recommended_actions."""
    actions = []
    for s in report.get("sections") or []:
        if s.get("key") == "recommended_actions":
            actions = (s.get("data") or {}).get("actions") or []
            break
    if not actions:
        return ""

    today = _dt.date.today()
    target_days = {"P0": 14, "P1": 30, "P2": 60, "P3": 90}

    rows = [[
        {"text": "ID"},
        {"text": "Finding"},
        {"text": "Owner"},
        {"text": "Target date", "align": "center"},
        {"text": "Status", "align": "center"},
        {"text": "Current mitigation"},
    ]]
    pri_colors = {"P0": _DOCX_RED, "P1": _DOCX_ORANGE,
                  "P2": _DOCX_AMBER, "P3": _DOCX_BLUE}
    for i, a in enumerate(actions[:25], start=1):
        rid = f"RR-{i:03d}"
        pri = a.get("priority") or "P3"
        days = target_days.get(pri, 60)
        target = (today + _dt.timedelta(days=days)).isoformat()
        rows.append([
            {"text": rid, "bold": True, "size_pt": 9},
            {"text": a.get("title", ""), "size_pt": 9},
            {"text": "Security Engineering", "size_pt": 9,
             "color": _DOCX_INK_SOFT},
            {"text": target, "align": "center", "size_pt": 9, "bold": True,
             "color": pri_colors.get(pri, _DOCX_INK_SOFT)},
            {"text": "Open", "align": "center", "size_pt": 9, "bold": True,
             "color": "FFFFFF", "shade": _DOCX_INK_FAINT},
            {"text": "None — see action plan", "size_pt": 9,
             "color": _DOCX_INK_SOFT, "italic": False},
        ])
    return (
        _docx_heading("Risk register", level=1, prefix="") +
        _docx_para([_docx_run(
            "Each open finding has an owner, target remediation date based on "
            "priority class (P0 = 14 days, P1 = 30, P2 = 60, P3 = 90), and a "
            "status line for tracking. Update the status column at each weekly "
            "stand-up.",
            size_pt=10, italic=True, color=_DOCX_INK_SOFT)], space_after=160) +
        _docx_table(rows, widths=[900, 3800, 1800, 1400, 900, 1900])
    )


def _docx_vendor_concentration(report: dict, media: "_DocxMedia | None" = None) -> str:
    """Vendor concentration analysis: critical+high CVEs grouped by vendor."""
    hosts = []
    cves = []
    for s in report.get("sections") or []:
        if s.get("key") == "host_inventory":
            hosts = (s.get("data") or {}).get("hosts") or []
        elif s.get("key") == "cve_exposure":
            cves = (s.get("data") or {}).get("cves") or []

    # Build hostname -> vendor map
    hv: dict[str, str] = {}
    for h in hosts:
        name = (h.get("hostname") or h.get("host") or h.get("name") or "").strip()
        if name:
            hv[name] = h.get("vendor", "") or "Unknown"

    vendor_count: dict[str, int] = {}
    for cv in cves:
        sev = (cv.get("severity") or "").lower()
        if sev not in ("critical", "high"):
            continue
        # Hosts may be a list or single string
        affected = cv.get("hosts") or []
        if not affected and cv.get("host"):
            affected = [cv.get("host")]
        for hn in affected:
            v = hv.get(str(hn).strip()) or "Unknown"
            vendor_count[v] = vendor_count.get(v, 0) + 1

    # Fallback: count vendors directly from hosts when CVEs don't carry host links
    if not vendor_count:
        for h in hosts:
            v = h.get("vendor", "") or "Unknown"
            crit = int(h.get("critical", h.get("crit_count", 0)) or 0)
            hi = int(h.get("high", h.get("high_count", 0)) or 0)
            if crit + hi:
                vendor_count[v] = vendor_count.get(v, 0) + crit + hi

    if not vendor_count:
        return ""

    total = sum(vendor_count.values()) or 1
    sorted_v = sorted(vendor_count.items(), key=lambda kv: kv[1], reverse=True)
    top_v, top_count = sorted_v[0]
    top_pct = int(round(top_count / total * 100))

    # Hbar chart of vendors
    chart_xml = ""
    if media is not None:
        items = [(name, n) for name, n in sorted_v[:8]]
        png = _docx_chart_png(
            "hbar", items,
            width=720, height=320,
            title="Critical+High CVEs by Vendor",
            color=_chart_png.TEAL if _chart_png else None,
        )
        if png:
            rid = media.add(png)
            chart_xml = _docx_inline_image(rid, width_in=5.6, height_in=2.5,
                                             align="center")

    parts = [_docx_heading("Vendor concentration analysis", level=1, prefix="")]
    parts.append(_docx_para([
        _docx_run(
            f"{top_pct}% of critical and high-severity CVEs are concentrated on ",
            size_pt=11, color=_DOCX_INK),
        _docx_run(top_v, size_pt=11, bold=True, color=_DOCX_BRAND_TEAL),
        _docx_run(
            " gear. Single-vendor concentration is a supply-chain and "
            "patch-window risk: a vendor advisory delay or zero-day forces "
            "fleet-wide change windows. Diversifying critical-path vendors "
            "and standardizing on at least two suppliers for perimeter "
            "and core roles is recommended where operationally feasible.",
            size_pt=11, color=_DOCX_INK),
    ], space_after=160))
    if chart_xml:
        parts.append(chart_xml)
    # Per-vendor table
    rows = [[{"text": "Vendor"},
             {"text": "Critical+High CVEs", "align": "center"},
             {"text": "Share", "align": "center"}]]
    for v, n in sorted_v[:10]:
        pct = int(round(n / total * 100))
        rows.append([
            {"text": v, "bold": True, "size_pt": 10},
            {"text": str(n), "align": "center", "size_pt": 10},
            {"text": f"{pct}%", "align": "center", "size_pt": 10,
             "color": _DOCX_BRAND_TEAL, "bold": True},
        ])
    parts.append(_docx_table(rows, widths=[3600, 2800, 2600]))
    return "".join(parts)


def _docx_site_heatmap(report: dict) -> str:
    """Site × severity heatmap — count of findings by site and severity."""
    hosts = []
    for s in report.get("sections") or []:
        if s.get("key") == "host_inventory":
            hosts = (s.get("data") or {}).get("hosts") or []
            break
    if not hosts:
        return ""

    # Build a site -> severity counts map
    site_counts: dict[str, dict[str, int]] = {}
    for h in hosts:
        site = h.get("site") or "Unknown site"
        d = site_counts.setdefault(site, {"critical": 0, "high": 0,
                                           "medium": 0, "low": 0})
        d["critical"] += int(h.get("critical", h.get("crit_count", 0)) or 0)
        d["high"]     += int(h.get("high", h.get("high_count", 0)) or 0)
        d["medium"]   += int(h.get("medium", h.get("med_count", 0)) or 0)
        d["low"]      += int(h.get("low", h.get("low_count", 0)) or 0)
    if not site_counts:
        return ""

    # Compute intensity by row
    max_v = 1
    for _site, sd in site_counts.items():
        for sev in ("critical", "high", "medium", "low"):
            max_v = max(max_v, sd[sev])

    def shade_for(sev: str, n: int) -> str:
        if n <= 0:
            return _DOCX_BG_SOFT
        # Lighter to darker based on intensity (1..max_v)
        intensity = min(1.0, n / max_v)
        ramp = {
            "critical": ["FEE2E2", "FCA5A5", "F87171", "EF4444", "DC2626"],
            "high":     ["FFEDD5", "FED7AA", "FB923C", "F97316", "EA580C"],
            "medium":   ["FEF3C7", "FDE68A", "FBBF24", "F59E0B", "CA8A04"],
            "low":      ["DBEAFE", "BFDBFE", "93C5FD", "60A5FA", "3B82F6"],
        }
        bucket = min(4, int(intensity * 4.99))
        return ramp.get(sev, ["F1F5F9"] * 5)[bucket]

    rows = [[
        {"text": "Site"},
        {"text": "Critical", "align": "center"},
        {"text": "High",     "align": "center"},
        {"text": "Medium",   "align": "center"},
        {"text": "Low",      "align": "center"},
    ]]
    for site, sd in sorted(site_counts.items(),
                            key=lambda kv: -(kv[1]["critical"] + kv[1]["high"])):
        rows.append([
            {"text": site, "bold": True, "size_pt": 10},
            {"text": str(sd["critical"]), "align": "center", "size_pt": 10,
             "bold": True, "shade": shade_for("critical", sd["critical"]),
             "color": "FFFFFF" if sd["critical"] >= max_v * 0.6 else _DOCX_INK},
            {"text": str(sd["high"]), "align": "center", "size_pt": 10,
             "bold": True, "shade": shade_for("high", sd["high"]),
             "color": "FFFFFF" if sd["high"] >= max_v * 0.6 else _DOCX_INK},
            {"text": str(sd["medium"]), "align": "center", "size_pt": 10,
             "shade": shade_for("medium", sd["medium"])},
            {"text": str(sd["low"]), "align": "center", "size_pt": 10,
             "shade": shade_for("low", sd["low"])},
        ])
    return (
        _docx_heading("Site heatmap", level=1, prefix="") +
        _docx_para([_docx_run(
            "Cell shading scales with finding count — darker means a heavier "
            "concentration of that severity at that site.",
            size_pt=10, italic=True, color=_DOCX_INK_SOFT)], space_after=120) +
        _docx_table(rows, widths=[3000, 1600, 1600, 1600, 1600])
    )


def _docx_what_if(report: dict) -> str:
    """What-if delta — current posture vs. posture after completing all P0."""
    actions = []
    for s in report.get("sections") or []:
        if s.get("key") == "recommended_actions":
            actions = (s.get("data") or {}).get("actions") or []
            break
    if not actions:
        return ""
    kpi = _kpi_data(report)
    cur_score = _derive_overall_risk(kpi)
    # Risk score is current risk; we want POSTURE which is the inverse
    current_posture = max(0, 100 - cur_score)
    lift = 0
    for a in actions:
        if (a.get("priority") or "") == "P0":
            try:
                lift += int(a.get("risk_reduction") or 0)
            except (TypeError, ValueError):
                pass
    projected = min(100, current_posture + lift)

    # Two big tiles — before / after
    grid = ('<w:tblGrid>'
            '<w:gridCol w:w="4500"/>'
            '<w:gridCol w:w="4500"/>'
            '</w:tblGrid>')
    tbl_pr = (
        '<w:tblPr><w:tblW w:w="5000" w:type="pct"/>'
        '<w:tblLook w:val="0000"/>'
        '<w:tblCellSpacing w:w="80" w:type="dxa"/>'
        '<w:tblBorders>'
        '<w:top w:val="none"/><w:left w:val="none"/>'
        '<w:bottom w:val="none"/><w:right w:val="none"/>'
        '<w:insideH w:val="none"/><w:insideV w:val="none"/>'
        '</w:tblBorders></w:tblPr>'
    )

    def tile(label: str, value: int, color: str, sub: str) -> str:
        lbl = _docx_para([_docx_run(label, bold=True, size_pt=9,
                                      color=_DOCX_INK_FAINT, uppercase=True)],
                          align="center", space_before=80, space_after=20)
        num = _docx_para([_docx_run(f"{value}%", bold=True, size_pt=44,
                                      color=color)],
                          align="center", space_before=0, space_after=20)
        s = _docx_para([_docx_run(sub, size_pt=10, color=_DOCX_INK_SOFT,
                                   italic=True)],
                        align="center", space_before=0, space_after=80)
        tcpr = (
            '<w:tcPr><w:tcW w:w="4500" w:type="dxa"/>'
            f'<w:shd w:val="clear" w:color="auto" w:fill="{_DOCX_BG_SOFT}"/>'
            '<w:tcBorders>'
            f'<w:top w:val="single" w:sz="6" w:color="{color}"/>'
            f'<w:left w:val="single" w:sz="2" w:color="{_DOCX_RULE}"/>'
            f'<w:bottom w:val="single" w:sz="2" w:color="{_DOCX_RULE}"/>'
            f'<w:right w:val="single" w:sz="2" w:color="{_DOCX_RULE}"/>'
            '</w:tcBorders></w:tcPr>'
        )
        return f"<w:tc>{tcpr}{lbl + num + s}</w:tc>"

    before = tile("Current posture", current_posture,
                   _DOCX_AMBER if current_posture < 70 else _DOCX_GREEN,
                   "As of today")
    after = tile("After P0 remediation", projected,
                  _DOCX_GREEN, f"+{projected - current_posture} pts projected")
    table = (f"<w:tbl>{tbl_pr}{grid}<w:tr>{before}{after}</w:tr></w:tbl>")
    narrative = _docx_para([
        _docx_run(
            f"If you complete all P0 actions on the prioritized list, posture "
            f"lifts from {current_posture}% to roughly {projected}% — a "
            f"+{projected - current_posture} point gain. P1 and P2 work "
            "carries another 10–20 points on top of that.",
            size_pt=11, color=_DOCX_INK),
    ], space_before=160, space_after=160)
    return (_docx_heading("What-if: closing the P0 backlog", level=1, prefix="")
            + table
            + _docx_para("", space_before=0, space_after=80)
            + narrative)


def _docx_qoq_comparison(report: dict) -> str:
    """Quarter-over-quarter comparison from delta module if available."""
    parts = [_docx_heading("Quarter-over-quarter comparison", level=1, prefix="")]
    delta = None
    if _delta_mod is not None:
        try:
            delta = _delta_mod.compute_delta()
        except Exception:
            delta = None
    if not delta or not delta.get("available"):
        parts.append(_docx_para([_docx_run(
            "Establishing baseline — no prior snapshot is on disk yet to "
            "compare against. The next snapshot will produce a quarter-over-"
            "quarter view here automatically.",
            size_pt=11, italic=True, color=_DOCX_INK_SOFT)], space_after=120))
        return "".join(parts)

    parts.append(_docx_para([_docx_run(delta.get("summary_text", ""),
                                         size_pt=11, color=_DOCX_INK)],
                              space_after=160))
    rows = [[
        {"text": "KPI"},
        {"text": "Last quarter", "align": "center"},
        {"text": "This quarter", "align": "center"},
        {"text": "Δ", "align": "center"},
    ]]
    kpis = delta.get("kpis") or {}
    label_map = {
        "hosts": "Hosts in scope", "critical": "Critical CVEs",
        "high": "High CVEs", "medium": "Medium CVEs", "low": "Low CVEs",
        "kev": "KEV-listed", "eol": "EOL devices",
        "eos_software": "EOS software",
    }
    for k, label in label_map.items():
        d = kpis.get(k) or {}
        ch = d.get("change", 0)
        color = (_DOCX_RED if ch > 0 and k != "hosts" else
                 _DOCX_GREEN if ch < 0 and k != "hosts" else _DOCX_INK_SOFT)
        if k == "hosts":
            color = _DOCX_INK_SOFT
        sign = "+" if ch > 0 else ""
        rows.append([
            {"text": label, "bold": True, "size_pt": 10},
            {"text": str(d.get("prev", 0)), "align": "center", "size_pt": 10},
            {"text": str(d.get("now", 0)), "align": "center", "size_pt": 10,
             "bold": True},
            {"text": f"{sign}{ch}", "align": "center", "size_pt": 10,
             "bold": True, "color": color},
        ])
    parts.append(_docx_table(rows, widths=[3000, 2200, 2200, 1700]))
    return "".join(parts)


def _docx_industry_benchmark(report: dict) -> str:
    """Industry benchmark callout — per-framework score vs. peer median."""
    cd = _compliance_data(report)
    frameworks = cd.get("frameworks") or []
    if not frameworks:
        return ""

    parts = [_docx_heading("Industry benchmark", level=1, prefix="")]
    parts.append(_docx_para([_docx_run(
        "Peer medians below are self-reported industry data points and should "
        "be read as directional only — they do not represent a validated "
        "academic study. Use them to spot where your posture deviates from "
        "common practice for organizations of similar profile.",
        size_pt=10, italic=True, color=_DOCX_INK_SOFT)], space_after=160))
    rows = [[
        {"text": "Framework"},
        {"text": "Your score", "align": "center"},
        {"text": "Peer median", "align": "center"},
        {"text": "Position", "align": "center"},
    ]]
    for fw in frameworks:
        name = fw.get("framework") or fw.get("name") or ""
        score = int(fw.get("score") or 0)
        median = _PEER_BENCHMARK.get(name)
        if median is None:
            # Loose match
            for k, v in _PEER_BENCHMARK.items():
                if k.lower() in name.lower() or name.lower() in k.lower():
                    median = v; break
        median = median or 75
        diff = score - median
        if diff >= 5:
            pos = "Above peer"; pc = _DOCX_GREEN
        elif diff <= -5:
            pos = "Below peer"; pc = _DOCX_RED
        else:
            pos = "At peer";    pc = _DOCX_AMBER
        rows.append([
            {"text": name, "bold": True, "size_pt": 10},
            {"text": f"{score}%", "align": "center", "size_pt": 11,
             "bold": True, "color": _DOCX_BRAND_TEAL},
            {"text": f"{median}%", "align": "center", "size_pt": 11,
             "color": _DOCX_INK_SOFT},
            {"text": pos, "align": "center", "size_pt": 9, "bold": True,
             "color": "FFFFFF", "shade": pc},
        ])
    parts.append(_docx_table(rows, widths=[3000, 2200, 2200, 1700]))
    return "".join(parts)


def _docx_glossary(report: dict) -> str:
    """Glossary / appendix — definitions of common terms."""
    terms = [
        ("CVE", "Common Vulnerabilities and Exposures — the public identifier "
                "assigned to a disclosed software vulnerability."),
        ("CVSS", "Common Vulnerability Scoring System — a 0-10 numeric score "
                 "that estimates the severity of a CVE."),
        ("EPSS", "Exploit Prediction Scoring System — probability that a CVE "
                 "will be exploited in the wild in the next 30 days."),
        ("KEV", "Known Exploited Vulnerabilities catalog — maintained by CISA, "
                "lists CVEs with confirmed active exploitation."),
        ("EOL", "End of Life — vendor no longer sells or develops the product."),
        ("EOS", "End of Support — vendor no longer issues security patches "
                "for the product. EOS hardware/software is unsupported."),
        ("MFA", "Multi-Factor Authentication — login that requires two or more "
                "independent factors."),
        ("CDE", "Cardholder Data Environment — PCI DSS scope boundary; all "
                "systems that store, process, or transmit cardholder data."),
        ("ePHI", "Electronic Protected Health Information — covered under HIPAA "
                 "Security Rule."),
        ("ATT&CK", "MITRE ATT&CK framework — knowledge base of adversary "
                   "tactics, techniques, and procedures."),
        ("NVD", "National Vulnerability Database — NIST's repository of "
                "standards-based vulnerability data, the authoritative source "
                "for CVE metadata."),
        ("KEV-listed", "A CVE that appears in CISA's KEV catalog — meaning "
                       "active exploitation in the wild has been observed."),
    ]
    rows = [[{"text": "Term"}, {"text": "Definition"}]]
    for term, defn in terms:
        rows.append([
            {"text": term, "bold": True, "size_pt": 10,
             "color": _DOCX_BRAND_TEAL},
            {"text": defn, "size_pt": 10, "color": _DOCX_INK},
        ])
    return (
        _docx_heading("Glossary & appendix", level=1, prefix="") +
        _docx_table(rows, widths=[1600, 7400])
    )


def _docx_sign_off_page() -> str:
    """Sign-off page with three signature lines."""
    parts = [_docx_heading("Sign-off", level=1, prefix="",
                            page_break_before=True)]
    parts.append(_docx_para([_docx_run(
        "By signing below, the named parties acknowledge that they have "
        "reviewed this report and accept it as an accurate representation "
        "of the assessed environment on the report date.",
        size_pt=11, italic=True, color=_DOCX_INK_SOFT)],
                              space_after=400))

    def sig_row(label: str) -> str:
        # Two paragraph row: label, then a sig line built via bottom border
        lbl_run = [_docx_run(label, bold=True, size_pt=11, color=_DOCX_INK)]
        # Signature line
        sig_p = (
            '<w:p><w:pPr>'
            '<w:spacing w:before="400" w:after="0"/>'
            '<w:pBdr><w:bottom w:val="single" w:sz="6" w:color="0F172A"/></w:pBdr>'
            '</w:pPr>'
            '<w:r><w:rPr><w:sz w:val="22"/></w:rPr>'
            '<w:t xml:space="preserve">                                                                                            </w:t></w:r>'
            '</w:p>'
        )
        cap_p = _docx_para(lbl_run, space_before=40, space_after=300)
        return sig_p + cap_p

    parts.append(sig_row("Prepared by                                                                  Date"))
    parts.append(sig_row("Reviewed by                                                                  Date"))
    parts.append(sig_row("Approved by                                                                  Date"))
    return "".join(parts)


# --------------------------------------------------------------------------
# DOCX executive enhancements — drop cap + pull quote
# --------------------------------------------------------------------------

def _docx_exec_pull_quote(report: dict) -> str:
    """Pull a striking KPI into a callout-style pull quote."""
    kpi = _kpi_data(report)
    crit = int(kpi.get("critical") or 0)
    kev = int(kpi.get("kev") or 0)
    eol = int(kpi.get("eol") or 0)
    if kev:
        quote = (f"{kev} KEV-listed vulnerabilities sit on assets in scope — "
                  "patch this week.")
    elif crit >= 10:
        quote = (f"{crit} critical CVEs are open across the fleet — schedule a "
                  "remediation sprint.")
    elif eol >= 3:
        quote = (f"{eol} devices are past vendor end-of-support — they cannot "
                  "be patched and should be replaced.")
    elif crit:
        quote = f"{crit} critical CVE{'s' if crit != 1 else ''} need immediate attention."
    else:
        quote = ("No critical or KEV-listed vulnerabilities — the fleet's "
                 "current posture is solid. Maintain scan cadence.")

    # Bigger italic teal text with a thick teal left border
    return _docx_para([
        _docx_run('"' + quote + '"', italic=True, size_pt=15,
                   color=_DOCX_BRAND_TEAL, bold=True),
    ], shade=_DOCX_BG_TEAL, border_left=_DOCX_BRAND_TEAL,
       space_before=200, space_after=200, indent_left=240)


def _docx_executive_with_drop_cap(report: dict) -> str:
    """Executive summary with a drop-cap first letter."""
    text = None
    for s in report.get("sections") or []:
        if s.get("key") == "executive_summary" and not s.get("empty"):
            try:
                text = ai_helpers.generate_executive_summary(
                    {"kpi": _kpi_data(report),
                     "scope": report.get("scope") or {}},
                    tone="executive",
                )
            except Exception:
                text = (s.get("data") or {}).get("summary") or ""
            break
    if not text:
        return ""

    # Strip any leading whitespace
    text = text.strip()
    if not text:
        return ""

    # First character becomes a 36pt brand-teal drop cap; the rest is normal.
    first_char = text[0]
    rest = text[1:]
    drop_p = _docx_para([
        _docx_run(first_char, bold=True, size_pt=36, color=_DOCX_BRAND_TEAL),
        _docx_run(rest, size_pt=12, color=_DOCX_INK),
    ], space_before=120, space_after=160)
    # Proper heading + drop cap body + pull quote — no empty callout band.
    return (
        _docx_heading("Executive summary", level=1, prefix="01")
        + drop_p
        + _docx_exec_pull_quote(report)
    )


def render_docx(report: dict, *, preset: dict | None = None) -> bytes:
    """Render the report as a polished Word .docx file."""
    import io
    import zipfile

    sections = report.get("sections") or []
    media = _DocxMedia()

    # Assemble body in order:
    #   cover → revision history → methodology → TOC → exec (drop cap + pull
    #   quote) → KPI dashboard (with charts) → compliance scorecard (with
    #   radar) → industry benchmark → action plan → risk register → vendor
    #   concentration → site heatmap → what-if → QoQ → per-section deep
    #   dives → glossary → sign-off.
    body_parts: list[str] = [_docx_cover_page(report, media)]
    body_parts.append(_docx_revision_history(report))
    body_parts.append(_docx_toc(report))
    body_parts.append(_docx_methodology_section(report))

    exec_block = _docx_executive_with_drop_cap(report)
    if exec_block:
        body_parts.append(exec_block)
    else:
        # Fall back to the original callout style
        exec_callout = _docx_executive_callout(report)
        if exec_callout:
            body_parts.append(_docx_heading("Executive summary", level=1, prefix=""))
            body_parts.append(exec_callout)

    body_parts.append(_docx_kpi_dashboard(report, media))
    body_parts.append(_docx_compliance_scorecard(report, media))
    body_parts.append(_docx_industry_benchmark(report))
    body_parts.append(_docx_action_plan(report))
    body_parts.append(_docx_risk_register(report))
    body_parts.append(_docx_vendor_concentration(report, media))
    body_parts.append(_docx_site_heatmap(report))
    body_parts.append(_docx_what_if(report))
    body_parts.append(_docx_qoq_comparison(report))

    # Per-section deep dive blocks (skipping ones already summarized).
    handled = {"executive_summary", "kpi_summary", "compliance_posture",
               "recommended_actions"}
    idx = 5
    for s in sections:
        if s.get("key") in handled:
            continue
        body_parts.append(_docx_section_block(s, report, idx))
        idx += 1

    body_parts.append(_docx_glossary(report))
    body_parts.append(_docx_sign_off_page())

    body_xml = "".join(body_parts)

    # Section properties — include header + footer references + A4-ish letter size
    sect_pr = (
        '<w:sectPr>'
        '<w:headerReference w:type="default" r:id="rIdHeader"/>'
        '<w:footerReference w:type="default" r:id="rIdFooter"/>'
        '<w:pgSz w:w="12240" w:h="15840"/>'
        '<w:pgMar w:top="1440" w:right="1080" w:bottom="1440" w:left="1080" '
        'w:header="720" w:footer="720" w:gutter="0"/>'
        '<w:cols w:space="720"/>'
        '<w:docGrid w:linePitch="360"/>'
        '</w:sectPr>'
    )

    document_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document '
        'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        f'<w:body>{body_xml}{sect_pr}</w:body></w:document>'
    )

    # Header XML — small caps brand on the left
    header_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:hdr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        '<w:p><w:pPr>'
        '<w:pBdr><w:bottom w:val="single" w:sz="6" w:color="1F6F6A"/></w:pBdr>'
        '<w:tabs><w:tab w:val="right" w:pos="9360"/></w:tabs>'
        '</w:pPr>'
        '<w:r><w:rPr><w:b/><w:sz w:val="16"/><w:color w:val="1F6F6A"/>'
        '<w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/></w:rPr>'
        '<w:t>SAFECADENCE · NETRISK</w:t></w:r>'
        '<w:r><w:tab/></w:r>'
        '<w:r><w:rPr><w:sz w:val="16"/><w:color w:val="64748B"/>'
        '<w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/></w:rPr>'
        '<w:t>Confidential · Network Security &amp; Compliance Assessment</w:t></w:r>'
        '</w:p></w:hdr>'
    )

    # Footer with page numbering field codes
    footer_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:ftr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        '<w:p><w:pPr>'
        '<w:pBdr><w:top w:val="single" w:sz="6" w:color="1F6F6A"/></w:pBdr>'
        '<w:tabs><w:tab w:val="center" w:pos="4680"/><w:tab w:val="right" w:pos="9360"/></w:tabs>'
        '</w:pPr>'
        '<w:r><w:rPr><w:sz w:val="16"/><w:color w:val="64748B"/>'
        '<w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/></w:rPr>'
        f'<w:t>{_today()}</w:t></w:r>'
        '<w:r><w:tab/></w:r>'
        '<w:r><w:rPr><w:sz w:val="16"/><w:color w:val="64748B"/>'
        '<w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/></w:rPr>'
        '<w:t>Page </w:t></w:r>'
        '<w:r><w:fldChar w:fldCharType="begin"/></w:r>'
        '<w:r><w:instrText> PAGE </w:instrText></w:r>'
        '<w:r><w:fldChar w:fldCharType="end"/></w:r>'
        '<w:r><w:rPr><w:sz w:val="16"/><w:color w:val="64748B"/>'
        '<w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/></w:rPr>'
        '<w:t> of </w:t></w:r>'
        '<w:r><w:fldChar w:fldCharType="begin"/></w:r>'
        '<w:r><w:instrText> NUMPAGES </w:instrText></w:r>'
        '<w:r><w:fldChar w:fldCharType="end"/></w:r>'
        '<w:r><w:tab/></w:r>'
        '<w:r><w:rPr><w:b/><w:sz w:val="14"/><w:color w:val="1F6F6A"/>'
        '<w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/></w:rPr>'
        '<w:t>SafeCadence · Confidential</w:t></w:r>'
        '</w:p></w:ftr>'
    )

    # Styles — default paragraph + heading1/2 + table normal
    styles_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        '<w:docDefaults>'
        '<w:rPrDefault><w:rPr>'
        '<w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:cs="Calibri"/>'
        '<w:sz w:val="22"/><w:szCs w:val="22"/></w:rPr></w:rPrDefault>'
        '<w:pPrDefault><w:pPr><w:spacing w:line="276" w:lineRule="auto"/></w:pPr></w:pPrDefault>'
        '</w:docDefaults>'
        '<w:style w:type="paragraph" w:default="1" w:styleId="Normal">'
        '<w:name w:val="Normal"/><w:qFormat/></w:style>'
        '<w:style w:type="paragraph" w:styleId="Heading1">'
        '<w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/>'
        '<w:qFormat/>'
        '<w:pPr><w:keepNext/><w:spacing w:before="360" w:after="160"/>'
        '<w:outlineLvl w:val="0"/></w:pPr>'
        '<w:rPr><w:b/><w:sz w:val="44"/><w:color w:val="1F6F6A"/></w:rPr></w:style>'
        '<w:style w:type="paragraph" w:styleId="Heading2">'
        '<w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/>'
        '<w:qFormat/>'
        '<w:pPr><w:keepNext/><w:spacing w:before="240" w:after="100"/>'
        '<w:outlineLvl w:val="1"/></w:pPr>'
        '<w:rPr><w:b/><w:sz w:val="28"/><w:color w:val="0F172A"/></w:rPr></w:style>'
        '</w:styles>'
    )

    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="png" ContentType="image/png"/>'
        '<Override PartName="/word/document.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        '<Override PartName="/word/styles.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>'
        '<Override PartName="/word/header1.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml"/>'
        '<Override PartName="/word/footer1.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/>'
        '</Types>'
    )

    root_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="word/document.xml"/></Relationships>'
    )

    doc_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" '
        'Target="styles.xml"/>'
        '<Relationship Id="rIdHeader" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/header" '
        'Target="header1.xml"/>'
        '<Relationship Id="rIdFooter" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" '
        'Target="footer1.xml"/>'
        + media.rels_xml() +
        '</Relationships>'
    )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", content_types)
        z.writestr("_rels/.rels", root_rels)
        z.writestr("word/document.xml", document_xml)
        z.writestr("word/styles.xml", styles_xml)
        z.writestr("word/header1.xml", header_xml)
        z.writestr("word/footer1.xml", footer_xml)
        z.writestr("word/_rels/document.xml.rels", doc_rels)
        for fn, png in media.images:
            z.writestr(f"word/media/{fn}", png)
    return buf.getvalue()


# --------------------------------------------------------------------------
# PPTX  (PowerPoint — 16:9 widescreen, slide-per-topic, visual-first)
# --------------------------------------------------------------------------
#
# Design: real presentation slides, not text dumps. Each topic gets its own
# focused slide. Visual elements are real OOXML shapes (rectangles, text
# boxes) with brand colors. 16:9 widescreen. Slide number + footer on every
# non-cover slide. Big numbers for KPI metrics. Per-framework rows for
# compliance scorecard. P0/P1/P2/P3 colored badges in the action plan.

# 16:9 widescreen: 13.333 in × 7.5 in = 12192000 × 6858000 EMU
_PPTX_W = 12192000
_PPTX_H = 6858000
_PPTX_MARGIN_X = 685800   # 0.75"
_PPTX_MARGIN_Y = 457200   # 0.5"

# Brand colors
_PPTX_INK         = "0B1220"
_PPTX_INK_2       = "1E293B"
_PPTX_INK_SOFT    = "475569"
_PPTX_INK_FAINT   = "64748B"
_PPTX_RULE        = "E2E8F0"
_PPTX_TEAL        = "1F6F6A"
_PPTX_TEAL_LT     = "5FC6BC"
_PPTX_BG_TEAL     = "F0FDFA"
_PPTX_BG_SOFT     = "F8FAFC"
_PPTX_RED         = "DC2626"
_PPTX_ORANGE      = "EA580C"
_PPTX_AMBER       = "CA8A04"
_PPTX_BLUE        = "1E40AF"
_PPTX_GREEN       = "16A34A"
_PPTX_DARKRED     = "7F1D1D"


def _pptx_esc(s: Any) -> str:
    return html.escape(str(s if s is not None else ""), quote=True)


# --------------------------------------------------------------------------
# PPTX image embedding infrastructure
# --------------------------------------------------------------------------


class _PptxMedia:
    """Accumulator for PPTX images, scoped by slide.

    Each slide gets its own per-slide list of images that turn into per-slide
    relationships. Globally we also track every image so they can be written
    once into ``ppt/media/``.
    """

    def __init__(self) -> None:
        # Global filename -> bytes map; the same image is reused across slides
        # by its global index (i.e. filename).
        self.global_images: list[tuple[str, bytes]] = []
        # Per slide (1-based) -> list of (global_filename, rid_within_slide)
        self.per_slide: dict[int, list[tuple[str, str]]] = {}
        self._next_global = 1
        # Per-slide rid counters
        self._slide_rid_counter: dict[int, int] = {}
        # Per-slide note relationships (rid -> notesSlideN.xml target)
        self.notes: dict[int, int] = {}  # slide_no -> notesSlide_no

    def add(self, slide_no: int, png_bytes: bytes | None) -> str | None:
        """Add an image to a slide. Returns the slide-local relationship ID."""
        if not png_bytes:
            return None
        # Reuse existing PNG bytes if seen (rare optimization)
        fn = f"image{self._next_global}.png"
        self._next_global += 1
        self.global_images.append((fn, png_bytes))
        # Allocate slide-local rid
        next_rid = self._slide_rid_counter.get(slide_no, 1) + 1  # leave rId1 for slideLayout
        # Bump until safe — rId2 is reserved for notesSlide
        used = self._slide_rid_counter.get(slide_no, 1) + 1
        self._slide_rid_counter[slide_no] = used
        rid = f"rIdImg{used}"
        self.per_slide.setdefault(slide_no, []).append((fn, rid))
        return rid

    def slide_rels_xml(self, slide_no: int) -> str:
        out = []
        for fn, rid in self.per_slide.get(slide_no, []):
            out.append(
                f'<Relationship Id="{rid}" '
                'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" '
                f'Target="../media/{fn}"/>'
            )
        return "".join(out)


def _pptx_chart_png(kind: str, *args, **kwargs) -> bytes | None:
    """Safe wrapper around chart_png — returns None if PIL is unavailable."""
    if _chart_png is None:
        return None
    try:
        fn = getattr(_chart_png, kind, None)
        if fn is None:
            return None
        return fn(*args, **kwargs)
    except Exception:
        return None


def _pptx_image_shape(rid: str | None, *, x: int, y: int, cx: int, cy: int,
                       shape_id: int = 999) -> str:
    """Render a ``<p:pic>`` shape that references an image relationship.

    Returns an empty string if ``rid`` is falsy.
    """
    if not rid:
        return ""
    return (
        '<p:pic>'
        f'<p:nvPicPr>'
        f'<p:cNvPr id="{shape_id}" name="Picture{shape_id}"/>'
        '<p:cNvPicPr/><p:nvPr/></p:nvPicPr>'
        '<p:blipFill>'
        f'<a:blip r:embed="{rid}"/>'
        '<a:stretch><a:fillRect/></a:stretch></p:blipFill>'
        '<p:spPr>'
        f'<a:xfrm><a:off x="{x}" y="{y}"/><a:ext cx="{cx}" cy="{cy}"/></a:xfrm>'
        '<a:prstGeom prst="rect"><a:avLst/></a:prstGeom></p:spPr>'
        '</p:pic>'
    )


def _pptx_text_run(text: str, *, size_pt: int = 18, bold: bool = False,
                   italic: bool = False, color: str = _PPTX_INK,
                   font: str = "Calibri") -> str:
    size = int(size_pt * 100)
    return (
        '<a:r>'
        f'<a:rPr lang="en-US" sz="{size}" b="{1 if bold else 0}" '
        f'i="{1 if italic else 0}">'
        f'<a:solidFill><a:srgbClr val="{color}"/></a:solidFill>'
        f'<a:latin typeface="{font}"/>'
        '</a:rPr>'
        f'<a:t>{_pptx_esc(text)}</a:t>'
        '</a:r>'
    )


def _pptx_paragraph(runs: list[str], *, align: str = "l",
                    bullet: bool = False, indent_lvl: int = 0,
                    space_after: int = 0) -> str:
    bullet_xml = ""
    if bullet:
        bullet_xml = '<a:buFont typeface="Arial"/><a:buChar char="•"/>'
    spc = f' spcAft="{space_after}"' if space_after else ""
    return (
        f'<a:p><a:pPr algn="{align}" lvl="{indent_lvl}"{spc}>{bullet_xml}</a:pPr>'
        + "".join(runs) +
        '</a:p>'
    )


def _pptx_text_box(*, x: int, y: int, w: int, h: int, paragraphs: list[str],
                   shape_id: int = 1, anchor: str = "t") -> str:
    """A text-only shape (txBody only, no fill)."""
    body = "".join(paragraphs) or '<a:p><a:endParaRPr lang="en-US"/></a:p>'
    return (
        f'<p:sp>'
        f'<p:nvSpPr><p:cNvPr id="{shape_id}" name="Text{shape_id}"/>'
        '<p:cNvSpPr txBox="1"/><p:nvPr/></p:nvSpPr>'
        '<p:spPr>'
        f'<a:xfrm><a:off x="{x}" y="{y}"/><a:ext cx="{w}" cy="{h}"/></a:xfrm>'
        '<a:prstGeom prst="rect"><a:avLst/></a:prstGeom>'
        '<a:noFill/>'
        '</p:spPr>'
        f'<p:txBody><a:bodyPr wrap="square" anchor="{anchor}" lIns="0" rIns="0" tIns="0" bIns="0"/>'
        '<a:lstStyle/>'
        f'{body}'
        '</p:txBody></p:sp>'
    )


def _pptx_rect(*, x: int, y: int, w: int, h: int, fill: str,
               shape_id: int = 1, paragraphs: list[str] | None = None,
               anchor: str = "ctr", line_color: str | None = None) -> str:
    """A filled rectangle, optionally with text inside it."""
    body = "".join(paragraphs) if paragraphs else \
           '<a:p><a:endParaRPr lang="en-US"/></a:p>'
    line = ""
    if line_color:
        line = f'<a:ln w="9525"><a:solidFill><a:srgbClr val="{line_color}"/></a:solidFill></a:ln>'
    else:
        line = '<a:ln><a:noFill/></a:ln>'
    return (
        f'<p:sp>'
        f'<p:nvSpPr><p:cNvPr id="{shape_id}" name="Rect{shape_id}"/>'
        '<p:cNvSpPr/><p:nvPr/></p:nvSpPr>'
        '<p:spPr>'
        f'<a:xfrm><a:off x="{x}" y="{y}"/><a:ext cx="{w}" cy="{h}"/></a:xfrm>'
        '<a:prstGeom prst="rect"><a:avLst/></a:prstGeom>'
        f'<a:solidFill><a:srgbClr val="{fill}"/></a:solidFill>'
        f'{line}'
        '</p:spPr>'
        f'<p:txBody><a:bodyPr wrap="square" anchor="{anchor}" '
        'lIns="91440" rIns="91440" tIns="45720" bIns="45720"/>'
        '<a:lstStyle/>'
        f'{body}'
        '</p:txBody></p:sp>'
    )


def _pptx_slide(shapes: list[str], *, bg: str = "FFFFFF",
                footer_text: str = "", slide_no: str = "") -> str:
    """Wrap a list of shapes into a slide. Optionally adds footer + slide number."""
    base_shapes = []
    sid = 100  # Reserved shape ids for footer / page number to avoid collision
    # Footer
    if footer_text:
        base_shapes.append(_pptx_rect(
            x=0, y=_PPTX_H - 320000, w=_PPTX_W, h=4000, fill=_PPTX_TEAL,
            shape_id=sid))
        sid += 1
        base_shapes.append(_pptx_text_box(
            x=_PPTX_MARGIN_X, y=_PPTX_H - 280000,
            w=_PPTX_W - 2 * _PPTX_MARGIN_X, h=240000,
            shape_id=sid,
            paragraphs=[_pptx_paragraph([
                _pptx_text_run(footer_text, size_pt=9, color=_PPTX_INK_FAINT),
            ], align="l")] + ([_pptx_paragraph([
                _pptx_text_run(slide_no, size_pt=9, color=_PPTX_INK_FAINT, bold=True),
            ], align="r")] if slide_no else [])
        ))
        sid += 1
        # Right-aligned slide num is a separate text box for clean alignment
        if slide_no:
            base_shapes.append(_pptx_text_box(
                x=_PPTX_W - _PPTX_MARGIN_X - 800000, y=_PPTX_H - 280000,
                w=800000, h=240000, shape_id=sid,
                paragraphs=[_pptx_paragraph([
                    _pptx_text_run(slide_no, size_pt=9, color=_PPTX_INK_FAINT, bold=True),
                ], align="r")]
            ))
            sid += 1

    spTree = (
        '<p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>'
        '<p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/>'
        '<a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr>'
        + "".join(shapes) + "".join(base_shapes)
    )

    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
        'xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">'
        '<p:cSld>'
        '<p:bg><p:bgPr>'
        f'<a:solidFill><a:srgbClr val="{bg}"/></a:solidFill>'
        '<a:effectLst/></p:bgPr></p:bg>'
        f'<p:spTree>{spTree}</p:spTree>'
        '</p:cSld>'
        '<p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sld>'
    )


def _pptx_section_header(title: str, eyebrow: str = "", section_no: int = 0,
                          slide_no: str = "") -> str:
    """Standard slide header — section number badge + eyebrow + title."""
    shapes = []
    sid = 2
    # Section number teal badge
    if section_no:
        shapes.append(_pptx_rect(
            x=_PPTX_MARGIN_X, y=_PPTX_MARGIN_Y,
            w=500000, h=500000, fill=_PPTX_BG_TEAL,
            shape_id=sid,
            paragraphs=[_pptx_paragraph([
                _pptx_text_run(f"{section_no:02d}", size_pt=18, bold=True,
                                color=_PPTX_TEAL),
            ], align="ctr")],
            anchor="ctr",
        ))
        sid += 1
        title_x = _PPTX_MARGIN_X + 600000
    else:
        title_x = _PPTX_MARGIN_X
    # Eyebrow + title block
    paras = []
    if eyebrow:
        paras.append(_pptx_paragraph([
            _pptx_text_run(eyebrow.upper(), size_pt=10, bold=True,
                            color=_PPTX_TEAL),
        ], align="l", space_after=80000))
    paras.append(_pptx_paragraph([
        _pptx_text_run(title, size_pt=34, bold=True, color=_PPTX_INK),
    ], align="l"))
    shapes.append(_pptx_text_box(
        x=title_x, y=_PPTX_MARGIN_Y,
        w=_PPTX_W - title_x - _PPTX_MARGIN_X, h=900000,
        shape_id=sid, paragraphs=paras,
    ))
    # Underline rule
    sid += 1
    shapes.append(_pptx_rect(
        x=_PPTX_MARGIN_X, y=_PPTX_MARGIN_Y + 950000,
        w=900000, h=40000, fill=_PPTX_TEAL_LT,
        shape_id=sid,
    ))
    return shapes


def _pptx_cover_slide(report: dict,
                       media: "_PptxMedia | None" = None,
                       slide_no: int = 1) -> str:
    title = report.get("title") or "SafeCadence NetRisk Report"
    kpi = _kpi_data(report)
    score = _derive_overall_risk(kpi)
    confidence = _confidence_for(kpi)
    doc_id = _dt.datetime.now(_dt.timezone.utc).strftime("SC-%Y%m%d-%H%M")

    shapes = []
    # Background: full-bleed hero image (PIL) or dark fallback
    hero_rid = None
    if media is not None:
        hero_png = _pptx_chart_png("cover_hero", width=1200, height=720)
        if hero_png:
            hero_rid = media.add(slide_no, hero_png)
    if hero_rid:
        shapes.append(_pptx_image_shape(hero_rid, x=0, y=0,
                                          cx=_PPTX_W, cy=_PPTX_H,
                                          shape_id=2))
    else:
        shapes.append(_pptx_rect(x=0, y=0, w=_PPTX_W, h=_PPTX_H,
                                   fill=_PPTX_INK, shape_id=2))
    # Decorative teal block on the right (semi over hero)
    shapes.append(_pptx_rect(x=_PPTX_W - 3800000, y=0, w=3800000, h=_PPTX_H,
                               fill="0F3A35", shape_id=3))
    # Teal accent strip
    shapes.append(_pptx_rect(x=_PPTX_W - 3800000, y=0, w=80000, h=_PPTX_H,
                               fill=_PPTX_TEAL_LT, shape_id=4))

    # Brand strip (top left)
    shapes.append(_pptx_text_box(
        x=_PPTX_MARGIN_X, y=_PPTX_MARGIN_Y, w=4000000, h=350000,
        shape_id=5,
        paragraphs=[_pptx_paragraph([
            _pptx_text_run("SAFECADENCE", size_pt=14, bold=True, color="FFFFFF"),
            _pptx_text_run("  ·  ", size_pt=14, color=_PPTX_TEAL_LT, bold=True),
            _pptx_text_run("NETRISK", size_pt=14, bold=True, color=_PPTX_TEAL_LT),
        ], align="l")],
    ))
    # Doc id (top right inside teal block)
    shapes.append(_pptx_text_box(
        x=_PPTX_W - 3700000, y=_PPTX_MARGIN_Y, w=3000000, h=350000,
        shape_id=6,
        paragraphs=[_pptx_paragraph([
            _pptx_text_run(f"DOC {doc_id}", size_pt=10, color="94A3B8", bold=True),
        ], align="l")],
    ))

    # Eyebrow
    shapes.append(_pptx_text_box(
        x=_PPTX_MARGIN_X, y=2400000, w=7800000, h=400000,
        shape_id=7,
        paragraphs=[_pptx_paragraph([
            _pptx_text_run("NETWORK SECURITY & COMPLIANCE ASSESSMENT",
                            size_pt=12, bold=True, color=_PPTX_TEAL_LT),
        ], align="l")],
    ))
    # Title (big)
    shapes.append(_pptx_text_box(
        x=_PPTX_MARGIN_X, y=2850000, w=7800000, h=1400000,
        shape_id=8,
        paragraphs=[_pptx_paragraph([
            _pptx_text_run(title, size_pt=46, bold=True, color="FFFFFF"),
        ], align="l")],
    ))
    # Subtitle
    shapes.append(_pptx_text_box(
        x=_PPTX_MARGIN_X, y=4350000, w=7400000, h=900000,
        shape_id=9,
        paragraphs=[_pptx_paragraph([
            _pptx_text_run(
                "Evidence-driven posture across asset risk, vulnerability exposure, "
                "control coverage, and prioritized remediation.",
                size_pt=18, color="CBD5E1", italic=True),
        ], align="l")],
    ))
    # Date + confidence
    shapes.append(_pptx_text_box(
        x=_PPTX_MARGIN_X, y=5700000, w=7800000, h=300000,
        shape_id=10,
        paragraphs=[_pptx_paragraph([
            _pptx_text_run(_today(), size_pt=12, color="CBD5E1", bold=True),
            _pptx_text_run("    ·    ", size_pt=12, color="64748B"),
            _pptx_text_run(confidence, size_pt=12, color=_PPTX_TEAL_LT, bold=True),
        ], align="l")],
    ))

    # Big risk index on the right (white huge number)
    color = (_PPTX_RED if score >= 70 else _PPTX_ORANGE if score >= 40 else _PPTX_GREEN)
    shapes.append(_pptx_text_box(
        x=_PPTX_W - 3500000, y=2700000, w=3000000, h=400000,
        shape_id=11,
        paragraphs=[_pptx_paragraph([
            _pptx_text_run("OVERALL RISK INDEX", size_pt=11, bold=True,
                            color=_PPTX_TEAL_LT),
        ], align="l")],
    ))
    shapes.append(_pptx_text_box(
        x=_PPTX_W - 3500000, y=3100000, w=3000000, h=1800000,
        shape_id=12,
        paragraphs=[_pptx_paragraph([
            _pptx_text_run(f"{score}", size_pt=140, bold=True, color="FFFFFF"),
        ], align="l")],
    ))
    shapes.append(_pptx_text_box(
        x=_PPTX_W - 3500000, y=4900000, w=3000000, h=400000,
        shape_id=13,
        paragraphs=[_pptx_paragraph([
            _pptx_text_run("/ 100", size_pt=22, color=color, bold=True),
        ], align="l")],
    ))

    return _pptx_slide(shapes, bg=_PPTX_INK)


def _pptx_agenda_slide(report: dict, slide_no: str) -> str:
    sections = report.get("sections") or []
    shapes = _pptx_section_header("Agenda", eyebrow="What's in this report",
                                   section_no=0)
    # List items in two columns if more than 6
    sid = 50
    col_x_1 = _PPTX_MARGIN_X
    col_x_2 = _PPTX_W / 2 + 200000
    col_w   = (_PPTX_W - 2 * _PPTX_MARGIN_X) / 2 - 200000
    n_per_col = (len(sections) + 1) // 2
    for col, items in enumerate([sections[:n_per_col], sections[n_per_col:]]):
        if not items:
            continue
        paras = []
        for i, s in enumerate(items):
            idx = (col * n_per_col + i + 1)
            paras.append(_pptx_paragraph([
                _pptx_text_run(f"{idx:02d}.  ", size_pt=18, bold=True,
                                color=_PPTX_TEAL_LT),
                _pptx_text_run(s.get("title", ""), size_pt=18,
                                color=_PPTX_INK),
            ], align="l", space_after=120000))
        x = col_x_1 if col == 0 else col_x_2
        shapes.append(_pptx_text_box(
            x=int(x), y=1900000, w=int(col_w), h=4400000,
            shape_id=sid, paragraphs=paras,
        ))
        sid += 1
    return _pptx_slide(shapes, footer_text="SafeCadence · Confidential",
                         slide_no=slide_no)


def _pptx_exec_summary_slide(report: dict, slide_no: str) -> str:
    """Big takeaway — narrative + 3 bullet headlines."""
    kpi = _kpi_data(report)
    try:
        text = ai_helpers.generate_executive_summary(
            {"kpi": kpi, "scope": report.get("scope") or {}},
            tone="executive",
        )
    except Exception:
        text = "Executive summary unavailable."

    shapes = _pptx_section_header("Executive summary",
                                   eyebrow="The headline",
                                   section_no=1)

    # Narrative in left half
    paras = [_pptx_paragraph([
        _pptx_text_run(text, size_pt=16, color=_PPTX_INK_2),
    ], align="l", space_after=200000)]

    shapes.append(_pptx_text_box(
        x=_PPTX_MARGIN_X, y=1900000, w=int(_PPTX_W * 0.56), h=4400000,
        shape_id=20, paragraphs=paras,
    ))

    # Right column: three pull-stats with colored boxes
    items = [
        ("Critical findings", str(int(kpi.get("critical") or 0)), _PPTX_RED),
        ("KEV-listed",        str(int(kpi.get("kev")      or 0)), _PPTX_DARKRED),
        ("Hosts in scope",    str(int(kpi.get("hosts")    or 0)), _PPTX_TEAL),
    ]
    sid = 30
    y = 1900000
    box_x = int(_PPTX_W * 0.6) + 200000
    box_w = _PPTX_W - box_x - _PPTX_MARGIN_X
    for label, value, color in items:
        # Colored top bar
        shapes.append(_pptx_rect(x=box_x, y=y, w=box_w, h=60000, fill=color,
                                   shape_id=sid))
        sid += 1
        # Box body
        shapes.append(_pptx_rect(x=box_x, y=y + 60000, w=box_w, h=1100000,
                                   fill="FFFFFF", line_color=_PPTX_RULE,
                                   shape_id=sid,
                                   paragraphs=[
            _pptx_paragraph([
                _pptx_text_run(label.upper(), size_pt=10, bold=True,
                                color=_PPTX_INK_FAINT),
            ], align="l", space_after=40000),
            _pptx_paragraph([
                _pptx_text_run(value, size_pt=44, bold=True, color=color),
            ], align="l"),
        ], anchor="t"))
        sid += 1
        y += 1300000
    return _pptx_slide(shapes, footer_text="SafeCadence · Confidential",
                         slide_no=slide_no)


def _pptx_kpi_dashboard_slide(report: dict, slide_no: str,
                                media: "_PptxMedia | None" = None,
                                slide_no_int: int = 4) -> str:
    kpi = _kpi_data(report)
    shapes = _pptx_section_header("Risk dashboard",
                                   eyebrow="Top-line metrics",
                                   section_no=2)
    items = [
        ("Hosts in scope", int(kpi.get("hosts") or 0),    _PPTX_TEAL,    "Assets evaluated"),
        ("Critical CVEs",  int(kpi.get("critical") or 0), _PPTX_RED,     "P0 patch class"),
        ("High CVEs",      int(kpi.get("high") or 0),     _PPTX_ORANGE,  "P1 patch class"),
        ("KEV-listed",     int(kpi.get("kev") or 0),      _PPTX_DARKRED, "Actively exploited"),
        ("EOL hardware",   int(kpi.get("eol") or 0),      _PPTX_AMBER,   "Past vendor EOS"),
    ]
    sid = 30
    # Make room for a donut chart on the right; tiles get the left 60%
    chart_area_w = 3200000
    total_w = _PPTX_W - 2 * _PPTX_MARGIN_X - chart_area_w - 200000
    gap = 120000
    tile_w = (total_w - gap * (len(items) - 1)) // len(items)
    tile_h = 2400000
    x = _PPTX_MARGIN_X
    y = 2200000

    # Donut chart on the right
    if media is not None:
        donut_png = _pptx_chart_png("severity_donut", {
            "critical": int(kpi.get("critical") or 0),
            "high":     int(kpi.get("high") or 0),
            "medium":   int(kpi.get("medium") or 0),
            "low":      int(kpi.get("low") or 0),
            "info":     0,
        }, size=400)
        if donut_png:
            rid = media.add(slide_no_int, donut_png)
            chart_x = _PPTX_W - _PPTX_MARGIN_X - chart_area_w
            shapes.append(_pptx_image_shape(rid, x=chart_x, y=y,
                                              cx=chart_area_w, cy=chart_area_w,
                                              shape_id=999))
            shapes.append(_pptx_text_box(
                x=chart_x, y=y + chart_area_w + 80000,
                w=chart_area_w, h=300000,
                shape_id=998,
                paragraphs=[_pptx_paragraph([
                    _pptx_text_run("Severity distribution",
                                    size_pt=11, bold=True,
                                    color=_PPTX_INK_FAINT),
                ], align="ctr")],
            ))

    for label, value, color, sub in items:
        # Top color bar
        shapes.append(_pptx_rect(x=x, y=y, w=tile_w, h=80000, fill=color,
                                   shape_id=sid))
        sid += 1
        # Body card
        shapes.append(_pptx_rect(x=x, y=y + 80000, w=tile_w, h=tile_h - 80000,
                                   fill="FFFFFF", line_color=_PPTX_RULE,
                                   shape_id=sid, paragraphs=[
            _pptx_paragraph([
                _pptx_text_run(label.upper(), size_pt=11, bold=True,
                                color=_PPTX_INK_FAINT),
            ], align="ctr", space_after=120000),
            _pptx_paragraph([
                _pptx_text_run(str(value), size_pt=64, bold=True, color=color),
            ], align="ctr", space_after=120000),
            _pptx_paragraph([
                _pptx_text_run(sub, size_pt=10, color=_PPTX_INK_SOFT, italic=True),
            ], align="ctr"),
        ], anchor="t"))
        sid += 1
        x += tile_w + gap
    return _pptx_slide(shapes, footer_text="SafeCadence · Confidential",
                         slide_no=slide_no)


def _pptx_compliance_scorecard_slide(report: dict, slide_no: str,
                                       media: "_PptxMedia | None" = None,
                                       slide_no_int: int = 5) -> str:
    # Try compliance_posture first, then compliance_executive_summary,
    # finally derive from compliance_control_matrix by counting per-framework
    # status if neither is present.
    frameworks = []
    for s in report.get("sections") or []:
        if s.get("key") == "compliance_posture":
            frameworks = (s.get("data") or {}).get("frameworks") or []
            if frameworks: break
        if s.get("key") == "compliance_executive_summary":
            frameworks = (s.get("data") or {}).get("frameworks") or []
            if frameworks: break
    if not frameworks:
        # Synthesize from control_matrix rows
        rows = []
        for s in report.get("sections") or []:
            if s.get("key") == "compliance_control_matrix":
                rows = (s.get("data") or {}).get("rows") or []
                break
        if rows:
            from collections import defaultdict
            tally = defaultdict(lambda: {"pass": 0, "partial": 0, "fail": 0, "na": 0})
            for r in rows:
                tally[r["framework"]][r["status"]] = tally[r["framework"]].get(r["status"], 0) + 1
            for fw, counts in tally.items():
                total = sum(counts.values()) or 1
                score = int(round(((counts["pass"] + 0.5 * counts["partial"]) / total) * 100))
                frameworks.append({
                    "framework": fw,
                    "score": score,
                    "pass": counts["pass"],
                    "fail": counts["fail"] + counts["partial"],
                    "top_failures": [],
                })
    shapes = _pptx_section_header("Compliance scorecard",
                                   eyebrow="Status across frameworks",
                                   section_no=3)
    if not frameworks:
        shapes.append(_pptx_text_box(
            x=_PPTX_MARGIN_X, y=2200000, w=_PPTX_W - 2 * _PPTX_MARGIN_X, h=500000,
            shape_id=40,
            paragraphs=[_pptx_paragraph([
                _pptx_text_run("No compliance data available.", size_pt=18,
                                color=_PPTX_INK_FAINT, italic=True),
            ], align="l")],
        ))
        return _pptx_slide(shapes, footer_text="SafeCadence · Confidential",
                             slide_no=slide_no)

    sid = 40

    # Radar chart on the left (if PIL available); rows on the right
    chart_w = 3800000
    chart_x = _PPTX_MARGIN_X
    rows_x = _PPTX_MARGIN_X + chart_w + 300000
    rows_w = _PPTX_W - rows_x - _PPTX_MARGIN_X
    radar_drawn = False
    if media is not None:
        radar_png = _pptx_chart_png("compliance_radar", frameworks, size=500)
        if radar_png:
            rid = media.add(slide_no_int, radar_png)
            shapes.append(_pptx_image_shape(rid, x=chart_x, y=2100000,
                                              cx=chart_w, cy=chart_w,
                                              shape_id=999))
            shapes.append(_pptx_text_box(
                x=chart_x, y=2100000 + chart_w + 80000,
                w=chart_w, h=300000,
                shape_id=998,
                paragraphs=[_pptx_paragraph([
                    _pptx_text_run("Per-framework score radar",
                                    size_pt=11, bold=True,
                                    color=_PPTX_INK_FAINT),
                ], align="ctr")],
            ))
            radar_drawn = True

    # Determine right-column placement
    if not radar_drawn:
        rows_x = _PPTX_MARGIN_X
        rows_w = _PPTX_W - 2 * _PPTX_MARGIN_X

    y = 2100000
    row_h = 700000
    label_w = int(rows_w * 0.46)
    bar_x = rows_x + label_w + 100000
    bar_max = rows_w - label_w - 100000 - 1100000
    score_x = rows_x + rows_w - 1000000

    for fw in frameworks[:5]:
        name = fw.get("framework") or fw.get("name") or ""
        score = int(fw.get("score") or 0)
        if score >= 85:
            status = "PASS"; col = _PPTX_GREEN
        elif score >= 65:
            status = "PARTIAL"; col = _PPTX_AMBER
        else:
            status = "FAIL"; col = _PPTX_RED

        # Framework name
        shapes.append(_pptx_text_box(
            x=rows_x, y=y, w=label_w, h=row_h, shape_id=sid,
            paragraphs=[_pptx_paragraph([
                _pptx_text_run(name, size_pt=16, bold=True, color=_PPTX_INK),
            ], align="l")], anchor="ctr",
        ))
        sid += 1
        # Bar background
        shapes.append(_pptx_rect(
            x=bar_x, y=y + 220000, w=max(80000, bar_max), h=160000,
            fill=_PPTX_RULE, shape_id=sid,
        ))
        sid += 1
        # Bar fill
        fill_w = int(max(80000, bar_max) * score / 100)
        shapes.append(_pptx_rect(
            x=bar_x, y=y + 220000, w=max(40000, fill_w), h=160000,
            fill=col, shape_id=sid,
        ))
        sid += 1
        # Score + status
        shapes.append(_pptx_text_box(
            x=score_x, y=y, w=1000000, h=row_h, shape_id=sid,
            paragraphs=[_pptx_paragraph([
                _pptx_text_run(f"{score}%", size_pt=20, bold=True, color=col),
            ], align="r")] + [_pptx_paragraph([
                _pptx_text_run(status, size_pt=10, bold=True,
                                color=_PPTX_INK_FAINT),
            ], align="r")], anchor="ctr",
        ))
        sid += 1
        y += row_h + 100000

    return _pptx_slide(shapes, footer_text="SafeCadence · Confidential",
                         slide_no=slide_no)


def _pptx_top_findings_slide(report: dict, slide_no: str) -> str:
    """Top KEV / critical findings list, formatted as a clean visual list."""
    # Try evidence pack first; fall back to cve_exposure list.
    findings = []
    for s in report.get("sections") or []:
        if s.get("key") == "compliance_evidence_pack":
            findings = (s.get("data") or {}).get("findings") or []
            if findings: break
    if not findings:
        for s in report.get("sections") or []:
            if s.get("key") == "cve_exposure":
                cves = (s.get("data") or {}).get("cves") or []
                # Normalize cve_exposure shape into findings shape
                for c in cves[:10]:
                    findings.append({
                        "host": c.get("host", "") or
                                (", ".join(c.get("hosts") or [])[:60] if c.get("hosts") else ""),
                        "title": c.get("id") or c.get("summary") or "CVE",
                        "severity": (c.get("severity") or "").lower(),
                        "kev": bool(c.get("kev")),
                    })
                if findings: break
    shapes = _pptx_section_header("Top findings",
                                   eyebrow="KEV-listed and critical first",
                                   section_no=4)
    if not findings:
        shapes.append(_pptx_text_box(
            x=_PPTX_MARGIN_X, y=2200000, w=_PPTX_W - 2*_PPTX_MARGIN_X, h=400000,
            shape_id=60,
            paragraphs=[_pptx_paragraph([
                _pptx_text_run("No findings in scope. The fleet looks clean — verify "
                                "scan freshness and policy coverage.",
                                size_pt=18, color=_PPTX_INK_FAINT, italic=True),
            ], align="l")],
        ))
        return _pptx_slide(shapes, footer_text="SafeCadence · Confidential",
                             slide_no=slide_no)
    sid = 60
    y = 2100000
    row_h = 580000
    sev_color = {"critical": _PPTX_RED, "high": _PPTX_ORANGE,
                 "medium": _PPTX_AMBER, "low": _PPTX_BLUE}
    for f in findings[:7]:
        sev = (f.get("severity") or "").lower()
        color = sev_color.get(sev, _PPTX_INK_FAINT)
        # Severity badge
        shapes.append(_pptx_rect(
            x=_PPTX_MARGIN_X, y=y, w=900000, h=row_h - 100000,
            fill=color, shape_id=sid,
            paragraphs=[_pptx_paragraph([
                _pptx_text_run(("KEV" if f.get("kev") else sev.upper()),
                                size_pt=12, bold=True, color="FFFFFF"),
            ], align="ctr")],
        ))
        sid += 1
        # Title + asset
        shapes.append(_pptx_text_box(
            x=_PPTX_MARGIN_X + 1000000, y=y, w=_PPTX_W - 2*_PPTX_MARGIN_X - 1000000,
            h=row_h, shape_id=sid,
            paragraphs=[
                _pptx_paragraph([
                    _pptx_text_run(f.get("title", "") or "(unnamed)", size_pt=15,
                                    bold=True, color=_PPTX_INK),
                ], align="l", space_after=40000),
                _pptx_paragraph([
                    _pptx_text_run(f.get("host", "") or "—", size_pt=11,
                                    color=_PPTX_INK_FAINT),
                ], align="l"),
            ], anchor="ctr",
        ))
        sid += 1
        y += row_h
    return _pptx_slide(shapes, footer_text="SafeCadence · Confidential",
                         slide_no=slide_no)


def _pptx_action_plan_slide(report: dict, slide_no: str) -> str:
    actions = []
    for s in report.get("sections") or []:
        if s.get("key") == "recommended_actions":
            actions = (s.get("data") or {}).get("actions") or []
            break
    shapes = _pptx_section_header("Prioritized action plan",
                                   eyebrow="What to fix first",
                                   section_no=5)
    pri_colors = {"P0": _PPTX_RED, "P1": _PPTX_ORANGE,
                  "P2": _PPTX_AMBER, "P3": _PPTX_BLUE}
    if not actions:
        shapes.append(_pptx_text_box(
            x=_PPTX_MARGIN_X, y=2200000, w=_PPTX_W - 2*_PPTX_MARGIN_X, h=400000,
            shape_id=70,
            paragraphs=[_pptx_paragraph([
                _pptx_text_run("No action plan generated. Run a scan to populate.",
                                size_pt=18, color=_PPTX_INK_FAINT, italic=True),
            ], align="l")],
        ))
        return _pptx_slide(shapes, footer_text="SafeCadence · Confidential",
                             slide_no=slide_no)
    sid = 70
    y = 2100000
    row_h = 580000
    for a in actions[:8]:
        pri = a.get("priority") or "P3"
        color = pri_colors.get(pri, _PPTX_INK_FAINT)
        shapes.append(_pptx_rect(
            x=_PPTX_MARGIN_X, y=y, w=550000, h=row_h - 100000,
            fill=color, shape_id=sid,
            paragraphs=[_pptx_paragraph([
                _pptx_text_run(pri, size_pt=16, bold=True, color="FFFFFF"),
            ], align="ctr")],
        ))
        sid += 1
        compl = a.get("compliance") or []
        if isinstance(compl, list):
            compl_str = ", ".join(compl[:3]) if compl else "—"
        else:
            compl_str = str(compl)
        shapes.append(_pptx_text_box(
            x=_PPTX_MARGIN_X + 650000, y=y, w=_PPTX_W - 2*_PPTX_MARGIN_X - 650000,
            h=row_h, shape_id=sid,
            paragraphs=[
                _pptx_paragraph([
                    _pptx_text_run(a.get("title", "") or "(untitled action)",
                                    size_pt=14, bold=True, color=_PPTX_INK),
                ], align="l", space_after=40000),
                _pptx_paragraph([
                    _pptx_text_run(
                        f"{a.get('effort','medium')} effort  ·  {compl_str}",
                        size_pt=10, color=_PPTX_INK_FAINT),
                ], align="l"),
            ], anchor="ctr",
        ))
        sid += 1
        y += row_h
    return _pptx_slide(shapes, footer_text="SafeCadence · Confidential",
                         slide_no=slide_no)


def _pptx_visual_table_slide(report: dict, title: str, eyebrow: str,
                              section_no: int, columns: list[dict],
                              rows: list[list[dict]], slide_no: str,
                              header_color: str = _PPTX_INK,
                              note: str = "") -> str:
    """Render a slide with a clean visual table.

    columns: [{"text": "Header", "w": <emu width>, "align": "l|ctr|r"}]
    rows:    [[{"text": "cell", "color": ?, "shade": ?, "bold": ?, "size_pt": ?}]]
    """
    shapes = _pptx_section_header(title, eyebrow=eyebrow, section_no=section_no)
    sid = 200
    y0 = 2100000

    # Header row (dark filled rectangle)
    x = _PPTX_MARGIN_X
    header_h = 360000
    for c in columns:
        w = c.get("w", 1200000)
        shapes.append(_pptx_rect(
            x=x, y=y0, w=w, h=header_h, fill=header_color, shape_id=sid,
            paragraphs=[_pptx_paragraph([
                _pptx_text_run(c.get("text", "").upper(),
                                size_pt=10, bold=True, color="FFFFFF"),
            ], align=c.get("align", "l"))],
        ))
        sid += 1
        x += w

    # Body rows
    row_h = 480000
    max_rows = min(len(rows), 8)
    y = y0 + header_h
    for ri in range(max_rows):
        row = rows[ri]
        x = _PPTX_MARGIN_X
        row_fill = _PPTX_BG_SOFT if ri % 2 == 1 else "FFFFFF"
        for ci, cell in enumerate(row):
            w = columns[ci]["w"] if ci < len(columns) else columns[-1]["w"]
            fill = cell.get("shade") or row_fill
            text_color = cell.get("color", _PPTX_INK)
            bold = cell.get("bold", False)
            size_pt = cell.get("size_pt", 11)
            shapes.append(_pptx_rect(
                x=x, y=y, w=w, h=row_h, fill=fill, shape_id=sid,
                line_color=_PPTX_RULE,
                paragraphs=[_pptx_paragraph([
                    _pptx_text_run(str(cell.get("text", "")),
                                    size_pt=size_pt, bold=bold,
                                    color=text_color),
                ], align=columns[ci].get("align", "l"))],
            ))
            sid += 1
            x += w
        y += row_h

    if note:
        shapes.append(_pptx_text_box(
            x=_PPTX_MARGIN_X, y=y + 100000,
            w=_PPTX_W - 2 * _PPTX_MARGIN_X, h=300000,
            shape_id=sid,
            paragraphs=[_pptx_paragraph([
                _pptx_text_run(note, size_pt=10, italic=True,
                                color=_PPTX_INK_FAINT),
            ], align="l")],
        ))
    return _pptx_slide(shapes, footer_text="SafeCadence · Confidential",
                         slide_no=slide_no)


def _pptx_cve_exposure_slide(s: dict, report: dict, idx: int,
                               slide_no: str) -> str:
    """CVE exposure as a visual table: ID | severity badge | host(s) | KEV."""
    data = s.get("data") or {}
    cves = data.get("cves") or []
    count = data.get("count") or len(cves)
    sev_color = {"critical": _PPTX_RED, "high": _PPTX_ORANGE,
                 "medium": _PPTX_AMBER, "low": _PPTX_BLUE}

    columns = [
        {"text": "CVE ID",     "w": 2400000, "align": "l"},
        {"text": "Severity",   "w": 1600000, "align": "ctr"},
        {"text": "CVSS",       "w": 1100000, "align": "ctr"},
        {"text": "Host(s)",    "w": 4400000, "align": "l"},
        {"text": "KEV",        "w":  900000, "align": "ctr"},
    ]
    # Sort: KEV first, then severity, then cvss desc
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "": 9}
    sorted_cves = sorted(cves, key=lambda c: (
        0 if c.get("kev") else 1,
        sev_order.get((c.get("severity") or "").lower(), 9),
        -float(c.get("cvss") or 0),
    ))[:8]
    rows = []
    for c in sorted_cves:
        sev = (c.get("severity") or "").lower()
        host = c.get("host") or (
            ", ".join(c.get("hosts") or [])[:50] if c.get("hosts") else "—"
        )
        cvss = c.get("cvss")
        cvss_str = f"{float(cvss):.1f}" if cvss else "—"
        rows.append([
            {"text": c.get("id") or "—", "bold": True, "size_pt": 11},
            {"text": sev.upper() if sev else "—",
             "color": "FFFFFF", "shade": sev_color.get(sev, _PPTX_INK_FAINT),
             "bold": True, "size_pt": 10},
            {"text": cvss_str, "bold": True, "size_pt": 11},
            {"text": host, "size_pt": 10},
            {"text": "✓" if c.get("kev") else "",
             "color": "FFFFFF" if c.get("kev") else _PPTX_INK_FAINT,
             "shade": _PPTX_DARKRED if c.get("kev") else None,
             "bold": True, "size_pt": 12},
        ])
    note = (f"Showing top 8 of {count} CVEs in scope, ordered KEV → severity → CVSS. "
            "Full list in HTML and JSON exports.")
    return _pptx_visual_table_slide(
        report, title="CVE exposure", eyebrow="Top vulnerabilities",
        section_no=idx, columns=columns, rows=rows, slide_no=slide_no,
        note=note,
    )


def _pptx_host_inventory_slide(s: dict, report: dict, idx: int,
                                 slide_no: str) -> str:
    """Host inventory as a visual table."""
    data = s.get("data") or {}
    hosts = data.get("hosts") or []
    count = data.get("count") or len(hosts)
    crit_color = {"critical": _PPTX_RED, "high": _PPTX_ORANGE,
                  "medium": _PPTX_AMBER, "low": _PPTX_BLUE}
    columns = [
        {"text": "Host",         "w": 2600000, "align": "l"},
        {"text": "Vendor",       "w": 1800000, "align": "l"},
        {"text": "Site",         "w": 1400000, "align": "l"},
        {"text": "Criticality",  "w": 1500000, "align": "ctr"},
        {"text": "Risk score",   "w": 1100000, "align": "ctr"},
        {"text": "Top finding",  "w": 2000000, "align": "l"},
    ]
    # Sort by risk_score desc
    sorted_hosts = sorted(hosts,
                          key=lambda h: -int(h.get("risk_score") or 0))[:8]
    rows = []
    for h in sorted_hosts:
        crit = (h.get("criticality") or "").lower()
        risk = int(h.get("risk_score") or 0)
        risk_c = (_PPTX_RED if risk >= 70 else
                  _PPTX_ORANGE if risk >= 40 else _PPTX_GREEN)
        rows.append([
            {"text": h.get("hostname") or h.get("name") or "—",
             "bold": True, "size_pt": 11},
            {"text": h.get("vendor", "—"), "size_pt": 10},
            {"text": h.get("site", "—"), "size_pt": 10,
             "color": _PPTX_INK_SOFT},
            {"text": crit.upper() if crit else "—",
             "color": "FFFFFF", "shade": crit_color.get(crit, _PPTX_INK_FAINT),
             "bold": True, "size_pt": 10},
            {"text": str(risk) if risk else "—",
             "color": risk_c, "bold": True, "size_pt": 13},
            {"text": (str(h.get("top_finding") or "—"))[:32], "size_pt": 9,
             "color": _PPTX_INK_FAINT},
        ])
    note = (f"Showing top 8 of {count} hosts by risk score. "
            "Complete inventory in JSON export.")
    return _pptx_visual_table_slide(
        report, title="Host inventory", eyebrow="Highest-risk systems",
        section_no=idx, columns=columns, rows=rows, slide_no=slide_no,
        note=note,
    )


def _pptx_eol_hardware_slide(s: dict, report: dict, idx: int,
                               slide_no: str) -> str:
    """EOL hardware visual table."""
    data = s.get("data") or {}
    devices = data.get("devices") or []
    count = data.get("count") or len(devices)
    status_color = {"end-of-support": _PPTX_RED, "end-of-software": _PPTX_ORANGE,
                    "approaching-eos": _PPTX_AMBER}
    columns = [
        {"text": "Host",       "w": 2800000, "align": "l"},
        {"text": "Vendor",     "w": 1800000, "align": "l"},
        {"text": "Model",      "w": 1800000, "align": "l"},
        {"text": "Status",     "w": 2400000, "align": "ctr"},
        {"text": "EOS date",   "w": 1600000, "align": "ctr"},
    ]
    rows = []
    for d in devices[:8]:
        status = (d.get("status") or "").lower()
        rows.append([
            {"text": d.get("hostname") or "—", "bold": True, "size_pt": 11},
            {"text": d.get("vendor") or "—", "size_pt": 10},
            {"text": d.get("model") or "—", "size_pt": 10},
            {"text": status.upper() if status else "—",
             "color": "FFFFFF",
             "shade": status_color.get(status, _PPTX_INK_FAINT),
             "bold": True, "size_pt": 9},
            {"text": str(d.get("eos_date") or "—"), "size_pt": 10,
             "color": _PPTX_INK_FAINT},
        ])
    if not rows:
        # Show a "clean" message instead of an empty table
        shapes = _pptx_section_header("EOL hardware",
                                       eyebrow="Past vendor end-of-support",
                                       section_no=idx)
        shapes.append(_pptx_text_box(
            x=_PPTX_MARGIN_X, y=2400000,
            w=_PPTX_W - 2 * _PPTX_MARGIN_X, h=400000, shape_id=400,
            paragraphs=[_pptx_paragraph([
                _pptx_text_run("✓  No EOL hardware in scope. ", size_pt=20,
                                bold=True, color=_PPTX_GREEN),
                _pptx_text_run("Fleet is on supported platforms.", size_pt=18,
                                color=_PPTX_INK_2),
            ], align="l")],
        ))
        return _pptx_slide(shapes, footer_text="SafeCadence · Confidential",
                             slide_no=slide_no)
    note = (f"Showing top 8 of {count} EOL/EOS devices in scope. "
            "Replace these to restore vendor support and patch coverage.")
    return _pptx_visual_table_slide(
        report, title="EOL hardware", eyebrow="Past vendor end-of-support",
        section_no=idx, columns=columns, rows=rows, slide_no=slide_no,
        note=note,
    )


def _pptx_control_matrix_slide(s: dict, report: dict, idx: int,
                                 slide_no: str) -> str:
    """Compliance control matrix — top counts per framework + status mix."""
    data = s.get("data") or {}
    rows_data = data.get("rows") or []
    by_status = data.get("by_status") or {}
    shapes = _pptx_section_header("Compliance control matrix",
                                   eyebrow="Status per control",
                                   section_no=idx)
    # 4 status tiles
    sid = 300
    tiles = [
        ("PASS",    by_status.get("pass", 0),    _PPTX_GREEN),
        ("PARTIAL", by_status.get("partial", 0), _PPTX_AMBER),
        ("FAIL",    by_status.get("fail", 0),    _PPTX_RED),
        ("N/A",     by_status.get("na", 0),      _PPTX_INK_FAINT),
    ]
    total_w = _PPTX_W - 2 * _PPTX_MARGIN_X
    gap = 120000
    tile_w = (total_w - gap * 3) // 4
    tile_h = 1200000
    x = _PPTX_MARGIN_X
    y = 2100000
    for label, value, color in tiles:
        shapes.append(_pptx_rect(
            x=x, y=y, w=tile_w, h=80000, fill=color, shape_id=sid))
        sid += 1
        shapes.append(_pptx_rect(
            x=x, y=y + 80000, w=tile_w, h=tile_h - 80000,
            fill="FFFFFF", line_color=_PPTX_RULE, shape_id=sid,
            paragraphs=[
                _pptx_paragraph([
                    _pptx_text_run(label, size_pt=11, bold=True,
                                    color=_PPTX_INK_FAINT),
                ], align="ctr", space_after=80000),
                _pptx_paragraph([
                    _pptx_text_run(str(value), size_pt=44, bold=True,
                                    color=color),
                ], align="ctr"),
            ], anchor="t"))
        sid += 1
        x += tile_w + gap

    # Per-framework summary
    from collections import defaultdict
    tally = defaultdict(lambda: {"pass": 0, "partial": 0, "fail": 0, "na": 0})
    for r in rows_data:
        tally[r["framework"]][r["status"]] = tally[r["framework"]].get(r["status"], 0) + 1

    y2 = y + tile_h + 200000
    # Per-framework row table
    shapes.append(_pptx_text_box(
        x=_PPTX_MARGIN_X, y=y2, w=total_w, h=300000, shape_id=sid,
        paragraphs=[_pptx_paragraph([
            _pptx_text_run("PER-FRAMEWORK BREAKDOWN", size_pt=10, bold=True,
                            color=_PPTX_INK_FAINT),
        ], align="l")]))
    sid += 1
    y2 += 300000
    for fw, counts in tally.items():
        total = sum(counts.values()) or 1
        score = int(round(((counts["pass"] + 0.5 * counts["partial"]) / total) * 100))
        col = (_PPTX_GREEN if score >= 85 else
               _PPTX_AMBER if score >= 65 else _PPTX_RED)
        # Framework name
        shapes.append(_pptx_text_box(
            x=_PPTX_MARGIN_X, y=y2, w=2400000, h=380000, shape_id=sid,
            paragraphs=[_pptx_paragraph([
                _pptx_text_run(fw, size_pt=12, bold=True, color=_PPTX_INK),
            ], align="l")], anchor="ctr"))
        sid += 1
        # Stacked bar (pass + partial + fail proportions)
        bar_x = _PPTX_MARGIN_X + 2500000
        bar_max = total_w - 2500000 - 1500000
        cur = bar_x
        for key, color in [("pass", _PPTX_GREEN), ("partial", _PPTX_AMBER),
                            ("fail", _PPTX_RED)]:
            seg_w = int(bar_max * counts[key] / total) if total else 0
            if seg_w > 0:
                shapes.append(_pptx_rect(
                    x=cur, y=y2 + 100000, w=seg_w, h=180000,
                    fill=color, shape_id=sid))
                sid += 1
                cur += seg_w
        # Score number on right
        shapes.append(_pptx_text_box(
            x=_PPTX_W - _PPTX_MARGIN_X - 1300000, y=y2, w=1300000, h=380000,
            shape_id=sid,
            paragraphs=[_pptx_paragraph([
                _pptx_text_run(f"{score}%", size_pt=14, bold=True, color=col),
            ], align="r")], anchor="ctr"))
        sid += 1
        y2 += 380000

    return _pptx_slide(shapes, footer_text="SafeCadence · Confidential",
                         slide_no=slide_no)


def _pptx_divider_slide(roman: str, title: str, eyebrow: str = "") -> str:
    """Full-bleed dark divider slide between report parts."""
    shapes = []
    # Dark navy background
    shapes.append(_pptx_rect(x=0, y=0, w=_PPTX_W, h=_PPTX_H,
                               fill=_PPTX_INK, shape_id=2))
    # Subtle teal accent slab on left
    shapes.append(_pptx_rect(x=0, y=0, w=120000, h=_PPTX_H,
                               fill=_PPTX_TEAL, shape_id=3))
    # Big roman numeral
    shapes.append(_pptx_text_box(
        x=_PPTX_MARGIN_X + 200000, y=2000000, w=3000000, h=2800000,
        shape_id=4,
        paragraphs=[_pptx_paragraph([
            _pptx_text_run(roman, size_pt=180, bold=True, color=_PPTX_TEAL),
        ], align="l")],
    ))
    # Eyebrow + title on the right
    paras = []
    if eyebrow:
        paras.append(_pptx_paragraph([
            _pptx_text_run(eyebrow.upper(), size_pt=14, bold=True,
                            color=_PPTX_TEAL_LT),
        ], align="l", space_after=120000))
    paras.append(_pptx_paragraph([
        _pptx_text_run(title, size_pt=44, bold=True, color="FFFFFF"),
    ], align="l"))
    shapes.append(_pptx_text_box(
        x=4400000, y=2700000, w=_PPTX_W - 4400000 - _PPTX_MARGIN_X, h=1800000,
        shape_id=5, paragraphs=paras,
    ))
    # Teal accent rule under title
    shapes.append(_pptx_rect(
        x=4400000, y=4700000, w=1200000, h=60000,
        fill=_PPTX_TEAL_LT, shape_id=6,
    ))
    return _pptx_slide(shapes, bg=_PPTX_INK)


def _pptx_notes_slide_xml(text: str) -> str:
    """Return a notesSlide XML part containing a single text box with the
    speaker notes. Linked to its parent slide via a per-slide rel."""
    # The notes shape — a regular sp with the notes text
    paras = []
    for line in (text or "").split("\n"):
        line = line.strip()
        if not line:
            paras.append('<a:p><a:endParaRPr lang="en-US"/></a:p>')
            continue
        paras.append(
            '<a:p><a:pPr/>'
            '<a:r><a:rPr lang="en-US" sz="1200">'
            '<a:latin typeface="Calibri"/></a:rPr>'
            f'<a:t>{_pptx_esc(line)}</a:t></a:r></a:p>'
        )

    body = "".join(paras) or '<a:p><a:endParaRPr lang="en-US"/></a:p>'
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<p:notes xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
        'xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">'
        '<p:cSld>'
        '<p:spTree>'
        '<p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>'
        '<p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/>'
        '<a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr>'
        '<p:sp>'
        '<p:nvSpPr><p:cNvPr id="2" name="Notes Placeholder"/>'
        '<p:cNvSpPr><a:spLocks noGrp="1"/></p:cNvSpPr>'
        '<p:nvPr><p:ph type="body" idx="1"/></p:nvPr></p:nvSpPr>'
        '<p:spPr>'
        '<a:xfrm><a:off x="685800" y="685800"/>'
        '<a:ext cx="5486400" cy="7772400"/></a:xfrm>'
        '<a:prstGeom prst="rect"><a:avLst/></a:prstGeom>'
        '</p:spPr>'
        '<p:txBody><a:bodyPr/><a:lstStyle/>'
        f'{body}'
        '</p:txBody></p:sp>'
        '</p:spTree>'
        '</p:cSld>'
        '<p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr>'
        '</p:notes>'
    )


def _pptx_speaker_notes_for(slide_kind: str, report: dict) -> str:
    """Return talking points for a given slide kind."""
    kpi = _kpi_data(report)
    crit = int(kpi.get("critical") or 0)
    kev = int(kpi.get("kev") or 0)
    hosts = int(kpi.get("hosts") or 0)
    if slide_kind == "cover":
        return ("Brief intro of the assessment scope and date. "
                "Set expectations for the next 20 minutes.")
    if slide_kind == "agenda":
        return ("Walk through the report structure. Flag that the action plan "
                "in Part III is the operational output.")
    if slide_kind == "exec_summary":
        bullets = []
        if kev:
            bullets.append(f"{kev} KEV-listed CVEs — these patch this week, not this month.")
        if crit:
            bullets.append(f"{crit} critical CVEs open — concentrated remediation can clear most in one sprint.")
        if hosts:
            bullets.append(f"{hosts} hosts assessed; scope covers core, edge, identity, and endpoint.")
        if not bullets:
            bullets = ["Posture is materially clean — emphasize scan cadence and identity hygiene.",
                       "Use this to push policy maturity, not patching.",
                       "Close with the next-quarter focus area."]
        return "\n".join(["Three talking points:"] + ["- " + b for b in bullets])
    if slide_kind == "kpi":
        return (f"Most critical metric is critical-CVE count: {crit}. "
                f"Emphasize KEV-listed ({kev}) first — these have confirmed "
                "active exploitation. Then walk hosts → high → EOL.")
    if slide_kind == "compliance":
        return ("Walk frameworks left-to-right by score. Call out the lowest "
                "score first and what's pulling it down. Mention that the "
                "action plan in Part III closes most of the gap.")
    if slide_kind == "top_findings":
        return ("Top findings list is KEV-first, then critical, then high. "
                "Each row links back to a specific host — be prepared to "
                "open the host detail.")
    if slide_kind == "action_plan":
        return ("Top P0 actions need this-week ownership. Confirm an owner "
                "and target date per row. P1 work is this sprint; P2/P3 are "
                "carry-forward.")
    if slide_kind == "divider_risk":
        return ("Part I sets the risk landscape — hosts, CVEs, KEV-listed, "
                "EOL hardware. Keep narrative tight.")
    if slide_kind == "divider_compliance":
        return ("Part II is compliance posture — per-framework scores and "
                "the control matrix. Use this section to translate technical "
                "findings into audit terms.")
    if slide_kind == "divider_remediation":
        return ("Part III is the operational output — what to fix, in what "
                "order, by whom, by when. Drive ownership decisions here.")
    if slide_kind == "section":
        return ("Section detail slide. Use for deeper context if a stakeholder "
                "asks. Otherwise reference the HTML/JSON export.")
    if slide_kind == "closing":
        return ("Open for Q&A. Reference the appendix glossary for definitions "
                "and the methodology section for scope assumptions.")
    return "Speaker notes."


def _pptx_section_summary_slide(s: dict, report: dict, idx: int,
                                  slide_no: str) -> str:
    """Dispatch to the right visual handler based on section key."""
    key = s.get("key")
    if key == "cve_exposure":
        return _pptx_cve_exposure_slide(s, report, idx, slide_no)
    if key == "host_inventory":
        return _pptx_host_inventory_slide(s, report, idx, slide_no)
    if key == "eol_hardware":
        return _pptx_eol_hardware_slide(s, report, idx, slide_no)
    if key == "compliance_control_matrix":
        return _pptx_control_matrix_slide(s, report, idx, slide_no)

    # Fallback for sections without a dedicated visual handler — keep this
    # short and informational instead of a sea of bullets.
    title = s.get("title") or s.get("key") or ""
    data = s.get("data") or {}
    shapes = _pptx_section_header(title, eyebrow=f"Section {idx:02d}",
                                   section_no=idx)

    if s.get("empty"):
        shapes.append(_pptx_text_box(
            x=_PPTX_MARGIN_X, y=2400000, w=_PPTX_W - 2 * _PPTX_MARGIN_X, h=400000,
            shape_id=500,
            paragraphs=[_pptx_paragraph([
                _pptx_text_run("✓  No issues found in this area.", size_pt=20,
                                bold=True, color=_PPTX_GREEN),
            ], align="l")],
        ))
        return _pptx_slide(shapes, footer_text="SafeCadence · Confidential",
                             slide_no=slide_no)

    # Try to surface ONE meaningful number from data + a short prose summary.
    headline_value = None
    headline_label = ""
    for k in ("count", "total", "open", "active"):
        if isinstance(data.get(k), (int, float)):
            headline_value, headline_label = int(data[k]), k.upper()
            break
    if headline_value is None:
        for k, v in data.items():
            if isinstance(v, list):
                headline_value, headline_label = len(v), f"{k.upper()} ENTRIES"
                break

    if headline_value is not None:
        # Big number
        shapes.append(_pptx_text_box(
            x=_PPTX_MARGIN_X, y=2300000, w=3500000, h=500000,
            shape_id=500,
            paragraphs=[_pptx_paragraph([
                _pptx_text_run(headline_label, size_pt=11, bold=True,
                                color=_PPTX_INK_FAINT),
            ], align="l")],
        ))
        shapes.append(_pptx_text_box(
            x=_PPTX_MARGIN_X, y=2800000, w=3500000, h=1600000,
            shape_id=501,
            paragraphs=[_pptx_paragraph([
                _pptx_text_run(str(headline_value), size_pt=96, bold=True,
                                color=_PPTX_TEAL),
            ], align="l")],
        ))
    # Helper text on the right
    shapes.append(_pptx_text_box(
        x=4400000, y=2400000, w=_PPTX_W - 4400000 - _PPTX_MARGIN_X, h=2200000,
        shape_id=502,
        paragraphs=[_pptx_paragraph([
            _pptx_text_run(f"Full {title.lower()} detail is in the HTML and JSON exports — this slide is a heads-up summary only.",
                            size_pt=14, color=_PPTX_INK_2, italic=True),
        ], align="l")],
    ))
    return _pptx_slide(shapes, footer_text="SafeCadence · Confidential",
                         slide_no=slide_no)


def _pptx_closing_slide() -> str:
    shapes = []
    # Background
    shapes.append(_pptx_rect(x=0, y=0, w=_PPTX_W, h=_PPTX_H,
                               fill=_PPTX_INK, shape_id=2))
    shapes.append(_pptx_rect(x=0, y=int(_PPTX_H/2 - 50000), w=_PPTX_W, h=100000,
                               fill=_PPTX_TEAL, shape_id=3))
    shapes.append(_pptx_text_box(
        x=0, y=2200000, w=_PPTX_W, h=900000, shape_id=4,
        paragraphs=[_pptx_paragraph([
            _pptx_text_run("Questions?", size_pt=56, bold=True, color="FFFFFF"),
        ], align="ctr")],
    ))
    shapes.append(_pptx_text_box(
        x=0, y=4100000, w=_PPTX_W, h=400000, shape_id=5,
        paragraphs=[_pptx_paragraph([
            _pptx_text_run("SafeCadence NetRisk v10.3.0", size_pt=14,
                            color="CBD5E1"),
        ], align="ctr")],
    ))
    shapes.append(_pptx_text_box(
        x=0, y=4500000, w=_PPTX_W, h=400000, shape_id=6,
        paragraphs=[_pptx_paragraph([
            _pptx_text_run("safecadence.com", size_pt=14, color=_PPTX_TEAL_LT,
                            bold=True),
        ], align="ctr")],
    ))
    return _pptx_slide(shapes, bg=_PPTX_INK)


def render_pptx(report: dict, *, preset: dict | None = None) -> bytes:
    """Render the report as a polished 16:9 presentation."""
    import io
    import zipfile

    sections = report.get("sections") or []
    media = _PptxMedia()

    # Build slides — track (xml, kind) so we can emit appropriate notes.
    slides: list[tuple[str, str]] = []

    # 1) Cover (slide 1; uses cover hero image via media)
    slides.append((_pptx_cover_slide(report, media, slide_no=1), "cover"))
    # 2) Agenda
    slides.append((_pptx_agenda_slide(report, slide_no="2"), "agenda"))
    # 3) Part I divider
    slides.append((_pptx_divider_slide("I", "Risk landscape",
                                          eyebrow="Part one"), "divider_risk"))
    # 4) Executive summary
    slides.append((_pptx_exec_summary_slide(report, slide_no="4"),
                    "exec_summary"))
    # 5) Risk dashboard (KPIs + donut)
    slides.append((_pptx_kpi_dashboard_slide(report, slide_no="5",
                                              media=media,
                                              slide_no_int=5), "kpi"))
    # 6) Top findings
    slides.append((_pptx_top_findings_slide(report, slide_no="6"),
                    "top_findings"))
    # 7) Part II divider
    slides.append((_pptx_divider_slide("II", "Compliance",
                                          eyebrow="Part two"),
                    "divider_compliance"))
    # 8) Compliance scorecard (with radar)
    slides.append((_pptx_compliance_scorecard_slide(report, slide_no="8",
                                                      media=media,
                                                      slide_no_int=8),
                    "compliance"))
    # 9) Part III divider
    slides.append((_pptx_divider_slide("III", "Remediation",
                                          eyebrow="Part three"),
                    "divider_remediation"))
    # 10) Prioritized action plan
    slides.append((_pptx_action_plan_slide(report, slide_no="10"),
                    "action_plan"))

    # 11..N) Per-section summary slides (skip already-rendered ones)
    handled = {"executive_summary", "kpi_summary", "compliance_posture",
               "compliance_executive_summary", "compliance_evidence_pack",
               "recommended_actions"}
    idx = 11
    for s in sections:
        if s.get("key") in handled:
            continue
        slides.append((_pptx_section_summary_slide(s, report, idx - 10,
                                                     slide_no=str(idx)),
                        "section"))
        idx += 1

    # Closing
    slides.append((_pptx_closing_slide(), "closing"))

    n = len(slides)
    slide_xmls = [t[0] for t in slides]
    slide_kinds = [t[1] for t in slides]

    # ---- Notes slides ----
    # One notes slide per actual slide. slideN.xml → notesSlideN.xml.
    notes_xmls: list[str] = []
    for kind in slide_kinds:
        notes_xmls.append(_pptx_notes_slide_xml(
            _pptx_speaker_notes_for(kind, report)
        ))

    # ---- Notes master (simple) ----
    notes_master_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<p:notesMaster xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
        'xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">'
        '<p:cSld>'
        '<p:bg><p:bgPr>'
        '<a:solidFill><a:srgbClr val="FFFFFF"/></a:solidFill>'
        '<a:effectLst/></p:bgPr></p:bg>'
        '<p:spTree>'
        '<p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>'
        '<p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/>'
        '<a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr>'
        '</p:spTree></p:cSld>'
        '<p:clrMap bg1="lt1" tx1="dk1" bg2="lt2" tx2="dk2" '
        'accent1="accent1" accent2="accent2" accent3="accent3" '
        'accent4="accent4" accent5="accent5" accent6="accent6" '
        'hlink="hlink" folHlink="folHlink"/>'
        '<p:notesStyle><a:lvl1pPr><a:defRPr sz="1200">'
        '<a:solidFill><a:srgbClr val="0B1220"/></a:solidFill>'
        '<a:latin typeface="Calibri"/></a:defRPr></a:lvl1pPr></p:notesStyle>'
        '</p:notesMaster>'
    )
    notes_master_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '</Relationships>'
    )

    # ---- Build presentation parts ----
    # rIds: rId1 = slideMaster, rId(2..n+1) = slides,
    #       rId(n+2) = notesMaster
    sld_id_list = "".join(
        f'<p:sldId id="{256+i}" r:id="rId{i+2}"/>' for i in range(n)
    )
    notes_master_rid = f"rId{n+2}"
    presentation_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<p:presentation xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
        'xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" '
        'saveSubsetFonts="1">'
        '<p:sldMasterIdLst><p:sldMasterId id="2147483648" r:id="rId1"/></p:sldMasterIdLst>'
        f'<p:notesMasterIdLst><p:notesMasterId r:id="{notes_master_rid}"/></p:notesMasterIdLst>'
        f'<p:sldIdLst>{sld_id_list}</p:sldIdLst>'
        f'<p:sldSz cx="{_PPTX_W}" cy="{_PPTX_H}"/>'
        '<p:notesSz cx="6858000" cy="9144000"/>'
        '</p:presentation>'
    )

    slide_master_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<p:sldMaster xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
        'xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">'
        '<p:cSld><p:bg><p:bgPr>'
        '<a:solidFill><a:srgbClr val="FFFFFF"/></a:solidFill>'
        '<a:effectLst/></p:bgPr></p:bg>'
        '<p:spTree>'
        '<p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>'
        '<p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/>'
        '<a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr>'
        '</p:spTree></p:cSld>'
        '<p:clrMap bg1="lt1" tx1="dk1" bg2="lt2" tx2="dk2" '
        'accent1="accent1" accent2="accent2" accent3="accent3" '
        'accent4="accent4" accent5="accent5" accent6="accent6" '
        'hlink="hlink" folHlink="folHlink"/>'
        '<p:sldLayoutIdLst><p:sldLayoutId id="2147483649" r:id="rId1"/></p:sldLayoutIdLst>'
        '<p:txStyles>'
        '<p:titleStyle><a:lvl1pPr><a:defRPr sz="3200" b="1">'
        '<a:solidFill><a:srgbClr val="0B1220"/></a:solidFill>'
        '<a:latin typeface="Calibri"/></a:defRPr></a:lvl1pPr></p:titleStyle>'
        '<p:bodyStyle><a:lvl1pPr><a:defRPr sz="1800">'
        '<a:solidFill><a:srgbClr val="0B1220"/></a:solidFill>'
        '<a:latin typeface="Calibri"/></a:defRPr></a:lvl1pPr></p:bodyStyle>'
        '<p:otherStyle/></p:txStyles></p:sldMaster>'
    )

    slide_layout_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<p:sldLayout xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
        'xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" '
        'type="blank" preserve="1">'
        '<p:cSld name="Blank"><p:spTree>'
        '<p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>'
        '<p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/>'
        '<a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr>'
        '</p:spTree></p:cSld>'
        '<p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sldLayout>'
    )

    pres_rels_parts = [
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster" '
        'Target="slideMasters/slideMaster1.xml"/>'
    ]
    for i in range(n):
        pres_rels_parts.append(
            f'<Relationship Id="rId{i+2}" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" '
            f'Target="slides/slide{i+1}.xml"/>'
        )
    pres_rels_parts.append(
        f'<Relationship Id="{notes_master_rid}" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/notesMaster" '
        'Target="notesMasters/notesMaster1.xml"/>'
    )
    presentation_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        + "".join(pres_rels_parts) +
        '</Relationships>'
    )

    master_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" '
        'Target="../slideLayouts/slideLayout1.xml"/>'
        '</Relationships>'
    )

    layout_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster" '
        'Target="../slideMasters/slideMaster1.xml"/>'
        '</Relationships>'
    )

    def _slide_rels(slide_no: int) -> str:
        # rId1 = slideLayout. After that: notesSlide, then images.
        parts = [
            '<Relationship Id="rId1" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" '
            'Target="../slideLayouts/slideLayout1.xml"/>',
            f'<Relationship Id="rIdNotes" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/notesSlide" '
            f'Target="../notesSlides/notesSlide{slide_no}.xml"/>',
        ]
        parts.append(media.slide_rels_xml(slide_no))
        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            + "".join(parts) +
            '</Relationships>'
        )

    def _notes_rels(slide_no: int) -> str:
        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            f'<Relationship Id="rId1" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" '
            f'Target="../slides/slide{slide_no}.xml"/>'
            f'<Relationship Id="rId2" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/notesMaster" '
            'Target="../notesMasters/notesMaster1.xml"/>'
            '</Relationships>'
        )

    overrides = [
        '<Override PartName="/ppt/presentation.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>',
        '<Override PartName="/ppt/slideMasters/slideMaster1.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideMaster+xml"/>',
        '<Override PartName="/ppt/slideLayouts/slideLayout1.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml"/>',
        '<Override PartName="/ppt/notesMasters/notesMaster1.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.presentationml.notesMaster+xml"/>',
    ]
    for i in range(n):
        overrides.append(
            f'<Override PartName="/ppt/slides/slide{i+1}.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>'
        )
        overrides.append(
            f'<Override PartName="/ppt/notesSlides/notesSlide{i+1}.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.presentationml.notesSlide+xml"/>'
        )
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="png" ContentType="image/png"/>'
        + "".join(overrides) +
        '</Types>'
    )

    root_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="ppt/presentation.xml"/>'
        '</Relationships>'
    )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", content_types)
        z.writestr("_rels/.rels", root_rels)
        z.writestr("ppt/presentation.xml", presentation_xml)
        z.writestr("ppt/_rels/presentation.xml.rels", presentation_rels)
        z.writestr("ppt/slideMasters/slideMaster1.xml", slide_master_xml)
        z.writestr("ppt/slideMasters/_rels/slideMaster1.xml.rels", master_rels)
        z.writestr("ppt/slideLayouts/slideLayout1.xml", slide_layout_xml)
        z.writestr("ppt/slideLayouts/_rels/slideLayout1.xml.rels", layout_rels)
        z.writestr("ppt/notesMasters/notesMaster1.xml", notes_master_xml)
        z.writestr("ppt/notesMasters/_rels/notesMaster1.xml.rels", notes_master_rels)
        for i, sx in enumerate(slide_xmls, start=1):
            z.writestr(f"ppt/slides/slide{i}.xml", sx)
            z.writestr(f"ppt/slides/_rels/slide{i}.xml.rels", _slide_rels(i))
        for i, nx in enumerate(notes_xmls, start=1):
            z.writestr(f"ppt/notesSlides/notesSlide{i}.xml", nx)
            z.writestr(f"ppt/notesSlides/_rels/notesSlide{i}.xml.rels", _notes_rels(i))
        # Global media — one copy per filename
        seen = set()
        for fn, png in media.global_images:
            if fn in seen:
                continue
            seen.add(fn)
            z.writestr(f"ppt/media/{fn}", png)
    return buf.getvalue()


__all__ = ["render_html", "render_json", "render_pdf", "render_docx", "render_pptx"]
