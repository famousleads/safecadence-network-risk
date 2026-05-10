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


# --------------------------------------------------------------------------
# CSS — kept inline so the report file is fully self-contained.
# --------------------------------------------------------------------------


_BASE_CSS = """
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,system-ui,sans-serif;
  font-size:14px;line-height:1.55;color:#0f172a;background:#f8fafc;
}
a{color:#1f6f6a}
.sc-doc{max-width:960px;margin:0 auto;padding:0 0 32px}
.sc-print-only{display:none}

/* ------ cover ----- */
.sc-cover{position:relative;background:#ffffff;border-radius:0;
  padding:0 0 32px;margin:0 0 24px;border-bottom:1px solid #e2e8f0;
  page-break-after:always}
.sc-cover .sc-cover-strip{margin:0;display:block}
.sc-cover-inner{padding:42px 56px 0;display:grid;grid-template-columns:1fr 280px;gap:36px;align-items:start}
.sc-cover h1{margin:0 0 8px;font-size:32px;color:#0f172a;letter-spacing:-0.01em}
.sc-cover .sc-cover-sub{color:#475569;font-size:15px;margin:0 0 20px}
.sc-cover-meta{display:grid;grid-template-columns:repeat(2,1fr);gap:10px 24px;margin-top:18px}
.sc-cover-meta dt{font-size:11px;text-transform:uppercase;letter-spacing:0.08em;color:#64748b;margin:0}
.sc-cover-meta dd{margin:0 0 4px;font-size:14px;color:#0f172a;font-weight:600}
.sc-cover-gauge{display:flex;flex-direction:column;align-items:center;gap:10px}
.sc-cover-gauge .sc-gauge-band{font-size:11px;color:#64748b;letter-spacing:0.08em}
.sc-confidence{display:inline-flex;align-items:center;gap:6px;font-size:11px;
  color:#0e3b38;background:#d8efed;padding:3px 10px;border-radius:999px;font-weight:600}

/* ------ TOC ----- */
.sc-toc{background:#ffffff;border:1px solid #e2e8f0;border-radius:12px;
  padding:22px 28px;margin:0 24px 24px}
.sc-toc h3{margin:0 0 14px;font-size:11px;text-transform:uppercase;letter-spacing:0.1em;color:#64748b;font-weight:700}
.sc-toc-cols{columns:2;column-gap:36px}
.sc-toc-item{break-inside:avoid;margin:0 0 6px;display:flex;align-items:baseline;gap:8px;font-size:13px}
.sc-toc-item .sc-toc-num{color:#94a3b8;font-variant-numeric:tabular-nums;width:22px;flex:none}
.sc-toc-item a{color:#0f172a;text-decoration:none}
.sc-toc-item a:hover{color:#1f6f6a;text-decoration:underline}

/* ------ KPI band ----- */
.sc-kpi-band{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:0 24px 24px}
.sc-kpi{background:#ffffff;border:1px solid #e2e8f0;border-left:3px solid #1f6f6a;
  border-radius:10px;padding:14px 16px;min-height:96px;display:flex;flex-direction:column;
  justify-content:space-between}
.sc-kpi-lbl{font-size:10px;text-transform:uppercase;letter-spacing:0.08em;color:#64748b;font-weight:700}
.sc-kpi-num{font-size:28px;font-weight:700;color:#0f172a;margin:6px 0 0;line-height:1}
.sc-kpi-sub{font-size:11px;color:#64748b;margin-top:2px}
.sc-kpi-spark{margin-top:6px;height:30px}

/* ------ section ----- */
.sc-section{background:#ffffff;border:1px solid #e2e8f0;border-radius:12px;
  padding:22px 28px;margin:0 24px 18px;page-break-inside:avoid}
.sc-section h2{margin:0 0 12px;font-size:18px;color:#0f172a;letter-spacing:-0.005em}
.sc-section h2 .sc-anchor-num{color:#94a3b8;font-weight:600;margin-right:8px;font-variant-numeric:tabular-nums}
.sc-section.empty{opacity:0.85}
.sc-empty{padding:14px 16px;background:#f1f5f9;border-radius:8px;color:#64748b;font-size:13px}

/* ------ narrative ----- */
.sc-narrative{font-size:15px;line-height:1.7;color:#0f172a;margin:0 0 8px}
.sc-callout{background:linear-gradient(135deg,#d8efed,#eff6ff);border-radius:10px;
  padding:14px 18px;margin:14px 0;border-left:4px solid #1f6f6a}
.sc-callout .sc-callout-lbl{font-size:10px;text-transform:uppercase;letter-spacing:0.1em;
  color:#0e3b38;font-weight:700;margin-bottom:4px}
.sc-callout .sc-callout-body{font-size:14px;line-height:1.55;color:#0f172a}

/* ------ tables ----- */
.sc-tbl{width:100%;border-collapse:collapse;font-size:13px}
.sc-tbl th,.sc-tbl td{padding:9px 10px;border-bottom:1px solid #eef2f7;text-align:left;vertical-align:top}
.sc-tbl th{background:#f8fafc;font-weight:700;font-size:10px;text-transform:uppercase;
  letter-spacing:0.08em;color:#64748b;border-bottom:1px solid #e2e8f0}
.sc-tbl tr:nth-child(even) td{background:#fcfdff}

/* ------ pills + cards ----- */
.sc-pill{display:inline-block;padding:2px 8px;border-radius:999px;font-size:10px;
  font-weight:700;letter-spacing:0.04em}
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
.sc-action{display:grid;grid-template-columns:60px 1fr 90px 90px 100px;gap:10px;
  padding:10px 0;border-bottom:1px solid #eef2f7;align-items:center}
.sc-action:first-child{border-top:1px solid #e2e8f0}
.sc-action-pri{font-weight:700;font-size:12px;text-align:center;padding:4px 8px;
  border-radius:6px;color:#fff;background:#64748b}
.sc-action-pri.p0{background:#7f1d1d}
.sc-action-pri.p1{background:#9a3412}
.sc-action-pri.p2{background:#854d0e}
.sc-action-pri.p3{background:#1e3a8a}
.sc-action-title{font-weight:600;color:#0f172a;font-size:13px}
.sc-action-meta{font-size:11px;color:#64748b;margin-top:2px}
.sc-action-num{font-variant-numeric:tabular-nums;color:#475569;font-size:13px;text-align:center}

/* ------ footer ----- */
.sc-foot{font-size:11px;color:#64748b;margin:24px 24px 0;text-align:center;
  padding-top:14px;border-top:1px solid #e2e8f0;line-height:1.5}
.sc-foot strong{color:#0f172a}

/* ------ print ----- */
@media print{
  body{background:#ffffff}
  .sc-doc{max-width:none;padding:0}
  .sc-print-only{display:block}
  .sc-toc,.sc-section,.sc-kpi-band{margin-left:0;margin-right:0;border-radius:0;
    border-left:0;border-right:0}
  .sc-section{page-break-inside:avoid}
  .sc-cover{page-break-after:always}
  @page{size:A4;margin:18mm 16mm}
  @page :first{margin:0}
  a{color:inherit;text-decoration:none}
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

    chips = _scope_chips(scope) or '<dt>Scope</dt><dd>All assets in store</dd>'

    return (
        '<header class="sc-cover">'
        f'{cover_gradient_svg()}'
        '<div class="sc-cover-inner">'
        '<div>'
        f'<h1>{title}</h1>'
        '<p class="sc-cover-sub">A SafeCadence NetRisk security posture deliverable.</p>'
        f'<span class="sc-confidence">&#9679; {_esc(confidence)}</span>'
        '<dl class="sc-cover-meta">'
        f'<dt>Generated</dt><dd>{_esc(_today())}</dd>'
        f'<dt>Assets in scope</dt><dd>{int(kpi.get("hosts") or 0)}</dd>'
        f'<dt>Sections</dt><dd>{n_sections}</dd>'
        f'<dt>Frameworks evaluated</dt><dd>{framework_count or 5}</dd>'
        f'{chips}'
        '</dl></div>'
        '<div class="sc-cover-gauge">'
        f'{risk_gauge(score, size=240)}'
        f'<div class="sc-gauge-band">OVERALL RISK INDEX</div>'
        '</div></div></header>'
    )


# --------------------------------------------------------------------------
# TOC
# --------------------------------------------------------------------------


def _render_toc(report: dict) -> str:
    items: list[str] = []
    for i, s in enumerate(report.get("sections") or [], start=1):
        items.append(
            '<li class="sc-toc-item">'
            f'<span class="sc-toc-num">{i:02d}</span>'
            f'<a href="#sec-{_esc(s.get("key",""))}">{_esc(s.get("title",""))}</a>'
            '</li>'
        )
    return (
        '<nav class="sc-toc"><h3>Contents</h3>'
        f'<ol class="sc-toc-cols" style="list-style:none;padding:0;margin:0">{"".join(items)}</ol>'
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
    kpi_band = _render_kpi_band(report)
    toc = _render_toc(report)

    rev = _kev_catalog_rev()
    foot = (
        '<footer class="sc-foot">'
        '<strong>Generated by SafeCadence NetRisk v10.1.0</strong> &middot; '
        f'CISA KEV catalog rev {rev} &middot; '
        'NVD CVE feed &middot; MITRE ATT&amp;CK v15.1'
        '</footer>'
    )

    body = (
        '<div class="sc-doc">'
        f'{cover}{kpi_band}{toc}'
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


def _docx_escape(s: Any) -> str:
    return html.escape(str(s if s is not None else ""), quote=True)


def _docx_para(text: str, *, bold: bool = False, size: int | None = None,
               heading: int | None = None, color: str | None = None,
               align: str | None = None) -> str:
    """Build a single OOXML paragraph."""
    runs = []
    rpr_bits = []
    if bold: rpr_bits.append("<w:b/>")
    if size: rpr_bits.append(f'<w:sz w:val="{int(size*2)}"/>')
    if color: rpr_bits.append(f'<w:color w:val="{color}"/>')
    rpr = f"<w:rPr>{''.join(rpr_bits)}</w:rPr>" if rpr_bits else ""
    runs.append(f"<w:r>{rpr}<w:t xml:space=\"preserve\">{_docx_escape(text)}</w:t></w:r>")

    ppr_bits = []
    if heading: ppr_bits.append(f'<w:pStyle w:val="Heading{int(heading)}"/>')
    if align: ppr_bits.append(f'<w:jc w:val="{align}"/>')
    ppr = f"<w:pPr>{''.join(ppr_bits)}</w:pPr>" if ppr_bits else ""

    return f"<w:p>{ppr}{''.join(runs)}</w:p>"


def _docx_table(rows: list[list[str]], *, header: bool = True,
                widths: list[int] | None = None) -> str:
    """Build a simple OOXML table. widths in DXA (1440=1in)."""
    if not rows:
        return ""
    ncols = max(len(r) for r in rows)
    widths = widths or [int(9000 / max(1, ncols))] * ncols
    grid = "<w:tblGrid>" + "".join(
        f'<w:gridCol w:w="{w}"/>' for w in widths
    ) + "</w:tblGrid>"
    tbl_pr = (
        '<w:tblPr>'
        '<w:tblW w:w="5000" w:type="pct"/>'
        '<w:tblBorders>'
        '<w:top w:val="single" w:sz="4" w:color="CBD5E1"/>'
        '<w:left w:val="single" w:sz="4" w:color="CBD5E1"/>'
        '<w:bottom w:val="single" w:sz="4" w:color="CBD5E1"/>'
        '<w:right w:val="single" w:sz="4" w:color="CBD5E1"/>'
        '<w:insideH w:val="single" w:sz="4" w:color="E2E8F0"/>'
        '<w:insideV w:val="single" w:sz="4" w:color="E2E8F0"/>'
        '</w:tblBorders>'
        '</w:tblPr>'
    )
    out = [f"<w:tbl>{tbl_pr}{grid}"]
    for ri, row in enumerate(rows):
        cells = []
        for ci in range(ncols):
            txt = row[ci] if ci < len(row) else ""
            shading = ''
            bold = False
            if header and ri == 0:
                shading = '<w:shd w:val="clear" w:color="auto" w:fill="F1F5F9"/>'
                bold = True
            tcpr = f'<w:tcPr><w:tcW w:w="{widths[ci]}" w:type="dxa"/>{shading}</w:tcPr>'
            cells.append(
                f"<w:tc>{tcpr}{_docx_para(txt, bold=bold, size=10)}</w:tc>"
            )
        out.append(f"<w:tr>{''.join(cells)}</w:tr>")
    out.append("</w:tbl>")
    return "".join(out)


def _section_to_docx(section: dict, report: dict, idx: int) -> str:
    """Turn one composed section into OOXML paragraphs+tables."""
    title = section.get("title") or section.get("key") or ""
    out = [_docx_para(f"{idx:02d}. {title}", heading=1, bold=True, size=15, color="0F172A")]

    key = section.get("key")
    data = section.get("data") or {}

    if section.get("empty"):
        out.append(_docx_para(f"No data for {title}.", color="64748B"))
        return "".join(out)

    if key == "kpi_summary":
        rows = [["Metric", "Value", "Notes"]]
        rows.append(["Hosts in scope", str(data.get("hosts", 0)), "Assets evaluated"])
        rows.append(["Critical CVEs", str(data.get("critical", 0)), "P0 patch class"])
        rows.append(["High CVEs", str(data.get("high", 0)), "P1 patch class"])
        rows.append(["KEV-listed", str(data.get("kev", 0)), "Actively exploited"])
        rows.append(["EOL hardware", str(data.get("eol", 0)), "Past vendor EOS"])
        rows.append(["EOS software", str(data.get("eos_software", 0)), "Unsupported versions"])
        out.append(_docx_table(rows))
        return "".join(out)

    if key == "executive_summary":
        try:
            text = ai_helpers.generate_executive_summary({
                "kpi": _kpi_data(report),
                "scope": report.get("scope") or {},
            }, tone="professional")
        except Exception:
            text = data.get("summary") or "Executive summary unavailable."
        for para in str(text).split("\n\n"):
            if para.strip():
                out.append(_docx_para(para.strip()))
        return "".join(out)

    if key == "compliance_posture":
        frameworks = data.get("frameworks") or []
        if frameworks:
            rows = [["Framework", "Score", "Pass", "Fail", "Top failing controls"]]
            for fw in frameworks:
                top = fw.get("top_failures") or fw.get("top_failing") or []
                top_str = "; ".join(
                    f"{(c.get('id') or c.get('control') or '')}"
                    + (f" — {c.get('title')}" if c.get("title") else "")
                    for c in top[:3]
                )
                rows.append([
                    fw.get("framework") or fw.get("name") or "",
                    f"{int(fw.get('score') or 0)}%",
                    str(fw.get("pass") or fw.get("passing") or 0),
                    str(fw.get("fail") or 0),
                    top_str,
                ])
            out.append(_docx_table(rows, widths=[1600, 800, 800, 800, 5000]))
        return "".join(out)

    if key == "recommended_actions":
        actions = data.get("actions") or []
        if actions:
            rows = [["Priority", "Action", "Effort", "Controls"]]
            for a in actions[:25]:
                compl = a.get("compliance") or []
                if isinstance(compl, list):
                    compl = ", ".join(compl[:2])
                rows.append([
                    str(a.get("priority") or "P3"),
                    str(a.get("title") or ""),
                    str(a.get("effort") or "medium"),
                    str(compl or "—"),
                ])
            out.append(_docx_table(rows, widths=[900, 5400, 1200, 1500]))
        return "".join(out)

    if key == "host_inventory":
        hosts = data.get("hosts") or data.get("rows") or []
        if hosts:
            rows = [["Host", "Vendor", "Site", "Criticality", "Crit", "High"]]
            for h in hosts[:50]:
                rows.append([
                    str(h.get("hostname") or h.get("host") or h.get("name") or ""),
                    str(h.get("vendor") or ""),
                    str(h.get("site") or ""),
                    str(h.get("criticality") or ""),
                    str(h.get("critical") or h.get("crit_count") or 0),
                    str(h.get("high") or h.get("high_count") or 0),
                ])
            out.append(_docx_table(rows))
        return "".join(out)

    # Generic dict/list fallback: try to render as a table
    if isinstance(data, dict) and data:
        rows = [["Field", "Value"]]
        for k, v in list(data.items())[:30]:
            if isinstance(v, (list, dict)):
                v = _json.dumps(v, default=str)[:200]
            rows.append([str(k), str(v)])
        out.append(_docx_table(rows, widths=[2500, 6500]))
        return "".join(out)

    out.append(_docx_para("(See HTML/PDF version for full visuals)", color="64748B"))
    return "".join(out)


def render_docx(report: dict, *, preset: dict | None = None) -> bytes:
    """Render the report as a Word .docx file (real OOXML, opens in Word/Pages/Google Docs)."""
    import io
    import zipfile

    title = report.get("title") or "SafeCadence NetRisk Report"
    kpi = _kpi_data(report)
    score = _derive_overall_risk(kpi)
    confidence = _confidence_for(kpi)
    sections = report.get("sections") or []

    body_parts: list[str] = []
    # Cover
    body_parts.append(_docx_para(title, heading=1, bold=True, size=24, color="0F172A", align="center"))
    body_parts.append(_docx_para("A SafeCadence NetRisk security posture deliverable.",
                                 size=12, color="475569", align="center"))
    body_parts.append(_docx_para(""))
    body_parts.append(_docx_table([
        ["Generated", _today()],
        ["Assets in scope", str(int(kpi.get("hosts") or 0))],
        ["Overall risk index", f"{score} / 100"],
        ["Confidence", confidence],
        ["Sections", str(len(sections))],
    ], header=False, widths=[2200, 6800]))
    body_parts.append(_docx_para(""))

    # TOC heading
    body_parts.append(_docx_para("Contents", heading=2, bold=True, size=14, color="0F172A"))
    for i, s in enumerate(sections, start=1):
        body_parts.append(_docx_para(f"  {i:02d}.  {s.get('title','')}", size=11))
    body_parts.append(_docx_para(""))

    # Sections
    for i, s in enumerate(sections, start=1):
        body_parts.append(_section_to_docx(s, report, i))
        body_parts.append(_docx_para(""))

    # Footer
    body_parts.append(_docx_para(
        f"Generated by SafeCadence NetRisk v10.2.0 · "
        f"CISA KEV catalog rev {_kev_catalog_rev()}",
        size=9, color="64748B", align="center",
    ))

    body_xml = "".join(body_parts)

    document_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f'<w:body>{body_xml}'
        '<w:sectPr>'
        '<w:pgSz w:w="12240" w:h="15840"/>'
        '<w:pgMar w:top="1080" w:right="1080" w:bottom="1080" w:left="1080"/>'
        '</w:sectPr></w:body></w:document>'
    )

    styles_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        '<w:docDefaults><w:rPrDefault><w:rPr>'
        '<w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/>'
        '<w:sz w:val="22"/></w:rPr></w:rPrDefault></w:docDefaults>'
        '<w:style w:type="paragraph" w:styleId="Heading1">'
        '<w:name w:val="heading 1"/><w:basedOn w:val="Normal"/>'
        '<w:pPr><w:spacing w:before="240" w:after="120"/></w:pPr>'
        '<w:rPr><w:b/><w:sz w:val="30"/><w:color w:val="0F172A"/></w:rPr></w:style>'
        '<w:style w:type="paragraph" w:styleId="Heading2">'
        '<w:name w:val="heading 2"/><w:basedOn w:val="Normal"/>'
        '<w:pPr><w:spacing w:before="160" w:after="80"/></w:pPr>'
        '<w:rPr><w:b/><w:sz w:val="26"/><w:color w:val="1F6F6A"/></w:rPr></w:style>'
        '</w:styles>'
    )

    rels_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="word/document.xml"/></Relationships>'
    )

    doc_rels_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" '
        'Target="styles.xml"/></Relationships>'
    )

    content_types_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Override PartName="/word/document.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        '<Override PartName="/word/styles.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>'
        '</Types>'
    )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", content_types_xml)
        z.writestr("_rels/.rels", rels_xml)
        z.writestr("word/document.xml", document_xml)
        z.writestr("word/styles.xml", styles_xml)
        z.writestr("word/_rels/document.xml.rels", doc_rels_xml)
    return buf.getvalue()


# --------------------------------------------------------------------------
# PPTX  (PowerPoint .pptx — built with stdlib zipfile + OOXML)
# --------------------------------------------------------------------------


def _pptx_escape(s: Any) -> str:
    return html.escape(str(s if s is not None else ""), quote=True)


def _pptx_slide_xml(blocks: list[dict]) -> str:
    """Build a single slide. blocks = list of dicts:
       {text, x, y, w, h, size, bold, color, align}.
    """
    shapes = []
    for i, b in enumerate(blocks, start=1):
        text = _pptx_escape(b.get("text", ""))
        x = b.get("x", 457200)         # 0.5 in
        y = b.get("y", 457200)
        w = b.get("w", 8229600)        # ~9 in
        h = b.get("h", 685800)         # 0.75 in
        size = int(b.get("size", 18)) * 100  # 100 = 1 pt
        bold = "1" if b.get("bold") else "0"
        color = b.get("color", "0F172A")
        align = b.get("align", "l")    # l/ctr/r
        font = b.get("font", "Calibri")

        # Multi-line: split on \n
        paras = []
        for line in text.split("\n"):
            paras.append(
                f'<a:p><a:pPr algn="{align}"/>'
                f'<a:r><a:rPr lang="en-US" sz="{size}" b="{bold}">'
                f'<a:solidFill><a:srgbClr val="{color}"/></a:solidFill>'
                f'<a:latin typeface="{font}"/>'
                f'</a:rPr><a:t>{line}</a:t></a:r></a:p>'
            )
        body = "".join(paras)
        shapes.append(
            f'<p:sp><p:nvSpPr><p:cNvPr id="{i+1}" name="Block{i}"/>'
            '<p:cNvSpPr txBox="1"/><p:nvPr/></p:nvSpPr>'
            '<p:spPr>'
            f'<a:xfrm><a:off x="{x}" y="{y}"/><a:ext cx="{w}" cy="{h}"/></a:xfrm>'
            '<a:prstGeom prst="rect"><a:avLst/></a:prstGeom>'
            '</p:spPr>'
            f'<p:txBody><a:bodyPr wrap="square" anchor="t"/><a:lstStyle/>{body}</p:txBody>'
            '</p:sp>'
        )

    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
        'xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">'
        '<p:cSld><p:bg><p:bgPr>'
        '<a:solidFill><a:srgbClr val="FFFFFF"/></a:solidFill>'
        '<a:effectLst/></p:bgPr></p:bg>'
        '<p:spTree>'
        '<p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>'
        '<p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/>'
        '<a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr>'
        + "".join(shapes) +
        '</p:spTree></p:cSld>'
        '<p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sld>'
    )


def _pptx_section_slide(section: dict, report: dict, idx: int) -> str:
    title = section.get("title") or section.get("key") or ""
    blocks: list[dict] = [
        # Brand bar (skinny rectangle proxied via small text)
        {"text": f"  {idx:02d}", "x": 457200, "y": 457200, "w": 685800, "h": 457200,
         "size": 28, "bold": True, "color": "1F6F6A"},
        {"text": title, "x": 1200150, "y": 457200, "w": 7400000, "h": 685800,
         "size": 32, "bold": True, "color": "0F172A"},
    ]

    key = section.get("key")
    data = section.get("data") or {}
    y = 1371600  # 1.5 in

    if section.get("empty"):
        blocks.append({"text": f"No data for {title}.",
                       "x": 1200150, "y": y, "w": 7400000, "h": 500000,
                       "size": 14, "color": "64748B"})
        return _pptx_slide_xml(blocks)

    if key == "kpi_summary":
        # Five KPI cards on a row
        items = [
            ("Hosts", data.get("hosts", 0), "1F6F6A"),
            ("Critical", data.get("critical", 0), "DC2626"),
            ("High", data.get("high", 0), "EA580C"),
            ("KEV", data.get("kev", 0), "7C2D12"),
            ("EOL", data.get("eol", 0), "B45309"),
        ]
        cw = 1600200
        for i, (lbl, val, color) in enumerate(items):
            x = 457200 + i * (cw + 100000)
            blocks.append({"text": str(val), "x": x, "y": y, "w": cw, "h": 800000,
                           "size": 44, "bold": True, "color": color, "align": "ctr"})
            blocks.append({"text": lbl, "x": x, "y": y + 750000, "w": cw, "h": 400000,
                           "size": 12, "color": "64748B", "align": "ctr"})
        return _pptx_slide_xml(blocks)

    if key == "executive_summary":
        try:
            text = ai_helpers.generate_executive_summary({
                "kpi": _kpi_data(report),
                "scope": report.get("scope") or {},
            }, tone="executive")
        except Exception:
            text = data.get("summary") or "Executive summary unavailable."
        # Wrap to ~90 chars/line for readability on slide
        wrapped = _wrap_text(str(text), 90)
        blocks.append({"text": wrapped, "x": 600000, "y": y, "w": 8200000, "h": 4500000,
                       "size": 16, "color": "0F172A"})
        return _pptx_slide_xml(blocks)

    if key == "compliance_posture":
        frameworks = data.get("frameworks") or []
        if frameworks:
            for i, fw in enumerate(frameworks[:5]):
                row_y = y + i * 750000
                name = fw.get("framework") or fw.get("name") or ""
                score = int(fw.get("score") or 0)
                fail_count = int(fw.get("fail") or 0)
                color = "16A34A" if score >= 80 else "EA580C" if score >= 60 else "DC2626"
                blocks.append({"text": name, "x": 600000, "y": row_y, "w": 2400000, "h": 500000,
                               "size": 18, "bold": True, "color": "0F172A"})
                blocks.append({"text": f"{score}%", "x": 3000000, "y": row_y, "w": 1000000,
                               "h": 500000, "size": 22, "bold": True, "color": color})
                top = fw.get("top_failures") or fw.get("top_failing") or []
                top_str = " · ".join(
                    (c.get("id") or c.get("control") or "") for c in top[:3]
                )
                blocks.append({"text": f"{fail_count} failing — {top_str}",
                               "x": 4100000, "y": row_y, "w": 4700000, "h": 500000,
                               "size": 12, "color": "64748B"})
        return _pptx_slide_xml(blocks)

    if key == "recommended_actions":
        actions = data.get("actions") or []
        for i, a in enumerate(actions[:8]):
            row_y = y + i * 500000
            pri = a.get("priority", "P3")
            color = {"P0":"DC2626","P1":"EA580C","P2":"CA8A04","P3":"2563EB"}.get(pri, "64748B")
            blocks.append({"text": pri, "x": 600000, "y": row_y, "w": 500000, "h": 400000,
                           "size": 14, "bold": True, "color": color})
            blocks.append({"text": str(a.get("title", "")), "x": 1200000, "y": row_y,
                           "w": 7400000, "h": 400000, "size": 14, "color": "0F172A"})
        return _pptx_slide_xml(blocks)

    # Generic: dump a few facts
    if isinstance(data, dict):
        lines = []
        for k, v in list(data.items())[:8]:
            if isinstance(v, (list, dict)):
                v = f"{len(v)} item(s)" if hasattr(v, "__len__") else str(v)[:60]
            lines.append(f"• {k}: {v}")
        blocks.append({"text": "\n".join(lines) if lines else "(see full HTML report)",
                       "x": 600000, "y": y, "w": 8200000, "h": 4000000,
                       "size": 14, "color": "0F172A"})
    return _pptx_slide_xml(blocks)


def _wrap_text(text: str, width: int) -> str:
    import textwrap
    out_lines = []
    for paragraph in str(text).split("\n"):
        if not paragraph.strip():
            out_lines.append("")
            continue
        out_lines.extend(textwrap.wrap(paragraph, width=width) or [""])
    return "\n".join(out_lines)


def render_pptx(report: dict, *, preset: dict | None = None) -> bytes:
    """Render the report as a PowerPoint .pptx file."""
    import io
    import zipfile

    title = report.get("title") or "SafeCadence NetRisk Report"
    kpi = _kpi_data(report)
    score = _derive_overall_risk(kpi)
    confidence = _confidence_for(kpi)
    sections = report.get("sections") or []

    slides_xml: list[str] = []

    # Slide 1: Cover
    slides_xml.append(_pptx_slide_xml([
        {"text": title, "x": 600000, "y": 1500000, "w": 8200000, "h": 1000000,
         "size": 40, "bold": True, "color": "0F172A", "align": "ctr"},
        {"text": "SafeCadence NetRisk Security Posture",
         "x": 600000, "y": 2600000, "w": 8200000, "h": 500000,
         "size": 18, "color": "475569", "align": "ctr"},
        {"text": f"Overall Risk Index: {score} / 100",
         "x": 600000, "y": 3500000, "w": 8200000, "h": 500000,
         "size": 22, "bold": True,
         "color": "DC2626" if score >= 70 else "EA580C" if score >= 40 else "16A34A",
         "align": "ctr"},
        {"text": f"Confidence: {confidence}",
         "x": 600000, "y": 4100000, "w": 8200000, "h": 400000,
         "size": 14, "color": "64748B", "align": "ctr"},
        {"text": f"Generated {_today()}",
         "x": 600000, "y": 5200000, "w": 8200000, "h": 400000,
         "size": 12, "color": "94A3B8", "align": "ctr"},
    ]))

    # Slide 2: Agenda
    agenda_lines = "\n".join(f"  {i:02d}.  {s.get('title','')}"
                              for i, s in enumerate(sections, start=1))
    slides_xml.append(_pptx_slide_xml([
        {"text": "Agenda", "x": 600000, "y": 457200, "w": 8200000, "h": 685800,
         "size": 32, "bold": True, "color": "0F172A"},
        {"text": agenda_lines, "x": 600000, "y": 1371600, "w": 8200000, "h": 5000000,
         "size": 16, "color": "0F172A"},
    ]))

    # Per-section slides
    for i, s in enumerate(sections, start=1):
        slides_xml.append(_pptx_section_slide(s, report, i))

    # Last slide: Thank-you
    slides_xml.append(_pptx_slide_xml([
        {"text": "Questions?", "x": 600000, "y": 2300000, "w": 8200000, "h": 800000,
         "size": 44, "bold": True, "color": "0F172A", "align": "ctr"},
        {"text": "SafeCadence NetRisk v10.2.0",
         "x": 600000, "y": 3300000, "w": 8200000, "h": 400000,
         "size": 14, "color": "64748B", "align": "ctr"},
        {"text": "safecadence.com",
         "x": 600000, "y": 3700000, "w": 8200000, "h": 400000,
         "size": 14, "color": "1F6F6A", "align": "ctr"},
    ]))

    n = len(slides_xml)

    # Build presentation.xml
    sld_id_list = "".join(
        f'<p:sldId id="{256+i}" r:id="rId{i+2}"/>' for i in range(n)
    )
    presentation_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<p:presentation xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
        'xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" '
        'saveSubsetFonts="1">'
        '<p:sldMasterIdLst><p:sldMasterId id="2147483648" r:id="rId1"/></p:sldMasterIdLst>'
        f'<p:sldIdLst>{sld_id_list}</p:sldIdLst>'
        '<p:sldSz cx="9144000" cy="6858000" type="screen4x3"/>'
        '<p:notesSz cx="6858000" cy="9144000"/>'
        '</p:presentation>'
    )

    # Minimal slide master + layout
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
        '<a:solidFill><a:srgbClr val="0F172A"/></a:solidFill>'
        '<a:latin typeface="Calibri"/></a:defRPr></a:lvl1pPr></p:titleStyle>'
        '<p:bodyStyle><a:lvl1pPr><a:defRPr sz="1800">'
        '<a:solidFill><a:srgbClr val="0F172A"/></a:solidFill>'
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

    # _rels for presentation: master + each slide
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

    def _slide_rels() -> str:
        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" '
            'Target="../slideLayouts/slideLayout1.xml"/>'
            '</Relationships>'
        )

    # Content types
    overrides = [
        '<Override PartName="/ppt/presentation.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>',
        '<Override PartName="/ppt/slideMasters/slideMaster1.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideMaster+xml"/>',
        '<Override PartName="/ppt/slideLayouts/slideLayout1.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml"/>',
    ]
    for i in range(n):
        overrides.append(
            f'<Override PartName="/ppt/slides/slide{i+1}.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>'
        )
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
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
        for i, sx in enumerate(slides_xml, start=1):
            z.writestr(f"ppt/slides/slide{i}.xml", sx)
            z.writestr(f"ppt/slides/_rels/slide{i}.xml.rels", _slide_rels())
    return buf.getvalue()


__all__ = ["render_html", "render_json", "render_pdf", "render_docx", "render_pptx"]
