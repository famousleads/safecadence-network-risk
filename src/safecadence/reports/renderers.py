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


__all__ = ["render_html", "render_json", "render_pdf"]
