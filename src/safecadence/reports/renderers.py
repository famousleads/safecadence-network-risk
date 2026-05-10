"""
Report renderers — turn a composed report dict into HTML, JSON, or PDF.

These are *separate* from the original ``reports/html.py`` etc., which
operate on a single :class:`ScanResult`. The wizard renderers work on
the multi-section dict produced by :func:`safecadence.reports.builder.compose_report`.
"""

from __future__ import annotations

import html
import json as _json
from typing import Any


# --------------------------------------------------------------------------
# HTML
# --------------------------------------------------------------------------


_BASE_CSS = """
*{box-sizing:border-box}
body{font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,sans-serif;
     color:#0b1020;background:#f6f7fb;margin:0}
.sc-doc{max-width:980px;margin:0 auto;padding:32px 40px}
.sc-cover{background:#0b1020;color:#fff;border-radius:14px;padding:44px 36px;margin-bottom:24px}
.sc-cover h1{margin:0 0 6px;font-size:28px}
.sc-cover .sub{opacity:.8}
.sc-meta{display:flex;flex-wrap:wrap;gap:14px;margin-top:18px;font-size:12px;opacity:.85}
.sc-meta span{background:#1a2240;padding:4px 10px;border-radius:999px}
.sc-toc{background:#fff;border:1px solid #e5e7f0;border-radius:10px;padding:18px 22px;margin-bottom:22px}
.sc-toc h3{margin:0 0 10px;font-size:14px;text-transform:uppercase;letter-spacing:.06em;color:#5b6685}
.sc-toc ol{margin:0;padding-left:22px}
.sc-toc a{color:#0b1020;text-decoration:none}
.sc-toc a:hover{text-decoration:underline}
.sc-section{background:#fff;border:1px solid #e5e7f0;border-radius:10px;padding:22px 26px;margin-bottom:18px}
.sc-section h2{margin:0 0 12px;font-size:18px}
.sc-section.empty{opacity:.7}
.sc-empty{padding:14px;background:#f0f3fa;border-radius:8px;color:#5b6685}
.sc-kpi-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}
.sc-kpi{background:#f4f6fb;border-radius:8px;padding:14px;text-align:center}
.sc-kpi-num{font-size:24px;font-weight:700;color:#0b1020}
.sc-kpi-lbl{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:#5b6685;margin-top:4px}
.sc-tbl{width:100%;border-collapse:collapse;font-size:13px}
.sc-tbl th,.sc-tbl td{padding:8px 10px;border-bottom:1px solid #eef0f5;text-align:left;vertical-align:top}
.sc-tbl th{background:#f0f3fa;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:#5b6685}
.sc-tbl tr:nth-child(even) td{background:#fafbff}
.sc-pill{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:600}
.sc-pill-red{background:#fdecec;color:#b42318}
.sc-pill-green{background:#e9f6ec;color:#1f7a3a}
.sc-cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:10px}
.sc-card{background:#f4f6fb;border-radius:8px;padding:14px}
.sc-card h4{margin:0 0 6px;font-size:13px}
.sc-card ul{margin:6px 0 0;padding-left:18px;font-size:12px}
.sc-row{display:flex;gap:6px;flex-wrap:wrap}
.sc-narrative{font-size:15px;line-height:1.6;margin:0}
.sc-foot{font-size:11px;color:#5b6685;margin-top:24px;text-align:center}
@media print{
  body{background:#fff}
  .sc-doc{padding:0;max-width:none}
  .sc-cover{break-after:page;background:#0b1020 !important;-webkit-print-color-adjust:exact;print-color-adjust:exact}
  .sc-toc{break-after:page}
  .sc-section{break-inside:avoid;page-break-inside:avoid}
  .sc-section + .sc-section{margin-top:14px}
  @page{margin:18mm 16mm}
}
"""


def _escape(s: Any) -> str:
    return html.escape(str(s if s is not None else ""))


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
        chips.append(f"<span>{_escape(k)}: {_escape(v)}</span>")
    return "".join(chips)


def render_html(report: dict, *, standalone: bool = True) -> str:
    """Render the composed report as HTML.

    ``standalone=True`` returns a complete HTML document (with CSS) suitable
    for direct download or PDF conversion. ``standalone=False`` returns just
    the inner ``<div class="sc-doc">…</div>`` so it can be embedded in an
    iframe or another page.
    """
    title = _escape(report.get("title") or "SafeCadence NetRisk Report")
    generated = _escape(report.get("generated_at") or "")
    scope = report.get("scope") or {}

    sections = report.get("sections") or []
    toc_items = "".join(
        f'<li><a href="#sec-{_escape(s.get("key",""))}">{_escape(s.get("title",""))}</a></li>'
        for s in sections
    )

    section_blocks = []
    for s in sections:
        empty_cls = " empty" if s.get("empty") else ""
        body = s.get("html_fragment") or (
            f'<div class="sc-empty">No data for {_escape(s.get("title",""))}.</div>'
        )
        section_blocks.append(
            f'<section class="sc-section{empty_cls}" id="sec-{_escape(s.get("key",""))}">'
            f'<h2>{_escape(s.get("title",""))}</h2>{body}</section>'
        )

    chips = _scope_chips(scope)
    body = (
        '<div class="sc-doc">'
        f'<header class="sc-cover">'
        f'<h1>{title}</h1>'
        f'<div class="sub">Generated {generated}</div>'
        f'<div class="sc-meta">{chips}</div>'
        f'</header>'
        f'<nav class="sc-toc"><h3>Contents</h3><ol>{toc_items}</ol></nav>'
        + "".join(section_blocks) +
        '<footer class="sc-foot">Generated by SafeCadence NetRisk &middot; Local-first, never executes.</footer>'
        '</div>'
    )

    if not standalone:
        return body

    return (
        "<!doctype html><html lang=\"en\"><head>"
        f"<meta charset=\"utf-8\"><title>{title}</title>"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        f"<style>{_BASE_CSS}</style></head><body>{body}</body></html>"
    )


# --------------------------------------------------------------------------
# JSON
# --------------------------------------------------------------------------


def render_json(report: dict) -> str:
    """Pretty-printed deterministic JSON."""
    safe = _strip_html(report)
    return _json.dumps(safe, indent=2, sort_keys=True, default=str)


def _strip_html(report: dict) -> dict:
    """Return a copy of `report` without the html_fragment fields (JSON consumers
    rarely want them, and they bloat the file)."""
    out = dict(report)
    out["sections"] = []
    for s in report.get("sections") or []:
        c = {k: v for k, v in s.items() if k != "html_fragment"}
        out["sections"].append(c)
    return out


# --------------------------------------------------------------------------
# PDF
# --------------------------------------------------------------------------


def render_pdf(report: dict) -> bytes:
    """Render the report as PDF bytes.

    Uses ``weasyprint`` if available. Falls back to UTF-8 HTML bytes so the
    caller can rely on a browser print dialog. We never add weasyprint as
    a hard dependency.
    """
    html_doc = render_html(report, standalone=True)
    try:
        from weasyprint import HTML  # type: ignore
        return HTML(string=html_doc).write_pdf()
    except Exception:
        return html_doc.encode("utf-8")


__all__ = ["render_html", "render_json", "render_pdf"]
