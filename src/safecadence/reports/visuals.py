"""
Reusable inline-SVG visual primitives for the SafeCadence NetRisk report.

Every function returns a self-contained ``str`` (HTML/SVG) — no JavaScript,
no external assets. Charts must render identically inside an ``<iframe
srcdoc>`` preview, a downloaded standalone HTML file, or a print/PDF
conversion.

Color palette (kept here so designers have one place to retune):

    Critical : #7f1d1d on #fee2e2
    High     : #9a3412 on #fef3c7
    Medium   : #854d0e on #fef9c3
    Low      : #1e3a8a on #dbeafe
    Pass/Safe: #14532d on #dcfce7
    KEV      : white on #dc2626
    Brand    : #1f6f6a / #2c8a82
"""

from __future__ import annotations

import html
import math
from typing import Any, Iterable


# --------------------------------------------------------------------------
# palette
# --------------------------------------------------------------------------


PALETTE: dict[str, dict[str, str]] = {
    "critical": {"fg": "#7f1d1d", "bg": "#fee2e2", "stroke": "#b91c1c"},
    "high":     {"fg": "#9a3412", "bg": "#fef3c7", "stroke": "#d97706"},
    "medium":   {"fg": "#854d0e", "bg": "#fef9c3", "stroke": "#ca8a04"},
    "low":      {"fg": "#1e3a8a", "bg": "#dbeafe", "stroke": "#2563eb"},
    "pass":     {"fg": "#14532d", "bg": "#dcfce7", "stroke": "#16a34a"},
    "info":     {"fg": "#0f172a", "bg": "#e2e8f0", "stroke": "#475569"},
    "kev":      {"fg": "#ffffff", "bg": "#dc2626", "stroke": "#7f1d1d"},
    "brand":    {"fg": "#0e3b38", "bg": "#d8efed", "stroke": "#1f6f6a"},
}

BRAND_TEAL = "#1f6f6a"
BRAND_TEAL_LIGHT = "#2c8a82"
COVER_GRADIENT = ("#0f172a", "#1e3a8a", "#1e40af")


def _esc(s: Any) -> str:
    return html.escape(str(s if s is not None else ""))


def _safe_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return default


def _clamp(v: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, v))


# --------------------------------------------------------------------------
# 1. Risk gauge (cover speedometer)
# --------------------------------------------------------------------------


def risk_gauge(score: int, *, size: int = 240) -> str:
    """Big half-circle speedometer 0..100. Higher score = redder needle."""
    score = int(_clamp(_safe_int(score), 0, 100))
    cx = size / 2
    cy = size * 0.62
    radius = size * 0.40
    stroke = size * 0.10

    # Color of needle / arc tip based on band.
    if score >= 80:
        fill = PALETTE["critical"]["stroke"]
        band = "Critical"
    elif score >= 60:
        fill = PALETTE["high"]["stroke"]
        band = "High"
    elif score >= 40:
        fill = PALETTE["medium"]["stroke"]
        band = "Medium"
    elif score >= 20:
        fill = PALETTE["low"]["stroke"]
        band = "Low"
    else:
        fill = PALETTE["pass"]["stroke"]
        band = "Minimal"

    def arc(start_deg: float, end_deg: float, color: str) -> str:
        a1 = math.radians(180 - start_deg)
        a2 = math.radians(180 - end_deg)
        x1 = cx + radius * math.cos(a1)
        y1 = cy - radius * math.sin(a1)
        x2 = cx + radius * math.cos(a2)
        y2 = cy - radius * math.sin(a2)
        large = 1 if (end_deg - start_deg) > 180 else 0
        return (
            f'<path d="M {x1:.2f} {y1:.2f} A {radius:.2f} {radius:.2f} '
            f'0 {large} 1 {x2:.2f} {y2:.2f}" stroke="{color}" '
            f'stroke-width="{stroke:.2f}" fill="none" stroke-linecap="round"/>'
        )

    bands = [
        (0, 20, PALETTE["pass"]["stroke"]),
        (20, 40, PALETTE["low"]["stroke"]),
        (40, 60, PALETTE["medium"]["stroke"]),
        (60, 80, PALETTE["high"]["stroke"]),
        (80, 100, PALETTE["critical"]["stroke"]),
    ]
    arcs = "".join(arc(b[0] * 1.8, b[1] * 1.8, b[2]) for b in bands)

    needle_angle = math.radians(180 - score * 1.8)
    nx = cx + (radius - stroke / 2) * math.cos(needle_angle)
    ny = cy - (radius - stroke / 2) * math.sin(needle_angle)
    needle = (
        f'<line x1="{cx:.2f}" y1="{cy:.2f}" x2="{nx:.2f}" y2="{ny:.2f}" '
        f'stroke="#0f172a" stroke-width="3" stroke-linecap="round"/>'
        f'<circle cx="{cx:.2f}" cy="{cy:.2f}" r="6" fill="#0f172a"/>'
    )

    label_y = cy + size * 0.18
    return (
        f'<svg viewBox="0 0 {size} {size * 0.85:.0f}" width="{size}" '
        f'role="img" aria-label="Overall risk gauge: {score} of 100, {band}" '
        f'xmlns="http://www.w3.org/2000/svg">'
        f'{arcs}{needle}'
        f'<text x="{cx}" y="{cy - 8}" text-anchor="middle" '
        f'font-size="{size * 0.22:.0f}" font-weight="700" fill="{fill}">{score}</text>'
        f'<text x="{cx}" y="{label_y:.0f}" text-anchor="middle" '
        f'font-size="{size * 0.07:.0f}" fill="#475569" '
        f'letter-spacing="0.08em">RISK · {band.upper()}</text>'
        '</svg>'
    )


# --------------------------------------------------------------------------
# 2. Severity donut
# --------------------------------------------------------------------------


def severity_donut(counts: dict, *, size: int = 220) -> str:
    """Donut chart of critical/high/medium/low counts."""
    order = ("critical", "high", "medium", "low")
    values = [(k, _safe_int(counts.get(k))) for k in order]
    total = sum(v for _, v in values) or 1
    cx, cy = size / 2, size / 2
    r_outer = size * 0.40
    r_inner = size * 0.26

    parts: list[str] = []
    legend: list[str] = []
    angle = -90.0
    for key, v in values:
        if v <= 0:
            continue
        sweep = (v / total) * 360
        a1 = math.radians(angle)
        a2 = math.radians(angle + sweep)
        large = 1 if sweep > 180 else 0
        x1 = cx + r_outer * math.cos(a1)
        y1 = cy + r_outer * math.sin(a1)
        x2 = cx + r_outer * math.cos(a2)
        y2 = cy + r_outer * math.sin(a2)
        x3 = cx + r_inner * math.cos(a2)
        y3 = cy + r_inner * math.sin(a2)
        x4 = cx + r_inner * math.cos(a1)
        y4 = cy + r_inner * math.sin(a1)
        d = (
            f"M {x1:.2f} {y1:.2f} "
            f"A {r_outer:.2f} {r_outer:.2f} 0 {large} 1 {x2:.2f} {y2:.2f} "
            f"L {x3:.2f} {y3:.2f} "
            f"A {r_inner:.2f} {r_inner:.2f} 0 {large} 0 {x4:.2f} {y4:.2f} Z"
        )
        parts.append(
            f'<path d="{d}" fill="{PALETTE[key]["stroke"]}" '
            f'aria-label="{key}: {v}"/>'
        )
        legend.append(
            f'<div class="sc-legend-row">'
            f'<span class="sc-legend-swatch" style="background:{PALETTE[key]["stroke"]}"></span>'
            f'{key.title()} <strong>{v}</strong></div>'
        )
        angle += sweep

    if not parts:
        parts.append(
            f'<circle cx="{cx}" cy="{cy}" r="{r_outer}" fill="#e5e7eb"/>'
            f'<circle cx="{cx}" cy="{cy}" r="{r_inner}" fill="#ffffff"/>'
        )

    center_text = (
        f'<text x="{cx}" y="{cy - 4}" text-anchor="middle" '
        f'font-size="{size * 0.16:.0f}" font-weight="700" fill="#0f172a">{total}</text>'
        f'<text x="{cx}" y="{cy + size * 0.10:.0f}" text-anchor="middle" '
        f'font-size="{size * 0.06:.0f}" fill="#475569" letter-spacing="0.06em">FINDINGS</text>'
    )

    svg = (
        f'<svg viewBox="0 0 {size} {size}" width="{size}" '
        f'role="img" aria-label="Severity breakdown donut chart" '
        f'xmlns="http://www.w3.org/2000/svg">{"".join(parts)}{center_text}</svg>'
    )
    return (
        f'<div class="sc-donut-wrap">{svg}'
        f'<div class="sc-legend">{"".join(legend) or "<em>No findings.</em>"}</div></div>'
    )


# --------------------------------------------------------------------------
# 3. Compliance radar (5-axis)
# --------------------------------------------------------------------------


def compliance_radar(frameworks: list, *, size: int = 320) -> str:
    """Radar/spider chart with one axis per framework."""
    if not frameworks:
        return '<div class="sc-empty"><em>No compliance data in scope.</em></div>'

    cx, cy = size / 2, size / 2
    radius = size * 0.36
    n = len(frameworks)

    grid_lines: list[str] = []
    for ring in (0.25, 0.5, 0.75, 1.0):
        pts: list[str] = []
        for i in range(n):
            a = -math.pi / 2 + 2 * math.pi * i / n
            x = cx + radius * ring * math.cos(a)
            y = cy + radius * ring * math.sin(a)
            pts.append(f"{x:.2f},{y:.2f}")
        grid_lines.append(
            f'<polygon points="{" ".join(pts)}" fill="none" '
            f'stroke="#cbd5e1" stroke-width="0.7"/>'
        )

    axes: list[str] = []
    labels: list[str] = []
    for i, fw in enumerate(frameworks):
        a = -math.pi / 2 + 2 * math.pi * i / n
        x = cx + radius * math.cos(a)
        y = cy + radius * math.sin(a)
        axes.append(
            f'<line x1="{cx}" y1="{cy}" x2="{x:.2f}" y2="{y:.2f}" '
            f'stroke="#e2e8f0" stroke-width="0.7"/>'
        )
        lx = cx + (radius + 18) * math.cos(a)
        ly = cy + (radius + 18) * math.sin(a)
        name = fw.get("framework") or fw.get("name") or ""
        labels.append(
            f'<text x="{lx:.2f}" y="{ly:.2f}" text-anchor="middle" '
            f'font-size="11" font-weight="600" fill="#334155">{_esc(name)}</text>'
        )

    pts: list[str] = []
    for i, fw in enumerate(frameworks):
        score = _safe_int(fw.get("score"))
        if not score:
            # derive from pass/fail when score missing
            p = _safe_int(fw.get("pass") or fw.get("passing"))
            f_ = _safe_int(fw.get("fail"))
            tot = p + f_
            score = int(round((p / tot) * 100)) if tot else 70
        score = int(_clamp(score, 0, 100))
        a = -math.pi / 2 + 2 * math.pi * i / n
        r = radius * (score / 100)
        x = cx + r * math.cos(a)
        y = cy + r * math.sin(a)
        pts.append(f"{x:.2f},{y:.2f}")

    polygon = (
        f'<polygon points="{" ".join(pts)}" fill="{BRAND_TEAL}" '
        f'fill-opacity="0.30" stroke="{BRAND_TEAL}" stroke-width="2"/>'
    )

    return (
        f'<svg viewBox="0 0 {size} {size}" width="{size}" '
        f'role="img" aria-label="Compliance posture radar across {n} frameworks" '
        f'xmlns="http://www.w3.org/2000/svg">'
        f'{"".join(grid_lines)}{"".join(axes)}{polygon}{"".join(labels)}'
        '</svg>'
    )


# --------------------------------------------------------------------------
# 4. Compliance heat-map
# --------------------------------------------------------------------------


def compliance_heatmap(controls: list) -> str:
    """Grid of small squares — green pass / red fail / amber partial."""
    if not controls:
        return '<div class="sc-empty"><em>No control data.</em></div>'

    cells: list[str] = []
    for c in controls:
        status = (c.get("status") or "").lower()
        if status in ("pass", "passing", "ok"):
            color = PALETTE["pass"]["stroke"]
            label = "Pass"
        elif status in ("partial", "warn", "warning"):
            color = PALETTE["medium"]["stroke"]
            label = "Partial"
        else:
            color = PALETTE["critical"]["stroke"]
            label = "Fail"
        title = (c.get("control") or c.get("id") or "")
        cells.append(
            f'<div class="sc-heat-cell" '
            f'style="background:{color}" '
            f'title="{_esc(title)} — {_esc(label)}"></div>'
        )

    legend = (
        f'<div class="sc-heat-legend">'
        f'<span><span class="sc-dot" style="background:{PALETTE["pass"]["stroke"]}"></span>Pass</span>'
        f'<span><span class="sc-dot" style="background:{PALETTE["medium"]["stroke"]}"></span>Partial</span>'
        f'<span><span class="sc-dot" style="background:{PALETTE["critical"]["stroke"]}"></span>Fail</span>'
        f'</div>'
    )
    return f'<div class="sc-heat-grid" role="img" aria-label="Control heat-map">{"".join(cells)}</div>{legend}'


# --------------------------------------------------------------------------
# 5. Severity bars
# --------------------------------------------------------------------------


def severity_bars(counts: dict, *, height: int = 120, width: int = 360) -> str:
    """Horizontal bar chart for severity counts."""
    order = ("critical", "high", "medium", "low")
    values = [(k, _safe_int(counts.get(k))) for k in order]
    total_max = max((v for _, v in values), default=0) or 1
    bar_h = (height - 16) / 4
    bars: list[str] = []
    label_w = 80
    bar_w_max = width - label_w - 50

    for i, (k, v) in enumerate(values):
        y = 4 + i * bar_h
        w = (v / total_max) * bar_w_max
        bars.append(
            f'<text x="0" y="{y + bar_h * 0.65:.1f}" font-size="11" '
            f'font-weight="600" fill="#334155">{k.title()}</text>'
            f'<rect x="{label_w}" y="{y:.1f}" width="{max(2, w):.1f}" height="{bar_h - 4:.1f}" '
            f'fill="{PALETTE[k]["stroke"]}" rx="3"/>'
            f'<text x="{label_w + max(2, w) + 6:.1f}" y="{y + bar_h * 0.65:.1f}" '
            f'font-size="11" fill="#0f172a" font-weight="700">{v}</text>'
        )
    return (
        f'<svg viewBox="0 0 {width} {height}" width="{width}" height="{height}" '
        f'role="img" aria-label="Severity bar chart" '
        f'xmlns="http://www.w3.org/2000/svg">{"".join(bars)}</svg>'
    )


# --------------------------------------------------------------------------
# 6. Sparkline
# --------------------------------------------------------------------------


def sparkline(values: list, *, color: str = BRAND_TEAL,
              width: int = 110, height: int = 30) -> str:
    """Small inline trend line."""
    nums = [float(v) for v in values if isinstance(v, (int, float))]
    if len(nums) < 2:
        return ""
    lo = min(nums)
    hi = max(nums)
    rng = (hi - lo) or 1.0
    step = width / (len(nums) - 1)
    pts: list[str] = []
    for i, v in enumerate(nums):
        x = i * step
        y = height - 2 - ((v - lo) / rng) * (height - 4)
        pts.append(f"{x:.1f},{y:.1f}")
    last_x, last_y = pts[-1].split(",")
    return (
        f'<svg viewBox="0 0 {width} {height}" width="{width}" height="{height}" '
        f'role="img" aria-label="Trend sparkline" '
        f'xmlns="http://www.w3.org/2000/svg">'
        f'<polyline points="{" ".join(pts)}" fill="none" stroke="{color}" '
        f'stroke-width="1.6" stroke-linejoin="round" stroke-linecap="round"/>'
        f'<circle cx="{last_x}" cy="{last_y}" r="2.2" fill="{color}"/>'
        '</svg>'
    )


# --------------------------------------------------------------------------
# 7. Attack-path graph
# --------------------------------------------------------------------------


def attack_path_graph(nodes: list, edges: list, *, width: int = 720, height: int = 280) -> str:
    """Layered network of nodes + arrows showing internet -> crown jewel."""
    if not nodes:
        return '<div class="sc-empty"><em>No attack paths in scope.</em></div>'

    # layout: bucket by 'tier' if present, otherwise even spread.
    tiers: dict[int, list[dict]] = {}
    for n in nodes:
        t = _safe_int(n.get("tier"), 0)
        tiers.setdefault(t, []).append(n)
    sorted_tiers = sorted(tiers.keys())
    if not sorted_tiers:
        sorted_tiers = [0]
        tiers[0] = nodes

    pos: dict[str, tuple[float, float]] = {}
    pad_x = 70
    col_w = (width - 2 * pad_x) / max(1, len(sorted_tiers) - 1) if len(sorted_tiers) > 1 else 0
    for ci, tier in enumerate(sorted_tiers):
        col = tiers[tier]
        col_h = height - 60
        for ri, n in enumerate(col):
            x = pad_x + ci * col_w if len(sorted_tiers) > 1 else width / 2
            y = 30 + (col_h * (ri + 1)) / (len(col) + 1)
            pos[n.get("id") or n.get("name") or f"n{ci}-{ri}"] = (x, y)

    # arrows
    defs = (
        '<defs><marker id="sc-arrow" viewBox="0 0 10 10" refX="9" refY="5" '
        'markerWidth="6" markerHeight="6" orient="auto-start-reverse">'
        f'<path d="M 0 0 L 10 5 L 0 10 z" fill="{PALETTE["critical"]["stroke"]}"/>'
        '</marker></defs>'
    )
    edge_svg: list[str] = []
    for e in edges or []:
        a = pos.get(e.get("from"))
        b = pos.get(e.get("to"))
        if not a or not b:
            continue
        dx = b[0] - a[0]
        cx1, cy1 = a[0] + dx * 0.5, a[1]
        cx2, cy2 = a[0] + dx * 0.5, b[1]
        edge_svg.append(
            f'<path d="M {a[0]:.1f} {a[1]:.1f} C {cx1:.1f} {cy1:.1f} '
            f'{cx2:.1f} {cy2:.1f} {b[0]:.1f} {b[1]:.1f}" stroke="#94a3b8" '
            f'stroke-width="1.6" fill="none" marker-end="url(#sc-arrow)" '
            'stroke-dasharray="4 3"/>'
        )

    node_svg: list[str] = []
    for n in nodes:
        nid = n.get("id") or n.get("name") or ""
        x, y = pos.get(nid, (0, 0))
        kind = (n.get("kind") or n.get("type") or "host").lower()
        if kind in ("internet", "external"):
            fill = PALETTE["critical"]["stroke"]
        elif kind in ("crown", "crown-jewel", "asset"):
            fill = BRAND_TEAL
        elif kind in ("dmz", "edge"):
            fill = PALETTE["high"]["stroke"]
        else:
            fill = PALETTE["info"]["stroke"]
        label = _esc(n.get("label") or nid)
        node_svg.append(
            f'<g><rect x="{x - 60:.1f}" y="{y - 16:.1f}" width="120" height="32" '
            f'rx="8" fill="{fill}" opacity="0.92"/>'
            f'<text x="{x:.1f}" y="{y + 4:.1f}" text-anchor="middle" '
            f'font-size="12" font-weight="600" fill="#ffffff">{label}</text></g>'
        )

    return (
        f'<svg viewBox="0 0 {width} {height}" width="100%" '
        f'role="img" aria-label="Attack path graph" '
        f'xmlns="http://www.w3.org/2000/svg">{defs}'
        f'{"".join(edge_svg)}{"".join(node_svg)}</svg>'
    )


# --------------------------------------------------------------------------
# 8. KPI card
# --------------------------------------------------------------------------


def kpi_card(label: str, value: Any, sub: str = "", tone: str = "info",
             spark: list | None = None) -> str:
    """Polished KPI card HTML (returns raw HTML, not SVG-only)."""
    p = PALETTE.get(tone) or PALETTE["info"]
    spark_html = sparkline(spark or [], color=p["stroke"]) if spark else ""
    sub_html = f'<div class="sc-kpi-sub">{_esc(sub)}</div>' if sub else ""
    return (
        f'<div class="sc-kpi" style="border-color:{p["stroke"]}33">'
        f'<div class="sc-kpi-lbl">{_esc(label)}</div>'
        f'<div class="sc-kpi-num" style="color:{p["fg"] if tone != "info" else "#0f172a"}">'
        f'{_esc(value)}</div>'
        f'{sub_html}'
        f'<div class="sc-kpi-spark">{spark_html}</div>'
        '</div>'
    )


# --------------------------------------------------------------------------
# 9. CVE badge
# --------------------------------------------------------------------------


def cve_badge(severity: str, *, kev: bool = False, exploit: bool = False) -> str:
    """Pill rendering severity + optional KEV / exploit-available badges."""
    sev = (severity or "").lower()
    p = PALETTE.get(sev) or PALETTE["info"]
    parts = [
        f'<span class="sc-pill" style="background:{p["bg"]};color:{p["fg"]};'
        f'border:1px solid {p["stroke"]}55">{_esc(sev.title() or "Info")}</span>'
    ]
    if kev:
        kp = PALETTE["kev"]
        parts.append(
            f'<span class="sc-pill" style="background:{kp["bg"]};color:{kp["fg"]};'
            f'font-weight:700">KEV</span>'
        )
    if exploit:
        parts.append(
            '<span class="sc-pill" style="background:#1e1b4b;color:#fff;'
            'font-weight:600">EXPLOIT</span>'
        )
    return '<span class="sc-pillrow">' + "".join(parts) + '</span>'


# --------------------------------------------------------------------------
# 10. Cover gradient strip
# --------------------------------------------------------------------------


def cover_gradient_svg(width: int = 1200, height: int = 70) -> str:
    """Top accent strip used on the cover page."""
    return (
        f'<svg viewBox="0 0 {width} {height}" width="100%" preserveAspectRatio="none" '
        f'aria-hidden="true" xmlns="http://www.w3.org/2000/svg">'
        '<defs><linearGradient id="sc-cov" x1="0%" y1="0%" x2="100%" y2="0%">'
        f'<stop offset="0%" stop-color="{COVER_GRADIENT[0]}"/>'
        f'<stop offset="55%" stop-color="{COVER_GRADIENT[1]}"/>'
        f'<stop offset="100%" stop-color="{COVER_GRADIENT[2]}"/>'
        '</linearGradient></defs>'
        f'<rect width="{width}" height="{height}" fill="url(#sc-cov)"/></svg>'
    )


__all__ = [
    "PALETTE", "BRAND_TEAL", "BRAND_TEAL_LIGHT",
    "risk_gauge", "severity_donut", "compliance_radar", "compliance_heatmap",
    "severity_bars", "sparkline", "attack_path_graph", "kpi_card", "cve_badge",
    "cover_gradient_svg",
]
