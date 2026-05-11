"""
PNG chart renderer — produces small chart images for embedding into
DOCX / PPTX / PDF.

PIL-based. All functions return ``bytes`` containing a PNG file. If PIL is
unavailable, functions return ``None`` and callers should skip the embed
gracefully (text fallback already provided by the renderers).

Color palette mirrors the HTML report's CSS variables.
"""

from __future__ import annotations

import io
import math
from typing import Sequence

try:
    from PIL import Image, ImageDraw, ImageFont  # type: ignore
    _PIL_OK = True
except Exception:  # pragma: no cover
    _PIL_OK = False
    Image = ImageDraw = ImageFont = None  # type: ignore


# Brand palette (RGB tuples)
INK         = (15, 23, 42)
INK_2       = (30, 41, 59)
INK_SOFT    = (71, 85, 105)
INK_FAINT   = (100, 116, 139)
RULE        = (226, 232, 240)
BG          = (255, 255, 255)
BG_SOFT     = (248, 250, 252)
BG_TEAL     = (240, 253, 250)
TEAL        = (31, 111, 106)
TEAL_LT     = (95, 198, 188)
RED         = (220, 38, 38)
ORANGE      = (234, 88, 12)
AMBER       = (202, 138, 4)
GREEN       = (22, 163, 74)
BLUE        = (30, 64, 175)
DARKRED     = (127, 29, 29)
NAVY        = (11, 18, 32)


# Try to find a TrueType font; fall back to default if not available.
def _font(size: int, *, bold: bool = False):
    if not _PIL_OK:
        return None
    candidates = [
        "/System/Library/Fonts/Helvetica.ttc",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if bold
            else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf" if bold
            else "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans.ttf",
    ]
    for p in candidates:
        try:
            return ImageFont.truetype(p, size)
        except Exception:
            continue
    try:
        return ImageFont.load_default()
    except Exception:
        return None


def _to_png(img) -> bytes:
    buf = io.BytesIO()
    img.save(buf, format="PNG", optimize=True)
    return buf.getvalue()


def _antialias_scale() -> int:
    """Render at 2x then downsample for crisp anti-aliasing."""
    return 2


# --------------------------------------------------------------------------
# 1. Severity donut — given a dict of severity → count, draws a donut chart
# --------------------------------------------------------------------------

def severity_donut(counts: dict, *, size: int = 360) -> bytes | None:
    """Donut chart: critical/high/medium/low/info segments around the ring."""
    if not _PIL_OK:
        return None
    s = size * _antialias_scale()
    img = Image.new("RGB", (s, s), BG)
    d = ImageDraw.Draw(img)

    order = [("critical", RED), ("high", ORANGE), ("medium", AMBER),
             ("low", BLUE), ("info", INK_FAINT)]
    total = sum(max(0, int(counts.get(k, 0))) for k, _ in order) or 1
    cx, cy = s // 2, s // 2
    outer_r = int(s * 0.40)
    inner_r = int(s * 0.26)

    start = -90.0  # top
    for sev, color in order:
        v = max(0, int(counts.get(sev, 0)))
        if v == 0:
            continue
        sweep = 360.0 * v / total
        # Outer wedge
        d.pieslice([cx - outer_r, cy - outer_r, cx + outer_r, cy + outer_r],
                    start=start, end=start + sweep, fill=color)
        start += sweep
    # Cut out the center to make it a donut
    d.ellipse([cx - inner_r, cy - inner_r, cx + inner_r, cy + inner_r],
               fill=BG)

    # Center label: total
    f_big = _font(int(s * 0.16), bold=True)
    f_lbl = _font(int(s * 0.045), bold=True)
    txt = str(total)
    if f_big:
        bbox = d.textbbox((0, 0), txt, font=f_big)
        d.text((cx - (bbox[2] - bbox[0]) // 2, cy - (bbox[3] - bbox[1]) // 2 - 8),
               txt, fill=INK, font=f_big)
    if f_lbl:
        lbl = "FINDINGS"
        bbox = d.textbbox((0, 0), lbl, font=f_lbl)
        d.text((cx - (bbox[2] - bbox[0]) // 2, cy + int(s * 0.09)),
               lbl, fill=INK_FAINT, font=f_lbl)

    img = img.resize((size, size), Image.LANCZOS)
    return _to_png(img)


# --------------------------------------------------------------------------
# 2. Horizontal bar — used for vendor concentration / sites
# --------------------------------------------------------------------------

def hbar(items: Sequence[tuple], *, width: int = 720, height: int = 320,
         title: str = "", color = TEAL, max_items: int = 8) -> bytes | None:
    """Horizontal bar chart. items = [(label, value), ...]."""
    if not _PIL_OK or not items:
        return None
    items = list(items)[:max_items]
    s = _antialias_scale()
    W, H = width * s, height * s
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)

    f_title = _font(int(H * 0.055), bold=True)
    f_lbl   = _font(int(H * 0.046))
    f_val   = _font(int(H * 0.05), bold=True)

    # Title
    top = 24 * s
    if title and f_title:
        d.text((24 * s, top), title.upper(), fill=INK_FAINT, font=f_title)
        top += int(H * 0.10)

    label_w = int(W * 0.30)
    bar_x = label_w + 24 * s
    bar_max_w = W - bar_x - int(W * 0.10)
    max_val = max((v for _, v in items), default=1) or 1
    row_h = (H - top - 24 * s) // max(1, len(items))
    bar_h = int(row_h * 0.6)
    pad_y = (row_h - bar_h) // 2

    for i, (label, value) in enumerate(items):
        y = top + i * row_h + pad_y
        # Label
        if f_lbl:
            d.text((24 * s, y + bar_h // 4),
                   str(label)[:24], fill=INK, font=f_lbl)
        # Bar bg
        d.rectangle([bar_x, y, bar_x + bar_max_w, y + bar_h],
                    fill=RULE)
        # Bar fill
        w = int(bar_max_w * value / max_val)
        d.rectangle([bar_x, y, bar_x + max(8 * s, w), y + bar_h],
                    fill=color)
        # Value at end
        if f_val:
            d.text((bar_x + w + 12 * s, y + bar_h // 4),
                   str(value), fill=INK, font=f_val)

    img = img.resize((width, height), Image.LANCZOS)
    return _to_png(img)


# --------------------------------------------------------------------------
# 3. Compliance radar — framework scores on a polar chart
# --------------------------------------------------------------------------

def compliance_radar(frameworks: list, *, size: int = 420) -> bytes | None:
    """Radar plot with one axis per framework."""
    if not _PIL_OK or not frameworks:
        return None
    s = size * _antialias_scale()
    img = Image.new("RGB", (s, s), BG)
    d = ImageDraw.Draw(img)

    n = max(3, len(frameworks))
    cx, cy = s // 2, s // 2 + int(s * 0.02)
    radius = int(s * 0.36)

    # Grid rings (4)
    for ring in range(1, 5):
        rr = radius * ring // 4
        # Approximate the polygon for the ring
        pts = []
        for i in range(n):
            angle = -math.pi / 2 + 2 * math.pi * i / n
            pts.append((cx + rr * math.cos(angle), cy + rr * math.sin(angle)))
        d.polygon(pts, outline=RULE)

    # Spokes + labels
    f_lbl = _font(int(s * 0.034), bold=True)
    f_score = _font(int(s * 0.030), bold=True)
    for i, fw in enumerate(frameworks):
        angle = -math.pi / 2 + 2 * math.pi * i / n
        ex = cx + radius * math.cos(angle)
        ey = cy + radius * math.sin(angle)
        d.line([cx, cy, ex, ey], fill=RULE)
        # Label
        name = fw.get("framework") or fw.get("name") or "?"
        if f_lbl:
            tx = cx + (radius + int(s * 0.06)) * math.cos(angle)
            ty = cy + (radius + int(s * 0.06)) * math.sin(angle)
            bbox = d.textbbox((0, 0), name, font=f_lbl)
            tw = bbox[2] - bbox[0]; th = bbox[3] - bbox[1]
            d.text((tx - tw // 2, ty - th // 2), name, fill=INK, font=f_lbl)

    # Data polygon
    pts = []
    for i, fw in enumerate(frameworks):
        score = max(0, min(100, int(fw.get("score") or 0)))
        rr = radius * score / 100.0
        angle = -math.pi / 2 + 2 * math.pi * i / n
        pts.append((cx + rr * math.cos(angle), cy + rr * math.sin(angle)))
    if len(pts) >= 3:
        # Translucent teal polygon — emulate alpha by drawing on RGBA layer
        overlay = Image.new("RGBA", (s, s), (0, 0, 0, 0))
        od = ImageDraw.Draw(overlay)
        od.polygon(pts, fill=(31, 111, 106, 110), outline=TEAL)
        img = img.convert("RGBA")
        img.alpha_composite(overlay)
        img = img.convert("RGB")
        d = ImageDraw.Draw(img)
        # Vertex dots + per-vertex score
        for i, (x, y) in enumerate(pts):
            d.ellipse([x - 6, y - 6, x + 6, y + 6], fill=TEAL_LT, outline=TEAL)
            score = max(0, min(100, int(frameworks[i].get("score") or 0)))
            if f_score:
                d.text((x + 8, y - 14), f"{score}%", fill=TEAL, font=f_score)

    img = img.resize((size, size), Image.LANCZOS)
    return _to_png(img)


# --------------------------------------------------------------------------
# 4. Sparkline / trend
# --------------------------------------------------------------------------

def sparkline(values: list, *, width: int = 400, height: int = 80,
              color = TEAL) -> bytes | None:
    if not _PIL_OK or not values:
        return None
    s = _antialias_scale()
    W, H = width * s, height * s
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    vmin, vmax = min(values), max(values) or 1
    if vmax == vmin: vmax = vmin + 1
    margin = 12 * s
    plot_w = W - margin * 2
    plot_h = H - margin * 2
    pts = []
    n = len(values)
    for i, v in enumerate(values):
        x = margin + (plot_w * i // max(1, n - 1))
        y = margin + plot_h - int(plot_h * (v - vmin) / (vmax - vmin))
        pts.append((x, y))
    # Filled area
    if len(pts) >= 2:
        fill_pts = pts + [(pts[-1][0], H - margin), (pts[0][0], H - margin)]
        overlay = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        od = ImageDraw.Draw(overlay)
        od.polygon(fill_pts, fill=color + (60,))
        img = img.convert("RGBA")
        img.alpha_composite(overlay)
        img = img.convert("RGB")
        d = ImageDraw.Draw(img)
        d.line(pts, fill=color, width=4 * s)
        # Last point dot
        x, y = pts[-1]
        d.ellipse([x - 6 * s, y - 6 * s, x + 6 * s, y + 6 * s], fill=color)
    img = img.resize((width, height), Image.LANCZOS)
    return _to_png(img)


# --------------------------------------------------------------------------
# 5. Risk gauge — half-donut with needle
# --------------------------------------------------------------------------

def risk_gauge(score: int, *, size: int = 320) -> bytes | None:
    if not _PIL_OK:
        return None
    s = size * _antialias_scale()
    img = Image.new("RGB", (s, int(s * 0.6)), BG)
    d = ImageDraw.Draw(img)

    score = max(0, min(100, int(score)))
    cx, cy = s // 2, int(s * 0.55)
    r_out = int(s * 0.42)
    r_in = int(s * 0.30)

    # Track segments: green / amber / red
    segments = [(180, 240, GREEN), (240, 300, AMBER), (300, 360, RED)]
    for a, b, color in segments:
        # PIL angles are clockwise from 3 o'clock; convert from "compass-like" mapping
        d.pieslice([cx - r_out, cy - r_out, cx + r_out, cy + r_out],
                    start=a, end=b, fill=color)
    # Cut center to make ring
    d.pieslice([cx - r_in, cy - r_in, cx + r_in, cy + r_in],
                start=180, end=360, fill=BG)

    # Needle
    # Map 0..100 to 180..360 degrees
    angle_deg = 180 + 1.8 * score
    angle = math.radians(angle_deg)
    nx = cx + int(r_out * 0.92 * math.cos(angle))
    ny = cy + int(r_out * 0.92 * math.sin(angle))
    d.line([cx, cy, nx, ny], fill=INK, width=int(s * 0.012))
    d.ellipse([cx - 12, cy - 12, cx + 12, cy + 12], fill=INK)

    # Score text
    f_big = _font(int(s * 0.18), bold=True)
    f_sub = _font(int(s * 0.045), bold=True)
    score_str = str(score)
    if f_big:
        bbox = d.textbbox((0, 0), score_str, font=f_big)
        d.text((cx - (bbox[2] - bbox[0]) // 2, cy + int(s * 0.02)),
                score_str, fill=INK, font=f_big)
    if f_sub:
        sub = "/ 100"
        bbox = d.textbbox((0, 0), sub, font=f_sub)
        d.text((cx - (bbox[2] - bbox[0]) // 2, cy + int(s * 0.20)),
                sub, fill=INK_FAINT, font=f_sub)

    img = img.resize((size, int(size * 0.6)), Image.LANCZOS)
    return _to_png(img)


# --------------------------------------------------------------------------
# 6. Logo mark — brand glyph for cover / letterhead
# --------------------------------------------------------------------------

def logo_mark(*, size: int = 200, on_dark: bool = False) -> bytes | None:
    """A minimal abstract mark: a shielded "S" glyph in brand teal."""
    if not _PIL_OK:
        return None
    s = size * _antialias_scale()
    bg = NAVY if on_dark else BG
    img = Image.new("RGB", (s, s), bg)
    d = ImageDraw.Draw(img)

    cx, cy = s // 2, s // 2
    # Outer shield (rounded rect)
    r = int(s * 0.42)
    box = [cx - r, cy - r, cx + r, cy + r]
    d.rounded_rectangle(box, radius=int(s * 0.10), fill=TEAL)
    # Inner glyph: stylized "SC" mark — concentric arcs
    glyph_r1 = int(s * 0.30)
    glyph_r2 = int(s * 0.18)
    d.ellipse([cx - glyph_r1, cy - glyph_r1, cx + glyph_r1, cy + glyph_r1],
               outline=TEAL_LT, width=int(s * 0.025))
    d.pieslice([cx - glyph_r2, cy - glyph_r2, cx + glyph_r2, cy + glyph_r2],
                start=45, end=315, fill=TEAL_LT)
    img = img.resize((size, size), Image.LANCZOS)
    return _to_png(img)


# --------------------------------------------------------------------------
# 7. Cover hero — abstract network/dataflow graphic
# --------------------------------------------------------------------------

def cover_hero(*, width: int = 800, height: int = 500) -> bytes | None:
    """Abstract network mesh on dark navy gradient — used on PPT/Word cover."""
    if not _PIL_OK:
        return None
    s = _antialias_scale()
    W, H = width * s, height * s
    img = Image.new("RGB", (W, H), NAVY)
    d = ImageDraw.Draw(img)

    # Vertical gradient overlay → deep teal-tinged shadow
    overlay = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    od = ImageDraw.Draw(overlay)
    for i in range(0, H, 4):
        a = int(120 * (i / H))
        od.rectangle([0, i, W, i + 4], fill=(15, 58, 53, a))
    img = img.convert("RGBA")
    img.alpha_composite(overlay)
    img = img.convert("RGB")
    d = ImageDraw.Draw(img)

    # Abstract network: scatter of points + connecting lines
    import random
    rnd = random.Random(42)
    nodes = []
    for _ in range(36):
        x = rnd.randint(int(W * 0.05), int(W * 0.95))
        y = rnd.randint(int(H * 0.10), int(H * 0.90))
        nodes.append((x, y))
    # Connect nearest neighbors
    for i, (x1, y1) in enumerate(nodes):
        dists = sorted([(((x1 - x2) ** 2 + (y1 - y2) ** 2) ** 0.5, j)
                        for j, (x2, y2) in enumerate(nodes) if i != j])[:2]
        for _, j in dists:
            x2, y2 = nodes[j]
            d.line([x1, y1, x2, y2], fill=(31, 111, 106, 200), width=int(2 * s))
    # Nodes
    for x, y in nodes:
        d.ellipse([x - 6 * s, y - 6 * s, x + 6 * s, y + 6 * s],
                   fill=TEAL_LT, outline=NAVY, width=int(2 * s))

    img = img.resize((width, height), Image.LANCZOS)
    return _to_png(img)


__all__ = [
    "severity_donut", "hbar", "compliance_radar", "sparkline",
    "risk_gauge", "logo_mark", "cover_hero",
]
