"""
Pure-stdlib PDF renderer.

Builds a minimal PDF (one Type-1 font, multi-page, no external deps).
Layout: cover header, scores table, findings list, optional running config.
"""

from __future__ import annotations

import io
import zlib
from dataclasses import dataclass

from safecadence.core.schema import Finding, ScanResult, Severity


_PAGE_W, _PAGE_H = 612, 792           # US Letter, points
_MARGIN_L, _MARGIN_R = 54, 54
_MARGIN_T, _MARGIN_B = 54, 54
_USABLE_W = _PAGE_W - _MARGIN_L - _MARGIN_R


def _esc(s: str) -> str:
    return (s or "").replace("\\", "\\\\").replace("(", r"\(").replace(")", r"\)")


def _wrap(text: str, max_chars: int) -> list[str]:
    """Naive char-based wrap (good enough for monospace + Helvetica at our sizes)."""
    out: list[str] = []
    for line in (text or "").splitlines() or [""]:
        while len(line) > max_chars:
            cut = line.rfind(" ", 0, max_chars)
            if cut <= 0:
                cut = max_chars
            out.append(line[:cut])
            line = line[cut:].lstrip()
        out.append(line)
    return out


@dataclass
class _Cursor:
    pages: list[list[str]]
    y: float
    def __post_init__(self):
        if not self.pages:
            self.pages = [[]]

    def page(self) -> list[str]:
        return self.pages[-1]

    def newline(self, n: float = 14):
        self.y -= n
        if self.y < _MARGIN_B + 30:
            self.pages.append([])
            self.y = _PAGE_H - _MARGIN_T

    def text(self, s: str, *, x: float = _MARGIN_L, font: str = "F1", size: float = 10):
        self.page().append(
            f"BT /{font} {size} Tf {x} {self.y} Td ({_esc(s)}) Tj ET"
        )

    def heading(self, s: str, *, size: float = 16):
        self.newline(size + 4)
        self.text(s, font="F2", size=size)
        self.newline(size + 4)

    def para(self, s: str, *, size: float = 10, font: str = "F1", chars: int = 95):
        for line in _wrap(s, chars):
            self.text(line, font=font, size=size)
            self.newline(size + 3)

    def hr(self):
        self.page().append(
            f"q 0.85 0.85 0.85 RG 0.5 w {_MARGIN_L} {self.y} m {_PAGE_W - _MARGIN_R} {self.y} l S Q"
        )
        self.newline(8)

    def kv(self, k: str, v: str, *, label_w: float = 110):
        self.text(k, font="F2", size=10)
        self.page().append(
            f"BT /F1 10 Tf {_MARGIN_L + label_w} {self.y} Td ({_esc(v)}) Tj ET"
        )
        self.newline(13)


def to_pdf_bytes(result: ScanResult, *, include_config: bool = True) -> bytes:
    p = result.parsed
    cur = _Cursor(pages=[[]], y=_PAGE_H - _MARGIN_T)

    cur.text("SafeCadence Network Risk", size=10, font="F2")
    cur.newline(14)
    cur.text(f"Scan report — {p.hostname or result.source}", size=20, font="F2")
    cur.newline(22)
    cur.text(f"Generated: {result.started_at}", size=9)
    cur.newline(8)
    cur.hr()

    cur.heading("Device", size=14)
    cur.kv("Source",     result.source)
    cur.kv("Vendor",     result.vendor)
    cur.kv("Hostname",   p.hostname or "—")
    cur.kv("Model",      p.model or "—")
    cur.kv("OS",         p.os or "—")
    cur.kv("Version",    p.version or "—")
    cur.kv("Interfaces", str(len(p.interfaces)))
    cur.newline(6)

    cur.heading("Scores", size=14)
    cur.kv("Health", f"{result.health_score}/100   ({result.health_band})")
    cur.kv("Risk",   f"{result.risk_score}/100   ({result.risk_band})")
    cur.kv("Summary", result.summary)
    if result.eol:
        cur.kv("EOL", f"{result.eol.get('status_today','?')}   "
                       f"end-of-software={result.eol.get('end_of_software','—')}, "
                       f"end-of-support={result.eol.get('end_of_support','—')}")
    cur.newline(4)

    if result.cves:
        cur.heading(f"CVEs ({len(result.cves)})", size=14)
        for c in result.cves[:25]:
            kev = " [KEV]" if c.get("kev") else ""
            cur.text(f"[{c.get('severity','').upper()}] {c.get('cve_id','')} "
                     f"CVSS {c.get('cvss','—')}{kev}", font="F2", size=10)
            cur.newline(13)
            cur.para("    " + (c.get("title") or ""), size=9, chars=100)
            cur.newline(2)

    cur.heading(f"Findings ({len(result.findings)})", size=14)
    if not result.findings:
        cur.text("No findings.", size=10)
        cur.newline(14)
    else:
        for f in result.findings:
            cur.text(f"[{f.severity.value.upper()}] {f.title}", font="F2", size=10)
            cur.newline(13)
            cur.text(f"    rule: {f.rule_id}   domain: {f.domain}", size=9)
            cur.newline(13)
            if f.description:
                cur.para("    " + f.description.strip(), size=9, chars=100)
            if f.remediation:
                cur.text("    Remediation:", font="F2", size=9)
                cur.newline(11)
                cur.para("      " + f.remediation.strip(), size=9, chars=100)
            cur.newline(4)

    if include_config and (result.parsed.raw_config or ""):
        cur.heading("Running config", size=14)
        for line in (result.parsed.raw_config or "").splitlines():
            for chunk in _wrap(line, 110):
                cur.text(chunk, font="F3", size=8)   # Courier
                cur.newline(10)

    return _build_pdf(cur.pages)


def to_pdf(result: ScanResult, path: str, *, include_config: bool = True) -> None:
    with open(path, "wb") as fh:
        fh.write(to_pdf_bytes(result, include_config=include_config))


# --------------------------------------------------------------- #
# Low-level PDF assembly                                          #
# --------------------------------------------------------------- #
def _build_pdf(pages: list[list[str]]) -> bytes:
    objects: list[bytes] = []   # 1-indexed (object 0 is the dummy free)

    def add(obj_bytes: bytes) -> int:
        objects.append(obj_bytes)
        return len(objects)      # 1-based id

    # Reserve catalog + pages-tree positions
    catalog_id = add(b"")        # placeholder, fill later
    pages_id   = add(b"")        # placeholder

    # Fonts
    font_helv = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    font_helvb= add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")
    font_cour = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>")

    # Each page: content stream + page object
    page_ids: list[int] = []
    for content_lines in pages:
        stream = "\n".join(content_lines).encode("utf-8")
        compressed = zlib.compress(stream)
        content_id = add(
            f"<< /Length {len(compressed)} /Filter /FlateDecode >>\nstream\n".encode()
            + compressed
            + b"\nendstream"
        )
        page_obj = (
            f"<< /Type /Page /Parent {pages_id} 0 R "
            f"/MediaBox [0 0 {_PAGE_W} {_PAGE_H}] "
            f"/Resources << /Font << /F1 {font_helv} 0 R /F2 {font_helvb} 0 R /F3 {font_cour} 0 R >> >> "
            f"/Contents {content_id} 0 R >>"
        ).encode()
        page_ids.append(add(page_obj))

    kids = " ".join(f"{pid} 0 R" for pid in page_ids)
    objects[pages_id - 1] = (
        f"<< /Type /Pages /Count {len(page_ids)} /Kids [{kids}] >>".encode()
    )
    objects[catalog_id - 1] = (
        f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode()
    )

    # Serialize
    buf = io.BytesIO()
    buf.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for i, obj in enumerate(objects, start=1):
        offsets.append(buf.tell())
        buf.write(f"{i} 0 obj\n".encode())
        buf.write(obj)
        buf.write(b"\nendobj\n")

    xref_pos = buf.tell()
    buf.write(f"xref\n0 {len(objects) + 1}\n".encode())
    buf.write(b"0000000000 65535 f \n")
    for off in offsets[1:]:
        buf.write(f"{off:010d} 00000 n \n".encode())
    buf.write(
        f"trailer\n<< /Size {len(objects) + 1} /Root {catalog_id} 0 R >>\n"
        f"startxref\n{xref_pos}\n%%EOF\n".encode()
    )
    return buf.getvalue()
