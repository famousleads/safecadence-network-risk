"""
Pure-stdlib DOCX report renderer.

A .docx file is a zip of XML parts. We build the minimal valid OOXML
package: [Content_Types].xml, _rels/.rels, word/_rels/document.xml.rels,
word/document.xml, word/styles.xml. No external deps.
"""

from __future__ import annotations

import io
import zipfile
from xml.sax.saxutils import escape

from safecadence.core.schema import Finding, ScanResult, Severity


_SEV_LABEL = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH:     "HIGH",
    Severity.MEDIUM:   "MEDIUM",
    Severity.LOW:      "LOW",
    Severity.INFO:     "INFO",
}

_SEV_COLOR = {
    Severity.CRITICAL: "C00000",
    Severity.HIGH:     "C2410C",
    Severity.MEDIUM:   "B45309",
    Severity.LOW:      "0369A1",
    Severity.INFO:     "374151",
}


# ---------------------------------------------------------------------------
# OOXML helpers — build paragraphs / runs as XML strings.
# ---------------------------------------------------------------------------
def _p(text: str = "", *, style: str | None = None,
       bold: bool = False, size: int | None = None, color: str | None = None,
       mono: bool = False) -> str:
    rpr_parts: list[str] = []
    if bold:
        rpr_parts.append('<w:b/><w:bCs/>')
    if size is not None:
        # OOXML font sizes are in half-points
        rpr_parts.append(f'<w:sz w:val="{size * 2}"/>')
    if color:
        rpr_parts.append(f'<w:color w:val="{color}"/>')
    if mono:
        rpr_parts.append('<w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:cs="Consolas"/>')
    rpr = f"<w:rPr>{''.join(rpr_parts)}</w:rPr>" if rpr_parts else ""

    pstyle = f'<w:pStyle w:val="{style}"/>' if style else ""
    pPr = f"<w:pPr>{pstyle}</w:pPr>" if pstyle else ""
    return (
        '<w:p>'
        f'{pPr}'
        f'<w:r>{rpr}<w:t xml:space="preserve">{escape(text)}</w:t></w:r>'
        '</w:p>'
    )


def _heading(text: str, level: int = 1) -> str:
    style = f"Heading{level}"
    return _p(text, style=style, bold=True, size=18 if level == 1 else 14)


def _table(rows: list[tuple[str, str]]) -> str:
    """Simple two-column key/value table."""
    body: list[str] = []
    for k, v in rows:
        body.append(
            '<w:tr>'
            '  <w:tc>'
            '    <w:tcPr><w:tcW w:w="2200" w:type="dxa"/></w:tcPr>'
            f'   <w:p><w:r><w:rPr><w:b/></w:rPr><w:t xml:space="preserve">{escape(k)}</w:t></w:r></w:p>'
            '  </w:tc>'
            '  <w:tc>'
            '    <w:tcPr><w:tcW w:w="6800" w:type="dxa"/></w:tcPr>'
            f'   <w:p><w:r><w:t xml:space="preserve">{escape(v)}</w:t></w:r></w:p>'
            '  </w:tc>'
            '</w:tr>'
        )
    return (
        '<w:tbl>'
        '  <w:tblPr>'
        '    <w:tblStyle w:val="TableGrid"/>'
        '    <w:tblW w:w="9000" w:type="dxa"/>'
        '    <w:tblBorders>'
        '      <w:top w:val="single" w:sz="4" w:color="CBD5E1"/>'
        '      <w:left w:val="single" w:sz="4" w:color="CBD5E1"/>'
        '      <w:bottom w:val="single" w:sz="4" w:color="CBD5E1"/>'
        '      <w:right w:val="single" w:sz="4" w:color="CBD5E1"/>'
        '      <w:insideH w:val="single" w:sz="4" w:color="E2E8F0"/>'
        '      <w:insideV w:val="single" w:sz="4" w:color="E2E8F0"/>'
        '    </w:tblBorders>'
        '  </w:tblPr>'
        + "".join(body) +
        '</w:tbl>'
        '<w:p/>'  # spacer paragraph after table
    )


def _code_block(text: str) -> str:
    """Render a multi-line code block in monospace, one paragraph per line."""
    out: list[str] = []
    for line in (text or "").splitlines() or [""]:
        out.append(
            '<w:p>'
            '<w:pPr><w:shd w:val="clear" w:color="auto" w:fill="0F172A"/></w:pPr>'
            '<w:r>'
            '<w:rPr>'
            '<w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:cs="Consolas"/>'
            '<w:color w:val="F1F5F9"/>'
            '<w:sz w:val="18"/>'
            '</w:rPr>'
            f'<w:t xml:space="preserve">{escape(line)}</w:t>'
            '</w:r>'
            '</w:p>'
        )
    return "".join(out)


def _finding_paragraphs(f: Finding) -> str:
    color = _SEV_COLOR[f.severity]
    label = _SEV_LABEL[f.severity]
    out: list[str] = []
    out.append(
        '<w:p>'
        '<w:r>'
        f'<w:rPr><w:b/><w:color w:val="{color}"/><w:sz w:val="20"/></w:rPr>'
        f'<w:t xml:space="preserve">[{label}] </w:t>'
        '</w:r>'
        '<w:r>'
        '<w:rPr><w:b/><w:sz w:val="22"/></w:rPr>'
        f'<w:t xml:space="preserve">{escape(f.title)}</w:t>'
        '</w:r>'
        '</w:p>'
    )
    out.append(_p(f"Rule: {f.rule_id}   ·   Domain: {f.domain}", color="64748B", size=9))
    if f.description:
        out.append(_p(f.description.strip()))
    if f.evidence and f.evidence != "(absent)":
        out.append(_p("Evidence:", bold=True, size=10, color="475569"))
        out.append(_p(f.evidence, mono=True, size=9))
    if f.remediation:
        out.append(_p("Remediation:", bold=True, size=10, color="475569"))
        out.append(_p(f.remediation.strip()))
    if f.fix_snippet:
        out.append(_p("Suggested config:", bold=True, size=10, color="475569"))
        out.append(_code_block(f.fix_snippet.strip()))
    if f.references:
        out.append(_p("References:", bold=True, size=10, color="475569"))
        for r in f.references:
            out.append(_p(f"  • {r}", size=9, color="1D4ED8"))
    out.append(_p(""))  # spacer
    return "".join(out)


# ---------------------------------------------------------------------------
# Static OOXML parts.
# ---------------------------------------------------------------------------
_CONTENT_TYPES = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
</Types>"""

_ROOT_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"""

_DOC_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>"""

_STYLES = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:docDefaults>
    <w:rPrDefault><w:rPr>
      <w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:cs="Calibri"/>
      <w:sz w:val="22"/>
    </w:rPr></w:rPrDefault>
  </w:docDefaults>
  <w:style w:type="paragraph" w:styleId="Heading1">
    <w:name w:val="heading 1"/>
    <w:pPr><w:spacing w:before="360" w:after="120"/></w:pPr>
    <w:rPr><w:b/><w:sz w:val="36"/><w:color w:val="0F172A"/></w:rPr>
  </w:style>
  <w:style w:type="paragraph" w:styleId="Heading2">
    <w:name w:val="heading 2"/>
    <w:pPr><w:spacing w:before="240" w:after="60"/></w:pPr>
    <w:rPr><w:b/><w:sz w:val="28"/><w:color w:val="1E3A8A"/></w:rPr>
  </w:style>
</w:styles>"""


def to_docx_bytes(result: ScanResult) -> bytes:
    """Render the scan result as a .docx and return raw bytes."""
    p = result.parsed
    title = f"SafeCadence Scan Report — {p.hostname or result.source}"

    body_parts: list[str] = []
    body_parts.append(_heading(title, level=1))
    body_parts.append(_p(f"Generated: {result.started_at}", color="64748B", size=10))

    body_parts.append(_heading("Device", level=2))
    body_parts.append(_table([
        ("Source",     result.source),
        ("Vendor",     result.vendor),
        ("Hostname",   p.hostname or "—"),
        ("Model",      p.model or "—"),
        ("OS",         p.os or "—"),
        ("Version",    p.version or "—"),
        ("Interfaces", str(len(p.interfaces))),
        ("Neighbors",  str(len(p.neighbors))),
    ]))

    body_parts.append(_heading("Scores", level=2))
    body_parts.append(_table([
        ("Health", f"{result.health_score}/100  ({result.health_band})"),
        ("Risk",   f"{result.risk_score}/100  ({result.risk_band})"),
        ("Summary", result.summary),
    ]))

    body_parts.append(_heading(f"Findings ({len(result.findings)})", level=2))
    if not result.findings:
        body_parts.append(_p("No findings — clean device or no rules matched.", color="16A34A"))
    else:
        for f in result.findings:
            body_parts.append(_finding_paragraphs(f))

    crit_count = sum(1 for f in result.findings if f.severity == Severity.CRITICAL)
    if result.risk_score >= 80 or crit_count >= 5:
        body_parts.append(_p(""))
        body_parts.append(_heading("Need help fixing these?", level=2))
        body_parts.append(_p(
            "This device shows a critical risk profile. SafeCadence offers end-to-end "
            "remediation engagements — prioritized fix plan, implementation support, "
            "and post-change validation. We work with the same open-source engine you "
            "just ran — no lock-in, no SaaS, no data leaves your environment.",
        ))
        body_parts.append(_p("Email: hello@safecadence.com", bold=True, color="1D4ED8"))
        body_parts.append(_p("Website: https://safecadence.com", bold=True, color="1D4ED8"))

    body_parts.append(_p(""))
    body_parts.append(_p(
        "Generated by SafeCadence Network Risk — open source · MIT license · BYOK AI.",
        color="64748B", size=9,
    ))

    document_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        '<w:body>'
        + "".join(body_parts) +
        '<w:sectPr><w:pgSz w:w="12240" w:h="15840"/>'
        '<w:pgMar w:top="1080" w:right="1080" w:bottom="1080" w:left="1080" '
        'w:header="720" w:footer="720" w:gutter="0"/></w:sectPr>'
        '</w:body>'
        '</w:document>'
    )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", _CONTENT_TYPES)
        z.writestr("_rels/.rels", _ROOT_RELS)
        z.writestr("word/_rels/document.xml.rels", _DOC_RELS)
        z.writestr("word/styles.xml", _STYLES)
        z.writestr("word/document.xml", document_xml)
    return buf.getvalue()


def to_docx(result: ScanResult, path: str) -> None:
    with open(path, "wb") as fh:
        fh.write(to_docx_bytes(result))
