"""Compliance evidence pack PDF generator.

Auditors don't want a markdown dump — they want a packaged PDF with
a cover page, a table of contents, framework→control→evidence
mapping, and a signature line. This module builds exactly that, one
PDF per framework.

PDF generation is deliberately dependency-free: we emit plain PDF
syntax (the same approach the reports module uses elsewhere) so the
[server] extras already cover us. No reportlab / weasyprint / wkhtmltopdf
to fight.

Usage:
    from safecadence.evidence_pack import generate
    pdf_bytes = generate(framework="pci")
    Path("acme-pci-2026-q1.pdf").write_bytes(pdf_bytes)
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


_FRAMEWORK_LABELS = {
    "nist":      "NIST 800-53 Rev 5",
    "cis":       "CIS Controls v8",
    "pci":       "PCI-DSS v4",
    "hipaa":     "HIPAA Security Rule",
    "iso":       "ISO 27001",
    "zerotrust": "NIST 800-207 Zero Trust",
}


# --------------------------------------------------------------------------
# Data collection
# --------------------------------------------------------------------------

def _collect(framework: str) -> dict[str, Any]:
    """Gather every signal that supports a framework's control:
       - Saved policies tagged with the framework
       - Their latest evaluation (pass/fail/coverage)
       - Recent drift findings tied to the same control_ids
       - Per-control framework-reference list (e.g. NIST 800-53 SC-8)
    """
    framework = (framework or "").lower()
    out: dict[str, Any] = {
        "framework": framework,
        "label": _FRAMEWORK_LABELS.get(framework, framework.upper()),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "controls": [],
    }
    try:
        from safecadence.policy.frameworks import load_mappings
        from safecadence.policy.controls import all_controls
        mappings = load_mappings() or {}
    except Exception:
        return out

    fw_match = framework
    if framework == "nist":     fw_match = "nist-800-53"
    if framework == "pci":      fw_match = "pci-dss"
    if framework == "iso":      fw_match = "iso-27001"
    if framework == "zerotrust": fw_match = "zero-trust"

    for spec in all_controls():
        refs = (mappings.get(spec.id) or {}).get(fw_match)
        if not refs:
            continue
        out["controls"].append({
            "control_id": spec.id,
            "description": spec.description,
            "applies_to": list(spec.applies_to or []),
            "severity": spec.severity.value,
            "framework_refs": list(refs),
        })

    # Per-control posture from saved policy evaluations
    try:
        from safecadence.policy.evaluator import evaluate
        from safecadence.policy.store import list_policies, get as _g
        from safecadence.server.platform_api import list_assets
        assets = list_assets()
        per_ctrl: dict[str, dict[str, int]] = {}
        for meta in list_policies():
            p = _g(meta["policy_id"])
            if not p:
                continue
            ev = evaluate(p, assets)
            for row in (ev.asset_results or []):
                for cid, status in (row.get("controls") or {}).items():
                    d = per_ctrl.setdefault(
                        cid, {"pass": 0, "fail": 0, "na": 0, "unknown": 0})
                    d[status if status in d else "unknown"] += 1
        out["evaluation"] = per_ctrl
        out["asset_count"] = len(assets)
    except Exception:
        out["evaluation"] = {}
        out["asset_count"] = 0
    return out


# --------------------------------------------------------------------------
# PDF emitter
# --------------------------------------------------------------------------

def _pdf_string(s: str) -> str:
    """PDF string literal escaping."""
    return ("(" + s.replace("\\", "\\\\").replace("(", "\\(")
                  .replace(")", "\\)") + ")")


def _build_pdf(pages: list[list[str]]) -> bytes:
    """Build a multi-page PDF from a list of pages, each a list of
    text lines. Helvetica, 11pt, ~1in margins.

    Pure-stdlib PDF emission — no reportlab. Good enough for an
    auditor-readable evidence pack."""
    obj_offsets: list[int] = []
    out = bytearray()
    out.extend(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")

    def add_obj(body: bytes) -> int:
        obj_offsets.append(len(out))
        idx = len(obj_offsets)
        out.extend(f"{idx} 0 obj\n".encode())
        out.extend(body)
        if not body.endswith(b"\n"):
            out.extend(b"\n")
        out.extend(b"endobj\n")
        return idx

    page_ids: list[int] = []
    page_content_ids: list[int] = []

    # Reserve obj 1 = catalog, 2 = pages, fonts later. We add them
    # in reverse and patch the /Kids list once page ids exist.
    for lines in pages:
        # Page content stream
        body_lines = ["BT", "/F1 11 Tf", "1 0 0 1 72 740 Tm",
                       "13 TL"]
        for ln in lines:
            body_lines.append(_pdf_string(ln) + " Tj T*")
        body_lines.append("ET")
        stream = "\n".join(body_lines).encode("latin-1", "replace")
        cid = add_obj(b"<< /Length " + str(len(stream)).encode()
                       + b" >>\nstream\n" + stream + b"\nendstream")
        page_content_ids.append(cid)

    font_id = add_obj(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    # Pages — placeholder /Parent will be patched
    for cid in page_content_ids:
        body = (b"<< /Type /Page /Parent 0 0 R /MediaBox [0 0 612 792]"
                 b" /Contents " + str(cid).encode() + b" 0 R"
                 b" /Resources << /Font << /F1 " + str(font_id).encode()
                 + b" 0 R >> >> >>")
        page_ids.append(add_obj(body))

    pages_kids = " ".join(f"{pid} 0 R" for pid in page_ids)
    pages_id = add_obj(
        ("<< /Type /Pages /Count " + str(len(page_ids))
          + " /Kids [" + pages_kids + "] >>").encode())

    # Patch each page's /Parent to point at pages_id
    rendered = bytes(out)
    for pid in page_ids:
        marker = f"<< /Type /Page /Parent 0 0 R".encode()
        replacement = f"<< /Type /Page /Parent {pages_id} 0 R".encode()
        rendered = rendered.replace(marker, replacement, 1)
    out = bytearray(rendered)

    catalog_id = add_obj(("<< /Type /Catalog /Pages "
                            + str(pages_id) + " 0 R >>").encode())

    xref_pos = len(out)
    out.extend(("xref\n0 " + str(len(obj_offsets) + 1)
                  + "\n0000000000 65535 f \n").encode())
    for off in obj_offsets:
        out.extend(f"{off:010d} 00000 n \n".encode())
    out.extend(("trailer << /Size " + str(len(obj_offsets) + 1)
                  + " /Root " + str(catalog_id) + " 0 R >>\n"
                  "startxref\n" + str(xref_pos) + "\n%%EOF\n").encode())
    return bytes(out)


# --------------------------------------------------------------------------
# Page builders
# --------------------------------------------------------------------------

def _cover_page(framework_label: str, asset_count: int) -> list[str]:
    return [
        "SafeCadence Evidence Pack",
        "",
        f"Framework:   {framework_label}",
        f"Generated:   {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"Assets:      {asset_count}",
        "",
        "This pack contains the policy controls SafeCadence has",
        "configured to satisfy the named framework, the latest",
        "per-asset evaluation results, and the framework reference",
        "for each control. It is suitable for auditor review.",
        "",
        "",
        "  ____________________________________",
        "    Auditor signature                                       Date",
        "",
        "",
        "  ____________________________________",
        "    Reviewed by (security owner)                            Date",
    ]


def _toc_page(controls: list[dict]) -> list[str]:
    out = ["Contents", ""]
    for c in controls:
        out.append(f"  • {c['control_id']:<35} ({c['severity']})")
    out.append("")
    out.append(f"Total controls covered: {len(controls)}")
    return out


def _control_pages(data: dict) -> list[list[str]]:
    out: list[list[str]] = []
    eval_map = data.get("evaluation") or {}
    for c in data["controls"]:
        cid = c["control_id"]
        verdicts = eval_map.get(cid, {})
        page = [
            f"Control: {cid}",
            "",
            f"Description:  {c['description']}",
            f"Severity:     {c['severity']}",
            f"Applies to:   {', '.join(c['applies_to']) or '(any)'}",
            "",
            "Framework references:",
        ]
        for r in c["framework_refs"]:
            page.append(f"  • {r}")
        page.append("")
        page.append("Latest evaluation across the fleet:")
        if verdicts:
            page.append(f"  pass:    {verdicts.get('pass', 0)}")
            page.append(f"  fail:    {verdicts.get('fail', 0)}")
            page.append(f"  na:      {verdicts.get('na', 0)}")
            page.append(f"  unknown: {verdicts.get('unknown', 0)}")
        else:
            page.append("  No saved policy currently includes this control.")
        page.append("")
        page.append("Evidence sources:")
        page.append("  • Asset configuration snapshots (raw_collection)")
        page.append("  • Policy evaluation results (~/.safecadence/policy_evaluations/)")
        page.append("  • Cross-system drift findings (where applicable)")
        page.append("  • Execution audit log (~/.safecadence/execution/audit/)")
        out.append(page)
    return out


# --------------------------------------------------------------------------
# Public entry
# --------------------------------------------------------------------------

def generate(framework: str) -> bytes:
    data = _collect(framework)
    if not data["controls"]:
        # Single-page "no coverage" PDF so the operator sees a real
        # file instead of a 0-byte bug.
        pdf = _build_pdf([[
            f"SafeCadence Evidence Pack — {data['label']}",
            "",
            "No SafeCadence controls are mapped to this framework.",
            "Add framework references in src/safecadence/policy/",
            "frameworks/mappings.yaml and re-run.",
        ]])
    else:
        pages = [
            _cover_page(data["label"], data.get("asset_count", 0)),
            _toc_page(data["controls"]),
        ]
        pages.extend(_control_pages(data))
        pdf = _build_pdf(pages)

    # v9.31 — append the generated pack to the tamper-evident hash
    # chain so the served bytes are auditor-verifiable. Best-effort:
    # chain failure must never block a pack generation.
    try:
        from safecadence.compliance.evidence_chain import append as _chain
        _chain(framework=framework, content=pdf,
                generated_by="evidence_pack.generate",
                note=data.get("label", framework))
    except Exception:
        pass

    return pdf
