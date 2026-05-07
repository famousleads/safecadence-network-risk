"""PDF exporter — uses reportlab if available, otherwise returns a text marker.

Cross-platform: reportlab is pure Python and works on Windows/Linux/macOS.
"""

from __future__ import annotations

from safecadence.policy.exporters import register_exporter
from safecadence.policy.exporters.markdown import export_markdown
from safecadence.policy.schema import RemediationPlan, SecurityPolicy


@register_exporter("pdf")
def export_pdf(policy: SecurityPolicy, plan: RemediationPlan):
    """Return PDF bytes if reportlab is installed, else markdown text wrapped in a marker."""
    try:
        from io import BytesIO
        from reportlab.lib.pagesizes import LETTER
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import (
            Paragraph, SimpleDocTemplate, Spacer, Preformatted,
        )
    except ImportError:
        # Fallback — return markdown so the caller can still write a file.
        return ("PDF rendering requires reportlab (pip install reportlab). "
                "Falling back to markdown:\n\n" + export_markdown(policy, plan)).encode("utf-8")

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=LETTER,
                            leftMargin=0.6*inch, rightMargin=0.6*inch,
                            topMargin=0.6*inch, bottomMargin=0.6*inch)
    styles = getSampleStyleSheet()
    code = ParagraphStyle("code", parent=styles["Code"], fontSize=8, leading=10)

    flow = []
    flow.append(Paragraph(f"{policy.policy_name} — Remediation Runbook", styles["Title"]))
    flow.append(Paragraph(f"Policy: {policy.policy_id}<br/>"
                          f"Plan: {plan.plan_id}<br/>"
                          f"Generated: {plan.generated_at}<br/>"
                          f"Severity: {policy.severity.value}", styles["Normal"]))
    flow.append(Spacer(1, 0.2*inch))

    by_asset: dict[str, list] = {}
    for s in plan.steps:
        by_asset.setdefault(s.asset_id, []).append(s)

    for aid, steps in by_asset.items():
        flow.append(Paragraph(f"<b>Asset:</b> {aid}", styles["Heading2"]))
        for s in steps:
            flow.append(Paragraph(
                f"<b>{s.control_id}</b> &nbsp; ({s.vendor_target}, severity={s.severity.value})",
                styles["Heading3"]))
            if s.fix_commands:
                flow.append(Paragraph("<b>Fix:</b>", styles["Normal"]))
                flow.append(Preformatted("\n".join(s.fix_commands), code))
            if s.rollback_commands:
                flow.append(Paragraph("<b>Rollback:</b>", styles["Normal"]))
                flow.append(Preformatted("\n".join(s.rollback_commands), code))
            if s.verify_commands:
                flow.append(Paragraph("<b>Verify:</b>", styles["Normal"]))
                flow.append(Preformatted("\n".join(s.verify_commands), code))
            if s.notes:
                flow.append(Paragraph(f"<i>Note: {s.notes}</i>", styles["Normal"]))
            flow.append(Spacer(1, 0.1*inch))
    doc.build(flow)
    return buf.getvalue()
