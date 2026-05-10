"""Report renderers + multi-section report builder.

Two distinct surfaces live here:

  1. Per-scan renderers (existing): ``to_markdown``, ``to_json``, ``to_html``,
     ``to_docx``, ``to_pdf`` operate on a single ``ScanResult``.

  2. Multi-section report builder (v10.1, new): :func:`compose_report`,
     :func:`list_section_keys`, :func:`list_scope_keys` plus template
     persistence and HTML/JSON/PDF renderers for the wizard UI.
"""

from safecadence.reports.docx import to_docx, to_docx_bytes
from safecadence.reports.html import to_html
from safecadence.reports.json import to_json
from safecadence.reports.markdown import to_markdown
from safecadence.reports.pdf import to_pdf, to_pdf_bytes

# v10.1 wizard surface — kept lazy-tolerant so legacy scan renderers above
# continue to work even if a sub-import fails on a stripped-down install.
try:
    from safecadence.reports.builder import (
        compose_report,
        list_scope_keys,
        list_section_keys,
    )
    from safecadence.reports.renderers import (
        render_html,
        render_json,
        render_pdf,
    )
    from safecadence.reports.templates import (
        delete_template,
        list_templates,
        load_template,
        new_template_id,
        save_template,
    )
    from safecadence.reports.presets import (
        apply_preset,
        get_preset,
        list_presets,
    )
    from safecadence.reports.delta import (
        snapshot_now,
        list_snapshots,
        get_snapshot,
        compute_delta,
        trend_series,
        cleanup_old_snapshots,
    )
    from safecadence.reports.webhooks import (
        list_webhook_endpoints,
        add_webhook_endpoint,
        remove_webhook_endpoint,
        fire_webhook,
        fire_all_webhooks,
        notify_completion,
    )
    from safecadence.reports.industry import (
        list_industry_templates,
        get_industry_template,
        apply_industry_template,
    )
    from safecadence.reports.ticketing import (
        list_ticketing_integrations,
        add_ticketing_integration,
        remove_ticketing_integration,
        auto_create_tickets,
        list_created_tickets,
    )
    _WIZARD_OK = True
except Exception:  # pragma: no cover
    _WIZARD_OK = False

__all__ = [
    # legacy per-scan renderers
    "to_markdown", "to_json", "to_html",
    "to_docx", "to_docx_bytes",
    "to_pdf", "to_pdf_bytes",
    # v10.1 wizard
    "compose_report", "list_section_keys", "list_scope_keys",
    "render_html", "render_json", "render_pdf",
    "save_template", "load_template", "list_templates", "delete_template",
    "new_template_id",
    "list_presets", "get_preset", "apply_preset",
    # Round 2: delta / webhooks / industry / ticketing
    "snapshot_now", "list_snapshots", "get_snapshot",
    "compute_delta", "trend_series", "cleanup_old_snapshots",
    "list_webhook_endpoints", "add_webhook_endpoint", "remove_webhook_endpoint",
    "fire_webhook", "fire_all_webhooks", "notify_completion",
    "list_industry_templates", "get_industry_template", "apply_industry_template",
    "list_ticketing_integrations", "add_ticketing_integration",
    "remove_ticketing_integration", "auto_create_tickets", "list_created_tickets",
]
