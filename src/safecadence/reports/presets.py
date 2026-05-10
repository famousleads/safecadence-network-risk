"""
Stakeholder report presets.

Each preset describes a curated starting point for the wizard:

  * ``id``              — slug, used in URLs / API
  * ``name``            — display name
  * ``description``     — single-sentence purpose
  * ``audience``        — who reads it (drives narrative tone)
  * ``icon``            — single emoji-free SVG glyph (used by the cards UI)
  * ``sections``        — ordered list of section keys
  * ``visual_style``    — cover style + page size hints
  * ``narrative_tone``  — passed to ai_helpers.generate_executive_summary
  * ``extras``          — flags (evidence appendix, control mappings, etc.)

Public API:
  - list_presets()                  -> list[dict] (everything except 'fn')
  - get_preset(preset_id)           -> dict | None
  - apply_preset(preset_id, scope)  -> {"sections", "scope", "render_options"}
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any


# All registry section keys, in pleasant default reading order. The new
# compliance-deep-dive sections fold in right after the headline compliance
# posture roll-up.
_ALL_SECTIONS = [
    "executive_summary",
    "kpi_summary",
    "host_inventory",
    "cve_exposure",
    "compliance_posture",
    "compliance_executive_summary",
    "compliance_control_matrix",
    "compliance_gap_analysis",
    "compliance_evidence_pack",
    "eol_hardware",
    "attack_paths",
    "identity_drift",
    "recommended_actions",
    "recent_changes",
]


_PRESETS: list[dict] = [
    # --------------------------------------------------------------
    # 1. Executive brief — 3 pages
    # --------------------------------------------------------------
    {
        "id": "exec_brief",
        "name": "Executive brief",
        "description": (
            "3-page board-ready report: cover, executive summary, and prioritized "
            "action plan. Designed for the CEO, CISO, or board readout."
        ),
        "audience": "ceo",
        "icon": "shield",
        "sections": [
            "kpi_summary",
            "executive_summary",
            "recommended_actions",
        ],
        "visual_style": {
            "cover_style": "gradient-bold",
            "page_size": "letter",
            "font_scale": 1.05,
            "show_kpi_band": True,
        },
        "narrative_tone": "executive",
        "extras": {
            "include_evidence_appendix": False,
            "include_control_mappings": False,
            "max_pages_hint": 3,
            "show_top_actions_callout": True,
        },
    },
    # --------------------------------------------------------------
    # 2. Technical deep-dive — full detail
    # --------------------------------------------------------------
    {
        "id": "technical_deepdive",
        "name": "Technical deep-dive",
        "description": (
            "Full 30–50 page report with every section, full CVE detail, ATT&CK "
            "mapping, and per-host evidence. For security engineers."
        ),
        "audience": "engineer",
        "icon": "wrench",
        "sections": list(_ALL_SECTIONS),
        "visual_style": {
            "cover_style": "gradient-bold",
            "page_size": "a4",
            "font_scale": 1.0,
            "show_kpi_band": True,
        },
        "narrative_tone": "technical",
        "extras": {
            "include_evidence_appendix": True,
            "include_control_mappings": True,
            "max_pages_hint": 50,
            "show_attack_path_graph": True,
        },
    },
    # --------------------------------------------------------------
    # 3. Compliance audit — auditor ready
    # --------------------------------------------------------------
    {
        "id": "compliance_audit",
        "name": "Compliance audit",
        "description": (
            "Auditor-ready: control mappings (NIST 800-53, CIS v8, PCI DSS, HIPAA, "
            "SOC 2), gap analysis, evidence appendix, in-scope host inventory."
        ),
        "audience": "auditor",
        "icon": "clipboard",
        "sections": [
            "kpi_summary",
            "compliance_executive_summary",
            "compliance_posture",
            "compliance_control_matrix",
            "compliance_gap_analysis",
            "compliance_evidence_pack",
            "host_inventory",
            "cve_exposure",
            "recommended_actions",
        ],
        "visual_style": {
            "cover_style": "gradient-soft",
            "page_size": "a4",
            "font_scale": 1.0,
            "show_kpi_band": True,
        },
        "narrative_tone": "audit",
        "extras": {
            "include_evidence_appendix": True,
            "include_control_mappings": True,
            "max_pages_hint": 25,
            "expand_compliance_section": True,
        },
    },
    # --------------------------------------------------------------
    # 4. Quarterly review — trend report
    # --------------------------------------------------------------
    {
        "id": "quarterly_review",
        "name": "Quarterly review",
        "description": (
            "Quarter-over-quarter trend report with delta sparklines, recent change "
            "log, and forward-looking action plan. For exec readouts."
        ),
        "audience": "ciso",
        "icon": "trend",
        "sections": [
            "kpi_summary",
            "executive_summary",
            "recent_changes",
            "recommended_actions",
        ],
        "visual_style": {
            "cover_style": "gradient-bold",
            "page_size": "letter",
            "font_scale": 1.0,
            "show_kpi_band": True,
        },
        "narrative_tone": "forward-looking",
        "extras": {
            "include_evidence_appendix": False,
            "include_control_mappings": False,
            "max_pages_hint": 8,
            "include_delta_sparklines": True,
            "quarter_over_quarter": True,
            "include_delta": True,
        },
    },
]


def _public(p: dict) -> dict:
    """Strip any non-serialisable fields."""
    return {k: v for k, v in p.items() if k != "fn"}


def list_presets() -> list[dict]:
    """Return public metadata for every preset."""
    return [_public(deepcopy(p)) for p in _PRESETS]


def get_preset(preset_id: str) -> dict | None:
    """Look up a single preset by id. Returns ``None`` if unknown."""
    if not preset_id:
        return None
    for p in _PRESETS:
        if p["id"] == preset_id:
            return _public(deepcopy(p))
    return None


def apply_preset(preset_id: str, scope: dict | None = None) -> dict:
    """Resolve a preset into a wizard config dict.

    Returns ``{"preset_id", "name", "sections", "scope", "render_options"}``
    suitable for piping straight into ``compose_report`` and
    ``render_html``. ``scope`` is merged on top of the preset's empty
    default scope, so callers can pre-fill site/criticality before applying.

    Raises ``ValueError`` for unknown preset ids.
    """
    p = get_preset(preset_id)
    if p is None:
        raise ValueError(f"Unknown preset: {preset_id!r}")

    merged_scope: dict[str, Any] = {
        "site": "",
        "criticality": [],
        "asset_type": [],
        "vendor": [],
        "date_range": {},
    }
    if scope:
        for k, v in scope.items():
            if v in (None, "", [], {}):
                continue
            merged_scope[k] = v

    render_options = {
        "audience": p.get("audience"),
        "narrative_tone": p.get("narrative_tone"),
        "visual_style": p.get("visual_style") or {},
        "extras": p.get("extras") or {},
    }
    return {
        "preset_id": p["id"],
        "name": p["name"],
        "description": p.get("description") or "",
        "sections": list(p.get("sections") or []),
        "scope": merged_scope,
        "render_options": render_options,
    }


# --------------------------------------------------------------------------
# preset card SVG icons (no external assets)
# --------------------------------------------------------------------------


PRESET_ICON_SVG: dict[str, str] = {
    "shield": (
        '<svg viewBox="0 0 24 24" width="22" height="22" fill="none" '
        'stroke="currentColor" stroke-width="1.8" stroke-linecap="round" '
        'stroke-linejoin="round" aria-hidden="true">'
        '<path d="M12 3l8 3v6c0 5-3.4 8.5-8 9-4.6-.5-8-4-8-9V6l8-3z"/>'
        '<path d="M9 12l2 2 4-4"/></svg>'
    ),
    "wrench": (
        '<svg viewBox="0 0 24 24" width="22" height="22" fill="none" '
        'stroke="currentColor" stroke-width="1.8" stroke-linecap="round" '
        'stroke-linejoin="round" aria-hidden="true">'
        '<path d="M14.7 6.3a4 4 0 1 0 5 5l-3 3-7 7a2 2 0 0 1-3-3l7-7 3-3z"/></svg>'
    ),
    "clipboard": (
        '<svg viewBox="0 0 24 24" width="22" height="22" fill="none" '
        'stroke="currentColor" stroke-width="1.8" stroke-linecap="round" '
        'stroke-linejoin="round" aria-hidden="true">'
        '<rect x="6" y="4" width="12" height="16" rx="2"/>'
        '<path d="M9 4h6v3H9z"/><path d="M9 12h6M9 16h4"/></svg>'
    ),
    "trend": (
        '<svg viewBox="0 0 24 24" width="22" height="22" fill="none" '
        'stroke="currentColor" stroke-width="1.8" stroke-linecap="round" '
        'stroke-linejoin="round" aria-hidden="true">'
        '<path d="M3 17l6-6 4 4 8-9"/><path d="M14 6h7v7"/></svg>'
    ),
    "blank": (
        '<svg viewBox="0 0 24 24" width="22" height="22" fill="none" '
        'stroke="currentColor" stroke-width="1.8" stroke-linecap="round" '
        'stroke-linejoin="round" aria-hidden="true">'
        '<rect x="4" y="4" width="16" height="16" rx="3"/>'
        '<path d="M12 8v8M8 12h8"/></svg>'
    ),
}


def render_preset_card_html(preset: dict) -> str:
    """Render an HTML card for a preset (used by the wizard Step 0)."""
    import html as _html
    icon = PRESET_ICON_SVG.get(preset.get("icon", ""), PRESET_ICON_SVG["blank"])
    pid = _html.escape(preset["id"])
    name = _html.escape(preset["name"])
    desc = _html.escape(preset.get("description", ""))
    audience = _html.escape((preset.get("audience") or "").upper())
    sec_n = len(preset.get("sections") or [])
    return (
        f'<button type="button" class="rep-preset-card" '
        f'onclick="repApplyPreset(\'{pid}\')" '
        f'aria-label="Use template {name}">'
        f'<span class="rep-preset-icon">{icon}</span>'
        f'<span class="rep-preset-body">'
        f'<span class="rep-preset-name">{name}</span>'
        f'<span class="rep-preset-desc">{desc}</span>'
        f'<span class="rep-preset-meta">'
        f'<span>{audience}</span><span>{sec_n} sections</span></span>'
        f'</span></button>'
    )


__all__ = [
    "list_presets", "get_preset", "apply_preset",
    "PRESET_ICON_SVG", "render_preset_card_html",
]
