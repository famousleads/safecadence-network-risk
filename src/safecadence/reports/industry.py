"""
Industry-specific report templates.

Templates are JSON files shipped alongside this module under
``industry_templates/``. Each template is a *preset definition* with
extra fields (``industry``, ``regulations``, ``narrative_persona``,
``scope_defaults``).

Industry-only section keys (``phi_exposure``, ``baa_gap_analysis``,
``cardholder_data_flow``, ``segregation_of_duties``, ``cui_handling``,
``supply_chain``, ``shared_responsibility``, ``tenancy_isolation``) are
implemented here as lightweight composers that consume the existing
NetRisk store + platform_assets and re-render with industry-specific
framing. They are registered into ``SECTION_REGISTRY`` on import so the
wizard treats them as first-class sections.

Public API:
  - list_industry_templates()             -> list[dict]
  - get_industry_template(template_id)    -> dict | None
  - apply_industry_template(template_id, scope=None) -> dict
"""

from __future__ import annotations

import json
import os
from copy import deepcopy
from pathlib import Path
from typing import Any


_TPL_DIR = Path(__file__).parent / "industry_templates"


def _load_all() -> list[dict]:
    out: list[dict] = []
    if not _TPL_DIR.exists():
        return out
    for p in sorted(_TPL_DIR.glob("*.json")):
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(d, dict) and d.get("id"):
                out.append(d)
        except (OSError, ValueError):
            continue
    return out


def list_industry_templates() -> list[dict]:
    return [deepcopy(t) for t in _load_all()]


def get_industry_template(template_id: str) -> dict | None:
    if not template_id:
        return None
    for t in _load_all():
        if t.get("id") == template_id:
            return deepcopy(t)
    return None


def apply_industry_template(template_id: str,
                            scope: dict | None = None) -> dict:
    """Resolve an industry template into a wizard config (mirrors
    ``presets.apply_preset``).
    """
    t = get_industry_template(template_id)
    if t is None:
        raise ValueError(f"Unknown industry template: {template_id!r}")

    merged_scope: dict[str, Any] = {
        "site": "",
        "criticality": [],
        "asset_type": [],
        "vendor": [],
        "date_range": {},
        "compliance_frameworks": list(
            (t.get("scope_defaults") or {}).get("compliance_frameworks") or []
        ),
    }
    if scope:
        for k, v in scope.items():
            if v in (None, "", [], {}):
                continue
            merged_scope[k] = v

    render_options = {
        "audience": t.get("audience"),
        "narrative_tone": t.get("narrative_tone"),
        "narrative_persona": t.get("narrative_persona"),
        "industry": t.get("industry"),
        "regulations": t.get("regulations") or [],
        "extras": t.get("extras") or {},
    }
    return {
        "template_id": t["id"],
        "name": t["name"],
        "description": t.get("description") or "",
        "industry": t.get("industry"),
        "sections": list(t.get("sections") or []),
        "scope": merged_scope,
        "render_options": render_options,
    }


# --------------------------------------------------------------------------
# Industry-specific section composers
#
# These are intentionally small. They build on the same data as
# compliance_posture / host_inventory / cve_exposure but reframe it for
# a specific regulation. When data is unavailable they return a clearly
# labeled placeholder card so the report still renders.
# --------------------------------------------------------------------------


def _esc(s: Any) -> str:
    import html as _html
    return _html.escape("" if s is None else str(s))


def _placeholder(title: str, regulations: str, blurb: str) -> dict:
    body = (
        f'<div class="sc-card sc-industry-card">'
        f'<div class="sc-card-tag">{_esc(regulations)}</div>'
        f'<h4 style="margin:6px 0">{_esc(title)}</h4>'
        f'<p style="margin:0;color:#475569;font-size:13px;line-height:1.5">{_esc(blurb)}</p>'
        f'</div>'
    )
    return {
        "title": title,
        "data": {"placeholder": True, "regulations": regulations},
        "html_fragment": body,
        "empty": False,
    }


def _hosts_with_tag(store: Any, scope: dict, tags: tuple[str, ...]) -> list[dict]:
    """Pull hosts whose criticality / asset_type / data_class hits one of `tags`."""
    try:
        from safecadence.reports.sections import (
            _filter_assets, _load_platform_assets, _asset_field,
        )
    except Exception:
        return []
    assets = _filter_assets(_load_platform_assets(), scope)
    out = []
    for a in assets or []:
        crit = (_asset_field(a, "criticality") or "").lower()
        atype = (_asset_field(a, "asset_type") or "").lower()
        site = (_asset_field(a, "site") or "").lower()
        text = " ".join([crit, atype, site])
        if any(t in text for t in tags):
            out.append({
                "hostname": _asset_field(a, "hostname") or _asset_field(a, "asset_id") or "?",
                "vendor": _asset_field(a, "vendor") or "",
                "site": _asset_field(a, "site") or "",
                "criticality": crit,
                "asset_type": atype,
            })
    return out


def _hosts_table(rows: list[dict]) -> str:
    if not rows:
        return '<div class="sc-empty"><em>No matching hosts in scope.</em></div>'
    head = ("<thead><tr><th>Hostname</th><th>Vendor</th><th>Type</th>"
            "<th>Site</th><th>Criticality</th></tr></thead>")
    body = "".join(
        "<tr>"
        f"<td>{_esc(r.get('hostname'))}</td>"
        f"<td>{_esc(r.get('vendor'))}</td>"
        f"<td>{_esc(r.get('asset_type'))}</td>"
        f"<td>{_esc(r.get('site'))}</td>"
        f"<td>{_esc(r.get('criticality'))}</td>"
        "</tr>"
        for r in rows[:80]
    )
    return f'<table class="sc-tbl">{head}<tbody>{body}</tbody></table>'


# Healthcare ----------------------------------------------------------------


def phi_exposure(store: Any, scope: dict) -> dict:
    rows = _hosts_with_tag(store, scope, ("clinic", "hospital", "ehr", "health",
                                          "imaging", "patient", "crown-jewel"))
    if not rows:
        return _placeholder(
            "PHI exposure",
            "HIPAA §164.312(a)(1) Access Control · §164.312(e)(1) Transmission Security",
            "No assets in scope are tagged as ePHI-bearing. The full report would "
            "list each system that stores or transmits Protected Health Information "
            "with control coverage, encryption posture, and last access review date."
        )
    return {
        "title": "PHI exposure",
        "data": {"hosts": rows},
        "html_fragment": _hosts_table(rows),
        "empty": False,
    }


def baa_gap_analysis(store: Any, scope: dict) -> dict:
    return _placeholder(
        "BAA gap analysis",
        "HIPAA §164.314 · 45 CFR §164.502(e)",
        "Stub for v10.2 — pulls executed Business Associate Agreements from the "
        "vendor inventory and flags vendors processing ePHI without a current BAA "
        "or with a BAA missing required HITECH safeguards."
    )


# Finance -------------------------------------------------------------------


def cardholder_data_flow(store: Any, scope: dict) -> dict:
    rows = _hosts_with_tag(store, scope, ("pci", "payment", "card", "pos",
                                          "checkout", "crown-jewel"))
    if not rows:
        return _placeholder(
            "Cardholder data flow",
            "PCI DSS 4.0 · Req 1, 3, 4",
            "Stub view — the full report traces cardholder data ingress, "
            "storage, and egress, mapping each network segment to the PCI "
            "DSS 4.0 control owner."
        )
    return {
        "title": "Cardholder data flow",
        "data": {"hosts": rows},
        "html_fragment": _hosts_table(rows),
        "empty": False,
    }


def segregation_of_duties(store: Any, scope: dict) -> dict:
    return _placeholder(
        "Segregation of duties",
        "SOX 404 · COBIT DSS06.03",
        "Stub for v10.2 — cross-references identity-store role assignments "
        "with privileged-access logs to surface SoD violations (e.g. the "
        "same identity approving and posting a journal entry)."
    )


# Defense -------------------------------------------------------------------


def cui_handling(store: Any, scope: dict) -> dict:
    rows = _hosts_with_tag(store, scope, ("cui", "classified", "ic", "siprnet",
                                          "crown-jewel"))
    if not rows:
        return _placeholder(
            "CUI handling",
            "CMMC 2.0 L2 · NIST 800-171 r2 §3.1, §3.13",
            "Stub view — the full report enumerates each CUI enclave, its "
            "FIPS 140-2/3 cryptographic posture, and the boundary devices "
            "enforcing CUI flow control."
        )
    return {
        "title": "CUI handling",
        "data": {"hosts": rows},
        "html_fragment": _hosts_table(rows),
        "empty": False,
    }


def supply_chain(store: Any, scope: dict) -> dict:
    return _placeholder(
        "Supply-chain risk",
        "NIST 800-161 · CMMC 2.0 L2 SR.L2",
        "Stub for v10.2 — pulls SBOMs and vendor attestations from the "
        "asset store and cross-checks against KEV and SBOM-VEX feeds for "
        "each critical component."
    )


# SaaS ---------------------------------------------------------------------


def shared_responsibility(store: Any, scope: dict) -> dict:
    return _placeholder(
        "Shared responsibility",
        "SOC 2 Type II · ISO 27017 · CC2.1, CC6.6",
        "Stub for v10.2 — splits each control between Customer / Provider / "
        "Joint responsibility based on the cloud-provider matrix and the "
        "tenant's actual configuration."
    )


def tenancy_isolation(store: Any, scope: dict) -> dict:
    rows = _hosts_with_tag(store, scope, ("multi-tenant", "saas", "shared",
                                          "tenant"))
    if not rows:
        return _placeholder(
            "Multi-tenancy isolation",
            "ISO 27017 · CLD.6.3.1 · SOC 2 CC6.1",
            "Stub view — the full report traces row-level vs schema-level "
            "vs database-level isolation for each multi-tenant data store, "
            "and lists every cross-tenant access path."
        )
    return {
        "title": "Multi-tenancy isolation",
        "data": {"hosts": rows},
        "html_fragment": _hosts_table(rows),
        "empty": False,
    }


# --------------------------------------------------------------------------
# Registry hook
# --------------------------------------------------------------------------


_INDUSTRY_SECTIONS = [
    {"key": "phi_exposure", "name": "PHI exposure",
     "description": "Hosts handling Protected Health Information (HIPAA §164.312).",
     "category": "Compliance", "default_enabled": False, "fn": phi_exposure},
    {"key": "baa_gap_analysis", "name": "BAA gap analysis",
     "description": "Vendors processing ePHI without a current Business Associate Agreement.",
     "category": "Compliance", "default_enabled": False, "fn": baa_gap_analysis},
    {"key": "cardholder_data_flow", "name": "Cardholder data flow",
     "description": "Hosts and segments in scope for PCI DSS 4.0.",
     "category": "Compliance", "default_enabled": False, "fn": cardholder_data_flow},
    {"key": "segregation_of_duties", "name": "Segregation of duties",
     "description": "SoD violations across financial reporting and IT identity.",
     "category": "Compliance", "default_enabled": False, "fn": segregation_of_duties},
    {"key": "cui_handling", "name": "CUI handling",
     "description": "CUI enclaves, encryption posture, boundary controls (CMMC L2).",
     "category": "Compliance", "default_enabled": False, "fn": cui_handling},
    {"key": "supply_chain", "name": "Supply-chain risk",
     "description": "SBOM + vendor attestation review (NIST 800-161).",
     "category": "Risk", "default_enabled": False, "fn": supply_chain},
    {"key": "shared_responsibility", "name": "Shared responsibility",
     "description": "Customer vs Provider vs Joint controls (SOC 2, ISO 27017).",
     "category": "Compliance", "default_enabled": False, "fn": shared_responsibility},
    {"key": "tenancy_isolation", "name": "Multi-tenancy isolation",
     "description": "Cross-tenant access paths and isolation tier per data store.",
     "category": "Compliance", "default_enabled": False, "fn": tenancy_isolation},
]


def _register_industry_sections() -> None:
    try:
        from safecadence.reports.sections import SECTION_REGISTRY
    except Exception:
        return
    existing = {s["key"] for s in SECTION_REGISTRY}
    for s in _INDUSTRY_SECTIONS:
        if s["key"] not in existing:
            SECTION_REGISTRY.append(s)


_register_industry_sections()


__all__ = [
    "list_industry_templates", "get_industry_template", "apply_industry_template",
    "phi_exposure", "baa_gap_analysis", "cardholder_data_flow",
    "segregation_of_duties", "cui_handling", "supply_chain",
    "shared_responsibility", "tenancy_isolation",
]
