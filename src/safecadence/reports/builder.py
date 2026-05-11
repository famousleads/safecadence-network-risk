"""
Report builder — composes a report from a list of section keys + a
scope dict by calling the corresponding section composer.

Public API:
  - list_section_keys() -> list of {key, name, description, category, default_enabled}
  - list_scope_keys()   -> list of {key, name, type, options?}
  - compose_report(*, sections, scope, store=None) -> dict

A "report" dict has the shape:
  {
    "title": str,
    "generated_at": ISO-8601 UTC string,
    "scope": dict (echoed back),
    "sections": [
        {"key": str, "title": str, "data": dict,
         "html_fragment": str, "empty": bool},
        ...
    ],
  }
"""

from __future__ import annotations

import datetime as _dt
from typing import Any, Iterable

from safecadence.reports.sections import SECTION_REGISTRY, get_section


def list_section_keys() -> list[dict]:
    """Return the public metadata for every available section."""
    out = []
    for s in SECTION_REGISTRY:
        out.append({k: v for k, v in s.items() if k != "fn"})
    return out


def list_scope_keys() -> list[dict]:
    """Return metadata for every supported scope filter."""
    return [
        {"key": "site", "name": "Site",
         "type": "string",
         "description": "Filter to a single site/location code (e.g. dc-east-1)."},
        {"key": "criticality", "name": "Criticality",
         "type": "multi-select",
         "options": ["low", "medium", "high", "critical"],
         "description": "Include only assets at the chosen criticality."},
        {"key": "asset_type", "name": "Asset type",
         "type": "multi-select",
         "options": ["network", "server", "identity", "cloud", "backup"],
         "description": "Include only assets of the chosen types."},
        {"key": "vendor", "name": "Vendor",
         "type": "multi-select",
         "description": "Include only assets from the chosen vendors."},
        {"key": "date_range", "name": "Date range",
         "type": "date-range",
         "description": "from/to (ISO-8601). Filters scans by started_at."},
    ]


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _open_default_store() -> Any | None:
    try:
        from pathlib import Path
        from safecadence.storage import open_store
        db_path = Path.home() / ".safecadence" / "ui.sqlite"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        return open_store(sqlite_path=str(db_path))
    except Exception:
        return None


def compose_report(
    *,
    sections: Iterable[str] | None = None,
    scope: dict | None = None,
    store: Any | None = None,
    title: str = "SafeCadence NetRisk Report",
    include_delta: bool = False,
    org_id: str | None = None,
) -> dict:
    """Compose a full report dict from the chosen sections + scope.

    When ``include_delta`` is True, attaches a top-level ``delta`` key with
    the current vs previous snapshot diff (used by the quarterly_review
    preset and the "Recent changes" section to render sparklines).

    v10.5: when ``org_id`` is provided, section composers that read from
    the on-disk ``platform_assets`` store will read from
    ``~/.safecadence/orgs/<org_id>/platform_assets/`` instead of the
    global directory. Pass ``None`` (the default) for the legacy global
    behavior — keeps every existing call site working.
    """
    scope = dict(scope or {})
    # v10.5: contextvar-scoped org id. Section composers take only
    # (store, scope) so we route the org_id through a process-wide
    # contextvar that _load_platform_assets() consults at read time.
    from safecadence.reports import _scope_ctx
    token = _scope_ctx.push_org(org_id)
    try:
        return _compose_report_impl(
            sections=sections,
            scope=scope,
            store=store,
            title=title,
            include_delta=include_delta,
        )
    finally:
        _scope_ctx.pop_org(token)


def _compose_report_impl(
    *,
    sections,
    scope: dict,
    store,
    title: str,
    include_delta: bool,
) -> dict:
    keys = list(sections) if sections else [s["key"] for s in SECTION_REGISTRY if s.get("default_enabled")]

    own_store = False
    if store is None:
        store = _open_default_store()
        own_store = True

    out_sections: list[dict] = []
    for key in keys:
        meta = get_section(key)
        if not meta:
            out_sections.append({
                "key": key, "title": key, "data": {},
                "html_fragment": "", "empty": True,
                "error": "unknown_section",
            })
            continue
        try:
            res = meta["fn"](store, scope)
        except Exception as exc:  # pragma: no cover - defensive
            res = {
                "title": meta["name"],
                "data": {"error": str(exc)},
                "html_fragment": (
                    f'<div class="sc-empty"><strong>{meta["name"]}</strong>'
                    f'<br><small>Section failed to render: {exc}</small></div>'),
                "empty": True,
            }
        out_sections.append({
            "key": key,
            "title": res.get("title") or meta["name"],
            "category": meta.get("category"),
            "data": res.get("data") or {},
            "html_fragment": res.get("html_fragment") or "",
            "empty": bool(res.get("empty")),
        })

    if own_store and store is not None:
        try:
            store.close()
        except Exception:
            pass

    delta_payload: dict | None = None
    if include_delta:
        try:
            from safecadence.reports.delta import (
                compute_delta, decorate_kpi_with_delta,
            )
            delta_payload = compute_delta()
            # Inject sparkline + change badge into the kpi_summary HTML if present.
            for sec in out_sections:
                if sec.get("key") == "kpi_summary" and sec.get("html_fragment"):
                    sec["html_fragment"] = decorate_kpi_with_delta(
                        sec["html_fragment"], delta=delta_payload
                    )
                    break
        except Exception:
            delta_payload = None

    out: dict[str, Any] = {
        "title": title,
        "generated_at": _now_iso(),
        "scope": scope,
        "sections": out_sections,
    }
    if delta_payload is not None:
        out["delta"] = delta_payload
    # v10.8: auto-capture SOC 2 evidence for every control covered by
    # a compliance report. We infer the framework + control list from
    # the scope (when provided) and persist one evidence-of-type-report
    # per control. The capture is best-effort and skipped silently when:
    #   * there's no scope.framework / scope.org_id
    #   * SC_READONLY=1 (the soc2_evidence module already enforces this)
    #   * the workflow package isn't importable
    fw = (scope or {}).get("framework")
    org = (scope or {}).get("org_id")
    controls = (scope or {}).get("controls") or []
    if fw and org and controls:
        try:
            from safecadence.workflow.soc2_evidence import (
                record_report_as_evidence,
            )
            record_report_as_evidence(
                org, fw, list(controls),
                report_blob=None,
                report_filename=f"{fw}-{out['generated_at'][:10]}.json",
                captured_by=(scope or {}).get("captured_by"),
                note="Auto-captured by compose_report()",
            )
        except Exception:                          # pragma: no cover
            pass
    return out


__all__ = ["compose_report", "list_section_keys", "list_scope_keys"]
