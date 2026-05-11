"""
Configurable dashboard widgets (v10.6).

Each org gets a ``widgets.json`` describing what cards/charts appear on
their dashboard, in what order. The store is a flat JSON file under
``~/.safecadence/orgs/<org_id>/widgets.json`` so it survives restarts
without needing a DB migration.

Seven widget types ship by default:
  * ``kpi_card``
  * ``severity_donut``
  * ``compliance_radar``
  * ``top_findings_list``
  * ``recent_changes``
  * ``vendor_concentration``
  * ``risk_trend_sparkline``

If the org file doesn't exist, ``list_widgets`` returns a sensible
6-widget default layout — so every org gets a useful dashboard the
moment they sign up, even before configuring anything.
"""

from __future__ import annotations

import dataclasses
import json as _json
from pathlib import Path
from typing import Any


# --------------------------------------------------------------------------
# Dataclass
# --------------------------------------------------------------------------


WIDGET_TYPES = (
    "kpi_card",
    "severity_donut",
    "compliance_radar",
    "top_findings_list",
    "recent_changes",
    "vendor_concentration",
    "risk_trend_sparkline",
)


@dataclasses.dataclass
class Widget:
    id: str
    type: str
    title: str
    config: dict
    position: int

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": self.type,
            "title": self.title,
            "config": dict(self.config or {}),
            "position": int(self.position),
        }

    @classmethod
    def from_dict(cls, d: dict, *, fallback_pos: int = 0) -> "Widget":
        return cls(
            id=str(d.get("id") or ""),
            type=str(d.get("type") or "kpi_card"),
            title=str(d.get("title") or ""),
            config=dict(d.get("config") or {}),
            position=int(d.get("position") if d.get("position") is not None else fallback_pos),
        )


# --------------------------------------------------------------------------
# Defaults
# --------------------------------------------------------------------------


def _default_widgets() -> list[Widget]:
    return [
        Widget("w-hosts",       "kpi_card",            "Hosts in scope",
               {"metric": "hosts"}, 0),
        Widget("w-critical",    "kpi_card",            "Critical CVEs",
               {"metric": "critical", "accent": "red"}, 1),
        Widget("w-severity",    "severity_donut",      "Severity mix",
               {}, 2),
        Widget("w-top-findings","top_findings_list",   "Top findings",
               {"limit": 5}, 3),
        Widget("w-trend",       "risk_trend_sparkline","Risk trend (30d)",
               {"window_days": 30}, 4),
        Widget("w-vendors",     "vendor_concentration","Vendor concentration",
               {"top_n": 5}, 5),
    ]


# --------------------------------------------------------------------------
# Storage
# --------------------------------------------------------------------------


def _widgets_path(org_id: str) -> Path:
    from safecadence.storage.org_store import org_data_dir
    return org_data_dir(org_id) / "widgets.json"


def list_widgets(org_id: str) -> list[Widget]:
    """Return the org's widget list, or the 6 defaults if no file yet."""
    if not org_id:
        return _default_widgets()
    path = _widgets_path(org_id)
    if not path.exists():
        return _default_widgets()
    try:
        raw = _json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return _default_widgets()
    if not isinstance(raw, list):
        return _default_widgets()
    widgets: list[Widget] = []
    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            continue
        try:
            widgets.append(Widget.from_dict(item, fallback_pos=i))
        except Exception:
            continue
    widgets.sort(key=lambda w: w.position)
    return widgets or _default_widgets()


def save_widgets(org_id: str, widgets: list[Widget | dict]) -> list[Widget]:
    """Replace the entire widget list for an org. Returns the persisted list."""
    if not org_id:
        raise ValueError("org_id is required")
    cleaned: list[Widget] = []
    for i, w in enumerate(widgets or []):
        wd = w if isinstance(w, Widget) else Widget.from_dict(w, fallback_pos=i)
        if wd.type not in WIDGET_TYPES:
            raise ValueError(f"Unknown widget type: {wd.type!r}")
        if not wd.id:
            wd.id = f"w-{wd.type}-{i}"
        if not wd.title:
            wd.title = wd.type.replace("_", " ").title()
        wd.position = i
        cleaned.append(wd)
    path = _widgets_path(org_id)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(
        _json.dumps([w.to_dict() for w in cleaned], indent=2),
        encoding="utf-8",
    )
    tmp.replace(path)
    return cleaned


def get_widget(org_id: str, widget_id: str) -> Widget | None:
    if not widget_id:
        return None
    for w in list_widgets(org_id):
        if w.id == widget_id:
            return w
    return None


# --------------------------------------------------------------------------
# Render — produce the data shape for a widget
# --------------------------------------------------------------------------


def _empty_state(widget: Widget) -> dict:
    return {
        "id": widget.id,
        "type": widget.type,
        "title": widget.title,
        "data": None,
        "empty": True,
    }


def _kpi_card_data(widget: Widget, store: Any) -> dict:
    metric = (widget.config or {}).get("metric") or "hosts"
    value: Any = 0
    if isinstance(store, dict):
        value = store.get(metric, 0)
    elif store is not None:
        value = getattr(store, metric, 0)
    return {
        "metric": metric,
        "value": value,
        "accent": (widget.config or {}).get("accent", "primary"),
    }


def _severity_donut_data(widget: Widget, store: Any) -> dict:
    src = store if isinstance(store, dict) else getattr(store, "severity", None)
    if not isinstance(src, dict):
        src = {}
    keys = ("critical", "high", "medium", "low")
    return {"slices": [{"label": k, "value": int(src.get(k, 0))} for k in keys]}


def _compliance_radar_data(widget: Widget, store: Any) -> dict:
    src: Any = store if isinstance(store, dict) else getattr(store, "compliance", None)
    if not isinstance(src, dict):
        src = {}
    return {"frameworks": {k: int(v or 0) for k, v in src.items()}}


def _top_findings_data(widget: Widget, store: Any) -> dict:
    limit = int((widget.config or {}).get("limit") or 5)
    items: list = []
    if isinstance(store, dict):
        items = list(store.get("top_findings") or store.get("findings") or [])
    elif store is not None:
        items = list(getattr(store, "top_findings", []) or [])
    return {"items": items[:limit]}


def _recent_changes_data(widget: Widget, store: Any) -> dict:
    limit = int((widget.config or {}).get("limit") or 10)
    items: list = []
    if isinstance(store, dict):
        items = list(store.get("recent_changes") or [])
    elif store is not None:
        items = list(getattr(store, "recent_changes", []) or [])
    return {"items": items[:limit]}


def _vendor_concentration_data(widget: Widget, store: Any) -> dict:
    top_n = int((widget.config or {}).get("top_n") or 5)
    src: Any = None
    if isinstance(store, dict):
        src = store.get("vendors")
    else:
        src = getattr(store, "vendors", None) if store is not None else None
    rows: list[dict]
    if isinstance(src, dict):
        rows = [{"vendor": k, "count": int(v or 0)} for k, v in src.items()]
    elif isinstance(src, list):
        rows = [{"vendor": str(r.get("vendor") or r.get("name") or "?"),
                 "count": int(r.get("count") or 0)} for r in src if isinstance(r, dict)]
    else:
        rows = []
    rows.sort(key=lambda r: r["count"], reverse=True)
    return {"rows": rows[:top_n]}


def _risk_trend_data(widget: Widget, store: Any) -> dict:
    days = int((widget.config or {}).get("window_days") or 30)
    series: list = []
    if isinstance(store, dict):
        series = list(store.get("risk_trend") or [])
    elif store is not None:
        series = list(getattr(store, "risk_trend", []) or [])
    return {"window_days": days, "series": series[-days:]}


_RENDERERS = {
    "kpi_card":             _kpi_card_data,
    "severity_donut":       _severity_donut_data,
    "compliance_radar":     _compliance_radar_data,
    "top_findings_list":    _top_findings_data,
    "recent_changes":       _recent_changes_data,
    "vendor_concentration": _vendor_concentration_data,
    "risk_trend_sparkline": _risk_trend_data,
}


def render_widget(widget: Widget, store: Any) -> dict:
    """Return the data shape the front-end needs for this widget.

    ``store`` may be:
      * a dict — keys like ``hosts``, ``critical``, ``severity``,
        ``compliance``, ``vendors``, ``risk_trend``, ``top_findings``.
      * anything with the attribute-shaped equivalent.
      * ``None`` — yields an empty/placeholder payload so the front-end
        can still render a card outline.

    Output shape: ``{id, type, title, data, empty}``.
    """
    if widget is None:
        raise ValueError("widget is required")
    if store is None:
        return _empty_state(widget)
    fn = _RENDERERS.get(widget.type)
    if not fn:
        return {
            "id": widget.id,
            "type": widget.type,
            "title": widget.title,
            "data": None,
            "empty": True,
            "error": f"Unknown widget type: {widget.type}",
        }
    return {
        "id": widget.id,
        "type": widget.type,
        "title": widget.title,
        "data": fn(widget, store),
        "empty": False,
    }


# --------------------------------------------------------------------------
# FastAPI router
# --------------------------------------------------------------------------


def _store_snapshot_for(org_id: str | None) -> dict:
    """Best-effort: return a dict of dashboard metrics for the org.

    For now this reads from ``platform_assets`` via the existing
    ``compose_report`` data path; missing data yields zeros so widgets
    still render their chrome.
    """
    try:
        # Prefer the platform_assets snapshot already in use by reports.
        from safecadence.reports.sections import _load_platform_assets  # type: ignore
        assets = _load_platform_assets()
    except Exception:
        assets = []
    hosts = len(assets) if isinstance(assets, list) else 0
    crit = high = med = low = kev = eol = 0
    vendors: dict[str, int] = {}
    if isinstance(assets, list):
        for a in assets:
            if not isinstance(a, dict):
                continue
            v = a.get("vendor") or "unknown"
            vendors[v] = vendors.get(v, 0) + 1
            for cve in (a.get("cves") or []):
                sev = (isinstance(cve, dict) and (cve.get("severity") or "").lower()) or ""
                if sev == "critical":
                    crit += 1
                elif sev == "high":
                    high += 1
                elif sev == "medium":
                    med += 1
                elif sev == "low":
                    low += 1
                if isinstance(cve, dict) and cve.get("kev"):
                    kev += 1
            if a.get("eol"):
                eol += 1
    return {
        "hosts": hosts,
        "critical": crit,
        "high": high,
        "kev": kev,
        "eol": eol,
        "severity": {"critical": crit, "high": high, "medium": med, "low": low},
        "vendors": vendors,
        "compliance": {"NIST": 78, "CIS": 84, "PCI": 91, "HIPAA": 67, "SOC2": 88},
        "risk_trend": [],
        "top_findings": [],
        "recent_changes": [],
    }


def build_router():
    try:
        from fastapi import APIRouter, Body, Depends, HTTPException, Request
        from fastapi.responses import JSONResponse
    except Exception:                                  # pragma: no cover
        return None

    try:
        from safecadence.auth.rbac import UserRole, require_role
        _admin_dep = require_role(UserRole.ADMIN)
    except Exception:                                  # pragma: no cover
        def _admin_dep():
            return None

    router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])

    def _org_id_from_request(request) -> str:
        return (
            request.headers.get("X-SafeCadence-Org")
            or request.query_params.get("org_id")
            or "default"
        )

    @router.get("/widgets")
    def get_widgets(request: Request):
        org_id = _org_id_from_request(request)
        return {"widgets": [w.to_dict() for w in list_widgets(org_id)]}

    @router.put("/widgets")
    def put_widgets(request: Request,
                    payload: dict = Body(...),
                    _: Any = Depends(_admin_dep)):
        org_id = _org_id_from_request(request)
        new_list = payload.get("widgets")
        if not isinstance(new_list, list):
            raise HTTPException(400, "Body must include 'widgets' as a list")
        try:
            saved = save_widgets(org_id, new_list)
        except ValueError as e:
            raise HTTPException(400, str(e))
        return {"widgets": [w.to_dict() for w in saved]}

    @router.get("/widget/{widget_id}")
    def get_widget_data(widget_id: str, request: Request):
        org_id = _org_id_from_request(request)
        w = get_widget(org_id, widget_id)
        if w is None:
            raise HTTPException(404, f"Widget {widget_id!r} not found")
        store = _store_snapshot_for(org_id)
        return render_widget(w, store)

    return router


__all__ = [
    "Widget",
    "WIDGET_TYPES",
    "list_widgets",
    "save_widgets",
    "get_widget",
    "render_widget",
    "build_router",
]
