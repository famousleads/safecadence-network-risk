"""
v12.0 — FastAPI mount for the read-only customer portal scaffold.

Thin wrapper that turns the renderers in ``customer_ui`` into routes
mountable from ``ui.app``. Lives in its own module so the scaffold
renderers stay framework-free + easy to unit-test.

Routes mounted:

  GET  /customer            — redirect to /customer/posture
  GET  /customer/posture    — Posture tab
  GET  /customer/reports    — Reports tab
  GET  /customer/help       — Help tab

This is a *scaffold*. Auth is intentionally permissive: the routes pull
the active org from a ``X-SafeCadence-Org`` header (or a hardcoded
demo org if the header is absent) and serve read-only HTML. The
magic-link login flow is documented in ``customer_ui.CUSTOMER_PORTAL_ROUTES``
and will land when the operator wires real auth.
"""
from __future__ import annotations

try:
    from fastapi import APIRouter, Request
    from fastapi.responses import HTMLResponse, RedirectResponse
    _FASTAPI_OK = True
except Exception:                                       # pragma: no cover
    _FASTAPI_OK = False


def _demo_org_from_request(request) -> dict:
    name = (request.headers.get("X-SafeCadence-Org") or "Customer").strip()
    return {"display_name": name or "Customer"}


def _make_router():
    if not _FASTAPI_OK:                                 # pragma: no cover
        return None

    from safecadence.portal.customer_ui import (
        render_shell, render_posture_tab,
        render_reports_tab, render_help_tab,
    )

    router = APIRouter()

    @router.get("/customer")
    def customer_root():
        return RedirectResponse(url="/customer/posture", status_code=302)

    @router.get("/customer/posture", response_class=HTMLResponse)
    def customer_posture(request: Request):
        org = _demo_org_from_request(request)
        # Posture is "snapshot of last scan" — pull from sqlite_store
        # when available, otherwise show empty-state.
        posture: dict = {}
        try:
            from safecadence.storage import sqlite_store as _ss
            assets = list(_ss.list_assets() or [])
            crit = sum(
                1 for a in assets for f in (a.get("findings") or [])
                if (f.get("severity") or "").lower() == "critical"
            )
            high = sum(
                1 for a in assets for f in (a.get("findings") or [])
                if (f.get("severity") or "").lower() == "high"
            )
            posture = {
                "asset_count": len(assets),
                "critical_open": crit,
                "high_open": high,
            }
        except Exception:
            pass
        try:
            from safecadence.scores.multi_dim_score import compute_safe_score_flat
            posture["safe_score"] = compute_safe_score_flat()
        except Exception:
            pass

        body = render_posture_tab(org, posture)
        return HTMLResponse(render_shell(
            org=org, active_tab="posture", body_html=body,
        ))

    @router.get("/customer/reports", response_class=HTMLResponse)
    def customer_reports(request: Request):
        org = _demo_org_from_request(request)
        body = render_reports_tab(org, [])  # real list arrives once wired
        return HTMLResponse(render_shell(
            org=org, active_tab="reports", body_html=body,
        ))

    @router.get("/customer/help", response_class=HTMLResponse)
    def customer_help(request: Request):
        org = _demo_org_from_request(request)
        body = render_help_tab(org)
        return HTMLResponse(render_shell(
            org=org, active_tab="help", body_html=body,
        ))

    return router


router = _make_router() if _FASTAPI_OK else None

__all__ = ["router"]
