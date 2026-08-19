"""
Events REST surface — /api/v1/events/*

  POST /api/v1/events/webhook   inbound event ingest (token-auth, for
                                 external senders that have no JWT —
                                 SIEM forwards, camera VMS callbacks,
                                 monitoring relays)
  GET  /api/v1/events           query (viewer+)
  GET  /api/v1/events/summary   counts by severity/source (viewer+)
  POST /api/v1/events/listeners/start   start syslog/trap listeners (admin)

Webhook auth: ``Authorization: Bearer $SC_EVENTS_WEBHOOK_TOKEN`` (or
``X-SC-Webhook-Token``). 503 when the token env is unset — ingest is
opt-in, never accidentally open.
"""

from __future__ import annotations

import hmac
import os
from typing import Any


def build_router():
    try:
        from fastapi import APIRouter, Body, Depends, HTTPException, Request
    except Exception:                                  # pragma: no cover
        return None

    try:
        from safecadence.auth.rbac import UserRole, require_role
        _viewer_dep = require_role(UserRole.VIEWER)
        _admin_dep = require_role(UserRole.ADMIN)
    except Exception:                                  # pragma: no cover
        def _viewer_dep():
            return None

        def _admin_dep():
            return None

    from safecadence.events.schema import Event
    from safecadence.events.store import append_event, event_counts, query_events

    router = APIRouter(prefix="/api/v1/events", tags=["events"])

    def _check_webhook_token(request) -> None:
        expected = (os.environ.get("SC_EVENTS_WEBHOOK_TOKEN") or "").strip()
        if not expected:
            raise HTTPException(503, "event webhook not configured "
                                       "(set SC_EVENTS_WEBHOOK_TOKEN)")
        auth = request.headers.get("Authorization", "")
        provided = auth[7:].strip() if auth.lower().startswith("bearer ") \
            else request.headers.get("X-SC-Webhook-Token", "").strip()
        if not provided or not hmac.compare_digest(provided, expected):
            raise HTTPException(401, "bad webhook token")

    @router.post("/webhook")
    async def webhook_ingest(request: Request, payload: dict = Body(...)):
        _check_webhook_token(request)
        sev = str(payload.get("severity", "info")).lower()
        if sev not in ("critical", "high", "medium", "low", "info"):
            sev = "info"
        evt = Event(
            source="webhook",
            source_ip=(request.client.host if request.client else ""),
            event_type=str(payload.get("event_type", "webhook.custom"))[:120],
            severity=sev,
            description=str(payload.get("description", ""))[:500],
            asset_id=str(payload.get("asset_id", ""))[:120],
            hostname=str(payload.get("hostname", ""))[:200],
            site=str(payload.get("site", ""))[:120],
            occurred_at=str(payload.get("occurred_at", ""))[:64],
            raw={"payload": {k: v for k, v in list(payload.items())[:40]}},
        )
        return append_event(evt)

    @router.get("")
    def list_events(limit: int = 200, severity: str = "", source: str = "",
                     asset_id: str = "", days: int = 2,
                     _: Any = Depends(_viewer_dep)):
        limit = max(1, min(int(limit), 1000))
        days = max(1, min(int(days), 30))
        return {"events": query_events(limit=limit, severity=severity,
                                          source=source, asset_id=asset_id,
                                          days=days)}

    @router.get("/summary")
    def summary(days: int = 2, _: Any = Depends(_viewer_dep)):
        return event_counts(days=max(1, min(int(days), 30)))

    @router.post("/listeners/start")
    def listeners_start(_: Any = Depends(_admin_dep)):
        from safecadence.events.listeners import start_listeners
        return start_listeners()

    return router
