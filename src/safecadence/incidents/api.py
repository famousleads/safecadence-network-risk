"""
Incidents REST surface — /api/v1/incidents/*

  GET    /api/v1/incidents                 list (viewer+)
  POST   /api/v1/incidents                 create (editor+)
  GET    /api/v1/incidents/{id}            detail (viewer+)
  POST   /api/v1/incidents/{id}/status     transition (editor+)
  POST   /api/v1/incidents/{id}/notes      add note (editor+)
  POST   /api/v1/incidents/{id}/events     attach events (editor+)
"""

from __future__ import annotations

from typing import Any


def build_router():
    try:
        from fastapi import APIRouter, Body, Depends, HTTPException
    except Exception:                                  # pragma: no cover
        return None

    try:
        from safecadence.auth.rbac import UserRole, require_role
        _viewer_dep = require_role(UserRole.VIEWER)
        _editor_dep = require_role(UserRole.EDITOR)
    except Exception:                                  # pragma: no cover
        def _viewer_dep():
            return None

        def _editor_dep():
            return None

    from safecadence.incidents.store import (
        add_note, attach_events, create_incident, get_incident,
        list_incidents, transition_incident,
    )

    router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])

    @router.get("")
    def _list(status: str = "", severity: str = "", site: str = "",
               limit: int = 200, _: Any = Depends(_viewer_dep)):
        return {"incidents": list_incidents(
            status=status, severity=severity, site=site,
            limit=max(1, min(int(limit), 1000)))}

    @router.post("")
    def _create(payload: dict = Body(...), _: Any = Depends(_editor_dep)):
        try:
            inc = create_incident(
                str(payload.get("title", "")),
                severity=str(payload.get("severity", "medium")),
                incident_type=str(payload.get("incident_type", "operational")),
                site=str(payload.get("site", "")),
                agency=str(payload.get("agency", "")),
                owner=str(payload.get("owner", "")),
                affected_assets=[str(a) for a in
                                   (payload.get("affected_assets") or [])],
                mission_impact=str(payload.get("mission_impact", "")),
                event_ids=[str(e) for e in (payload.get("event_ids") or [])],
                actor=str(payload.get("actor", "api")))
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        return inc.to_dict()

    @router.get("/{incident_id}")
    def _detail(incident_id: str, _: Any = Depends(_viewer_dep)):
        inc = get_incident(incident_id)
        if inc is None:
            raise HTTPException(404, "incident not found")
        return inc.to_dict()

    @router.post("/{incident_id}/status")
    def _status(incident_id: str, payload: dict = Body(...),
                 _: Any = Depends(_editor_dep)):
        try:
            inc = transition_incident(
                incident_id, str(payload.get("status", "")),
                actor=str(payload.get("actor", "api")),
                note=str(payload.get("note", "")),
                resolution=str(payload.get("resolution", "")))
        except KeyError as exc:
            raise HTTPException(404, "incident not found") from exc
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        return inc.to_dict()

    @router.post("/{incident_id}/notes")
    def _note(incident_id: str, payload: dict = Body(...),
               _: Any = Depends(_editor_dep)):
        try:
            inc = add_note(incident_id, str(payload.get("note", "")),
                            actor=str(payload.get("actor", "api")))
        except KeyError as exc:
            raise HTTPException(404, "incident not found") from exc
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        return inc.to_dict()

    @router.post("/{incident_id}/events")
    def _events(incident_id: str, payload: dict = Body(...),
                 _: Any = Depends(_editor_dep)):
        try:
            inc = attach_events(
                incident_id,
                [str(e) for e in (payload.get("event_ids") or [])],
                actor=str(payload.get("actor", "api")))
        except KeyError as exc:
            raise HTTPException(404, "incident not found") from exc
        return inc.to_dict()

    return router
