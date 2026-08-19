"""
Incident model + JSON store + lifecycle.

Storage: one JSON file per incident under ``<data_dir>/incidents/``
(same file-backed pattern as the platform asset store — no DB
dependency, trivially backed up, greppable).

Lifecycle (forward-only, except reopen):
    open → acknowledged → investigating → resolved → closed
    closed → open   (reopen, recorded in the timeline)

Every mutation appends a timeline entry — the incident record IS the
after-action narrative.
"""

from __future__ import annotations

import json
import os
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VALID_STATUSES = ("open", "acknowledged", "investigating",
                    "resolved", "closed")

_TRANSITIONS: dict[str, set[str]] = {
    "open":           {"acknowledged", "investigating", "resolved", "closed"},
    "acknowledged":   {"investigating", "resolved", "closed"},
    "investigating":  {"resolved", "closed"},
    "resolved":       {"closed", "investigating"},   # verify-failed → back
    "closed":         {"open"},                        # reopen
}

_SEVERITIES = ("critical", "high", "medium", "low", "info")
_SAFE_ID = re.compile(r"^inc-[a-f0-9]{12}$")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Incident:
    incident_id: str = field(default_factory=lambda: f"inc-{uuid.uuid4().hex[:12]}")
    title: str = ""
    incident_type: str = "operational"    # operational | security | lifecycle
    severity: str = "medium"
    status: str = "open"
    opened_at: str = field(default_factory=_now)
    closed_at: str = ""
    site: str = ""
    agency: str = ""
    owner: str = ""                        # assignee
    affected_assets: list[str] = field(default_factory=list)
    affected_capabilities: list[str] = field(default_factory=list)
    mission_impact: str = ""
    event_ids: list[str] = field(default_factory=list)
    timeline: list[dict] = field(default_factory=list)
    resolution: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------- storage

def _dir() -> Path:
    root = os.environ.get("SC_DATA_DIR") or str(Path.home() / ".safecadence")
    p = Path(root) / "incidents"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _path(incident_id: str) -> Path:
    if not _SAFE_ID.match(incident_id or ""):
        raise ValueError("bad incident id")
    return _dir() / f"{incident_id}.json"


def _save(inc: Incident) -> None:
    _path(inc.incident_id).write_text(
        json.dumps(inc.to_dict(), ensure_ascii=False, indent=1),
        encoding="utf-8")


def _log(inc: Incident, kind: str, detail: str, actor: str = "") -> None:
    inc.timeline.append({"at": _now(), "kind": kind,
                           "detail": detail, "actor": actor})


# ---------------------------------------------------------------- CRUD

def create_incident(title: str, *, severity: str = "medium",
                     incident_type: str = "operational", site: str = "",
                     agency: str = "", owner: str = "",
                     affected_assets: list[str] | None = None,
                     mission_impact: str = "",
                     event_ids: list[str] | None = None,
                     actor: str = "") -> Incident:
    if not (title or "").strip():
        raise ValueError("title required")
    if severity not in _SEVERITIES:
        raise ValueError(f"severity must be one of {_SEVERITIES}")
    inc = Incident(title=title.strip()[:300], severity=severity,
                    incident_type=incident_type, site=site, agency=agency,
                    owner=owner,
                    affected_assets=list(affected_assets or [])[:200],
                    mission_impact=mission_impact[:500],
                    event_ids=list(event_ids or [])[:500])
    _log(inc, "opened", f"Incident opened (severity={severity})", actor)
    _save(inc)
    return inc


def get_incident(incident_id: str) -> Incident | None:
    try:
        raw = json.loads(_path(incident_id).read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError):
        return None
    except Exception:
        return None
    inc = Incident()
    for k, v in raw.items():
        if hasattr(inc, k):
            setattr(inc, k, v)
    return inc


def list_incidents(*, status: str = "", severity: str = "",
                     site: str = "", limit: int = 200) -> list[dict]:
    out: list[dict] = []
    for f in sorted(_dir().glob("inc-*.json"),
                     key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            rec = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        if status and rec.get("status") != status:
            continue
        if severity and rec.get("severity") != severity:
            continue
        if site and rec.get("site") != site:
            continue
        out.append(rec)
        if len(out) >= limit:
            break
    return out


# ---------------------------------------------------------------- lifecycle

def transition_incident(incident_id: str, new_status: str, *,
                          actor: str = "", note: str = "",
                          resolution: str = "") -> Incident:
    inc = get_incident(incident_id)
    if inc is None:
        raise KeyError(incident_id)
    if new_status not in VALID_STATUSES:
        raise ValueError(f"status must be one of {VALID_STATUSES}")
    if new_status == inc.status:
        return inc
    allowed = _TRANSITIONS.get(inc.status, set())
    if new_status not in allowed:
        raise ValueError(
            f"illegal transition {inc.status} → {new_status} "
            f"(allowed: {sorted(allowed)})")
    old = inc.status
    inc.status = new_status
    if new_status in ("resolved", "closed"):
        if resolution:
            inc.resolution = resolution[:1000]
        if new_status == "closed":
            inc.closed_at = _now()
    if new_status == "open" and old == "closed":
        inc.closed_at = ""
    _log(inc, "status", f"{old} → {new_status}"
          + (f" — {note}" if note else ""), actor)
    _save(inc)
    return inc


def add_note(incident_id: str, note: str, actor: str = "") -> Incident:
    inc = get_incident(incident_id)
    if inc is None:
        raise KeyError(incident_id)
    if not (note or "").strip():
        raise ValueError("note required")
    _log(inc, "note", note.strip()[:2000], actor)
    _save(inc)
    return inc


def attach_events(incident_id: str, event_ids: list[str],
                    actor: str = "") -> Incident:
    inc = get_incident(incident_id)
    if inc is None:
        raise KeyError(incident_id)
    seen = set(inc.event_ids)
    added: list[str] = []
    for e in event_ids:
        if e and e not in seen:
            seen.add(e)
            added.append(e)
    inc.event_ids.extend(added[:500])
    if added:
        _log(inc, "events", f"attached {len(added)} event(s)", actor)
        _save(inc)
    return inc


# ---------------------------------------------------------------- auto-group

_AUTO_SEVERITIES = ("critical", "high")


def attach_or_open_for_event(event: dict, *, actor: str = "auto") -> Incident | None:
    """Correlation-lite: a critical/high event with a resolved asset
    either attaches to that asset's newest open incident or opens a new
    one. Info/medium events never auto-open incidents (noise control).

    Returns the incident touched, or None when the event doesn't
    qualify."""
    sev = str(event.get("severity", "info"))
    asset_id = str(event.get("asset_id", ""))
    if sev not in _AUTO_SEVERITIES or not asset_id:
        return None
    for rec in list_incidents(limit=100):
        if rec.get("status") in ("resolved", "closed"):
            continue
        if asset_id in (rec.get("affected_assets") or []):
            return attach_events(rec["incident_id"],
                                   [str(event.get("event_id", ""))], actor=actor)
    title = (f"{sev.upper()} event on {event.get('hostname') or asset_id}: "
              f"{str(event.get('event_type', 'event'))}")
    return create_incident(
        title[:300], severity=sev,
        incident_type="security" if str(event.get("source")) != "syslog"
        else "operational",
        site=str(event.get("site", "")),
        affected_assets=[asset_id],
        event_ids=[str(event.get("event_id", ""))],
        actor=actor)
