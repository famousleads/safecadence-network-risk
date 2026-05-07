"""
v7.9 — Timeline / "what changed".

Aggregates events from multiple persistent stores into one
chronological view:

  * audit log          (every approval, every commit)
  * JIT grants         (created, expired, revoked)
  * comments           (added)
  * assignments        (created, status changes)
  * watchlists         (snapshot deltas)
  * automation         (rule fires)

Provides filtering by entity, kind, severity, time window. Read-only —
this module never mutates source data.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Iterable

from safecadence.intel._store import read


@dataclass
class TimelineEvent:
    timestamp: float
    kind: str                  # audit | jit | comment | assignment | watch | automation
    entity_kind: str = ""
    entity_id: str = ""
    actor: str = ""
    summary: str = ""
    severity: str = "info"
    detail: dict = field(default_factory=dict)


def build_timeline(*, since_seconds: int = 7 * 86400,
                   entity_id: str | None = None,
                   kinds: list[str] | None = None,
                   limit: int = 500,
                   now: float | None = None,
                   audit_events: Iterable[dict] | None = None,
                   jit_grants: Iterable[dict] | None = None) -> list[TimelineEvent]:
    """Compose the timeline. Caller can inject audit_events/jit_grants
    so tests don't depend on the real audit store."""
    t_now = now if now is not None else time.time()
    cutoff = t_now - since_seconds
    events: list[TimelineEvent] = []

    # audit log
    if audit_events is None:
        try:
            from safecadence.audit_engine import recent_events
            audit_events = recent_events(limit=2000)
        except Exception:
            audit_events = []
    for a in (audit_events or []):
        ts = float(a.get("timestamp") or a.get("at") or 0)
        if ts < cutoff:
            continue
        events.append(TimelineEvent(
            timestamp=ts, kind="audit",
            entity_kind=str(a.get("entity_kind") or a.get("kind") or ""),
            entity_id=str(a.get("entity_id") or ""),
            actor=str(a.get("actor") or a.get("user") or ""),
            summary=str(a.get("summary") or a.get("action") or "audit event"),
            severity=str(a.get("severity") or "info"),
            detail=a,
        ))

    # JIT
    if jit_grants is None:
        try:
            from safecadence.identity.jit import list_grants
            jit_grants = [
                {"grant_id": g.grant_id, "principal": g.principal,
                  "action": g.action, "resource": g.resource,
                  "status": g.status, "target": g.target,
                  "created_at": g.created_at, "expires_at": g.expires_at}
                for g in list_grants()
            ]
        except Exception:
            jit_grants = []
    for g in (jit_grants or []):
        for ts_field, label in (
            ("created_at", "JIT grant created"),
            ("expires_at", "JIT grant expired" if g.get("status") == "expired" else None),
        ):
            ts = float(g.get(ts_field) or 0)
            if not label or ts < cutoff or ts > t_now:
                continue
            events.append(TimelineEvent(
                timestamp=ts, kind="jit",
                entity_kind="principal", entity_id=g["principal"],
                actor="system",
                summary=f"{label}: {g['action']} → {g['resource']} via {g['target']}",
                severity="info", detail=g,
            ))

    # comments
    cdata = read("comments", {"comments": [], "assignments": []})
    for c in (cdata.get("comments") or []):
        ts = float(c.get("created_at") or 0)
        if ts < cutoff:
            continue
        events.append(TimelineEvent(
            timestamp=ts, kind="comment",
            entity_kind=c.get("entity_kind", ""),
            entity_id=c.get("entity_id", ""),
            actor=c.get("user", ""),
            summary=(c.get("text", "")[:140] +
                      ("…" if len(c.get("text", "")) > 140 else "")),
            severity="info", detail=c,
        ))
    for a in (cdata.get("assignments") or []):
        ts = float(a.get("updated_at") or a.get("created_at") or 0)
        if ts < cutoff:
            continue
        events.append(TimelineEvent(
            timestamp=ts, kind="assignment",
            entity_kind=a.get("entity_kind", ""),
            entity_id=a.get("entity_id", ""),
            actor=a.get("assigned_by", ""),
            summary=f"assigned to {a.get('assigned_to')} ({a.get('status')})",
            severity="info", detail=a,
        ))

    # watchlist deltas
    wdata = read("watchlists", {})
    for user, watches in wdata.items():
        for w in watches or []:
            ts = float(w.get("last_change_at") or 0)
            if ts < cutoff:
                continue
            events.append(TimelineEvent(
                timestamp=ts, kind="watch",
                entity_kind=w.get("entity_kind", ""),
                entity_id=w.get("entity_id", ""),
                actor=user,
                summary=f"watchlist change: {w.get('last_change_summary')}",
                severity="info", detail=w,
            ))

    # automation fires
    audata = read("automation", {"rules": [], "fires": []})
    for f in (audata.get("fires") or []):
        ts = float(f.get("at") or 0)
        if ts < cutoff:
            continue
        events.append(TimelineEvent(
            timestamp=ts, kind="automation",
            entity_kind="rule", entity_id=f.get("rule_id", ""),
            actor="automation",
            summary=f"rule {f.get('rule_name')} fired ({f.get('action')})",
            severity=f.get("severity", "info"),
            detail=f,
        ))

    # Filter + sort + limit
    if entity_id:
        events = [e for e in events if e.entity_id == entity_id]
    if kinds:
        events = [e for e in events if e.kind in kinds]
    events.sort(key=lambda e: e.timestamp, reverse=True)
    return events[:limit]
