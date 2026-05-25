"""
v16.0 — Proactive operator-nudge queue.

A "nudge" is the agent saying: *"hey, you probably want to know about
this — here's what I noticed, here's what I'd recommend."* It lands
in the operator's inbox at `/nudges`. They accept (agent files the
recommendation), dismiss (agent learns to not re-suggest), or snooze
(re-surface in N days).

This is what makes the v16 agent **proactive** rather than
request-response. The operator doesn't have to ask. The agent watches,
notices, and surfaces.

Storage
-------

::

    CREATE TABLE agent_nudges (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        agent_id    TEXT NOT NULL,
        signature   TEXT NOT NULL,            -- dedup; matches memory.signature
        title       TEXT NOT NULL,
        body        TEXT NOT NULL,
        severity    TEXT NOT NULL DEFAULT 'info',  -- info|warning|critical
        category    TEXT NOT NULL DEFAULT 'general',
        suggested_action TEXT,                 -- machine-actionable hint
        status      TEXT NOT NULL DEFAULT 'pending',  -- pending|accepted|dismissed|snoozed
        created_at  INTEGER NOT NULL,
        decided_at  INTEGER,
        decided_by  TEXT,
        snooze_until INTEGER,
        evidence    TEXT NOT NULL DEFAULT '{}'   -- JSON for the UI to render
    );

Live updates
------------

When a new nudge is created, we publish to the v13 SSE event bus
so any open dashboard tab gets it instantly without a refresh.

Public API
----------

* ``ensure_nudge_schema(conn)``
* ``create_nudge(conn, agent_id, signature, title, body, **kw)`` → id
  (returns 0 if dedup'd via has_recent in agent_memory)
* ``list_nudges(conn, *, status='pending', limit=50)``
* ``accept_nudge(conn, nudge_id, operator)``
* ``dismiss_nudge(conn, nudge_id, operator, reason='')``
* ``snooze_nudge(conn, nudge_id, operator, days=7)``
* ``promote_due_snoozes(conn)``  — moves expired snoozes back to pending
* ``nudge_summary(conn)``  → ``{pending, accepted, dismissed, snoozed}``
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any

from safecadence.agents.memory import has_recent, record

_log = logging.getLogger("safecadence.agents.nudges")


VALID_STATUSES = ("pending", "accepted", "dismissed", "snoozed")
VALID_SEVERITIES = ("info", "warning", "critical")


_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS agent_nudges (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id         TEXT NOT NULL,
    signature        TEXT NOT NULL,
    title            TEXT NOT NULL,
    body             TEXT NOT NULL,
    severity         TEXT NOT NULL DEFAULT 'info',
    category         TEXT NOT NULL DEFAULT 'general',
    suggested_action TEXT,
    status           TEXT NOT NULL DEFAULT 'pending',
    created_at       INTEGER NOT NULL,
    decided_at       INTEGER,
    decided_by       TEXT,
    snooze_until     INTEGER,
    evidence         TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_nudges_status
    ON agent_nudges(status);
CREATE INDEX IF NOT EXISTS idx_nudges_agent
    ON agent_nudges(agent_id);
CREATE INDEX IF NOT EXISTS idx_nudges_created
    ON agent_nudges(created_at);
"""


def ensure_nudge_schema(conn: Any) -> None:
    cur = conn.cursor()
    for stmt in _SCHEMA_SQL.split(";"):
        s = stmt.strip()
        if s:
            cur.execute(s)
    conn.commit()


def _publish_live(event_kind: str, payload: dict) -> None:
    """Fan out to the v13 SSE bus. Best-effort; never raises."""
    try:
        from safecadence.dashboards.sse import publish
        publish(event_kind, payload)
    except Exception:
        pass


def create_nudge(
    conn: Any,
    *,
    agent_id: str,
    signature: str,
    title: str,
    body: str,
    severity: str = "info",
    category: str = "general",
    suggested_action: str | None = None,
    evidence: dict | None = None,
    dedup_within_days: int = 14,
    now_ts: int | None = None,
) -> int:
    """Create a nudge. Returns the new id, or 0 when a recent nudge
    with the same (agent_id, signature) already exists (dedup'd).

    Dedup uses ``agent_memory.has_recent`` — same signature pattern
    the rest of the agent stack uses.
    """
    if severity not in VALID_SEVERITIES:
        raise ValueError(f"unknown severity: {severity!r}")
    now = now_ts if now_ts is not None else int(time.time())

    # Dedup against the agent's own memory of prior nudges.
    if has_recent(
        conn, agent_id=agent_id, signature=signature,
        within_days=dedup_within_days, now_ts=now,
    ):
        return 0

    cur = conn.execute(
        "INSERT INTO agent_nudges "
        "(agent_id, signature, title, body, severity, category, "
        "suggested_action, status, created_at, evidence) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)",
        (agent_id, signature, title, body, severity, category,
         suggested_action,
         now, json.dumps(evidence or {}, sort_keys=True)),
    )
    nudge_id = int(cur.lastrowid)
    conn.commit()

    # Record into agent_memory so future create_nudge with same sig dedup's.
    record(
        conn, agent_id=agent_id, kind="nudge_sent",
        signature=signature,
        payload={"nudge_id": nudge_id, "title": title},
        ttl_days=dedup_within_days,
        now_ts=now,
    )

    # Live push to dashboards.
    _publish_live("nudge_created", {
        "id": nudge_id, "agent_id": agent_id,
        "title": title, "severity": severity,
        "category": category,
    })
    return nudge_id


def _row_to_dict(r: tuple) -> dict:
    return {
        "id": r[0], "agent_id": r[1], "signature": r[2],
        "title": r[3], "body": r[4], "severity": r[5],
        "category": r[6], "suggested_action": r[7],
        "status": r[8], "created_at": r[9], "decided_at": r[10],
        "decided_by": r[11], "snooze_until": r[12],
        "evidence": json.loads(r[13] or "{}"),
    }


def list_nudges(
    conn: Any, *, status: str | None = "pending",
    agent_id: str | None = None, limit: int = 50,
) -> list[dict]:
    sql = (
        "SELECT id, agent_id, signature, title, body, severity, "
        "category, suggested_action, status, created_at, decided_at, "
        "decided_by, snooze_until, evidence FROM agent_nudges WHERE 1=1"
    )
    params: list = []
    if status:
        sql += " AND status = ?"
        params.append(status)
    if agent_id:
        sql += " AND agent_id = ?"
        params.append(agent_id)
    sql += " ORDER BY created_at DESC LIMIT ?"
    params.append(int(limit))
    rows = conn.execute(sql, params).fetchall()
    return [_row_to_dict(r) for r in rows]


def accept_nudge(conn: Any, nudge_id: int, operator: str) -> bool:
    """Operator accepted the nudge — record the decision."""
    now = int(time.time())
    cur = conn.execute(
        "UPDATE agent_nudges SET status='accepted', decided_at=?, decided_by=? "
        "WHERE id=? AND status='pending'",
        (now, operator, nudge_id),
    )
    conn.commit()
    if cur.rowcount > 0:
        row = conn.execute(
            "SELECT agent_id, signature, title FROM agent_nudges WHERE id=?",
            (nudge_id,),
        ).fetchone()
        if row:
            record(conn, agent_id=row[0], kind="decision",
                    signature=f"accepted:{row[1]}",
                    payload={"nudge_id": nudge_id, "by": operator,
                             "title": row[2]},
                    ttl_days=None)
        _publish_live("nudge_decided", {"id": nudge_id, "decision": "accepted"})
    return cur.rowcount > 0


def dismiss_nudge(
    conn: Any, nudge_id: int, operator: str, reason: str = "",
) -> bool:
    """Operator dismissed it — don't re-suggest (until memory expires)."""
    now = int(time.time())
    cur = conn.execute(
        "UPDATE agent_nudges SET status='dismissed', decided_at=?, decided_by=? "
        "WHERE id=? AND status='pending'",
        (now, operator, nudge_id),
    )
    conn.commit()
    if cur.rowcount > 0:
        row = conn.execute(
            "SELECT agent_id, signature, title FROM agent_nudges WHERE id=?",
            (nudge_id,),
        ).fetchone()
        if row:
            record(conn, agent_id=row[0], kind="decision",
                    signature=f"dismissed:{row[1]}",
                    payload={"nudge_id": nudge_id, "by": operator,
                             "title": row[2], "reason": reason},
                    ttl_days=None)
        _publish_live("nudge_decided", {"id": nudge_id, "decision": "dismissed"})
    return cur.rowcount > 0


def snooze_nudge(
    conn: Any, nudge_id: int, operator: str, days: int = 7,
) -> bool:
    """Snooze for N days; the daily ``promote_due_snoozes`` job moves it
    back to pending when the snooze expires."""
    now = int(time.time())
    until = now + max(1, int(days)) * 86_400
    cur = conn.execute(
        "UPDATE agent_nudges SET status='snoozed', snooze_until=?, "
        "decided_at=?, decided_by=? "
        "WHERE id=? AND status='pending'",
        (until, now, operator, nudge_id),
    )
    conn.commit()
    return cur.rowcount > 0


def promote_due_snoozes(conn: Any, *, now_ts: int | None = None) -> int:
    """Move snoozed-but-expired nudges back to pending."""
    now = now_ts if now_ts is not None else int(time.time())
    cur = conn.execute(
        "UPDATE agent_nudges SET status='pending', snooze_until=NULL "
        "WHERE status='snoozed' AND snooze_until IS NOT NULL AND snooze_until < ?",
        (now,),
    )
    conn.commit()
    return cur.rowcount


def nudge_summary(conn: Any) -> dict:
    counts = {}
    for s in VALID_STATUSES:
        row = conn.execute(
            "SELECT COUNT(*) FROM agent_nudges WHERE status = ?", (s,),
        ).fetchone()
        counts[s] = int(row[0]) if row else 0
    return counts


__all__ = [
    "VALID_STATUSES", "VALID_SEVERITIES",
    "ensure_nudge_schema",
    "create_nudge",
    "list_nudges",
    "accept_nudge", "dismiss_nudge", "snooze_nudge",
    "promote_due_snoozes",
    "nudge_summary",
]
