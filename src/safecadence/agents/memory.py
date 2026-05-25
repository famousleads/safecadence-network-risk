"""
v16.0 — Long-running, stateful agent memory.

Most "AI agents" today are stateless: ask a question, get an answer,
conversation ends. SafeCadence v16 agents have **persistent memory**
across days/weeks/months, which is what makes them *proactive* and
*non-repetitive*. The agent remembers:

* Observations it made ("I noticed drift on edge-fw-01 last Tuesday")
* Decisions the operator made in response ("you said this was intentional")
* Nudges it already sent ("I already asked about MFA exception X
  three days ago — don't re-pester")

Storage
-------

One SQLite table per install (NOT per agent — shared so cross-agent
memory works):

    CREATE TABLE agent_memory (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        agent_id   TEXT NOT NULL,
        kind       TEXT NOT NULL,           -- "observation" | "decision" | "nudge_sent"
        signature  TEXT NOT NULL,           -- dedup key (per agent + kind)
        payload    TEXT NOT NULL,           -- JSON
        recorded_at INTEGER NOT NULL,
        expires_at INTEGER                  -- nullable; default 90 days
    );

Why a `signature` column: when a drift event triggers "I should
nudge the operator about exception X expiring," the agent computes
a deterministic signature like `nudge:exception-expiry:X`. Before
sending the nudge, it checks: have I sent this same signature in
the past N days? If yes, skip. This is the single most important
property of a non-annoying assistant.

Public API
----------

* ``ensure_memory_schema(conn)``
* ``record(conn, agent_id, kind, signature, payload, ttl_days=90)`` → id
* ``has_recent(conn, agent_id, signature, within_days=30)`` → bool
* ``recall(conn, agent_id, *, kind=None, since_days=90, limit=200)`` → list[dict]
* ``forget(conn, agent_id, signature)`` → int (rows deleted)
* ``prune_expired(conn)`` → int  (housekeeping)
"""
from __future__ import annotations

import json
import time
from typing import Any


VALID_KINDS = ("observation", "decision", "nudge_sent", "tool_call",
               "review_request", "exception_filed")


_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS agent_memory (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id    TEXT NOT NULL,
    kind        TEXT NOT NULL,
    signature   TEXT NOT NULL,
    payload     TEXT NOT NULL DEFAULT '{}',
    recorded_at INTEGER NOT NULL,
    expires_at  INTEGER
);

CREATE INDEX IF NOT EXISTS idx_agent_memory_agent_sig
    ON agent_memory(agent_id, signature);
CREATE INDEX IF NOT EXISTS idx_agent_memory_kind
    ON agent_memory(kind);
CREATE INDEX IF NOT EXISTS idx_agent_memory_recorded
    ON agent_memory(recorded_at);
"""


def ensure_memory_schema(conn: Any) -> None:
    cur = conn.cursor()
    for stmt in _SCHEMA_SQL.split(";"):
        s = stmt.strip()
        if s:
            cur.execute(s)
    conn.commit()


def record(
    conn: Any,
    *,
    agent_id: str,
    kind: str,
    signature: str,
    payload: dict | None = None,
    ttl_days: int | None = 90,
    now_ts: int | None = None,
) -> int:
    """Append a memory row. Returns the new row id.

    ``ttl_days=None`` means permanent (e.g. operator decisions about
    accepted risks shouldn't expire).
    """
    if kind not in VALID_KINDS:
        raise ValueError(
            f"unknown kind {kind!r}; must be one of {VALID_KINDS}"
        )
    now = now_ts if now_ts is not None else int(time.time())
    expires = (now + ttl_days * 86_400) if ttl_days else None
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO agent_memory "
        "(agent_id, kind, signature, payload, recorded_at, expires_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (agent_id, kind, signature,
         json.dumps(payload or {}, sort_keys=True), now, expires),
    )
    conn.commit()
    return int(cur.lastrowid)


def has_recent(
    conn: Any,
    *,
    agent_id: str,
    signature: str,
    within_days: int = 30,
    now_ts: int | None = None,
) -> bool:
    """True when this (agent, signature) was recorded within window.

    This is the dedup check the agent does before sending a nudge:
    "did I already pester the operator about this in the last N days?"
    """
    now = now_ts if now_ts is not None else int(time.time())
    cutoff = now - within_days * 86_400
    row = conn.execute(
        "SELECT 1 FROM agent_memory "
        "WHERE agent_id = ? AND signature = ? AND recorded_at >= ? "
        "LIMIT 1",
        (agent_id, signature, cutoff),
    ).fetchone()
    return row is not None


def recall(
    conn: Any,
    agent_id: str,
    *,
    kind: str | None = None,
    since_days: int = 90,
    limit: int = 200,
    now_ts: int | None = None,
) -> list[dict]:
    """Return the agent's memory rows, most recent first.

    Use the same kind + signature scheme the agent records under
    to reconstruct prior context for a new decision.
    """
    now = now_ts if now_ts is not None else int(time.time())
    cutoff = now - since_days * 86_400
    sql = (
        "SELECT id, agent_id, kind, signature, payload, recorded_at, "
        "expires_at FROM agent_memory "
        "WHERE agent_id = ? AND recorded_at >= ?"
    )
    params: list[Any] = [agent_id, cutoff]
    if kind:
        sql += " AND kind = ?"
        params.append(kind)
    sql += " ORDER BY recorded_at DESC LIMIT ?"
    params.append(int(limit))
    rows = conn.execute(sql, params).fetchall()
    return [
        {"id": r[0], "agent_id": r[1], "kind": r[2],
         "signature": r[3], "payload": json.loads(r[4] or "{}"),
         "recorded_at": r[5], "expires_at": r[6]}
        for r in rows
    ]


def forget(conn: Any, agent_id: str, signature: str) -> int:
    """Delete all memory rows matching (agent_id, signature).

    Use when the operator says "stop bothering me about X" — we
    forget the prior decision so we don't bring it back up.
    """
    cur = conn.execute(
        "DELETE FROM agent_memory WHERE agent_id = ? AND signature = ?",
        (agent_id, signature),
    )
    conn.commit()
    return cur.rowcount


def prune_expired(conn: Any, *, now_ts: int | None = None) -> int:
    """Housekeeping: delete rows past expires_at. Safe to run on a cron."""
    now = now_ts if now_ts is not None else int(time.time())
    cur = conn.execute(
        "DELETE FROM agent_memory WHERE expires_at IS NOT NULL AND expires_at < ?",
        (now,),
    )
    conn.commit()
    return cur.rowcount


__all__ = [
    "VALID_KINDS",
    "ensure_memory_schema",
    "record",
    "has_recent",
    "recall",
    "forget",
    "prune_expired",
]
