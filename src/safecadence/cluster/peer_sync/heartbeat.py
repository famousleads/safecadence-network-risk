"""
v12.2 — Peer-sync heartbeat + auto-promotion.

In peer-sync mode the standby decides whether to promote itself based
on the answer to two questions, **both** of which must be "yes":

1. **Is the peer connection silent?**  — no heartbeat-ack and no
   inbound event for > ``PROMOTE_AFTER_S`` seconds.

2. **Are we sure we won't split-brain?** — the standby has *not*
   received any event in the same window. If we're receiving events
   the active is alive; the heartbeat may have been dropped, but the
   bigger truth is that data is flowing.

Both conditions together prevent the classic split-brain failure
mode (network blip → standby thinks active is dead → both write).

Manual override
---------------

``request_demotion()`` flips a flag in the local DB asking the active
to step down. The streamer surfaces that on the next heartbeat; the
active relinquishes (stops the streamer loop, sets a "we are
standby" flag). The peer's standby-side liveness monitor then
auto-promotes within ~PROMOTE_AFTER_S.

Lease state
-----------

Peer-sync mode does NOT use the Redis lease (that's Architecture A).
The active/standby state lives in a single-row table
``peer_role(id INTEGER PRIMARY KEY, role TEXT, last_role_change INT)``.

Public API
----------

* ``ensure_role_schema(conn)``
* ``get_role(conn)`` → "active" | "standby" | None
* ``set_role(conn, role)``
* ``LivenessMonitor(conn, peer_sync_state_reader)``
* ``monitor.tick()``       — call from a daemon loop every few seconds
* ``request_demotion()``   — flag-based manual flip
* ``promote_self(conn)``   — operator command
* ``demote_self(conn)``    — operator command
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, Callable

_log = logging.getLogger("safecadence.cluster.peer_sync.heartbeat")


PROMOTE_AFTER_S: float = 30.0   # silent peer for this long → promote
DEMOTE_GRACE_S:  float = 5.0    # operator demotion grace period


_ROLE_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS peer_role (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    role TEXT NOT NULL DEFAULT 'standby',
    last_role_change INTEGER NOT NULL,
    demotion_requested INTEGER NOT NULL DEFAULT 0
);
"""


def ensure_role_schema(conn: Any) -> None:
    cur = conn.cursor()
    for stmt in _ROLE_SCHEMA_SQL.split(";"):
        s = stmt.strip()
        if s:
            cur.execute(s)
    cur.execute(
        "INSERT OR IGNORE INTO peer_role "
        "(id, role, last_role_change) VALUES (1, 'standby', ?)",
        (int(time.time()),),
    )
    conn.commit()


def get_role(conn: Any) -> str:
    ensure_role_schema(conn)
    row = conn.execute(
        "SELECT role FROM peer_role WHERE id = 1"
    ).fetchone()
    return str(row[0]) if row else "standby"


def set_role(conn: Any, role: str) -> None:
    if role not in ("active", "standby"):
        raise ValueError(f"unknown role: {role!r}")
    ensure_role_schema(conn)
    conn.execute(
        "UPDATE peer_role SET role = ?, last_role_change = ? WHERE id = 1",
        (role, int(time.time())),
    )
    conn.commit()


def request_demotion(conn: Any) -> None:
    """Mark this active node for graceful demotion. The streamer checks
    this flag and stops shipping; the peer auto-promotes via the
    LivenessMonitor when heartbeats stop."""
    ensure_role_schema(conn)
    conn.execute(
        "UPDATE peer_role SET demotion_requested = 1 WHERE id = 1"
    )
    conn.commit()


def is_demotion_requested(conn: Any) -> bool:
    ensure_role_schema(conn)
    row = conn.execute(
        "SELECT demotion_requested FROM peer_role WHERE id = 1"
    ).fetchone()
    return bool(row and row[0])


def clear_demotion(conn: Any) -> None:
    ensure_role_schema(conn)
    conn.execute(
        "UPDATE peer_role SET demotion_requested = 0 WHERE id = 1"
    )
    conn.commit()


def promote_self(conn: Any) -> None:
    """Operator command. Used by /api/v1/cluster/peer/promote."""
    set_role(conn, "active")
    clear_demotion(conn)
    _log.info("peer-sync: promoted self to ACTIVE")


def demote_self(conn: Any) -> None:
    """Operator command. Used by /api/v1/cluster/peer/demote."""
    set_role(conn, "standby")
    _log.info("peer-sync: demoted self to STANDBY")


# --------------------------------------------------------------------------
# LivenessMonitor — decides when to auto-promote
# --------------------------------------------------------------------------


@dataclass
class LivenessSignals:
    last_event_received_at: float   # 0 = never
    last_heartbeat_received_at: float  # 0 = never
    now: float


class LivenessMonitor:
    """Polls signals from the applier; promotes self when peer silent.

    The applier should keep two timestamps current (last inbound event,
    last inbound heartbeat) and pass them into ``tick()``. The monitor
    is otherwise stateless — easy to unit-test.
    """

    def __init__(
        self,
        conn: Any,
        *,
        promote_after_s: float = PROMOTE_AFTER_S,
    ) -> None:
        self.conn = conn
        self.promote_after_s = promote_after_s

    def tick(self, signals: LivenessSignals) -> dict:
        """One liveness check. Returns a dict describing the decision."""
        role = get_role(self.conn)
        now = signals.now

        # Active node tick: check if a demotion was requested.
        if role == "active":
            if is_demotion_requested(self.conn):
                demote_self(self.conn)
                return {"action": "demoted", "reason": "demotion_requested"}
            return {"action": "noop", "role": "active"}

        # Standby tick: should we promote?
        last_event = signals.last_event_received_at
        last_hb    = signals.last_heartbeat_received_at
        # Use max() so either signal keeps us standby.
        last_any   = max(last_event, last_hb)
        silent_for = now - last_any if last_any > 0 else float("inf")

        if silent_for > self.promote_after_s:
            promote_self(self.conn)
            return {
                "action": "promoted",
                "reason": f"peer silent for {silent_for:.1f}s",
                "silent_for_s": silent_for,
            }
        return {
            "action": "noop", "role": "standby",
            "silent_for_s": silent_for,
        }


__all__ = [
    "PROMOTE_AFTER_S", "DEMOTE_GRACE_S",
    "ensure_role_schema", "get_role", "set_role",
    "request_demotion", "is_demotion_requested", "clear_demotion",
    "promote_self", "demote_self",
    "LivenessSignals", "LivenessMonitor",
]
