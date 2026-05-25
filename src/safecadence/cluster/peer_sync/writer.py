"""
v12.2 — Peer-sync event log writer.

Every state-changing operation on the active node calls
``record_event(kind, payload)``. The event is appended to a local
SQLite table with a monotonic seq + HMAC. The streamer reads new
rows from that table and ships them to the standby.

The writer is **synchronous** with the originating operation —
write the event in the same transaction that wrote the underlying
data. That guarantees: if the data exists locally, the event row
exists locally; if the standby applies the event, the underlying
data exists there too. There's no "data wrote but event didn't" gap.

Schema
------

``peer_events`` columns:

* ``seq``        — INTEGER PRIMARY KEY AUTOINCREMENT. Monotonic.
* ``kind``       — short string identifying the payload schema.
* ``payload``    — JSON-encoded blob.
* ``hmac``       — SHA-256 HMAC over (seq, kind, payload) using the
                   shared peer secret. Verified by the applier.
* ``created_at`` — UNIX seconds for ops triage.

Public API
----------

* ``ensure_event_schema(conn)``
* ``record_event(conn, kind, payload)`` → seq (int)
* ``list_events_since(conn, last_seq, limit=500)``
* ``oldest_seq(conn)``  / ``newest_seq(conn)``
* ``trim_events_below(conn, min_seq)``
* ``compute_hmac(seq, kind, payload_json, secret)``

The HMAC secret is loaded from ``SC_PEER_SECRET`` env var. Without
it the writer still records events (in-process testing path) but the
streamer refuses to ship them to a remote peer — fail closed.
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import os
import time
from typing import Any


_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS peer_events (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT NOT NULL,
    payload     TEXT NOT NULL,
    hmac        TEXT NOT NULL,
    created_at  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_peer_events_kind ON peer_events(kind);
"""


def ensure_event_schema(conn: Any) -> None:
    cur = conn.cursor()
    for stmt in _SCHEMA_SQL.split(";"):
        s = stmt.strip()
        if s:
            cur.execute(s)
    conn.commit()


def _secret() -> bytes:
    return (os.getenv("SC_PEER_SECRET") or "").encode("utf-8")


def compute_hmac(seq: int, kind: str, payload_json: str, secret: bytes | None = None) -> str:
    """Stable HMAC over (seq, kind, payload). Hex-encoded SHA-256."""
    s = secret if secret is not None else _secret()
    msg = f"{seq}\n{kind}\n{payload_json}".encode("utf-8")
    return _hmac.new(s, msg, hashlib.sha256).hexdigest()


def verify_hmac(
    seq: int, kind: str, payload_json: str, mac: str,
    secret: bytes | None = None,
) -> bool:
    expected = compute_hmac(seq, kind, payload_json, secret=secret)
    return _hmac.compare_digest(expected, mac)


def record_event(conn: Any, kind: str, payload: dict | list) -> int:
    """Insert an event row and return its assigned seq.

    Idempotent in spirit only — caller decides whether to dedupe before
    calling. Two record_event(..) calls with the same (kind, payload)
    produce two rows with two seqs (since seq is autoincrement).
    """
    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    now = int(time.time())
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO peer_events (kind, payload, hmac, created_at) "
        "VALUES (?, ?, '', ?)",
        (kind, payload_json, now),
    )
    seq = cur.lastrowid
    # Now compute the HMAC over the assigned seq and update.
    mac = compute_hmac(seq, kind, payload_json)
    cur.execute("UPDATE peer_events SET hmac = ? WHERE seq = ?", (mac, seq))
    conn.commit()
    return int(seq)


def list_events_since(
    conn: Any, last_seq: int, limit: int = 500,
) -> list[dict]:
    """Return events with seq > last_seq, ordered by seq ascending."""
    rows = conn.execute(
        "SELECT seq, kind, payload, hmac, created_at FROM peer_events "
        "WHERE seq > ? ORDER BY seq ASC LIMIT ?",
        (int(last_seq), int(limit)),
    ).fetchall()
    return [
        {"seq": r[0], "kind": r[1], "payload": r[2],
         "hmac": r[3], "created_at": r[4]}
        for r in rows
    ]


def oldest_seq(conn: Any) -> int | None:
    row = conn.execute("SELECT MIN(seq) FROM peer_events").fetchone()
    return int(row[0]) if row and row[0] is not None else None


def newest_seq(conn: Any) -> int | None:
    row = conn.execute("SELECT MAX(seq) FROM peer_events").fetchone()
    return int(row[0]) if row and row[0] is not None else None


def trim_events_below(conn: Any, min_seq: int) -> int:
    """Delete events with seq < min_seq. Used to prune the buffer once
    the standby has confirmed it's caught up past that point.

    Returns the number of rows deleted.
    """
    cur = conn.execute(
        "DELETE FROM peer_events WHERE seq < ?", (int(min_seq),),
    )
    conn.commit()
    return cur.rowcount


__all__ = [
    "ensure_event_schema",
    "record_event",
    "list_events_since",
    "oldest_seq", "newest_seq",
    "trim_events_below",
    "compute_hmac", "verify_hmac",
]
