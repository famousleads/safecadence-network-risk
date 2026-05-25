"""
v12.2 — Peer-sync applier (the standby's receive loop).

The standby listens on a TCP port. The active node connects to it
and starts shipping events. Each event the applier receives:

1. Has its HMAC verified against the shared ``SC_PEER_SECRET``.
2. Is checked for idempotency — if ``seq <= last_applied_seq``, it's
   silently dropped (the active is just re-sending in case we missed
   the ack).
3. Is dispatched to a per-kind handler. The handler decides what to
   write into the local stores.
4. ``last_applied_seq`` is bumped and persisted.
5. An ``ack`` frame is sent back with the new ``last_applied_seq``.

The applier never raises out of its loop. A bad handler, a malformed
event, or a broken connection logs + continues / reconnects.

Persistence
-----------

``last_applied_seq`` lives in a single-row SQLite table
``peer_sync_state(id INTEGER PRIMARY KEY, last_applied_seq INTEGER)``
so a standby restart resumes from where it left off.

Public API
----------

* ``ensure_applier_schema(conn)``
* ``last_applied_seq(conn)`` → int
* ``set_last_applied_seq(conn, seq)``
* ``register_handler(kind, fn)``  — operator wires a handler per kind
* ``apply_event(conn, event)``     — pure: verify + dispatch + bump
* ``serve(conn, host, port)``      — blocks; the standby's main loop
"""
from __future__ import annotations

import logging
import socket
import time
from typing import Any, Callable

from safecadence.cluster.peer_sync.transport import (
    FrameError, recv_frame, send_frame,
)
from safecadence.cluster.peer_sync.writer import verify_hmac

_log = logging.getLogger("safecadence.cluster.peer_sync.applier")


# In-process registry of (kind → handler). Handlers receive
# (conn, payload_dict). They MUST be idempotent — the applier already
# dedupes on seq, but the handler should still tolerate replay.
_HANDLERS: dict[str, Callable[[Any, dict], None]] = {}


def register_handler(kind: str, fn: Callable[[Any, dict], None]) -> None:
    """Wire a handler for an event kind.

    Convention: the active node ships kinds matching what the writer
    records (``webhook_fire``, ``email_send``, ``finding_upsert``,
    ``scan_complete``, ``audit_append``, etc.). A kind without a
    registered handler is dropped with a warning — fail open, never
    crash the standby.
    """
    _HANDLERS[kind] = fn


def _state_schema(conn: Any) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS peer_sync_state ("
        "id INTEGER PRIMARY KEY CHECK (id = 1), "
        "last_applied_seq INTEGER NOT NULL DEFAULT 0)"
    )
    conn.execute(
        "INSERT OR IGNORE INTO peer_sync_state (id, last_applied_seq) "
        "VALUES (1, 0)"
    )
    conn.commit()


def ensure_applier_schema(conn: Any) -> None:
    _state_schema(conn)


def last_applied_seq(conn: Any) -> int:
    _state_schema(conn)
    row = conn.execute(
        "SELECT last_applied_seq FROM peer_sync_state WHERE id = 1"
    ).fetchone()
    return int(row[0]) if row else 0


def set_last_applied_seq(conn: Any, seq: int) -> None:
    _state_schema(conn)
    conn.execute(
        "UPDATE peer_sync_state SET last_applied_seq = ? WHERE id = 1",
        (int(seq),),
    )
    conn.commit()


def apply_event(conn: Any, event: dict) -> tuple[bool, str]:
    """Verify HMAC, dispatch to handler, bump last_applied_seq.

    Returns (ok, note).
    """
    seq = int(event.get("seq", 0))
    kind = str(event.get("kind", ""))
    payload_json = str(event.get("payload", ""))
    mac = str(event.get("hmac", ""))

    if not verify_hmac(seq, kind, payload_json, mac):
        return False, "bad_hmac"

    if seq <= last_applied_seq(conn):
        return True, "duplicate_dropped"

    handler = _HANDLERS.get(kind)
    if handler is None:
        # Fail open: bump seq so we don't keep re-receiving this
        # event, but log loudly so the operator notices the gap.
        set_last_applied_seq(conn, seq)
        _log.warning("no handler for kind=%s; event dropped", kind)
        return True, "no_handler"

    try:
        import json as _json
        payload = _json.loads(payload_json) if payload_json else {}
        handler(conn, payload)
    except Exception as exc:
        _log.exception("handler %s raised: %s", kind, exc)
        # Don't bump seq — the active will retry on next connect.
        return False, f"handler_error: {type(exc).__name__}"

    set_last_applied_seq(conn, seq)
    return True, "applied"


def serve(
    conn: Any,
    host: str = "0.0.0.0",
    port: int = 8767,
    *,
    accept_timeout: float = 1.0,
    stop_event: Any = None,
) -> None:
    """Listen on (host, port) and apply events from connected peers.

    Blocks. Spawn this in a daemon thread from your boot code.

    ``stop_event`` (optional ``threading.Event``) lets tests stop the
    loop cleanly.
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(1)
    srv.settimeout(accept_timeout)
    _log.info("peer-sync applier listening on %s:%d", host, port)

    try:
        while True:
            if stop_event is not None and stop_event.is_set():
                return
            try:
                client, addr = srv.accept()
            except socket.timeout:
                continue
            _log.info("peer-sync applier connection from %s", addr)
            try:
                _serve_one(conn, client, stop_event=stop_event)
            except Exception as exc:
                _log.warning("connection handler exited: %s", exc)
            finally:
                try:
                    client.close()
                except Exception:
                    pass
    finally:
        srv.close()


def _serve_one(conn: Any, client: socket.socket, *, stop_event: Any) -> None:
    """One connected-peer session. Reads frames, dispatches, ACKs."""
    # First frame should be a "hello" so we know the peer's seq state.
    client.settimeout(10.0)
    hello = recv_frame(client)
    if not hello or hello.get("type") != "hello":
        send_frame(client, {"type": "error", "reason": "expected hello"})
        return
    _log.info("hello from %s; their last_applied_seq=%s",
              hello.get("node"), hello.get("last_applied_seq"))

    # Tell the peer our last_applied_seq so they can replay from there.
    send_frame(client, {
        "type": "hello-ack",
        "last_applied_seq": last_applied_seq(conn),
        "ts": int(time.time()),
    })

    client.settimeout(60.0)
    while True:
        if stop_event is not None and stop_event.is_set():
            return
        try:
            frame = recv_frame(client)
        except (FrameError, socket.timeout, OSError) as exc:
            _log.info("frame error / disconnect: %s", exc)
            return
        if frame is None:
            _log.info("peer closed cleanly")
            return

        t = frame.get("type")
        if t == "event":
            ok, note = apply_event(conn, frame)
            send_frame(client, {
                "type": "ack",
                "applied_seq": last_applied_seq(conn),
                "ok": ok, "note": note,
            })
        elif t == "heartbeat":
            send_frame(client, {
                "type": "heartbeat-ack",
                "ts": int(time.time()),
            })
        else:
            send_frame(client, {
                "type": "error",
                "reason": f"unknown frame type: {t}",
            })


__all__ = [
    "ensure_applier_schema",
    "last_applied_seq", "set_last_applied_seq",
    "register_handler",
    "apply_event",
    "serve",
]
