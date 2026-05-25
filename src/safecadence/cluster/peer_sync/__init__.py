"""
v12.2 — Peer-to-peer continuous-sync HA (Architecture B).

The alternative to Architecture A (shared Postgres + Redis + S3).
Two SafeCadence nodes talk directly to each other over a single TCP
socket; the active node ships every state-changing event to the
standby as it happens. No shared infrastructure required — perfect
for MSP pair-of-boxes deployments and air-gapped installs.

How to enable
-------------

Set on **both** nodes (in addition to the default ``safecadence ui``
config)::

    SC_HA_MODE=peer-sync
    SC_PEER_SECRET=<shared HMAC secret>             # required, >= 24 chars
    SC_PEER_HOST=<the OTHER node's hostname/IP>
    SC_PEER_PORT=8767                               # default
    SC_PEER_LISTEN_HOST=0.0.0.0                     # default
    SC_PEER_LISTEN_PORT=8767                        # default

The active node opens an outbound TCP connection to ``SC_PEER_HOST``.
The standby listens on ``SC_PEER_LISTEN_PORT``. Both nodes try to be
active; the one that successfully promotes wins.

Single-node behavior
--------------------

When ``SC_HA_MODE`` is unset (or ``none``), this entire module is
inert. No threads start, no sockets open, no schema migration runs.

Submodules
----------

* ``writer``     — event log (peer_events table + record_event())
* ``transport``  — length-prefixed JSON-over-TCP framing
* ``streamer``   — active node sender + reconnect/catch-up loop
* ``applier``    — standby receiver + idempotent apply + ACKs
* ``heartbeat``  — liveness monitor + auto-promotion + manual flips

Public top-level functions
--------------------------

* ``start_peer_sync(conn, *, mode=None)`` — wires everything up based
  on env vars. Idempotent; safe to call from ``ui/app.py`` boot.
* ``stop_peer_sync()`` — stops the daemon threads (for tests + clean
  shutdown).
* ``peer_sync_status()`` → dict with role + streamer state + applier
  state.

The five submodule public APIs are also re-exported here.
"""
from __future__ import annotations

import logging
import os
import socket
import threading
import time
from typing import Any

from safecadence.cluster.peer_sync.applier import (
    ensure_applier_schema,
    last_applied_seq,
    register_handler,
    serve as _serve_applier,
)
from safecadence.cluster.peer_sync.heartbeat import (
    LivenessMonitor,
    LivenessSignals,
    PROMOTE_AFTER_S,
    demote_self,
    ensure_role_schema,
    get_role,
    promote_self,
    request_demotion,
    set_role,
)
from safecadence.cluster.peer_sync.streamer import (
    Streamer,
    StreamerConfig,
)
from safecadence.cluster.peer_sync.writer import (
    ensure_event_schema,
    list_events_since,
    newest_seq,
    oldest_seq,
    record_event,
)

_log = logging.getLogger("safecadence.cluster.peer_sync")


# --------------------------------------------------------------------------
# Module-level daemon state
# --------------------------------------------------------------------------


_STATE: dict = {
    "active_streamer": None,    # Streamer instance
    "streamer_thread": None,
    "applier_thread": None,
    "monitor_thread": None,
    "stop_event": None,
    "conn": None,
    "last_event_received_at": 0.0,
    "last_heartbeat_received_at": 0.0,
}


# --------------------------------------------------------------------------
# Public start / stop / status
# --------------------------------------------------------------------------


def is_enabled() -> bool:
    return (os.getenv("SC_HA_MODE") or "").lower() == "peer-sync"


def start_peer_sync(conn: Any) -> bool:
    """Wire up the writer/applier/streamer/monitor daemon threads.

    Returns True when something was actually started; False when
    SC_HA_MODE != peer-sync (no-op).
    """
    if not is_enabled():
        return False
    if _STATE["stop_event"] is not None:
        return True  # already running

    # Required configuration
    secret = (os.getenv("SC_PEER_SECRET") or "").strip()
    if len(secret) < 24:
        _log.error(
            "SC_PEER_SECRET must be set and >= 24 chars; peer-sync disabled"
        )
        return False
    peer_host = (os.getenv("SC_PEER_HOST") or "").strip()
    peer_port = int(os.getenv("SC_PEER_PORT") or "8767")
    listen_host = os.getenv("SC_PEER_LISTEN_HOST") or "0.0.0.0"
    listen_port = int(os.getenv("SC_PEER_LISTEN_PORT") or "8767")
    node_name = os.getenv("SC_NODE_NAME") or socket.gethostname()

    # Schema bootstrap
    ensure_event_schema(conn)
    ensure_applier_schema(conn)
    ensure_role_schema(conn)

    stop = threading.Event()
    _STATE["conn"] = conn
    _STATE["stop_event"] = stop

    # Applier always runs (every node can receive).
    applier_t = threading.Thread(
        target=_serve_applier,
        args=(conn, listen_host, listen_port),
        kwargs={"stop_event": stop, "accept_timeout": 1.0},
        daemon=True, name="peer-sync-applier",
    )
    applier_t.start()
    _STATE["applier_thread"] = applier_t

    # Streamer runs only when we're active and we have a peer to send to.
    # We start it always; it'll stay idle if there are no events.
    if peer_host:
        streamer = Streamer(conn, StreamerConfig(
            peer_host=peer_host, peer_port=peer_port, node_name=node_name,
        ))
        streamer_t = threading.Thread(
            target=streamer.run, args=(stop,),
            daemon=True, name="peer-sync-streamer",
        )
        streamer_t.start()
        _STATE["active_streamer"] = streamer
        _STATE["streamer_thread"] = streamer_t

    # Liveness monitor: every 5s, check whether we should promote.
    monitor = LivenessMonitor(conn, promote_after_s=PROMOTE_AFTER_S)
    monitor_t = threading.Thread(
        target=_monitor_loop, args=(monitor, stop),
        daemon=True, name="peer-sync-monitor",
    )
    monitor_t.start()
    _STATE["monitor_thread"] = monitor_t

    _log.info(
        "peer-sync started: node=%s peer=%s:%s listen=%s:%s",
        node_name, peer_host, peer_port, listen_host, listen_port,
    )
    return True


def stop_peer_sync() -> None:
    stop = _STATE.get("stop_event")
    if stop is None:
        return
    stop.set()
    for key in ("streamer_thread", "applier_thread", "monitor_thread"):
        t = _STATE.get(key)
        if t is not None:
            t.join(timeout=3)
        _STATE[key] = None
    _STATE["stop_event"] = None
    _STATE["active_streamer"] = None
    _log.info("peer-sync stopped")


def record_replicated_event(kind: str, payload: dict) -> int | None:
    """Module-level convenience: record an event using the daemon's
    own connection. Returns the assigned seq, or None when peer-sync
    is disabled / not initialized.

    Mutation paths call this from inside their existing guards so that
    when peer-sync is off, the call is a cheap no-op.
    """
    if not is_enabled():
        return None
    conn = _STATE.get("conn")
    if conn is None:
        return None
    try:
        return record_event(conn, kind, payload)
    except Exception:
        return None


def peer_sync_status() -> dict:
    """One-shot status snapshot for /api/v1/cluster/peer/status."""
    conn = _STATE.get("conn")
    role = None
    last_applied = None
    n_oldest = None
    n_newest = None
    if conn is not None:
        try:
            role = get_role(conn)
            last_applied = last_applied_seq(conn)
            n_oldest = oldest_seq(conn)
            n_newest = newest_seq(conn)
        except Exception:
            pass

    streamer = _STATE.get("active_streamer")
    streamer_status = streamer.status() if streamer is not None else None

    return {
        "enabled": is_enabled(),
        "role": role,
        "last_applied_seq": last_applied,
        "local_event_log": {"oldest": n_oldest, "newest": n_newest},
        "streamer": streamer_status,
        "last_event_received_at": _STATE.get("last_event_received_at", 0.0),
        "last_heartbeat_received_at":
            _STATE.get("last_heartbeat_received_at", 0.0),
    }


# --------------------------------------------------------------------------
# Monitor loop
# --------------------------------------------------------------------------


def _monitor_loop(monitor: LivenessMonitor, stop: threading.Event) -> None:
    while not stop.is_set():
        try:
            sig = LivenessSignals(
                last_event_received_at=_STATE["last_event_received_at"],
                last_heartbeat_received_at=_STATE["last_heartbeat_received_at"],
                now=time.time(),
            )
            monitor.tick(sig)
        except Exception as exc:
            _log.exception("monitor tick failed: %s", exc)
        stop.wait(5.0)


# --------------------------------------------------------------------------
# Public re-exports
# --------------------------------------------------------------------------


__all__ = [
    # entry points
    "is_enabled", "start_peer_sync", "stop_peer_sync", "peer_sync_status",
    "record_replicated_event",
    # writer
    "ensure_event_schema", "record_event",
    "list_events_since", "oldest_seq", "newest_seq",
    # applier
    "ensure_applier_schema", "last_applied_seq", "register_handler",
    # heartbeat / role control
    "ensure_role_schema", "get_role", "set_role",
    "request_demotion", "promote_self", "demote_self",
    "LivenessSignals", "LivenessMonitor", "PROMOTE_AFTER_S",
    # streamer
    "Streamer", "StreamerConfig",
]
