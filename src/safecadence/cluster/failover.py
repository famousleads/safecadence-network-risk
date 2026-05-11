"""
Active/passive failover lease (v10.7).

Single global key in Redis: ``safecadence:cluster:active_node``.

* Lease lives 60s. Active node refreshes it every 15s.
* If the active node dies, the key expires and another node can take it
  via SETNX (NX + EX in one call).
* If Redis isn't configured (``SC_REDIS_URL`` unset), we report this
  node as active forever — that matches the single-node demo behaviour.

Public API::

    am_i_active() -> bool       # boolean check
    renew_lease() -> bool       # refresh, only if we already hold it
    try_take_lease() -> bool    # attempt to grab when nobody holds it
    release_lease() -> None     # voluntarily relinquish
    start_lease_loop(interval=15)  # background thread

A background thread can be started by the daemon at boot.
"""

from __future__ import annotations

import logging
import os
import socket
import threading
import time
from typing import Any

_log = logging.getLogger("safecadence.cluster.failover")

LEASE_KEY = "safecadence:cluster:active_node"
LEASE_TTL_S = 60
RENEW_INTERVAL_S = 15

_NODE_ID = os.environ.get("SC_NODE_NAME") or socket.gethostname() or "node-unknown"
_STOP = threading.Event()
_THREAD: threading.Thread | None = None
_FAKE_OWNER: str | None = None  # used when Redis isn't configured / for tests


# --------------------------------------------------------------------------
# Internals
# --------------------------------------------------------------------------


def _redis_available() -> bool:
    return bool(os.environ.get("SC_REDIS_URL"))


def _redis_cmd(*args: str):
    """Call the stdlib redis client; raises on socket failure."""
    from safecadence.queue.redis_queue import _command  # type: ignore
    return _command(*args)


def _get_current_owner() -> str | None:
    if not _redis_available():
        return _FAKE_OWNER
    try:
        val = _redis_cmd("GET", LEASE_KEY)
        if val is None:
            return None
        return val.decode() if isinstance(val, (bytes, bytearray)) else str(val)
    except Exception as exc:
        _log.debug("lease GET failed: %s", exc)
        return None


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def node_id() -> str:
    return _NODE_ID


def am_i_active() -> bool:
    """Do we currently hold the active-node lease?"""
    if not _redis_available():
        return True  # single-node mode always wins
    owner = _get_current_owner()
    return owner == _NODE_ID


def try_take_lease() -> bool:
    """If nobody holds the lease, take it. Returns True if we now own it."""
    if not _redis_available():
        # Single-node fallback — we always "win".
        global _FAKE_OWNER
        if _FAKE_OWNER is None:
            _FAKE_OWNER = _NODE_ID
        return _FAKE_OWNER == _NODE_ID
    try:
        # SET key value NX EX ttl  -> "OK" if set, None if NX failed.
        res = _redis_cmd("SET", LEASE_KEY, _NODE_ID, "NX", "EX", str(LEASE_TTL_S))
        if res == "OK":
            _log.info("cluster: %s took the active-node lease", _NODE_ID)
            return True
        # Already held — maybe by us
        return am_i_active()
    except Exception as exc:
        _log.warning("lease SETNX failed: %s", exc)
        return False


def renew_lease() -> bool:
    """Refresh the lease if we currently own it. Returns True on success."""
    if not _redis_available():
        return True
    if not am_i_active():
        return False
    try:
        # Use SET XX EX to refresh only when already set + we'll verify owner.
        _redis_cmd("SET", LEASE_KEY, _NODE_ID, "XX", "EX", str(LEASE_TTL_S))
        return True
    except Exception as exc:
        _log.warning("lease renew failed: %s", exc)
        return False


def release_lease() -> None:
    """Voluntarily give up the lease (graceful shutdown)."""
    if not _redis_available():
        global _FAKE_OWNER
        if _FAKE_OWNER == _NODE_ID:
            _FAKE_OWNER = None
        return
    if not am_i_active():
        return
    try:
        _redis_cmd("DEL", LEASE_KEY)
        _log.info("cluster: %s released the lease", _NODE_ID)
    except Exception as exc:  # pragma: no cover
        _log.warning("lease DEL failed: %s", exc)


def _loop(interval: int) -> None:
    while not _STOP.is_set():
        try:
            if am_i_active():
                renew_lease()
            else:
                try_take_lease()
        except Exception as exc:  # pragma: no cover
            _log.exception("lease loop iteration failed: %s", exc)
        _STOP.wait(interval)


def start_lease_loop(interval: int = RENEW_INTERVAL_S) -> threading.Thread:
    """Spawn a daemon thread that renews / contests the lease."""
    global _THREAD
    if _THREAD and _THREAD.is_alive():
        return _THREAD
    _STOP.clear()
    t = threading.Thread(target=_loop, args=(interval,), daemon=True,
                         name="safecadence-failover")
    t.start()
    _THREAD = t
    return t


def stop_lease_loop() -> None:
    """Stop the background renewer (mostly for tests)."""
    _STOP.set()
    global _THREAD
    if _THREAD:
        _THREAD.join(timeout=2.0)
        _THREAD = None


def reset_for_tests() -> None:
    """Wipe in-process state — only the tests use this."""
    global _FAKE_OWNER, _THREAD
    _STOP.set()
    _FAKE_OWNER = None
    _THREAD = None
    _STOP.clear()


__all__ = [
    "am_i_active", "renew_lease", "try_take_lease", "release_lease",
    "start_lease_loop", "stop_lease_loop", "node_id", "reset_for_tests",
    "LEASE_KEY", "LEASE_TTL_S",
]
