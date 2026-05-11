"""
SafeCadence job queue (v10.7).

Single public entry point::

    from safecadence.queue import enqueue, dequeue, set_status, get_status

If ``SC_REDIS_URL`` is set, calls are proxied to :mod:`safecadence.queue.redis_queue`
(a stdlib-only RESP client). Otherwise calls fall through to an
in-memory dict so the local CLI / demo / unit tests keep working
without Redis.

Demo behaviour is preserved: no Redis = no new mandatory dep.
"""

from __future__ import annotations

import os
import threading
import time as _time
import uuid
from typing import Any


# --------------------------------------------------------------------------
# In-memory fallback
# --------------------------------------------------------------------------


_LOCK = threading.Lock()
_QUEUES: dict[str, list[tuple[str, dict]]] = {}
_STATUS: dict[str, dict[str, Any]] = {}
_STATUS_TTL = 60 * 60  # 1h


def _redis_url() -> str | None:
    return os.environ.get("SC_REDIS_URL") or None


def _reap() -> None:
    cutoff = _time.time() - _STATUS_TTL
    with _LOCK:
        for jid in list(_STATUS.keys()):
            if _STATUS[jid].get("_ts", 0) < cutoff:
                _STATUS.pop(jid, None)


def _mem_enqueue(queue_name: str, payload: dict) -> str:
    job_id = uuid.uuid4().hex[:16]
    with _LOCK:
        _QUEUES.setdefault(queue_name, []).append((job_id, dict(payload)))
        _STATUS[job_id] = {"status": "queued", "_ts": _time.time()}
    return job_id


def _mem_dequeue(queue_name: str, timeout: int = 0):
    deadline = _time.time() + max(0, timeout)
    while True:
        with _LOCK:
            q = _QUEUES.get(queue_name)
            if q:
                job_id, payload = q.pop(0)
                return job_id, payload
        if timeout <= 0 or _time.time() >= deadline:
            return None
        _time.sleep(0.05)


def _mem_set_status(job_id: str, status: str, result=None) -> None:
    with _LOCK:
        entry = _STATUS.setdefault(job_id, {})
        entry["status"] = status
        entry["_ts"] = _time.time()
        if result is not None:
            entry["result"] = result


def _mem_get_status(job_id: str) -> dict:
    with _LOCK:
        e = _STATUS.get(job_id)
        return dict(e) if e else {"status": "unknown"}


# --------------------------------------------------------------------------
# Public API — proxy to Redis when configured
# --------------------------------------------------------------------------


def is_redis_configured() -> bool:
    return bool(_redis_url())


def enqueue(queue_name: str, payload: dict) -> str:
    """Push a job onto the queue, return its id."""
    if _redis_url():
        from safecadence.queue import redis_queue as rq
        return rq.enqueue(queue_name, payload)
    return _mem_enqueue(queue_name, payload)


def dequeue(queue_name: str, timeout: int = 30):
    """Blocking pop. Returns ``(job_id, payload)`` or ``None`` on timeout."""
    _reap()
    if _redis_url():
        from safecadence.queue import redis_queue as rq
        return rq.dequeue(queue_name, timeout=timeout)
    return _mem_dequeue(queue_name, timeout=timeout)


def set_status(job_id: str, status: str, result=None) -> None:
    if _redis_url():
        from safecadence.queue import redis_queue as rq
        return rq.set_status(job_id, status, result=result)
    _mem_set_status(job_id, status, result=result)


def get_status(job_id: str) -> dict:
    if _redis_url():
        from safecadence.queue import redis_queue as rq
        return rq.get_status(job_id)
    return _mem_get_status(job_id)


def clear_local_for_tests() -> None:
    """Test helper: wipe the in-memory state."""
    with _LOCK:
        _QUEUES.clear()
        _STATUS.clear()


__all__ = [
    "enqueue", "dequeue", "set_status", "get_status",
    "is_redis_configured", "clear_local_for_tests",
]
