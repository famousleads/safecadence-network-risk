"""
v13.0 — Server-Sent Events live dashboards.

A tiny pub/sub bus over an in-process Queue per connected client,
exposed via the SSE wire format (text/event-stream). Other modules
``publish()`` an event; every connected dashboard tab receives it
within a few hundred milliseconds.

What gets published
-------------------

* Drift events from the v13 drift_daemon
* New findings from a scheduled scan completion
* Ticket-status updates from the v13 bidirectional ticketing module
* Cluster role flips from peer-sync (active ↔ standby)

The publisher is fire-and-forget; if no clients are connected the
event just expires. There is no event log here — that's the
``cluster.peer_sync.writer`` module's job.

Public API
----------

* ``EventBus()`` — one instance per process; ``get_event_bus()``
  returns the singleton.
* ``publish(event_type, payload)`` — module-level helper.
* ``register_routes(app)`` — mounts ``GET /api/v1/events/stream`` on
  the given FastAPI app.

SSE wire format
---------------

Each event sent down the connection looks like::

    event: drift
    data: {"hostname":"fw-01","severity":"high","detail":"SSH open"}

    event: heartbeat
    data: {"ts":1779000123}

The browser-side ``EventSource`` API receives these as named events.
"""
from __future__ import annotations

import json
import logging
import queue
import threading
import time
from typing import Any

_log = logging.getLogger("safecadence.dashboards.sse")


HEARTBEAT_INTERVAL_S: float = 20.0
MAX_QUEUE_PER_CLIENT: int = 200


# --------------------------------------------------------------------------
# Event bus
# --------------------------------------------------------------------------


class EventBus:
    """In-process pub/sub. Each subscriber gets its own bounded queue.

    Thread-safe. Lockless on the publish path (we just iterate over a
    snapshot of subscribers); the only lock guards add/remove of
    subscribers themselves.
    """

    def __init__(self) -> None:
        self._subs: list[queue.Queue] = []
        self._lock = threading.Lock()
        self._sent = 0
        self._dropped = 0

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=MAX_QUEUE_PER_CLIENT)
        with self._lock:
            self._subs.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            try:
                self._subs.remove(q)
            except ValueError:
                pass

    def publish(self, event_type: str, payload: Any) -> int:
        """Fan out to every subscriber's queue. Returns the number of
        subscribers that received the event (subscribers whose queues
        are full are silently dropped — keeps a slow tab from blocking
        a fast one)."""
        with self._lock:
            snapshot = list(self._subs)
        delivered = 0
        for q in snapshot:
            try:
                q.put_nowait((event_type, payload))
                delivered += 1
            except queue.Full:
                self._dropped += 1
        self._sent += delivered
        return delivered

    def stats(self) -> dict:
        with self._lock:
            return {
                "subscribers": len(self._subs),
                "sent_total": self._sent,
                "dropped_total": self._dropped,
            }


_BUS: EventBus | None = None
_BUS_LOCK = threading.Lock()


def get_event_bus() -> EventBus:
    global _BUS
    with _BUS_LOCK:
        if _BUS is None:
            _BUS = EventBus()
        return _BUS


def publish(event_type: str, payload: Any) -> int:
    """Module-level shortcut. Safe to call from anywhere."""
    return get_event_bus().publish(event_type, payload)


# --------------------------------------------------------------------------
# SSE wire format
# --------------------------------------------------------------------------


def _format_sse(event_type: str, payload: Any) -> bytes:
    """Encode one (event_type, payload) as an SSE frame."""
    body = json.dumps(payload, separators=(",", ":"))
    return f"event: {event_type}\ndata: {body}\n\n".encode("utf-8")


def _stream_generator(stop_after_seconds: float | None = None):
    """Generator that yields SSE bytes for the duration of the
    connection. Each subscriber gets its own copy of this generator.

    ``stop_after_seconds`` is for tests — production calls leave it
    None and the generator runs until the client disconnects."""
    bus = get_event_bus()
    q = bus.subscribe()
    start = time.time()
    last_heartbeat = start
    POLL_INTERVAL = 0.25  # short enough to honor stop_after_seconds
    try:
        # Send a hello so the browser knows the connection is alive.
        yield _format_sse("hello", {"ts": int(start)})
        while True:
            now = time.time()
            if stop_after_seconds is not None:
                if (now - start) >= stop_after_seconds:
                    return
            try:
                ev, payload = q.get(timeout=POLL_INTERVAL)
                yield _format_sse(ev, payload)
            except queue.Empty:
                if (now - last_heartbeat) >= HEARTBEAT_INTERVAL_S:
                    last_heartbeat = now
                    yield _format_sse("heartbeat", {"ts": int(now)})
    finally:
        bus.unsubscribe(q)


# --------------------------------------------------------------------------
# FastAPI wiring
# --------------------------------------------------------------------------


def register_routes(app: Any) -> None:
    """Mount ``GET /api/v1/events/stream`` + ``GET /api/v1/events/stats``."""
    try:
        from fastapi.responses import StreamingResponse
    except Exception:
        return

    @app.get("/api/v1/events/stream")
    def _stream():
        return StreamingResponse(
            _stream_generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",  # disable nginx buffering
            },
        )

    @app.get("/api/v1/events/stats")
    def _stats():
        return get_event_bus().stats()


__all__ = [
    "EventBus", "get_event_bus", "publish",
    "register_routes",
    "HEARTBEAT_INTERVAL_S", "MAX_QUEUE_PER_CLIENT",
]
