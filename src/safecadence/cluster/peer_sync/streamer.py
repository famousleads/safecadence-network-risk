"""
v12.2 — Peer-sync streamer (the active node's sender).

Holds a persistent TCP connection to the standby's applier, ships new
events as they're recorded, and tracks the standby's last-applied seq
via ACK frames.

Reconnect + catch-up
--------------------

On disconnect (peer reboot, network blip, anything), the streamer:

1. Closes the socket cleanly.
2. Waits ``RECONNECT_BACKOFF_S`` (default 5s; doubles on consecutive
   failures up to ``MAX_BACKOFF_S`` 60s).
3. Reconnects + sends a ``hello`` frame with our identity.
4. Reads the standby's ``hello-ack`` to learn its ``last_applied_seq``.
5. Catches up by streaming every event with seq > that value before
   resuming live tail.

This is the same pattern Postgres streaming replication uses (WAL
shipping + replay from last LSN). Idempotency on the applier side
(seq-based dedupe) is what makes this safe even if we mis-count a
boundary.

Public API
----------

* ``StreamerConfig(peer_host, peer_port, node_name)``
* ``Streamer(conn, config)``
* ``streamer.run(stop_event=None)``   — blocks; spawn in a thread
* ``streamer.status()`` → dict
"""
from __future__ import annotations

import logging
import socket
import threading
import time
from dataclasses import dataclass
from typing import Any

from safecadence.cluster.peer_sync.transport import (
    FrameError, recv_frame, send_frame,
)
from safecadence.cluster.peer_sync.writer import (
    list_events_since, oldest_seq, trim_events_below,
)

_log = logging.getLogger("safecadence.cluster.peer_sync.streamer")


RECONNECT_BACKOFF_S: float = 5.0
MAX_BACKOFF_S:       float = 60.0
HEARTBEAT_INTERVAL_S: float = 5.0
BATCH_SIZE:          int   = 200
POLL_INTERVAL_S:     float = 1.0
SOCKET_TIMEOUT_S:    float = 30.0


@dataclass
class StreamerConfig:
    peer_host: str
    peer_port: int
    node_name: str
    keep_trim: bool = True   # prune the local event log once peer is caught up
    trim_keep_recent_seq: int = 100   # keep N most-recent events as buffer


class Streamer:
    """One Streamer per peer. Owns the socket + reconnect state."""

    def __init__(self, conn: Any, config: StreamerConfig) -> None:
        self.conn = conn
        self.config = config
        self._sock: socket.socket | None = None
        self._last_acked_seq: int = 0
        self._last_heartbeat_sent_at: float = 0.0
        self._last_ack_at: float = 0.0
        self._consecutive_failures: int = 0

    # ---------- public ---------------------------------------------- #

    def status(self) -> dict:
        return {
            "peer": f"{self.config.peer_host}:{self.config.peer_port}",
            "connected": self._sock is not None,
            "last_acked_seq": self._last_acked_seq,
            "last_ack_at": self._last_ack_at,
            "consecutive_failures": self._consecutive_failures,
        }

    def run(self, stop_event: threading.Event | None = None) -> None:
        """Main streaming loop. Blocks forever (or until stop_event)."""
        while True:
            if stop_event is not None and stop_event.is_set():
                self._close()
                return
            try:
                self._connect_and_stream(stop_event)
                self._consecutive_failures = 0
            except (socket.error, FrameError, OSError) as exc:
                self._consecutive_failures += 1
                wait = min(
                    RECONNECT_BACKOFF_S * (2 ** (self._consecutive_failures - 1)),
                    MAX_BACKOFF_S,
                )
                _log.info("streamer disconnected (%s); reconnect in %.1fs", exc, wait)
                self._close()
                self._sleep(wait, stop_event)

    # ---------- internals ------------------------------------------ #

    def _connect_and_stream(self, stop_event: threading.Event | None) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(SOCKET_TIMEOUT_S)
        sock.connect((self.config.peer_host, self.config.peer_port))
        self._sock = sock

        # Handshake
        send_frame(sock, {
            "type": "hello",
            "node": self.config.node_name,
            "last_applied_seq": 0,  # we're the sender; peer cares about its own
            "ts": int(time.time()),
        })
        ack = recv_frame(sock)
        if not ack or ack.get("type") != "hello-ack":
            raise FrameError(f"bad hello-ack: {ack}")
        peer_seq = int(ack.get("last_applied_seq", 0))
        self._last_acked_seq = peer_seq
        self._last_ack_at = time.time()
        _log.info(
            "streamer connected to %s:%d; peer last_applied_seq=%d",
            self.config.peer_host, self.config.peer_port, peer_seq,
        )

        # Stream loop: ship events, ack-track, heartbeat.
        while True:
            if stop_event is not None and stop_event.is_set():
                return

            events = list_events_since(
                self.conn, self._last_acked_seq, limit=BATCH_SIZE,
            )

            if events:
                for e in events:
                    send_frame(sock, {
                        "type": "event",
                        "seq": e["seq"],
                        "kind": e["kind"],
                        "payload": e["payload"],
                        "hmac": e["hmac"],
                    })
                    ack_frame = recv_frame(sock)
                    if not ack_frame or ack_frame.get("type") != "ack":
                        raise FrameError(f"expected ack, got {ack_frame}")
                    applied = int(ack_frame.get("applied_seq", 0))
                    if applied > self._last_acked_seq:
                        self._last_acked_seq = applied
                        self._last_ack_at = time.time()

                # Optional buffer prune.
                if self.config.keep_trim:
                    self._maybe_trim()
            else:
                # Idle: maybe heartbeat, then poll.
                now = time.time()
                if (now - self._last_heartbeat_sent_at) >= HEARTBEAT_INTERVAL_S:
                    send_frame(sock, {"type": "heartbeat", "ts": int(now)})
                    self._last_heartbeat_sent_at = now
                    hb = recv_frame(sock)
                    if not hb:
                        raise FrameError("peer closed during heartbeat")
                self._sleep(POLL_INTERVAL_S, stop_event)

    def _maybe_trim(self) -> None:
        """Prune the event log below (last_acked - trim_keep_recent_seq).

        Keeps a small recent buffer so a transient reconnect doesn't
        have to repull everything from scratch.
        """
        keep_from = self._last_acked_seq - self.config.trim_keep_recent_seq
        if keep_from > 1:
            old = oldest_seq(self.conn)
            if old is not None and old < keep_from:
                trim_events_below(self.conn, keep_from)

    def _close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except Exception:
                pass
        self._sock = None

    @staticmethod
    def _sleep(seconds: float, stop_event: threading.Event | None) -> None:
        if stop_event is None:
            time.sleep(seconds)
            return
        # Interruptible sleep.
        end = time.time() + seconds
        while time.time() < end:
            if stop_event.is_set():
                return
            time.sleep(min(0.5, end - time.time()))


__all__ = [
    "StreamerConfig", "Streamer",
    "RECONNECT_BACKOFF_S", "MAX_BACKOFF_S",
    "HEARTBEAT_INTERVAL_S", "BATCH_SIZE", "POLL_INTERVAL_S",
]
