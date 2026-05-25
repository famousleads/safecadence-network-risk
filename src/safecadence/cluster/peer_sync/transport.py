"""
v12.2 — Peer-sync transport (length-prefixed JSON frames over TCP).

Wire format
-----------

Every frame is a 4-byte big-endian length prefix followed by that
many bytes of UTF-8 JSON. No keep-alive bytes, no compression, no
framing tricks — just one JSON object per frame.

::

    +----------+-----------------------+
    | len (4B) |    JSON payload       |
    +----------+-----------------------+

The frame payload is always one of these JSON shapes:

* ``{"type":"event",   "seq":N, "kind":"...", "payload":"...", "hmac":"..."}``
* ``{"type":"ack",     "applied_seq":N}``
* ``{"type":"heartbeat","ts":N}``
* ``{"type":"heartbeat-ack","ts":N}``
* ``{"type":"hello",   "node":"...", "last_applied_seq":N}``  (sent on connect)
* ``{"type":"error",   "reason":"..."}``

Why stdlib socket and not WebSocket / gRPC / NATS
-------------------------------------------------

The peer-sync architecture targets the customer who wants two boxes
that talk to each other with no extra infrastructure. Adding a
WebSocket library or gRPC dependency would defeat the purpose. Pure
stdlib socket + struct + json is enough, runs in any Python install,
and works air-gapped.

Public API
----------

* ``MAX_FRAME_BYTES``         — safety cap (default 8 MiB)
* ``send_frame(sock, dict)``
* ``recv_frame(sock, timeout=...)`` → dict | None on clean close
* ``FrameError``
"""
from __future__ import annotations

import json
import socket
import struct
from typing import Any


MAX_FRAME_BYTES: int = 8 * 1024 * 1024  # 8 MiB ceiling per frame


class FrameError(Exception):
    """Raised on protocol violations (oversized frame, malformed JSON,
    peer closed mid-frame, etc.)."""


def _recv_exact(sock: socket.socket, n: int) -> bytes | None:
    """Read exactly n bytes from sock. Returns None on clean EOF
    before any bytes are received; raises FrameError on partial read."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            if not buf:
                return None  # clean close before any data
            raise FrameError(
                f"peer closed mid-frame after {len(buf)} of {n} bytes"
            )
        buf.extend(chunk)
    return bytes(buf)


def send_frame(sock: socket.socket, payload: dict[str, Any]) -> None:
    """Serialize and send one frame. Raises socket.error / FrameError."""
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    if len(body) > MAX_FRAME_BYTES:
        raise FrameError(
            f"frame too large: {len(body)} > {MAX_FRAME_BYTES} bytes"
        )
    header = struct.pack(">I", len(body))
    sock.sendall(header + body)


def recv_frame(sock: socket.socket) -> dict[str, Any] | None:
    """Read one frame. Returns None on clean peer close. Raises
    FrameError on protocol violation, socket.error on connection drop."""
    header = _recv_exact(sock, 4)
    if header is None:
        return None
    (length,) = struct.unpack(">I", header)
    if length <= 0:
        raise FrameError(f"non-positive frame length: {length}")
    if length > MAX_FRAME_BYTES:
        raise FrameError(
            f"frame length exceeds ceiling: {length} > {MAX_FRAME_BYTES}"
        )
    body = _recv_exact(sock, length)
    if body is None:
        raise FrameError("peer closed before frame body")
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FrameError(f"malformed JSON: {exc}") from exc


__all__ = ["MAX_FRAME_BYTES", "FrameError", "send_frame", "recv_frame"]
