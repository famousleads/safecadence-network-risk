"""
Stdlib-only Redis client (v10.7).

We deliberately don't depend on the ``redis`` package — keeps zero new
mandatory deps. Talks raw RESP2 over a TCP socket to the Redis server
specified by ``SC_REDIS_URL`` (``redis://host:port/db``).

The surface area is intentionally tiny — just what the job queue
needs:

    * ``enqueue(queue_name, payload) -> job_id``       (LPUSH + HSET status)
    * ``dequeue(queue_name, timeout=30) -> (id, dict)``  (BRPOP)
    * ``set_status(job_id, status, result=None)``      (HSET + EXPIRE)
    * ``get_status(job_id) -> dict``                   (HGETALL)

If a connection fails we log + fall back to the in-memory queue from
``safecadence.queue.__init__`` rather than crashing — the demo / local
CLI never depends on a healthy Redis.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import threading
import time as _time
import uuid
from typing import Any
from urllib.parse import urlparse

_log = logging.getLogger("safecadence.queue.redis")

_STATUS_TTL_SECONDS = 60 * 60  # 1h


# --------------------------------------------------------------------------
# Connection cache (one socket per thread, lazy)
# --------------------------------------------------------------------------


_TLS = threading.local()


def _parse_url(url: str) -> tuple[str, int, int, str | None]:
    u = urlparse(url)
    host = u.hostname or "127.0.0.1"
    port = int(u.port or 6379)
    db = 0
    if u.path and u.path.strip("/").isdigit():
        db = int(u.path.strip("/"))
    password = u.password
    return host, port, db, password


def _connect() -> socket.socket:
    url = os.environ.get("SC_REDIS_URL", "")
    if not url:
        raise RuntimeError("SC_REDIS_URL not configured")
    host, port, db, password = _parse_url(url)
    sock = socket.create_connection((host, port), timeout=5.0)
    if password:
        _send(sock, "AUTH", password)
        _recv(sock)
    if db:
        _send(sock, "SELECT", str(db))
        _recv(sock)
    return sock


def _get_sock() -> socket.socket:
    sock = getattr(_TLS, "sock", None)
    if sock is None:
        sock = _connect()
        _TLS.sock = sock
    return sock


def _drop_sock() -> None:
    sock = getattr(_TLS, "sock", None)
    if sock is not None:
        try:
            sock.close()
        except Exception:
            pass
        _TLS.sock = None


# --------------------------------------------------------------------------
# RESP protocol (request: array of bulk strings; response: parse)
# --------------------------------------------------------------------------


def _encode(*args: str) -> bytes:
    out = [f"*{len(args)}\r\n".encode()]
    for a in args:
        b = a.encode() if isinstance(a, str) else bytes(a)
        out.append(f"${len(b)}\r\n".encode())
        out.append(b)
        out.append(b"\r\n")
    return b"".join(out)


def _send(sock: socket.socket, *args: str) -> None:
    sock.sendall(_encode(*args))


def _recv_line(sock: socket.socket) -> bytes:
    buf = bytearray()
    while True:
        ch = sock.recv(1)
        if not ch:
            raise ConnectionError("redis closed connection")
        buf += ch
        if buf.endswith(b"\r\n"):
            return bytes(buf[:-2])


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("redis closed connection")
        buf += chunk
    return bytes(buf)


def _recv(sock: socket.socket):
    line = _recv_line(sock)
    if not line:
        raise ConnectionError("empty reply")
    t = line[:1]
    body = line[1:]
    if t == b"+":
        return body.decode()
    if t == b"-":
        raise RuntimeError(f"REDIS ERR: {body.decode()}")
    if t == b":":
        return int(body)
    if t == b"$":
        n = int(body)
        if n == -1:
            return None
        data = _recv_exact(sock, n)
        _recv_exact(sock, 2)  # trailing \r\n
        return data
    if t == b"*":
        n = int(body)
        if n == -1:
            return None
        return [_recv(sock) for _ in range(n)]
    raise RuntimeError(f"Unknown RESP type: {line!r}")


def _command(*args: str):
    try:
        sock = _get_sock()
        _send(sock, *args)
        return _recv(sock)
    except (ConnectionError, OSError, socket.timeout) as exc:
        _log.warning("redis command %s failed: %s", args[0] if args else "?", exc)
        _drop_sock()
        raise


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def _job_key(job_id: str) -> str:
    return f"safecadence:job:{job_id}"


def _queue_key(queue_name: str) -> str:
    return f"safecadence:queue:{queue_name}"


def enqueue(queue_name: str, payload: dict) -> str:
    job_id = uuid.uuid4().hex[:16]
    body = json.dumps({"job_id": job_id, "payload": payload})
    try:
        _command("HSET", _job_key(job_id), "status", "queued", "ts", str(_time.time()))
        _command("EXPIRE", _job_key(job_id), str(_STATUS_TTL_SECONDS))
        _command("LPUSH", _queue_key(queue_name), body)
        return job_id
    except Exception:
        # Fall back to in-memory so callers never crash.
        from safecadence import queue as _q
        return _q._mem_enqueue(queue_name, payload)


def dequeue(queue_name: str, timeout: int = 30):
    try:
        res = _command("BRPOP", _queue_key(queue_name), str(max(0, timeout)))
        if not res:
            return None
        # res is [key_bytes, value_bytes]
        _key, value = res[0], res[1]
        body = value.decode() if isinstance(value, (bytes, bytearray)) else value
        msg = json.loads(body)
        return msg["job_id"], msg.get("payload", {})
    except Exception:
        from safecadence import queue as _q
        return _q._mem_dequeue(queue_name, timeout=timeout)


def set_status(job_id: str, status: str, result=None) -> None:
    try:
        args = ["HSET", _job_key(job_id), "status", status, "ts", str(_time.time())]
        if result is not None:
            args += ["result", json.dumps(result, default=str)]
        _command(*args)
        _command("EXPIRE", _job_key(job_id), str(_STATUS_TTL_SECONDS))
    except Exception:
        from safecadence import queue as _q
        _q._mem_set_status(job_id, status, result=result)


def get_status(job_id: str) -> dict:
    try:
        res = _command("HGETALL", _job_key(job_id))
        if not res:
            return {"status": "unknown"}
        out: dict[str, Any] = {}
        # RESP returns a flat list [k, v, k, v, ...] in RESP2.
        for i in range(0, len(res), 2):
            k = res[i].decode() if isinstance(res[i], (bytes, bytearray)) else res[i]
            v = res[i + 1].decode() if isinstance(res[i + 1], (bytes, bytearray)) else res[i + 1]
            out[k] = v
        if "result" in out:
            try:
                out["result"] = json.loads(out["result"])
            except Exception:
                pass
        return out
    except Exception:
        from safecadence import queue as _q
        return _q._mem_get_status(job_id)


def ping() -> bool:
    """Diagnostic: is Redis reachable right now?"""
    try:
        return _command("PING") == "PONG"
    except Exception:
        return False


__all__ = ["enqueue", "dequeue", "set_status", "get_status", "ping"]
