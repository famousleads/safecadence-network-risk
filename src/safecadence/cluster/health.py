"""
Cluster health (v10.7).

Local + remote node snapshots. The result of :func:`node_health` is what
``/healthz/detail`` returns on every node. :func:`cluster_state` aggregates
that across every peer named in ``SC_CLUSTER_PEERS`` (comma-separated
host[:port]).

All calls are stdlib-only and fail-safe — a misbehaving peer never
takes down the local healthz endpoint.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import time
from typing import Any
from urllib import error as _urlerr
from urllib import request as _urlreq


# --------------------------------------------------------------------------
# Local probes
# --------------------------------------------------------------------------


def _disk_pct() -> float | None:
    try:
        usage = shutil.disk_usage("/")
        return round(usage.used * 100.0 / max(1, usage.total), 1)
    except Exception:
        return None


def _mem_pct() -> float | None:
    """Linux-only /proc/meminfo. Returns None elsewhere."""
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as fh:
            data = {}
            for line in fh:
                k, _, v = line.partition(":")
                v = v.strip().split(" ")[0]
                if v.isdigit():
                    data[k] = int(v)
        total = data.get("MemTotal", 0)
        avail = data.get("MemAvailable", 0)
        if total:
            return round((total - avail) * 100.0 / total, 1)
    except Exception:
        pass
    return None


def _load_avg() -> tuple[float, float, float] | None:
    try:
        return tuple(round(x, 2) for x in os.getloadavg())  # type: ignore[return-value]
    except (AttributeError, OSError):
        return None


def _last_scan_age_seconds() -> int | None:
    """Best-effort: how long since the most recent stored scan."""
    try:
        from safecadence.storage import open_store
        store = open_store()
        try:
            rows = store.list(limit=1)
        finally:
            store.close()
        if not rows:
            return None
        ts_iso = rows[0].get("started_at") or ""
        if not ts_iso:
            return None
        from datetime import datetime, timezone
        ts_iso = ts_iso.replace("Z", "+00:00")
        ts = datetime.fromisoformat(ts_iso)
        return int((datetime.now(timezone.utc) - ts).total_seconds())
    except Exception:
        return None


def _db_status() -> str:
    try:
        from safecadence.storage import open_store
        store = open_store()
        try:
            store.list(limit=1)
        finally:
            store.close()
        return "ok"
    except Exception as exc:  # pragma: no cover
        return f"error: {type(exc).__name__}"


def _redis_status() -> str:
    if not os.environ.get("SC_REDIS_URL"):
        return "not_configured"
    try:
        from safecadence.queue import redis_queue as rq
        return "ok" if rq.ping() else "unreachable"
    except Exception as exc:
        return f"error: {type(exc).__name__}"


def _s3_status() -> str:
    try:
        from safecadence.storage import s3_store as _s3
    except Exception:  # pragma: no cover
        return "not_available"
    if not _s3.is_configured():
        return "not_configured"
    try:
        client = _s3.S3Store()
        client.list_objects(prefix="__healthz__/")
        return "ok"
    except Exception as exc:
        return f"error: {type(exc).__name__}"


def _hostname() -> str:
    return os.environ.get("SC_NODE_NAME") or socket.gethostname()


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def node_health() -> dict[str, Any]:
    """One-shot snapshot of this node's health."""
    return {
        "node": _hostname(),
        "ts": int(time.time()),
        "cpu_load": _load_avg(),
        "mem_used_pct": _mem_pct(),
        "disk_used_pct": _disk_pct(),
        "last_scan_age_s": _last_scan_age_seconds(),
        "db_status": _db_status(),
        "redis_status": _redis_status(),
        "s3_status": _s3_status(),
        "is_active_node": _safe_am_active(),
    }


def _safe_am_active() -> bool:
    try:
        from safecadence.cluster.failover import am_i_active
        return am_i_active()
    except Exception:
        return True  # single-node default


def _peers() -> list[str]:
    raw = os.environ.get("SC_CLUSTER_PEERS", "")
    return [p.strip() for p in raw.split(",") if p.strip()]


def _fetch_peer(host: str, timeout: float = 3.0) -> dict[str, Any]:
    """GET ``http(s)://host/healthz/detail`` and return the parsed JSON."""
    url = host if host.startswith(("http://", "https://")) else f"http://{host}/healthz/detail"
    req = _urlreq.Request(url, headers={"User-Agent": "safecadence-cluster/10.7"})
    try:
        with _urlreq.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            return {"peer": host, "reachable": True, "data": json.loads(body)}
    except (_urlerr.URLError, OSError, ValueError) as exc:
        return {"peer": host, "reachable": False, "error": type(exc).__name__}


def cluster_state(*, fetcher=None) -> dict[str, Any]:
    """Aggregate this node's status with every configured peer.

    ``fetcher`` is injected by tests to avoid real HTTP. By default it
    points at :func:`_fetch_peer`.
    """
    fetch = fetcher or _fetch_peer
    local = node_health()
    peer_results = [fetch(p) for p in _peers()]
    reachable = sum(1 for p in peer_results if p.get("reachable"))
    return {
        "local": local,
        "peers": peer_results,
        "peer_count": len(peer_results),
        "reachable_peers": reachable,
        "healthy": local.get("db_status") == "ok",
    }


__all__ = ["node_health", "cluster_state"]
