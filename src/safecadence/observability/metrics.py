"""
Stdlib-only Prometheus exposition + /healthz/detail dashboard.

We don't depend on ``prometheus_client``. The text format is small,
stable, and easy to hand-render. Counters and histograms live in
process memory (dicts protected by a Lock); a single FastAPI worker is
the v10.x deployment shape, so the visibility/aggregation tradeoff is
fine.

Exposed series
--------------
  * ``safecadence_requests_total{path,method,status}`` — counter.
  * ``safecadence_request_duration_seconds_bucket{path,method,le}`` —
    histogram (plus ``_count`` and ``_sum`` aggregates).
  * ``safecadence_active_sessions`` — gauge of unexpired session count.
  * ``safecadence_reports_generated_total{format,preset}`` — counter
    incremented by report renderers.

Both the middleware and the helpers can be safely no-op'd by removing
the include_router / add_middleware calls. Nothing else depends on
this module at import time.
"""

from __future__ import annotations

import os
import threading
import time
from collections import defaultdict
from typing import Any

try:
    from fastapi import APIRouter, Request
    from fastapi.responses import JSONResponse, PlainTextResponse
    from starlette.middleware.base import BaseHTTPMiddleware
    _FASTAPI_OK = True
except Exception:                                  # pragma: no cover
    _FASTAPI_OK = False
    BaseHTTPMiddleware = object  # type: ignore


# --------------------------------------------------------------------------
# Metric stores
# --------------------------------------------------------------------------


_LOCK = threading.Lock()

# {(path, method, status): count}
REQUESTS_TOTAL: dict[tuple[str, str, str], int] = defaultdict(int)
# {(path, method): {"sum": float, "count": int, "buckets": {le: count}}}
REQUEST_DURATION: dict[tuple[str, str], dict[str, Any]] = {}
# {(format, preset): count}
REPORTS_GENERATED: dict[tuple[str, str], int] = defaultdict(int)

# Histogram bucket boundaries in seconds.
_HISTOGRAM_BUCKETS = (
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5,
    1.0, 2.5, 5.0, 10.0,
)

# Server start time — drives ``uptime_seconds`` on /healthz/detail.
_STARTED_AT = time.time()


def reset_metrics_for_tests() -> None:
    """Wipe in-memory metric state — only call from tests."""
    with _LOCK:
        REQUESTS_TOTAL.clear()
        REQUEST_DURATION.clear()
        REPORTS_GENERATED.clear()


# --------------------------------------------------------------------------
# Recording helpers
# --------------------------------------------------------------------------


def _normalize_path(raw: str) -> str:
    """Collapse path-param ids so cardinality stays sane.

    ``/asset/abc123`` → ``/asset/{id}``. We don't have full route
    knowledge here, so we approximate: any segment that looks like a
    UUID, hex, or 8+ alnum chars becomes ``{id}``.
    """
    if not raw:
        return "/"
    parts = []
    for seg in raw.split("/"):
        if not seg:
            parts.append("")
            continue
        if len(seg) >= 8 and any(c.isdigit() for c in seg) and seg.replace("-", "").replace("_", "").isalnum():
            parts.append("{id}")
        elif len(seg) >= 24 and seg.replace("-", "").isalnum():
            parts.append("{id}")
        else:
            parts.append(seg)
    return "/".join(parts) or "/"


def record_request(path: str, method: str, status: int, duration_s: float) -> None:
    """Update counters + histogram for one finished request."""
    p = _normalize_path(path)
    m = (method or "GET").upper()
    st = str(status)
    with _LOCK:
        REQUESTS_TOTAL[(p, m, st)] += 1
        key = (p, m)
        slot = REQUEST_DURATION.get(key)
        if slot is None:
            slot = {"sum": 0.0, "count": 0,
                    "buckets": {b: 0 for b in _HISTOGRAM_BUCKETS}}
            REQUEST_DURATION[key] = slot
        slot["sum"] += duration_s
        slot["count"] += 1
        for b in _HISTOGRAM_BUCKETS:
            if duration_s <= b:
                slot["buckets"][b] += 1


def record_report_generated(fmt: str, preset: str = "") -> None:
    """Bump the per-(format, preset) report counter."""
    with _LOCK:
        REPORTS_GENERATED[((fmt or "").lower(), (preset or "").lower())] += 1


# --------------------------------------------------------------------------
# Prometheus text renderer
# --------------------------------------------------------------------------


def _esc(v: str) -> str:
    return (v or "").replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def render_metrics_text() -> str:
    """Return the full /metrics text response."""
    from safecadence.auth.magic_link import active_session_count

    out: list[str] = []
    with _LOCK:
        out.append("# HELP safecadence_requests_total Total HTTP requests by path/method/status.")
        out.append("# TYPE safecadence_requests_total counter")
        for (p, m, st), n in sorted(REQUESTS_TOTAL.items()):
            out.append(
                f'safecadence_requests_total{{path="{_esc(p)}",method="{_esc(m)}",status="{_esc(st)}"}} {n}'
            )

        out.append("# HELP safecadence_request_duration_seconds HTTP request latency.")
        out.append("# TYPE safecadence_request_duration_seconds histogram")
        for (p, m), slot in sorted(REQUEST_DURATION.items()):
            for b in _HISTOGRAM_BUCKETS:
                out.append(
                    f'safecadence_request_duration_seconds_bucket{{path="{_esc(p)}",method="{_esc(m)}",le="{b}"}} {slot["buckets"][b]}'
                )
            out.append(
                f'safecadence_request_duration_seconds_bucket{{path="{_esc(p)}",method="{_esc(m)}",le="+Inf"}} {slot["count"]}'
            )
            out.append(
                f'safecadence_request_duration_seconds_sum{{path="{_esc(p)}",method="{_esc(m)}"}} {slot["sum"]:.6f}'
            )
            out.append(
                f'safecadence_request_duration_seconds_count{{path="{_esc(p)}",method="{_esc(m)}"}} {slot["count"]}'
            )

        out.append("# HELP safecadence_active_sessions Currently unexpired sessions on disk.")
        out.append("# TYPE safecadence_active_sessions gauge")
        try:
            n_sess = active_session_count()
        except Exception:
            n_sess = 0
        out.append(f"safecadence_active_sessions {n_sess}")

        out.append("# HELP safecadence_reports_generated_total Reports rendered by format/preset.")
        out.append("# TYPE safecadence_reports_generated_total counter")
        for (fmt, preset), n in sorted(REPORTS_GENERATED.items()):
            out.append(
                f'safecadence_reports_generated_total{{format="{_esc(fmt)}",preset="{_esc(preset)}"}} {n}'
            )

    out.append("")  # trailing newline
    return "\n".join(out)


# --------------------------------------------------------------------------
# Middleware
# --------------------------------------------------------------------------


class MetricsMiddleware(BaseHTTPMiddleware):       # type: ignore[misc]
    """Record request/response counters + duration. Also funnels
    exceptions into the error log."""

    async def dispatch(self, request, call_next):  # type: ignore[override]
        start = time.perf_counter()
        path = request.url.path if hasattr(request, "url") else ""
        method = request.method if hasattr(request, "method") else "GET"
        status = 500
        try:
            response = await call_next(request)
            status = getattr(response, "status_code", 200)
            return response
        except Exception as exc:
            from safecadence.observability.errors import record_error
            record_error(exc, context={"path": path, "method": method})
            raise
        finally:
            duration = time.perf_counter() - start
            try:
                record_request(path, method, status, duration)
            except Exception:                      # pragma: no cover
                pass


# --------------------------------------------------------------------------
# Health helpers
# --------------------------------------------------------------------------


def _disk_free_mb() -> int:
    import shutil
    try:
        usage = shutil.disk_usage(os.path.expanduser("~"))
        return int(usage.free // (1024 * 1024))
    except Exception:
        return 0


def _scheduled_jobs_age_seconds() -> int:
    """Age of the most recent scheduler heartbeat in seconds.

    We look at the mtime of ``~/.safecadence/reports/scheduler.lock``
    (created by the report scheduler). Missing file → -1 ("never run").
    """
    try:
        from pathlib import Path
        p = Path.home() / ".safecadence" / "reports" / "scheduler.lock"
        if not p.exists():
            return -1
        return int(time.time() - p.stat().st_mtime)
    except Exception:
        return -1


def healthz_detail() -> dict:
    """JSON payload for /healthz/detail."""
    from safecadence.observability.errors import recent_error_count
    try:
        from safecadence import __version__
    except Exception:
        __version__ = "unknown"

    free_mb = _disk_free_mb()
    err_count = recent_error_count(window_seconds=3600)
    sched_age = _scheduled_jobs_age_seconds()
    uptime = int(time.time() - _STARTED_AT)

    # Thresholds:
    #   degraded if >10 errors/hr OR disk <500MB OR scheduler >24h stale.
    #   unhealthy if disk <50MB OR errors >100/hr.
    status = "healthy"
    if free_mb < 50 or err_count > 100:
        status = "unhealthy"
    elif free_mb < 500 or err_count > 10 or (sched_age > 86400):
        status = "degraded"

    return {
        "status": status,
        "version": __version__,
        "uptime_seconds": uptime,
        "disk_free_mb": free_mb,
        "recent_errors_count": err_count,
        "scheduled_jobs_age_seconds": sched_age,
    }


# --------------------------------------------------------------------------
# Router
# --------------------------------------------------------------------------


def _make_router():
    if not _FASTAPI_OK:                            # pragma: no cover
        return None
    r = APIRouter()

    @r.get("/metrics", response_class=PlainTextResponse)
    def _metrics() -> str:
        return render_metrics_text()

    @r.get("/healthz/detail")
    def _healthz_detail() -> JSONResponse:
        payload = healthz_detail()
        code = 200 if payload["status"] != "unhealthy" else 503
        return JSONResponse(payload, status_code=code)

    @r.get("/api/v1/admin/errors")
    def _admin_errors() -> dict:
        from safecadence.observability.errors import recent_errors
        return {"errors": recent_errors(limit=100)}

    return r


router = _make_router() if _FASTAPI_OK else None


__all__ = [
    "router",
    "MetricsMiddleware",
    "render_metrics_text",
    "record_request",
    "record_report_generated",
    "healthz_detail",
    "reset_metrics_for_tests",
    "REQUESTS_TOTAL",
    "REQUEST_DURATION",
    "REPORTS_GENERATED",
]
