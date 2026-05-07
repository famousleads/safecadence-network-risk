"""v9.47 — ASGI middleware that logs every authenticated mutation.

Plugs into a FastAPI / Starlette app via ``app.add_middleware``.
Intercepts the request, records the start time, lets the handler
run, then writes one ActivityRecord per request when:

    * the request is a mutation (POST / PUT / PATCH / DELETE) OR
    * SC_ACTIVITY_LOG_READS=1 is set (forensic mode for GETs)

Reads (GET / HEAD / OPTIONS) skip logging by default — too noisy
for a normal install.

Actor extraction: tries the usual JWT bearer token first
(``Authorization: Bearer …``), falls back to
``request.session['user']`` for the cookie-session local UI, and
finally lands on ``"anonymous"`` for unauthenticated probes.

The store write is best-effort; a failed disk write never breaks
the request.
"""

from __future__ import annotations

import os
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from .store import append, ActivityRecord


_MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


# v9.57 — paths the middleware never logs even in forensic mode.
# Pre-v9.57 the only skipped paths were /static/ and /api/activity
# (the latter to avoid a self-logging loop). That left noise like
# /api/v9/search (one row per keystroke in the command palette),
# /favicon.ico, and load-balancer health probes blasting the log.
#
# Operators can extend at runtime with SC_ACTIVITY_SKIP_PREFIXES
# (comma-separated). Default list aims for "noise that hides real
# activity" — anything write-shaped or auth-shaped is logged.
_DEFAULT_SKIP_PREFIXES = (
    "/static/",
    "/api/activity",      # would self-log infinitely
    "/api/v9/search",     # palette keystrokes
    "/favicon.ico",
    "/healthz",           # k8s/lb probes
    "/health",
    "/readyz",
    "/livez",
    "/_status",
    "/api/_ping",
    "/robots.txt",
)


class ActivityMiddleware(BaseHTTPMiddleware):
    """Append a row to the JSONL store after every authenticated
    mutation. Wire it once on the FastAPI app:

        from safecadence.activity import ActivityMiddleware
        app.add_middleware(ActivityMiddleware, jwt_secret=secret)

    Pass ``jwt_secret`` so the middleware can decode the bearer
    token. If decoding fails, actor defaults to ``"anonymous"`` —
    we still record the attempt for forensic purposes.
    """

    def __init__(self, app, *, jwt_secret: Optional[str] = None,
                  log_reads: Optional[bool] = None,
                  skip_prefixes: Optional[tuple] = None):
        super().__init__(app)
        self.jwt_secret = jwt_secret
        if log_reads is None:
            log_reads = os.environ.get("SC_ACTIVITY_LOG_READS",
                                          "") == "1"
        self.log_reads = log_reads
        # v9.57 — skip-list resolution: explicit arg first, env
        # extension second, default list third. Env values are
        # appended (not overridden) so an operator can ADD prefixes
        # without losing the noise floor we ship.
        if skip_prefixes is not None:
            self.skip_prefixes = tuple(skip_prefixes)
        else:
            extra = [p.strip() for p in
                       (os.environ.get("SC_ACTIVITY_SKIP_PREFIXES", "")
                        ).split(",") if p.strip()]
            self.skip_prefixes = _DEFAULT_SKIP_PREFIXES + tuple(extra)

    async def dispatch(self, request: Request, call_next) -> Response:
        start = time.monotonic()
        request_id = "req_" + uuid.uuid4().hex[:12]
        # Stash the request ID so handlers can include it in their
        # responses for client-side correlation.
        request.state.request_id = request_id
        try:
            response = await call_next(request)
        except Exception:
            duration_ms = int((time.monotonic() - start) * 1000)
            self._record(request, status=500, duration_ms=duration_ms,
                         request_id=request_id)
            raise
        duration_ms = int((time.monotonic() - start) * 1000)
        # Add header for downstream clients (curl -i, browser net tab)
        try:
            response.headers["X-SC-Request-Id"] = request_id
        except Exception:               # pragma: no cover
            pass
        self._record(request, status=response.status_code,
                     duration_ms=duration_ms, request_id=request_id)
        return response

    # ------------------------------------------------------------
    def _record(self, request: Request, *, status: int,
                  duration_ms: int, request_id: str) -> None:
        method = request.method.upper()
        if method not in _MUTATING_METHODS and not self.log_reads:
            return
        path = request.url.path or ""
        # v9.57 — configurable skip-list. Default covers /static/,
        # /api/activity (self-loop), /api/v9/search (palette
        # keystrokes), /favicon, and common k8s/lb probe paths.
        # Extend via SC_ACTIVITY_SKIP_PREFIXES (comma-sep).
        for prefix in self.skip_prefixes:
            if path.startswith(prefix):
                return
        actor, tenant = self._who(request)
        # v9.57.1 — populate `extra` with a shape signal so /audit
        # rows from the middleware are distinguishable from rows
        # written directly by callers (caps store, /ask, automation
        # fires). Pre-v9.57.1 middleware rows had `extra={}` while
        # direct-write rows had rich payloads — the auditor couldn't
        # tell which kind they were looking at, and the noise filter
        # treated them the same.
        #
        # `source: "http"` marks the row as middleware-written.
        # `query` carries the URL query string (capped) so the
        # auditor sees the filters / params used. We don't try to
        # log the request body — that can contain credentials and
        # other things that don't belong in an append-only log.
        extra: dict = {"source": "http"}
        try:
            qs = request.url.query or ""
            if qs:
                # Cap to avoid hostile-input log bloat.
                extra["query"] = qs[:500]
            ua = request.headers.get("user-agent", "")
            if ua:
                extra["ua"] = ua[:200]
        except Exception:                                   # pragma: no cover
            pass
        rec = ActivityRecord(
            ts=datetime.now(timezone.utc).isoformat(
                timespec="seconds").replace("+00:00", "Z"),
            actor=actor,
            tenant=tenant,
            method=method,
            path=path,
            status=status,
            ip=self._ip(request),
            duration_ms=duration_ms,
            request_id=request_id,
            extra=extra,
        )
        try:
            append(rec)
        except Exception:               # pragma: no cover
            # Disk full / read-only mount — never break the request.
            pass

    def _who(self, request: Request) -> tuple[str, str]:
        # Bearer JWT first (the api server path).
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer ") and self.jwt_secret:
            token = auth.split(" ", 1)[1].strip()
            try:
                from safecadence.server.auth import decode_jwt
                user = decode_jwt(token, secret=self.jwt_secret)
                return (getattr(user, "username", "") or "anonymous",
                         getattr(user, "tenant", "default"))
            except Exception:
                pass
        # Cookie-session (local UI).
        try:
            sess = request.session if hasattr(request, "session") else {}
            u = sess.get("user") if isinstance(sess, dict) else None
            if u:
                return (str(u), str(sess.get("tenant", "default")))
        except Exception:               # pragma: no cover
            pass
        # state.user is set by some routes' Depends(get_current_user).
        u = getattr(request.state, "user", None)
        if u is not None:
            return (getattr(u, "username", "") or "anonymous",
                     getattr(u, "tenant", "default"))
        return ("anonymous", "default")

    def _ip(self, request: Request) -> str:
        # Honour X-Forwarded-For if present (one nginx hop in front).
        xff = request.headers.get("x-forwarded-for", "")
        if xff:
            return xff.split(",")[0].strip()
        client = request.client
        return client.host if client else ""
