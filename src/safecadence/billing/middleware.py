"""
Usage-metering middleware (v10.9).

Counts every ``/api/v1/*`` hit as one ``api_calls`` event for the
requesting org, except internal probes:

  * ``/api/v1/billing/*``  — never quota-gated
  * ``/api/v1/me``         — identity / health
  * GET ``/api/v1/plans``  — public catalogue

Org id resolution mirrors the rest of the stack: ``X-SafeCadence-Org``
header first, then ``?org_id=`` query param. No org → no event.

When the org's quota is already exhausted, the middleware short-circuits
the response with HTTP 402 ``{"error": "quota_exceeded", ...}``.
Disable via ``SC_USAGE_METERING_DISABLED=1`` (defaults to enabled).
"""

from __future__ import annotations

import json
import os

try:
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.responses import JSONResponse
    _OK = True
except Exception:                                      # pragma: no cover
    _OK = False
    BaseHTTPMiddleware = object  # type: ignore


_EXEMPT_PREFIXES = ("/api/v1/billing", "/api/v1/me",
                    "/api/v1/plans", "/api/billing/webhook")


class UsageMeteringMiddleware(BaseHTTPMiddleware):     # type: ignore[misc]
    async def dispatch(self, request, call_next):
        if not _OK or os.environ.get("SC_USAGE_METERING_DISABLED", "") == "1":
            return await call_next(request)
        path = request.url.path or ""
        if not path.startswith("/api/v1/"):
            return await call_next(request)
        if any(path.startswith(p) for p in _EXEMPT_PREFIXES):
            return await call_next(request)
        org_id = (
            request.headers.get("X-SafeCadence-Org")
            or request.query_params.get("org_id")
            or ""
        ).strip()
        if not org_id:
            return await call_next(request)

        # Quota check first — refuse if over the line.
        try:
            from safecadence.billing.plans import check_quota, quota_error_payload
            q = check_quota(org_id, "api_calls")
            if not q.get("ok"):
                return JSONResponse(
                    quota_error_payload(q), status_code=402,
                )
        except Exception:                              # pragma: no cover
            pass

        response = await call_next(request)
        try:
            from safecadence.billing.usage import record_usage
            record_usage(org_id, "api_calls", count=1,
                         meta={"path": path})
        except Exception:                              # pragma: no cover
            pass
        return response


__all__ = ["UsageMeteringMiddleware"]
