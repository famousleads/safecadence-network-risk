"""v9.49.1 — Caller resolution for capability-gated endpoints.

The same v9_pages register() is mounted in two places:
  * ui/app.py — local UI, single-user, password-cookie auth
  * server/app.py — multi-user, JWT bearer auth

require_capability() needs a user object with username/tenant/roles.
This helper provides one in both cases:

  * If the request carries a valid JWT, decode it (multi-user path).
  * Otherwise, fall back to a synthetic admin user (single-user path
    where the password cookie has already gated access).

The capability check short-circuits on the ``admin`` role, so the
single-user fallback is permissive by design — local UI users have
already authenticated via password and are trusted at the role level.
The capability layer adds value only in multi-user deployments.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

try:
    from fastapi import Request
except ImportError:                                     # pragma: no cover
    Request = None             # type: ignore[assignment]


@dataclass
class _SyntheticUser:
    username: str
    tenant: str
    roles: list


def caller_user(request) -> _SyntheticUser:
    """Resolve a user object for capability checks.

    Priority:
      1. Authorization: Bearer <jwt> → decode and return the real user.
      2. request.state.user (set by upstream auth middleware) → return it.
      3. Fallback → synthetic admin (single-user / password-cookie mode).

    Always returns *something* — never raises 401. The 401 is the
    auth middleware's job; this helper just feeds the capability gate.
    """
    # JWT path first (multi-user API)
    auth = request.headers.get("authorization", "") if request else ""
    if auth.lower().startswith("bearer "):
        secret = os.environ.get("SC_JWT_SECRET", "")
        if secret:
            try:
                from safecadence.server.auth import decode_jwt
                token = auth.split(" ", 1)[1].strip()
                u = decode_jwt(token, secret=secret)
                return _SyntheticUser(
                    username=getattr(u, "username", "") or "anonymous",
                    tenant=getattr(u, "tenant", "default"),
                    roles=list(getattr(u, "roles", []) or []),
                )
            except Exception:                           # pragma: no cover
                pass
    # Upstream-set user (some routes' Depends already populated this)
    u = getattr(request, "state", None)
    state_user = getattr(u, "user", None) if u else None
    if state_user is not None:
        return _SyntheticUser(
            username=getattr(state_user, "username", "") or "anonymous",
            tenant=getattr(state_user, "tenant", "default"),
            roles=list(getattr(state_user, "roles", []) or []),
        )
    # Single-user fallback — password gate has already authenticated
    # the operator. Synthetic admin makes the capability check a no-op.
    return _SyntheticUser(
        username="local-admin",
        tenant="default",
        roles=["admin"],
    )
