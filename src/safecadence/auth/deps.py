"""
FastAPI dependencies for SafeCadence NetRisk auth.

``require_session`` resolves the current session from either the
``sc_session`` cookie or the ``Authorization: Bearer <token>`` header.
When :envvar:`SC_AUTH_DISABLED` is set, it returns the demo session
unconditionally — that's what keeps the public read-only demo open.
"""

from __future__ import annotations

import os

try:
    from fastapi import HTTPException, Request
    _FASTAPI_OK = True
except Exception:                                  # pragma: no cover
    _FASTAPI_OK = False

from safecadence.auth.magic_link import get_session, _demo_session


SESSION_COOKIE = "sc_session"


def _bearer_token(request) -> str | None:
    auth = request.headers.get("Authorization") or ""
    if auth.lower().startswith("bearer "):
        return auth.split(None, 1)[1].strip() or None
    return None


def require_session(request: "Request") -> dict:
    """Return the session dict for the current request.

    Order of resolution:
      1. ``SC_AUTH_DISABLED=1`` → demo session.
      2. ``sc_session`` cookie value.
      3. ``Authorization: Bearer <token>`` header.

    Raises 401 if no valid session resolves.
    """
    if os.environ.get("SC_AUTH_DISABLED", "") == "1":
        return _demo_session()
    if not _FASTAPI_OK:                            # pragma: no cover
        raise RuntimeError("FastAPI not installed")
    tok = request.cookies.get(SESSION_COOKIE) or _bearer_token(request)
    sess = get_session(tok) if tok else None
    if not sess:
        raise HTTPException(status_code=401, detail="Sign in required.")
    return sess


def optional_session(request: "Request") -> dict | None:
    """Like :func:`require_session` but returns None instead of 401."""
    if os.environ.get("SC_AUTH_DISABLED", "") == "1":
        return _demo_session()
    if not _FASTAPI_OK:                            # pragma: no cover
        return None
    tok = request.cookies.get(SESSION_COOKIE) or _bearer_token(request)
    return get_session(tok) if tok else None


__all__ = ["require_session", "optional_session", "SESSION_COOKIE"]
