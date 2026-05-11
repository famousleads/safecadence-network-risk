"""
Magic-link email auth for SafeCadence NetRisk.

Why this exists
---------------
v10.4 shipped multi-user roles but had no first-class browser login flow.
The wizard / inventory / reports UI was either anonymous (demo) or
gated by JWT bearer tokens (API only). v10.5 closes the gap with a
classic "type your email, click the link" flow that needs zero new
infrastructure beyond the existing SMTP env vars.

Storage
-------
* Magic-link tokens live in ``~/.safecadence/auth_tokens.json`` with a
  15-minute TTL. One-shot — the entry is deleted on first successful
  verify, so a leaked link in your browser history is also a dead link.
* Sessions live in ``~/.safecadence/sessions.json`` with a 30-day TTL.
  Cookie value is the session token; server validates it on each
  protected request via :func:`get_session`.

Email is sent via :func:`safecadence.reports.email_delivery.send_email_raw`,
which itself is a thin wrapper over the existing SMTP env contract
(``SC_SMTP_HOST/_PORT/_USER/_PASS/_FROM``).

Demo bypass
-----------
If ``SC_AUTH_DISABLED=1`` is set:
  * :func:`request_login` returns ``{"sent": True, "demo": True}`` without
    writing anything to disk;
  * :func:`verify_token` accepts any non-empty token and returns the
    demo identity;
  * :func:`create_session` returns a deterministic ``"demo-session"``
    token;
  * :func:`get_session` always returns the demo session dict.

This is what keeps the public read-only ``demo.safecadence.com``
deployment working without anyone having to log in.

The functions never raise — every failure path returns a friendly dict
or ``None`` so the caller can render a human error.
"""

from __future__ import annotations

import json
import os
import secrets
import time
from pathlib import Path
from typing import Any


# --------------------------------------------------------------------------
# Demo bypass
# --------------------------------------------------------------------------


def _auth_disabled() -> bool:
    return os.environ.get("SC_AUTH_DISABLED", "") == "1"


DEMO_EMAIL = "demo@safecadence.com"
DEMO_USER_ID = "user_demo"
DEMO_SESSION_TOKEN = "demo-session"


def _demo_session() -> dict:
    return {
        "token": DEMO_SESSION_TOKEN,
        "user_id": DEMO_USER_ID,
        "email": DEMO_EMAIL,
        "created_at": int(time.time()),
        "expires_at": int(time.time()) + 30 * 86400,
        "demo": True,
    }


# --------------------------------------------------------------------------
# On-disk storage helpers (atomic-ish; concurrent-process safety is best
# effort — the assumption is a single uvicorn worker, which is the
# v10.x deployment shape).
# --------------------------------------------------------------------------


def _data_dir() -> Path:
    root = os.environ.get("SAFECADENCE_HOME") or os.environ.get("SC_AUTH_HOME")
    base = Path(root) if root else Path.home() / ".safecadence"
    base.mkdir(parents=True, exist_ok=True)
    return base


def _tokens_path() -> Path:
    return _data_dir() / "auth_tokens.json"


def _sessions_path() -> Path:
    return _data_dir() / "sessions.json"


def _read_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _write_json(path: Path, payload: dict) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    tmp.replace(path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


# --------------------------------------------------------------------------
# Token TTLs
# --------------------------------------------------------------------------


TOKEN_TTL_SECONDS = 15 * 60           # 15 minutes
SESSION_TTL_SECONDS = 30 * 86400      # 30 days


# --------------------------------------------------------------------------
# Public API — magic links
# --------------------------------------------------------------------------


def _user_id_for(email: str) -> str:
    """Stable user id derived from email (lowercased)."""
    return "user_" + (email or "").strip().lower().replace("@", "_at_").replace(".", "_")


def request_login(email: str, return_url: str | None = None) -> dict:
    """Issue a magic-link token for ``email`` and email it.

    Returns ``{"sent": True}`` on success or
    ``{"sent": False, "error": "..."}`` on failure.

    When :envvar:`SC_AUTH_DISABLED` is set, returns
    ``{"sent": True, "demo": True}`` immediately — useful for the
    public demo where we never actually want to send mail.
    """
    if _auth_disabled():
        return {"sent": True, "demo": True}

    email = (email or "").strip().lower()
    if not email or "@" not in email:
        return {"sent": False, "error": "Enter a valid email address."}

    token = secrets.token_urlsafe(32)
    now = int(time.time())
    payload = _read_json(_tokens_path())
    # Prune expired entries opportunistically — keeps the file small.
    payload = {
        k: v for k, v in payload.items()
        if isinstance(v, dict) and int(v.get("expires_at") or 0) > now
    }
    payload[token] = {
        "email": email,
        "user_id": _user_id_for(email),
        "created_at": now,
        "expires_at": now + TOKEN_TTL_SECONDS,
        "return_url": return_url or "/home",
    }
    _write_json(_tokens_path(), payload)

    # Build the link. Caller passes return_url; we wrap it in /auth/callback.
    base = os.environ.get("SC_PUBLIC_URL") or "http://localhost:8003"
    base = base.rstrip("/")
    link = f"{base}/auth/callback?token={token}"
    subject = "Sign in to SafeCadence"
    body = (
        "Click the link below to sign in. The link expires in 15 minutes "
        "and can only be used once.\n\n"
        f"{link}\n\n"
        "If you didn't request this, you can safely ignore this email."
    )
    try:
        from safecadence.reports.email_delivery import send_email_raw
        err = send_email_raw(email, subject, body)
    except Exception as exc:                       # pragma: no cover
        err = f"Email module unavailable: {exc}"
    if err:
        return {"sent": False, "error": err}
    return {"sent": True}


def verify_token(token: str) -> tuple[str, str] | None:
    """Validate and consume a magic-link token.

    Returns ``(user_id, email)`` on success, ``None`` on
    expired/missing/invalid token.

    When :envvar:`SC_AUTH_DISABLED` is set, any non-empty token returns
    the demo identity (kept consistent across calls).
    """
    if _auth_disabled():
        if not token:
            return None
        return (DEMO_USER_ID, DEMO_EMAIL)

    if not token:
        return None
    payload = _read_json(_tokens_path())
    entry = payload.get(token)
    if not entry or not isinstance(entry, dict):
        return None
    now = int(time.time())
    if int(entry.get("expires_at") or 0) <= now:
        # Best-effort cleanup
        payload.pop(token, None)
        _write_json(_tokens_path(), payload)
        return None
    user_id = entry.get("user_id") or _user_id_for(entry.get("email") or "")
    email = entry.get("email") or ""
    # Consume — one-shot.
    payload.pop(token, None)
    _write_json(_tokens_path(), payload)
    return (user_id, email)


# --------------------------------------------------------------------------
# Public API — sessions
# --------------------------------------------------------------------------


def create_session(user_id: str, email: str) -> str:
    """Create a session and persist it. Returns the session token.

    When :envvar:`SC_AUTH_DISABLED` is set, returns the deterministic
    demo token without writing anything.
    """
    if _auth_disabled():
        return DEMO_SESSION_TOKEN
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    payload = _read_json(_sessions_path())
    payload = {
        k: v for k, v in payload.items()
        if isinstance(v, dict) and int(v.get("expires_at") or 0) > now
    }
    payload[token] = {
        "token": token,
        "user_id": user_id,
        "email": email,
        "created_at": now,
        "expires_at": now + SESSION_TTL_SECONDS,
    }
    _write_json(_sessions_path(), payload)
    return token


def get_session(token: str) -> dict | None:
    """Return the session dict for ``token`` or ``None``.

    When :envvar:`SC_AUTH_DISABLED` is set, returns the demo session
    for any token value (including ``None``) so the rest of the stack
    can treat the request as authenticated.
    """
    if _auth_disabled():
        return _demo_session()
    if not token:
        return None
    payload = _read_json(_sessions_path())
    entry = payload.get(token)
    if not entry or not isinstance(entry, dict):
        return None
    if int(entry.get("expires_at") or 0) <= int(time.time()):
        payload.pop(token, None)
        _write_json(_sessions_path(), payload)
        return None
    return entry


def revoke_session(token: str) -> bool:
    """Delete the session. Returns True if a session was removed.

    Bypassed (no-op, returns True) when :envvar:`SC_AUTH_DISABLED`.
    """
    if _auth_disabled():
        return True
    if not token:
        return False
    payload = _read_json(_sessions_path())
    if token not in payload:
        return False
    payload.pop(token, None)
    _write_json(_sessions_path(), payload)
    return True


def active_session_count() -> int:
    """How many unexpired sessions are currently on disk.

    Used by the Prometheus ``safecadence_active_sessions`` gauge.
    """
    if _auth_disabled():
        return 1
    payload = _read_json(_sessions_path())
    now = int(time.time())
    return sum(
        1 for v in payload.values()
        if isinstance(v, dict) and int(v.get("expires_at") or 0) > now
    )


__all__ = [
    "DEMO_EMAIL",
    "DEMO_USER_ID",
    "DEMO_SESSION_TOKEN",
    "TOKEN_TTL_SECONDS",
    "SESSION_TTL_SECONDS",
    "request_login",
    "verify_token",
    "create_session",
    "get_session",
    "revoke_session",
    "active_session_count",
]
