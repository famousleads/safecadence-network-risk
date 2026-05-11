"""
Self-service signup (v10.9).

Flow
----
1. User POSTs ``{email, org_name, plan}`` to ``/signup``.
2. :func:`request_signup` creates a pending record, emails a magic
   verification link (or surfaces it directly in demo mode).
3. User clicks the link → ``GET /signup/verify?token=...`` →
   :func:`verify_signup` provisions the Org + User + ADMIN role +
   assigns the initial plan. Free → straight to portal; paid →
   returns ``checkout_url`` so the router can redirect to Stripe.

Why a dedicated module (vs. reusing :mod:`safecadence.auth.magic_link`)?
The magic-link flow is for sign-in to an *existing* account. Signup
needs to capture extra fields (org name + plan choice) before the
verification, so the pending record lives in a separate file
(``~/.safecadence/signups.json``) keyed by a fresh token.

Read-only droplet behaviour
---------------------------
``SC_READONLY=1`` rejects writes with PermissionError so the public
demo can mount the form for visual-smoke testing without polluting
state.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import os
import secrets
import time
from pathlib import Path
from typing import Any

_log = logging.getLogger("safecadence.auth.signup")


SIGNUP_TTL_SECONDS = 24 * 60 * 60   # 24 hours


# --------------------------------------------------------------------------
# Storage helpers
# --------------------------------------------------------------------------


def _root() -> Path:
    root = os.environ.get("SAFECADENCE_HOME") or os.environ.get("SC_AUTH_HOME")
    base = Path(root) if root else Path.home() / ".safecadence"
    base.mkdir(parents=True, exist_ok=True)
    return base


def _signups_path() -> Path:
    return _root() / "signups.json"


def _read_signups() -> dict:
    path = _signups_path()
    if not path.exists():
        return {}
    try:
        d = json.loads(path.read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def _write_signups(payload: dict) -> None:
    path = _signups_path()
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    tmp.replace(path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _is_readonly() -> bool:
    return os.environ.get("SC_READONLY", "") == "1"


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def request_signup(email: str, org_name: str,
                    plan: str = "Free",
                    return_url: str | None = None) -> dict:
    """Create a pending signup record and email a verification link.

    Returns ``{"sent": True, "token": "..."}`` so the caller can also
    deep-link the user immediately if they prefer (useful for demo).
    On failure, returns ``{"sent": False, "error": "..."}``.

    Idempotent on the (email, org_name, plan) tuple: a repeat call
    issues a fresh token and discards any older pending entries for
    the same email.
    """
    if _is_readonly():
        raise PermissionError("Signups are disabled in read-only mode.")
    email = (email or "").strip().lower()
    org_name = (org_name or "").strip()
    plan = (plan or "Free").strip()
    if not email or "@" not in email:
        return {"sent": False, "error": "Enter a valid email address."}
    if not org_name:
        return {"sent": False, "error": "Org name is required."}

    # Validate plan
    from safecadence.billing.plans import get_plan
    plan_obj = get_plan(plan)

    token = secrets.token_urlsafe(32)
    now = int(time.time())
    payload = _read_signups()
    # Prune expired + same-email entries.
    payload = {
        k: v for k, v in payload.items()
        if isinstance(v, dict)
        and int(v.get("expires_at") or 0) > now
        and (v.get("email") or "") != email
    }
    payload[token] = {
        "token": token,
        "email": email,
        "org_name": org_name,
        "plan": plan_obj.id,
        "created_at": now,
        "expires_at": now + SIGNUP_TTL_SECONDS,
        "return_url": return_url or "/portal",
    }
    _write_signups(payload)

    base = (os.environ.get("SC_PUBLIC_URL") or "http://localhost:8003").rstrip("/")
    link = f"{base}/signup/verify?token={token}"
    subject = "Confirm your SafeCadence signup"
    body = (
        f"Welcome to SafeCadence!\n\n"
        f"You're signing up the org \"{org_name}\" on the {plan_obj.id} plan.\n"
        f"Click the link below within 24 hours to activate your account:\n\n"
        f"{link}\n\n"
        "If you didn't request this, you can safely ignore this email."
    )
    sent = True
    err: str | None = None
    if not os.environ.get("SC_AUTH_DISABLED"):
        try:
            from safecadence.reports.email_delivery import send_email_raw
            err = send_email_raw(email, subject, body)
        except Exception as exc:                       # pragma: no cover
            err = f"Email module unavailable: {exc}"
    if err:
        sent = False
    return {
        "sent": sent,
        "token": token,
        "verify_url": link,
        "error": err,
        "plan": plan_obj.id,
    }


def verify_signup(token: str) -> dict:
    """Consume the token, provision Org + User + plan.

    Returns a dict::

        {
          "ok": True,
          "org_id": "org_xxx",
          "user_id": "user_xxx",
          "email": "...",
          "plan": "Free" | "Pro" | "Enterprise",
          "checkout_url": "https://checkout.stripe.com/..." | None,
          "session_token": "..."
        }

    or ``{"ok": False, "error": "..."}`` on bad / expired token.
    """
    if not token:
        return {"ok": False, "error": "Missing token."}
    payload = _read_signups()
    entry = payload.get(token)
    if not entry or not isinstance(entry, dict):
        return {"ok": False, "error": "That link is invalid or already used."}
    now = int(time.time())
    if int(entry.get("expires_at") or 0) <= now:
        payload.pop(token, None)
        _write_signups(payload)
        return {"ok": False, "error": "That link has expired."}

    email = entry.get("email") or ""
    org_name = entry.get("org_name") or ""
    plan = entry.get("plan") or "Free"

    # Provision Org.
    from safecadence.storage.org_store import create_org
    from safecadence.auth.rbac import assign_role, UserRole
    from safecadence.billing.plans import set_org_plan, get_plan

    try:
        org = create_org(name=org_name, owner_email=email)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}

    # Ensure ADMIN role. create_org already does it, but be defensive.
    try:
        assign_role(org.id, email, UserRole.ADMIN)
    except Exception:                                  # pragma: no cover
        pass

    # Set initial plan.
    set_org_plan(org.id, plan, source="signup",
                  status="trialing" if plan != "Free" else "active")

    # Create a session for the new user via the magic_link module.
    from safecadence.auth.magic_link import create_session, _user_id_for
    user_id = _user_id_for(email)
    session_token = create_session(user_id, email)

    # Best-effort audit.
    try:
        from safecadence.workflow.change_mgmt import record_change
        record_change(org.id, "signup_completed",
                       before=None,
                       after={"email": email, "plan": plan,
                              "org_name": org_name},
                       actor=email)
    except Exception:                                  # pragma: no cover
        pass

    # Consume token.
    payload.pop(token, None)
    _write_signups(payload)

    # If paid plan, build a checkout URL (best-effort; non-fatal if Stripe
    # is unconfigured — we still complete signup, the user will be a
    # trialing Free until they enter billing details).
    checkout_url: str | None = None
    if plan != "Free":
        try:
            from safecadence.billing import stripe_client
            if stripe_client.is_configured():
                base = (os.environ.get("SC_PUBLIC_URL") or
                        "https://app.safecadence.com").rstrip("/")
                out = stripe_client.create_checkout_session(
                    plan=plan,
                    customer_email=email,
                    success_url=f"{base}/portal/billing?ok=1&org={org.id}",
                    cancel_url=f"{base}/portal/billing?cancelled=1",
                    metadata={"org_id": org.id, "plan": plan},
                )
                checkout_url = out.get("url")
        except Exception as exc:                       # pragma: no cover
            _log.warning("checkout creation failed for %s: %s", org.id, exc)

    return {
        "ok": True,
        "org_id": org.id,
        "user_id": user_id,
        "email": email,
        "plan": plan,
        "checkout_url": checkout_url,
        "session_token": session_token,
        "return_url": entry.get("return_url") or "/portal",
    }


def list_pending_signups() -> list[dict]:
    """For the admin console — pending verifications."""
    payload = _read_signups()
    now = int(time.time())
    out: list[dict] = []
    for entry in payload.values():
        if not isinstance(entry, dict):
            continue
        if int(entry.get("expires_at") or 0) <= now:
            continue
        e = dict(entry)
        e.pop("token", None)
        out.append(e)
    out.sort(key=lambda r: int(r.get("created_at") or 0), reverse=True)
    return out


__all__ = [
    "request_signup",
    "verify_signup",
    "list_pending_signups",
    "SIGNUP_TTL_SECONDS",
]
