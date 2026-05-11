"""
Slack OAuth 2.0 + slash command integration (v10.6).

Three pieces, all in this module:

  1. **OAuth install** — ``/oauth/slack/install`` redirects to Slack's
     consent screen; ``/oauth/slack/callback`` exchanges the code for a
     workspace bot token and persists it to
     ``~/.safecadence/orgs/<org_id>/slack_install.json``.

  2. **Slash command** — ``/slack/commands`` receives Slack's
     ``application/x-www-form-urlencoded`` payload, verifies the request
     signature (HMAC-SHA256 over ``v0:{timestamp}:{body}`` with
     ``SLACK_SIGNING_SECRET``), and dispatches:

         /safecadence report exec_brief
         /safecadence status
         /safecadence findings critical

  3. **Outbound** — ``post_message(channel, text, *, token=None)`` calls
     ``chat.postMessage`` (stdlib HTTPS POST). Used to reply
     asynchronously or push alerts.

Env-gated. If ``SLACK_CLIENT_ID`` is unset, the install endpoint
returns a friendly "not configured" message rather than 500.
"""

from __future__ import annotations

import hashlib
import hmac
import json as _json
import os
import time as _time
from typing import Any
from urllib import error as _urlerr
from urllib import parse as _urlparse
from urllib import request as _urlreq


# --------------------------------------------------------------------------
# Persistence
# --------------------------------------------------------------------------


def _install_path(org_id: str):
    """Return the path to this org's Slack install JSON."""
    from safecadence.storage.org_store import org_data_dir
    return org_data_dir(org_id) / "slack_install.json"


def save_install(org_id: str, payload: dict) -> dict:
    """Persist an install record. Returns the saved payload."""
    if not org_id:
        raise ValueError("org_id is required")
    path = _install_path(org_id)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(_json.dumps(payload, indent=2), encoding="utf-8")
    tmp.replace(path)
    return payload


def load_install(org_id: str) -> dict | None:
    """Return the persisted install dict, or ``None`` if missing/unreadable."""
    if not org_id:
        return None
    path = _install_path(org_id)
    if not path.exists():
        return None
    try:
        d = _json.loads(path.read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else None
    except Exception:
        return None


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------


def is_configured() -> bool:
    """True iff the minimum env to run the install flow is present."""
    return bool(os.environ.get("SLACK_CLIENT_ID") and os.environ.get("SLACK_CLIENT_SECRET"))


def install_url(*, state: str = "", scopes: str | None = None) -> str:
    """Build the Slack consent URL. Returns ``""`` if not configured."""
    cid = os.environ.get("SLACK_CLIENT_ID")
    if not cid:
        return ""
    redirect_uri = os.environ.get(
        "SLACK_REDIRECT_URI", "https://app.safecadence.com/oauth/slack/callback")
    scope = scopes or os.environ.get(
        "SLACK_SCOPES",
        "chat:write,commands,channels:read,team:read",
    )
    params = {
        "client_id": cid,
        "scope": scope,
        "redirect_uri": redirect_uri,
    }
    if state:
        params["state"] = state
    return "https://slack.com/oauth/v2/authorize?" + _urlparse.urlencode(params)


# --------------------------------------------------------------------------
# OAuth code exchange
# --------------------------------------------------------------------------


def _http_post(url: str, data: dict, headers: dict | None = None,
               timeout: float = 15.0) -> dict | None:
    """Send a form-encoded or JSON POST; return parsed JSON or None."""
    hdrs = {"Accept": "application/json"}
    if headers:
        hdrs.update(headers)
    if hdrs.get("Content-Type", "").startswith("application/json"):
        body = _json.dumps(data).encode("utf-8")
    else:
        hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
        body = _urlparse.urlencode(data).encode("utf-8")
    req = _urlreq.Request(url, data=body, headers=hdrs, method="POST")
    try:
        with _urlreq.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return _json.loads(raw)
    except (_urlerr.HTTPError, _urlerr.URLError, ValueError, OSError):
        return None
    except Exception:                                  # pragma: no cover
        return None


def exchange_code(code: str) -> dict | None:
    """Trade an OAuth code for a bot token. Returns Slack's JSON payload."""
    if not code:
        return None
    if not is_configured():
        return None
    out = _http_post(
        "https://slack.com/api/oauth.v2.access",
        {
            "client_id": os.environ["SLACK_CLIENT_ID"],
            "client_secret": os.environ["SLACK_CLIENT_SECRET"],
            "code": code,
            "redirect_uri": os.environ.get(
                "SLACK_REDIRECT_URI",
                "https://app.safecadence.com/oauth/slack/callback"),
        },
    )
    return out


# --------------------------------------------------------------------------
# Signature verification
# --------------------------------------------------------------------------


# Slack rejects requests older than 5 minutes; we mirror that.
_MAX_SLACK_REQUEST_AGE_SEC = 300


def verify_signature(body: bytes | str, timestamp: str, signature: str,
                     *, signing_secret: str | None = None) -> bool:
    """Verify Slack's HMAC-SHA256 request signature.

    Slack signs ``v0:{timestamp}:{body}`` with the workspace signing
    secret. The header ``X-Slack-Signature`` is the lowercase hex digest
    prefixed with ``v0=``.
    """
    secret = signing_secret or os.environ.get("SLACK_SIGNING_SECRET")
    if not secret:
        return False
    if not timestamp or not signature:
        return False
    try:
        ts = int(timestamp)
    except (TypeError, ValueError):
        return False
    if abs(_time.time() - ts) > _MAX_SLACK_REQUEST_AGE_SEC:
        return False
    if isinstance(body, str):
        body_bytes = body.encode("utf-8")
    else:
        body_bytes = body
    basestring = f"v0:{timestamp}:".encode("utf-8") + body_bytes
    digest = hmac.new(secret.encode("utf-8"), basestring,
                      hashlib.sha256).hexdigest()
    expected = "v0=" + digest
    return hmac.compare_digest(expected, signature)


# --------------------------------------------------------------------------
# Slash command dispatch
# --------------------------------------------------------------------------


# Map subcommand → handler. Each handler takes (args, context) → response dict.
_SUBCOMMANDS: dict[str, Any] = {}


def _register(name: str):
    def deco(fn):
        _SUBCOMMANDS[name] = fn
        return fn
    return deco


@_register("report")
def _cmd_report(args: list[str], ctx: dict) -> dict:
    preset = (args[0] if args else "exec_brief").strip()
    return {
        "response_type": "in_channel",
        "text": (
            f"Composing *{preset}* report — I'll DM you when it's ready.\n"
            "Tip: try `/safecadence report compliance_audit` for the auditor format."
        ),
        "command": "report",
        "preset": preset,
    }


@_register("status")
def _cmd_status(args: list[str], ctx: dict) -> dict:
    return {
        "response_type": "ephemeral",
        "text": (
            "SafeCadence NetRisk is online. "
            "Latest scan: see <https://demo.safecadence.com/home|the demo dashboard>."
        ),
        "command": "status",
    }


@_register("findings")
def _cmd_findings(args: list[str], ctx: dict) -> dict:
    sev = (args[0] if args else "critical").lower()
    if sev not in {"critical", "high", "medium", "low", "kev"}:
        sev = "critical"
    return {
        "response_type": "in_channel",
        "text": f"Pulling *{sev}* findings… results land in this channel.",
        "command": "findings",
        "severity": sev,
    }


def dispatch_command(text: str, *, channel_id: str = "", user_id: str = "",
                     team_id: str = "") -> dict:
    """Route ``text`` (the slash command's body, e.g. ``report exec_brief``)
    to the right handler.

    Returns a Slack-compatible response dict. Unknown commands return a
    help text response.
    """
    parts = (text or "").strip().split()
    if not parts:
        return {
            "response_type": "ephemeral",
            "text": (
                "Usage: `/safecadence <subcommand> [args]`\n"
                "Subcommands: `report`, `status`, `findings`."
            ),
            "command": "help",
        }
    sub, *rest = parts
    handler = _SUBCOMMANDS.get(sub.lower())
    if not handler:
        return {
            "response_type": "ephemeral",
            "text": f"Unknown subcommand `{sub}`. Try `report`, `status`, or `findings`.",
            "command": "unknown",
        }
    ctx = {"channel_id": channel_id, "user_id": user_id, "team_id": team_id}
    return handler(rest, ctx)


# --------------------------------------------------------------------------
# Outbound — chat.postMessage
# --------------------------------------------------------------------------


def post_message(channel: str, text: str, *, token: str | None = None,
                 timeout: float = 10.0) -> dict | None:
    """POST to chat.postMessage. Returns Slack's JSON or ``None`` on error.

    The token comes from the kwarg or env ``SLACK_BOT_TOKEN``. If
    neither is set, returns ``None`` without raising.
    """
    bot_token = token or os.environ.get("SLACK_BOT_TOKEN")
    if not bot_token or not channel:
        return None
    return _http_post(
        "https://slack.com/api/chat.postMessage",
        {"channel": channel, "text": text},
        headers={
            "Authorization": f"Bearer {bot_token}",
            "Content-Type": "application/json; charset=utf-8",
        },
        timeout=timeout,
    )


# --------------------------------------------------------------------------
# FastAPI router (mounted by server.app when available)
# --------------------------------------------------------------------------


def build_router():
    """Return an APIRouter for the install + slash command endpoints, or
    ``None`` if FastAPI isn't importable. Kept lazy so unit tests that
    only exercise the pure functions don't pay for it.
    """
    try:
        from fastapi import APIRouter, Form, HTTPException, Request
        from fastapi.responses import JSONResponse, RedirectResponse
    except Exception:                                  # pragma: no cover
        return None

    router = APIRouter(tags=["slack"])

    @router.get("/oauth/slack/install")
    def slack_install(request: Request):
        if not is_configured():
            return JSONResponse(
                status_code=503,
                content={
                    "error": "not_configured",
                    "message": "Slack OAuth is not configured. Set SLACK_CLIENT_ID and SLACK_CLIENT_SECRET.",
                },
            )
        org_id = request.query_params.get("org_id") or ""
        url = install_url(state=org_id)
        return RedirectResponse(url=url, status_code=302)

    @router.get("/oauth/slack/callback")
    def slack_callback(request: Request):
        code = request.query_params.get("code") or ""
        state = request.query_params.get("state") or ""
        if not code:
            raise HTTPException(400, "Missing code")
        if not is_configured():
            return JSONResponse(
                status_code=503,
                content={"error": "not_configured"},
            )
        payload = exchange_code(code)
        if not payload or not payload.get("ok"):
            raise HTTPException(400, "OAuth exchange failed")
        org_id = state or "default"
        # Slim down what we save — keep token + team + scope + installer.
        save_install(org_id, {
            "access_token": payload.get("access_token"),
            "bot_user_id": payload.get("bot_user_id"),
            "team": payload.get("team") or {},
            "scope": payload.get("scope"),
            "installed_at": int(_time.time()),
            "authed_user": payload.get("authed_user") or {},
        })
        return JSONResponse({"ok": True, "org_id": org_id})

    @router.post("/slack/commands")
    async def slack_commands(request: Request):
        raw_body = await request.body()
        ts = request.headers.get("X-Slack-Request-Timestamp", "")
        sig = request.headers.get("X-Slack-Signature", "")
        if not verify_signature(raw_body, ts, sig):
            raise HTTPException(401, "Bad Slack signature")
        # Slack sends form-encoded payload.
        form_pairs = _urlparse.parse_qsl(raw_body.decode("utf-8", errors="replace"))
        form = dict(form_pairs)
        return dispatch_command(
            form.get("text", ""),
            channel_id=form.get("channel_id", ""),
            user_id=form.get("user_id", ""),
            team_id=form.get("team_id", ""),
        )

    return router


__all__ = [
    "is_configured",
    "install_url",
    "exchange_code",
    "save_install",
    "load_install",
    "verify_signature",
    "dispatch_command",
    "post_message",
    "build_router",
]
