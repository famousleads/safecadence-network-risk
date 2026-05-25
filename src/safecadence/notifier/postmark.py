"""
v12.0 — Postmark transactional email scaffold.

The v11.x notifier ships with raw SMTP. That's fine for self-hosters
but a real pain for the hosted/managed-support use case: ESPs reject
mail from low-reputation SMTP, you have to babysit DKIM/SPF/DMARC,
and you lose delivery telemetry.

Postmark is the operator-side default: pay per email, established IP
warmup, real delivery events. This module is a thin opt-in wrapper.

Design choices made on the user's behalf
----------------------------------------

* **Stdlib-only HTTPS POST.** No `postmarker` dependency — `urllib`
  is enough for a single endpoint and keeps SafeCadence install-size
  small.

* **Env-gated.** Without `SC_POSTMARK_TOKEN` the module returns a
  ``("dry_run", body_preview)`` tuple instead of sending. CI and dev
  installs never accidentally hit the live API.

* **Drop-in interface.** The single public function signature mirrors
  the existing `email_notifier.send_email()` so the v11.x notifier
  registry can route to Postmark as a provider with no caller changes.

* **No tracking pixels, no link rewriting.** The product is local-first
  and "no telemetry"; the same applies to the operator's outbound mail.
  Postmark's track-opens / track-links flags are explicitly forced off.

DNS prerequisites (operator does once)
--------------------------------------

These are domain-level records the operator adds at their registrar —
not something the code can set up. Documented here so the operator has
a single place to look:

* Add the sending domain in Postmark, verify it.
* Add the DKIM `TXT` record Postmark provides.
* Add a Return-Path `CNAME` record Postmark provides.
* Tighten SPF to include `spf.mtasv.net`.

Env vars consumed
-----------------

::

    SC_POSTMARK_TOKEN          (server token — REQUIRED to send)
    SC_POSTMARK_FROM           (verified from address — REQUIRED to send)
    SC_POSTMARK_MESSAGE_STREAM (default: "outbound")

Public API
----------

* ``send_via_postmark(to, subject, body_text, body_html=None,
                      reply_to=None, message_stream=None)``
  → ``(status, info)`` where status is one of ``"sent"``,
  ``"dry_run"``, or ``"error"``.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request


POSTMARK_API_URL = "https://api.postmarkapp.com/email"


def _env(name: str, default: str = "") -> str:
    return (os.getenv(name) or default).strip()


def send_via_postmark(
    *,
    to: str,
    subject: str,
    body_text: str,
    body_html: str | None = None,
    reply_to: str | None = None,
    message_stream: str | None = None,
    timeout: float = 8.0,
) -> tuple[str, dict]:
    """Send a single transactional email via Postmark.

    Returns one of:
      ``("sent",    {"message_id": "...", "to": "...", "submitted_at": "..."})``
      ``("dry_run", {"reason": "...", "preview": {...}})``
      ``("error",   {"reason": "...", "detail": "..."})``

    Never raises. The caller can log the result and decide whether to
    fall back to the existing SMTP notifier.
    """
    token = _env("SC_POSTMARK_TOKEN")
    sender = _env("SC_POSTMARK_FROM")
    stream = (message_stream or _env("SC_POSTMARK_MESSAGE_STREAM") or "outbound")

    preview = {
        "to": to,
        "from": sender or "<unset>",
        "subject": subject,
        "stream": stream,
        "body_text_preview": (body_text or "")[:160],
    }

    if not token or not sender:
        return ("dry_run", {
            "reason": "SC_POSTMARK_TOKEN or SC_POSTMARK_FROM not set",
            "preview": preview,
        })

    payload: dict = {
        "From": sender,
        "To": to,
        "Subject": subject,
        "TextBody": body_text,
        "MessageStream": stream,
        # Hard "no telemetry" defaults to match SafeCadence's privacy stance.
        "TrackOpens": False,
        "TrackLinks": "None",
    }
    if body_html:
        payload["HtmlBody"] = body_html
    if reply_to:
        payload["ReplyTo"] = reply_to

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        POSTMARK_API_URL,
        data=data,
        method="POST",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Postmark-Server-Token": token,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
        info = {}
        try:
            info = json.loads(body)
        except Exception:
            info = {"raw": body}
        return ("sent", {
            "message_id": info.get("MessageID"),
            "to": info.get("To", to),
            "submitted_at": info.get("SubmittedAt"),
        })
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read().decode("utf-8", errors="replace")[:500]
        except Exception:
            pass
        return ("error", {"reason": f"HTTP {e.code}", "detail": detail})
    except urllib.error.URLError as e:
        return ("error", {"reason": "URLError", "detail": str(e.reason)[:200]})
    except Exception as e:
        return ("error", {"reason": type(e).__name__, "detail": str(e)[:200]})


__all__ = ["send_via_postmark", "POSTMARK_API_URL"]
