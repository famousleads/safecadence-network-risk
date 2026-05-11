"""
SMTP-based email delivery for rendered reports.

This module deliberately uses only the Python standard library
(``email.message.EmailMessage`` + ``smtplib.SMTP`` with STARTTLS), so
analysts can wire scheduled report deliveries without adding a single
new dependency to the platform.

Configuration is read from environment variables:

  * ``SC_SMTP_HOST`` (required)
  * ``SC_SMTP_PORT`` (optional, default: 587)
  * ``SC_SMTP_USER`` (required for auth)
  * ``SC_SMTP_PASS`` (required for auth)
  * ``SC_SMTP_FROM`` (required — From: address)

If any required variable is missing, :func:`send_report` returns an
informative error string rather than raising — callers (CLI, scheduler,
API job runner) can surface the message to the user without writing
their own try/except boilerplate.

Public API::

    err = send_report(
        recipients=["ciso@acme.com"],
        subject="Weekly exec brief",
        body_text="See attached weekly exec brief.",
        attachment_bytes=pdf_bytes,
        attachment_filename="weekly-exec-brief.pdf",
        attachment_mimetype="application/pdf",
    )
    if err:
        print("email failed:", err)

Returns ``None`` on success, a string error on failure.
"""

from __future__ import annotations

import os
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from typing import Sequence


# --------------------------------------------------------------------------
# MIME type detection (stdlib only, narrow case)
# --------------------------------------------------------------------------


_FORMAT_MIME = {
    "html":  "text/html",
    "json":  "application/json",
    "pdf":   "application/pdf",
    "docx":  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "pptx":  "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "xlsx":  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}


def mimetype_for_format(fmt: str) -> str:
    """Return the IANA MIME type for one of the report renderer formats."""
    return _FORMAT_MIME.get((fmt or "").lower(), "application/octet-stream")


# --------------------------------------------------------------------------
# Env helpers
# --------------------------------------------------------------------------


def _env(name: str, default: str = "") -> str:
    val = os.environ.get(name, default)
    return val.strip() if isinstance(val, str) else val


def _missing_envs() -> list[str]:
    """Return list of required SMTP env vars that are not set."""
    required = ["SC_SMTP_HOST", "SC_SMTP_USER", "SC_SMTP_PASS", "SC_SMTP_FROM"]
    return [k for k in required if not _env(k)]


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def send_report(
    *,
    recipients: Sequence[str],
    subject: str,
    body_text: str,
    attachment_bytes: bytes,
    attachment_filename: str,
    attachment_mimetype: str = "application/octet-stream",
    cc: Sequence[str] | None = None,
    bcc: Sequence[str] | None = None,
    body_html: str | None = None,
) -> str | None:
    """Send a rendered report by email.

    Returns ``None`` on success, an informative error string on failure
    (missing env, bad recipients, SMTP exception, etc.). Never raises.
    """
    if not recipients:
        return "No recipients supplied."

    missing = _missing_envs()
    if missing:
        return (
            "SMTP not configured — set "
            + ", ".join(missing)
            + " and try again."
        )

    host = _env("SC_SMTP_HOST")
    port = int(_env("SC_SMTP_PORT") or "587")
    user = _env("SC_SMTP_USER")
    password = _env("SC_SMTP_PASS")
    sender = _env("SC_SMTP_FROM")

    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    if cc:
        msg["Cc"] = ", ".join(cc)
    msg["Subject"] = subject or "SafeCadence NetRisk report"
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain="safecadence.local")
    msg["X-SafeCadence-Generator"] = "netrisk-reports"

    msg.set_content(body_text or "See attached SafeCadence NetRisk report.")
    if body_html:
        msg.add_alternative(body_html, subtype="html")

    if attachment_bytes:
        maintype, _, subtype = (attachment_mimetype or "application/octet-stream").partition("/")
        if not subtype:
            subtype = "octet-stream"
        msg.add_attachment(
            attachment_bytes,
            maintype=maintype or "application",
            subtype=subtype,
            filename=attachment_filename or "report.bin",
        )

    all_rcpts = list(recipients) + list(cc or []) + list(bcc or [])

    try:
        ctx = ssl.create_default_context()
        with smtplib.SMTP(host, port, timeout=30) as smtp:
            smtp.ehlo()
            try:
                smtp.starttls(context=ctx)
                smtp.ehlo()
            except smtplib.SMTPException:
                # Some local relays don't speak STARTTLS — try without TLS
                # but still attempt auth if the server advertises it.
                pass
            if user and password:
                smtp.login(user, password)
            smtp.send_message(msg, from_addr=sender, to_addrs=all_rcpts)
    except smtplib.SMTPException as exc:
        return f"SMTP error: {exc}"
    except OSError as exc:
        return f"Network error contacting SMTP server: {exc}"
    except Exception as exc:  # pragma: no cover - defensive
        return f"Unexpected email error: {exc}"

    return None


__all__ = ["send_report", "mimetype_for_format"]
