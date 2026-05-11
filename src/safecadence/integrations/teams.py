"""
Microsoft Teams integration (v10.7).

Posts to a Teams incoming webhook. No OAuth required — admins set up a
channel webhook in Teams and paste the URL into our config.

Env:

    SC_TEAMS_WEBHOOK_URL   the channel webhook URL

Public:

    is_configured() -> bool
    post_message(text, *, title=None, theme_color=None) -> dict | None
    post_finding(finding) -> dict | None   # turns a finding into a card
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any
from urllib import error as _urlerr
from urllib import request as _urlreq

_log = logging.getLogger("safecadence.integrations.teams")


_SEV_COLOR = {
    "critical": "B00020",
    "high":     "EA580C",
    "medium":   "EAB308",
    "low":      "2563EB",
    "info":     "6B7280",
}


def is_configured() -> bool:
    return bool(os.environ.get("SC_TEAMS_WEBHOOK_URL"))


def _build_card(title: str, text: str, *, theme_color: str = "0078D4",
                facts: list[tuple[str, str]] | None = None) -> dict:
    """Return a Microsoft Connector Card payload (legacy MessageCard)."""
    card: dict[str, Any] = {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": title or "SafeCadence notification",
        "themeColor": theme_color,
        "title": title,
        "text": text,
    }
    if facts:
        card["sections"] = [{
            "facts": [{"name": k, "value": str(v)} for k, v in facts]
        }]
    return card


def post_message(text: str, *, title: str | None = None,
                 theme_color: str | None = None,
                 facts: list[tuple[str, str]] | None = None,
                 timeout: float = 6.0) -> dict | None:
    """Send a MessageCard to the configured Teams webhook.

    Returns ``{"status_code": int}`` on success, ``None`` if not configured.
    """
    if not is_configured():
        _log.info("teams not configured — skipping")
        return None
    url = os.environ["SC_TEAMS_WEBHOOK_URL"]
    card = _build_card(title or "SafeCadence", text, theme_color=theme_color or "0078D4",
                       facts=facts)
    req = _urlreq.Request(
        url,
        data=json.dumps(card).encode(),
        method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "safecadence/10.7"},
    )
    try:
        with _urlreq.urlopen(req, timeout=timeout) as resp:
            return {"status_code": getattr(resp, "status", 200)}
    except _urlerr.HTTPError as e:
        _log.warning("teams webhook returned HTTP %s", e.code)
        return {"status_code": e.code}
    except (_urlerr.URLError, OSError) as e:  # pragma: no cover
        _log.warning("teams webhook network error: %s", e)
        raise


def post_finding(finding: dict) -> dict | None:
    """Convenience: format a SafeCadence finding as a card and post it."""
    sev = (finding.get("severity") or "medium").lower()
    title = f"[{sev.upper()}] {finding.get('title') or 'SafeCadence finding'}"
    facts = [
        ("Host", finding.get("hostname") or "—"),
        ("CVE", finding.get("cve") or finding.get("cve_id") or "—"),
        ("Severity", sev),
        ("Site", finding.get("site") or "—"),
    ]
    text = (finding.get("description")
            or finding.get("detail")
            or finding.get("summary")
            or "").strip()
    return post_message(text or title, title=title,
                        theme_color=_SEV_COLOR.get(sev, "0078D4"), facts=facts)


__all__ = ["is_configured", "post_message", "post_finding"]
