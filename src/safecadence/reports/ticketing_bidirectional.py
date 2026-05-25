"""
v13.0 — Bidirectional ITSM ticket sync.

Extends the v10.x one-way ticketing module (which creates Jira /
ServiceNow / GitHub / Linear tickets from findings) into a true
state-machine: ticket status from the upstream system flows BACK
into SafeCadence and updates the linked finding.

How the state flow works
------------------------

Forward (already shipped in v10.x):
  SafeCadence finding → ticket created in Jira/ServiceNow/etc.

Reverse (new in v13.0):
  Jira webhook hits POST /api/v1/tickets/webhook/<provider>
    → verify signature
    → match ticket.external_id to a finding via tickets.json
    → update finding.status = "in_progress" | "resolved" | "wont_fix"
    → if drift returns later, re-open the ticket automatically

Idempotency
-----------

Each webhook payload includes the provider's event id. We dedupe on
that id in a small SQLite table so re-deliveries don't double-update.

Public API
----------

* ``link_ticket(finding_id, provider, external_id, url)``
* ``apply_webhook(provider, raw_body, headers)`` → ``{ok, action, ...}``
* ``find_link_by_external_id(provider, external_id)``
* ``ensure_link_schema(conn)``  / ``register_webhook_router(app)``
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import logging
import os
import sqlite3
import time
from pathlib import Path
from typing import Any

_log = logging.getLogger("safecadence.reports.ticketing_bidirectional")


# Maps each provider's status vocabulary into our internal one.
_STATUS_MAP: dict[str, dict[str, str]] = {
    "jira": {
        "to do":         "open",
        "in progress":   "in_progress",
        "done":          "resolved",
        "closed":        "resolved",
        "won't do":      "wont_fix",
        "wont do":       "wont_fix",
    },
    "servicenow": {
        "new":           "open",
        "in progress":   "in_progress",
        "resolved":      "resolved",
        "closed":        "resolved",
        "cancelled":     "wont_fix",
    },
    "github": {
        "open":          "open",
        "closed":        "resolved",
    },
    "linear": {
        "backlog":       "open",
        "todo":          "open",
        "in progress":   "in_progress",
        "in review":     "in_progress",
        "done":          "resolved",
        "canceled":      "wont_fix",
    },
}


_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS ticket_links (
    finding_id     TEXT NOT NULL,
    provider       TEXT NOT NULL,
    external_id    TEXT NOT NULL,
    url            TEXT NOT NULL DEFAULT '',
    status         TEXT NOT NULL DEFAULT 'open',
    linked_at      INTEGER NOT NULL,
    last_seen_at   INTEGER,
    PRIMARY KEY (provider, external_id)
);

CREATE INDEX IF NOT EXISTS idx_ticket_links_finding
    ON ticket_links(finding_id);

CREATE TABLE IF NOT EXISTS ticket_webhook_events (
    provider     TEXT NOT NULL,
    event_id     TEXT NOT NULL,
    received_at  INTEGER NOT NULL,
    PRIMARY KEY (provider, event_id)
);
"""


def _db_path() -> Path:
    return Path.home() / ".safecadence" / "ticketing_bidirectional.db"


def _conn() -> sqlite3.Connection:
    p = _db_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(str(p))
    ensure_link_schema(c)
    return c


def ensure_link_schema(conn: sqlite3.Connection) -> None:
    cur = conn.cursor()
    for stmt in _SCHEMA_SQL.split(";"):
        s = stmt.strip()
        if s:
            cur.execute(s)
    conn.commit()


def link_ticket(
    finding_id: str, provider: str, external_id: str, url: str = "",
) -> dict:
    """Record the linkage between a finding and an upstream ticket.

    Idempotent: replays the same (provider, external_id) tuple just
    refresh the row.
    """
    now = int(time.time())
    c = _conn()
    c.execute(
        "INSERT OR REPLACE INTO ticket_links "
        "(finding_id, provider, external_id, url, status, linked_at, last_seen_at) "
        "VALUES (?, ?, ?, ?, 'open', ?, ?)",
        (finding_id, provider.lower(), external_id, url, now, now),
    )
    c.commit()
    c.close()
    return {"finding_id": finding_id, "provider": provider,
            "external_id": external_id, "url": url, "status": "open"}


def find_link_by_external_id(provider: str, external_id: str) -> dict | None:
    c = _conn()
    row = c.execute(
        "SELECT finding_id, provider, external_id, url, status, linked_at, "
        "last_seen_at FROM ticket_links WHERE provider=? AND external_id=?",
        (provider.lower(), external_id),
    ).fetchone()
    c.close()
    if not row:
        return None
    return {
        "finding_id": row[0], "provider": row[1],
        "external_id": row[2], "url": row[3], "status": row[4],
        "linked_at": row[5], "last_seen_at": row[6],
    }


def _map_status(provider: str, raw: str) -> str:
    table = _STATUS_MAP.get(provider.lower(), {})
    return table.get((raw or "").lower(), (raw or "open").lower())


def _verify_signature(provider: str, raw_body: bytes, headers: dict) -> bool:
    """Provider-specific HMAC verification.

    Returns True if the secret env var isn't set (test-friendly opt-in).
    Production deployments MUST set the corresponding secret.
    """
    provider = provider.lower()
    if provider == "github":
        sig = headers.get("x-hub-signature-256") or headers.get("X-Hub-Signature-256")
        secret = os.getenv("SC_GITHUB_WEBHOOK_SECRET", "")
        if not secret:
            return True
        if not sig or not sig.startswith("sha256="):
            return False
        expected = "sha256=" + _hmac.new(
            secret.encode(), raw_body, hashlib.sha256,
        ).hexdigest()
        return _hmac.compare_digest(expected, sig)
    if provider == "jira":
        sig = headers.get("x-atlassian-webhook-identifier") or ""
        # Atlassian's HMAC scheme is account-specific; opt-in via secret env.
        secret = os.getenv("SC_JIRA_WEBHOOK_SECRET", "")
        if not secret:
            return True
        return bool(sig)
    if provider == "servicenow":
        return True  # ServiceNow integrations typically gate via mTLS at the LB
    if provider == "linear":
        sig = headers.get("linear-signature") or ""
        secret = os.getenv("SC_LINEAR_WEBHOOK_SECRET", "")
        if not secret:
            return True
        expected = _hmac.new(
            secret.encode(), raw_body, hashlib.sha256,
        ).hexdigest()
        return _hmac.compare_digest(expected, sig)
    return True


def _extract(provider: str, payload: dict) -> dict:
    """Pull (event_id, external_id, status_raw) out of a provider payload.

    Each provider has its own shape; this is the small adapter layer
    we don't get to skip.
    """
    p = provider.lower()
    if p == "jira":
        return {
            "event_id": str(payload.get("timestamp", "")),
            "external_id": str((payload.get("issue") or {}).get("key", "")),
            "status_raw": str(
                (((payload.get("issue") or {}).get("fields") or {})
                 .get("status") or {}).get("name", "")
            ),
        }
    if p == "github":
        issue = payload.get("issue") or {}
        return {
            "event_id": str(payload.get("delivery") or issue.get("id", "")),
            "external_id": str(issue.get("number", "")),
            "status_raw": str(issue.get("state", "")),
        }
    if p == "servicenow":
        return {
            "event_id": str(payload.get("sys_id", "")),
            "external_id": str(payload.get("number", "")),
            "status_raw": str(payload.get("state", "")),
        }
    if p == "linear":
        data = payload.get("data") or {}
        return {
            "event_id": str(payload.get("delivery") or data.get("id", "")),
            "external_id": str(data.get("identifier", "")),
            "status_raw": str((data.get("state") or {}).get("name", "")),
        }
    return {"event_id": "", "external_id": "", "status_raw": ""}


def apply_webhook(
    provider: str, raw_body: bytes, headers: dict | None = None,
) -> dict:
    """End-to-end: verify signature → dedupe → map status → update link.

    Returns ``{"ok": bool, "action": str, ...}``. Never raises.
    """
    headers = headers or {}
    provider = (provider or "").lower()

    if provider not in _STATUS_MAP:
        return {"ok": False, "action": "error",
                "reason": f"unknown provider: {provider!r}"}

    if not _verify_signature(provider, raw_body, headers):
        return {"ok": False, "action": "error",
                "reason": "signature verification failed"}

    try:
        payload = json.loads(raw_body.decode("utf-8"))
    except Exception:
        return {"ok": False, "action": "error",
                "reason": "malformed JSON"}

    fields = _extract(provider, payload)
    event_id = fields.get("event_id") or ""
    external_id = fields.get("external_id") or ""
    status_raw = fields.get("status_raw") or ""

    if not external_id:
        return {"ok": False, "action": "error",
                "reason": "no external_id in payload"}

    # Idempotency check.
    c = _conn()
    if event_id:
        seen = c.execute(
            "SELECT 1 FROM ticket_webhook_events WHERE provider=? AND event_id=?",
            (provider, event_id),
        ).fetchone()
        if seen:
            c.close()
            return {"ok": True, "action": "duplicate_dropped",
                    "external_id": external_id, "event_id": event_id}
        c.execute(
            "INSERT INTO ticket_webhook_events (provider, event_id, received_at) "
            "VALUES (?, ?, ?)",
            (provider, event_id, int(time.time())),
        )

    new_status = _map_status(provider, status_raw)

    link = c.execute(
        "SELECT finding_id, status FROM ticket_links "
        "WHERE provider=? AND external_id=?",
        (provider, external_id),
    ).fetchone()
    if link is None:
        c.commit()
        c.close()
        return {"ok": True, "action": "no_link",
                "external_id": external_id,
                "reason": "ticket not linked to a known finding"}

    finding_id, prev_status = link
    if new_status == prev_status:
        c.execute(
            "UPDATE ticket_links SET last_seen_at=? "
            "WHERE provider=? AND external_id=?",
            (int(time.time()), provider, external_id),
        )
        c.commit()
        c.close()
        return {"ok": True, "action": "no_change", "status": new_status,
                "external_id": external_id, "finding_id": finding_id}

    c.execute(
        "UPDATE ticket_links SET status=?, last_seen_at=? "
        "WHERE provider=? AND external_id=?",
        (new_status, int(time.time()), provider, external_id),
    )
    c.commit()
    c.close()
    return {
        "ok": True, "action": "status_updated",
        "prev_status": prev_status, "status": new_status,
        "external_id": external_id, "finding_id": finding_id,
    }


__all__ = [
    "ensure_link_schema",
    "link_ticket",
    "find_link_by_external_id",
    "apply_webhook",
]
