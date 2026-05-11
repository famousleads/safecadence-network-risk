"""
Tiny support-ticket store used by the customer portal (v10.9).

Persisted as JSONL at ``~/.safecadence/orgs/<org_id>/support_tickets.jsonl``.
This is intentionally minimal — production deployments are expected to
forward to Zendesk / Front / etc. via a webhook hook in
:mod:`safecadence.workflow.change_mgmt`.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import secrets
from pathlib import Path


def _path(org_id: str) -> Path:
    from safecadence.storage.org_store import org_data_dir
    return org_data_dir(org_id) / "support_tickets.jsonl"


def _is_readonly() -> bool:
    return os.environ.get("SC_READONLY", "") == "1"


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def create_ticket(org_id: str, email: str, subject: str, message: str) -> dict:
    if _is_readonly():
        return {"id": "demo-noop", "status": "open", "subject": subject,
                "created_at": _now_iso(), "email": email}
    ticket = {
        "id": "tkt_" + secrets.token_urlsafe(8),
        "org_id": org_id,
        "email": email,
        "subject": (subject or "").strip()[:200],
        "message": (message or "").strip()[:4000],
        "status": "open",
        "created_at": _now_iso(),
    }
    path = _path(org_id)
    with path.open("a", encoding="utf-8") as fp:
        fp.write(json.dumps(ticket) + "\n")
    return ticket


def list_tickets(org_id: str) -> list[dict]:
    if not org_id:
        return []
    path = _path(org_id)
    if not path.exists():
        return []
    rows: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except Exception:
            continue
    rows.sort(key=lambda r: r.get("created_at") or "", reverse=True)
    return rows


__all__ = ["create_ticket", "list_tickets"]
