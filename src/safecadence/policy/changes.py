"""
v9.32 — policy change approval workflow.

Every edit to a policy (create / modify / activate / archive) lands
here as a change record:

  * change_id, policy_id, action, before/after snapshot, requested_by,
    requested_at, status, approved_by, approved_at

Changes default to ``pending``; the policy itself doesn't go live
until an approver flips the status to ``approved``. This is the
SOX-like "every config change has a ticket" pattern.

Storage: file-backed JSON-lines at $SC_DATA_DIR/policy_changes.jsonl
so appends stay O(1).
"""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional


_VALID_ACTIONS = ("create", "update", "activate", "archive", "delete")
_VALID_STATUSES = ("pending", "approved", "rejected", "auto_applied")


def _store() -> Path:
    home = (os.environ.get("SC_DATA_DIR")
              or os.environ.get("SAFECADENCE_HOME")
              or str(Path.home() / ".safecadence"))
    p = Path(home)
    p.mkdir(parents=True, exist_ok=True)
    return p / "policy_changes.jsonl"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class PolicyChange:
    id: str
    policy_id: str
    action: str
    before: dict
    after: dict
    requested_by: str
    requested_at: str
    status: str = "pending"
    approved_by: str = ""
    approved_at: str = ""
    note: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _append(rec: PolicyChange) -> None:
    p = _store()
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec.to_dict(), separators=(",", ":")) + "\n")


def _iter_records() -> Iterable[dict]:
    p = _store()
    if not p.exists():
        return
    with p.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except Exception:
                continue


def _rewrite(records: list[dict]) -> None:
    """Used by approve/reject to update an existing record (we don't
    want a separate 'mutations' file — the change log itself is the
    history)."""
    p = _store()
    p.write_text("\n".join(
        json.dumps(r, separators=(",", ":")) for r in records
    ) + ("\n" if records else ""), encoding="utf-8")


def request_change(*, policy_id: str, action: str,
                     before: dict, after: dict,
                     requested_by: str, note: str = "") -> PolicyChange:
    if action not in _VALID_ACTIONS:
        raise ValueError(f"action must be one of {_VALID_ACTIONS}")
    if not policy_id or not requested_by:
        raise ValueError("policy_id and requested_by are required")
    rec = PolicyChange(
        id=f"chg-{uuid.uuid4().hex[:12]}",
        policy_id=policy_id, action=action,
        before=dict(before or {}), after=dict(after or {}),
        requested_by=requested_by.strip(),
        requested_at=_now(), status="pending",
        note=(note or "").strip(),
    )
    _append(rec)
    return rec


def list_changes(*, policy_id: Optional[str] = None,
                   status: Optional[str] = None,
                   limit: int = 200) -> list[dict]:
    out = []
    for r in _iter_records():
        if policy_id and r.get("policy_id") != policy_id:
            continue
        if status and r.get("status") != status:
            continue
        out.append(r)
    out.sort(key=lambda r: r.get("requested_at", ""), reverse=True)
    return out[:limit]


def approve(change_id: str, *, approved_by: str,
              note: str = "") -> Optional[dict]:
    records = list(_iter_records())
    for r in records:
        if r.get("id") == change_id:
            if r.get("status") != "pending":
                return None
            r["status"] = "approved"
            r["approved_by"] = approved_by
            r["approved_at"] = _now()
            if note:
                r["note"] = ((r.get("note", "") or "") + " | " + note).strip(" |")
            _rewrite(records)
            return r
    return None


def reject(change_id: str, *, approved_by: str,
             note: str = "") -> Optional[dict]:
    records = list(_iter_records())
    for r in records:
        if r.get("id") == change_id:
            if r.get("status") != "pending":
                return None
            r["status"] = "rejected"
            r["approved_by"] = approved_by
            r["approved_at"] = _now()
            if note:
                r["note"] = ((r.get("note", "") or "") + " | " + note).strip(" |")
            _rewrite(records)
            return r
    return None


def pending_count() -> int:
    return sum(1 for r in _iter_records() if r.get("status") == "pending")
