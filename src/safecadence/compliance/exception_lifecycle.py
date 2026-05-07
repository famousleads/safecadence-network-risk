"""
v9.28 — Exception lifecycle.

A risk acceptance / exception isn't just "this finding is OK." Auditors
expect every exception to carry:

  * a written justification
  * the person who accepted the risk
  * an expiry date
  * a re-review date (typically halfway between approval and expiry)
  * the linked control ID and finding/asset

Exceptions that pass their re-review or expiry without action become
findings of their own — the daemon promotes them via
:func:`expiring_exceptions_as_findings`. This is what SOC 2 CC4 asks
for.

Storage: file-backed at ``$SC_DATA_DIR/exceptions.json`` so the
operator's notes survive restarts.
"""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------- store


def _store_path() -> Path:
    home = (os.environ.get("SC_DATA_DIR")
              or os.environ.get("SAFECADENCE_HOME")
              or str(Path.home() / ".safecadence"))
    p = Path(home)
    p.mkdir(parents=True, exist_ok=True)
    return p / "exceptions.json"


def _read_all() -> list[dict]:
    p = _store_path()
    if not p.exists():
        return []
    try:
        return list(json.loads(p.read_text(encoding="utf-8")) or [])
    except Exception:
        return []


def _write_all(rows: list[dict]) -> None:
    p = _store_path()
    p.write_text(json.dumps(rows, separators=(",", ":")),
                  encoding="utf-8")


# ---------------------------------------------------------------- model


@dataclass
class Exception_:
    """One exception record. Named with trailing underscore so we
    don't shadow the builtin in module-level use."""
    id: str
    control_id: str
    asset_id: str
    finding_id: str
    justification: str
    accepted_by: str
    created_at: str
    expires_at: str
    re_review_at: str
    status: str = "active"   # active | expired | revoked

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------- crud


def create_exception(*, control_id: str, asset_id: str,
                       finding_id: str, justification: str,
                       accepted_by: str,
                       valid_for_days: int = 90) -> Exception_:
    if valid_for_days <= 0 or valid_for_days > 365:
        raise ValueError("valid_for_days must be 1..365")
    if len(justification.strip()) < 10:
        raise ValueError("justification must be at least 10 characters")
    now = datetime.now(timezone.utc)
    exp = now + timedelta(days=valid_for_days)
    review = now + timedelta(days=max(7, valid_for_days // 2))
    rec = Exception_(
        id=f"exc-{uuid.uuid4().hex[:12]}",
        control_id=control_id, asset_id=asset_id,
        finding_id=finding_id,
        justification=justification.strip(),
        accepted_by=accepted_by.strip(),
        created_at=now.isoformat(),
        expires_at=exp.isoformat(),
        re_review_at=review.isoformat(),
        status="active",
    )
    rows = _read_all()
    rows.append(rec.to_dict())
    _write_all(rows)
    return rec


def list_exceptions(*, status: Optional[str] = None) -> list[dict]:
    rows = _read_all()
    if status:
        rows = [r for r in rows if r.get("status") == status]
    return rows


def revoke_exception(exception_id: str, *, by: str = "") -> bool:
    rows = _read_all()
    for r in rows:
        if r.get("id") == exception_id:
            r["status"] = "revoked"
            r["revoked_by"] = by
            r["revoked_at"] = datetime.now(timezone.utc).isoformat()
            _write_all(rows)
            return True
    return False


# ---------------------------------------------------------------- daemon hooks


def _parse(ts: str) -> datetime:
    s = (ts or "").replace("Z", "+00:00")
    try:
        out = datetime.fromisoformat(s)
        if out.tzinfo is None:
            out = out.replace(tzinfo=timezone.utc)
        return out
    except Exception:
        return datetime.now(timezone.utc)


def expiring_exceptions(*, within_days: int = 14) -> list[dict]:
    """Exceptions due for re-review or expiry within N days."""
    now = datetime.now(timezone.utc)
    cutoff = now + timedelta(days=within_days)
    out: list[dict] = []
    for r in _read_all():
        if r.get("status") != "active":
            continue
        review = _parse(r.get("re_review_at", ""))
        expires = _parse(r.get("expires_at", ""))
        soonest = min(review, expires)
        if soonest <= cutoff:
            out.append({**r, "soonest_action": soonest.isoformat()})
    return out


def expiring_exceptions_as_findings(within_days: int = 14) -> list[dict]:
    """Synthetic findings the daemon emits so expiring exceptions
    show up on /findings + Splunk + Slack like any other issue."""
    out: list[dict] = []
    now = datetime.now(timezone.utc)
    for ex in expiring_exceptions(within_days=within_days):
        soonest = _parse(ex["soonest_action"])
        days = max(0, (soonest - now).days)
        out.append({
            "id": f"exc-expiring::{ex['id']}",
            "kind": "exception_expiring",
            "severity": "high" if days <= 3 else "medium",
            "asset_id": ex.get("asset_id", ""),
            "title": f"Exception {ex['id']} needs review",
            "message": (f"Exception for control {ex.get('control_id')} "
                          f"on {ex.get('asset_id')} requires action in "
                          f"{days} day(s). Justification: "
                          f"{ex.get('justification','')[:120]}"),
            "control_id": ex.get("control_id", ""),
            "exception_id": ex.get("id"),
        })
    return out


def auto_expire_past_due() -> int:
    """Mark any active exception past its expiry as 'expired'.
    Returns count expired. Call from the daemon each cycle."""
    now = datetime.now(timezone.utc)
    rows = _read_all()
    n = 0
    for r in rows:
        if r.get("status") != "active":
            continue
        if _parse(r.get("expires_at", "")) <= now:
            r["status"] = "expired"
            r["expired_at"] = now.isoformat()
            n += 1
    if n:
        _write_all(rows)
    return n
