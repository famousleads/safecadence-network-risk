"""
Risk-acceptance / exception management.

Each exception is asset-scoped + control-scoped + time-bound. The
evaluator queries this module via SecurityPolicy.exceptions to skip
covered controls. An audit entry is written on every add / revoke /
auto-expire.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from safecadence.policy.audit import log as audit_log
from safecadence.policy.schema import PolicyException, SecurityPolicy
from safecadence.policy.store import get, save


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def add_exception(policy_id: str, *, asset_id: str, control_id: str,
                  justification: str, approved_by: str,
                  expires_at: str = "", actor: str = "system") -> PolicyException:
    p = get(policy_id)
    if not p:
        raise KeyError(f"policy not found: {policy_id}")
    ex = PolicyException(
        exception_id=f"exc_{uuid.uuid4().hex[:8]}",
        asset_id=asset_id, control_id=control_id,
        justification=justification, approved_by=approved_by,
        approved_at=_now(), expires_at=expires_at, status="active",
    )
    p.exceptions = list(p.exceptions or []) + [ex]
    save(p, actor=actor)
    audit_log("exception_added", actor=actor, policy_id=policy_id,
              detail={"exception_id": ex.exception_id, "asset_id": asset_id,
                      "control_id": control_id, "expires_at": expires_at})
    return ex


def revoke_exception(policy_id: str, exception_id: str, *, actor: str = "system") -> bool:
    p = get(policy_id)
    if not p:
        return False
    found = False
    for ex in (p.exceptions or []):
        if ex.exception_id == exception_id and ex.status == "active":
            ex.status = "revoked"
            found = True
    if found:
        save(p, actor=actor)
        audit_log("exception_revoked", actor=actor, policy_id=policy_id,
                  detail={"exception_id": exception_id})
    return found


def expire_overdue(policy_id: str, *, actor: str = "system") -> int:
    p = get(policy_id)
    if not p:
        return 0
    now = _now()
    expired = 0
    for ex in (p.exceptions or []):
        if ex.status == "active" and ex.expires_at and ex.expires_at < now:
            ex.status = "expired"
            expired += 1
    if expired:
        save(p, actor=actor)
        audit_log("exceptions_expired", actor=actor, policy_id=policy_id,
                  detail={"count": expired})
    return expired


def list_exceptions(policy_id: str) -> list[dict]:
    p = get(policy_id)
    if not p:
        return []
    return [{"exception_id": ex.exception_id, "asset_id": ex.asset_id,
             "control_id": ex.control_id, "justification": ex.justification,
             "approved_by": ex.approved_by, "approved_at": ex.approved_at,
             "expires_at": ex.expires_at, "status": ex.status}
            for ex in (p.exceptions or [])]
