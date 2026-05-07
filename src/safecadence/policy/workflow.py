"""
Approval workflow — Draft → Review → Approved → Deprecated.

State transitions only (no execution). Multi-approver gating is logical:
'critical' policies require an additional approver before they can move
from Review → Approved.
"""

from __future__ import annotations

from datetime import datetime, timezone

from safecadence.policy.audit import log as audit_log
from safecadence.policy.schema import PolicyState, SecurityPolicy, Severity
from safecadence.policy.store import save, get


_TRANSITIONS = {
    PolicyState.DRAFT:      {PolicyState.REVIEW, PolicyState.DEPRECATED},
    PolicyState.REVIEW:     {PolicyState.DRAFT, PolicyState.APPROVED, PolicyState.DEPRECATED},
    PolicyState.APPROVED:   {PolicyState.REVIEW, PolicyState.DEPRECATED},
    PolicyState.DEPRECATED: {PolicyState.DRAFT},
}


class WorkflowError(Exception):
    pass


def transition(policy_id: str, target: PolicyState, *, actor: str,
               approvers: list[str] | None = None) -> SecurityPolicy:
    p = get(policy_id)
    if not p:
        raise WorkflowError(f"policy not found: {policy_id}")
    cur = p.state
    if isinstance(cur, str):
        cur = PolicyState(cur)
    if isinstance(target, str):
        target = PolicyState(target)
    if target not in _TRANSITIONS.get(cur, set()):
        raise WorkflowError(f"illegal transition {cur.value} → {target.value}")

    sev = p.severity if isinstance(p.severity, Severity) else Severity(p.severity)
    if (cur == PolicyState.REVIEW and target == PolicyState.APPROVED
            and sev == Severity.CRITICAL and len(approvers or []) < 2):
        raise WorkflowError("critical policies require at least 2 approvers")

    p.state = target
    p.updated_at = datetime.now(timezone.utc).isoformat()
    save(p, actor=actor)
    audit_log("policy_transition", actor=actor, policy_id=policy_id,
              detail={"from": cur.value, "to": target.value,
                      "approvers": approvers or []})
    return p
