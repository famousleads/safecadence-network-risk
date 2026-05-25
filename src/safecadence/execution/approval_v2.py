"""
v13.0 — Approval workflow v2.

Extends the existing v9.x execution-approval triple-gate with:

* **Multi-approver chains** — a single approval policy can require
  N-of-M approvers (e.g. "any 2 of [alice, bob, carol]").
* **Delegation** — when an approver is out of office, approval routes
  to the named delegate automatically.
* **Per-asset-class policies** — different gear types can require
  different chains. Firewalls require 2 approvers; switches require 1;
  identity systems require 3 + a CISO sign-off.
* **Time-bound approval validity** — approvals expire after N hours
  (default 24) so a change approved Friday can't be silently executed
  Monday after the world changed.
* **Audit-grade approval log** — every approve/reject/expire event is
  appended to the v11.3 hash-chained audit log.

Single-approver behavior is preserved as a special case (`N=1, M=1`).

This module is pure orchestration on top of the existing execution
schema. It does NOT change the actual SSH execution path; the
triple-gate (capability + acknowledge + TOTP) still applies on top.

Public API
----------

* ``ApprovalPolicy(name, asset_class, n_required, approvers, delegate_map, ttl_hours)``
* ``Approval(job_id, approver_user_id, decision, at, comment)``
* ``decide(job_id, approver_user_id, decision, policy, prior_approvals, ...)``
    → ``{"state": "pending" | "approved" | "rejected" | "expired",
         "satisfied_by": [user_ids], "needed": int, "policy_name": str}``
* ``resolve_approver(asked_user_id, delegate_map)``  — follows delegation
* ``policy_for_asset(asset, policies)``  — picks the right policy
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


VALID_DECISIONS = ("approve", "reject", "abstain")


# --------------------------------------------------------------------------
# Schema
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ApprovalPolicy:
    name: str
    asset_class: str                   # "firewall" | "switch" | "identity" | "*"
    n_required: int                    # how many distinct approvers needed
    approvers: tuple[str, ...]         # allowed approver user_ids
    delegate_map: tuple[tuple[str, str], ...] = ()   # ((from_user, to_user), ...)
    ttl_hours: int = 24

    @property
    def delegate_dict(self) -> dict[str, str]:
        return dict(self.delegate_map)

    @property
    def m_pool(self) -> int:
        return len(self.approvers)


@dataclass(frozen=True)
class Approval:
    job_id: str
    approver_user_id: str
    decision: str                      # one of VALID_DECISIONS
    at: int                            # unix seconds
    comment: str = ""

    def __post_init__(self) -> None:
        if self.decision not in VALID_DECISIONS:
            raise ValueError(f"unknown decision: {self.decision!r}")


# --------------------------------------------------------------------------
# Pure helpers
# --------------------------------------------------------------------------


def resolve_approver(
    asked_user_id: str, delegate_map: dict[str, str],
) -> str:
    """If asked_user_id has a delegate, return the delegate.

    Follows a single hop only; circular delegations are detected + the
    original asked_user_id is returned (operator should fix the loop).
    """
    if not delegate_map or asked_user_id not in delegate_map:
        return asked_user_id
    target = delegate_map[asked_user_id]
    # Detect a 2-cycle (asked → target → asked).
    if delegate_map.get(target) == asked_user_id:
        return asked_user_id
    return target


def policy_for_asset(
    asset: dict, policies: list[ApprovalPolicy],
) -> ApprovalPolicy | None:
    """Find the first policy whose asset_class matches the asset.

    Policies with ``asset_class="*"`` match anything (catch-all). They
    should be ordered LAST in the list so specific policies win.
    """
    klass = (asset.get("asset_class") or asset.get("asset_type") or "").lower()
    for p in policies:
        ac = p.asset_class.lower()
        if ac == "*" or ac == klass:
            return p
    return None


def _expired(approvals: list[Approval], now_ts: int, ttl_hours: int) -> bool:
    """True when the OLDEST approval is older than ttl_hours."""
    if not approvals:
        return False
    oldest = min(a.at for a in approvals if a.decision == "approve")
    return (now_ts - int(oldest)) > ttl_hours * 3600


def decide(
    *,
    job_id: str,
    approver_user_id: str,
    decision: str,
    policy: ApprovalPolicy,
    prior_approvals: list[Approval] | None = None,
    now_ts: int | None = None,
    comment: str = "",
) -> dict:
    """Apply one approval/rejection and report the new aggregate state.

    Pure function. Storage of approvals + audit logging is the caller's
    job; this function just decides what the world looks like after
    one more approval lands.

    Returns:
        {
          "state": "pending" | "approved" | "rejected" | "expired",
          "satisfied_by": [user_ids],
          "needed": int,
          "policy_name": str,
          "applied_approval": Approval | None,
          "note": str,
        }
    """
    import time
    now = now_ts if now_ts is not None else int(time.time())
    prior = list(prior_approvals or [])

    # Reject overrides everything: one explicit reject ends the chain.
    if any(a.decision == "reject" for a in prior):
        return {
            "state": "rejected",
            "satisfied_by": [],
            "needed": policy.n_required,
            "policy_name": policy.name,
            "applied_approval": None,
            "note": "chain previously rejected by an approver",
        }

    if _expired(prior, now, policy.ttl_hours):
        return {
            "state": "expired",
            "satisfied_by": [],
            "needed": policy.n_required,
            "policy_name": policy.name,
            "applied_approval": None,
            "note": f"oldest approval > {policy.ttl_hours}h",
        }

    # Resolve delegation up front so the approver who actually files
    # is the resolved one.
    real_approver = resolve_approver(
        approver_user_id, policy.delegate_dict,
    )
    if real_approver not in policy.approvers:
        return {
            "state": "pending",
            "satisfied_by": [a.approver_user_id for a in prior
                              if a.decision == "approve"],
            "needed": policy.n_required,
            "policy_name": policy.name,
            "applied_approval": None,
            "note": (f"{real_approver!r} is not in the approver pool for "
                     f"policy {policy.name!r}"),
        }

    if decision not in VALID_DECISIONS:
        return {
            "state": "pending",
            "satisfied_by": [a.approver_user_id for a in prior
                              if a.decision == "approve"],
            "needed": policy.n_required,
            "policy_name": policy.name,
            "applied_approval": None,
            "note": f"unknown decision: {decision!r}",
        }

    # Build the new approval row.
    new_approval = Approval(
        job_id=job_id,
        approver_user_id=real_approver,
        decision=decision,
        at=now,
        comment=comment,
    )

    if decision == "reject":
        return {
            "state": "rejected",
            "satisfied_by": [],
            "needed": policy.n_required,
            "policy_name": policy.name,
            "applied_approval": new_approval,
            "note": f"rejected by {real_approver}",
        }

    if decision == "abstain":
        # Doesn't count toward N; doesn't block either.
        return {
            "state": "pending",
            "satisfied_by": sorted({a.approver_user_id for a in prior
                                     if a.decision == "approve"}),
            "needed": policy.n_required,
            "policy_name": policy.name,
            "applied_approval": new_approval,
            "note": "abstain recorded; chain still pending",
        }

    # decision == "approve"
    unique = sorted({a.approver_user_id for a in prior
                     if a.decision == "approve"} | {real_approver})

    if len(unique) >= policy.n_required:
        return {
            "state": "approved",
            "satisfied_by": unique,
            "needed": policy.n_required,
            "policy_name": policy.name,
            "applied_approval": new_approval,
            "note": f"approved by {len(unique)} of {policy.n_required}",
        }

    return {
        "state": "pending",
        "satisfied_by": unique,
        "needed": policy.n_required,
        "policy_name": policy.name,
        "applied_approval": new_approval,
        "note": f"{len(unique)}/{policy.n_required} approvals so far",
    }


__all__ = [
    "VALID_DECISIONS",
    "ApprovalPolicy", "Approval",
    "resolve_approver", "policy_for_asset", "decide",
]
