"""
Approval chains for risk acceptance (v10.8).

The v10.4 :mod:`safecadence.reports.risk_acceptance` module lets a single
caller accept a finding. Real customers (especially regulated ones) need
multi-step sign-off before a risk-acceptance entry is binding.

This module is the workflow engine that sits in front of
``risk_acceptance.add_acceptance``:

* :func:`define_chain` saves a chain *template* (a sequence of roles).
* :func:`start_approval` creates an *approval instance* bound to a
  finding, in ``status="pending"`` with the first step open.
* :func:`sign_step` records a signature on the current step, advances
  the chain to the next, and, when the last step is signed, applies the
  underlying risk acceptance (so accepted-by-policy means accepted-in-
  the-acceptance-log).
* :func:`cancel_approval` halts a chain (``status="cancelled"``).
* :func:`list_approvals` returns every approval for an org (optionally
  filtered by status).

Persistence
-----------
One JSON file per org under
``~/.safecadence/orgs/<org_id>/approval_chains.json`` for chain templates,
and one JSON-lines file at ``approvals.jsonl`` for the *instances*.
JSON Lines lets us append every state transition without rewriting the
whole file — a property the v10.3 audit log used to good effect.

RBAC
----
Signing requires the signer's role for the org to match the role the
step demands. The mapping is :mod:`safecadence.auth.rbac` (admin /
editor / viewer); roles outside that set are accepted verbatim so
custom labels like "CISO" or "compliance-officer" still work — we
treat them as informational strings until RBAC v2 ships.

Read-only mode (``SC_READONLY=1``) refuses ``define_chain`` /
``start_approval`` / ``sign_step`` / ``cancel_approval`` with
``PermissionError`` so the public demo can mount the routes without
state changes.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import json
import os
import secrets
from pathlib import Path
from typing import Any

# Module-level imports must succeed without optional deps.


# --------------------------------------------------------------------------
# Paths + helpers
# --------------------------------------------------------------------------


def _org_dir(org_id: str) -> Path:
    if not org_id:
        raise ValueError("org_id is required")
    from safecadence.storage.org_store import org_data_dir
    return org_data_dir(org_id)


def _chains_path(org_id: str) -> Path:
    return _org_dir(org_id) / "approval_chains.json"


def _instances_path(org_id: str) -> Path:
    return _org_dir(org_id) / "approvals.jsonl"


def _is_readonly() -> bool:
    return os.environ.get("SC_READONLY", "") == "1"


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------
# Data shapes
# --------------------------------------------------------------------------


@dataclasses.dataclass
class ApprovalStep:
    role: str
    signed_by: str | None = None
    signed_at: str | None = None
    note: str | None = None

    def to_dict(self) -> dict:
        d = dataclasses.asdict(self)
        return {k: v for k, v in d.items() if v is not None or k == "role"}


@dataclasses.dataclass
class ApprovalChain:
    """An *instance* of an approval chain bound to a finding."""

    id: str
    org_id: str
    name: str
    finding_id: str
    host: str | None
    steps: list[ApprovalStep]
    status: str  # "pending" | "approved" | "cancelled"
    started_at: str
    completed_at: str | None = None
    cancelled_reason: str | None = None
    acceptance_id: str | None = None  # id of the risk_acceptance row, when approved
    rationale: str | None = None
    expires_at: str | None = None

    def to_dict(self) -> dict:
        d = dataclasses.asdict(self)
        d["steps"] = [s if isinstance(s, dict) else s for s in d["steps"]]
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "ApprovalChain":
        steps = [
            ApprovalStep(**s) if isinstance(s, dict) else s
            for s in (d.get("steps") or [])
        ]
        return cls(
            id=str(d.get("id") or ""),
            org_id=str(d.get("org_id") or ""),
            name=str(d.get("name") or ""),
            finding_id=str(d.get("finding_id") or ""),
            host=d.get("host"),
            steps=steps,
            status=str(d.get("status") or "pending"),
            started_at=str(d.get("started_at") or ""),
            completed_at=d.get("completed_at"),
            cancelled_reason=d.get("cancelled_reason"),
            acceptance_id=d.get("acceptance_id"),
            rationale=d.get("rationale"),
            expires_at=d.get("expires_at"),
        )


# --------------------------------------------------------------------------
# Chain template CRUD
# --------------------------------------------------------------------------


def _read_chains(org_id: str) -> dict[str, list[str]]:
    p = _chains_path(org_id)
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}
    if isinstance(data, dict):
        return {str(k): list(v) for k, v in data.items() if isinstance(v, list)}
    return {}


def _write_chains(org_id: str, chains: dict[str, list[str]]) -> None:
    p = _chains_path(org_id)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(chains, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(p)


def define_chain(org_id: str, name: str, role_steps: list[str]) -> dict:
    """Persist a chain template.

    Returns the saved chain spec as a dict ``{name, role_steps}``.
    Raises :class:`PermissionError` when read-only.
    """
    if _is_readonly():
        raise PermissionError("read_only: chains cannot be defined when SC_READONLY=1")
    name = (name or "").strip()
    if not name:
        raise ValueError("chain name is required")
    if not role_steps or not isinstance(role_steps, list):
        raise ValueError("role_steps must be a non-empty list of role strings")
    steps = [str(r).strip().lower() for r in role_steps if str(r).strip()]
    if not steps:
        raise ValueError("role_steps must contain at least one role")
    chains = _read_chains(org_id)
    chains[name] = steps
    _write_chains(org_id, chains)
    return {"name": name, "role_steps": steps}


def get_chain(org_id: str, name: str) -> list[str] | None:
    return _read_chains(org_id).get(name)


def list_chains(org_id: str) -> list[dict]:
    return [{"name": k, "role_steps": v} for k, v in sorted(_read_chains(org_id).items())]


# --------------------------------------------------------------------------
# Instance persistence — append-only JSONL
# --------------------------------------------------------------------------


def _new_approval_id() -> str:
    return "apr_" + secrets.token_urlsafe(9).replace("-", "").replace("_", "")[:12]


def _append_event(org_id: str, payload: dict) -> None:
    p = _instances_path(org_id)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload, default=str) + "\n")


def _read_events(org_id: str) -> list[dict]:
    p = _instances_path(org_id)
    if not p.exists():
        return []
    out: list[dict] = []
    with p.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if isinstance(obj, dict):
                out.append(obj)
    return out


def _fold(events: list[dict]) -> dict[str, ApprovalChain]:
    """Replay the JSONL stream into the current state of every approval."""
    out: dict[str, ApprovalChain] = {}
    for ev in events:
        kind = ev.get("event")
        aid = ev.get("id")
        if not aid:
            continue
        if kind == "start":
            out[aid] = ApprovalChain.from_dict(ev.get("approval") or {})
        elif kind == "sign":
            ap = out.get(aid)
            if not ap:
                continue
            idx = int(ev.get("step_index") or 0)
            if 0 <= idx < len(ap.steps):
                ap.steps[idx].signed_by = ev.get("user_email")
                ap.steps[idx].signed_at = ev.get("ts")
                ap.steps[idx].note = ev.get("note")
            # Status transition + acceptance application
            if ev.get("approved"):
                ap.status = "approved"
                ap.completed_at = ev.get("ts")
                ap.acceptance_id = ev.get("acceptance_id")
        elif kind == "cancel":
            ap = out.get(aid)
            if not ap:
                continue
            ap.status = "cancelled"
            ap.completed_at = ev.get("ts")
            ap.cancelled_reason = ev.get("reason")
    return out


# --------------------------------------------------------------------------
# Public API — instance lifecycle
# --------------------------------------------------------------------------


def start_approval(
    org_id: str,
    finding_id: str,
    chain_name: str,
    *,
    host: str | None = None,
    rationale: str | None = None,
    expires_at: str | None = None,
) -> ApprovalChain:
    """Create a new pending approval instance for ``finding_id``."""
    if _is_readonly():
        raise PermissionError("read_only: approvals cannot start when SC_READONLY=1")
    if not finding_id:
        raise ValueError("finding_id is required")
    role_steps = get_chain(org_id, chain_name)
    if not role_steps:
        raise KeyError(f"no chain named {chain_name!r} in org {org_id!r}")
    aid = _new_approval_id()
    approval = ApprovalChain(
        id=aid,
        org_id=org_id,
        name=chain_name,
        finding_id=finding_id,
        host=host,
        steps=[ApprovalStep(role=r) for r in role_steps],
        status="pending",
        started_at=_now_iso(),
        rationale=rationale,
        expires_at=expires_at,
    )
    _append_event(org_id, {
        "event": "start",
        "id": aid,
        "ts": approval.started_at,
        "approval": _approval_to_jsonable(approval),
    })
    # Hook: announce a "risk_accepted" candidate is in flight.
    try:
        from safecadence.workflow.change_mgmt import record_change
        record_change(
            org_id, "approval_started",
            before=None,
            after={"approval_id": aid, "finding_id": finding_id, "chain": chain_name},
            actor=None,
        )
    except Exception:  # pragma: no cover
        pass
    return approval


def _approval_to_jsonable(ap: ApprovalChain) -> dict:
    d = ap.to_dict()
    d["steps"] = [s.to_dict() if isinstance(s, ApprovalStep) else s for s in ap.steps]
    return d


def get_approval(org_id: str, approval_id: str) -> ApprovalChain | None:
    return _fold(_read_events(org_id)).get(approval_id)


def list_approvals(org_id: str, status: str | None = None) -> list[ApprovalChain]:
    items = list(_fold(_read_events(org_id)).values())
    if status:
        items = [a for a in items if a.status == status]
    items.sort(key=lambda a: a.started_at, reverse=True)
    return items


def _user_has_role(org_id: str, user_email: str, required: str) -> bool:
    """Check whether the user has the required role in the org.

    Falls back to a literal string match when the role isn't part of the
    built-in RBAC vocabulary — keeps "CISO" / "compliance-officer" etc.
    workable until proper custom roles ship.
    """
    if os.environ.get("SC_AUTH_DISABLED", "") == "1":
        return True
    required = (required or "").strip().lower()
    try:
        from safecadence.auth.rbac import get_role, UserRole
        actual = get_role(org_id, user_email)
        if actual is None:
            return False
        if required in {r.value for r in UserRole}:
            # Built-in role — compare strictly.
            return actual.value == required
        # Custom role — fall back to a labels-file lookup.
    except Exception:
        return False

    return _has_custom_role(org_id, user_email, required)


def _custom_roles_path(org_id: str) -> Path:
    return _org_dir(org_id) / "custom_roles.json"


def _has_custom_role(org_id: str, user_email: str, role: str) -> bool:
    p = _custom_roles_path(org_id)
    if not p.exists():
        return False
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return False
    user = (user_email or "").strip().lower()
    members = data.get(role) or []
    return isinstance(members, list) and user in {str(m).lower() for m in members}


def assign_custom_role(org_id: str, role: str, user_email: str) -> None:
    """Add ``user_email`` to a custom role list (e.g. ``CISO``)."""
    if _is_readonly():
        raise PermissionError("read_only: custom roles cannot be assigned when SC_READONLY=1")
    p = _custom_roles_path(org_id)
    data: dict = {}
    if p.exists():
        try:
            data = json.loads(p.read_text(encoding="utf-8")) or {}
        except Exception:
            data = {}
    users = set(map(str.lower, data.get(role) or []))
    users.add((user_email or "").strip().lower())
    data[role] = sorted(users)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def sign_step(
    approval_id: str,
    user_email: str,
    role: str,
    *,
    note: str | None = None,
    org_id: str | None = None,
) -> ApprovalChain:
    """Record a signature.

    Verifies the signer holds ``role`` (via RBAC or custom-role file).
    When the *final* step is signed, applies the underlying risk
    acceptance and returns the now-approved chain.

    Raises:
        PermissionError when ``SC_READONLY=1``.
        ValueError for missing approval / wrong role / already-decided
            approval.
    """
    if _is_readonly():
        raise PermissionError("read_only: cannot sign when SC_READONLY=1")
    if not approval_id or not user_email or not role:
        raise ValueError("approval_id, user_email, role are required")

    # We need org_id to read the JSONL — accept it as kwarg or look it
    # up across known orgs.
    if not org_id:
        org_id = _find_org_for(approval_id)
        if not org_id:
            raise ValueError(f"no approval with id {approval_id!r}")

    approval = get_approval(org_id, approval_id)
    if not approval:
        raise ValueError(f"no approval with id {approval_id!r}")
    if approval.status != "pending":
        raise ValueError(f"approval already {approval.status}")

    # Locate the next unsigned step + verify expected role
    idx = next((i for i, s in enumerate(approval.steps) if not s.signed_by), None)
    if idx is None:
        raise ValueError("approval has no remaining steps")
    expected = approval.steps[idx].role
    role_norm = (role or "").strip().lower()
    if role_norm != expected:
        raise ValueError(
            f"step {idx} requires role {expected!r}, got {role!r}"
        )
    if not _user_has_role(org_id, user_email, role_norm):
        raise ValueError(
            f"{user_email} does not hold role {role_norm!r} in org {org_id!r}"
        )

    ts = _now_iso()
    is_last = (idx == len(approval.steps) - 1)
    acceptance_id: str | None = None
    if is_last:
        # Apply the acceptance now — chain is fully signed.
        try:
            from safecadence.reports.risk_acceptance import add_acceptance
            entry = add_acceptance({
                "finding_id": approval.finding_id,
                "host": approval.host,
                "accepted_by": user_email,
                "rationale": (approval.rationale
                              or f"Approved via chain {approval.name}"),
                "expires_at": approval.expires_at,
                "compensating_controls": [],
                "approval_id": approval.id,
            })
            acceptance_id = entry.get("id")
        except Exception as exc:  # pragma: no cover
            raise ValueError(f"failed to apply acceptance: {exc}") from exc

    _append_event(org_id, {
        "event": "sign",
        "id": approval_id,
        "ts": ts,
        "step_index": idx,
        "user_email": user_email,
        "role": role_norm,
        "note": note,
        "approved": is_last,
        "acceptance_id": acceptance_id,
    })

    # Hook: change_mgmt
    try:
        from safecadence.workflow.change_mgmt import record_change
        record_change(
            org_id,
            "approval_signed" if not is_last else "risk_accepted",
            before={"step_index": idx, "status": "pending"},
            after={
                "step_index": idx,
                "user_email": user_email,
                "approved": is_last,
                "acceptance_id": acceptance_id,
            },
            actor=user_email,
        )
    except Exception:  # pragma: no cover
        pass

    refreshed = get_approval(org_id, approval_id)
    return refreshed or approval


def cancel_approval(approval_id: str, reason: str, *, org_id: str | None = None,
                    actor: str | None = None) -> ApprovalChain:
    """Mark an approval as cancelled. No acceptance is applied."""
    if _is_readonly():
        raise PermissionError("read_only: cannot cancel when SC_READONLY=1")
    if not org_id:
        org_id = _find_org_for(approval_id)
    if not org_id:
        raise ValueError(f"no approval with id {approval_id!r}")
    approval = get_approval(org_id, approval_id)
    if not approval:
        raise ValueError(f"no approval with id {approval_id!r}")
    if approval.status != "pending":
        raise ValueError(f"approval already {approval.status}")
    ts = _now_iso()
    _append_event(org_id, {
        "event": "cancel",
        "id": approval_id,
        "ts": ts,
        "reason": reason or "",
        "actor": actor,
    })
    try:
        from safecadence.workflow.change_mgmt import record_change
        record_change(org_id, "approval_cancelled",
                      before={"status": "pending"},
                      after={"reason": reason},
                      actor=actor)
    except Exception:  # pragma: no cover
        pass
    refreshed = get_approval(org_id, approval_id)
    return refreshed or approval


def _find_org_for(approval_id: str) -> str | None:
    """Locate which org owns ``approval_id`` by scanning every org's JSONL."""
    try:
        from safecadence.storage.org_store import list_orgs
        for org in list_orgs():
            if get_approval(org.id, approval_id):
                return org.id
    except Exception:
        return None
    return None


__all__ = [
    "ApprovalStep",
    "ApprovalChain",
    "define_chain",
    "get_chain",
    "list_chains",
    "start_approval",
    "sign_step",
    "cancel_approval",
    "get_approval",
    "list_approvals",
    "assign_custom_role",
]
