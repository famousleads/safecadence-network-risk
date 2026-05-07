"""
v7.6 — Just-in-Time access workflow.

Time-bounded grants. The CLI calls `grant()` with a duration, the
function persists a JITGrant to ~/.safecadence/jit.json, compiles a
temporary IR with severity=advisory and applies it to the chosen
target. When the grant expires (caller is responsible for invoking
`expire_due()` on a schedule — typically the existing `safecadence
daemon`), the matching revoke IR is generated and applied.

Storage is JSON file by design — small footprint, atomic writes,
inspectable in a text editor. v7.7 will move to the platform store
once we have a migration story.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterable

from safecadence.identity.ir import UnifiedPolicyIR, validate_ir


@dataclass
class JITGrant:
    grant_id: str
    principal: str
    action: str
    resource: str
    expires_at: float                 # Unix timestamp
    created_at: float
    created_by: str
    target: str = "okta"              # which IdP enforces this
    reason: str = ""
    status: str = "active"            # active | expired | revoked
    revoke_ir: dict = field(default_factory=dict)


# ---------------------------------------------------------------- store


def _store_path() -> Path:
    return Path(os.environ.get("SC_JIT_STORE",
                                str(Path.home() / ".safecadence" / "jit.json")))


def _read_store() -> list[JITGrant]:
    p = _store_path()
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    return [JITGrant(**g) for g in (data.get("grants") or [])
             if isinstance(g, dict)]


def _write_store(grants: list[JITGrant]) -> None:
    p = _store_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = {"version": 1, "grants": [asdict(g) for g in grants]}
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True),
                    encoding="utf-8")
    os.replace(tmp, p)


# ---------------------------------------------------------------- public api


def grant(*, principal: str, action: str, resource: str,
          duration_seconds: int, target: str = "okta",
          created_by: str = "cli", reason: str = "",
          now: float | None = None) -> JITGrant:
    """Persist a new JIT grant and return it.

    Caller is responsible for actually applying the grant via the
    target adapter's `apply_policy()`. We separate the concerns so
    apply can be approval-gated through Tier-3 without coupling.
    """
    if duration_seconds <= 0:
        raise ValueError("duration_seconds must be positive")
    if duration_seconds > 86400 * 14:
        raise ValueError("duration_seconds > 14 days — escalate to human review")
    t = now if now is not None else time.time()
    g = JITGrant(
        grant_id="jit_" + uuid.uuid4().hex[:12],
        principal=principal, action=action, resource=resource,
        expires_at=t + duration_seconds,
        created_at=t,
        created_by=created_by,
        target=target,
        reason=reason,
    )
    # Compute the revoke IR up front so expire is purely mechanical
    g.revoke_ir = _build_revoke_ir(g)
    grants = _read_store()
    grants.append(g)
    _write_store(grants)
    # v9.45 — fan out via dispatch_event so JIT grants flow through the
    # same channels (email DM if opted in, channel webhooks for the
    # team, multi-provider). Best-effort — never break the grant flow.
    try:
        from safecadence.notifier.registry import dispatch_event
        dispatch_event(
            kind="jit_granted",
            title=f"JIT granted: {principal} → {action} → {resource}",
            summary=(f"Time-bounded grant {g.grant_id} expires at "
                     f"{int(g.expires_at)} on target {target}. "
                     f"Reason: {reason or '—'}"),
            severity="info",
            extra={"grant_id": g.grant_id,
                    "principal": principal,
                    "action": action,
                    "resource": resource,
                    "target": target,
                    "expires_at": g.expires_at,
                    "duration_seconds": duration_seconds},
            link="/jit",
            requested_by=created_by,
        )
    except Exception:               # pragma: no cover
        pass
    return g


def list_grants(*, only_active: bool = False) -> list[JITGrant]:
    grants = _read_store()
    if only_active:
        return [g for g in grants if g.status == "active"]
    return grants


def expire_due(*, now: float | None = None) -> list[JITGrant]:
    """Mark active grants whose expires_at has passed as expired.

    Returns the list of newly-expired grants — the caller can then
    feed each `revoke_ir` into the matching adapter's apply_policy()
    to actually pull the access.
    """
    t = now if now is not None else time.time()
    grants = _read_store()
    expired: list[JITGrant] = []
    for g in grants:
        if g.status == "active" and g.expires_at <= t:
            g.status = "expired"
            expired.append(g)
    if expired:
        _write_store(grants)
        # v9.45 — emit one notification per expired grant so the team
        # learns auto-revoke happened through their configured channels.
        try:
            from safecadence.notifier.registry import dispatch_event
            for g in expired:
                dispatch_event(
                    kind="jit_granted",
                    title=f"JIT expired: {g.principal} → {g.action} → {g.resource}",
                    summary=(f"Grant {g.grant_id} on {g.target} hit its "
                             f"expiry. Auto-revoke IR queued for apply."),
                    severity="info",
                    extra={"grant_id": g.grant_id,
                            "principal": g.principal,
                            "action": g.action,
                            "resource": g.resource,
                            "target": g.target,
                            "lifecycle": "expired"},
                    link="/jit",
                    requested_by="daemon",
                )
        except Exception:           # pragma: no cover
            pass
    return expired


def revoke(grant_id: str) -> JITGrant | None:
    grants = _read_store()
    target: JITGrant | None = None
    for g in grants:
        if g.grant_id == grant_id:
            g.status = "revoked"
            target = g
            break
    if target:
        _write_store(grants)
        # v9.45 — manual revoke fan-out so the team sees this in the
        # same channels they get grants in.
        try:
            from safecadence.notifier.registry import dispatch_event
            dispatch_event(
                kind="jit_granted",
                title=f"JIT revoked: {target.principal} → {target.action} → {target.resource}",
                summary=(f"Grant {target.grant_id} on {target.target} was "
                         f"manually revoked. Revoke IR queued for apply."),
                severity="info",
                extra={"grant_id": target.grant_id,
                        "principal": target.principal,
                        "action": target.action,
                        "resource": target.resource,
                        "target": target.target,
                        "lifecycle": "revoked"},
                link="/jit",
                requested_by="cli",
            )
        except Exception:           # pragma: no cover
            pass
    return target


def grant_to_ir(g: JITGrant) -> UnifiedPolicyIR:
    """Turn an active grant into a temporary IR (effect=allow)."""
    return validate_ir({
        "intent": (f"JIT: {g.principal} → {g.action} → {g.resource} "
                    f"(expires {int(g.expires_at)})"),
        "effect": "allow",
        "actions": [g.action],
        "subjects": {"principals": [g.principal]},
        "resources": {"asset_ids": [g.resource]},
        "severity": "advisory",      # JIT is tracked, not strictly enforced
        "targets": [g.target],
        "author": g.created_by,
    })


# ---------------------------------------------------------------- helpers


def _build_revoke_ir(g: JITGrant) -> dict:
    """The revoke counterpart — same selectors, opposite effect."""
    return {
        "intent": f"JIT-revoke: {g.principal} → {g.action} → {g.resource}",
        "effect": "deny",
        "actions": [g.action],
        "subjects": {"principals": [g.principal]},
        "resources": {"asset_ids": [g.resource]},
        "severity": "enforce",
        "targets": [g.target],
        "author": g.created_by,
    }
