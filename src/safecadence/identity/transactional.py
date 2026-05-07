"""
v7.7 — Transactional multi-target apply.

Apply a UnifiedPolicyIR across N identity systems atomically. If any
target fails, roll back the changes already committed to the earlier
targets (if their adapter supports rollback).

The function is pure orchestration — adapters do the work via their
existing apply_policy() and a new _rollback() hook.
"""

from __future__ import annotations

from typing import Any, Optional

from safecadence.identity.confirm_token import (
    ConfirmTokenError, mint as _mint_confirm, verify as _verify_confirm,
)
from safecadence.identity.ir import UnifiedPolicyIR


def apply_all(ir: UnifiedPolicyIR, adapters: dict[str, Any], *,
              dry_run: bool = True,
              actor: str = "system",
              confirm_token: Optional[str] = None,
              on_failure: str = "rollback") -> dict:
    """Apply IR across many targets.

    Parameters
    ----------
    ir         The validated UnifiedPolicyIR.
    adapters   { 'okta': OktaAdapter(...), 'ise': CiscoISEAdapter(...), ... }
               Caller is responsible for instantiating adapters with
               the right credentials.
    dry_run    If True, every per-target call runs in dry-run. Useful
               for atomic preview ("would this work end-to-end?").
    on_failure
       'rollback'  (default) — on first failure, rollback prior commits
       'continue'  — keep going, return per-target status
       'abort'     — stop, leave prior commits in place (no rollback)

    Returns
    -------
    {
      'status': 'all_committed' | 'rolled_back' | 'partial',
      'dry_run': bool,
      'per_target': { 'okta': <ApplyResult>, ... },
      'rollbacks':  { 'okta': <rollback_result>, ... },  # only if rollback ran
    }
    """
    per_target: dict[str, dict] = {}
    rollbacks: dict[str, dict] = {}
    committed_order: list[str] = []     # order matters for rollback

    failure: tuple[str, str] | None = None    # (target, error)

    # v9.33 #2 — multi-target apply uses an aggregate confirm_token
    # bound to the IR + the sorted target set + the actor. The same
    # rules apply: dry-run mints, commit verifies.
    multi_scope = sorted(adapters.keys())
    aggregate_token: Optional[str] = None
    if not dry_run:
        try:
            _verify_confirm(confirm_token or "", ir=ir,
                              scope=multi_scope, actor=actor)
        except ConfirmTokenError as exc:
            return {
                "status": "rejected",
                "dry_run": False,
                "ir_intent": ir.intent,
                "per_target": {},
                "rollbacks": {},
                "failure": {"target": "*",
                              "error": f"confirm_token rejected: {exc}"},
                "confirm_token_required": True,
            }

    for target, adapter in adapters.items():
        # v9.33 #2 — pass the verified actor through to each adapter.
        # For multi-target commit, mint a per-target confirm_token from
        # the aggregate decision so the per-adapter gate still verifies.
        per_target_token: Optional[str] = None
        if not dry_run:
            per_target_token = _mint_confirm(
                ir=ir, scope=target, actor=actor,
            )
        try:
            r = adapter.apply_policy(
                ir, dry_run=dry_run, actor=actor,
                confirm_token=per_target_token,
            )
        except Exception as exc:                                 # pragma: no cover
            r = {"target": target, "dry_run": dry_run,
                  "operations": [], "diff": "", "committed_ids": [],
                  "warnings": [], "error": f"adapter raised: {exc}"}
        per_target[target] = r
        if r.get("error"):
            failure = (target, str(r["error"]))
            if on_failure == "rollback" and not dry_run:
                break
            if on_failure == "abort":
                break
            continue
        if not dry_run and r.get("committed_ids"):
            committed_order.append(target)

    if failure and on_failure == "rollback" and not dry_run:
        for tgt in reversed(committed_order):
            adapter = adapters[tgt]
            ids = per_target[tgt].get("committed_ids", []) or []
            try:
                rollback_fn = getattr(adapter, "_rollback", None)
                if rollback_fn is None:
                    rollbacks[tgt] = {
                        "ok": False,
                        "error": f"{tgt}: adapter has no _rollback() hook"}
                else:
                    # Adapters that take seam kwargs accept them via
                    # **kwargs; legacy fakes that don't will swallow
                    # them in their signature. We always call by name.
                    rollbacks[tgt] = rollback_fn(ids) or {"ok": True}
            except Exception as exc:                             # pragma: no cover
                rollbacks[tgt] = {"ok": False,
                                   "error": f"{tgt}: rollback raised: {exc}"}
        status = "rolled_back"
    elif failure:
        status = "partial"
    else:
        status = "all_committed" if not dry_run else "preview_ok"

    # v9.33 #2 — on dry-run aggregate, mint the multi-target token the
    # operator will need to commit.
    if dry_run:
        try:
            aggregate_token = _mint_confirm(
                ir=ir, scope=multi_scope, actor=actor,
            )
        except Exception:                                       # pragma: no cover
            aggregate_token = None

    out: dict = {
        "status": status,
        "dry_run": dry_run,
        "ir_intent": ir.intent,
        "per_target": per_target,
        "rollbacks": rollbacks,
        "failure": ({"target": failure[0], "error": failure[1]}
                     if failure else None),
    }
    if aggregate_token is not None:
        out["confirm_token"] = aggregate_token
    return out
