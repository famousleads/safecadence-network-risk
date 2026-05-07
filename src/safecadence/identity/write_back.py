"""
v7.6 — Identity write-back framework.

Generalizes the v7.5 OktaAdapter pattern. Every identity-system adapter
that wants to support `apply_policy(ir)` mixes in `IdentityWriteBackMixin`
and implements two hooks:

    _build_operation(ir, plan)   ->  Operation | None
    _commit(operation, *, http_post, http_put, http_patch)  ->  dict

The mixin handles everything else: dry-run gating, ApplyResult shape,
test seam injection, exception wrapping, audit-friendly payloads.

By having every adapter share the same return shape and same dry-run
gate, the CLI, REST API, audit log, and React UI render the same widget
regardless of which IdP the operation targets.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from safecadence.identity.compiler import compile_plan
from safecadence.identity.confirm_token import (
    ConfirmTokenError, mint as _mint_confirm, verify as _verify_confirm,
)
from safecadence.identity.ir import UnifiedPolicyIR


@dataclass
class ApplyResult:
    """Consistent shape across all 5 identity adapters."""
    target: str
    dry_run: bool
    operations: list[dict] = field(default_factory=list)
    diff: str = ""
    committed_ids: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    error: Optional[str] = None
    # v9.33 #2 — minted on dry-run, required to commit
    confirm_token: Optional[str] = None
    # v9.33 #2 — populated on commit so the audit log can record
    # both the dry-run hash and the apply hash.
    confirm_token_payload: Optional[dict] = None

    def to_dict(self) -> dict:
        out: dict = {
            "target": self.target,
            "dry_run": self.dry_run,
            "operations": self.operations,
            "diff": self.diff,
            "committed_ids": self.committed_ids,
            "warnings": self.warnings,
            "error": self.error,
        }
        if self.confirm_token is not None:
            out["confirm_token"] = self.confirm_token
        if self.confirm_token_payload is not None:
            out["confirm_token_payload"] = self.confirm_token_payload
        return out


class IdentityWriteBackMixin:
    """Mixin that turns a read-only adapter into a write-back-capable one.

    Subclasses:
      * MUST set `target_name` to the canonical identity-system name
        (matches `compiler.compile_plan` operation targets and
        `UnifiedPolicyIR.targets`).
      * MUST implement `_commit(operation, **seams)` returning a dict
        with optional 'committed_ids' (list[str]) and 'warnings'
        (list[str]).
      * MAY override `_post_compile_warnings(plan)` to add per-target
        warnings (e.g. "ISE 3.0 doesn't support condition X").

    The mixin's apply_policy() is the only public method.
    """

    # Subclasses override
    target_name: str = ""

    def apply_policy(self, ir: UnifiedPolicyIR, *, dry_run: bool = True,
                     actor: str = "system",
                     confirm_token: Optional[str] = None,
                     http_post: Optional[Callable] = None,
                     http_put: Optional[Callable] = None,
                     http_patch: Optional[Callable] = None,
                     ldap_modify: Optional[Callable] = None) -> dict:
        """Apply (or preview the apply of) a UnifiedPolicyIR.

        Parameters
        ----------
        ir       UnifiedPolicyIR (already validated upstream)
        dry_run  Default True. Caller must explicitly opt into commits.
        actor    Operator identity. Bound into the confirm_token so a
                 dry-run minted by user A cannot be applied by user B.
                 Defaults to ``"system"`` for back-end / daemon callers.
        confirm_token
                 v9.33 #2: required when ``dry_run=False``. Must have
                 been minted by an earlier dry-run with the same IR,
                 same target, and same actor. Stale, mismatched, or
                 missing tokens return an ApplyResult with ``error``
                 populated and no commit attempted.
        http_post / http_put / http_patch / ldap_modify
                 Test seams. Each adapter uses whichever it needs.

        Returns
        -------
        dict (see ApplyResult.to_dict). Stable shape across every
        adapter. On dry-run, includes a ``confirm_token`` you must
        present back to commit.
        """
        plan = compile_plan(ir)
        target = self.target_name
        op = next((o for o in plan.operations if o.target == target), None)

        result = ApplyResult(target=target, dry_run=dry_run,
                              diff=plan.diff(),
                              warnings=list(plan.warnings))

        if op is None:
            result.error = f"no operation for target={target}"
            return result.to_dict()

        if op.deferred:
            result.warnings.append(
                f"compiler marked {target} op as deferred — "
                "this should not happen in v7.6+. "
                "Returning preview only.")
            result.operations = [{
                "op_kind": op.op_kind, "summary": op.summary,
                "payload": op.payload, "risk": op.risk,
            }]
            return result.to_dict()

        result.operations = [{
            "op_kind": op.op_kind, "summary": op.summary,
            "payload": op.payload, "risk": op.risk,
        }]

        # Per-target compile-time warnings
        for w in self._post_compile_warnings(plan, op):
            result.warnings.append(w)

        if dry_run:
            # v9.33 #2 — mint a confirm_token bound to this IR + target +
            # actor. The operator must present this token back to commit.
            try:
                result.confirm_token = _mint_confirm(
                    ir=ir, scope=target, actor=actor,
                )
            except Exception as exc:                          # pragma: no cover
                # Minting should never fail in normal operation. If it
                # does, surface the error rather than emit a result that
                # silently can't be committed.
                result.error = f"confirm_token mint failed: {exc}"
            return result.to_dict()

        # ---- real commit path -----------------------------------------
        # v9.33 #2 — verify the operator first ran a dry-run against
        # this exact IR + target + actor, and that the dry-run is
        # still fresh.
        try:
            result.confirm_token_payload = _verify_confirm(
                confirm_token or "", ir=ir, scope=target, actor=actor,
            )
        except ConfirmTokenError as exc:
            result.error = f"confirm_token rejected: {exc}"
            return result.to_dict()
        try:
            commit = self._commit(
                op,
                http_post=http_post or self._real_post,
                http_put=http_put or self._real_put,
                http_patch=http_patch or self._real_patch,
                ldap_modify=ldap_modify or self._real_ldap_modify,
            )
        except NotImplementedError as exc:
            result.error = f"{target}: {exc}"
            return result.to_dict()
        except Exception as exc:
            result.error = f"{target} commit failed: {exc}"
            return result.to_dict()

        if isinstance(commit, dict):
            for cid in commit.get("committed_ids", []) or []:
                result.committed_ids.append(str(cid))
            for w in commit.get("warnings", []) or []:
                result.warnings.append(w)
            if commit.get("error"):
                result.error = str(commit["error"])

        return result.to_dict()

    # ---- subclass hooks (override) ------------------------------------

    def _commit(self, operation, *, http_post, http_put,
                http_patch, ldap_modify) -> dict:
        raise NotImplementedError(
            f"{self.__class__.__name__} did not implement _commit()")

    def _post_compile_warnings(self, plan, operation) -> list[str]:
        return []

    # ---- default seams (overridable per-adapter) ----------------------
    # The base implementations raise NotImplementedError so accidental
    # use of the wrong seam in a real adapter fails loudly. Adapters
    # that need a particular verb override the matching `_real_*`.

    def _real_post(self, url, headers, body):                # pragma: no cover
        raise NotImplementedError(
            f"{self.__class__.__name__} doesn't support http_post")

    def _real_put(self, url, headers, body):                 # pragma: no cover
        raise NotImplementedError(
            f"{self.__class__.__name__} doesn't support http_put")

    def _real_patch(self, url, headers, body):               # pragma: no cover
        raise NotImplementedError(
            f"{self.__class__.__name__} doesn't support http_patch")

    def _real_delete(self, url, headers):                    # pragma: no cover
        raise NotImplementedError(
            f"{self.__class__.__name__} doesn't support http_delete")

    def _real_ldap_modify(self, dn, changes):                # pragma: no cover
        raise NotImplementedError(
            f"{self.__class__.__name__} doesn't support ldap_modify")
