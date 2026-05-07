"""
v9.33 #2 — Proof-of-review confirm tokens.

Trust property: an external identity system cannot be mutated unless
the operator first ran a dry-run against the same IR + scope and
their actor identity. The dry-run mints a short-lived HMAC token; the
apply path requires the exact token. Stale, substituted, or
counterfeit tokens are rejected with a typed error.

This closes the audit hole identified in
``docs/v9.33-write-back-audit.md`` finding #4: "anyone with a writer
token can POST `apply: true` and commit without ever looking at a
dry-run".

Design properties:

* **Bound to the IR.** A token minted for one IR cannot apply a
  different IR — even one byte of difference flips the SHA-256.
* **Bound to the scope.** Single-target tokens carry the target
  name (``"okta"``); multi-target tokens carry the comma-sorted
  list (``"ad,entra,okta"``). A token minted for one scope cannot
  apply against a different one.
* **Bound to the actor.** Operator A's dry-run cannot be applied
  by operator B. Audit trail integrity.
* **Time-bound.** Default 10-minute TTL. Reduces the window in
  which a leaked token is useful.
* **Adapter-version-bound.** ``ADAPTER_VERSION`` must match. If
  the write-back contract changes (e.g. between v9.33 and v9.34
  someone rewires what an Okta op actually emits) the old tokens
  become invalid; operators have to re-review.
* **Air-gap friendly.** No external KMS — uses the existing
  ``SC_JWT_SECRET`` which the bootstrap already manages.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from typing import Optional

from safecadence.identity.ir import UnifiedPolicyIR

DEFAULT_TTL_SECONDS = 600
ADAPTER_VERSION = "v9.33"


class ConfirmTokenError(Exception):
    """Raised when a confirm_token is missing, malformed, expired,
    or doesn't match the IR/scope/actor it's being used against.

    Callers should map this to HTTP 409 (conflict) so the operator
    sees it as "your dry-run is stale, re-review and try again".
    """


@dataclass
class _Payload:
    ir_hash: str
    scope: str
    actor: str
    issued_at: int
    ttl: int

    def as_dict(self) -> dict:
        return {
            "ir_hash": self.ir_hash,
            "scope": self.scope,
            "actor": self.actor,
            "issued_at": self.issued_at,
            "ttl": self.ttl,
            "av": ADAPTER_VERSION,
        }


def _ir_hash(ir: UnifiedPolicyIR) -> str:
    """Stable hash of the IR — any IR mutation flips the hash."""
    try:
        from dataclasses import asdict
        d = asdict(ir)
    except Exception:
        d = ir.__dict__
    blob = json.dumps(d, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _secret() -> bytes:
    s = os.environ.get("SC_JWT_SECRET", "")
    if not s:
        # Air-gapped first-run fallback. The auth bootstrap warns
        # separately when SC_JWT_SECRET is unset; we just need
        # SOME deterministic key to sign with.
        s = "safecadence-fallback-confirm-token-secret-do-not-use-in-prod"
    return s.encode("utf-8")


def _sign(payload: dict) -> str:
    blob = json.dumps(payload, sort_keys=True).encode("utf-8")
    sig = hmac.new(_secret(), blob, hashlib.sha256).hexdigest()
    return blob.hex() + "." + sig


def _unsign(token: str) -> dict:
    if not token or "." not in token:
        raise ConfirmTokenError("malformed confirm_token")
    blob_hex, sig = token.split(".", 1)
    try:
        blob = bytes.fromhex(blob_hex)
    except ValueError as e:                              # pragma: no cover
        raise ConfirmTokenError(f"malformed confirm_token: {e}")
    expected_sig = hmac.new(_secret(), blob, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected_sig):
        raise ConfirmTokenError(
            "confirm_token signature mismatch — token forged or "
            "minted with a different SC_JWT_SECRET")
    try:
        return json.loads(blob.decode("utf-8"))
    except Exception as e:                               # pragma: no cover
        raise ConfirmTokenError(f"malformed confirm_token payload: {e}")


def normalize_scope(scope) -> str:
    """Helper: canonicalize multi-target scope so callers don't have
    to remember to sort/lowercase. Single string passes through;
    iterable becomes lowercase comma-sorted CSV."""
    if isinstance(scope, str):
        return scope.lower()
    items = sorted(str(s).lower() for s in scope)
    return ",".join(items)


def mint(*, ir: UnifiedPolicyIR, scope, actor: str,
         ttl_seconds: int = DEFAULT_TTL_SECONDS) -> str:
    """Mint a confirm_token bound to (IR, scope, actor)."""
    p = _Payload(
        ir_hash=_ir_hash(ir),
        scope=normalize_scope(scope),
        actor=actor,
        issued_at=int(time.time()),
        ttl=int(ttl_seconds),
    )
    return _sign(p.as_dict())


def verify(token: str, *, ir: UnifiedPolicyIR, scope, actor: str,
           now: Optional[float] = None) -> dict:
    """Verify that ``token`` was minted for the same IR, scope, and
    actor and is still within TTL. Raises ConfirmTokenError otherwise.

    Returns the decoded payload on success (useful for audit logging
    so we can record both the dry-run hash and the apply hash).
    """
    if not token:
        raise ConfirmTokenError(
            "apply requires a confirm_token from a prior dry-run; "
            "none was supplied. Run dry-run first, review the diff, "
            "then re-submit with the returned confirm_token.")
    payload = _unsign(token)
    expect_hash = _ir_hash(ir)
    if payload.get("ir_hash") != expect_hash:
        raise ConfirmTokenError(
            "IR hash mismatch — confirm_token was minted for a "
            "different IR than the one being applied. Re-run the "
            "dry-run against the exact IR you intend to commit.")
    expect_scope = normalize_scope(scope)
    if payload.get("scope") != expect_scope:
        raise ConfirmTokenError(
            f"scope mismatch — confirm_token minted for scope="
            f"'{payload.get('scope')}' but apply targets scope="
            f"'{expect_scope}'.")
    if payload.get("actor") != actor:
        raise ConfirmTokenError(
            f"actor mismatch — confirm_token was minted for "
            f"actor='{payload.get('actor')}', not '{actor}'. "
            "Each operator must mint and apply with their own "
            "dry-run.")
    issued_at = int(payload.get("issued_at", 0))
    ttl = int(payload.get("ttl", 0))
    t = now if now is not None else time.time()
    if issued_at + ttl < int(t):
        raise ConfirmTokenError(
            f"confirm_token expired — minted {int(t) - issued_at}s "
            f"ago, ttl={ttl}s. Re-run the dry-run.")
    if payload.get("av") != ADAPTER_VERSION:
        raise ConfirmTokenError(
            "adapter-version drift — the write-back contract has "
            "changed since this confirm_token was minted; re-run "
            "the dry-run to mint a fresh one.")
    return payload
