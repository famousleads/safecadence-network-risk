"""
v9.33 #2 — Confirm-token gate tests.

Trust property under test:

    "An external identity system cannot be mutated unless the operator
    first ran a dry-run against the same IR + scope and their actor."

Each test below pins one mutation a malicious or careless operator
might attempt. If any of these regress, the trust posture breaks.
"""

from __future__ import annotations

import time

import pytest

from safecadence.identity.confirm_token import (
    ConfirmTokenError, mint, normalize_scope, verify,
)
from safecadence.identity.ir import validate_ir


def _ir(intent="t1"):
    return validate_ir({
        "intent": intent, "effect": "deny", "actions": ["ssh"],
        "subjects": {"groups": ["Contractors"]}, "targets": ["okta"],
    })


# --------------------------------------------------------- mint + verify


def test_mint_then_verify_round_trip():
    ir = _ir()
    tok = mint(ir=ir, scope="okta", actor="alice")
    payload = verify(tok, ir=ir, scope="okta", actor="alice")
    assert payload["actor"] == "alice"
    assert payload["scope"] == "okta"


def test_verify_rejects_missing_token():
    ir = _ir()
    with pytest.raises(ConfirmTokenError, match="apply requires"):
        verify("", ir=ir, scope="okta", actor="alice")


def test_verify_rejects_ir_mismatch():
    """Token minted for IR-A must not commit IR-B. Defends against
    the operator dry-running one change and applying a different one."""
    tok = mint(ir=_ir("intent-a"), scope="okta", actor="alice")
    with pytest.raises(ConfirmTokenError, match="IR hash mismatch"):
        verify(tok, ir=_ir("intent-b"), scope="okta", actor="alice")


def test_verify_rejects_scope_mismatch():
    """Token minted against Okta must not apply against ISE."""
    ir = _ir()
    tok = mint(ir=ir, scope="okta", actor="alice")
    with pytest.raises(ConfirmTokenError, match="scope mismatch"):
        verify(tok, ir=ir, scope="ise", actor="alice")


def test_verify_rejects_actor_mismatch():
    """Alice's dry-run cannot be applied by Bob — preserves audit-trail
    integrity ('who saw the diff')."""
    ir = _ir()
    tok = mint(ir=ir, scope="okta", actor="alice")
    with pytest.raises(ConfirmTokenError, match="actor mismatch"):
        verify(tok, ir=ir, scope="okta", actor="bob")


def test_verify_rejects_expired_token():
    """A token older than its TTL must not commit — reduces window in
    which a leaked token is useful."""
    ir = _ir()
    tok = mint(ir=ir, scope="okta", actor="alice", ttl_seconds=1)
    # Look 10 seconds into the future, well past the 1s TTL.
    with pytest.raises(ConfirmTokenError, match="expired"):
        verify(tok, ir=ir, scope="okta", actor="alice",
                now=time.time() + 10)


def test_verify_rejects_forged_signature():
    """Hand-built or tampered tokens must fail HMAC verification."""
    with pytest.raises(ConfirmTokenError, match="malformed|signature"):
        verify("not-a-token", ir=_ir(), scope="okta", actor="alice")
    # Valid format, bogus signature
    valid = mint(ir=_ir(), scope="okta", actor="alice")
    blob_hex, _ = valid.split(".", 1)
    forged = blob_hex + ".deadbeef"
    with pytest.raises(ConfirmTokenError, match="signature"):
        verify(forged, ir=_ir(), scope="okta", actor="alice")


def test_normalize_scope_canonicalizes_target_lists():
    """Multi-target tokens should match regardless of insertion order
    or case — the scope normalizer fixes this."""
    assert normalize_scope("Okta") == "okta"
    assert normalize_scope(["Okta", "AD", "Entra"]) == "ad,entra,okta"
    # mint/verify with scrambled scope still verifies
    ir = _ir()
    tok = mint(ir=ir, scope=["Okta", "AD"], actor="a")
    verify(tok, ir=ir, scope=["AD", "okta"], actor="a")


# ----------------------------------------------- adapter integration


class _StubAdapter:
    """Minimal adapter for end-to-end mixin testing without touching
    the real Okta/ISE/AD connection layers."""
    target_name = "okta"
    capabilities = type("C", (), {"supports_write": True})

    def __init__(self):
        self.committed = False

    def _commit(self, op, **_seams):
        self.committed = True
        return {"committed_ids": ["stub-1"], "warnings": []}

    def _post_compile_warnings(self, plan, op):
        return []

    # default seams
    def _real_post(self, *a, **k): return {}
    def _real_put(self, *a, **k): return {}
    def _real_patch(self, *a, **k): return {}
    def _real_ldap_modify(self, *a, **k): return {}


def _make_adapter():
    from safecadence.identity.write_back import IdentityWriteBackMixin
    A = type("A", (_StubAdapter, IdentityWriteBackMixin), {})
    return A()


def test_apply_policy_mints_token_on_dry_run():
    a = _make_adapter()
    out = a.apply_policy(_ir(), dry_run=True, actor="alice")
    assert out["dry_run"] is True
    assert out["confirm_token"], "dry-run must mint a confirm_token"
    # No commit happened.
    assert a.committed is False


def test_apply_policy_commit_without_token_is_rejected():
    """The trust hole the audit identified — POST apply with no token
    used to commit. Now it must fail loudly."""
    a = _make_adapter()
    out = a.apply_policy(_ir(), dry_run=False, actor="alice",
                          confirm_token=None)
    assert out["error"], "commit without token must populate error"
    assert "confirm_token rejected" in out["error"]
    assert a.committed is False, "no commit may have happened"


def test_apply_policy_commit_with_token_succeeds():
    a = _make_adapter()
    ir = _ir()
    dry = a.apply_policy(ir, dry_run=True, actor="alice")
    out = a.apply_policy(ir, dry_run=False, actor="alice",
                          confirm_token=dry["confirm_token"])
    assert out["error"] is None
    assert out["committed_ids"] == ["stub-1"]
    assert out["confirm_token_payload"]["actor"] == "alice"
    assert a.committed is True


def test_apply_policy_commit_rejects_stale_token():
    """Token minted for a different IR must not commit this one."""
    a = _make_adapter()
    other = a.apply_policy(_ir("other"), dry_run=True, actor="alice")
    out = a.apply_policy(_ir("real"), dry_run=False, actor="alice",
                          confirm_token=other["confirm_token"])
    assert out["error"] and "IR hash mismatch" in out["error"]
    assert a.committed is False


def test_apply_policy_commit_rejects_other_operators_token():
    """Alice's dry-run cannot be committed by Bob. Audit integrity."""
    a = _make_adapter()
    ir = _ir()
    alice_tok = a.apply_policy(ir, dry_run=True,
                                  actor="alice")["confirm_token"]
    out = a.apply_policy(ir, dry_run=False, actor="bob",
                          confirm_token=alice_tok)
    assert out["error"] and "actor mismatch" in out["error"]
    assert a.committed is False


# ---------------------------------------------- transactional integration


class _FakeT:
    def __init__(self, name):
        self.name = name
        self.committed = []

    def apply_policy(self, ir, *, dry_run=True, actor="t",
                       confirm_token=None, **_):
        # Inside transactional, the per-target token is freshly minted
        # by apply_all when it propagates the verified aggregate
        # decision. We don't re-verify here (the fake just trusts the
        # caller) — that mirrors how a real adapter behaves under the
        # mixin: if we got here with a token, transactional already
        # verified the aggregate.
        ids = [] if dry_run else [f"{self.name}-1"]
        self.committed = ids
        return {"target": self.name, "dry_run": dry_run,
                 "operations": [], "diff": "", "committed_ids": ids,
                 "warnings": [], "error": None}

    def _rollback(self, ids):
        return {"ok": True}


def test_apply_all_dry_run_returns_aggregate_token():
    from safecadence.identity.transactional import apply_all
    adapters = {"okta": _FakeT("okta"), "ise": _FakeT("ise")}
    out = apply_all(_ir(), adapters, dry_run=True, actor="alice")
    assert out["status"] == "preview_ok"
    assert out["confirm_token"], (
        "transactional dry-run must mint an aggregate confirm_token "
        "covering the sorted target set"
    )


def test_apply_all_commit_without_token_is_rejected():
    """The multi-target version of the audit hole."""
    from safecadence.identity.transactional import apply_all
    adapters = {"okta": _FakeT("okta"), "ise": _FakeT("ise")}
    out = apply_all(_ir(), adapters, dry_run=False, actor="alice",
                     confirm_token=None)
    assert out["status"] == "rejected"
    # Nothing got committed.
    assert all(not a.committed for a in adapters.values())


def test_apply_all_commit_with_aggregate_token_succeeds():
    from safecadence.identity.transactional import apply_all
    adapters = {"okta": _FakeT("okta"), "ise": _FakeT("ise")}
    dry = apply_all(_ir(), {"okta": _FakeT("okta"),
                                "ise": _FakeT("ise")},
                       dry_run=True, actor="alice")
    out = apply_all(_ir(), adapters, dry_run=False, actor="alice",
                     confirm_token=dry["confirm_token"])
    assert out["status"] == "all_committed"


def test_apply_all_commit_rejects_token_from_different_target_set():
    """Token minted for {okta, ise} must not commit a {okta, ad} apply.
    Defends against the operator approving one fanout and surreptitiously
    swapping the target list before commit."""
    from safecadence.identity.transactional import apply_all
    a_dry = apply_all(_ir(),
                         {"okta": _FakeT("okta"), "ise": _FakeT("ise")},
                         dry_run=True, actor="alice")
    out = apply_all(_ir(),
                       {"okta": _FakeT("okta"), "ad": _FakeT("ad")},
                       dry_run=False, actor="alice",
                       confirm_token=a_dry["confirm_token"])
    assert out["status"] == "rejected"
    assert "scope mismatch" in (out.get("failure") or {}).get("error", "")
