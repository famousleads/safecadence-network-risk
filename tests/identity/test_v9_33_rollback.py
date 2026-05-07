"""
v9.33 #3 — Rollback coverage for all 5 identity adapters.

Each test:
  1. Calls `_rollback(committed_ids, http_delete=stub)` (or
     `ldap_modify=stub` for AD).
  2. Asserts the stub was called with the right URL/DN/changes.
  3. Asserts the returned receipt has the expected shape.

Trust property: when a multi-target apply fails partway through,
every adapter that already committed must have a real path to undo
its work. Before v9.33, none of the 5 adapters implemented `_rollback`
and the transactional layer logged "no _rollback hook" silently.
"""

from __future__ import annotations


def test_okta_rollback_deletes_each_committed_rule_id():
    from safecadence.platform.adapters.identity_adapters import OktaAdapter
    a = OktaAdapter(target="acme.okta.com",
                     credentials={"api_token": "x"})
    deletes: list[str] = []

    def stub_delete(url, headers):
        deletes.append(url)
        return {"status_code": 204}

    out = a._rollback(["rul_A", "rul_B"], http_delete=stub_delete)
    assert out["ok"] is True
    assert out["target"] == "okta"
    assert out["rolled_back_ids"] == ["rul_A", "rul_B"]
    assert len(deletes) == 2
    assert all("/groups/rules/" in u for u in deletes)
    assert deletes[0].endswith("/groups/rules/rul_A")


def test_okta_rollback_records_errors_and_keeps_going():
    from safecadence.platform.adapters.identity_adapters import OktaAdapter
    a = OktaAdapter(target="acme.okta.com",
                     credentials={"api_token": "x"})
    seen: list[str] = []

    def stub_delete(url, headers):
        seen.append(url)
        if "rul_BAD" in url:
            raise RuntimeError("simulated 500")

    out = a._rollback(["rul_A", "rul_BAD", "rul_C"], http_delete=stub_delete)
    assert out["ok"] is False
    assert out["rolled_back_ids"] == ["rul_A", "rul_C"]
    assert len(out["errors"]) == 1 and "rul_BAD" in out["errors"][0]


def test_ise_rollback_deletes_each_authz_rule():
    from safecadence.platform.adapters.identity_adapters import CiscoISEAdapter
    a = CiscoISEAdapter(target="ise.example",
                         credentials={"username": "x", "password": "y"})
    deletes: list[str] = []

    def stub_delete(url, headers):
        deletes.append(url)

    out = a._rollback(["ise-1", "ise-2"], http_delete=stub_delete)
    assert out["ok"] is True
    assert out["target"] == "ise"
    assert all("/config/authorization/" in u for u in deletes)


def test_clearpass_rollback_drops_policy_before_profile():
    """Order matters — the policy references the profile, so we must
    delete the policy first, then the profile."""
    from safecadence.platform.adapters.identity_adapters import HPEClearPassAdapter
    a = HPEClearPassAdapter(target="cp.example",
                             credentials={"client_id": "x",
                                            "client_secret": "y"})
    deletes: list[str] = []

    def stub_delete(url, headers):
        deletes.append(url)

    out = a._rollback(["profile:p1", "policy:l1"], http_delete=stub_delete)
    assert out["ok"] is True
    # We seeded [profile, policy] (the order _commit emits).
    # _rollback must reverse that, so policy first then profile.
    assert "/enforcement-policy/l1" in deletes[0]
    assert "/enforcement-profile/p1" in deletes[1]


def test_clearpass_rollback_records_unknown_id_format_as_error():
    from safecadence.platform.adapters.identity_adapters import HPEClearPassAdapter
    a = HPEClearPassAdapter(target="cp.example",
                             credentials={"client_id": "x",
                                            "client_secret": "y"})
    out = a._rollback(["malformed"], http_delete=lambda *a: None)
    assert out["ok"] is False
    assert "unrecognized id format" in out["errors"][0]


def test_ad_rollback_emits_modify_delete_for_each_membership():
    from safecadence.platform.adapters.identity_adapters import (
        ActiveDirectoryAdapter,
    )
    a = ActiveDirectoryAdapter(
        target="ldap://ad.example",
        credentials={"bind_dn": "x", "bind_password": "y",
                      "base_dn": "DC=corp,DC=local"},
    )
    modifies: list = []

    def stub_modify(dn, changes):
        modifies.append((dn, changes))

    committed = ["quarantine:CN=alice,OU=Contractors->CN=Quarantine,OU=Groups"]
    out = a._rollback(committed, ldap_modify=stub_modify)
    assert out["ok"] is True
    assert out["target"] == "ad"
    assert len(modifies) == 1
    target_dn, changes = modifies[0]
    assert target_dn == "CN=Quarantine,OU=Groups"
    # Must be a delete operation, not an add — the trust property is
    # "we undo the membership change we made in _commit".
    assert "MODIFY_DELETE" in str(changes)
    assert "CN=alice,OU=Contractors" in str(changes)


def test_entra_rollback_deletes_each_ca_policy_id():
    from safecadence.platform.adapters.identity_adapters import EntraIDAdapter
    a = EntraIDAdapter(target="tenant.onmicrosoft.com",
                        credentials={"tenant_id": "t",
                                      "client_id": "c",
                                      "client_secret": "s"})
    # Pre-seed the token so _rollback doesn't try to hit the network.
    a._token = "fake-token"
    deletes: list[str] = []

    def stub_delete(url, headers):
        deletes.append(url)
        # Token must be on every request
        assert headers.get("Authorization") == "Bearer fake-token"

    out = a._rollback(["pol-1", "pol-2"], http_delete=stub_delete)
    assert out["ok"] is True
    assert out["target"] == "entra"
    assert all(
        "graph.microsoft.com" in u and
        "/conditionalAccess/policies/" in u for u in deletes
    )


def test_entra_rollback_returns_not_ok_when_no_token():
    from safecadence.platform.adapters.identity_adapters import EntraIDAdapter
    a = EntraIDAdapter(target="tenant.onmicrosoft.com",
                        credentials={"tenant_id": "",
                                      "client_id": "",
                                      "client_secret": ""})
    out = a._rollback(["pol-1"])
    assert out["ok"] is False
    assert "no Graph token" in (out.get("errors") or [""])[0]


# --------------------------------------------------- transactional integration


def test_transactional_apply_all_invokes_real_rollback_on_failure():
    """End-to-end: a multi-target apply where the second target fails
    must call the real adapter's _rollback() (not just log "no hook")."""
    from safecadence.identity.transactional import apply_all
    from safecadence.identity.ir import validate_ir
    from safecadence.platform.adapters.identity_adapters import OktaAdapter

    # We use a real Okta adapter for target 1 (so its _rollback runs)
    # and a fake-failing adapter for target 2.
    okta = OktaAdapter(target="acme.okta.com",
                        credentials={"api_token": "x"})
    okta_deletes: list[str] = []

    # Stub Okta's _real_post / _real_put / _real_delete via the
    # apply_policy seams.  We'll thread http_post/put through commit
    # and capture http_delete via the rollback path.
    def fake_post(url, headers, body):
        return {"id": "rul_OK", "status": "INACTIVE"}

    def fake_put(url, headers, body):
        return {"status": "ACTIVE"}

    # Monkey-patch the adapter's _real_delete since transactional
    # doesn't currently thread http_delete to _rollback. Adapters
    # call self._real_delete() when no seam is passed.
    okta._real_delete = lambda url, headers: okta_deletes.append(url)

    class _FailAdapter:
        target_name = "ise"
        def apply_policy(self, ir, *, dry_run=True, actor="t",
                           confirm_token=None, **_):
            if dry_run:
                return {"target": "ise", "dry_run": True,
                         "operations": [], "diff": "",
                         "committed_ids": [], "warnings": [],
                         "error": None}
            return {"target": "ise", "dry_run": False,
                     "operations": [], "diff": "",
                     "committed_ids": [], "warnings": [],
                     "error": "ISE blew up"}

    ir = validate_ir({
        "intent": "no contractors", "effect": "deny",
        "actions": ["ssh"],
        "subjects": {"groups": ["Contractors"]},
        "targets": ["okta", "ise"],
    })

    # Wrap Okta's apply_policy so we can inject the test seams.
    real_apply = okta.apply_policy
    def patched_apply(ir, *, dry_run=True, actor="t",
                        confirm_token=None, **kw):
        return real_apply(ir, dry_run=dry_run, actor=actor,
                            confirm_token=confirm_token,
                            http_post=fake_post, http_put=fake_put,
                            **kw)
    okta.apply_policy = patched_apply

    fail = _FailAdapter()
    adapters = {"okta": okta, "ise": fail}

    # Mint the multi-target token via dry-run.
    dry = apply_all(ir, adapters, dry_run=True, actor="alice")
    out = apply_all(ir, adapters, dry_run=False, actor="alice",
                     confirm_token=dry["confirm_token"],
                     on_failure="rollback")

    assert out["status"] == "rolled_back"
    # The real Okta _rollback fired and tried to DELETE the committed
    # rule. Before v9.33 this asserted "adapter has no _rollback hook".
    assert okta_deletes, (
        "Okta's real _rollback() must have been called — verifies the "
        "v9.33 #3 trust property end-to-end"
    )
    assert "/groups/rules/rul_OK" in okta_deletes[0]
    rb = out["rollbacks"]["okta"]
    assert rb["ok"] is True
    assert rb["target"] == "okta"
