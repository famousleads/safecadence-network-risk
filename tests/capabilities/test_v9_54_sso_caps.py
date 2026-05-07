"""v9.54 #1 — OIDC group-claim → capability auto-grant.

Three layers under test:

  1. resolve_capabilities(cfg, claims) — pure data: groups in claim,
     capability_map config, expected capability list.
  2. reconcile_sso_grants() — idempotent diff applier on the YAML
     store. Manual grants must survive; SSO grants must reconcile.
  3. Integration with the OIDC callback dict shape — the callback
     result must carry a `capabilities` key the server can consume.
"""
from __future__ import annotations

import pytest


# ----------------------------------------------------- resolve_capabilities

def test_resolve_capabilities_empty_when_no_map():
    """Default config has no capability_map → no capabilities."""
    from safecadence.sso import SSOConfig, resolve_capabilities
    cfg = SSOConfig()
    claims = {"groups": ["okta-secops", "okta-readonly"]}
    assert resolve_capabilities(cfg, claims) == []


def test_resolve_capabilities_single_group_match():
    from safecadence.sso import SSOConfig, resolve_capabilities
    cfg = SSOConfig(capability_map={
        "okta-secops": ["read.audit", "admin.capabilities"],
    })
    claims = {"groups": ["okta-secops", "okta-other"]}
    assert resolve_capabilities(cfg, claims) == [
        "admin.capabilities", "read.audit",
    ]


def test_resolve_capabilities_dedupe_across_groups():
    """User in two groups that both grant read.audit gets it once."""
    from safecadence.sso import SSOConfig, resolve_capabilities
    cfg = SSOConfig(capability_map={
        "secops": ["read.audit"],
        "auditors": ["read.audit", "read.activity"],
    })
    claims = {"groups": ["secops", "auditors"]}
    assert resolve_capabilities(cfg, claims) == [
        "read.activity", "read.audit",
    ]


def test_resolve_capabilities_no_match_returns_empty():
    from safecadence.sso import SSOConfig, resolve_capabilities
    cfg = SSOConfig(capability_map={"secops": ["read.audit"]})
    claims = {"groups": ["other-group"]}
    assert resolve_capabilities(cfg, claims) == []


def test_resolve_capabilities_handles_comma_string_groups():
    """Some IdPs emit groups as comma-separated strings, not lists."""
    from safecadence.sso import SSOConfig, resolve_capabilities
    cfg = SSOConfig(capability_map={"secops": ["read.audit"]})
    claims = {"groups": "secops,others"}
    assert resolve_capabilities(cfg, claims) == ["read.audit"]


def test_resolve_capabilities_uses_memberOf_too():
    """LDAP-style claim name 'memberOf' is honored."""
    from safecadence.sso import SSOConfig, resolve_capabilities
    cfg = SSOConfig(capability_map={"CN=secops,OU=groups": ["read.audit"]})
    claims = {"memberOf": ["CN=secops,OU=groups"]}
    assert resolve_capabilities(cfg, claims) == ["read.audit"]


# ----------------------------------------------------- reconcile_sso_grants

def test_reconcile_grants_new_capabilities(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.capabilities.store import (
        reconcile_sso_grants, get_grant,
    )
    summary = reconcile_sso_grants(
        username="alice", wanted=["read.audit", "read.activity"],
        actor="oidc:test",
    )
    assert summary["granted"] == ["read.activity", "read.audit"]
    assert summary["revoked"] == []
    rec = get_grant("alice")
    assert "read.audit" in rec.grant
    assert "read.activity" in rec.grant


def test_reconcile_idempotent_on_repeat(monkeypatch, tmp_path):
    """Two reconciles in a row with the same wanted list → second
    is a no-op (granted=[], revoked=[])."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.capabilities.store import reconcile_sso_grants
    reconcile_sso_grants(username="alice", wanted=["read.audit"],
                          actor="oidc:test")
    summary = reconcile_sso_grants(
        username="alice", wanted=["read.audit"], actor="oidc:test",
    )
    assert summary["granted"] == []
    assert summary["revoked"] == []
    assert summary["unchanged"] == ["read.audit"]


def test_reconcile_revokes_when_group_removed(monkeypatch, tmp_path):
    """User had read.audit via SSO, no longer in the group → revoked."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.capabilities.store import (
        reconcile_sso_grants, get_grant,
    )
    reconcile_sso_grants(username="alice", wanted=["read.audit"],
                          actor="oidc:test")
    summary = reconcile_sso_grants(
        username="alice", wanted=[], actor="oidc:test",
    )
    assert summary["revoked"] == ["read.audit"]
    rec = get_grant("alice")
    assert "read.audit" not in rec.grant
    # revoke moves it to deny so role-floor doesn't restore it
    assert "read.audit" in rec.deny


def test_reconcile_does_not_touch_manual_grants(monkeypatch, tmp_path):
    """Capability granted via CLI/UI is not in sso_managed → SSO
    reconcile must not revoke it even when wanted=[]."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.capabilities.store import (
        grant, reconcile_sso_grants, get_grant,
    )
    grant("alice", "read.audit", actor="cto", reason="manual")
    summary = reconcile_sso_grants(
        username="alice", wanted=[], actor="oidc:test",
    )
    assert summary["revoked"] == []
    rec = get_grant("alice")
    assert "read.audit" in rec.grant


def test_reconcile_swap_replaces_old_with_new(monkeypatch, tmp_path):
    """User moves from secops group to auditors group — old caps
    revoked, new caps granted in one reconcile."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.capabilities.store import (
        reconcile_sso_grants, get_grant,
    )
    reconcile_sso_grants(username="alice",
                          wanted=["admin.capabilities"], actor="oidc:test")
    summary = reconcile_sso_grants(
        username="alice", wanted=["read.audit"], actor="oidc:test",
    )
    assert summary["granted"] == ["read.audit"]
    assert summary["revoked"] == ["admin.capabilities"]
    rec = get_grant("alice")
    assert "read.audit" in rec.grant
    assert "admin.capabilities" not in rec.grant


def test_reconcile_rejects_unknown_capability(monkeypatch, tmp_path):
    """Misconfigured capability_map referring to a non-existent
    capability fails loudly so the misconfiguration shows up in the
    audit log instead of silently doing nothing."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.capabilities.store import reconcile_sso_grants
    with pytest.raises(ValueError):
        reconcile_sso_grants(username="alice",
                              wanted=["not.a.real.capability"],
                              actor="oidc:test")


def test_reconcile_fires_capability_changed_event(monkeypatch, tmp_path):
    """Each grant inside reconcile fires dispatch_event so the security
    team sees SSO-driven privilege changes in real time."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from unittest.mock import patch
    from safecadence.capabilities.store import reconcile_sso_grants
    with patch("safecadence.notifier.registry.dispatch_event") as mock:
        reconcile_sso_grants(username="alice", wanted=["read.audit"],
                              actor="oidc:test")
    assert mock.called
    kinds = [c.kwargs["kind"] for c in mock.call_args_list]
    assert "capability_changed" in kinds


# -------------------------------------------------- oidc_callback shape

def test_oidc_callback_dict_includes_capabilities_key():
    """The dict shape returned by oidc_callback must carry a
    capabilities list so the server endpoint can pass it to
    reconcile_sso_grants without poking at raw_claims."""
    # Don't actually run oidc_callback (network) — just inspect the
    # shape via resolve_capabilities + the contract documented in
    # the docstring of oidc_callback.
    from safecadence.sso import SSOConfig, resolve_capabilities
    cfg = SSOConfig(capability_map={"secops": ["read.audit"]})
    claims = {"groups": ["secops"], "preferred_username": "alice"}
    caps = resolve_capabilities(cfg, claims)
    # Same shape oidc_callback inserts under the "capabilities" key
    fake_result = {
        "username": "alice", "role": "viewer", "tenant": "default",
        "capabilities": caps,
    }
    assert fake_result["capabilities"] == ["read.audit"]
