"""v9.50 — has_explicit_grant() + Tier-3 dual-system gate."""
from __future__ import annotations

import pytest


def test_explicit_grant_admin_short_circuit_does_not_apply(monkeypatch,
                                                              tmp_path):
    """Even an admin user must have an explicit grant — has_capability
    short-circuits on admin role, has_explicit_grant does NOT."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.capabilities import (
        has_capability, has_explicit_grant, Capability,
    )
    # Admin: standard has_capability returns True for everything
    assert has_capability(username="alice", roles=["admin"],
                            capability=Capability.EXECUTE_REAL) is True
    # has_explicit_grant: admin role doesn't help — needs an explicit
    # grant entry
    assert has_explicit_grant(username="alice",
                                 capability=Capability.EXECUTE_REAL) is False


def test_explicit_grant_returns_true_after_grant(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.capabilities import (
        has_explicit_grant, Capability,
    )
    from safecadence.capabilities.store import grant
    grant("alice", Capability.EXECUTE_REAL, actor="cto")
    assert has_explicit_grant(username="alice",
                                 capability=Capability.EXECUTE_REAL) is True


def test_explicit_grant_blocked_by_deny(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.capabilities import (
        has_explicit_grant, Capability,
    )
    from safecadence.capabilities.store import grant, revoke
    grant("alice", Capability.EXECUTE_REAL, actor="cto")
    revoke("alice", Capability.EXECUTE_REAL, actor="cto",
           reason="incident-handled")
    assert has_explicit_grant(username="alice",
                                 capability=Capability.EXECUTE_REAL) is False


def test_explicit_grant_unknown_capability_returns_false(monkeypatch,
                                                            tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.capabilities import has_explicit_grant
    assert has_explicit_grant(username="alice",
                                 capability="totally.made.up") is False


def test_tier3_check_activation_blocks_without_explicit_grant(monkeypatch,
                                                                tmp_path):
    """The v9.50 dual-gate: legacy rbac OK + env OK, but no v9.48
    explicit grant → Tier3DisabledError."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_TIER3_ENABLED", "1")
    from safecadence.execution.tier3 import (
        _check_activation, Tier3DisabledError,
    )
    from safecadence.execution.rbac import Role
    # Patch the legacy can() so it returns True; the v9.48 check is
    # what should fail.
    import safecadence.execution.tier3 as tier3_mod
    monkeypatch.setattr(tier3_mod, "can", lambda role, cap: True)
    with pytest.raises(Tier3DisabledError) as excinfo:
        _check_activation(role=Role.SUPER_ADMIN, acknowledge=True,
                            i_mean_it=True,
                            username="alice", tenant="default")
    assert "explicit" in str(excinfo.value).lower()
    assert "execute.real" in str(excinfo.value).lower()


def test_tier3_check_activation_passes_with_explicit_grant(monkeypatch,
                                                              tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_TIER3_ENABLED", "1")
    from safecadence.capabilities import Capability
    from safecadence.capabilities.store import grant
    grant("alice", Capability.EXECUTE_REAL, actor="cto")
    from safecadence.execution.tier3 import _check_activation
    from safecadence.execution.rbac import Role
    import safecadence.execution.tier3 as tier3_mod
    monkeypatch.setattr(tier3_mod, "can", lambda role, cap: True)
    # Should not raise
    _check_activation(role=Role.SUPER_ADMIN, acknowledge=True,
                       i_mean_it=True,
                       username="alice", tenant="default")


def test_tier3_legacy_callers_skip_v9_48_check(monkeypatch, tmp_path):
    """Backward compat: callers that don't pass username keep working
    on the legacy rbac gate alone. No v9.48 check applies."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_TIER3_ENABLED", "1")
    from safecadence.execution.tier3 import _check_activation
    from safecadence.execution.rbac import Role
    import safecadence.execution.tier3 as tier3_mod
    monkeypatch.setattr(tier3_mod, "can", lambda role, cap: True)
    # No username → v9.48 check skipped → no exception
    _check_activation(role=Role.SUPER_ADMIN, acknowledge=True,
                       i_mean_it=True)
