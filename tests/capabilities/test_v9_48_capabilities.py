"""v9.48 — Capability-based RBAC: store, gate, decorator.

Covers:
  * Resolution priority (admin short-circuit, deny > grant > floor)
  * grant/revoke/clear-deny round-trip + history append
  * Unknown capability raises ValueError
  * require_capability decorator returns 403 on missing capability
  * Granting writes to the v9.47 activity log
"""
from __future__ import annotations

import pytest


# ----------------------------------------------------------- store

def test_admin_short_circuits(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.capabilities import (
        user_capabilities, ALL_CAPABILITIES, Capability,
    )
    eff = user_capabilities(username="alice", roles=["admin"])
    assert eff == set(ALL_CAPABILITIES)
    # Even with an explicit deny, admin keeps everything (short-circuit
    # is intentional — admin role IS the authority floor).
    from safecadence.capabilities.store import revoke
    revoke("alice", Capability.EXECUTE_REAL, actor="test")
    eff_after = user_capabilities(username="alice", roles=["admin"])
    assert eff_after == set(ALL_CAPABILITIES)


def test_role_floor_for_viewer(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.capabilities import user_capabilities, Capability
    eff = user_capabilities(username="carol", roles=["viewer"])
    assert Capability.READ_ASSET in eff
    assert Capability.WRITE_POLICY not in eff
    assert Capability.EXECUTE_REAL not in eff


def test_grant_overrides_floor(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.capabilities import user_capabilities, Capability
    from safecadence.capabilities.store import grant
    grant("bob", Capability.WRITE_POLICY,
          actor="admin", reason="approved-by-cto")
    eff = user_capabilities(username="bob", roles=["viewer"])
    assert Capability.WRITE_POLICY in eff


def test_deny_overrides_grant_and_floor(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.capabilities import user_capabilities, Capability
    from safecadence.capabilities.store import grant, revoke
    grant("carol", Capability.APPROVE_JOB,
          actor="admin", reason="grant-then-revoke")
    # revoke also adds to deny list
    revoke("carol", Capability.APPROVE_JOB,
           actor="admin", reason="changed-our-mind")
    eff = user_capabilities(username="carol", roles=["approver"])
    # APPROVE_JOB is in approver floor, but explicit deny wins.
    assert Capability.APPROVE_JOB not in eff


def test_clear_deny_falls_back_to_floor(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.capabilities import user_capabilities, Capability
    from safecadence.capabilities.store import revoke, clear_deny
    revoke("dave", Capability.READ_ASSET, actor="admin")
    eff = user_capabilities(username="dave", roles=["viewer"])
    assert Capability.READ_ASSET not in eff
    clear_deny("dave", Capability.READ_ASSET, actor="admin",
                reason="restoring-default")
    eff_after = user_capabilities(username="dave", roles=["viewer"])
    assert Capability.READ_ASSET in eff_after


def test_unknown_capability_raises(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.capabilities.store import grant, revoke
    with pytest.raises(ValueError):
        grant("eve", "totally.made.up", actor="admin")
    with pytest.raises(ValueError):
        revoke("eve", "totally.made.up", actor="admin")


def test_history_appended(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.capabilities import Capability
    from safecadence.capabilities.store import grant, revoke, get_grant
    grant("frank", Capability.GRANT_JIT, actor="admin",
          reason="incident-response-on-call")
    revoke("frank", Capability.GRANT_JIT, actor="admin",
           reason="incident-resolved")
    rec = get_grant("frank")
    assert len(rec.history) == 2
    assert rec.history[0]["action"] == "grant"
    assert rec.history[1]["action"] == "revoke"
    assert "incident" in rec.history[0]["reason"]


def test_grant_writes_to_activity_log(monkeypatch, tmp_path):
    """v9.47 activity log should pick up every capability change so
    /audit shows the provenance trail."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.capabilities import Capability
    from safecadence.capabilities.store import grant
    from safecadence.activity import read_range
    grant("george", Capability.MANAGE_USERS,
          actor="cto", reason="promotion")
    rows = read_range(days=1)
    paths = [r.path for r in rows]
    assert any("capabilities/george" in p for p in paths), \
        f"capability grant should land in activity log; got {paths}"


# ----------------------------------------------------------- gate

def test_require_capability_blocks_without(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from fastapi import HTTPException
    from safecadence.capabilities import require_capability, Capability

    class _U:
        username = "carol"
        tenant = "default"
        roles = ["viewer"]

    dep = require_capability(Capability.MANAGE_USERS)
    with pytest.raises(HTTPException) as excinfo:
        dep(_U())
    assert excinfo.value.status_code == 403
    assert "MANAGE_USERS".lower() in str(excinfo.value.detail).lower() or \
           "admin.users" in str(excinfo.value.detail)


def test_require_capability_passes_with_grant(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.capabilities import require_capability, Capability
    from safecadence.capabilities.store import grant

    grant("hank", Capability.MANAGE_WEBHOOKS, actor="admin")

    class _U:
        username = "hank"
        tenant = "default"
        roles = ["viewer"]

    dep = require_capability(Capability.MANAGE_WEBHOOKS)
    assert dep(_U()).username == "hank"
