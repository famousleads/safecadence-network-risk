"""
v9.40 — Per-principal asset breakdown.

The v7.5 ``decide()`` resolver answers one (action, resource, principal)
question at a time. v9.40 adds the breakdown shape an auditor needs:
"show me everything alice@acme can reach across the fleet, and which
systems grant each permission."

These tests pin:
  - Allowed actions surface, denied actions surface, step-up surfaces
  - granted_by_systems collects the systems that contributed each allow
  - only_granted=True filters out no-access assets
  - The HTTP endpoint accepts the same shape and returns the breakdown
"""

from __future__ import annotations

import pytest

from safecadence.identity.access_breakdown import (
    breakdown_for_principal, DEFAULT_ACTIONS, PROBE_TYPES,
)


def _asset(asset_id: str, hostname: str, *, asset_type="server",
            env="prod", crit="high", rules=None) -> dict:
    """Helper: build a UnifiedAsset dict with optional declared rules."""
    return {
        "identity": {
            "asset_id": asset_id, "hostname": hostname,
            "asset_type": asset_type, "environment": env,
            "criticality": crit, "site": "dc1",
        },
        "identity_block": {
            "provider": "okta",
            "declared_rules": rules or [],
        },
    }


def _allow_rule(*, system="okta", principals, actions, resources,
                priority=100, conditions=None):
    return {
        "system": system,
        "rule_id": f"r-{system}-{priority}",
        "rule_name": f"{system}-allow-{actions[0]}",
        "effect": "allow",
        "principals": principals,
        "actions": actions,
        "resources": resources,
        "conditions": conditions or [],
        "priority": priority,
    }


def _deny_rule(*, system="okta", principals, actions, resources,
                priority=10):
    return {
        "system": system,
        "rule_id": f"d-{system}-{priority}",
        "rule_name": f"{system}-deny-{actions[0]}",
        "effect": "deny",
        "principals": principals,
        "actions": actions,
        "resources": resources,
        "conditions": [],
        "priority": priority,
    }


# ---------------------------------------------------------- core breakdown


def test_breakdown_returns_per_asset_grant_objects():
    assets = [
        _asset("prod-db-01", "prod-db-01", rules=[
            _allow_rule(principals=["user:alice@acme"],
                        actions=["ssh"],
                        resources=["asset_type:server"]),
        ]),
    ]
    out = breakdown_for_principal(principal="alice@acme", assets=assets)
    assert out["principal"] == "alice@acme"
    assert out["actions_probed"] == list(DEFAULT_ACTIONS)
    grants = out["grants"]
    assert len(grants) == 1
    g = grants[0]
    assert g["asset_id"] == "prod-db-01"
    assert "ssh" in g["actions_allowed"]
    # Other default actions weren't allowed
    assert "rdp" in g["actions_denied"]


def test_granted_by_systems_collects_all_contributors():
    assets = [
        _asset("server-1", "server-1", rules=[
            _allow_rule(system="okta", principals=["user:bob@acme"],
                         actions=["ssh"],
                         resources=["asset_type:server"]),
            _allow_rule(system="ad", principals=["user:bob@acme"],
                         actions=["ssh"],
                         resources=["asset_type:server"],
                         priority=50),
        ]),
    ]
    out = breakdown_for_principal(principal="bob@acme", assets=assets)
    g = out["grants"][0]
    # Both systems contributed an allow for ssh
    assert "okta" in g["granted_by_systems"]
    assert "ad" in g["granted_by_systems"]


def test_deny_rule_blocks_grant():
    assets = [
        _asset("prod-db-01", "prod-db-01", rules=[
            _allow_rule(principals=["user:alice@acme"],
                        actions=["ssh"],
                        resources=["asset_type:server"]),
            _deny_rule(principals=["user:alice@acme"],
                        actions=["ssh"],
                        resources=["env:prod"]),
        ]),
    ]
    out = breakdown_for_principal(principal="alice@acme", assets=assets)
    g = out["grants"][0]
    assert "ssh" in g["actions_denied"]
    assert "ssh" not in g["actions_allowed"]


def test_only_granted_filters_no_access_assets():
    """Use a resource selector that targets ONE asset_id explicitly so
    the rule doesn't broadcast across the fleet (rules_from_assets
    aggregates rules and applies them to every matching resource)."""
    assets = [
        _asset("a1", "a1", rules=[
            _allow_rule(principals=["user:alice@acme"],
                        actions=["ssh"],
                        resources=["a1"]),       # exact asset_id only
        ]),
        _asset("a2", "a2"),       # no rules → no grants for alice
    ]
    full = breakdown_for_principal(principal="alice@acme", assets=assets)
    filtered = breakdown_for_principal(principal="alice@acme",
                                         assets=assets, only_granted=True)
    assert len(full["grants"]) == 2
    assert len(filtered["grants"]) == 1
    assert filtered["grants"][0]["asset_id"] == "a1"


def test_summary_counts_match_grants():
    """Per-asset rules so they don't broadcast across the fleet."""
    assets = [
        _asset("a1", "a1", rules=[
            _allow_rule(principals=["user:alice@acme"],
                        actions=["ssh"],
                        resources=["a1"]),
        ]),
        _asset("a2", "a2", rules=[
            _allow_rule(principals=["user:alice@acme"],
                        actions=["rdp"],
                        resources=["a2"]),
        ]),
        _asset("a3", "a3"),       # no grants
    ]
    out = breakdown_for_principal(principal="alice@acme", assets=assets)
    s = out["summary"]
    assert s["assets_total"] == 3
    assert s["assets_with_any_grant"] == 2
    assert s["actions_granted"] >= 2


def test_groups_let_group_rules_match():
    """Most IdPs grant by group. Without principal_groups, group rules
    don't match — confirm passing them in produces grants."""
    assets = [
        _asset("a1", "a1", rules=[
            _allow_rule(principals=["group:Engineering"],
                        actions=["ssh"],
                        resources=["asset_type:server"]),
        ]),
    ]
    no_groups = breakdown_for_principal(principal="alice@acme",
                                          assets=assets)
    # Resolver expects bare group names (no "group:" prefix) per
    # effective_permissions._match
    with_groups = breakdown_for_principal(
        principal="alice@acme", assets=assets,
        principal_groups=["Engineering"],
    )
    assert "ssh" not in no_groups["grants"][0]["actions_allowed"]
    assert "ssh" in with_groups["grants"][0]["actions_allowed"]


def test_asset_types_filter_excludes_irrelevant():
    """asset_types restricts the probe so the breakdown isn't full of
    printer rows the operator doesn't care about."""
    assets = [
        _asset("server-1", "server-1", asset_type="server"),
        _asset("printer-1", "printer-1", asset_type="printer"),
    ]
    out = breakdown_for_principal(
        principal="alice@acme", assets=assets,
        asset_types=("server",),
    )
    assert len(out["grants"]) == 1
    assert out["grants"][0]["asset_id"] == "server-1"


def test_chain_includes_rule_names_for_audit():
    """The chain is what the auditor reads. Rule names must surface."""
    assets = [
        _asset("a1", "a1", rules=[
            _allow_rule(principals=["user:alice@acme"],
                        actions=["ssh"],
                        resources=["asset_type:server"]),
        ]),
    ]
    out = breakdown_for_principal(principal="alice@acme", assets=assets)
    chain = out["grants"][0]["chain"]
    assert chain
    rule_names = [c["rule_name"] for c in chain]
    assert any("allow-ssh" in n for n in rule_names)


def test_default_probe_types_include_security_relevant_kinds():
    """Sanity: the default probe set covers the asset types operators
    care about for /access. Catching regressions where someone drops
    'firewall' from the default."""
    for required in ("server", "network", "firewall", "endpoint"):
        assert required in PROBE_TYPES


# ----------------------------------------------------- HTTP endpoint


@pytest.fixture
def access_client(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    pytest.importorskip("yaml")
    monkeypatch.setenv("SAFECADENCE_HOME", str(tmp_path))
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_USERS_FILE", str(tmp_path / "users.yaml"))
    monkeypatch.setenv("SC_JWT_SECRET", "test-secret")
    monkeypatch.setenv("SC_AI_DISABLED", "1")
    pytest.importorskip("cryptography")
    from cryptography.fernet import Fernet
    monkeypatch.setenv("SAFECADENCE_VAULT_KEY",
                        Fernet.generate_key().decode("ascii"))
    import yaml
    from safecadence.server.auth import hash_password
    (tmp_path / "users.yaml").write_text(yaml.safe_dump({
        "tenants": {"acme": {"users": [{
            "username": "alice",
            "password_hash": hash_password("hunter2"),
            "roles": ["admin"],
        }]}}
    }))
    from fastapi.testclient import TestClient
    from safecadence.server import create_app
    app = create_app(users_file=str(tmp_path / "users.yaml"),
                     db_url=f"sqlite:///{tmp_path}/sc.db",
                     jwt_secret="test-secret")
    c = TestClient(app)
    tok = c.post("/api/login",
                  data={"username": "alice", "password": "hunter2"}
                  ).json()["access_token"]
    c._hdr = {"Authorization": f"Bearer {tok}"}
    return c


def test_access_endpoint_returns_breakdown(access_client):
    r = access_client.get(
        "/api/identity/access",
        headers=access_client._hdr,
        params={"principal": "alice@acme",
                "groups": "group:Engineering",
                "only_granted": "false"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["principal"] == "alice@acme"
    assert "grants" in body
    assert "summary" in body
    assert "actions_probed" in body
    # Even with empty fleet, the response shape is present
    assert isinstance(body["grants"], list)


def test_access_endpoint_accepts_custom_action_list(access_client):
    r = access_client.get(
        "/api/identity/access",
        headers=access_client._hdr,
        params={"principal": "alice@acme",
                "actions": "ssh,console"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["actions_probed"] == ["ssh", "console"]
