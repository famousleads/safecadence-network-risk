"""Tests for v6.4 — asset tags, asset groups, policy targeting."""

from __future__ import annotations


# --------------------------------------------------------------------------
# Demo fleet now carries derived tags
# --------------------------------------------------------------------------

def test_demo_fleet_assets_carry_tags():
    from safecadence.demo import build_demo_fleet
    fleet = build_demo_fleet()
    tagged = [a for a in fleet if a.get("tags")]
    # Almost every asset should pick up at least one derived tag
    assert len(tagged) >= 28
    sample = next((a for a in fleet
                   if (a["identity"].get("vendor") or "").lower() == "cisco"), None)
    assert sample is not None
    assert "vendor:cisco" in sample["tags"]
    assert any(t.startswith("env:") for t in sample["tags"])
    assert any(t.startswith("type:") for t in sample["tags"])


# --------------------------------------------------------------------------
# Filter language — clauses, AND/OR/NOT, dot-walk
# --------------------------------------------------------------------------

def test_filter_eq_and_in():
    from safecadence.policy.asset_groups import _match_clause
    asset = {"identity": {"asset_id": "x", "vendor": "Cisco",
                           "environment": "prod"}}
    assert _match_clause(asset, {"field": "vendor", "op": "eq",
                                  "value": "cisco"})
    assert _match_clause(asset, {"field": "environment", "op": "in",
                                  "value": ["prod", "staging"]})
    assert not _match_clause(asset, {"field": "vendor", "op": "neq",
                                      "value": "cisco"})


def test_filter_has_tag_and_dot_walk():
    from safecadence.policy.asset_groups import _match_clause
    asset = {"identity": {"asset_id": "x"},
             "tags": ["env:prod", "kev:yes"],
             "security": {"kev_cves": 2}}
    assert _match_clause(asset, {"field": "tags", "op": "has_tag",
                                  "value": "kev:yes"})
    assert not _match_clause(asset, {"field": "tags", "op": "has_tag",
                                      "value": "missing"})
    # security.kev_cves dot-walk
    assert _match_clause(asset, {"field": "security.kev_cves",
                                  "op": "eq", "value": 2})


def test_filter_all_any_not():
    from safecadence.policy.asset_groups import _match_filter
    asset = {"identity": {"asset_id": "x", "vendor": "cisco",
                           "environment": "prod"},
             "tags": ["env:prod", "vendor:cisco"]}
    spec = {"all": [
        {"field": "vendor", "op": "eq", "value": "cisco"},
        {"any": [
            {"field": "environment", "op": "eq", "value": "prod"},
            {"field": "environment", "op": "eq", "value": "staging"},
        ]},
        {"not": {"field": "tags", "op": "has_tag", "value": "deprecated"}},
    ]}
    assert _match_filter(asset, spec)


def test_filter_rejects_unknown_field_or_op():
    from safecadence.policy.asset_groups import _match_clause
    asset = {"identity": {"asset_id": "x", "vendor": "cisco"}}
    assert not _match_clause(asset, {"field": "rooted_field", "op": "eq",
                                      "value": "x"})
    assert not _match_clause(asset, {"field": "vendor", "op": "regex",
                                      "value": "cisc.*"})


# --------------------------------------------------------------------------
# Group resolution — static, dynamic, exclusions
# --------------------------------------------------------------------------

def test_resolve_static_group():
    from safecadence.policy.asset_groups import AssetGroup, resolve_members
    assets = [{"identity": {"asset_id": "a"}},
              {"identity": {"asset_id": "b"}},
              {"identity": {"asset_id": "c"}}]
    g = AssetGroup(group_id="pci", name="PCI",
                   asset_ids=["a", "c", "missing"])
    members = resolve_members(g, assets)
    assert len(members) == 2
    ids = {(m["identity"]["asset_id"]) for m in members}
    assert ids == {"a", "c"}


def test_resolve_dynamic_group_with_exclusion():
    from safecadence.policy.asset_groups import AssetGroup, resolve_members
    assets = [
        {"identity": {"asset_id": "router-01", "vendor": "cisco"}},
        {"identity": {"asset_id": "router-02", "vendor": "cisco"}},
        {"identity": {"asset_id": "router-03", "vendor": "cisco"}},
        {"identity": {"asset_id": "fortigate-01", "vendor": "fortinet"}},
    ]
    g = AssetGroup(group_id="cisco-only", name="Cisco only",
                   filter={"all": [{"field": "vendor", "op": "eq",
                                    "value": "cisco"}]},
                   exclude_asset_ids=["router-02"])
    members = resolve_members(g, assets)
    ids = {(m["identity"]["asset_id"]) for m in members}
    assert ids == {"router-01", "router-03"}


def test_empty_filter_matches_nothing_not_everything():
    from safecadence.policy.asset_groups import AssetGroup, resolve_members
    assets = [{"identity": {"asset_id": "a"}}]
    g = AssetGroup(group_id="empty", name="empty", filter={})
    assert resolve_members(g, assets) == []


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------

def test_validation_rejects_static_and_dynamic_simultaneously():
    from safecadence.policy.asset_groups import AssetGroup, validate_group
    g = AssetGroup(group_id="bad", name="bad",
                   asset_ids=["a"],
                   filter={"all": [{"field": "vendor", "op": "eq",
                                     "value": "cisco"}]})
    errs = validate_group(g)
    assert any("static" in e.lower() and "dynamic" in e.lower() for e in errs)


def test_validation_rejects_traversal_in_group_id():
    from safecadence.policy.asset_groups import AssetGroup, validate_group
    g = AssetGroup(group_id="../../etc/passwd", name="x")
    errs = validate_group(g)
    assert any("illegal" in e.lower() for e in errs)


def test_validation_rejects_unknown_field():
    from safecadence.policy.asset_groups import AssetGroup, validate_group
    g = AssetGroup(group_id="g", name="g",
                   filter={"all": [{"field": "unknown", "op": "eq",
                                     "value": "x"}]})
    errs = validate_group(g)
    assert any("unknown field" in e for e in errs)


# --------------------------------------------------------------------------
# Persistence
# --------------------------------------------------------------------------

def test_save_get_list_delete_round_trip(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_ASSET_GROUPS_STORE", str(tmp_path))
    from safecadence.policy.asset_groups import (
        AssetGroup, save, get, list_groups, delete,
    )
    g = AssetGroup(group_id="cisco-edge", name="Cisco edge",
                   filter={"all": [{"field": "vendor", "op": "eq",
                                    "value": "cisco"}]})
    save(g)
    fetched = get("cisco-edge")
    assert fetched is not None and fetched.name == "Cisco edge"
    listing = list_groups()
    assert len(listing) == 1
    assert delete("cisco-edge") is True
    assert get("cisco-edge") is None


# --------------------------------------------------------------------------
# Policy targeting through groups
# --------------------------------------------------------------------------

def test_policy_applies_only_to_group_members(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_ASSET_GROUPS_STORE", str(tmp_path))
    from safecadence.policy.asset_groups import AssetGroup, save
    from safecadence.policy.schema import SecurityPolicy

    save(AssetGroup(group_id="prod-only", name="Prod only",
                    filter={"all": [{"field": "environment",
                                       "op": "eq", "value": "prod"}]}))
    policy = SecurityPolicy(policy_id="p1", policy_name="p",
                             applies_to_groups=["prod-only"])
    prod_asset = {"identity": {"asset_id": "a", "environment": "prod"}}
    dev_asset = {"identity": {"asset_id": "b", "environment": "dev"}}
    # Membership cache pre-resolved by the evaluator in real usage;
    # we test the effect here.
    cache = {"a"}
    assert policy.applies_to(prod_asset, group_member_cache=cache)
    assert not policy.applies_to(dev_asset, group_member_cache=cache)


def test_to_policy_picks_up_applies_to_groups():
    """The /api/policy/ POST handler builds a SecurityPolicy via _to_policy.
    The Builder wizard sends applies_to_groups; verify it's preserved."""
    from safecadence.policy.templates import _to_policy
    body = {
        "policy_id": "p1", "policy_name": "p",
        "target_asset_types": ["network"],
        "applies_to_groups": ["cisco-edge", "pci-scope"],
        "controls": [],
    }
    p = _to_policy(body)
    assert p.applies_to_groups == ["cisco-edge", "pci-scope"]


def test_builder_wizard_html_has_six_steps():
    """v6.4 — wizard expanded from 5 to 6 steps. Verify the rendered
    template carries the new step numbering and the group-picker step."""
    from safecadence.ui.policy_ui import render_policy_ui
    html = render_policy_ui()
    assert "Step 1 of 6" in html
    assert "Step 2 of 6" in html
    assert "Step 6 of 6" in html
    assert "renderStep2Groups" in html
    assert "Apply to which devices?" in html
    assert "asset_group_ids" in html
    # And the version badge has been bumped
    assert ">v6.4<" in html


def test_evaluator_pre_resolves_groups(tmp_path, monkeypatch):
    """End-to-end: evaluator filters by group membership."""
    monkeypatch.setenv("SC_ASSET_GROUPS_STORE", str(tmp_path))
    from safecadence.policy.asset_groups import AssetGroup, save
    from safecadence.policy.schema import SecurityPolicy
    from safecadence.policy.evaluator import evaluate

    save(AssetGroup(group_id="prod-only", name="Prod",
                    filter={"all": [{"field": "environment",
                                       "op": "eq", "value": "prod"}]}))
    assets = [
        {"identity": {"asset_id": "a", "asset_type": "network",
                       "environment": "prod", "vendor": "cisco"}},
        {"identity": {"asset_id": "b", "asset_type": "network",
                       "environment": "dev", "vendor": "cisco"}},
    ]
    policy = SecurityPolicy(policy_id="p1", policy_name="p",
                             target_asset_types=["network"],
                             applies_to_groups=["prod-only"])
    ev = evaluate(policy, assets)
    # Only the prod asset should have been considered. The evaluator
    # appends one row to asset_results per applicable asset.
    assert len(ev.asset_results) == 1
    assert ev.asset_results[0]["asset_id"] == "a"
