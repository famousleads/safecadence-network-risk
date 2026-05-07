"""
v9.1 — AI asset enrichment tests.
"""

from __future__ import annotations

import json

import pytest

from safecadence.intel.asset_enrichment import (
    enrich_asset, enrich_fleet, merge_enrichment, Enrichment,
)


# ---------------------------------------------------------------- fallback


def test_enrichment_infers_edge_router_role():
    asset = {"identity": {
        "asset_id": "edge-rtr-01.acme.local",
        "hostname": "edge-rtr-01.acme.local",
        "vendor": "cisco",
        "asset_type": "network",
    }}
    e = enrich_asset(asset)
    assert e.inferred_role == "edge-router"
    assert e.inferred_criticality == "crown-jewel"
    assert "role:edge-router" in e.suggested_tags
    assert e.suggested_owner_team == "network-eng"


def test_enrichment_infers_db_server():
    asset = {"identity": {
        "asset_id": "db-prod-customer-01",
        "hostname": "db-prod-customer-01",
        "asset_type": "server",
    }}
    e = enrich_asset(asset)
    assert e.inferred_role == "db-server"
    assert e.inferred_environment == "prod"
    assert "env:prod" in e.suggested_tags
    assert e.compliance_tier == "pci"  # db + prod → PCI


def test_enrichment_infers_branch_router():
    asset = {"identity": {
        "asset_id": "branch-rtr-east-04",
        "hostname": "branch-rtr-east-04",
        "vendor": "cisco",
    }}
    e = enrich_asset(asset)
    assert e.inferred_role == "branch-router"
    assert "role:branch-router" in e.suggested_tags


def test_enrichment_infers_identity_provider_for_okta():
    asset = {"identity": {
        "asset_id": "okta-acme",
        "hostname": "okta-acme",
        "vendor": "okta",
        "asset_type": "identity",
    }}
    e = enrich_asset(asset)
    assert e.inferred_role == "identity-provider"
    assert e.compliance_tier == "sox"
    assert e.suggested_owner_team == "identity-eng"


def test_enrichment_keeps_existing_criticality():
    asset = {"identity": {
        "asset_id": "x",
        "hostname": "random-host",
        "criticality": "crown-jewel",
    }}
    e = enrich_asset(asset)
    assert e.inferred_criticality == "crown-jewel"


def test_enrichment_summary_is_human():
    asset = {"identity": {
        "asset_id": "edge-rtr-01",
        "hostname": "edge-rtr-01",
        "vendor": "cisco",
    }}
    e = enrich_asset(asset)
    assert e.summary
    assert "edge router" in e.summary.lower()


def test_enrichment_environment_from_hostname():
    asset = {"identity": {"hostname": "web-stg-01.example", "asset_id": "x"}}
    e = enrich_asset(asset)
    assert e.inferred_environment == "staging"


def test_enrichment_falls_back_when_unrecognized():
    asset = {"identity": {
        "asset_id": "weirdname123",
        "hostname": "weirdname123",
    }}
    e = enrich_asset(asset)
    # Doesn't match any role pattern — but still produces medium/empty defaults
    assert e.inferred_role == ""           # no match in patterns
    assert e.inferred_criticality == "medium"
    assert e.confidence == "medium"


# ---------------------------------------------------------------- AI path


def test_enrichment_uses_ai_stub_when_provided():
    """ai_call seam returns canned JSON; merge into Enrichment."""
    fake = json.dumps({
        "inferred_role": "edge-router",
        "inferred_environment": "prod",
        "inferred_site": "dc1",
        "inferred_criticality": "crown-jewel",
        "compliance_tier": "sox",
        "suggested_tags": ["role:edge-router", "env:prod", "site:dc1"],
        "suggested_owner_team": "network-eng",
        "summary": "edge router at dc1",
    })

    def stub(system, user, model):
        return fake

    asset = {"identity": {"asset_id": "x", "hostname": "x"}}
    e = enrich_asset(asset, ai_call=stub)
    assert e.used_ai is True
    assert e.confidence == "high"
    assert e.inferred_role == "edge-router"
    assert "role:edge-router" in e.suggested_tags


def test_enrichment_falls_back_when_ai_returns_garbage():
    def stub(system, user, model):
        return "this is not JSON"

    asset = {"identity": {"hostname": "edge-rtr-01", "asset_id": "x"}}
    e = enrich_asset(asset, ai_call=stub)
    assert e.used_ai is False
    assert e.inferred_role == "edge-router"  # fallback worked


# ---------------------------------------------------------------- merge


def test_merge_appends_tags_without_duplicates():
    asset = {"identity": {
        "asset_id": "x", "hostname": "x", "tags": ["env:prod"],
        "custom_fields": {"business_owner": "alice"},
    }}
    e = Enrichment(
        suggested_tags=["env:prod", "role:db-server"],   # env:prod already exists
        inferred_role="db-server",
        suggested_owner_team="data-eng",
    )
    merged = merge_enrichment(asset, e)
    tags = merged["identity"]["tags"]
    assert tags.count("env:prod") == 1   # not duplicated
    assert "role:db-server" in tags
    # Existing custom fields preserved
    assert merged["identity"]["custom_fields"]["business_owner"] == "alice"
    # AI custom fields added
    assert merged["identity"]["custom_fields"]["ai_role"] == "db-server"


def test_merge_overwrites_ai_prefixed_fields():
    asset = {"identity": {
        "asset_id": "x", "hostname": "x",
        "custom_fields": {"ai_role": "old"},
    }}
    e = Enrichment(inferred_role="new-role")
    merged = merge_enrichment(asset, e)
    assert merged["identity"]["custom_fields"]["ai_role"] == "new-role"


# ---------------------------------------------------------------- bulk


def test_enrich_fleet_processes_all_assets():
    assets = [
        {"identity": {"asset_id": f"host-{i}",
                       "hostname": "edge-rtr-01" if i == 0 else "x"}}
        for i in range(3)
    ]
    results = enrich_fleet(assets)
    assert len(results) == 3
    assert results[0].inferred_role == "edge-router"
