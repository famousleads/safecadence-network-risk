"""
Tests for v12.0.0a6 — operator UI page wrappers for v12+ surfaces.

Verifies /cluster-status, /ai-agents, /api-keys all render under the
default single-node config (no peers, no agents, no keys).
"""
from __future__ import annotations

import os

import pytest


@pytest.fixture()
def client():
    os.environ["SC_AUTH_DISABLED"] = "1"
    os.environ.pop("SC_HA_MODE", None)
    from fastapi.testclient import TestClient
    from safecadence.ui.app import create_app
    return TestClient(create_app())


def test_cluster_status_page_renders(client):
    r = client.get("/cluster-status")
    assert r.status_code == 200
    assert "<title>" in r.text
    assert "Cluster status" in r.text


def test_cluster_status_shows_single_node_when_no_peers(client):
    r = client.get("/cluster-status")
    assert r.status_code == 200
    body = r.text
    # Single-node default: ACTIVE pill + "No peers configured" text
    assert "ACTIVE" in body
    assert ("single-node" in body) or ("No peers" in body)


def test_cluster_status_includes_manual_drain_form(client):
    r = client.get("/cluster-status")
    assert r.status_code == 200
    assert "/api/v1/cluster/transfer" in r.text
    assert "Drain" in r.text


def test_ai_agents_page_renders_empty(client):
    r = client.get("/ai-agents")
    assert r.status_code == 200
    assert "<title>" in r.text
    assert ("No AI agents registered" in r.text) or ("agent_id" in r.text)


def test_api_keys_page_renders_empty(client):
    r = client.get("/api-keys")
    assert r.status_code == 200
    assert "<title>" in r.text
    assert ("No API keys tracked" in r.text) or ("provider" in r.text.lower())


def test_v12_pages_router_has_three_routes():
    from safecadence.ui.v12_pages import router
    paths = {r.path for r in router.routes}
    assert paths == {"/cluster-status", "/ai-agents", "/api-keys"}


def test_v12_pages_never_500_when_underlying_apis_fail(client, monkeypatch):
    """Defensive degradation: even if the cluster/ai_governance modules
    raise, the pages should still render a polite empty state."""
    import safecadence.cluster.health as health_mod

    def boom():
        raise RuntimeError("simulated failure")

    monkeypatch.setattr(health_mod, "cluster_state", boom)
    r = client.get("/cluster-status")
    assert r.status_code == 200
    assert "Error:" in r.text or "Cluster status" in r.text
