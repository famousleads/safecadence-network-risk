"""v9.52.1 — integration smoke for the /capabilities org matrix.

The v9.50.1 page test only verified the HTML rendered. This test
exercises the full data flow: seed users + grants, fetch
/api/capabilities, verify the response shape contains everything the
matrix needs to populate cells correctly.
"""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient


def _build_app(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_ACTIVITY_DISABLED", "1")
    app = FastAPI()
    from safecadence.ui.v9_pages import register
    register(app)
    return app


def test_caps_matrix_data_shape_has_everything_cells_need(monkeypatch,
                                                            tmp_path):
    """The page renders cells based on grants, denies, descriptions,
    role_floor, and all_capabilities. The endpoint should return all
    five so the page can compute G/R/D/— per cell client-side."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_ACTIVITY_DISABLED", "1")
    from safecadence.capabilities.store import grant, revoke
    from safecadence.capabilities import Capability
    grant("alice", Capability.MANAGE_USERS, actor="cto")
    grant("alice", Capability.MANAGE_WEBHOOKS, actor="cto")
    revoke("bob", Capability.EXECUTE_REAL, actor="cto",
           reason="rotation-ended")

    app = _build_app(monkeypatch, tmp_path)
    client = TestClient(app)
    r = client.get("/api/capabilities")
    assert r.status_code == 200
    body = r.json()
    # All five fields the matrix script reads
    assert "all_capabilities" in body
    assert "descriptions" in body
    assert "role_floor" in body
    assert "grants" in body
    # Count check
    assert len(body["all_capabilities"]) == 26
    assert len(body["descriptions"]) == 26
    # Grants: alice has 2, bob has 1 (with deny)
    by_user = {g["username"]: g for g in body["grants"]}
    assert "alice" in by_user
    assert Capability.MANAGE_USERS in by_user["alice"]["grant"]
    assert Capability.MANAGE_WEBHOOKS in by_user["alice"]["grant"]
    assert "bob" in by_user
    assert Capability.EXECUTE_REAL in by_user["bob"]["deny"]


def test_caps_matrix_role_floor_includes_admin_full_set(monkeypatch,
                                                          tmp_path):
    """The matrix reads role_floor['admin'] to know admin should
    show R (via role) cells everywhere. Verify the API hands back
    the full admin set."""
    app = _build_app(monkeypatch, tmp_path)
    client = TestClient(app)
    body = client.get("/api/capabilities").json()
    assert "admin" in body["role_floor"]
    # Admin should have every capability via short-circuit
    assert set(body["role_floor"]["admin"]) == set(body["all_capabilities"])


def test_caps_matrix_descriptions_match_all_capabilities(monkeypatch,
                                                          tmp_path):
    """Every capability key in all_capabilities must have a matching
    description entry (UI uses descriptions for hover tooltips)."""
    app = _build_app(monkeypatch, tmp_path)
    client = TestClient(app)
    body = client.get("/api/capabilities").json()
    for cap in body["all_capabilities"]:
        assert cap in body["descriptions"], \
            f"capability {cap!r} has no description"


def test_caps_page_html_references_real_endpoints(monkeypatch, tmp_path):
    """Pin the wiring tokens that the matrix script depends on so a
    rename of the endpoint URL would fail this test."""
    app = _build_app(monkeypatch, tmp_path)
    client = TestClient(app)
    r = client.get("/capabilities")
    assert r.status_code == 200
    # The script fetches /api/capabilities and /api/users (for roles)
    assert "/api/capabilities" in r.text
    assert "/api/users" in r.text
    assert "cmLoad" in r.text
    # The cell badges must be in the HTML
    assert "pill pill-ok" in r.text       # G — granted
    assert "pill pill-bad" in r.text      # D — denied
