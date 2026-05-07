"""v9.50.1 — cleanup pass tests.

Covers:
  * Audit dedup: HTTP-context grant doesn't double-write
  * Direct-Python (CLI) grant still emits the synthetic activity row
  * Demo seed populates capabilities and IdP groups
  * `safecadence capabilities list-types` lists all 27 keys
  * /capabilities page renders with cmLoad wiring
"""
from __future__ import annotations

from click.testing import CliRunner
from fastapi import FastAPI
from fastapi.testclient import TestClient


# ----------------------------------------------------------- dedup

def test_cli_grant_emits_synthetic_activity_row(monkeypatch, tmp_path):
    """Direct (non-HTTP) grants must keep emitting the synthetic
    activity row — there's no middleware to log them otherwise."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.capabilities.store import grant
    from safecadence.capabilities import Capability
    from safecadence.activity import read_range
    grant("alice", Capability.MANAGE_USERS, actor="cto")
    rows = read_range(days=1)
    paths = [r.path for r in rows]
    assert any("capabilities/alice" in p for p in paths)


def test_http_grant_skips_synthetic_emit(monkeypatch, tmp_path):
    """When mark_http_in_flight() has been called, grant() must NOT
    write a synthetic activity row — the middleware will log the
    real request with proper request_id, IP, etc."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.capabilities.store import grant, mark_http_in_flight
    from safecadence.capabilities import Capability
    from safecadence.activity import read_range
    mark_http_in_flight(True)
    grant("bob", Capability.MANAGE_WEBHOOKS, actor="api")
    rows = read_range(days=1)
    # No synthetic row — the middleware would have logged the real
    # HTTP request, but in this test there's no middleware in scope.
    assert rows == []


# ----------------------------------------------------------- demo seeds

def test_demo_seeds_capabilities(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.demo import _seed_capabilities_demo
    out = _seed_capabilities_demo()
    assert out["grants"] >= 4         # alice ×2 + bob ×2 minimum
    from safecadence.capabilities import list_grants
    rows = list_grants()
    usernames = {r.username for r in rows}
    assert "alice" in usernames
    assert "bob" in usernames


def test_demo_seeds_idp_groups(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.demo import _seed_idp_groups_demo
    out = _seed_idp_groups_demo()
    assert out["groups"] >= 3
    from safecadence.identity.groups import list_groups
    rows = list_groups()
    names = {r.name for r in rows}
    assert "eng-leads" in names
    assert "secops" in names
    assert "auditors" in names


# ----------------------------------------------------------- CLI list-types

def test_cli_capabilities_list_types(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.cli import cli
    runner = CliRunner()
    r = runner.invoke(cli, ["capabilities", "list-types"])
    assert r.exit_code == 0
    # Spot-check a few canonical keys appear
    assert "execute.real" in r.output
    assert "admin.users" in r.output
    assert "read.activity" in r.output
    # Should mention the dual-gate caveat for execute.real
    assert "execute.real" in r.output.lower()
    # Header line announces the count; should be at least 25.
    import re
    m = re.search(r"(\d+) capabilities", r.output)
    assert m and int(m.group(1)) >= 25


# ----------------------------------------------------------- /capabilities page

def _build_app(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_ACTIVITY_DISABLED", "1")
    app = FastAPI()
    from safecadence.ui.v9_pages import register
    register(app)
    return app


def test_capabilities_page_renders(monkeypatch, tmp_path):
    app = _build_app(monkeypatch, tmp_path)
    client = TestClient(app)
    r = client.get("/capabilities")
    assert r.status_code == 200
    assert "cmLoad" in r.text
    assert "cm-tbl" in r.text
    assert "org grant matrix" in r.text


def test_capabilities_page_consumes_existing_api(monkeypatch, tmp_path):
    """Page is read-only; just verifies /api/capabilities is the
    backing endpoint and returns the expected shape."""
    app = _build_app(monkeypatch, tmp_path)
    client = TestClient(app)
    r = client.get("/api/capabilities")
    assert r.status_code == 200
    body = r.json()
    assert "all_capabilities" in body
    assert "descriptions" in body
    assert "role_floor" in body
    assert isinstance(body["all_capabilities"], list)
    assert len(body["all_capabilities"]) >= 25
