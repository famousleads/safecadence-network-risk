"""v9.54 #2 — cross-tenant capability admin view.

The ``/api/capabilities/all-tenants`` endpoint flattens every grant
across every tenant into one response so MSP-style operators can
audit the full estate from one screen. Gate is admin.capabilities
on at least one tenant, OR the synthetic admin in single-user mode.
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


# ---------------------------------------------------- store helpers

def test_list_tenants_empty(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.capabilities.store import list_tenants
    assert list_tenants() == []


def test_list_tenants_after_grants(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.capabilities.store import grant, list_tenants
    grant("alice", "read.audit", tenant="acme", actor="cto")
    grant("bob", "execute.real", tenant="globex", actor="cto")
    grant("carol", "admin.users", tenant="initech", actor="cto")
    assert list_tenants() == ["acme", "globex", "initech"]


def test_list_all_grants_walks_every_tenant(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.capabilities.store import grant, list_all_grants
    grant("alice", "read.audit", tenant="acme", actor="cto")
    grant("bob", "execute.real", tenant="globex", actor="cto")
    rows = list_all_grants()
    assert len(rows) == 2
    by_tenant = {r.tenant: r for r in rows}
    assert "acme" in by_tenant and by_tenant["acme"].username == "alice"
    assert "globex" in by_tenant and by_tenant["globex"].username == "bob"


# ---------------------------------------------------- HTTP endpoint

def test_all_tenants_endpoint_synth_admin_passes(monkeypatch, tmp_path):
    """In single-user mode the synthetic 'local-admin' has roles=['admin']
    so the endpoint passes without needing a per-tenant capability."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_ACTIVITY_DISABLED", "1")
    from safecadence.capabilities.store import grant
    grant("alice", "read.audit", tenant="acme", actor="cto")
    grant("bob", "execute.real", tenant="globex", actor="cto")
    from fastapi import FastAPI
    app = FastAPI()
    from safecadence.ui.v9_pages import register
    register(app)
    client = TestClient(app)
    r = client.get("/api/capabilities/all-tenants")
    assert r.status_code == 200
    body = r.json()
    assert body["row_count"] == 2
    assert "acme" in body["by_tenant"]
    assert "globex" in body["by_tenant"]
    assert body["by_tenant"]["acme"][0]["username"] == "alice"
    assert "read.audit" in body["by_tenant"]["acme"][0]["grant"]


def test_all_tenants_response_includes_metadata(monkeypatch, tmp_path):
    """Front-end needs all_capabilities + descriptions + role_floor
    in the same response so it can render labels without a 2nd round."""
    app = _build_app(monkeypatch, tmp_path)
    client = TestClient(app)
    r = client.get("/api/capabilities/all-tenants")
    assert r.status_code == 200
    body = r.json()
    assert "all_capabilities" in body
    assert "descriptions" in body
    assert "role_floor" in body
    assert "tenants" in body
    # role_floor values are sorted lists, not sets, for JSON
    for r_name, caps in body["role_floor"].items():
        assert isinstance(caps, list)


def test_all_tenants_endpoint_empty_store(monkeypatch, tmp_path):
    """Fresh install with no grants → 200 with empty by_tenant."""
    app = _build_app(monkeypatch, tmp_path)
    client = TestClient(app)
    r = client.get("/api/capabilities/all-tenants")
    assert r.status_code == 200
    assert r.json()["row_count"] == 0
    assert r.json()["by_tenant"] == {}


def test_all_tenants_history_truncated(monkeypatch, tmp_path):
    """history is capped at last 10 per user — keeps payload small for
    multi-tenant deployments where some users have hundreds of rows."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_ACTIVITY_DISABLED", "1")
    from safecadence.capabilities.store import grant
    for i in range(15):
        # Re-grant the same cap to grow the history (granted-no-op
        # still appends a history row in our store).
        grant("alice", "read.audit", tenant="acme",
               actor=f"cto-{i}", reason=f"r{i}")
    from fastapi import FastAPI
    app = FastAPI()
    from safecadence.ui.v9_pages import register
    register(app)
    client = TestClient(app)
    r = client.get("/api/capabilities/all-tenants")
    assert r.status_code == 200
    rows = r.json()["by_tenant"]["acme"]
    # Re-grants of the same cap keep appending history rows; UI cap=10.
    assert len(rows[0]["history"]) <= 10
