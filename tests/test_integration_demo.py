"""The demo exercises real offline importers but exposes no customer state."""
import json
import socket
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from safecadence.ui.integration_pages import _snapshot, demo_snapshot, register


@pytest.fixture
def client():
    app = FastAPI()
    register(app)
    with TestClient(app) as c:
        yield c


@pytest.mark.parametrize("mode,count,sources", [("security", 4, 4), ("safety", 9, 5)])
def test_demo_real_imports_without_network(mode, count, sources):
    _snapshot.cache_clear()
    with patch.object(socket, "socket", side_effect=AssertionError("no network")):
        data = demo_snapshot(mode)
    assert data["sample_data"] and not data["live_connector"] and not data["controls_enabled"]
    assert len(data["events"]) == count
    assert len(data["sources"]) == sources
    assert data["audit"]["chain_valid"]
    failures = [r for r in data["audit"]["records"] if r["status"] == "rejected"]
    assert len(failures) == 1 and failures[0]["recommendation"]
    assert all(s["sensor_health"] == "unknown" for s in data["sources"])
    data["events"].clear()
    assert len(demo_snapshot(mode)["events"]) == count


@pytest.mark.parametrize("mode", ["security", "safety"])
def test_routes_are_get_only(client, mode):
    api = "/api/integration-demo/" + mode
    response = client.get(api)
    assert response.status_code == 200 and response.headers["cache-control"] == "no-store"
    assert response.json()["sample_data"]
    assert client.post(api, json={"command": "unlock"}).status_code == 405
    assert client.delete(api).status_code == 405
    page = client.get("/" + mode + "-integrations")
    assert page.status_code == 200
    assert "SIMULATED SAMPLE DATA" in page.text
    assert "Download sample report" in page.text
    assert "textContent" in page.text


def test_unknown_demo_has_no_path_or_tenant_access(client):
    assert client.get("/api/integration-demo/production").status_code == 404
    response = client.get("/api/integration-demo/security?tenant=customer&path=/etc/passwd")
    assert {e["tenant"] for e in response.json()["events"]} == {"synthetic-demo"}
    assert "root:" not in json.dumps(response.json())


def test_brand_observations_never_verified():
    data = demo_snapshot("safety")
    brands = [r for r in data["events"] if r["source"] in ("sherlock", "maigret")]
    assert len(brands) == 2
    assert all(r["review"]["decision"] == "unreviewed" and not r["review"]["identity_verified"] for r in brands)
