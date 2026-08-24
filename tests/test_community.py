"""Community layer — consent-based camera registry + watch requests."""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _iso(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    yield tmp_path


def test_consent_is_mandatory():
    from safecadence import community
    with pytest.raises(ValueError, match="consent"):
        community.register_camera(
            owner_name="Jane Doe", contact="555-0100",
            address="12 Oak St", latitude=27.95, longitude=-82.46,
            consent_confirmed=False)
    assert community.list_cameras() == []


def test_register_list_remove_and_near():
    from safecadence import community
    a = community.register_camera(
        owner_name="Jane Doe", contact="555-0100", address="12 Oak St",
        latitude=27.9500, longitude=-82.4600, camera_kind="doorbell",
        consent_confirmed=True)
    community.register_camera(
        owner_name="Far Away", contact="555-0200", address="99 Elm",
        latitude=28.60, longitude=-81.30, consent_confirmed=True)
    assert a["consent_confirmed"] is True and a["consent_recorded_at"]
    assert len(community.list_cameras()) == 2

    # near: ~50m offset is a hit at 500m radius; Orlando is not
    hits = community.cameras_near(27.9504, -82.4600, radius_m=500)
    assert [h["owner_name"] for h in hits] == ["Jane Doe"]
    assert 0 < hits[0]["distance_m"] < 100

    # withdraw consent — soft remove, drops from active list + near()
    community.remove_camera(a["id"], reason="owner withdrew")
    assert len(community.list_cameras()) == 1
    assert community.cameras_near(27.9504, -82.4600, radius_m=500) == []


def test_watch_lifecycle_checks_and_expiry():
    from safecadence import community
    w = community.request_watch(
        requester_name="Bob Smith", contact="555-0300",
        address="7 Pine Ave", latitude=27.96, longitude=-82.45,
        start_date="2026-08-20", end_date="2099-01-01")
    # attributable checks: officer required
    with pytest.raises(ValueError, match="officer"):
        community.log_check(w["id"], officer="")
    community.log_check(w["id"], officer="Dep. Alvarez", note="all quiet")
    community.log_check(w["id"], officer="Dep. Chen")
    got = [x for x in community.list_watches() if x["id"] == w["id"]][0]
    assert len(got["checks"]) == 2
    assert got["checks"][0]["officer"] == "Dep. Alvarez"

    # auto-expire past end_date
    old = community.request_watch(
        requester_name="Past Person", contact="555-0400",
        address="1 Ago Ln", latitude=27.9, longitude=-82.4,
        start_date="2020-01-01", end_date="2020-01-08")
    statuses = {x["id"]: x["status"] for x in community.list_watches()}
    assert statuses[old["id"]] == "expired"
    assert statuses[w["id"]] == "active"

    community.complete_watch(w["id"])
    assert community.list_watches("active") == []


def test_summary_and_map_points():
    from safecadence import community
    community.register_camera(
        owner_name="Cam Owner", contact="c", address="x",
        latitude=27.95, longitude=-82.46, consent_confirmed=True)
    community.request_watch(
        requester_name="Watcher", contact="w", address="y",
        latitude=27.96, longitude=-82.45,
        start_date="2026-01-01", end_date="2099-01-01")
    s = community.summary()
    assert s["registered_cameras"] == 1
    assert s["active_watches"] == 1
    kinds = {p["kind"] for p in s["map_points"]}
    assert kinds == {"registry", "watch"}


def test_bad_inputs_rejected():
    from safecadence import community
    with pytest.raises(ValueError):
        community.register_camera(
            owner_name="X", contact="y", address="z",
            latitude=999, longitude=0, consent_confirmed=True)
    with pytest.raises(ValueError):
        community.request_watch(
            requester_name="X", contact="y", address="z",
            latitude=0, longitude=0,
            start_date="2026-02-01", end_date="2026-01-01")
    with pytest.raises(KeyError):
        community.log_check("wr-doesnotexist1", officer="A")


def test_routes_gated_and_serving(_iso):
    fastapi = pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from safecadence.license import start_trial
    from safecadence.ui.desat_pages import register
    start_trial("public_safety")   # trial mode unlocks the gate
    from safecadence import community
    community.register_camera(
        owner_name="Rt Test", contact="555", address="1 Rd",
        latitude=27.95, longitude=-82.46, consent_confirmed=True)
    app = fastapi.FastAPI()
    register(app)
    c = TestClient(app)
    assert c.get("/community").status_code == 200
    assert "Camera Registry" in c.get("/community").text
    r = c.get("/api/v1/desat/community")
    assert r.status_code == 200 and r.json()["registered_cameras"] == 1
    r = c.get("/api/v1/desat/community/cameras/near",
               params={"lat": 27.95, "lon": -82.46, "radius_m": 500})
    assert r.status_code == 200 and len(r.json()["cameras"]) == 1
    # consent enforced at the API boundary too
    r = c.post("/api/v1/desat/community/cameras", json={
        "owner_name": "No Consent", "contact": "x", "address": "y",
        "latitude": 27.9, "longitude": -82.4, "consent_confirmed": False})
    assert r.status_code == 400
