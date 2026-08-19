"""
DESAT — sheriff demo tenant + native UI pages.

Covers:
  demo:  fleet shape (every asset geo-tagged + agency-stamped), the 5
         scenario assets, loader idempotency (incl. --overwrite), the
         evidence-health + geojson engines fed by the real fleet
  ui:    /map, /evidence-infrastructure, /incidents render inside the
         v9 chrome; /api/v1/desat/* endpoints serve the seeded data
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SAFECADENCE_HOME", str(tmp_path))
    monkeypatch.setenv("SC_PLATFORM_STORE", str(tmp_path / "platform_assets"))
    from safecadence.events.store import reset_for_tests
    reset_for_tests()
    yield


# ============================================================ fleet


def test_fleet_every_asset_geotagged_and_agency_stamped():
    from safecadence.demo_sheriff import AGENCY, build_sheriff_fleet
    fleet = build_sheriff_fleet()
    assert len(fleet) >= 20
    for a in fleet:
        ps = a["public_safety"]
        assert ps["agency"] == AGENCY
        assert ps["latitude"] and ps["longitude"]
        assert "demo:sheriff" in a["identity"]["tags"]


def test_fleet_contains_all_five_scenarios():
    from safecadence.demo_sheriff import build_sheriff_fleet
    by_id = {a["identity"]["asset_id"]: a for a in build_sheriff_fleet()}
    # S1 — degraded district switch + its dead cameras
    assert by_id["sh-sw-d1-01"]["health"]["risk_band"] == "critical"
    assert by_id["sh-cam-d1-lot-1"]["health"]["overall_score"] <= 30
    # S2 — evidence NAS at 91% with degraded replication
    st = by_id["sh-evid-nas-01"]["storage"]
    assert st["used_capacity_tb"] / st["total_capacity_tb"] > 0.85
    assert st["replication_status"] == "degraded"
    # S3 — KEV on the VMS
    assert by_id["sh-vms-01"]["security"]["kev_cves"] == 1
    # S4 — CAD cert expiring
    assert any("certificate" in f.lower() for f in
                by_id["sh-cad-01"]["compliance_signals"]["weak_config_findings"])
    # S5 — identity provider present
    assert by_id["sh-idp-entra"]["identity_block"]["provider"] == "entra"


def test_evidence_roles_cover_all_chain_stages():
    from safecadence.demo_sheriff import build_sheriff_fleet
    from safecadence.platform.evidence_health import STAGES
    roles: set[str] = set()
    for a in build_sheriff_fleet():
        roles.update(a["public_safety"]["evidence_roles"])
    assert roles.issuperset(STAGES)


# ============================================================ loader


def test_loader_writes_seeds_and_is_idempotent(tmp_path):
    from safecadence.demo_sheriff import load_sheriff_demo
    from safecadence.incidents.store import list_incidents
    store = tmp_path / "platform_assets"
    r1 = load_sheriff_demo(target_dir=store)
    assert r1["written"] >= 20
    assert r1["events_seeded"] == 5
    assert r1["incidents_seeded"] == 5
    assert len(list_incidents()) == 5
    # plain re-run: nothing new
    r2 = load_sheriff_demo(target_dir=store)
    assert r2["written"] == 0
    assert r2["incidents_seeded"] == 0
    # --overwrite re-run: assets rewritten, incidents still not duplicated
    r3 = load_sheriff_demo(target_dir=store, overwrite=True)
    assert r3["written"] >= 20
    assert r3["incidents_seeded"] == 0
    assert len(list_incidents()) == 5


def test_scenario_incident_statuses():
    from safecadence.demo_sheriff import load_sheriff_demo
    from safecadence.incidents.store import list_incidents
    load_sheriff_demo()
    statuses = {i["title"][:20]: i["status"] for i in list_incidents()}
    joined = {i["status"] for i in list_incidents()}
    # The five scenarios land in five distinct lifecycle states.
    assert joined == {"open", "investigating", "acknowledged", "resolved"}
    resolved = [i for i in list_incidents(status="resolved")]
    assert len(resolved) == 1
    assert "Identity provider" in resolved[0]["title"]


def test_clear_removes_only_sheriff_assets(tmp_path):
    from safecadence.demo_sheriff import clear_sheriff_demo, load_sheriff_demo
    store = tmp_path / "platform_assets"
    store.mkdir(parents=True, exist_ok=True)
    (store / "other-asset.json").write_text('{"identity": {"tags": []}}')
    load_sheriff_demo(target_dir=store)
    r = clear_sheriff_demo(target_dir=store)
    assert r["removed"] >= 20
    assert (store / "other-asset.json").exists()


# ============================================================ engines on the fleet


def test_evidence_health_over_sheriff_fleet():
    from safecadence.demo_sheriff import build_sheriff_fleet
    from safecadence.platform.evidence_health import (
        evidence_infrastructure_summary,
    )
    s = evidence_infrastructure_summary(build_sheriff_fleet())
    assert s["overall_status"] == "critical"          # S1 + S3 guarantee it
    assert s["stages"]["store"]["status"] == "critical"   # replication degraded
    assert s["stages"]["capture"]["status"] == "critical"  # dead d1 cameras
    assert s["stages"]["preserve"]["status"] in ("warning", "critical")  # RPO
    assert s["stages_covered"] == 5


def test_geojson_over_sheriff_fleet():
    from safecadence.demo_sheriff import build_sheriff_fleet
    from safecadence.platform.geo_api import assets_geojson
    fleet = build_sheriff_fleet()
    gj = assets_geojson(fleet)
    assert len(gj["features"]) == len(fleet)          # every asset geo-tagged
    assert gj["properties"]["assets_without_geo"] == 0
    crit = assets_geojson(fleet, risk_band="critical")
    ids = {f["properties"]["asset_id"] for f in crit["features"]}
    assert {"sh-sw-d1-01", "sh-vms-01"}.issubset(ids)


# ============================================================ UI pages


@pytest.fixture()
def ui_client(tmp_path):
    fastapi = pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from safecadence.demo_sheriff import load_sheriff_demo
    from safecadence.ui.desat_pages import register
    load_sheriff_demo(target_dir=tmp_path / "platform_assets")
    app = fastapi.FastAPI()
    register(app)
    return TestClient(app)


def test_pages_render_in_chrome(ui_client):
    for path, marker in (("/map", "Asset map"),
                           ("/evidence-infrastructure", "Evidence infrastructure"),
                           ("/incidents", "Incidents")):
        r = ui_client.get(path)
        assert r.status_code == 200
        assert marker in r.text
        # the v9 chrome shell is present (sidebar + palette)
        assert "sc-sidebar" in r.text
        assert "SafeCadence" in r.text


def test_desat_geo_api_serves_fleet(ui_client):
    r = ui_client.get("/api/v1/desat/geo")
    assert r.status_code == 200
    gj = r.json()
    assert gj["type"] == "FeatureCollection"
    assert len(gj["features"]) >= 20


def test_desat_evidence_health_api(ui_client):
    r = ui_client.get("/api/v1/desat/evidence-health")
    assert r.status_code == 200
    body = r.json()
    assert body["overall_status"] == "critical"
    assert body["stages_covered"] == 5


def test_desat_incidents_api_list_and_detail(ui_client):
    r = ui_client.get("/api/v1/desat/incidents")
    assert r.status_code == 200
    incs = r.json()["incidents"]
    assert len(incs) == 5
    detail = ui_client.get(
        f"/api/v1/desat/incidents?id={incs[0]['incident_id']}").json()
    assert detail["incident_id"] == incs[0]["incident_id"]
    assert detail["timeline"]
