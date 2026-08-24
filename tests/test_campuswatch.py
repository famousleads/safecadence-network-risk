"""CampusWatch — the school-district skin of the wedge engine."""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _iso(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_PLATFORM_STORE", str(tmp_path / "platform_assets"))
    yield tmp_path


def _fleet():
    from safecadence.demo_campus import build_campus_fleet
    return build_campus_fleet()


def test_campus_report_watches_doors_and_groups_by_school():
    from safecadence.evidencewatch import build_report
    r = build_report(_fleet(), profile="campus")
    assert r["profile"] == "campus"
    types = {d["type"] for d in r["dark"]}
    assert "access_control" in types            # offline door controller
    assert "camera" in types                    # dark gym camera
    assert len(r["sites"]) >= 3                 # per-school rollup
    dark_schools = {x["site"] for x in r["sites"] if x["dark"]}
    assert {"lincoln-middle", "roosevelt-high"} <= dark_schools
    healthy = [x for x in r["sites"] if x["site"] == "jefferson-elem"][0]
    assert healthy["dark"] == 0
    assert "door" in r["action"].lower() or "camera" in r["action"].lower()


def test_agency_profile_ignores_doors():
    from safecadence.evidencewatch import build_report
    r = build_report(_fleet(), profile="agency")
    assert all(d["type"] != "access_control" for d in r["dark"])


def test_campus_render_has_school_table_and_no_le_jargon():
    from safecadence.evidencewatch import build_report, render_report_html
    r = build_report(_fleet(), profile="campus")
    html = render_report_html(r, agency="Cypress County Public Schools",
                                profile="campus")
    assert "CAMPUSWATCH" in html
    assert "PER-SCHOOL COVERAGE" in html
    assert "roosevelt-high" in html
    assert "EVIDENCE CHAIN" not in html         # LE framing dropped
    assert "suppression hearing" not in html
    assert "no student\n data is touched" in html or "no student" in html


def test_campus_chain_separate_from_agency(_iso):
    from safecadence import evidencewatch as ew
    ew.snapshot(ew.build_report(_fleet(), profile="campus"), profile="campus")
    assert ew.verify_history("campus")["weeks"] == 1
    assert ew.verify_history("agency")["weeks"] == 0    # separate chains
    assert (_iso / "campuswatch").exists()


def test_campus_ui_routes(_iso):
    fastapi = pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from safecadence.ui.desat_pages import register
    from safecadence.license import start_trial
    start_trial("public_safety")   # trial mode unlocks the gate
    app = fastapi.FastAPI()
    register(app)
    c = TestClient(app)
    r = c.get("/campuswatch?district=Test District&demo=1")
    assert r.status_code == 200 and "CAMPUSWATCH" in r.text
    r = c.get("/api/v1/desat/campuswatch")
    assert r.status_code == 200 and r.json()["profile"] == "campus"
    r = c.get("/campuswatch/audit")
    assert r.status_code == 200 and "Campuswatch Audit Pack" in r.text
