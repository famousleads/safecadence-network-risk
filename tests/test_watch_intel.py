"""Watch Intelligence — the deterministic dot-connector.

No AI key in the test env, so every path exercises the grounded
deterministic engine + fallback note (exactly what ships by default).
"""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _iso(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_PLATFORM_STORE", str(tmp_path / "platform_assets"))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    yield tmp_path


def _asset(host, site, atype, status="online", score=90, ps_cat=None,
           storage=None):
    a = {"identity": {"hostname": host, "asset_id": host, "site": site,
                       "asset_type": atype, "operational_status": status},
         "health": {"overall_score": score}}
    if ps_cat:
        a["public_safety"] = {"ps_category": ps_cat}
    if storage:
        a["storage"] = storage
    return a


def _cluster_fleet():
    """2 dark cameras + a dark door at ONE school, plus the site switch
    degraded (the root cause), plus a healthy control site."""
    return [
        _asset("cam-gym", "lincoln", "camera", "offline", 10, "camera"),
        _asset("cam-hall", "lincoln", "camera", "offline", 12, "camera"),
        _asset("door-front", "lincoln", "door_controller", "offline", 15,
                "door_controller"),
        _asset("sw-lincoln-1", "lincoln", "switch", "degraded", 30),
        _asset("cam-ok", "adams", "camera", "online", 95, "camera"),
        _asset("nvr-1", "district", "vms", "online", 80, "vms",
                storage={"total_capacity_tb": 100, "used_capacity_tb": 92,
                          "replication_status": "degraded"}),
    ]


def test_site_cluster_names_the_root_cause_switch():
    from safecadence.evidencewatch import build_report
    from safecadence.watch_intel import connect_dots
    r = build_report(_cluster_fleet(), profile="campus")
    cs = connect_dots(r, _cluster_fleet(), "campus")
    cluster = [c for c in cs if c["kind"] == "site_cluster"]
    assert cluster, f"no site_cluster in {[c['kind'] for c in cs]}"
    assert "sw-lincoln-1" in cluster[0]["headline"]
    assert cluster[0]["severity"] == "critical"
    assert any("sw-lincoln-1" in e for e in cluster[0]["evidence"])


def test_video_and_door_blind_site_detected():
    from safecadence.evidencewatch import build_report
    from safecadence.watch_intel import connect_dots
    r = build_report(_cluster_fleet(), profile="campus")
    cs = connect_dots(r, _cluster_fleet(), "campus")
    vd = [c for c in cs if c["kind"] == "video_and_door"]
    assert vd and "lincoln" in vd[0]["headline"]


def test_recorder_double_exposure():
    from safecadence.evidencewatch import build_report
    from safecadence.watch_intel import connect_dots
    r = build_report(_cluster_fleet(), profile="campus")
    cs = connect_dots(r, _cluster_fleet(), "campus")
    rd = [c for c in cs if c["kind"] == "recorder_double_exposure"]
    assert rd and "nvr-1" in rd[0]["headline"]
    assert "92" in rd[0]["headline"]


def test_incident_at_blind_site_correlates():
    from safecadence.evidencewatch import build_report
    from safecadence.incidents.store import create_incident
    from safecadence.watch_intel import connect_dots
    create_incident("Vandalism report at gym", severity="high",
                     site="lincoln")
    r = build_report(_cluster_fleet(), profile="campus")
    cs = connect_dots(r, _cluster_fleet(), "campus")
    ib = [c for c in cs if c["kind"] == "incident_blind_site"]
    assert ib and "Vandalism" in ib[0]["headline"]
    assert "no video record" in ib[0]["recommendation"]


def test_community_leads_correlation():
    from safecadence import community
    from safecadence.evidencewatch import build_report
    from safecadence.incidents.store import create_incident
    from safecadence.watch_intel import connect_dots
    community.register_camera(
        owner_name="Neighbor", contact="555", address="near gym",
        latitude=27.95, longitude=-82.46, consent_confirmed=True)
    create_incident("Break-in", severity="critical", site="elsewhere")
    r = build_report(_cluster_fleet(), profile="agency")
    cs = connect_dots(r, _cluster_fleet(), "agency")
    cl = [c for c in cs if c["kind"] == "community_leads"]
    assert cl and "1 registered community" in cl[0]["headline"]


def test_healthy_fleet_yields_no_correlations_and_honest_note():
    from safecadence.evidencewatch import build_report
    from safecadence.watch_intel import build_intel
    fleet = [_asset("cam-a", "s1", "camera", "online", 95, "camera")]
    r = build_report(fleet, profile="agency")
    intel = build_intel(r, fleet, "agency")
    assert intel["correlations"] == []
    assert intel["ai_generated"] is False
    assert "keep the watch" in intel["note"].lower() or \
        "independent" in intel["note"].lower()


def test_report_embeds_intel_and_renders_it():
    from safecadence.evidencewatch import build_report, render_report_html
    r = build_report(_cluster_fleet(), profile="campus")
    assert r["intel"]["correlation_count"] >= 3
    assert r["intel"]["note"]
    html = render_report_html(r, agency="Test District", profile="campus")
    assert "CONNECTING THE DOTS" in html
    assert "sw-lincoln-1" in html
    assert "computed from device records" in html


def test_facility_profile_end_to_end():
    from safecadence.evidencewatch import PROFILES, build_report, \
        render_report_html
    assert "facility" in PROFILES
    r = build_report(_cluster_fleet(), profile="facility")
    assert r["profile"] == "facility"
    # doors are first-class in the facility profile too
    assert any(d["type"] == "door_controller" for d in r["dark"])
    html = render_report_html(r, agency="Westfield Galleria",
                               profile="facility")
    assert "FACILITYWATCH" in html
    assert "PER-BUILDING COVERAGE" in html
    assert "Westfield Galleria" in html
    # no law-enforcement framing for commercial buyers
    assert "suppression hearing" not in html
