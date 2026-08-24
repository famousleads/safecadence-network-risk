"""Situation Analytics — normalization, correlation rules, honesty."""
from __future__ import annotations

from datetime import timedelta

import pytest


@pytest.fixture(autouse=True)
def _iso(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    yield tmp_path


def _ev(**kw):
    from safecadence import situation as st
    base = dict(event_type="person", site="hq", camera="cam-1",
                 vendor="edge", confidence=0.9)
    base.update(kw)
    return st.ingest_video_event(base)


def test_normalization_aliases_and_bounds():
    from safecadence import situation as st
    r = st.ingest_video_event({"type": "Gun-Detected", "confidence": "1.7",
                                 "location": "school", "source": "zx-1",
                                 "vendor": "zeroeyes"})
    assert r["event_type"] == "weapon"
    assert r["confidence"] == 1.0
    assert r["site"] == "school" and r["camera"] == "zx-1"
    r2 = st.ingest_video_event({"topic": "LineCrossing"})
    assert r2["event_type"] == "line_cross"
    r3 = st.ingest_video_event({"event_type": "quantum_flux"})
    assert r3["event_type"] == "other"


def test_weapon_card_is_critical_and_prepares_not_sends():
    from safecadence import situation as st
    _ev(event_type="weapon", site="lincoln-middle", vendor="zeroeyes")
    cards = st.assess(30, after_hours=False)
    w = [c for c in cards if c["kind"] == "weapon_detected"]
    assert w and w[0]["severity"] == "critical"
    assert "named approver" in w[0]["recommended_action"]


def test_breakin_correlation_door_plus_person():
    from safecadence import situation as st
    _ev(event_type="door_forced", site="evidence-facility")
    _ev(event_type="person", site="evidence-facility", camera="cam-2")
    _ev(event_type="person", site="somewhere-else")
    cards = st.assess(30, after_hours=False)
    b = [c for c in cards if c["kind"] == "possible_breakin"]
    assert len(b) == 1
    assert b[0]["site"] == "evidence-facility"
    assert len(b[0]["evidence"]) >= 2


def test_after_hours_cluster_only_after_hours():
    from safecadence import situation as st
    for _ in range(3):
        _ev(event_type="person", site="district-north")
    day = st.assess(30, after_hours=False)
    night = st.assess(30, after_hours=True)
    assert not [c for c in day if c["kind"] == "after_hours_cluster"]
    assert [c for c in night if c["kind"] == "after_hours_cluster"]


def test_tamper_escalates_with_dark_neighbor():
    from safecadence import situation as st
    _ev(event_type="tamper", site="county-jail")
    plain = st.assess(30, after_hours=False)
    assert [c for c in plain if c["kind"] == "camera_interference"
             and c["severity"] == "high"]
    assets = [{"identity": {"site": "county-jail", "hostname": "cam-x",
                              "operational_status": "offline"}}]
    esc = st.assess(30, assets=assets, after_hours=False)
    assert [c for c in esc if c["kind"] == "camera_interference"
             and c["severity"] == "critical"]


def test_quiet_window_is_honestly_quiet():
    from safecadence import situation as st
    _ev(event_type="motion", site="hq")          # one event, no pattern
    cards = st.assess(30, after_hours=False)
    assert cards == []
    note = st.situation_note(cards)
    assert "Quiet" in note["note"] and note["ai_generated"] is False


def test_demo_seed_lights_every_rule():
    from safecadence import situation as st
    out = st.seed_demo(after_hours=True)
    assert out["seeded"] >= 10
    cards = st.assess(30, after_hours=True)
    kinds = {c["kind"] for c in cards}
    assert {"possible_breakin", "after_hours_cluster",
             "camera_interference", "crowd_building",
             "persistent_loitering"} <= kinds


def test_routes_gated_and_serving(_iso):
    fastapi = pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from safecadence.license import start_trial
    from safecadence.ui.desat_pages import register
    start_trial("public_safety")
    app = fastapi.FastAPI()
    register(app)
    c = TestClient(app)
    r = c.post("/api/v1/desat/video-event",
                json={"event_type": "person", "site": "hq"})
    assert r.status_code == 200 and r.json()["event_type"] == "person"
    r = c.get("/api/v1/desat/situations?window=30")
    assert r.status_code == 200
    assert r.json()["summary"]["events_in_window"] == 1
    assert "ai_use_policy" in r.json()["summary"]
    page = c.get("/situations")
    assert page.status_code == 200
    assert "Situation Analytics" in page.text
    assert "never watch video" in page.text
