"""Standing Watches — NL parsing, authorization, firing, provable log."""
from __future__ import annotations

import json

import pytest


@pytest.fixture(autouse=True)
def _iso(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("SC_NOTIFY_LIVE", raising=False)
    yield tmp_path


def test_deterministic_parser_understands_plain_english():
    from safecadence import watches as sw
    it = sw.interpret("Tell me whenever a door is forced at any school "
                        "after hours")
    f = it["filter"]
    assert "door_forced" in f["event_types"]
    assert "school" in f["sites"]
    assert f["after_hours_only"] is True
    assert "door_forced" in it["interpretation"]
    assert "school" in it["interpretation"]

    f2 = sw.parse_query("alert me if at least 3 people gather near the "
                          "courthouse within 15 minutes")
    assert "person" in f2["event_types"] or "crowd" in f2["event_types"]
    assert f2["min_count"] == 3
    assert f2["window_minutes"] == 15
    assert "courthouse" in f2["sites"]


def test_watch_requires_named_creator_and_understandable_query():
    from safecadence import watches as sw
    with pytest.raises(ValueError, match="created_by"):
        sw.create_watch(query="weapon anywhere", created_by="")
    with pytest.raises(ValueError, match="could not understand"):
        sw.create_watch(query="xyzzy plugh", created_by="Lt Ruiz")
    w = sw.create_watch(query="weapon detected anywhere",
                         created_by="Lt Ruiz")
    assert w["enabled"] and w["created_by"] == "Lt Ruiz"


def test_watch_fires_once_per_window_with_preauthorized_notify():
    from safecadence import mass_notify, situation, watches as sw
    mass_notify.save_group(name="B Shift", members=[
        {"name": "Dep. One", "email": "one@agency.local"}])
    sw.create_watch(query="door forced at the evidence building",
                     created_by="Lt Ruiz", notify_group="B Shift")
    situation.ingest_video_event({"event_type": "door_forced",
                                    "site": "evidence-facility"})
    cards = sw.check_watches(after_hours=False)
    assert len(cards) == 1
    assert cards[0]["kind"] == "standing_watch"
    assert "Lt Ruiz" in " ".join(cards[0]["evidence"])
    # notification carried the creator's pre-authorization
    log = mass_notify.alert_log(1)[0]
    assert "STANDING WATCH" in log["subject"]
    assert "pre-authorized at watch creation" in log["approved_by"]
    # second check within the window: silent (no alert storm)
    situation.ingest_video_event({"event_type": "door_forced",
                                    "site": "evidence-facility"})
    assert sw.check_watches(after_hours=False) == []
    assert sw.verify_log()["ok"]


def test_disabled_watch_does_not_fire():
    from safecadence import situation, watches as sw
    w = sw.create_watch(query="crowd at the plaza", created_by="Sgt V")
    sw.set_enabled(w["id"], False)
    situation.ingest_video_event({"event_type": "crowd", "site": "plaza"})
    assert sw.check_watches(after_hours=False) == []


def test_after_hours_watch_respects_time_gate():
    from safecadence import situation, watches as sw
    sw.create_watch(query="motion at the depot after hours",
                     created_by="Sgt V")
    situation.ingest_video_event({"event_type": "motion", "site": "depot"})
    assert sw.check_watches(after_hours=False) == []
    assert len(sw.check_watches(after_hours=True)) == 1


def test_fire_log_is_tamper_evident(tmp_path):
    from safecadence import situation, watches as sw
    sw.create_watch(query="vehicle at the gate", created_by="A")
    situation.ingest_video_event({"event_type": "vehicle", "site": "gate"})
    sw.check_watches(after_hours=False)
    assert sw.verify_log() == {"ok": True, "entries": 1}
    f = tmp_path / "watches" / "watch-log.jsonl"
    line = json.loads(f.read_text().strip())
    line["name"] = "REWRITTEN"
    f.write_text(json.dumps(line) + "\n")
    assert sw.verify_log()["ok"] is False


def test_routes_and_situations_merge(_iso):
    fastapi = pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from safecadence import situation
    from safecadence.license import start_trial
    from safecadence.ui.desat_pages import register
    start_trial("public_safety")
    app = fastapi.FastAPI()
    register(app)
    c = TestClient(app)
    r = c.post("/api/v1/desat/watches/preview",
                json={"query": "weapon at any school"})
    assert r.status_code == 200 and "weapon" in r.json()["interpretation"]
    r = c.post("/api/v1/desat/watches", json={
        "query": "weapon at any school", "created_by": "Lt Web"})
    assert r.status_code == 200
    r = c.post("/api/v1/desat/watches", json={
        "query": "weapon at any school", "created_by": ""})
    assert r.status_code == 400
    situation.ingest_video_event({"event_type": "weapon",
                                    "site": "lincoln-school"})
    j = c.get("/api/v1/desat/situations?window=30").json()
    kinds = {s["kind"] for s in j["situations"]}
    assert "standing_watch" in kinds
    assert c.get("/api/v1/desat/watches").json()["summary"]["watches"] == 1
    page = c.get("/situations")
    assert "Standing watches" in page.text
