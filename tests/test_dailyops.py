"""Daily-ops wave: SafeCheck, custody, roll-call, env/ALPR situations."""
from __future__ import annotations

import json

import pytest


@pytest.fixture(autouse=True)
def _iso(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("SC_NOTIFY_LIVE", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    yield tmp_path


# ---------------------------------------------------------------- safecheck

def test_safecheck_lifecycle_and_preauthorized_alert():
    from safecadence import mass_notify, safecheck
    mass_notify.save_group(name="B Shift", members=[
        {"name": "Dep. One", "email": "one@agency.local"}])
    r = safecheck.start_check(officer="Dep. Vega",
                                location="Warehouse row 3",
                                minutes=1, notify_group="B Shift")
    assert r["pre_authorized_by"] == "Dep. Vega"
    assert len(safecheck.list_active()) == 1
    # force overdue by rewriting due_at into the past
    f = safecheck._active_file(r["check_id"])
    rec = json.loads(f.read_text())
    rec["due_at"] = "2020-01-01T00:00:00+00:00"
    f.write_text(json.dumps(rec))
    out = safecheck.sweep()
    assert out["alerts_fired"] and out["alerts_fired"][0]["sent"] is True
    assert out["alerts_fired"][0]["mode"] == "test"
    # alert fires once only
    assert safecheck.sweep()["alerts_fired"] == []
    # the notification carries the pre-authorization
    log = mass_notify.alert_log(1)[0]
    assert "SAFECHECK OVERDUE" in log["subject"]
    assert "pre-authorized at check start" in log["approved_by"]
    # clear + chain verify
    safecheck.clear_check(r["check_id"], "Dep. Vega")
    assert safecheck.list_active() == []
    assert safecheck.verify_log()["ok"]


def test_safecheck_requires_officer_and_location():
    from safecadence import safecheck
    with pytest.raises(ValueError):
        safecheck.start_check(officer="", location="x")
    with pytest.raises(ValueError):
        safecheck.start_check(officer="A", location="")


# ---------------------------------------------------------------- custody

def test_custody_full_chain_and_tamper_evidence(tmp_path):
    from safecadence import custody
    item = custody.add_item(case_number="26-4411",
                              description="Sealed envelope, 1 phone",
                              category="digital_media",
                              storage_location="Shelf B-14",
                              entered_by="Tech Ruiz")
    with pytest.raises(ValueError, match="purpose"):
        custody.checkout(item["item_id"], officer="Det. Cho", purpose="")
    custody.checkout(item["item_id"], officer="Det. Cho", purpose="lab")
    with pytest.raises(ValueError, match="already checked out"):
        custody.checkout(item["item_id"], officer="X", purpose="court")
    custody.checkin(item["item_id"], officer="Det. Cho",
                     note="returned from lab")
    with pytest.raises(ValueError, match="authority"):
        custody.dispose(item["item_id"], officer="Tech Ruiz",
                         authority="", method="destruction")
    custody.dispose(item["item_id"], officer="Tech Ruiz",
                     authority="Court order 26-4411-D",
                     method="destruction")
    hist = custody.item_history(item["item_id"])
    assert [e["action"] for e in hist["history"]] == [
        "checked_out", "checked_in", "disposed"]
    assert custody.verify_log()["ok"]
    # tamper the chained log -> verify fails
    f = tmp_path / "custody" / "custody-log.jsonl"
    lines = f.read_text().strip().splitlines()
    e = json.loads(lines[1])
    e["officer"] = "Somebody Else"
    lines[1] = json.dumps(e)
    f.write_text("\n".join(lines) + "\n")
    assert custody.verify_log()["ok"] is False


# ---------------------------------------------------------------- rollcall

def test_rollcall_brief_gathers_and_renders():
    from safecadence import custody, rollcall, safecheck, situation
    from safecadence.incidents.store import create_incident
    situation.ingest_video_event({"event_type": "door_forced",
                                    "site": "evidence-facility"})
    situation.ingest_video_event({"event_type": "person",
                                    "site": "evidence-facility"})
    create_incident("Vandalism at gym", severity="high", site="lincoln")
    safecheck.start_check(officer="Dep. A", location="North lot",
                            minutes=30)
    custody.add_item(case_number="26-1", description="Item",
                      storage_location="A-1", entered_by="T")
    b = rollcall.build_brief()
    assert b["situation_count"] >= 1
    assert b["incident_count"] == 1
    assert b["safechecks_active"] == 1
    assert b["custody"]["items"] == 1
    assert b["note"]["ai_generated"] is False
    assert "Start with:" in b["note"]["text"]
    html = rollcall.render_brief_html(b, agency="Cypress County SO",
                                       shift="day")
    assert "ROLL-CALL BRIEF" in html and "Cypress County SO" in html
    assert "Vandalism at gym" in html


def test_rollcall_quiet_morning_is_honest():
    from safecadence import rollcall
    b = rollcall.build_brief()
    assert "Quiet overnight" in b["note"]["text"]


# ---------------------------------------------------------------- situations+

def test_environmental_card_escalates_for_evidence_room():
    from safecadence import situation as st
    st.ingest_video_event({"event_type": "temperature",
                             "site": "evidence-facility",
                             "note": "78F rising, threshold 72F"})
    st.ingest_video_event({"event_type": "water_leak", "site": "north-lot"})
    cards = st.assess(30, after_hours=False)
    env = [c for c in cards if c["kind"] == "environment"]
    assert len(env) == 2
    sev = {c["site"]: c["severity"] for c in env}
    assert sev["evidence-facility"] == "critical"
    assert sev["north-lot"] == "medium"


def test_alpr_card_is_verify_first():
    from safecadence import situation as st
    st.ingest_video_event({"type": "plate_hit", "site": "sr-60-east",
                             "vendor": "flock",
                             "note": "hotlist match - stolen vehicle"})
    cards = st.assess(30, after_hours=False)
    v = [c for c in cards if c["kind"] == "vehicle_of_interest"]
    assert v and v[0]["severity"] == "high"
    assert "not probable cause" in v[0]["recommended_action"]


# ---------------------------------------------------------------- routes

def test_dailyops_routes(_iso):
    fastapi = pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from safecadence.license import start_trial
    from safecadence.ui.desat_pages import register
    start_trial("public_safety")
    app = fastapi.FastAPI()
    register(app)
    c = TestClient(app)
    r = c.post("/api/v1/desat/safecheck/start", json={
        "officer": "Dep. Web", "location": "Lobby", "minutes": 20})
    assert r.status_code == 200
    cid = r.json()["check_id"]
    assert c.get("/api/v1/desat/safecheck").json()["summary"]["active"] == 1
    assert c.post("/api/v1/desat/safecheck/clear",
                   json={"check_id": cid}).status_code == 200
    r = c.post("/api/v1/desat/custody/items", json={
        "case_number": "26-9", "description": "USB drive",
        "storage_location": "B-2", "entered_by": "T"})
    assert r.status_code == 200
    assert c.get("/api/v1/desat/custody").json()["summary"]["items"] == 1
    assert c.get("/rollcall").status_code == 200
    assert "ROLL-CALL BRIEF" in c.get("/rollcall").text
    assert c.get("/safecheck").status_code == 200
    assert c.get("/custody").status_code == 200
