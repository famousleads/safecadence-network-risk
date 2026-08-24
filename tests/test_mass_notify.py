"""Mass Notification — approval gate, consent, adapters, provable log."""
from __future__ import annotations

import json

import pytest


@pytest.fixture(autouse=True)
def _iso(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("SC_NOTIFY_LIVE", raising=False)
    monkeypatch.delenv("SC_SMTP_HOST", raising=False)
    yield tmp_path


def _grp(**kw):
    from safecadence import mass_notify as mn
    base = dict(name="B Shift", members=[
        {"name": "Dep. One", "email": "one@agency.local",
         "phone": "+18135550101", "extension": "1101",
         "sms_gateway": "8135550101@vtext.example"},
        {"name": "Dep. Two", "email": "two@agency.local"},
    ], channels=["email", "sms_gateway"])
    base.update(kw)
    return mn.save_group(**base)


def test_approval_gate_is_mandatory():
    from safecadence import mass_notify as mn
    _grp()
    with pytest.raises(ValueError, match="approved_by"):
        mn.send_notification(group="B Shift", template="lockdown",
                              site="Jail", initiated_by="Sgt V",
                              approved_by="")
    assert mn.alert_log() == []          # nothing logged, nothing sent


def test_templates_and_test_mode_pipeline():
    from safecadence import mass_notify as mn
    _grp()
    out = mn.send_notification(group="B Shift", template="lockdown",
                                site="County Jail", initiated_by="Sgt Vega",
                                approved_by="Lt Ruiz")
    assert out["ok"] and out["mode"] == "test"
    chans = {c["channel"]: c for c in out["channels"]}
    assert chans["email"]["targets"] == 2
    assert chans["sms_gateway"]["targets"] == 1
    log = mn.alert_log()
    assert len(log) == 1
    assert "LOCKDOWN - County Jail" in log[0]["subject"]
    assert log[0]["approved_by"] == "Lt Ruiz"
    assert mn.verify_log()["ok"]


def test_community_group_requires_consent():
    from safecadence import mass_notify as mn
    with pytest.raises(ValueError, match="consent"):
        mn.save_group(name="Residents", community=True, members=[
            {"name": "Jane", "email": "j@x.example"}])
    grp = mn.save_group(name="Residents", community=True, members=[
        {"name": "Jane", "email": "j@x.example", "consent_confirmed": True}])
    assert grp["members"][0]["consent_confirmed"] is True
    out = mn.send_notification(group="Residents", template="shelter",
                                site="Downtown", initiated_by="EOC",
                                approved_by="Chief Ada")
    assert out["ok"]


def test_alert_bridge_and_telephony_test_mode():
    from safecadence import mass_notify as mn
    _grp(name="All Hands", channels=["asterisk", "informacast",
                                       "alert_bridge"])
    mn.save_channel_config("alert_bridge", {
        "provider": "everbridge", "url": "https://alerts.example/api"})
    out = mn.send_notification(group="All Hands", subject="Drill",
                                body="This is a drill.",
                                initiated_by="Ops", approved_by="Lt R")
    chans = {c["channel"]: c for c in out["channels"]}
    assert chans["asterisk"]["mode"] == "test"
    assert chans["asterisk"]["targets"] == 1     # one member has an extension
    assert chans["alert_bridge"]["provider"] == "everbridge"
    assert chans["informacast"]["mode"] == "test"


def test_log_chain_is_tamper_evident(tmp_path):
    from safecadence import mass_notify as mn
    _grp()
    for i in range(3):
        mn.send_notification(group="B Shift", subject=f"s{i}", body="b",
                              initiated_by="a", approved_by="b")
    assert mn.verify_log() == {"ok": True, "entries": 3}
    f = tmp_path / "notify" / "alert-log.jsonl"
    lines = f.read_text().strip().splitlines()
    e = json.loads(lines[1])
    e["subject"] = "REWRITTEN HISTORY"
    lines[1] = json.dumps(e)
    f.write_text("\n".join(lines) + "\n")
    v = mn.verify_log()
    assert v["ok"] is False and v["reason"] in ("entry tampered",
                                                  "chain broken")


def test_unknown_group_and_template():
    from safecadence import mass_notify as mn
    _grp()
    with pytest.raises(KeyError):
        mn.send_notification(group="Nope", subject="x", body="y",
                              initiated_by="a", approved_by="b")
    with pytest.raises(ValueError, match="unknown template"):
        mn.send_notification(group="B Shift", template="klaxon",
                              initiated_by="a", approved_by="b")


def test_summary_shape():
    from safecadence import mass_notify as mn
    _grp()
    s = mn.summary()
    assert s["groups"] == 1 and s["members"] == 2
    assert "asterisk" in s["channels_available"]
    assert "alert_bridge" in s["channels_available"]
    assert s["live_mode"] is False and s["log_ok"] is True


def test_routes_gated_and_serving(_iso):
    fastapi = pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from safecadence.license import start_trial
    from safecadence.ui.desat_pages import register
    start_trial("public_safety")
    _grp()
    app = fastapi.FastAPI()
    register(app)
    c = TestClient(app)
    assert c.get("/notify").status_code == 200
    assert "Mass Notification" in c.get("/notify").text
    r = c.get("/api/v1/desat/notify")
    assert r.status_code == 200 and r.json()["groups"] == 1
    r = c.post("/api/v1/desat/notify/send", json={
        "group": "B Shift", "template": "evacuation", "site": "HQ",
        "initiated_by": "web", "approved_by": "Lt Ruiz"})
    assert r.status_code == 200 and r.json()["mode"] == "test"
    # approval gate enforced at the API boundary
    r = c.post("/api/v1/desat/notify/send", json={
        "group": "B Shift", "subject": "x", "body": "y",
        "initiated_by": "web", "approved_by": ""})
    assert r.status_code == 400
