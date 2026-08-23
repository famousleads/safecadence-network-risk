"""Retention engine + immutable purge log (RFP 4.10.2.3 scored item)."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest


@pytest.fixture(autouse=True)
def _iso(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    yield tmp_path


def _old_day(days_ago: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).strftime("%Y%m%d")


def _seed_events(tmp_path, days_ago: int, n: int = 3):
    f = tmp_path / f"events-{_old_day(days_ago)}.jsonl"
    f.write_text("\n".join(json.dumps({"i": i}) for i in range(n)))
    return f


def _seed_incident(tmp_path, iid: str, status: str, closed_days_ago: int):
    d = tmp_path / "incidents"; d.mkdir(exist_ok=True)
    closed = (datetime.now(timezone.utc) -
               timedelta(days=closed_days_ago)).isoformat()
    (d / f"{iid}.json").write_text(json.dumps(
        {"incident_id": iid, "status": status, "closed_at": closed}))


def test_policy_defaults_and_preset(_iso):
    from safecadence.platform import retention as rt
    p = rt.load_policy()
    assert p["events"]["days"] >= 365
    applied = rt.apply_preset("fl_public_records", actor="test")
    assert applied["closed_incidents"]["days"] == 1460
    assert rt.load_policy()["events"]["basis"].startswith("FL")
    with pytest.raises(KeyError):
        rt.apply_preset("nope")
    with pytest.raises(ValueError):
        rt.save_policy({"events": {"days": 0}})


def test_evaluate_finds_only_aged_records(_iso):
    from safecadence.platform import retention as rt
    rt.save_policy({"events": {"days": 30},
                     "closed_incidents": {"days": 60}}, actor="test")
    _seed_events(_iso, days_ago=45)              # due
    _seed_events(_iso, days_ago=5)               # keep
    _seed_incident(_iso, "inc-old", "resolved", 90)    # due
    _seed_incident(_iso, "inc-new", "resolved", 10)    # keep
    _seed_incident(_iso, "inc-open", "open", 400)      # NEVER (not closed)
    due = rt.evaluate()["due"]
    assert due["events"]["count"] == 1
    assert due["closed_incidents"]["files"] == ["inc-old.json"]


def test_run_purges_and_logs_chain(_iso):
    from safecadence.platform import retention as rt
    rt.save_policy({"events": {"days": 30},
                     "closed_incidents": {"days": 60}}, actor="test")
    old = _seed_events(_iso, days_ago=45)
    keep = _seed_events(_iso, days_ago=5)
    _seed_incident(_iso, "inc-old", "closed", 90)
    # rehearse first — logged, nothing deleted
    r1 = rt.run(dry_run=True, actor="test")
    assert old.exists() and keep.exists()
    assert r1["results"]["events"]["dry_run"] is True
    # real run — aged records gone, fresh kept
    r2 = rt.run(dry_run=False, actor="test")
    assert not old.exists() and keep.exists()
    assert not (_iso / "incidents" / "inc-old.json").exists()
    assert r2["log_verified"] is True
    # chain has entries for both runs and verifies
    v = rt.verify_log()
    assert v["ok"] and v["entries"] >= 3


def test_purge_log_is_tamper_evident(_iso):
    from safecadence.platform import retention as rt
    rt.save_policy({"events": {"days": 30}}, actor="test")
    _seed_events(_iso, days_ago=45)
    rt.run(dry_run=False, actor="test")
    _seed_events(_iso, days_ago=50)
    rt.run(dry_run=False, actor="test")
    assert rt.verify_log()["ok"]
    log = _iso / "purge-log.jsonl"
    lines = log.read_text().splitlines()
    # 1) edit a field -> hash mismatch
    e = json.loads(lines[0]); e["count"] = 999
    log.write_text("\n".join([json.dumps(e, sort_keys=True)] + lines[1:]) + "\n")
    assert rt.verify_log()["ok"] is False
    # 2) delete an entry -> chain break
    log.write_text("\n".join(lines[1:]) + "\n")
    assert rt.verify_log()["ok"] is False
    # 3) restore -> verifies again
    log.write_text("\n".join(lines) + "\n")
    assert rt.verify_log()["ok"] is True


def test_status_shape(_iso):
    from safecadence.platform import retention as rt
    s = rt.status()
    assert set(s) >= {"policy", "due", "log", "policy_file", "log_file"}
    assert s["log"]["ok"] is True                # empty chain verifies
