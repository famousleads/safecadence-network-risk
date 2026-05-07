"""
v9.21 — unit tests for the v9.17/v9.18/v9.19 intel modules.

  - safecadence.intel.coverage         (compute_coverage)
  - safecadence.intel.fleet_changes    (write_snapshot + compute_changes)
  - safecadence.intel.discovery_jobs   (CRUD + due-detection)

These cover the green-path + a couple of edge cases each. They use
SC_DATA_DIR via tmp_path so file-backed state doesn't collide with
the operator's real ~/.safecadence dir.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone, timedelta

import pytest


@pytest.fixture(autouse=True)
def _isolated_data_dir(tmp_path, monkeypatch):
    """Run every test in this file with a fresh SC_DATA_DIR."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    yield


# ------------------------------------------------------------- coverage


def _asset(aid: str, *, src: str = "manual", last_seen: str = "",
           **kwargs) -> dict:
    ident = {"asset_id": aid, "hostname": aid, "discovery_source": src,
             **kwargs}
    if last_seen:
        ident["last_seen"] = last_seen
    return {"identity": ident}


def test_coverage_empty_fleet():
    from safecadence.intel.coverage import compute_coverage
    r = compute_coverage([])
    assert r["totals"]["fleet_size"] == 0
    assert r["score"] == 0
    # All sources reported as never-connected
    assert all(s["estimated_gap"] == "never-connected" for s in r["sources"])


def test_coverage_classifies_known_sources():
    from safecadence.intel.coverage import compute_coverage
    now = datetime.now(timezone.utc).isoformat()
    fleet = [
        _asset("a1", src="lan-scan", last_seen=now),
        _asset("a2", src="snmp-harvest", last_seen=now),
        _asset("a3", src="entra", last_seen=now),
        _asset("a4", src="manual"),
        _asset("a5", src="weird"),     # unknown bucket
    ]
    r = compute_coverage(fleet)
    by_key = {s["key"]: s for s in r["sources"]}
    assert by_key["lan-scan"]["asset_count"] == 1
    assert by_key["snmp"]["asset_count"] == 1
    assert by_key["entra"]["asset_count"] == 1
    assert by_key["manual"]["asset_count"] == 1
    assert by_key["unknown"]["asset_count"] == 1
    assert by_key["lan-scan"]["estimated_gap"] == "fresh"


def test_coverage_score_climbs_with_diversity():
    from safecadence.intel.coverage import compute_coverage
    now = datetime.now(timezone.utc).isoformat()
    one = compute_coverage([_asset("a1", src="manual", last_seen=now)])
    three = compute_coverage([
        _asset("a1", src="manual", last_seen=now),
        _asset("a2", src="snmp-harvest", last_seen=now),
        _asset("a3", src="entra", last_seen=now),
    ])
    assert three["score"] > one["score"]


def test_coverage_recommendations_deep_link_format():
    """v9.20.1: recommendations point at /inventory?open=<key> deep-links."""
    from safecadence.intel.coverage import compute_coverage
    r = compute_coverage([_asset("a1", src="manual")])
    for rec in r["recommendations"]:
        assert rec["cta_url"].startswith("/inventory?open=")
        assert "source_key" in rec


def test_coverage_stale_source_triggers_refresh_rec():
    """An old-enough timestamp should generate a 'Refresh' rec."""
    from safecadence.intel.coverage import compute_coverage
    week_ago = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    r = compute_coverage([_asset("a1", src="snmp", last_seen=week_ago)])
    titles = [rec["title"] for rec in r["recommendations"]]
    assert any("Refresh" in t for t in titles)


# --------------------------------------------------------- fleet_changes


def test_fleet_changes_no_baseline_first_run():
    from safecadence.intel.fleet_changes import compute_changes
    r = compute_changes([_asset("a1"), _asset("a2")])
    assert r["no_baseline"] is True
    assert r["counts"]["added"] == 0
    assert r["counts"]["removed"] == 0
    assert r["counts"]["modified"] == 0


def test_fleet_changes_detects_added_removed_modified():
    from safecadence.intel.fleet_changes import (
        compute_changes, write_snapshot,
    )
    yesterday = datetime.now(timezone.utc) - timedelta(days=1)
    # Yesterday: 3 assets
    write_snapshot([
        _asset("router-1", asset_type="network", vendor="cisco"),
        _asset("router-2", asset_type="network", vendor="arista"),
        _asset("server-1", asset_type="server", vendor="dell"),
    ], when=yesterday)
    # Today: router-1 changed vendor, router-2 same, server-1 removed,
    # new switch added.
    today = [
        _asset("router-1", asset_type="network", vendor="juniper"),
        _asset("router-2", asset_type="network", vendor="arista"),
        _asset("switch-1", asset_type="network", vendor="cisco"),
    ]
    r = compute_changes(today, since_days=1)
    assert r["no_baseline"] is False
    assert r["counts"]["added"] == 1
    assert r["counts"]["removed"] == 1
    assert r["counts"]["modified"] == 1
    assert r["added"][0]["asset_id"] == "switch-1"
    assert r["removed"][0]["asset_id"] == "server-1"
    assert r["modified"][0]["asset_id"] == "router-1"
    assert "vendor" in r["modified"][0]["fields_changed"]


def test_fleet_changes_history_returns_30_days():
    from safecadence.intel.fleet_changes import compute_changes
    r = compute_changes([_asset("a1")], write_today=True)
    assert isinstance(r["history"], list)
    assert len(r["history"]) == 31  # today + 30 prior


# --------------------------------------------------------- discovery_jobs


_AD_PARAMS = {"server": "ad.acme.local", "base_dn": "dc=acme,dc=local"}


def test_discovery_job_create_and_persist():
    from safecadence.intel.discovery_jobs import create_job, list_jobs
    # v9.36 — required params must be supplied at create time
    j = create_job(name="Daily AD pull", source="ad",
                   params=_AD_PARAMS, interval_hours=24)
    assert j.job_id
    assert j.next_run_at        # set on save
    found = [x for x in list_jobs() if x.job_id == j.job_id]
    assert len(found) == 1
    assert found[0].source == "ad"


def test_discovery_job_create_rejects_unknown_source():
    from safecadence.intel.discovery_jobs import create_job
    with pytest.raises(ValueError):
        create_job(name="x", source="bogus", interval_hours=24)


def test_discovery_job_create_rejects_bad_interval():
    from safecadence.intel.discovery_jobs import create_job
    with pytest.raises(ValueError):
        create_job(name="x", source="ad",
                   params=_AD_PARAMS, interval_hours=0)


def test_discovery_job_mark_run_advances_next_run_at():
    from safecadence.intel.discovery_jobs import create_job, mark_run, get_job
    j = create_job(name="snmp", source="snmp",
                   params={"host": "10.0.0.1"}, interval_hours=6)
    before = j.next_run_at
    after = mark_run(j.job_id, ok=True)
    assert after.last_status == "ok"
    assert after.last_run_at
    assert after.next_run_at != before


def test_discovery_job_mark_run_records_error():
    from safecadence.intel.discovery_jobs import create_job, mark_run
    j = create_job(name="x", source="ad",
                   params=_AD_PARAMS, interval_hours=1)
    after = mark_run(j.job_id, ok=False, error="bind failed")
    assert after.last_status == "error"
    assert "bind failed" in after.last_error


def test_discovery_job_delete():
    from safecadence.intel.discovery_jobs import (
        create_job, delete_job, get_job,
    )
    # dhcp has no required params — empty params is fine
    j = create_job(name="kill-me", source="dhcp", interval_hours=12)
    assert delete_job(j.job_id) is True
    assert get_job(j.job_id) is None
    # Idempotent — deleting again returns False but doesn't crash
    assert delete_job(j.job_id) is False


def test_discovery_job_invalid_id_rejected():
    from safecadence.intel.discovery_jobs import delete_job, get_job
    # path traversal attempt
    assert get_job("../../etc/passwd") is None
    assert delete_job("../../etc/passwd") is False
