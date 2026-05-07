"""
v9.25 — unit tests for the Safe Score history store.
"""

from __future__ import annotations

import pytest
from datetime import datetime, timedelta, timezone


@pytest.fixture(autouse=True)
def _isolated_data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    yield


def _fleet_result(score: int) -> dict:
    return {
        "fleet_score": score,
        "fleet_band": "C" if 60 <= score < 70 else "B" if score >= 80 else "F",
        "asset_count": 3,
        "per_asset": [
            {"asset_id": "a1", "score": score, "band": "C"},
            {"asset_id": "a2", "score": min(100, score + 10), "band": "B"},
        ],
    }


def test_append_then_fleet_history():
    from safecadence.scores.history import append_snapshot, fleet_history
    append_snapshot(_fleet_result(70))
    append_snapshot(_fleet_result(72))
    h = fleet_history(days=30)
    assert len(h) == 2
    assert h[0]["fleet_score"] == 70
    assert h[1]["fleet_score"] == 72


def test_asset_history_only_returns_that_asset():
    from safecadence.scores.history import append_snapshot, asset_history
    append_snapshot(_fleet_result(70))
    append_snapshot(_fleet_result(75))
    h = asset_history("a1", days=30)
    assert len(h) == 2
    assert all("score" in row for row in h)
    # a3 was never in the snapshots → empty result
    assert asset_history("a3", days=30) == []


def test_retention_drops_old_snapshots():
    from safecadence.scores.history import append_snapshot, fleet_history
    old_ts = datetime.now(timezone.utc) - timedelta(days=120)
    append_snapshot(_fleet_result(50), when=old_ts, retention_days=90)
    append_snapshot(_fleet_result(70))  # today
    h = fleet_history(days=180)
    assert len(h) == 1   # the 120-day-old row was dropped
    assert h[0]["fleet_score"] == 70


def test_trend_computes_direction_and_delta():
    from safecadence.scores.history import append_snapshot, trend
    week_ago = datetime.now(timezone.utc) - timedelta(days=8)
    append_snapshot(_fleet_result(60), when=week_ago)
    append_snapshot(_fleet_result(75))
    t = trend(days=7)
    assert t["current"] == 75
    assert t["previous"] == 60
    assert t["delta"] == 15
    assert t["direction"] == "up"


def test_trend_handles_no_history():
    from safecadence.scores.history import trend
    t = trend(days=7)
    assert t["delta"] == 0
    assert t["direction"] == "flat"
    assert t["samples"] == 0


def test_clear_wipes_history():
    from safecadence.scores.history import append_snapshot, fleet_history, clear
    append_snapshot(_fleet_result(70))
    assert len(fleet_history(days=30)) == 1
    clear()
    assert fleet_history(days=30) == []
