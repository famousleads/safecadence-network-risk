"""Free 90-day Public Safety trial — auto-start, countdown, expiry, unlock."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest


@pytest.fixture()
def trial_env(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_TRIAL_PATH", str(tmp_path / "trials.json"))
    monkeypatch.setenv("SC_LICENSE_PATH", str(tmp_path / "license.json"))
    monkeypatch.delenv("SC_LICENSE_PUBKEY_PATH", raising=False)
    return tmp_path


def test_trial_auto_starts_on_first_access(trial_env):
    from safecadence.license import feature_access, trial_status
    assert not trial_status("public_safety")["started"]
    acc = feature_access("public_safety")
    assert acc["mode"] == "trial"
    assert acc["days_remaining"] == 90
    assert trial_status("public_safety")["started"]


def test_trial_stamp_is_idempotent(trial_env):
    from safecadence.license import feature_access, trial_status
    feature_access("public_safety")
    first = trial_status("public_safety")["started_at"]
    feature_access("public_safety")
    assert trial_status("public_safety")["started_at"] == first


def test_trial_counts_down_and_expires(trial_env):
    from safecadence.license import feature_access
    # Backdate the stamp 30 days -> ~60 remaining.
    stamp = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
    (trial_env / "trials.json").write_text(
        json.dumps({"public_safety": {"started_at": stamp}}))
    acc = feature_access("public_safety")
    assert acc["mode"] == "trial"
    assert 58 <= acc["days_remaining"] <= 60
    # Backdate 91 days -> expired.
    stamp = (datetime.now(timezone.utc) - timedelta(days=91)).isoformat()
    (trial_env / "trials.json").write_text(
        json.dumps({"public_safety": {"started_at": stamp}}))
    acc = feature_access("public_safety")
    assert acc["mode"] == "expired"
    assert acc["days_remaining"] == 0


def test_license_beats_trial(trial_env):
    from safecadence.license import feature_access
    (trial_env / "license.json").write_text(json.dumps({
        "licensee": "Cypress County SO",
        "features": ["base", "public_safety"],
    }))
    acc = feature_access("public_safety")
    assert acc["mode"] == "licensed"


def test_license_unlocks_after_expiry(trial_env):
    from safecadence.license import feature_access
    stamp = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat()
    (trial_env / "trials.json").write_text(
        json.dumps({"public_safety": {"started_at": stamp}}))
    assert feature_access("public_safety")["mode"] == "expired"
    (trial_env / "license.json").write_text(json.dumps({
        "licensee": "Cypress County SO",
        "features": ["public_safety"],
    }))
    assert feature_access("public_safety")["mode"] == "licensed"


def test_unknown_feature_has_no_trial(trial_env):
    from safecadence.license import feature_access
    assert feature_access("branded_reports")["mode"] == "unavailable"


def test_ps_access_states(trial_env):
    """The desat gate maps trial/expired correctly."""
    from safecadence.ui.desat_pages import _ps_access
    assert _ps_access() == "trial"            # auto-started
    stamp = (datetime.now(timezone.utc) - timedelta(days=95)).isoformat()
    (trial_env / "trials.json").write_text(
        json.dumps({"public_safety": {"started_at": stamp}}))
    assert _ps_access() in ("locked", "evaluation")  # expired (evaluation
    # only if a sheriff demo dataset happens to be loaded in this env)
    (trial_env / "license.json").write_text(json.dumps({
        "licensee": "x", "features": ["public_safety"]}))
    assert _ps_access() == "licensed"
