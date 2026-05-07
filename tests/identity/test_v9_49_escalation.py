"""v9.49 — Phase C: PagerDuty escalation on stale CRITICAL approvals.

Covers threshold reads, idempotency, opt-in defaults, and the
deterministic dedup_key shape PD relies on for de-duping.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta


def test_disabled_when_no_pd_key(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("SC_APPROVAL_ESCALATION_PD_KEY", raising=False)
    from safecadence.execution import escalation as esc
    assert esc.is_enabled() is False
    out = esc.run_cycle()
    assert out["enabled"] is False
    assert out["fired"] == 0


def test_disabled_when_threshold_zero(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_APPROVAL_ESCALATION_PD_KEY", "k")
    monkeypatch.setenv("SC_APPROVAL_ESCALATION_MINUTES", "0")
    from safecadence.execution import escalation as esc
    assert esc.is_enabled() is False


def test_threshold_minutes_default(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("SC_APPROVAL_ESCALATION_MINUTES", raising=False)
    from safecadence.execution import escalation as esc
    assert esc.threshold_minutes() == 30


def test_threshold_minutes_invalid_falls_back(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_APPROVAL_ESCALATION_MINUTES", "not-an-int")
    from safecadence.execution import escalation as esc
    assert esc.threshold_minutes() == 30


def test_dedup_key_is_deterministic(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_APPROVAL_ESCALATION_PD_KEY", "k")
    from safecadence.execution import escalation as esc
    rec = esc.fire_escalation({"job_id": "j_42", "name": "test"})
    assert rec.pd_dedup_key == "safecadence:approval:j_42"


def test_idempotent_already_fired(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_APPROVAL_ESCALATION_PD_KEY", "k")
    from safecadence.execution import escalation as esc
    esc.record_fire(esc.EscalationRecord(
        job_id="j_seen", fired_at="2026-05-07T00:00:00Z",
        pd_dedup_key="safecadence:approval:j_seen",
        ok=True, detail="HTTP 202",
    ))
    assert esc.already_fired("j_seen") is True
    assert esc.already_fired("j_unseen") is False


def test_run_cycle_fires_only_new(monkeypatch, tmp_path):
    """Two stale jobs in the queue, one already escalated → only the
    fresh one fires."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_APPROVAL_ESCALATION_PD_KEY", "k")
    monkeypatch.setenv("SC_APPROVAL_ESCALATION_MINUTES", "30")
    from safecadence.execution import escalation as esc

    old_ts = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(
        timespec="seconds").replace("+00:00", "Z")
    fake_jobs = [
        {"job_id": "j_already", "name": "old1", "submitted_at": old_ts,
         "submitted_by": "alice", "approvers": ["bob"],
         "approvals_required": 1, "asset_count": 3},
        {"job_id": "j_new", "name": "old2", "submitted_at": old_ts,
         "submitted_by": "alice", "approvers": ["bob"],
         "approvals_required": 1, "asset_count": 1},
    ]
    monkeypatch.setattr(esc, "stale_critical_jobs",
                          lambda *, now=None: fake_jobs)
    monkeypatch.setattr(esc, "_post_pd",
                          lambda url, payload: (True, "HTTP 202"))
    esc.record_fire(esc.EscalationRecord(
        job_id="j_already", fired_at="2026-05-07T00:00:00Z",
        pd_dedup_key="safecadence:approval:j_already",
        ok=True, detail="prior",
    ))
    out = esc.run_cycle()
    assert out["enabled"] is True
    assert out["fired"] == 1
    assert out["fires"][0]["job_id"] == "j_new"


def test_failure_still_records_fire(monkeypatch, tmp_path):
    """A 5xx response from PD shouldn't make the daemon retry next
    cycle — that would create the "two pages for one job" failure
    mode the docstring warns about."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_APPROVAL_ESCALATION_PD_KEY", "k")
    from safecadence.execution import escalation as esc
    monkeypatch.setattr(esc, "_post_pd",
                          lambda url, payload: (False, "HTTP 502"))
    rec = esc.fire_escalation({"job_id": "j_fail", "name": "x"})
    assert rec.ok is False
    assert "502" in rec.detail
    assert esc.already_fired("j_fail") is True
