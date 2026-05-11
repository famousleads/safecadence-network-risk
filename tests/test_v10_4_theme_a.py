"""Tests for v10.4 Theme A — scheduled & scriptable reports.

Covers:
  * CLI ``safecadence report compose`` + ``report list-presets``
  * Email delivery sanity (missing env returns an error string)
  * Cron parser corner cases
  * Scheduler add / list / remove round-trip + run_due filter
  * Async report-generation API job lifecycle
"""

from __future__ import annotations

import datetime as _dt
import os
from pathlib import Path

import pytest

# CliRunner is supplied by Click, which is already a hard dep.
from click.testing import CliRunner


# --------------------------------------------------------------------------
# Fixtures — isolate per-test schedules.yaml and report jobs
# --------------------------------------------------------------------------


@pytest.fixture
def isolated_schedules(tmp_path, monkeypatch):
    """Point the scheduler at a per-test schedules.yaml."""
    sched_file = tmp_path / "schedules.yaml"
    monkeypatch.setenv("SC_SCHEDULES_PATH", str(sched_file))
    # Wipe SMTP env so the scheduler's send step deterministically errors.
    for k in ("SC_SMTP_HOST", "SC_SMTP_PORT", "SC_SMTP_USER",
              "SC_SMTP_PASS", "SC_SMTP_FROM"):
        monkeypatch.delenv(k, raising=False)
    yield sched_file


@pytest.fixture(autouse=True)
def _clean_api_jobs():
    """Reset the in-memory API job table between tests."""
    from safecadence.reports import api_v1
    api_v1._REPORT_JOBS.clear()
    yield
    api_v1._REPORT_JOBS.clear()


# --------------------------------------------------------------------------
# 1. CLI tests
# --------------------------------------------------------------------------


def test_cli_report_compose(tmp_path):
    """Invoking `safecadence report compose --format json` writes a file."""
    from safecadence.cli import cli
    out_path = tmp_path / "report.json"
    result = CliRunner().invoke(
        cli,
        ["report", "compose",
         "--preset", "exec_brief",
         "--format", "json",
         "--out", str(out_path),
         "--prepared-for", "Acme Corp"],
    )
    assert result.exit_code == 0, result.output
    assert out_path.exists(), "compose did not write a file"
    assert out_path.stat().st_size > 100
    assert f"Wrote: {out_path}" in result.output


def test_cli_report_list_presets():
    """`report list-presets` enumerates the canonical presets."""
    from safecadence.cli import cli
    result = CliRunner().invoke(cli, ["report", "list-presets"])
    assert result.exit_code == 0, result.output
    assert "exec_brief" in result.output
    assert "compliance_audit" in result.output


def test_cli_report_list_sections():
    """`report list-sections` enumerates section keys."""
    from safecadence.cli import cli
    result = CliRunner().invoke(cli, ["report", "list-sections"])
    assert result.exit_code == 0, result.output
    assert "kpi_summary" in result.output
    assert "compliance_posture" in result.output


# --------------------------------------------------------------------------
# 2. Email delivery
# --------------------------------------------------------------------------


def test_email_delivery_missing_env(monkeypatch):
    """send_report returns an informative string when SMTP env is unset."""
    from safecadence.reports import email_delivery
    for k in ("SC_SMTP_HOST", "SC_SMTP_USER", "SC_SMTP_PASS", "SC_SMTP_FROM"):
        monkeypatch.delenv(k, raising=False)
    err = email_delivery.send_report(
        recipients=["alice@example.com"],
        subject="ping",
        body_text="hi",
        attachment_bytes=b"abc",
        attachment_filename="x.bin",
    )
    assert err is not None
    assert "SMTP not configured" in err
    # Specific missing vars are surfaced
    assert "SC_SMTP_HOST" in err


def test_email_delivery_no_recipients():
    """Empty recipient list -> immediate error string, no SMTP attempt."""
    from safecadence.reports import email_delivery
    err = email_delivery.send_report(
        recipients=[],
        subject="x",
        body_text="x",
        attachment_bytes=b"",
        attachment_filename="x",
    )
    assert err is not None
    assert "No recipients" in err


def test_email_mimetype_lookup():
    """mimetype_for_format covers each renderer."""
    from safecadence.reports.email_delivery import mimetype_for_format
    assert mimetype_for_format("pdf") == "application/pdf"
    assert "wordprocessingml" in mimetype_for_format("docx")
    assert "presentationml" in mimetype_for_format("pptx")
    assert mimetype_for_format("html") == "text/html"
    assert mimetype_for_format("json") == "application/json"
    assert mimetype_for_format("nope") == "application/octet-stream"


# --------------------------------------------------------------------------
# 3. Scheduler — cron parser
# --------------------------------------------------------------------------


def test_scheduler_parse_cron_basic():
    from safecadence.reports.scheduler import parse_cron
    f = parse_cron("* * * * *")
    assert 0 in f["minute"] and 59 in f["minute"]
    assert len(f["hour"]) == 24
    assert len(f["dow"]) == 7


def test_scheduler_parse_cron_specific_dow():
    from safecadence.reports.scheduler import parse_cron
    f = parse_cron("0 8 * * MON")
    assert f["minute"] == {0}
    assert f["hour"] == {8}
    # MON = 1 in our cron-style (Sun=0..Sat=6)
    assert f["dow"] == {1}


def test_scheduler_parse_cron_step():
    from safecadence.reports.scheduler import parse_cron
    f = parse_cron("*/15 * * * *")
    assert f["minute"] == {0, 15, 30, 45}


def test_scheduler_parse_cron_range_and_list():
    from safecadence.reports.scheduler import parse_cron
    f = parse_cron("0 9-17 * * MON,WED,FRI")
    assert f["hour"] == set(range(9, 18))
    assert f["dow"] == {1, 3, 5}  # MON=1, WED=3, FRI=5


def test_scheduler_parse_cron_rejects_garbage():
    from safecadence.reports.scheduler import parse_cron
    with pytest.raises(ValueError):
        parse_cron("not a cron expression")
    with pytest.raises(ValueError):
        parse_cron("0 8 * *")  # too few fields
    with pytest.raises(ValueError):
        parse_cron("99 8 * * *")  # minute out of range


def test_scheduler_cron_matches():
    from safecadence.reports.scheduler import cron_matches
    # Monday 2026-05-11 08:00 UTC — should match "0 8 * * MON"
    monday_8am = _dt.datetime(2026, 5, 11, 8, 0, tzinfo=_dt.timezone.utc)
    assert cron_matches("0 8 * * MON", monday_8am)
    # Same time on Tuesday — should NOT match
    tuesday_8am = _dt.datetime(2026, 5, 12, 8, 0, tzinfo=_dt.timezone.utc)
    assert not cron_matches("0 8 * * MON", tuesday_8am)
    # Quarter-hourly
    assert cron_matches("*/15 * * * *", _dt.datetime(2026, 5, 11, 8, 30,
                                                     tzinfo=_dt.timezone.utc))
    assert not cron_matches("*/15 * * * *", _dt.datetime(2026, 5, 11, 8, 7,
                                                         tzinfo=_dt.timezone.utc))


# --------------------------------------------------------------------------
# 4. Scheduler — persistence round-trip
# --------------------------------------------------------------------------


def test_scheduler_add_remove_round_trip(isolated_schedules):
    from safecadence.reports import scheduler

    assert scheduler.load_schedules() == []

    rec = scheduler.add_schedule({
        "name": "Weekly exec",
        "cron": "0 8 * * MON",
        "preset": "exec_brief",
        "format": "pdf",
        "to": ["ciso@acme.com"],
    })
    assert rec["id"], "id should be auto-generated"
    items = scheduler.load_schedules()
    assert len(items) == 1
    assert items[0]["preset"] == "exec_brief"

    ok = scheduler.remove_schedule(rec["id"])
    assert ok is True
    assert scheduler.load_schedules() == []

    # Removing a missing id returns False, not raise.
    assert scheduler.remove_schedule(rec["id"]) is False


def test_scheduler_add_validates_cron(isolated_schedules):
    from safecadence.reports import scheduler
    with pytest.raises(ValueError):
        scheduler.add_schedule({
            "cron": "garbage",
            "preset": "exec_brief",
            "format": "pdf",
            "to": ["a@b.com"],
        })


def test_scheduler_add_requires_fields(isolated_schedules):
    from safecadence.reports import scheduler
    with pytest.raises(ValueError):
        scheduler.add_schedule({"cron": "* * * * *",
                                "format": "pdf", "to": ["a@b.com"]})  # no preset
    with pytest.raises(ValueError):
        scheduler.add_schedule({"cron": "* * * * *",
                                "preset": "exec_brief", "format": "pdf"})  # no to


# --------------------------------------------------------------------------
# 5. Scheduler — run_due filter
# --------------------------------------------------------------------------


def test_scheduler_run_due_filter(isolated_schedules, monkeypatch):
    """run_due fires schedules whose cron matches now, skips others.

    We patch the compose+render+send pipeline so we don't depend on a
    real SMTP server. The schedule should still get its last_run +
    last_status updated.
    """
    from safecadence.reports import scheduler as _sched
    rec = _sched.add_schedule({
        "name": "monday morning",
        "cron": "0 8 * * MON",
        "preset": "exec_brief",
        "format": "json",
        "to": ["alice@example.com"],
    })

    calls: list[dict] = []

    def fake_run(schedule, *, now):
        calls.append({"id": schedule.get("id"), "now": now})
        return {"id": schedule["id"], "ok": True, "format": "json",
                "size_bytes": 42}

    monkeypatch.setattr(_sched, "_compose_render_send", fake_run)

    # Tuesday — nothing should fire.
    tues = _dt.datetime(2026, 5, 12, 8, 0, tzinfo=_dt.timezone.utc)
    res = _sched.run_due(now=tues)
    assert res == []
    assert calls == []

    # Monday 8:00 — our schedule fires exactly once.
    mon = _dt.datetime(2026, 5, 11, 8, 0, tzinfo=_dt.timezone.utc)
    res = _sched.run_due(now=mon)
    assert len(res) == 1
    assert res[0]["ok"] is True
    assert len(calls) == 1

    # Running again at the same minute must be a no-op (dedupe by last_run_minute).
    res2 = _sched.run_due(now=mon)
    assert res2 == []

    # Disabled schedules are skipped entirely.
    _sched.update_schedule(rec["id"], enabled=False, last_run_minute=None)
    res3 = _sched.run_due(now=mon)
    assert res3 == []


# --------------------------------------------------------------------------
# 6. REST API — job lifecycle
# --------------------------------------------------------------------------


def test_api_generate_job_lifecycle():
    """POST /api/v1/reports/generate -> poll -> download."""
    fastapi = pytest.importorskip("fastapi")
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from safecadence.reports.api_v1 import build_router

    app = FastAPI()
    app.include_router(build_router())
    client = TestClient(app)

    r = client.post(
        "/api/v1/reports/generate",
        json={"preset": "exec_brief", "format": "json"},
    )
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["job_id"].startswith("rpt_")
    assert "status_url" in body
    job_id = body["job_id"]

    # Poll until complete (background thread; bounded retries).
    import time as _t
    for _ in range(80):
        st = client.get(f"/api/v1/reports/{job_id}").json()
        if st.get("status") in ("complete", "failed"):
            break
        _t.sleep(0.05)
    assert st.get("status") == "complete", st

    # Download returns the actual bytes
    dl = client.get(f"/api/v1/reports/{job_id}/download")
    assert dl.status_code == 200
    assert dl.headers["content-type"].startswith("application/json")
    assert b'"sections"' in dl.content  # composed JSON has sections


def test_api_generate_validation():
    """generate endpoint requires preset+format; rejects email w/o recipients."""
    pytest.importorskip("fastapi")
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from safecadence.reports.api_v1 import build_router

    app = FastAPI()
    app.include_router(build_router())
    client = TestClient(app)

    r = client.post("/api/v1/reports/generate", json={"format": "pdf"})
    assert r.status_code == 400

    r = client.post("/api/v1/reports/generate", json={"preset": "exec_brief"})
    assert r.status_code == 400

    r = client.post(
        "/api/v1/reports/generate",
        json={"preset": "exec_brief", "format": "pdf", "deliver_via": "email"},
    )
    assert r.status_code == 400  # missing `to`


def test_api_unknown_job_id_returns_404():
    pytest.importorskip("fastapi")
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from safecadence.reports.api_v1 import build_router

    app = FastAPI()
    app.include_router(build_router())
    client = TestClient(app)
    assert client.get("/api/v1/reports/rpt_nope").status_code == 404
    assert client.get("/api/v1/reports/rpt_nope/download").status_code == 404
