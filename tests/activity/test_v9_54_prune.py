"""v9.54 #3 — daemon-driven activity log retention.

The activity directory grew linearly forever in v9.47-v9.53. v9.53
shipped logrotate + systemd-timer examples for production. v9.54
adds a daemon hook so pip-install deployments — which typically
don't have either of those — get retention out of the box.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta


def _seed_jsonl(root, day_offset_days, content="{}\n"):
    """Drop a JSONL file dated N days ago into the activity dir."""
    day = (datetime.now(timezone.utc)
            - timedelta(days=day_offset_days)).strftime("%Y-%m-%d")
    p = root / f"{day}.jsonl"
    p.write_text(content, encoding="utf-8")
    return p


# ---------------------------------------------------- prune unit

def test_prune_empty_dir(monkeypatch, tmp_path):
    """Fresh install — no activity dir yet → no error, zero counts."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.activity import prune
    summary = prune(retention_days=90)
    assert summary["deleted"] == 0
    assert summary["kept"] == 0
    assert summary["errors"] == []


def test_prune_keeps_recent_files(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    activity = tmp_path / "activity"
    activity.mkdir()
    _seed_jsonl(activity, 1)
    _seed_jsonl(activity, 30)
    _seed_jsonl(activity, 89)
    from safecadence.activity import prune
    summary = prune(retention_days=90)
    assert summary["deleted"] == 0
    assert summary["kept"] == 3


def test_prune_deletes_old_files(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    activity = tmp_path / "activity"
    activity.mkdir()
    keep = _seed_jsonl(activity, 5)
    drop1 = _seed_jsonl(activity, 100)
    drop2 = _seed_jsonl(activity, 200)
    from safecadence.activity import prune
    summary = prune(retention_days=90)
    assert summary["deleted"] == 2
    assert summary["kept"] == 1
    assert keep.exists()
    assert not drop1.exists()
    assert not drop2.exists()


def test_prune_ignores_non_date_files(monkeypatch, tmp_path):
    """If someone drops README.md or notes.txt in the activity
    directory, prune leaves them alone — only YYYY-MM-DD.jsonl is
    in scope."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    activity = tmp_path / "activity"
    activity.mkdir()
    _seed_jsonl(activity, 200)  # should be deleted
    note = activity / "notes.jsonl"      # bad date format
    note.write_text("noted", encoding="utf-8")
    from safecadence.activity import prune
    summary = prune(retention_days=90)
    assert summary["deleted"] == 1
    assert note.exists()


def test_prune_respects_retention_arg(monkeypatch, tmp_path):
    """7-day retention with a 30-day-old file → that file goes."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    activity = tmp_path / "activity"
    activity.mkdir()
    _seed_jsonl(activity, 30)
    from safecadence.activity import prune
    summary = prune(retention_days=7)
    assert summary["deleted"] == 1
    assert summary["retention_days"] == 7


def test_prune_records_freed_bytes(monkeypatch, tmp_path):
    """Summary reports bytes freed so the daemon log shows real impact."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    activity = tmp_path / "activity"
    activity.mkdir()
    big = _seed_jsonl(activity, 200, content="x" * 1000 + "\n")
    from safecadence.activity import prune
    summary = prune(retention_days=90)
    assert summary["deleted"] == 1
    assert summary["freed_bytes"] >= 1000


# ---------------------------------------------------- daemon integration

def test_daemon_calls_prune_when_retention_positive(monkeypatch, tmp_path):
    """run_cycle() includes activity_prune in compliance_hooks when
    SC_ACTIVITY_RETENTION_DAYS is positive (default = 90)."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_ACTIVITY_RETENTION_DAYS", "90")
    activity = tmp_path / "activity"
    activity.mkdir()
    _seed_jsonl(activity, 100)  # old file to delete
    from safecadence.daemon import run_cycle
    report = run_cycle()
    assert "activity_prune" in report["compliance_hooks"]
    summary = report["compliance_hooks"]["activity_prune"]
    assert summary["retention_days"] == 90
    assert summary["deleted"] == 1


def test_daemon_skips_prune_when_retention_zero(monkeypatch, tmp_path):
    """SC_ACTIVITY_RETENTION_DAYS=0 disables the daemon hook so
    deployments using logrotate/systemd timer aren't double-pruning."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_ACTIVITY_RETENTION_DAYS", "0")
    activity = tmp_path / "activity"
    activity.mkdir()
    old = _seed_jsonl(activity, 200)
    from safecadence.daemon import run_cycle
    report = run_cycle()
    assert "activity_prune" not in report["compliance_hooks"]
    assert old.exists()  # not pruned because hook was disabled
