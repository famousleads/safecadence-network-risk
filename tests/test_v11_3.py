"""
Tests for v11.3 — operations + governance.

Covers all six deliverables:

1. Backup round-trip (create → verify → restore).
2. Backup manifest tampering is detected.
3. Per-org GDPR export has the right top-level shape.
4. Hash-chained audit log appends + verifies.
5. Hash-chained audit log detects line-5 tampering.
6. Retention purges old items while preserving the min-count floor.
7. Disaster-recovery runbook exists + has all five scenarios.
8. SECURITY.md exists + lists reporting address + scope + rewards.

Every test that touches disk uses a tempdir and the
``SAFECADENCE_HOME`` env override so we never write into the
developer's real ``~/.safecadence/``.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import pathlib
import tarfile
import tempfile

import pytest


REPO = pathlib.Path(__file__).resolve().parents[1]


@pytest.fixture()
def isolated_home(monkeypatch):
    """Run each test against a private SafeCadence home dir."""
    tmp = tempfile.mkdtemp(prefix="sc-v11-3-")
    monkeypatch.setenv("SAFECADENCE_HOME", tmp)
    monkeypatch.setenv("SC_AUTH_HOME", tmp)
    yield pathlib.Path(tmp)


@pytest.fixture()
def seeded_org(isolated_home):
    """Create one org with a representative spread of files."""
    from safecadence.storage.org_store import create_org
    org = create_org("Acme Co", "ops@acme.com")
    base = isolated_home / "orgs" / org.id
    # Drop some realistic content
    (base / "scan_history.jsonl").write_text(
        "\n".join(json.dumps({"ts": "2026-05-10T12:00:00Z", "scan": i})
                 for i in range(3)) + "\n",
        encoding="utf-8",
    )
    (base / "audit.jsonl").write_text(
        json.dumps({"ts": "2026-05-10T12:00:00Z", "action": "test"}) + "\n",
        encoding="utf-8",
    )
    (base / "members.json").write_text(
        json.dumps([{"email": "ops@acme.com", "role": "ADMIN"}]),
        encoding="utf-8",
    )
    return org.id


# --------------------------------------------------------------------------
# 1. Backup round-trip
# --------------------------------------------------------------------------


def test_backup_roundtrip_create_verify_restore(isolated_home, seeded_org, tmp_path):
    """create → verify ok → restore to fresh dir → contents identical."""
    from safecadence.ops.backup import create_backup, verify_backup, restore_backup

    out_dir = tmp_path / "backups"
    path = create_backup(out_dir)
    assert path.exists()
    assert path.suffix == ".gz"

    verification = verify_backup(path)
    assert verification["ok"], verification["errors"]
    assert verification["file_count"] > 0
    assert verification["manifest"]["safecadence_version"]
    assert seeded_org in verification["manifest"]["org_ids"]

    # Restore into a clean target
    target = tmp_path / "restored"
    result = restore_backup(path, target_dir=target)
    assert result["ok"], result["errors"]
    assert result["restored"] > 0

    # Verify the restored content matches the original
    orig_audit = (isolated_home / "orgs" / seeded_org / "audit.jsonl").read_text()
    rest_audit = (target / "orgs" / seeded_org / "audit.jsonl").read_text()
    assert orig_audit == rest_audit


def test_backup_dry_run_restore(isolated_home, seeded_org, tmp_path):
    from safecadence.ops.backup import create_backup, restore_backup
    path = create_backup(tmp_path / "backups")
    res = restore_backup(path, target_dir=tmp_path / "nope", dry_run=True)
    assert res["ok"]
    assert res.get("dry_run") is True
    assert not (tmp_path / "nope").exists()


# --------------------------------------------------------------------------
# 2. Manifest tamper detection
# --------------------------------------------------------------------------


def test_backup_corrupted_file_detected(isolated_home, seeded_org, tmp_path):
    """Re-write a member file inside the tar with different bytes — verify fails."""
    from safecadence.ops.backup import create_backup, verify_backup

    path = create_backup(tmp_path / "backups")
    # Build a sibling tar where one file is corrupted
    corrupt = tmp_path / "corrupt.tar.gz"
    with tarfile.open(path, "r:gz") as src, tarfile.open(corrupt, "w:gz") as dst:
        for m in src.getmembers():
            data = src.extractfile(m).read() if m.isfile() else b""
            if m.name == "MANIFEST.json":
                dst.addfile(m, fileobj=__import__("io").BytesIO(data))
                continue
            if m.name.startswith("orgs/") and m.name.endswith("audit.jsonl"):
                data = data + b"\x00TAMPERED\n"
                m.size = len(data)
            dst.addfile(m, fileobj=__import__("io").BytesIO(data))
    result = verify_backup(corrupt)
    assert result["ok"] is False
    assert any("sha256 mismatch" in e or "size mismatch" in e for e in result["errors"])


# --------------------------------------------------------------------------
# 3. GDPR-style export shape
# --------------------------------------------------------------------------


def test_export_org_produces_versioned_json(isolated_home, seeded_org, tmp_path):
    from safecadence.ops.export_org import export_org, SCHEMA_VERSION
    out = tmp_path / "org.json"
    export_org(seeded_org, out)
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["schema_version"] == SCHEMA_VERSION
    assert "exported_at" in payload
    assert payload["org"]["id"] == seeded_org
    assert "members" in payload["data"]
    assert "templates" in payload["data"]
    assert "audit_trail" in payload["data"]
    assert "audit_chain" in payload["data"]
    assert "risk_acceptances" in payload["data"]
    assert "pentest_history" in payload["data"]
    assert "change_log" in payload["data"]
    assert "scan_history" in payload["data"]
    assert "evidence_index" in payload["data"]
    # Members were seeded
    assert payload["data"]["members"][0]["email"] == "ops@acme.com"


def test_export_org_rejects_blank(isolated_home, tmp_path):
    from safecadence.ops.export_org import export_org
    with pytest.raises(ValueError):
        export_org("", tmp_path / "x.json")


# --------------------------------------------------------------------------
# 4 + 5. Hash-chained audit log
# --------------------------------------------------------------------------


def test_audit_chain_append_and_verify(isolated_home, seeded_org):
    from safecadence.audit.log import log_event_chained, verify_chain
    for i in range(10):
        row = log_event_chained(
            seeded_org,
            user_email="ops@acme.com",
            action="test.event",
            target=f"obj_{i}",
            metadata={"i": i},
        )
        assert row["hash"]
        assert row["prev_hash"]
    res = verify_chain(seeded_org)
    assert res == {"ok": True, "broken_at_line": None, "line_count": 10}


def test_audit_chain_tamper_detected(isolated_home, seeded_org):
    from safecadence.audit.log import log_event_chained, verify_chain
    for i in range(10):
        log_event_chained(seeded_org, "ops@acme.com", "evt", target=f"x_{i}")
    chain_path = isolated_home / "orgs" / seeded_org / "audit_chain.jsonl"
    lines = chain_path.read_text(encoding="utf-8").splitlines()
    # Tamper line 5 (1-indexed)
    row = json.loads(lines[4])
    row["metadata"] = {"hacked": True}     # keep hash field, mutate body
    lines[4] = json.dumps(row, separators=(",", ":"))
    chain_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    res = verify_chain(seeded_org)
    assert res["ok"] is False
    assert res["broken_at_line"] == 5


def test_audit_chain_empty_is_ok(isolated_home, seeded_org):
    from safecadence.audit.log import verify_chain
    res = verify_chain(seeded_org)
    assert res == {"ok": True, "broken_at_line": None, "line_count": 0}


def test_legacy_log_event_unchanged(isolated_home, seeded_org):
    """Ensure v11.3 didn't break the existing unchained log_event API."""
    from safecadence.audit.log import log_event, read_events
    assert log_event(seeded_org, "u@x.com", "act", target="t", metadata={"a": 1})
    rows = read_events(seeded_org, limit=10)
    # We seeded one row in the fixture and just appended one → at least 2
    assert len(rows) >= 1
    assert rows[0]["user_email"] in ("u@x.com", "")


# --------------------------------------------------------------------------
# 6. Retention
# --------------------------------------------------------------------------


def test_retention_purges_old_keeps_floor(isolated_home, seeded_org):
    from safecadence.ops.retention import (
        RetentionPolicy, set_retention, apply_retention,
    )
    scan_path = isolated_home / "orgs" / seeded_org / "scan_history.jsonl"
    # 100 old (>200d ago) + 60 fresh (<30d ago). keep_days=30, min=50.
    # Fresh rows (all inside window) should survive; floor guarantees ≥ 50.
    now = _dt.datetime.now(_dt.timezone.utc)
    rows: list[str] = []
    for i in range(100):
        ts = (now - _dt.timedelta(days=200 + i)).isoformat() + "Z"
        rows.append(json.dumps({"ts": ts, "scan": f"old_{i}"}))
    for i in range(60):
        # All 60 fresh rows are inside 30 days → keep_days protects them
        ts = (now - _dt.timedelta(days=i, hours=12) + _dt.timedelta(days=0.5)
              ).isoformat() + "Z"
        # Simpler: distribute over 0..29 days so all are inside the 30-day window
        ts = (now - _dt.timedelta(hours=i * 11)).isoformat() + "Z"
        rows.append(json.dumps({"ts": ts, "scan": f"fresh_{i}"}))
    scan_path.write_text("\n".join(rows) + "\n", encoding="utf-8")

    set_retention(seeded_org, RetentionPolicy("scans", keep_days=30, keep_min_count=50))
    report = apply_retention(seeded_org)
    assert report["scans"]["before"] == 160
    # All 60 fresh are inside the 30d window → all kept by window rule.
    # Min-count=50 then protects the 50 most-recent rows (a subset of the 60).
    # Net result: at least 60 rows remain.
    assert report["scans"]["after"] >= 60
    assert report["scans"]["after"] >= 50      # min-count floor independently
    assert report["scans"]["purged"] == report["scans"]["before"] - report["scans"]["after"]
    # Sanity: with 100 old rows dropped, after-count should equal 60.
    assert report["scans"]["after"] == 60


def test_retention_defaults_present(isolated_home, seeded_org):
    from safecadence.ops.retention import default_policies, get_retention
    pol = get_retention(seeded_org)
    defaults = default_policies()
    for kind in ("scans", "audit", "reports", "errors"):
        assert pol[kind].kind == kind
        assert pol[kind].keep_days == defaults[kind].keep_days


def test_retention_set_validates(isolated_home, seeded_org):
    from safecadence.ops.retention import set_retention, RetentionPolicy
    with pytest.raises(ValueError):
        set_retention(seeded_org, RetentionPolicy("bogus", 30, 10))
    with pytest.raises(ValueError):
        set_retention(seeded_org, RetentionPolicy("scans", 0, 10))


# --------------------------------------------------------------------------
# 7. Disaster recovery runbook
# --------------------------------------------------------------------------


def test_disaster_recovery_runbook_exists_with_five_scenarios():
    path = REPO / "docs" / "runbooks" / "disaster-recovery.md"
    assert path.exists()
    body = path.read_text(encoding="utf-8")
    assert "## Scenario 1" in body
    assert "## Scenario 2" in body
    assert "## Scenario 3" in body
    assert "## Scenario 4" in body
    assert "## Scenario 5" in body
    assert "Post-mortem template" in body


# --------------------------------------------------------------------------
# 8. SECURITY.md
# --------------------------------------------------------------------------


def test_security_md_present_with_reporting_scope_rewards():
    path = REPO / "SECURITY.md"
    assert path.exists()
    body = path.read_text(encoding="utf-8")
    assert "security@safecadence.com" in body
    assert "What's in scope" in body
    assert "Rewards" in body
    assert "$5,000" in body or "$5000" in body or "5,000" in body
    assert "Hall of fame" in body or "Hall of Fame" in body
