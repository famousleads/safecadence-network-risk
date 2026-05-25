"""
Tests for v14.0 — Intelligence layer matures into a real release.

Covers:
  * intelligence.multi_turn (Conversation state + turn limits)
  * intelligence.dismissal_learning (record + match + annotate + list)
  * intelligence.remediation_executor (preview + queue degradation)
"""
from __future__ import annotations

import sqlite3
import time

import pytest


# --------------------------------------------------------------------------
# multi_turn
# --------------------------------------------------------------------------


def test_conversation_send_returns_envelope_with_turn_index():
    from safecadence.intelligence import Conversation
    c = Conversation()
    r = c.send("hello")
    assert "turn" in r
    assert r["turn"] >= 1
    assert "answer" in r
    assert "calls" in r


def test_conversation_history_grows_with_send():
    from safecadence.intelligence import Conversation
    c = Conversation()
    c.send("first")
    c.send("second")
    h = c.history()
    # Each send adds 2 turns (user + assistant)
    assert len(h) == 4
    assert [t["role"] for t in h] == ["user", "assistant", "user", "assistant"]


def test_conversation_reset_clears_history():
    from safecadence.intelligence import Conversation
    c = Conversation()
    c.send("one")
    c.reset()
    assert c.history() == []


def test_conversation_max_turns_caps_send():
    from safecadence.intelligence import Conversation
    c = Conversation(max_turns=2)
    c.send("one")
    c.send("two")
    r3 = c.send("three")
    assert "max_turns_reached" in r3["warnings"]


# --------------------------------------------------------------------------
# dismissal_learning
# --------------------------------------------------------------------------


@pytest.fixture()
def db():
    from safecadence.intelligence import ensure_dismissal_schema
    c = sqlite3.connect(":memory:")
    ensure_dismissal_schema(c)
    return c


def test_dismissal_record_and_match(db):
    from safecadence.intelligence import (
        find_matching_dismissals, record_dismissal,
    )
    record_dismissal(db, rule_id="R1", decision="exception",
                      operator="alice", reason="approved exception")
    matches = find_matching_dismissals(db, {"rule_id": "R1"})
    assert len(matches) == 1
    assert matches[0]["decision"] == "exception"


def test_dismissal_match_filters_by_asset_class(db):
    from safecadence.intelligence import (
        find_matching_dismissals, record_dismissal,
    )
    record_dismissal(db, rule_id="R1", decision="false_positive",
                      operator="alice", asset_class="firewall")
    fw_matches = find_matching_dismissals(
        db, {"rule_id": "R1", "asset_class": "firewall"},
    )
    sw_matches = find_matching_dismissals(
        db, {"rule_id": "R1", "asset_class": "switch"},
    )
    assert len(fw_matches) == 1
    assert sw_matches == []


def test_dismissal_empty_asset_class_matches_anything(db):
    from safecadence.intelligence import (
        find_matching_dismissals, record_dismissal,
    )
    record_dismissal(db, rule_id="R1", decision="exception",
                      operator="alice")  # asset_class default ""
    assert len(find_matching_dismissals(
        db, {"rule_id": "R1", "asset_class": "firewall"})) == 1
    assert len(find_matching_dismissals(
        db, {"rule_id": "R1", "asset_class": "switch"})) == 1


def test_dismissal_ttl_expires(db):
    from safecadence.intelligence import (
        find_matching_dismissals, record_dismissal,
    )
    record_dismissal(db, rule_id="R1", decision="exception",
                      operator="alice", ttl_days=1)
    now = int(time.time()) + 2 * 86_400  # 2 days later
    matches = find_matching_dismissals(db, {"rule_id": "R1"}, now_ts=now)
    assert matches == []


def test_dismissal_annotate_findings_decorates_matches(db):
    from safecadence.intelligence import annotate_findings, record_dismissal
    record_dismissal(db, rule_id="R1", decision="false_positive",
                      operator="alice", reason="noisy rule")
    findings = [
        {"id": "F1", "rule_id": "R1"},
        {"id": "F2", "rule_id": "R2"},
    ]
    out = annotate_findings(db, findings)
    assert out[0]["dismissed_by"] == "alice"
    assert out[0]["dismissal_decision"] == "false_positive"
    assert "dismissed_by" not in out[1]


def test_dismissal_rejects_unknown_decision(db):
    from safecadence.intelligence import record_dismissal
    with pytest.raises(ValueError):
        record_dismissal(db, rule_id="R1", decision="maybe",
                          operator="alice")


def test_dismissal_list_active_only(db):
    from safecadence.intelligence import list_dismissals, record_dismissal
    record_dismissal(db, rule_id="R1", decision="exception",
                      operator="alice", ttl_days=1)
    record_dismissal(db, rule_id="R2", decision="exception",
                      operator="alice")
    now = int(time.time()) + 2 * 86_400
    active = list_dismissals(db, active_only=True, now_ts=now)
    all_ = list_dismissals(db, active_only=False)
    assert len(active) == 1
    assert len(all_) == 2


# --------------------------------------------------------------------------
# remediation_executor
# --------------------------------------------------------------------------


def test_remediation_preview_returns_draft():
    from safecadence.intelligence import preview_remediation
    r = preview_remediation(
        {"title": "SSH open", "severity": "high", "family": "ssh_open"},
        asset={"hostname": "edge-fw-01", "vendor": "cisco_ios"},
    )
    assert r["ok"] is True
    assert r["source"] in ("recipe", "llm")
    assert r["forward"]
    assert r["rollback"]


def test_remediation_queue_when_no_recipe_returns_not_ok():
    from safecadence.intelligence import queue_remediation
    r = queue_remediation(
        {"title": "?", "family": "unknown", "severity": "low"},
        asset={"hostname": "x", "vendor": "unknown_vendor"},
        operator="alice",
    )
    assert r["ok"] is False
    assert "draft_not_actionable" in r["warnings"]


def test_remediation_queue_with_recipe_degrades_when_execution_unavailable():
    """When v9.x execution.workflow.create_command_job has a different
    signature, we degrade to 'ready but not queued' instead of crashing.
    This test exercises that path since we can't guarantee the v9.x API
    matches across test environments."""
    from safecadence.intelligence import queue_remediation
    r = queue_remediation(
        {"title": "SSH open", "family": "ssh_open", "severity": "high"},
        asset={"hostname": "edge-fw-01", "vendor": "cisco_ios"},
        operator="alice",
    )
    # Either it queued (ok+queued) OR it degraded cleanly (ok+not queued).
    # Either is acceptable; what's NOT acceptable is an unhandled crash.
    assert r["ok"] is True
    assert "draft_source" in r
    assert "warnings" in r
