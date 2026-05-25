"""
Tests for v16.0 — behavioral agents layer.

Covers memory, nudges, adversarial pair, drift explainer,
regulatory watcher, and the four new UI routes.
"""
from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import time
from pathlib import Path

import pytest


# --------------------------------------------------------------------------
# memory
# --------------------------------------------------------------------------


@pytest.fixture()
def mem_conn():
    from safecadence.agents.memory import ensure_memory_schema
    c = sqlite3.connect(":memory:")
    ensure_memory_schema(c)
    return c


def test_memory_record_and_recall(mem_conn):
    from safecadence.agents.memory import record, recall
    nid = record(mem_conn, agent_id="a", kind="observation",
                  signature="sig1", payload={"x": 1})
    assert nid > 0
    rows = recall(mem_conn, "a")
    assert len(rows) == 1
    assert rows[0]["payload"] == {"x": 1}


def test_memory_has_recent_dedup(mem_conn):
    from safecadence.agents.memory import has_recent, record
    record(mem_conn, agent_id="a", kind="nudge_sent", signature="sig1")
    assert has_recent(mem_conn, agent_id="a", signature="sig1") is True
    assert has_recent(mem_conn, agent_id="a", signature="other") is False


def test_memory_forget_removes_rows(mem_conn):
    from safecadence.agents.memory import forget, has_recent, record
    record(mem_conn, agent_id="a", kind="decision", signature="sig1")
    forget(mem_conn, "a", "sig1")
    assert has_recent(mem_conn, agent_id="a", signature="sig1") is False


def test_memory_rejects_unknown_kind(mem_conn):
    from safecadence.agents.memory import record
    with pytest.raises(ValueError):
        record(mem_conn, agent_id="a", kind="bogus", signature="x")


def test_memory_prune_expired(mem_conn):
    from safecadence.agents.memory import prune_expired, record
    record(mem_conn, agent_id="a", kind="observation",
            signature="sig", ttl_days=1)
    future = int(time.time()) + 5 * 86400
    deleted = prune_expired(mem_conn, now_ts=future)
    assert deleted == 1


# --------------------------------------------------------------------------
# nudges
# --------------------------------------------------------------------------


@pytest.fixture()
def nudge_conn():
    from safecadence.agents.memory import ensure_memory_schema
    from safecadence.agents.nudges import ensure_nudge_schema
    c = sqlite3.connect(":memory:")
    ensure_memory_schema(c)
    ensure_nudge_schema(c)
    return c


def test_create_nudge_returns_id(nudge_conn):
    from safecadence.agents.nudges import create_nudge
    nid = create_nudge(nudge_conn, agent_id="a", signature="s",
                        title="T", body="B")
    assert nid > 0


def test_create_nudge_dedups_on_signature(nudge_conn):
    from safecadence.agents.nudges import create_nudge
    create_nudge(nudge_conn, agent_id="a", signature="s",
                  title="T", body="B")
    second = create_nudge(nudge_conn, agent_id="a", signature="s",
                          title="T2", body="B2")
    assert second == 0


def test_accept_nudge_changes_status(nudge_conn):
    from safecadence.agents.nudges import (
        accept_nudge, create_nudge, list_nudges,
    )
    nid = create_nudge(nudge_conn, agent_id="a", signature="s",
                        title="T", body="B")
    accept_nudge(nudge_conn, nid, "alice")
    pending = list_nudges(nudge_conn, status="pending")
    accepted = list_nudges(nudge_conn, status="accepted")
    assert pending == []
    assert len(accepted) == 1


def test_snooze_then_promote_due(nudge_conn):
    from safecadence.agents.nudges import (
        create_nudge, list_nudges, promote_due_snoozes, snooze_nudge,
    )
    nid = create_nudge(nudge_conn, agent_id="a", signature="s",
                        title="T", body="B")
    snooze_nudge(nudge_conn, nid, "alice", days=3)
    assert list_nudges(nudge_conn, status="pending") == []
    future = int(time.time()) + 4 * 86400
    promoted = promote_due_snoozes(nudge_conn, now_ts=future)
    assert promoted == 1
    assert len(list_nudges(nudge_conn, status="pending")) == 1


def test_nudge_summary_counts(nudge_conn):
    from safecadence.agents.nudges import (
        accept_nudge, create_nudge, nudge_summary,
    )
    n1 = create_nudge(nudge_conn, agent_id="a", signature="s1",
                       title="T", body="B")
    create_nudge(nudge_conn, agent_id="a", signature="s2",
                  title="T", body="B")
    accept_nudge(nudge_conn, n1, "alice")
    s = nudge_summary(nudge_conn)
    assert s["pending"] == 1
    assert s["accepted"] == 1


def test_create_nudge_rejects_unknown_severity(nudge_conn):
    from safecadence.agents.nudges import create_nudge
    with pytest.raises(ValueError):
        create_nudge(nudge_conn, agent_id="a", signature="s",
                      title="T", body="B", severity="ULTRACRIT")


# --------------------------------------------------------------------------
# adversarial
# --------------------------------------------------------------------------


def _fake_graph_with_path():
    """Build a tiny fleet that produces at least one red-walker path."""
    from safecadence.graph.build import build_graph_from_assets
    from safecadence.graph.schema import Edge
    from safecadence.graph.store import GraphStore
    g = GraphStore()
    build_graph_from_assets(g, [
        {"hostname": "edge-fw-01", "vendor": "cisco_ios",
         "crown_jewel": False,
         "findings": [{"id": "F1", "severity": "high",
                       "title": "SSH open",
                       "controls": [{"control_id": "CC6.1",
                                     "framework": "soc2",
                                     "title": "Access"}]}]},
        {"hostname": "db-crown-01", "vendor": "postgres",
         "crown_jewel": True,
         "findings": []},
    ])
    g.add_edge(Edge("asset", "edge-fw-01", "depends_on",
                     "asset", "db-crown-01"))
    return g


def test_adversarial_run_red_finds_path():
    from safecadence.agents.adversarial import run_red
    g = _fake_graph_with_path()
    candidates = run_red(g)
    assert len(candidates) >= 1
    assert "path" in candidates[0]
    assert "red_says" in candidates[0]


def test_adversarial_run_blue_annotates_verdict():
    from safecadence.agents.adversarial import run_blue, run_red
    g = _fake_graph_with_path()
    candidates = run_red(g)
    verdicts = run_blue(g, candidates)
    for v in verdicts:
        assert "agreement" in v
        assert v["agreement"] in (
            "agree_exposed", "agree_safe", "disagreement",
        )


def test_adversarial_run_round_returns_summary(nudge_conn):
    from safecadence.agents.adversarial import run_round
    g = _fake_graph_with_path()
    summary = run_round(g, nudge_conn=nudge_conn)
    assert "candidates" in summary
    assert "agreements_exposed" in summary
    assert "disagreements" in summary
    assert "nudges_created" in summary


# --------------------------------------------------------------------------
# drift_explainer
# --------------------------------------------------------------------------


def test_drift_identify_responsible_engineer(tmp_path):
    from safecadence.agents.drift_explainer import (
        identify_responsible_engineer,
    )
    log = tmp_path / "audit.jsonl"
    log.write_text("\n".join([
        json.dumps({"actor": "alice@x", "resource": "edge-fw-01",
                     "at": 1000}),
        json.dumps({"actor": "bob@x", "resource": "edge-fw-01",
                     "at": 2000}),
        json.dumps({"actor": "carol@x", "resource": "other",
                     "at": 3000}),
    ]))
    result = identify_responsible_engineer(
        {"hostname": "edge-fw-01"}, audit_log_path=log,
    )
    assert result == "bob@x"


def test_drift_identify_returns_none_when_no_match(tmp_path):
    from safecadence.agents.drift_explainer import (
        identify_responsible_engineer,
    )
    log = tmp_path / "audit.jsonl"
    log.write_text("")
    assert identify_responsible_engineer(
        {"hostname": "edge-fw-01"}, audit_log_path=log,
    ) is None


def test_drift_explain_creates_nudge(nudge_conn, tmp_path):
    from safecadence.agents.drift_explainer import explain_drift
    log = tmp_path / "audit.jsonl"
    log.write_text(
        json.dumps({"actor": "bob", "resource": "fw-01", "at": 1})
    )
    drift = {"kind": "finding_added", "hostname": "fw-01",
              "finding_id": "F1", "severity": "high",
              "detail": "Something drifted"}
    r = explain_drift(drift, nudge_conn=nudge_conn, audit_log_path=log)
    assert r["nudge_id"] > 0
    assert r["responsible_user"] == "bob"


def test_drift_explain_dedup_on_replay(nudge_conn, tmp_path):
    from safecadence.agents.drift_explainer import explain_drift
    log = tmp_path / "audit.jsonl"
    log.write_text("")
    drift = {"kind": "finding_added", "hostname": "fw-01",
              "finding_id": "F1", "severity": "high",
              "detail": "drift"}
    r1 = explain_drift(drift, nudge_conn=nudge_conn, audit_log_path=log)
    r2 = explain_drift(drift, nudge_conn=nudge_conn, audit_log_path=log)
    assert r1["nudge_id"] > 0
    assert r2["nudge_id"] == 0  # deduped


def test_drift_handle_response_intentional(nudge_conn, tmp_path):
    from safecadence.agents.drift_explainer import (
        explain_drift, handle_response,
    )
    log = tmp_path / "audit.jsonl"
    log.write_text("")
    drift = {"kind": "finding_added", "hostname": "fw-01",
              "severity": "high", "detail": "x"}
    r = explain_drift(drift, nudge_conn=nudge_conn, audit_log_path=log)
    h = handle_response(nudge_conn, r["nudge_id"],
                         answer="intentional", operator="alice")
    assert h["action"] == "exception_filed"
    assert h["ok"]


# --------------------------------------------------------------------------
# regulatory_watcher
# --------------------------------------------------------------------------


def test_classify_matches_vendor():
    from safecadence.agents.regulatory_watcher import classify_relevance
    items = [{"id": "1", "vendor": "Cisco",
               "description": "RCE in IOS-XE", "source": "kev"}]
    out = classify_relevance(items, fleet_vendors=["cisco"],
                              frameworks=[])
    assert out[0]["relevant"] is True


def test_classify_matches_framework_in_description():
    from safecadence.agents.regulatory_watcher import classify_relevance
    items = [{"id": "1", "title": "NIST 800-53 rev 6 published",
               "description": "Rev 6 of NIST 800-53 is now active.",
               "source": "pub"}]
    out = classify_relevance(items, fleet_vendors=[],
                              frameworks=["nist-800-53"])
    assert out[0]["relevant"] is True


def test_classify_marks_unrelated_irrelevant():
    from safecadence.agents.regulatory_watcher import classify_relevance
    items = [{"id": "1", "vendor": "weird",
               "description": "totally unrelated", "source": "kev"}]
    out = classify_relevance(items, fleet_vendors=["cisco"],
                              frameworks=["soc2"])
    assert out[0]["relevant"] is False


def test_fetch_feed_dead_url_returns_empty():
    from safecadence.agents.regulatory_watcher import fetch_feed
    out = fetch_feed("http://127.0.0.1:1/nope", timeout=1)
    assert out == []


def test_run_watch_pass_with_dead_feed_no_crash(nudge_conn):
    from safecadence.agents.regulatory_watcher import run_watch_pass
    s = run_watch_pass(
        nudge_conn=nudge_conn,
        fleet_vendors=["cisco"],
        frameworks=["nist-800-53"],
        feeds={"fake": "http://127.0.0.1:1/nope"},
    )
    assert s["items_fetched"] == 0
    assert s["nudges_created"] == 0


# --------------------------------------------------------------------------
# UI routes
# --------------------------------------------------------------------------


@pytest.fixture()
def web_client(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("SC_AUTH_DISABLED", "1")
    monkeypatch.delenv("SC_READONLY", raising=False)
    from fastapi.testclient import TestClient
    from safecadence.ui.app import create_app
    return TestClient(create_app())


def test_route_nudges_renders(web_client):
    r = web_client.get("/nudges")
    assert r.status_code == 200
    assert "<title>" in r.text


def test_route_red_vs_blue_renders(web_client):
    r = web_client.get("/red-vs-blue")
    assert r.status_code == 200


def test_route_agent_new_form_renders(web_client):
    r = web_client.get("/ai-agents/new")
    assert r.status_code == 200
    assert "Register" in r.text or "register" in r.text.lower()


def test_route_agent_create_via_post(web_client):
    r = web_client.post(
        "/api/v1/agents/create",
        data={"name": "QA bot", "owner_user_id": "alice@x",
              "model": "gpt-4o-mini", "allowed_tools": "query_topology"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    # Now /ai-agents should list it
    r2 = web_client.get("/ai-agents")
    assert "QA bot" in r2.text


def test_route_nudge_action_readonly_blocked(web_client, monkeypatch):
    monkeypatch.setenv("SC_READONLY", "1")
    r = web_client.post("/api/v1/nudges/1/accept")
    assert r.status_code == 403


def test_route_unknown_nudge_verb_returns_400(web_client):
    r = web_client.post("/api/v1/nudges/1/explode")
    assert r.status_code == 400
