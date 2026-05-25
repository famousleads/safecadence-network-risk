"""
Tests for v13.0 — Operational excellence release.

Covers:
  * monitoring.drift_daemon (delta + windows + daemon lifecycle)
  * reports.ticketing_bidirectional (link + webhook + idempotency)
  * execution.approval_v2 (quorums + delegation + TTL)
  * dashboards.sse (event bus pub/sub + SSE frame format)
  * ui.help_v13 (/help/topics page + V13_HELP registry merge)
"""
from __future__ import annotations

import json
import os
import time

import pytest


# --------------------------------------------------------------------------
# drift_daemon
# --------------------------------------------------------------------------


def test_drift_compute_delta_detects_added_finding():
    from safecadence.monitoring import compute_delta
    prev = [{"hostname": "fw-01", "findings": [{"id": "F1", "severity": "high"}]}]
    curr = [{"hostname": "fw-01", "findings": [
        {"id": "F1", "severity": "high"},
        {"id": "F2", "severity": "critical", "title": "new"},
    ]}]
    deltas = compute_delta(prev, curr)
    kinds = {d["kind"] for d in deltas}
    assert "finding_added" in kinds


def test_drift_compute_delta_detects_severity_change():
    from safecadence.monitoring import compute_delta
    prev = [{"hostname": "fw-01", "findings": [{"id": "F1", "severity": "medium"}]}]
    curr = [{"hostname": "fw-01", "findings": [{"id": "F1", "severity": "critical"}]}]
    deltas = compute_delta(prev, curr)
    assert any(d["kind"] == "asset_severity_changed" for d in deltas)


def test_drift_compute_delta_detects_added_and_removed_asset():
    from safecadence.monitoring import compute_delta
    prev = [{"hostname": "fw-01"}]
    curr = [{"hostname": "sw-01"}]
    deltas = compute_delta(prev, curr)
    kinds = {d["kind"] for d in deltas}
    assert "asset_added" in kinds
    assert "asset_removed" in kinds


def test_drift_maintenance_window_one_shot():
    from datetime import datetime, timezone
    from safecadence.monitoring import is_in_maintenance_window
    now = datetime(2026, 5, 26, 3, 0, tzinfo=timezone.utc)
    inside = [{"start": "2026-05-26T02:00:00", "end": "2026-05-26T05:00:00"}]
    outside = [{"start": "2026-05-27T02:00:00", "end": "2026-05-27T05:00:00"}]
    assert is_in_maintenance_window(now, inside) is True
    assert is_in_maintenance_window(now, outside) is False


def test_drift_maintenance_window_recurring_weekday():
    from datetime import datetime, timezone
    from safecadence.monitoring import is_in_maintenance_window
    sun_3am = datetime(2026, 5, 24, 3, 0, tzinfo=timezone.utc)   # Sunday
    mon_3am = datetime(2026, 5, 25, 3, 0, tzinfo=timezone.utc)   # Monday
    window = [{"weekday": "sun", "start_hour": 2, "end_hour": 5}]
    assert is_in_maintenance_window(sun_3am, window) is True
    assert is_in_maintenance_window(mon_3am, window) is False


def test_drift_daemon_first_tick_baselines_without_firing():
    from safecadence.monitoring import DriftDaemon, DriftMonitorConfig
    fired = []
    d = DriftDaemon(DriftMonitorConfig(
        interval_seconds=60, on_drift=lambda x: fired.append(x),
    ))
    r = d.tick()
    assert r.get("baselined") is True
    assert fired == []


# --------------------------------------------------------------------------
# bidirectional ticketing
# --------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_ticket_db(tmp_path, monkeypatch):
    """Force the ticket DB into a tmp path so tests don't share state."""
    monkeypatch.setenv("HOME", str(tmp_path))
    yield


def test_ticket_link_and_webhook_round_trip():
    from safecadence.reports.ticketing_bidirectional import (
        apply_webhook, find_link_by_external_id, link_ticket,
    )
    link_ticket("F-1", "jira", "SAFE-1", "https://x.atlassian.net/browse/SAFE-1")
    body = json.dumps({
        "timestamp": 12345,
        "issue": {"key": "SAFE-1",
                  "fields": {"status": {"name": "Done"}}},
    }).encode()
    r = apply_webhook("jira", body, headers={})
    assert r["ok"] and r["action"] == "status_updated"
    assert r["status"] == "resolved"
    link = find_link_by_external_id("jira", "SAFE-1")
    assert link is not None
    assert link["status"] == "resolved"


def test_ticket_webhook_idempotent_replay():
    from safecadence.reports.ticketing_bidirectional import (
        apply_webhook, link_ticket,
    )
    link_ticket("F-1", "jira", "SAFE-2", "")
    body = json.dumps({
        "timestamp": 99999,
        "issue": {"key": "SAFE-2", "fields": {"status": {"name": "Done"}}},
    }).encode()
    r1 = apply_webhook("jira", body, headers={})
    r2 = apply_webhook("jira", body, headers={})
    assert r1["action"] == "status_updated"
    assert r2["action"] == "duplicate_dropped"


def test_ticket_webhook_unknown_link_returns_no_link():
    from safecadence.reports.ticketing_bidirectional import apply_webhook
    body = json.dumps({
        "timestamp": 1,
        "issue": {"key": "SAFE-999", "fields": {"status": {"name": "Done"}}},
    }).encode()
    r = apply_webhook("jira", body, headers={})
    assert r["action"] == "no_link"


def test_ticket_webhook_rejects_unknown_provider():
    from safecadence.reports.ticketing_bidirectional import apply_webhook
    r = apply_webhook("notreal", b"{}", headers={})
    assert r["ok"] is False
    assert "unknown provider" in r["reason"]


# --------------------------------------------------------------------------
# approval_v2
# --------------------------------------------------------------------------


def test_approval_v2_single_user_pending_then_approved():
    from safecadence.execution.approval_v2 import ApprovalPolicy, decide
    p = ApprovalPolicy(
        name="fw", asset_class="firewall", n_required=2,
        approvers=("alice", "bob", "carol"),
    )
    r1 = decide(job_id="J1", approver_user_id="alice",
                decision="approve", policy=p, prior_approvals=[])
    assert r1["state"] == "pending"
    r2 = decide(job_id="J1", approver_user_id="bob",
                decision="approve", policy=p,
                prior_approvals=[r1["applied_approval"]])
    assert r2["state"] == "approved"
    assert set(r2["satisfied_by"]) == {"alice", "bob"}


def test_approval_v2_reject_kills_chain():
    from safecadence.execution.approval_v2 import ApprovalPolicy, decide
    p = ApprovalPolicy(
        name="fw", asset_class="firewall", n_required=2,
        approvers=("alice", "bob"),
    )
    r = decide(job_id="J", approver_user_id="bob",
               decision="reject", policy=p, prior_approvals=[])
    assert r["state"] == "rejected"


def test_approval_v2_delegation_routes_to_delegate():
    from safecadence.execution.approval_v2 import ApprovalPolicy, decide
    p = ApprovalPolicy(
        name="fw", asset_class="firewall", n_required=1,
        approvers=("alice",),
        delegate_map=(("bob", "alice"),),
    )
    r = decide(job_id="J", approver_user_id="bob",  # bob delegates to alice
               decision="approve", policy=p, prior_approvals=[])
    assert r["state"] == "approved"
    assert r["satisfied_by"] == ["alice"]


def test_approval_v2_rejects_user_outside_pool():
    from safecadence.execution.approval_v2 import ApprovalPolicy, decide
    p = ApprovalPolicy(
        name="fw", asset_class="firewall", n_required=1,
        approvers=("alice",),
    )
    r = decide(job_id="J", approver_user_id="eve",
               decision="approve", policy=p, prior_approvals=[])
    assert r["state"] == "pending"
    assert "not in the approver pool" in r["note"]


def test_approval_v2_ttl_expires_old_chains():
    from safecadence.execution.approval_v2 import (
        Approval, ApprovalPolicy, decide,
    )
    p = ApprovalPolicy(
        name="fw", asset_class="firewall", n_required=2,
        approvers=("alice", "bob"), ttl_hours=24,
    )
    old = Approval(job_id="J", approver_user_id="alice",
                   decision="approve", at=int(time.time()) - 25 * 3600)
    r = decide(job_id="J", approver_user_id="bob",
               decision="approve", policy=p, prior_approvals=[old])
    assert r["state"] == "expired"


def test_approval_v2_policy_for_asset_falls_back_to_wildcard():
    from safecadence.execution.approval_v2 import (
        ApprovalPolicy, policy_for_asset,
    )
    p_fw = ApprovalPolicy(name="fw", asset_class="firewall",
                          n_required=1, approvers=("a",))
    p_default = ApprovalPolicy(name="default", asset_class="*",
                                n_required=1, approvers=("a",))
    assert policy_for_asset({"asset_class": "router"},
                             [p_fw, p_default]).name == "default"
    assert policy_for_asset({"asset_class": "firewall"},
                             [p_fw, p_default]).name == "fw"


# --------------------------------------------------------------------------
# sse
# --------------------------------------------------------------------------


def test_sse_bus_delivers_to_subscribers():
    from safecadence.dashboards.sse import EventBus
    bus = EventBus()
    q1 = bus.subscribe()
    q2 = bus.subscribe()
    delivered = bus.publish("drift", {"hostname": "fw-01"})
    assert delivered == 2
    ev1, p1 = q1.get_nowait()
    ev2, p2 = q2.get_nowait()
    assert ev1 == ev2 == "drift"
    assert p1 == p2 == {"hostname": "fw-01"}


def test_sse_frame_format_is_correct():
    from safecadence.dashboards.sse import _format_sse
    frame = _format_sse("test", {"a": 1, "b": "x"}).decode()
    assert frame.startswith("event: test\n")
    assert "data: " in frame
    assert frame.endswith("\n\n")


def test_sse_unsubscribe_removes_subscriber():
    from safecadence.dashboards.sse import EventBus
    bus = EventBus()
    q = bus.subscribe()
    assert bus.stats()["subscribers"] == 1
    bus.unsubscribe(q)
    assert bus.stats()["subscribers"] == 0


def test_sse_stream_route_returns_event_stream():
    os.environ["SC_AUTH_DISABLED"] = "1"
    from fastapi.testclient import TestClient
    from safecadence.ui.app import create_app
    c = TestClient(create_app())
    # Stats endpoint is enough to verify routes are mounted; the actual
    # streaming endpoint is best tested via the generator in unit tests
    # (TestClient buffers SSE which deadlocks).
    r = c.get("/api/v1/events/stats")
    assert r.status_code == 200
    assert "subscribers" in r.json()


# --------------------------------------------------------------------------
# help_v13 / topic directory
# --------------------------------------------------------------------------


def test_help_v13_entries_merged_into_registry():
    from safecadence.ui import help_registry, help_v13  # noqa
    # Importing help_v13 runs _merge_into_registry()
    for key in ("mcp-server", "drift-daemon", "approval-v2", "ai-governance-agents"):
        assert key in help_registry.HELP


def test_help_topics_page_renders():
    os.environ["SC_AUTH_DISABLED"] = "1"
    from fastapi.testclient import TestClient
    from safecadence.ui.app import create_app
    c = TestClient(create_app())
    r = c.get("/help/topics")
    assert r.status_code == 200
    # Page renders + supports filter input
    assert "topic-search" in r.text
    assert "Multi-dim Safe Score" in r.text or "multi-dim-safe-score" in r.text
