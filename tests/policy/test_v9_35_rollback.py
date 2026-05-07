"""
v9.35 #2 — Rollback plan generator tests.

Pinned trust property: ``_generate_rollback_plan`` must produce
operationally correct inverse commands, not just record that a
rollback happened. Each test below pins one mutation pattern.
"""

from __future__ import annotations

import pytest

pytest.importorskip("yaml", reason="execution engine deps")


def _make_job(commands_by_vendor):
    """Build a CommandJob with inline commands. Skips the full
    constructor so we don't need to set every field."""
    from safecadence.execution.schema import (
        CommandJob, CommandMode, JobStatus,
    )
    job = CommandJob(
        job_id="job-test", name="t", description="t",
        mode=CommandMode.CONFIG, status=JobStatus.APPROVED,
    )
    job.inline_commands = dict(commands_by_vendor)
    return job


def test_rollback_inverts_simple_no_prefix():
    """'no shutdown' must roll back to 'shutdown'."""
    from safecadence.execution.workflow import _generate_rollback_plan
    job = _make_job({"cisco_ios": ["no shutdown"]})
    plan = _generate_rollback_plan(job)
    assert plan.asset_rollbacks["cisco_ios"] == ["shutdown"]


def test_rollback_inverts_shutdown_to_no_shutdown():
    from safecadence.execution.workflow import _generate_rollback_plan
    job = _make_job({"cisco_ios": ["shutdown"]})
    plan = _generate_rollback_plan(job)
    assert plan.asset_rollbacks["cisco_ios"] == ["no shutdown"]


def test_rollback_preserves_remainder_of_line():
    """Critical: 'ip route 10.0.0.0 255.0.0.0 1.1.1.1' should invert
    to 'no ip route 10.0.0.0 255.0.0.0 1.1.1.1' — the remainder must
    survive the prefix flip, otherwise rollback removes nothing."""
    from safecadence.execution.workflow import _generate_rollback_plan
    job = _make_job({"cisco_ios": [
        "ip route 10.0.0.0 255.0.0.0 1.1.1.1",
    ]})
    plan = _generate_rollback_plan(job)
    out = plan.asset_rollbacks["cisco_ios"]
    assert out == ["no ip route 10.0.0.0 255.0.0.0 1.1.1.1"], (
        f"Expected the remainder of the line to be preserved; got {out!r}"
    )


def test_rollback_inverts_in_reverse_order():
    """Multi-command jobs must roll back last-in, first-out so
    dependencies are torn down in the right order."""
    from safecadence.execution.workflow import _generate_rollback_plan
    job = _make_job({"cisco_ios": [
        "ip http server",
        "snmp-server community public RO",
    ]})
    plan = _generate_rollback_plan(job)
    out = plan.asset_rollbacks["cisco_ios"]
    # snmp was added LAST → must be undone FIRST
    assert out[0].startswith("no snmp-server community")
    assert out[1] == "no ip http server"


def test_rollback_marks_interface_block_for_review():
    """We must NOT auto-rollback 'interface eth0' to 'no interface
    eth0' — that deletes the interface entirely. Operator-edit only."""
    from safecadence.execution.workflow import _generate_rollback_plan
    job = _make_job({"cisco_ios": ["interface GigabitEthernet0/1"]})
    plan = _generate_rollback_plan(job)
    out = plan.asset_rollbacks["cisco_ios"]
    assert out and out[0].startswith("# REVIEW"), (
        "Interface blocks must be flagged for manual review, never "
        "auto-inverted (would delete the interface)"
    )


def test_rollback_inverts_junos_set_to_delete():
    """Junos config commands use set/delete — symmetric inversion."""
    from safecadence.execution.workflow import _generate_rollback_plan
    job = _make_job({"junos": [
        "set system services ssh root-login deny",
    ]})
    plan = _generate_rollback_plan(job)
    out = plan.asset_rollbacks["junos"]
    assert out[0].startswith("delete "), (
        f"Junos set→delete inversion broken; got {out!r}"
    )


def test_rollback_unknown_command_emits_review_marker():
    """Anything we can't auto-invert must emit a # REVIEW line, not
    silently drop the command. Operator must know what's missing."""
    from safecadence.execution.workflow import _generate_rollback_plan
    job = _make_job({"cisco_ios": ["completely-unknown-command xyz"]})
    plan = _generate_rollback_plan(job)
    out = plan.asset_rollbacks["cisco_ios"]
    assert out and out[0].startswith("# REVIEW"), (
        "Unknown commands must produce a REVIEW marker so the "
        "operator notices the gap"
    )


def test_rollback_drops_comments_and_blanks():
    """Comments and blank lines shouldn't generate undo commands."""
    from safecadence.execution.workflow import _generate_rollback_plan
    job = _make_job({"cisco_ios": [
        "# this is a comment",
        "",
        "! Cisco-style banner",
        "shutdown",
    ]})
    plan = _generate_rollback_plan(job)
    out = plan.asset_rollbacks["cisco_ios"]
    assert out == ["no shutdown"]


def test_rollback_per_vendor_isolation():
    """A multi-vendor job must produce per-vendor rollback lists."""
    from safecadence.execution.workflow import _generate_rollback_plan
    job = _make_job({
        "cisco_ios": ["shutdown"],
        "junos":     ["set system services ssh root-login deny"],
    })
    plan = _generate_rollback_plan(job)
    assert "cisco_ios" in plan.asset_rollbacks
    assert "junos" in plan.asset_rollbacks
    assert plan.asset_rollbacks["cisco_ios"] == ["no shutdown"]
    assert plan.asset_rollbacks["junos"][0].startswith("delete ")


# ----------------------------------------------------- v9.35 #5 builder AI


def test_builder_ai_fallback_skipped_when_disabled(monkeypatch):
    """SC_AI_DISABLED=1 must skip the AI path entirely — air-gap
    deployments must not reach for any provider."""
    monkeypatch.setenv("SC_AI_DISABLED", "1")
    from safecadence.execution.builder import build_plan
    plan = build_plan("undocumented intent that no pack matches")
    assert plan.matched_packs == []
    assert "AI fallback was unavailable" in plan.summary


def test_builder_ai_fallback_skipped_when_no_provider(monkeypatch):
    """Without an API key, the AI fallback returns None and the
    operator gets the existing 'no pack matched' message."""
    for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY",
                "OLLAMA_HOST", "SAFECADENCE_LOCAL_LLM"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.delenv("SC_AI_DISABLED", raising=False)
    from safecadence.execution.builder import build_plan
    plan = build_plan("xyzzy frobnicate the widget")
    assert plan.matched_packs == []


# ----------------------------------------------------- v9.35 #4 notify


def test_approval_notification_skipped_when_no_webhook(monkeypatch):
    """When no webhook is configured, _notify_approval_requested is a
    no-op — must NOT raise. The audit log already captures the event;
    the notifier is a degradable nice-to-have."""
    for k in ("SC_SLACK_WEBHOOK", "SAFECADENCE_SLACK_WEBHOOK",
                "SC_WEBHOOK_URL"):
        monkeypatch.delenv(k, raising=False)
    from safecadence.execution.workflow import _notify_approval_requested
    from safecadence.execution.schema import (
        ApprovalRequest, CommandJob, JobStatus, RiskLevel,
    )
    job = CommandJob(job_id="job-x", name="t", risk=RiskLevel.HIGH,
                       status=JobStatus.REVIEW)
    req = ApprovalRequest(job_id="job-x", requested_by="alice")
    # Must not raise.
    _notify_approval_requested(job, req, "alice")


def test_approval_notification_payload_shape(monkeypatch):
    """Stub the notifier and assert the structured payload contains
    job_id, risk, target_count, link, and the right severity."""
    captured = {}

    def fake_notify(webhook, events, *, signing_secret=None):
        captured["webhook"] = webhook
        captured["events"] = events
        return {"sent": True}

    import safecadence.notifier as notifier_mod
    monkeypatch.setattr(notifier_mod, "notify", fake_notify)
    monkeypatch.setenv("SC_SLACK_WEBHOOK",
                        "https://hooks.slack.com/services/T/B/X")

    from safecadence.execution.workflow import _notify_approval_requested
    from safecadence.execution.schema import (
        ApprovalRequest, CommandJob, JobStatus, RiskLevel,
    )
    job = CommandJob(job_id="job-y", name="patch routes",
                       risk=RiskLevel.CRITICAL, status=JobStatus.REVIEW,
                       target_asset_ids=["r1", "r2", "r3"])
    req = ApprovalRequest(job_id="job-y", requested_by="alice")
    _notify_approval_requested(job, req, "alice")
    assert captured["events"], "notifier must have been called"
    ev = captured["events"][0]
    # v9.44 — renamed from "execution_approval_requested" to the
    # NOTIFY_CATEGORIES-aligned "approval_requested" so the same key
    # serves the registry, the per-user prefs, and the webhook filters.
    assert ev["kind"] == "approval_requested"
    assert ev["job_id"] == "job-y"
    assert ev["risk"] == "critical"
    # CRITICAL-risk job → severity escalates to 'critical' so the
    # notifier prioritizes the page appropriately.
    assert ev["severity"] == "critical"
    assert ev["target_count"] == 3
    assert ev["requested_by"] == "alice"
    assert ev["link"].startswith("/approvals")
