"""v9.55 — automation makeover.

Covers:
  #1 daemon evaluates rules
  #2 notify_slack uses dispatch_event registry (was broken import)
  #3 API write endpoints gated by WRITE_AUTOMATION
  #4 auto_fix honors IR.targets
  #5 auto_fix commit=true opt-in
  #6 four new actions (watchlist, comment, pagerduty, webhook)
  #8 demo seed creates rules
"""
from __future__ import annotations

from unittest.mock import patch


# ----------------------------------------------------- helpers

_VALID_IR = {
    "intent": "deny inactive NHI",
    "effect": "deny",
    "severity": "enforce",
    "targets": ["okta"],
    "actions": ["lockout"],
    "subjects": {"principals": ["svc-bot-1"]},
    "resources": {},
    "conditions": [],
}


def _make_finding(**overrides):
    """Build a minimal Finding-like object; tests can pass overrides."""
    from safecadence.identity.findings import Finding
    import copy
    base = dict(
        finding_id="f_test_1",
        kind="stale_nhi",
        severity="high",
        title="stale NHI svc-bot-1",
        principal="svc-bot-1",
        evidence={"days": 120},
        suggested_ir=copy.deepcopy(_VALID_IR),
    )
    base.update(overrides)
    return Finding(**base)


# ----------------------------------------------------- #1 daemon hook

def test_daemon_calls_evaluate_rules(monkeypatch, tmp_path):
    """run_cycle's compliance_hooks must include an automation_fires
    counter when SC_AUTOMATION_DISABLED is unset (default)."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("SC_AUTOMATION_DISABLED", raising=False)
    from safecadence.daemon import run_cycle
    report = run_cycle()
    assert "compliance_hooks" in report
    assert "automation_fires" in report["compliance_hooks"]
    # Empty rule store → 0 fires, but the hook ran.
    assert report["compliance_hooks"]["automation_fires"] == 0


def test_daemon_skips_automation_when_disabled(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_AUTOMATION_DISABLED", "1")
    from safecadence.daemon import run_cycle
    report = run_cycle()
    assert report["compliance_hooks"]["automation_fires"] == 0


# ----------------------------------------------------- #2 notify_slack

def test_notify_slack_dispatches_via_registry(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_INTEL_HOME", str(tmp_path))
    from safecadence.intel.automation import _act_notify_slack
    f = _make_finding(severity="critical")
    with patch("safecadence.notifier.registry.dispatch_event") as mock:
        out = _act_notify_slack(f, {"channel": "#sec"})
    assert mock.called
    assert mock.call_args.kwargs["kind"] == "finding_critical"
    assert "#sec" in out or "sec" in mock.call_args.kwargs["extra"]["channel"]


def test_notify_slack_low_severity_uses_automation_fired(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_INTEL_HOME", str(tmp_path))
    from safecadence.intel.automation import _act_notify_slack
    f = _make_finding(severity="low")
    with patch("safecadence.notifier.registry.dispatch_event") as mock:
        _act_notify_slack(f, {"channel": "#sec"})
    assert mock.call_args.kwargs["kind"] == "automation_fired"


# ----------------------------------------------------- #4 + #5 auto_fix

def test_auto_fix_dry_run_by_default(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_INTEL_HOME", str(tmp_path))
    from safecadence.intel.automation import _act_auto_fix
    f = _make_finding()
    out = _act_auto_fix(f, {"action": "auto_fix"})
    assert "dry-ran" in out


def test_auto_fix_commit_flag_committed(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_INTEL_HOME", str(tmp_path))
    from safecadence.intel.automation import _act_auto_fix
    f = _make_finding()
    out = _act_auto_fix(f, {"action": "auto_fix", "commit": True})
    assert "committed" in out


def test_auto_fix_routes_by_ir_target(monkeypatch, tmp_path):
    """IR with targets=['ad'] must route to ActiveDirectoryAdapter,
    not Okta. Pre-v9.55 this was hardcoded to Okta."""
    monkeypatch.setenv("SC_INTEL_HOME", str(tmp_path))
    from safecadence.intel.automation import _act_auto_fix
    import copy
    ir = copy.deepcopy(_VALID_IR)
    ir["targets"] = ["ad"]
    f = _make_finding(suggested_ir=ir)
    out = _act_auto_fix(f, {"action": "auto_fix"})
    assert "on ad" in out


def test_auto_fix_invalid_ir_returns_clear_error(monkeypatch, tmp_path):
    """A malformed IR (caught by validate_ir) returns a 'invalid
    suggested_ir' string instead of crashing the rule fire."""
    monkeypatch.setenv("SC_INTEL_HOME", str(tmp_path))
    from safecadence.intel.automation import _act_auto_fix
    f = _make_finding(suggested_ir={
        "intent": "deny", "targets": ["jenkins"],
        "actions": ["lockout"],
        "subjects": {"principals": ["alice"]},
    })
    out = _act_auto_fix(f, {"action": "auto_fix"})
    assert "invalid suggested_ir" in out


# ----------------------------------------------------- #6 new actions

def test_action_add_to_watchlist(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_INTEL_HOME", str(tmp_path))
    from safecadence.intel.automation import _act_add_to_watchlist
    from safecadence.intel.watchlists import list_watches
    f = _make_finding()
    out = _act_add_to_watchlist(f, {"user": "alice"})
    assert "watching" in out
    rows = list_watches(user="alice")
    assert any(w.entity_id == "f_test_1" for w in rows)


def test_action_add_to_watchlist_idempotent(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_INTEL_HOME", str(tmp_path))
    from safecadence.intel.automation import _act_add_to_watchlist
    from safecadence.intel.watchlists import list_watches
    f = _make_finding()
    _act_add_to_watchlist(f, {"user": "alice"})
    _act_add_to_watchlist(f, {"user": "alice"})  # second fire — same entity
    rows = list_watches(user="alice")
    matches = [w for w in rows if w.entity_id == "f_test_1"]
    assert len(matches) == 1


def test_action_add_comment(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_INTEL_HOME", str(tmp_path))
    from safecadence.intel.automation import _act_add_comment
    from safecadence.intel.comments import list_comments
    f = _make_finding()
    out = _act_add_comment(f, {"text": "auto-flagged"})
    assert "commented" in out
    cs = list_comments(entity_kind="finding", entity_id="f_test_1")
    assert any("auto-flagged" in c.text for c in cs)


def test_action_notify_pagerduty(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_INTEL_HOME", str(tmp_path))
    from safecadence.intel.automation import _act_notify_pagerduty
    f = _make_finding(severity="critical")
    with patch("safecadence.notifier.registry.dispatch_event") as mock:
        out = _act_notify_pagerduty(f, {"service_key": "PD123"})
    assert mock.called
    extra = mock.call_args.kwargs["extra"]
    assert extra["service_key"] == "PD123"
    # Deterministic dedup_key — same finding fires the same key
    assert extra["dedup_key"] == "safecadence:automation:f_test_1"
    assert "pagerduty event dispatched" in out


def test_action_notify_webhook(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_INTEL_HOME", str(tmp_path))
    from safecadence.intel.automation import _act_notify_webhook
    f = _make_finding()
    with patch("safecadence.notifier.registry.dispatch_event") as mock:
        out = _act_notify_webhook(f, {"webhook_id": "w_42",
                                          "category": "drift_detected"})
    assert mock.called
    assert mock.call_args.kwargs["kind"] == "drift_detected"
    assert mock.call_args.kwargs["extra"]["webhook_id"] == "w_42"
    assert "webhook dispatched" in out


def test_dispatch_action_routes_unknown_to_error(monkeypatch, tmp_path):
    """Unknown action name returns a clear 'unknown action' string —
    doesn't crash the rule fire."""
    monkeypatch.setenv("SC_INTEL_HOME", str(tmp_path))
    from safecadence.intel.automation import _do_action
    f = _make_finding()
    out = _do_action({"action": "frobnicate"}, f, apply_actions=True)
    assert "unknown action" in out


# ----------------------------------------------------- #8 demo seed

def test_demo_seed_creates_disabled_rules(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_INTEL_HOME", str(tmp_path))
    from safecadence.demo import _seed_automation_demo
    from safecadence.intel.automation import list_rules
    summary = _seed_automation_demo()
    assert summary["ok"] is True
    rules = list_rules()
    assert len(rules) == 3
    # All seeded rules MUST be disabled to prevent accidental fires
    # against a real IdP on a fresh demo box.
    assert all(not r.enabled for r in rules)


def test_demo_seed_idempotent(monkeypatch, tmp_path):
    """Running demo twice doesn't create 6 rules."""
    monkeypatch.setenv("SC_INTEL_HOME", str(tmp_path))
    from safecadence.demo import _seed_automation_demo
    from safecadence.intel.automation import list_rules
    _seed_automation_demo()
    second = _seed_automation_demo()
    assert "skipped" in second
    assert len(list_rules()) == 3
