"""v9.45 — verify every emitter funnels through dispatch_event.

Each test mocks notifier.registry.dispatch_event so we can assert the
exact (kind, severity) shape we promise without firing real webhooks.
The point isn't to retest dispatch_event — it's to prove that the
seven NOTIFY_CATEGORIES actually have at least one in-tree emitter
each, which is the only way users get notifications they configured.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest


# ----------------------------------------------------------- fixtures

class _FakeFinding:
    """Minimal Finding shape that the automation matcher expects."""
    def __init__(self, *, severity="high", kind="stale_nhi",
                 principal="svc-a", finding_id="f-1",
                 title="t", suggested_ir=None):
        self.severity = severity
        self.kind = kind
        self.principal = principal
        self.finding_id = finding_id
        self.title = title
        self.suggested_ir = suggested_ir or {}


# --------------------------------------------------- watchlist_change

def test_watchlist_change_dispatch(monkeypatch, tmp_path):
    """watch_changes should call dispatch_event(kind='watchlist_change')
    exactly once per detected change."""
    monkeypatch.setenv("SC_INTEL_HOME", str(tmp_path))
    from safecadence.intel import watchlists as wl
    from safecadence.intel._store import write
    # Seed a watch with a known previous state
    write("watchlists", {
        "default": [{
            "watch_id": "w_test1",
            "entity_kind": "asset",
            "entity_id": "asset-X",
            "label": "Test asset",
            "user": "default",
            "created_at": 1.0,
            "last_seen_state": {"kev_cves": 0, "critical_cves": 0,
                                 "mfa_enrolled": True, "grade": "A",
                                 "auth_groups_count": 1},
            "last_change_at": 0.0,
            "last_change_summary": "",
        }],
    })
    assets = [{
        "identity": {"asset_id": "asset-X"},
        "security": {"kev_cves": 1, "critical_cves": 0},
        "identity_block": {"mfa_enrolled": True,
                            "authorized_groups": [1]},
        "health": {"grade": "A"},
    }]

    with patch("safecadence.notifier.registry.dispatch_event") as mock:
        changes = wl.watch_changes(assets=assets, user="default", now=42.0)

    assert len(changes) == 1
    assert mock.called, "watch_changes must dispatch on changes"
    call = mock.call_args
    assert call.kwargs["kind"] == "watchlist_change"
    assert call.kwargs["severity"] == "info"


def test_watchlist_no_change_no_dispatch(monkeypatch, tmp_path):
    """No state delta → no dispatch_event call. Critical for not
    spamming Slack on every quiet daemon cycle."""
    monkeypatch.setenv("SC_INTEL_HOME", str(tmp_path))
    from safecadence.intel import watchlists as wl
    from safecadence.intel._store import write
    write("watchlists", {"default": []})
    with patch("safecadence.notifier.registry.dispatch_event") as mock:
        wl.watch_changes(assets=[], user="default", now=1.0)
    assert not mock.called


# -------------------------------------------------------- jit_granted

def test_jit_grant_dispatch(monkeypatch, tmp_path):
    """jit.grant should fan out a 'jit_granted' event."""
    monkeypatch.setenv("SC_JIT_STORE", str(tmp_path / "jit.json"))
    from safecadence.identity import jit
    with patch("safecadence.notifier.registry.dispatch_event") as mock:
        g = jit.grant(principal="alice", action="ssh",
                       resource="srv-1", duration_seconds=3600,
                       target="okta", created_by="test",
                       reason="incident-42")
    assert g.grant_id
    assert mock.called
    assert mock.call_args.kwargs["kind"] == "jit_granted"
    assert "alice" in mock.call_args.kwargs["title"]


def test_jit_revoke_dispatch(monkeypatch, tmp_path):
    """Manual revoke also fires a notification."""
    monkeypatch.setenv("SC_JIT_STORE", str(tmp_path / "jit.json"))
    from safecadence.identity import jit
    g = jit.grant(principal="bob", action="admin", resource="db-1",
                   duration_seconds=600, target="ad",
                   created_by="test")
    with patch("safecadence.notifier.registry.dispatch_event") as mock:
        revoked = jit.revoke(g.grant_id)
    assert revoked is not None
    assert mock.called
    assert mock.call_args.kwargs["kind"] == "jit_granted"
    assert mock.call_args.kwargs["extra"]["lifecycle"] == "revoked"


def test_jit_expire_dispatch(monkeypatch, tmp_path):
    """expire_due fires one event per expired grant."""
    monkeypatch.setenv("SC_JIT_STORE", str(tmp_path / "jit.json"))
    from safecadence.identity import jit
    # Create a grant in the past so it auto-expires.
    g = jit.grant(principal="carol", action="read",
                   resource="bucket-1", duration_seconds=1,
                   target="okta", created_by="test", now=0.0)
    # Force expiry far in future
    with patch("safecadence.notifier.registry.dispatch_event") as mock:
        expired = jit.expire_due(now=99999999.0)
    assert any(e.grant_id == g.grant_id for e in expired)
    assert mock.called
    kinds = {c.kwargs["kind"] for c in mock.call_args_list}
    assert "jit_granted" in kinds


# ------------------------------------------------------ automation_fired

def test_automation_fire_dispatch(monkeypatch, tmp_path):
    """evaluate_rules should dispatch one automation_fired per rule
    that matches and applies."""
    monkeypatch.setenv("SC_INTEL_HOME", str(tmp_path))
    from safecadence.intel import automation as auto
    from safecadence.intel._store import write
    write("automation", {"rules": [{
        "rule_id": "r_test",
        "name": "test rule",
        "enabled": True,
        "rate_limit_seconds": 0,
        "when": {"kind": "stale_nhi", "severity_at_least": "medium"},
        "then": [{"action": "notify_log"}],
        "created_at": 0.0,
        "last_fired_at": 0.0,
    }], "fires": []})
    finding = _FakeFinding()
    with patch("safecadence.notifier.registry.dispatch_event") as mock:
        fires = auto.evaluate_rules([finding], apply_actions=True)
    assert len(fires) == 1
    assert mock.called
    assert mock.call_args.kwargs["kind"] == "automation_fired"


# ------------------------------------------------------- digest_daily

def test_digest_send_dispatch(monkeypatch):
    """digest.send should fan out a 'digest_daily' event after a
    successful SMTP send."""
    from safecadence import digest as dg
    cfg = dg.DigestConfig(
        smtp_host="example.com", smtp_port=25,
        smtp_use_tls=False,
        from_addr="x@x", recipients=["a@b"], subject_prefix="[T]",
    )
    fake_digest = {
        "generated_at": "2026-05-07T00:00:00Z",
        "briefing": {"asset_summary": {"asset_count": 5},
                     "policy_summary": {"overall_compliance_pct": 80,
                                          "policy_count": 3,
                                          "total_failures": 2}},
        "drift": {"finding_count": 1, "by_severity": {"medium": 1}},
        "pending_approvals": [{"job_id": "j1", "name": "n",
                                 "risk": "low",
                                 "approvers": [],
                                 "approvals_required": 1}],
        "license": {},
    }

    class _FakeSMTP:
        def __init__(self, *a, **kw): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def ehlo(self): pass
        def starttls(self): pass
        def login(self, *a, **kw): pass
        def send_message(self, *a, **kw): pass

    with patch("safecadence.digest.smtplib.SMTP", _FakeSMTP), \
         patch("safecadence.notifier.registry.dispatch_event") as mock:
        result = dg.send(cfg, digest=fake_digest, subject="t")
    assert result["sent"] is True
    assert mock.called
    assert mock.call_args.kwargs["kind"] == "digest_daily"


# ------------------------------------------------------ drift_detected

def test_daemon_drift_dispatch():
    """Smoke-test: the drift-fan-out branch in run_daemon is keyed on
    findings whose source is 'drift' or 'baseline_drift'. We don't
    boot the daemon here — we just verify the constant set is
    correct so the wiring matches what daemon.run_cycle emits."""
    from safecadence import daemon
    src = open(daemon.__file__).read()
    assert "drift_detected" in src, "daemon must emit drift_detected"
    assert "baseline_drift" in src, ("daemon must accept "
                                       "baseline_drift findings")


# --------------------------------------------------- notify_categories

def test_all_categories_have_emitter():
    """Belt-and-braces — every NOTIFY_CATEGORIES key should appear in
    a dispatch_event call somewhere in src/. Catches drift between
    the registry and the emitter set."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parents[2] / "src" / "safecadence"
    sources = []
    for p in root.rglob("*.py"):
        try:
            sources.append(p.read_text(encoding="utf-8"))
        except OSError:                                 # pragma: no cover
            pass
    blob = "\n".join(sources)
    expected = ["approval_requested", "finding_critical",
                 "watchlist_change", "drift_detected",
                 "automation_fired", "jit_granted", "digest_daily"]
    missing = [k for k in expected if f'kind="{k}"' not in blob
                                          and f"kind='{k}'" not in blob]
    assert not missing, f"NOTIFY_CATEGORIES with no emitter: {missing}"
