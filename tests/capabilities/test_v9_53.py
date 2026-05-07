"""v9.53 — capability info-disclosure gate, CSV export, capability_changed dispatch."""
from __future__ import annotations

from unittest.mock import patch
from fastapi import FastAPI
from fastapi.testclient import TestClient


def _build_app(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_ACTIVITY_DISABLED", "1")
    app = FastAPI()
    from safecadence.ui.v9_pages import register
    register(app)
    return app


# ----------------------------------------------------------- caps GET gate

def test_caps_get_self_read_passes(monkeypatch, tmp_path):
    """Self-read must always work — caller looking at their own grants
    doesn't need any extra capability."""
    app = _build_app(monkeypatch, tmp_path)
    client = TestClient(app)
    # In single-user mode caller_user returns synthetic admin = "local-admin"
    # so requesting /api/capabilities/local-admin is self-read.
    r = client.get("/api/capabilities/local-admin")
    assert r.status_code == 200


def test_caps_get_other_user_passes_with_admin_role(monkeypatch, tmp_path):
    """Synthetic admin (single-user mode) has all capabilities, so
    reading another user's grants succeeds."""
    app = _build_app(monkeypatch, tmp_path)
    client = TestClient(app)
    r = client.get("/api/capabilities/alice")
    assert r.status_code == 200


# ----------------------------------------------------------- CSV export

def test_activity_csv_export(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_ACTIVITY_DISABLED", "1")
    # Seed an activity row
    from safecadence.activity import append, ActivityRecord
    append(ActivityRecord(actor="alice", method="POST",
                            path="/api/users", status=200,
                            request_id="req_abc"))
    app = _build_app(monkeypatch, tmp_path)
    client = TestClient(app)
    r = client.get("/api/activity?format=csv&days=1")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert "Content-Disposition" in r.headers
    assert "safecadence-activity-" in r.headers["Content-Disposition"]
    # CSV header + at least one row
    lines = r.text.strip().split("\n")
    assert len(lines) >= 2
    assert lines[0].startswith("ts,actor,tenant,method,path")
    assert "alice" in lines[1]


def test_activity_json_default(monkeypatch, tmp_path):
    """Default format is JSON; CSV is opt-in via ?format=csv."""
    app = _build_app(monkeypatch, tmp_path)
    client = TestClient(app)
    r = client.get("/api/activity?days=1")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")


# ------------------------------------------------ capability_changed event

def test_capability_changed_dispatch_fires(monkeypatch, tmp_path):
    """grant() must fire dispatch_event(kind='capability_changed')
    in addition to writing the activity row."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.capabilities.store import grant
    from safecadence.capabilities import Capability
    with patch("safecadence.notifier.registry.dispatch_event") as mock:
        grant("alice", Capability.MANAGE_USERS, actor="cto")
    assert mock.called
    call = mock.call_args
    assert call.kwargs["kind"] == "capability_changed"
    assert "alice" in call.kwargs["title"]
    assert call.kwargs["extra"]["action"] == "grant"
    assert call.kwargs["extra"]["capability"] == Capability.MANAGE_USERS


def test_capability_revoke_dispatches_too(monkeypatch, tmp_path):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.capabilities.store import grant, revoke
    from safecadence.capabilities import Capability
    grant("alice", Capability.MANAGE_USERS, actor="cto")
    with patch("safecadence.notifier.registry.dispatch_event") as mock:
        revoke("alice", Capability.MANAGE_USERS, actor="cto",
               reason="role-changed")
    assert mock.called
    assert mock.call_args.kwargs["extra"]["action"] == "revoke"


def test_high_value_capability_changes_severity_high(monkeypatch, tmp_path):
    """Granting execute.real or admin.* should be 'high' severity so
    security-team channels treat it as urgent."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.capabilities.store import grant
    from safecadence.capabilities import Capability
    with patch("safecadence.notifier.registry.dispatch_event") as mock:
        grant("alice", Capability.EXECUTE_REAL, actor="cto",
              reason="incident")
    assert mock.call_args.kwargs["severity"] == "high"


def test_low_value_capability_change_severity_info(monkeypatch, tmp_path):
    """Granting a read or analyst-tier capability is 'info'."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.capabilities.store import grant
    from safecadence.capabilities import Capability
    with patch("safecadence.notifier.registry.dispatch_event") as mock:
        grant("alice", Capability.WRITE_TAG, actor="cto")
    assert mock.call_args.kwargs["severity"] == "info"


# ------------------------------------------------- new NOTIFY_CATEGORIES key

def test_capability_changed_in_notify_categories():
    """The new category must be enumerable so /settings notify-prefs
    matrix has a row for it."""
    from safecadence.notifier.registry import NOTIFY_CATEGORIES, category_keys
    keys = category_keys()
    assert "capability_changed" in keys
    rec = next(c for c in NOTIFY_CATEGORIES if c["key"] == "capability_changed")
    assert "privilege" in rec["description"].lower()
