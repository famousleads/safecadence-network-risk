"""
v7.9 — intel features: watchlists, comments, timeline, automation,
briefing, AI assistant, intel UI pages.
"""

from __future__ import annotations

import os
import yaml
import time
from dataclasses import dataclass
from pathlib import Path

import pytest


# ---------------------------------------------------------------- watchlists


def test_watchlist_add_list_remove(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_INTEL_HOME", str(tmp_path))
    from safecadence.intel.watchlists import (
        add_watch, list_watches, remove_watch,
    )
    w = add_watch(entity_kind="asset", entity_id="srv-1",
                   label="my favorite server", user="alice")
    assert w.watch_id.startswith("w_")
    assert any(x.entity_id == "srv-1" for x in list_watches(user="alice"))
    assert remove_watch(w.watch_id, user="alice") is True
    assert list_watches(user="alice") == []


def test_watchlist_idempotent(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_INTEL_HOME", str(tmp_path))
    from safecadence.intel.watchlists import add_watch, list_watches
    w1 = add_watch(entity_kind="asset", entity_id="srv-1", user="alice")
    w2 = add_watch(entity_kind="asset", entity_id="srv-1", user="alice")
    assert w1.watch_id == w2.watch_id
    assert len(list_watches(user="alice")) == 1


def test_watchlist_changes_detected(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_INTEL_HOME", str(tmp_path))
    from safecadence.intel.watchlists import add_watch, watch_changes
    add_watch(entity_kind="asset", entity_id="srv-1", user="alice")
    # First run captures baseline
    assets = [{"identity": {"asset_id": "srv-1"},
                "security": {"kev_cves": 0, "critical_cves": 0},
                "identity_block": {"mfa_enrolled": True},
                "health": {"grade": "A"}}]
    changes_first = watch_changes(assets=assets, user="alice")
    assert len(changes_first) == 1   # first sighting counts as a change
    # Second run with same data — no change
    changes_second = watch_changes(assets=assets, user="alice")
    assert changes_second == []
    # Third run with changed data
    assets2 = [{"identity": {"asset_id": "srv-1"},
                 "security": {"kev_cves": 7, "critical_cves": 0},
                 "identity_block": {"mfa_enrolled": False},
                 "health": {"grade": "C"}}]
    changes_third = watch_changes(assets=assets2, user="alice")
    assert changes_third
    assert "kev_cves" in changes_third[0]["summary"]


# ---------------------------------------------------------------- comments


def test_comment_add_and_list(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_INTEL_HOME", str(tmp_path))
    from safecadence.intel.comments import add_comment, list_comments
    c = add_comment(entity_kind="finding", entity_id="f-1",
                     user="alice", text="working on this")
    assert c.comment_id
    out = list_comments(entity_kind="finding", entity_id="f-1")
    assert len(out) == 1
    assert out[0].text == "working on this"


def test_comment_rejects_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_INTEL_HOME", str(tmp_path))
    from safecadence.intel.comments import add_comment
    with pytest.raises(ValueError):
        add_comment(entity_kind="x", entity_id="y", user="z", text="   ")


def test_assignment_lifecycle(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_INTEL_HOME", str(tmp_path))
    from safecadence.intel.comments import (
        assign, list_assignments, update_assignment,
    )
    a = assign(entity_kind="finding", entity_id="f-1",
                assigned_to="alice", assigned_by="bob",
                note="please look at this")
    assert a.status == "open"
    listed = list_assignments(assigned_to="alice")
    assert len(listed) == 1
    updated = update_assignment(a.assignment_id, status="resolved")
    assert updated and updated.status == "resolved"


def test_assignment_invalid_status(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_INTEL_HOME", str(tmp_path))
    from safecadence.intel.comments import update_assignment
    with pytest.raises(ValueError):
        update_assignment("a-1", status="bogus")


# ---------------------------------------------------------------- automation


@dataclass
class _F:
    finding_id: str
    kind: str
    severity: str
    principal: str = ""
    title: str = ""
    suggested_ir: dict = None


def test_automation_save_list_delete(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_INTEL_HOME", str(tmp_path))
    from safecadence.intel.automation import save_rule, list_rules, delete_rule
    r = save_rule({"name": "test rule",
                    "when": {"kind": "stale_nhi"},
                    "then": [{"action": "notify_log"}]})
    assert r.rule_id.startswith("r_")
    assert any(x.rule_id == r.rule_id for x in list_rules())
    assert delete_rule(r.rule_id) is True
    assert not any(x.rule_id == r.rule_id for x in list_rules())


def test_automation_evaluates_matching_rule(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_INTEL_HOME", str(tmp_path))
    from safecadence.intel.automation import save_rule, evaluate_rules
    save_rule({"name": "fix-stale",
                "when": {"kind": "stale_nhi", "severity_at_least": "medium"},
                "then": [{"action": "notify_log"}]})
    findings = [_F("f1", "stale_nhi", "high"),
                 _F("f2", "no_mfa", "low")]   # different kind — should skip
    fires: list = []
    def stub(name, finding, kw):
        fires.append((name, finding.finding_id))
        return "stub"
    out = evaluate_rules(findings, on_action=stub)
    assert len(fires) == 1
    assert fires[0] == ("notify_log", "f1")


def test_automation_severity_threshold(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_INTEL_HOME", str(tmp_path))
    from safecadence.intel.automation import save_rule, evaluate_rules
    save_rule({"name": "high-only",
                "when": {"severity_at_least": "high"},
                "then": [{"action": "notify_log"}]})
    findings = [_F("f1", "no_mfa", "high"),
                 _F("f2", "stale_nhi", "low")]
    out = evaluate_rules(findings, on_action=lambda *a, **k: "ok")
    matches = [o for o in out if o["finding_id"] == "f1"]
    nope    = [o for o in out if o["finding_id"] == "f2"]
    assert matches and not nope


# ---------------------------------------------------------------- timeline


def test_timeline_aggregates_comments(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_INTEL_HOME", str(tmp_path))
    from safecadence.intel.comments import add_comment
    from safecadence.intel.timeline import build_timeline
    add_comment(entity_kind="asset", entity_id="srv-1",
                 user="alice", text="checked this")
    events = build_timeline(audit_events=[], jit_grants=[],
                              since_seconds=86400)
    kinds = {e.kind for e in events}
    assert "comment" in kinds


def test_timeline_filters_by_kind(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_INTEL_HOME", str(tmp_path))
    from safecadence.intel.comments import add_comment, assign
    from safecadence.intel.timeline import build_timeline
    add_comment(entity_kind="asset", entity_id="x", user="a", text="hi")
    assign(entity_kind="asset", entity_id="x",
            assigned_to="a", assigned_by="b")
    events = build_timeline(audit_events=[], jit_grants=[],
                              kinds=["assignment"])
    assert all(e.kind == "assignment" for e in events)


# ---------------------------------------------------------------- briefing


def test_briefing_handles_empty_fleet(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_INTEL_HOME", str(tmp_path))
    from safecadence.intel.briefing import build_briefing, render_text
    b = build_briefing(assets=[], findings=[], attack_paths=[],
                        jit_grants=[], automation_fires=[])
    assert "All quiet" in b.summary_line
    text = render_text(b)
    assert "Morning briefing" in text


def test_briefing_with_critical_findings(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_INTEL_HOME", str(tmp_path))
    from safecadence.intel.briefing import build_briefing
    findings = [_F("f-crit", "no_mfa", "critical", title="prod tenant no MFA")]
    b = build_briefing(assets=[], findings=findings, attack_paths=[],
                        jit_grants=[], automation_fires=[])
    # Top actions surface the critical-count message
    assert any("critical" in a["title"].lower() for a in b.top_actions)
    assert b.overnight_findings
    assert b.overnight_findings[0]["title"] == "prod tenant no MFA"


# ---------------------------------------------------------------- ai assistant


def test_ai_assistant_with_stub():
    """v9.56 — citations now require cross-check against snapshot IDs.
    The stubbed response mentions an asset_id ('srv-prod-1') that
    actually exists in the snapshot, so it's cited; 'build-bot' (not
    in snapshot) would NOT be cited under v9.56's tightened rules."""
    from safecadence.intel.ai_assistant import ask_assistant
    def stub(system, user, model):
        return "There are 3 NHIs, including 1 stale on (srv-prod-1)."
    assets = [{"identity": {"asset_id": "srv-prod-1",
                                "asset_type": "server",
                                "criticality": "high"},
                 "nhi": {"nhi_id": "x", "subtype": "service_account"}}]
    ans = ask_assistant("how many NHIs?", assets=assets,
                         findings=[], attack_paths=[], ai_call=stub)
    assert ans.used_ai is True
    assert "NHIs" in ans.text
    assert ans.cited and ans.cited[0]["id"] == "srv-prod-1"
    assert ans.cited[0]["kind"] == "asset"


def test_ai_assistant_falls_back_when_no_key(monkeypatch):
    """If no AI provider is configured, deterministic fallback answers."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    monkeypatch.delenv("SAFECADENCE_LOCAL_LLM", raising=False)
    from safecadence.intel.ai_assistant import ask_assistant
    ans = ask_assistant("how many crown-jewel assets are there?",
                         assets=[{"identity": {"asset_id": "db-1",
                                                  "criticality": "crown-jewel"}}],
                         findings=[], attack_paths=[])
    assert ans.used_ai is False
    assert "crown-jewel" in ans.text
    assert "db-1" in ans.text


def test_ai_assistant_rejects_empty():
    from safecadence.intel.ai_assistant import ask_assistant
    ans = ask_assistant("   ", assets=[], findings=[], attack_paths=[])
    assert "no question" in ans.text


# ---------------------------------------------------------------- REST + UI


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_USERS_FILE", str(tmp_path / "users.yaml"))
    monkeypatch.setenv("SC_JIT_STORE", str(tmp_path / "jit.json"))
    monkeypatch.setenv("SC_INTEL_HOME", str(tmp_path / "intel"))
    monkeypatch.setenv("SAFECADENCE_HOME", str(tmp_path / ".safecadence"))
    from fastapi.testclient import TestClient
    from safecadence.server import create_app
    app = create_app(users_file=str(tmp_path / "users.yaml"),
                       db_url=f"sqlite:///{tmp_path}/sc.db",
                       jwt_secret="test-secret")
    return TestClient(app)


def _auth(client):
    from safecadence.server.auth import hash_password
    p = Path(os.environ["SC_USERS_FILE"])
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(yaml.safe_dump({
        "tenants": {"default": {"users": [{
            "username": "admin",
            "password_hash": hash_password("test-pw"),
            "roles": ["admin"],
        }]}}
    }), encoding="utf-8")
    r = client.post("/api/login",
                     data={"username": "admin", "password": "test-pw"})
    return r.json()["access_token"]


def test_intel_routes_mounted(client):
    """All /api/intel/* and intel UI pages should resolve."""
    t = _auth(client)
    h = {"Authorization": f"Bearer {t}"}
    # API
    assert client.post("/api/intel/briefing", json={}, headers=h).status_code == 200
    assert client.get("/api/intel/timeline", headers=h).status_code == 200
    assert client.get("/api/intel/watchlists", headers=h).status_code == 200
    assert client.get("/api/intel/automation/rules", headers=h).status_code == 200
    # UI pages
    for path in ("/ask", "/timeline", "/briefing", "/automation", "/onboarding"):
        r = client.get(path)
        assert r.status_code == 200, f"{path} failed: {r.text[:200]}"
        assert "SafeCadence" in r.text


def test_intel_watchlist_round_trip_via_api(client):
    t = _auth(client)
    h = {"Authorization": f"Bearer {t}"}
    r = client.post("/api/intel/watchlists",
                     headers=h,
                     json={"entity_kind": "asset",
                           "entity_id": "srv-1",
                           "label": "test"})
    assert r.status_code == 200, r.text
    wid = r.json()["watch_id"]
    listed = client.get("/api/intel/watchlists", headers=h).json()
    assert any(w["watch_id"] == wid for w in listed["watches"])


def test_intel_automation_rule_round_trip(client):
    t = _auth(client)
    h = {"Authorization": f"Bearer {t}"}
    r = client.post("/api/intel/automation/rules",
                     headers=h,
                     json={"name": "test rule",
                           "when": {"kind": "stale_nhi"},
                           "then": [{"action": "notify_log"}]})
    assert r.status_code == 200
    rid = r.json()["rule_id"]
    listed = client.get("/api/intel/automation/rules", headers=h).json()
    assert any(rl["rule_id"] == rid for rl in listed["rules"])
    d = client.delete(f"/api/intel/automation/rules/{rid}", headers=h)
    assert d.json()["deleted"] is True
