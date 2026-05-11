"""
v10.6 tests — real AI hooks, Slack + Jira integrations, dashboard widgets.

Every external HTTP call is mocked. None of these tests touch the
network. The autouse ``_isolated_home`` fixture redirects
``~/.safecadence`` to a temp dir so saves don't pollute the developer's
real config.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import time
import urllib.parse
from unittest import mock

import pytest


# --------------------------------------------------------------------------
# Fixture: isolate ~/.safecadence per test
# --------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFECADENCE_HOME", str(tmp_path / "sc_home"))
    monkeypatch.delenv("SC_AUTH_DISABLED", raising=False)
    # Clear any LLM keys so the default fallback is the stub path.
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    monkeypatch.delenv("SAFECADENCE_LOCAL_LLM", raising=False)
    yield


def _fake_urlopen_factory(payload_bytes: bytes, status: int = 200):
    """Build a fake context manager that mimics urlopen()."""
    class _Resp:
        def __init__(self):
            self._buf = io.BytesIO(payload_bytes)
            self.status = status
            self.code = status
        def read(self):
            return self._buf.read()
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
    def _fake(*args, **kwargs):
        return _Resp()
    return _fake


# --------------------------------------------------------------------------
# 1. AI: deterministic stub path
# --------------------------------------------------------------------------


def test_ai_exec_summary_stub_path_uses_templates():
    from safecadence.reports import ai_helpers
    out = ai_helpers.generate_executive_summary(
        {"kpi": {"hosts": 34, "critical": 14, "high": 42, "kev": 5, "eol": 4}},
        tone="executive",
    )
    assert isinstance(out, str) and out
    # Must contain real numbers from the KPI payload.
    assert "34" in out
    assert "14" in out


def test_ai_llm_status_when_no_keys_set():
    from safecadence.reports.ai_helpers import llm_status
    assert llm_status() == {"provider": None, "model": None}


# --------------------------------------------------------------------------
# 2. AI: explain_cve with and without LLM keys
# --------------------------------------------------------------------------


def test_explain_cve_stub_returns_templated_text():
    from safecadence.reports.ai_helpers import explain_cve
    out = explain_cve("CVE-2024-1234", "critical", host="fw-01.example.com")
    assert out["source"] == "stub"
    assert "CVE-2024-1234" in out["explanation"]
    assert "fw-01.example.com" in out["explanation"]
    assert "critical" in out["explanation"].lower()


def test_explain_cve_kev_flag_changes_message():
    from safecadence.reports.ai_helpers import explain_cve
    plain = explain_cve("CVE-2024-9999", "high")
    kev = explain_cve("CVE-2024-9999", "high", kev=True)
    assert plain["source"] == "stub"
    assert kev["source"] == "stub"
    assert "exploit" in kev["explanation"].lower()


def test_explain_cve_with_openai_uses_llm(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    fake_body = json.dumps({
        "choices": [{"message": {"content": "Plain-English: attacker can run code."}}]
    }).encode("utf-8")
    with mock.patch(
        "safecadence.reports.ai_helpers._urlreq.urlopen",
        new=_fake_urlopen_factory(fake_body),
    ):
        from safecadence.reports.ai_helpers import explain_cve
        out = explain_cve("CVE-2024-1234", "critical")
    assert out["source"] == "llm"
    assert "attacker" in out["explanation"].lower()


def test_explain_cve_with_anthropic_uses_llm(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    fake_body = json.dumps({
        "content": [{"type": "text", "text": "An attacker on the network can RCE."}]
    }).encode("utf-8")
    with mock.patch(
        "safecadence.reports.ai_helpers._urlreq.urlopen",
        new=_fake_urlopen_factory(fake_body),
    ):
        from safecadence.reports.ai_helpers import explain_cve
        out = explain_cve("CVE-2024-1111", "high")
    assert out["source"] == "llm"
    assert "rce" in out["explanation"].lower()


# --------------------------------------------------------------------------
# 3. AI: detect_quick_wins ranking
# --------------------------------------------------------------------------


def test_detect_quick_wins_heuristic_ranking_no_keys():
    from safecadence.reports.ai_helpers import detect_quick_wins
    actions = [
        {"id": "a1", "title": "Patch FW", "risk_reduction": 30, "effort_minutes": 60},
        {"id": "a2", "title": "Disable SNMPv1", "risk_reduction": 25, "effort_minutes": 10},
        {"id": "a3", "title": "Replace EOL switch", "risk_reduction": 50, "effort_minutes": 480},
    ]
    out = detect_quick_wins(actions, top_n=3)
    assert len(out) == 3
    # a2 has the highest risk_reduction/effort_minutes ratio (2.5) → first.
    assert out[0]["id"] == "a2"
    assert all(o["source"] == "heuristic" for o in out)


def test_detect_quick_wins_empty_returns_empty():
    from safecadence.reports.ai_helpers import detect_quick_wins
    assert detect_quick_wins([]) == []


def test_detect_quick_wins_with_llm_orders_by_llm_response(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    actions = [
        {"id": "a1", "title": "Patch FW", "risk_reduction": 30, "effort_minutes": 60},
        {"id": "a2", "title": "Disable SNMPv1", "risk_reduction": 25, "effort_minutes": 10},
        {"id": "a3", "title": "EOL replace", "risk_reduction": 50, "effort_minutes": 480},
    ]
    # LLM picks a3 first even though a2 wins by ratio.
    fake_body = json.dumps({
        "choices": [{"message": {"content": '["a3","a1","a2"]'}}]
    }).encode("utf-8")
    with mock.patch(
        "safecadence.reports.ai_helpers._urlreq.urlopen",
        new=_fake_urlopen_factory(fake_body),
    ):
        from safecadence.reports.ai_helpers import detect_quick_wins
        out = detect_quick_wins(actions, top_n=3)
    assert [o["id"] for o in out] == ["a3", "a1", "a2"]
    assert all(o["source"] == "llm" for o in out)


# --------------------------------------------------------------------------
# 4. Slack: signature verification
# --------------------------------------------------------------------------


def _sign(secret: str, ts: str, body: bytes) -> str:
    base = f"v0:{ts}:".encode("utf-8") + body
    return "v0=" + hmac.new(secret.encode("utf-8"), base, hashlib.sha256).hexdigest()


def test_slack_signature_valid(monkeypatch):
    monkeypatch.setenv("SLACK_SIGNING_SECRET", "topsecret")
    from safecadence.integrations import slack as sl
    ts = str(int(time.time()))
    body = b"token=abc&command=/safecadence"
    sig = _sign("topsecret", ts, body)
    assert sl.verify_signature(body, ts, sig) is True


def test_slack_signature_bad_secret(monkeypatch):
    monkeypatch.setenv("SLACK_SIGNING_SECRET", "topsecret")
    from safecadence.integrations import slack as sl
    ts = str(int(time.time()))
    body = b"token=abc"
    bad_sig = _sign("wrong-secret", ts, body)
    assert sl.verify_signature(body, ts, bad_sig) is False


def test_slack_signature_expired_timestamp(monkeypatch):
    monkeypatch.setenv("SLACK_SIGNING_SECRET", "topsecret")
    from safecadence.integrations import slack as sl
    # 10 minutes ago — past the 5-minute window.
    ts = str(int(time.time()) - 600)
    body = b"x=1"
    sig = _sign("topsecret", ts, body)
    assert sl.verify_signature(body, ts, sig) is False


def test_slack_signature_no_signing_secret(monkeypatch):
    monkeypatch.delenv("SLACK_SIGNING_SECRET", raising=False)
    from safecadence.integrations import slack as sl
    ts = str(int(time.time()))
    assert sl.verify_signature(b"x=1", ts, "v0=abc") is False


# --------------------------------------------------------------------------
# 5. Slack: install token round-trip
# --------------------------------------------------------------------------


def test_slack_install_save_load_roundtrip():
    from safecadence.integrations.slack import save_install, load_install
    org_id = "org_demo"
    payload = {
        "access_token": "xoxb-fake-bot-token",
        "bot_user_id": "U123",
        "team": {"id": "T1", "name": "ACME"},
        "scope": "chat:write,commands",
        "installed_at": int(time.time()),
    }
    save_install(org_id, payload)
    loaded = load_install(org_id)
    assert loaded == payload


def test_slack_install_load_missing_returns_none():
    from safecadence.integrations.slack import load_install
    assert load_install("org_nope") is None


def test_slack_install_url_unconfigured_returns_empty(monkeypatch):
    monkeypatch.delenv("SLACK_CLIENT_ID", raising=False)
    from safecadence.integrations.slack import install_url, is_configured
    assert install_url() == ""
    assert is_configured() is False


def test_slack_install_url_configured(monkeypatch):
    monkeypatch.setenv("SLACK_CLIENT_ID", "cid")
    monkeypatch.setenv("SLACK_CLIENT_SECRET", "csec")
    from safecadence.integrations.slack import install_url, is_configured
    assert is_configured() is True
    url = install_url(state="org_demo")
    assert url.startswith("https://slack.com/oauth/v2/authorize?")
    assert "client_id=cid" in url
    assert "state=org_demo" in url


# --------------------------------------------------------------------------
# 6. Slack: slash-command dispatch routing
# --------------------------------------------------------------------------


def test_slack_dispatch_report_subcommand():
    from safecadence.integrations.slack import dispatch_command
    out = dispatch_command("report exec_brief")
    assert out["command"] == "report"
    assert out["preset"] == "exec_brief"
    assert out["response_type"] in ("in_channel", "ephemeral")


def test_slack_dispatch_status_subcommand():
    from safecadence.integrations.slack import dispatch_command
    out = dispatch_command("status")
    assert out["command"] == "status"


def test_slack_dispatch_findings_severity():
    from safecadence.integrations.slack import dispatch_command
    out = dispatch_command("findings critical")
    assert out["command"] == "findings"
    assert out["severity"] == "critical"


def test_slack_dispatch_findings_invalid_severity_defaults_critical():
    from safecadence.integrations.slack import dispatch_command
    out = dispatch_command("findings purple")
    assert out["severity"] == "critical"


def test_slack_dispatch_unknown_returns_help():
    from safecadence.integrations.slack import dispatch_command
    out = dispatch_command("flibbertigibbet")
    assert out["command"] == "unknown"


def test_slack_dispatch_empty_returns_usage():
    from safecadence.integrations.slack import dispatch_command
    out = dispatch_command("")
    assert out["command"] == "help"


# --------------------------------------------------------------------------
# 7. Jira: install token round-trip
# --------------------------------------------------------------------------


def test_jira_install_save_load_roundtrip():
    from safecadence.integrations.jira import save_install, load_install
    payload = {
        "access_token": "atlassian-token",
        "refresh_token": "atlassian-refresh",
        "cloud_id": "abcd-1234",
        "scope": "read:jira-work write:jira-work",
        "installed_at": int(time.time()),
    }
    save_install("org_demo", payload)
    assert load_install("org_demo") == payload


def test_jira_install_url_unconfigured(monkeypatch):
    monkeypatch.delenv("JIRA_CLIENT_ID", raising=False)
    from safecadence.integrations.jira import install_url, is_configured
    assert install_url() == ""
    assert is_configured() is False


def test_jira_install_url_configured(monkeypatch):
    monkeypatch.setenv("JIRA_CLIENT_ID", "jcid")
    monkeypatch.setenv("JIRA_CLIENT_SECRET", "jcsec")
    from safecadence.integrations.jira import install_url
    url = install_url(state="org_demo")
    assert url.startswith("https://auth.atlassian.com/authorize?")
    assert "client_id=jcid" in url
    assert "audience=api.atlassian.com" in url


# --------------------------------------------------------------------------
# 8. Jira: create_jira_ticket via mocked HTTP
# --------------------------------------------------------------------------


def test_create_jira_ticket_returns_issue_key(monkeypatch):
    monkeypatch.setenv("JIRA_ACCESS_TOKEN", "atlassian-token")
    monkeypatch.setenv("JIRA_CLOUD_ID", "cloud-9")
    fake_body = json.dumps({"id": "10001", "key": "SAFE-42",
                            "self": "https://api.atlassian.com/.../issue/10001"}).encode()
    with mock.patch(
        "safecadence.integrations.jira._urlreq.urlopen",
        new=_fake_urlopen_factory(fake_body),
    ):
        from safecadence.integrations.jira import create_jira_ticket
        out = create_jira_ticket(
            {"title": "Patch CVE-2024-1234",
             "host": "fw-01",
             "severity": "critical",
             "cve": "CVE-2024-1234"},
            project_key="SAFE",
        )
    assert out is not None
    assert out["issue_key"] == "SAFE-42"
    assert "SAFE-42" in out["url"]


def test_create_jira_ticket_without_token_returns_none(monkeypatch):
    monkeypatch.delenv("JIRA_ACCESS_TOKEN", raising=False)
    monkeypatch.delenv("JIRA_CLOUD_ID", raising=False)
    from safecadence.integrations.jira import create_jira_ticket
    assert create_jira_ticket({"title": "x"}, org_id=None) is None


# --------------------------------------------------------------------------
# 9. Dashboard widgets — default + round-trip + render
# --------------------------------------------------------------------------


def test_dashboard_default_widget_list_shape():
    from safecadence.dashboard.widgets import list_widgets
    widgets = list_widgets("brand_new_org")
    assert len(widgets) == 6
    types = [w.type for w in widgets]
    assert "kpi_card" in types
    assert "severity_donut" in types
    # Positions are contiguous from 0.
    assert [w.position for w in widgets] == list(range(len(widgets)))


def test_dashboard_save_load_roundtrip():
    from safecadence.dashboard.widgets import (
        list_widgets, save_widgets, Widget,
    )
    org = "org_widgets_rt"
    custom = [
        Widget("hero", "kpi_card", "Hosts", {"metric": "hosts"}, 0),
        Widget("donut", "severity_donut", "Severity", {}, 1),
    ]
    saved = save_widgets(org, custom)
    assert len(saved) == 2
    reloaded = list_widgets(org)
    assert [w.id for w in reloaded] == ["hero", "donut"]
    assert reloaded[0].type == "kpi_card"


def test_dashboard_save_rejects_unknown_widget_type():
    from safecadence.dashboard.widgets import save_widgets, Widget
    with pytest.raises(ValueError):
        save_widgets("org_bad", [Widget("x", "not_a_real_type", "X", {}, 0)])


def test_dashboard_render_widget_with_dict_store():
    from safecadence.dashboard.widgets import render_widget, Widget
    w = Widget("w-hosts", "kpi_card", "Hosts", {"metric": "hosts"}, 0)
    out = render_widget(w, {"hosts": 34, "critical": 14})
    assert out["empty"] is False
    assert out["data"]["value"] == 34


def test_dashboard_render_widget_with_none_store_is_empty():
    from safecadence.dashboard.widgets import render_widget, Widget
    w = Widget("w-donut", "severity_donut", "Severity", {}, 0)
    out = render_widget(w, None)
    assert out["empty"] is True


def test_dashboard_render_unknown_type_marked_empty():
    from safecadence.dashboard.widgets import render_widget, Widget
    w = Widget("w-bad", "made_up_type", "Bad", {}, 0)
    out = render_widget(w, {"hosts": 5})
    assert out["empty"] is True
    assert "Unknown" in (out.get("error") or "")


def test_dashboard_render_severity_donut_slices():
    from safecadence.dashboard.widgets import render_widget, Widget
    w = Widget("w-d", "severity_donut", "Severity", {}, 0)
    out = render_widget(w, {"severity": {"critical": 3, "high": 7, "medium": 2, "low": 1}})
    labels = [s["label"] for s in out["data"]["slices"]]
    assert labels == ["critical", "high", "medium", "low"]


def test_dashboard_render_vendor_concentration_top_n():
    from safecadence.dashboard.widgets import render_widget, Widget
    w = Widget("v", "vendor_concentration", "Vendors", {"top_n": 2}, 0)
    out = render_widget(w, {"vendors": {"cisco": 12, "aruba": 5, "juniper": 8}})
    rows = out["data"]["rows"]
    assert len(rows) == 2
    assert rows[0]["vendor"] == "cisco"
    assert rows[1]["vendor"] == "juniper"
