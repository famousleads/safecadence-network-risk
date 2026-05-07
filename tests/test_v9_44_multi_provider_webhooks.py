"""
v9.44 — Multi-provider webhooks + dispatch fan-out.

Coverage:
  - Provider URL detection
  - Per-provider payload shape (Slack / Teams / Discord / PagerDuty /
    Opsgenie / ServiceNow / Google Chat / Webex / generic_hmac)
  - Webhook registry: encryption-at-rest, validate inputs, list/upsert/delete
  - Filter rules: categories AND min_severity AND'd together
  - dispatch_event fan-out hits all matching webhooks; one failure
    doesn't block others
  - HTTP API: admin-only writes, URL never returned, test endpoint
  - URL redaction in to_public_dict
"""

from __future__ import annotations

import json
import pytest


# --------------------------------------------------- providers


def test_provider_detection_known_urls():
    from safecadence.notifier.providers import detect_provider
    cases = {
        "https://hooks.slack.com/services/T0/B0/xxx": "slack",
        "https://discord.com/api/webhooks/123/abc": "discord",
        "https://outlook.office.com/webhook/xxx": "teams",
        "https://webhook.office.com/webhookb2/xxx": "teams",
        "https://events.pagerduty.com/v2/enqueue": "pagerduty",
        "https://api.opsgenie.com/v2/alerts": "opsgenie",
        "https://chat.googleapis.com/v1/spaces/xxx/messages": "google_chat",
        "https://webexapis.com/v1/messages": "webex",
        "https://acme.service-now.com/api/now/table/incident": "servicenow",
        "https://example.com/some/random/url": "generic_webhook",
    }
    for url, expected in cases.items():
        assert detect_provider(url) == expected, (
            f"{url} → expected {expected}, got {detect_provider(url)}"
        )


def test_slack_render_includes_block_kit_attachment():
    from safecadence.notifier.providers import _render_slack
    body = _render_slack({
        "kind": "finding_critical", "title": "T", "summary": "S",
        "severity": "high", "link": "/findings#x",
        "slack_mentions": "<@U1> <@U2>",
    })
    assert body["attachments"]
    a = body["attachments"][0]
    assert a["color"]                # severity color
    assert "<@U1>" in a["text"]      # mentions woven in
    assert any("Open in SafeCadence" in (act.get("text") or "")
                for act in a.get("actions") or [])


def test_teams_render_uses_message_card_schema():
    from safecadence.notifier.providers import _render_teams
    body = _render_teams({"title": "t", "summary": "s",
                            "severity": "critical",
                            "link": "https://example.com/x"})
    assert body["@type"] == "MessageCard"
    assert body["themeColor"]        # hex color, no leading #
    assert "potentialAction" in body
    assert body["potentialAction"][0]["targets"][0]["uri"] \
            == "https://example.com/x"


def test_discord_render_uses_embeds_with_color_int():
    from safecadence.notifier.providers import _render_discord
    body = _render_discord({"title": "t", "summary": "s",
                              "severity": "critical",
                              "link": "https://example.com/x"})
    assert "embeds" in body
    e = body["embeds"][0]
    assert isinstance(e["color"], int)
    assert e["title"] == "t"
    # critical maps to a red int
    assert e["color"] == 0xDC2626


def test_pagerduty_render_uses_events_v2_schema():
    from safecadence.notifier.providers import _render_pagerduty
    body = _render_pagerduty({"title": "t", "summary": "s",
                                "severity": "high",
                                "link": "/x", "kind": "finding_critical"})
    assert body["event_action"] == "trigger"
    assert body["payload"]["severity"] == "error"
    assert body["payload"]["custom_details"]["kind"] == "finding_critical"


def test_opsgenie_render_maps_severity_to_priority():
    from safecadence.notifier.providers import _render_opsgenie
    cases = {"critical": "P1", "high": "P2", "medium": "P3",
              "low": "P4", "info": "P5"}
    for sev, pri in cases.items():
        body = _render_opsgenie({"title": "t", "summary": "s",
                                    "severity": sev})
        assert body["priority"] == pri


def test_servicenow_render_maps_severity_to_impact():
    from safecadence.notifier.providers import _render_servicenow
    body = _render_servicenow({"title": "t", "summary": "s",
                                  "severity": "critical"})
    assert body["impact"] == "1"
    assert body["urgency"] == "1"
    assert body["category"] == "security"
    assert body["u_source"] == "safecadence"


def test_google_chat_render_includes_card_v2():
    from safecadence.notifier.providers import _render_google_chat
    body = _render_google_chat({"title": "t", "summary": "s",
                                   "severity": "info",
                                   "link": "https://example.com/x"})
    assert "cardsV2" in body
    assert body["cardsV2"][0]["card"]["header"]["title"] == "t"


def test_webex_render_uses_markdown():
    from safecadence.notifier.providers import _render_webex
    body = _render_webex({"title": "t", "summary": "s",
                            "severity": "high",
                            "link": "https://example.com/x"})
    assert "markdown" in body
    assert "**t**" in body["markdown"]
    assert "[Open in SafeCadence]" in body["markdown"]


# --------------------------------------------------- registry


def test_registry_url_encrypted_at_rest(tmp_path, monkeypatch):
    """Trust property: webhook URL must be Fernet ciphertext on disk,
    NOT plaintext. Bearer-secret leak canary."""
    pytest.importorskip("cryptography")
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from cryptography.fernet import Fernet
    monkeypatch.setenv("SAFECADENCE_VAULT_KEY",
                        Fernet.generate_key().decode("ascii"))
    from safecadence.notifier import webhook_registry as wr
    wr.upsert({
        "id": "secops-slack", "provider": "slack",
        "url": "https://hooks.slack.com/services/T0/B0/PLAINTEXT-LEAK-CANARY",
        "categories": ["finding_critical"], "min_severity": "high",
    })
    on_disk = (tmp_path / "settings" / "webhooks.json").read_text()
    assert "PLAINTEXT-LEAK-CANARY" not in on_disk, (
        "webhook URL landed on disk in plaintext"
    )
    assert "FERNET:" in on_disk


def test_registry_to_public_dict_never_exposes_url(tmp_path, monkeypatch):
    pytest.importorskip("cryptography")
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from cryptography.fernet import Fernet
    monkeypatch.setenv("SAFECADENCE_VAULT_KEY",
                        Fernet.generate_key().decode("ascii"))
    from safecadence.notifier import webhook_registry as wr
    wr.upsert({
        "id": "discord1", "provider": "discord",
        "url": "https://discord.com/api/webhooks/123/SECRET-TAIL-12345",
    })
    public = wr.list_webhooks()[0].to_public_dict()
    blob = json.dumps(public)
    assert "SECRET-TAIL-12345" not in blob
    assert public["has_url"] is True
    assert "discord.com" in (public["url_preview"] or "")


def test_registry_validates_url_scheme(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.notifier import webhook_registry as wr
    with pytest.raises(ValueError):
        wr.upsert({"id": "x", "url": "ftp://nope"})


def test_registry_validates_min_severity(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.notifier import webhook_registry as wr
    with pytest.raises(ValueError):
        wr.upsert({"id": "x", "url": "https://example.com/",
                    "min_severity": "MAYBE"})


def test_registry_blank_url_preserves_existing(tmp_path, monkeypatch):
    """Editing a webhook without re-supplying the URL must NOT wipe it.
    Same UX pattern as the email config password field."""
    pytest.importorskip("cryptography")
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from cryptography.fernet import Fernet
    monkeypatch.setenv("SAFECADENCE_VAULT_KEY",
                        Fernet.generate_key().decode("ascii"))
    from safecadence.notifier import webhook_registry as wr
    wr.upsert({"id": "x", "provider": "slack",
                "url": "https://hooks.slack.com/services/T/B/AAA"})
    # Edit without resupplying url
    wr.upsert({"id": "x", "categories": ["digest_daily"]})
    w = wr.get("x")
    assert w.url_encrypted              # not wiped
    assert w.categories == ["digest_daily"]


# ------------------------------------------------- filters


def test_webhook_matches_categories_and_severity_anded(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.notifier import webhook_registry as wr
    w = wr._from_dict({
        "id": "x", "enabled": True,
        "categories": ["finding_critical"],
        "min_severity": "high",
    })
    assert wr.webhook_matches(w, kind="finding_critical", severity="high")
    assert wr.webhook_matches(w, kind="finding_critical", severity="critical")
    assert not wr.webhook_matches(w, kind="digest_daily", severity="critical"), (
        "wrong category — must NOT match even if severity is high enough"
    )
    assert not wr.webhook_matches(w, kind="finding_critical", severity="medium"), (
        "right category but severity below floor — must NOT match"
    )


def test_webhook_disabled_never_matches(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.notifier import webhook_registry as wr
    w = wr._from_dict({"id": "x", "enabled": False, "categories": [],
                         "min_severity": ""})
    assert not wr.webhook_matches(w, kind="any", severity="critical")


def test_webhook_with_no_filters_matches_anything(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.notifier import webhook_registry as wr
    w = wr._from_dict({"id": "x", "enabled": True, "categories": [],
                         "min_severity": ""})
    assert wr.webhook_matches(w, kind="anything", severity="info")
    assert wr.webhook_matches(w, kind="random", severity="critical")


# --------------------------------------------- dispatch fan-out


def test_dispatch_fans_out_to_matching_webhooks(tmp_path, monkeypatch):
    """The whole point: dispatch_event hits every webhook whose
    filter matches the event's kind+severity. We monkey-patch the
    underlying urllib.request.urlopen so no real network."""
    pytest.importorskip("cryptography")
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from cryptography.fernet import Fernet
    monkeypatch.setenv("SAFECADENCE_VAULT_KEY",
                        Fernet.generate_key().decode("ascii"))
    from safecadence.notifier import webhook_registry as wr
    wr.upsert({"id": "secops-slack", "url":
                  "https://hooks.slack.com/services/T0/B0/A",
                "categories": ["finding_critical"]})
    wr.upsert({"id": "ops-discord", "url":
                  "https://discord.com/api/webhooks/123/B",
                "categories": ["automation_fired"]})
    wr.upsert({"id": "all-incidents-pd", "url":
                  "https://events.pagerduty.com/v2/enqueue",
                "min_severity": "high"})

    posted = []
    def fake_urlopen(req, timeout=None):
        posted.append({"url": req.full_url,
                          "data": req.data.decode("utf-8")})
        class _R:
            status = 200
            def __enter__(s): return s
            def __exit__(s, *a): return False
        return _R()
    import urllib.request as ur
    monkeypatch.setattr(ur, "urlopen", fake_urlopen)

    # Critical finding — should fire to secops-slack (category match)
    # AND all-incidents-pd (severity floor) but NOT ops-discord
    from safecadence.notifier.registry import dispatch_event
    res = dispatch_event(kind="finding_critical", title="t", summary="s",
                          severity="critical")
    fired_ids = {f["webhook_id"] for f in res.webhook_fires
                  if f["ok"]}
    assert "secops-slack" in fired_ids
    assert "all-incidents-pd" in fired_ids
    assert "ops-discord" not in fired_ids


def test_dispatch_one_failing_webhook_doesnt_block_others(
    tmp_path, monkeypatch
):
    pytest.importorskip("cryptography")
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from cryptography.fernet import Fernet
    monkeypatch.setenv("SAFECADENCE_VAULT_KEY",
                        Fernet.generate_key().decode("ascii"))
    from safecadence.notifier import webhook_registry as wr
    wr.upsert({"id": "broken", "provider": "slack",
                "url": "https://hooks.slack.com/services/T/B/BROKEN"})
    wr.upsert({"id": "good", "provider": "slack",
                "url": "https://hooks.slack.com/services/T/B/GOOD"})
    import urllib.request as ur
    def fake_urlopen(req, timeout=None):
        if "BROKEN" in req.full_url:
            raise ur.URLError("simulated DNS failure")
        class _R:
            status = 200
            def __enter__(s): return s
            def __exit__(s, *a): return False
        return _R()
    monkeypatch.setattr(ur, "urlopen", fake_urlopen)
    from safecadence.notifier.registry import dispatch_event
    res = dispatch_event(kind="approval_requested", title="t",
                          summary="s", severity="info")
    by_id = {f["webhook_id"]: f for f in res.webhook_fires}
    assert by_id["good"]["ok"] is True
    assert by_id["broken"]["ok"] is False
    assert by_id["broken"]["error"]


# ------------------------------------------------------ HTTP API


@pytest.fixture
def admin_client(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    pytest.importorskip("yaml")
    pytest.importorskip("cryptography")
    monkeypatch.setenv("SAFECADENCE_HOME", str(tmp_path))
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_USERS_FILE", str(tmp_path / "users.yaml"))
    monkeypatch.setenv("SC_JWT_SECRET", "test-secret")
    monkeypatch.setenv("SC_AI_DISABLED", "1")
    from cryptography.fernet import Fernet
    monkeypatch.setenv("SAFECADENCE_VAULT_KEY",
                        Fernet.generate_key().decode("ascii"))
    import yaml
    from safecadence.server.auth import hash_password
    (tmp_path / "users.yaml").write_text(yaml.safe_dump({
        "tenants": {"acme": {"users": [
            {"username": "alice", "password_hash": hash_password("pw"),
              "roles": ["admin"]},
            {"username": "bob", "password_hash": hash_password("pw"),
              "roles": ["analyst"]},
        ]}}
    }))
    from fastapi.testclient import TestClient
    from safecadence.server import create_app
    app = create_app(users_file=str(tmp_path / "users.yaml"),
                     db_url=f"sqlite:///{tmp_path}/sc.db",
                     jwt_secret="test-secret")
    c = TestClient(app)
    tok = c.post("/api/login",
                  data={"username": "alice", "password": "pw"}
                  ).json()["access_token"]
    c._hdr = {"Authorization": f"Bearer {tok}"}
    btok = c.post("/api/login",
                    data={"username": "bob", "password": "pw"}
                    ).json()["access_token"]
    c._bhdr = {"Authorization": f"Bearer {btok}"}
    return c


def test_webhooks_create_admin_only(admin_client):
    r = admin_client.post("/api/webhooks", headers=admin_client._bhdr,
                            json={"id": "x", "url": "https://example.com/h"})
    assert r.status_code == 403


def test_webhooks_list_never_returns_url(admin_client):
    admin_client.post("/api/webhooks", headers=admin_client._hdr,
                        json={"id": "secret-leak-test",
                              "provider": "slack",
                              "url": "https://hooks.slack.com/services/T/B/LEAK-CANARY-77"})
    r = admin_client.get("/api/webhooks", headers=admin_client._hdr)
    assert r.status_code == 200
    body = r.text
    assert "LEAK-CANARY-77" not in body
    rows = r.json()["webhooks"]
    assert any(w["id"] == "secret-leak-test" for w in rows)


def test_webhooks_delete_admin_only_404_unknown(admin_client):
    r = admin_client.delete("/api/webhooks/not-a-real-id",
                              headers=admin_client._hdr)
    assert r.status_code == 404


def test_webhooks_test_endpoint_admin_only(admin_client):
    """Bob (analyst) can't fire a test event."""
    admin_client.post("/api/webhooks", headers=admin_client._hdr,
                        json={"id": "y", "provider": "generic_webhook",
                              "url": "https://example.com/h"})
    r = admin_client.post("/api/webhooks/y/test",
                            headers=admin_client._bhdr)
    assert r.status_code == 403


# ------------------------------------------------ UI surface


def test_settings_has_webhooks_tab():
    from safecadence.ui import v9_pages
    body = v9_pages._SETTINGS_BODY
    src = v9_pages._SETTINGS_SCRIPT
    assert "Webhooks" in body
    assert "wh-tbl" in body
    # JS calls the API + has add/edit/delete/test handlers
    assert "/api/webhooks" in src
    assert "whOpenAdd" in src
    assert "whEdit" in src
    assert "whDelete" in src
    assert "whTest" in src


def test_settings_renders_redacted_url_preview_in_table():
    """Trust note in the UI: URLs are shown as `url_preview`, not the
    full URL. Pinned so the table can't regress to showing the secret."""
    from safecadence.ui import v9_pages
    src = v9_pages._SETTINGS_SCRIPT
    assert "url_preview" in src
    # And the trust note about Fernet encryption is present
    assert "Fernet-encrypted" in v9_pages._SETTINGS_BODY


# ------------------------------------------------------ workflow + daemon wire-in


def test_workflow_uses_dispatch_event_for_approval(tmp_path, monkeypatch):
    """The approval notifier now routes through dispatch_event so
    multi-provider webhooks fan out automatically. Verified by
    monkey-patching dispatch_event and confirming the workflow calls it."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_USERS_FILE", str(tmp_path / "users.yaml"))
    (tmp_path / "users.yaml").write_text(
        "tenants: {acme: {users: [{username: alice, roles: [admin],\n"
        "  email: a@x.com}]}}\n"
    )
    captured = []
    from safecadence.notifier import registry
    monkeypatch.setattr(registry, "dispatch_event",
                         lambda **kw: captured.append(kw) or
                                          registry.DispatchResult(kind=kw["kind"]))
    from safecadence.execution import workflow
    from safecadence.execution.schema import (
        CommandJob, CommandMode, JobStatus, RiskLevel,
    )
    job = CommandJob(
        job_id="wf1", name="x", description="x",
        mode=CommandMode.CONFIG, risk=RiskLevel.MEDIUM,
        status=JobStatus.REVIEW, tenant="acme",
        approvers_invited=["alice"],
    )
    req = workflow.ApprovalRequest(job_id="wf1", requested_by="bob",
                                     approval_id="ar")
    workflow._notify_approval_requested(job, req, "bob")
    assert captured, "workflow must call dispatch_event"
    call = captured[0]
    assert call["kind"] == "approval_requested"
    assert "alice" in call["invitees"]
