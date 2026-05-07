"""
v9.43 — Generalized notification routing.

Tests the new dispatch_event registry, per-user notify_prefs, tenant
defaults, validate_prefs trust gates, the new /api/users/me/notify-prefs
+ /api/settings/notify-defaults endpoints, and the Slack/Teams DM
@-mention enrichment on the channel webhook payload.
"""

from __future__ import annotations

import pytest


# ------------------------------------------------------- prefs module


def _user(username="alice", *, email="", slack="", teams="",
           prefs=None, tenant="acme"):
    """Helper: build a UserRecord with the v9.43 fields populated."""
    from safecadence.users.directory import UserRecord
    notify = {}
    if slack:
        notify["slack_user_id"] = slack
    if teams:
        notify["teams_user_id"] = teams
    return UserRecord(
        username=username, tenant=tenant,
        roles=["admin"],
        email=email, notify=notify,
        notify_prefs=prefs or {},
    )


def test_validate_prefs_rejects_channel_without_contact_info():
    """Trust gate: a user can't enable email if they have no email
    on file. Catches the misconfig before it lands in YAML."""
    from safecadence.notifier.prefs import validate_prefs
    rec = _user(email="")           # no email
    errs = validate_prefs(rec, {"finding_critical": ["email"]})
    assert errs and "contact info" in errs[0]


def test_validate_prefs_accepts_channel_with_contact_info():
    from safecadence.notifier.prefs import validate_prefs
    rec = _user(email="alice@acme.com", slack="U03ABC")
    errs = validate_prefs(rec, {"finding_critical": ["email", "slack_dm"]})
    assert errs == []


def test_validate_prefs_rejects_unknown_category():
    from safecadence.notifier.prefs import validate_prefs
    rec = _user(email="alice@acme.com")
    errs = validate_prefs(rec, {"not_a_real_kind": ["email"]})
    assert errs and "unknown category" in errs[0]


def test_user_channels_for_kind_falls_back_to_tenant_defaults(
    tmp_path, monkeypatch
):
    """If the user has no override for a kind, the tenant default
    decides — but still intersected with that user's available
    channels."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.notifier.prefs import (
        save_tenant_defaults, user_channels_for_kind,
    )
    save_tenant_defaults({"finding_critical": ["email", "slack_dm"]})
    # Alice has email but no slack — should resolve to ["email"] only
    rec = _user(email="alice@acme.com")
    chans = user_channels_for_kind(rec, kind="finding_critical")
    assert chans == ["email"]


def test_user_override_beats_tenant_default(tmp_path, monkeypatch):
    """An explicit override (even an empty list to opt out) wins
    over the tenant default."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.notifier.prefs import (
        save_tenant_defaults, user_channels_for_kind,
    )
    save_tenant_defaults({"finding_critical": ["email"]})
    # Empty override = "I opted out, even though the default is on"
    rec = _user(email="alice@acme.com",
                  prefs={"finding_critical": []})
    chans = user_channels_for_kind(rec, kind="finding_critical")
    assert chans == []


def test_tenant_defaults_round_trip_to_disk(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.notifier.prefs import (
        save_tenant_defaults, load_tenant_defaults,
    )
    save_tenant_defaults({"finding_critical": ["email"]})
    out = load_tenant_defaults()
    assert out["finding_critical"] == ["email"]


def test_tenant_defaults_drops_unknown_category_or_channel(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.notifier.prefs import save_tenant_defaults
    out = save_tenant_defaults({
        "finding_critical": ["email", "fax_lol"],
        "not_a_kind": ["email"],
    })
    assert out["finding_critical"] == ["email"]
    assert "not_a_kind" not in out


# ----------------------------------------------------- directory v9.43


def test_directory_round_trips_notify_prefs(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_USERS_FILE", str(tmp_path / "users.yaml"))
    from safecadence.users.directory import upsert_user, get_user
    upsert_user({
        "username": "alice", "roles": ["admin"],
        "email": "alice@acme.com",
        "notify_prefs": {
            "finding_critical": ["email"],
            "digest_daily": ["email"],
        },
    }, tenant="acme")
    rec = get_user("alice", tenant="acme")
    assert rec.notify_prefs["finding_critical"] == ["email"]
    assert rec.notify_prefs["digest_daily"] == ["email"]


# ----------------------------------------------------- registry


def test_dispatch_skips_email_when_smtp_off(tmp_path, monkeypatch):
    """Air-gap path: SMTP not configured = no email DMs, no exception.
    The channel webhook is not provided either, so the result is
    empty deliveries."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_USERS_FILE", str(tmp_path / "users.yaml"))
    (tmp_path / "users.yaml").write_text(
        "tenants:\n  acme:\n    users:\n"
        "      - username: alice\n"
        "        roles: [admin]\n"
        "        email: alice@acme.com\n"
        "        notify_prefs:\n"
        "          finding_critical: [email]\n"
    )
    from safecadence.notifier.registry import dispatch_event
    out = dispatch_event(
        kind="finding_critical",
        title="t", summary="s", severity="high",
        invitees=["alice"], tenant="acme",
        channel_webhook=None,
    )
    assert out.channel_webhook_fired is False
    # alice's pref says email, but SMTP is off — delivery records the
    # smtp_not_configured reason instead of raising
    assert out.deliveries
    assert out.deliveries[0]["ok"] is False
    assert "smtp" in out.deliveries[0]["reason"]


def test_dispatch_calls_send_email_for_opted_in_user(tmp_path, monkeypatch):
    """When a user opts in to a category and SMTP is configured,
    dispatch_event sends them an email."""
    pytest.importorskip("cryptography")
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_USERS_FILE", str(tmp_path / "users.yaml"))
    from cryptography.fernet import Fernet
    monkeypatch.setenv("SAFECADENCE_VAULT_KEY",
                        Fernet.generate_key().decode("ascii"))
    (tmp_path / "users.yaml").write_text(
        "tenants:\n  acme:\n    users:\n"
        "      - username: bob\n"
        "        roles: [admin]\n"
        "        email: bob@acme.com\n"
        "        notify_prefs:\n"
        "          finding_critical: [email]\n"
    )
    from safecadence.notifier.email_notifier import (
        EmailConfig, save_email_config,
    )
    save_email_config(EmailConfig(
        enabled=True, host="smtp.acme.local",
        username="x", password="pw", from_addr="from@acme.com",
    ))

    sent = []
    from safecadence.notifier import email_notifier
    monkeypatch.setattr(email_notifier, "send_email",
                         lambda **kw: (sent.append(kw), (True, ""))[1])

    from safecadence.notifier.registry import dispatch_event
    out = dispatch_event(
        kind="finding_critical",
        title="A new critical finding", summary="bad thing",
        severity="critical", invitees=["bob"], tenant="acme",
    )
    assert sent and sent[0]["to"] == "bob@acme.com"
    assert any(d["ok"] for d in out.deliveries)


def test_dispatch_user_who_opted_out_gets_no_email(tmp_path, monkeypatch):
    """User explicitly opted out (empty list) — no email sent even
    though they have email on file and SMTP is configured."""
    pytest.importorskip("cryptography")
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_USERS_FILE", str(tmp_path / "users.yaml"))
    from cryptography.fernet import Fernet
    monkeypatch.setenv("SAFECADENCE_VAULT_KEY",
                        Fernet.generate_key().decode("ascii"))
    (tmp_path / "users.yaml").write_text(
        "tenants:\n  acme:\n    users:\n"
        "      - username: carol\n"
        "        roles: [admin]\n"
        "        email: carol@acme.com\n"
        "        notify_prefs:\n"
        "          finding_critical: []\n"     # explicit opt-out
    )
    from safecadence.notifier.email_notifier import (
        EmailConfig, save_email_config,
    )
    save_email_config(EmailConfig(
        enabled=True, host="smtp.acme.local",
        username="x", password="pw", from_addr="f@acme.com",
    ))
    sent = []
    from safecadence.notifier import email_notifier
    monkeypatch.setattr(email_notifier, "send_email",
                         lambda **kw: (sent.append(kw), (True, ""))[1])
    from safecadence.notifier.registry import dispatch_event
    dispatch_event(kind="finding_critical", title="t", summary="s",
                    invitees=["carol"], tenant="acme")
    assert sent == [], "user opted out — no email should have fired"


def test_dispatch_approval_invite_ignores_prefs(tmp_path, monkeypatch):
    """approval_requested is always-on for invitees — the operator
    can't opt out of a direct ask. (Other categories respect prefs.)"""
    pytest.importorskip("cryptography")
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_USERS_FILE", str(tmp_path / "users.yaml"))
    from cryptography.fernet import Fernet
    monkeypatch.setenv("SAFECADENCE_VAULT_KEY",
                        Fernet.generate_key().decode("ascii"))
    (tmp_path / "users.yaml").write_text(
        "tenants:\n  acme:\n    users:\n"
        "      - username: dave\n"
        "        roles: [admin]\n"
        "        email: dave@acme.com\n"
        "        notify_prefs:\n"
        "          approval_requested: []\n"   # tries to opt out
    )
    from safecadence.notifier.email_notifier import (
        EmailConfig, save_email_config,
    )
    save_email_config(EmailConfig(
        enabled=True, host="smtp.acme.local",
        username="x", password="pw", from_addr="f@acme.com",
    ))
    sent = []
    from safecadence.notifier import email_notifier
    monkeypatch.setattr(email_notifier, "send_email",
                         lambda **kw: (sent.append(kw), (True, ""))[1])
    from safecadence.notifier.registry import dispatch_event
    dispatch_event(kind="approval_requested", title="t", summary="s",
                    invitees=["dave"], tenant="acme")
    assert sent and sent[0]["to"] == "dave@acme.com", (
        "approval_requested must always page invitees regardless of "
        "their notify_prefs — direct invite is not opt-out-able"
    )


def test_dispatch_enriches_channel_payload_with_slack_user_ids(
    tmp_path, monkeypatch
):
    """When invitees have slack_user_id, the channel webhook payload
    must include the @-mention strings so the Slack receiver can
    notify them in-line."""
    monkeypatch.setenv("SC_USERS_FILE", str(tmp_path / "users.yaml"))
    (tmp_path / "users.yaml").write_text(
        "tenants:\n  acme:\n    users:\n"
        "      - username: alice\n"
        "        roles: [admin]\n"
        "        notify:\n"
        "          slack_user_id: U03ALICE\n"
        "      - username: bob\n"
        "        roles: [admin]\n"
        "        notify:\n"
        "          slack_user_id: U03BOB\n"
    )
    captured = []
    # Stub the underlying notify() to capture the payload
    from safecadence import notifier as notifier_pkg
    monkeypatch.setattr(notifier_pkg, "notify",
                         lambda url, events, **kw:
                            captured.append((url, events)))
    from safecadence.notifier.registry import dispatch_event
    dispatch_event(
        kind="approval_requested", title="t", summary="s",
        invitees=["alice", "bob"], tenant="acme",
        channel_webhook="https://hooks.slack.test/x",
    )
    assert captured, "channel webhook must fire"
    payload = captured[0][1][0]
    assert payload.get("slack_user_ids") == ["U03ALICE", "U03BOB"]
    assert "<@U03ALICE>" in payload.get("slack_mentions", "")
    assert "<@U03BOB>" in payload.get("slack_mentions", "")


# ----------------------------------------------------- HTTP API


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
              "roles": ["admin"], "email": "alice@acme.com"},
            {"username": "bob", "password_hash": hash_password("pw"),
              "roles": ["analyst"], "email": "bob@acme.com"},
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


def test_categories_endpoint_lists_known_kinds(admin_client):
    r = admin_client.get("/api/notify/categories",
                          headers=admin_client._hdr)
    assert r.status_code == 200
    body = r.json()
    keys = [c["key"] for c in body["categories"]]
    for required in ("approval_requested", "finding_critical",
                      "watchlist_change", "drift_detected",
                      "digest_daily"):
        assert required in keys
    chs = [c["key"] for c in body["channels"]]
    assert "email" in chs
    assert "slack_dm" in chs


def test_tenant_defaults_admin_only(admin_client):
    """Bob (analyst) can't write tenant defaults — admin role only."""
    r = admin_client.post("/api/settings/notify-defaults",
                            headers=admin_client._bhdr,
                            json={"defaults": {"finding_critical":
                                                  ["email"]}})
    assert r.status_code == 403


def test_tenant_defaults_round_trip(admin_client):
    """Save then read back."""
    r = admin_client.post("/api/settings/notify-defaults",
                            headers=admin_client._hdr,
                            json={"defaults": {"finding_critical":
                                                  ["email"]}})
    assert r.status_code == 200
    r = admin_client.get("/api/settings/notify-defaults",
                            headers=admin_client._hdr)
    assert r.json()["defaults"]["finding_critical"] == ["email"]


def test_me_notify_prefs_reports_available_channels(admin_client):
    """Self-service GET surfaces what channels the user has, so the
    UI can gray out cells they can't toggle on."""
    r = admin_client.get("/api/users/me/notify-prefs",
                          headers=admin_client._hdr)
    assert r.status_code == 200
    body = r.json()
    assert body["username"] == "alice"
    assert "email" in body["available_channels"]
    # Alice has no slack_user_id → not available
    assert "slack_dm" not in body["available_channels"]


def test_me_notify_prefs_can_edit_self(admin_client):
    r = admin_client.post("/api/users/me/notify-prefs",
                            headers=admin_client._hdr,
                            json={"notify_prefs":
                                    {"finding_critical": ["email"]}})
    assert r.status_code == 200
    assert (r.json()["notify_prefs"]["finding_critical"]
            == ["email"])


def test_me_notify_prefs_rejects_channel_user_doesnt_have(admin_client):
    """Trust gate — alice has no slack_user_id; trying to enable
    slack_dm must 400."""
    r = admin_client.post("/api/users/me/notify-prefs",
                            headers=admin_client._hdr,
                            json={"notify_prefs":
                                    {"finding_critical": ["slack_dm"]}})
    assert r.status_code == 400


def test_admin_can_view_other_users_prefs(admin_client):
    r = admin_client.get("/api/users/bob/notify-prefs",
                          headers=admin_client._hdr)
    assert r.status_code == 200


def test_non_admin_cannot_view_other_users_prefs(admin_client):
    r = admin_client.get("/api/users/alice/notify-prefs",
                          headers=admin_client._bhdr)
    assert r.status_code == 403


def test_non_admin_can_view_own_prefs_through_admin_route(admin_client):
    r = admin_client.get("/api/users/bob/notify-prefs",
                          headers=admin_client._bhdr)
    assert r.status_code == 200


def test_non_admin_cannot_edit_other_users_prefs(admin_client):
    r = admin_client.post("/api/users/alice/notify-prefs",
                            headers=admin_client._bhdr,
                            json={"notify_prefs":
                                    {"finding_critical": ["email"]}})
    assert r.status_code == 403


# ----------------------------------------------------- UI surfaces


def test_users_page_has_directory_table_wiring():
    """The /users admin page must call the directory API and have
    the add/edit/delete handlers wired."""
    from safecadence.ui import v9_pages
    body = v9_pages._USERS_BODY
    src = v9_pages._USERS_SCRIPT
    assert "Users" in body
    assert "/api/users" in src
    assert "uxOpenAdd" in src
    assert "uxDelete" in src


def test_settings_page_has_three_tabs():
    from safecadence.ui import v9_pages
    body = v9_pages._SETTINGS_BODY
    src = v9_pages._SETTINGS_SCRIPT
    for label in ("Email (SMTP)", "Tenant defaults", "My notifications"):
        assert label in body
    # Tabs wire to all three load functions
    assert "stLoadEmail" in src
    assert "stLoadDefaults" in src
    assert "stLoadPrefs" in src
    # And the matrix renderer is shared between defaults and prefs
    assert "_stRenderMatrix" in src
    assert "_stCollectMatrix" in src


def test_settings_renders_trust_note():
    """Channel webhook always fires regardless of toggles —
    operator must understand this."""
    from safecadence.ui import v9_pages
    body = v9_pages._SETTINGS_BODY
    assert "channel webhook" in body.lower()
    assert "regardless" in body.lower()
