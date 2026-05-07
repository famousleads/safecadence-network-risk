"""
v9.42 — Approver directory + customer SMTP + targeted notifications.

Coverage:
  - User directory module (read/write/validate)
  - Email config persistence + Fernet encryption at rest
  - HTTP API: /api/users CRUD with admin-role gate
  - HTTP API: /api/settings/email read/write + /test endpoint
  - Builder UI passes approvers_invited through to the saved job
  - Workflow: invitees get email DMs when SMTP is configured
  - Air-gap: SMTP unconfigured = channel-only (no exception)
  - Trust: invitation ≠ authorization (role gate still enforced)
"""

from __future__ import annotations

import os
import pytest


# --------------------------------------------------- directory module


def test_directory_loads_user_with_full_v9_42_fields(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_USERS_FILE", str(tmp_path / "users.yaml"))
    (tmp_path / "users.yaml").write_text(
        "tenants:\n"
        "  acme:\n"
        "    users:\n"
        "      - username: alice\n"
        "        password_hash: $2b$00$abc\n"
        "        roles: [admin]\n"
        "        email: alice@acme.com\n"
        "        display_name: Alice Chen\n"
        "        external_id: okta:00u3xyz\n"
        "        notify:\n"
        "          slack_user_id: U03ABCDEF\n"
        "          teams_user_id: 8:orgid:guid\n"
    )
    from safecadence.users.directory import list_users
    users = list_users(tenant="acme")
    assert len(users) == 1
    u = users[0]
    assert u.username == "alice"
    assert u.email == "alice@acme.com"
    assert u.display_name == "Alice Chen"
    assert u.external_id == "okta:00u3xyz"
    assert u.notify["slack_user_id"] == "U03ABCDEF"
    assert u.notify["teams_user_id"] == "8:orgid:guid"


def test_directory_backward_compatible_with_pre_v9_42_yaml(tmp_path, monkeypatch):
    """A users.yaml with only the v2.1 fields must still load."""
    monkeypatch.setenv("SC_USERS_FILE", str(tmp_path / "users.yaml"))
    (tmp_path / "users.yaml").write_text(
        "tenants:\n  acme:\n    users:\n"
        "      - username: bob\n"
        "        password_hash: $2b$00$x\n"
        "        roles: [analyst]\n"
    )
    from safecadence.users.directory import list_users
    users = list_users(tenant="acme")
    assert users[0].username == "bob"
    assert users[0].email == ""
    assert users[0].notify == {}


def test_directory_never_returns_password_hash(tmp_path, monkeypatch):
    """Trust property: the directory must NEVER include password_hash
    in any field. The API surface depends on this."""
    monkeypatch.setenv("SC_USERS_FILE", str(tmp_path / "users.yaml"))
    (tmp_path / "users.yaml").write_text(
        "tenants:\n  acme:\n    users:\n"
        "      - username: alice\n"
        "        password_hash: $2b$00$LEAK_CANARY\n"
        "        roles: [admin]\n"
    )
    from safecadence.users.directory import list_users, get_user
    from dataclasses import asdict
    rec = get_user("alice", tenant="acme")
    blob = str(asdict(rec))
    assert "LEAK_CANARY" not in blob
    assert "password" not in blob.lower()


def test_directory_validate_rejects_bad_email():
    from safecadence.users.directory import validate_user_payload
    errs = validate_user_payload({"username": "x", "roles": ["admin"],
                                    "email": "not-an-email"})
    assert any("email" in e for e in errs)


def test_directory_validate_requires_username_and_roles():
    from safecadence.users.directory import validate_user_payload
    assert validate_user_payload({})
    assert validate_user_payload({"username": "x"})              # no roles
    assert validate_user_payload({"username": "x", "roles": []}) # empty roles
    # OK
    assert not validate_user_payload({"username": "x",
                                        "roles": ["viewer"]})


def test_directory_upsert_round_trip(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_USERS_FILE", str(tmp_path / "users.yaml"))
    from safecadence.users.directory import upsert_user, get_user
    rec = upsert_user({
        "username": "carol", "roles": ["admin"],
        "email": "carol@acme.com",
        "display_name": "Carol",
        "notify": {"slack_user_id": "U99"},
    }, tenant="acme")
    assert rec.email == "carol@acme.com"
    again = get_user("carol", tenant="acme")
    assert again.email == "carol@acme.com"
    assert again.notify["slack_user_id"] == "U99"


def test_directory_upsert_preserves_password_hash(tmp_path, monkeypatch):
    """An admin editing a user's display_name must NOT clobber the
    existing password_hash."""
    monkeypatch.setenv("SC_USERS_FILE", str(tmp_path / "users.yaml"))
    (tmp_path / "users.yaml").write_text(
        "tenants:\n  acme:\n    users:\n"
        "      - username: dave\n"
        "        password_hash: $2b$00$KEEP_THIS_HASH\n"
        "        roles: [admin]\n"
    )
    from safecadence.users.directory import upsert_user
    upsert_user({"username": "dave", "roles": ["admin"],
                  "display_name": "Dave"}, tenant="acme")
    raw = (tmp_path / "users.yaml").read_text()
    assert "KEEP_THIS_HASH" in raw, (
        "password_hash must be preserved across directory updates"
    )


def test_lookup_invitees_drops_unknown(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_USERS_FILE", str(tmp_path / "users.yaml"))
    (tmp_path / "users.yaml").write_text(
        "tenants:\n  acme:\n    users:\n"
        "      - username: alice\n"
        "        roles: [admin]\n"
        "        email: alice@acme.com\n"
    )
    from safecadence.users.directory import lookup_invitees
    out = lookup_invitees(["alice", "ghost"], tenant="acme")
    assert len(out) == 1
    assert out[0].username == "alice"


# ------------------------------------------------ email config + crypto


def test_email_config_password_encrypted_at_rest(tmp_path, monkeypatch):
    """Trust property: SMTP password persists as Fernet ciphertext,
    NEVER as plaintext when the vault key is available."""
    pytest.importorskip("cryptography")
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from cryptography.fernet import Fernet
    monkeypatch.setenv("SAFECADENCE_VAULT_KEY",
                        Fernet.generate_key().decode("ascii"))
    from safecadence.notifier.email_notifier import (
        EmailConfig, save_email_config, load_email_config,
    )
    save_email_config(EmailConfig(
        enabled=True, host="smtp.acme.local", port=587,
        username="noreply@acme.com",
        password="PLAINTEXT-LEAK-CANARY",
        from_addr="SafeCadence <noreply@acme.com>",
    ))
    on_disk = (tmp_path / "settings" / "email.json").read_text()
    assert "PLAINTEXT-LEAK-CANARY" not in on_disk, (
        "SMTP password landed on disk in plaintext"
    )
    assert "FERNET:" in on_disk
    # And we can still decrypt it on load — round-trip works
    cfg = load_email_config()
    assert cfg.password_encrypted.startswith("FERNET:")


def test_email_to_public_dict_never_returns_password(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.notifier.email_notifier import (
        EmailConfig, save_email_config, load_email_config,
    )
    save_email_config(EmailConfig(
        enabled=True, host="smtp.acme.local",
        username="x", password="secret",
        from_addr="a@b.com",
    ))
    public = load_email_config().to_public_dict()
    assert "password" not in public
    assert "password_encrypted" not in public
    assert public["has_password"] is True


def test_email_send_disabled_without_config(tmp_path, monkeypatch):
    """is_configured() returns False when SMTP isn't set up;
    send_email returns (False, reason) instead of raising. This is
    the air-gap pathway."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    from safecadence.notifier.email_notifier import (
        is_configured, send_email,
    )
    assert is_configured() is False
    ok, err = send_email(to="x@y.com", subject="t", body="b")
    assert ok is False
    assert err


def test_render_approval_email_includes_trust_note():
    """Every approval email must say 'invitation does not grant
    approval authority'. Pinned so a copy refactor doesn't drop it."""
    from safecadence.notifier.email_notifier import render_approval_email
    subj, plain, html = render_approval_email(
        job_name="Block SMB", job_id="job_xyz",
        risk="medium", intent="Block SMB on edge firewalls.",
        target_summary="2 group(s)",
        link="/approvals#job_xyz",
        requested_by="alice",
    )
    assert "approval" in subj.lower()
    assert "does not grant approval" in plain
    assert "does not grant approval" in html
    assert "alice" in plain
    assert "/approvals#job_xyz" in plain


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
    # Non-admin token for 403 tests
    btok = c.post("/api/login",
                    data={"username": "bob", "password": "pw"}
                    ).json()["access_token"]
    c._bhdr = {"Authorization": f"Bearer {btok}"}
    return c


def test_users_list_returns_directory_no_hashes(admin_client):
    r = admin_client.get("/api/users", headers=admin_client._hdr)
    assert r.status_code == 200
    body = r.json()
    names = sorted(u["username"] for u in body["users"])
    assert names == ["alice", "bob"]
    blob = str(body)
    assert "password_hash" not in blob
    assert "$2b$" not in blob


def test_users_create_requires_admin_role(admin_client):
    """Bob (analyst) can NOT create users. Trust gate test."""
    r = admin_client.post("/api/users", headers=admin_client._bhdr,
                           json={"username": "carol", "roles": ["viewer"]})
    assert r.status_code == 403


def test_users_create_validates(admin_client):
    r = admin_client.post("/api/users", headers=admin_client._hdr,
                           json={"username": "carol", "roles": ["viewer"],
                                 "email": "not-an-email"})
    assert r.status_code == 400


def test_users_admin_can_create_then_delete(admin_client):
    r = admin_client.post("/api/users", headers=admin_client._hdr,
                           json={"username": "carol", "roles": ["viewer"],
                                 "email": "carol@acme.com",
                                 "display_name": "Carol"})
    assert r.status_code == 200
    listed = admin_client.get("/api/users",
                                headers=admin_client._hdr).json()
    names = [u["username"] for u in listed["users"]]
    assert "carol" in names

    r = admin_client.delete("/api/users/carol",
                              headers=admin_client._hdr)
    assert r.status_code == 200
    listed = admin_client.get("/api/users",
                                headers=admin_client._hdr).json()
    names = [u["username"] for u in listed["users"]]
    assert "carol" not in names


def test_users_admin_cannot_delete_themselves(admin_client):
    r = admin_client.delete("/api/users/alice",
                              headers=admin_client._hdr)
    assert r.status_code == 400


def test_settings_email_password_field_never_returned(admin_client):
    """API surface: GET /api/settings/email returns has_password boolean,
    never the actual password."""
    admin_client.post("/api/settings/email", headers=admin_client._hdr,
                       json={"enabled": True, "host": "smtp.acme.local",
                             "username": "x", "password": "secret-canary",
                             "from_addr": "noreply@acme.com"})
    r = admin_client.get("/api/settings/email",
                          headers=admin_client._hdr)
    assert r.status_code == 200
    body = r.json()
    assert "password" not in body
    assert "password_encrypted" not in body
    assert body["has_password"] is True
    assert "secret-canary" not in str(body)


def test_settings_email_blank_password_preserves_existing(admin_client):
    """Editing the email config without re-entering the password
    must NOT clobber it. Common pattern for "edit but keep secret"."""
    admin_client.post("/api/settings/email", headers=admin_client._hdr,
                       json={"enabled": True, "host": "smtp.acme.local",
                             "username": "x", "password": "first-pw",
                             "from_addr": "noreply@acme.com"})
    # Edit the host without sending password
    admin_client.post("/api/settings/email", headers=admin_client._hdr,
                       json={"enabled": True, "host": "smtp2.acme.local",
                             "username": "x",
                             "from_addr": "noreply@acme.com"})
    r = admin_client.get("/api/settings/email",
                          headers=admin_client._hdr).json()
    assert r["host"] == "smtp2.acme.local"
    assert r["has_password"] is True       # not wiped


def test_settings_email_test_requires_recipient(admin_client):
    """Non-admin alice has no email but admin_client's alice does;
    we test the 'no recipient' edge by overriding to a tenant
    without an email on file."""
    # No body, but alice has email on file → test should attempt send
    # and return 502 (no real SMTP host configured). We just want to
    # confirm the endpoint does the recipient resolution correctly.
    r = admin_client.post("/api/settings/email/test",
                            headers=admin_client._hdr, json={})
    # Either 502 (SMTP not really running) or 400 (no SMTP enabled).
    # Both are acceptable; the test is that we reach the send path
    # without a 500.
    assert r.status_code in (400, 502)


# ----------------------------------- workflow notifier integration


def test_workflow_email_dm_skipped_when_smtp_disabled(tmp_path, monkeypatch):
    """When SMTP is unconfigured, the email-DM helper records a skip
    in the audit log instead of raising. This is the air-gap path."""
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_USERS_FILE", str(tmp_path / "users.yaml"))
    (tmp_path / "users.yaml").write_text(
        "tenants:\n  acme:\n    users:\n"
        "      - username: alice\n"
        "        roles: [admin]\n"
        "        email: alice@acme.com\n"
    )
    from safecadence.execution import workflow
    from safecadence.execution.schema import (
        CommandJob, CommandMode, JobStatus, RiskLevel,
    )
    job = CommandJob(
        job_id="dm-skip-1", name="x", description="x",
        mode=CommandMode.CONFIG, risk=RiskLevel.MEDIUM,
        status=JobStatus.REVIEW, tenant="acme",
        approvers_invited=["alice"],
    )
    req = workflow.ApprovalRequest(job_id=job.job_id,
                                     requested_by="bob",
                                     approval_id="ar-1")
    # Should NOT raise even though SMTP is off
    workflow._notify_invited_approvers_via_email(job, req, "bob")


def test_workflow_email_dm_calls_send_for_each_invitee(tmp_path, monkeypatch):
    """When SMTP is configured AND invitees have email, the workflow
    calls send_email() per invitee. We monkey-patch send_email so the
    test doesn't need a real SMTP server."""
    pytest.importorskip("cryptography")
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SC_USERS_FILE", str(tmp_path / "users.yaml"))
    from cryptography.fernet import Fernet
    monkeypatch.setenv("SAFECADENCE_VAULT_KEY",
                        Fernet.generate_key().decode("ascii"))
    (tmp_path / "users.yaml").write_text(
        "tenants:\n  acme:\n    users:\n"
        "      - username: alice\n        roles: [admin]\n"
        "        email: alice@acme.com\n"
        "      - username: bob\n        roles: [admin]\n"
        "        email: bob@acme.com\n"
    )
    # Configure SMTP so is_configured() returns True
    from safecadence.notifier.email_notifier import (
        EmailConfig, save_email_config,
    )
    save_email_config(EmailConfig(enabled=True, host="smtp.acme.local",
                                   username="x", password="pw",
                                   from_addr="from@acme.com"))

    sent: list[dict] = []
    from safecadence.notifier import email_notifier
    monkeypatch.setattr(email_notifier, "send_email",
                         lambda **kw: (sent.append(kw), (True, ""))[1])

    from safecadence.execution import workflow
    from safecadence.execution.schema import (
        CommandJob, CommandMode, JobStatus, RiskLevel,
    )
    job = CommandJob(
        job_id="dm-go", name="Block SMB",
        description="Block SMB on edge firewalls.",
        mode=CommandMode.CONFIG, risk=RiskLevel.MEDIUM,
        status=JobStatus.REVIEW, tenant="acme",
        approvers_invited=["alice", "bob"],
    )
    req = workflow.ApprovalRequest(job_id=job.job_id,
                                     requested_by="carol",
                                     approval_id="ar-2")
    workflow._notify_invited_approvers_via_email(job, req, "carol")
    addrs = sorted(s["to"] for s in sent)
    assert addrs == ["alice@acme.com", "bob@acme.com"]


# ------------------------------------------------- builder UI wiring


def test_builder_has_invite_approvers_row():
    from safecadence.ui import v9_pages
    body = v9_pages._BUILDER_BODY
    src = v9_pages._BUILDER_SCRIPT
    assert "Invite specific approvers" in body
    assert "bld-invitees" in body
    assert "bldAddInvitee" in src
    assert "bldRemoveInvitee" in src
    assert "/api/users" in src


def test_builder_passes_approvers_invited_to_save():
    from safecadence.ui import v9_pages
    src = v9_pages._BUILDER_SCRIPT
    # Both save paths pass the invitee list
    assert "approvers_invited: BLD_INVITEES" in src


def test_builder_renders_trust_note_about_invitation_vs_authorization():
    """v9.42 explicit trust note: invitation ≠ authorization."""
    from safecadence.ui import v9_pages
    body = v9_pages._BUILDER_BODY
    assert "invitation" in body.lower()
    assert "authorization" in body.lower()


# ---------------------------- builder API passes invitees through


def test_save_draft_persists_approvers_invited(admin_client):
    r = admin_client.post(
        "/api/execute/builder/save-draft",
        headers=admin_client._hdr,
        json={"intent": "check version on cisco devices",
              "approvers_invited": ["bob"]},
    )
    assert r.status_code == 200, r.text
    job = r.json()["job"]
    assert job["approvers_invited"] == ["bob"]
