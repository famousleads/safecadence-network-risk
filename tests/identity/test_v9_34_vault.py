"""
v9.34 #2 — IdentityVault tests.

Verifies the trust property: credentials cannot land in the vault
without an explicit ``test_passed=True`` flag, and what's listed for
the UI never includes the actual secrets.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("cryptography",
                     reason="cryptography required for vault tests")


@pytest.fixture
def vault(tmp_path, monkeypatch):
    """Fresh IdentityVault per test, isolated to a tmp dir so we don't
    touch a real ~/.safecadence/identity_vault.sqlite."""
    monkeypatch.setenv("SAFECADENCE_HOME", str(tmp_path))
    # Avoid clobbering an operator's real key — force a per-test key.
    from cryptography.fernet import Fernet
    monkeypatch.setenv("SAFECADENCE_VAULT_KEY",
                        Fernet.generate_key().decode("ascii"))
    from safecadence.identity.vault import IdentityVault
    return IdentityVault(db_path=tmp_path / "id.sqlite")


def test_save_and_load_round_trip(vault):
    rec = vault.save_creds(
        system="okta", target="acme.okta.com",
        credentials={"api_token": "secret-1"},
        test_passed=True, actor="alice",
    )
    assert rec.system == "okta"
    assert rec.last_test_ok is True

    loaded = vault.load_creds("okta")
    assert loaded is not None
    assert loaded.target == "acme.okta.com"
    assert loaded.credentials == {"api_token": "secret-1"}
    assert loaded.last_test_ok is True


def test_save_refuses_without_test_passed(vault):
    """The trust property: vault never holds untested credentials."""
    with pytest.raises(ValueError, match="test_passed=True"):
        vault.save_creds(
            system="okta", target="acme.okta.com",
            credentials={"api_token": "x"},
            test_passed=False,
        )
    assert vault.load_creds("okta") is None


def test_save_refuses_empty_credentials(vault):
    with pytest.raises(ValueError, match="non-empty dict"):
        vault.save_creds(system="okta", target="x",
                          credentials={}, test_passed=True)


def test_unsupported_system_rejected(vault):
    with pytest.raises(ValueError, match="unsupported"):
        vault.save_creds(system="duo", target="x",
                          credentials={"x": "y"}, test_passed=True)


def test_save_is_idempotent_upsert(vault):
    """Saving twice for the same system replaces, doesn't duplicate."""
    vault.save_creds(system="okta", target="old.okta.com",
                      credentials={"api_token": "v1"}, test_passed=True)
    vault.save_creds(system="okta", target="new.okta.com",
                      credentials={"api_token": "v2"}, test_passed=True)
    rec = vault.load_creds("okta")
    assert rec.target == "new.okta.com"
    assert rec.credentials == {"api_token": "v2"}
    listed = vault.list_connected()
    assert sum(1 for r in listed if r["system"] == "okta") == 1


def test_list_connected_never_leaks_secrets(vault):
    """The UI consumes list_connected() to render the connector strip.
    Defends against secrets-in-DOM by asserting the field is absent."""
    vault.save_creds(system="okta", target="acme.okta.com",
                      credentials={"api_token": "DO_NOT_LEAK"},
                      test_passed=True)
    rows = vault.list_connected()
    assert len(rows) == 1
    serialized = json.dumps(rows)
    assert "DO_NOT_LEAK" not in serialized, (
        "list_connected() must NEVER include the actual credentials"
    )
    assert "api_token" not in serialized
    assert rows[0]["system"] == "okta"
    assert rows[0]["target"] == "acme.okta.com"
    assert rows[0]["last_test_ok"] is True


def test_disconnect_removes_record(vault):
    vault.save_creds(system="entra", target="acme.onmicrosoft.com",
                      credentials={"client_id": "c", "client_secret": "s",
                                    "tenant_id": "t"},
                      test_passed=True)
    assert vault.load_creds("entra") is not None
    assert vault.disconnect("entra") is True
    assert vault.load_creds("entra") is None
    assert vault.disconnect("entra") is False    # already gone


def test_mark_synced_updates_only_sync_timestamp(vault):
    vault.save_creds(system="ad", target="ldap://ad.example",
                      credentials={"bind_dn": "x", "bind_password": "y",
                                    "base_dn": "DC=corp,DC=local"},
                      test_passed=True)
    before = vault.load_creds("ad")
    assert before.last_synced_at == ""
    vault.mark_synced("ad")
    after = vault.load_creds("ad")
    assert after.last_synced_at, "mark_synced must populate last_synced_at"
    # last_test_at must be preserved across sync (auditor needs it).
    assert after.last_test_at == before.last_test_at
    assert after.last_test_ok is True


def test_master_key_bootstrap_creates_persisted_key(tmp_path, monkeypatch):
    """When SAFECADENCE_VAULT_KEY is unset, a fresh key is generated
    and persisted with restrictive perms — operators don't have to
    set an env var to start using the product."""
    monkeypatch.setenv("SAFECADENCE_HOME", str(tmp_path))
    monkeypatch.delenv("SAFECADENCE_VAULT_KEY", raising=False)
    from safecadence.identity.vault import _bootstrap_master_key, _key_path
    k1 = _bootstrap_master_key()
    p = _key_path()
    assert p.exists()
    # Same call again returns the same key (no rotation on every read).
    k2 = _bootstrap_master_key()
    assert k1 == k2
    # File mode should be at most 0600 (no group/world bits).
    mode = p.stat().st_mode & 0o077
    assert mode == 0, f"key file mode 0{p.stat().st_mode & 0o777:o} too permissive"
