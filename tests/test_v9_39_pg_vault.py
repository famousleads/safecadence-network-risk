"""
v9.39 — Postgres-backed identity vault.

Before v9.39, IdentityVault was hardcoded to SQLite via PlatformVault.
For multi-instance HA / large-fleet deployments, operators set
DATABASE_URL and expect the rest of the platform to use Postgres —
v7.1 wired that for assets/policies/jobs but identity vault was an
exception. v9.39 closes that gap:

  - DATABASE_URL set + sqlalchemy installed → Postgres path via
    sc_identity_vault table.
  - Otherwise → SQLite via PlatformVault (the v9.34 default).

Both paths Fernet-encrypt credentials before storage; only metadata
(target, last_test_at, last_synced_at) is queryable in the clear.

Tests run the full save/load/list/disconnect lifecycle against an
in-memory SQLite-via-SQLAlchemy URL so they don't need a live
Postgres server but exercise the same code path.
"""

from __future__ import annotations

import os
import pytest

pytest.importorskip("cryptography")
pytest.importorskip("sqlalchemy")


@pytest.fixture
def pg_vault(tmp_path, monkeypatch):
    """Boot an IdentityVault against a fresh sqlite-via-sqlalchemy URL.

    This exercises the v9.39 Postgres-style code path (the
    `_PgIdentityBackend` class) without requiring a Postgres server.
    The same SQLAlchemy queries run against either backend — we just
    point DATABASE_URL at a file SQLite for the test.
    """
    monkeypatch.setenv("SAFECADENCE_HOME", str(tmp_path))
    db_file = tmp_path / "v939.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file}")
    # Reset storage_pg's module-level engine cache so the next
    # _ensure() picks up our DATABASE_URL.
    from safecadence import storage_pg
    storage_pg._engine = None
    storage_pg._meta = None
    from cryptography.fernet import Fernet
    monkeypatch.setenv("SAFECADENCE_VAULT_KEY",
                        Fernet.generate_key().decode("ascii"))
    from safecadence.identity.vault import IdentityVault
    v = IdentityVault(tenant="acme")
    assert v.backend == "postgres", (
        f"v9.39 must auto-select postgres backend when DATABASE_URL "
        f"is set; got {v.backend}"
    )
    yield v
    # Cleanup the engine so a subsequent test (without DATABASE_URL)
    # doesn't reuse it.
    storage_pg._engine = None
    storage_pg._meta = None


@pytest.fixture
def sqlite_vault(tmp_path, monkeypatch):
    """Boot an IdentityVault against the SQLite (PlatformVault) path."""
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("SAFECADENCE_HOME", str(tmp_path))
    from safecadence import storage_pg
    storage_pg._engine = None
    storage_pg._meta = None
    from cryptography.fernet import Fernet
    monkeypatch.setenv("SAFECADENCE_VAULT_KEY",
                        Fernet.generate_key().decode("ascii"))
    from safecadence.identity.vault import IdentityVault
    v = IdentityVault(force_sqlite=True)
    assert v.backend == "sqlite"
    yield v


# --------------------------------------------------- Postgres path


def test_pg_vault_save_and_load_roundtrip(pg_vault):
    rec = pg_vault.save_creds(
        system="okta", target="acme.okta.com",
        credentials={"api_token": "secret-token-12345"},
        test_passed=True,
    )
    assert rec.system == "okta"
    assert rec.last_test_ok is True

    loaded = pg_vault.load_creds("okta")
    assert loaded is not None
    assert loaded.target == "acme.okta.com"
    assert loaded.credentials == {"api_token": "secret-token-12345"}
    assert loaded.last_test_at      # present
    assert loaded.last_test_ok is True


def test_pg_vault_upsert_replaces_prior_record(pg_vault):
    pg_vault.save_creds(system="okta", target="old.okta.com",
                         credentials={"api_token": "old"},
                         test_passed=True)
    pg_vault.save_creds(system="okta", target="new.okta.com",
                         credentials={"api_token": "new"},
                         test_passed=True)
    loaded = pg_vault.load_creds("okta")
    assert loaded.target == "new.okta.com"
    assert loaded.credentials == {"api_token": "new"}
    # And only one row in the listing
    listed = pg_vault.list_connected()
    assert sum(1 for s in listed if s["system"] == "okta") == 1


def test_pg_vault_list_excludes_secrets(pg_vault):
    pg_vault.save_creds(system="okta", target="acme.okta.com",
                         credentials={"api_token": "leak-me-not"},
                         test_passed=True)
    listed = pg_vault.list_connected()
    okta = next(s for s in listed if s["system"] == "okta")
    # Trust property: no credential field on the listing
    assert "credentials" not in okta
    assert "api_token" not in str(okta)
    assert okta["target"] == "acme.okta.com"


def test_pg_vault_disconnect_removes_record(pg_vault):
    pg_vault.save_creds(system="okta", target="acme.okta.com",
                         credentials={"api_token": "x"},
                         test_passed=True)
    assert pg_vault.disconnect("okta") is True
    assert pg_vault.load_creds("okta") is None
    # Deleting again is idempotent — returns False, doesn't crash
    assert pg_vault.disconnect("okta") is False


def test_pg_vault_mark_synced_updates_only_metadata(pg_vault):
    pg_vault.save_creds(system="okta", target="acme.okta.com",
                         credentials={"api_token": "x"},
                         test_passed=True)
    before = pg_vault.load_creds("okta")
    pg_vault.mark_synced("okta")
    after = pg_vault.load_creds("okta")
    assert after.last_synced_at      # populated
    assert after.last_synced_at != before.last_synced_at
    # Credentials + last_test_* preserved
    assert after.credentials == before.credentials
    assert after.last_test_at == before.last_test_at


def test_pg_vault_save_refuses_untested_creds(pg_vault):
    with pytest.raises(ValueError) as exc:
        pg_vault.save_creds(system="okta", target="x", credentials={"a": 1},
                             test_passed=False)
    assert "test_passed=True" in str(exc.value)


def test_pg_vault_save_refuses_empty_creds(pg_vault):
    with pytest.raises(ValueError):
        pg_vault.save_creds(system="okta", target="x", credentials={},
                             test_passed=True)


def test_pg_vault_credentials_are_encrypted_at_rest(pg_vault, tmp_path,
                                                     monkeypatch):
    """The credential blob in the DB must be Fernet ciphertext, not
    plaintext. Even an attacker with read access to the database
    (e.g. a stale backup) cannot recover the secrets without the
    master key."""
    pg_vault.save_creds(system="okta", target="acme.okta.com",
                         credentials={"api_token": "PLAINTEXT-LEAK-CANARY"},
                         test_passed=True)
    # Read the raw payload column directly
    from safecadence import storage_pg
    eng = storage_pg._ensure()
    from sqlalchemy import select
    table = storage_pg._meta.tables["sc_identity_vault"]
    with eng.connect() as conn:
        row = conn.execute(select(table)).first()
    payload = row._mapping["payload"]
    blob = payload.get("encrypted_blob", "")
    assert "PLAINTEXT-LEAK-CANARY" not in blob, (
        "credentials must be encrypted at rest in Postgres backend"
    )
    assert "PLAINTEXT-LEAK-CANARY" not in str(payload)


def test_pg_vault_per_tenant_isolation(tmp_path, monkeypatch):
    """Two tenants on the same DB don't see each other's connectors."""
    monkeypatch.setenv("SAFECADENCE_HOME", str(tmp_path))
    db_file = tmp_path / "iso.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file}")
    from safecadence import storage_pg
    storage_pg._engine = None
    storage_pg._meta = None
    from cryptography.fernet import Fernet
    monkeypatch.setenv("SAFECADENCE_VAULT_KEY",
                        Fernet.generate_key().decode("ascii"))
    from safecadence.identity.vault import IdentityVault
    a = IdentityVault(tenant="acme")
    b = IdentityVault(tenant="globex")

    a.save_creds(system="okta", target="acme.okta.com",
                  credentials={"t": "acme-token"}, test_passed=True)
    b.save_creds(system="okta", target="globex.okta.com",
                  credentials={"t": "globex-token"}, test_passed=True)

    # Each tenant sees only its own row
    a_okta = a.load_creds("okta")
    b_okta = b.load_creds("okta")
    assert a_okta.target == "acme.okta.com"
    assert b_okta.target == "globex.okta.com"
    assert a_okta.credentials != b_okta.credentials

    # And cross-tenant disconnect doesn't affect the other
    a.disconnect("okta")
    assert a.load_creds("okta") is None
    assert b.load_creds("okta") is not None
    storage_pg._engine = None
    storage_pg._meta = None


# --------------------------------------------------- SQLite path
# The SQLite path was already covered by tests/identity/test_v9_34_vault.py.
# These tests just confirm the v9.39 selector still routes correctly.


def test_sqlite_vault_used_when_database_url_unset(sqlite_vault):
    rec = sqlite_vault.save_creds(
        system="okta", target="legacy.okta.com",
        credentials={"api_token": "still-works"},
        test_passed=True,
    )
    assert rec.system == "okta"
    assert sqlite_vault.load_creds("okta").target == "legacy.okta.com"


def test_force_sqlite_overrides_database_url(tmp_path, monkeypatch):
    """force_sqlite=True bypasses the Postgres path even if
    DATABASE_URL is set. Used by the local bootstrap and tests."""
    monkeypatch.setenv("SAFECADENCE_HOME", str(tmp_path))
    monkeypatch.setenv("DATABASE_URL",
                        f"sqlite:///{tmp_path / 'unused.db'}")
    from safecadence import storage_pg
    storage_pg._engine = None
    storage_pg._meta = None
    from cryptography.fernet import Fernet
    monkeypatch.setenv("SAFECADENCE_VAULT_KEY",
                        Fernet.generate_key().decode("ascii"))
    from safecadence.identity.vault import IdentityVault
    v = IdentityVault(force_sqlite=True)
    assert v.backend == "sqlite"
    storage_pg._engine = None
    storage_pg._meta = None
