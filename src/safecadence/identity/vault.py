"""
v9.34 #2 — Identity credential vault.

Thin wrapper around the existing ``platform.credential_vault.PlatformVault``
specialized for the 5 identity systems (Okta / Entra / ISE / ClearPass /
AD). The wrapper handles three things the underlying vault doesn't:

  1. Master-key bootstrap — auto-generates ``~/.safecadence/.identity_
     vault.key`` on first run so operators don't have to set an env var
     before they can save their first connector. Permissions chmod 600.
  2. One-record-per-system semantics — `save_creds("okta", ...)` upserts
     the single Okta record rather than appending labelled rows.
  3. Last-test/last-synced metadata — every record carries when it was
     last successfully test_connection'd and when it was last sync'd, so
     the connector status strip can render an honest "last synced 2s ago".

Trust property: a credential blob never lands in the vault unless the
caller flagged ``test_passed=True``. The /api/identity/connect handler
runs ``adapter.test_connection()`` first and only persists on success.

Encryption: Fernet (AES-128 in CBC + HMAC-SHA256) via the same
``cryptography`` dep we already require for [vault] extras.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


SUPPORTED_SYSTEMS = ("okta", "entra", "ise", "clearpass", "ad")

# Map system name → label used inside PlatformVault. Keeping the
# 'identity:' prefix lets PlatformVault list() be partitioned by
# product surface without needing a new table.
def _label_for(system: str) -> str:
    s = (system or "").strip().lower()
    if s not in SUPPORTED_SYSTEMS:
        raise ValueError(
            f"unsupported identity system {system!r} — expected one of "
            f"{SUPPORTED_SYSTEMS}"
        )
    return f"identity:{s}"


@dataclass
class IdentityCredRecord:
    """What the vault stores per system. Credentials live encrypted;
    metadata lives in plain SQLite columns for fast list()."""
    system: str
    target: str
    credentials: dict = field(default_factory=dict)
    last_test_at: str = ""             # ISO 8601, empty if never tested
    last_test_ok: bool = False
    last_synced_at: str = ""           # ISO 8601, empty if never synced
    notes: str = ""

    def to_blob(self) -> dict:
        """The piece that lands inside the encrypted blob — only the
        actual credentials, never the metadata. That way `list()`
        results the UI shows can include status without leaking
        secrets."""
        return {"credentials": self.credentials, "system": self.system,
                "target": self.target}


# ----------------------------------------------------------- key bootstrap


def _key_path() -> Path:
    home = Path(os.environ.get("SAFECADENCE_HOME") or
                  (Path.home() / ".safecadence"))
    home.mkdir(parents=True, exist_ok=True)
    return home / ".identity_vault.key"


def _bootstrap_master_key() -> str:
    """Resolve a Fernet master key for the identity vault.

    Order:
      1. ``SAFECADENCE_VAULT_KEY`` env var (production)
      2. ``$SAFECADENCE_HOME/.identity_vault.key`` (auto-generated)
      3. Generate a fresh key, persist it with 0600 perms, return it

    Trust property: the auto-generated path is the only place we make
    fallback decisions. We never silently default to a hardcoded key.
    """
    explicit = os.environ.get("SAFECADENCE_VAULT_KEY") or ""
    if explicit:
        return explicit
    p = _key_path()
    if p.exists():
        return p.read_text(encoding="utf-8").strip()
    try:
        from cryptography.fernet import Fernet
    except ImportError as exc:                                  # pragma: no cover
        raise RuntimeError(
            "cryptography is required for the identity vault. "
            "Install with: pip install 'safecadence-netrisk[vault]'"
        ) from exc
    key = Fernet.generate_key().decode("ascii")
    p.write_text(key + "\n", encoding="utf-8")
    try:
        os.chmod(p, 0o600)
    except OSError:                                             # pragma: no cover
        pass
    return key


# --------------------------------------------------------------- IdentityVault


class IdentityVault:
    """One row per identity system. Upsert-on-save semantics.

    Storage backend selection (v9.39):
      - DATABASE_URL set + SQLAlchemy installed → Postgres path via
        ``storage_pg`` (same engine the rest of the platform shares).
      - Otherwise → SQLite via PlatformVault (the v9.34 default).

    The Fernet encryption layer is identical in both backends —
    credentials never land in plaintext, only the indexed metadata
    (last_test_at, last_synced_at, target) is queryable without
    decryption.
    """

    def __init__(self, *, db_path: Optional[Path] = None,
                  master_key: str = "",
                  tenant: str = "local",
                  force_sqlite: bool = False):
        self._tenant = tenant or "local"
        self._master_key = master_key or _bootstrap_master_key()
        self._pg = None
        # v9.39 — opt into Postgres when DATABASE_URL is set, unless
        # the caller explicitly forces sqlite (used by the local
        # bootstrap + tests that don't want a network DB).
        if not force_sqlite:
            try:
                from safecadence import storage_pg
                if storage_pg.is_enabled():
                    self._pg = _PgIdentityBackend(
                        master_key=self._master_key,
                        tenant=self._tenant,
                    )
            except Exception:                        # pragma: no cover
                self._pg = None
        if self._pg is not None:
            self._inner = None
            return
        from safecadence.platform.credential_vault import PlatformVault
        if db_path is None:
            home = Path(os.environ.get("SAFECADENCE_HOME") or
                          (Path.home() / ".safecadence"))
            home.mkdir(parents=True, exist_ok=True)
            db_path = home / "identity_vault.sqlite"
        self._inner = PlatformVault(
            db_path=db_path,
            master_key=self._master_key,
        )

    # ---------- backend selector helpers ---------------------------- #
    @property
    def backend(self) -> str:
        """'postgres' if running against DATABASE_URL, else 'sqlite'.
        Surfaced so the connector status strip can render an honest
        'Storage: Postgres' badge."""
        return "postgres" if self._pg is not None else "sqlite"

    # ---- write ------------------------------------------------------ #
    def save_creds(self, *, system: str, target: str,
                    credentials: dict, test_passed: bool,
                    actor: str = "ui", notes: str = "") -> IdentityCredRecord:
        """Persist creds for ``system``. Idempotent — overwrites prior
        record for the same system. ``test_passed`` MUST be True; the
        caller is the only place that knows whether the test actually
        ran. We require the explicit flag so a misuse can't silently
        save un-tested credentials."""
        if not test_passed:
            raise ValueError(
                "save_creds requires test_passed=True. Run "
                "adapter.test_connection() first and only persist on "
                "success — that's the v9.34 trust property.")
        if not isinstance(credentials, dict) or not credentials:
            raise ValueError("credentials must be a non-empty dict")
        label = _label_for(system)
        rec = IdentityCredRecord(
            system=system.lower(), target=target,
            credentials=credentials,
            last_test_at=datetime.now(timezone.utc).isoformat(),
            last_test_ok=True,
            notes=notes,
        )
        if self._pg is not None:
            self._pg.upsert(rec)
            return rec
        # Upsert — delete prior then store. PlatformVault enforces a
        # UNIQUE constraint on label so this is the simplest path.
        try:
            self._inner.delete(label)
        except Exception:
            pass
        self._inner.store(
            label=label,
            adapter_name=system.lower(),
            target=target,
            credentials=rec.to_blob(),
            notes=json.dumps({
                "last_test_at": rec.last_test_at,
                "last_test_ok": rec.last_test_ok,
                "last_synced_at": rec.last_synced_at,
            }),
        )
        return rec

    # ---- read ------------------------------------------------------- #
    def load_creds(self, system: str) -> Optional[IdentityCredRecord]:
        """Return the persisted record for ``system``, or None if not
        connected. Mutating the returned dict won't mutate the vault."""
        if self._pg is not None:
            return self._pg.get(system.lower())
        label = _label_for(system)
        row = self._inner.get(label)
        if not row:
            return None
        blob = row.get("credentials") or {}
        meta = {}
        try:
            meta = json.loads(row.get("notes") or "{}")
        except Exception:
            meta = {}
        return IdentityCredRecord(
            system=system.lower(),
            target=row.get("target", ""),
            credentials=dict(blob.get("credentials") or {}),
            last_test_at=meta.get("last_test_at", ""),
            last_test_ok=bool(meta.get("last_test_ok", False)),
            last_synced_at=meta.get("last_synced_at", ""),
        )

    # ---- list ------------------------------------------------------- #
    def list_connected(self) -> list[dict]:
        """Surface what's connected without leaking secrets. Returns a
        list of {system, target, last_test_at, last_test_ok,
        last_synced_at}. Used by the connector status strip."""
        if self._pg is not None:
            return self._pg.list()
        out: list[dict] = []
        for row in self._inner.list():
            label = row.get("label", "")
            if not label.startswith("identity:"):
                continue
            try:
                meta = json.loads(row.get("notes") or "{}")
            except Exception:
                meta = {}
            out.append({
                "system": label.split(":", 1)[1],
                "target": row.get("target", ""),
                "last_test_at": meta.get("last_test_at", ""),
                "last_test_ok": bool(meta.get("last_test_ok", False)),
                "last_synced_at": meta.get("last_synced_at", ""),
            })
        return out

    # ---- delete ----------------------------------------------------- #
    def disconnect(self, system: str) -> bool:
        if self._pg is not None:
            return self._pg.delete(system.lower())
        return bool(self._inner.delete(_label_for(system)))

    # ---- mark sync timestamp --------------------------------------- #
    def mark_synced(self, system: str) -> None:
        """Update last_synced_at on the existing record. Called by the
        sync endpoint after a successful adapter.collect() pass."""
        rec = self.load_creds(system)
        if rec is None:
            return
        rec.last_synced_at = datetime.now(timezone.utc).isoformat()
        if self._pg is not None:
            self._pg.upsert(rec)
            return
        # Re-save without a new test; preserve last_test_at/ok.
        label = _label_for(system)
        try:
            self._inner.delete(label)
        except Exception:
            pass
        self._inner.store(
            label=label,
            adapter_name=system.lower(),
            target=rec.target,
            credentials=rec.to_blob(),
            notes=json.dumps({
                "last_test_at": rec.last_test_at,
                "last_test_ok": rec.last_test_ok,
                "last_synced_at": rec.last_synced_at,
            }),
        )


# ----------------------------------------------------- Postgres backend


class _PgIdentityBackend:
    """v9.39 — Postgres-backed identity vault.

    Mirrors PlatformVault's storage interface but uses the same
    SQLAlchemy engine the rest of the platform shares via
    ``storage_pg``. Credentials are still Fernet-encrypted before they
    land in the JSON ``payload`` column — the database never sees
    plaintext secrets, even on dump/restore.
    """

    def __init__(self, *, master_key: str, tenant: str):
        from cryptography.fernet import Fernet
        from safecadence import storage_pg
        self._tenant = tenant or "local"
        self._fernet = Fernet(
            master_key.encode() if isinstance(master_key, str)
            else master_key)
        # Force engine init + table creation now so save_creds doesn't
        # race with first read.
        storage_pg._ensure()
        from safecadence.storage_pg import _meta as meta
        self._table = meta.tables["sc_identity_vault"]

    def _encrypt(self, blob: dict) -> str:
        return self._fernet.encrypt(json.dumps(blob).encode("utf-8")
                                      ).decode("ascii")

    def _decrypt(self, ciphertext: str) -> dict:
        if not ciphertext:
            return {}
        try:
            return json.loads(
                self._fernet.decrypt(ciphertext.encode("ascii")
                                       ).decode("utf-8"))
        except Exception:
            return {}

    def upsert(self, rec: IdentityCredRecord) -> None:
        from safecadence import storage_pg
        eng = storage_pg._ensure()
        if not eng:                                  # pragma: no cover
            raise RuntimeError("DATABASE_URL no longer reachable")
        from sqlalchemy import update
        payload = {
            "encrypted_blob": self._encrypt(rec.to_blob()),
            "last_test_at": rec.last_test_at,
            "last_test_ok": rec.last_test_ok,
            "last_synced_at": rec.last_synced_at,
        }
        with eng.begin() as conn:
            upd = (update(self._table)
                    .where(self._table.c.system == rec.system)
                    .where(self._table.c.tenant == self._tenant)
                    .values(target=rec.target, payload=payload))
            r = conn.execute(upd)
            if r.rowcount == 0:
                conn.execute(self._table.insert().values(
                    system=rec.system, tenant=self._tenant,
                    target=rec.target, payload=payload,
                ))

    def get(self, system: str) -> Optional[IdentityCredRecord]:
        from safecadence import storage_pg
        eng = storage_pg._ensure()
        if not eng:                                  # pragma: no cover
            return None
        from sqlalchemy import select
        with eng.connect() as conn:
            r = conn.execute(
                select(self._table)
                .where(self._table.c.system == system)
                .where(self._table.c.tenant == self._tenant)
            ).first()
        if not r:
            return None
        m = r._mapping
        payload = m["payload"] or {}
        blob = self._decrypt(payload.get("encrypted_blob", ""))
        return IdentityCredRecord(
            system=system,
            target=m["target"] or "",
            credentials=dict(blob.get("credentials") or {}),
            last_test_at=payload.get("last_test_at", ""),
            last_test_ok=bool(payload.get("last_test_ok", False)),
            last_synced_at=payload.get("last_synced_at", ""),
        )

    def list(self) -> list[dict]:
        from safecadence import storage_pg
        eng = storage_pg._ensure()
        if not eng:                                  # pragma: no cover
            return []
        from sqlalchemy import select
        out: list[dict] = []
        with eng.connect() as conn:
            for r in conn.execute(
                select(self._table)
                .where(self._table.c.tenant == self._tenant)
            ):
                m = r._mapping
                payload = m["payload"] or {}
                out.append({
                    "system": m["system"],
                    "target": m["target"] or "",
                    "last_test_at": payload.get("last_test_at", ""),
                    "last_test_ok": bool(payload.get("last_test_ok", False)),
                    "last_synced_at": payload.get("last_synced_at", ""),
                })
        return out

    def delete(self, system: str) -> bool:
        from safecadence import storage_pg
        eng = storage_pg._ensure()
        if not eng:                                  # pragma: no cover
            return False
        from sqlalchemy import delete
        with eng.begin() as conn:
            r = conn.execute(
                delete(self._table)
                .where(self._table.c.system == system)
                .where(self._table.c.tenant == self._tenant)
            )
        return bool(r.rowcount)
