"""
Multi-vendor credential vault — extends the existing security/vault.py
with platform-specific niceties:
  - Per-credential metadata (vendor, asset type, last-used)
  - Multiple credentials per asset (e.g., iDRAC + OS root + SNMP community)
  - Credential rotation tracking
  - Audit log of credential reads

Encrypted at rest with Fernet (existing vault).
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_SCHEMA = """
CREATE TABLE IF NOT EXISTS platform_credentials (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    label           TEXT NOT NULL UNIQUE,           -- e.g. "dell-idrac-r740-01"
    adapter_name    TEXT NOT NULL,                  -- e.g. "dell_idrac"
    target          TEXT NOT NULL,                  -- e.g. "idrac.dc1.acme.local"
    encrypted_blob  BLOB NOT NULL,                  -- Fernet-encrypted JSON of credentials
    notes           TEXT DEFAULT '',
    last_used       TEXT DEFAULT '',
    created_at      TEXT DEFAULT (datetime('now')),
    rotated_at      TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS credential_audit (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    credential_id   INTEGER,
    action          TEXT,                           -- read | written | rotated | deleted
    actor           TEXT,
    ts              TEXT DEFAULT (datetime('now')),
    detail          TEXT
);

CREATE INDEX IF NOT EXISTS idx_creds_adapter ON platform_credentials(adapter_name);
"""


class PlatformVault:
    """SQLite-backed credential vault with Fernet at-rest encryption."""

    def __init__(self, db_path: Path | None = None, *, master_key: str = ""):
        self.db_path = db_path or (Path.home() / ".safecadence" / "platform_credentials.sqlite")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        # Fernet master key — caller provides, OR derive from env, OR refuse to start
        import os
        self.master_key = master_key or os.environ.get("SAFECADENCE_VAULT_KEY", "")
        if not self.master_key:
            raise RuntimeError(
                "PlatformVault requires a master key. Provide via:\n"
                "  - PlatformVault(master_key=...)\n"
                "  - SAFECADENCE_VAULT_KEY env var\n"
                "Generate a fresh key with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
            )

        try:
            from cryptography.fernet import Fernet
        except ImportError:
            raise RuntimeError("cryptography required: pip install 'safecadence-netrisk[vault]'")
        self._fernet = Fernet(self.master_key.encode() if isinstance(self.master_key, str) else self.master_key)

        with self._conn() as c:
            c.executescript(_SCHEMA)

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def store(self, label: str, adapter_name: str, target: str,
              credentials: dict[str, str], notes: str = "") -> int:
        """Store/update a credential record."""
        encrypted = self._fernet.encrypt(json.dumps(credentials).encode("utf-8"))
        with self._conn() as c:
            existing = c.execute("SELECT id FROM platform_credentials WHERE label=?", (label,)).fetchone()
            now = datetime.now(timezone.utc).isoformat()
            if existing:
                c.execute(
                    "UPDATE platform_credentials SET adapter_name=?, target=?, encrypted_blob=?, "
                    "notes=?, rotated_at=? WHERE id=?",
                    (adapter_name, target, encrypted, notes, now, existing["id"]),
                )
                cid = existing["id"]
                c.execute("INSERT INTO credential_audit (credential_id, action) VALUES (?, ?)",
                          (cid, "rotated"))
            else:
                cur = c.execute(
                    "INSERT INTO platform_credentials (label, adapter_name, target, encrypted_blob, notes) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (label, adapter_name, target, encrypted, notes),
                )
                cid = cur.lastrowid
                c.execute("INSERT INTO credential_audit (credential_id, action) VALUES (?, ?)",
                          (cid, "written"))
            return cid

    def get(self, label: str) -> dict | None:
        """Retrieve a credential by label. Returns decrypted dict + metadata."""
        with self._conn() as c:
            row = c.execute("SELECT * FROM platform_credentials WHERE label=?", (label,)).fetchone()
            if not row:
                return None
            try:
                creds = json.loads(self._fernet.decrypt(row["encrypted_blob"]).decode("utf-8"))
            except Exception as e:
                return {"error": f"decrypt failed: {e}"}
            now = datetime.now(timezone.utc).isoformat()
            c.execute("UPDATE platform_credentials SET last_used=? WHERE id=?", (now, row["id"]))
            c.execute("INSERT INTO credential_audit (credential_id, action) VALUES (?, ?)",
                      (row["id"], "read"))
            return {
                "label": row["label"],
                "adapter_name": row["adapter_name"],
                "target": row["target"],
                "credentials": creds,
                "notes": row["notes"],
                "last_used": now,
                "created_at": row["created_at"],
                "rotated_at": row["rotated_at"],
            }

    def list(self) -> list[dict]:
        """List all credentials (without secrets)."""
        with self._conn() as c:
            rows = c.execute(
                "SELECT id, label, adapter_name, target, notes, last_used, created_at, rotated_at "
                "FROM platform_credentials ORDER BY label"
            ).fetchall()
        return [dict(r) for r in rows]

    def delete(self, label: str) -> bool:
        with self._conn() as c:
            row = c.execute("SELECT id FROM platform_credentials WHERE label=?", (label,)).fetchone()
            if not row:
                return False
            c.execute("DELETE FROM platform_credentials WHERE id=?", (row["id"],))
            c.execute("INSERT INTO credential_audit (credential_id, action) VALUES (?, ?)",
                      (row["id"], "deleted"))
            return True

    def audit_log(self, *, label: str | None = None, limit: int = 100) -> list[dict]:
        """Retrieve audit log entries."""
        with self._conn() as c:
            if label:
                row = c.execute("SELECT id FROM platform_credentials WHERE label=?", (label,)).fetchone()
                if not row:
                    return []
                rows = c.execute(
                    "SELECT * FROM credential_audit WHERE credential_id=? ORDER BY ts DESC LIMIT ?",
                    (row["id"], limit),
                ).fetchall()
            else:
                rows = c.execute(
                    "SELECT * FROM credential_audit ORDER BY ts DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        return [dict(r) for r in rows]
