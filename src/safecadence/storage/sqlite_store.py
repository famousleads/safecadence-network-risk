"""Stdlib SQLite backend — adapted from core.store with tenant scoping."""

from __future__ import annotations

import json
import os
import sqlite3
import sys
from pathlib import Path
from typing import Any

from safecadence.storage.base import BaseStore


def _data_dir() -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming")))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local" / "share")))
    return base / "safecadence"


_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id   TEXT NOT NULL DEFAULT 'default',
    started_at  TEXT NOT NULL,
    source      TEXT NOT NULL,
    vendor      TEXT NOT NULL,
    hostname    TEXT,
    ip          TEXT,
    site        TEXT,
    health      INTEGER,
    risk        INTEGER,
    risk_band   TEXT,
    eol_status  TEXT,
    cves        INTEGER DEFAULT 0,
    findings    INTEGER DEFAULT 0,
    summary     TEXT,
    payload     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_tenant   ON scans(tenant_id);
CREATE INDEX IF NOT EXISTS idx_scans_hostname ON scans(hostname);
CREATE INDEX IF NOT EXISTS idx_scans_started  ON scans(started_at);

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id   TEXT NOT NULL,
    actor       TEXT,
    action      TEXT NOT NULL,
    resource    TEXT,
    detail      TEXT,
    at          TEXT NOT NULL
);
"""


class SqliteStore(BaseStore):
    def __init__(self, db_path: Path | None = None):
        self.path = Path(db_path) if db_path else (_data_dir() / "history.db")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        # v12 — bootstrap multi-tenant org schema on the same connection.
        # Idempotent; safe to call on every boot. Single-tenant installs
        # keep working because every existing query passes org_id=None.
        try:
            from safecadence.multitenant import ensure_org_schema
            ensure_org_schema(self._conn)
        except Exception:
            # Never let optional v12 wiring break v11.x store init.
            pass

    # ---- BaseStore ---------------------------------------------- #
    def save(self, scan_dict: dict, *, tenant_id: str = "default") -> int:
        asset = scan_dict.get("asset", {}) or {}
        ps = scan_dict.get("parsed_summary", {}) or {}
        cur = self._conn.execute(
            "INSERT INTO scans (tenant_id, started_at, source, vendor, hostname, ip, site, "
            "health, risk, risk_band, eol_status, cves, findings, summary, payload) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                tenant_id,
                scan_dict.get("started_at", ""),
                scan_dict.get("source", ""),
                scan_dict.get("vendor", ""),
                asset.get("hostname") or ps.get("hostname", ""),
                asset.get("ip", ""),
                (asset.get("location") or {}).get("site", "") or asset.get("site", ""),
                int(scan_dict.get("health_score") or 0),
                int(scan_dict.get("risk_score") or 0),
                scan_dict.get("risk_band", ""),
                (scan_dict.get("eol") or {}).get("status_today", ""),
                len(scan_dict.get("cves", [])),
                len(scan_dict.get("findings", [])),
                scan_dict.get("summary", ""),
                json.dumps(scan_dict, default=str),
            ),
        )
        self._conn.commit()
        return int(cur.lastrowid or 0)

    def list(self, *, limit: int = 50, source: str | None = None,
             tenant_id: str | None = None) -> list[dict]:
        sql = ("SELECT id, tenant_id, started_at, source, vendor, hostname, ip, site, "
               "health, risk, risk_band, eol_status, cves, findings FROM scans WHERE 1=1")
        params: list = []
        if tenant_id:
            sql += " AND tenant_id = ?"
            params.append(tenant_id)
        if source:
            sql += " AND source = ?"
            params.append(source)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        rows = self._conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def get(self, scan_id: int, *, tenant_id: str | None = None) -> dict | None:
        sql = "SELECT payload FROM scans WHERE id = ?"
        params: list = [scan_id]
        if tenant_id:
            sql += " AND tenant_id = ?"
            params.append(tenant_id)
        row = self._conn.execute(sql, params).fetchone()
        return json.loads(row["payload"]) if row else None

    def latest_per_host(self, *, tenant_id: str | None = None) -> list[dict]:
        sql = (
            "SELECT s.* FROM scans s "
            "WHERE s.id IN ("
            "  SELECT MAX(id) FROM scans WHERE 1=1 "
            f"  {'AND tenant_id = ?' if tenant_id else ''} "
            "  GROUP BY hostname"
            ")"
        )
        params = [tenant_id] if tenant_id else []
        rows = self._conn.execute(sql, params).fetchall()
        return [{
            "id": r["id"], "hostname": r["hostname"], "ip": r["ip"],
            "vendor": r["vendor"], "site": r["site"],
            "health_score": r["health"], "risk_score": r["risk"],
            "risk_band": r["risk_band"], "eol_status": r["eol_status"],
            "cves": r["cves"], "findings": r["findings"],
            "started_at": r["started_at"],
        } for r in rows]

    def audit(self, *, tenant_id: str, actor: str, action: str,
              resource: str = "", detail: str = "") -> None:
        from datetime import datetime, timezone
        self._conn.execute(
            "INSERT INTO audit_log (tenant_id, actor, action, resource, detail, at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (tenant_id, actor, action, resource, detail,
             datetime.now(timezone.utc).isoformat()),
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()
