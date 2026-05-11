"""
Postgres-backed scan store (v10.7).

Same interface as :class:`safecadence.storage.sqlite_store.SqliteStore` so
the rest of the codebase doesn't care which one is wired in.

Stdlib + ``psycopg`` (3.x) when available. We import it lazily so the
module loads cleanly on hosts that don't have it — construction raises
an informative error if you actually try to use this store without
psycopg installed.

Activation:
    SC_POSTGRES_URL=postgresql://user:pass@host:5432/dbname

When unset, the existing SQLite path is used (see ``open_store`` below).
"""

from __future__ import annotations

import json
import os
from typing import Any

from safecadence.storage.base import BaseStore

try:
    import psycopg  # type: ignore
    _HAS_PSYCOPG = True
except Exception:  # pragma: no cover
    psycopg = None  # type: ignore
    _HAS_PSYCOPG = False


_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          BIGSERIAL PRIMARY KEY,
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
    id          BIGSERIAL PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    actor       TEXT,
    action      TEXT NOT NULL,
    resource    TEXT,
    detail      TEXT,
    at          TEXT NOT NULL
);
"""


class PostgresStore(BaseStore):
    """Postgres backend mirroring the SQLite schema column-for-column."""

    def __init__(self, dsn: str | None = None):
        if not _HAS_PSYCOPG:
            raise RuntimeError(
                "PostgresStore requires the 'psycopg' package "
                "(pip install psycopg[binary]). To stay on SQLite, "
                "leave SC_POSTGRES_URL unset."
            )
        dsn = dsn or os.environ.get("SC_POSTGRES_URL", "")
        if not dsn:
            raise RuntimeError("SC_POSTGRES_URL not set and no dsn given")
        self._conn = psycopg.connect(dsn, autocommit=True)
        self._ensure_schema()

    # ---- internal -------------------------------------------------- #

    def _ensure_schema(self) -> None:
        with self._conn.cursor() as cur:
            cur.execute(_SCHEMA)

    # ---- BaseStore ------------------------------------------------- #

    def save(self, scan_dict: dict, *, tenant_id: str = "default") -> int:
        asset = scan_dict.get("asset", {}) or {}
        ps = scan_dict.get("parsed_summary", {}) or {}
        row = (
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
        )
        with self._conn.cursor() as cur:
            cur.execute(
                "INSERT INTO scans (tenant_id, started_at, source, vendor, hostname, ip, site, "
                "health, risk, risk_band, eol_status, cves, findings, summary, payload) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
                row,
            )
            new_id = cur.fetchone()[0]
        return int(new_id)

    def list(self, *, limit: int = 50, source: str | None = None,
             tenant_id: str | None = None) -> list[dict]:
        sql = ("SELECT id, tenant_id, started_at, source, vendor, hostname, ip, site, "
               "health, risk, risk_band, eol_status, cves, findings FROM scans WHERE 1=1")
        params: list = []
        if tenant_id:
            sql += " AND tenant_id = %s"
            params.append(tenant_id)
        if source:
            sql += " AND source = %s"
            params.append(source)
        sql += " ORDER BY id DESC LIMIT %s"
        params.append(limit)
        with self._conn.cursor() as cur:
            cur.execute(sql, params)
            cols = [c[0] for c in cur.description]
            return [dict(zip(cols, r)) for r in cur.fetchall()]

    def get(self, scan_id: int, *, tenant_id: str | None = None) -> dict | None:
        sql = "SELECT payload FROM scans WHERE id = %s"
        params: list = [scan_id]
        if tenant_id:
            sql += " AND tenant_id = %s"
            params.append(tenant_id)
        with self._conn.cursor() as cur:
            cur.execute(sql, params)
            row = cur.fetchone()
        return json.loads(row[0]) if row else None

    def latest_per_host(self, *, tenant_id: str | None = None) -> list[dict]:
        sql = (
            "SELECT s.* FROM scans s "
            "JOIN (SELECT hostname, MAX(id) AS mid FROM scans "
            f"      WHERE 1=1 {'AND tenant_id = %s' if tenant_id else ''} "
            "      GROUP BY hostname) m "
            "ON s.id = m.mid"
        )
        params: list = [tenant_id] if tenant_id else []
        with self._conn.cursor() as cur:
            cur.execute(sql, params)
            cols = [c[0] for c in cur.description]
            rows = [dict(zip(cols, r)) for r in cur.fetchall()]
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
        with self._conn.cursor() as cur:
            cur.execute(
                "INSERT INTO audit_log (tenant_id, actor, action, resource, detail, at) "
                "VALUES (%s, %s, %s, %s, %s, %s)",
                (tenant_id, actor, action, resource, detail,
                 datetime.now(timezone.utc).isoformat()),
            )

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass


__all__ = ["PostgresStore"]
