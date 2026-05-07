"""
Local SQLite store — opt-in scan history.

Used when the user passes --save-history. Lives at:
  $XDG_DATA_HOME/safecadence/history.db   (Linux)
  ~/Library/Application Support/safecadence/history.db   (macOS)
  %APPDATA%\\safecadence\\history.db   (Windows)
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

from safecadence.core.schema import ScanResult


def _data_dir() -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming")))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local" / "share")))
    return base / "safecadence"


SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at  TEXT NOT NULL,
    source      TEXT NOT NULL,
    vendor      TEXT NOT NULL,
    hostname    TEXT,
    health      INTEGER,
    risk        INTEGER,
    summary     TEXT,
    findings    INTEGER,
    payload     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_source  ON scans(source);
CREATE INDEX IF NOT EXISTS idx_scans_vendor  ON scans(vendor);
CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at);
"""


class HistoryStore:
    def __init__(self, db_path: Path | None = None):
        self.path = Path(db_path) if db_path else (_data_dir() / "history.db")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path))
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def save(self, result: ScanResult) -> int:
        cur = self._conn.execute(
            "INSERT INTO scans (started_at, source, vendor, hostname, health, risk, summary, findings, payload) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                result.started_at,
                result.source,
                result.vendor,
                result.parsed.hostname,
                result.health_score,
                result.risk_score,
                result.summary,
                len(result.findings),
                json.dumps(result.to_dict()),
            ),
        )
        self._conn.commit()
        return int(cur.lastrowid or 0)

    def list(self, *, limit: int = 50, source: str | None = None) -> list[dict]:
        sql = "SELECT id, started_at, source, vendor, hostname, health, risk, findings FROM scans"
        params: list = []
        if source:
            sql += " WHERE source = ?"
            params.append(source)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        rows = self._conn.execute(sql, params).fetchall()
        return [
            dict(zip(("id", "started_at", "source", "vendor", "hostname", "health", "risk", "findings"), r))
            for r in rows
        ]

    def get(self, scan_id: int) -> dict | None:
        row = self._conn.execute("SELECT payload FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def close(self) -> None:
        self._conn.close()
