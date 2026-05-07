"""
Server-side persistence for discovery runs.

Stores complete discover payloads in SQLite so the user can:
  - reload past scans across server restarts
  - compare today's scan to last week's
  - keep an auditable history of every fleet snapshot

Lives in ~/.safecadence/discover.sqlite — separate from the main scans DB
so it doesn't pollute the audit trail.
"""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any


_SCHEMA = """
CREATE TABLE IF NOT EXISTS discover_runs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    cidr          TEXT NOT NULL,
    mode          TEXT NOT NULL,
    label         TEXT DEFAULT '',
    host_count    INTEGER DEFAULT 0,
    risk_critical INTEGER DEFAULT 0,
    risk_high     INTEGER DEFAULT 0,
    cve_count     INTEGER DEFAULT 0,
    kev_count     INTEGER DEFAULT 0,
    duration_ms   INTEGER DEFAULT 0,
    created_at    TEXT DEFAULT (datetime('now')),
    payload       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_discover_cidr ON discover_runs(cidr, created_at DESC);
"""


class DiscoverStore:
    def __init__(self, db_path: Path | None = None):
        self.db_path = db_path or (Path.home() / ".safecadence" / "discover.sqlite")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
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

    # ---------------------------------------------------------------- write
    def save_run(self, payload: dict, *, label: str = "") -> int:
        """Save a complete discover payload. Returns the new run's id."""
        summary = payload.get("summary", {})
        bands = summary.get("by_risk_band", {})
        cves = summary.get("cves", {})
        with self._conn() as c:
            cur = c.execute(
                """
                INSERT INTO discover_runs (
                    cidr, mode, label, host_count,
                    risk_critical, risk_high, cve_count, kev_count, duration_ms,
                    payload
                ) VALUES (?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    payload.get("cidr", ""),
                    payload.get("mode", ""),
                    label,
                    payload.get("count", 0),
                    bands.get("critical", 0),
                    bands.get("high", 0),
                    cves.get("total_cves", 0),
                    cves.get("kev_cves", 0),
                    payload.get("duration_ms", 0),
                    json.dumps(payload, default=str),
                ),
            )
            return cur.lastrowid

    # ---------------------------------------------------------------- read
    def list_runs(self, *, limit: int = 50, cidr: str | None = None) -> list[dict]:
        """List recent runs (without payload — small response)."""
        with self._conn() as c:
            if cidr:
                rows = c.execute(
                    "SELECT id, cidr, mode, label, host_count, risk_critical, risk_high, "
                    "cve_count, kev_count, duration_ms, created_at "
                    "FROM discover_runs WHERE cidr=? ORDER BY created_at DESC LIMIT ?",
                    (cidr, limit),
                ).fetchall()
            else:
                rows = c.execute(
                    "SELECT id, cidr, mode, label, host_count, risk_critical, risk_high, "
                    "cve_count, kev_count, duration_ms, created_at "
                    "FROM discover_runs ORDER BY created_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            return [dict(r) for r in rows]

    def get_run(self, run_id: int) -> dict | None:
        """Get a single run including the full payload."""
        with self._conn() as c:
            row = c.execute(
                "SELECT * FROM discover_runs WHERE id=?", (run_id,)
            ).fetchone()
        if not row:
            return None
        d = dict(row)
        try:
            d["payload"] = json.loads(d["payload"])
        except Exception:
            d["payload"] = {}
        return d

    def list_subnets(self) -> list[dict]:
        """List all distinct subnets ever scanned, with most-recent run summary."""
        with self._conn() as c:
            rows = c.execute(
                """
                SELECT cidr,
                       COUNT(*) as run_count,
                       MAX(created_at) as last_scan,
                       SUM(host_count) as total_hosts_seen
                FROM discover_runs
                GROUP BY cidr
                ORDER BY last_scan DESC
                """
            ).fetchall()
            return [dict(r) for r in rows]

    def diff_runs(self, old_id: int, new_id: int) -> dict:
        """Compute a diff between two discovery runs of the same subnet."""
        old_run = self.get_run(old_id)
        new_run = self.get_run(new_id)
        if not old_run or not new_run:
            return {"error": "one or both runs not found"}

        old_results = (old_run.get("payload") or {}).get("results", [])
        new_results = (new_run.get("payload") or {}).get("results", [])

        old_by_ip = {r.get("ip"): r for r in old_results if r.get("ip")}
        new_by_ip = {r.get("ip"): r for r in new_results if r.get("ip")}

        added = [new_by_ip[ip] for ip in new_by_ip if ip not in old_by_ip]
        removed = [old_by_ip[ip] for ip in old_by_ip if ip not in new_by_ip]
        changed = []
        for ip in new_by_ip:
            if ip in old_by_ip:
                old_r = old_by_ip[ip]
                new_r = new_by_ip[ip]
                changes = []
                if (old_r.get("open_ports") or []) != (new_r.get("open_ports") or []):
                    changes.append({
                        "field": "open_ports",
                        "old": old_r.get("open_ports"),
                        "new": new_r.get("open_ports"),
                    })
                if old_r.get("risk_score", 0) != new_r.get("risk_score", 0):
                    changes.append({
                        "field": "risk_score",
                        "old": old_r.get("risk_score", 0),
                        "new": new_r.get("risk_score", 0),
                    })
                old_cve_ids = {c.get("cve_id") for c in (old_r.get("cves") or [])}
                new_cve_ids = {c.get("cve_id") for c in (new_r.get("cves") or [])}
                if old_cve_ids != new_cve_ids:
                    changes.append({
                        "field": "cves",
                        "added": sorted(new_cve_ids - old_cve_ids),
                        "removed": sorted(old_cve_ids - new_cve_ids),
                    })
                if changes:
                    changed.append({"ip": ip, "hostname": new_r.get("hostname"), "changes": changes})

        return {
            "old_run_id": old_id,
            "new_run_id": new_id,
            "old_at": old_run.get("created_at"),
            "new_at": new_run.get("created_at"),
            "added": added,
            "removed": removed,
            "changed": changed,
            "summary": {
                "added_count": len(added),
                "removed_count": len(removed),
                "changed_count": len(changed),
            },
        }

    def delete_run(self, run_id: int) -> bool:
        with self._conn() as c:
            c.execute("DELETE FROM discover_runs WHERE id=?", (run_id,))
        return True


_singleton: DiscoverStore | None = None

def get_discover_store() -> DiscoverStore:
    global _singleton
    if _singleton is None:
        _singleton = DiscoverStore()
    return _singleton
