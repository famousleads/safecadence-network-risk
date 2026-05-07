"""
Per-device asset tagging — stored server-side in SQLite.

Lets users assign:
  - tags: arbitrary labels (prod, dev, crown-jewel, finance-vlan, ...)
  - owner: email/name of person responsible
  - criticality: low | medium | high | crown-jewel
  - notes: free text

Tags persist across scans (keyed by IP+MAC) and feed into the management
report + alerts (so owner of a critical device gets pinged when their
device's risk score changes).
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path


_SCHEMA = """
CREATE TABLE IF NOT EXISTS asset_tags (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip          TEXT NOT NULL,
    mac         TEXT DEFAULT '',
    tags        TEXT DEFAULT '',           -- JSON array
    owner       TEXT DEFAULT '',
    criticality TEXT DEFAULT 'medium',     -- low | medium | high | crown-jewel
    notes       TEXT DEFAULT '',
    updated_at  TEXT DEFAULT (datetime('now'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_asset_ip ON asset_tags(ip);
CREATE INDEX IF NOT EXISTS idx_asset_owner ON asset_tags(owner);
"""


class AssetTagStore:
    def __init__(self, db_path: Path | None = None):
        self.db_path = db_path or (Path.home() / ".safecadence" / "asset_tags.sqlite")
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

    def upsert(self, ip: str, *, mac: str = "", tags: list[str] | None = None,
               owner: str = "", criticality: str = "medium", notes: str = "") -> int:
        tags_json = json.dumps(tags or [])
        with self._conn() as c:
            existing = c.execute(
                "SELECT id FROM asset_tags WHERE ip=?", (ip,)
            ).fetchone()
            if existing:
                c.execute(
                    "UPDATE asset_tags SET mac=?, tags=?, owner=?, criticality=?, notes=?, "
                    "updated_at=datetime('now') WHERE id=?",
                    (mac, tags_json, owner, criticality, notes, existing["id"]),
                )
                return existing["id"]
            else:
                cur = c.execute(
                    "INSERT INTO asset_tags (ip, mac, tags, owner, criticality, notes) "
                    "VALUES (?,?,?,?,?,?)",
                    (ip, mac, tags_json, owner, criticality, notes),
                )
                return cur.lastrowid

    def get(self, ip: str) -> dict | None:
        with self._conn() as c:
            row = c.execute("SELECT * FROM asset_tags WHERE ip=?", (ip,)).fetchone()
        if not row:
            return None
        d = dict(row)
        try:
            d["tags"] = json.loads(d["tags"] or "[]")
        except json.JSONDecodeError:
            d["tags"] = []
        return d

    def list_all(self) -> list[dict]:
        with self._conn() as c:
            rows = c.execute("SELECT * FROM asset_tags ORDER BY ip").fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["tags"] = json.loads(d["tags"] or "[]")
            except json.JSONDecodeError:
                d["tags"] = []
            out.append(d)
        return out

    def list_by_tag(self, tag: str) -> list[dict]:
        all_tags = self.list_all()
        return [t for t in all_tags if tag in t["tags"]]

    def list_by_owner(self, owner: str) -> list[dict]:
        with self._conn() as c:
            rows = c.execute("SELECT * FROM asset_tags WHERE owner=?", (owner,)).fetchall()
        return [dict(r) for r in rows]

    def delete(self, ip: str) -> bool:
        with self._conn() as c:
            c.execute("DELETE FROM asset_tags WHERE ip=?", (ip,))
        return True

    def all_tags(self) -> list[str]:
        """Return a sorted list of every distinct tag in use across all assets."""
        all_tags = self.list_all()
        seen = set()
        for a in all_tags:
            for t in a.get("tags", []):
                seen.add(t)
        return sorted(seen)


_singleton: AssetTagStore | None = None

def get_asset_store() -> AssetTagStore:
    global _singleton
    if _singleton is None:
        _singleton = AssetTagStore()
    return _singleton


def annotate_results(results: list[dict]) -> list[dict]:
    """Merge per-device tags into a discover results list (in-place)."""
    store = get_asset_store()
    all_tags = {t["ip"]: t for t in store.list_all()}
    for d in results:
        ip = d.get("ip")
        if ip and ip in all_tags:
            t = all_tags[ip]
            d["asset_tags"] = t["tags"]
            d["asset_owner"] = t["owner"]
            d["asset_criticality"] = t["criticality"]
            d["asset_notes"] = t["notes"]
            # Boost risk for crown-jewel assets
            if t["criticality"] == "crown-jewel" and d.get("risk_score", 0) > 0:
                d["risk_score"] = min(100, d.get("risk_score", 0) + 15)
    return results
