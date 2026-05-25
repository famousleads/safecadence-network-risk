"""
v14 — API key inventory.

Tracks API keys across the customer's environment without ever
holding the secret material. Each row stores:

* A handle (provider + label + last-four for visual identification)
* Who owns it (owner_user_id + nullable agent_id)
* What scopes it has (free-form list — provider-specific)
* When it was created / last rotated
* When it was last seen used (updated via record_seen)

The trust scoring module reads from this table to compute per-key
trust scores; the v12 MCP server can record_seen() on every call
that uses a key so age + last-use stay current.

Public API
----------

* ``ensure_api_key_schema(conn)``
* ``register_api_key(conn, ...)``
* ``list_api_keys(conn, org_id=None)``
* ``record_seen(conn, key_id)``
* ``rotate(conn, key_id, new_last_four)``
* ``deprecate(conn, key_id)``
* ``age_days(key)``  — pure helper
"""
from __future__ import annotations

import time
import uuid
from typing import Any


_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS ai_api_keys (
    key_id           TEXT PRIMARY KEY,
    org_id           TEXT NOT NULL DEFAULT 'local',
    provider         TEXT NOT NULL,
    label            TEXT NOT NULL,
    last_four        TEXT NOT NULL DEFAULT '',
    owner_user_id    TEXT NOT NULL,
    agent_id         TEXT,
    scopes           TEXT NOT NULL DEFAULT '[]',
    created_at       INTEGER NOT NULL,
    rotated_at       INTEGER,
    last_seen_at     INTEGER,
    is_deprecated    INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_api_keys_org      ON ai_api_keys(org_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_provider ON ai_api_keys(provider);
"""


def ensure_api_key_schema(conn: Any) -> None:
    cur = conn.cursor()
    for stmt in _SCHEMA_SQL.split(";"):
        s = stmt.strip()
        if s:
            cur.execute(s)
    conn.commit()


def register_api_key(
    conn: Any,
    *,
    provider: str,
    label: str,
    owner_user_id: str,
    org_id: str = "local",
    last_four: str = "",
    agent_id: str | None = None,
    scopes: list[str] | None = None,
    key_id: str | None = None,
) -> dict:
    """Insert a new key row. NEVER pass the secret — only the last four."""
    import json
    kid = key_id or f"key_{uuid.uuid4().hex[:12]}"
    now = int(time.time())
    conn.execute(
        "INSERT INTO ai_api_keys (key_id, org_id, provider, label, last_four, "
        "owner_user_id, agent_id, scopes, created_at, rotated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (kid, org_id, provider, label, (last_four or "")[-4:],
         owner_user_id, agent_id, json.dumps(scopes or []), now, now),
    )
    conn.commit()
    return _get_one(conn, kid)


def _get_one(conn: Any, key_id: str) -> dict | None:
    import json
    row = conn.execute(
        "SELECT key_id, org_id, provider, label, last_four, owner_user_id, "
        "agent_id, scopes, created_at, rotated_at, last_seen_at, is_deprecated "
        "FROM ai_api_keys WHERE key_id = ?",
        (key_id,),
    ).fetchone()
    if row is None:
        return None
    return {
        "key_id": row[0], "org_id": row[1], "provider": row[2],
        "label": row[3], "last_four": row[4], "owner_user_id": row[5],
        "agent_id": row[6], "scopes": json.loads(row[7] or "[]"),
        "created_at": row[8], "rotated_at": row[9],
        "last_seen_at": row[10],
        "is_deprecated": bool(row[11]),
    }


def list_api_keys(
    conn: Any,
    org_id: str | None = None,
    *,
    include_deprecated: bool = False,
) -> list[dict]:
    import json
    sql = (
        "SELECT key_id, org_id, provider, label, last_four, owner_user_id, "
        "agent_id, scopes, created_at, rotated_at, last_seen_at, is_deprecated "
        "FROM ai_api_keys WHERE 1=1"
    )
    params: list = []
    if org_id is not None:
        sql += " AND org_id = ?"
        params.append(org_id)
    if not include_deprecated:
        sql += " AND is_deprecated = 0"
    sql += " ORDER BY provider, label COLLATE NOCASE"
    rows = conn.execute(sql, params).fetchall()
    out: list[dict] = []
    for r in rows:
        out.append({
            "key_id": r[0], "org_id": r[1], "provider": r[2],
            "label": r[3], "last_four": r[4], "owner_user_id": r[5],
            "agent_id": r[6], "scopes": json.loads(r[7] or "[]"),
            "created_at": r[8], "rotated_at": r[9],
            "last_seen_at": r[10],
            "is_deprecated": bool(r[11]),
        })
    return out


def record_seen(conn: Any, key_id: str) -> bool:
    cur = conn.execute(
        "UPDATE ai_api_keys SET last_seen_at = ? WHERE key_id = ?",
        (int(time.time()), key_id),
    )
    conn.commit()
    return cur.rowcount > 0


def rotate(conn: Any, key_id: str, new_last_four: str) -> bool:
    cur = conn.execute(
        "UPDATE ai_api_keys SET last_four = ?, rotated_at = ? WHERE key_id = ?",
        ((new_last_four or "")[-4:], int(time.time()), key_id),
    )
    conn.commit()
    return cur.rowcount > 0


def deprecate(conn: Any, key_id: str) -> bool:
    cur = conn.execute(
        "UPDATE ai_api_keys SET is_deprecated = 1 WHERE key_id = ?",
        (key_id,),
    )
    conn.commit()
    return cur.rowcount > 0


def age_days(key: dict, *, now_ts: int | None = None) -> int:
    """Pure helper: age in days since creation (or rotation if rotated)."""
    if not key:
        return 0
    started = key.get("rotated_at") or key.get("created_at") or 0
    now = now_ts if now_ts is not None else int(time.time())
    if started <= 0:
        return 0
    return max(0, (now - int(started)) // 86_400)


__all__ = [
    "ensure_api_key_schema", "register_api_key",
    "list_api_keys", "record_seen", "rotate", "deprecate", "age_days",
]
