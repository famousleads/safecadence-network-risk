"""
v12.0 — Multi-tenant org scaffold.

Best-judgement default for SafeCadence's MSP use case (one platform
operator, many customer "orgs"). Ships opt-in: v11.x single-tenant
behavior is preserved when no org id is supplied.

Design choices made on the user's behalf
----------------------------------------

1. **Org as a first-class row, not a column prefix.** A single `orgs`
   table holds metadata (display name, plan tier, created-at, soft-delete
   flag). Other tables that need org scope grow a nullable `org_id`
   foreign key. Nullable = "global / single-tenant install" so existing
   data keeps working.

2. **Membership table, not user.org_id.** A `org_users` table maps users
   to orgs with a role (`owner` | `admin` | `member` | `viewer`). One
   user can belong to several orgs — this matches the MSP analyst who
   logs in once and sees several customers.

3. **No row-level security at the DB layer.** SQLite doesn't have it and
   forcing PostgreSQL would defeat the local-first promise. Instead, every
   query helper that lives above this module passes the active `org_id`
   through and the helper appends `WHERE org_id = ?`. The
   `with_org_filter()` helper formalizes that pattern.

4. **System org for built-ins.** The seed migration inserts one row with
   `id = "system"`, used for global controls, prompt templates, etc. that
   ship with the product and shouldn't be deletable.

5. **No org switching in the URL.** Active org lives in the session
   cookie. Switching is a POST that updates the session, not a URL param.
   Keeps share-links / report URLs free of `?org=` clutter.

Public API
----------

* ``ensure_org_schema(conn)``     — idempotent CREATE TABLE.
* ``create_org(conn, ...)``       — new org + adds creator as owner.
* ``list_orgs_for_user(conn, u)`` — orgs the user belongs to.
* ``get_user_role(conn, u, o)``   — role or None.
* ``with_org_filter(sql, org_id)``— appends `AND org_id = ?` safely.
* ``SYSTEM_ORG_ID``               — module-level constant.

Migrations
----------

Run ``ensure_org_schema(conn)`` once at startup; it's safe to call on
every boot. We don't pull in an Alembic-style migration runner because
the rest of the v11.x storage uses the same hand-rolled
``CREATE TABLE IF NOT EXISTS`` pattern.
"""
from __future__ import annotations

import time
import uuid
from typing import Any


SYSTEM_ORG_ID = "system"


# --------------------------------------------------------------------------
# Schema
# --------------------------------------------------------------------------


_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS orgs (
    id              TEXT PRIMARY KEY,
    display_name    TEXT NOT NULL,
    plan_tier       TEXT NOT NULL DEFAULT 'free',
    created_at      INTEGER NOT NULL,
    is_deleted      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS org_users (
    org_id          TEXT NOT NULL,
    user_id         TEXT NOT NULL,
    role            TEXT NOT NULL DEFAULT 'member',
    added_at        INTEGER NOT NULL,
    PRIMARY KEY (org_id, user_id),
    FOREIGN KEY (org_id) REFERENCES orgs(id)
);

CREATE INDEX IF NOT EXISTS idx_org_users_user ON org_users(user_id);
"""


def ensure_org_schema(conn: Any) -> None:
    """Idempotent schema bootstrap. Also seeds the `system` org."""
    cur = conn.cursor()
    for stmt in _SCHEMA_SQL.split(";"):
        s = stmt.strip()
        if s:
            cur.execute(s)
    # Seed the system org once.
    cur.execute(
        "INSERT OR IGNORE INTO orgs (id, display_name, plan_tier, created_at) "
        "VALUES (?, ?, ?, ?)",
        (SYSTEM_ORG_ID, "System (built-ins)", "system", int(time.time())),
    )
    conn.commit()


# --------------------------------------------------------------------------
# Org CRUD
# --------------------------------------------------------------------------


def create_org(
    conn: Any,
    *,
    display_name: str,
    creator_user_id: str,
    plan_tier: str = "free",
    org_id: str | None = None,
) -> dict:
    """Create a new org and add the creator as owner. Returns the row dict."""
    oid = org_id or f"org_{uuid.uuid4().hex[:12]}"
    now = int(time.time())
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO orgs (id, display_name, plan_tier, created_at) "
        "VALUES (?, ?, ?, ?)",
        (oid, display_name, plan_tier, now),
    )
    cur.execute(
        "INSERT INTO org_users (org_id, user_id, role, added_at) "
        "VALUES (?, ?, 'owner', ?)",
        (oid, creator_user_id, now),
    )
    conn.commit()
    return {
        "id": oid,
        "display_name": display_name,
        "plan_tier": plan_tier,
        "created_at": now,
        "is_deleted": 0,
    }


def list_orgs_for_user(conn: Any, user_id: str) -> list[dict]:
    """Return non-deleted orgs the user belongs to, with role attached."""
    cur = conn.cursor()
    rows = cur.execute(
        """
        SELECT o.id, o.display_name, o.plan_tier, o.created_at, u.role
          FROM orgs o
          JOIN org_users u ON u.org_id = o.id
         WHERE u.user_id = ? AND o.is_deleted = 0
         ORDER BY o.display_name COLLATE NOCASE
        """,
        (user_id,),
    ).fetchall()
    return [
        {
            "id": r[0],
            "display_name": r[1],
            "plan_tier": r[2],
            "created_at": r[3],
            "role": r[4],
        }
        for r in rows
    ]


def get_user_role(conn: Any, user_id: str, org_id: str) -> str | None:
    """Return the user's role in the org, or None if they're not a member."""
    cur = conn.cursor()
    row = cur.execute(
        "SELECT role FROM org_users WHERE user_id = ? AND org_id = ?",
        (user_id, org_id),
    ).fetchone()
    return row[0] if row else None


# --------------------------------------------------------------------------
# Helper used by callers to add the WHERE clause uniformly
# --------------------------------------------------------------------------


def with_org_filter(sql: str, org_id: str | None) -> tuple[str, tuple]:
    """Append an org filter to a SELECT. Pass the result straight to execute().

    >>> sql, params = with_org_filter("SELECT id FROM findings", "org_abc")
    >>> sql
    'SELECT id FROM findings WHERE org_id = ?'
    >>> params
    ('org_abc',)

    If `org_id` is None, returns the SQL unchanged with empty params —
    this is the single-tenant code path.
    """
    if org_id is None:
        return sql, ()
    glue = " AND " if " WHERE " in sql.upper() else " WHERE "
    return f"{sql}{glue}org_id = ?", (org_id,)


__all__ = [
    "SYSTEM_ORG_ID",
    "ensure_org_schema",
    "create_org",
    "list_orgs_for_user",
    "get_user_role",
    "with_org_filter",
]
