"""
v14 — AI agent registry.

The first concrete piece of AI Governance. Lets an operator inventory
the AI agents (LangChain agents, Claude Computer Use sessions,
in-house agentic workflows, MCP clients) that act on behalf of users
or autonomously, and tag each agent with:

* Owner (the human accountable for what the agent does)
* Allowed tools (which MCP tools / API endpoints it may call)
* Status (active / paused / deprecated)
* Model + prompt-version fingerprint (so model-drift is visible)

Why a registry instead of "log the calls and reconstruct after":
attribution after the fact is fragile. A registry forces the operator
to declare an agent before it acts, and the v12 MCP server already
emits the agent's identifier in the audit log, so every action ties
back to a declared entry.

The registry is SQLite-backed and uses the same multitenant pattern
as the rest of v12 — every agent row has an ``org_id`` so MSPs can
keep customer agents isolated.

Public API
----------

* ``ensure_agent_schema(conn)``
* ``register_agent(conn, ...)``     → new agent dict
* ``list_agents(conn, org_id=None)``
* ``get_agent(conn, agent_id)``
* ``set_agent_status(conn, agent_id, status)``
* ``record_invocation(conn, agent_id, tool, result_status)``
"""
from __future__ import annotations

import time
import uuid
from typing import Any


VALID_STATUS = ("active", "paused", "deprecated")


_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS ai_agents (
    agent_id        TEXT PRIMARY KEY,
    org_id          TEXT NOT NULL DEFAULT 'local',
    name            TEXT NOT NULL,
    owner_user_id   TEXT NOT NULL,
    model           TEXT NOT NULL DEFAULT '',
    prompt_version  TEXT NOT NULL DEFAULT '',
    allowed_tools   TEXT NOT NULL DEFAULT '[]',
    status          TEXT NOT NULL DEFAULT 'active',
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ai_agents_org ON ai_agents(org_id);

CREATE TABLE IF NOT EXISTS ai_agent_invocations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id        TEXT NOT NULL,
    tool            TEXT NOT NULL,
    result_status   TEXT NOT NULL,
    at              INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ai_inv_agent ON ai_agent_invocations(agent_id);
"""


def ensure_agent_schema(conn: Any) -> None:
    cur = conn.cursor()
    for stmt in _SCHEMA_SQL.split(";"):
        s = stmt.strip()
        if s:
            cur.execute(s)
    conn.commit()


def register_agent(
    conn: Any,
    *,
    name: str,
    owner_user_id: str,
    org_id: str = "local",
    model: str = "",
    prompt_version: str = "",
    allowed_tools: list[str] | None = None,
    agent_id: str | None = None,
) -> dict:
    """Create + return a new agent row."""
    import json
    aid = agent_id or f"agt_{uuid.uuid4().hex[:12]}"
    now = int(time.time())
    tools_json = json.dumps(allowed_tools or [])
    conn.execute(
        "INSERT INTO ai_agents (agent_id, org_id, name, owner_user_id, "
        "model, prompt_version, allowed_tools, status, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)",
        (aid, org_id, name, owner_user_id, model, prompt_version,
         tools_json, now, now),
    )
    conn.commit()
    return get_agent(conn, aid)


def get_agent(conn: Any, agent_id: str) -> dict | None:
    import json
    row = conn.execute(
        "SELECT agent_id, org_id, name, owner_user_id, model, prompt_version, "
        "allowed_tools, status, created_at, updated_at "
        "FROM ai_agents WHERE agent_id = ?",
        (agent_id,),
    ).fetchone()
    if row is None:
        return None
    return {
        "agent_id": row[0], "org_id": row[1], "name": row[2],
        "owner_user_id": row[3], "model": row[4],
        "prompt_version": row[5],
        "allowed_tools": json.loads(row[6] or "[]"),
        "status": row[7],
        "created_at": row[8], "updated_at": row[9],
    }


def list_agents(conn: Any, org_id: str | None = None) -> list[dict]:
    import json
    sql = (
        "SELECT agent_id, org_id, name, owner_user_id, model, prompt_version, "
        "allowed_tools, status, created_at, updated_at FROM ai_agents"
    )
    params: tuple = ()
    if org_id is not None:
        sql += " WHERE org_id = ?"
        params = (org_id,)
    sql += " ORDER BY name COLLATE NOCASE"
    rows = conn.execute(sql, params).fetchall()
    out: list[dict] = []
    for r in rows:
        out.append({
            "agent_id": r[0], "org_id": r[1], "name": r[2],
            "owner_user_id": r[3], "model": r[4],
            "prompt_version": r[5],
            "allowed_tools": json.loads(r[6] or "[]"),
            "status": r[7],
            "created_at": r[8], "updated_at": r[9],
        })
    return out


def set_agent_status(conn: Any, agent_id: str, status: str) -> bool:
    if status not in VALID_STATUS:
        raise ValueError(f"Unknown status: {status!r}")
    cur = conn.execute(
        "UPDATE ai_agents SET status = ?, updated_at = ? WHERE agent_id = ?",
        (status, int(time.time()), agent_id),
    )
    conn.commit()
    return cur.rowcount > 0


def record_invocation(
    conn: Any, agent_id: str, tool: str, result_status: str = "ok",
) -> None:
    """Log an agent's tool call. Used for cross-tool attribution."""
    conn.execute(
        "INSERT INTO ai_agent_invocations (agent_id, tool, result_status, at) "
        "VALUES (?, ?, ?, ?)",
        (agent_id, tool, result_status, int(time.time())),
    )
    conn.commit()


__all__ = [
    "VALID_STATUS", "ensure_agent_schema", "register_agent",
    "list_agents", "get_agent", "set_agent_status", "record_invocation",
]
