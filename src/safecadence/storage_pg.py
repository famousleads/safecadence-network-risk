"""Postgres-first storage adapter (v7.1).

Mirrors the file-backed JSON store API for the four big object families:
  - assets         (platform_assets table)
  - policies       (policies table)
  - jobs           (command_jobs table)
  - executions     (command_executions table)
  - audit          (command_audit table)

Opt-in via ``DATABASE_URL`` environment variable (e.g. ``postgresql://
user:pass@host/db``). When DATABASE_URL is unset the rest of the
platform falls back to the existing file-backed JSON path — this
adapter is purely additive.

Why file-JSON stays the default:
  * Air-gapped customers can't always run Postgres.
  * Single-node deployments have no benefit from a network DB.
  * Test isolation is trivial with a tmp_path; Postgres tests need
    a server.

When you DO need Postgres:
  * Multi-instance HA where every API node sees the same data.
  * Large fleets (10k+ assets) where JSON-glob scans get slow.
  * Compliance shops that demand transactional ACID guarantees.

This module is intentionally small: SQLAlchemy Core + JSON columns
for the dataclass payloads. We don't try to model every dataclass
field as a column — the JSON column gives us forward-compat with
schema evolution. Three indexed columns per table (id, tenant,
updated_at) cover all current query patterns.
"""

from __future__ import annotations

import json
import os
from typing import Any, Iterable

try:
    from sqlalchemy import (
        JSON, Column, DateTime, MetaData, String, Table, create_engine,
        delete, select, update, func,
    )
    from sqlalchemy.exc import SQLAlchemyError
    _SA_AVAILABLE = True
except ImportError:                              # pragma: no cover
    _SA_AVAILABLE = False


_engine = None
_meta: Any = None


def _ensure() -> Any:
    """Lazy-init the engine + metadata. Returns the engine, or None if
    DATABASE_URL is unset. Raises if SQLAlchemy isn't installed."""
    global _engine, _meta
    if _engine is not None:
        return _engine
    url = os.environ.get("DATABASE_URL")
    if not url:
        return None
    if not _SA_AVAILABLE:
        raise RuntimeError(
            "DATABASE_URL is set but SQLAlchemy is not installed. "
            "Run `pip install 'safecadence-netrisk[server]'` to enable "
            "the Postgres backend."
        )
    _engine = create_engine(url, pool_pre_ping=True, future=True)
    _meta = MetaData()

    Table(
        "sc_assets", _meta,
        Column("asset_id", String(256), primary_key=True),
        Column("tenant", String(64), nullable=False, index=True),
        Column("payload", JSON, nullable=False),
        Column("updated_at", DateTime(timezone=True),
                server_default=func.now(), onupdate=func.now()),
    )
    Table(
        "sc_policies", _meta,
        Column("policy_id", String(128), primary_key=True),
        Column("tenant", String(64), nullable=False, index=True),
        Column("payload", JSON, nullable=False),
        Column("updated_at", DateTime(timezone=True),
                server_default=func.now(), onupdate=func.now()),
    )
    Table(
        "sc_jobs", _meta,
        Column("job_id", String(64), primary_key=True),
        Column("tenant", String(64), nullable=False, index=True),
        Column("status", String(32), nullable=False, index=True),
        Column("payload", JSON, nullable=False),
        Column("updated_at", DateTime(timezone=True),
                server_default=func.now(), onupdate=func.now()),
    )
    Table(
        "sc_executions", _meta,
        Column("execution_id", String(64), primary_key=True),
        Column("job_id", String(64), nullable=False, index=True),
        Column("payload", JSON, nullable=False),
        Column("updated_at", DateTime(timezone=True),
                server_default=func.now(), onupdate=func.now()),
    )
    Table(
        "sc_audit", _meta,
        Column("audit_id", String(64), primary_key=True),
        Column("tenant", String(64), nullable=False, index=True),
        Column("job_id", String(64), index=True),
        Column("action", String(64), nullable=False, index=True),
        Column("payload", JSON, nullable=False),
        Column("created_at", DateTime(timezone=True),
                server_default=func.now()),
    )
    # v9.39 — identity vault rows. Encrypted credential blob lives in
    # `payload.encrypted_blob` (Fernet ciphertext, base64 string). Plain
    # metadata in indexed columns so the connector status strip can
    # render `last_synced_at` without decrypting. One row per (tenant,
    # system) — upsert semantics.
    Table(
        "sc_identity_vault", _meta,
        Column("system", String(32), primary_key=True),
        Column("tenant", String(64), primary_key=True, default="local"),
        Column("target", String(256), nullable=False),
        Column("payload", JSON, nullable=False),
        Column("updated_at", DateTime(timezone=True),
                server_default=func.now(), onupdate=func.now()),
    )
    _meta.create_all(_engine)
    return _engine


def is_enabled() -> bool:
    """True if DATABASE_URL is set and SQLAlchemy is importable."""
    return _SA_AVAILABLE and bool(os.environ.get("DATABASE_URL"))


# --------------------------------------------------------------------------
# Generic upsert / fetch / list helpers
# --------------------------------------------------------------------------

def _upsert(table_name: str, pk_col: str, key: str,
             row: dict[str, Any]) -> None:
    eng = _ensure()
    if not eng:
        return
    table = _meta.tables[table_name]
    with eng.begin() as conn:
        # Try update first; if zero rows, insert. Avoids requiring
        # dialect-specific ON CONFLICT for the lowest-common-denominator path.
        upd = update(table).where(getattr(table.c, pk_col) == key).values(**row)
        result = conn.execute(upd)
        if result.rowcount == 0:
            conn.execute(table.insert().values(**{pk_col: key, **row}))


def _get(table_name: str, pk_col: str, key: str) -> dict | None:
    eng = _ensure()
    if not eng:
        return None
    table = _meta.tables[table_name]
    with eng.connect() as conn:
        row = conn.execute(
            select(table.c.payload).where(getattr(table.c, pk_col) == key)
        ).fetchone()
    if not row:
        return None
    payload = row[0]
    return payload if isinstance(payload, dict) else json.loads(payload)


def _list(table_name: str, *, where: dict[str, Any] | None = None,
           limit: int | None = None) -> list[dict]:
    eng = _ensure()
    if not eng:
        return []
    table = _meta.tables[table_name]
    stmt = select(table.c.payload)
    for k, v in (where or {}).items():
        if v is not None and hasattr(table.c, k):
            stmt = stmt.where(getattr(table.c, k) == v)
    if limit:
        stmt = stmt.limit(limit)
    with eng.connect() as conn:
        rows = conn.execute(stmt).fetchall()
    out = []
    for r in rows:
        p = r[0]
        out.append(p if isinstance(p, dict) else json.loads(p))
    return out


def _delete(table_name: str, pk_col: str, key: str) -> bool:
    eng = _ensure()
    if not eng:
        return False
    table = _meta.tables[table_name]
    with eng.begin() as conn:
        r = conn.execute(delete(table).where(getattr(table.c, pk_col) == key))
    return r.rowcount > 0


# --------------------------------------------------------------------------
# Public asset API — same shape as platform_api.list_assets etc.
# --------------------------------------------------------------------------

def save_asset(asset: dict, *, tenant: str = "local") -> str:
    aid = (asset.get("identity") or {}).get("asset_id")
    if not aid:
        raise ValueError("asset has no asset_id")
    _upsert("sc_assets", "asset_id", aid,
             {"tenant": tenant, "payload": asset})
    return aid


def get_asset(asset_id: str) -> dict | None:
    return _get("sc_assets", "asset_id", asset_id)


def list_assets(*, tenant: str | None = None) -> list[dict]:
    return _list("sc_assets", where={"tenant": tenant})


def delete_asset(asset_id: str) -> bool:
    return _delete("sc_assets", "asset_id", asset_id)


# --------------------------------------------------------------------------
# Policy / job / execution / audit shortcuts
# --------------------------------------------------------------------------

def save_policy(policy_id: str, payload: dict, *, tenant: str = "local") -> None:
    _upsert("sc_policies", "policy_id", policy_id,
             {"tenant": tenant, "payload": payload})


def get_policy(policy_id: str) -> dict | None:
    return _get("sc_policies", "policy_id", policy_id)


def list_policies(*, tenant: str | None = None) -> list[dict]:
    return _list("sc_policies", where={"tenant": tenant})


def save_job(job_id: str, payload: dict, *, tenant: str = "local",
             status: str = "draft") -> None:
    _upsert("sc_jobs", "job_id", job_id,
             {"tenant": tenant, "status": status, "payload": payload})


def get_job(job_id: str) -> dict | None:
    return _get("sc_jobs", "job_id", job_id)


def list_jobs(*, tenant: str | None = None,
              status: str | None = None) -> list[dict]:
    return _list("sc_jobs", where={"tenant": tenant, "status": status})


def save_execution(execution_id: str, job_id: str, payload: dict) -> None:
    _upsert("sc_executions", "execution_id", execution_id,
             {"job_id": job_id, "payload": payload})


def get_execution(execution_id: str) -> dict | None:
    return _get("sc_executions", "execution_id", execution_id)


def list_executions(*, job_id: str | None = None) -> list[dict]:
    return _list("sc_executions", where={"job_id": job_id})


def write_audit(audit_id: str, payload: dict, *,
                 tenant: str = "local", job_id: str = "",
                 action: str = "") -> None:
    eng = _ensure()
    if not eng:
        return
    table = _meta.tables["sc_audit"]
    with eng.begin() as conn:
        conn.execute(table.insert().values(
            audit_id=audit_id, tenant=tenant, job_id=job_id,
            action=action, payload=payload,
        ))


def read_audit(*, tenant: str | None = None, job_id: str | None = None,
                limit: int = 200) -> list[dict]:
    return _list("sc_audit",
                   where={"tenant": tenant, "job_id": job_id},
                   limit=limit)
