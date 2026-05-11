"""
Pluggable storage backends.

Three implementations:
  - sqlite_store    : pure stdlib, default (also used for local mode)
  - sql_store       : SQLAlchemy-backed (PostgreSQL or any SQLAlchemy URL)
                      activated when --db-url is provided OR DATABASE_URL env
  - postgres_store  : stdlib + psycopg, activated by SC_POSTGRES_URL (v10.7+)

All implement the same interface: save(scan_dict, *, tenant_id) -> int,
list(...), get(id), latest_per_host(), close().
"""


from __future__ import annotations

import os

from safecadence.storage.base import BaseStore
from safecadence.storage.sqlite_store import SqliteStore

__all__ = ["BaseStore", "SqliteStore", "open_store"]


def open_store(db_url: str | None = None, *, sqlite_path: str | None = None) -> BaseStore:
    """Return the right store for the current env / db_url.

    Resolution order:
      1. ``SC_POSTGRES_URL`` env → :class:`PostgresStore` (stdlib + psycopg).
      2. ``db_url`` starting with ``postgresql://`` or other SQLAlchemy
         schemes → SQLAlchemy-backed :class:`SqlStore`.
      3. Plain ``sqlite:///path`` or ``None`` → :class:`SqliteStore`.
    """
    pg_url = os.environ.get("SC_POSTGRES_URL")
    if pg_url:
        from safecadence.storage.postgres_store import PostgresStore
        return PostgresStore(pg_url)
    if not db_url or (db_url.startswith("sqlite:///") and "+" not in db_url.split("://", 1)[0]):
        # Plain sqlite path — use stdlib backend
        from pathlib import Path as _P
        p = sqlite_path
        if db_url and db_url.startswith("sqlite:///"):
            p = db_url[len("sqlite:///"):]
        return SqliteStore(_P(p) if p else None)
    # SQLAlchemy-backed
    from safecadence.storage.sql_store import SqlStore
    return SqlStore(db_url)
