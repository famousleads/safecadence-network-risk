"""
Pluggable storage backends.

Two implementations:
  - sqlite_store : pure stdlib, default (also used for local mode)
  - sql_store    : SQLAlchemy-backed (PostgreSQL or any SQLAlchemy URL)
                   activated when --db-url is provided OR DATABASE_URL env

Both implement the same interface: save(scan_dict, *, tenant_id) -> int,
list(...), get(id), close().
"""


from __future__ import annotations

from safecadence.storage.base import BaseStore
from safecadence.storage.sqlite_store import SqliteStore

__all__ = ["BaseStore", "SqliteStore", "open_store"]


def open_store(db_url: str | None = None, *, sqlite_path: str | None = None) -> BaseStore:
    """Return the right store for the given DB URL.

    - None / sqlite:// path → SqliteStore (no extra deps)
    - postgresql://… or sqlite+sqlalchemy → SqlStore (requires [server] extras)
    """
    if not db_url or db_url.startswith("sqlite:///") and "+" not in db_url.split("://", 1)[0]:
        # Plain sqlite path — use stdlib backend
        from pathlib import Path as _P
        p = sqlite_path
        if db_url and db_url.startswith("sqlite:///"):
            p = db_url[len("sqlite:///"):]
        return SqliteStore(_P(p) if p else None)
    # SQLAlchemy-backed
    from safecadence.storage.sql_store import SqlStore
    return SqlStore(db_url)
