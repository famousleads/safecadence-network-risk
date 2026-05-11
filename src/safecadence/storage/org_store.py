"""
Per-org (tenant) data isolation primitives.

v10.5 takes the first concrete step toward a multi-tenant deployment:
each org gets its own subdirectory under ``~/.safecadence/orgs/<org_id>/``
where its scan history, audit log, RBAC member list, and report
templates live. Operations that previously read from the global
``~/.safecadence/`` directly continue to work — passing ``org_id=None``
means "global / legacy / single-tenant" everywhere downstream.

What this module owns
---------------------
* Org dataclass.
* CRUD over the org list, persisted to ``~/.safecadence/orgs.json``.
* The well-known data dir for an org.

What it deliberately does NOT do
--------------------------------
* It does not enforce membership — that's RBAC (:mod:`safecadence.auth.rbac`).
* It does not move existing global data into per-org dirs — backwards
  compatibility is the goal; migration of single-tenant installs is a
  v10.6+ problem.
"""

from __future__ import annotations

import dataclasses
import json
import os
import secrets
import time
from pathlib import Path


@dataclasses.dataclass
class Org:
    id: str
    name: str
    created_at: int
    owner_email: str

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Org":
        return cls(
            id=str(d.get("id") or ""),
            name=str(d.get("name") or ""),
            created_at=int(d.get("created_at") or 0),
            owner_email=str(d.get("owner_email") or ""),
        )


# --------------------------------------------------------------------------
# Storage helpers
# --------------------------------------------------------------------------


def _root() -> Path:
    root = os.environ.get("SAFECADENCE_HOME") or os.environ.get("SC_AUTH_HOME")
    base = Path(root) if root else Path.home() / ".safecadence"
    base.mkdir(parents=True, exist_ok=True)
    return base


def _orgs_index_path() -> Path:
    return _root() / "orgs.json"


def _read_index() -> list[dict]:
    path = _orgs_index_path()
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    if isinstance(data, list):
        return [d for d in data if isinstance(d, dict)]
    return []


def _write_index(rows: list[dict]) -> None:
    path = _orgs_index_path()
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    tmp.replace(path)


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def _new_org_id() -> str:
    """Short, URL-safe, collision-resistant id."""
    return "org_" + secrets.token_urlsafe(9).replace("-", "").replace("_", "")[:12]


def create_org(name: str, owner_email: str) -> Org:
    """Create an org row, persist to the index, and provision its data dir."""
    name = (name or "").strip()
    owner = (owner_email or "").strip().lower()
    if not name:
        raise ValueError("Org name is required.")
    if not owner or "@" not in owner:
        raise ValueError("Owner email is required and must look like an email.")
    org = Org(
        id=_new_org_id(),
        name=name,
        created_at=int(time.time()),
        owner_email=owner,
    )
    rows = _read_index()
    rows.append(org.to_dict())
    _write_index(rows)
    # Provision the data dir + RBAC members file with the owner as ADMIN.
    org_data_dir(org.id)
    try:
        from safecadence.auth.rbac import assign_role, UserRole
        assign_role(org.id, owner, UserRole.ADMIN)
    except Exception:                              # pragma: no cover
        pass
    return org


def get_org(org_id: str) -> Org | None:
    """Return the Org for ``org_id`` or None."""
    if not org_id:
        return None
    for row in _read_index():
        if row.get("id") == org_id:
            return Org.from_dict(row)
    return None


def list_orgs() -> list[Org]:
    """Return all orgs sorted oldest-first."""
    rows = _read_index()
    rows.sort(key=lambda r: int(r.get("created_at") or 0))
    return [Org.from_dict(r) for r in rows]


def org_data_dir(org_id: str) -> Path:
    """Return the per-org data dir, creating it if missing.

    Layout (created on demand):
      ~/.safecadence/orgs/<org_id>/
        platform_assets/   (mirrors the global layout)
        scans/
        reports/
        members.json       (RBAC member list)
        audit.jsonl        (append-only audit trail)
    """
    if not org_id:
        raise ValueError("org_id is required for org_data_dir()")
    base = _root() / "orgs" / org_id
    base.mkdir(parents=True, exist_ok=True)
    for sub in ("platform_assets", "scans", "reports"):
        (base / sub).mkdir(parents=True, exist_ok=True)
    return base


def delete_org(org_id: str) -> bool:
    """Remove the org from the index. Does NOT delete on-disk data — that's
    a destructive op left for a v10.6+ admin tool."""
    rows = _read_index()
    n = len(rows)
    rows = [r for r in rows if r.get("id") != org_id]
    if len(rows) == n:
        return False
    _write_index(rows)
    return True


__all__ = [
    "Org",
    "create_org",
    "get_org",
    "list_orgs",
    "org_data_dir",
    "delete_org",
]
