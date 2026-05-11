"""
Role-based access control for SafeCadence NetRisk orgs.

Three roles, deliberately small::

  VIEWER  — read-only. Can see reports, inventory, dashboards.
  EDITOR  — VIEWER + create/edit/delete reports + run report jobs.
  ADMIN   — EDITOR + invite teammates + change roles + delete org-level data.

Membership is persisted per-org in
``~/.safecadence/orgs/<org_id>/members.json`` as
``{"<email>": "<role>", ...}``. The same file is the source of truth
for the FastAPI :func:`require_role` dependency.
"""

from __future__ import annotations

import enum
import json
import os
from typing import Optional


class UserRole(str, enum.Enum):
    VIEWER = "viewer"
    EDITOR = "editor"
    ADMIN = "admin"

    @classmethod
    def from_str(cls, s: str | None) -> "UserRole | None":
        if not s:
            return None
        s = s.lower().strip()
        for r in cls:
            if r.value == s:
                return r
        return None


_ROLE_ORDER = {
    UserRole.VIEWER: 1,
    UserRole.EDITOR: 2,
    UserRole.ADMIN: 3,
}


def role_satisfies(actual: UserRole | None, minimum: UserRole) -> bool:
    """Does ``actual`` meet or exceed ``minimum``?"""
    if actual is None:
        return False
    return _ROLE_ORDER[actual] >= _ROLE_ORDER[minimum]


# --------------------------------------------------------------------------
# Storage helpers
# --------------------------------------------------------------------------


def _members_path(org_id: str):
    from safecadence.storage.org_store import org_data_dir
    return org_data_dir(org_id) / "members.json"


def _read_members(org_id: str) -> dict[str, str]:
    path = _members_path(org_id)
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    if isinstance(data, dict):
        return {str(k).lower(): str(v).lower() for k, v in data.items()}
    return {}


def _write_members(org_id: str, members: dict[str, str]) -> None:
    path = _members_path(org_id)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(members, indent=2), encoding="utf-8")
    tmp.replace(path)


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def assign_role(org_id: str, user_email: str, role: UserRole | str) -> UserRole:
    """Assign ``role`` to ``user_email`` in ``org_id``. Creates the
    members file if missing. Returns the canonical role."""
    if not org_id:
        raise ValueError("org_id is required")
    email = (user_email or "").strip().lower()
    if not email or "@" not in email:
        raise ValueError("user_email must be a valid email")
    role_enum = role if isinstance(role, UserRole) else UserRole.from_str(role)
    if role_enum is None:
        raise ValueError(f"Unknown role: {role!r}")
    members = _read_members(org_id)
    members[email] = role_enum.value
    _write_members(org_id, members)
    return role_enum


def get_role(org_id: str, user_email: str) -> Optional[UserRole]:
    """Return the user's role in this org, or None if not a member.

    When :envvar:`SC_AUTH_DISABLED` is set, every user is treated as an
    org ADMIN — keeps the demo working with zero setup.
    """
    if os.environ.get("SC_AUTH_DISABLED", "") == "1":
        return UserRole.ADMIN
    if not org_id or not user_email:
        return None
    email = user_email.strip().lower()
    members = _read_members(org_id)
    raw = members.get(email)
    return UserRole.from_str(raw)


def remove_role(org_id: str, user_email: str) -> bool:
    """Remove the user from the org's RBAC list. Returns True if removed."""
    if not org_id or not user_email:
        return False
    email = user_email.strip().lower()
    members = _read_members(org_id)
    if email not in members:
        return False
    members.pop(email, None)
    _write_members(org_id, members)
    return True


def list_members(org_id: str) -> list[dict]:
    """Return all members of an org as ``[{email, role}, ...]``."""
    members = _read_members(org_id)
    out = [{"email": k, "role": v} for k, v in members.items()]
    out.sort(key=lambda r: r["email"])
    return out


# --------------------------------------------------------------------------
# FastAPI dependency factory
# --------------------------------------------------------------------------


def require_role(min_role: UserRole | str):
    """Return a FastAPI dependency that enforces ``min_role``.

    The dependency reads the org id from the request (header
    ``X-SafeCadence-Org`` or query param ``org_id``); if absent it
    falls back to global mode where any authenticated session passes
    (legacy single-tenant behavior). When :envvar:`SC_AUTH_DISABLED`
    the dependency passes through unconditionally.
    """
    min_enum = min_role if isinstance(min_role, UserRole) else UserRole.from_str(min_role)
    if min_enum is None:
        raise ValueError(f"Unknown min_role: {min_role!r}")

    try:
        from fastapi import Depends, HTTPException, Request
    except Exception:                              # pragma: no cover
        def _stub(*_a, **_kw):
            return None
        return _stub

    from safecadence.auth.deps import require_session

    def _dep(request: "Request", session: dict = Depends(require_session)) -> dict:
        if os.environ.get("SC_AUTH_DISABLED", "") == "1":
            return session
        org_id = (
            request.headers.get("X-SafeCadence-Org")
            or request.query_params.get("org_id")
            or ""
        ).strip()
        if not org_id:
            # Legacy single-tenant — any authenticated session passes.
            return session
        email = session.get("email") or ""
        actual = get_role(org_id, email)
        if not role_satisfies(actual, min_enum):
            raise HTTPException(
                status_code=403,
                detail=f"Requires role {min_enum.value}+ in org {org_id}.",
            )
        return session

    return _dep


__all__ = [
    "UserRole",
    "assign_role",
    "get_role",
    "remove_role",
    "list_members",
    "require_role",
    "role_satisfies",
]
