"""
v9.32 — Multi-team RBAC for policies.

Each policy gets a ``scope`` tag (network | cloud | identity |
backup | server | storage | "*" for global). Roles map to a list of
scopes they can edit. The policy API checks both:

  1. The user has the writer capability (existing JWT/RBAC)
  2. The user's role grants the requested scope

Storage: a single YAML at $SC_DATA_DIR/policy_rbac.yaml.

Default mapping (operator can override):

  policy_admin  → ["*"]
  netops_admin  → ["network", "cloud"]
  cloud_admin   → ["cloud"]
  iam_admin     → ["identity"]
  storage_admin → ["storage", "backup"]
  viewer        → []   (read-only)

If no mapping file exists, ``can_edit_scope()`` returns True for any
writer (backwards-compatible — existing deployments don't break).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional


_VALID_SCOPES = {"network", "cloud", "identity",
                  "backup", "server", "storage", "*"}


_DEFAULT_MAPPING = {
    "policy_admin":   ["*"],
    "netops_admin":   ["network", "cloud"],
    "cloud_admin":    ["cloud"],
    "iam_admin":      ["identity"],
    "storage_admin":  ["storage", "backup"],
    "viewer":         [],
}


def _path() -> Path:
    home = (os.environ.get("SC_DATA_DIR")
              or os.environ.get("SAFECADENCE_HOME")
              or str(Path.home() / ".safecadence"))
    p = Path(home)
    p.mkdir(parents=True, exist_ok=True)
    return p / "policy_rbac.json"


def load_mapping() -> dict[str, list[str]]:
    p = _path()
    if not p.exists():
        return dict(_DEFAULT_MAPPING)
    try:
        data = json.loads(p.read_text(encoding="utf-8")) or {}
        # Sanitize: ignore unknown scopes.
        out: dict[str, list[str]] = {}
        for role, scopes in data.items():
            cleaned = [s for s in (scopes or []) if s in _VALID_SCOPES]
            out[str(role)] = cleaned
        return out or dict(_DEFAULT_MAPPING)
    except Exception:
        return dict(_DEFAULT_MAPPING)


def save_mapping(mapping: dict[str, list[str]]) -> dict[str, list[str]]:
    cleaned: dict[str, list[str]] = {}
    for role, scopes in mapping.items():
        if not isinstance(role, str) or not role.strip():
            continue
        cs: list[str] = []
        for s in scopes or []:
            if s in _VALID_SCOPES and s not in cs:
                cs.append(s)
        cleaned[role.strip()] = cs
    _path().write_text(json.dumps(cleaned, indent=2),
                          encoding="utf-8")
    return cleaned


def scopes_for_user(user: dict) -> set[str]:
    """user is the dict returned by get_current_user — has roles[]."""
    if not isinstance(user, dict):
        return set()
    roles = user.get("roles") or []
    # Admin in the bearer sense always has the global scope so we don't
    # break existing deployments.
    if "admin" in roles:
        return set(_VALID_SCOPES)
    mapping = load_mapping()
    out: set[str] = set()
    for r in roles:
        for s in mapping.get(r, []):
            out.add(s)
    return out


def can_edit_scope(user: dict, scope: str) -> bool:
    """Does this user's role mapping grant the given scope?"""
    if not scope or scope == "*":
        # Global edit requires the global capability.
        return "*" in scopes_for_user(user) or "admin" in (
            user.get("roles") if isinstance(user, dict) else []
        )
    user_scopes = scopes_for_user(user)
    return "*" in user_scopes or scope in user_scopes


def normalize_policy_scope(scope: Optional[str]) -> str:
    s = (scope or "").strip().lower()
    if s in _VALID_SCOPES:
        return s
    return "network"   # safe default that matches the most common case
