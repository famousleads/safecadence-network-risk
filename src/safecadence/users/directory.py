"""
v9.42 — User directory.

Extends the v2.1 ``auth.load_users()`` shape with the optional contact
fields needed for targeted approval notifications:

  - ``email``                -- direct email DM
  - ``display_name``         -- "Alice Chen" instead of "alice"
  - ``notify.email``         -- override email (defaults to ``email``)
  - ``notify.slack_user_id`` -- @-mention in Slack webhook
  - ``notify.teams_user_id`` -- @-mention in Teams webhook
  - ``notify.pagerduty_user_id`` -- for v9.43 escalation hook
  - ``external_id``          -- e.g. ``okta:00u3xyz``; v9.43 IdP-sourced
                                 group resolution will use this

Backward compatible: every new field is optional. A pre-v9.42
users.yaml loads unchanged, the directory just returns empty contact
fields. The role gate (``auth.require_role``) is unchanged — adding
contact info doesn't grant any new authority.

Trust property: ``approvers_invited`` on a CommandJob is exactly that
— an *invitation* list. The actual approve action is still gated by
the role-based check in workflow.approve(). Inviting alice@acme to a
job she lacks the role to approve is a no-op (she gets the email and
sees the queue page; click goes to a 403). This is by design — the
invite is a hint to reduce noise, not an authorization.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml


# Loose RFC-5322 — operators paste in unusual addresses; we just want
# to catch obvious typos. Real validation happens at SMTP send time.
_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


@dataclass
class UserRecord:
    """One row in the directory.

    The password_hash is intentionally NOT included — every consumer
    should be reading either the auth path (which works on the raw
    YAML and never exposes hashes) or the directory path (this), which
    is for non-secret data only.
    """
    username: str
    tenant: str
    roles: list[str] = field(default_factory=list)
    email: str = ""
    display_name: str = ""
    notify: dict[str, str] = field(default_factory=dict)
    external_id: str = ""
    # v9.43 — per-user category × channel prefs.
    # Schema: {category_key: [channel_key, ...]}.
    # Empty/missing == fall back to tenant defaults.
    notify_prefs: dict[str, list[str]] = field(default_factory=dict)

    def label(self) -> str:
        """What to render in UI lists. Falls back through display_name
        → email → username so something always shows."""
        return self.display_name or self.email or self.username

    def primary_email(self) -> str:
        """Where to send email DMs. ``notify.email`` overrides the
        canonical email so an admin can route Alice's notifications
        to a shared inbox without changing her login email."""
        return (self.notify.get("email") or self.email or "").strip()


def _users_file_path(explicit: Optional[Path | str] = None) -> Path:
    if explicit:
        return Path(explicit)
    return Path(os.environ.get("SC_USERS_FILE",
                                 "safecadence-users.yaml"))


def _load_yaml(path: Path) -> dict:
    if not path.exists():
        return {"tenants": {}}
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {
            "tenants": {}}
    except yaml.YAMLError as e:
        raise RuntimeError(f"users.yaml parse error: {e}") from e


def _record_from_dict(tenant: str, raw: dict) -> UserRecord:
    notify_raw = raw.get("notify") or {}
    if not isinstance(notify_raw, dict):
        notify_raw = {}
    # Coerce values to strings so the API serialises cleanly even if
    # an admin pasted an int Slack user id.
    notify = {k: str(v) for k, v in notify_raw.items() if v is not None}
    # v9.43 — pull notify_prefs (per-user category × channel matrix)
    np_raw = raw.get("notify_prefs") or {}
    notify_prefs: dict[str, list[str]] = {}
    if isinstance(np_raw, dict):
        for cat, chans in np_raw.items():
            if not isinstance(chans, list):
                continue
            notify_prefs[str(cat)] = [str(c) for c in chans
                                        if isinstance(c, str)]
    return UserRecord(
        username=str(raw.get("username", "")).strip(),
        tenant=tenant,
        roles=[r for r in (raw.get("roles") or []) if isinstance(r, str)],
        email=str(raw.get("email") or "").strip(),
        display_name=str(raw.get("display_name") or "").strip(),
        notify=notify,
        external_id=str(raw.get("external_id") or "").strip(),
        notify_prefs=notify_prefs,
    )


def list_users(*, tenant: Optional[str] = None,
                path: Optional[Path | str] = None) -> list[UserRecord]:
    """Return the full directory, optionally filtered to one tenant.

    Never includes password hashes. Safe to return from a public API.
    """
    p = _users_file_path(path)
    data = _load_yaml(p)
    tenants = data.get("tenants") or {}
    out: list[UserRecord] = []
    for tid, t in tenants.items():
        if tenant is not None and tid != tenant:
            continue
        for u in (t.get("users") or []):
            if not isinstance(u, dict):
                continue
            rec = _record_from_dict(tid, u)
            if rec.username:
                out.append(rec)
    return out


def get_user(username: str, *, tenant: Optional[str] = None,
              path: Optional[Path | str] = None) -> Optional[UserRecord]:
    for u in list_users(tenant=tenant, path=path):
        if u.username == username:
            return u
    return None


def lookup_invitees(usernames: list[str], *, tenant: str,
                     path: Optional[Path | str] = None) -> list[UserRecord]:
    """Resolve a list of usernames to UserRecords inside one tenant.

    Unknown usernames are silently dropped — the caller can compare
    counts if it wants to flag them. (We don't raise so a stale
    invitation reference on an old job doesn't break the notifier.)
    """
    if not usernames:
        return []
    by_name = {u.username: u for u in list_users(tenant=tenant, path=path)}
    return [by_name[n] for n in usernames if n in by_name]


# ----------------------------------------------------- write side


def validate_user_payload(body: dict) -> list[str]:
    """Return list of human-readable validation errors. Empty = ok.

    Used by the /api/users POST/PUT endpoints. Email is optional; if
    present, it must look like an email. roles must be non-empty.
    """
    errs: list[str] = []
    username = str(body.get("username") or "").strip()
    if not username:
        errs.append("username is required")
    elif not re.match(r"^[a-zA-Z0-9._\-]+$", username):
        errs.append("username may only contain letters, digits, . _ -")
    roles = body.get("roles") or []
    if not isinstance(roles, list) or not roles:
        errs.append("roles must be a non-empty list")
    email = str(body.get("email") or "").strip()
    if email and not _EMAIL_RE.match(email):
        errs.append(f"email looks malformed: {email!r}")
    notify = body.get("notify") or {}
    if notify and not isinstance(notify, dict):
        errs.append("notify must be a JSON object")
    if isinstance(notify, dict):
        ne = str(notify.get("email") or "").strip()
        if ne and not _EMAIL_RE.match(ne):
            errs.append(f"notify.email looks malformed: {ne!r}")
    return errs


def upsert_user(body: dict, *, tenant: str,
                 path: Optional[Path | str] = None,
                 password_hash: Optional[str] = None) -> UserRecord:
    """Create-or-update by ``(tenant, username)``.

    The caller is responsible for the role check. ``password_hash`` is
    only set on the record when explicitly passed (admin-set new
    password) — otherwise the existing hash is preserved.
    """
    errs = validate_user_payload(body)
    if errs:
        raise ValueError("; ".join(errs))
    p = _users_file_path(path)
    data = _load_yaml(p)
    tenants = data.setdefault("tenants", {})
    t = tenants.setdefault(tenant, {"users": []})
    users = t.setdefault("users", [])
    username = str(body["username"]).strip()
    # Find existing
    target: Optional[dict] = None
    for u in users:
        if isinstance(u, dict) and u.get("username") == username:
            target = u
            break
    if target is None:
        target = {"username": username}
        users.append(target)
    target["roles"] = [r for r in (body.get("roles") or [])
                        if isinstance(r, str)]
    # Optional fields — overwrite when present, leave alone when omitted
    for key in ("email", "display_name", "external_id"):
        if key in body and body[key] is not None:
            target[key] = str(body[key]).strip()
    if "notify" in body and isinstance(body["notify"], dict):
        target["notify"] = {k: str(v).strip()
                             for k, v in body["notify"].items()
                             if v is not None}
    # v9.43 — accept notify_prefs round-trips
    if "notify_prefs" in body and isinstance(body["notify_prefs"], dict):
        cleaned: dict[str, list[str]] = {}
        for cat, chans in body["notify_prefs"].items():
            if not isinstance(chans, list):
                continue
            cleaned[str(cat)] = [str(c) for c in chans
                                  if isinstance(c, str)]
        target["notify_prefs"] = cleaned
    if password_hash is not None:
        target["password_hash"] = password_hash

    p.write_text(yaml.safe_dump(data), encoding="utf-8")
    try:
        os.chmod(p, 0o600)                      # secrets — pgo permissions
    except OSError:                             # pragma: no cover
        pass
    return _record_from_dict(tenant, target)


def delete_user(username: str, *, tenant: str,
                 path: Optional[Path | str] = None) -> bool:
    p = _users_file_path(path)
    data = _load_yaml(p)
    t = (data.get("tenants") or {}).get(tenant) or {}
    users = t.get("users") or []
    new_users = [u for u in users
                  if not (isinstance(u, dict) and u.get("username") == username)]
    if len(new_users) == len(users):
        return False
    t["users"] = new_users
    p.write_text(yaml.safe_dump(data), encoding="utf-8")
    try:
        os.chmod(p, 0o600)
    except OSError:                             # pragma: no cover
        pass
    return True
