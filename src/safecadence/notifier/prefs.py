"""
v9.43 — Notification preferences.

Three layers, in order of precedence:

  1. Code defaults — ``approval_requested`` is always-on for invitees,
     other categories ship default off (operator opts in).
  2. Tenant defaults — admin sets "what new users start with" at
     ``/settings/notifications``. Persists to
     ``$SC_DATA_DIR/settings/notify_defaults.json``.
  3. Per-user overrides — each user's ``notify_prefs`` field in
     ``users.yaml``. Empty/missing == fall back to tenant defaults.

Schema for ``notify_prefs`` on a user record:

    notify_prefs:
      approval_requested:    [email, slack_dm]
      finding_critical:      [email]
      digest_daily:          [email]
      drift_detected:        []          # explicit opt-out

A category not in the dict means "use the tenant default for this
category".

Trust property: a user can't enable a channel they have no contact
info for. ``validate_prefs`` rejects ``email`` if the user has no
email on file.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

from safecadence.notifier.registry import (
    NOTIFY_CATEGORIES, NOTIFY_CHANNELS,
    category_keys, channel_keys,
)


_TENANT_DEFAULTS_FILE = "notify_defaults.json"


# ---------------------------------------------------- tenant defaults


def _defaults_path() -> Path:
    base = Path(os.environ.get("SC_DATA_DIR") or
                  (Path.home() / ".safecadence"))
    d = base / "settings"
    d.mkdir(parents=True, exist_ok=True)
    return d / _TENANT_DEFAULTS_FILE


def load_tenant_defaults() -> dict[str, list[str]]:
    """Return ``{category_key: [channel_key, ...]}`` for the tenant.

    When the file doesn't exist we synthesize from the code-default
    column on each NOTIFY_CATEGORIES row so a fresh deployment has
    sensible behaviour without an admin lifting a finger.
    """
    p = _defaults_path()
    if p.exists():
        try:
            data = json.loads(p.read_text(encoding="utf-8")) or {}
        except Exception:
            data = {}
    else:
        data = {}
    # Synthesize from code defaults for any category the file omits
    out: dict[str, list[str]] = {}
    for cat in NOTIFY_CATEGORIES:
        key = cat["key"]
        if key in data and isinstance(data[key], list):
            out[key] = [c for c in data[key] if c in channel_keys()]
        else:
            default = cat.get("default_channels", "") or ""
            out[key] = [c.strip() for c in default.split(",")
                          if c.strip() and c.strip() in channel_keys()]
    return out


def save_tenant_defaults(prefs: dict[str, list[str]]) -> dict[str, list[str]]:
    """Persist + return the cleaned, validated set."""
    cleaned: dict[str, list[str]] = {}
    valid_cats = set(category_keys())
    valid_chs = set(channel_keys())
    for k, v in (prefs or {}).items():
        if k not in valid_cats:
            continue
        if not isinstance(v, list):
            continue
        cleaned[k] = [c for c in v if isinstance(c, str) and c in valid_chs]
    p = _defaults_path()
    p.write_text(json.dumps(cleaned, indent=2), encoding="utf-8")
    try:
        os.chmod(p, 0o644)
    except OSError:                                                # pragma: no cover
        pass
    return cleaned


# ---------------------------------------------------- per-user prefs


def user_prefs(rec) -> dict[str, list[str]]:
    """Read ``notify_prefs`` off a UserRecord-shaped object.

    Always returns a dict[str, list[str]] — empty when the user has
    no overrides.
    """
    raw = getattr(rec, "notify_prefs", None) or {}
    if not isinstance(raw, dict):
        return {}
    out: dict[str, list[str]] = {}
    valid_cats = set(category_keys())
    valid_chs = set(channel_keys())
    for k, v in raw.items():
        if k not in valid_cats:
            continue
        if not isinstance(v, list):
            continue
        out[k] = [c for c in v if isinstance(c, str) and c in valid_chs]
    return out


def user_channels_for_kind(rec, *, kind: str,
                            tenant: str = "local") -> list[str]:
    """Which channels should we reach this user on for this event kind?

    Resolution order:
      1. user override for this kind (if explicitly set, even to [])
      2. tenant default for this kind
      3. category code default

    Then *intersect* with the channels this user actually has contact
    info for. A pref enabling email is silently ignored if the user
    has no email on file — defense-in-depth on top of validate_prefs.
    """
    overrides = user_prefs(rec)
    if kind in overrides:
        wanted = overrides[kind]
    else:
        td = load_tenant_defaults()
        wanted = td.get(kind, [])
    avail = _available_channels(rec)
    return [c for c in wanted if c in avail]


def _available_channels(rec) -> set[str]:
    out: set[str] = set()
    if rec.primary_email():
        out.add("email")
    if rec.notify.get("slack_user_id"):
        out.add("slack_dm")
    if rec.notify.get("teams_user_id"):
        out.add("teams_dm")
    return out


def validate_prefs(rec, prefs: dict[str, list[str]]) -> list[str]:
    """Reject prefs that enable a channel the user has no contact for.

    Returns a list of human-readable error strings (empty == ok).
    """
    errs: list[str] = []
    valid_cats = set(category_keys())
    valid_chs = set(channel_keys())
    avail = _available_channels(rec)
    for k, v in (prefs or {}).items():
        if k not in valid_cats:
            errs.append(f"unknown category: {k!r}")
            continue
        if not isinstance(v, list):
            errs.append(f"{k}: must be a list of channel keys")
            continue
        for c in v:
            if c not in valid_chs:
                errs.append(f"{k}: unknown channel {c!r}")
            elif c not in avail:
                errs.append(
                    f"{k}: channel {c!r} requires contact info "
                    f"({_field_for_channel(c)}); not on this user")
    return errs


def _field_for_channel(channel: str) -> str:
    for ch in NOTIFY_CHANNELS:
        if ch["key"] == channel:
            return ch["user_field"]
    return "?"
