"""v9.49 — IdP-sourced approver groups.

Approver directory entries can reference ``@group:eng-leads`` instead
of listing individual usernames. The group's members are resolved at
notification dispatch time from the latest cached snapshot.

Cache layout (``$SC_DATA_DIR/identity/groups.json``)::

    {
      "version": 1,
      "synced_at": "2026-05-07T12:00:00Z",
      "groups": [
        {"system": "okta", "id": "00g123",
         "name": "eng-leads", "members": ["alice", "bob"]},
        {"system": "ad",   "id": "CN=secops,OU=Groups,DC=...",
         "name": "secops",   "members": ["carol"]}
      ]
    }

The daemon refreshes this snapshot once per cycle from each connected
IdP via the existing identity adapters' ``list_groups()`` capability.
Groups not refreshed in the last 24 h are flagged ``stale`` so the UI
can warn approvers that the resolution might be out of date.

The cache is read-only at notification dispatch time — we never block
on a network round trip when an approval needs to fire.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional


_STALE_AFTER_HOURS = 24


@dataclass
class GroupRecord:
    system: str = ""               # okta | entra | ad | ise | clearpass
    id: str = ""                   # vendor-native group id (sub, dn, gid)
    name: str = ""                 # operator-friendly name
    members: list[str] = field(default_factory=list)
    synced_at: str = ""            # ISO8601 UTC


def _store_path() -> Path:
    base = Path(os.environ.get("SC_DATA_DIR") or
                  (Path.home() / ".safecadence"))
    d = base / "identity"
    d.mkdir(parents=True, exist_ok=True)
    return d / "groups.json"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(
        timespec="seconds").replace("+00:00", "Z")


def _load_raw() -> dict:
    p = _store_path()
    if not p.exists():
        return {"version": 1, "synced_at": "", "groups": []}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"version": 1, "synced_at": "", "groups": []}


def _save_raw(data: dict) -> None:
    p = _store_path()
    p.write_text(json.dumps(data, indent=2, sort_keys=True),
                  encoding="utf-8")
    try:
        os.chmod(p, 0o600)
    except OSError:                                     # pragma: no cover
        pass


def list_groups(*, system: Optional[str] = None) -> list[GroupRecord]:
    data = _load_raw()
    out = [GroupRecord(**g) for g in (data.get("groups") or [])
           if isinstance(g, dict)]
    if system:
        out = [g for g in out if g.system == system]
    out.sort(key=lambda g: (g.system, g.name))
    return out


def get_group(name_or_id: str) -> Optional[GroupRecord]:
    """Look up a group by name first (operator-friendly), then by id.
    Cross-system collision resolution: name match wins; if multiple
    systems have the same group name, the one synced most recently
    is returned."""
    rows = list_groups()
    by_name = sorted(
        [g for g in rows if g.name == name_or_id],
        key=lambda g: g.synced_at, reverse=True,
    )
    if by_name:
        return by_name[0]
    by_id = [g for g in rows if g.id == name_or_id]
    if by_id:
        return by_id[0]
    return None


def members_of(name_or_id: str) -> list[str]:
    """Return the list of usernames in this group, or [] if unknown.

    The dispatcher pattern is `members_of('eng-leads') or fall back
    to a hard-coded list` — this function NEVER raises, so a deleted
    group degrades gracefully into "no DM goes out" rather than
    breaking the approval flow."""
    g = get_group(name_or_id)
    return list(g.members) if g else []


def resolve_invitees(invitees: list[str]) -> list[str]:
    """Expand any ``@group:NAME`` entries in an invitee list into the
    underlying usernames. Plain usernames pass through unchanged.

    Duplicates are de-duped while preserving first-seen order."""
    seen: set[str] = set()
    out: list[str] = []
    for entry in invitees:
        if not isinstance(entry, str):
            continue
        if entry.startswith("@group:"):
            for u in members_of(entry[len("@group:"):]):
                if u and u not in seen:
                    seen.add(u)
                    out.append(u)
        else:
            if entry and entry not in seen:
                seen.add(entry)
                out.append(entry)
    return out


def upsert_group(rec: GroupRecord | dict) -> GroupRecord:
    """Insert-or-update one group record. Identity is the
    (system, id) pair; if that pair already exists, the row is
    overwritten with the new members + synced_at."""
    if isinstance(rec, dict):
        rec = GroupRecord(**rec)
    if not rec.synced_at:
        rec.synced_at = _now_iso()
    data = _load_raw()
    rows = data.get("groups") or []
    rows = [r for r in rows
            if not (r.get("system") == rec.system and r.get("id") == rec.id)]
    rows.append(asdict(rec))
    data["groups"] = rows
    data["synced_at"] = _now_iso()
    _save_raw(data)
    return rec


def stale_groups(*, hours: int = _STALE_AFTER_HOURS) -> list[GroupRecord]:
    """Return groups whose ``synced_at`` is older than ``hours`` ago.
    The dispatcher uses this list to flag risky resolutions in the
    UI — a group with stale membership might be DM'ing the wrong
    people."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    out: list[GroupRecord] = []
    for g in list_groups():
        if not g.synced_at:
            out.append(g)
            continue
        try:
            ts = datetime.fromisoformat(g.synced_at.replace("Z", "+00:00"))
        except ValueError:
            out.append(g)
            continue
        if ts < cutoff:
            out.append(g)
    return out


def refresh_from_adapters() -> dict:
    """Daemon hook: walk each connected identity system in the vault,
    call its ``list_groups()`` capability, and upsert the result.
    Returns a per-system summary so the daemon can include it in the
    cycle report. Best-effort — a slow Okta call never aborts the
    refresh of the other systems.
    """
    summary: dict[str, dict] = {}
    try:
        from safecadence.identity.vault import IdentityVault
    except Exception:                                   # pragma: no cover
        return {"error": "vault module unavailable"}
    try:
        vault = IdentityVault()
        connected = vault.list_connected() or []
    except Exception as exc:                            # pragma: no cover
        return {"error": f"{type(exc).__name__}: {exc}"}
    for c in connected:
        sys_name = c.get("system", "")
        if not sys_name:
            continue
        try:
            n = _refresh_one_system(vault, sys_name)
            summary[sys_name] = {"ok": True, "count": n}
        except Exception as exc:                        # pragma: no cover
            summary[sys_name] = {"ok": False,
                                  "error": f"{type(exc).__name__}: {exc}"}
    return summary


# ---------------------------------------------------------------- internals


def _refresh_one_system(vault, system: str) -> int:
    """Pull groups for one system from its adapter. Falls back to the
    cached snapshot if the adapter doesn't expose ``list_groups``
    yet — we don't want a partial adapter implementation to wipe a
    healthy cache."""
    try:
        rec = vault.load_creds(system)
    except Exception:
        rec = None
    if rec is None:
        return 0
    try:
        from safecadence.platform.adapters.identity_adapters import (
            ActiveDirectoryAdapter, CiscoISEAdapter,
            EntraIDAdapter, HPEClearPassAdapter, OktaAdapter,
        )
    except Exception:                                   # pragma: no cover
        return 0
    cls_map = {
        "okta": OktaAdapter, "entra": EntraIDAdapter,
        "ad": ActiveDirectoryAdapter,
        "ise": CiscoISEAdapter, "clearpass": HPEClearPassAdapter,
    }
    cls = cls_map.get(system)
    if cls is None:
        return 0
    adapter = cls(target=rec.target,
                   credentials=dict(rec.credentials))
    list_groups_fn = getattr(adapter, "list_groups", None)
    if not callable(list_groups_fn):
        return 0
    rows = list_groups_fn() or []
    n = 0
    for raw in rows:
        if not isinstance(raw, dict):
            continue
        upsert_group(GroupRecord(
            system=system,
            id=str(raw.get("id") or raw.get("name") or ""),
            name=str(raw.get("name") or raw.get("id") or ""),
            members=[str(m) for m in (raw.get("members") or [])
                      if isinstance(m, str)],
            synced_at=_now_iso(),
        ))
        n += 1
    return n
