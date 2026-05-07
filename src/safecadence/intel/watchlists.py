"""
v7.9 — Watchlists.

Personal pins on entities the operator cares about (this asset, that
NHI, this principal, this finding). The daemon detects changes
between cycles and surfaces them in the morning briefing + the /home
"Your watchlist" card.

Stickiness lever — once a user has 5–10 things on their watchlist,
they open SafeCadence daily to see what changed.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any

from safecadence.intel._store import read, write


@dataclass
class Watch:
    watch_id: str
    entity_kind: str          # asset | nhi | principal | finding | policy | path
    entity_id: str            # asset_id, nhi_id, finding_id, etc.
    label: str = ""           # operator-friendly nickname
    user: str = ""            # who owns the watch
    created_at: float = 0.0
    last_seen_state: dict = field(default_factory=dict)
    last_change_at: float = 0.0
    last_change_summary: str = ""


def add_watch(*, entity_kind: str, entity_id: str,
              label: str = "", user: str = "default") -> Watch:
    if not entity_kind or not entity_id:
        raise ValueError("entity_kind and entity_id are required")
    data = read("watchlists", {})
    user_list = data.setdefault(user, [])
    # Idempotent: same user+kind+id returns existing
    for w in user_list:
        if w["entity_kind"] == entity_kind and w["entity_id"] == entity_id:
            return Watch(**w)
    w = Watch(
        watch_id="w_" + uuid.uuid4().hex[:10],
        entity_kind=entity_kind, entity_id=entity_id,
        label=label or f"{entity_kind}:{entity_id}",
        user=user, created_at=time.time(),
    )
    user_list.append(asdict(w))
    write("watchlists", data)
    return w


def list_watches(*, user: str = "default") -> list[Watch]:
    data = read("watchlists", {})
    return [Watch(**d) for d in (data.get(user) or [])]


def remove_watch(watch_id: str, *, user: str = "default") -> bool:
    data = read("watchlists", {})
    user_list = data.get(user) or []
    before = len(user_list)
    data[user] = [w for w in user_list if w["watch_id"] != watch_id]
    write("watchlists", data)
    return len(data[user]) < before


def watch_changes(*, assets: list[dict] | None = None,
                  user: str = "default",
                  now: float | None = None) -> list[dict]:
    """Compare each watch's last_seen_state against current state in
    `assets`; return the deltas that should appear in the briefing."""
    data = read("watchlists", {})
    user_list = data.get(user) or []
    if not user_list:
        return []
    by_id = {(a.get("identity") or {}).get("asset_id"): a
              for a in (assets or []) if a}

    changes: list[dict] = []
    t = now if now is not None else time.time()

    for w in user_list:
        cur = _snapshot(w, by_id)
        prev = w.get("last_seen_state") or {}
        if cur and cur != prev:
            summary = _summarize_diff(prev, cur)
            changes.append({
                "watch_id": w["watch_id"],
                "label": w["label"],
                "entity_kind": w["entity_kind"],
                "entity_id": w["entity_id"],
                "summary": summary,
            })
            w["last_seen_state"] = cur
            w["last_change_at"] = t
            w["last_change_summary"] = summary

    if changes:
        write("watchlists", data)
        # v9.45 — fan out via dispatch_event so watchlist-watchers hear
        # about changes through their configured channels (email DM if
        # opted in, channel webhooks for the team). Best-effort — never
        # break the daemon loop if a webhook is misconfigured.
        try:
            from safecadence.notifier.registry import dispatch_event
            for ch in changes:
                dispatch_event(
                    kind="watchlist_change",
                    title=f"Watchlist changed: {ch['label']}",
                    summary=ch["summary"],
                    severity="info",
                    extra={"watch_id": ch["watch_id"],
                            "entity_kind": ch["entity_kind"],
                            "entity_id": ch["entity_id"]},
                    link="/watchlists",
                    requested_by="daemon",
                    invitees=[user] if user and user != "default" else None,
                )
        except Exception:               # pragma: no cover
            pass
    return changes


def _snapshot(watch: dict, by_id: dict) -> dict:
    """Capture the few fields we care about for change detection.

    Different entity kinds care about different fields. This keeps
    the snapshot small — the diff would be useless if it showed every
    raw_collection byte changing every cycle.
    """
    if watch["entity_kind"] == "asset":
        a = by_id.get(watch["entity_id"])
        if not a:
            return {}
        sec = (a.get("security") or {})
        ib = (a.get("identity_block") or {})
        h = (a.get("health") or {})
        return {
            "kev_cves": sec.get("kev_cves", 0),
            "critical_cves": sec.get("critical_cves", 0),
            "mfa_enrolled": ib.get("mfa_enrolled"),
            "grade": h.get("grade", ""),
            "auth_groups_count": len(ib.get("authorized_groups") or []),
        }
    if watch["entity_kind"] == "nhi":
        a = by_id.get(watch["entity_id"])
        nhi = (a or {}).get("nhi") or {}
        return {
            "last_used_at": nhi.get("last_used_at", ""),
            "last_rotated_at": nhi.get("last_rotated_at", ""),
            "scope_count": len(nhi.get("effective_scopes") or []),
        }
    # principal/finding/policy/path: caller passes nothing useful — just
    # mark the watch existing. Daemon caller may pass extra data via a
    # future parameter.
    return {"present": True}


def _summarize_diff(prev: dict, cur: dict) -> str:
    parts: list[str] = []
    for k in sorted(set(prev) | set(cur)):
        if prev.get(k) != cur.get(k):
            parts.append(f"{k}: {prev.get(k)!r} → {cur.get(k)!r}")
    return "; ".join(parts) or "state changed"
