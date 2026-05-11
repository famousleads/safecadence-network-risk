"""Audit trail for finding-level state transitions.

Appends one JSON object per line to ``~/.safecadence/audit_trail.jsonl``::

    {"finding_id":"CVE-2024-12345","host":"h1","event":"discovered",
     "ts":"2026-05-01T08:00:00Z","actor":"netrisk-scanner"}
    {"finding_id":"CVE-2024-12345","host":"h1","event":"triaged",
     "ts":"2026-05-02T10:00:00Z","actor":"security-eng","note":"Confirmed"}
    {"finding_id":"CVE-2024-12345","host":"h1","event":"remediated",
     "ts":"2026-05-05T14:00:00Z","actor":"netops","note":"Patched"}

Events provide the time-to-triage (TTT) and time-to-remediate (TTR) numbers
that surface in the compliance evidence pack section.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
from pathlib import Path


DEFAULT_PATH = "~/.safecadence/audit_trail.jsonl"

KNOWN_EVENTS = (
    "discovered",
    "triaged",
    "in_progress",
    "remediated",
    "accepted",
    "reopened",
    "verified",
    "note",
)


def _store_path(path: str | None = None) -> Path:
    if path:
        return Path(path)
    env = os.environ.get("SAFECADENCE_AUDIT_TRAIL_PATH")
    if env:
        return Path(env)
    return Path(os.path.expanduser(DEFAULT_PATH))


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log_event(
    finding_id: str,
    host: str | None,
    event: str,
    *,
    actor: str | None = None,
    note: str | None = None,
    ts: str | None = None,
    path: str | None = None,
) -> dict:
    """Append a single event to the audit trail. Returns the stored record."""
    if not finding_id:
        raise ValueError("finding_id is required")
    if not event:
        raise ValueError("event is required")
    record: dict = {
        "finding_id": finding_id,
        "host": host,
        "event": event,
        "ts": ts or _now_iso(),
    }
    if actor:
        record["actor"] = actor
    if note:
        record["note"] = note
    p = _store_path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")
    # v10.8: replay every state transition into the workflow change log
    # so the org-wide change feed sees them.
    if event in {"triaged", "in_progress", "remediated",
                 "accepted", "reopened", "verified"}:
        try:
            from safecadence.workflow.change_mgmt import record_change
            record_change(
                None,                       # global / single-tenant for now
                "finding_transition",
                before=None,
                after={
                    "finding_id": finding_id,
                    "host": host,
                    "event": event,
                },
                actor=actor,
                asset_id=host,
            )
        except Exception:                          # pragma: no cover
            pass
    return record


def _read_all(path: str | None = None) -> list[dict]:
    p = _store_path(path)
    if not p.exists():
        return []
    out: list[dict] = []
    try:
        with p.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                if isinstance(obj, dict):
                    out.append(obj)
    except Exception:
        return out
    return out


def events_for(
    finding_id: str,
    host: str | None = None,
    *,
    path: str | None = None,
) -> list[dict]:
    """Return events for the given finding (optionally narrowed by host),
    sorted oldest-first."""
    if not finding_id:
        return []
    items = []
    for e in _read_all(path):
        if e.get("finding_id") != finding_id:
            continue
        if host is not None and e.get("host") not in (None, "", host):
            continue
        items.append(e)
    items.sort(key=lambda e: e.get("ts") or "")
    return items


def _parse_ts(ts: str | None) -> _dt.datetime | None:
    if not ts:
        return None
    try:
        # Tolerate trailing 'Z' (UTC) and offsets.
        s = ts.replace("Z", "+00:00")
        return _dt.datetime.fromisoformat(s)
    except Exception:
        return None


def summary_for(
    finding_id: str,
    host: str | None = None,
    *,
    path: str | None = None,
) -> dict:
    """Return ``{discovered_at, triaged_at, remediated_at, ttt, ttr}`` where
    ``ttt`` (time-to-triage) and ``ttr`` (time-to-remediate) are integer days
    when both endpoints are known.
    """
    events = events_for(finding_id, host, path=path)
    discovered = triaged = remediated = None
    for e in events:
        ev = e.get("event")
        ts = e.get("ts")
        if ev == "discovered" and not discovered:
            discovered = ts
        elif ev == "triaged" and not triaged:
            triaged = ts
        elif ev == "remediated" and not remediated:
            remediated = ts
    d_dt = _parse_ts(discovered)
    t_dt = _parse_ts(triaged)
    r_dt = _parse_ts(remediated)
    ttt = None
    ttr = None
    if d_dt and t_dt:
        ttt = max(0, (t_dt.date() - d_dt.date()).days)
    if d_dt and r_dt:
        ttr = max(0, (r_dt.date() - d_dt.date()).days)
    return {
        "finding_id": finding_id,
        "host": host,
        "discovered_at": discovered,
        "triaged_at": triaged,
        "remediated_at": remediated,
        "ttt": ttt,
        "ttr": ttr,
        "events": events,
    }


def reset(path: str | None = None) -> None:
    """Truncate the audit trail (used by tests)."""
    p = _store_path(path)
    if p.exists():
        p.unlink()


__all__ = [
    "DEFAULT_PATH",
    "KNOWN_EVENTS",
    "log_event",
    "events_for",
    "summary_for",
    "reset",
]
