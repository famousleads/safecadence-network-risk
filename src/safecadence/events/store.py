"""
Event store — append-only JSONL under the NetRisk data dir, with
window-based dedup and asset linking.

Design:
  * One file per UTC day (``events-YYYYMMDD.jsonl``) so retention is a
    file delete, and a busy syslog source can't produce one giant file.
  * Dedup: an event whose ``dedup_key()`` was seen within
    ``SC_EVENTS_DEDUP_WINDOW_SEC`` (default 300s) increments
    ``repeat_count`` on the FIRST occurrence's record in memory index
    and is not re-appended. Honest: the first record notes repeats.
  * Asset linking: best-effort IP → asset_id via the platform store's
    discovery snapshots; refreshed lazily, never raises.
"""

from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from safecadence.events.schema import Event

_LOCK = threading.Lock()
# dedup_key -> (monotonic_ts, event_id, repeat_count)
_RECENT: dict[str, list] = {}
# ip -> (asset_id, hostname, site) cache
_IP_INDEX: dict[str, tuple[str, str, str]] = {}
_IP_INDEX_AT: float = 0.0
_IP_INDEX_TTL_SEC = 300


def _data_dir() -> Path:
    root = os.environ.get("SC_DATA_DIR") or str(Path.home() / ".safecadence")
    p = Path(root) / "events"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _dedup_window() -> float:
    try:
        return float(os.environ.get("SC_EVENTS_DEDUP_WINDOW_SEC", "300"))
    except ValueError:
        return 300.0


def _day_file(when: datetime | None = None) -> Path:
    d = (when or datetime.now(timezone.utc)).strftime("%Y%m%d")
    return _data_dir() / f"events-{d}.jsonl"


# ---------------------------------------------------------------- asset link

def _refresh_ip_index() -> None:
    global _IP_INDEX_AT
    now = time.monotonic()
    if _IP_INDEX and now - _IP_INDEX_AT < _IP_INDEX_TTL_SEC:
        return
    try:
        from safecadence.server.platform_api import list_assets
        idx: dict[str, tuple[str, str, str]] = {}
        for a in list_assets():
            ident = a.get("identity") or {}
            ip = ((a.get("raw_collection") or {}).get("discover") or {}).get("ip", "")
            if ip:
                idx[str(ip)] = (str(ident.get("asset_id", "")),
                                 str(ident.get("hostname", "")),
                                 str(ident.get("site", "")))
        _IP_INDEX.clear()
        _IP_INDEX.update(idx)
        _IP_INDEX_AT = now
    except Exception:
        _IP_INDEX_AT = now      # don't hammer a broken store


def link_asset_by_ip(event: Event) -> Event:
    """Fill asset_id/hostname/site from the platform store when the
    sender IP matches a known asset. Best-effort, never raises."""
    if not event.source_ip:
        return event
    _refresh_ip_index()
    hit = _IP_INDEX.get(event.source_ip)
    if hit:
        event.asset_id = event.asset_id or hit[0]
        event.hostname = event.hostname or hit[1]
        event.site = event.site or hit[2]
    return event


# ---------------------------------------------------------------- append/query

def append_event(event: Event, *, link_asset: bool = True) -> dict:
    """Persist an event (with dedup). Returns
    ``{stored: bool, event_id, deduped_into: id|None, repeat_count}``."""
    if link_asset:
        link_asset_by_ip(event)
    key = event.dedup_key()
    now = time.monotonic()
    with _LOCK:
        hit = _RECENT.get(key)
        if hit and now - hit[0] <= _dedup_window():
            hit[2] += 1
            return {"stored": False, "event_id": event.event_id,
                     "deduped_into": hit[1], "repeat_count": hit[2]}
        _RECENT[key] = [now, event.event_id, 0]
        # opportunistic pruning
        if len(_RECENT) > 5000:
            cutoff = now - _dedup_window()
            for k in [k for k, v in _RECENT.items() if v[0] < cutoff]:
                _RECENT.pop(k, None)
        event.correlation_id = event.correlation_id or key
        line = json.dumps(event.to_dict(), ensure_ascii=False)
        with _day_file().open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")

    incident_id = ""
    # Correlation-lite: critical/high events on known assets open (or
    # join) an incident. Opt-in — SC_EVENTS_AUTO_INCIDENT=1 — and fully
    # guarded so incident problems never lose an event.
    if os.environ.get("SC_EVENTS_AUTO_INCIDENT", "") == "1":
        try:
            from safecadence.incidents.store import attach_or_open_for_event
            inc = attach_or_open_for_event(event.to_dict())
            incident_id = inc.incident_id if inc else ""
        except Exception:
            incident_id = ""
    return {"stored": True, "event_id": event.event_id,
             "deduped_into": None, "repeat_count": 0,
             "incident_id": incident_id}


def query_events(*, limit: int = 200, severity: str = "",
                  source: str = "", asset_id: str = "",
                  days: int = 2) -> list[dict]:
    """Most-recent-first slice of the store. Reads at most ``days``
    day-files. Never raises."""
    out: list[dict] = []
    files = sorted(_data_dir().glob("events-*.jsonl"), reverse=True)[:max(1, days)]
    for f in files:
        try:
            lines = f.read_text(encoding="utf-8").splitlines()
        except Exception:
            continue
        for ln in reversed(lines):
            try:
                rec = json.loads(ln)
            except Exception:
                continue
            if severity and rec.get("severity") != severity:
                continue
            if source and rec.get("source") != source:
                continue
            if asset_id and rec.get("asset_id") != asset_id:
                continue
            out.append(rec)
            if len(out) >= limit:
                return out
    return out


_COUNT_SCAN_CAP = 20000  # audit fix: bound the dashboard rollup scan


def event_counts(days: int = 2) -> dict[str, Any]:
    """Cheap rollup for dashboards: totals by severity + source.

    Bounded: scans at most ``_COUNT_SCAN_CAP`` newest events so a
    flooded event log (e.g. a syslog storm) can't make every dashboard
    load O(all events). When the cap is hit, ``truncated`` is True and
    ``total`` reflects the scanned window, not the absolute count.
    """
    by_sev: dict[str, int] = {}
    by_src: dict[str, int] = {}
    total = 0
    for rec in query_events(limit=_COUNT_SCAN_CAP, days=days):
        total += 1
        by_sev[rec.get("severity", "info")] = by_sev.get(rec.get("severity", "info"), 0) + 1
        by_src[rec.get("source", "?")] = by_src.get(rec.get("source", "?"), 0) + 1
    return {"total": total, "by_severity": by_sev, "by_source": by_src,
            "truncated": total >= _COUNT_SCAN_CAP}


def reset_for_tests() -> None:
    """Clear in-memory dedup/index state (tests only)."""
    with _LOCK:
        _RECENT.clear()
        _IP_INDEX.clear()
        global _IP_INDEX_AT
        _IP_INDEX_AT = 0.0
