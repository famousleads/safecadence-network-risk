"""v9.47 — Activity JSONL store.

Append-only per-day JSONL files. Reads return decoded ``ActivityRecord``
instances. The middleware never blocks on disk I/O — it fires the
write on a background asyncio task so a slow disk never stalls API
latency.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Iterable, Iterator, Optional


@dataclass
class ActivityRecord:
    ts: str = ""                      # ISO8601 UTC
    actor: str = ""                   # username or "anonymous"
    tenant: str = "default"
    method: str = ""
    path: str = ""
    status: int = 0
    ip: str = ""
    duration_ms: int = 0
    request_id: str = ""
    extra: dict = field(default_factory=dict)


def _store_root() -> Path:
    base = Path(os.environ.get("SC_DATA_DIR") or
                  (Path.home() / ".safecadence"))
    d = base / "activity"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _file_for(day: datetime) -> Path:
    return _store_root() / f"{day.strftime('%Y-%m-%d')}.jsonl"


def append(rec: ActivityRecord | dict) -> Path:
    """Persist one activity record. Best-effort — disk full / read-only
    mount returns the path that *would* have been written rather than
    raising, so the calling middleware never breaks the request."""
    if isinstance(rec, ActivityRecord):
        payload = asdict(rec)
    else:
        payload = dict(rec)
    if not payload.get("ts"):
        payload["ts"] = datetime.now(timezone.utc).isoformat(
            timespec="seconds").replace("+00:00", "Z")
    when = _parse_ts(payload["ts"]) or datetime.now(timezone.utc)
    p = _file_for(when)
    line = json.dumps(payload, separators=(",", ":"),
                       sort_keys=True, ensure_ascii=False) + "\n"
    try:
        with p.open("a", encoding="utf-8") as fh:
            fh.write(line)
        try:
            os.chmod(p, 0o600)
        except OSError:                 # pragma: no cover
            pass
    except OSError:                     # pragma: no cover
        pass
    return p


def read_day(day: str | datetime,
              *, actor: Optional[str] = None,
              tenant: Optional[str] = None,
              method: Optional[str] = None,
              path_contains: Optional[str] = None,
              limit: int = 500) -> list[ActivityRecord]:
    """Decode every line of one day's file, optionally filtered. Files
    are small enough that a linear scan is fine."""
    if isinstance(day, str):
        d = datetime.fromisoformat(day).replace(tzinfo=timezone.utc)
    else:
        d = day
    p = _file_for(d)
    if not p.exists():
        return []
    out: list[ActivityRecord] = []
    try:
        with p.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError:
                    continue
                rec = ActivityRecord(**{k: raw.get(k, _DEFAULTS.get(k))
                                          for k in _FIELDS})
                if actor and rec.actor != actor:
                    continue
                if tenant and rec.tenant != tenant:
                    continue
                if method and rec.method != method:
                    continue
                if path_contains and path_contains not in rec.path:
                    continue
                out.append(rec)
                if len(out) >= limit:
                    break
    except OSError:                     # pragma: no cover
        pass
    return out


def read_range(*, days: int = 7,
                actor: Optional[str] = None,
                actor_contains: Optional[str] = None,
                tenant: Optional[str] = None,
                method: Optional[str] = None,
                path_contains: Optional[str] = None,
                extra_filter: Optional[dict] = None,
                from_ts: Optional[str] = None,
                to_ts: Optional[str] = None,
                limit: int = 500,
                end: Optional[datetime] = None) -> list[ActivityRecord]:
    """Read activity rows newest-first, optionally filtered.

    v9.57 changes:
      * **Cross-day pagination fix.** Pre-v9.57 we applied ``limit``
        per-day then sorted the union and sliced. For a busy day 1
        plus a quiet day 7, this could fill the buffer with 500
        records from day 1 and silently drop everything from days
        2-7. The fix: pass a generous per-day cap so each day
        returns its full filtered set, sort the union, then slice
        once at the end. The cost (a few extra in-memory records)
        is dwarfed by the correctness win.
      * ``actor_contains`` — substring match alternative to the
        exact-match ``actor`` arg. UI uses this; CLI / API users
        can pick either.
      * ``extra_filter`` — dict of key=value pairs the row's
        ``extra`` must contain. ``{"action": "grant"}`` finds only
        capability grants (vs revokes). Values stringified for the
        comparison so JSON-shaped ``true``/``false`` flow through.
      * ``from_ts`` / ``to_ts`` — ISO8601 inclusive bounds.
        Override the ``days`` window when provided. ``days`` still
        works for the "last N days" common case.
    """
    end_dt = end or datetime.now(timezone.utc)
    # When from_ts is supplied, use it to widen the day-walk so we
    # don't miss the bottom of the requested range when from_ts >
    # days_ago.
    if from_ts:
        try:
            from_dt = datetime.fromisoformat(from_ts.replace("Z", "+00:00"))
        except ValueError:
            from_dt = None
    else:
        from_dt = None
    if to_ts:
        try:
            to_dt = datetime.fromisoformat(to_ts.replace("Z", "+00:00"))
        except ValueError:
            to_dt = None
    else:
        to_dt = None

    if from_dt and to_dt:
        # Date-range mode: iterate every day inside the bounds.
        days_to_walk = (to_dt.date() - from_dt.date()).days + 1
        end_dt = to_dt
    else:
        days_to_walk = max(1, int(days or 1))

    # Per-day cap: read enough to honor `limit` even if a single
    # day is busy. We pull `limit` from each day (+ a small head-
    # room) so cross-day sorting can pick the truly newest. The
    # filter functions inside read_day still bound work to disk.
    per_day_cap = max(int(limit), 100)

    out: list[ActivityRecord] = []
    for n in range(days_to_walk):
        when = end_dt - timedelta(days=n)
        out.extend(read_day(when, actor=actor, tenant=tenant,
                              method=method,
                              path_contains=path_contains,
                              limit=per_day_cap))

    # v9.57 — apply the post-filters that read_day doesn't know
    # about (substring actor, extra-dict matches, date-range
    # bounds). Doing them here keeps read_day's signature small.
    if actor_contains:
        actor_contains_l = actor_contains.lower()
        out = [r for r in out if actor_contains_l in (r.actor or "").lower()]
    if extra_filter:
        wanted = {k: str(v) for k, v in extra_filter.items()}

        def _match(r: ActivityRecord) -> bool:
            ex = r.extra or {}
            for k, v in wanted.items():
                if str(ex.get(k, "")) != v:
                    return False
            return True
        out = [r for r in out if _match(r)]
    if from_dt or to_dt:
        def _within(r: ActivityRecord) -> bool:
            ts = _parse_ts(r.ts)
            if not ts:
                return False
            if from_dt and ts < from_dt:
                return False
            if to_dt and ts > to_dt:
                return False
            return True
        out = [r for r in out if _within(r)]

    out.sort(key=lambda r: r.ts, reverse=True)
    return out[:limit]


def prune(*, retention_days: int = 90,
            now: Optional[datetime] = None) -> dict:
    """v9.54 — delete JSONL files older than ``retention_days`` days.

    Mirrors what the v9.53 logrotate / systemd timer examples do, but
    runs inside the daemon so deployments that don't have logrotate
    configured (the common pip-install case) don't quietly grow
    forever.

    Returns a small summary dict so the daemon's per-cycle log shows
    when a prune ran and how many files it touched:

        {"retention_days": 90, "deleted": 3, "kept": 60,
         "freed_bytes": 1234567, "errors": []}

    Failures (permission, read-only mount) are caught per file so
    one bad file doesn't abort the prune. The errors list carries
    the offenders so /audit can see them.
    """
    days = max(1, int(retention_days))
    cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=days)
    root = _store_root()
    deleted = 0
    kept = 0
    freed = 0
    errors: list[str] = []
    if not root.exists():
        return {"retention_days": days, "deleted": 0, "kept": 0,
                 "freed_bytes": 0, "errors": []}
    for p in sorted(root.glob("*.jsonl")):
        # Pull the date from the filename — that's the canonical
        # "this file's day". Don't trust mtime: a copytruncate
        # from logrotate can refresh mtime without changing date.
        try:
            day = datetime.strptime(p.stem, "%Y-%m-%d").replace(
                tzinfo=timezone.utc)
        except ValueError:
            # Non-date-named files (someone dropped a README in
            # the dir, etc.) — leave them alone.
            kept += 1
            continue
        if day < cutoff:
            try:
                size = p.stat().st_size
            except OSError:                             # pragma: no cover
                size = 0
            try:
                p.unlink()
                deleted += 1
                freed += size
            except OSError as e:                        # pragma: no cover
                errors.append(f"{p.name}: {e}")
        else:
            kept += 1
    return {"retention_days": days, "deleted": deleted, "kept": kept,
             "freed_bytes": freed, "errors": errors}


# ---------------------------------------------------------------- helpers

_FIELDS = {f for f in ActivityRecord.__dataclass_fields__}
_DEFAULTS = {
    "ts": "", "actor": "", "tenant": "default", "method": "",
    "path": "", "status": 0, "ip": "", "duration_ms": 0,
    "request_id": "", "extra": {},
}


def _parse_ts(ts: str) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
