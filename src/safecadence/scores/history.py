"""
v9.25 — Safe Score history store.

Persists one snapshot per write into a single JSON file at
``$SC_DATA_DIR/score_history.json``. Each snapshot captures the
fleet-wide Safe Score plus the per-asset score so we can answer
both "how did the fleet do over time" and "show me this asset's
trend."

Storage shape (intentionally flat for forward-compat):

    {
      "snapshots": [
        {
          "ts": "2026-05-06T11:30:00+00:00",
          "fleet_score": 73,
          "fleet_band": "C",
          "asset_count": 31,
          "per_asset": {"edge-fw-01": 64, "core-sw-01": 81, ...}
        },
        ...
      ]
    }

Retention:
  * Default: 90 days. Older snapshots dropped on every write.
  * One snapshot per cycle is plenty — a 30-min daemon = 1.4k
    snapshots over 90 days, well under any size concern.
  * If the file exceeds ~5MB we trim to the most recent 1000
    snapshots regardless of age (defense against runaway growth).

Reads are tolerant: missing/corrupt file → empty list.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional


_RETENTION_DAYS_DEFAULT = 90
_HARD_CAP_SNAPSHOTS = 1000
_SOFT_CAP_BYTES = 5 * 1024 * 1024  # 5 MB


def _store_path() -> Path:
    home = os.environ.get("SC_DATA_DIR") or os.environ.get("SAFECADENCE_HOME") \
            or str(Path.home() / ".safecadence")
    p = Path(home)
    p.mkdir(parents=True, exist_ok=True)
    return p / "score_history.json"


def _read_all() -> list[dict]:
    p = _store_path()
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8")) or {}
        return list(data.get("snapshots") or [])
    except Exception:
        return []


def _write_all(snapshots: list[dict]) -> None:
    p = _store_path()
    p.write_text(json.dumps({"snapshots": snapshots},
                              separators=(",", ":")),
                  encoding="utf-8")


def append_snapshot(fleet_result: dict, *,
                     when: Optional[datetime] = None,
                     retention_days: int = _RETENTION_DAYS_DEFAULT) -> dict:
    """Append a snapshot from a `score_fleet_safe()` result.

    Args:
        fleet_result: the dict returned by
                      ``safecadence.scores.score_fleet_safe()``
        when: timestamp; defaults to now (UTC)
        retention_days: drop snapshots older than this many days

    Returns the snapshot that was written (handy for tests).
    """
    when = when or datetime.now(timezone.utc)
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)

    snap = {
        "ts": when.isoformat(),
        "fleet_score": int(fleet_result.get("fleet_score", 0)),
        "fleet_band": fleet_result.get("fleet_band", ""),
        "asset_count": int(fleet_result.get("asset_count", 0)),
        "per_asset": {
            row["asset_id"]: int(row["score"])
            for row in (fleet_result.get("per_asset") or [])
            if row.get("asset_id")
        },
    }

    snapshots = _read_all()
    snapshots.append(snap)

    # Prune by age first.
    cutoff = (when - timedelta(days=retention_days)).isoformat()
    snapshots = [s for s in snapshots if s.get("ts", "") >= cutoff]

    # Hard cap on snapshot count (defense against runaway daemon).
    if len(snapshots) > _HARD_CAP_SNAPSHOTS:
        snapshots = snapshots[-_HARD_CAP_SNAPSHOTS:]

    _write_all(snapshots)

    # Soft size check: if file is huge, trim more aggressively.
    p = _store_path()
    try:
        if p.stat().st_size > _SOFT_CAP_BYTES and len(snapshots) > 100:
            snapshots = snapshots[-100:]
            _write_all(snapshots)
    except OSError:
        pass

    return snap


def fleet_history(days: int = 30) -> list[dict]:
    """Return fleet-wide score history for the last `days` days.

    Each row is ``{"ts": "...", "fleet_score": N, "fleet_band": "..."}`` —
    drops the per_asset dict so the response stays small for sparkline
    rendering.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    return [
        {"ts": s["ts"],
          "fleet_score": s.get("fleet_score", 0),
          "fleet_band": s.get("fleet_band", ""),
          "asset_count": s.get("asset_count", 0)}
        for s in _read_all() if s.get("ts", "") >= cutoff
    ]


def asset_history(asset_id: str, days: int = 30) -> list[dict]:
    """Return per-asset score history for the last `days` days.

    Snapshots that don't include this asset are skipped (e.g. asset
    didn't exist yet, or wasn't in the fleet at that time).
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    out: list[dict] = []
    for s in _read_all():
        if s.get("ts", "") < cutoff:
            continue
        per = s.get("per_asset") or {}
        if asset_id in per:
            out.append({"ts": s["ts"], "score": int(per[asset_id])})
    return out


def trend(days: int = 7) -> dict:
    """Compute the fleet trend over the last `days` days.

    Returns ``{"current": N, "previous": M, "delta": D, "direction": ...}``.
    Useful for the /home pill: "↑ +3 this week" instead of randomness.
    The "previous" value is the snapshot closest to ``days`` days ago;
    the "current" is the most recent. If there's no history the deltas
    are zero.
    """
    snaps = _read_all()
    if not snaps:
        return {"current": None, "previous": None,
                "delta": 0, "direction": "flat", "samples": 0}

    snaps = sorted(snaps, key=lambda s: s.get("ts", ""))
    current = snaps[-1].get("fleet_score", 0)
    cutoff = (datetime.now(timezone.utc)
                - timedelta(days=days)).isoformat()
    older = [s for s in snaps if s.get("ts", "") <= cutoff]
    previous = older[-1].get("fleet_score", current) if older else current
    delta = current - previous
    direction = "up" if delta > 0 else "down" if delta < 0 else "flat"
    return {"current": current, "previous": previous,
            "delta": delta, "direction": direction,
            "samples": len(snaps)}


def clear() -> None:
    """Wipe the history (test helper / 'reset' button)."""
    p = _store_path()
    if p.exists():
        p.unlink()
