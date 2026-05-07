"""
v9.18 — Fleet change report.

Tracks inventory snapshots over time, diffs them, and produces a human
report: "last 7 days: X new, Y removed, Z modified".

Snapshot strategy:
  - When `compute_changes()` runs, read the current inventory and
    write a tiny digest (asset_id → identity-hash) to disk under
    SC_DATA_DIR/inventory_snapshots/YYYY-MM-DD.json
  - To compute the diff, find the newest snapshot from `since_days` ago
    and compare every asset's hash to today's.
  - Write today's snapshot at the end of the call.

Daemon-friendly: idempotent within a day. If you call it 5x in one day,
it overwrites today's snapshot 5x (always reflecting "now") but doesn't
double-count.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Iterable


# ----------------------------------------------------------------- paths


def _snap_dir() -> Path:
    base = os.environ.get("SC_DATA_DIR") or str(Path.home() / ".safecadence")
    p = Path(base) / "inventory_snapshots"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _today_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


# -------------------------------------------------------- digest building


# Identity fields whose change should count as a "modification".
# Volatile fields (last_seen, last_collected_at) are excluded so they
# don't generate noise.
_TRACKED = (
    "hostname", "asset_type", "vendor", "model",
    "site", "environment", "owner", "team",
    "criticality", "mgmt_ip", "mgmt_url", "serial_number",
    "discovery_source",
)


def _asset_digest(asset: dict) -> tuple[str, str]:
    """(asset_id, sha256-of-tracked-fields)."""
    ident = asset.get("identity") or {}
    aid = ident.get("asset_id") or ""
    payload = "|".join(str(ident.get(k) or "") for k in _TRACKED)
    # Add tags + custom_fields too — sorted so order is stable
    tags = ",".join(sorted(ident.get("tags") or []))
    cf = ident.get("custom_fields") or {}
    cf_str = "|".join(f"{k}={cf[k]}" for k in sorted(cf))
    payload = f"{payload}|tags={tags}|cf={cf_str}"
    h = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
    return aid, h


def _build_snapshot(assets: Iterable[dict]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for a in assets:
        aid, h = _asset_digest(a)
        if not aid:
            continue
        ident = a.get("identity") or {}
        out[aid] = {
            "h": h,
            "hostname": ident.get("hostname") or "",
            "type":  ident.get("asset_type") or "",
            "vendor": ident.get("vendor") or "",
            "site":  ident.get("site") or "",
            "criticality": ident.get("criticality") or "",
        }
    return out


def write_snapshot(assets: Iterable[dict],
                   *, when: datetime | None = None) -> Path:
    """Write today's snapshot. Overwrites any existing file for today."""
    when = when or datetime.now(timezone.utc)
    snap = _build_snapshot(assets)
    f = _snap_dir() / f"{when.strftime('%Y-%m-%d')}.json"
    f.write_text(json.dumps({"written_at": when.isoformat(),
                             "asset_count": len(snap),
                             "assets": snap}, indent=2))
    return f


def _load_snapshot(date_iso: str) -> dict[str, dict] | None:
    f = _snap_dir() / f"{date_iso}.json"
    if not f.exists():
        return None
    try:
        return (json.loads(f.read_text()) or {}).get("assets") or {}
    except Exception:
        return None


def _find_baseline(since_days: int) -> tuple[str, dict[str, dict]] | None:
    """Find the newest snapshot at or before `since_days` ago.
    Returns (date_iso, snapshot) or None if no snapshot exists."""
    target = datetime.now(timezone.utc).date() - timedelta(days=since_days)
    # Walk backward from target up to 60 days, picking the first match
    for delta in range(0, 60):
        d = target - timedelta(days=delta)
        s = _load_snapshot(d.isoformat())
        if s is not None:
            return (d.isoformat(), s)
    return None


# ------------------------------------------------------------------ diff


def compute_changes(assets: list[dict],
                    *, since_days: int = 7,
                    write_today: bool = True) -> dict:
    """Compare current inventory against the newest snapshot ≤ since_days
    days old. Returns:

      {
        baseline_date, current_date, since_days,
        added:    [{asset_id, hostname, type, vendor, site, criticality}],
        removed:  [...],
        modified: [{asset_id, fields_changed: ['vendor','site',...]}],
        counts:   {added, removed, modified, by_type, by_day_added,
                   by_day_removed},
        history:  [{date, asset_count}, …]    # last 30 days for sparkline
        no_baseline: bool                      # True on first run
      }
    """
    today_snap = _build_snapshot(assets)
    today_iso = _today_iso()

    baseline = _find_baseline(since_days)
    history = _build_history(days=30)

    out: dict = {
        "baseline_date": baseline[0] if baseline else None,
        "current_date": today_iso,
        "since_days": since_days,
        "added": [], "removed": [], "modified": [],
        "counts": {"added": 0, "removed": 0, "modified": 0,
                    "by_type": {"added": {}, "removed": {}, "modified": {}}},
        "history": history,
        "no_baseline": baseline is None,
    }

    if baseline:
        baseline_snap = baseline[1]
        # Added: in today but not in baseline
        for aid, info in today_snap.items():
            if aid not in baseline_snap:
                out["added"].append({
                    "asset_id": aid, **{k: info.get(k) for k in
                                         ("hostname", "type", "vendor",
                                          "site", "criticality")}})
                t = info.get("type") or "unknown"
                out["counts"]["by_type"]["added"][t] = \
                    out["counts"]["by_type"]["added"].get(t, 0) + 1

        # Removed: in baseline but not in today
        for aid, info in baseline_snap.items():
            if aid not in today_snap:
                out["removed"].append({
                    "asset_id": aid, **{k: info.get(k) for k in
                                         ("hostname", "type", "vendor",
                                          "site", "criticality")}})
                t = info.get("type") or "unknown"
                out["counts"]["by_type"]["removed"][t] = \
                    out["counts"]["by_type"]["removed"].get(t, 0) + 1

        # Modified: same id, different hash. Diff field-by-field for
        # human-readable "what changed".
        for aid, today_info in today_snap.items():
            old = baseline_snap.get(aid)
            if not old or today_info["h"] == old["h"]:
                continue
            changed = [k for k in ("hostname", "type", "vendor", "site",
                                    "criticality")
                       if today_info.get(k) != old.get(k)]
            if today_info["h"] != old["h"] and not changed:
                changed = ["tags-or-custom-fields"]
            out["modified"].append({
                "asset_id": aid,
                "hostname": today_info.get("hostname"),
                "type": today_info.get("type"),
                "vendor": today_info.get("vendor"),
                "fields_changed": changed,
            })
            t = today_info.get("type") or "unknown"
            out["counts"]["by_type"]["modified"][t] = \
                out["counts"]["by_type"]["modified"].get(t, 0) + 1

    out["counts"]["added"] = len(out["added"])
    out["counts"]["removed"] = len(out["removed"])
    out["counts"]["modified"] = len(out["modified"])

    if write_today:
        try: write_snapshot(assets)
        except Exception: pass

    return out


def _build_history(days: int = 30) -> list[dict]:
    """Read every recent snapshot file and return [(date, asset_count), ...].
    Used for the sparkline."""
    out = []
    today = datetime.now(timezone.utc).date()
    for delta in range(days, -1, -1):
        d = today - timedelta(days=delta)
        s = _load_snapshot(d.isoformat())
        out.append({"date": d.isoformat(),
                    "asset_count": len(s) if s else None})
    return out
