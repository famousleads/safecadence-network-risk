"""
Usage metering for v10.9 quota enforcement.

Records every asset add / report generation / API call as a one-line
JSON event in ``~/.safecadence/orgs/<org_id>/usage.jsonl``. Aggregation
is computed on read; the on-disk log is append-only so it doubles as
an audit trail.

Public API
----------
``record_usage(org_id, resource, count=1, meta=None)``
``get_usage(org_id, period="month")``
``get_usage_history(org_id, resource, months=6)``

``record_usage`` is a no-op when ``SC_READONLY=1`` (demo droplet).
``get_usage`` returns ``{}`` for unknown / missing orgs.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import threading
from pathlib import Path
from typing import Any

_LOCK = threading.Lock()

_VALID_RESOURCES = ("assets", "reports", "api_calls")


def _usage_path(org_id: str) -> Path:
    from safecadence.storage.org_store import org_data_dir
    return org_data_dir(org_id) / "usage.jsonl"


def _is_readonly() -> bool:
    return os.environ.get("SC_READONLY", "") == "1"


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _period_key(ts_iso: str, *, period: str = "month") -> str:
    """Return ``YYYY-MM`` for monthly, ``YYYY-MM-DD`` for daily."""
    try:
        ts = _dt.datetime.fromisoformat(ts_iso.replace("Z", "+00:00"))
    except Exception:
        return ""
    if period == "day":
        return ts.strftime("%Y-%m-%d")
    return ts.strftime("%Y-%m")


def _current_period_key(period: str = "month") -> str:
    return _period_key(_now_iso(), period=period)


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def record_usage(org_id: str, resource: str, count: int = 1,
                  meta: dict | None = None) -> dict | None:
    """Append a usage event. Returns the event dict (or ``None`` if skipped)."""
    if not org_id:
        return None
    if resource not in _VALID_RESOURCES:
        raise ValueError(f"Unknown resource: {resource!r}")
    if _is_readonly():
        return None
    if count <= 0:
        return None
    event = {
        "ts": _now_iso(),
        "org_id": org_id,
        "resource": resource,
        "count": int(count),
    }
    if meta:
        event["meta"] = meta
    path = _usage_path(org_id)
    with _LOCK:
        with path.open("a", encoding="utf-8") as fp:
            fp.write(json.dumps(event) + "\n")
    return event


def get_usage(org_id: str, period: str = "month") -> dict:
    """Aggregate usage for the current period (or ``"all"``).

    Returns ``{"assets": int, "reports": int, "api_calls": int, "period": "YYYY-MM"}``
    """
    out: dict[str, Any] = {r: 0 for r in _VALID_RESOURCES}
    if not org_id:
        out["period"] = _current_period_key(period if period != "all" else "month")
        return out
    path = _usage_path(org_id)
    if not path.exists():
        out["period"] = _current_period_key(period if period != "all" else "month")
        return out
    target = _current_period_key(period) if period in ("day", "month") else None
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except Exception:
                continue
            if target is not None:
                if _period_key(ev.get("ts") or "", period=period) != target:
                    continue
            r = ev.get("resource")
            if r in out:
                out[r] += int(ev.get("count") or 0)
    except Exception:
        pass
    out["period"] = target or "all"
    return out


def get_usage_history(org_id: str, resource: str,
                       months: int = 6) -> list[dict]:
    """Return ``[{period: 'YYYY-MM', count: N}, ...]`` for the last N months."""
    if resource not in _VALID_RESOURCES:
        raise ValueError(f"Unknown resource: {resource!r}")
    if not org_id:
        return []
    path = _usage_path(org_id)
    if not path.exists():
        return []
    buckets: dict[str, int] = {}
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except Exception:
                continue
            if ev.get("resource") != resource:
                continue
            key = _period_key(ev.get("ts") or "", period="month")
            if not key:
                continue
            buckets[key] = buckets.get(key, 0) + int(ev.get("count") or 0)
    except Exception:
        return []
    # Build window of the last N months ending with current.
    today = _dt.datetime.now(_dt.timezone.utc).replace(day=1)
    out: list[dict] = []
    for i in range(months - 1, -1, -1):
        year = today.year
        month = today.month - i
        while month <= 0:
            month += 12
            year -= 1
        key = f"{year:04d}-{month:02d}"
        out.append({"period": key, "count": buckets.get(key, 0)})
    return out


def reset_usage_for_tests(org_id: str) -> None:
    """Wipe the usage log. Test-only — not part of the public API."""
    if not org_id:
        return
    path = _usage_path(org_id)
    if path.exists():
        path.unlink()


__all__ = [
    "record_usage",
    "get_usage",
    "get_usage_history",
    "reset_usage_for_tests",
]
