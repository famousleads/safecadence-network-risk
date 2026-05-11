"""
Best-effort error log at ``~/.safecadence/errors.jsonl``.

Each line is a single JSON object: ``{ts, type, message, context}``.
Records are appended on every uncaught middleware exception and on
explicit calls to :func:`record_error`. The /api/v1/admin/errors
endpoint returns the last 100 entries for the operator console.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import traceback
from pathlib import Path
from typing import Any


def _errors_path() -> Path:
    root = os.environ.get("SAFECADENCE_HOME") or os.environ.get("SC_AUTH_HOME")
    base = Path(root) if root else Path.home() / ".safecadence"
    base.mkdir(parents=True, exist_ok=True)
    return base / "errors.jsonl"


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def record_error(exc: BaseException, context: dict | None = None) -> bool:
    """Append one error row. Never raises."""
    try:
        row = {
            "ts": _now_iso(),
            "type": exc.__class__.__name__,
            "message": str(exc)[:500],
            "traceback": "".join(traceback.format_exception(exc))[-4000:],
            "context": context or {},
        }
        with _errors_path().open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, separators=(",", ":")) + "\n")
        return True
    except Exception:
        return False


def recent_errors(limit: int = 100) -> list[dict]:
    """Return the last ``limit`` errors (newest first)."""
    path = _errors_path()
    if not path.exists():
        return []
    rows: list[dict] = []
    try:
        with path.open("r", encoding="utf-8") as fh:
            for ln in fh:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    rows.append(json.loads(ln))
                except Exception:
                    continue
    except Exception:
        return []
    rows.reverse()
    return rows[: max(limit, 0)]


def recent_error_count(window_seconds: int = 3600) -> int:
    """Count errors logged in the last ``window_seconds``."""
    if window_seconds <= 0:
        return 0
    cutoff = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(seconds=window_seconds)
    cutoff_iso = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")
    n = 0
    path = _errors_path()
    if not path.exists():
        return 0
    try:
        with path.open("r", encoding="utf-8") as fh:
            for ln in fh:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    obj = json.loads(ln)
                except Exception:
                    continue
                if obj.get("ts", "") >= cutoff_iso:
                    n += 1
    except Exception:
        return 0
    return n


__all__ = ["record_error", "recent_errors", "recent_error_count"]
