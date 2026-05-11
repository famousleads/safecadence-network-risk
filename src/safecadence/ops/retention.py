"""
v11.3 — Per-org data retention policies.

Each org carries a small ``retention.json`` file at the root of its
data dir::

    {
      "scans":   {"keep_days": 365, "keep_min_count": 50},
      "audit":   {"keep_days": 730, "keep_min_count": 50},
      "reports": {"keep_days": 180, "keep_min_count": 50},
      "errors":  {"keep_days":  90, "keep_min_count": 50}
    }

:func:`apply_retention` walks the four kinds and deletes (or truncates)
items older than ``keep_days``, always keeping at least
``keep_min_count`` of the most recent items per kind. The function
returns a small report of what was purged for use in operator
audit trails / CLI output.

Storage shapes per kind:

* ``scans``   — JSONL at ``scan_history.jsonl`` (one row per scan).
* ``audit``   — JSONL at ``audit.jsonl`` AND ``audit_chain.jsonl``
* ``reports`` — JSON files at ``reports/saved/<id>.json``
* ``errors``  — JSONL at ``errors.jsonl`` (best-effort)

Operators can call :func:`set_retention` programmatically; the CLI at
``safecadence ops retention …`` is the user-facing surface.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import json
from pathlib import Path
from typing import Literal


KIND = Literal["scans", "audit", "reports", "errors"]
VALID_KINDS: tuple[str, ...] = ("scans", "audit", "reports", "errors")


@dataclasses.dataclass
class RetentionPolicy:
    """How long to keep one kind of data and the floor count to preserve."""

    kind: str                  # "scans"|"audit"|"reports"|"errors"
    keep_days: int             # max age in days
    keep_min_count: int = 50   # always retain at least this many

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "keep_days": int(self.keep_days),
            "keep_min_count": int(self.keep_min_count),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "RetentionPolicy":
        return cls(
            kind=str(d.get("kind") or ""),
            keep_days=int(d.get("keep_days") or 0),
            keep_min_count=int(d.get("keep_min_count") or 0),
        )


def default_policies() -> dict[str, RetentionPolicy]:
    return {
        "scans":   RetentionPolicy("scans",   365, 50),
        "audit":   RetentionPolicy("audit",   730, 50),
        "reports": RetentionPolicy("reports", 180, 50),
        "errors":  RetentionPolicy("errors",   90, 50),
    }


def _org_dir(org_id: str) -> Path:
    from safecadence.storage.org_store import org_data_dir
    return org_data_dir(org_id)


def _retention_path(org_id: str) -> Path:
    return _org_dir(org_id) / "retention.json"


def get_retention(org_id: str) -> dict[str, RetentionPolicy]:
    """Return the current policy dict for ``org_id`` (defaults applied)."""
    out = default_policies()
    path = _retention_path(org_id)
    if path.exists():
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            for kind, spec in (raw or {}).items():
                if kind in VALID_KINDS and isinstance(spec, dict):
                    out[kind] = RetentionPolicy(
                        kind=kind,
                        keep_days=int(spec.get("keep_days") or out[kind].keep_days),
                        keep_min_count=int(spec.get("keep_min_count") or out[kind].keep_min_count),
                    )
        except Exception:
            pass
    return out


def set_retention(org_id: str, policy: RetentionPolicy) -> dict[str, RetentionPolicy]:
    """Persist a single-kind policy update. Returns the new full set."""
    if policy.kind not in VALID_KINDS:
        raise ValueError(f"unknown retention kind: {policy.kind!r}")
    if policy.keep_days < 1:
        raise ValueError("keep_days must be >= 1")
    if policy.keep_min_count < 0:
        raise ValueError("keep_min_count must be >= 0")
    current = get_retention(org_id)
    current[policy.kind] = policy
    raw = {k: p.to_dict() for k, p in current.items()}
    path = _retention_path(org_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(raw, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(path)
    return current


def _cutoff_iso(days: int) -> str:
    cutoff = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=days)
    return cutoff.isoformat() + "Z"


def _ts_from_row(row: dict) -> str:
    """Extract a sortable timestamp string from a row, best-effort."""
    for key in ("ts", "timestamp", "created_at", "completed_at", "scanned_at"):
        v = row.get(key)
        if isinstance(v, str) and v:
            return v
        if isinstance(v, (int, float)) and v > 0:
            try:
                return _dt.datetime.fromtimestamp(v, _dt.timezone.utc).isoformat() + "Z"
            except Exception:
                pass
    return ""


def _prune_jsonl(path: Path, *, keep_days: int, keep_min_count: int) -> dict:
    """Truncate a JSONL file in place using retention rules."""
    if not path.exists():
        return {"path": str(path), "before": 0, "after": 0, "purged": 0}
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
        return {"path": str(path), "before": 0, "after": 0, "purged": 0}
    before = len(rows)
    cutoff = _cutoff_iso(keep_days)
    # Keep rows that are either (a) inside the retention window OR
    # (b) part of the most-recent N rows (where N = keep_min_count).
    # First sort by ts so "most recent" is well-defined.
    rows.sort(key=lambda r: _ts_from_row(r))
    floor_index = max(0, len(rows) - keep_min_count)
    kept: list[dict] = []
    for idx, r in enumerate(rows):
        ts = _ts_from_row(r)
        if not ts or ts >= cutoff or idx >= floor_index:
            kept.append(r)
    after = len(kept)
    # Atomic rewrite
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        for r in kept:
            fh.write(json.dumps(r, separators=(",", ":")) + "\n")
    tmp.replace(path)
    return {
        "path": str(path),
        "before": before,
        "after": after,
        "purged": before - after,
    }


def _prune_report_files(reports_dir: Path, *, keep_days: int, keep_min_count: int) -> dict:
    """Delete oldest report JSONs past retention."""
    if not reports_dir.exists():
        return {"path": str(reports_dir), "before": 0, "after": 0, "purged": 0}
    files = sorted(
        [p for p in reports_dir.glob("*.json") if p.is_file()],
        key=lambda p: p.stat().st_mtime,
    )
    before = len(files)
    cutoff_ts = (
        _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=keep_days)
    ).timestamp()
    floor_index = max(0, len(files) - keep_min_count)
    purged = 0
    for idx, p in enumerate(files):
        if idx >= floor_index:
            continue   # protected by min-count floor
        if p.stat().st_mtime >= cutoff_ts:
            continue   # inside retention window
        try:
            p.unlink()
            purged += 1
        except Exception:
            continue
    return {
        "path": str(reports_dir),
        "before": before,
        "after": before - purged,
        "purged": purged,
    }


def apply_retention(org_id: str) -> dict:
    """Run the retention pass for ``org_id`` once. Returns a report."""
    pol = get_retention(org_id)
    base = _org_dir(org_id)
    report: dict[str, dict] = {}

    # 1. Scans — JSONL
    report["scans"] = _prune_jsonl(
        base / "scan_history.jsonl",
        keep_days=pol["scans"].keep_days,
        keep_min_count=pol["scans"].keep_min_count,
    )

    # 2. Audit — both files
    audit_main = _prune_jsonl(
        base / "audit.jsonl",
        keep_days=pol["audit"].keep_days,
        keep_min_count=pol["audit"].keep_min_count,
    )
    audit_chain = _prune_jsonl(
        base / "audit_chain.jsonl",
        keep_days=pol["audit"].keep_days,
        keep_min_count=pol["audit"].keep_min_count,
    )
    report["audit"] = {
        "before": audit_main["before"] + audit_chain["before"],
        "after": audit_main["after"] + audit_chain["after"],
        "purged": audit_main["purged"] + audit_chain["purged"],
        "files": [audit_main, audit_chain],
    }

    # 3. Reports — directory of JSON files
    report["reports"] = _prune_report_files(
        base / "reports" / "saved",
        keep_days=pol["reports"].keep_days,
        keep_min_count=pol["reports"].keep_min_count,
    )

    # 4. Errors — JSONL
    report["errors"] = _prune_jsonl(
        base / "errors.jsonl",
        keep_days=pol["errors"].keep_days,
        keep_min_count=pol["errors"].keep_min_count,
    )

    total_purged = sum(int(v.get("purged") or 0) for v in report.values())
    report["total_purged"] = total_purged   # type: ignore[assignment]
    return report


__all__ = [
    "RetentionPolicy",
    "VALID_KINDS",
    "default_policies",
    "get_retention",
    "set_retention",
    "apply_retention",
]
