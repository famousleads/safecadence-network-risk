"""
v9.28 — Control test history (SOC 2 Type 2 evidence).

Persists every control evaluation result: which control, on which
asset, when, what the outcome was, and what method we used. Auditors
need this to assert "controls operated effectively over a period"
rather than "controls existed on a date."

Storage: file-backed JSON-lines at
``$SC_DATA_DIR/control_history.jsonl`` so appends are O(1) and the
file plays nicely with rotation/log-shipping.

Retention default: 365 days (most audit windows are 12 months). The
caller can override.
"""

from __future__ import annotations

import json
import os
import time as _time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Optional


_DEFAULT_RETENTION_DAYS = 365


def _store_path() -> Path:
    home = (os.environ.get("SC_DATA_DIR")
              or os.environ.get("SAFECADENCE_HOME")
              or str(Path.home() / ".safecadence"))
    p = Path(home)
    p.mkdir(parents=True, exist_ok=True)
    return p / "control_history.jsonl"


@dataclass
class ControlTestRecord:
    ts: str
    control_id: str
    asset_id: str
    outcome: str           # pass | fail | exception | not_applicable
    method: str            # config_inspection | api_pull | log_review | manual
    sample_size: int = 1
    evidence_ref: str = ""
    evaluator: str = "daemon"   # who/what ran the test
    note: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def record(control_id: str, asset_id: str, outcome: str, *,
            method: str = "config_inspection",
            sample_size: int = 1,
            evidence_ref: str = "",
            evaluator: str = "daemon",
            note: str = "",
            when: Optional[datetime] = None) -> ControlTestRecord:
    when = when or datetime.now(timezone.utc)
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    rec = ControlTestRecord(
        ts=when.isoformat(),
        control_id=control_id, asset_id=asset_id,
        outcome=outcome, method=method, sample_size=int(sample_size),
        evidence_ref=evidence_ref, evaluator=evaluator, note=note,
    )
    p = _store_path()
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec.to_dict(), separators=(",", ":")) + "\n")
    return rec


def _iter_lines(path: Path) -> Iterable[dict]:
    if not path.exists():
        return
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except Exception:
                continue


def _parse(ts: str) -> datetime:
    try:
        out = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        if out.tzinfo is None:
            out = out.replace(tzinfo=timezone.utc)
        return out
    except Exception:
        return datetime.now(timezone.utc) - timedelta(days=10000)


def history(*, control_id: Optional[str] = None,
              asset_id: Optional[str] = None,
              days: int = 90,
              limit: int = 1000) -> list[dict]:
    """Return matching records newest-first."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    rows: list[dict] = []
    for r in _iter_lines(_store_path()):
        if control_id and r.get("control_id") != control_id:
            continue
        if asset_id and r.get("asset_id") != asset_id:
            continue
        if _parse(r.get("ts", "")) < cutoff:
            continue
        rows.append(r)
    rows.sort(key=lambda r: r.get("ts", ""), reverse=True)
    return rows[:limit]


def summary_for_evidence_pack(*, days: int = 90) -> list[dict]:
    """Per-control rollup for the evidence pack: total tests in window,
    pass/fail counts, oldest + newest sample timestamps. This is the
    Type 2 'operated effectively' artifact."""
    rows = history(days=days, limit=100_000)
    by_ctrl: dict[str, dict] = {}
    for r in rows:
        cid = r.get("control_id", "")
        if not cid:
            continue
        bucket = by_ctrl.setdefault(cid, {
            "control_id": cid, "tests": 0,
            "pass": 0, "fail": 0, "exception": 0, "not_applicable": 0,
            "first_ts": r.get("ts"), "last_ts": r.get("ts"),
        })
        bucket["tests"] += 1
        out = (r.get("outcome") or "").lower()
        if out in bucket:
            bucket[out] += 1
        ts = r.get("ts") or ""
        if ts < (bucket["first_ts"] or ts):
            bucket["first_ts"] = ts
        if ts > (bucket["last_ts"] or ""):
            bucket["last_ts"] = ts
    out = list(by_ctrl.values())
    for b in out:
        b["effectiveness_pct"] = round(
            100.0 * b["pass"] / b["tests"], 1) if b["tests"] else 0.0
    out.sort(key=lambda b: b["control_id"])
    return out


def prune(retention_days: int = _DEFAULT_RETENTION_DAYS) -> int:
    """Drop rows older than retention_days. Returns count removed."""
    p = _store_path()
    if not p.exists():
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    keep: list[str] = []
    removed = 0
    for r in _iter_lines(p):
        if _parse(r.get("ts", "")) < cutoff:
            removed += 1
            continue
        keep.append(json.dumps(r, separators=(",", ":")))
    p.write_text("\n".join(keep) + ("\n" if keep else ""),
                  encoding="utf-8")
    return removed
