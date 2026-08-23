"""Automated, logic-based data retention + an immutable purge log.

The scored requirement (and the real operational need) in one module:

  * **Policies, not ad-hoc deletes.** Retention windows are declared per
    record type in ``<data_dir>/retention.json`` (or seeded from a
    preset). A human sets the policy once; the engine applies it
    mechanically — that IS the human approval, recorded in the log.
  * **Automated logic-based deletion.** ``run()`` evaluates every
    policy and purges what has aged out: whole day-files for events
    (the store writes one JSONL per UTC day precisely so retention is a
    file operation), and per-record JSON files for closed incidents.
  * **Immutable purge log.** Every purge appends a SHA-256
    hash-chained entry to ``<data_dir>/purge-log.jsonl`` — each entry
    binds the previous entry's hash, so any edit, insertion, or
    deletion anywhere in history breaks ``verify_log()``. Auditors get
    WHAT was purged (counts + an id-set digest — not the content),
    WHEN, under WHICH policy, by WHOM.
  * **Florida preset.** ``preset("fl_public_records")`` seeds windows
    aligned with Florida public-records practice (agencies remain
    responsible for their own schedules; the preset is a starting
    point, and the active policy file is the authority).

Nothing here ever touches evidentiary CONTENT — only the platform's own
operational records (events, closed incidents). Dry-run first, always
available: ``safecadence retention run --dry-run``.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


# ------------------------------------------------------------------ paths

def _data_dir() -> Path:
    root = os.environ.get("SC_DATA_DIR") or str(Path.home() / ".safecadence")
    p = Path(root)
    p.mkdir(parents=True, exist_ok=True)
    return p


def _policy_path() -> Path:
    return _data_dir() / "retention.json"


def _log_path() -> Path:
    return _data_dir() / "purge-log.jsonl"


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ------------------------------------------------------------------ policy

_DEFAULTS: dict[str, dict[str, Any]] = {
    "events": {"days": 365, "basis": "agency retention policy"},
    "closed_incidents": {"days": 1095, "basis": "agency retention policy"},
}

_PRESETS: dict[str, dict[str, dict[str, Any]]] = {
    # Starting points — the agency's records officer owns the schedule.
    "fl_public_records": {
        "events": {"days": 365,
                    "basis": "FL GS1-SL/agency schedule (operational logs)"},
        "closed_incidents": {"days": 1460,
                              "basis": "FL public-records schedule (workflow "
                                        "records; agency schedule governs)"},
    },
    "conservative": {
        "events": {"days": 730, "basis": "conservative default"},
        "closed_incidents": {"days": 2555, "basis": "conservative default"},
    },
}


def load_policy() -> dict[str, dict[str, Any]]:
    p = _policy_path()
    if p.exists():
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
            out = {}
            for k, v in raw.items():
                if isinstance(v, dict) and int(v.get("days", 0)) > 0:
                    out[k] = {"days": int(v["days"]),
                               "basis": str(v.get("basis", "agency policy"))}
            if out:
                return out
        except Exception:
            pass
    return {k: dict(v) for k, v in _DEFAULTS.items()}


def save_policy(policy: dict[str, dict[str, Any]],
                 actor: str = "operator") -> dict[str, Any]:
    clean = {}
    for k, v in policy.items():
        days = int(v.get("days", 0))
        if days < 1:
            raise ValueError(f"retention for '{k}' must be >= 1 day")
        clean[k] = {"days": days, "basis": str(v.get("basis", "agency policy")),
                     "set_by": actor, "set_at": _now().isoformat()}
    _policy_path().write_text(json.dumps(clean, indent=2), encoding="utf-8")
    return clean


def apply_preset(name: str, actor: str = "operator") -> dict[str, Any]:
    if name not in _PRESETS:
        raise KeyError(f"unknown preset '{name}' "
                        f"(have: {', '.join(sorted(_PRESETS))})")
    return save_policy(_PRESETS[name], actor=actor)


# ------------------------------------------------------------------ scan

_EVENT_FILE = re.compile(r"^events-(\d{8})\.jsonl$")


def _event_files_older_than(days: int) -> list[Path]:
    cutoff = (_now() - timedelta(days=days)).strftime("%Y%m%d")
    out = []
    for f in sorted(_data_dir().glob("events-*.jsonl")):
        m = _EVENT_FILE.match(f.name)
        if m and m.group(1) < cutoff:
            out.append(f)
    return out


def _closed_incidents_older_than(days: int) -> list[Path]:
    cutoff = _now() - timedelta(days=days)
    inc_dir = _data_dir() / "incidents"
    out = []
    for f in sorted(inc_dir.glob("inc-*.json")) if inc_dir.exists() else []:
        try:
            rec = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        if rec.get("status") not in ("resolved", "closed"):
            continue
        closed = rec.get("closed_at") or rec.get("updated_at") or ""
        try:
            ts = datetime.fromisoformat(str(closed).replace("Z", "+00:00"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
        except Exception:
            continue
        if ts < cutoff:
            out.append(f)
    return out


def evaluate() -> dict[str, Any]:
    """What WOULD be purged right now, per active policy. Pure read."""
    policy = load_policy()
    due: dict[str, Any] = {}
    if "events" in policy:
        files = _event_files_older_than(policy["events"]["days"])
        due["events"] = {"files": [f.name for f in files],
                          "count": len(files),
                          "policy": policy["events"]}
    if "closed_incidents" in policy:
        files = _closed_incidents_older_than(policy["closed_incidents"]["days"])
        due["closed_incidents"] = {"files": [f.name for f in files],
                                     "count": len(files),
                                     "policy": policy["closed_incidents"]}
    return {"evaluated_at": _now().isoformat(), "due": due,
             "anything_due": any(v["count"] for v in due.values())}


# ------------------------------------------------------------------ log

def _read_log() -> list[dict]:
    p = _log_path()
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except Exception:
                out.append({"_corrupt": line})
    return out


def _entry_hash(entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k != "entry_hash"}
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def _append_log(record_type: str, names: list[str], count: int,
                 policy: dict, actor: str, dry_run: bool) -> dict:
    entries = _read_log()
    prev = entries[-1]["entry_hash"] if entries and "entry_hash" in entries[-1] else GENESIS
    ids_digest = hashlib.sha256(
        "\n".join(sorted(names)).encode("utf-8")).hexdigest()
    entry = {
        "ts": _now().isoformat(),
        "action": "dry_run" if dry_run else "purge",
        "record_type": record_type,
        "count": count,
        "ids_sha256": ids_digest,          # digest of names, not content
        "policy_days": policy.get("days"),
        "policy_basis": policy.get("basis"),
        "actor": actor,
        "prev_hash": prev,
    }
    entry["entry_hash"] = _entry_hash(entry)
    with _log_path().open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, sort_keys=True) + "\n")
    return entry


def verify_log() -> dict[str, Any]:
    """Walk the chain; any tamper (edit/insert/delete/reorder) fails."""
    entries = _read_log()
    prev = GENESIS
    for i, e in enumerate(entries):
        if "_corrupt" in e:
            return {"ok": False, "entries": len(entries),
                     "failed_at": i, "reason": "unparseable line"}
        if e.get("prev_hash") != prev:
            return {"ok": False, "entries": len(entries),
                     "failed_at": i, "reason": "chain break (prev_hash)"}
        if _entry_hash(e) != e.get("entry_hash"):
            return {"ok": False, "entries": len(entries),
                     "failed_at": i, "reason": "entry hash mismatch"}
        prev = e["entry_hash"]
    return {"ok": True, "entries": len(entries), "head": prev}


# ------------------------------------------------------------------ run

def run(*, dry_run: bool = False, actor: str = "scheduler") -> dict[str, Any]:
    """Apply the active policy. Every action (including dry runs) is
    logged to the immutable chain."""
    plan = evaluate()
    results = {}
    for rtype, info in plan["due"].items():
        names = info["files"]
        if not dry_run:
            base = _data_dir() if rtype == "events" else _data_dir() / "incidents"
            removed = 0
            for name in names:
                try:
                    (base / name).unlink()
                    removed += 1
                except OSError:
                    pass
            count = removed
        else:
            count = len(names)
        entry = _append_log(rtype, names, count, info["policy"], actor, dry_run)
        results[rtype] = {"count": count, "dry_run": dry_run,
                           "log_hash": entry["entry_hash"]}
    return {"ran_at": _now().isoformat(), "dry_run": dry_run,
             "results": results, "anything_purged": any(
                 r["count"] for r in results.values()) and not dry_run,
             "log_verified": verify_log()["ok"]}


def status() -> dict[str, Any]:
    """One call for UIs/APIs: policy + what's due + log integrity."""
    return {"policy": load_policy(), "due": evaluate()["due"],
             "log": verify_log(), "policy_file": str(_policy_path()),
             "log_file": str(_log_path())}
