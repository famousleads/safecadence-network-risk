"""SafeCheck — the check-in timer that watches the watcher.

A deputy starts a solo building check, a traffic stop on a dead
stretch, an evidence-room audit at 2 AM. They start a SafeCheck:
"if I don't clear this in N minutes, alert my shift." If the timer
runs out, Mass Notification sends the alert with the last known
location — pre-authorized BY THAT OFFICER at the moment they started
the timer, so the named-human-approval rule holds even when the human
can no longer respond. That is the point.

Every start / extend / clear / overdue-alert lands in a hash-chained
log. Runs entirely on the agency's hardware, like everything else.

Storage: ``<SC_DATA_DIR>/safecheck/`` (active/*.json + chained log).
"""
from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _root() -> Path:
    base = os.environ.get("SC_DATA_DIR") or str(Path.home() / ".safecadence")
    p = Path(base) / "safecheck"
    (p / "active").mkdir(parents=True, exist_ok=True)
    return p


def _entry_hash(body: dict) -> str:
    canon = json.dumps({k: v for k, v in body.items() if k != "entry_hash"},
                        sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def _log(entry: dict) -> dict:
    f = _root() / "safecheck-log.jsonl"
    prev = GENESIS
    if f.exists():
        lines = f.read_text(encoding="utf-8").strip().splitlines()
        if lines:
            try:
                prev = json.loads(lines[-1]).get("entry_hash", GENESIS)
            except Exception:
                prev = GENESIS
    entry["prev_hash"] = prev
    entry["entry_hash"] = _entry_hash(entry)
    with f.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return entry


def verify_log() -> dict:
    f = _root() / "safecheck-log.jsonl"
    if not f.exists():
        return {"ok": True, "entries": 0}
    prev, n = GENESIS, 0
    for line in f.read_text(encoding="utf-8").strip().splitlines():
        try:
            e = json.loads(line)
        except Exception:
            return {"ok": False, "entries": n, "reason": "unparseable"}
        if e.get("prev_hash") != prev or _entry_hash(e) != e.get("entry_hash"):
            return {"ok": False, "entries": n, "failed_at": e.get("check_id"),
                     "reason": "chain broken"}
        prev, n = e["entry_hash"], n + 1
    return {"ok": True, "entries": n}


# ================================================================ lifecycle

def start_check(*, officer: str, location: str, minutes: int = 15,
                 notify_group: str = "", note: str = "") -> dict[str, Any]:
    """Start a timer. The officer starting it IS the named approver for
    the overdue alert — recorded here, at the moment of consent."""
    if not (officer or "").strip():
        raise ValueError("officer is required")
    if not (location or "").strip():
        raise ValueError("location is required")
    minutes = max(1, min(240, int(minutes)))
    rec = {
        "check_id": f"sc-{uuid.uuid4().hex[:10]}",
        "officer": str(officer).strip()[:120],
        "location": str(location).strip()[:200],
        "note": str(note or "").strip()[:300],
        "started_at": _now().isoformat(),
        "due_at": (_now() + timedelta(minutes=minutes)).isoformat(),
        "minutes": minutes,
        "notify_group": str(notify_group or "").strip()[:80],
        "pre_authorized_by": str(officer).strip()[:120],
        "status": "active",
        "alerted": False,
    }
    (_root() / "active" / f"{rec['check_id']}.json").write_text(
        json.dumps(rec, indent=1), encoding="utf-8")
    _log({"check_id": rec["check_id"], "at": rec["started_at"],
           "action": "started", "officer": rec["officer"],
           "location": rec["location"], "minutes": minutes,
           "notify_group": rec["notify_group"]})
    return rec


def _active_file(check_id: str) -> Path:
    return _root() / "active" / f"{check_id}.json"


def _load_active(check_id: str) -> dict | None:
    f = _active_file(check_id)
    if not f.exists():
        return None
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except Exception:
        return None


def list_active() -> list[dict]:
    out = []
    for f in sorted((_root() / "active").glob("*.json")):
        try:
            rec = json.loads(f.read_text(encoding="utf-8"))
            rec["overdue"] = _now().isoformat() > rec.get("due_at", "")
            out.append(rec)
        except Exception:
            continue
    out.sort(key=lambda r: r.get("due_at", ""))
    return out


def extend_check(check_id: str, minutes: int = 10) -> dict:
    rec = _load_active(check_id)
    if not rec:
        raise KeyError("active check not found")
    minutes = max(1, min(120, int(minutes)))
    rec["due_at"] = (max(_now(), datetime.fromisoformat(rec["due_at"]))
                      + timedelta(minutes=minutes)).isoformat()
    rec["alerted"] = False
    _active_file(check_id).write_text(json.dumps(rec, indent=1),
                                        encoding="utf-8")
    _log({"check_id": check_id, "at": _now().isoformat(),
           "action": "extended", "officer": rec["officer"],
           "minutes": minutes})
    return rec


def clear_check(check_id: str, officer: str = "") -> dict:
    rec = _load_active(check_id)
    if not rec:
        raise KeyError("active check not found")
    rec["status"] = "cleared"
    rec["cleared_at"] = _now().isoformat()
    _active_file(check_id).unlink(missing_ok=True)
    _log({"check_id": check_id, "at": rec["cleared_at"],
           "action": "cleared", "officer": officer or rec["officer"],
           "location": rec["location"]})
    return rec


# ================================================================ sweep

def sweep(live: bool | None = None) -> dict[str, Any]:
    """Find overdue checks and fire the pre-authorized alert through
    Mass Notification (once per check; extend re-arms it). Honors
    notify test/live mode."""
    alerted, overdue = [], []
    for rec in list_active():
        if not rec.get("overdue") or rec.get("alerted"):
            if rec.get("overdue"):
                overdue.append(rec["check_id"])
            continue
        overdue.append(rec["check_id"])
        result: dict[str, Any] = {"sent": False}
        if rec.get("notify_group"):
            try:
                from safecadence import mass_notify
                out = mass_notify.send_notification(
                    group=rec["notify_group"],
                    subject=f"SAFECHECK OVERDUE - {rec['officer']}",
                    body=(f"{rec['officer']} started a {rec['minutes']}-min "
                           f"check at {rec['location']} "
                           f"({rec['started_at'][11:16]}Z) and has not "
                           f"cleared it. Last note: "
                           f"{rec.get('note') or 'none'}. Attempt contact, "
                           "then send a unit."),
                    initiated_by="SafeCheck timer",
                    approved_by=rec["pre_authorized_by"] +
                                 " (pre-authorized at check start)",
                    force=True, live=live)
                result = {"sent": True, "mode": out.get("mode"),
                           "alert_id": out.get("id")}
            except Exception as exc:
                result = {"sent": False, "error": str(exc)[:200]}
        rec["alerted"] = True
        rec["alert_result"] = result
        _active_file(rec["check_id"]).write_text(
            json.dumps(rec, indent=1), encoding="utf-8")
        _log({"check_id": rec["check_id"], "at": _now().isoformat(),
               "action": "overdue_alert", "officer": rec["officer"],
               "location": rec["location"], "result": result})
        alerted.append({"check_id": rec["check_id"], **result})
    return {"active": len(list_active()), "overdue": overdue,
             "alerts_fired": alerted}


def summary() -> dict[str, Any]:
    active = list_active()
    v = verify_log()
    return {"active": len(active),
             "overdue": sum(1 for r in active if r.get("overdue")),
             "log_entries": v.get("entries", 0), "log_ok": v.get("ok")}
