"""Evidence Custody — who touched what, when, and why. Provably.

EvidenceWatch watches the INFRASTRUCTURE evidence depends on; this
module watches the HANDLING. Every item action — logged in, checked
out, checked in, transferred, disposed — is a hash-chained record with
a named officer and a stated purpose. `verify` re-computes the chain,
so an auditor (or a defense attorney) can confirm nothing was altered
after the fact. No item contents, no photos, no case narratives —
custody metadata only, on the agency's own hardware.

Storage: ``<SC_DATA_DIR>/custody/`` (items/*.json + chained log).
"""
from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS = "0" * 64
CATEGORIES = ("physical", "digital_media", "firearm", "narcotics",
               "currency", "biological", "document", "other")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _root() -> Path:
    base = os.environ.get("SC_DATA_DIR") or str(Path.home() / ".safecadence")
    p = Path(base) / "custody"
    (p / "items").mkdir(parents=True, exist_ok=True)
    return p


def _entry_hash(body: dict) -> str:
    canon = json.dumps({k: v for k, v in body.items() if k != "entry_hash"},
                        sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def _log(entry: dict) -> dict:
    f = _root() / "custody-log.jsonl"
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
    f = _root() / "custody-log.jsonl"
    if not f.exists():
        return {"ok": True, "entries": 0}
    prev, n = GENESIS, 0
    for line in f.read_text(encoding="utf-8").strip().splitlines():
        try:
            e = json.loads(line)
        except Exception:
            return {"ok": False, "entries": n, "reason": "unparseable"}
        if e.get("prev_hash") != prev or _entry_hash(e) != e.get("entry_hash"):
            return {"ok": False, "entries": n, "failed_at": e.get("item_id"),
                     "reason": "chain broken"}
        prev, n = e["entry_hash"], n + 1
    return {"ok": True, "entries": n}


def _item_file(item_id: str) -> Path:
    return _root() / "items" / f"{item_id}.json"


def _load(item_id: str) -> dict | None:
    f = _item_file(item_id)
    if not f.exists():
        return None
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except Exception:
        return None


def _save(item: dict) -> None:
    _item_file(item["item_id"]).write_text(
        json.dumps(item, indent=1, ensure_ascii=False), encoding="utf-8")


# ================================================================ actions

def add_item(*, case_number: str, description: str,
              category: str = "physical", storage_location: str,
              entered_by: str) -> dict[str, Any]:
    for field, val in (("case_number", case_number),
                        ("description", description),
                        ("storage_location", storage_location),
                        ("entered_by", entered_by)):
        if not (val or "").strip():
            raise ValueError(f"{field} is required")
    item = {
        "item_id": f"EV-{uuid.uuid4().hex[:8].upper()}",
        "case_number": str(case_number).strip()[:60],
        "description": str(description).strip()[:300],
        "category": category if category in CATEGORIES else "other",
        "storage_location": str(storage_location).strip()[:120],
        "status": "in_storage",
        "custodian": "",
        "entered_by": str(entered_by).strip()[:120],
        "entered_at": _now(),
        "history": [],
    }
    _save(item)
    _log({"item_id": item["item_id"], "at": item["entered_at"],
           "action": "logged_in", "officer": item["entered_by"],
           "case_number": item["case_number"],
           "location": item["storage_location"]})
    return item


def checkout(item_id: str, *, officer: str, purpose: str) -> dict:
    """Purpose is mandatory — 'court', 'lab', 'viewing' — every removal
    is attributable AND explainable."""
    item = _load(item_id)
    if not item:
        raise KeyError("item not found")
    if not (officer or "").strip() or not (purpose or "").strip():
        raise ValueError("officer and purpose are required")
    if item["status"] == "checked_out":
        raise ValueError(f"already checked out to {item['custodian']}")
    if item["status"] == "disposed":
        raise ValueError("item was disposed - no further custody actions")
    ev = {"at": _now(), "action": "checked_out",
           "officer": str(officer).strip()[:120],
           "purpose": str(purpose).strip()[:200]}
    item["history"].append(ev)
    item["status"] = "checked_out"
    item["custodian"] = ev["officer"]
    _save(item)
    _log({"item_id": item_id, **ev, "case_number": item["case_number"]})
    return item


def checkin(item_id: str, *, officer: str, note: str = "",
             storage_location: str = "") -> dict:
    item = _load(item_id)
    if not item:
        raise KeyError("item not found")
    if not (officer or "").strip():
        raise ValueError("officer is required")
    if item["status"] != "checked_out":
        raise ValueError("item is not checked out")
    ev = {"at": _now(), "action": "checked_in",
           "officer": str(officer).strip()[:120],
           "note": str(note or "").strip()[:200]}
    item["history"].append(ev)
    item["status"] = "in_storage"
    item["custodian"] = ""
    if storage_location:
        item["storage_location"] = str(storage_location).strip()[:120]
    _save(item)
    _log({"item_id": item_id, **ev, "case_number": item["case_number"],
           "location": item["storage_location"]})
    return item


def dispose(item_id: str, *, officer: str, authority: str,
             method: str) -> dict:
    """Disposal needs a named AUTHORITY (court order, case closure
    approval) on top of the acting officer."""
    item = _load(item_id)
    if not item:
        raise KeyError("item not found")
    for field, val in (("officer", officer), ("authority", authority),
                        ("method", method)):
        if not (val or "").strip():
            raise ValueError(f"{field} is required for disposal")
    if item["status"] == "checked_out":
        raise ValueError("check the item in before disposal")
    ev = {"at": _now(), "action": "disposed",
           "officer": str(officer).strip()[:120],
           "authority": str(authority).strip()[:200],
           "method": str(method).strip()[:120]}
    item["history"].append(ev)
    item["status"] = "disposed"
    _save(item)
    _log({"item_id": item_id, **ev, "case_number": item["case_number"]})
    return item


def list_items(status: str = "") -> list[dict]:
    out = []
    for f in sorted((_root() / "items").glob("*.json")):
        try:
            item = json.loads(f.read_text(encoding="utf-8"))
            if not status or item.get("status") == status:
                out.append(item)
        except Exception:
            continue
    out.sort(key=lambda i: i.get("entered_at", ""), reverse=True)
    return out


def item_history(item_id: str) -> dict:
    item = _load(item_id)
    if not item:
        raise KeyError("item not found")
    return item


def summary() -> dict[str, Any]:
    items = list_items()
    v = verify_log()
    return {
        "items": len(items),
        "in_storage": sum(1 for i in items if i["status"] == "in_storage"),
        "checked_out": sum(1 for i in items if i["status"] == "checked_out"),
        "disposed": sum(1 for i in items if i["status"] == "disposed"),
        "log_entries": v.get("entries", 0),
        "log_ok": v.get("ok"),
    }
