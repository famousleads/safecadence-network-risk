"""Standing Watches — tell the platform what to watch for, in English.

    "Tell me whenever a door is forced at any school after hours."

That sentence becomes a NAMED, PRE-AUTHORIZED rule: a deterministic
filter over the analytics event stream that raises a situation card
when it matches — and, if a notify group is attached, sends the alert
through Mass Notification carrying the creator's pre-authorization
(the SafeCheck model: the named human consents at creation time, so
the approval rule holds at 3 AM when nobody is at a desk).

Honesty mechanics:
  * The parser ECHOES its interpretation ("I will watch for:
    door_forced or glass_break · sites matching 'school' · after hours
    only") so the human confirms what the machine understood before
    saving. AI can do the parsing when a key is configured — grounded
    to the fixed event vocabulary, strictly validated — but the
    deterministic keyword parser ALWAYS works, offline.
  * A watch fires at most once per its window (no alert storms).
  * Every fire is recorded in a hash-chained log with verify().

Storage: ``<SC_DATA_DIR>/watches/`` (watches.json + chained log).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from safecadence.situation import EVENT_TYPES, recent_events

GENESIS = "0" * 64

_TYPE_WORDS: dict[str, str] = {
    "person": "person", "people": "person", "intruder": "person",
    "someone": "person", "anybody": "person",
    "vehicle": "vehicle", "car": "vehicle", "truck": "vehicle",
    "motion": "motion", "movement": "motion",
    "line": "line_cross", "fence": "line_cross", "perimeter": "line_cross",
    "loiter": "loiter", "loitering": "loiter",
    "crowd": "crowd", "crowds": "crowd", "gathering": "crowd",
    "weapon": "weapon", "gun": "weapon", "gunshot": "weapon",
    "firearm": "weapon", "shots": "weapon",
    "tamper": "tamper", "tampering": "tamper", "vandalize": "tamper",
    "door": "door_forced", "forced": "door_forced", "break-in": "door_forced",
    "breakin": "door_forced", "burglary": "door_forced",
    "propped": "door_held", "held": "door_held",
    "glass": "glass_break",
    "plate": "alpr_hit", "alpr": "alpr_hit", "lpr": "alpr_hit",
    "hotlist": "alpr_hit",
    "temperature": "temp_high", "heat": "temp_high", "hot": "temp_high",
    "humidity": "humidity_high",
    "water": "water_leak", "leak": "water_leak", "flood": "water_leak",
    "power": "power_loss", "outage": "power_loss",
}
_STOP_SITES = {
    "the", "a", "an", "any", "all", "every", "me", "us", "hours", "night",
    "least", "same", "site", "sites", "building", "buildings", "location",
    "locations", "minutes", "minute", "time", "once", "camera", "cameras",
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _root() -> Path:
    base = os.environ.get("SC_DATA_DIR") or str(Path.home() / ".safecadence")
    p = Path(base) / "watches"
    p.mkdir(parents=True, exist_ok=True)
    return p


# ================================================================ parser

def parse_query(query: str) -> dict[str, Any]:
    """Deterministic NL → filter. Always works, always explainable."""
    q = " " + str(query or "").lower() + " "
    types: list[str] = []
    for word, etype in _TYPE_WORDS.items():
        if re.search(r"[^a-z]" + re.escape(word) + r"[^a-z]", q):
            if etype not in types:
                types.append(etype)
    after_hours = bool(re.search(
        r"after hours|overnight|at night|late night|nighttime", q))
    m = re.search(r"(?:at least|more than|(\d+)\s*(?:or more|\+))|(\d+)\s+or more", q)
    min_count = 1
    m2 = re.search(r"at least (\d+)|(\d+) or more|more than (\d+)", q)
    if m2:
        n = next(g for g in m2.groups() if g)
        min_count = max(1, int(n))
        if "more than" in m2.group(0):
            min_count += 1
    m3 = re.search(r"within (\d+)\s*min", q)
    window = int(m3.group(1)) if m3 else 30
    m4 = re.search(r"confidence (?:above|over|at least)\s*(0?\.\d+|\d+)%?", q)
    min_conf = 0.0
    if m4:
        v = float(m4.group(1))
        min_conf = v / 100.0 if v > 1 else v
    sites: list[str] = []
    for m5 in re.finditer(r"(?:at|near|around) (?:the |any |all |every )?"
                            r"([a-z][a-z0-9-]{2,})", q):
        w = m5.group(1)
        if w not in _STOP_SITES and w not in _TYPE_WORDS and w not in sites:
            sites.append(w)
    return {"event_types": types, "sites": sites,
             "after_hours_only": after_hours, "min_count": min_count,
             "window_minutes": max(5, min(720, window)),
             "min_confidence": round(min_conf, 2)}


def _ai_parse(query: str) -> dict | None:
    """Optional AI parse, strictly validated against the fixed schema."""
    if os.environ.get("SC_WATCH_AI", "1") == "0":
        return None
    try:
        from safecadence.ai.client import (
            AIProvider, _call_anthropic, detect_provider)
        key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
        if not key or detect_provider() != AIProvider.ANTHROPIC:
            return None
        prompt = (
            "Convert this watch request into JSON with EXACTLY these "
            "keys: event_types (subset of "
            + ", ".join(EVENT_TYPES) + "), sites (lowercase substrings), "
            "after_hours_only (bool), min_count (int>=1), window_minutes "
            "(int 5-720), min_confidence (0-1). Output ONLY the JSON.\n\n"
            "Request: " + str(query)[:300])
        raw = _call_anthropic(prompt, api_key=key,
                               model=os.environ.get("SC_AI_MODEL",
                                                      "claude-fable-5"),
                               timeout=30, effort="low")
        m = re.search(r"\{.*\}", raw or "", re.S)
        if not m:
            return None
        f = json.loads(m.group(0))
        return {
            "event_types": [t for t in f.get("event_types", [])
                             if t in EVENT_TYPES],
            "sites": [str(s).lower()[:60] for s in f.get("sites", [])][:5],
            "after_hours_only": bool(f.get("after_hours_only")),
            "min_count": max(1, min(50, int(f.get("min_count", 1)))),
            "window_minutes": max(5, min(720,
                                           int(f.get("window_minutes", 30)))),
            "min_confidence": max(0.0, min(1.0,
                                             float(f.get("min_confidence", 0)))),
        }
    except Exception:
        return None


def interpret(query: str) -> dict[str, Any]:
    """Parse + a plain-English echo of what will be watched."""
    f = _ai_parse(query) or parse_query(query)
    bits = []
    bits.append("events: " + (" or ".join(f["event_types"])
                                if f["event_types"] else "ANY type"))
    if f["sites"]:
        bits.append("sites matching: " + ", ".join(f["sites"]))
    if f["after_hours_only"]:
        bits.append("after hours only (10 PM - 6 AM)")
    if f["min_count"] > 1:
        bits.append(f"at least {f['min_count']} events "
                     f"within {f['window_minutes']} min")
    if f["min_confidence"]:
        bits.append(f"confidence >= {f['min_confidence']}")
    return {"filter": f, "interpretation": "I will watch for: "
             + " · ".join(bits)}


# ================================================================ store

def list_watches() -> list[dict]:
    f = _root() / "watches.json"
    if not f.exists():
        return []
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except Exception:
        return []


def _save_all(watches: list[dict]) -> None:
    (_root() / "watches.json").write_text(
        json.dumps(watches, indent=1, ensure_ascii=False), encoding="utf-8")


def create_watch(*, query: str, created_by: str, name: str = "",
                  notify_group: str = "",
                  severity: str = "high") -> dict[str, Any]:
    """A named human creates — and thereby pre-authorizes — the watch."""
    if not (created_by or "").strip():
        raise ValueError("created_by is required - a standing watch is a "
                          "standing authorization, and authorizations "
                          "carry a name")
    if not (query or "").strip():
        raise ValueError("query is required")
    it = interpret(query)
    if not it["filter"]["event_types"] and not it["filter"]["sites"]:
        raise ValueError(
            "could not understand the request - name at least an event "
            "type (door forced, weapon, crowd...) or a site. "
            "Parser heard: " + it["interpretation"])
    w = {
        "id": f"sw-{uuid.uuid4().hex[:10]}",
        "name": (name or query).strip()[:120],
        "query": str(query).strip()[:300],
        "filter": it["filter"],
        "interpretation": it["interpretation"],
        "created_by": str(created_by).strip()[:120],
        "created_at": _now().isoformat(),
        "notify_group": str(notify_group or "").strip()[:80],
        "severity": severity if severity in ("critical", "high",
                                               "medium") else "high",
        "enabled": True,
        "last_fired_at": "",
        "fire_count": 0,
    }
    watches = list_watches()
    watches.append(w)
    _save_all(watches)
    return w


def set_enabled(watch_id: str, enabled: bool) -> dict:
    watches = list_watches()
    for w in watches:
        if w["id"] == watch_id:
            w["enabled"] = bool(enabled)
            _save_all(watches)
            return w
    raise KeyError("watch not found")


def delete_watch(watch_id: str) -> dict:
    watches = list_watches()
    keep = [w for w in watches if w["id"] != watch_id]
    if len(keep) == len(watches):
        raise KeyError("watch not found")
    _save_all(keep)
    return {"deleted": watch_id}


# ================================================================ fire log

def _entry_hash(body: dict) -> str:
    canon = json.dumps({k: v for k, v in body.items() if k != "entry_hash"},
                        sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def _log_fire(entry: dict) -> dict:
    f = _root() / "watch-log.jsonl"
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
    f = _root() / "watch-log.jsonl"
    if not f.exists():
        return {"ok": True, "entries": 0}
    prev, n = GENESIS, 0
    for line in f.read_text(encoding="utf-8").strip().splitlines():
        try:
            e = json.loads(line)
        except Exception:
            return {"ok": False, "entries": n, "reason": "unparseable"}
        if e.get("prev_hash") != prev or _entry_hash(e) != e.get("entry_hash"):
            return {"ok": False, "entries": n, "reason": "chain broken"}
        prev, n = e["entry_hash"], n + 1
    return {"ok": True, "entries": n}


# ================================================================ engine

def _matches(w: dict, e: dict, after_hours: bool) -> bool:
    f = w["filter"]
    if f["event_types"] and e.get("event_type") not in f["event_types"]:
        return False
    if f["sites"]:
        site = (e.get("site") or "").lower()
        if not any(s in site for s in f["sites"]):
            return False
    if f["min_confidence"] and (e.get("confidence") or 0) < f["min_confidence"]:
        return False
    if f["after_hours_only"] and not after_hours:
        return False
    return True


def check_watches(after_hours: bool | None = None,
                   live: bool | None = None) -> list[dict]:
    """Evaluate every enabled watch. Fires at most once per window per
    watch. Returns situation-style cards for everything that fired."""
    if after_hours is None:
        from safecadence.situation import _is_after_hours
        after_hours = _is_after_hours()
    watches = list_watches()
    cards: list[dict] = []
    changed = False
    for w in watches:
        if not w.get("enabled"):
            continue
        window = w["filter"]["window_minutes"]
        if w.get("last_fired_at"):
            try:
                since = (_now() - datetime.fromisoformat(
                    w["last_fired_at"])).total_seconds() / 60
                if since < window:
                    continue
            except Exception:
                pass
        events = [e for e in recent_events(window)
                   if _matches(w, e, after_hours)]
        if len(events) < w["filter"]["min_count"]:
            continue
        from safecadence.situation import _fmt
        card = {
            "id": f"sit-{uuid.uuid4().hex[:10]}",
            "kind": "standing_watch",
            "severity": w["severity"],
            "headline": f"Standing watch fired: {w['name']}",
            "site": events[0].get("site") or "",
            "confidence": round(min(0.95, max(
                e.get("confidence", 0.7) for e in events)), 2),
            "evidence": [_fmt(e) for e in events[:5]]
                         + [f"watch created by {w['created_by']} - "
                            f"\"{w['query']}\""],
            "recommended_action": ("Review the matching events. This "
                                     "watch was set for a reason - act on "
                                     "it or clear it."),
            "created_at": _now().isoformat(),
            "watch_id": w["id"],
        }
        cards.append(card)
        notified = None
        if w.get("notify_group"):
            try:
                from safecadence import mass_notify
                out = mass_notify.send_notification(
                    group=w["notify_group"],
                    subject=f"STANDING WATCH - {w['name']}"[:120],
                    body=(f"{card['headline']}. "
                           + " | ".join(card["evidence"][:3])),
                    initiated_by="Standing watch engine",
                    approved_by=w["created_by"]
                                 + " (pre-authorized at watch creation)",
                    force=True, live=live)
                notified = {"sent": True, "mode": out.get("mode"),
                             "alert_id": out.get("id")}
            except Exception as exc:
                notified = {"sent": False, "error": str(exc)[:200]}
        w["last_fired_at"] = _now().isoformat()
        w["fire_count"] = int(w.get("fire_count", 0)) + 1
        changed = True
        _log_fire({"watch_id": w["id"], "at": w["last_fired_at"],
                    "name": w["name"], "matched": len(events),
                    "created_by": w["created_by"], "notified": notified})
    if changed:
        _save_all(watches)
    return cards


def summary() -> dict[str, Any]:
    watches = list_watches()
    v = verify_log()
    return {"watches": len(watches),
             "enabled": sum(1 for w in watches if w.get("enabled")),
             "total_fires": sum(int(w.get("fire_count", 0))
                                 for w in watches),
             "log_entries": v.get("entries", 0), "log_ok": v.get("ok")}
