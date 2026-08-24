"""Situation Analytics — the layer ABOVE video analytics.

SafeCadence does not watch video and does not identify people. Edge
detection stays where it belongs — in the cameras, VMSes, and certified
detection vendors the agency already owns (ONVIF analytics, Axis/Bosch/
Hanwha edge events, Milestone/Genetec VMS events, gun-detection vendors
like ZeroEyes). Those systems emit EVENTS; SafeCadence ingests the
events and does the thing none of them do: connect them — across
cameras, doors, incidents, device health, and time — into SITUATION
CARDS a dispatcher can act on:

    "Door forced at Evidence Facility + person detected on two
     adjacent cameras, 11:42 PM — possible break-in in progress."

Every card carries its evidence, a confidence, and ONE recommended
action. When the recommendation is an alert, it goes through Mass
Notification's named-approver gate — the situation engine PREPARES,
a human APPROVES. Detection accuracy remains the detection vendor's
certification; correlation and accountability are ours.

AI-use policy (also exported as AI_USE_POLICY for the UI/RFP):
no facial recognition, no biometric identification, no autonomous
action, no video content ingestion — metadata events only, processed
on the agency's own hardware.

Storage: day files under ``<SC_DATA_DIR>/situations/``.
"""
from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

AI_USE_POLICY = (
    "SafeCadence Situation Analytics ingests analytics EVENTS from the "
    "agency's own cameras, video management systems, and certified "
    "detection vendors. It does not ingest or analyze video content, "
    "does not perform facial recognition or biometric identification, "
    "and never takes autonomous action. AI is used to correlate events "
    "and explain situations in plain language, grounded only in the "
    "ingested records; every recommended action requires a named human "
    "approver. All processing runs on the agency's own hardware.")

EVENT_TYPES = (
    "person", "vehicle", "motion", "line_cross", "loiter", "crowd",
    "weapon", "tamper", "left_object", "door_forced", "door_held",
    "glass_break", "audio_aggression", "alpr_hit", "temp_high",
    "humidity_high", "water_leak", "power_loss", "other")

_AFTER_HOURS = (22, 6)      # 10pm-6am local server time


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _root() -> Path:
    base = os.environ.get("SC_DATA_DIR") or str(Path.home() / ".safecadence")
    p = Path(base) / "situations"
    p.mkdir(parents=True, exist_ok=True)
    return p


# ================================================================ ingest

def ingest_video_event(payload: dict) -> dict[str, Any]:
    """Normalize one analytics event from any source — a vendor webhook,
    a VMS event bridge, or an ONVIF event relay. Accepts loose vendor
    shapes; stores a canonical record. No video content, ever."""
    etype = str(payload.get("event_type") or payload.get("type")
                 or payload.get("topic") or "other").strip().lower()
    etype = etype.replace("-", "_").replace(" ", "_")
    aliases = {
        "human": "person", "people": "person", "intrusion": "person",
        "linecrossing": "line_cross", "line_crossing": "line_cross",
        "loitering": "loiter", "crowding": "crowd", "crowd_density": "crowd",
        "gun": "weapon", "gun_detected": "weapon", "firearm": "weapon",
        "camera_tamper": "tamper", "tampering": "tamper",
        "forced_entry": "door_forced", "door_prop": "door_held",
        "glassbreak": "glass_break", "aggression": "audio_aggression",
        "abandoned_object": "left_object",
        "lpr": "alpr_hit", "alpr": "alpr_hit", "plate_hit": "alpr_hit",
        "hotlist": "alpr_hit", "temperature": "temp_high",
        "high_temp": "temp_high", "humidity": "humidity_high",
        "flood": "water_leak", "leak": "water_leak",
        "power_failure": "power_loss", "ups_on_battery": "power_loss",
    }
    etype = aliases.get(etype, etype)
    if etype not in EVENT_TYPES:
        etype = "other"
    try:
        conf = float(payload.get("confidence", 0.8))
    except (TypeError, ValueError):
        conf = 0.8
    conf = max(0.0, min(1.0, conf))
    at = str(payload.get("at") or payload.get("timestamp") or
              _now().isoformat())
    rec = {
        "id": f"ve-{uuid.uuid4().hex[:10]}",
        "at": at,
        "event_type": etype,
        "site": str(payload.get("site") or payload.get("location")
                     or "").strip()[:120],
        "camera": str(payload.get("camera") or payload.get("source")
                       or payload.get("asset_id") or "").strip()[:120],
        "vendor": str(payload.get("vendor") or "generic").strip()[:60],
        "confidence": round(conf, 2),
        "zone": str(payload.get("zone") or "").strip()[:80],
        "note": str(payload.get("note") or "").strip()[:300],
    }
    day = _now().strftime("%Y%m%d")
    with (_root() / f"events-{day}.jsonl").open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return rec


def recent_events(minutes: int = 60) -> list[dict]:
    cutoff = _now() - timedelta(minutes=minutes)
    out = []
    for day in (cutoff.strftime("%Y%m%d"), _now().strftime("%Y%m%d")):
        f = _root() / f"events-{day}.jsonl"
        if not f.exists():
            continue
        for line in f.read_text(encoding="utf-8").strip().splitlines():
            try:
                e = json.loads(line)
                ts = datetime.fromisoformat(
                    str(e.get("at", "")).replace("Z", "+00:00"))
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                if ts >= cutoff:
                    out.append(e)
            except Exception:
                continue
    # de-dupe across the two day files
    seen: set = set()
    uniq = []
    for e in out:
        if e["id"] in seen:
            continue
        seen.add(e["id"])
        uniq.append(e)
    uniq.sort(key=lambda e: e.get("at", ""))
    return uniq


def _is_after_hours(dt: datetime | None = None) -> bool:
    h = (dt or datetime.now()).hour
    start, end = _AFTER_HOURS
    return h >= start or h < end


# ================================================================ engine

def _card(kind: str, severity: str, headline: str, site: str,
           confidence: float, evidence: list[str],
           recommended_action: str) -> dict[str, Any]:
    return {
        "id": f"sit-{uuid.uuid4().hex[:10]}",
        "kind": kind, "severity": severity, "headline": headline,
        "site": site, "confidence": round(confidence, 2),
        "evidence": evidence, "recommended_action": recommended_action,
        "created_at": _now().isoformat(),
    }


def _fmt(e: dict) -> str:
    return (f"{e['event_type']} on {e.get('camera') or 'camera'}"
            f" at {e.get('site') or 'site'}"
            f" ({e.get('at', '')[11:16]}, conf {e.get('confidence')})")


def assess(window_minutes: int = 30, assets: list[dict] | None = None,
            after_hours: bool | None = None) -> list[dict]:
    """Correlate the recent event stream into situation cards. Pure and
    deterministic — every card shows the events that produced it."""
    events = recent_events(window_minutes)
    if after_hours is None:
        after_hours = _is_after_hours()
    cards: list[dict] = []
    by_site: dict[str, list[dict]] = {}
    for e in events:
        by_site.setdefault(e.get("site") or "", []).append(e)

    # 1 — weapon: always critical, never buried -----------------------
    for e in events:
        if e["event_type"] == "weapon":
            cards.append(_card(
                "weapon_detected", "critical",
                f"Possible weapon detected at {e.get('site') or 'a site'} "
                f"({e.get('vendor')})",
                e.get("site") or "", e.get("confidence", 0.8),
                [_fmt(e), "Detection by the vendor's certified system - "
                  "verify on the camera before acting."],
                "Verify the feed now. If confirmed, send the lockdown "
                "template via Mass Notification - a named approver is "
                "required before anything goes out."))

    # 2 — possible break-in: door forced + human activity -------------
    for site, evs in by_site.items():
        forced = [e for e in evs if e["event_type"] in
                   ("door_forced", "glass_break")]
        humans = [e for e in evs if e["event_type"] in
                   ("person", "motion", "line_cross")]
        if forced and humans:
            conf = min(0.95, 0.6 + 0.1 * len(humans))
            cards.append(_card(
                "possible_breakin", "critical",
                f"Possible break-in in progress at {site or 'a site'}",
                site, conf,
                [_fmt(e) for e in (forced + humans)[:5]],
                "Dispatch a unit to check the building. Preserve the "
                "recordings for these cameras now."))

    # 3 — after-hours activity cluster --------------------------------
    if after_hours:
        for site, evs in by_site.items():
            humans = [e for e in evs if e["event_type"] in
                       ("person", "motion", "line_cross")]
            covered = any(c["site"] == site and c["kind"] ==
                           "possible_breakin" for c in cards)
            if len(humans) >= 3 and not covered:
                cards.append(_card(
                    "after_hours_cluster", "high",
                    f"Unusual after-hours activity at {site or 'a site'} "
                    f"- {len(humans)} detections in {window_minutes} min",
                    site, min(0.9, 0.5 + 0.1 * len(humans)),
                    [_fmt(e) for e in humans[:5]],
                    "Pull up the live feeds for this site and decide if "
                    "a drive-by check is warranted."))

    # 4 — camera interference: tamper + dark neighbors ----------------
    dark_sites = set()
    for a in assets or []:
        ident = a.get("identity") or {}
        status = str(ident.get("operational_status") or "").lower()
        if status in ("offline", "down", "failed", "unreachable"):
            dark_sites.add(ident.get("site") or "")
    for e in events:
        if e["event_type"] == "tamper":
            extra = (e.get("site") in dark_sites)
            cards.append(_card(
                "camera_interference", "high" if not extra else "critical",
                f"Camera tampering at {e.get('site') or 'a site'}"
                + (" - and another camera there is already dark" if extra
                   else ""),
                e.get("site") or "", e.get("confidence", 0.8),
                [_fmt(e)] + (["another camera at this site is offline"]
                              if extra else []),
                "Treat as possible deliberate interference - check the "
                "site physically, not just the console."))

    # 5 — crowd building ----------------------------------------------
    for site, evs in by_site.items():
        crowds = [e for e in evs if e["event_type"] == "crowd"]
        if len(crowds) >= 2:
            cards.append(_card(
                "crowd_building", "medium",
                f"Crowd building at {site or 'a site'} "
                f"({len(crowds)} readings)",
                site, 0.7,
                [_fmt(e) for e in crowds[:4]],
                "Monitor the density trend; stage a unit nearby if it "
                "keeps climbing."))

    # 6 — persistent loitering ----------------------------------------
    by_cam: dict[str, list[dict]] = {}
    for e in events:
        if e["event_type"] == "loiter":
            by_cam.setdefault(e.get("camera") or "", []).append(e)
    for cam, evs in by_cam.items():
        if len(evs) >= 2:
            cards.append(_card(
                "persistent_loitering", "medium",
                f"Persistent loitering on {cam or 'a camera'} "
                f"at {evs[0].get('site') or 'a site'}",
                evs[0].get("site") or "", 0.65,
                [_fmt(e) for e in evs[:4]],
                "Review the feed; consider a walk-through or a courtesy "
                "contact."))

    # 7 — environmental threat to evidence / server rooms ---------------
    for e in events:
        if e["event_type"] in ("temp_high", "humidity_high", "water_leak",
                                 "power_loss"):
            sensitive = "evidence" in (e.get("site") or "").lower() or                          "server" in (e.get("site") or "").lower() or                          "evidence" in (e.get("note") or "").lower()
            label = e["event_type"].replace("_", " ")
            cards.append(_card(
                "environment", "critical" if sensitive else "medium",
                f"Environmental alarm at {e.get('site') or 'a site'}: "
                f"{label}"
                + (" - evidence integrity at risk" if sensitive else ""),
                e.get("site") or "", e.get("confidence", 0.9),
                [_fmt(e)] + ([e["note"]] if e.get("note") else []),
                "Send someone now - heat, water, and power loss destroy "
                "recordings and evidence faster than any intruder."
                if sensitive else
                "Check the space and the HVAC/UPS behind the alarm."))

    # 8 — ALPR hit: a lead to VERIFY, never probable cause on its own ---
    for e in events:
        if e["event_type"] == "alpr_hit":
            note = (e.get("note") or "").lower()
            hot = any(k in note for k in ("hotlist", "stolen", "wanted",
                                            "amber", "felony"))
            cards.append(_card(
                "vehicle_of_interest", "high" if hot else "medium",
                f"ALPR alert at {e.get('site') or 'a site'} "
                f"({e.get('vendor')})",
                e.get("site") or "", e.get("confidence", 0.7),
                [_fmt(e)] + ([e["note"]] if e.get("note") else []),
                "VERIFY in your ALPR console before acting - plate reads "
                "misfire; an alert is a lead, not probable cause. Confirm "
                "plate, state, and vehicle description match."))

    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    cards.sort(key=lambda c: (sev_rank.get(c["severity"], 9),
                                -c["confidence"]))
    return cards


def situation_note(cards: list[dict]) -> dict[str, Any]:
    """Plain-language rollup. AI (grounded in the cards only) when a key
    is configured; deterministic sentence otherwise — always works."""
    if not cards:
        text = ("Quiet right now: no correlated situations in the "
                 "current window. Individual events keep streaming into "
                 "the log.")
        return {"note": text, "ai_generated": False}
    ai_text = None
    if os.environ.get("SC_WATCH_AI", "1") != "0":
        try:
            from safecadence.ai.client import (
                AIProvider, _call_anthropic, detect_provider)
            key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
            if key and detect_provider() == AIProvider.ANTHROPIC:
                prompt = (
                    "You are the watch-floor analyst. Using ONLY these "
                    "situation cards (JSON), write 2-3 plain sentences "
                    "for a dispatcher: what is happening, where to look "
                    "first, and the single next step. Never invent "
                    "details.\n\n" + json.dumps(cards[:5], indent=1))
                ai_text = _call_anthropic(
                    prompt, api_key=key,
                    model=os.environ.get("SC_AI_MODEL", "claude-fable-5"),
                    timeout=45, effort="low")
                ai_text = (ai_text or "").strip()[:900] or None
        except Exception:
            ai_text = None
    if ai_text:
        return {"note": ai_text, "ai_generated": True}
    top = cards[0]
    text = (f"{len(cards)} situation(s) in the window. Start with: "
             f"{top['headline']} (confidence {top['confidence']}). "
             f"{top['recommended_action']}")
    return {"note": text, "ai_generated": False}


def summary(window_minutes: int = 60) -> dict[str, Any]:
    events = recent_events(window_minutes)
    cards = assess(window_minutes)
    return {
        "window_minutes": window_minutes,
        "events_in_window": len(events),
        "event_types": sorted({e["event_type"] for e in events}),
        "situations": len(cards),
        "critical": sum(1 for c in cards if c["severity"] == "critical"),
        "ai_use_policy": AI_USE_POLICY,
    }


# ================================================================ demo

def seed_demo(after_hours: bool = True) -> dict:
    """Synthetic vendor events that light up every rule — for demos and
    evaluation only. Clearly labeled sample data."""
    now = _now()
    evs = [
        {"event_type": "door_forced", "site": "evidence-facility",
          "camera": "cam-evd-door-1", "vendor": "vms-demo",
          "confidence": 0.93, "at": (now - timedelta(minutes=9)).isoformat()},
        {"event_type": "person", "site": "evidence-facility",
          "camera": "cam-evd-yard-2", "vendor": "edge-demo",
          "confidence": 0.88, "at": (now - timedelta(minutes=7)).isoformat()},
        {"event_type": "person", "site": "evidence-facility",
          "camera": "cam-evd-hall-1", "vendor": "edge-demo",
          "confidence": 0.9, "at": (now - timedelta(minutes=5)).isoformat()},
        {"event_type": "motion", "site": "district-north",
          "camera": "cam-dn-lot-3", "vendor": "edge-demo",
          "confidence": 0.7, "at": (now - timedelta(minutes=12)).isoformat()},
        {"event_type": "person", "site": "district-north",
          "camera": "cam-dn-lot-3", "vendor": "edge-demo",
          "confidence": 0.8, "at": (now - timedelta(minutes=10)).isoformat()},
        {"event_type": "person", "site": "district-north",
          "camera": "cam-dn-gate", "vendor": "edge-demo",
          "confidence": 0.82, "at": (now - timedelta(minutes=6)).isoformat()},
        {"event_type": "tamper", "site": "county-jail",
          "camera": "cam-jail-sally-2", "vendor": "vms-demo",
          "confidence": 0.86, "at": (now - timedelta(minutes=4)).isoformat()},
        {"event_type": "crowd", "site": "downtown-campus",
          "camera": "cam-dt-plaza-1", "vendor": "edge-demo",
          "confidence": 0.75, "at": (now - timedelta(minutes=15)).isoformat()},
        {"event_type": "crowd", "site": "downtown-campus",
          "camera": "cam-dt-plaza-1", "vendor": "edge-demo",
          "confidence": 0.8, "at": (now - timedelta(minutes=3)).isoformat()},
        {"event_type": "loiter", "site": "downtown-campus",
          "camera": "cam-dt-atm", "vendor": "edge-demo",
          "confidence": 0.7, "at": (now - timedelta(minutes=18)).isoformat()},
        {"event_type": "loiter", "site": "downtown-campus",
          "camera": "cam-dt-atm", "vendor": "edge-demo",
          "confidence": 0.72, "at": (now - timedelta(minutes=2)).isoformat()},
    ]
    for e in evs:
        ingest_video_event(e)
    cards = assess(30, after_hours=after_hours)
    return {"seeded": len(evs), "situations": len(cards)}
