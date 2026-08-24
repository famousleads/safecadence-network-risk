"""Community layer — consent-based, agency-controlled. No surveillance.

Two beloved small-agency programs, digitized:

  * **Camera Registry** — residents and businesses VOLUNTARILY register
    "I have a camera at this address; you may contact me." No feeds,
    no access, no monitoring — a map layer and a contact list so an
    investigator can knock politely instead of canvassing blind.
    Consent is a required, recorded field; entries are agency-entered.
  * **Watch Requests** — vacation/business checks. A resident asks for
    extra patrols while away; deputies log each check; requests expire
    on their end date. The paper clipboard, retired.

Design lines we hold: no public self-serve intake in v1 (agency staff
enter records — no spam/abuse surface), no social feeds, no "suspicious
person" reporting, nothing leaves the agency's network.

Storage: JSON files under ``<SC_DATA_DIR>/community/``.
"""
from __future__ import annotations

import json
import math
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_SAFE_ID = re.compile(r"^[a-z]{2,3}-[0-9a-f]{10}$")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _root() -> Path:
    base = os.environ.get("SC_DATA_DIR") or str(Path.home() / ".safecadence")
    p = Path(base) / "community"
    (p / "registry").mkdir(parents=True, exist_ok=True)
    (p / "watch").mkdir(parents=True, exist_ok=True)
    return p


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def _load_all(sub: str) -> list[dict]:
    out = []
    for f in sorted((_root() / sub).glob("*.json")):
        try:
            out.append(json.loads(f.read_text(encoding="utf-8")))
        except Exception:
            continue
    return out


def _save(sub: str, rec: dict) -> None:
    rid = rec["id"]
    if not _SAFE_ID.match(rid):
        raise ValueError("bad record id")
    (_root() / sub / f"{rid}.json").write_text(
        json.dumps(rec, indent=1, ensure_ascii=False), encoding="utf-8")


def _get(sub: str, rid: str) -> dict | None:
    if not _SAFE_ID.match(rid or ""):
        return None
    f = _root() / sub / f"{rid}.json"
    if not f.exists():
        return None
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except Exception:
        return None


def _dist_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Haversine distance in meters."""
    r = 6371000.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = (math.sin(dp / 2) ** 2 +
          math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2)
    return 2 * r * math.asin(math.sqrt(a))


# ================================================================ registry

CAMERA_KINDS = ("doorbell", "residential", "business", "hoa", "other")


def register_camera(*, owner_name: str, contact: str, address: str,
                     latitude: float, longitude: float,
                     camera_kind: str = "residential", notes: str = "",
                     consent_confirmed: bool = False,
                     entered_by: str = "staff") -> dict[str, Any]:
    """Add a voluntary registry entry. Consent is mandatory and recorded."""
    if not consent_confirmed:
        raise ValueError(
            "consent_confirmed is required: the owner must explicitly agree "
            "to be listed and contacted. No consent, no entry.")
    if not (owner_name or "").strip() or not (contact or "").strip():
        raise ValueError("owner_name and contact are required")
    lat, lon = float(latitude), float(longitude)
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        raise ValueError("invalid coordinates")
    kind = camera_kind if camera_kind in CAMERA_KINDS else "other"
    rec = {
        "id": _new_id("cr"),
        "owner_name": str(owner_name).strip()[:120],
        "contact": str(contact).strip()[:160],
        "address": str(address or "").strip()[:200],
        "latitude": lat, "longitude": lon,
        "camera_kind": kind,
        "notes": str(notes or "").strip()[:500],
        "consent_confirmed": True,
        "consent_recorded_at": _now(),
        "entered_by": str(entered_by)[:80],
        "status": "active",
        "created_at": _now(),
    }
    _save("registry", rec)
    return rec


def list_cameras(status: str = "active") -> list[dict]:
    out = [r for r in _load_all("registry")
            if not status or r.get("status") == status]
    out.sort(key=lambda r: r.get("created_at", ""), reverse=True)
    return out


def remove_camera(camera_id: str, reason: str = "owner request") -> dict:
    """Soft-remove (owner can withdraw consent at any time)."""
    rec = _get("registry", camera_id)
    if not rec:
        raise KeyError("registry entry not found")
    rec["status"] = "removed"
    rec["removed_at"] = _now()
    rec["removed_reason"] = str(reason)[:200]
    _save("registry", rec)
    return rec


def cameras_near(latitude: float, longitude: float,
                  radius_m: float = 500.0) -> list[dict]:
    """Investigator lookup: active registered cameras within radius,
    nearest first, distance attached."""
    lat, lon = float(latitude), float(longitude)
    hits = []
    for r in list_cameras("active"):
        d = _dist_m(lat, lon, r["latitude"], r["longitude"])
        if d <= float(radius_m):
            hits.append({**r, "distance_m": round(d, 1)})
    hits.sort(key=lambda r: r["distance_m"])
    return hits


# ================================================================ watch

def request_watch(*, requester_name: str, contact: str, address: str,
                   latitude: float, longitude: float,
                   start_date: str, end_date: str, notes: str = "",
                   entered_by: str = "staff") -> dict[str, Any]:
    if not (requester_name or "").strip() or not (contact or "").strip():
        raise ValueError("requester_name and contact are required")
    lat, lon = float(latitude), float(longitude)
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        raise ValueError("invalid coordinates")
    if str(end_date) < str(start_date):
        raise ValueError("end_date before start_date")
    rec = {
        "id": _new_id("wr"),
        "requester_name": str(requester_name).strip()[:120],
        "contact": str(contact).strip()[:160],
        "address": str(address or "").strip()[:200],
        "latitude": lat, "longitude": lon,
        "start_date": str(start_date)[:10],
        "end_date": str(end_date)[:10],
        "notes": str(notes or "").strip()[:500],
        "status": "active",
        "checks": [],
        "entered_by": str(entered_by)[:80],
        "created_at": _now(),
    }
    _save("watch", rec)
    return rec


def list_watches(status: str = "") -> list[dict]:
    today = _now()[:10]
    out = []
    for r in _load_all("watch"):
        # auto-expire past end date (visible state, no deletion)
        if r.get("status") == "active" and r.get("end_date", "9999") < today:
            r["status"] = "expired"
            _save("watch", r)
        if not status or r.get("status") == status:
            out.append(r)
    out.sort(key=lambda r: (r.get("status") != "active",
                              r.get("end_date", "")))
    return out


def log_check(watch_id: str, *, officer: str, note: str = "") -> dict:
    rec = _get("watch", watch_id)
    if not rec:
        raise KeyError("watch request not found")
    if not (officer or "").strip():
        raise ValueError("officer is required — every check is attributable")
    rec.setdefault("checks", []).append({
        "ts": _now(), "officer": str(officer).strip()[:120],
        "note": str(note or "").strip()[:300],
    })
    _save("watch", rec)
    return rec


def complete_watch(watch_id: str) -> dict:
    rec = _get("watch", watch_id)
    if not rec:
        raise KeyError("watch request not found")
    rec["status"] = "completed"
    rec["completed_at"] = _now()
    _save("watch", rec)
    return rec


# ================================================================ summary

def summary() -> dict[str, Any]:
    cams = list_cameras("active")
    watches = list_watches()
    active = [w for w in watches if w["status"] == "active"]
    return {
        "registered_cameras": len(cams),
        "active_watches": len(active),
        "total_checks_logged": sum(len(w.get("checks", [])) for w in watches),
        "map_points": (
            [{"kind": "registry", "id": c["id"], "label": c["owner_name"],
               "lat": c["latitude"], "lon": c["longitude"],
               "meta": c["camera_kind"]} for c in cams] +
            [{"kind": "watch", "id": w["id"], "label": w["requester_name"],
               "lat": w["latitude"], "lon": w["longitude"],
               "meta": f"until {w['end_date']}"} for w in active]),
    }
