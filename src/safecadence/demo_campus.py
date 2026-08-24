"""Synthetic school-district fleet for CampusWatch demos and tests.

Three fictional schools with cameras, door controllers, intercoms,
panic buttons, NVR storage, and network gear — seeded with the exact
failure shapes a safety director recognizes: a dark camera at a gym, an
offline main-entrance door controller, and an NVR filling up. Entirely
fictional; mirrors the sheriff-fleet asset shape so every engine works.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

DISTRICT = "Cypress County Public Schools"

_SCHOOLS = [
    ("lincoln-middle", "Lincoln Middle School", 27.95, -82.48),
    ("roosevelt-high", "Roosevelt High School", 27.97, -82.44),
    ("jefferson-elem", "Jefferson Elementary", 27.93, -82.51),
]


def _asset(aid: str, name: str, atype: str, school: str, lat: float,
            lon: float, *, score: int = 95, status: str = "",
            days_stale: int = 0, storage: dict | None = None) -> dict[str, Any]:
    seen = (datetime.now(timezone.utc) -
             timedelta(days=days_stale)).isoformat()
    band = ("critical" if score <= 30 else
             "high" if score <= 55 else
             "medium" if score <= 75 else "safe")
    a: dict[str, Any] = {
        "identity": {
            "asset_id": aid, "hostname": name, "asset_type": "iot",
            "site": school, "vendor": "demo", "model": "demo",
            "criticality": "high" if atype in ("access_control",
                                                 "panic_button") else "medium",
            "owner": "District Safety", "team": "Facilities IT",
            "environment": "production", "tags": ["demo:campus"],
            "discovered_at": seen, "last_collected_at": seen,
            "discovery_source": "demo",
        },
        "public_safety": {
            "agency": DISTRICT, "department": "Safety & Security",
            "ps_category": atype, "mission_function": "campus_safety",
            "evidence_roles": ["capture"] if "cam" in atype else [],
            "cji_classification": "none",
            "latitude": lat, "longitude": lon, "geo_source": "demo",
        },
        "health": {"hardware_health": score, "security_health": score,
                    "lifecycle_health": score, "operational_health": score,
                    "overall_score": score,
                    "grade": "A" if score >= 90 else "C" if score > 30 else "F",
                    "risk_band": band},
        "raw_collection": {},
    }
    if status:
        a["identity"]["operational_status"] = status
    if storage:
        a["storage"] = storage
    return a


def build_campus_fleet() -> list[dict[str, Any]]:
    fleet: list[dict[str, Any]] = []
    for i, (sid, sname, lat, lon) in enumerate(_SCHOOLS):
        # cameras — 4 per school; Lincoln's gym camera is DARK
        for c in range(1, 5):
            dark = (sid == "lincoln-middle" and c == 3)
            fleet.append(_asset(
                f"{sid}-cam-{c}",
                f"{sname} {'Gym' if c == 3 else ['Main Entrance', 'Bus Loop', 'Gym', 'Cafeteria'][c-1]} Camera",
                "camera", sid, lat + c * 1e-3, lon + c * 1e-3,
                score=18 if dark else 92 + c % 3,
                status="offline" if dark else "",
                days_stale=9 if dark else 0))
        # door controllers — Roosevelt's MAIN ENTRANCE controller is offline
        for d, door in enumerate(["Main Entrance", "Gym Wing"], start=1):
            down = (sid == "roosevelt-high" and d == 1)
            fleet.append(_asset(
                f"{sid}-door-{d}", f"{sname} {door} Door Controller",
                "access_control", sid, lat - d * 1e-3, lon - d * 1e-3,
                score=22 if down else 94, status="offline" if down else "",
                days_stale=4 if down else 0))
        # intercom + panic button
        fleet.append(_asset(f"{sid}-intercom", f"{sname} Intercom/PA",
                              "intercom", sid, lat, lon - 2e-3, score=96))
        fleet.append(_asset(f"{sid}-panic", f"{sname} Panic Button Hub",
                              "panic_button", sid, lat + 2e-3, lon, score=97))
        # network switch (not watched by CampusWatch; proves filtering)
        fleet.append(_asset(f"{sid}-sw", f"{sname} MDF Switch",
                              "network", sid, lat, lon, score=88))
    # district NVR — filling up
    fleet.append(_asset(
        "district-nvr-01", "District Video NVR", "vms",
        "district-office", 27.94, -82.46, score=80,
        storage={"total_capacity_tb": 96.0, "used_capacity_tb": 85.5,
                  "replication_status": "healthy"}))
    return fleet
