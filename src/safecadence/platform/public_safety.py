"""
Public-safety asset taxonomy (DESAT) — canonical categories + classifier.

Maps discovery output (category + vendor + banners) onto the
``PublicSafety`` block of a UnifiedAsset, so sheriffs'/agencies' fleets
get first-class camera/ALPR/UAS/evidence-platform identities instead of
a generic "iot".

Design constraints (deliberate):
  * Additive — never changes ``asset_type`` semantics; a camera stays
    asset_type=iot for every existing consumer, and gains
    ``public_safety.ps_category="camera"`` on top.
  * Honest defaults — ``cji_classification`` starts from the category's
    typical posture but is a HINT, not a determination; operators can
    override. Certification obligations follow actual CJI handling,
    which only the agency can attest.
  * Pure stdlib, no network calls.
"""

from __future__ import annotations

from typing import Any

from safecadence.platform.schema import PublicSafety

# ---------------------------------------------------------------- taxonomy

# Canonical category registry. label = UI string; mission = default
# mission_function; roles = evidence-chain stages the category usually
# participates in; cji = default cji_classification hint.
PS_CATEGORIES: dict[str, dict[str, Any]] = {
    "camera": {
        "label": "Surveillance camera",
        "mission": "surveillance",
        "roles": ["capture"],
        "cji": "unknown",
    },
    "vms": {
        "label": "Video management system",
        "mission": "evidence_storage",
        "roles": ["store", "access"],
        "cji": "cji",
    },
    "body_camera_infrastructure": {
        "label": "Body-worn camera infrastructure (docks/upload)",
        "mission": "evidence_transfer",
        "roles": ["capture", "transfer"],
        "cji": "cji",
    },
    "alpr": {
        "label": "License plate recognition (ALPR/LPR)",
        "mission": "patrol_support",
        "roles": ["capture"],
        "cji": "cji",
    },
    "uas": {
        "label": "Unmanned aerial system (drone/dock)",
        "mission": "surveillance",
        "roles": ["capture"],
        "cji": "unknown",
    },
    "evidence_platform": {
        "label": "Digital evidence platform",
        "mission": "evidence_storage",
        "roles": ["store", "access", "preserve"],
        "cji": "cji",
    },
    "cad_rms": {
        "label": "CAD/RMS endpoint",
        "mission": "dispatch",
        "roles": ["access"],
        "cji": "cji",
    },
    "access_control": {
        "label": "Physical access control",
        "mission": "facility_security",
        "roles": [],
        "cji": "non_cji",
    },
    "radio_comms": {
        "label": "Radio / communications infrastructure",
        "mission": "communications",
        "roles": [],
        "cji": "non_cji",
    },
    "environmental_sensor": {
        "label": "Environmental / acoustic sensor",
        "mission": "surveillance",
        "roles": ["capture"],
        "cji": "non_cji",
    },
    "dispatch": {
        "label": "Dispatch / 911 infrastructure",
        "mission": "dispatch",
        "roles": [],
        "cji": "cji",
    },
    "interview_room": {
        "label": "Interview-room recording",
        "mission": "evidence_capture",
        "roles": ["capture"],
        "cji": "cji",
    },
}

# Vendor substring -> ps_category. Checked against the normalized vendor
# string AND banner text. Order matters — first match wins, so the more
# specific public-safety vendors come before generic camera brands.
_VENDOR_HINTS: list[tuple[str, str]] = [
    # ALPR
    ("flock",       "alpr"),
    ("vigilant",    "alpr"),
    ("elsag",       "alpr"),
    ("autovu",      "alpr"),
    # Body-worn camera ecosystems (docks, upload stations)
    ("axon",        "body_camera_infrastructure"),
    ("watchguard video", "body_camera_infrastructure"),
    ("getac video", "body_camera_infrastructure"),
    # UAS
    ("dji",         "uas"),
    ("skydio",      "uas"),
    ("brinc",       "uas"),
    ("autel",       "uas"),
    ("parrot",      "uas"),
    # VMS
    ("milestone",   "vms"),
    ("genetec",     "vms"),
    ("avigilon",    "vms"),
    ("exacqvision", "vms"),
    # Acoustic / environmental
    ("shotspotter", "environmental_sensor"),
    ("soundthinking", "environmental_sensor"),
    ("flir",        "environmental_sensor"),
    # Access control
    ("lenel",       "access_control"),
    ("brivo",       "access_control"),
    ("hid global",  "access_control"),
    ("s2 security", "access_control"),
    # Radio / comms (Motorola makes many things; radio is its PS default)
    ("l3harris",    "radio_comms"),
    ("harris",      "radio_comms"),
    ("tait",        "radio_comms"),
    ("kenwood",     "radio_comms"),
    ("motorola solutions", "radio_comms"),
    # Generic surveillance camera brands
    ("hikvision",   "camera"),
    ("dahua",       "camera"),
    ("axis",        "camera"),
    ("verkada",     "camera"),
    ("hanwha",      "camera"),
    ("bosch security", "camera"),
]

# Discovery categories that map 1:1 onto a ps_category even without a
# recognized vendor.
_CATEGORY_HINTS: dict[str, str] = {
    "camera":        "camera",
    "alpr":          "alpr",
    "uas":           "uas",
    "vms":           "vms",
    "bodycam-infra": "body_camera_infrastructure",
    "radio":         "radio_comms",
    "access-control": "access_control",
}


def ps_category_for(vendor: str = "", category: str = "",
                     banners_text: str = "") -> str:
    """Best-effort public-safety category, or "" when the asset doesn't
    look public-safety related. Vendor beats generic category so a Flock
    device classified 'camera' still lands as ALPR."""
    hay = f"{(vendor or '').lower()} {(banners_text or '').lower()}"
    for needle, cat in _VENDOR_HINTS:
        if needle in hay:
            return cat
    return _CATEGORY_HINTS.get((category or "").lower(), "")


def classify_public_safety(vendor: str = "", category: str = "",
                            banners_text: str = "") -> PublicSafety:
    """Build a PublicSafety block from discovery signals. Returns an
    empty block (ps_category="") when nothing matches — safe to assign
    unconditionally."""
    cat = ps_category_for(vendor=vendor, category=category,
                           banners_text=banners_text)
    if not cat:
        return PublicSafety()
    meta = PS_CATEGORIES.get(cat, {})
    return PublicSafety(
        ps_category=cat,
        mission_function=str(meta.get("mission", "")),
        evidence_roles=list(meta.get("roles", [])),
        cji_classification=str(meta.get("cji", "unknown")),
    )


def is_evidence_infrastructure(ps: PublicSafety | dict) -> bool:
    """Does this asset participate in the evidence chain (capture →
    transfer → store → access → preserve)? Accepts the dataclass or its
    dict form (stored assets)."""
    roles = ps.get("evidence_roles") if isinstance(ps, dict) else ps.evidence_roles
    return bool(roles)
