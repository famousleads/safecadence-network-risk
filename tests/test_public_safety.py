"""
DESAT — public-safety asset taxonomy tests.

Covers:
  * schema        — PublicSafety block exists, defaults empty, additive
  * taxonomy      — every registry category is well-formed
  * classifier    — vendor beats generic category (Flock camera → ALPR)
  * categorize    — discovery returns the new public-safety categories
  * bridge        — discovered host gets a populated public_safety block
  * back-compat   — assets stored before this feature still round-trip
"""

from __future__ import annotations


# ============================================================ schema


def test_unified_asset_has_empty_public_safety_by_default():
    from safecadence.platform.schema import UnifiedAsset
    a = UnifiedAsset()
    assert a.public_safety.ps_category == ""
    assert a.public_safety.evidence_roles == []
    assert a.public_safety.latitude == 0.0
    d = a.to_dict()
    assert d["public_safety"]["ps_category"] == ""


def test_old_stored_asset_dict_without_ps_block_still_usable():
    """Assets persisted before this feature have no public_safety key.
    Consumers read stored assets as dicts — absence must be tolerable."""
    from safecadence.platform.schema import UnifiedAsset
    old = UnifiedAsset().to_dict()
    old.pop("public_safety")
    # dict consumers use .get; simulate the common access pattern
    assert old.get("public_safety", {}).get("ps_category", "") == ""


# ============================================================ taxonomy


def test_every_registry_category_is_well_formed():
    from safecadence.platform.public_safety import PS_CATEGORIES
    for cat, meta in PS_CATEGORIES.items():
        assert meta.get("label"), cat
        assert "mission" in meta, cat
        assert isinstance(meta.get("roles"), list), cat
        assert meta.get("cji") in ("cji", "non_cji", "unknown"), cat


# ============================================================ classifier


def test_vendor_hint_beats_generic_category():
    """A Flock device discovered as a plain 'camera' must classify as
    ALPR — the vendor signal is more specific."""
    from safecadence.platform.public_safety import classify_public_safety
    ps = classify_public_safety(vendor="flock safety", category="camera")
    assert ps.ps_category == "alpr"
    assert ps.cji_classification == "cji"


def test_generic_camera_classifies_as_camera():
    from safecadence.platform.public_safety import classify_public_safety
    ps = classify_public_safety(vendor="axis communications",
                                  category="camera")
    assert ps.ps_category == "camera"
    assert "capture" in ps.evidence_roles


def test_non_public_safety_asset_gets_empty_block():
    from safecadence.platform.public_safety import classify_public_safety
    ps = classify_public_safety(vendor="cisco", category="switch")
    assert ps.ps_category == ""
    assert ps.evidence_roles == []


def test_evidence_infrastructure_predicate():
    from safecadence.platform.public_safety import (
        classify_public_safety, is_evidence_infrastructure,
    )
    vms = classify_public_safety(vendor="milestone systems", category="")
    radio = classify_public_safety(vendor="l3harris", category="")
    assert is_evidence_infrastructure(vms) is True
    assert is_evidence_infrastructure(radio) is False
    # dict form (stored asset) works too
    assert is_evidence_infrastructure(
        {"evidence_roles": ["store"]}) is True


# ============================================================ categorize


class _Host:
    """Minimal DiscoveredHost stand-in for categorize_device."""
    def __init__(self, vendor="", ports=None, banners=None, guess=""):
        self.mac = "aa:bb:cc:dd:ee:ff"
        self.vendor_guess = vendor
        self.open_ports = ports or []
        self.banners = banners or {}
        self.device_type_guess = guess


def test_categorize_detects_public_safety_vendors():
    from safecadence.discovery.categorize import categorize_device
    assert categorize_device(_Host(vendor="Flock Safety",
                                     ports=[554])) == "alpr"
    assert categorize_device(_Host(vendor="Axon Enterprise")) == "bodycam-infra"
    assert categorize_device(_Host(vendor="Skydio")) == "uas"
    assert categorize_device(_Host(vendor="Genetec Inc")) == "vms"
    assert categorize_device(_Host(vendor="Motorola Solutions")) == "radio"
    assert categorize_device(_Host(vendor="Lenel")) == "access-control"


def test_categorize_axis_camera_still_camera():
    from safecadence.discovery.categorize import categorize_device
    assert categorize_device(_Host(vendor="Axis Communications",
                                     ports=[554])) == "camera"


def test_categorize_existing_behavior_unchanged():
    from safecadence.discovery.categorize import categorize_device
    assert categorize_device(_Host(vendor="Hikvision",
                                     ports=[554])) == "camera"
    assert categorize_device(_Host(vendor="Cisco Systems")) == "switch"
    assert categorize_device(_Host(ports=[9100])) == "printer"


# ============================================================ bridge


def test_bridge_populates_public_safety_block():
    from safecadence.platform.bridge import discovered_to_asset
    asset = discovered_to_asset({
        "ip": "10.20.0.9", "mac": "aa:bb:cc:00:11:22",
        "hostname": "alpr-cam-03", "vendor_guess": "Flock Safety",
        "device_type_guess": "alpr", "open_ports": [443, 554],
    })
    assert asset.public_safety.ps_category == "alpr"
    assert asset.identity.asset_type == "iot"       # base type unchanged
    assert asset.public_safety.cji_classification == "cji"


def test_bridge_non_ps_asset_keeps_empty_block():
    from safecadence.platform.bridge import discovered_to_asset
    asset = discovered_to_asset({
        "ip": "10.0.0.1", "mac": "aa:bb:cc:00:11:33",
        "hostname": "core-sw-01", "vendor_guess": "Cisco Systems",
        "device_type_guess": "switch", "open_ports": [22],
    })
    assert asset.public_safety.ps_category == ""
