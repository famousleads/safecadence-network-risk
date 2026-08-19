"""
DESAT — Evidence Infrastructure Health tests.

Engine (platform/evidence_health.py):
  * honest empty state — no evidence assets → unknown, never healthy
  * stage selection via public_safety.evidence_roles AND operator tags
  * store-stage capacity/replication checks
  * preserve-stage backup staleness/immutability checks
  * KEV on evidence infrastructure escalates to critical
  * coverage gaps reported even when monitored stages are healthy

Report section (reports/sections.py):
  * registered in SECTION_REGISTRY, default OFF (back-compat)
  * composes against a scoped platform-asset store
"""

from __future__ import annotations

import json


def _asset(hostname, roles=None, tags=None, **over):
    """Minimal stored-asset dict in the asdict(UnifiedAsset) shape."""
    a = {
        "identity": {"asset_id": hostname, "hostname": hostname,
                       "asset_type": over.pop("asset_type", "iot"),
                       "site": over.pop("site", "hq"),
                       "tags": tags or []},
        "public_safety": {"ps_category": over.pop("ps_category", "camera"),
                            "evidence_roles": roles or []},
        "health": {"overall_score": over.pop("score", 95),
                    "risk_band": over.pop("band", "safe")},
        "security": {"kev_cves": over.pop("kev", 0),
                      "critical_cves": over.pop("crit_cves", 0),
                      "weak_protocols": over.pop("weak", [])},
        "storage": over.pop("storage", {}),
        "backup": over.pop("backup", {}),
    }
    return a


# ============================================================ engine


def test_empty_fleet_is_unknown_not_healthy():
    from safecadence.platform.evidence_health import (
        evidence_infrastructure_summary,
    )
    s = evidence_infrastructure_summary([])
    assert s["overall_status"] == "unknown"
    assert "not established" in s["headline"]
    assert s["guidance"]


def test_non_evidence_assets_do_not_count():
    from safecadence.platform.evidence_health import (
        evidence_infrastructure_summary,
    )
    sw = _asset("core-sw-01", roles=[], ps_category="")
    s = evidence_infrastructure_summary([sw])
    assert s["overall_status"] == "unknown"


def test_healthy_capture_stage_with_coverage_gap_guidance():
    from safecadence.platform.evidence_health import (
        evidence_infrastructure_summary,
    )
    cam = _asset("cam-01", roles=["capture"])
    s = evidence_infrastructure_summary([cam])
    assert s["stages"]["capture"]["status"] == "healthy"
    assert s["overall_status"] == "healthy"
    # Missing stages are called out as a gap, not silently ignored.
    assert "store" in s["guidance"]


def test_operator_tag_enrolls_asset_in_stage():
    from safecadence.platform.evidence_health import (
        evidence_infrastructure_summary,
    )
    nas = _asset("evid-nas-01", roles=[], ps_category="",
                  tags=["evidence:store"], asset_type="storage")
    s = evidence_infrastructure_summary([nas])
    assert s["stages"]["store"]["asset_count"] == 1
    # bare "evidence" tag = every stage
    all_st = _asset("evid-core", roles=[], ps_category="", tags=["evidence"])
    s2 = evidence_infrastructure_summary([all_st])
    assert all(s2["stages"][st]["asset_count"] == 1
                for st in ("capture", "transfer", "store", "access", "preserve"))


def test_store_capacity_thresholds():
    from safecadence.platform.evidence_health import (
        evidence_infrastructure_summary,
    )
    warn = _asset("nas-warn", roles=["store"],
                   storage={"total_capacity_tb": 100, "used_capacity_tb": 90})
    crit = _asset("nas-crit", roles=["store"],
                   storage={"total_capacity_tb": 100, "used_capacity_tb": 96})
    s = evidence_infrastructure_summary([warn])
    assert s["stages"]["store"]["status"] == "warning"
    s = evidence_infrastructure_summary([crit])
    assert s["stages"]["store"]["status"] == "critical"
    assert s["overall_status"] == "critical"


def test_broken_replication_is_critical():
    from safecadence.platform.evidence_health import (
        evidence_infrastructure_summary,
    )
    nas = _asset("nas-01", roles=["store"],
                  storage={"replication_status": "broken"})
    s = evidence_infrastructure_summary([nas])
    assert s["stages"]["store"]["status"] == "critical"


def test_preserve_stage_backup_checks():
    from safecadence.platform.evidence_health import (
        evidence_infrastructure_summary,
    )
    stale = _asset("veeam-tgt", roles=["preserve"],
                    backup={"platform": "veeam", "last_backup_status": "success",
                             "rpo_target_hours": 24, "actual_rpo_hours": 72,
                             "immutability_enabled": True})
    s = evidence_infrastructure_summary([stale])
    assert s["stages"]["preserve"]["status"] == "warning"
    assert any("72h old" in i["message"]
                for i in s["stages"]["preserve"]["issues"])

    failed = _asset("veeam-tgt2", roles=["preserve"],
                     backup={"platform": "veeam",
                              "last_backup_status": "failed"})
    s = evidence_infrastructure_summary([failed])
    assert s["stages"]["preserve"]["status"] == "critical"


def test_kev_on_evidence_infrastructure_is_critical():
    from safecadence.platform.evidence_health import (
        evidence_infrastructure_summary,
    )
    vms = _asset("vms-01", roles=["store", "access"], kev=2)
    s = evidence_infrastructure_summary([vms])
    assert s["stages"]["access"]["status"] == "critical"
    assert s["overall_status"] == "critical"


def test_disclaimer_present():
    from safecadence.platform.evidence_health import (
        evidence_infrastructure_summary,
    )
    s = evidence_infrastructure_summary([])
    assert "chain-of-custody" in s["disclaimer"]


# ============================================================ report section


def test_section_registered_default_off():
    from safecadence.reports.sections import SECTION_REGISTRY
    entry = next((s for s in SECTION_REGISTRY
                   if s["key"] == "evidence_infrastructure"), None)
    assert entry is not None
    assert entry["default_enabled"] is False
    assert entry["category"] == "Public safety"


def test_section_composes_from_store(tmp_path, monkeypatch):
    # reports/sections._load_platform_assets reads SC_DATA_DIR/platform_assets
    monkeypatch.setenv("SC_DATA_DIR", str(tmp_path))
    store = tmp_path / "platform_assets"
    store.mkdir()
    cam = _asset("cam-hq-01", roles=["capture"])
    (store / "cam-hq-01.json").write_text(json.dumps(cam))

    from safecadence.reports.sections import evidence_infrastructure
    out = evidence_infrastructure(None, {})
    assert out["title"] == "Evidence infrastructure health"
    assert out["empty"] is False
    assert "capture" in out["html_fragment"].lower()
    assert out["data"]["stages"]["capture"]["asset_count"] == 1
