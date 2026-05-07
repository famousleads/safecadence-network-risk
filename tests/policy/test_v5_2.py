"""Test coverage for the v5.2 modules:
  - bridge          (Discovery → Platform)
  - cve_enrichment  (KEV + EPSS + exploit-availability prioritization)
  - search          (Fleet-wide search with facets + free text)
  - attack_paths    (Blast-radius graph + attack-paths-to)
  - scheduler       (run_cycle one-shot)
  - attack_mapping  (MITRE ATT&CK technique coverage)
  - executive_briefing (offline + compliance gap delta)
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


# --------------------------------------------------------------------------
# Discovery → Platform bridge
# --------------------------------------------------------------------------

def test_bridge_basic_conversion():
    from safecadence.platform.bridge import discovered_to_asset
    h = {"ip": "10.0.0.5", "hostname": "r5", "mac": "aa:bb:cc:dd:ee:01",
         "vendor_guess": "cisco", "os_guess": "ios-xe",
         "device_type_guess": "router", "open_ports": [22, 23, 443]}
    a = discovered_to_asset(h)
    assert a.identity.asset_id
    assert a.identity.vendor == "cisco"
    assert a.identity.asset_type == "network"
    assert "telnet" in a.security.weak_protocols
    assert a.health is not None


def test_bridge_adopt_persists(isolated_home):
    """adopt_discovered should write JSON files under platform_assets/."""
    from safecadence.platform.bridge import adopt_discovered
    res = adopt_discovered({"hosts": [
        {"ip": "10.0.0.6", "mac": "aa:bb:cc:dd:ee:02",
         "vendor_guess": "arista", "device_type_guess": "switch"},
    ]})
    assert res["adopted"] == 1
    assert (Path.home() / ".safecadence" / "platform_assets").exists()


# --------------------------------------------------------------------------
# CVE enrichment
# --------------------------------------------------------------------------

def test_priority_ranking_beats_cvss_only():
    """KEV-listed CVE must rank ABOVE a higher-CVSS one with no real exploit."""
    from safecadence.platform.cve_enrichment import enrich_cve, priority_score
    high_cvss_no_exploit = enrich_cve({"cve_id": "CVE-X-1", "cvss": 9.8,
                                        "kev": False, "epss": 0.01})
    kev_med_cvss = enrich_cve({"cve_id": "CVE-X-2", "cvss": 6.5,
                                "kev": True, "epss": 0.95})
    assert kev_med_cvss["priority_score"] > high_cvss_no_exploit["priority_score"]
    assert kev_med_cvss["priority_band"] in ("critical", "high")


def test_priority_band_thresholds():
    from safecadence.platform.cve_enrichment import priority_band
    assert priority_band(700) == "critical"
    assert priority_band(450) == "high"
    assert priority_band(250) == "medium"
    assert priority_band(75) == "low"
    assert priority_band(10) == "info"


# --------------------------------------------------------------------------
# Fleet search
# --------------------------------------------------------------------------

def _fake_assets():
    return [
        {"identity": {"asset_id": "r1", "vendor": "cisco", "asset_type": "network",
                      "environment": "prod", "hostname": "edge-1"},
         "health": {"grade": "C"}, "security": {"kev_cves": 2, "critical_cves": 3}},
        {"identity": {"asset_id": "srv1", "vendor": "dell", "asset_type": "server",
                      "environment": "prod", "hostname": "web1"},
         "health": {"grade": "A"}, "security": {"kev_cves": 0, "critical_cves": 0}},
        {"identity": {"asset_id": "cl1", "vendor": "aws", "asset_type": "cloud"},
         "cloud": {"public_exposure": True},
         "security": {"kev_cves": 0, "critical_cves": 5}},
    ]


def test_search_facet_vendor_and_env():
    from safecadence.platform.search import search
    r = search(_fake_assets(), "vendor:cisco env:prod")
    assert r["count"] == 1
    assert r["results"][0]["asset_id"] == "r1"


def test_search_facet_kev():
    from safecadence.platform.search import search
    r = search(_fake_assets(), "kev:true")
    assert r["count"] == 1
    assert r["results"][0]["asset_id"] == "r1"


def test_search_free_text_filters():
    from safecadence.platform.search import search
    r = search(_fake_assets(), "cisco")
    # Free text "cisco" matches r1 (vendor) and nothing else — score must be > 0
    assert r["count"] == 1


def test_search_grade_facet():
    from safecadence.platform.search import search
    r = search(_fake_assets(), "grade:A")
    ids = [x["asset_id"] for x in r["results"]]
    assert "srv1" in ids


# --------------------------------------------------------------------------
# Attack-path engine
# --------------------------------------------------------------------------

def _correlated_fleet():
    return [
        {"identity": {"asset_id": "esxi1", "asset_type": "hypervisor",
                       "vendor": "vmware", "environment": "prod"},
         "virtualization": {"datastores": [{"name": "lun-001"}],
                             "vms": [{"name": "vm-a"}]}},
        {"identity": {"asset_id": "pure1", "asset_type": "storage",
                       "vendor": "pure", "environment": "prod"},
         "storage": {"volumes": [{"name": "lun-001"}]}},
        {"identity": {"asset_id": "veeam1", "asset_type": "backup",
                       "vendor": "veeam", "environment": "prod"},
         "raw_collection": {"protected": "esxi1 vm-a"}},
        {"identity": {"asset_id": "aws-1", "asset_type": "cloud", "vendor": "aws"},
         "cloud": {"public_exposure": True, "account_id": "1234"}},
        {"identity": {"asset_id": "aws-2", "asset_type": "cloud", "vendor": "aws"},
         "cloud": {"account_id": "1234"}},
    ]


def test_blast_radius_from_hypervisor():
    from safecadence.platform.attack_paths import blast_radius
    br = blast_radius("esxi1", _correlated_fleet())
    types = br["by_type"]
    assert "storage" in types        # via datastore→volume
    assert br["reached"] >= 2


def test_blast_radius_from_internet():
    from safecadence.platform.attack_paths import blast_radius
    br = blast_radius("internet", _correlated_fleet())
    assert br["reached"] >= 1
    # First hop must be the public-exposure asset
    assert any(p["asset_id"] == "aws-1" and p["hops"] == 1 for p in br["paths"])


def test_blast_radius_unknown_asset_returns_error():
    from safecadence.platform.attack_paths import blast_radius
    br = blast_radius("does-not-exist", _correlated_fleet())
    assert br.get("error") == "asset not found"


def test_attack_paths_to_target():
    from safecadence.platform.attack_paths import attack_paths_to
    paths = attack_paths_to("aws-2", _correlated_fleet())
    starts = {p["starting_asset"] for p in paths}
    assert "aws-1" in starts


# --------------------------------------------------------------------------
# Scheduler
# --------------------------------------------------------------------------

def test_scheduler_run_cycle_with_no_policies():
    """Empty fleet, no policies — must still return a clean summary."""
    from safecadence.policy.scheduler import run_cycle
    s = run_cycle()
    assert s["policies_evaluated"] == 0
    assert s["regressions_detected"] == 0


def test_scheduler_run_cycle_with_one_policy(cisco_router_clean):
    from safecadence.policy.scheduler import run_cycle
    from safecadence.policy.store import save
    from safecadence.policy.templates import load_template
    p = load_template("tmpl_network_hardening")
    save(p, actor="t")
    # Seed an asset
    asset_dir = Path.home() / ".safecadence" / "platform_assets"
    asset_dir.mkdir(parents=True, exist_ok=True)
    (asset_dir / "r1.json").write_text(json.dumps(cisco_router_clean), encoding="utf-8")
    s = run_cycle()
    assert s["policies_evaluated"] == 1
    assert s["assets_scanned"] == 1


# --------------------------------------------------------------------------
# ATT&CK mapping
# --------------------------------------------------------------------------

def test_attack_mapping_for_disable_telnet():
    from safecadence.policy.attack_mapping import techniques_for_control
    techs = techniques_for_control("disable_telnet")
    assert any(t["technique_id"].startswith("T1021") for t in techs)
    assert any(t["technique_id"] == "T1040" for t in techs)


def test_attack_coverage_report():
    from safecadence.policy.attack_mapping import coverage_report
    rep = coverage_report(["disable_telnet", "enforce_mfa", "block_public_exposure"])
    assert rep["control_count"] == 3
    assert rep["techniques_covered"] >= 5
    assert rep["tactics_covered"] >= 3
    assert "Initial Access" in rep["tactics"]


def test_violation_to_attack_mapping():
    from safecadence.policy.attack_mapping import violation_to_attack
    v = [{"violation_id": "v1", "control_id": "enforce_mfa",
          "asset_id": "srv1", "severity": "high"}]
    out = violation_to_attack(v)
    assert len(out) == 1
    assert out[0]["enables_techniques"]


# --------------------------------------------------------------------------
# Executive briefing + compliance gap delta
# --------------------------------------------------------------------------

def test_executive_briefing_offline_renders():
    from safecadence.policy.executive_briefing import build_briefing_offline
    assets = [
        {"identity": {"asset_id": "x", "asset_type": "server", "criticality": "crown-jewel"},
         "health": {"grade": "F"}, "security": {"critical_cves": 2, "kev_cves": 1}},
    ]
    metas = [{"policy_id": "p1", "policy_name": "Server Hardening"}]
    evals = {"p1": {"pass": 3, "fail": 2, "coverage_pct": 60}}
    b = build_briefing_offline(assets, metas, evals)
    assert "Executive Security Briefing" in b["markdown"]
    assert "KEV" in b["markdown"]
    assert b["asset_summary"]["asset_count"] == 1
    assert b["asset_summary"]["crown_jewels"] == 1


def test_compliance_gap_delta_detects_regression():
    from safecadence.policy.executive_briefing import compliance_gap_delta
    prev = {"evaluated_at": "2026-05-01", "pass_count": 8, "fail_count": 2,
            "asset_results": [{"asset_id": "r1",
                                "controls": {"enforce_ssh_v2": "pass",
                                             "disable_telnet": "pass"}}]}
    curr = {"evaluated_at": "2026-05-04", "pass_count": 6, "fail_count": 4,
            "asset_results": [{"asset_id": "r1",
                                "controls": {"enforce_ssh_v2": "pass",
                                             "disable_telnet": "fail"}}]}
    d = compliance_gap_delta(prev, curr)
    assert d["regression_count"] == 1
    assert d["compliance_pct_delta"] < 0
    assert d["regressions"][0]["control_id"] == "disable_telnet"


def test_compliance_gap_delta_detects_improvement():
    from safecadence.policy.executive_briefing import compliance_gap_delta
    prev = {"pass_count": 1, "fail_count": 1,
            "asset_results": [{"asset_id": "r1",
                                "controls": {"enforce_mfa": "fail"}}]}
    curr = {"pass_count": 2, "fail_count": 0,
            "asset_results": [{"asset_id": "r1",
                                "controls": {"enforce_mfa": "pass"}}]}
    d = compliance_gap_delta(prev, curr)
    assert d["improvement_count"] == 1
    assert d["compliance_pct_delta"] > 0
