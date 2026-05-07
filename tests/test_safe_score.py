"""
v9.24 — unit tests for the Safe Score module.

Covers:
  * Per-asset score with each signal type independently
  * Fleet aggregate is criticality-weighted (not a flat mean)
  * Caps bind so a single signal can't zero the score
  * Weak-link picks the asset on the most paths and projects a
    higher fleet score after remediation
  * Empty / missing inputs degrade gracefully
"""

from __future__ import annotations

import pytest

from safecadence.scores import (
    score_asset_safe,
    score_fleet_safe,
    weak_link,
)


# ----------------------------------------------------------- helpers


def _asset(aid: str, *, criticality: str = "medium",
            hostname: str | None = None) -> dict:
    return {
        "identity": {
            "asset_id": aid,
            "hostname": hostname or aid,
            "criticality": criticality,
        },
    }


# ------------------------------------------------------------- per-asset


def test_safe_score_no_signals_is_perfect():
    s = score_asset_safe(_asset("a1"))
    assert s.score == 100
    assert s.band == "A"
    assert s.reasons == []


def test_safe_score_drops_for_critical_finding():
    s = score_asset_safe(
        _asset("a1"),
        findings=[{"asset_id": "a1", "severity": "critical",
                   "kind": "exposed_admin"}],
    )
    assert s.score < 100
    assert any(r[0] == "findings" for r in s.reasons)


def test_safe_score_kev_cve_hits_harder_than_plain_cvss():
    plain = score_asset_safe(
        _asset("a1"),
        cves=[{"asset_id": "a1",
                "cves": [{"id": "CVE-2021-1", "cvss": 7.5}]}],
    )
    kev = score_asset_safe(
        _asset("a1"),
        cves=[{"asset_id": "a1",
                "cves": [{"id": "CVE-2021-1", "cvss": 7.5,
                           "kev": True, "epss": 0.7}]}],
    )
    assert kev.score < plain.score


def test_safe_score_attack_path_membership_deducts():
    s = score_asset_safe(
        _asset("a1"),
        paths=[{"target": "crown-jewel",
                 "target_criticality": "critical",
                 "nodes": ["a1", "a2", "crown-jewel"]}],
    )
    assert s.score < 100
    assert s.inputs["paths"] == 1


def test_safe_score_findings_for_other_asset_dont_count():
    s = score_asset_safe(
        _asset("a1"),
        findings=[{"asset_id": "a2", "severity": "critical",
                   "kind": "exposed_admin"}],
    )
    assert s.score == 100


def test_safe_score_caps_so_one_category_cant_zero_it():
    """100 critical findings on one asset shouldn't drop it below the
    findings-cap minimum (i.e. score should be > 0 after only finding
    deductions).
    """
    findings = [{"asset_id": "a1", "severity": "critical",
                  "kind": "x"} for _ in range(100)]
    s = score_asset_safe(_asset("a1"), findings=findings)
    # Only the findings cap applies; other categories haven't hit.
    # Cap is 35, so score >= 100 - 35 = 65.
    assert s.score >= 65


def test_safe_score_band_thresholds():
    # 100 → A, 0 → F
    perfect = score_asset_safe(_asset("a1"))
    assert perfect.band == "A"
    bad = score_asset_safe(
        _asset("a1"),
        findings=[{"asset_id": "a1", "severity": "critical", "kind": "x"}
                   for _ in range(10)],
        cves=[{"asset_id": "a1",
                "cves": [{"id": f"CVE-2021-{i}", "cvss": 9.5,
                           "kev": True, "epss": 0.9}
                          for i in range(10)]}],
        paths=[{"target": "x", "target_criticality": "critical",
                 "nodes": ["a1", "x"]} for _ in range(10)],
        drift_count=10, missing_controls=10,
    )
    assert bad.band == "F"
    assert bad.score == 0


# --------------------------------------------------------------- fleet


def test_fleet_score_returns_per_asset_and_headline():
    assets = [_asset("a1"), _asset("a2"), _asset("a3")]
    r = score_fleet_safe(assets)
    assert r["fleet_score"] == 100
    assert r["asset_count"] == 3
    assert len(r["per_asset"]) == 3
    assert r["band_counts"]["A"] == 3


def test_fleet_score_criticality_weighted():
    """One bad CRITICAL asset should drag the fleet score harder than
    one bad LOW asset."""
    bad_findings_for = lambda aid: [
        {"asset_id": aid, "severity": "critical", "kind": "x"}
        for _ in range(8)
    ]
    crit_bad = score_fleet_safe(
        [_asset("crit", criticality="critical"),
          _asset("ok-1"), _asset("ok-2")],
        findings=bad_findings_for("crit"),
    )
    low_bad = score_fleet_safe(
        [_asset("low", criticality="low"),
          _asset("ok-1"), _asset("ok-2")],
        findings=bad_findings_for("low"),
    )
    assert crit_bad["fleet_score"] < low_bad["fleet_score"]


def test_fleet_score_worst_assets_top5():
    assets = [_asset(f"a{i}") for i in range(10)]
    findings = [{"asset_id": "a0", "severity": "critical", "kind": "x"}
                  for _ in range(5)]
    r = score_fleet_safe(assets, findings=findings)
    assert r["worst_assets"][0]["asset_id"] == "a0"
    assert len(r["worst_assets"]) <= 5


def test_fleet_score_handles_empty_input():
    r = score_fleet_safe([])
    assert r["fleet_score"] == 100
    assert r["asset_count"] == 0


# ----------------------------------------------------------- weak link


def test_weak_link_picks_node_on_most_paths():
    assets = [_asset("a1"), _asset("a2"), _asset("a3"),
                _asset("crown", criticality="critical")]
    paths = [
        {"target": "crown", "target_criticality": "critical",
          "nodes": ["a1", "a2", "crown"]},
        {"target": "crown", "target_criticality": "critical",
          "nodes": ["a1", "a3", "crown"]},
        {"target": "crown", "target_criticality": "critical",
          "nodes": ["a1", "crown"]},
    ]
    wl = weak_link(assets, paths)
    assert wl is not None
    # a1 is on all 3 paths, a2 only on 1, a3 only on 1 → a1 wins.
    assert wl["asset_id"] == "a1"
    assert wl["paths_killed"] == 3


def test_weak_link_target_is_not_its_own_weak_link():
    assets = [_asset("a1"), _asset("crown", criticality="critical")]
    paths = [{"target": "crown", "target_criticality": "critical",
                "nodes": ["a1", "crown"]}]
    wl = weak_link(assets, paths)
    assert wl is not None
    assert wl["asset_id"] != "crown"


def test_weak_link_projects_higher_fleet_score():
    """Removing the weak link's findings should raise the fleet score."""
    assets = [_asset("a1"), _asset("a2"),
                _asset("crown", criticality="critical")]
    findings = [{"asset_id": "a1", "severity": "critical",
                  "kind": "rce"} for _ in range(5)]
    paths = [{"target": "crown", "target_criticality": "critical",
                "nodes": ["a1", "crown"]}]
    wl = weak_link(assets, paths, findings=findings)
    assert wl is not None
    assert wl["projected_fleet_score"] > wl["current_fleet_score"]
    assert wl["score_lift"] > 0


def test_weak_link_returns_none_when_no_paths():
    assets = [_asset("a1"), _asset("a2")]
    assert weak_link(assets, []) is None


def test_safe_score_to_dict_serializable():
    """The UI consumes JSON; make sure we can roundtrip."""
    import json
    s = score_asset_safe(
        _asset("a1"),
        findings=[{"asset_id": "a1", "severity": "high", "kind": "x"}],
    )
    d = s.to_dict()
    assert json.dumps(d)  # raises if not serializable
    assert d["asset_id"] == "a1"
    assert "score" in d and "band" in d and "reasons" in d
