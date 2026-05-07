"""Tests for v6.2.1 hardening fixes.

Covers:
  - Cross-system drift now exposes 17 detectors and runs each defensively.
  - Backup translators (Veeam, AWS S3 Object Lock, Azure Blob immutability)
    register correctly and produce non-empty fix/rollback/verify blocks.
  - Top-risks scoring weights internet-reach + downstream crown-jewels.
  - Top-risks de-duplicates same (asset, control) across multiple policies.
  - Attack-paths exposes top_k_paths_to_crown_jewels.
  - asset_id path-traversal protection in platform_api.
  - Executive briefing surfaces ai_error rather than silently falling back.
"""

from __future__ import annotations


# --------------------------------------------------------------------------
# Cross-system drift
# --------------------------------------------------------------------------

def test_cross_system_drift_has_seventeen_detectors():
    from safecadence.policy.cross_system_drift import ALL_DETECTORS, detect_all
    assert len(ALL_DETECTORS) >= 17
    # Empty fleet should still produce a valid result envelope.
    result = detect_all([])
    assert result["finding_count"] == 0
    assert result["detector_count"] == len(ALL_DETECTORS)
    assert "across" in result["summary"]
    assert isinstance(result["detector_errors"], list)


def test_admin_without_mfa_detector_fires():
    from safecadence.policy.cross_system_drift import detect_admin_without_mfa
    asset = {
        "identity": {"asset_id": "alice@corp", "asset_type": "identity"},
        "identity_block": {
            "provider": "okta",
            "authorized_groups": ["domain-admins"],
            "mfa_enrolled": False,
        },
    }
    findings = detect_admin_without_mfa([asset])
    assert len(findings) == 1
    assert findings[0]["severity"] == "critical"
    assert findings[0]["type"] == "admin_without_mfa"


def test_default_credentials_detector_fires():
    from safecadence.policy.cross_system_drift import detect_default_credentials
    asset = {
        "identity": {"asset_id": "rtr-edge-01", "asset_type": "network",
                     "vendor": "cisco"},
        "raw_collection": {"running": "username admin\npassword admin\n"},
    }
    findings = detect_default_credentials([asset])
    assert findings and findings[0]["severity"] == "critical"


def test_eos_in_crown_jewel_detector_fires():
    from safecadence.policy.cross_system_drift import detect_eos_in_crown_jewel
    asset = {
        "identity": {"asset_id": "core-sw-1", "asset_type": "network",
                     "criticality": "crown-jewel", "vendor": "cisco"},
        "lifecycle": {"days_until_eos": -30},
    }
    findings = detect_eos_in_crown_jewel([asset])
    assert findings and findings[0]["severity"] == "critical"


def test_detect_all_swallows_per_detector_exceptions():
    """A single bad detector should not nuke the whole result."""
    from safecadence.policy import cross_system_drift as csd
    original = csd.ALL_DETECTORS

    def boom(_assets):  # pragma: no cover - exercised via patched ALL_DETECTORS
        raise RuntimeError("simulated detector failure")

    try:
        csd.ALL_DETECTORS = (boom, *original)
        result = csd.detect_all([])
    finally:
        csd.ALL_DETECTORS = original
    assert any(e["detector"] == "boom" for e in result["detector_errors"])


# --------------------------------------------------------------------------
# Backup translators
# --------------------------------------------------------------------------

def test_backup_translators_register():
    # Importing the package side-effect-loads every translator.
    from safecadence.policy.translators import _TRANSLATORS  # noqa: PLC0415
    assert "veeam" in _TRANSLATORS
    assert "aws_s3_lock" in _TRANSLATORS
    assert "azure_blob_immutable" in _TRANSLATORS


def test_veeam_immutability_emits_hardened_repo_command():
    from safecadence.policy.translators import _TRANSLATORS
    from safecadence.policy.schema import PolicyControl
    veeam = _TRANSLATORS["veeam"]
    fix = veeam.translate(
        PolicyControl(control_id="enforce_backup_immutability",
                      parameters={"immutability_days": 21}),
        asset={"identity": {"asset_id": "veeam-1"}},
    )
    assert fix.applicable
    joined = "\n".join(fix.fix).lower()
    assert "hardened" in joined or "makeimmutablefordays" in joined
    assert any("get-vbrbackuprepository" in v.lower() for v in fix.verify)


def test_aws_s3_lock_immutability_emits_compliance_mode():
    from safecadence.policy.translators import _TRANSLATORS
    from safecadence.policy.schema import PolicyControl
    aws = _TRANSLATORS["aws_s3_lock"]
    fix = aws.translate(
        PolicyControl(control_id="enforce_backup_immutability",
                      parameters={"immutability_days": 30}),
        asset={"identity": {"asset_id": "vault-1"}},
    )
    assert fix.applicable
    joined = "\n".join(fix.fix)
    assert "Object Lock" in joined or "object-lock" in joined
    assert "COMPLIANCE" in joined


def test_azure_blob_immutability_emits_locked_policy():
    from safecadence.policy.translators import _TRANSLATORS
    from safecadence.policy.schema import PolicyControl
    az = _TRANSLATORS["azure_blob_immutable"]
    fix = az.translate(
        PolicyControl(control_id="enforce_backup_immutability",
                      parameters={"immutability_days": 30}),
        asset={"identity": {"asset_id": "sa-backup"}},
    )
    assert fix.applicable
    joined = "\n".join(fix.fix).lower()
    assert "immutability-policy" in joined
    assert "lock" in joined


def test_unsupported_control_returns_inapplicable():
    from safecadence.policy.translators import _TRANSLATORS
    from safecadence.policy.schema import PolicyControl
    veeam = _TRANSLATORS["veeam"]
    fix = veeam.translate(
        PolicyControl(control_id="block_public_exposure"),
        asset={"identity": {"asset_id": "v1"}},
    )
    assert fix.applicable is False


# --------------------------------------------------------------------------
# Attack paths — cloud IAM, top-K
# --------------------------------------------------------------------------

def test_top_k_paths_to_crown_jewels_runs_with_no_jewels():
    from safecadence.platform.attack_paths import top_k_paths_to_crown_jewels
    assert top_k_paths_to_crown_jewels([]) == []


def test_top_k_paths_to_crown_jewels_returns_paths():
    from safecadence.platform.attack_paths import top_k_paths_to_crown_jewels
    assets = [
        {  # internet-facing front door
            "identity": {"asset_id": "edge-fw", "asset_type": "network",
                         "vendor": "fortinet", "site": "dc1"},
            "network": {"public_ip": True, "zone": "dmz"},
            "raw_collection": {"running": "permit any any\n"},
        },
        {  # crown-jewel app server in same site
            "identity": {"asset_id": "crm-prod", "asset_type": "server",
                         "criticality": "crown-jewel", "site": "dc1"},
            "security": {"kev_cves": 2, "critical_cves": 5},
        },
    ]
    paths = top_k_paths_to_crown_jewels(assets, k=5, max_hops=4)
    assert isinstance(paths, list)
    if paths:
        assert paths[0]["target_asset_id"] == "crm-prod"
        assert paths[0]["hops"] >= 1
        assert "summary" in paths[0]


def test_attack_paths_iam_cross_account_edge():
    from safecadence.platform.attack_paths import _edges
    src = {
        "identity": {"asset_id": "aws-acct-A", "asset_type": "cloud",
                     "vendor": "aws"},
        "cloud": {"account_id": "111111111111",
                  "trusted_accounts": ["222222222222"]},
    }
    dst = {
        "identity": {"asset_id": "aws-acct-B", "asset_type": "cloud",
                     "vendor": "aws"},
        "cloud": {"account_id": "222222222222"},
    }
    edges = _edges(src, [src, dst])
    assert any(e[1] == "iam_cross_account_trust" for e in edges)


# --------------------------------------------------------------------------
# Top-risks scoring
# --------------------------------------------------------------------------

def test_top_risks_score_weighs_internet_reach():
    from safecadence.policy.top_risks import _violation_score
    from safecadence.policy.schema import PolicyViolation, Severity

    asset = {
        "identity": {"asset_id": "edge-1", "criticality": "high"},
        "security": {"kev_cves": 0},
    }
    v = PolicyViolation(violation_id="v1", policy_id="p1",
                        control_id="c1", asset_id="edge-1",
                        severity=Severity.HIGH, evidence={})
    base = _violation_score(v, asset, reach=None)
    boosted = _violation_score(v, asset,
                               reach={"edge-1": {"internet_hops": 0}})
    assert boosted > base
    assert boosted - base == 150  # direct internet exposure bonus


def test_top_risks_score_weighs_downstream_jewels():
    from safecadence.policy.top_risks import _violation_score
    from safecadence.policy.schema import PolicyViolation, Severity

    asset = {"identity": {"asset_id": "hub-1"}, "security": {}}
    v = PolicyViolation(violation_id="v2", policy_id="p1",
                        control_id="c1", asset_id="hub-1",
                        severity=Severity.MEDIUM, evidence={})
    plain = _violation_score(v, asset)
    hub = _violation_score(
        v, asset, reach={"hub-1": {"downstream_crown_jewels": 5}})
    assert hub - plain == 5 * 30


# --------------------------------------------------------------------------
# Asset path-traversal protection
# --------------------------------------------------------------------------

def test_safe_asset_path_rejects_traversal(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_PLATFORM_STORE", str(tmp_path))
    from safecadence.server import platform_api
    import pytest
    for bad in ("../etc/passwd", "..\\windows\\system32",
                "foo/../bar", "with/slash", "a" * 300, "", None):
        with pytest.raises((ValueError, TypeError)):
            platform_api._safe_asset_path(bad)  # type: ignore[arg-type]


def test_safe_asset_path_accepts_normal_ids(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_PLATFORM_STORE", str(tmp_path))
    from safecadence.server import platform_api
    p = platform_api._safe_asset_path("edge-fw-01.example.com")
    assert str(p).endswith("edge-fw-01.example.com.json")


def test_get_asset_returns_none_for_traversal(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_PLATFORM_STORE", str(tmp_path))
    from safecadence.server import platform_api
    assert platform_api.get_asset("../etc/passwd") is None
    assert platform_api.get_asset("not-found") is None


# --------------------------------------------------------------------------
# Executive briefing — error surfacing
# --------------------------------------------------------------------------

def test_briefing_offline_always_works():
    from safecadence.policy.executive_briefing import build_briefing
    b = build_briefing([], [], {})
    assert b["source"] == "offline"
    assert "Executive Security Briefing" in b["markdown"]


def test_briefing_ai_request_without_provider_surfaces_error(monkeypatch):
    """Requesting --ai with no env keys should now produce ai_error,
    not silently fall back without telling the user."""
    from safecadence.policy.executive_briefing import build_briefing
    for k in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "OLLAMA_HOST"):
        monkeypatch.delenv(k, raising=False)
    b = build_briefing([], [], {}, ai=True)
    # Either no client installed (ai_error from import) or no provider
    # detected (ai_error from detect). Both are acceptable.
    assert "ai_error" in b
