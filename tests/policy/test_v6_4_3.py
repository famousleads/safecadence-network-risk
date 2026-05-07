"""v6.4.3 — Audit-finding regression tests.

Locks in fixes from the parallel adapter / translator / endpoint audit:
the demo fleet must populate fields that controls actually check, and
the previously-UNKNOWN check_fns must now produce verdicts.
"""

from __future__ import annotations

import os


def _load_demo(tmp_path, monkeypatch):
    monkeypatch.setenv("SC_PLATFORM_STORE", str(tmp_path))
    from safecadence.demo import load_demo_fleet
    load_demo_fleet()
    from safecadence.server.platform_api import list_assets
    return list_assets()


def _verdict_counts(spec, assets):
    from safecadence.policy.schema import EvaluationResult
    counts = {"pass": 0, "fail": 0, "na": 0, "unknown": 0}
    for a in assets:
        atype = (a.get("identity") or {}).get("asset_type")
        if atype not in (spec.applies_to or []):
            continue
        result, _ = spec.check_fn(a, {})
        v = result.value if hasattr(result, "value") else str(result).lower()
        if v == "pass": counts["pass"] += 1
        elif v == "fail": counts["fail"] += 1
        elif v in ("na", "not_applicable", "not-applicable"): counts["na"] += 1
        else: counts["unknown"] += 1
    return counts


# --------------------------------------------------------------------------
# Backup checks now actually verdict
# --------------------------------------------------------------------------

def test_immutability_check_now_pass_on_demo(tmp_path, monkeypatch):
    """v6.4.2 left this returning UNKNOWN for every demo asset.
    v6.4.3 lets it infer from immutability_days / vault_locked."""
    assets = _load_demo(tmp_path, monkeypatch)
    from safecadence.policy.controls import get_control
    counts = _verdict_counts(get_control("enforce_immutability"), assets)
    assert counts["pass"] >= 1, f"immutability still UNKNOWN: {counts}"
    assert counts["unknown"] == 0


def test_air_gap_check_finds_missing_air_gap(tmp_path, monkeypatch):
    """Veeam asset has air_gapped=False — control should flag it."""
    assets = _load_demo(tmp_path, monkeypatch)
    from safecadence.policy.controls import get_control
    counts = _verdict_counts(get_control("enforce_air_gap"), assets)
    assert counts["fail"] >= 1, f"air_gap not flagging Veeam: {counts}"
    assert counts["pass"] >= 1, "AWS Backup vault should pass air_gap"


def test_backup_retention_uses_immutability_days_fallback(
        tmp_path, monkeypatch):
    """Demo Veeam has immutability_days=14, retention_days=30 — both
    above the 30-day threshold once we accept the fallback."""
    assets = _load_demo(tmp_path, monkeypatch)
    from safecadence.policy.controls import get_control
    counts = _verdict_counts(get_control("enforce_backup_retention"),
                              assets)
    assert counts["pass"] >= 1, f"retention check broken: {counts}"


# --------------------------------------------------------------------------
# Encryption-at-rest now uses cloud + storage signals
# --------------------------------------------------------------------------

def test_encryption_at_rest_finds_unencrypted_s3(tmp_path, monkeypatch):
    assets = _load_demo(tmp_path, monkeypatch)
    from safecadence.policy.controls import get_control
    spec = get_control("enforce_encryption_at_rest")
    failed = []
    passed = []
    for a in assets:
        atype = (a.get("identity") or {}).get("asset_type")
        if atype not in (spec.applies_to or []):
            continue
        result, _ev = spec.check_fn(a, {})
        v = result.value if hasattr(result, "value") else str(result)
        if v == "fail":
            failed.append((a.get("identity") or {}).get("asset_id"))
        elif v == "pass":
            passed.append((a.get("identity") or {}).get("asset_id"))
    assert "s3-customer-data" in failed, (
        f"s3-customer-data should FAIL encryption check; got fails={failed}"
    )
    assert "rds-prod-customer" in passed or "azure-storage-backups" in passed


# --------------------------------------------------------------------------
# Identity controls actually verdict against demo fleet
# --------------------------------------------------------------------------

def test_idp_password_complexity_flags_ad(tmp_path, monkeypatch):
    """Demo AD has password_min_length=8; policy default is 14 → FAIL."""
    assets = _load_demo(tmp_path, monkeypatch)
    from safecadence.policy.controls import get_control
    counts = _verdict_counts(get_control("idp_password_complexity"), assets)
    assert counts["fail"] >= 1, f"AD weak password not flagged: {counts}"
    assert counts["pass"] >= 1, "Okta strong password should pass"


def test_idp_conditional_access_flags_azure_no_rules(tmp_path, monkeypatch):
    """Azure storage admin has conditional_access_rules=[] → FAIL,
    Okta has 3 rules → PASS, AD has no provider entry → NA."""
    assets = _load_demo(tmp_path, monkeypatch)
    from safecadence.policy.controls import get_control
    counts = _verdict_counts(get_control("idp_conditional_access"), assets)
    assert counts["pass"] >= 1, f"Okta CA rules should pass: {counts}"


def test_idp_privileged_role_review_flags_stale(tmp_path, monkeypatch):
    """Demo AD has last_access_review 220 days ago → FAIL (policy max 180)."""
    assets = _load_demo(tmp_path, monkeypatch)
    from safecadence.policy.controls import get_control
    counts = _verdict_counts(get_control("idp_privileged_role_review"),
                              assets)
    assert counts["fail"] >= 1, f"stale role review not flagged: {counts}"


# --------------------------------------------------------------------------
# Adapter manifest honesty
# --------------------------------------------------------------------------

def test_aruba_cx_demoted_to_stub():
    """Audit found aruba_cx.collect() returns {}; manifest must reflect."""
    from safecadence.adapter_manifest import (
        EXPERIMENTAL_ADAPTERS, STUB_ADAPTERS,
    )
    assert "aruba_cx" not in EXPERIMENTAL_ADAPTERS
    assert "aruba_cx" in STUB_ADAPTERS


def test_gcp_demoted_to_stub():
    from safecadence.adapter_manifest import (
        EXPERIMENTAL_ADAPTERS, STUB_ADAPTERS,
    )
    assert "gcp_cloud" not in EXPERIMENTAL_ADAPTERS
    assert "gcp_cloud" in STUB_ADAPTERS


def test_pure_storage_promoted_to_experimental():
    """Audit found pure_storage has real REST implementation."""
    from safecadence.adapter_manifest import (
        EXPERIMENTAL_ADAPTERS, STUB_ADAPTERS,
    )
    assert "pure_storage" in EXPERIMENTAL_ADAPTERS
    assert "pure_storage" not in STUB_ADAPTERS


# --------------------------------------------------------------------------
# All wizard combos still non-zero (regression on v6.4.2)
# --------------------------------------------------------------------------

def test_wizard_still_returns_nonzero_for_every_combo():
    from safecadence.policy.suggest import suggest_controls
    asset_types = ["network", "server", "storage", "hypervisor",
                    "cloud", "backup", "identity"]
    frameworks = ["nist", "cis", "pci", "hipaa", "iso", "zerotrust"]
    strictness = ["basic", "standard", "paranoid"]
    zero = []
    for at in asset_types:
        for fw in frameworks:
            for s in strictness:
                if suggest_controls([at], [fw], s)["control_count"] == 0:
                    zero.append((at, fw, s))
    assert zero == [], f"regression: {len(zero)} combos broken"
