"""v6.4.2 — Honesty pass tests.

These tests lock down the regressions a real user would hit:
  - The wizard must produce non-empty results for every advertised
    (asset_type, framework, strictness) combination.
  - Identity must have working controls (was completely empty in 6.4.1).
  - Zero Trust framework must surface controls (was completely empty).
  - The full smoke flow — demo → drift → top-K paths — must not regress.
"""

from __future__ import annotations


def test_wizard_returns_nonzero_for_every_advertised_combo():
    """The Builder wizard advertises 7 asset types × 6 frameworks × 3
    strictness levels. Every one must produce at least one suggested
    control or the user lands on an empty 'No controls match' screen."""
    from safecadence.policy.suggest import suggest_controls
    asset_types = ["network", "server", "storage", "hypervisor",
                    "cloud", "backup", "identity"]
    frameworks = ["nist", "cis", "pci", "hipaa", "iso", "zerotrust"]
    strictness = ["basic", "standard", "paranoid"]
    zero_combos = []
    for at in asset_types:
        for fw in frameworks:
            for s in strictness:
                r = suggest_controls([at], [fw], s)
                if r["control_count"] == 0:
                    zero_combos.append((at, fw, s))
    assert zero_combos == [], (
        f"{len(zero_combos)} wizard combinations return ZERO controls — "
        f"the user lands on an empty screen for: {zero_combos[:5]}..."
    )


def test_identity_has_dedicated_controls():
    """v6.0 shipped Identity Engine but the control library had zero
    identity controls. Lock the fix in."""
    from safecadence.policy.controls import all_controls
    identity_controls = [c for c in all_controls()
                         if "identity" in (c.applies_to or [])]
    assert len(identity_controls) >= 5, (
        f"only {len(identity_controls)} identity controls; need at least 5"
    )
    # The five we shipped
    ids = {c.id for c in identity_controls}
    assert "idp_require_mfa_for_admins" in ids
    assert "idp_disable_dormant_accounts" in ids
    assert "idp_password_complexity" in ids
    assert "idp_conditional_access" in ids
    assert "idp_privileged_role_review" in ids


def test_zero_trust_framework_surfaces_controls():
    """The Builder wizard offers Zero Trust as a framework option; it
    used to suggest nothing for any asset type. Lock the fix in."""
    from safecadence.policy.suggest import suggest_controls
    for at in ("network", "server", "cloud", "identity", "backup"):
        r = suggest_controls([at], ["zerotrust"], "standard")
        assert r["control_count"] >= 1, (
            f"zero-trust + {at} returns {r['control_count']} controls"
        )


def test_iso_27001_covers_every_asset_type():
    """ISO 27001 was missing from many controls in 6.4.1 — storage,
    cloud, hypervisor, backup, identity all returned 0 ISO suggestions."""
    from safecadence.policy.suggest import suggest_controls
    for at in ("network", "server", "storage", "hypervisor",
                "cloud", "backup", "identity"):
        r = suggest_controls([at], ["iso"], "standard")
        assert r["control_count"] >= 1, (
            f"iso-27001 + {at} returns 0 controls"
        )


def test_hipaa_covers_every_asset_type():
    from safecadence.policy.suggest import suggest_controls
    for at in ("network", "server", "storage", "hypervisor",
                "cloud", "backup", "identity"):
        r = suggest_controls([at], ["hipaa"], "standard")
        assert r["control_count"] >= 1, (
            f"hipaa + {at} returns 0 controls"
        )


def test_identity_mfa_check_runs_against_demo_fleet(tmp_path, monkeypatch):
    """End-to-end: load the demo fleet, run the new MFA control,
    verify it actually flags the AD asset that lacks MFA."""
    monkeypatch.setenv("SC_PLATFORM_STORE", str(tmp_path))
    from safecadence.demo import load_demo_fleet
    from safecadence.policy.controls import get_control
    from safecadence.policy.schema import EvaluationResult
    load_demo_fleet()
    from safecadence.server.platform_api import list_assets
    spec = get_control("idp_require_mfa_for_admins")
    assert spec is not None
    flagged = []
    for a in list_assets():
        result, ev = spec.check_fn(a, {})
        if result == EvaluationResult.FAIL:
            flagged.append((a.get("identity") or {}).get("asset_id"))
    # The demo fleet's AD asset has admin groups + mfa_enrolled=False
    assert "ad-acme-local" in flagged


def test_demo_fleet_drift_finds_real_issues(tmp_path, monkeypatch):
    """Smoke test: demo fleet should produce real drift findings.
    Locks in that the demo + drift detectors stay wired together."""
    monkeypatch.setenv("SC_PLATFORM_STORE", str(tmp_path))
    from safecadence.demo import load_demo_fleet
    from safecadence.policy.cross_system_drift import detect_all
    from safecadence.server.platform_api import list_assets
    load_demo_fleet()
    result = detect_all(list_assets())
    assert result["finding_count"] >= 10, (
        f"demo fleet only produced {result['finding_count']} drift "
        "findings — should produce at least 10 to feel populated"
    )
    assert result["detector_count"] == 17


def test_demo_fleet_attack_paths_find_internet_reachable_jewels(
        tmp_path, monkeypatch):
    """The demo fleet was crafted with internet-facing edges and crown-
    jewel assets so top_k_paths_to_crown_jewels has something to find."""
    monkeypatch.setenv("SC_PLATFORM_STORE", str(tmp_path))
    from safecadence.demo import load_demo_fleet
    from safecadence.platform.attack_paths import top_k_paths_to_crown_jewels
    from safecadence.server.platform_api import list_assets
    load_demo_fleet()
    paths = top_k_paths_to_crown_jewels(list_assets(), k=10, max_hops=5)
    assert len(paths) >= 1, "demo fleet has no internet→crown-jewel path"
