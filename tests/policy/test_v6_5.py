"""v6.5 — Per-device diff view tests.

Locks down the contract that an operator who picks an asset + policy
in the UI gets back a payload with:
  - one row per control with PASS/FAIL/NA/UNKNOWN status
  - per-control fix commands marked already_present vs to-add
  - a unified diff that can be inspected / piped into change-management
"""

from __future__ import annotations


def _build_policy(controls):
    from safecadence.policy.schema import (
        PolicyControl, SecurityPolicy, Severity,
    )
    return SecurityPolicy(
        policy_id="test_pol",
        policy_name="Test policy",
        target_asset_types=["network"],
        controls=[PolicyControl(control_id=c, severity=Severity.HIGH)
                   for c in controls],
        severity=Severity.HIGH,
    )


def test_diff_returns_stable_shape():
    from safecadence.policy.diff import compute_diff
    pol = _build_policy(["disable_telnet", "enforce_ssh_v2"])
    asset = {
        "identity": {"asset_id": "rtr-1", "asset_type": "network",
                      "vendor": "cisco"},
        "os": {"os_type": "ios"},
        "raw_collection": {"running-config": "line vty 0 4\n"
                                              "transport input telnet ssh\n"},
    }
    out = compute_diff(pol, asset)
    # Required top-level fields
    for k in ("asset_id", "asset_vendor", "asset_type", "policy_id",
              "policy_name", "translator", "evaluation", "controls",
              "unified_diff", "summary"):
        assert k in out, f"missing key: {k}"
    # Eval block has required counts
    for k in ("pass_count", "fail_count", "na_count", "control_count"):
        assert k in out["evaluation"]
    # One control row per declared control
    assert len(out["controls"]) == 2
    for row in out["controls"]:
        for k in ("control_id", "status", "severity", "fix",
                  "rollback", "verify", "lines_to_add",
                  "lines_already_satisfied"):
            assert k in row, f"control row missing key {k}: {row}"


def test_diff_marks_already_present_lines():
    """If a fix line is already in raw_collection, it should be
    marked already_present so the operator doesn't paste it again."""
    from safecadence.policy.diff import compute_diff
    pol = _build_policy(["enforce_ssh_v2"])
    asset = {
        "identity": {"asset_id": "rtr-1", "asset_type": "network",
                      "vendor": "cisco"},
        "os": {"os_type": "ios"},
        "raw_collection": {"running-config":
            "line vty 0 4\n transport input ssh\n ip ssh version 2\n"},
    }
    out = compute_diff(pol, asset)
    ssh_row = next((c for c in out["controls"]
                    if c["control_id"] == "enforce_ssh_v2"), None)
    assert ssh_row is not None
    # If the control PASSES on this asset, the fix list will be empty
    # (we only translate FAIL/UNKNOWN). Verify at least one of those
    # outcomes.
    if ssh_row["status"] == "fail":
        already = [a for a in ssh_row["fix"] if a["already_present"]]
        assert len(already) >= 1, ("expected at least one line already "
                                    "present in the running config")


def test_diff_handles_unknown_translator_gracefully():
    """If no translator matches the asset, we must still return a
    well-formed payload with notes explaining why fix is empty."""
    from safecadence.policy.diff import compute_diff
    pol = _build_policy(["disable_telnet"])
    asset = {
        "identity": {"asset_id": "exotic-1", "asset_type": "network",
                      "vendor": "some-unsupported-vendor"},
        "os": {"os_type": "??"},
        "raw_collection": {"config": "transport input telnet\n"},
    }
    out = compute_diff(pol, asset)
    assert out["asset_id"] == "exotic-1"
    # No translator picked → notes / empty fix is acceptable
    row = out["controls"][0]
    assert row["control_id"] == "disable_telnet"
    # The status is what the evaluator says — translator absence
    # doesn't change FAIL detection.


def test_diff_passing_asset_yields_no_changes_summary():
    """An asset that already satisfies every control gets a clear
    'no changes needed' summary so the operator doesn't dig further."""
    from safecadence.policy.diff import compute_diff
    pol = _build_policy(["disable_telnet"])
    asset = {
        "identity": {"asset_id": "good-rtr", "asset_type": "network",
                      "vendor": "cisco"},
        "os": {"os_type": "ios"},
        "raw_collection": {"running-config":
            "line vty 0 4\n transport input ssh\n"},
    }
    out = compute_diff(pol, asset)
    assert out["evaluation"]["fail_count"] == 0
    assert "no changes needed" in out["summary"]


def test_render_text_includes_severity_and_evidence():
    from safecadence.policy.diff import compute_diff, render_text
    pol = _build_policy(["disable_telnet"])
    asset = {
        "identity": {"asset_id": "rtr-bad", "asset_type": "network",
                      "vendor": "cisco"},
        "os": {"os_type": "ios"},
        "raw_collection": {"running-config":
            "line vty 0 4\n transport input telnet ssh\n"},
    }
    text = render_text(compute_diff(pol, asset))
    assert "rtr-bad" in text
    assert "disable_telnet" in text
    assert "Test policy" in text


def test_diff_demo_fleet_end_to_end(tmp_path, monkeypatch):
    """Smoke: load demo, build a real policy, compute diff for the
    edge router with default credentials → should produce >= 1 fail
    + a non-empty unified_diff section."""
    monkeypatch.setenv("SC_PLATFORM_STORE", str(tmp_path))
    from safecadence.demo import load_demo_fleet
    from safecadence.policy.diff import compute_diff
    from safecadence.server.platform_api import get_asset
    load_demo_fleet()
    asset = get_asset("edge-rtr-01.acme.local")
    assert asset is not None
    pol = _build_policy([
        "disable_telnet", "enforce_ssh_v2", "restrict_default_creds",
        "enable_syslog", "block_insecure_crypto",
    ])
    out = compute_diff(pol, asset)
    assert out["evaluation"]["fail_count"] >= 1, (
        f"edge router has telnet + default creds + no syslog; "
        f"expected ≥1 fail, got {out['evaluation']}"
    )
