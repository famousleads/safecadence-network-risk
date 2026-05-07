"""Control library — verify each control returns the expected verdict."""

from __future__ import annotations

from safecadence.policy.controls import all_controls, get_control
from safecadence.policy.schema import EvaluationResult


def test_22_controls_registered():
    ids = [c.id for c in all_controls()]
    # Must be at least these foundational ones
    must_have = ["disable_telnet", "enforce_ssh_v2", "require_aaa", "enforce_snmpv3",
                 "enable_syslog", "enable_ntp", "block_insecure_crypto",
                 "restrict_management_access", "enforce_patch_level",
                 "enforce_encryption_at_rest", "enforce_encryption_in_transit",
                 "restrict_default_creds", "enforce_password_policy", "enforce_mfa",
                 "enforce_least_privilege", "block_public_exposure",
                 "enforce_cloud_iam", "enforce_logging",
                 "enforce_backup_retention", "enforce_immutability",
                 "enforce_air_gap", "replication_enabled"]
    for cid in must_have:
        assert cid in ids, f"missing control {cid}"


def test_disable_telnet_pass(cisco_router_clean):
    spec = get_control("disable_telnet")
    result, evidence = spec.check_fn(cisco_router_clean, {})
    assert result == EvaluationResult.PASS, evidence


def test_disable_telnet_fail(cisco_router_messy):
    spec = get_control("disable_telnet")
    result, _ = spec.check_fn(cisco_router_messy, {})
    assert result == EvaluationResult.FAIL


def test_enforce_ssh_v2_pass(cisco_router_clean):
    spec = get_control("enforce_ssh_v2")
    result, _ = spec.check_fn(cisco_router_clean, {})
    assert result == EvaluationResult.PASS


def test_enforce_snmpv3_fail_on_v2_community(cisco_router_messy):
    spec = get_control("enforce_snmpv3")
    result, _ = spec.check_fn(cisco_router_messy, {})
    assert result == EvaluationResult.FAIL


def test_enable_syslog_param_target(cisco_router_clean):
    spec = get_control("enable_syslog")
    result, _ = spec.check_fn(cisco_router_clean, {"syslog_target": "10.10.10.50"})
    assert result == EvaluationResult.PASS
    # Wrong target → fail
    result, _ = spec.check_fn(cisco_router_clean, {"syslog_target": "9.9.9.9"})
    assert result == EvaluationResult.FAIL


def test_block_public_exposure(cloud_asset_public):
    spec = get_control("block_public_exposure")
    result, _ = spec.check_fn(cloud_asset_public, {})
    assert result == EvaluationResult.FAIL


def test_enforce_patch_level_fail(linux_server):
    spec = get_control("enforce_patch_level")
    result, _ = spec.check_fn(linux_server, {})
    assert result == EvaluationResult.FAIL


def test_enforce_mfa_fail(linux_server):
    spec = get_control("enforce_mfa")
    result, _ = spec.check_fn(linux_server, {})
    assert result == EvaluationResult.FAIL
