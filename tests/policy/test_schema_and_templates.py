"""Schema, templates, framework mapping smoke tests."""

from __future__ import annotations


def test_severity_and_enforcement_enums():
    from safecadence.policy import Severity, EnforcementMode
    assert Severity.CRITICAL.value == "critical"
    assert EnforcementMode.OBSERVE.value == "observe"


def test_all_10_templates_load():
    from safecadence.policy.templates import list_templates, load_template
    metas = list_templates()
    ids = {m["id"] for m in metas}
    expected = {
        "tmpl_network_hardening", "tmpl_firewall_baseline",
        "tmpl_router_switch_baseline", "tmpl_server_hardening",
        "tmpl_cloud_security", "tmpl_logging_monitoring",
        "tmpl_identity_access_control", "tmpl_encryption",
        "tmpl_backup_security", "tmpl_zero_trust",
    }
    assert expected.issubset(ids), f"missing: {expected - ids}"
    # Every template must load without error and have at least 1 control
    for m in metas:
        p = load_template(m["id"])
        assert p is not None, m["id"]
        assert len(p.controls) >= 1


def test_framework_mappings():
    from safecadence.policy.frameworks import load_mappings, control_framework_refs
    m = load_mappings()
    assert "disable_telnet" in m
    refs = control_framework_refs("disable_telnet")
    assert any("nist" in r for r in refs)


def test_applies_to_filtering():
    from safecadence.policy.schema import SecurityPolicy
    p = SecurityPolicy(target_asset_types=["network"])
    assert p.applies_to({"identity": {"asset_type": "network"}})
    assert not p.applies_to({"identity": {"asset_type": "server"}})
