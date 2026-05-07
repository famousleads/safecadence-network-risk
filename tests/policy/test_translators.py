"""Translator coverage — every translator produces non-empty output for at
least one control, and applicable=False for unknown controls."""

from __future__ import annotations

import pytest

from safecadence.policy.schema import PolicyControl, Severity
from safecadence.policy.translators import all_translators, get_translator, pick_translator_for_asset


def test_12_translators_registered():
    names = {t.vendor_target for t in all_translators()}
    expected = {
        "cisco_ios", "cisco_nxos", "cisco_asa", "arista_eos", "juniper_junos",
        "fortinet_fortios", "paloalto_panos", "linux", "windows",
        "aws_iam", "azure", "gcp",
    }
    assert expected.issubset(names), f"missing: {expected - names}"


@pytest.mark.parametrize("vendor,control_id", [
    ("cisco_ios", "disable_telnet"),
    ("cisco_ios", "enforce_ssh_v2"),
    ("cisco_ios", "require_aaa"),
    ("cisco_nxos", "disable_telnet"),
    ("cisco_asa", "disable_telnet"),
    ("arista_eos", "enforce_ssh_v2"),
    ("juniper_junos", "disable_telnet"),
    ("fortinet_fortios", "enable_syslog"),
    ("paloalto_panos", "disable_telnet"),
    ("linux", "enforce_ssh_v2"),
    ("windows", "enforce_password_policy"),
    ("aws_iam", "block_public_exposure"),
    ("azure", "enforce_logging"),
    ("gcp", "enforce_encryption_at_rest"),
])
def test_translator_produces_fix_lines(vendor, control_id):
    t = get_translator(vendor)
    assert t is not None, f"missing translator {vendor}"
    pc = PolicyControl(control_id=control_id, severity=Severity.MEDIUM)
    res = t.translate(pc, {"identity": {"asset_id": "x", "asset_type": "network"}})
    assert res.applicable
    assert res.fix, f"{vendor}.{control_id} produced no fix lines"


def test_translator_applicable_false_for_unknown_control():
    t = get_translator("cisco_ios")
    pc = PolicyControl(control_id="nonexistent_control_xyz", severity=Severity.LOW)
    res = t.translate(pc, {"identity": {"asset_id": "x", "asset_type": "network"}})
    assert not res.applicable


def test_pick_translator_for_cisco_ios_router():
    asset = {"identity": {"vendor": "cisco", "asset_type": "network"},
             "os": {"os_type": "ios-xe"}}
    t = pick_translator_for_asset(asset)
    assert t is not None
    assert t.vendor_target == "cisco_ios"


def test_pick_translator_for_aws_account():
    asset = {"identity": {"vendor": "aws", "asset_type": "cloud"}}
    t = pick_translator_for_asset(asset)
    assert t is not None
    assert t.vendor_target == "aws_iam"


def test_cisco_ios_acl_uses_correct_wildcard():
    """Smoke: 10.10.10.0/24 → wildcard 0.0.0.255 in the generated ACL."""
    t = get_translator("cisco_ios")
    pc = PolicyControl(control_id="restrict_management_access",
                       parameters={"allowed_cidrs": ["10.10.10.0/24"]})
    res = t.translate(pc, {"identity": {"asset_id": "x", "asset_type": "network"}})
    joined = "\n".join(res.fix)
    assert "10.10.10.0" in joined
    assert "0.0.0.255" in joined
