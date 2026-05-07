"""v6.0 — Identity Intelligence Engine tests.

Coverage:
  - Identity dataclass + UnifiedAsset integration
  - 5 identity adapters register cleanly + don't crash on construction
  - 4 identity translators produce non-empty fixes
  - Cross-system drift detector fires for each known scenario
"""

from __future__ import annotations

import json

import pytest


def test_identity_dataclass_added_to_unified_asset():
    from safecadence.platform.schema import UnifiedAsset, Identity
    a = UnifiedAsset()
    assert isinstance(a.identity_block, Identity)
    a.identity_block.provider = "cisco-ise"
    assert a.identity_block.provider == "cisco-ise"


def test_5_identity_adapters_registered():
    import safecadence.platform.adapters
    from safecadence.platform.adapter_base import _REGISTRY
    must_have = {"cisco_ise", "hpe_clearpass", "active_directory",
                  "entra_id", "okta"}
    assert must_have.issubset(set(_REGISTRY)), \
        f"missing identity adapters: {must_have - set(_REGISTRY)}"


@pytest.mark.parametrize("name", ["cisco_ise", "hpe_clearpass", "active_directory",
                                    "entra_id", "okta"])
def test_identity_adapter_constructs(name):
    import safecadence.platform.adapters
    from safecadence.platform.adapter_base import _REGISTRY
    cls = _REGISTRY[name]
    a = cls(target="example.local", credentials={
        "username": "u", "password": "p", "client_id": "x",
        "client_secret": "y", "api_token": "tok", "tenant_id": "tid",
        "bind_dn": "cn=u", "bind_password": "p", "base_dn": "dc=ex",
    })
    assert a is not None
    # normalize() must accept an empty raw dict and not crash
    out = a.normalize("smoke", {})
    assert out.identity_block is not None


def test_4_identity_translators_registered():
    from safecadence.policy.translators import all_translators
    names = {t.vendor_target for t in all_translators()}
    must_have = {"cisco_ise", "clearpass_role", "ad_gpo", "azure_ca"}
    assert must_have.issubset(names), f"missing: {must_have - names}"


@pytest.mark.parametrize("vendor,control_id", [
    ("cisco_ise", "enforce_mfa"),
    ("cisco_ise", "block_public_exposure"),
    ("clearpass_role", "enforce_mfa"),
    ("ad_gpo", "enforce_password_policy"),
    ("ad_gpo", "restrict_default_creds"),
    ("azure_ca", "enforce_mfa"),
    ("azure_ca", "block_public_exposure"),
])
def test_identity_translator_produces_fix(vendor, control_id):
    from safecadence.policy.translators import get_translator
    from safecadence.policy.schema import PolicyControl
    t = get_translator(vendor)
    f = t.translate(PolicyControl(control_id=control_id),
                    {"identity": {"asset_id": "x", "asset_type": "identity"}})
    assert f.applicable
    assert f.fix


def test_cross_system_drift_detector_fires():
    from safecadence.policy.cross_system_drift import detect_all
    assets = [
        # AD with admin/contractor groups
        {"identity": {"asset_id": "ad1", "asset_type": "identity", "vendor": "microsoft"},
         "identity_block": {"provider": "ad",
                             "authorized_groups": ["Contractors", "Domain Users"]}},
        # Network device with weak Cisco type-7 password
        {"identity": {"asset_id": "sw1", "asset_type": "network", "vendor": "cisco"},
         "raw_collection": {"show_running-config":
             "username admin password 7 094F471A1A0A"}},
        # Entra with MFA + Azure cloud asset with no MFA on SP
        {"identity": {"asset_id": "entra1", "asset_type": "identity", "vendor": "microsoft"},
         "identity_block": {"provider": "entra", "mfa_enrolled": True}},
        {"identity": {"asset_id": "aks1", "asset_type": "cloud", "vendor": "azure"},
         "cloud": {"iam_role": "Owner"},
         "security": {"findings": ["service principal with Owner role, no MFA"]}},
    ]
    res = detect_all(assets)
    assert res["finding_count"] >= 2
    types = {f["type"] for f in res["findings"]}
    assert "weak_local_password_vs_corp_policy" in types
    assert "mfa_bypass_via_rbac" in types


def test_cross_system_drift_clean_returns_no_findings():
    from safecadence.policy.cross_system_drift import detect_all
    res = detect_all([])
    assert res["finding_count"] == 0
    assert "No cross-system" in res["summary"]


def test_identity_translator_unknown_control_returns_not_applicable():
    from safecadence.policy.translators import get_translator
    from safecadence.policy.schema import PolicyControl
    for v in ("cisco_ise", "clearpass_role", "ad_gpo", "azure_ca"):
        t = get_translator(v)
        f = t.translate(PolicyControl(control_id="totally_made_up"),
                        {"identity": {"asset_id": "x", "asset_type": "identity"}})
        assert not f.applicable
