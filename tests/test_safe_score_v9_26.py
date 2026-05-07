"""
v9.26 — tests for posture, vendor best-practice, software currency,
and the three-layer Safe Score 2.0 formula.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta

import pytest

pytest.importorskip("yaml", reason="PyYAML is required for v9.26 packs")


# =================================================== posture evaluator


def test_posture_disk_encryption_earns_credit():
    from safecadence.scores.posture import evaluate_asset
    asset = {
        "identity": {"asset_id": "srv-1", "asset_type": "server"},
        "os": {"disk_encryption": "enabled"},
    }
    r = evaluate_asset(asset)
    assert any(e["id"] == "endpoint-disk-encryption" for e in r.earned)
    assert r.credit >= 5


def test_posture_does_not_apply_router_to_disk_encryption():
    """Routers shouldn't be eligible for BitLocker checks."""
    from safecadence.scores.posture import evaluate_asset
    asset = {
        "identity": {"asset_id": "rtr-1", "asset_type": "network"},
        "os": {"disk_encryption": "enabled"},
    }
    r = evaluate_asset(asset)
    ids = {e["id"] for e in r.eligible}
    assert "endpoint-disk-encryption" not in ids


def test_posture_credit_is_capped():
    from safecadence.scores.posture import evaluate_asset
    asset = {
        "identity": {"asset_id": "srv-1", "asset_type": "server"},
        "os": {"disk_encryption": "enabled"},
        "security": {"edr_vendor": "crowdstrike",
                      "host_firewall_enabled": True,
                      "secure_boot": True},
        "lifecycle": {"os_patches_age_days": 5},
        "backup": {"last_success_age_days": 7,
                    "immutable_copy": True},
    }
    r = evaluate_asset(asset)
    assert r.credit <= r.cap        # caps at 20 by default
    assert r.cap == 20


def test_posture_router_earns_network_credit():
    from safecadence.scores.posture import evaluate_asset
    asset = {
        "identity": {"asset_id": "rtr-1", "asset_type": "network"},
        "network_security": {
            "mgmt_https_only": True,
            "ssh_key_auth_only": True,
            "snmp_version": "v3",
        },
        "logs": {"syslog_targets_count": 2},
    }
    r = evaluate_asset(asset)
    earned_ids = {e["id"] for e in r.earned}
    for c in ("network-mgmt-https-only", "network-ssh-key-auth",
                "network-snmpv3-only", "network-logging-shipped"):
        assert c in earned_ids, c


# =================================================== best-practice (Cisco)


def _cisco_asset(running_config: str) -> dict:
    return {
        "identity": {
            "asset_id": "rtr-1", "hostname": "rtr-1",
            "vendor": "Cisco",
            "product_family": "Cisco IOS Software",
            "asset_type": "network",
        },
        "raw_collection": {"running": running_config},
        "os": {"version": "15.9(3)M9"},
    }


def test_best_practice_passes_hardened_cisco_config():
    from safecadence.scores.best_practice import evaluate_asset
    cfg = (
        "aaa new-model\n"
        "service password-encryption\n"
        "no ip http server\n"
        "ip http secure-server\n"
        "ip ssh version 2\n"
        "logging host 10.0.0.5\n"
        "ntp server 10.0.0.6\n"
        "no ip source-route\n"
        "enable secret 5 $1$abc$xyz\n"
        "snmp-server group MyG v3 priv\n"
        "snmp-server user admin MyG v3 auth sha PASSWD\n"
        "login block-for 60 attempts 3 within 60\n"
        "banner motd ^ AUTHORIZED USE ONLY ^\n"
        "line vty 0 4\n"
        " transport input ssh\n"
        " login local\n"
    )
    r = evaluate_asset(_cisco_asset(cfg))
    assert r.vendor_key.startswith("cisco")
    passed_ids = {p["id"] for p in r.passed}
    for must in ("cisco-ios-aaa-enabled", "cisco-ios-no-http-server",
                  "cisco-ios-ssh-v2", "cisco-ios-logging-host",
                  "cisco-ios-no-ip-source-route",
                  "cisco-ios-service-password-encryption",
                  "cisco-ios-enable-secret"):
        assert must in passed_ids, must
    assert r.credit > 0


def test_best_practice_fails_default_snmp_community():
    from safecadence.scores.best_practice import evaluate_asset
    cfg = (
        "aaa new-model\n"
        "snmp-server community public RO\n"
        "ip ssh version 2\n"
    )
    r = evaluate_asset(_cisco_asset(cfg))
    failed_ids = {f["id"] for f in r.failed}
    assert "cisco-ios-no-snmp-community-public" in failed_ids


def test_best_practice_no_pack_for_unknown_vendor():
    from safecadence.scores.best_practice import evaluate_asset
    asset = {
        "identity": {"asset_id": "x", "vendor": "AcmeCorp",
                      "product_family": "AcmeOS"},
        "raw_collection": {"running": "config goes here"},
    }
    r = evaluate_asset(asset)
    assert not r.passed and not r.failed
    assert r.credit == 0


# =================================================== software currency


def test_software_currency_current_version():
    from safecadence.scores.software_currency import evaluate_asset
    asset = {
        "identity": {"vendor": "Cisco",
                      "product_family": "Cisco IOS XE Software",
                      "asset_id": "rtr-1"},
        "os": {"version": "17.12.4"},
    }
    r = evaluate_asset(asset)
    assert r.status == "current"
    assert r.posture_credit > 0
    assert r.risk_deduction == 0


def test_software_currency_eol_deducts_risk():
    from safecadence.scores.software_currency import evaluate_asset
    asset = {
        "identity": {"vendor": "Cisco",
                      "product_family": "Cisco IOS XE Software",
                      "asset_id": "rtr-1"},
        "os": {"version": "16.6.1"},
    }
    r = evaluate_asset(asset)
    assert r.status == "eol"
    assert r.risk_deduction > 0


def test_software_currency_kev_version_flagged():
    from safecadence.scores.software_currency import evaluate_asset
    asset = {
        "identity": {"vendor": "Palo Alto",
                      "product_family": "PAN-OS",
                      "asset_id": "fw-1"},
        "os": {"version": "10.2.3"},
    }
    r = evaluate_asset(asset)
    assert r.status == "kev_vulnerable"
    assert r.risk_deduction >= 10


def test_software_currency_unknown_vendor():
    from safecadence.scores.software_currency import evaluate_asset
    asset = {"identity": {"vendor": "AcmeCorp"},
              "os": {"version": "1.0"}}
    r = evaluate_asset(asset)
    assert r.status == "unknown"


# =================================================== confidence


def test_confidence_low_for_bare_asset():
    """An asset with nothing but an asset_id should have low
    confidence — we don't really know anything about it."""
    from safecadence.scores import score_asset_safe
    s = score_asset_safe({"identity": {"asset_id": "ghost",
                                         "asset_type": "network"}})
    assert s.confidence < 0.3
    assert "no last_seen" in " ".join(s.confidence_reasons).lower() or \
            len(s.confidence_reasons) >= 3


def test_confidence_high_for_recently_scanned_asset():
    from safecadence.scores import score_asset_safe
    now = datetime.now(timezone.utc).isoformat()
    asset = {
        "identity": {"asset_id": "rtr-1", "asset_type": "network",
                      "last_seen": now,
                      "vendor": "Cisco",
                      "product_family": "Cisco IOS Software"},
        "raw_collection": {"running": "aaa new-model\n"},
    }
    s = score_asset_safe(
        asset,
        findings=[{"asset_id": "rtr-1", "severity": "low",
                    "kind": "x"}],
        cves=[{"asset_id": "rtr-1", "cves": []}],
        paths=[{"target": "y", "nodes": ["rtr-1", "y"]}],
    )
    assert s.confidence >= 0.7


def test_safe_score_includes_posture_and_risk_breakdown():
    from safecadence.scores import score_asset_safe
    asset = {
        "identity": {"asset_id": "srv-1", "asset_type": "server"},
        "os": {"disk_encryption": "enabled"},
        "security": {"edr_vendor": "crowdstrike"},
    }
    s = score_asset_safe(asset)
    assert s.posture_credit > 0
    d = s.to_dict()
    assert "posture_credit" in d
    assert "confidence" in d
    assert "confidence_reasons" in d
