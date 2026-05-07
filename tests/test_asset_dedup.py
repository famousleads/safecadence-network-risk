"""
v9.7 — asset dedup + shadow-IT tests.

The dedup logic is deterministic — no AI required for the matching,
only for the optional human summary. These tests cover the cascade
(MAC > IP > hostname > asset_id) and the shadow-IT detector.
"""

from __future__ import annotations

import pytest

from safecadence.intel.asset_dedup import (
    CanonicalAsset, DedupResult,
    merge_asset_groups, find_shadow_it, describe_dedup_result,
    _norm_mac, _norm_host, _pick_primary_ip,
)


# ----------------------------------------------------- normalizers

def test_norm_mac_strips_separators():
    assert _norm_mac("00:11:22:33:44:55") == "001122334455"
    assert _norm_mac("00-11-22-33-44-55") == "001122334455"
    assert _norm_mac("0011.2233.4455") == "001122334455"


def test_norm_host_lowercases_and_strips_domain():
    assert _norm_host("PC-01.acme.local") == "pc-01"
    assert _norm_host("server.") == "server"


def test_pick_primary_ip_prefers_mgmt():
    rec = {"identity": {"mgmt_ip": "10.0.0.1", "ip": "192.168.1.1"}}
    assert _pick_primary_ip(rec) == "10.0.0.1"


def test_pick_primary_ip_falls_back_to_interfaces():
    rec = {"identity": {}, "interfaces": [{"ip_address": "10.5.0.4"}]}
    assert _pick_primary_ip(rec) == "10.5.0.4"


# ----------------------------------------------------- merge cascade

def _r(**kw):
    """Helper: build a record with identity wrapper."""
    return {"identity": kw}


def test_merge_dedups_by_mac_across_sources():
    groups = {
        "lan":   [_r(asset_id="lan-1", mac="00:11:22:33:44:55", ip="10.0.0.5",
                     hostname="seenip", asset_type="server")],
        "ad":    [_r(asset_id="PC-01", mac="00-11-22-33-44-55",
                     hostname="PC-01.acme.local", asset_type="server")],
        "entra": [_r(hostname="PC-01", asset_type="server")],   # no MAC, no IP
    }
    result = merge_asset_groups(groups)
    assert len(result.canonical) == 1, \
        "all three records should fold into one canonical"
    ca = result.canonical[0]
    assert set(ca.sources) == {"lan", "ad", "entra"}
    assert "mac=001122334455" in " ".join(ca.match_reasons)


def test_merge_dedups_by_ip_when_no_mac():
    groups = {
        "lan":   [_r(ip="10.0.0.42", hostname="x")],
        "dhcp":  [_r(ip="10.0.0.42", hostname="x", mac="aa:bb:cc:dd:ee:ff")],
    }
    result = merge_asset_groups(groups)
    assert len(result.canonical) == 1
    ca = result.canonical[0]
    assert "ip=10.0.0.42" in " ".join(ca.match_reasons)
    assert ca.mac          # was filled in from DHCP record


def test_merge_dedups_by_hostname_when_no_mac_no_ip():
    groups = {
        "ad":    [_r(hostname="srv-db-01.acme.local")],
        "manual": [_r(hostname="srv-db-01")],
    }
    result = merge_asset_groups(groups)
    assert len(result.canonical) == 1
    assert "hostname=srv-db-01" in " ".join(result.canonical[0].match_reasons)


def test_merge_keeps_distinct_when_no_keys_match():
    groups = {
        "ad": [_r(hostname="host-a"), _r(hostname="host-b")],
    }
    result = merge_asset_groups(groups)
    assert len(result.canonical) == 2


def test_merge_counts_by_source_is_correct():
    groups = {
        "lan": [_r(mac="00:00:00:00:00:01"), _r(mac="00:00:00:00:00:02")],
        "ad":  [_r(mac="00:00:00:00:00:01"), _r(mac="00:00:00:00:00:03")],
    }
    result = merge_asset_groups(groups)
    assert result.counts_by_source == {"lan": 2, "ad": 2}
    assert len(result.canonical) == 3   # 1 shared + 1 LAN-only + 1 AD-only


# ----------------------------------------------------- shadow IT

def test_shadow_it_flags_active_only_devices():
    """LAN-scanned device that's not in AD → shadow IT."""
    groups = {
        "lan": [_r(mac="aa:aa:aa:aa:aa:aa", hostname="rogue-pi"),
                _r(mac="bb:bb:bb:bb:bb:bb", hostname="approved-srv")],
        "ad":  [_r(mac="bb-bb-bb-bb-bb-bb", hostname="approved-srv")],
    }
    result = merge_asset_groups(groups)
    shadow = find_shadow_it(result)
    assert len(shadow) == 1
    assert shadow[0].hostname == "rogue-pi"


def test_shadow_it_empty_when_everything_is_declared():
    groups = {
        "lan": [_r(mac="aa:aa:aa:aa:aa:aa")],
        "ad":  [_r(mac="aa-aa-aa-aa-aa-aa")],
    }
    result = merge_asset_groups(groups)
    assert find_shadow_it(result) == []


def test_shadow_it_treats_manual_as_declarative():
    """Manually-added crown jewels shouldn't be flagged."""
    groups = {
        "lan":    [_r(hostname="edge-rtr-01")],
        "manual": [_r(hostname="edge-rtr-01")],
    }
    result = merge_asset_groups(groups)
    assert find_shadow_it(result) == []


# ----------------------------------------------------- AI summary

def test_describe_dedup_result_template_when_no_ai():
    groups = {
        "lan": [_r(mac="00:11:22:33:44:55"), _r(mac="aa:bb:cc:dd:ee:ff")],
        "ad":  [_r(mac="00-11-22-33-44-55")],
    }
    result = merge_asset_groups(groups)
    text = describe_dedup_result(result)   # no ai_call → fallback template
    assert "Reconciled" in text
    assert "shadow-IT" in text
    # Should mention 2+ source counts somewhere


def test_describe_dedup_result_uses_ai_when_provided():
    groups = {"lan": [_r(mac="00:11:22:33:44:55")]}
    result = merge_asset_groups(groups)
    captured = {}
    def fake_ai(system, user, model):
        captured["system"] = system; captured["user"] = user
        return "AI-generated summary text."
    text = describe_dedup_result(result, ai_call=fake_ai)
    assert text == "AI-generated summary text."
    assert "1 canonical" in captured["user"] or "1 canonical devices" in captured["user"]


def test_describe_dedup_result_falls_back_when_ai_raises():
    def boom(s, u, m): raise RuntimeError("rate-limited")
    groups = {"lan": [_r(mac="00:00:00:00:00:01")]}
    result = merge_asset_groups(groups)
    text = describe_dedup_result(result, ai_call=boom)
    assert "Reconciled" in text   # fell back to template


# ----------------------------------------------------- end-to-end

def test_realistic_three_source_dedup():
    """Active LAN + AD + AWS with overlap + cloud-only + shadow."""
    groups = {
        "lan": [
            _r(asset_id="10.0.0.5", mac="00:11:22:33:44:55",
               ip="10.0.0.5", hostname="srv-prod-01"),
            _r(asset_id="10.0.0.99", mac="bb:bb:bb:bb:bb:bb",
               ip="10.0.0.99", hostname="rogue-pi"),         # shadow IT
        ],
        "ad": [
            _r(asset_id="srv-prod-01", mac="00-11-22-33-44-55",
               hostname="srv-prod-01.acme.local"),
            _r(asset_id="laptop-alice", mac="cc:cc:cc:cc:cc:cc",
               hostname="laptop-alice"),                     # off-net
        ],
        "aws": [
            _r(asset_id="i-cloudonly", ip="54.10.20.30",
               hostname="ec2-prod-web", asset_type="server"),
        ],
    }
    result = merge_asset_groups(groups)
    # 4 canonical: prod-01 (lan+ad), rogue-pi (lan-only),
    #              laptop-alice (ad-only), ec2-prod-web (aws-only)
    assert len(result.canonical) == 4
    by_host = {ca.hostname: ca for ca in result.canonical
               if ca.hostname}
    # The "srv-prod-01" entry was matched twice; canonical hostname
    # should be one of them.
    matched = [ca for ca in result.canonical
               if "srv-prod-01" in ca.hostname.lower()]
    assert len(matched) == 1
    assert set(matched[0].sources) == {"lan", "ad"}

    # Shadow IT: rogue-pi (active scan, no AD) AND ec2-prod-web (aws, no AD).
    shadow = find_shadow_it(result)
    shadow_hosts = {c.hostname for c in shadow}
    assert "rogue-pi" in shadow_hosts
    assert "ec2-prod-web" in shadow_hosts
