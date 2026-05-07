"""
v9.4 — SNMP harvest unit tests.

These tests use the `walk_fn` seam so they don't shell out to net-snmp
or need real gear. The fixture lines mimic real `snmpwalk -O Qn` output
captured from a Cisco IOS box and an Arista EOS box.
"""

from __future__ import annotations

import pytest

from safecadence.discovery.snmp_harvest import (
    HarvestResult,
    harvest_from_router,
    neighbors_as_discovered_hosts,
    parse_cdp_walk,
    parse_lldp_walk,
    parse_mac_table_walk,
    _hex_to_mac, _hex_to_ip, _strip_type,
)


# --------------------------------------------------- helpers ----


_SYSDESCR_LINES = [
    '.1.3.6.1.2.1.1.1.0 = STRING: "Cisco IOS Software, ISR4451-X"',
]
_SYSNAME_LINES = [
    '.1.3.6.1.2.1.1.5.0 = STRING: "edge-rtr-01.acme.local"',
]


# Two LLDP neighbors: an Arista switch + a Linux server
_LLDP_LINES = [
    '.1.0.8802.1.1.2.1.4.1.1.5.0.1.1 = Hex-STRING: 00 11 22 33 44 55',
    '.1.0.8802.1.1.2.1.4.1.1.7.0.1.1 = STRING: "Et1"',
    '.1.0.8802.1.1.2.1.4.1.1.8.0.1.1 = STRING: "uplink to core"',
    '.1.0.8802.1.1.2.1.4.1.1.9.0.1.1 = STRING: "core-sw-01.acme.local"',
    '.1.0.8802.1.1.2.1.4.1.1.10.0.1.1 = STRING: "Arista EOS 4.30.0F"',

    '.1.0.8802.1.1.2.1.4.1.1.5.0.2.2 = Hex-STRING: aa bb cc dd ee ff',
    '.1.0.8802.1.1.2.1.4.1.1.7.0.2.2 = STRING: "eth0"',
    '.1.0.8802.1.1.2.1.4.1.1.9.0.2.2 = STRING: "linux-srv-04"',
    '.1.0.8802.1.1.2.1.4.1.1.10.0.2.2 = STRING: "Linux 5.15"',
]

# One CDP neighbor: a Cisco access switch
_CDP_LINES = [
    '.1.3.6.1.4.1.9.9.23.1.2.1.1.4.1.1 = Hex-STRING: 0A 00 00 02',
    '.1.3.6.1.4.1.9.9.23.1.2.1.1.5.1.1 = STRING: "Cisco IOS XE 17.9.4a"',
    '.1.3.6.1.4.1.9.9.23.1.2.1.1.6.1.1 = STRING: "access-sw-02.acme.local"',
    '.1.3.6.1.4.1.9.9.23.1.2.1.1.7.1.1 = STRING: "WS-C3850-48P"',
    '.1.3.6.1.4.1.9.9.23.1.2.1.1.8.1.1 = INTEGER: 64',  # decimal 64 = 0x40 = router bit
]

# Three MAC table entries
_MAC_LINES = [
    '.1.3.6.1.2.1.17.4.3.1.1.0.17.34.51.68.85 = Hex-STRING: 00 11 22 33 44 55',
    '.1.3.6.1.2.1.17.4.3.1.2.0.17.34.51.68.85 = INTEGER: 1',
    '.1.3.6.1.2.1.17.4.3.1.1.170.187.204.221.238.255 = Hex-STRING: AA BB CC DD EE FF',
    '.1.3.6.1.2.1.17.4.3.1.2.170.187.204.221.238.255 = INTEGER: 24',
    '.1.3.6.1.2.1.17.4.3.1.1.16.32.48.64.80.96 = Hex-STRING: 10 20 30 40 50 60',
    '.1.3.6.1.2.1.17.4.3.1.2.16.32.48.64.80.96 = INTEGER: 7',
]


def _fake_walk(host, community, oid, *, version="2c", timeout=5):
    """Test seam: dispatch on OID prefix to the appropriate fixture."""
    if oid.startswith(".1.3.6.1.2.1.1.1"):
        return _SYSDESCR_LINES
    if oid.startswith(".1.3.6.1.2.1.1.5"):
        return _SYSNAME_LINES
    if oid.startswith(".1.0.8802.1.1.2.1.4.1.1"):
        return _LLDP_LINES
    if oid.startswith(".1.3.6.1.4.1.9.9.23.1.2.1.1"):
        return _CDP_LINES
    if oid.startswith(".1.3.6.1.2.1.17.4.3.1"):
        return _MAC_LINES
    return []


# ---------------------------------------------------- parsers ----


def test_strip_type_removes_typename():
    assert _strip_type('STRING: "edge-rtr-01"') == "edge-rtr-01"
    assert _strip_type("INTEGER: 42") == "42"


def test_hex_to_mac_normal_case():
    assert _hex_to_mac("00 11 22 33 44 55") == "00:11:22:33:44:55"


def test_hex_to_ip_from_hex_string():
    assert _hex_to_ip("0A 00 00 02") == "10.0.0.2"


def test_hex_to_ip_passthrough_for_dotted():
    assert _hex_to_ip("10.0.0.42") == "10.0.0.42"


def test_parse_lldp_walk_groups_by_index():
    neighbors = parse_lldp_walk(_LLDP_LINES, via_router="10.0.0.1")
    assert len(neighbors) == 2
    by_host = {n.hostname: n for n in neighbors}
    core = by_host["core-sw-01.acme.local"]
    assert core.source_protocol == "lldp"
    assert core.chassis_id == "00:11:22:33:44:55"
    assert core.port_id == "Et1"
    assert "Arista" in core.sys_description
    linux = by_host["linux-srv-04"]
    assert linux.chassis_id == "aa:bb:cc:dd:ee:ff"


def test_parse_cdp_walk_extracts_ip_and_platform():
    neighbors = parse_cdp_walk(_CDP_LINES, via_router="10.0.0.1")
    assert len(neighbors) == 1
    n = neighbors[0]
    assert n.source_protocol == "cdp"
    assert n.hostname == "access-sw-02.acme.local"
    assert n.ip_address == "10.0.0.2"
    assert n.platform == "WS-C3850-48P"
    assert "router" in n.capabilities


def test_parse_mac_table_walk_pairs_address_and_port():
    macs = parse_mac_table_walk(_MAC_LINES, via_router="10.0.0.1")
    assert len(macs) == 3
    by_mac = {m.mac: m for m in macs}
    assert by_mac["00:11:22:33:44:55"].port == 1
    assert by_mac["aa:bb:cc:dd:ee:ff"].port == 24
    assert by_mac["10:20:30:40:50:60"].port == 7


# ---------------------------------------------------- harvester ----


def test_harvest_from_router_full_flow():
    r = harvest_from_router("10.0.0.1", "public", walk_fn=_fake_walk)
    assert isinstance(r, HarvestResult)
    assert r.sys_name == "edge-rtr-01.acme.local"
    assert "Cisco IOS" in r.sys_descr
    assert r.neighbor_count == 3   # 2 LLDP + 1 CDP
    assert r.mac_count == 3
    assert not r.error
    sources = {n.source_protocol for n in r.neighbors}
    assert sources == {"lldp", "cdp"}


def test_harvest_returns_error_on_sysname_failure():
    def bad_walk(host, community, oid, **kw):
        if oid.startswith(".1.3.6.1.2.1.1"):
            raise RuntimeError("timeout")
        return []
    r = harvest_from_router("10.0.0.1", "public", walk_fn=bad_walk)
    assert "timeout" in r.error
    assert r.neighbor_count == 0


def test_harvest_partial_failure_records_error_but_keeps_other_data():
    """LLDP succeeds, CDP fails → still get LLDP neighbors + an error note."""
    def partial_walk(host, community, oid, **kw):
        if oid.startswith(".1.3.6.1.2.1.1.1"):
            return _SYSDESCR_LINES
        if oid.startswith(".1.3.6.1.2.1.1.5"):
            return _SYSNAME_LINES
        if oid.startswith(".1.0.8802.1.1.2.1.4.1.1"):
            return _LLDP_LINES
        if oid.startswith(".1.3.6.1.4.1.9.9.23"):
            raise RuntimeError("CDP not enabled")
        return []
    r = harvest_from_router("10.0.0.1", "public", walk_fn=partial_walk)
    assert r.sys_name == "edge-rtr-01.acme.local"
    assert r.neighbor_count == 2     # LLDP only
    assert "CDP not enabled" in r.error


# ---------------------------------------------------- adapter ----


def test_neighbors_as_discovered_hosts_shape_matches_bridge():
    r = harvest_from_router("10.0.0.1", "public", walk_fn=_fake_walk)
    hosts = neighbors_as_discovered_hosts(r)
    # Bridge.discovered_to_asset() requires these keys:
    required = {"ip", "hostname", "mac", "vendor_guess",
                "device_type_guess", "open_ports", "banners"}
    for h in hosts:
        assert required <= set(h.keys()), \
            f"missing required keys in: {set(h.keys())}"
    # CDP neighbor should have its IP populated
    cdp_host = next(h for h in hosts if h["hostname"] == "access-sw-02.acme.local")
    assert cdp_host["ip"] == "10.0.0.2"
    assert "router" in (cdp_host["device_type_guess"] or "")
    assert cdp_host["vendor_guess"] == "cisco"


def test_capability_to_device_type_inference():
    """The 'router' CDP capability should map to device_type='router'."""
    r = harvest_from_router("10.0.0.1", "public", walk_fn=_fake_walk)
    hosts = neighbors_as_discovered_hosts(r)
    types = {h["device_type_guess"] for h in hosts}
    assert "router" in types
