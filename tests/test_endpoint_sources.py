"""
v9.5 — AD / Entra / DHCP harvest unit tests.

Use the test seams (search_fn / http_fn / read_fn) so we never need a
real DC, real Microsoft Graph, or a real DHCP server.
"""

from __future__ import annotations

import pytest

from safecadence.discovery.ad_harvest import (
    ADHarvestResult, harvest_ad, computers_as_discovered_hosts,
    _ou_from_dn, _enabled_from_uac,
)
from safecadence.discovery.entra_harvest import (
    EntraHarvestResult, harvest_entra, devices_as_discovered_hosts,
)
from safecadence.discovery.dhcp_harvest import (
    DhcpHarvestResult, harvest_isc, harvest_windows,
    parse_isc_leases_text, parse_windows_dhcp_csv,
    leases_as_discovered_hosts,
)


# ============================================================== AD


_FAKE_AD_ENTRIES = [
    {
        "name": "PC-ALICE-01",
        "dNSHostName": "pc-alice-01.acme.local",
        "operatingSystem": "Windows 11 Pro",
        "operatingSystemVersion": "10.0 (22631)",
        "userAccountControl": 4096,
        "distinguishedName": "CN=PC-ALICE-01,OU=Workstations,OU=Corp,DC=acme,DC=com",
        "lastLogonTimestamp": "2026-04-30T18:00:00Z",
    },
    {
        "name": "SRV-DC01",
        "dNSHostName": "srv-dc01.acme.local",
        "operatingSystem": "Windows Server 2022 Datacenter",
        "operatingSystemVersion": "10.0 (20348)",
        "userAccountControl": 4098,   # bit 0x2 set → disabled
        "distinguishedName": "CN=SRV-DC01,OU=DomainControllers,DC=acme,DC=com",
        "lastLogonTimestamp": "2026-05-04T01:00:00Z",
    },
]


def _fake_ad_search(server, base_dn, *, bind_dn, password,
                    ldap_filter, use_ssl):
    return list(_FAKE_AD_ENTRIES)


def test_ou_from_dn_extracts_nested_OUs():
    dn = "CN=PC1,OU=Workstations,OU=Corp,DC=acme,DC=com"
    assert _ou_from_dn(dn) == "Corp/Workstations"


def test_enabled_from_uac_disabled_bit():
    assert _enabled_from_uac(4096) is True       # normal account
    assert _enabled_from_uac(4098) is False      # 4096 + 2 (DISABLED)


def test_harvest_ad_returns_parsed_computers():
    r = harvest_ad("dc01.acme.local",
                   bind_dn="x", password="y", base_dn="DC=acme,DC=com",
                   search_fn=_fake_ad_search)
    assert isinstance(r, ADHarvestResult)
    assert r.count == 2
    pc = next(c for c in r.computers if c.name == "PC-ALICE-01")
    assert pc.dns_hostname == "pc-alice-01.acme.local"
    assert pc.ou == "Corp/Workstations"
    assert pc.enabled is True
    dc = next(c for c in r.computers if c.name == "SRV-DC01")
    assert dc.enabled is False


def test_harvest_ad_records_error_on_search_failure():
    def boom(*a, **kw): raise RuntimeError("LDAP bind failed")
    r = harvest_ad("dc01", bind_dn="x", password="y", base_dn="DC=a,DC=b",
                   search_fn=boom)
    assert "LDAP bind failed" in r.error
    assert r.count == 0


def test_ad_computers_as_discovered_hosts_shape():
    r = harvest_ad("dc01", bind_dn="x", password="y", base_dn="DC=a",
                   search_fn=_fake_ad_search)
    hosts = computers_as_discovered_hosts(r)
    required = {"ip", "hostname", "mac", "vendor_guess", "device_type_guess",
                "open_ports", "banners"}
    for h in hosts:
        assert required <= set(h.keys())
    pc_host = next(h for h in hosts if h["hostname"] == "pc-alice-01.acme.local")
    assert pc_host["os_guess"] == "windows"
    assert pc_host["vendor_guess"] == "microsoft"
    assert "ad on" in pc_host["banners"]["_via"]


# ============================================================== Entra


_FAKE_ENTRA_DEVICES = [
    {"id": "abc-1", "displayName": "MBP-faz", "deviceId": "uuid-1",
     "operatingSystem": "MacMDM", "operatingSystemVersion": "14.4",
     "accountEnabled": True, "deviceOwnership": "Company",
     "isCompliant": True, "isManaged": True,
     "approximateLastSignInDateTime": "2026-05-04T12:00:00Z",
     "registrationDateTime": "2024-01-15T08:00:00Z"},
    {"id": "abc-2", "displayName": "iPhone-ali", "deviceId": "uuid-2",
     "operatingSystem": "IOS", "operatingSystemVersion": "17.5",
     "accountEnabled": True, "deviceOwnership": "Personal",
     "isCompliant": False, "isManaged": True,
     "approximateLastSignInDateTime": "2026-05-04T11:00:00Z",
     "registrationDateTime": "2025-06-01T08:00:00Z"},
]


def _fake_entra_http(method, url, headers, body=None):
    if "oauth2/v2.0/token" in url:
        return {"access_token": "fake-token", "token_type": "Bearer",
                "expires_in": 3600}
    if "/devices" in url:
        return {"value": list(_FAKE_ENTRA_DEVICES)}
    raise RuntimeError(f"unexpected URL in test: {url}")


def test_harvest_entra_token_then_devices():
    r = harvest_entra("tenant-x", "client-y", "secret-z",
                      http_fn=_fake_entra_http)
    assert isinstance(r, EntraHarvestResult)
    assert r.count == 2
    mac = next(d for d in r.devices if d.display_name == "MBP-faz")
    assert mac.os.lower().startswith("mac")
    assert mac.compliant is True
    assert mac.ownership.lower() == "company"


def test_harvest_entra_records_token_failure():
    def fail(method, url, headers, body=None):
        raise RuntimeError("invalid_client")
    r = harvest_entra("t", "c", "s", http_fn=fail)
    assert "invalid_client" in r.error
    assert r.count == 0


def test_entra_harvest_requires_all_creds():
    r = harvest_entra("", "", "", http_fn=_fake_entra_http)
    assert "required" in r.error


def test_entra_devices_as_discovered_hosts_categorizes_mobile():
    r = harvest_entra("t", "c", "s", http_fn=_fake_entra_http)
    hosts = devices_as_discovered_hosts(r)
    iphone = next(h for h in hosts if h["hostname"] == "iPhone-ali")
    assert iphone["device_type_guess"] == "mobile"
    assert iphone["vendor_guess"] == "apple"
    assert iphone["os_guess"] == "ios"


# ============================================================== DHCP (ISC)


_ISC_TEXT = """
# ISC dhcpd lease database
lease 10.0.0.42 {
  starts 5 2026/05/03 21:00:00;
  ends 5 2026/05/04 09:00:00;
  binding state active;
  hardware ethernet 00:11:22:33:44:55;
  client-hostname "alice-laptop";
  set vendor-class-identifier = "MSFT 5.0";
}
lease 10.0.0.99 {
  starts 5 2026/05/02 10:00:00;
  ends 5 2026/05/02 22:00:00;
  binding state expired;
  hardware ethernet aa:bb:cc:dd:ee:ff;
  client-hostname "iot-cam-04";
  set vendor-class-identifier = "udhcp 1.30.1";
}
lease 10.0.0.7 {
  starts 5 2026/05/04 08:00:00;
  ends 5 2026/05/04 20:00:00;
  binding state active;
  hardware ethernet 12:34:56:78:9a:bc;
  client-hostname "ubuntu-srv-3";
  set vendor-class-identifier = "dhcpcd-7.0.8";
}
"""


def test_parse_isc_leases_text_extracts_three():
    leases = parse_isc_leases_text(_ISC_TEXT)
    assert len(leases) == 3
    by_ip = {L.ip: L for L in leases}
    alice = by_ip["10.0.0.42"]
    assert alice.mac == "00:11:22:33:44:55"
    assert alice.hostname == "alice-laptop"
    assert alice.state == "active"
    assert "MSFT" in alice.vendor_class
    iot = by_ip["10.0.0.99"]
    assert iot.state == "expired"


def test_harvest_isc_uses_read_fn_seam():
    r = harvest_isc("/fake/path", read_fn=lambda p: _ISC_TEXT)
    assert isinstance(r, DhcpHarvestResult)
    assert r.count == 3
    assert not r.error


def test_harvest_isc_records_read_failure():
    def boom(p): raise FileNotFoundError(p)
    r = harvest_isc("/missing", read_fn=boom)
    assert "failed to read" in r.error
    assert r.count == 0


def test_dhcp_leases_classify_iot_via_vendor_class():
    r = harvest_isc("/x", read_fn=lambda p: _ISC_TEXT)
    hosts = leases_as_discovered_hosts(r)
    by_ip = {h["ip"]: h for h in hosts}
    assert by_ip["10.0.0.42"]["os_guess"] == "windows"
    assert by_ip["10.0.0.42"]["vendor_guess"] == "microsoft"
    assert by_ip["10.0.0.99"]["device_type_guess"] == "iot"
    assert by_ip["10.0.0.7"]["os_guess"] == "linux"


# ============================================================== DHCP (Windows)


_WINDOWS_CSV = '''"IPAddress","ClientId","HostName","AddressState","LeaseExpiryTime"
"10.1.0.5","00-11-22-33-44-55","srv-print","Active","2026-05-05 10:00:00"
"10.1.0.99","aa-bb-cc-dd-ee-ff","iot-thermo","ActiveReservation","2026-05-06 12:00:00"
'''


def test_parse_windows_dhcp_csv_normalizes_mac_separator():
    leases = parse_windows_dhcp_csv(_WINDOWS_CSV)
    assert len(leases) == 2
    by_ip = {L.ip: L for L in leases}
    assert by_ip["10.1.0.5"].mac == "00:11:22:33:44:55"
    assert by_ip["10.1.0.99"].hostname == "iot-thermo"


def test_harvest_windows_with_csv_text_no_powershell():
    r = harvest_windows(csv_text=_WINDOWS_CSV)
    assert r.count == 2
    assert not r.error


def test_dhcp_leases_as_discovered_hosts_shape():
    r = harvest_isc("/x", read_fn=lambda p: _ISC_TEXT)
    hosts = leases_as_discovered_hosts(r)
    required = {"ip", "hostname", "mac", "vendor_guess", "device_type_guess",
                "open_ports", "banners"}
    for h in hosts:
        assert required <= set(h.keys())
        assert h["banners"]["_via"].startswith("dhcp")
