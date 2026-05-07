"""Realistic demo fleet — 30 fake assets covering every major asset type.

The point: when somebody runs `pip install safecadence-netrisk` and then
`safecadence ui` for the first time, the UI should not be empty. Empty
UIs are a 100%-bounce experience. This module loads a realistic fake
fleet that immediately shows:

  - KEV-listed CVEs on internet-facing gear
  - End-of-support hardware in critical paths
  - Identity drift (admins without MFA, dormant privileged accounts)
  - Backup gap on a crown-jewel asset
  - A traceable internet → crown-jewel attack path
  - Policy violations across NIST 800-53 / CIS / SOC 2 frameworks

Every asset uses real-looking vendors, IPs, and configurations so the
findings the engine surfaces look like findings a real shop would have.

Loaded by:
  - The CLI command `safecadence demo`
  - The first-run onboarding panel in the platform UI
  - Tests, so the entire policy / drift / attack-path stack stays
    exercised end-to-end on every CI run.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


# --------------------------------------------------------------------------
# Builders — small helpers so each asset stays readable
# --------------------------------------------------------------------------

def _ts(days_ago: int = 0) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()


def _identity(asset_id: str, asset_type: str, vendor: str, *,
              hostname: str = "", criticality: str = "medium",
              site: str = "dc-east-1", environment: str = "prod",
              owner: str = "netops",
              team: str = "Network Operations",
              country: str = "US",
              city: str = "Ashburn",
              campus: str = "DC1",
              building: str = "B1",
              floor: str = "2",
              rack: str = "R12",
              support_contract: str = "SmartNet-2026") -> dict:
    """v7.0 — every asset now carries owner/team + a full physical
    location (country / city / campus / building / floor / rack) plus
    a support contract reference. These map straight onto the spec's
    inventory model and unlock the location-grouped reports."""
    return {
        "asset_id": asset_id,
        "asset_type": asset_type,
        "vendor": vendor,
        "hostname": hostname or asset_id,
        "criticality": criticality,
        "site": site,
        "environment": environment,
        "owner": owner,
        "team": team,
        "country": country,
        "city": city,
        "campus": campus,
        "building": building,
        "floor": floor,
        "rack": rack,
        "support_contract": support_contract,
        "first_seen": _ts(120),
        "last_seen": _ts(0),
    }


def _asset(ident: dict, **blocks: Any) -> dict:
    """Compose a UnifiedAsset-shaped dict.

    v6.4 — every demo asset gets a derived ``tags`` list so the
    asset-groups primitive has something interesting to slice on right
    out of the box. Tags are computed from identity / network /
    security / lifecycle so they reflect the truth about the asset.
    """
    out = {"identity": ident}
    out.update(blocks)
    out["tags"] = _derive_tags(out)
    return out


def _derive_tags(asset: dict) -> list[str]:
    """Compute searchable tags from the asset's other blocks.

    Each tag has a stable prefix so users can build groups like
    ``has_tag: env:prod`` or ``has_tag: kev:yes`` without guessing.
    """
    tags: list[str] = []
    ident = asset.get("identity") or {}
    if ident.get("environment"):
        tags.append(f"env:{ident['environment']}")
    if ident.get("site"):
        tags.append(f"site:{ident['site']}")
    if ident.get("vendor"):
        tags.append(f"vendor:{ident['vendor']}")
    if ident.get("criticality"):
        tags.append(f"crit:{ident['criticality']}")
    if ident.get("asset_type"):
        tags.append(f"type:{ident['asset_type']}")
    sec = asset.get("security") or {}
    if (sec.get("kev_cves") or 0) > 0:
        tags.append("kev:yes")
    if (sec.get("critical_cves") or 0) > 0:
        tags.append("critical-cve:yes")
    net = asset.get("network") or {}
    if net.get("internet_facing") or net.get("public_ip"):
        tags.append("internet-facing")
    if (net.get("zone") or "").lower() == "dmz":
        tags.append("dmz")
    lc = asset.get("lifecycle") or {}
    days = lc.get("days_until_eos")
    if days is not None and days <= 0:
        tags.append("eos:past")
    elif days is not None and days <= 365:
        tags.append("eos:within-year")
    return tags


# --------------------------------------------------------------------------
# Fleet — 30 assets with deliberate, traceable findings
# --------------------------------------------------------------------------

def _network_assets() -> list[dict]:
    """5 Cisco IOS + 3 Palo Alto + 2 Arista + 2 Fortinet = 12 network assets."""
    out: list[dict] = []

    # Internet-facing edge router with KEV CVE — the seed of an attack path.
    # v9.1 — populated richly across all 13 field groups so /asset/{id}
    # shows every category for at least one device.
    out.append(_asset(
        _identity("edge-rtr-01.acme.local", "network", "cisco",
                  criticality="crown-jewel", site="dc-east-1"),
        os={"os_type": "ios-xe", "version": "16.9.4",
            "release_date": "2019-04-15", "boot_image": "asr1000rp1-adventerprisek9.16.09.04.SPA.bin",
            "config_register": "0x2102", "uptime_seconds": 7344000,  # ~85 days
            "kernel_version": "Linux 4.14.78"},
        hardware={"model": "ASR-1001-X", "serial": "FXS2018Q3DX",
                  "chassis_pid": "ASR1001-X", "chassis_vid": "V05",
                  "cpu_model": "Intel Xeon", "cpu_count": 4,
                  "memory_total_mb": 8192, "memory_used_mb": 4123,
                  "firmware_version": "16.9(4)", "bios_version": "ROMMON v15.6(2r)S",
                  "modules": [
                      {"slot": "0", "pid": "ASR1000-RP1", "serial": "FXS2018Q3DA"},
                      {"slot": "1", "pid": "ASR1000-ESP10", "serial": "FXS2018Q3DB"},
                  ],
                  "transceivers": [
                      {"port": "Gi0/0/0", "type": "GLC-LH-SMD", "serial": "AGM2330"},
                      {"port": "Gi0/0/1", "type": "GLC-T", "serial": "AGM2331"},
                  ],
                  "power_supplies": [
                      {"slot": "PS1", "status": "ok", "watts": 250},
                      {"slot": "PS2", "status": "failed", "watts": 0},
                  ],
                  "fans": [{"slot": "FAN1", "status": "ok", "rpm": 5000}]},
        network={"public_ip": "203.0.113.42", "internet_facing": True,
                 "zone": "edge", "mgmt_ip": "10.0.0.1"},
        security={"critical_cves": 3, "high_cves": 5, "kev_cves": 1,
                  "findings": ["telnet enabled", "snmpv2c with public string",
                               "default credentials", "PSU2 failed"],
                  "weak_protocols": ["telnet", "snmpv1", "snmpv2c", "http"]},
        lifecycle={"days_until_eos": 320, "last_patched": _ts(180),
                   "purchase_date": "2019-03-12", "warranty_status": "expired",
                   "warranty_expires": "2024-03-12",
                   "eol_status": "last-day-of-support",
                   "eol_date": "2024-09-30", "eos_date": "2027-09-30"},
        health={"grade": "D", "hardware_health": 60, "security_health": 30,
                "lifecycle_health": 50, "operational_health": 75,
                "overall_score": 45, "risk_band": "high"},
        license={"license_type": "smart", "license_level": "advantage",
                 "license_status": "active", "smart_license_enabled": True,
                 "license_expiry_date": "2026-09-30",
                 "licensed_features": ["routing", "qos", "ipsec",
                                        "voice-survivability"],
                 "seats_total": 1, "seats_used": 1},
        system_resources={"cpu_utilization_percent": 42.0,
                          "cpu_5sec": 38.0, "cpu_1min": 42.0, "cpu_5min": 40.0,
                          "memory_total_bytes": 8 * 1024 * 1024 * 1024,
                          "memory_used_bytes": 4 * 1024 * 1024 * 1024 + 123 * 1024 * 1024,
                          "memory_free_bytes": 3877 * 1024 * 1024,
                          "memory_utilization_percent": 50.3},
        routing={"routing_table_size": 421, "default_gateway": "203.0.113.1",
                 "static_routes_count": 8, "connected_routes_count": 14,
                 "ospf_routes_count": 312, "bgp_routes_count": 87,
                 "eigrp_routes_count": 0},
        l2_tables={"arp_entries_count": 256, "mac_table_entries_count": 1842,
                   "sample_mac_entries": [
                       {"mac": "0050.56a1.2b3c", "vlan_id": 10, "interface": "Gi0/0/0"},
                       {"mac": "0050.56a1.2b3d", "vlan_id": 20, "interface": "Gi0/0/1"},
                   ]},
        network_security={
            "aaa_enabled": False,
            "ssh_enabled": True, "telnet_enabled": True,  # ← finding!
            "http_server_enabled": True, "https_server_enabled": False,
            "snmp_v1_enabled": False, "snmp_v2c_enabled": True,
            "snmp_v3_enabled": False,
            "number_of_local_users": 3,
            "password_encryption_enabled": False,
            "acl_count": 12,
            "open_ports": [22, 23, 80, 161, 443, 8080],
            "vpn_tunnels_active": 4,
            "weak_default_creds_present": True,
        },
        routing_protocols={
            "ospf_enabled": True, "ospf_neighbor_count": 6,
            "ospf_areas": ["0.0.0.0", "0.0.0.1"],
            "bgp_enabled": True, "bgp_neighbor_count": 2, "bgp_asn": 65001,
            "eigrp_enabled": False,
            "routing_protocols_configured": ["OSPF", "BGP", "static"],
        },
        system_logging={
            "system_time": "2026-05-04T14:23:11Z",
            "timezone": "UTC",
            "ntp_status": "synced (stratum-3)",
            "ntp_servers": ["10.0.0.250", "time.nist.gov"],
            "syslog_servers": ["10.10.10.50:514"],
            "log_buffer_size_bytes": 16384,
            "critical_log_count": 2,
            "error_log_count": 14,
            "warning_log_count": 47,
            "last_log_message": "%LINK-3-UPDOWN: Interface Gi0/0/3, changed state to down",
        },
        compliance_signals={
            "eos_status": "last-day-of-support",
            "eol_status": "announced",
            "known_cves": ["CVE-2024-20356", "CVE-2024-20399", "CVE-2023-20198"],
            "weak_config_detected": True,
            "weak_config_findings": [
                "telnet enabled (RFC 854 — cleartext)",
                "SNMPv2c with default community 'public'",
                "default 'admin/admin' local user present",
                "HTTP management plane (no TLS)",
            ],
            "missing_best_practices": [
                "AAA TACACS+ not configured",
                "Mgmt-plane ACL too permissive (any/any)",
                "Logging buffer too small",
                "Config not backed up in last 7 days",
            ],
            "config_drift_detected": True,
            "drift_summary": "running-config differs from last-known-good baseline (5 lines)",
            "risk_score_0_100": 78,
        },
        raw_collection={"running": (
            "hostname edge-rtr-01\n"
            "username admin password admin\n"  # default creds — detector trip
            "line vty 0 4\n transport input telnet ssh\n"  # cleartext mgmt
            "ip http server\n"
            "snmp-server community public RO\n"
            "ip access-list extended MGMT permit ip any any\n"  # 0/0 mgmt
        )},
    ))

    # Healthy spine switch
    out.append(_asset(
        _identity("spine-sw-01", "network", "cisco",
                  criticality="high", site="dc-east-1"),
        os={"os_type": "nx-os", "version": "9.3.10"},
        hardware={"model": "Nexus-9504", "serial": "FOX2401Z1AA"},
        network={"mgmt_ip": "10.0.1.10"},
        security={"critical_cves": 0, "high_cves": 1, "kev_cves": 0},
        lifecycle={"days_until_eos": 1100, "last_patched": _ts(45)},
        health={"grade": "A"},
        raw_collection={"running": (
            "hostname spine-sw-01\n"
            "ip ssh version 2\n"
            "logging host 10.10.10.50\n"
            "snmp-server engineID local 0102030405\n"
        )},
    ))

    # End-of-support core switch — drift detector for EoS-in-crown-jewel
    out.append(_asset(
        _identity("core-sw-eos", "network", "cisco",
                  criticality="crown-jewel", site="dc-east-1"),
        os={"os_type": "ios", "version": "12.4(15)T"},
        hardware={"model": "Catalyst-6500", "serial": "SAL2001PRGS"},
        network={"mgmt_ip": "10.0.1.20"},
        security={"critical_cves": 4, "high_cves": 8, "kev_cves": 0},
        lifecycle={"days_until_eos": -90, "last_patched": _ts(720)},
        health={"grade": "F"},
        raw_collection={"running": (
            "hostname core-sw-eos\n"
            "no service password-encryption\n"
            "username root password 7 0822455D0A16\n"  # type-7 weak
        )},
    ))

    out.append(_asset(
        _identity("dist-sw-02", "network", "arista",
                  criticality="high", site="dc-east-1"),
        os={"os_type": "eos", "version": "4.30.5M"},
        hardware={"model": "DCS-7280SR3-48YC8"},
        network={"mgmt_ip": "10.0.1.30"},
        security={"critical_cves": 0, "high_cves": 0, "kev_cves": 0},
        lifecycle={"days_until_eos": 900, "last_patched": _ts(15)},
        health={"grade": "A"},
        raw_collection={"running": "ip ssh version 2\nsnmp-server v3\n"},
    ))

    out.append(_asset(
        _identity("dmz-fw-01", "network", "palo-alto",
                  criticality="crown-jewel", site="dc-east-1"),
        os={"os_type": "panos", "version": "10.2.6"},
        hardware={"model": "PA-3260"},
        network={"public_ip": "203.0.113.10", "internet_facing": True,
                 "zone": "dmz", "mgmt_ip": "10.0.10.1"},
        security={"critical_cves": 1, "high_cves": 2, "kev_cves": 0,
                  "findings": ["any-any outbound rule"]},
        lifecycle={"days_until_eos": 600, "last_patched": _ts(30)},
        health={"grade": "B"},
        raw_collection={"running": (
            "set rulebase security rules egress-any from trust to untrust "
            "source any destination any application any service any "
            "action allow\n"  # open egress detector
        )},
    ))

    out.append(_asset(
        _identity("internal-fw-01", "network", "fortinet",
                  criticality="high", site="dc-east-1"),
        os={"os_type": "fortios", "version": "7.4.3"},
        hardware={"model": "FortiGate-100F"},
        network={"mgmt_ip": "10.0.20.1"},
        security={"critical_cves": 0, "high_cves": 0, "kev_cves": 0},
        lifecycle={"days_until_eos": 800, "last_patched": _ts(20)},
        health={"grade": "A"},
        raw_collection={"running": "config system global\nset admintimeout 5\nend\n"},
    ))

    out.append(_asset(
        _identity("guest-wifi-fw", "network", "palo-alto",
                  criticality="medium", site="dc-east-1"),
        os={"os_type": "panos", "version": "9.1.16"},  # also out of LTS
        hardware={"model": "PA-220"},
        network={"mgmt_ip": "10.0.30.1"},
        security={"critical_cves": 1, "high_cves": 1, "kev_cves": 1},
        lifecycle={"days_until_eos": 0, "last_patched": _ts(400)},
        health={"grade": "C"},
        raw_collection={"running": "set tls-version 1.0\n"},  # legacy proto
    ))

    out.append(_asset(
        _identity("branch-rtr-nyc", "network", "cisco",
                  criticality="medium", site="branch-nyc"),
        os={"os_type": "ios-xe", "version": "17.6.5"},
        hardware={"model": "ISR-4331"},
        network={"public_ip": "198.51.100.7", "internet_facing": True,
                 "zone": "edge"},
        security={"critical_cves": 0, "high_cves": 1, "kev_cves": 0},
        lifecycle={"days_until_eos": 700, "last_patched": _ts(60)},
        health={"grade": "B"},
        raw_collection={"running": "ip ssh version 2\n"},
    ))

    out.append(_asset(
        _identity("branch-rtr-lax", "network", "cisco",
                  criticality="medium", site="branch-lax"),
        os={"os_type": "ios-xe", "version": "17.6.5"},
        hardware={"model": "ISR-4331"},
        network={"public_ip": "198.51.100.8", "internet_facing": True,
                 "zone": "edge"},
        security={"critical_cves": 0, "high_cves": 0, "kev_cves": 0},
        lifecycle={"days_until_eos": 700, "last_patched": _ts(60)},
        health={"grade": "A"},
    ))

    out.append(_asset(
        _identity("storage-sw-01", "network", "arista",
                  criticality="high", site="dc-east-1"),
        os={"os_type": "eos", "version": "4.29.1F"},
        hardware={"model": "DCS-7050X3-32S"},
        network={"mgmt_ip": "10.0.40.1"},
        security={"critical_cves": 0, "high_cves": 0, "kev_cves": 0},
        lifecycle={"days_until_eos": 800},
        health={"grade": "A"},
    ))

    out.append(_asset(
        _identity("oob-mgmt-sw", "network", "cisco",
                  criticality="medium", site="dc-east-1"),
        os={"os_type": "ios", "version": "15.2(7)E5"},
        hardware={"model": "Catalyst-3850"},
        security={"critical_cves": 0, "high_cves": 1, "kev_cves": 0},
        lifecycle={"days_until_eos": 200},
        health={"grade": "B"},
    ))

    out.append(_asset(
        _identity("vpn-concentrator", "network", "fortinet",
                  criticality="high", site="dc-east-1"),
        os={"os_type": "fortios", "version": "7.2.6"},
        hardware={"model": "FortiGate-VM"},
        network={"public_ip": "203.0.113.50", "internet_facing": True,
                 "zone": "edge"},
        security={"critical_cves": 0, "high_cves": 1, "kev_cves": 1},
        lifecycle={"days_until_eos": 500, "last_patched": _ts(90)},
        health={"grade": "C"},
    ))
    return out


def _server_assets() -> list[dict]:
    """4 Linux + 3 Windows = 7 servers, including a crown-jewel app server."""
    out: list[dict] = []

    out.append(_asset(
        _identity("crm-prod-01", "server", "ubuntu",
                  criticality="crown-jewel", site="dc-east-1"),
        os={"os_type": "linux", "version": "Ubuntu 20.04 LTS"},
        hardware={"model": "Dell PowerEdge R750"},
        network={"mgmt_ip": "10.20.10.50"},
        security={"critical_cves": 1, "high_cves": 4, "kev_cves": 1,
                  "findings": ["sshd PermitRootLogin yes",
                               "no SELinux/AppArmor enforcement"],
                  "ssh_authorized_keys": ["AAAAB3NzaC1...REUSED-KEY-A"]},
        lifecycle={"days_until_eos": 365, "last_patched": _ts(45)},
        health={"grade": "C"},
    ))

    out.append(_asset(
        _identity("crm-prod-02", "server", "ubuntu",
                  criticality="crown-jewel", site="dc-east-1"),
        os={"os_type": "linux", "version": "Ubuntu 20.04 LTS"},
        hardware={"model": "Dell PowerEdge R750"},
        network={"mgmt_ip": "10.20.10.51"},
        # Same SSH key as crm-prod-01 — triggers ssh_key_reuse edge
        security={"critical_cves": 0, "high_cves": 2, "kev_cves": 0,
                  "ssh_authorized_keys": ["AAAAB3NzaC1...REUSED-KEY-A"]},
        lifecycle={"days_until_eos": 365, "last_patched": _ts(45)},
        health={"grade": "B"},
    ))

    out.append(_asset(
        _identity("legacy-app-01", "server", "rhel",
                  criticality="high", site="dc-east-1"),
        os={"os_type": "linux", "version": "RHEL 7.9"},  # EoS June 2024
        hardware={"model": "HP DL380 Gen9"},
        security={"critical_cves": 2, "high_cves": 6, "kev_cves": 0},
        lifecycle={"days_until_eos": -200, "last_patched": _ts(400)},
        health={"grade": "F"},
    ))

    out.append(_asset(
        _identity("jump-host", "server", "debian",
                  criticality="high", site="dc-east-1"),
        os={"os_type": "linux", "version": "Debian 12"},
        security={"critical_cves": 0, "high_cves": 0, "kev_cves": 0},
        lifecycle={"days_until_eos": 800},
        health={"grade": "A"},
    ))

    out.append(_asset(
        _identity("dc-01.acme.local", "server", "microsoft",
                  criticality="crown-jewel", site="dc-east-1"),
        os={"os_type": "windows", "version": "Windows Server 2019"},
        hardware={"model": "Dell PowerEdge R650"},
        network={"mgmt_ip": "10.20.20.10"},
        security={"critical_cves": 1, "high_cves": 3, "kev_cves": 0,
                  "findings": ["SMBv1 enabled", "NTLMv1 allowed"]},
        identity_block={"provider": "ad", "domain": "acme.local"},
        lifecycle={"days_until_eos": 200},
        health={"grade": "C"},
        raw_collection={"running": "EnableSMB1Protocol = $true\n"},
    ))

    out.append(_asset(
        _identity("file-srv-01", "server", "microsoft",
                  criticality="high", site="dc-east-1"),
        os={"os_type": "windows", "version": "Windows Server 2022"},
        security={"critical_cves": 0, "high_cves": 1, "kev_cves": 0},
        identity_block={"provider": "ad", "domain": "acme.local"},
        lifecycle={"days_until_eos": 1500},
        health={"grade": "A"},
    ))

    out.append(_asset(
        _identity("rds-host-01", "server", "microsoft",
                  criticality="medium", site="branch-nyc"),
        os={"os_type": "windows", "version": "Windows Server 2016"},  # EoS soon
        security={"critical_cves": 0, "high_cves": 2, "kev_cves": 0},
        identity_block={"provider": "ad", "domain": "acme.local"},
        lifecycle={"days_until_eos": 30, "last_patched": _ts(120)},
        health={"grade": "C"},
    ))
    return out


def _cloud_assets() -> list[dict]:
    """4 AWS + 3 Azure = 7 cloud assets."""
    out: list[dict] = []

    # Internet-exposed S3 with secrets — the public-cloud crown-jewel risk
    out.append(_asset(
        _identity("s3-customer-data", "cloud", "aws",
                  criticality="crown-jewel", site="us-east-1"),
        cloud={"account_id": "111122223333", "region": "us-east-1",
               "service": "s3", "public_exposure": True,
               "iam_role": "arn:aws:iam::111122223333:role/AppRole",
               "default_encryption": False,    # detector trip
               "encryption_at_rest": False},
        storage={"encryption_at_rest": False},
        security={"critical_cves": 0, "high_cves": 0, "kev_cves": 0,
                  "findings": ["public ACL allows ListBucket",
                               "no default encryption configured"]},
        identity_block={"authorized_users": ["devops@acme.com",
                                              "intern@acme.com",
                                              "former-employee@acme.com"]},
        health={"grade": "D"},
    ))

    out.append(_asset(
        _identity("ec2-jump-prod", "cloud", "aws",
                  criticality="high", site="us-east-1"),
        cloud={"account_id": "111122223333", "region": "us-east-1",
               "service": "ec2", "public_ip": "54.84.10.20",
               "trusted_accounts": ["444455556666"]},  # cross-acct trust
        network={"public_ip": "54.84.10.20", "internet_facing": True,
                 "zone": "edge"},
        security={"critical_cves": 1, "high_cves": 2, "kev_cves": 1},
        health={"grade": "C"},
    ))

    out.append(_asset(
        _identity("rds-prod-customer", "cloud", "aws",
                  criticality="crown-jewel", site="us-east-1"),
        cloud={"account_id": "111122223333", "region": "us-east-1",
               "service": "rds", "engine": "postgres",
               "public_exposure": False,
               "encryption_at_rest": True,
               "kms_key_id": "arn:aws:kms:us-east-1:111122223333:key/abc"},
        storage={"encryption_at_rest": True},
        security={"critical_cves": 0, "high_cves": 1, "kev_cves": 0,
                  "findings": ["backup retention only 7 days"]},
        health={"grade": "B"},
    ))

    out.append(_asset(
        _identity("aws-acct-prod", "cloud", "aws",
                  criticality="crown-jewel", site="us-east-1"),
        cloud={"account_id": "111122223333", "region": "us-east-1",
               "service": "organizations",
               "trusted_accounts": ["444455556666"]},
        identity_block={"authorized_users": ["root@acme.com"],
                        "authorized_groups": ["AdminTeam"]},
        health={"grade": "B"},
    ))

    out.append(_asset(
        _identity("azure-storage-backups", "cloud", "azure",
                  criticality="crown-jewel", site="eastus2"),
        cloud={"subscription_id": "abcd-1234-...",
               "service": "storage_account",
               "iam_role": "Owner",
               "default_encryption": True,
               "encryption_at_rest": True,
               "has_locked_immutability_policy": False},
        storage={"encryption_at_rest": True},
        security={"critical_cves": 0, "high_cves": 0, "kev_cves": 0,
                  "findings": ["immutability policy disabled",
                               "soft delete disabled"]},
        identity_block={"provider": "entra",
                        "authorized_users": ["sp-app-only"],
                        "authorized_groups": ["Owners"],
                        "mfa_enrolled": False,    # admin without MFA
                        "last_login": _ts(1),
                        "conditional_access_rules": []},  # idp_conditional_access → FAIL
        health={"grade": "D"},
    ))

    out.append(_asset(
        _identity("azure-aks-prod", "cloud", "azure",
                  criticality="high", site="eastus2"),
        cloud={"subscription_id": "abcd-1234-...",
               "service": "aks", "iam_role": "Contributor"},
        security={"critical_cves": 0, "high_cves": 1, "kev_cves": 0},
        health={"grade": "B"},
    ))

    out.append(_asset(
        _identity("azure-vm-test", "cloud", "azure",
                  criticality="low", site="eastus2", environment="dev"),
        cloud={"subscription_id": "abcd-1234-...",
               "service": "vm", "iam_role": "Reader"},
        security={"critical_cves": 0, "high_cves": 0, "kev_cves": 0},
        health={"grade": "A"},
    ))
    return out


def _identity_assets() -> list[dict]:
    """3 identity sources — AD, Okta, Cisco ISE — with realistic drift."""
    out: list[dict] = []

    out.append(_asset(
        _identity("ad-acme-local", "identity", "microsoft",
                  criticality="crown-jewel", site="dc-east-1"),
        identity_block={
            "provider": "ad", "domain": "acme.local",
            "authorized_users": [
                "alice.admin", "bob.engineer", "carol.intern",
                "dave.former",  # dormant
                "eve.contractor", "frank.dba", "grace.helpdesk",
                "henry.former", "ivan.devops", "jane.cfo",
                "kate.exec", "lou.it", "matt.eng",
            ],
            "authorized_groups": ["Domain Admins", "Helpdesk", "Contractors"],
            "mfa_enrolled": False,    # idp_require_mfa_for_admins → FAIL
            "posture_score": 8,       # idp_password_complexity → FAIL (< 14)
            "password_min_length": 8,
            "last_login": _ts(2),
            # Privileged-role review: more than 180 days ago → FAIL
            "last_access_review": _ts(220),
        },
        security={"findings": ["password policy minLen=8",
                                "no MFA on Domain Admins"]},
        health={"grade": "D"},
    ))

    out.append(_asset(
        _identity("okta-acme", "identity", "okta",
                  criticality="crown-jewel"),
        identity_block={
            "provider": "okta", "domain": "acme.okta.com",
            "authorized_users": ["alice.admin", "bob.engineer",
                                  "carol.intern", "frank.dba",
                                  "ivan.devops", "kate.exec"],
            "authorized_groups": ["Engineering", "Finance", "Admins"],
            "mfa_enrolled": True,
            "password_min_length": 16,
            "last_login": _ts(0),
            "last_access_review": _ts(45),
            "conditional_access_rules": [
                "block-legacy-auth", "require-mfa-for-admin-portal",
                "require-compliant-device-for-finance",
            ],
        },
        health={"grade": "A"},
    ))

    out.append(_asset(
        _identity("ise-corp", "identity", "cisco-ise",
                  criticality="high", site="dc-east-1"),
        identity_block={
            "provider": "cisco-ise",
            "authorized_groups": ["EmployeeFull", "GuestRestricted",
                                   "ContractorRestricted"],
        },
        raw_collection=("policy contractor-restricted permit "
                         "10.50.0.0/16 -> quarantine\n"),
        health={"grade": "B"},
    ))

    # v7.8 — populate group_memberships, authorized_groups for attack-path
    # discovery, and add NHIs (service accounts) so the Identity tab has
    # something to surface on first run instead of empty tables.

    # Augment AD asset with group memberships (so over-privileged finder fires)
    out[0]["identity_block"]["group_memberships"] = {
        "alice.admin@acme.local": [
            "Domain Admins", "Helpdesk", "Engineering", "Finance",
            "BackupOperators", "ServerOperators",  # 6 groups → over-privileged
        ],
        "ivan.devops@acme.local": ["BuildEngineers", "Engineering"],
        "frank.dba@acme.local": ["Finance"],
    }

    # Add NHI assets — the v7.5+ first-class non-human identity model
    out.append(_asset(
        _identity("nhi-build-bot", "identity", "okta",
                   criticality="high"),
        nhi={
            "nhi_id": "nhi-build-bot",
            "subtype": "service_account",
            "display_name": "BuildBot Production CI",
            "owner_principal": "ivan.devops@acme.local",
            "provider": "okta",
            "created_at": _ts(720),                   # 2 years ago
            "last_used_at": _ts(0),                   # active
            "last_rotated_at": _ts(720),              # never rotated → finding
            "rotation_policy_days": 90,
            "credential_type": "client_secret",
            "effective_scopes": ["okta.users.read", "okta.groups.write"],
            "can_impersonate": ["AdminRole"],          # privilege-escalation edge
            "risk_findings": [],
        },
        health={"grade": "C"},
    ))

    out.append(_asset(
        _identity("nhi-legacy-importer", "identity", "ad",
                   criticality="medium"),
        nhi={
            "nhi_id": "nhi-legacy-importer",
            "subtype": "service_account",
            "display_name": "Legacy CSV importer (deprecated)",
            "owner_principal": "henry.former@acme.local",  # departed → orphan
            "provider": "ad",
            "created_at": _ts(1095),                   # 3 years ago
            "last_used_at": _ts(180),                   # stale → finding
            "last_rotated_at": _ts(1095),               # never rotated
            "rotation_policy_days": 90,
            "credential_type": "password",
            "effective_scopes": ["read:legacy-files"],
            "risk_findings": [],
        },
        health={"grade": "F"},
    ))

    out.append(_asset(
        _identity("nhi-aws-ci-role", "identity", "aws",
                   criticality="high"),
        nhi={
            "nhi_id": "nhi-aws-ci-role",
            "subtype": "iam_role",
            "display_name": "GitHub Actions CI role",
            "owner_principal": "ivan.devops@acme.local",
            "provider": "aws",
            "created_at": _ts(120),
            "last_used_at": _ts(0),
            "last_rotated_at": _ts(30),
            "credential_type": "private_key",
            "effective_scopes": ["s3:GetObject", "s3:PutObject",
                                  "ec2:DescribeInstances"],
            "risk_findings": [],
        },
        health={"grade": "B"},
    ))

    return out


def _backup_assets() -> list[dict]:
    """1 Veeam, 1 healthy AWS Backup vault — covers backup-gap drift."""
    out: list[dict] = []

    # Veeam protecting most of the fleet, but missing crm-prod-02 — gap
    out.append(_asset(
        _identity("veeam-prod-01", "backup", "veeam",
                  criticality="high", site="dc-east-1"),
        backup={
            "platform": "veeam-br-12",
            "protected_assets": ["crm-prod-01", "dc-01.acme.local",
                                  "file-srv-01", "legacy-app-01"],
            "immutability_days": 14,
            "immutability_enabled": True,
            "retention_days": 30,
            "air_gapped": False,           # no tape job — drift detector trip
            "offsite_copies": 0,
            "last_run": _ts(0), "last_success": _ts(0),
        },
        health={"grade": "B"},
    ))

    out.append(_asset(
        _identity("aws-backup-vault-prod", "backup", "aws",
                  criticality="crown-jewel"),
        cloud={"account_id": "111122223333", "service": "backup-vault"},
        backup={
            "platform": "aws-backup",
            "protected_assets": ["rds-prod-customer", "s3-customer-data"],
            "immutability_days": 30,
            "immutability_enabled": True,
            "retention_days": 35,
            "vault_locked": True,
            "air_gapped": True,
            "cross_region_copy": True,
            "cross_account_copy": True,
        },
        health={"grade": "A"},
    ))
    return out


def build_demo_fleet() -> list[dict]:
    """Return the complete 30-asset demo fleet as plain dicts."""
    fleet: list[dict] = []
    fleet.extend(_network_assets())
    fleet.extend(_server_assets())
    fleet.extend(_cloud_assets())
    fleet.extend(_identity_assets())
    fleet.extend(_backup_assets())
    return fleet


# --------------------------------------------------------------------------
# Loader — write the fleet to the platform asset store
# --------------------------------------------------------------------------

def load_demo_fleet(target_dir: Path | None = None,
                    *, overwrite: bool = False) -> dict:
    """Materialise the demo fleet into the platform asset store.

    Returns a small report dict (count, target_dir, skipped) so the CLI
    + UI can show meaningful feedback. Idempotent — re-running with
    overwrite=False keeps existing files.
    """
    from safecadence.server.platform_api import _store_dir, _safe_asset_path

    base = Path(target_dir) if target_dir else _store_dir()
    base.mkdir(parents=True, exist_ok=True)

    fleet = build_demo_fleet()
    written = 0
    skipped = 0
    asset_ids: list[str] = []
    for asset in fleet:
        aid = (asset.get("identity") or {}).get("asset_id")
        if not aid:
            continue
        # Reuse the same path-traversal-safe writer as the rest of the platform
        try:
            from safecadence.server.platform_api import _store_dir as _sd
            target_root = Path(target_dir) if target_dir else _sd()
            # Build the safe path manually so we honour an alternative root
            # (used by tests). _safe_asset_path always resolves relative to
            # the SC_PLATFORM_STORE / default; if the caller passed an
            # explicit target_dir we trust it after the same sanitisation.
            from safecadence.server.platform_api import _SAFE_ASSET_ID
            if (not _SAFE_ASSET_ID.match(aid)
                    or "/" in aid or ".." in aid):
                skipped += 1
                continue
            target = target_root / f"{aid}.json"
        except Exception:
            skipped += 1
            continue
        if target.exists() and not overwrite:
            skipped += 1
            continue
        target.write_text(json.dumps(asset, indent=2, default=str),
                          encoding="utf-8")
        written += 1
        asset_ids.append(aid)

    # v9.31 — seed compliance surfaces so /compliance, /risks, /scores,
    # /findings and the evidence chain aren't empty on first boot.
    # Best-effort: each block is wrapped so a single failure doesn't
    # break the demo loader.
    compliance_seeded = _seed_compliance_demo(asset_ids)

    # v9.35.1 #1 — three-tier identity vault + NHIs + execution jobs
    # so /identity, /access, /queue, /approvals, /rollback, and
    # /per-device-diff aren't empty on first boot. Each block is
    # best-effort.
    identity_seeded = _seed_identity_vault_demo()
    nhi_seeded = _seed_nhi_demo()
    execution_seeded = _seed_execution_demo(asset_ids)

    # v9.45 — populate the v9.42-v9.44 surfaces (/users, /settings)
    # so first-time visitors aren't staring at empty pages.
    users_seeded = _seed_users_and_webhooks_demo()

    # v9.50.1 — seed capability grants + IdP-sourced groups so
    # /users#caps and /idp-groups aren't empty after demo. Each
    # block is best-effort; failure here doesn't abort the demo.
    caps_seeded = _seed_capabilities_demo()
    groups_seeded = _seed_idp_groups_demo()

    # v9.55 — seed example automation rules so /automation isn't an
    # empty page on first visit. New users immediately see what a
    # realistic rule looks like and can clone/edit instead of
    # starting from scratch.
    automation_seeded = _seed_automation_demo()

    return {
        "demo_loaded": True,
        "total_in_fleet": len(fleet),
        "written": written,
        "skipped": skipped,
        "target_dir": str(base),
        "asset_ids": asset_ids,
        "summary": _summary_text(fleet),
        "compliance_seeded": compliance_seeded,
        "identity_seeded": identity_seeded,
        "nhi_seeded": nhi_seeded,
        "execution_seeded": execution_seeded,
        "users_seeded": users_seeded,
        "caps_seeded": caps_seeded,
        "groups_seeded": groups_seeded,
        "automation_seeded": automation_seeded,
    }


def _seed_automation_demo() -> dict:
    """v9.55 — seed three example automation rules so /automation
    isn't a blank page on first visit. The set covers the three
    most common patterns:

      1. notify-only on critical (no side effects → safe even if
         the demo box has a real PagerDuty configured)
      2. assign-and-watch on stale NHIs (workflow-heavy, no IdP
         mutation)
      3. dry-run auto_fix on no_mfa (proof of the auto-remediate
         path; commit=false so nothing escapes)

    Each rule is created DISABLED so a fresh `safecadence demo`
    box doesn't accidentally fire automations against a real IdP
    if SC_AUTOMATION_DISABLED isn't set. Operators flip them on
    via /automation when they're ready.
    """
    try:
        from safecadence.intel.automation import save_rule, list_rules
    except Exception:
        return {"ok": False, "error": "automation module unavailable"}

    # Idempotent — if any rules already exist, leave them alone.
    if list_rules():
        return {"ok": True, "skipped": "rules already present"}

    examples = [
        {
            "name": "demo: notify on CRITICAL",
            "enabled": False,
            "when": {"severity_at_least": "critical"},
            "then": [
                {"action": "notify_log"},
                {"action": "notify_slack", "channel": "#sec-alerts"},
            ],
            "rate_limit_seconds": 1800,
        },
        {
            "name": "demo: assign + watch stale NHIs",
            "enabled": False,
            "when": {"kind": "stale_nhi", "severity_at_least": "medium"},
            "then": [
                {"action": "assign", "to": "alice@example.com"},
                {"action": "add_to_watchlist", "user": "alice"},
                {"action": "add_comment",
                  "text": "auto-flagged by 'stale NHI' rule — please rotate or retire",
                  "user": "automation"},
            ],
            "rate_limit_seconds": 86400,
        },
        {
            "name": "demo: dry-run auto_fix on no_mfa (HIGH+)",
            "enabled": False,
            "when": {"kind": "no_mfa", "severity_at_least": "high"},
            "then": [
                {"action": "auto_fix"},   # commit defaults to false
                {"action": "notify_pagerduty", "service_key": ""},
            ],
            "rate_limit_seconds": 3600,
        },
    ]
    saved = []
    for rule in examples:
        try:
            r = save_rule(rule)
            saved.append(r.rule_id)
        except Exception:
            continue
    return {"ok": True, "rules_seeded": saved,
             "note": ("All demo rules are DISABLED by default — flip "
                       "them on in /automation after reviewing.")}


def _seed_capabilities_demo() -> dict:
    """Seed example capability grants so /users#caps shows real
    rows on first visit. Mirrors a realistic small-team
    distribution: alice = security lead with admin extras,
    bob = approver with rollback rights, carol = read-only auditor
    plus an explicit execute.real DENY (which actually does nothing
    on a viewer floor — but proves the deny mechanic in the UI)."""
    out = {"grants": 0}
    try:
        from safecadence.capabilities.store import grant, revoke
        from safecadence.capabilities import Capability
        sample = [
            ("alice", Capability.MANAGE_CAPABILITIES, "demo-cto"),
            ("alice", Capability.MANAGE_WEBHOOKS, "demo-cto"),
            ("bob",   Capability.EXECUTE_ROLLBACK, "demo-cto"),
            ("bob",   Capability.GRANT_JIT, "demo-cto"),
        ]
        for username, cap, actor in sample:
            try:
                grant(username, cap, actor=actor,
                      reason="demo seed — example grant")
                out["grants"] += 1
            except Exception:                           # pragma: no cover
                continue
        # Belt-and-braces deny example
        try:
            revoke("carol", Capability.EXECUTE_REAL,
                    actor="demo-cto",
                    reason="demo seed — explicit deny example")
            out["denies"] = 1
        except Exception:                               # pragma: no cover
            out["denies"] = 0
    except Exception:                                   # pragma: no cover
        pass
    return out


def _seed_idp_groups_demo() -> dict:
    """Seed example IdP-sourced groups so /idp-groups shows real
    rows on first visit. Members reference the demo users seeded
    by `_seed_users_and_webhooks_demo`.

    v9.52.1 honesty note: these are SYNTHETIC fixtures — `eng-leads`
    and `secops` are tagged ``system='okta'`` but no Okta tenant is
    actually connected by `safecadence demo`. Same for the `auditors`
    group tagged ``system='ad'``. A real adapter sync would replace
    these with whatever ``list_groups()`` returns from the connected
    IdP. The fixtures exist so /idp-groups + ``@group:NAME`` invitee
    expansion can be exercised on a fresh demo box without wiring
    real credentials.
    """
    out = {"groups": 0}
    try:
        from safecadence.identity.groups import upsert_group, GroupRecord
        sample = [
            GroupRecord(system="okta", id="00g-eng-leads",
                          name="eng-leads",
                          members=["alice", "bob"]),
            GroupRecord(system="okta", id="00g-secops",
                          name="secops",
                          members=["alice"]),
            GroupRecord(system="ad", id="cn-auditors",
                          name="auditors",
                          members=["carol"]),
        ]
        for g in sample:
            try:
                upsert_group(g)
                out["groups"] += 1
            except Exception:                           # pragma: no cover
                continue
    except Exception:                                   # pragma: no cover
        pass
    return out


def _seed_users_and_webhooks_demo() -> dict:
    """Seed the user directory + webhook registry with realistic-looking
    examples so the /users admin page and /settings#webhooks tab are
    populated on first run. Best-effort. Webhook URLs are clearly
    fake (example.com) so no real delivery is attempted, but they
    prove out the form + filter UI."""
    out = {"users": 0, "webhooks": 0}

    # Users — directory is YAML, tenant-scoped
    try:
        from safecadence.users import directory as _dir
        tenant = "default"
        sample_users = [
            dict(username="alice",
                 email="alice@example.com",
                 display_name="Alice Chen (demo)",
                 roles=["admin"]),
            dict(username="bob",
                 email="bob@example.com",
                 display_name="Bob Martinez (demo)",
                 roles=["approver"]),
            dict(username="carol",
                 email="carol@example.com",
                 display_name="Carol Singh (demo)",
                 roles=["viewer"]),
        ]
        try:
            existing = {u.username for u in _dir.list_users(tenant=tenant)}
        except Exception:                           # pragma: no cover
            existing = set()
        for u in sample_users:
            if u["username"] in existing:
                continue
            try:
                _dir.upsert_user(u, tenant=tenant)
                out["users"] += 1
            except Exception:                       # pragma: no cover
                continue
    except Exception:                               # pragma: no cover
        pass

    # Webhooks — example URLs only, all start disabled. Operators
    # toggle them on after replacing the URL with a real one. The
    # Test button on disabled rows is fine — it sends a synthetic
    # event and reports the HTTP failure clearly.
    try:
        from safecadence.notifier import webhook_registry as _wh
        sample_hooks = [
            dict(id="demo-slack",
                 provider="slack",
                 url="https://hooks.slack.com/services/EXAMPLE/DEMO/REPLACE",
                 categories=["finding_critical", "drift_detected"],
                 min_severity="high",
                 enabled=False,
                 notes="Demo Slack channel — replace URL to enable"),
            dict(id="demo-pagerduty",
                 provider="pagerduty",
                 url="https://events.pagerduty.com/v2/enqueue",
                 api_token="EXAMPLE_INTEGRATION_KEY",
                 categories=["finding_critical"],
                 min_severity="critical",
                 enabled=False,
                 notes="Demo PagerDuty — replace integration key"),
            dict(id="demo-teams",
                 provider="teams",
                 url=("https://outlook.office.com/webhook/EXAMPLE/"
                      "IncomingWebhook/REPLACE"),
                 categories=["digest_daily", "automation_fired"],
                 min_severity="info",
                 enabled=False,
                 notes="Demo Teams channel — replace URL to enable"),
        ]
        try:
            existing = {w.id for w in _wh.list_webhooks()}
        except Exception:                           # pragma: no cover
            existing = set()
        for h in sample_hooks:
            if h["id"] in existing:
                continue
            try:
                _wh.upsert(h)
                out["webhooks"] += 1
            except Exception:                       # pragma: no cover
                continue
    except Exception:                               # pragma: no cover
        pass

    return out


def _seed_compliance_demo(asset_ids: list[str]) -> dict:
    """Populate risk register, exceptions, control test history,
    sample baselines, and evidence chain with realistic demo data so
    the v9.27..v9.30 surfaces have something to render. Pure best-
    effort — every block is independent so a partial failure doesn't
    kill the rest."""
    out = {"risks": 0, "exceptions": 0, "control_history": 0,
           "baselines": 0, "evidence_chain": 0, "vendors": 0}

    # 1) Risk register — a handful of representative risks.
    try:
        from safecadence.compliance.risk_register import create_risk
        sample_risks = [
            dict(title="Ransomware via misconfigured RDP",
                 description="Public RDP exposed on jump host without MFA",
                 owner="ciso@acme.com", domain="server",
                 likelihood=4, impact=5,
                 control_ids=["enforce_mfa", "restrict_default_creds"],
                 mitigation="Enforce MFA + remove public RDP via CA"),
            dict(title="Stale privileged AD accounts",
                 description="Admin accounts not rotated in 365+ days",
                 owner="iam@acme.com", domain="identity",
                 likelihood=3, impact=4,
                 control_ids=["idp_disable_dormant_accounts",
                              "idp_privileged_role_review"],
                 mitigation="Quarterly privileged role review"),
            dict(title="Missing immutable backup tier",
                 description="Veeam pool lacks object-locked copy",
                 owner="sysadmin@acme.com", domain="backup",
                 likelihood=2, impact=5,
                 control_ids=["enforce_immutability", "enforce_air_gap"],
                 mitigation="Add S3 Object Lock target"),
            dict(title="Internet-exposed firewall mgmt plane",
                 description="Edge firewall accepts mgmt from any source",
                 owner="netops@acme.com", domain="network",
                 likelihood=3, impact=5,
                 control_ids=["restrict_management_access",
                              "enforce_ssh_v2"],
                 mitigation="Lock mgmt to jump-host ACL"),
        ]
        for r in sample_risks:
            create_risk(**r)
            out["risks"] += 1
    except Exception:
        pass

    # 2) Exception lifecycle — 2 active, 1 expiring soon.
    try:
        from safecadence.compliance.exception_lifecycle import create_exception
        if asset_ids:
            create_exception(
                control_id="enforce_mfa",
                asset_id=asset_ids[0],
                finding_id="demo-finding-1",
                justification=("Legacy ICS controller scheduled for "
                               "retirement Q3 — vendor doesn't support "
                               "MFA on this firmware tier."),
                accepted_by="ciso@acme.com",
                valid_for_days=60,
            )
            out["exceptions"] += 1
            create_exception(
                control_id="enforce_patch_level",
                asset_id=asset_ids[min(1, len(asset_ids) - 1)],
                finding_id="demo-finding-2",
                justification=("Vendor patch incompatible with our HA pair; "
                               "targeting next maintenance window."),
                accepted_by="netops@acme.com",
                valid_for_days=14,   # near re-review boundary
            )
            out["exceptions"] += 1
    except Exception:
        pass

    # 3) Control test history — fill 30 days of pass/fail records so
    # the control-history-summary endpoint shows real Type 2 evidence.
    try:
        from safecadence.compliance.control_history import record
        from datetime import datetime, timezone, timedelta
        controls = ["enforce_mfa", "enforce_logging", "enforce_ssh_v2",
                    "disable_telnet", "block_public_exposure",
                    "enforce_backup_retention"]
        now = datetime.now(timezone.utc)
        for i, cid in enumerate(controls):
            for d in range(30):
                ts = now - timedelta(days=29 - d)
                # Mostly pass; one fail per control so the rate is
                # interesting (29/30 = 96.7%) instead of either 0 or 100.
                outcome = "fail" if d == (10 + i) else "pass"
                aid = (asset_ids[(d + i) % len(asset_ids)]
                       if asset_ids else "demo")
                record(cid, aid, outcome,
                       method="config_inspection",
                       evaluator="demo",
                       when=ts)
                out["control_history"] += 1
    except Exception:
        pass

    # 4) Baselines — declare a baseline for the first 3 network assets.
    # IMPORTANT: the baseline is INTENTIONALLY different from the
    # demo asset's current running config so /drift's Baseline tab
    # actually has rows to show. Without the difference, the page
    # renders empty and the operator can't see the feature working.
    try:
        from safecadence.compliance.baseline_drift import set_baseline
        # The demo's network assets ship with weaker configs (one has
        # `ip http server` enabled, another lacks logging). The
        # baseline below is the *gold-standard* config — so every
        # weak demo asset shows actionable drift on first run.
        gold_baseline = (
            "aaa new-model\n"
            "ip ssh version 2\n"
            "no ip http server\n"           # asset has it ON → drift
            "ip http secure-server\n"
            "logging host 10.0.0.5\n"        # asset missing → drift
            "logging trap informational\n"
            "ntp server 10.0.0.6\n"
            "service password-encryption\n"
            "no ip source-route\n"
            "snmp-server group SCG v3 priv\n"
        )
        for aid in asset_ids[:3]:
            set_baseline(aid, gold_baseline, set_by="demo")
            out["baselines"] += 1
    except Exception:
        pass

    # 5) Vendor risk — seed a few representative third parties so
    # /vendors isn't empty on first run. Includes one with a short-
    # expiry attestation so the "expiring < 60d" card lights up.
    try:
        from safecadence.compliance.vendor_risk import (
            create_vendor, add_attestation,
        )
        from datetime import datetime as _dt, timezone as _tz, timedelta as _td
        soon = (_dt.now(_tz.utc) + _td(days=45)).isoformat()
        far  = (_dt.now(_tz.utc) + _td(days=300)).isoformat()
        v_aws = create_vendor(name="AWS", category="cloud",
                                  criticality="critical",
                                  contact="aws-security@amazon.com",
                                  residual_risk="low",
                                  notes="Hosts production VPC + RDS")
        add_attestation(v_aws.id, type="soc2_type2",
                          status="active", expires_at=far)
        out["vendors"] += 1
        v_okta = create_vendor(name="Okta", category="saas",
                                   criticality="critical",
                                   contact="security@okta.com",
                                   residual_risk="medium")
        add_attestation(v_okta.id, type="soc2_type2",
                          status="active", expires_at=soon)
        add_attestation(v_okta.id, type="iso27001",
                          status="active", expires_at=far)
        out["vendors"] += 1
        v_msp = create_vendor(name="AcmeManaged",
                                  category="msp",
                                  criticality="high",
                                  residual_risk="high",
                                  notes="Managed firewall + SIEM")
        add_attestation(v_msp.id, type="soc2_type1",
                          status="active", expires_at=soon)
        out["vendors"] += 1
    except Exception:
        pass

    # 6) Evidence chain — append a couple of pretend packs so the
    # tamper-evident chain has links to verify.
    try:
        from safecadence.compliance.evidence_chain import append
        for fw in ("soc2", "iso27001", "nist-800-53"):
            append(framework=fw,
                   content=f"DEMO {fw} pack — synthetic".encode("utf-8"),
                   generated_by="demo",
                   note="seeded by safecadence demo")
            out["evidence_chain"] += 1
    except Exception:
        pass

    return out


def _seed_identity_vault_demo() -> dict:
    """v9.35.1 #1 — three-tier identity-vault seed.

    Populates the IdentityVault with three fake-but-realistic
    connector records so /identity, /access, and the connector
    status strip show meaningful content on first run.

    Tiers:
      good    — Okta tenant, recent test pass, recent sync
      medium  — ClearPass, test passed but never synced
      broken  — AD with anonymous-bind misconfiguration mocked

    Trust property: the seed only writes records that PASSED a
    fake test_connection (test_passed=True). Real outbound calls
    do NOT happen during demo seeding.
    """
    out = {"good": False, "medium": False, "broken": False}
    try:
        from safecadence.identity.vault import IdentityVault
        v = IdentityVault()
        # Good tier — Okta with all the right knobs.
        try:
            v.save_creds(
                system="okta",
                target="acme-good.okta.com",
                credentials={"api_token": "DEMO-token-good-tier-do-not-use"},
                test_passed=True,
                actor="demo",
                notes="DEMO TIER=GOOD: MFA enforced, no stale users, "
                      "group-rule based access.",
            )
            v.mark_synced("okta")
            out["good"] = True
        except Exception:
            pass
        # Medium tier — ClearPass that's been connected but never synced.
        try:
            v.save_creds(
                system="clearpass",
                target="cp-medium.acme.demo",
                credentials={"client_id": "demo-medium",
                             "client_secret": "DEMO-secret-medium"},
                test_passed=True,
                actor="demo",
                notes="DEMO TIER=MEDIUM: connected but never synced; "
                      "expect stale data warning.",
            )
            # Intentionally do NOT mark_synced — operator sees an
            # un-synced connector and knows to click Sync.
            out["medium"] = True
        except Exception:
            pass
        # Broken tier — AD with deliberately misconfigured target.
        try:
            v.save_creds(
                system="ad",
                target="ldap://ad-broken.acme.demo",   # plain LDAP, no S
                credentials={"bind_dn": "CN=anon",
                             "bind_password": "DEMO-empty",
                             "base_dn": "DC=corp,DC=demo"},
                test_passed=True,
                actor="demo",
                notes="DEMO TIER=BROKEN: anonymous-bind allowed, "
                      "RC4 Kerberos still enabled, krbtgt last "
                      "rotated 2017. Use this row to demo finding "
                      "severity escalation.",
            )
            out["broken"] = True
        except Exception:
            pass
    except Exception:
        pass
    return out


def _seed_nhi_demo() -> dict:
    """v9.35.1 #1 — six demo NHIs across the lifecycle.

    The set is deliberate: covers each finding kind the stale-finder
    can produce (nhi_stale, nhi_rotation_overdue) plus the healthy
    case (well-attested + recently rotated) and the deprecated case
    (registered but excluded from findings)."""
    from datetime import datetime, timedelta, timezone
    out = {"created": 0}
    try:
        from safecadence.identity import nhi_store
    except Exception:
        return out
    now = datetime.now(timezone.utc)

    def _backdate(rec_id: str, *, last_used_days: int = -1,
                   last_rotated_days: int = -1,
                   created_days: int = 0,
                   deprecate: bool = False) -> None:
        rec = nhi_store.get(rec_id)
        if rec is None:
            return
        if last_used_days >= 0:
            rec.last_used_at = (now - timedelta(days=last_used_days)).isoformat()
        if last_rotated_days >= 0:
            rec.last_rotated_at = (now - timedelta(days=last_rotated_days)).isoformat()
        if created_days > 0:
            rec.created_at = (now - timedelta(days=created_days)).isoformat()
        if deprecate:
            rec.deprecated = True
        nhi_store._save(rec)

    # 1) GOOD tier — recently attested, recently rotated, owned.
    r = nhi_store.register(
        name="payroll-prod-svc", subtype="service_account",
        owner="alice@acme.demo", provider="okta",
        rotation_policy_days=90,
        notes="DEMO GOOD: rotated last week, owner attested 2 weeks ago.",
    )
    nhi_store.attest(r.nhi_id, by="alice@acme.demo")
    _backdate(r.nhi_id, last_used_days=2, last_rotated_days=7,
                created_days=400)
    out["created"] += 1

    # 2) GOOD tier — IAM role with active rotation discipline.
    r = nhi_store.register(
        name="prod-deploy-role", subtype="iam_role",
        owner="bob@acme.demo", provider="aws",
        rotation_policy_days=90,
        notes="DEMO GOOD: IAM role used daily; managed by deploy pipeline.",
    )
    _backdate(r.nhi_id, last_used_days=0, last_rotated_days=30,
                created_days=730)
    out["created"] += 1

    # 3) MEDIUM tier — rotation overdue (60 days past 90-day policy).
    r = nhi_store.register(
        name="ci-build-bot", subtype="oauth_client",
        owner="bob@acme.demo", provider="github",
        rotation_policy_days=90,
        notes="DEMO MEDIUM: rotation overdue 60 days — rotation hook "
              "should fire here.",
    )
    _backdate(r.nhi_id, last_used_days=1, last_rotated_days=150,
                created_days=900)
    out["created"] += 1

    # 4) MEDIUM tier — used recently but no owner, no rotation policy.
    r = nhi_store.register(
        name="legacy-snmp-poller", subtype="api_key",
        owner="",
        provider="custom",
        rotation_policy_days=0,
        notes="DEMO MEDIUM: no owner, no rotation policy — appears "
              "in /findings as policy violation.",
    )
    _backdate(r.nhi_id, last_used_days=10, created_days=400)
    out["created"] += 1

    # 5) BROKEN tier — stale 200+ days, never attested.
    r = nhi_store.register(
        name="nhi-legacy-importer", subtype="service_account",
        owner="(unknown)", provider="custom",
        rotation_policy_days=90,
        notes="DEMO BROKEN: unused 220 days, never rotated, no "
              "attestation. Stale-finder should flag this as HIGH "
              "severity.",
    )
    _backdate(r.nhi_id, last_used_days=220, created_days=900)
    out["created"] += 1

    # 6) DEPRECATED — registered but flagged for removal. Should NOT
    # appear in stale findings (it's already been triaged).
    r = nhi_store.register(
        name="nhi-deprecated-test",
        subtype="machine_cert", owner="alice@acme.demo",
        provider="custom",
        notes="DEMO DEPRECATED: marked for removal; should not "
              "produce findings.",
    )
    _backdate(r.nhi_id, last_used_days=400, created_days=600,
                deprecate=True)
    out["created"] += 1

    return out


def _seed_execution_demo(asset_ids: list[str]) -> dict:
    """v9.35.1 #1 — populate the Execute section with jobs in every
    lifecycle state so /queue, /approvals, /rollback, /per-device-diff
    aren't empty on first run.

    States covered:
      DRAFT      — operator hasn't submitted yet
      REVIEW     — pending approval (the approval-notification path)
      APPROVED   — approved but not executed (queue waiting)
      RUNNING    — currently executing (rare in demo, sets timestamp)
      DONE       — completed dry-run with synthetic outputs
      FAILED     — completed with errors (output has issues)
      ROLLED_BACK — rolled back; rollback plan is visible
    """
    out = {"jobs": 0, "executions": 0}
    try:
        from safecadence.execution import store as exec_store, workflow
        from safecadence.execution.schema import (
            CommandAuditLog, CommandExecution, CommandJob, CommandMode,
            CommandOutput, ExecutionMethod, JobStatus, RiskLevel,
        )
    except Exception:
        return out

    targets = list(asset_ids[:8]) or ["demo-router-01", "demo-fw-02"]
    common_cmds = {
        "cisco_ios": ["show version", "show running-config | include aaa"],
    }
    config_cmds = {
        "cisco_ios": [
            "configure terminal",
            "ntp server 10.0.0.10",
            "ntp server 10.0.0.11",
            "ip route 10.50.0.0 255.255.0.0 10.0.0.1",
            "end",
            "write memory",
        ],
    }

    def _save(job: CommandJob, *, audit_action: str) -> None:
        exec_store.save_job(job)
        try:
            exec_store.write_audit(CommandAuditLog(
                actor="demo", action=audit_action, job_id=job.job_id,
                detail=f"demo-seeded {job.status.value}",
            ))
        except Exception:
            pass
        out["jobs"] += 1

    # 1) DRAFT — operator drafted but didn't submit.
    j = CommandJob(
        job_id="demo-job-draft-001", name="DEMO: Diagnose BGP on edge",
        description="Operator started a job and walked away.",
        mode=CommandMode.DIAGNOSTIC, risk=RiskLevel.SAFE,
        status=JobStatus.DRAFT, target_asset_ids=targets[:2],
        inline_commands=common_cmds, method=ExecutionMethod.MANUAL,
    )
    _save(j, audit_action="demo_seed_draft")

    # 2) REVIEW — pending approval. CRITICAL risk so the multi-
    # approver gate is visible on /approvals.
    j = CommandJob(
        job_id="demo-job-review-002",
        name="DEMO: Add NTP servers across access tier",
        description="Configures two new NTP peers — needs approval.",
        mode=CommandMode.CONFIG, risk=RiskLevel.HIGH,
        status=JobStatus.REVIEW, target_asset_ids=targets[:5],
        inline_commands=config_cmds, method=ExecutionMethod.SSH,
        approvals_required=2,
    )
    _save(j, audit_action="demo_seed_review")
    try:
        # Also write the ApprovalRequest so /approvals shows it.
        from safecadence.execution.schema import ApprovalRequest
        req = ApprovalRequest(job_id=j.job_id, requested_by="alice@acme.demo")
        exec_store.save_approval(req)
    except Exception:
        pass

    # 3) APPROVED + rollback plan persisted. Pull-quote for /rollback.
    j = CommandJob(
        job_id="demo-job-approved-003",
        name="DEMO: Add static route to backup DC",
        description="Approved, awaiting execution window.",
        mode=CommandMode.CONFIG, risk=RiskLevel.MEDIUM,
        status=JobStatus.APPROVED, target_asset_ids=targets[:3],
        inline_commands={
            "cisco_ios": [
                "ip route 10.99.0.0 255.255.0.0 10.0.0.250",
                "logging host 10.99.0.5",
            ],
        },
        method=ExecutionMethod.SSH,
    )
    _save(j, audit_action="demo_seed_approved")
    # Generate rollback plan so /rollback has something to show.
    try:
        plan = workflow._generate_rollback_plan(j)
        exec_store.save_rollback(plan)
        j.rollback_plan_id = plan.plan_id
        exec_store.save_job(j)
    except Exception:
        pass

    # 4) DONE — dry-run with synthetic before/after snapshots so
    # /per-device-diff?job=… renders an actual diff.
    j = CommandJob(
        job_id="demo-job-done-004",
        name="DEMO: Tighten SSH timeout on core switches",
        description="Successfully applied (dry-run).",
        mode=CommandMode.CONFIG, risk=RiskLevel.MEDIUM,
        status=JobStatus.DONE, target_asset_ids=targets[:2],
        inline_commands={
            "cisco_ios": [
                "line vty 0 4",
                "exec-timeout 5 0",
                "transport input ssh",
            ],
        },
    )
    _save(j, audit_action="demo_seed_done")
    pre = ("line vty 0 4\n"
            " exec-timeout 30 0\n"
            " transport input ssh telnet\n")
    post = ("line vty 0 4\n"
             " exec-timeout 5 0\n"
             " transport input ssh\n")
    for aid in targets[:2]:
        try:
            ex = CommandExecution(
                job_id=j.job_id, asset_id=aid, vendor="cisco_ios",
                rendered_commands=list(j.inline_commands["cisco_ios"]),
                started_at=_ts(0), finished_at=_ts(0),
                status=JobStatus.DONE, dry_run=True,
                pre_config_snapshot=pre, post_config_snapshot=post,
            )
            exec_store.save_execution(ex)
            out["executions"] += 1
        except Exception:
            pass

    # 5) FAILED — visible error pattern in output.
    j = CommandJob(
        job_id="demo-job-failed-005",
        name="DEMO: Disable Telnet on legacy edge",
        description="Failed: % Invalid input on legacy IOS.",
        mode=CommandMode.CONFIG, risk=RiskLevel.HIGH,
        status=JobStatus.FAILED, target_asset_ids=[targets[0]],
        inline_commands={
            "cisco_ios": ["line vty 0 4", "no transport input telnet"],
        },
    )
    _save(j, audit_action="demo_seed_failed")
    try:
        ex = CommandExecution(
            job_id=j.job_id, asset_id=targets[0], vendor="cisco_ios",
            rendered_commands=list(j.inline_commands["cisco_ios"]),
            started_at=_ts(0), finished_at=_ts(0),
            status=JobStatus.FAILED, dry_run=False,
            error="% Invalid input detected at '^' marker.",
        )
        exec_store.save_execution(ex)
        out["executions"] += 1
    except Exception:
        pass

    # 6) ROLLED_BACK — operator pushed something, then rolled back.
    j = CommandJob(
        job_id="demo-job-rolled-006",
        name="DEMO: Pushed wrong VLAN, rolled back",
        description="Pushed VLAN 999 mistakenly, rolled back via plan.",
        mode=CommandMode.CONFIG, risk=RiskLevel.HIGH,
        status=JobStatus.ROLLED_BACK, target_asset_ids=targets[:2],
        inline_commands={
            "cisco_ios": ["vlan 999", "name PROD-WRONG"],
        },
    )
    _save(j, audit_action="demo_seed_rolled_back")
    try:
        plan = workflow._generate_rollback_plan(j)
        exec_store.save_rollback(plan)
        j.rollback_plan_id = plan.plan_id
        exec_store.save_job(j)
    except Exception:
        pass

    return out


def _summary_text(fleet: list[dict]) -> str:
    """One-line description so the UI can show what was loaded."""
    by_type: dict[str, int] = {}
    crown = 0
    kev = 0
    eos = 0
    for a in fleet:
        ident = a.get("identity") or {}
        t = ident.get("asset_type") or "unknown"
        by_type[t] = by_type.get(t, 0) + 1
        if (ident.get("criticality") or "").lower() == "crown-jewel":
            crown += 1
        sec = a.get("security") or {}
        kev += sec.get("kev_cves", 0)
        lc = a.get("lifecycle") or {}
        if (lc.get("days_until_eos") or 99999) <= 0:
            eos += 1
    parts = [f"{n} {t}" for t, n in sorted(by_type.items())]
    return (f"{len(fleet)} assets ({', '.join(parts)}); "
            f"{crown} crown-jewels, {kev} KEV CVEs, "
            f"{eos} past end-of-support — designed to surface "
            "policy violations + cross-system drift on first scan.")


def clear_demo_fleet(target_dir: Path | None = None) -> dict:
    """Remove demo assets only — leaves any real assets the user has loaded."""
    from safecadence.server.platform_api import _store_dir
    base = Path(target_dir) if target_dir else _store_dir()
    if not base.exists():
        return {"removed": 0, "target_dir": str(base)}
    demo_ids = {(a.get("identity") or {}).get("asset_id")
                for a in build_demo_fleet()}
    removed = 0
    for f in base.glob("*.json"):
        if f.stem in demo_ids:
            try:
                f.unlink()
                removed += 1
            except OSError:
                pass
    return {"removed": removed, "target_dir": str(base)}
