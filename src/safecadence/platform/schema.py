"""
Unified normalized schema — the lingua franca every adapter outputs.

Every vendor's wildly-different data (SNMP MIBs, Redfish JSON, vSphere SOAP,
NetApp REST, AWS API responses) gets parsed into the same UnifiedAsset
dataclass. Reports, correlation, AI, health scoring all operate on
UnifiedAsset objects without caring about vendor.

Designed to handle ALL asset types with optional sub-objects:
  - A network switch fills: identity, hardware, os, security, lifecycle
  - A server fills:          identity, hardware, os, security, lifecycle
  - A storage array fills:   identity, hardware, storage, security, lifecycle
  - A hypervisor fills:      identity, hardware, os, virtualization
  - An EC2 instance fills:   identity, cloud, security
  - A backup target fills:   identity, backup, security
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class AssetIdentity:
    """Universal identity for any asset, regardless of type."""
    asset_id: str = ""                 # globally-unique within installation
    hostname: str = ""
    vendor: str = ""                   # cisco, dell, vmware, aws, ...
    product_family: str = ""           # ios, idrac, vsphere, ec2, ...
    model: str = ""
    serial_number: str = ""
    chassis_serial_number: str = ""
    asset_type: str = ""               # network | server | storage | hypervisor | cloud | backup
    location: str = ""
    site: str = ""
    rack: str = ""
    datacenter: str = ""
    environment: str = ""              # prod | staging | dev | test | dr
    owner: str = ""                    # email
    team: str = ""                     # operating team name (v7.0)
    criticality: str = "medium"        # low | medium | high | crown-jewel
    tags: list[str] = field(default_factory=list)            # operator-set tags
    custom_fields: dict[str, Any] = field(default_factory=dict)
    discovered_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_collected_at: str = ""
    discovery_source: str = ""         # how we know about this asset:
                                        # discovery | csv-import | manual | adapter | api


@dataclass
class Hardware:
    """Physical hardware details — applies to servers, switches, storage controllers."""
    chassis_pid: str = ""
    chassis_vid: str = ""              # version ID
    cpu_model: str = ""
    cpu_count: int = 0
    cores_per_cpu: int = 0
    threads_per_core: int = 0
    cpu_speed_mhz: int = 0
    memory_total_mb: int = 0
    memory_used_mb: int = 0
    disk_count: int = 0
    disk_total_gb: int = 0
    disk_type: str = ""                # ssd | nvme | hdd | mixed
    raid_status: str = ""              # ok | degraded | failed
    firmware_version: str = ""
    bios_version: str = ""
    bmc_version: str = ""              # iDRAC/iLO/CIMC/IPMI version
    power_supplies: list[dict] = field(default_factory=list)  # [{slot, status, watts}]
    fans: list[dict] = field(default_factory=list)            # [{slot, status, rpm}]
    temperatures: list[dict] = field(default_factory=list)    # [{sensor, celsius, status}]
    modules: list[dict] = field(default_factory=list)         # for switches: line cards
    transceivers: list[dict] = field(default_factory=list)    # SFPs / QSFPs


@dataclass
class OperatingSystem:
    """OS-level info."""
    os_type: str = ""                  # ios | ios-xe | nxos | linux | windows | esxi | ontap
    os_version: str = ""
    kernel_version: str = ""
    boot_image: str = ""
    config_register: str = ""          # Cisco-specific
    uptime_seconds: int = 0
    patch_level: str = ""
    last_reboot: str = ""
    running_services: list[str] = field(default_factory=list)
    enabled_services: list[str] = field(default_factory=list)
    installed_packages: list[dict] = field(default_factory=list)


@dataclass
class Interface:
    """A single network interface."""
    name: str = ""
    status: str = ""                   # up | down | admin-down
    protocol_status: str = ""
    ip_address: str = ""
    netmask: str = ""
    mac_address: str = ""
    speed_mbps: int = 0
    duplex: str = ""
    mtu: int = 0
    vlan: str = ""
    description: str = ""
    errors_in: int = 0
    errors_out: int = 0
    crc_errors: int = 0


@dataclass
class Storage:
    """Storage system (array) details OR per-server local storage summary."""
    total_capacity_tb: float = 0
    used_capacity_tb: float = 0
    free_capacity_tb: float = 0
    pools: list[dict] = field(default_factory=list)            # [{name, total, used, free, raid_level}]
    volumes: list[dict] = field(default_factory=list)          # [{name, size, protocol, attached_hosts}]
    luns: list[dict] = field(default_factory=list)
    snapshots: list[dict] = field(default_factory=list)
    replication_status: str = ""                                # ok | degraded | broken | none
    replication_partners: list[str] = field(default_factory=list)
    dedupe_ratio: float = 0
    compression_ratio: float = 0


@dataclass
class Virtualization:
    """Hypervisor cluster + VM info."""
    hypervisor_type: str = ""          # esxi | hyper-v | ahv | proxmox | xen
    hypervisor_version: str = ""
    cluster_name: str = ""
    host_count: int = 0
    vm_count: int = 0
    vm_powered_on: int = 0
    vm_powered_off: int = 0
    datastores: list[dict] = field(default_factory=list)       # [{name, total, used, type}]
    networks: list[dict] = field(default_factory=list)
    drs_enabled: bool = False
    ha_enabled: bool = False
    vms: list[dict] = field(default_factory=list)              # [{name, cpu, memory, datastore, host}]


@dataclass
class Cloud:
    """Cloud-specific resource fields."""
    provider: str = ""                 # aws | azure | gcp | oci
    account_id: str = ""               # AWS account / Azure subscription / GCP project
    region: str = ""
    availability_zone: str = ""
    instance_id: str = ""
    instance_type: str = ""
    image_id: str = ""                 # AMI / image
    vpc_id: str = ""
    subnet_id: str = ""
    security_groups: list[dict] = field(default_factory=list)
    iam_role: str = ""
    tags: dict[str, str] = field(default_factory=dict)
    public_exposure: bool = False
    public_ip: str = ""


@dataclass
class Backup:
    """Backup state for a backup-managed asset."""
    platform: str = ""                 # veeam | commvault | rubrik | cohesity | netbackup
    last_backup_status: str = ""       # success | warning | failed | never
    last_backup_at: str = ""
    last_successful_backup_at: str = ""
    failed_jobs_24h: int = 0
    retention_policy: str = ""
    retention_days: int = 0
    rpo_target_hours: int = 0
    actual_rpo_hours: int = 0          # how stale is the latest backup
    backup_size_gb: float = 0
    immutability_enabled: bool = False
    air_gapped: bool = False


@dataclass
class Security:
    """Security findings — populated by audit + CVE matching + active probing."""
    vulnerabilities: list[dict] = field(default_factory=list)  # [{cve_id, severity, kev, cvss, ...}]
    critical_cves: int = 0
    high_cves: int = 0
    kev_cves: int = 0                  # CISA KEV-listed
    exposed_services: list[dict] = field(default_factory=list) # [{port, protocol, service, public}]
    weak_protocols: list[str] = field(default_factory=list)    # [telnet, ftp, smb1, sslv3, ...]
    missing_patches: list[str] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)          # human-readable
    recommended_actions: list[str] = field(default_factory=list)
    toxic_combinations: list[dict] = field(default_factory=list)


@dataclass
class Identity:
    """v6.0 — identity / NAC / directory data normalized across providers.

    Populated by the v6 identity adapters (ISE, ClearPass, AD/LDAP,
    Entra ID, Okta). One UnifiedAsset can carry both 'platform' state
    (e.g. a switch's config) AND identity context (which AD users / NAC
    groups have access to it).
    """
    provider: str = ""                         # cisco-ise | clearpass | ad | entra | okta | ldap
    tenant_id: str = ""                        # AD domain / Okta org / Azure tenant
    user_count: int = 0
    group_count: int = 0
    privileged_user_count: int = 0
    nac_enrollment_status: str = ""            # quarantine | profiled | unknown | not-enrolled
    posture_score: int = 0                     # 0..100 (NAC posture compliance)
    last_authn_at: str = ""
    authorized_users: list[str] = field(default_factory=list)
    authorized_groups: list[str] = field(default_factory=list)
    authorized_roles: list[str] = field(default_factory=list)
    active_authz_rule: str = ""                # ISE/ClearPass rule applied
    active_enforcement_profile: str = ""
    privileged_accounts: list[dict] = field(default_factory=list)
    mfa_enrolled: bool = False
    mfa_methods: list[str] = field(default_factory=list)


@dataclass
class NonHumanIdentity:
    """v7.5 — first-class non-human identity.

    Service accounts, AWS IAM roles, Azure managed identities, K8s
    service accounts, OAuth client credentials, machine certs, API keys.
    These show up in the unified asset graph as standalone assets so
    drift detectors, attack-path scoring, and effective-permission
    lookups can include them in reasoning.
    """
    nhi_id: str = ""                  # globally-unique within installation
    subtype: str = ""                 # service_account | managed_identity | iam_role
                                       # | k8s_sa | oauth_client | machine_cert | api_key
    display_name: str = ""
    owner_principal: str = ""         # human or NHI that owns/created this
    provider: str = ""                # aws | azure | gcp | k8s | github | okta | ad | entra
    created_at: str = ""
    last_used_at: str = ""
    last_rotated_at: str = ""
    expires_at: str = ""
    rotation_policy_days: int = 0
    credential_type: str = ""         # password | client_secret | private_key | jwt | x509
    effective_scopes: list[str] = field(default_factory=list)
    can_impersonate: list[str] = field(default_factory=list)   # principal IDs
    risk_findings: list[str] = field(default_factory=list)     # stale, over-privileged, etc.


@dataclass
class Lifecycle:
    """Hardware/software EOL/EOS + warranty."""
    purchase_date: str = ""
    warranty_status: str = ""          # active | expired | unknown
    warranty_expires: str = ""
    eol_status: str = ""               # supported | last-day-of-support | end-of-software | end-of-support
    eol_date: str = ""                 # end-of-software date
    eos_date: str = ""                 # end-of-support date
    days_until_eos: int = 0
    replacement_recommended: bool = False
    replacement_part: str = ""


@dataclass
class HealthScores:
    """Multi-dimensional scoring — each 0-100, higher is better."""
    hardware_health: int = 100         # power/fans/temp/RAID
    security_health: int = 100         # vulns + exposed services
    lifecycle_health: int = 100        # EOL/EOS / warranty
    operational_health: int = 100      # uptime / errors / load
    overall_score: int = 100           # weighted composite
    grade: str = "A"                   # A | B | C | D | F
    risk_band: str = "safe"            # safe | low | medium | high | critical


@dataclass
class License:
    """v9.1 — software / subscription licensing on the device.
    Populated from `show license summary` (Cisco) or vendor equivalents."""
    license_type: str = ""              # smart | classic | reservation
    license_level: str = ""             # essentials | advantage | dna | premier
    license_status: str = ""            # active | expired | grace | trial
    smart_license_enabled: bool = False
    license_expiry_date: str = ""       # ISO date
    licensed_features: list[str] = field(default_factory=list)
    seats_total: int = 0
    seats_used: int = 0


@dataclass
class SystemResources:
    """v9.1 — live CPU + memory state. Populated from
    `show processes cpu`, `show memory`, /proc, vendor APIs."""
    cpu_utilization_percent: float = 0.0
    cpu_5sec: float = 0.0
    cpu_1min: float = 0.0
    cpu_5min: float = 0.0
    memory_total_bytes: int = 0
    memory_used_bytes: int = 0
    memory_free_bytes: int = 0
    memory_utilization_percent: float = 0.0
    swap_total_bytes: int = 0
    swap_used_bytes: int = 0


@dataclass
class Routing:
    """v9.1 — Layer-3 forwarding state from `show ip route` and friends."""
    routing_table_size: int = 0
    default_gateway: str = ""
    static_routes_count: int = 0
    connected_routes_count: int = 0
    ospf_routes_count: int = 0
    bgp_routes_count: int = 0
    eigrp_routes_count: int = 0
    rip_routes_count: int = 0


@dataclass
class L2Tables:
    """v9.1 — Layer-2 tables from `show arp`, `show mac address-table`."""
    arp_entries_count: int = 0
    mac_table_entries_count: int = 0
    sample_mac_entries: list[dict] = field(default_factory=list)
    # [{"mac": "...", "vlan_id": 10, "interface": "Gi0/1"}, ...]


@dataclass
class NetworkSecurity:
    """v9.1 — control-plane security posture. AAA / SSH / Telnet /
    HTTP / ACL / open ports / VPN tunnels. Distinct from the broader
    `Security` block which covers vuln/CVE state."""
    aaa_enabled: bool = False
    ssh_enabled: bool = True
    telnet_enabled: bool = False
    http_server_enabled: bool = False
    https_server_enabled: bool = False
    snmp_v1_enabled: bool = False
    snmp_v2c_enabled: bool = False
    snmp_v3_enabled: bool = True
    number_of_local_users: int = 0
    password_encryption_enabled: bool = True
    acl_count: int = 0
    open_ports: list[int] = field(default_factory=list)
    vpn_tunnels_active: int = 0
    weak_default_creds_present: bool = False


@dataclass
class RoutingProtocols:
    """v9.1 — which dynamic routing protocols are configured + neighbor counts."""
    ospf_enabled: bool = False
    ospf_neighbor_count: int = 0
    ospf_areas: list[str] = field(default_factory=list)
    bgp_enabled: bool = False
    bgp_neighbor_count: int = 0
    bgp_asn: int = 0
    eigrp_enabled: bool = False
    eigrp_neighbor_count: int = 0
    rip_enabled: bool = False
    is_is_enabled: bool = False
    routing_protocols_configured: list[str] = field(default_factory=list)


@dataclass
class SystemLogging:
    """v9.1 — clock + NTP + syslog + log buffer."""
    system_time: str = ""
    timezone: str = ""
    ntp_status: str = ""                # synced | unsynced | stratum-N
    ntp_servers: list[str] = field(default_factory=list)
    syslog_servers: list[str] = field(default_factory=list)
    log_buffer_size_bytes: int = 0
    critical_log_count: int = 0
    error_log_count: int = 0
    warning_log_count: int = 0
    last_log_message: str = ""


@dataclass
class VoiceUC:
    """v9.1 — voice / unified communications state (CUCM / CUBE / SIP gw)."""
    active_calls: int = 0
    sip_status: str = ""                # registered | unregistered | partial
    registered_endpoints: int = 0
    dial_peers_count: int = 0
    rtp_sessions: int = 0
    codec_usage: dict[str, int] = field(default_factory=dict)
    # {"G711": 12, "G729": 4, "OPUS": 0}
    sip_trunk_count: int = 0


@dataclass
class ComplianceSignals:
    """v9.1 — AI-generated risk signals derived from config + version
    + CVE feed + best-practice checks."""
    eos_status: str = ""                # supported | last-day-of-support | end-of-software | end-of-support
    eol_status: str = ""                # active | announced | passed
    known_cves: list[str] = field(default_factory=list)
    weak_config_detected: bool = False
    weak_config_findings: list[str] = field(default_factory=list)
    missing_best_practices: list[str] = field(default_factory=list)
    config_drift_detected: bool = False
    drift_summary: str = ""
    risk_score_0_100: int = 0


@dataclass
class UnifiedAsset:
    """The single source of truth for any infrastructure asset.

    Adapters fill in only the sub-objects relevant to their asset type.
    Downstream consumers (reports, correlation, AI) read whichever
    sub-objects are populated.
    """
    identity: AssetIdentity = field(default_factory=AssetIdentity)
    hardware: Hardware = field(default_factory=Hardware)
    os: OperatingSystem = field(default_factory=OperatingSystem)
    interfaces: list[Interface] = field(default_factory=list)
    storage: Storage = field(default_factory=Storage)
    virtualization: Virtualization = field(default_factory=Virtualization)
    cloud: Cloud = field(default_factory=Cloud)
    backup: Backup = field(default_factory=Backup)
    security: Security = field(default_factory=Security)
    lifecycle: Lifecycle = field(default_factory=Lifecycle)
    identity_block: Identity = field(default_factory=Identity)   # v6.0 — NAC / directory
    nhi: NonHumanIdentity = field(default_factory=NonHumanIdentity)  # v7.5 — non-human identity
    health: HealthScores = field(default_factory=HealthScores)

    # v9.1 — richer device fact sheet (license, routing, security flags,
    # logging, voice, AI compliance signals)
    license: License = field(default_factory=License)
    system_resources: SystemResources = field(default_factory=SystemResources)
    routing: Routing = field(default_factory=Routing)
    l2_tables: L2Tables = field(default_factory=L2Tables)
    network_security: NetworkSecurity = field(default_factory=NetworkSecurity)
    routing_protocols: RoutingProtocols = field(default_factory=RoutingProtocols)
    system_logging: SystemLogging = field(default_factory=SystemLogging)
    voice_uc: VoiceUC = field(default_factory=VoiceUC)
    compliance_signals: ComplianceSignals = field(default_factory=ComplianceSignals)

    # Relationships — populated by the correlation engine
    relationships: list[dict] = field(default_factory=list)
    # Examples:
    #   {"type": "hosts", "target": "vcenter-01.acme/host-01/vm-prod-db-01"}
    #   {"type": "consumes_storage", "target": "netapp-01:vol01"}
    #   {"type": "backed_up_by", "target": "veeam-01:job-prod-db-daily"}
    #   {"type": "located_in", "target": "rack-A12-DC1"}

    raw_collection: dict[str, Any] = field(default_factory=dict)
    # Adapter dumps the raw vendor response here for debugging / re-parsing.

    def to_dict(self) -> dict:
        from dataclasses import asdict
        return asdict(self)
