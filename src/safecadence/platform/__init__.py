"""
SafeCadence Device Intelligence Platform — multi-vendor inventory + audit framework.

Extends safecadence-netrisk from a network-only audit tool into a full
enterprise infrastructure platform covering:

  - Network gear (existing)
  - Servers (Dell iDRAC, HPE iLO, Cisco UCS, Lenovo XClarity, Supermicro IPMI)
  - Storage (NetApp ONTAP, Pure, Dell EMC, HPE, IBM, Synology, QNAP)
  - Virtualization (VMware vCenter, Hyper-V, Nutanix, Proxmox, Citrix)
  - Cloud (AWS, Azure, GCP, OCI, Cloudflare, Kubernetes)
  - Backup (Veeam, Commvault, Rubrik, Cohesity, NetBackup, Acronis)

Architecture:

  ┌────────────────────────────────────────────────────────────┐
  │                    SafeCadence Platform                    │
  ├────────────────────────────────────────────────────────────┤
  │  Frontend (existing UI tabs, extended for multi-vendor)    │
  ├────────────────────────────────────────────────────────────┤
  │              FastAPI Backend (existing)                    │
  ├────────────────────────────────────────────────────────────┤
  │           Adapter Framework  ←  THIS MODULE                │
  │  ┌──────────────────────────────────────────────────┐      │
  │  │  BaseAdapter ⇄ ConnectionManager ⇄ Vault         │      │
  │  └──────────────────────────────────────────────────┘      │
  ├────────────────────────────────────────────────────────────┤
  │   network_*  server_*  storage_*  virt_*  cloud_*  backup_*│
  │   adapters    adapters  adapters   adapters adapters adapters│
  ├────────────────────────────────────────────────────────────┤
  │      Normalization → Unified Schema → SQLite/Postgres      │
  ├────────────────────────────────────────────────────────────┤
  │   Correlation engine  AI engine  Health scoring  Reports   │
  └────────────────────────────────────────────────────────────┘

Each adapter is a Python class that subclasses BaseAdapter and implements:
  - connect()
  - discover()
  - collect()
  - normalize()  →  returns a UnifiedAsset

UnifiedAsset is the lingua franca — every adapter normalizes to it.
Reports, correlation, AI all operate on UnifiedAsset objects regardless
of original vendor.
"""

from __future__ import annotations

__all__ = [
    "BaseAdapter",
    "AdapterCapabilities",
    "ConnectionType",
    "UnifiedAsset",
    "AssetIdentity",
    "Hardware",
    "OperatingSystem",
    "Storage",
    "Virtualization",
    "Cloud",
    "Backup",
    "Security",
    "Lifecycle",
    "HealthScores",
    "ConnectionManager",
    "PlatformVault",
    "score_asset_health",
    "register_adapter",
    "get_adapter",
    "list_adapters",
]

from safecadence.platform.schema import (
    UnifiedAsset,
    AssetIdentity,
    Hardware,
    OperatingSystem,
    Storage,
    Virtualization,
    Cloud,
    Backup,
    Security,
    Lifecycle,
    HealthScores,
)
from safecadence.platform.adapter_base import (
    BaseAdapter,
    AdapterCapabilities,
    ConnectionType,
    register_adapter,
    get_adapter,
    list_adapters,
)
from safecadence.platform.connection_manager import ConnectionManager
from safecadence.platform.credential_vault import PlatformVault
from safecadence.platform.health_scoring import score_asset_health
