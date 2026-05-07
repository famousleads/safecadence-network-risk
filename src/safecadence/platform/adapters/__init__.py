"""
Vendor adapters — each subclasses BaseAdapter.

To add an adapter:
  1. Create a new file: src/safecadence/platform/adapters/<vendor>_<product>.py
  2. Subclass BaseAdapter and decorate with @register_adapter('your_name')
  3. Implement test_connection(), discover(), collect(), normalize()
  4. Document required credentials in capabilities.required_credentials
  5. Add to MVP_ADAPTERS list in this file when production-ready

Reference adapter:
  - dell_idrac.py — REST/Redfish, full implementation, can be used as a template

Stub adapters (skeleton only — community-buildable):
  - hpe_ilo.py            — Redfish (very similar to Dell iDRAC)
  - cisco_ucs.py          — UCS Manager XML API
  - vmware_vcenter.py     — pyvmomi or REST API
  - netapp_ontap.py       — REST API
  - aws_account.py        — boto3 SDK
  - azure_subscription.py — azure-sdk-for-python
"""

from __future__ import annotations

# Auto-register adapters by importing them
# v3.0 — foundation
from safecadence.platform.adapters import dell_idrac          # Dell PowerEdge via iDRAC Redfish
from safecadence.platform.adapters import hpe_ilo             # HPE ProLiant via iLO Redfish
from safecadence.platform.adapters import cisco_network       # Cisco IOS/IOS-XE/NX-OS/ASA via SSH
from safecadence.platform.adapters import vmware_vcenter      # vSphere REST API
from safecadence.platform.adapters import aws_account         # AWS via boto3
from safecadence.platform.adapters import netapp_ontap        # NetApp ONTAP REST

# v3.1 — multi-vendor expansion
from safecadence.platform.adapters import arista_eos          # Arista EOS via eAPI
from safecadence.platform.adapters import juniper_junos       # Juniper Junos REST/NETCONF
from safecadence.platform.adapters import fortinet_fortigate  # Fortinet FortiGate REST
from safecadence.platform.adapters import palo_alto_panos     # Palo Alto PAN-OS XML
from safecadence.platform.adapters import pure_storage        # Pure FlashArray REST
from safecadence.platform.adapters import cisco_ucs           # Cisco UCS Manager XML
from safecadence.platform.adapters import lenovo_xclarity     # Lenovo + Supermicro Redfish
from safecadence.platform.adapters import veeam               # Veeam Backup & Replication
from safecadence.platform.adapters import azure_subscription  # Azure SDK
from safecadence.platform.adapters import nutanix_prism       # Nutanix + Hyper-V
from safecadence.platform.adapters import more_adapters       # Aruba CX, Proxmox, GCP, Rubrik, Cohesity, Synology, K8s

# v3.2 / v4.0 — closes out the platform spec
from safecadence.platform.adapters import more_adapters_v2    # Brocade, ProCurve, IBM Power, Dell EMC Unity/PowerStore, HPE Primera/Nimble, IBM FlashSystem, Hitachi VSP, Citrix, OCI, Cloudflare, Commvault, NetBackup, Acronis

# v6.0 — Identity Intelligence Engine
from safecadence.platform.adapters import identity_adapters   # Cisco ISE, HPE ClearPass, Active Directory, Entra ID, Okta


MVP_ADAPTERS = [
    # Servers (6)
    "dell_idrac", "hpe_ilo", "lenovo_xclarity", "supermicro_ipmi", "cisco_ucs",
    "ibm_power_hmc",
    # Network (8)
    "cisco_network", "arista_eos", "juniper_junos", "fortinet_fortigate",
    "palo_alto_panos", "aruba_cx", "brocade_fos", "hpe_procurve",
    # Storage (9)
    "netapp_ontap", "pure_storage", "synology_dsm", "dell_emc_unity",
    "dell_emc_powerstore", "hpe_primera", "hpe_nimble", "ibm_flashsystem",
    "hitachi_vsp",
    # Virtualization (5)
    "vmware_vcenter", "nutanix_prism", "hyperv_host", "proxmox_ve",
    "citrix_hypervisor",
    # Cloud (6)
    "aws_account", "azure_subscription", "gcp_project", "kubernetes_cluster",
    "oci_tenancy", "cloudflare_zone",
    # Backup (6)
    "veeam_backup", "rubrik_cdm", "cohesity_cluster",
    "commvault_commcell", "veritas_netbackup", "acronis_cyber",
    # Identity (5) — v6.0
    "cisco_ise", "hpe_clearpass", "active_directory", "entra_id", "okta",
]

BETA_ADAPTERS: list[str] = [
    # Adapters that need additional real-hardware validation
    "cisco_ucs", "aruba_cx", "synology_dsm", "kubernetes_cluster", "gcp_project",
    "brocade_fos", "hpe_procurve", "ibm_power_hmc", "dell_emc_unity",
    "dell_emc_powerstore", "hpe_primera", "hpe_nimble", "ibm_flashsystem",
    "hitachi_vsp", "citrix_hypervisor", "oci_tenancy", "cloudflare_zone",
    "commvault_commcell", "veritas_netbackup", "acronis_cyber",
]
