"""Truthful adapter manifest — what actually works vs what's a skeleton.

For v6.3 we walked every adapter file and classified honestly:

  - "production"   — full implementation, has been exercised against
                     a real device or a high-fidelity fixture, returns
                     a populated UnifiedAsset
  - "experimental" — implementation exists, parses real responses, but
                     has not been validated against every product
                     variant a vendor ships
  - "stub"         — class skeleton + minimal `discover()` returning
                     placeholder data; useful as a starting point for
                     a community contributor, not a working adapter

The marketing claim "45 adapters" was materially misleading because it
counted every stub. The honest number is below. We surface this manifest
in two places:

  - /api/platform/adapter-manifest        — JSON for the UI's overview
  - `safecadence list-adapters` (CLI)      — for operators sizing scope

When an operator actually wires an adapter and validates it, we promote
it from experimental → production by editing this file. No silent
upgrades from "passes pytest" to "production" — promotion is human-gated.
"""

from __future__ import annotations


# Production-ready: full implementation, real-system-validated.
PRODUCTION_ADAPTERS = {
    # Network — vendor SSH-screen-scraping is well-tested
    "cisco_ios":          "Cisco IOS / IOS-XE — SSH show-running parser",
    "cisco_nxos":         "Cisco NX-OS — SSH show-running parser",
    "cisco_asa":          "Cisco ASA — SSH show-run parser",
    "arista_eos":         "Arista EOS — SSH + eAPI",
    "juniper_junos":      "Juniper Junos — SSH show-config | display set",
    "fortinet_fortigate": "Fortinet FortiGate — SSH show full-configuration",
    "palo_alto_panos":    "Palo Alto PAN-OS — XML API config dump",

    # Servers
    "linux_server":       "Linux — SSH + sysctl/systemd inspection",

    # Cloud (read-only roles)
    "aws_account":        "AWS Account — boto3 read-only inventory",

    # Identity
    "active_directory":   "Active Directory — LDAP query of users/groups",
}

# Experimental: implementation exists, returns useful data, but coverage
# of vendor-specific edge cases hasn't been validated end-to-end.
EXPERIMENTAL_ADAPTERS = {
    "windows_server":     "Windows Server — WinRM PowerShell remoting",
    "vmware_esxi":        "VMware ESXi — esxcli over SSH",
    "vmware_vcenter":     "vCenter — REST API",
    "azure_subscription": "Azure — azure-sdk-for-python read-only",
    "dell_idrac":         "Dell iDRAC — Redfish (reference adapter)",
    "hpe_ilo":            "HPE iLO — Redfish",
    "veeam":              "Veeam B&R — REST API",
    "netapp_ontap":       "NetApp ONTAP — REST API",
    "okta":               "Okta — Users/Groups REST API",
    "entra_id":           "Microsoft Entra ID — Graph API",
    "cisco_ise":          "Cisco ISE — ERS API",
    "hpe_clearpass":      "HPE ClearPass — REST API",
    # v6.4.3 — promoted from stub: code review showed real REST
    # implementation (login + GET endpoints), not skeleton.
    "pure_storage":       "Pure FlashArray REST",
    "nutanix_prism":      "Nutanix Prism — REST",
    "proxmox_ve":         "Proxmox VE — REST",
    "rubrik_cdm":         "Rubrik CDM — REST",
}

# Stubs: skeleton class only, returns placeholder data. Listed here so
# users can see them coming, not so we can pad the count.
STUB_ADAPTERS = {
    # v6.4.3 — demoted from experimental: collect() returns {} hardcoded.
    # The audit caught these: marketing them as 'experimental' was lying.
    "aruba_cx":           "Aruba CX — collect() returns {} (stub)",
    "gcp_cloud":          "GCP — collect() returns {} (stub)",
    "cisco_ucs":          "Cisco UCS — XML POST broken (stub)",
    "lenovo_xclarity":    "Lenovo XClarity Redfish",
    "supermicro_ipmi":    "Supermicro IPMI",
    "ibm_power_hmc":      "IBM Power HMC",
    "brocade_fos":        "Brocade FabricOS",
    "hpe_procurve":       "HPE ProCurve",
    "synology_dsm":       "Synology DSM",
    "dell_emc_unity":     "Dell EMC Unity",
    "dell_emc_powerstore": "Dell EMC PowerStore",
    "hpe_primera":        "HPE Primera / 3PAR",
    "hpe_nimble":         "HPE Nimble",
    "ibm_flashsystem":    "IBM FlashSystem",
    "hitachi_vsp":        "Hitachi VSP",
    "hyperv_host":        "Microsoft Hyper-V",
    "citrix_hypervisor":  "Citrix Hypervisor (XenServer)",
    "kubernetes_cluster": "Kubernetes (kubeconfig)",
    "oci_tenancy":        "Oracle Cloud Infrastructure",
    "cloudflare_zone":    "Cloudflare zones / WAF",
    "cohesity_cluster":   "Cohesity",
    "commvault_commcell": "Commvault CommCell",
    "veritas_netbackup":  "Veritas NetBackup",
    "acronis_cyber":      "Acronis Cyber Protect",
}


def manifest() -> dict:
    """Aggregated, machine-readable view of every adapter we ship."""
    rows: list[dict] = []
    for name, desc in PRODUCTION_ADAPTERS.items():
        rows.append({"name": name, "status": "production",
                     "description": desc})
    for name, desc in EXPERIMENTAL_ADAPTERS.items():
        rows.append({"name": name, "status": "experimental",
                     "description": desc})
    for name, desc in STUB_ADAPTERS.items():
        rows.append({"name": name, "status": "stub",
                     "description": desc})
    return {
        "production_count": len(PRODUCTION_ADAPTERS),
        "experimental_count": len(EXPERIMENTAL_ADAPTERS),
        "stub_count": len(STUB_ADAPTERS),
        "total": len(PRODUCTION_ADAPTERS) + len(EXPERIMENTAL_ADAPTERS) + len(STUB_ADAPTERS),
        "adapters": sorted(rows, key=lambda r: (
            {"production": 0, "experimental": 1, "stub": 2}[r["status"]],
            r["name"],
        )),
        "tagline": (
            f"{len(PRODUCTION_ADAPTERS)} production adapters, "
            f"{len(EXPERIMENTAL_ADAPTERS)} experimental, "
            f"{len(STUB_ADAPTERS)} stub. "
            "Marketing-count of 45 was inflated; this is the truthful "
            "view operators see when sizing a deployment."
        ),
    }
