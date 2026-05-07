#!/bin/bash
# Ship v4.0.0 — complete Device Intelligence Platform.
#   - 40 vendor adapters across 6 domains (was 25 in v3.1)
#   - /api/platform/* REST surface
#   - cross-domain correlation engine
#   - 10 platform-wide report types
#   - 6-tab platform UI dashboard
set -e
cd "$(dirname "$0")"

git add -A 2>/dev/null
if ! git diff --cached --quiet; then
  git commit -m "feat: v4.0.0 — complete Device Intelligence Platform

Closes out the multi-vendor platform spec end-to-end:

ADAPTERS — 40 total across 6 domains (was 25 in v3.1):
  Network (8):       cisco_network, arista_eos, juniper_junos,
                     fortinet_fortigate, palo_alto_panos, aruba_cx,
                     brocade_fos, hpe_procurve
  Servers (6):       dell_idrac, hpe_ilo, lenovo_xclarity,
                     supermicro_ipmi, cisco_ucs, ibm_power_hmc
  Storage (9):       netapp_ontap, pure_storage, synology_dsm,
                     dell_emc_unity, dell_emc_powerstore, hpe_primera,
                     hpe_nimble, ibm_flashsystem, hitachi_vsp
  Virtualization (5): vmware_vcenter, nutanix_prism, hyperv_host,
                     proxmox_ve, citrix_hypervisor
  Cloud (6):         aws_account, azure_subscription, gcp_project,
                     kubernetes_cluster, oci_tenancy, cloudflare_zone
  Backup (6):        veeam_backup, rubrik_cdm, cohesity_cluster,
                     commvault_commcell, veritas_netbackup, acronis_cyber

PLATFORM API (/api/platform/*):
  /inventory, /asset/{id}, /servers, /storage, /virtualization,
  /network, /cloud, /backup, /health, /lifecycle,
  /correlate/{id}, /correlate/orphans,
  /reports, /reports/{id}, /ui

CORRELATION ENGINE (safecadence.platform.correlation):
  - build_dependency_chain — VM->host->datastore->array->backup
  - find_orphans           — assets at risk of orphaning
  - find_toxic_combinations — cross-domain risk detection

REPORTS (safecadence.reports.platform_reports):
  lifecycle, security_posture, capacity, backup_compliance,
  vendor_inventory, eol_eos, health_summary, risk_register,
  cloud_exposure, executive_overview

UI (/api/platform/ui):
  Single-file HTML dashboard with 9 tabs (Overview, Inventory,
  Servers, Storage, Virtualization, Network, Cloud, Backup, Reports).
  Vanilla JS + bearer-token auth, no build step.

Each adapter follows the BaseAdapter pattern. Vendor-specific code is
grounded in published API documentation. Community contributors validate
against real hardware via the contribute-an-adapter pattern in
docs/PLATFORM_ARCHITECTURE.md."
  git push origin main
fi

git tag -a v4.0.0 -m "v4.0.0 — complete Device Intelligence Platform (40 adapters, API, correlation, reports, UI)" 2>/dev/null || true
git push origin v4.0.0 2>/dev/null || true

mkdir -p dist/old && mv dist/safecadence_netrisk-3.* dist/old/ 2>/dev/null || true
if [[ -x .venv/bin/python ]]; then
  .venv/bin/python -m build
else
  python3 -m build
fi

echo ""; echo "Paste your PyPI token..."
LAST=""; GOT=""
for i in $(seq 1 180); do
  CLIP=$(pbpaste 2>/dev/null)
  PREVIEW=$(printf '%s' "$CLIP" | head -c 12)
  if [[ "$PREVIEW" != "$LAST" ]]; then echo "  [${i}s] '${PREVIEW}...'"; LAST="$PREVIEW"; fi
  if [[ "$CLIP" == pypi-AgEI* ]] && [[ ${#CLIP} -gt 100 ]]; then GOT="$CLIP"; break; fi
  sleep 1
done
[[ -z "$GOT" ]] && { echo "Timeout"; exit 1; }

if [[ -x .venv/bin/python ]]; then
  TWINE_USERNAME=__token__ TWINE_PASSWORD="$GOT" \
    .venv/bin/python -m twine upload dist/safecadence_netrisk-4.0.0*
else
  TWINE_USERNAME=__token__ TWINE_PASSWORD="$GOT" \
    python3 -m twine upload dist/safecadence_netrisk-4.0.0*
fi

if command -v gh &>/dev/null; then
  gh release create v4.0.0 \
    --title "v4.0.0 — Complete Device Intelligence Platform" \
    --notes "**v4.0.0** is the major release that closes out the SafeCadence Device Intelligence Platform spec end-to-end.

## What's new

**40 vendor adapters across 6 infrastructure domains** (up from 25 in v3.1):
- Network (8): cisco_network, arista_eos, juniper_junos, fortinet_fortigate, palo_alto_panos, aruba_cx, **brocade_fos**, **hpe_procurve**
- Servers (6): dell_idrac, hpe_ilo, lenovo_xclarity, supermicro_ipmi, cisco_ucs, **ibm_power_hmc**
- Storage (9): netapp_ontap, pure_storage, synology_dsm, **dell_emc_unity**, **dell_emc_powerstore**, **hpe_primera**, **hpe_nimble**, **ibm_flashsystem**, **hitachi_vsp**
- Virtualization (5): vmware_vcenter, nutanix_prism, hyperv_host, proxmox_ve, **citrix_hypervisor**
- Cloud (6): aws_account, azure_subscription, gcp_project, kubernetes_cluster, **oci_tenancy**, **cloudflare_zone**
- Backup (6): veeam_backup, rubrik_cdm, cohesity_cluster, **commvault_commcell**, **veritas_netbackup**, **acronis_cyber**

**Platform REST surface** at \`/api/platform/*\` — inventory, per-domain views, health, lifecycle, correlation, reports, UI.

**Cross-domain correlation engine** — walks VM → host → datastore → array → backup chains, surfaces orphans, detects toxic combinations.

**10 platform-wide reports** — lifecycle, security posture, capacity, backup compliance, vendor inventory, EOL/EOS, health summary, risk register, cloud exposure, executive overview.

**Self-contained platform UI** at \`/api/platform/ui\` — 9-tab dashboard (Overview / Inventory / Servers / Storage / Virtualization / Network / Cloud / Backup / Reports).

## Install

\`pip install --upgrade safecadence-netrisk\`

Run the local UI: \`safecadence ui\`, then visit \`/api/platform/ui\` in your browser.

## Validation model

Each adapter is grounded in vendor's published API documentation. The platform is open-source so community contributors can validate against real hardware and PR fixes back — see \`docs/PLATFORM_ARCHITECTURE.md\` for the contribute-an-adapter guide." \
    dist/safecadence_netrisk-4.0.0-py3-none-any.whl \
    dist/safecadence_netrisk-4.0.0.tar.gz
fi

echo ""
echo "============================================================"
echo " v4.0.0 SHIPPED — Complete Device Intelligence Platform"
echo "  - 40 vendor adapters across 6 domains"
echo "  - /api/platform/* REST surface"
echo "  - correlation engine + 10 reports + 6-tab UI"
echo "============================================================"
