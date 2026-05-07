#!/bin/bash
# Ship v3.1.0 — 19 additional vendor adapters across all 6 domains.
set -e
cd "$(dirname "$0")"

git add -A 2>/dev/null
if ! git diff --cached --quiet; then
  git commit -m "feat: v3.1.0 — 19 additional vendor adapters (25 total)

Expands the platform from 6 reference adapters to 25 across all 6
infrastructure domains:

NETWORK:
  - arista_eos          (eAPI JSON-RPC)
  - juniper_junos       (REST + NETCONF)
  - fortinet_fortigate  (FortiOS REST API)
  - palo_alto_panos     (PAN-OS XML API)
  - aruba_cx            (REST API)

SERVERS:
  - cisco_ucs           (UCS Manager XML API)
  - lenovo_xclarity     (Redfish — extends Dell)
  - supermicro_ipmi     (Redfish — extends Dell)

STORAGE:
  - pure_storage        (FlashArray REST)
  - synology_dsm        (DSM REST)

VIRTUALIZATION:
  - hyperv_host         (PowerShell over WinRM)
  - nutanix_prism       (Prism Element REST)
  - proxmox_ve          (REST API)

CLOUD:
  - azure_subscription  (Azure SDK)
  - gcp_project         (Google Cloud SDK)
  - kubernetes_cluster  (kubectl/python-client)

BACKUP:
  - veeam_backup        (Veeam REST API v11+)
  - rubrik_cdm          (Rubrik REST)
  - cohesity_cluster    (Cohesity REST)

Each adapter follows the BaseAdapter pattern. Vendor-specific code is
grounded in published API documentation. Community contributors validate
against real hardware via the contribute-an-adapter pattern in
docs/PLATFORM_ARCHITECTURE.md."
  git push origin main
fi

git tag -a v3.1.0 -m "v3.1.0 — 25 vendor adapters across 6 domains" 2>/dev/null || true
git push origin v3.1.0 2>/dev/null || true

mkdir -p dist/old && mv dist/safecadence_netrisk-3.0.* dist/old/ 2>/dev/null || true
.venv/bin/python -m build

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

TWINE_USERNAME=__token__ TWINE_PASSWORD="$GOT" \
  .venv/bin/python -m twine upload dist/safecadence_netrisk-3.1.0*

if command -v gh &>/dev/null; then
  gh release create v3.1.0 \
    --title "v3.1.0 — 25 vendor adapters across all 6 infrastructure domains" \
    --notes "**v3.1.0** expands the multi-vendor adapter library from 6 to **25 adapters** covering Network (6), Servers (5), Storage (3), Virtualization (4), Cloud (4), Backup (3).

**New in this release:**
- arista_eos, juniper_junos, fortinet_fortigate, palo_alto_panos, aruba_cx
- cisco_ucs, lenovo_xclarity, supermicro_ipmi
- pure_storage, synology_dsm
- hyperv_host, nutanix_prism, proxmox_ve
- azure_subscription, gcp_project, kubernetes_cluster
- veeam_backup, rubrik_cdm, cohesity_cluster

Each adapter is grounded in vendor's published API documentation. Validate against your real hardware and contribute fixes back via PR — see \`docs/PLATFORM_ARCHITECTURE.md\` for the contribute-an-adapter guide.

\`pip install --upgrade safecadence-netrisk\`" \
    dist/safecadence_netrisk-3.1.0-py3-none-any.whl \
    dist/safecadence_netrisk-3.1.0.tar.gz
fi

echo ""
echo "============================================================"
echo " v3.1.0 SHIPPED — 25 vendor adapters"
echo "============================================================"
