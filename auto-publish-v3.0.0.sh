#!/bin/bash
# Ship v3.0.0 — Device Intelligence Platform foundation + 6 reference adapters.
#
# Run: bash ~/Documents/FamousTec/safecadence-network-risk/auto-publish-v3.0.0.sh
#
# This is a MAJOR version bump because it adds an entirely new module
# surface (src/safecadence/platform/) that turns the network audit tool
# into a multi-vendor enterprise infrastructure platform.

set -e
cd "$(dirname "$0")"

git add -A 2>/dev/null
if ! git diff --cached --quiet; then
  git commit -m "feat: v3.0.0 — Device Intelligence Platform foundation

MAJOR: introduces src/safecadence/platform/ — a multi-vendor adapter
framework that transforms safecadence-netrisk from a network-only audit
tool into a full enterprise infrastructure platform.

Foundation:
- UnifiedAsset schema (single source of truth for any asset type)
- BaseAdapter framework with capability declaration + registry
- ConnectionManager (rate-limited, auditable HTTP/SSH/SNMP/Redfish)
- PlatformVault (Fernet-encrypted multi-vendor credentials + audit log)
- 4-dimensional health scoring engine (hardware/security/lifecycle/operational)
- Composite scoring with letter grade A-F + risk band

Reference adapters (6):
- dell_idrac      — Dell PowerEdge via iDRAC Redfish (full implementation)
- hpe_ilo         — HPE ProLiant via iLO Redfish (extends Dell)
- cisco_network   — Cisco IOS/IOS-XE/NX-OS/ASA via SSH (bridges existing engine)
- vmware_vcenter  — vSphere REST API
- aws_account     — AWS via boto3 (EC2 + security groups)
- netapp_ontap    — NetApp ONTAP REST API

Comprehensive architecture documented in docs/PLATFORM_ARCHITECTURE.md
including the 30+ additional adapters spec'd as community-buildable
(each requires real hardware to test — see doc for honest scope reality).

The existing v2.x network risk audit tool remains fully functional and
unchanged — the platform is purely additive."
  git push origin main
fi

git tag -a v3.0.0 -m "v3.0.0 — Device Intelligence Platform foundation" 2>/dev/null || true
git push origin v3.0.0 2>/dev/null || true

# Build
mkdir -p dist/old && mv dist/safecadence_netrisk-2.* dist/old/ 2>/dev/null || true
.venv/bin/python -m build

# Poll clipboard for token
echo ""; echo "Paste your PyPI token..."
LAST=""; GOT=""
for i in $(seq 1 180); do
  CLIP=$(pbpaste 2>/dev/null)
  PREVIEW=$(printf '%s' "$CLIP" | head -c 12)
  if [[ "$PREVIEW" != "$LAST" ]]; then
    echo "  [${i}s] '${PREVIEW}...'"
    LAST="$PREVIEW"
  fi
  if [[ "$CLIP" == pypi-AgEI* ]] && [[ ${#CLIP} -gt 100 ]]; then
    GOT="$CLIP"; break
  fi
  sleep 1
done
[[ -z "$GOT" ]] && { echo "Timeout"; exit 1; }

TWINE_USERNAME=__token__ TWINE_PASSWORD="$GOT" \
  .venv/bin/python -m twine upload dist/safecadence_netrisk-3.0.0*

if command -v gh &>/dev/null; then
  gh release create v3.0.0 \
    --title "v3.0.0 — Device Intelligence Platform foundation" \
    --notes "**Major release.** Introduces \`src/safecadence/platform/\` — multi-vendor adapter framework that turns safecadence-netrisk into a full enterprise infrastructure platform covering network, servers, storage, virtualization, cloud, backup.

**Foundation:** UnifiedAsset schema, BaseAdapter framework, ConnectionManager, multi-vendor credential vault, 4-dimensional health scoring (hardware/security/lifecycle/operational with composite + grade A-F).

**Reference adapters (6):**
- \`dell_idrac\` — Dell PowerEdge via iDRAC Redfish (full implementation)
- \`hpe_ilo\` — HPE ProLiant via iLO Redfish
- \`cisco_network\` — Cisco IOS/IOS-XE/NX-OS/ASA via SSH
- \`vmware_vcenter\` — vSphere REST API
- \`aws_account\` — AWS via boto3 (EC2 + security groups)
- \`netapp_ontap\` — NetApp ONTAP REST API

Architecture spec for the next 30+ adapters (Pure / Veeam / Azure / GCP / Fortinet / Nutanix / etc.) in \`docs/PLATFORM_ARCHITECTURE.md\` — each is community-buildable per the same template.

**Backward compatibility:** All v2.x network audit features unchanged. Platform layer is purely additive.

Install: \`pip install --upgrade safecadence-netrisk\`" \
    dist/safecadence_netrisk-3.0.0-py3-none-any.whl \
    dist/safecadence_netrisk-3.0.0.tar.gz
fi

echo ""
echo "============================================================"
echo " v3.0.0 SHIPPED — Device Intelligence Platform"
echo " PyPI:    https://pypi.org/project/safecadence-netrisk/3.0.0/"
echo " GitHub:  https://github.com/famousleads/safecadence-network-risk/releases/tag/v3.0.0"
echo " Docs:    docs/PLATFORM_ARCHITECTURE.md"
echo "============================================================"
