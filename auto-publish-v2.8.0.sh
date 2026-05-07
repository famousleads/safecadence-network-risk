#!/bin/bash
# Ship v2.8.0 — UI tabs for compliance, threat hunt, AI architect, asset tags + CSV export.
#
# Run: bash ~/Documents/FamousTec/safecadence-network-risk/auto-publish-v2.8.0.sh

set -e
cd "$(dirname "$0")"

# Commit + push (includes v2.7 source if not yet committed)
git add -A 2>/dev/null
if ! git diff --cached --quiet; then
  git commit -m "feat: v2.8.0 — UI tabs for compliance, threat hunt, AI architect, asset tagging + CSV export

Adds 4 new tabs to the local UI making the v2.7.0 backend features
actually usable from the browser:

- 📋 Compliance packs tab — pick framework (SOC2/PCI/HIPAA/NIST/CIS),
  fill org/auditor/period, generate auditor-ready HTML pack.
- 🎯 Threat hunting tab — fetch live CISA KEV catalog, hunt fleet for
  matches, see Required Actions per CVE.
- 🏛 AI Architect tab — one-click architectural analysis with grade,
  segmentation gaps, lateral movement risks, zero-trust roadmap.
- 📌 Assets & tags tab — add/update per-device tags, owners,
  criticality. Crown-jewel assets get +15 risk boost automatically.
- CSV export button on Subnet sweep results for spreadsheet-loving
  auditors.

Backend was already shipped in v2.7.0; this version completes the UX." 2>/dev/null || true
  git push origin main
fi

git tag -a v2.8.0 -m "v2.8.0 — UI completeness for v2.7 backend + CSV export" 2>/dev/null || true
git push origin v2.8.0 2>/dev/null || true

# Build wheel
mkdir -p dist/old && mv dist/safecadence_netrisk-2.7.* dist/old/ 2>/dev/null || true
.venv/bin/python -m build

# Poll clipboard for token + upload
echo ""
echo "Paste your PyPI token (project-scoped from https://pypi.org/manage/account/token/)..."
LAST=""; GOT=""
for i in $(seq 1 180); do
  CLIP=$(pbpaste 2>/dev/null)
  PREVIEW=$(printf '%s' "$CLIP" | head -c 12)
  if [[ "$PREVIEW" != "$LAST" ]]; then
    echo "  [${i}s] '${PREVIEW}...' (len=${#CLIP})"
    LAST="$PREVIEW"
  fi
  if [[ "$CLIP" == pypi-AgEI* ]] && [[ ${#CLIP} -gt 100 ]]; then
    GOT="$CLIP"; break
  fi
  sleep 1
done
[[ -z "$GOT" ]] && { echo "Timeout"; exit 1; }

TWINE_USERNAME=__token__ TWINE_PASSWORD="$GOT" \
  .venv/bin/python -m twine upload dist/safecadence_netrisk-2.8.0*

# GitHub release
if command -v gh &>/dev/null; then
  gh release create v2.8.0 \
    --title "v2.8.0 — UI for compliance + threat hunt + AI architect + asset tags + CSV export" \
    --notes "Backend features from v2.7.0 now have full UI tabs. Compliance audit packs (5 frameworks), live CISA KEV threat hunting, AI Network Architect analysis, per-device asset tagging with owner + criticality, CSV export of fleet inventory." \
    dist/safecadence_netrisk-2.8.0-py3-none-any.whl \
    dist/safecadence_netrisk-2.8.0.tar.gz
fi

echo ""
echo "============================================================"
echo " v2.8.0 SHIPPED"
echo "============================================================"
echo "PyPI:    https://pypi.org/project/safecadence-netrisk/2.8.0/"
echo "GitHub:  https://github.com/famousleads/safecadence-network-risk/releases/tag/v2.8.0"
