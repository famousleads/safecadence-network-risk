#!/bin/bash
# Commits v2.7.0 source, pushes, tags, polls clipboard for token, uploads to PyPI,
# cuts GitHub release.
#
# Run: bash ~/Documents/FamousTec/safecadence-network-risk/auto-publish-v2.7.0.sh

set -e
cd "$(dirname "$0")"

echo "============================================================"
echo " v2.7.0 ship — commit, push, tag, upload, release"
echo "============================================================"

# 1. Commit v2.7.0 source changes
echo ""
echo "Step 1: commit v2.7.0 source"
git status --short
git add src/safecadence/__init__.py \
        pyproject.toml \
        src/safecadence/discovery/compliance_pack.py \
        src/safecadence/discovery/ai_architect.py \
        src/safecadence/discovery/threat_hunt.py \
        src/safecadence/ui/asset_tags.py \
        src/safecadence/ui/app.py 2>/dev/null || true

if git diff --cached --quiet; then
    echo "  (nothing new to commit — already on v2.7.0?)"
else
    git commit -m "feat: v2.7.0 — compliance packs + AI architect + threat hunting + asset tags

Adds 4 net-new capabilities:

1. Compliance audit packs — auditor-ready HTML evidence packs for
   SOC 2, PCI-DSS, HIPAA, NIST 800-53, CIS Controls v8. Maps fleet
   findings to specific control IDs with sign-off blocks.

2. AI Network Architect (POST /api/ai/architect) — analyzes the
   network as a system: segmentation gaps, zero-trust posture,
   lateral movement risks, modernization roadmap.

3. Threat hunting feed — pulls live CISA KEV catalog, filters to
   recent N-day window, matches against fleet vendors. Shows
   'you match these recently-active threat actor TTPs.'

4. Asset tagging + ownership — per-device tags, owner, criticality
   (with crown-jewel risk boost), notes. Stored server-side in
   ~/.safecadence/asset_tags.sqlite.

Backend complete; UI tabs to follow in v2.8."
    git push origin main
fi

echo ""
echo "Step 2: tag v2.7.0"
git tag -a v2.7.0 -m "v2.7.0 — compliance + AI architect + threat hunt + asset tags" 2>/dev/null || echo "  (tag already exists)"
git push origin v2.7.0 2>/dev/null || true

# 2. Poll clipboard for PyPI token
echo ""
echo "Step 3: paste your PyPI token (or get a new one from"
echo "        https://pypi.org/manage/account/token/ — project scope)"
echo ""

LAST=""
GOT_TOKEN=""
for i in $(seq 1 180); do
  CLIP=$(pbpaste 2>/dev/null)
  PREVIEW=$(printf '%s' "$CLIP" | head -c 12)
  if [[ "$PREVIEW" != "$LAST" ]]; then
    echo "  [${i}s] Clipboard: '${PREVIEW}...' (len=${#CLIP})"
    LAST="$PREVIEW"
  fi
  if [[ "$CLIP" == pypi-AgEI* ]] && [[ ${#CLIP} -gt 100 ]]; then
    GOT_TOKEN="$CLIP"
    break
  fi
  sleep 1
done

if [[ -z "$GOT_TOKEN" ]]; then
  echo "Timeout — no PyPI token detected. Re-run after copying."
  exit 1
fi

echo ""
echo "Step 4: upload v2.7.0 to PyPI"
TWINE_USERNAME=__token__ TWINE_PASSWORD="$GOT_TOKEN" \
  .venv/bin/python -m twine upload dist/safecadence_netrisk-2.7.0*

# 3. GitHub release
echo ""
echo "Step 5: GitHub release"
if command -v gh &>/dev/null; then
  gh release create v2.7.0 \
    --title "v2.7.0 — compliance packs + AI architect + threat hunting + asset tags" \
    --notes "## What's new

**Compliance audit packs** — auditor-ready HTML evidence packs for SOC 2, PCI-DSS, HIPAA, NIST 800-53, CIS Controls v8. Each pack maps your fleet's findings to specific control IDs with status, evidence, and sign-off blocks. Sell directly to consulting clients.

\`\`\`
POST /api/discover/compliance-pack
{\"framework\": \"soc2\", \"organization\": \"Acme Corp\", ...}
\`\`\`

**AI Network Architect** — analyzes your network as a system instead of per-device. Returns architecture grade (A-F), segmentation gaps, zero-trust violations, lateral movement risks, prioritized modernization roadmap.

\`\`\`
POST /api/ai/architect
{\"fleet\": ..., \"provider\": \"openai\", \"api_key\": \"sk-...\"}
\`\`\`

**Threat hunting feed** — pulls live CISA Known Exploited Vulnerabilities catalog, filters to recent N-day window, matches against your fleet's identified vendors. Tells you which currently-active threats apply to your network.

\`\`\`
POST /api/discover/threat-hunt
{\"fleet\": ..., \"days\": 30}
\`\`\`

**Asset tagging + ownership** — tag any device with arbitrary labels (\`prod\`, \`crown-jewel\`, \`owner:alice@\`), criticality, notes. Stored server-side. Crown-jewel devices auto-boost risk score for prioritization.

\`\`\`
POST /api/assets/tags
{\"ip\": \"192.168.4.1\", \"tags\": [\"prod\"], \"owner\": \"alice@acme.com\", \"criticality\": \"crown-jewel\"}
\`\`\`

## Install / upgrade

\`\`\`
pip install --upgrade 'safecadence-netrisk[server]'
safecadence ui
\`\`\`" \
    dist/safecadence_netrisk-2.7.0-py3-none-any.whl \
    dist/safecadence_netrisk-2.7.0.tar.gz
fi

echo ""
echo "============================================================"
echo " DONE — v2.7.0 SHIPPED"
echo "============================================================"
echo "PyPI:    https://pypi.org/project/safecadence-netrisk/2.7.0/"
echo "GitHub:  https://github.com/famousleads/safecadence-network-risk/releases/tag/v2.7.0"
