#!/bin/bash
# Ship v2.9.0 — Docker container + GitHub Actions integration.
#
# Run: bash ~/Documents/FamousTec/safecadence-network-risk/auto-publish-v2.9.0.sh

set -e
cd "$(dirname "$0")"

# Commit + push
git add -A 2>/dev/null
if ! git diff --cached --quiet; then
  git commit -m "feat: v2.9.0 — Docker container + GitHub Actions integration

Distribution layer additions — open the product to non-Python users
and DevSecOps audiences:

1. Multi-arch Docker image (linux/amd64 + linux/arm64), Alpine-based,
   ~80MB final size. Builds with all extras included.
   Usage:
     docker run --rm safecadence/netrisk discover 10.10.10.0/24
     docker run -p 8765:8765 safecadence/netrisk ui --host 0.0.0.0
   Plus docker-compose.yml example with persistent state volume.

2. GitHub Actions composite action (action.yml at repo root). Lets any
   repo audit network configs as part of CI/CD with:
     - uses: famousleads/safecadence-network-risk@v2.9.0
   Configurable: vendor override, fail-on threshold (critical/high/etc),
   output format (json/html/markdown/sarif), SARIF upload to Code Scanning,
   AI explanation gated on AI_API_KEY secret.
   Returns outputs: total-findings, critical-count, high-count,
   health-score, risk-score, report-path.

3. CI workflows added:
   - .github/workflows/docker-publish.yml — auto-builds + pushes
     multi-arch image to ghcr.io/famousleads/safecadence-netrisk on
     every v*.*.* tag.
   - .github/workflows/example-audit.yml — example showing how external
     repos can use the action."
  git push origin main
fi

git tag -a v2.9.0 -m "v2.9.0 — Docker + GitHub Actions" 2>/dev/null || true
git push origin v2.9.0 2>/dev/null || true

# Build wheel
mkdir -p dist/old && mv dist/safecadence_netrisk-2.8.* dist/old/ 2>/dev/null || true
.venv/bin/python -m build

# Poll clipboard for token + upload
echo ""
echo "Paste your PyPI token..."
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
  .venv/bin/python -m twine upload dist/safecadence_netrisk-2.9.0*

# GitHub release
if command -v gh &>/dev/null; then
  gh release create v2.9.0 \
    --title "v2.9.0 — Docker container + GitHub Actions integration" \
    --notes "**Distribution layer:** Docker image (multi-arch) + GitHub Actions composite action. Opens the product to non-Python users + DevSecOps teams.

\`\`\`yaml
- uses: famousleads/safecadence-network-risk@v2.9.0
  with:
    config-path: configs/
    fail-on: high
    output-format: sarif
    upload-sarif: true
\`\`\`

\`\`\`bash
docker run --rm safecadence/netrisk discover 10.10.10.0/24
docker run -p 8765:8765 safecadence/netrisk ui --host 0.0.0.0
\`\`\`

The Docker image is auto-built + pushed to \`ghcr.io/famousleads/safecadence-netrisk\` for every tag via the new docker-publish workflow." \
    dist/safecadence_netrisk-2.9.0-py3-none-any.whl \
    dist/safecadence_netrisk-2.9.0.tar.gz
fi

echo ""
echo "============================================================"
echo " v2.9.0 SHIPPED"
echo "============================================================"
echo "PyPI:    https://pypi.org/project/safecadence-netrisk/2.9.0/"
echo "GitHub:  https://github.com/famousleads/safecadence-network-risk/releases/tag/v2.9.0"
echo ""
echo "The docker-publish workflow will now auto-build + push the image to:"
echo "  ghcr.io/famousleads/safecadence-netrisk:2.9.0"
echo "  ghcr.io/famousleads/safecadence-netrisk:latest"
echo ""
echo "Watch the build at: https://github.com/famousleads/safecadence-network-risk/actions"
