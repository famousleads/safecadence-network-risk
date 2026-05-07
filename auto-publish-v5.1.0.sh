#!/bin/bash
# Ship v5.1.0 — unified UI shell + Docker first-class + curl|sh installer.
#   - Sidebar in the local UI now shows Audit (v2) + Platform (v4) + Policy (v5)
#   - Policy + Platform UIs work in both bearer-auth and local-no-auth modes
#   - Iframe-mounted v4/v5 dashboards inside the v2.3 shell — one product, three eras
#   - Platform/policy UIs now honor #hash so the parent can deep-link to a tab
#   - Dockerfile labels updated; image will be republished as :5.1.0 + :latest
#   - install.sh — auto-detect pipx/pip/docker, cross-platform
set -e
cd "$(dirname "$0")"

if command -v pytest &>/dev/null; then
  echo "Running test suite..."
  PYTHONPATH=src pytest tests/policy/ -q || { echo "TESTS FAILED"; exit 1; }
fi

git add -A 2>/dev/null
if ! git diff --cached --quiet; then
  git commit -m "feat: v5.1.0 — unified UI shell + Docker first-class + curl|sh installer

The local UI's sidebar now shows the v4.0 Platform tabs and v5.0 Policy tabs
inline as new sections. Same single 'safecadence ui' command, three eras of UI
under one nav. Each new tab iframe-mounts the existing platform/policy
dashboard and deep-links via URL hash so navigation is one click.

Both the platform and policy UIs now skip the Authorization header when no
JWT token is present in localStorage — so they work in:
  - the multi-user server app (bearer auth required)
  - the single-user local UI (no auth)

Other:
  - Dockerfile labels refreshed to advertise v5.0 platform + policy capabilities
  - install.sh — one-command installer that auto-picks pipx / pip / docker
    on macOS / Linux / Windows-bash. Pure bash, no curl-piped sudo, --help
    + --docker / --pipx / --pip / --no-launch flags.
  - Policy package __init__ now re-exports PolicyState / PolicyException /
    RemediationStep so policy_api can import them from the top-level package.
  - 64 unit tests still pass."
  git push origin main
fi

git tag -a v5.1.0 -m "v5.1.0 — unified UI shell + Docker first-class + curl|sh installer" 2>/dev/null || true
git push origin v5.1.0 2>/dev/null || true

mkdir -p dist/old && mv dist/safecadence_netrisk-5.0.* dist/old/ 2>/dev/null || true
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
    .venv/bin/python -m twine upload dist/safecadence_netrisk-5.1.0*
else
  TWINE_USERNAME=__token__ TWINE_PASSWORD="$GOT" \
    python3 -m twine upload dist/safecadence_netrisk-5.1.0*
fi

if command -v gh &>/dev/null; then
  gh release create v5.1.0 \
    --title "v5.1.0 — Unified UI + Docker first-class + curl|sh installer" \
    --notes "**v5.1.0** unifies the three eras of UI (v2.3 Audit, v4.0 Platform, v5.0 Policy) under a single sidebar in \`safecadence ui\` — one product, three eras.

## What's new

- **Unified local UI sidebar** — adds **Platform (v4) ★** and **Policy (v5) ★** sections to the existing nav. Each tab iframe-mounts the matching dashboard and deep-links via URL hash. Sidebar version label bumped from \`v2.3.0\` → \`v5.1.0\`.
- **Auth-flexible UIs** — platform + policy dashboards now skip the \`Authorization\` header when no JWT is present in localStorage, so they work both in the multi-user server app (bearer-auth) and the single-user local UI (no-auth).
- **Docker first-class** — Dockerfile labels updated to advertise v5.0 platform + policy capabilities. Image republished as \`safecadence/netrisk:5.1.0\` and \`:latest\` (multi-arch amd64 + arm64).
- **One-command installer** — \`install.sh\` auto-picks pipx → pip → docker on macOS / Linux / Windows-bash. Cross-platform pure bash. Available at \`https://safecadence.com/install.sh\` (after you upload it).

## Three install paths now supported

\`\`\`bash
# Python users (preferred)
pipx install safecadence-netrisk

# Non-Python users — Docker
docker run -p 8765:8765 safecadence/netrisk:5.1.0 ui --host 0.0.0.0

# Anyone — one-line
curl -fsSL https://safecadence.com/install.sh | bash
\`\`\`

## Quick start

\`\`\`bash
pipx upgrade safecadence-netrisk
safecadence ui
\`\`\`

The sidebar now shows Audit · Platform · Policy as sections. Click any Platform tab to see the 40-vendor inventory, or any Policy tab to author / interpret / evaluate / export remediation.

64 unit tests still pass. Cross-platform: macOS, Linux, Windows; physical or virtual." \
    dist/safecadence_netrisk-5.1.0-py3-none-any.whl \
    dist/safecadence_netrisk-5.1.0.tar.gz \
    install.sh
fi

echo ""
echo "============================================================"
echo " v5.1.0 SHIPPED — Unified UI + Docker first-class + installer"
echo "============================================================"
echo
echo " Optional next steps (do these manually when ready):"
echo "   1. Build & push the multi-arch Docker image:"
echo "      docker buildx build --platform linux/amd64,linux/arm64 \\"
echo "        -t safecadence/netrisk:5.1.0 -t safecadence/netrisk:latest --push ."
echo
echo "   2. Upload install.sh to the SafeCadence website root"
echo "      so 'curl -fsSL https://safecadence.com/install.sh | bash' resolves."
echo
echo "   3. Push the WordPress + analyzer site changes from earlier:"
echo "      cd ~/Documents/FamousTec/sc-v5-site-update && cat DEPLOY.md"
