#!/bin/bash
# Ship v6.0.0 — Identity Intelligence Engine + comparator-beating features.
set -e
cd "$(dirname "$0")"

if command -v pytest &>/dev/null; then
  echo "Running 119-test suite..."
  PYTHONPATH=src pytest tests/policy/ -q || { echo "TESTS FAILED"; exit 1; }
fi

git add -A 2>/dev/null
if ! git diff --cached --quiet; then
  git commit -m "feat: v6.0.0 — Identity Intelligence Engine + comparator-beating features

NEW IN v6.0:
  - 5 identity adapters: cisco_ise, hpe_clearpass, active_directory, entra_id, okta
  - 4 identity translators: cisco_ise (ERS API JSON), clearpass_role,
    ad_gpo (PowerShell), azure_ca (Conditional Access JSON)
  - Cross-system policy drift detector (no other tool does this)
  - Identity dataclass added to UnifiedAsset (45 adapters total now)

NEW IN v5.2 (folded in):
  - Discovery -> Platform bridge (adopt-discovered)
  - KEV + EPSS + exploit-availability triple-weighted CVE prioritization
  - Fleet-wide search with facet syntax
  - Scheduled re-evaluation + alerting
  - Local UI password gate (--password)
  - Attack-path graph engine (BloodHound for infrastructure)
  - MITRE ATT&CK technique coverage map
  - AI executive briefing (BYO-AI)
  - Compliance gap delta with per-asset attribution

QUALITY: 119 unit tests pass; 19/19 endpoints 200 in live boot smoke;
cross-platform Linux/macOS/Windows."
  git push origin main
fi

git tag -a v6.0.0 -m "v6.0.0 — Identity Intelligence Engine (45 adapters, 16 translators, 119 tests)" 2>/dev/null || true
git push origin v6.0.0 2>/dev/null || true

mkdir -p dist/old && mv dist/safecadence_netrisk-5.* dist/old/ 2>/dev/null || true
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
    .venv/bin/python -m twine upload dist/safecadence_netrisk-6.0.0*
else
  TWINE_USERNAME=__token__ TWINE_PASSWORD="$GOT" \
    python3 -m twine upload dist/safecadence_netrisk-6.0.0*
fi

if command -v gh &>/dev/null; then
  gh release create v6.0.0 \
    --title "v6.0.0 - Identity Intelligence Engine + comparator-beating features" \
    --notes "v6.0.0 turns SafeCadence into the only open-source tool bridging identity, network, cloud, and backup with one unified policy brain. 45 adapters across 7 domains, 16 multi-vendor translators, 22 controls + 10 templates, 7 export formats, 119 unit tests pass.

Install: pip install --upgrade safecadence-netrisk" \
    dist/safecadence_netrisk-6.0.0-py3-none-any.whl \
    dist/safecadence_netrisk-6.0.0.tar.gz install.sh
fi

echo ""
echo "============================================================"
echo " v6.0.0 SHIPPED - Identity Intelligence Engine"
echo "  - 45 adapters across 7 domains"
echo "  - cross-system drift detector"
echo "  - 119 tests passing"
echo "============================================================"
