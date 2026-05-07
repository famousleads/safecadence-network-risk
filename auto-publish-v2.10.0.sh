#!/bin/bash
# Ship v2.10.0 — comprehensive README rewrite + email digest module.
set -e
cd "$(dirname "$0")"

git add -A 2>/dev/null
if ! git diff --cached --quiet; then
  git commit -m "feat: v2.10.0 — comprehensive README rewrite + email digest module

- README: full rewrite covering all v2.2 → v2.10 features. Comparison
  table vs Tenable / Qualys / Rapid7 / AlgoSec. Architecture diagram,
  3 install methods (pip/pipx/Docker), full feature catalog. Removes
  out-of-date v2.2-era content. Highest-impact change for adoption.
- email_digest.py: pure-stdlib smtplib email digest delivery. Renders
  inline-styled HTML email with KPI grid + spotlight devices.
  Pairs with safecadence watch via env-driven SMTP config." 2>/dev/null
  git push origin main
fi

git tag -a v2.10.0 -m "v2.10.0 — README + email digest" 2>/dev/null || true
git push origin v2.10.0 2>/dev/null || true

mkdir -p dist/old && mv dist/safecadence_netrisk-2.9.* dist/old/ 2>/dev/null || true
.venv/bin/python -m build

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
  .venv/bin/python -m twine upload dist/safecadence_netrisk-2.10.0*

if command -v gh &>/dev/null; then
  gh release create v2.10.0 \
    --title "v2.10.0 — comprehensive README rewrite + email digest" \
    --notes "Documentation refresh: full README rewrite covering all v2.2 → v2.10 features, with comparison table vs Tenable/Qualys/Rapid7/AlgoSec. Plus email_digest.py module — pure-stdlib SMTP delivery for daily/weekly fleet summaries to pair with \`safecadence watch\`." \
    dist/safecadence_netrisk-2.10.0-py3-none-any.whl \
    dist/safecadence_netrisk-2.10.0.tar.gz
fi

echo ""
echo "============================================================"
echo " v2.10.0 SHIPPED"
echo " PyPI:    https://pypi.org/project/safecadence-netrisk/2.10.0/"
echo " GitHub:  https://github.com/famousleads/safecadence-network-risk/releases/tag/v2.10.0"
echo "============================================================"
