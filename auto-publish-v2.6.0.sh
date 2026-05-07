#!/bin/bash
# Polls macOS clipboard for a PyPI token, uploads safecadence-netrisk v2.6.0.
#
# Run: bash ~/Documents/FamousTec/safecadence-network-risk/auto-publish-v2.6.0.sh
#
# Then in Chrome on https://pypi.org/manage/account/token/ :
#   1. Click "Add API token"
#   2. Name: safecadence-netrisk-v4
#   3. Scope: Project: safecadence-netrisk
#   4. Click "Create token"
#   5. Click the page's "Copy token" button
# This script auto-detects the token on the clipboard and uploads.

set -e
cd "$(dirname "$0")"

DST="$HOME/.pypi-token-tmp"

echo "============================================================"
echo " v2.6.0 auto-publish — waiting for PyPI token on clipboard"
echo "============================================================"
echo ""
echo " Open https://pypi.org/manage/account/token/ in Chrome,"
echo " confirm your password, create a new project-scoped token,"
echo " click 'Copy token'. This script picks it up and uploads."
echo ""
echo "Polling clipboard (180-second timeout)..."
echo ""

LAST=""
for i in $(seq 1 180); do
  CLIP=$(pbpaste 2>/dev/null)
  PREVIEW=$(printf '%s' "$CLIP" | head -c 12)
  if [[ "$PREVIEW" != "$LAST" ]]; then
    echo "  [${i}s] Clipboard: '${PREVIEW}...' (len=${#CLIP})"
    LAST="$PREVIEW"
  fi
  if [[ "$CLIP" == pypi-AgEI* ]] && [[ ${#CLIP} -gt 100 ]]; then
    printf '%s' "$CLIP" > "$DST"
    chmod 600 "$DST"
    echo ""
    echo "============================================================"
    echo " Got token (len=${#CLIP}). Uploading v2.6.0 to PyPI..."
    echo "============================================================"

    TWINE_USERNAME=__token__ TWINE_PASSWORD="$(cat $DST)" \
      .venv/bin/python -m twine upload dist/safecadence_netrisk-2.6.0*
    UPLOAD_RC=$?

    # Shred token file
    SIZE=$(wc -c < "$DST")
    for j in 1 2 3; do
      dd if=/dev/urandom of="$DST" bs=1 count="$SIZE" conv=notrunc 2>/dev/null
    done
    rm -f "$DST"

    if [[ $UPLOAD_RC -eq 0 ]]; then
      echo ""
      echo "============================================================"
      echo " v2.6.0 LIVE on PyPI!"
      echo " https://pypi.org/project/safecadence-netrisk/2.6.0/"
      echo "============================================================"

      # Cut GitHub release if gh is installed
      if command -v gh &>/dev/null; then
        echo ""
        echo "Creating GitHub release..."
        gh release create v2.6.0 \
          --title "v2.6.0 — toxic combos + AI attack paths + watch + webhooks + saved scans + topology + chat" \
          --notes "Major release. See CHANGELOG.md for the full feature list across v2.4 + v2.5 + v2.6 (all combined into this release)." \
          dist/safecadence_netrisk-2.6.0-py3-none-any.whl \
          dist/safecadence_netrisk-2.6.0.tar.gz
      fi
    fi
    exit $UPLOAD_RC
  fi
  sleep 1
done

echo ""
echo "Timeout — no PyPI token detected. Re-run after copying the token."
exit 1
