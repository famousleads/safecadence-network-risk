#!/bin/bash
# Watches the clipboard for a PyPI token. Once detected, uploads v2.3.0 to PyPI,
# verifies the install, and shreds the token file.
#
# Run: bash ~/Documents/FamousTec/safecadence-network-risk/auto-publish-v2.3.0.sh

set -e
cd "$(dirname "$0")"

DST="$HOME/Documents/FamousTec/.pypi-token-v3"

echo "============================================================"
echo " v2.3.0 auto-publish — waiting for PyPI token on clipboard"
echo "============================================================"
echo ""
echo " 1. Open the PyPI tab (it should already be on the password screen)."
echo " 2. Type your PyPI password and click Confirm."
echo " 3. Tell Claude 'confirmed' — Claude creates the token + clicks Copy."
echo " 4. THIS SCRIPT auto-detects the token and uploads. No copy from chat."
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
    echo " Got token (len=${#CLIP}). Uploading v2.3.0 to PyPI..."
    echo "============================================================"

    TWINE_USERNAME=__token__ TWINE_PASSWORD="$(cat $DST)" \
      .venv/bin/python -m twine upload dist/safecadence_netrisk-2.3.0*

    UPLOAD_RC=$?

    # Shred token file (3-pass overwrite + unlink)
    SIZE=$(wc -c < "$DST")
    for j in 1 2 3; do
      dd if=/dev/urandom of="$DST" bs=1 count="$SIZE" conv=notrunc 2>/dev/null
    done
    rm -f "$DST"
    echo ""
    echo "  Token file shredded + deleted."

    if [[ $UPLOAD_RC -eq 0 ]]; then
      echo ""
      echo "============================================================"
      echo " v2.3.0 LIVE on PyPI!"
      echo " https://pypi.org/project/safecadence-netrisk/2.3.0/"
      echo "============================================================"
      echo ""
      echo "Verifying in your active venv..."
      pip install --upgrade --quiet safecadence-netrisk 2>&1 | tail -3
      echo ""
      echo "  Version: $(safecadence --version 2>&1)"
      echo ""
      echo "Launch the UI now with:  safecadence ui"
    else
      echo "Upload failed — check the twine output above."
    fi
    exit $UPLOAD_RC
  fi
  sleep 1
done

echo ""
echo "Timeout (180s) — no PyPI token detected on clipboard."
echo "Re-run the script and try again."
exit 1
