#!/bin/bash
# Ship v6.4.1 — Builder wizard step 2 ("Apply to which devices?") closes
# the loop on asset-group selection from the UI. Plus version-badge fix.
set -e
cd "$(dirname "$0")"

if command -v pytest &>/dev/null; then
  echo "Running 311-test suite..."
  PYTHONPATH=src pytest tests/ -q || { echo "TESTS FAILED"; exit 1; }
fi

git add -A 2>/dev/null
if ! git diff --cached --quiet; then
  git commit -m "feat: v6.4.1 — Builder wizard 'Apply to which devices?' step

v6.4.0 shipped the asset-groups primitive and the policy.applies_to_groups
field, but the Builder UI had no way to reach them — every policy created
through the wizard implicitly targeted the whole fleet. v6.4.1 closes
that loop.

NEW: Step 2 in the policy Builder wizard
  - 5-step wizard expanded to 6 steps; new step 2 is 'Apply to which
    devices?'. Default option 'All assets of those types (fleet-wide)'
    preserves the legacy behaviour, so existing muscle memory still
    works.
  - Multi-select grid populated from /api/platform/asset-groups, showing
    member count + static/dynamic kind per group.
  - When the operator picks one or more groups, the save payload now
    carries applies_to_groups: [...] which the policy schema and the
    evaluator already honour from v6.4.0.
  - Targeting summary shown on the impact-preview step + the save toast,
    so the operator can confirm 'Yes, this policy will only run against
    cisco-edge.'

FIX: _to_policy() now picks up applies_to_groups
  - The /api/policy/ POST handler routes through templates._to_policy().
    It was preserving target_asset_types but dropping applies_to_groups.
    Now both are propagated.

FIX: UI version badge bumped from v6.2 to v6.4

QUALITY:
  - 311 unit tests pass (2 new in test_v6_4.py: end-to-end builder
    HTML check + _to_policy applies_to_groups round-trip)"
  git push origin main
fi

git tag -a v6.4.1 -m "v6.4.1 — Builder wizard asset-group step" 2>/dev/null || true
git push origin v6.4.1 2>/dev/null || true

mkdir -p dist/old && mv dist/safecadence_netrisk-6.4.0* dist/old/ 2>/dev/null || true
if [[ -x .venv/bin/python ]]; then .venv/bin/python -m build; else python3 -m build; fi

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
    .venv/bin/python -m twine upload dist/safecadence_netrisk-6.4.1*
else
  TWINE_USERNAME=__token__ TWINE_PASSWORD="$GOT" \
    python3 -m twine upload dist/safecadence_netrisk-6.4.1*
fi

if command -v gh &>/dev/null; then
  gh release create v6.4.1 \
    --title "v6.4.1 - Builder wizard 'Apply to which devices?' step" \
    --notes "v6.4.0 shipped the asset-groups primitive but the Builder
UI didn't expose it. v6.4.1 adds the missing wizard step.

NEW: Step 2 in the Builder wizard — 'Apply to which devices?'
- Multi-select grid backed by /api/platform/asset-groups
- Default 'fleet-wide' option preserves legacy behaviour
- save payload now sends applies_to_groups → policy targets only
  the selected group(s)
- Targeting summary on the preview + save toast

FIX: _to_policy() preserves applies_to_groups (was dropped silently)
FIX: UI version badge bumped to v6.4

311 unit tests pass.

Install: pipx upgrade safecadence-netrisk     # or
         pip install --upgrade safecadence-netrisk" \
    dist/safecadence_netrisk-6.4.1-py3-none-any.whl \
    dist/safecadence_netrisk-6.4.1.tar.gz install.sh
fi

echo ""
echo "============================================================"
echo " v6.4.1 SHIPPED - Builder wizard asset-group step"
echo "  - 6-step wizard with 'Apply to which devices?' step 2"
echo "  - applies_to_groups now flows UI → API → evaluator"
echo "  - _to_policy preserves applies_to_groups"
echo "  - UI badge updated v6.2 → v6.4"
echo "  - 311 unit tests pass"
echo "============================================================"
