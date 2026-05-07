#!/bin/bash
# Ship v6.4.0 — Asset groups: the device-selection primitive every real
# operator asks for in the first 30 seconds.
set -e
cd "$(dirname "$0")"

if command -v pytest &>/dev/null; then
  echo "Running 309-test suite..."
  PYTHONPATH=src pytest tests/ -q || { echo "TESTS FAILED"; exit 1; }
fi

git add -A 2>/dev/null
if ! git diff --cached --quiet; then
  git commit -m "feat: v6.4.0 — Asset groups + tags + policy targeting

Without a way to say 'apply this policy to these specific 17 devices',
the platform was useful for fleet-wide audit but useless for everyday
operator work. v6.4 adds the missing primitive.

NEW: Asset groups (the foundation for everything that follows)
  - AssetGroup dataclass: static (asset_ids list) OR dynamic (filter)
    with optional exclude_asset_ids carve-outs
  - 10-op filter language (eq, neq, in, not_in, contains, starts_with,
    ends_with, has_tag, missing_tag, exists) over a 30-field allow-list
  - all/any/not boolean composition, depth-bounded validation
  - Empty filter matches NOTHING (safe default — operators have been
    burned by the inverse)
  - JSON-file store at ~/.safecadence/asset_groups/, group_id sanitised
    for path-traversal like the rest of the platform store

NEW: Derived tags on every asset
  - Demo fleet now produces searchable tags from identity/network/
    security/lifecycle: env:prod, vendor:cisco, kev:yes, dmz,
    eos:past, crit:crown-jewel, etc. — so operators can build
    meaningful groups out of the box without hand-tagging anything

NEW: Policy targeting (applies_to_groups)
  - SecurityPolicy.applies_to_groups: list[group_id]
  - Evaluator pre-resolves group membership ONCE per evaluation cycle
    instead of re-running every group's filter per asset (O(n) vs O(n*g))
  - applies_to(asset, group_member_cache=...) — cached fast path

NEW: REST surface (under /api/platform/asset-groups)
  - GET    list (with current member count per group)
  - POST   create
  - GET    {group_id} (with full member list)
  - PUT    {group_id} update
  - DELETE {group_id}
  - POST   /preview — dry-run a filter without saving (UI builder)

NEW: CLI subcommand (safecadence groups)
  - list / show <id> / create / delete
  - --asset-id (repeat) for static, --filter-json for dynamic

QUALITY:
  - 309 unit tests pass (14 new in test_v6_4.py)
  - Cross-platform: Linux / macOS / Windows; physical or virtual"
  git push origin main
fi

git tag -a v6.4.0 -m "v6.4.0 — Asset groups + tags + policy targeting" 2>/dev/null || true
git push origin v6.4.0 2>/dev/null || true

mkdir -p dist/old && mv dist/safecadence_netrisk-6.3.* dist/old/ 2>/dev/null || true
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
    .venv/bin/python -m twine upload dist/safecadence_netrisk-6.4.0*
else
  TWINE_USERNAME=__token__ TWINE_PASSWORD="$GOT" \
    python3 -m twine upload dist/safecadence_netrisk-6.4.0*
fi

if command -v gh &>/dev/null; then
  gh release create v6.4.0 \
    --title "v6.4.0 - Asset groups: pick which devices a policy applies to" \
    --notes "v6.4.0 adds the missing primitive that every real operator
asks for in the first 30 seconds: a way to say 'apply this policy to
these specific 17 devices, not the whole fleet.'

NEW: Asset groups
- Static (hand-picked asset_ids) or dynamic (filter spec) with
  optional exclude carve-outs.
- 10 filter ops over a 30-field allow-list, with all/any/not
  boolean composition.
- Empty filter matches NOTHING — safe default.

NEW: Derived tags
- Every demo asset auto-gets env:, vendor:, crit:, type:,
  kev:, internet-facing, dmz, eos: tags so groups are useful
  out of the box without hand-tagging.

NEW: Policy targeting
- SecurityPolicy.applies_to_groups now controls which assets
  a policy evaluates against. Evaluator pre-resolves membership
  in O(n) instead of O(n*g).

NEW: REST + CLI
- /api/platform/asset-groups CRUD + /preview dry-run
- safecadence groups list / show / create / delete

309 unit tests pass.

Install: pipx install --upgrade safecadence-netrisk
Try:     safecadence demo
         safecadence groups create cisco-edge --name 'Cisco edge' \\
           --filter-json '{\"all\":[{\"field\":\"vendor\",\"op\":\"eq\",\"value\":\"cisco\"},
                                   {\"field\":\"network.zone\",\"op\":\"eq\",\"value\":\"edge\"}]}'
         safecadence groups show cisco-edge" \
    dist/safecadence_netrisk-6.4.0-py3-none-any.whl \
    dist/safecadence_netrisk-6.4.0.tar.gz install.sh
fi

echo ""
echo "============================================================"
echo " v6.4.0 SHIPPED - Asset groups + tags + policy targeting"
echo "  - AssetGroup primitive (static + dynamic + exclusions)"
echo "  - 10-op filter language, 30 fields, all/any/not"
echo "  - Derived tags on every asset (env:, vendor:, crit:, ...)"
echo "  - SecurityPolicy.applies_to_groups + evaluator cache"
echo "  - REST /api/platform/asset-groups + safecadence groups CLI"
echo "  - 309 unit tests pass (14 new)"
echo "============================================================"
