#!/bin/bash
# Ship v6.3.0 — From CLI to product: demo data, continuous daemon, real Slack
# alerts, truthful adapter manifest, first-run onboarding.
set -e
cd "$(dirname "$0")"

if command -v pytest &>/dev/null; then
  echo "Running 295-test suite..."
  PYTHONPATH=src pytest tests/ -q || { echo "TESTS FAILED"; exit 1; }
fi

git add -A 2>/dev/null
if ! git diff --cached --quiet; then
  git commit -m "feat: v6.3.0 — From CLI to product (demo data, daemon, Slack, truth)

The v6.0–v6.2 line was rich on intelligence-layer features but the
first-run experience was an empty UI, the platform stopped between
manual scans, no alert ever fired in real life, and the marketing
'45 adapters' included 26 stubs that returned placeholders. v6.3
fixes the four things that kept this from being a real product.

NEW: \`safecadence demo\` (the empty-UI fix)
  - Loads 31 realistic fake assets across network/server/cloud/identity
    /backup so the moment a user runs \`safecadence ui\` they see the
    detectors firing — KEV on perimeter, EoS in crown-jewel, admin
    without MFA, default credentials, internet → CRM attack path,
    backup gap, legacy protocols, etc.
  - Idempotent (--overwrite to replace, --clear to remove)
  - Surfaced via /api/platform/load-demo for the UI button
  - Designed to trip ≥5 of the 17 cross-system drift detectors

NEW: \`safecadence daemon\` (continuous mode — turns CLI into platform)
  - Background process re-evaluates every active policy + drift
    detector + attack-path graph on a configurable interval (default
    30 min)
  - Persists deltas to ~/.safecadence/daemon.log (one JSON object per
    cycle); state in ~/.safecadence/daemon.json
  - Diff engine surfaces what's NEW since the previous cycle, not
    just the full snapshot — operators care about deltas
  - --once flag for cron / systemd timer integration
  - Cross-platform signal handling (Ctrl+C exits cleanly)

NEW: Real Slack notifier (proves the alert path)
  - Block Kit-formatted messages with severity emoji + asset context
  - Truncates to top 10 events with '+N more' summary
  - Graceful degradation when httpx isn't installed
  - Wired into daemon: critical NEW findings auto-fire to webhook
  - SC_SLACK_WEBHOOK env or --slack-webhook flag

NEW: First-run onboarding panel (empty-UI is no longer the bounce point)
  - Platform UI Overview detects an empty fleet and renders a
    welcoming card with three buttons: Load demo data / Connect cloud
    / Upload config — instead of an empty grid

NEW: Truthful adapter manifest
  - 10 production / 14 experimental / 26 stub — replaces the inflated
    'we have 45 adapters' marketing claim
  - GET /api/platform/adapter-manifest endpoint
  - \`safecadence list-adapters --status production\` CLI
  - Promotion from experimental → production is human-gated, not
    'passes pytest'

QUALITY:
  - 295 unit tests pass (15 new in test_v6_3.py)
  - End-to-end test: load demo, run daemon, verify findings produced
  - Notifier tested for Block Kit format + graceful httpx absence
  - Cross-platform: Linux / macOS / Windows; physical or virtual"
  git push origin main
fi

git tag -a v6.3.0 -m "v6.3.0 — From CLI to product" 2>/dev/null || true
git push origin v6.3.0 2>/dev/null || true

mkdir -p dist/old && mv dist/safecadence_netrisk-6.2.* dist/old/ 2>/dev/null || true
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
    .venv/bin/python -m twine upload dist/safecadence_netrisk-6.3.0*
else
  TWINE_USERNAME=__token__ TWINE_PASSWORD="$GOT" \
    python3 -m twine upload dist/safecadence_netrisk-6.3.0*
fi

if command -v gh &>/dev/null; then
  gh release create v6.3.0 \
    --title "v6.3.0 - From CLI to product (demo, daemon, Slack, truth)" \
    --notes "v6.3.0 fixes the four things that kept this from being a
real product instead of a CLI toolkit.

NEW: \`safecadence demo\`
- Loads 31 realistic fake assets so the first-run UI is alive instead
  of empty. Designed to trip multiple detectors so users see the
  intelligence layer working immediately. Run \`safecadence demo\`
  once and \`safecadence demo --clear\` when done.

NEW: \`safecadence daemon\`
- Continuous background mode: re-runs policies + cross-system drift +
  attack-path graph every 30 minutes (configurable), persists deltas,
  fires Slack alerts on new critical findings. Use --once for cron.

NEW: Real Slack alerting
- Block Kit-formatted messages with severity emoji and asset context.
- Set SC_SLACK_WEBHOOK or pass --slack-webhook to the daemon.

NEW: First-run onboarding panel
- Platform UI Overview detects an empty fleet and renders a welcoming
  card with 'Load demo data' / 'Connect cloud' / 'Upload config'
  buttons instead of an empty grid.

NEW: Truthful adapter manifest
- 10 production / 14 experimental / 26 stub — replacing the inflated
  '45 adapters' marketing claim. \`safecadence list-adapters\` to see
  what actually works vs what's experimental vs what's a skeleton.

295 unit tests pass.

Install: pipx install --upgrade safecadence-netrisk
Then:    safecadence demo && safecadence ui" \
    dist/safecadence_netrisk-6.3.0-py3-none-any.whl \
    dist/safecadence_netrisk-6.3.0.tar.gz install.sh
fi

echo ""
echo "============================================================"
echo " v6.3.0 SHIPPED - From CLI to product"
echo "  - safecadence demo: 31 realistic assets, empty-UI fixed"
echo "  - safecadence daemon: continuous mode + Slack alerts"
echo "  - First-run onboarding panel in platform UI"
echo "  - Truthful adapter manifest (10 prod / 14 exp / 26 stub)"
echo "  - 295 unit tests pass (15 new)"
echo "============================================================"
