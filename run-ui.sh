#!/usr/bin/env bash
# One-command local UI launcher.
#
#   bash run-ui.sh
#
# Creates the project venv on first run, installs the [server] extras
# only when they're missing, then starts the SafeCadence UI. Safe to
# re-run any time — subsequent runs skip straight to launch.

set -euo pipefail
cd "$(dirname "$0")"

if [ ! -d .venv ]; then
  echo "==> Creating virtualenv (.venv) — first run only"
  python3 -m venv .venv
fi

# Check the package itself AND the server deps — a venv left half-installed
# by an interrupted pip run self-heals here.
if ! ./.venv/bin/python -c "import safecadence, fastapi, uvicorn" 2>/dev/null; then
  echo "==> Installing SafeCadence with [server] extras"
  ./.venv/bin/pip install -q -e ".[server]"
fi

echo "==> Starting the SafeCadence UI (Ctrl+C to stop)"
exec ./.venv/bin/safecadence ui
