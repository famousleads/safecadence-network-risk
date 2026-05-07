#!/usr/bin/env bash
# SafeCadence one-shot bootstrap.
#
#   curl-and-pray, but local: rebuilds the .venv on a Python that can actually
#   run v7.4, installs the in-repo source with all extras, loads demo data,
#   resets the admin password, and starts the local UI on a non-conflicting
#   port. Idempotent — safe to re-run.
#
# Usage:
#   ./bootstrap.sh                    # interactive password prompt
#   SC_PORT=8780 ./bootstrap.sh       # custom port
#   SC_PASSWORD=... ./bootstrap.sh    # non-interactive
set -eu

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${SC_PORT:-8766}"

cd "$REPO"

# ---------------------------------------------------------------- step 1
# Find a Python interpreter ≥ 3.11 (3.10 works but 3.11 is the modern floor
# and what we test against).
echo "▸ Finding a usable Python interpreter…"
PY=""
for candidate in python3.13 python3.12 python3.11 python3.10; do
  if command -v "$candidate" >/dev/null 2>&1; then
    PY="$(command -v "$candidate")"
    echo "  ✓ Using $PY ($("$PY" --version))"
    break
  fi
done
if [ -z "$PY" ]; then
  echo "  ✗ No Python ≥ 3.10 found on PATH."
  echo "    Install one with:  brew install python@3.12"
  echo "    Then re-run this script."
  exit 1
fi

# ---------------------------------------------------------------- step 2
# Build (or rebuild) the venv. If the existing one is on the wrong Python,
# blow it away — editable installs cache fast, so this is cheap.
VENV="$REPO/.venv"
EXPECTED_VER="$(grep -E '^version = "' "$REPO/pyproject.toml" | head -1 | sed 's/version = "\(.*\)"/\1/')"
MARKER="$VENV/.safecadence_installed_version"
LAST_VER=""
[ -f "$MARKER" ] && LAST_VER="$(cat "$MARKER" 2>/dev/null || true)"

# Reuse the venv ONLY when the marker exactly matches the expected
# version AND a smoke test of the entry point still works. PEP 660
# editable installs on Python 3.13 are flaky between version bumps and
# leave .pth state that races at import time. Forcing a clean rebuild
# whenever the version moves (or the marker is missing) is the cheapest
# path to "always works".
SHOULD_REBUILD=1
if [ -x "$VENV/bin/python" ] && [ "$LAST_VER" = "$EXPECTED_VER" ]; then
  if "$VENV/bin/python" -c "from safecadence.cli import cli" 2>/dev/null \
     && "$VENV/bin/safecadence" admin reset-password --help >/dev/null 2>&1 ; then
    SHOULD_REBUILD=0
  fi
fi

if [ "$SHOULD_REBUILD" = "1" ]; then
  if [ -d "$VENV" ]; then
    echo "▸ Rebuilding .venv from scratch (cheap, reliable, ≈30s)…"
  else
    echo "▸ Building .venv on Python from $PY…"
  fi
  rm -rf "$VENV"
  "$PY" -m venv "$VENV"
else
  echo "▸ Reusing existing .venv (last installed: $LAST_VER)"
fi

# Activate
# shellcheck disable=SC1091
source "$VENV/bin/activate"

# Sanity check the venv has a working pip. Some venv rebuilds can leave
# pip half-installed (no __main__.py) which makes `python -m pip` fail
# with "No module named pip.__main__". Detect and recreate.
if ! python -m pip --version >/dev/null 2>&1; then
  echo "▸ pip is broken in the existing venv — recreating from scratch…"
  deactivate 2>/dev/null || true
  rm -rf "$VENV"
  "$PY" -m venv "$VENV"
  # shellcheck disable=SC1091
  source "$VENV/bin/activate"
  python -m ensurepip --upgrade >/dev/null 2>&1 || true
fi

# ---------------------------------------------------------------- step 3
echo "▸ Upgrading pip / setuptools / wheel…"
python -m pip install --quiet --upgrade pip setuptools wheel

# ---------------------------------------------------------------- step 4
# Force-clean any prior install in this venv. Editable installs from
# different versions can leave multiple `__editable__.*.pth` files
# behind, which race at import time and produce intermittent
# ModuleNotFoundError. Uninstalling first guarantees the install is
# the only one in site-packages.
echo "▸ Installing safecadence-netrisk from this repo (editable, with [server,ai,vault])…"
# Belt-and-suspenders: pip uninstall + manual cleanup of any stragglers
# left from previous editable installs, then fresh install.
python -m pip uninstall --quiet -y safecadence-netrisk 2>/dev/null || true
find "$VENV/lib" -maxdepth 5 \( -name "__editable__.*safecadence*" -o \
                                 -name "_editable_impl_safecadence*" -o \
                                 -name "safecadence_netrisk-*.dist-info" \) \
                 -exec rm -rf {} + 2>/dev/null || true
python -m pip install --quiet -e ".[server,ai,vault]"
# Stamp the marker so the next bootstrap run knows what's installed.
echo "$EXPECTED_VER" > "$VENV/.safecadence_installed_version"

INSTALLED_VER="$(safecadence --version 2>&1 | awk '{print $NF}')"
echo "  ✓ safecadence --version: $INSTALLED_VER"
# Accept any current major (7+). Semver moves forward; the bootstrap
# shouldn't need a release-time edit for every minor bump.
case "$INSTALLED_VER" in
  7.*|8.*|9.*) : ;;
  *) echo "  ✗ Expected v7+, got $INSTALLED_VER — abort."; exit 1 ;;
esac

# Sanity check — partial / broken editable installs can leave a working
# `safecadence --version` while the *console_script* entry can't import.
# Exercise the same path the wrapper uses (a fresh subprocess) so we
# detect race-prone .pth state instead of relying on an in-process
# import that may be served from a stale cache.
if ! python -c "import safecadence, safecadence.cli; from safecadence.cli import cli" 2>/dev/null \
   || ! safecadence --help >/dev/null 2>&1 \
   || ! safecadence admin --help >/dev/null 2>&1 ; then
  echo "  ✗ safecadence install is broken — rebuilding venv from scratch…"
  deactivate 2>/dev/null || true
  rm -rf "$VENV"
  "$PY" -m venv "$VENV"
  # shellcheck disable=SC1091
  source "$VENV/bin/activate"
  python -m pip install --quiet --upgrade pip setuptools wheel
  python -m pip install --quiet -e ".[server,ai,vault]"
  safecadence --help >/dev/null   # must succeed now
  echo "  ✓ rebuilt — safecadence is fully usable"
fi

# ---------------------------------------------------------------- step 5
# Make sure nothing else is on $PORT.
if lsof -tiTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "▸ Killing existing listener on :$PORT…"
  lsof -tiTCP:"$PORT" -sTCP:LISTEN | xargs kill -9 || true
  sleep 1
fi

# ---------------------------------------------------------------- step 6
echo "▸ Loading demo data (31-asset realistic fleet)…"
safecadence demo >/dev/null 2>&1 || true

# ---------------------------------------------------------------- step 7
# Reset (or set) the admin password. If SC_PASSWORD isn't given, prompt.
if [ -z "${SC_PASSWORD:-}" ]; then
  printf "▸ Pick an admin password (won't be echoed): "
  stty -echo
  read -r SC_PASSWORD
  stty echo
  echo
fi
safecadence admin reset-password -u admin -p "$SC_PASSWORD" >/dev/null
echo "  ✓ Admin password set"

# ---------------------------------------------------------------- step 8
echo
echo "════════════════════════════════════════════════════════════"
echo "  SafeCadence v$INSTALLED_VER ready"
echo "  URL:      http://127.0.0.1:$PORT"
echo "  Username: admin"
echo "  Password: (the one you just typed)"
echo "  Stop:     Ctrl+C in this terminal"
echo "════════════════════════════════════════════════════════════"
echo
exec safecadence ui --port "$PORT" --password "$SC_PASSWORD"
