#!/usr/bin/env bash
# SafeCadence Device Intelligence Platform — one-command installer.
#
#   curl -fsSL https://safecadence.com/install.sh | bash
#
# Detects platform + available tooling and offers the cleanest install path:
#   1. pipx (preferred for Python users — isolated, on-PATH)
#   2. pip   (fallback when only pip is available)
#   3. docker (chosen when --docker flag passed OR Python isn't available)
#
# Cross-platform: macOS (Intel/Apple Silicon), Linux (any glibc/musl distro), and
# Windows via WSL or Git-Bash. Pure bash, no curl-piped sudo, no surprises.

set -euo pipefail

# ----- styling -----
if [[ -t 1 ]]; then
  C_BOLD=$'\e[1m'; C_DIM=$'\e[2m'; C_RED=$'\e[31m'; C_GREEN=$'\e[32m'
  C_YELLOW=$'\e[33m'; C_BLUE=$'\e[34m'; C_RESET=$'\e[0m'
else
  C_BOLD=""; C_DIM=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_RESET=""
fi
say()  { printf "%s%s%s\n" "$C_BLUE" "» $*" "$C_RESET"; }
ok()   { printf "%s%s%s\n" "$C_GREEN" "✓ $*" "$C_RESET"; }
warn() { printf "%s%s%s\n" "$C_YELLOW" "! $*" "$C_RESET"; }
die()  { printf "%s%s%s\n" "$C_RED" "✗ $*" "$C_RESET" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# ----- args -----
MODE="auto"
NO_LAUNCH=0
for arg in "$@"; do
  case "$arg" in
    --docker)    MODE="docker" ;;
    --pipx)      MODE="pipx" ;;
    --pip)       MODE="pip" ;;
    --auto)      MODE="auto" ;;
    --no-launch) NO_LAUNCH=1 ;;
    --help|-h)
      cat <<EOF
SafeCadence Device Intelligence Platform — installer

Usage:
  curl -fsSL https://safecadence.com/install.sh | bash
  curl -fsSL https://safecadence.com/install.sh | bash -s -- --docker
  curl -fsSL https://safecadence.com/install.sh | bash -s -- --pipx --no-launch

Modes:
  --auto    (default) pick the best available: pipx → pip → docker
  --pipx    install via pipx (recommended for Python users)
  --pip     install via system pip (with --break-system-packages on PEP-668 distros)
  --docker  pull and run the Docker image (no Python needed)

Options:
  --no-launch  install only, don't open the local UI when finished
  --help       show this message
EOF
      exit 0 ;;
    *) die "unknown option: $arg" ;;
  esac
done

# ----- platform -----
OS="$(uname -s)"
ARCH="$(uname -m)"
case "$OS" in
  Darwin)  PLATFORM="macos"   ;;
  Linux)   PLATFORM="linux"   ;;
  MINGW*|MSYS*|CYGWIN*) PLATFORM="windows-bash" ;;
  *)       PLATFORM="unknown" ;;
esac

say "SafeCadence installer  · platform: $PLATFORM ($ARCH) · mode: $MODE"

# ----- pick a method -----
choose_method() {
  if [[ "$MODE" != "auto" ]]; then echo "$MODE"; return; fi
  if   have pipx   && have python3; then echo "pipx"
  elif have pip3   || have pip;     then echo "pip"
  elif have docker;                  then echo "docker"
  else echo "none"
  fi
}

METHOD="$(choose_method)"

# ----- installers -----
install_via_pipx() {
  say "Installing via pipx (isolated venv, added to PATH)"
  pipx install safecadence-netrisk --force >/dev/null
  pipx ensurepath >/dev/null 2>&1 || true
  ok  "Installed safecadence (pipx)"
}

install_via_pip() {
  say "Installing via pip"
  local pip_cmd="pip3"; have pip3 || pip_cmd="pip"
  # Some distros (Debian 12+, Ubuntu 24+) require --break-system-packages
  local extra=""
  if "$pip_cmd" install --help 2>/dev/null | grep -q -- '--break-system-packages'; then
    extra="--break-system-packages"
  fi
  "$pip_cmd" install --user --upgrade $extra "safecadence-netrisk[server]" >/dev/null
  ok  "Installed safecadence-netrisk[server] (pip)"
  # Make sure ~/.local/bin is on PATH
  case ":$PATH:" in
    *":$HOME/.local/bin:"*) ;;
    *) warn "Add this to your shell profile so 'safecadence' is on PATH:"
       echo  "    export PATH=\"\$HOME/.local/bin:\$PATH\"" ;;
  esac
}

install_via_docker() {
  have docker || die "Docker isn't installed. Install Docker Desktop or run --pipx instead."
  say "Pulling fkarim1/netrisk:latest"
  docker pull fkarim1/netrisk:latest >/dev/null
  ok "Image ready: fkarim1/netrisk:latest"
  say "Convenience wrapper at ~/.local/bin/safecadence (uses Docker under the hood)"
  mkdir -p "$HOME/.local/bin"
  cat > "$HOME/.local/bin/safecadence" <<'WRAPPER'
#!/usr/bin/env bash
# SafeCadence Docker wrapper — preserves cwd as /work and persistent state in sc-data.
exec docker run --rm -it -p 8765:8765 -v "$PWD:/work" -v sc-data:/data \
  fkarim1/netrisk:latest "$@"
WRAPPER
  chmod +x "$HOME/.local/bin/safecadence"
  case ":$PATH:" in
    *":$HOME/.local/bin:"*) ;;
    *) warn "Add ~/.local/bin to PATH (e.g. echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.zshrc)" ;;
  esac
  ok "Wrapper installed: safecadence ..."
}

case "$METHOD" in
  pipx)    install_via_pipx ;;
  pip)     install_via_pip ;;
  docker)  install_via_docker ;;
  none)    die "No supported install method found. Install one of: pipx, pip3, docker." ;;
  *)       die "unknown METHOD: $METHOD" ;;
esac

# ----- launch -----
echo
ok "$C_BOLD SafeCadence v5.0.0 installed.$C_RESET"
cat <<EOF

Quick start:

  ${C_BOLD}safecadence ui${C_RESET}                   open the local web UI (http://127.0.0.1:8765)
  ${C_BOLD}safecadence policy templates${C_RESET}     list 10 built-in security policy templates
  ${C_BOLD}safecadence policy interpret "..."${C_RESET}  plain-English → structured policy
  ${C_BOLD}safecadence --help${C_RESET}               full CLI reference

Docs:   https://github.com/famousleads/safecadence-network-risk
PyPI:   https://pypi.org/project/safecadence-netrisk/

EOF

if [[ "$NO_LAUNCH" != "1" ]] && have safecadence; then
  say "Launching local UI (Ctrl-C to stop)..."
  exec safecadence ui
fi
