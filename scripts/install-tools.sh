#!/usr/bin/env bash
# Installs the external scanner tools BANNIN's plugins shell out to:
# semgrep, osv-scanner, trivy, gitleaks, checkov, and OWASP ZAP (zap.sh
# on PATH). It does NOT install Go or Node — those are build-time
# prerequisites for BANNIN itself, checked (not installed) here, since
# forcing a language runtime install is much higher-risk than adding a
# CLI tool and most dev machines already have an opinion about how they
# want Go/Node managed.
#
# Idempotent: every tool is skipped if already on PATH. Safe to re-run.
#
# Usage:
#   ./scripts/install-tools.sh              # install everything
#   ./scripts/install-tools.sh --only zap    # install just one tool
#   ./scripts/install-tools.sh --ci          # non-interactive (CI runners)
#   ./scripts/install-tools.sh --skip-zap    # everything except ZAP
#
# Supports macOS (Homebrew) and Debian/Ubuntu Linux (apt). Other
# platforms get manual-install instructions printed instead of a
# blind attempt.

set -euo pipefail

ONLY=""
CI_MODE=false
SKIP_ZAP=false

while [ $# -gt 0 ]; do
  case "$1" in
    --only) ONLY="$2"; shift 2 ;;
    --ci) CI_MODE=true; shift ;;
    --skip-zap) SKIP_ZAP=true; shift ;;
    -h|--help)
      sed -n '2,20p' "$0"
      exit 0
      ;;
    *) echo "unknown flag: $1" >&2; exit 1 ;;
  esac
done

OS="$(uname -s)"
ARCH="$(uname -m)"

have() { command -v "$1" >/dev/null 2>&1; }

wants() {
  # wants <tool>: true unless --only restricts to a different tool.
  [ -z "$ONLY" ] || [ "$ONLY" = "$1" ]
}

log()  { printf '\n\033[1;36m==>\033[0m %s\n' "$1"; }
ok()   { printf '  \033[1;32m✓\033[0m %s\n' "$1"; }
warn() { printf '  \033[1;33m!\033[0m %s\n' "$1"; }

BREW_AVAILABLE=false
APT_AVAILABLE=false
if [ "$OS" = "Darwin" ] && have brew; then BREW_AVAILABLE=true; fi
if [ "$OS" = "Linux" ] && have apt-get; then APT_AVAILABLE=true; fi

# ---- semgrep ---------------------------------------------------------
install_semgrep() {
  wants semgrep || return 0
  log "semgrep"
  if have semgrep; then ok "already installed ($(semgrep --version))"; return 0; fi
  if $BREW_AVAILABLE; then brew install semgrep
  elif have pipx; then pipx install semgrep
  elif have pip3; then pip3 install --user semgrep
  else warn "no supported installer found; see https://semgrep.dev/docs/getting-started/"; return 0
  fi
  ok "installed"
}

# ---- osv-scanner -------------------------------------------------------
install_osv_scanner() {
  wants osv-scanner || return 0
  log "osv-scanner"
  if have osv-scanner; then ok "already installed ($(osv-scanner --version 2>&1 | head -1))"; return 0; fi
  if $BREW_AVAILABLE; then brew install osv-scanner
  elif have go; then go install github.com/google/osv-scanner/cmd/osv-scanner@latest
  else warn "no supported installer found; see https://github.com/google/osv-scanner#installation"; return 0
  fi
  ok "installed"
}

# ---- trivy -------------------------------------------------------------
install_trivy() {
  wants trivy || return 0
  log "trivy"
  if have trivy; then ok "already installed ($(trivy --version | head -1))"; return 0; fi
  if $BREW_AVAILABLE; then
    brew install trivy
  elif $APT_AVAILABLE; then
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
      | sh -s -- -b /usr/local/bin
  else
    warn "no supported installer found; see https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
    return 0
  fi
  ok "installed"
}

# ---- gitleaks ------------------------------------------------------------
install_gitleaks() {
  wants gitleaks || return 0
  log "gitleaks"
  if have gitleaks; then ok "already installed ($(gitleaks version))"; return 0; fi
  if $BREW_AVAILABLE; then brew install gitleaks
  elif have go; then go install github.com/gitleaks/gitleaks/v8@latest
  else warn "no supported installer found; see https://github.com/gitleaks/gitleaks#installing"; return 0
  fi
  ok "installed"
}

# ---- checkov ---------------------------------------------------------------
install_checkov() {
  wants checkov || return 0
  log "checkov"
  if have checkov; then ok "already installed ($(checkov --version))"; return 0; fi
  if $BREW_AVAILABLE; then brew install checkov
  elif have pipx; then pipx install checkov
  elif have pip3; then pip3 install --user checkov
  else warn "no supported installer found; see https://www.checkov.io/2.Basics/Installing%20Checkov.html"; return 0
  fi
  ok "installed"
}

# ---- OWASP ZAP -------------------------------------------------------------
# plugins/zap invokes "zap.sh" directly via PATH lookup (no Docker
# indirection), so installation has to end with zap.sh reachable on
# PATH, not just "ZAP is installed somewhere."
install_zap() {
  $SKIP_ZAP && return 0
  wants zap || return 0
  log "OWASP ZAP"
  if have zap.sh; then ok "already installed ($(zap.sh -version 2>&1 | head -1))"; return 0; fi

  if [ "$OS" = "Darwin" ] && $BREW_AVAILABLE; then
    brew install --cask zaproxy
    local app="/Applications/OWASP ZAP.app/Contents/Java/zap.sh"
    if [ -f "$app" ]; then
      local bindir
      bindir="$(brew --prefix)/bin"
      chmod +x "$app"
      ln -sf "$app" "$bindir/zap.sh"
      ok "installed, symlinked into $bindir"
    else
      warn "cask installed but $app not found — open OWASP ZAP.app once, or symlink its zap.sh onto PATH manually"
    fi
    return 0
  fi

  if [ "$OS" = "Linux" ]; then
    if ! have java; then
      if $APT_AVAILABLE; then
        warn "installing openjdk (ZAP requires Java 11+)"
        sudo apt-get update -y && sudo apt-get install -y default-jre-headless
      else
        warn "ZAP requires Java 11+ and none was found; install a JRE first"
        return 0
      fi
    fi

    log "fetching latest ZAP release metadata"
    local asset_url
    asset_url="$(curl -sfL https://api.github.com/repos/zaproxy/zaproxy/releases/latest \
      | grep -o '"browser_download_url": *"[^"]*Linux\.tar\.gz"' \
      | head -1 | sed -E 's/.*"(https[^"]+)"/\1/')"
    if [ -z "$asset_url" ]; then
      warn "couldn't resolve the latest ZAP download automatically; see https://www.zaproxy.org/download/"
      return 0
    fi

    local install_dir="${HOME}/.local/opt/zap"
    mkdir -p "$install_dir"
    log "downloading $asset_url"
    curl -sfL "$asset_url" | tar xz -C "$install_dir" --strip-components=1

    local bindir="${HOME}/.local/bin"
    mkdir -p "$bindir"
    chmod +x "$install_dir/zap.sh"
    ln -sf "$install_dir/zap.sh" "$bindir/zap.sh"
    ok "installed to $install_dir, symlinked into $bindir"
    case ":$PATH:" in
      *":$bindir:"*) ;;
      *) warn "$bindir is not on PATH — add \`export PATH=\"$bindir:\$PATH\"\` to your shell profile" ;;
    esac
    return 0
  fi

  warn "unsupported platform for automatic ZAP install; see https://www.zaproxy.org/download/"
}

if $CI_MODE; then
  export DEBIAN_FRONTEND=noninteractive
fi

install_semgrep
install_osv_scanner
install_trivy
install_gitleaks
install_checkov
install_zap

log "prerequisite check (not installed by this script)"
if have go; then ok "go: $(go version)"; else warn "go not found — https://go.dev/dl/ (BANNIN needs 1.24+)"; fi
if have node; then ok "node: $(node --version)"; else warn "node not found — https://nodejs.org/ (needed for web/, the dashboard frontend)"; fi

log "summary"
for t in semgrep osv-scanner trivy gitleaks checkov zap.sh; do
  if have "$t"; then ok "$t"; else warn "$t — not on PATH"; fi
done
echo
echo "Re-run this script any time; already-installed tools are skipped."
