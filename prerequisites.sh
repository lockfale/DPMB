#!/usr/bin/env bash
# ============================================================================
# 802.11DPMB — Prerequisites Installer
# Installs system packages required by setup.sh.
# Supports: Ubuntu/Debian (apt), Fedora/RHEL (dnf), Arch (pacman)
# ============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

ok()   { printf "  ${GREEN}OK${NC}    %s\n" "$1"; }
warn() { printf "  ${YELLOW}WARN${NC}  %s\n" "$1"; }
fail() { printf "  ${RED}FAIL${NC}  %s\n" "$1"; exit 1; }
info() { printf "  ${BOLD}...${NC}   %s\n" "$1"; }

printf "\n${CYAN}${BOLD}Installing 802.11DPMB prerequisites${NC}\n\n"

# --------------------------------------------------------------------------
# Detect package manager
# --------------------------------------------------------------------------
if command -v apt-get &>/dev/null; then
    PKG_MGR="apt"
elif command -v dnf &>/dev/null; then
    PKG_MGR="dnf"
elif command -v pacman &>/dev/null; then
    PKG_MGR="pacman"
else
    fail "No supported package manager found (need apt, dnf, or pacman)."
fi
ok "Package manager: ${PKG_MGR}"

# --------------------------------------------------------------------------
# Package name mapping per distro
# --------------------------------------------------------------------------
declare -A APT_PKGS=(
    [python3]="python3"
    [pip]="python3-pip"
    [venv]="python3-venv"
    [systemd]="python3-systemd"
    [iw]="iw"
    [git]="git"
)

declare -A DNF_PKGS=(
    [python3]="python3"
    [pip]="python3-pip"
    [venv]="python3-libs"
    [systemd]="python3-systemd"
    [iw]="iw"
    [git]="git"
)

declare -A PACMAN_PKGS=(
    [python3]="python"
    [pip]="python-pip"
    [venv]="python"
    [systemd]="python-systemd"
    [iw]="iw"
    [git]="git"
)

# --------------------------------------------------------------------------
# Check what's missing
# --------------------------------------------------------------------------
MISSING=()

# python3
if ! command -v python3 &>/dev/null; then
    MISSING+=("python3")
else
    ok "python3 $(python3 --version 2>&1 | awk '{print $2}')"
fi

# pip
if ! python3 -m pip --version &>/dev/null 2>&1; then
    MISSING+=("pip")
else
    ok "pip $(python3 -m pip --version 2>/dev/null | awk '{print $2}')"
fi

# venv
if ! python3 -m venv --help &>/dev/null 2>&1; then
    MISSING+=("venv")
else
    ok "python3-venv"
fi

# python3-systemd
if python3 -c "import systemd.daemon" &>/dev/null 2>&1; then
    ok "python3-systemd"
else
    MISSING+=("systemd")
fi

# iw
if ! command -v iw &>/dev/null; then
    MISSING+=("iw")
else
    ok "iw $(iw --version 2>/dev/null | awk '{print $NF}' || echo 'present')"
fi

# git
if ! command -v git &>/dev/null; then
    MISSING+=("git")
else
    ok "git $(git --version 2>/dev/null | awk '{print $3}')"
fi

# --------------------------------------------------------------------------
# Install missing packages
# --------------------------------------------------------------------------
if [[ ${#MISSING[@]} -eq 0 ]]; then
    printf "\n${GREEN}${BOLD}All prerequisites already installed.${NC}\n\n"
    exit 0
fi

printf "\n"
info "Missing packages: ${MISSING[*]}"
info "Installing via ${PKG_MGR}..."

# Build install list from package map
INSTALL_LIST=()
for key in "${MISSING[@]}"; do
    case "$PKG_MGR" in
        apt)    INSTALL_LIST+=("${APT_PKGS[$key]}") ;;
        dnf)    INSTALL_LIST+=("${DNF_PKGS[$key]}") ;;
        pacman) INSTALL_LIST+=("${PACMAN_PKGS[$key]}") ;;
    esac
done

# Deduplicate
INSTALL_LIST=($(printf '%s\n' "${INSTALL_LIST[@]}" | sort -u))

case "$PKG_MGR" in
    apt)
        apt-get update -qq
        apt-get install -y "${INSTALL_LIST[@]}"
        ;;
    dnf)
        dnf install -y "${INSTALL_LIST[@]}"
        ;;
    pacman)
        pacman -Sy --noconfirm "${INSTALL_LIST[@]}"
        ;;
esac

printf "\n"
ok "Installed: ${INSTALL_LIST[*]}"

# --------------------------------------------------------------------------
# Verify python version
# --------------------------------------------------------------------------
PYTHON_VERSION="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
PYTHON_MAJOR="${PYTHON_VERSION%%.*}"
PYTHON_MINOR="${PYTHON_VERSION##*.}"

if [[ "$PYTHON_MAJOR" -lt 3 ]] || { [[ "$PYTHON_MAJOR" -eq 3 ]] && [[ "$PYTHON_MINOR" -lt 11 ]]; }; then
    warn "Python ${PYTHON_VERSION} found but >= 3.11 required."
    warn "You may need to install a newer Python from a PPA or pyenv."
else
    ok "Python ${PYTHON_VERSION} (>= 3.11)"
fi

printf "\n${GREEN}${BOLD}Prerequisites ready. Run setup.sh next.${NC}\n\n"
