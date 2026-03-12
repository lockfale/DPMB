#!/usr/bin/env bash
# ============================================================================
# 802.11DPMB — Setup Script
# Takes a fresh clone to a running DPMB system.
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DPMB_VENV="${DPMB_VENV:-/opt/dpmb/venv}"

# --------------------------------------------------------------------------
# Color helpers
# --------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

step_num=0

header() {
    step_num=$((step_num + 1))
    printf "\n${CYAN}${BOLD}[%d] %s${NC}\n" "$step_num" "$1"
}

ok()   { printf "  ${GREEN}OK${NC}    %s\n" "$1"; }
warn() { printf "  ${YELLOW}WARN${NC}  %s\n" "$1"; }
fail() { printf "  ${RED}FAIL${NC}  %s\n" "$1"; exit 1; }
info() { printf "  ${BOLD}...${NC}   %s\n" "$1"; }

# ============================================================================
# Step 1: Check root
# ============================================================================
header "Checking root privileges"

if [[ $EUID -ne 0 ]]; then
    fail "This script must be run as root (use sudo)."
fi
ok "Running as root."

# ============================================================================
# Step 2: Install / verify prerequisites
# ============================================================================
header "Installing prerequisites"

bash "${SCRIPT_DIR}/prerequisites.sh"

# Final gate — verify Python version
PYTHON_VERSION="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
PYTHON_MAJOR="${PYTHON_VERSION%%.*}"
PYTHON_MINOR="${PYTHON_VERSION##*.}"

if [[ "$PYTHON_MAJOR" -lt 3 ]] || { [[ "$PYTHON_MAJOR" -eq 3 ]] && [[ "$PYTHON_MINOR" -lt 11 ]]; }; then
    fail "Python >= 3.11 required (found $PYTHON_VERSION)."
fi
ok "All prerequisites satisfied."

# ============================================================================
# Step 3: Detect monitor-mode capable WiFi interfaces
# ============================================================================
header "Detecting monitor-mode capable WiFi interfaces"

declare -A PHY_TO_IFACES

# Parse iw phy output: find phys that support monitor mode
current_phy=""
in_supported_modes=0

while IFS= read -r line; do
    # Detect new phy block
    if [[ "$line" =~ ^Wiphy\ (phy[0-9]+) ]]; then
        current_phy="${BASH_REMATCH[1]}"
        in_supported_modes=0
        continue
    fi

    # Detect "Supported interface modes:" section
    if [[ "$line" =~ "Supported interface modes:" ]]; then
        in_supported_modes=1
        continue
    fi

    # If we are inside the supported modes block, look for "monitor"
    if [[ $in_supported_modes -eq 1 ]]; then
        # The section ends when a line does not start with whitespace + *
        if [[ "$line" =~ ^[[:space:]]+\*[[:space:]] ]]; then
            if [[ "$line" =~ monitor ]]; then
                PHY_TO_IFACES["$current_phy"]=""
            fi
        else
            in_supported_modes=0
        fi
    fi
done < <(iw phy 2>/dev/null || true)

if [[ ${#PHY_TO_IFACES[@]} -eq 0 ]]; then
    warn "No monitor-mode capable wireless interfaces detected."
    warn "You can still install DPMB and configure an interface later."
else
    # Map each phy to its network interface(s) via /sys/class/net
    for iface_path in /sys/class/net/*/phy80211; do
        [[ -e "$iface_path" ]] || continue
        iface_name="$(basename "$(dirname "$iface_path")")"
        iface_phy="$(basename "$(readlink -f "$iface_path/device/..")" 2>/dev/null || cat "$iface_path/../phy80211/name" 2>/dev/null || true)"

        # Try another method: read the phy name from the symlink
        if [[ -z "$iface_phy" ]] || [[ ! -v PHY_TO_IFACES["$iface_phy"] ]]; then
            iface_phy="$(basename "$(readlink -f "$iface_path")" 2>/dev/null || true)"
        fi

        if [[ -n "$iface_phy" ]] && [[ -v PHY_TO_IFACES["$iface_phy"] ]]; then
            if [[ -z "${PHY_TO_IFACES[$iface_phy]}" ]]; then
                PHY_TO_IFACES["$iface_phy"]="$iface_name"
            else
                PHY_TO_IFACES["$iface_phy"]="${PHY_TO_IFACES[$iface_phy]}, $iface_name"
            fi
        fi
    done

    # Also try iw dev to map phys to interfaces (more reliable)
    current_phy=""
    while IFS= read -r line; do
        if [[ "$line" =~ ^phy#([0-9]+) ]]; then
            current_phy="phy${BASH_REMATCH[1]}"
        elif [[ "$line" =~ Interface[[:space:]]+(.+) ]]; then
            iface_name="${BASH_REMATCH[1]}"
            if [[ -n "$current_phy" ]] && [[ -v PHY_TO_IFACES["$current_phy"] ]]; then
                existing="${PHY_TO_IFACES[$current_phy]}"
                if [[ -z "$existing" ]]; then
                    PHY_TO_IFACES["$current_phy"]="$iface_name"
                elif [[ ! "$existing" =~ "$iface_name" ]]; then
                    PHY_TO_IFACES["$current_phy"]="$existing, $iface_name"
                fi
            fi
        fi
    done < <(iw dev 2>/dev/null || true)

    printf "\n"
    printf "  ${BOLD}%-12s  %-20s${NC}\n" "PHY" "INTERFACE(S)"
    printf "  %-12s  %-20s\n" "------------" "--------------------"
    for phy in $(echo "${!PHY_TO_IFACES[@]}" | tr ' ' '\n' | sort); do
        ifaces="${PHY_TO_IFACES[$phy]}"
        if [[ -z "$ifaces" ]]; then
            ifaces="(no interface found)"
        fi
        printf "  %-12s  %-20s\n" "$phy" "$ifaces"
    done
    printf "\n"
    ok "${#PHY_TO_IFACES[@]} monitor-capable device(s) found."
fi

# ============================================================================
# Step 4: Create virtual environment
# ============================================================================
header "Creating virtual environment at ${DPMB_VENV}"

if [[ -d "$DPMB_VENV" ]]; then
    warn "Virtual environment already exists at ${DPMB_VENV}."
    info "Re-using existing venv. Delete and re-run to recreate."
else
    mkdir -p "$(dirname "$DPMB_VENV")"
    python3 -m venv --system-site-packages "$DPMB_VENV"
    ok "Created venv at ${DPMB_VENV}"
fi

VENV_BIN="${DPMB_VENV}/bin"

# Ensure pip is up to date inside venv
"${VENV_BIN}/pip" install --upgrade pip --quiet
ok "pip upgraded inside venv."

# ============================================================================
# Step 5: Install DPMB package into venv
# ============================================================================
header "Installing DPMB package into venv"

info "Installing from ${SCRIPT_DIR} ..."
"${VENV_BIN}/pip" install "${SCRIPT_DIR}" --quiet
ok "dpmb installed: $(${VENV_BIN}/dpmb --version 2>/dev/null || echo 'package ready')"

# Clean up root-owned build artifacts so user can manage their clone
rm -rf "${SCRIPT_DIR}/build" "${SCRIPT_DIR}/src/"*.egg-info 2>/dev/null || true

# ============================================================================
# Step 6: Create system directories
# ============================================================================
header "Creating system directories"

for dir in /etc/dpmb /var/lib/dpmb /var/lib/dpmb/handshakes; do
    if [[ -d "$dir" ]]; then
        ok "$dir (exists)"
    else
        mkdir -p "$dir"
        ok "$dir (created)"
    fi
done

chmod 750 /var/lib/dpmb/handshakes
ok "Permissions set on /var/lib/dpmb/handshakes (750)"

# ============================================================================
# Step 7: Generate and install systemd units
# ============================================================================
header "Installing systemd units"

INSTALL_DIR="${SCRIPT_DIR}/install"
SYSTEMD_DIR="/etc/systemd/system"

for unit_template in "${INSTALL_DIR}"/*.service "${INSTALL_DIR}"/*.timer; do
    [[ -f "$unit_template" ]] || continue
    unit_name="$(basename "$unit_template")"
    dest="${SYSTEMD_DIR}/${unit_name}"

    sed "s|@VENV_BIN@|${VENV_BIN}|g" "$unit_template" > "$dest"
    chmod 644 "$dest"
    ok "${unit_name} -> ${dest}"
done

systemctl daemon-reload
ok "systemd daemon reloaded."

# ============================================================================
# Step 8: Install udev rule
# ============================================================================
header "Installing udev rule"

UDEV_SRC="${INSTALL_DIR}/90-dpmb.rules"
UDEV_DEST="/etc/udev/rules.d/90-dpmb.rules"

if [[ -f "$UDEV_SRC" ]]; then
    cp "$UDEV_SRC" "$UDEV_DEST"
    chmod 644 "$UDEV_DEST"
    udevadm control --reload-rules 2>/dev/null || true
    udevadm trigger 2>/dev/null || true
    ok "90-dpmb.rules installed and udev reloaded."
else
    warn "90-dpmb.rules not found in ${INSTALL_DIR} — skipping."
fi

# ============================================================================
# Step 9: Auto-configure (dpmb init --auto)
# ============================================================================
header "Configuring DPMB"

info "Auto-detecting interface and writing config..."
printf "\n"

"${VENV_BIN}/dpmb" init --auto

printf "\n"
ok "Configuration complete."

# ============================================================================
# Step 10: Enable and start services
# ============================================================================
header "Enabling and starting services"

SERVICES=("dpmb-scanner" "dpmb-dashboard" "dpmb-heartbeat.timer")

for svc in "${SERVICES[@]}"; do
    systemctl enable "$svc" 2>/dev/null
    systemctl start "$svc" 2>/dev/null
    ok "${svc} enabled and started."
done

# ============================================================================
# Step 11: Summary
# ============================================================================
header "Setup complete"

printf "\n"
printf "  ${GREEN}${BOLD}802.11DPMB is now running.${NC}\n"
printf "\n"

# Determine dashboard URL
DASH_PORT="$(grep -oP 'port\s*=\s*\K[0-9]+' /etc/dpmb/config.toml 2>/dev/null || echo '5000')"
HOSTNAME_STR="$(hostname -I 2>/dev/null | awk '{print $1}')"
if [[ -z "$HOSTNAME_STR" ]]; then
    HOSTNAME_STR="$(hostname)"
fi

printf "  ${BOLD}Dashboard:${NC}  http://%s:%s\n" "$HOSTNAME_STR" "$DASH_PORT"
printf "\n"
printf "  ${BOLD}Service Status:${NC}\n"

for svc in "${SERVICES[@]}"; do
    status="$(systemctl is-active "$svc" 2>/dev/null || echo 'unknown')"
    if [[ "$status" == "active" ]]; then
        printf "    ${GREEN}%-28s %s${NC}\n" "$svc" "$status"
    else
        printf "    ${YELLOW}%-28s %s${NC}\n" "$svc" "$status"
    fi
done

printf "\n"
printf "  ${BOLD}Venv:${NC}       %s\n" "$DPMB_VENV"
printf "  ${BOLD}Config:${NC}     /etc/dpmb/config.toml\n"
printf "  ${BOLD}Data:${NC}       /var/lib/dpmb/\n"
printf "  ${BOLD}Logs:${NC}       journalctl -u dpmb-scanner -f\n"
printf "\n"
printf "  ${BOLD}Next steps:${NC}\n"
printf "    1. Verify dashboard at the URL above\n"
printf "    2. Check scanner logs:  journalctl -u dpmb-scanner -f\n"
printf "    3. Edit config:         nano /etc/dpmb/config.toml\n"
printf "    4. Restart services:    systemctl restart dpmb-scanner\n"
printf "\n"
