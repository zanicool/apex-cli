#!/bin/bash
# Docker Engine Installer / Repairer for Ubuntu & Linux Mint
# Based on: https://docs.docker.com/engine/install/ubuntu/
#
# Safe to run multiple times — detects existing installs, repairs broken ones.
# Supports Ubuntu 22.04+, 24.04+, 26.04+ and Linux Mint (uses UBUNTU_CODENAME).

RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
NC='\033[0m'

ERRORS=0

ok()   { echo -e "  ${GREEN}[✓]${NC} $1"; }
warn() { echo -e "  ${YELLOW}[~]${NC} $1"; }
fail() { echo -e "  ${RED}[!]${NC} $1"; ERRORS=$((ERRORS + 1)); }
info() { echo -e "  ${CYAN}[+]${NC} $1"; }

echo -e "${CYAN}Docker Engine — Install / Repair${NC}"
echo ""

# ─── Preflight checks ───
echo -e "${CYAN}[1/5] Preflight${NC}"

if [ "$(id -u)" -ne 0 ]; then
    fail "Must run as root: sudo ./docker-install.sh"
    exit 1
fi
ok "Running as root"

if ! command -v apt-get &>/dev/null; then
    fail "apt-get not found — this script supports Ubuntu/Debian/Mint only"
    exit 1
fi
ok "apt-get available"

# Detect codename (Mint sets UBUNTU_CODENAME, Ubuntu sets VERSION_CODENAME)
. /etc/os-release 2>/dev/null
CODENAME="${UBUNTU_CODENAME:-$VERSION_CODENAME}"
if [ -z "$CODENAME" ]; then
    fail "Could not detect Ubuntu codename from /etc/os-release"
    exit 1
fi
ARCH="$(dpkg --print-architecture)"
ok "Detected: $PRETTY_NAME ($CODENAME, $ARCH)"

# ─── Remove conflicting packages ───
echo ""
echo -e "${CYAN}[2/5] Remove conflicting packages${NC}"
CONFLICTS="docker.io docker-compose docker-compose-v2 docker-doc podman-docker containerd runc"
FOUND=""
for pkg in $CONFLICTS; do
    if dpkg -s "$pkg" &>/dev/null; then
        FOUND="$FOUND $pkg"
    fi
done
if [ -n "$FOUND" ]; then
    info "Removing:$FOUND"
    apt-get remove -y $FOUND &>/dev/null
    ok "Removed conflicting packages"
else
    ok "No conflicting packages found"
fi

# ─── Set up Docker apt repository ───
echo ""
echo -e "${CYAN}[3/5] Configure Docker apt repository${NC}"

apt-get update -qq 2>/dev/null
apt-get install -y -qq ca-certificates curl &>/dev/null
ok "ca-certificates, curl"

install -m 0755 -d /etc/apt/keyrings
if curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc; then
    chmod a+r /etc/apt/keyrings/docker.asc
    ok "Docker GPG key"
else
    fail "Failed to download Docker GPG key — check network"
fi

# Write sources file (idempotent — overwrites if exists)
cat > /etc/apt/sources.list.d/docker.list <<EOF
deb [arch=$ARCH signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $CODENAME stable
EOF
ok "Apt source: docker.list ($CODENAME/$ARCH)"

if apt-get update -qq 2>/dev/null; then
    ok "apt update"
else
    fail "apt update failed — check /etc/apt/sources.list.d/docker.list"
fi

# ─── Install Docker Engine ───
echo ""
echo -e "${CYAN}[4/5] Install Docker Engine${NC}"

DOCKER_PKGS="docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin"

if apt-get install -y $DOCKER_PKGS 2>/dev/null; then
    ok "Docker packages installed"
else
    # Repair attempt: clean and retry
    warn "First install attempt failed — attempting repair..."
    apt-get --fix-broken install -y &>/dev/null
    dpkg --configure -a &>/dev/null
    apt-get update -qq 2>/dev/null
    if apt-get install -y $DOCKER_PKGS 2>/dev/null; then
        ok "Docker packages installed (after repair)"
    else
        fail "Docker install failed — see errors above"
    fi
fi

# Ensure Docker is running
if systemctl is-active --quiet docker 2>/dev/null; then
    ok "Docker daemon running"
else
    info "Starting Docker daemon..."
    if systemctl start docker 2>/dev/null; then
        ok "Docker daemon started"
    else
        fail "Could not start Docker daemon — check: journalctl -xeu docker"
    fi
fi

systemctl enable docker &>/dev/null

# ─── Post-install: add user to docker group ───
echo ""
echo -e "${CYAN}[5/5] Post-install & verification${NC}"

REAL_USER="${SUDO_USER:-$USER}"
if [ "$REAL_USER" != "root" ]; then
    if id -nG "$REAL_USER" | grep -qw docker; then
        ok "$REAL_USER already in docker group"
    else
        usermod -aG docker "$REAL_USER"
        ok "Added $REAL_USER to docker group (log out/in or run: newgrp docker)"
    fi
fi

# Verify
if docker --version &>/dev/null; then
    ok "$(docker --version)"
else
    fail "docker CLI not working"
fi

if docker compose version &>/dev/null; then
    ok "$(docker compose version)"
else
    fail "docker compose not working"
fi

# Test with hello-world
info "Running hello-world container..."
if docker run --rm hello-world &>/dev/null; then
    ok "hello-world container ran successfully"
else
    warn "hello-world failed — may need: newgrp docker (or log out/in)"
fi

# ─── Summary ───
echo ""
if [ "$ERRORS" -eq 0 ]; then
    echo -e "${GREEN}✓ Docker Engine installed and working!${NC}"
else
    echo -e "${YELLOW}⚠ Completed with ${ERRORS} issue(s) — check [!] items above${NC}"
    echo -e "  Safe to re-run this script to retry failed steps."
fi
echo ""
echo -e "  Test:     ${CYAN}docker run hello-world${NC}"
echo -e "  Compose:  ${CYAN}docker compose version${NC}"
echo -e "  Status:   ${CYAN}sudo systemctl status docker${NC}"
if [ "$REAL_USER" != "root" ]; then
    echo -e "  No sudo:  ${CYAN}newgrp docker${NC}  (or log out and back in)"
fi
