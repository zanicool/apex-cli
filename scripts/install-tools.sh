#!/bin/bash
# Apex CLI — External toolchain installer
# Installs optional DAST tools that apex-cli orchestrates.
set -e

echo "=== Apex CLI Toolchain Installer ==="
echo ""

OS=$(uname -s)
ARCH=$(uname -m)

install_go_tool() {
  local name=$1 pkg=$2
  if command -v "$name" >/dev/null 2>&1; then
    echo "  ✓ $name (already installed)"
  else
    echo "  → Installing $name..."
    go install "$pkg" 2>/dev/null && echo "  ✓ $name" || echo "  ✗ $name (failed — need Go)"
  fi
}

install_pip_tool() {
  local name=$1 pkg=$2
  if command -v "$name" >/dev/null 2>&1; then
    echo "  ✓ $name (already installed)"
  else
    echo "  → Installing $name..."
    pip3 install "$pkg" 2>/dev/null && echo "  ✓ $name" || echo "  ✗ $name (failed)"
  fi
}

install_brew_tool() {
  local name=$1 pkg=$2
  if command -v "$name" >/dev/null 2>&1; then
    echo "  ✓ $name (already installed)"
  else
    if [ "$OS" = "Darwin" ] && command -v brew >/dev/null 2>&1; then
      echo "  → Installing $name..."
      brew install "$pkg" 2>/dev/null && echo "  ✓ $name" || echo "  ✗ $name (failed)"
    else
      echo "  ✗ $name (install manually: $pkg)"
    fi
  fi
}

echo "[1/4] Core scanning engines"
install_go_tool "nuclei" "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
install_pip_tool "sqlmap" "sqlmap"
install_pip_tool "dalfox" "dalfox" || install_go_tool "dalfox" "github.com/hahwul/dalfox/v2@latest"

echo ""
echo "[2/4] Discovery & recon"
install_go_tool "httpx" "github.com/projectdiscovery/httpx/cmd/httpx@latest"
install_go_tool "katana" "github.com/projectdiscovery/katana/cmd/katana@latest"
install_go_tool "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
install_go_tool "ffuf" "github.com/ffuf/ffuf/v2@latest"

echo ""
echo "[3/4] Fuzzing & deep testing"
install_pip_tool "wapiti" "wapiti3"
install_pip_tool "schemathesis" "schemathesis"
install_brew_tool "nikto" "nikto"

echo ""
echo "[4/4] OWASP ZAP"
if command -v zap.sh >/dev/null 2>&1 || [ -f "/Applications/ZAP.app/Contents/Java/zap.sh" ]; then
  echo "  ✓ ZAP (installed)"
else
  echo "  → ZAP not found. Install from: https://www.zaproxy.org/download/"
  if [ "$OS" = "Darwin" ] && command -v brew >/dev/null 2>&1; then
    echo "    Or: brew install --cask zap"
  fi
fi

echo ""
echo "=== Status ==="
echo ""
for tool in nuclei httpx katana subfinder ffuf sqlmap dalfox nikto wapiti schemathesis zap.sh; do
  if command -v "$tool" >/dev/null 2>&1; then
    printf "  ✓ %-15s %s\n" "$tool" "$(which $tool)"
  else
    printf "  ✗ %-15s not found\n" "$tool"
  fi
done
echo ""
echo "Run './build/apex-cli <target>' — tools are used automatically when available."
