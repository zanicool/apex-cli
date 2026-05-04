#!/bin/bash
# Scan all vulnerability_battery Docker containers with apex-cli
# Usage: ./scan-battery.sh [--deep]
#
# - Builds & starts all containers from vulnerability_battery/
# - Scans each one with apex-cli
# - Collects reports in scan_results/<timestamp>/

CYAN='\033[1;36m'
GREEN='\033[1;32m'
RED='\033[1;31m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BATTERY_DIR="$SCRIPT_DIR/vulnerability_battery"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_DIR="$SCRIPT_DIR/scan_results/$TIMESTAMP"
DEEP_FLAG=""
[ "$1" = "--deep" ] && DEEP_FLAG="--deep"

export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin"

mkdir -p "$RESULTS_DIR"

echo -e "${CYAN}═══ Apex CLI — Vulnerability Battery Scanner ═══${NC}"
echo -e "Results: ${CYAN}$RESULTS_DIR${NC}"
echo ""

# Discover all containers with a Dockerfile in vulnerability_battery/
TARGETS=()
for dir in "$BATTERY_DIR"/*/; do
    [ -f "$dir/Dockerfile" ] || continue
    TARGETS+=("$(basename "$dir")")
done

if [ ${#TARGETS[@]} -eq 0 ]; then
    echo -e "${RED}No Dockerfiles found in $BATTERY_DIR${NC}"
    exit 1
fi

echo -e "${CYAN}Found ${#TARGETS[@]} targets:${NC} ${TARGETS[*]}"
echo ""

# Build, start, and scan each target
PORT=5000
SUMMARY=""
for name in "${TARGETS[@]}"; do
    echo -e "${CYAN}─── $name (port $PORT) ───${NC}"
    CONTAINER="vuln-$name"

    # Build
    if ! docker build -q -t "$CONTAINER" "$BATTERY_DIR/$name" >/dev/null 2>&1; then
        echo -e "${RED}  Build failed — skipping${NC}"
        SUMMARY+="  $name: BUILD FAILED\n"
        PORT=$((PORT + 1))
        continue
    fi

    # Start (remove old if exists)
    docker rm -f "$CONTAINER" &>/dev/null
    docker run -d --name "$CONTAINER" -p "$PORT:$PORT" "$CONTAINER" >/dev/null 2>&1

    # Wait for container to be ready
    for i in $(seq 1 10); do
        curl -s -o /dev/null "http://localhost:$PORT" && break
        sleep 1
    done

    # Scan
    SCAN_DIR="$RESULTS_DIR/$name"
    mkdir -p "$SCAN_DIR"
    echo -e "  Scanning http://localhost:$PORT ..."
    apex-cli "http://localhost:$PORT" $DEEP_FLAG --report terminal json html \
        > "$SCAN_DIR/scan.log" 2>&1

    # Collect apex output (it creates scan_* dirs in cwd)
    LATEST_SCAN=$(ls -dt "$SCRIPT_DIR"/scan_localhost* 2>/dev/null | head -1)
    if [ -n "$LATEST_SCAN" ]; then
        mv "$LATEST_SCAN"/* "$SCAN_DIR/" 2>/dev/null
        rmdir "$LATEST_SCAN" 2>/dev/null
    fi

    # Count findings
    FINDINGS=$(grep -c '"severity"' "$SCAN_DIR/report.json" 2>/dev/null || echo "0")
    echo -e "  ${GREEN}Done — $FINDINGS finding(s)${NC} → $SCAN_DIR/"
    SUMMARY+="  $name: $FINDINGS finding(s)\n"

    # Cleanup container
    docker rm -f "$CONTAINER" &>/dev/null
    PORT=$((PORT + 1))
done

# Summary
echo ""
echo -e "${CYAN}═══ Summary ═══${NC}"
echo -e "$SUMMARY"
echo -e "Full reports: ${CYAN}$RESULTS_DIR${NC}"
