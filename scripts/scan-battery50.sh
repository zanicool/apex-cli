#!/usr/bin/env bash
# scan-battery50.sh — Scan 50 vulnerable docker images, report what apex-cli finds vs expects.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APEX="${ROOT}/build/apex-cli"
COMPOSE="${ROOT}/docker-compose.battery50.yml"
RESULTS="${ROOT}/tests/battery50-results"
PARALLEL=6

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'; C='\033[0;36m'; DIM='\033[2m'; NC='\033[0m'

# Parse args
NO_DOCKER=false; QUICK=false
for arg in "$@"; do
  case $arg in
    --no-docker) NO_DOCKER=true ;;
    --quick) QUICK=true ;;
    --teardown) docker compose -f "$COMPOSE" down --remove-orphans -v 2>/dev/null; echo "Done."; exit 0 ;;
  esac
done

[ -f "$APEX" ] || { echo "Building apex-cli..."; make -C "$ROOT" build 2>&1 | tail -3; }

# Extract targets from compose labels
declare -a TARGETS=()
while IFS= read -r line; do
  TARGETS+=("$line")
done < <(python3 -c "
import yaml, sys
with open('$COMPOSE') as f:
    data = yaml.safe_load(f)
for name, svc in data.get('services', {}).items():
    labels = svc.get('labels', {})
    expect = labels.get('apex.expect', '')
    if not expect: continue
    ports = svc.get('ports', [])
    if not ports: continue
    port = str(ports[0]).split(':')[0]
    print(f'{name}|{port}|{expect}')
" 2>/dev/null || python3 -c "
import re, sys
content = open('$COMPOSE').read()
# Parse manually if no yaml module
blocks = re.split(r'\n  (t\d+-[^:]+):', content)
for i in range(1, len(blocks)-1, 2):
    name = blocks[i]
    block = blocks[i+1]
    port_m = re.search(r'ports:.*?\"(\d+):', block)
    expect_m = re.search(r'apex\.expect:\s*\"([^\"]+)\"', block)
    if port_m and expect_m:
        print(f'{name}|{port_m.group(1)}|{expect_m.group(1)}')
")

echo -e "${B}▶ Battery50: ${#TARGETS[@]} targets${NC}\n"

# Start docker
if [ "$NO_DOCKER" = false ]; then
  echo -e "${B}▶ Starting containers (this may take a while on first run)...${NC}"
  # Only start lightweight ones in quick mode
  if [ "$QUICK" = true ]; then
    SERVICES=$(printf '%s\n' "${TARGETS[@]}" | cut -d'|' -f1 | grep -v "gitlab\|jenkins\|elastic\|kibana\|sonarqube\|spring\|keycloak" | tr '\n' ' ')
  else
    SERVICES=$(printf '%s\n' "${TARGETS[@]}" | cut -d'|' -f1 | tr '\n' ' ')
  fi
  docker compose -f "$COMPOSE" up -d $SERVICES 2>&1 | tail -5
  echo -e "  Waiting 20s for services to start..."
  sleep 20
fi

# Scan
rm -rf "$RESULTS"; mkdir -p "$RESULTS"
SCAN_START=$(date +%s)

scan_target() {
  local name=$1 port=$2
  local url="http://localhost:${port}"
  local outdir="${RESULTS}/${name}"
  mkdir -p "$outdir"
  # Quick scan with --quick flag for speed
  "$APEX" "$url" --quick --threads 30 --timeout 6 --output "$outdir" --report json > "$outdir/stdout.log" 2>&1 || true
}

# Run scans in parallel batches
COMPLETED=0
TOTAL=${#TARGETS[@]}
for ((i=0; i<TOTAL; i+=PARALLEL)); do
  pids=()
  for ((j=i; j<i+PARALLEL && j<TOTAL; j++)); do
    entry="${TARGETS[$j]}"
    name="${entry%%|*}"
    rest="${entry#*|}"
    port="${rest%%|*}"
    # Check if port is reachable
    if curl -sf --max-time 2 "http://localhost:${port}/" >/dev/null 2>&1 || \
       curl -sf --max-time 2 "http://localhost:${port}/health" >/dev/null 2>&1; then
      scan_target "$name" "$port" &
      pids+=($!)
    else
      mkdir -p "${RESULTS}/${name}"
      echo "UNREACHABLE" > "${RESULTS}/${name}/.status"
      COMPLETED=$((COMPLETED + 1))
    fi
  done
  for pid in "${pids[@]:-}"; do
    [ -n "$pid" ] && wait "$pid" 2>/dev/null || true
    COMPLETED=$((COMPLETED + 1))
  done
  printf "\r  Progress: %d/%d" "$COMPLETED" "$TOTAL"
done
echo ""

SCAN_ELAPSED=$(( $(date +%s) - SCAN_START ))

# Validate
echo -e "\n${B}▶ Results${NC}\n"
printf "  ${DIM}%-20s %-6s %-40s %s${NC}\n" "TARGET" "PORT" "EXPECTED" "STATUS"
echo "  ────────────────────────────────────────────────────────────────────────────"

TOTAL_PASS=0; TOTAL_FAIL=0; TOTAL_SKIP=0; TOTAL_CHECKS=0
MISSED_TYPES=""

for entry in "${TARGETS[@]}"; do
  name="${entry%%|*}"
  rest="${entry#*|}"
  port="${rest%%|*}"
  expected="${rest#*|}"
  outdir="${RESULTS}/${name}"

  # Skip unreachable
  if [ -f "$outdir/.status" ]; then
    printf "  %-20s %-6s %-40s ${DIM}SKIP (unreachable)${NC}\n" "$name" "$port" "$expected"
    TOTAL_SKIP=$((TOTAL_SKIP + 1))
    continue
  fi

  IFS=',' read -ra PATTERNS <<< "$expected"
  found=0; missed=0; missed_list=""
  for pattern in "${PATTERNS[@]}"; do
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if grep -rqi "$pattern" "$outdir/" 2>/dev/null; then
      found=$((found + 1))
      TOTAL_PASS=$((TOTAL_PASS + 1))
    else
      missed=$((missed + 1))
      TOTAL_FAIL=$((TOTAL_FAIL + 1))
      missed_list+="$pattern,"
      MISSED_TYPES+="$pattern\n"
    fi
  done

  if [ $missed -eq 0 ]; then
    printf "  ${G}✓${NC} %-18s %-6s %-40s ${G}%d/%d${NC}\n" "$name" "$port" "$expected" "$found" "$((found+missed))"
  else
    printf "  ${R}✗${NC} %-18s %-6s %-40s ${R}%d/%d${NC} miss: ${Y}%s${NC}\n" "$name" "$port" "$expected" "$found" "$((found+missed))" "${missed_list%,}"
  fi
done

# Summary
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
RATE=0; [ $TOTAL_CHECKS -gt 0 ] && RATE=$((TOTAL_PASS * 100 / TOTAL_CHECKS))
echo -e "  Targets:     ${B}${#TARGETS[@]}${NC} (${TOTAL_SKIP} skipped)"
echo -e "  Scan time:   ${B}${SCAN_ELAPSED}s${NC}"
echo -e "  Detection:   ${B}${TOTAL_PASS}/${TOTAL_CHECKS}${NC} (${RATE}%)"
echo -e "  Passed:      ${G}${TOTAL_PASS}${NC}"
echo -e "  Failed:      ${R}${TOTAL_FAIL}${NC}"

if [ -n "$MISSED_TYPES" ]; then
  echo -e "\n  ${Y}Most missed categories:${NC}"
  echo -e "$MISSED_TYPES" | sort | uniq -c | sort -rn | head -10 | while read count type; do
    echo -e "    ${R}${count}x${NC} ${type}"
  done
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "  Results: ${RESULTS}/"
echo -e "  Teardown: $0 --teardown"
echo ""

# Write machine-readable summary
python3 -c "
import json, os
summary = {'total': $TOTAL_CHECKS, 'passed': $TOTAL_PASS, 'failed': $TOTAL_FAIL, 'rate': $RATE, 'skipped': $TOTAL_SKIP}
with open('${RESULTS}/summary.json', 'w') as f:
    json.dump(summary, f, indent=2)
" 2>/dev/null || true
