#!/usr/bin/env bash
# scan-all.sh — Fast parallel scan of all vulnerability battery targets.
#
# Features:
#   • Parallel scanning with live progress bar
#   • Expected-finding validation per target
#   • Elapsed time tracking per scan
#   • Summary with detection rate
#
# Usage:
#   ./scripts/scan-all.sh              # Full run (custom targets only)
#   ./scripts/scan-all.sh --all        # Include well-known images (DVWA, Juice Shop, etc.)
#   ./scripts/scan-all.sh --no-docker  # Skip docker start (targets already running)
#   ./scripts/scan-all.sh --teardown   # Stop all containers
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APEX="${ROOT}/build/apex-cli"
COMPOSE="${ROOT}/tests/vulnerability_battery/docker-compose.yml"
RESULTS="${ROOT}/tests/vulnerability_battery/results"
PARALLEL=4

# Colors
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'; C='\033[0;36m'; DIM='\033[2m'; NC='\033[0m'

# Parse args
ALL=false; NO_DOCKER=false
for arg in "$@"; do
  case $arg in
    --all) ALL=true ;;
    --no-docker) NO_DOCKER=true ;;
    --teardown) docker compose -f "$COMPOSE" down --remove-orphans; echo "Done."; exit 0 ;;
  esac
done

# ─── Expected findings per target ───────────────────────────────────────────
# Format: "target_name|port|pattern1,pattern2,..."
declare -a TARGETS=(
  "vuln-web|8081|SQL,XSS,SSRF,CMDi,LFI,SSTI,Redirect,GraphQL"
  "vuln-auth|8082|JWT,IDOR,CSRF,Session"
  "vuln-headers|8083|Header,CORS,Cookie"
  "vuln-upload|8084|Upload,XXE"
  "vuln-api|8085|Swagger,GraphQL,API"
  "vuln-infra|8086|Secret,Directory,credential"
  "vuln-ssrf|8087|SSRF,metadata"
  "vuln-cicd|8088|git,Secret,registry"
)

if [ "$ALL" = true ]; then
  TARGETS+=(
    "dvwa|8090|SQL,XSS,Header"
    "juice-shop|8091|XSS,SQL,Header"
    "vampi|8093|API,Header"
  )
fi

# ─── Helpers ────────────────────────────────────────────────────────────────
elapsed() { echo "$(( $(date +%s) - $1 ))s"; }

spinner() {
  local pid=$1 name=$2
  local chars='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
  local i=0
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r  ${C}${chars:i%10:1}${NC} Scanning ${B}%s${NC}..." "$name"
    i=$((i+1))
    sleep 0.1
  done
  printf "\r"
}

progress_bar() {
  local done=$1 total=$2 width=30
  local filled=$((done * width / total))
  local empty=$((width - filled))
  printf "${B}[${G}"
  printf '█%.0s' $(seq 1 $filled 2>/dev/null) || true
  printf "${DIM}"
  printf '░%.0s' $(seq 1 $empty 2>/dev/null) || true
  printf "${NC}${B}]${NC} %d/%d" "$done" "$total"
}

# ─── Build ──────────────────────────────────────────────────────────────────
if [ ! -f "$APEX" ]; then
  echo -e "${Y}Building apex-cli...${NC}"
  make -C "$ROOT" build 2>&1 | tail -3
fi

# ─── Docker ─────────────────────────────────────────────────────────────────
if [ "$NO_DOCKER" = false ]; then
  echo -e "\n${B}▶ Starting targets...${NC}"
  SERVICES=""
  for entry in "${TARGETS[@]}"; do
    name="${entry%%|*}"
    SERVICES+="$name "
  done

  # Build custom targets, pull well-known
  docker compose -f "$COMPOSE" build --quiet ${SERVICES} 2>/dev/null || true
  docker compose -f "$COMPOSE" up -d ${SERVICES} 2>&1 | grep -v "^$" | tail -5

  # Wait for health with progress
  echo -ne "  Waiting for health checks "
  PORTS=()
  for entry in "${TARGETS[@]}"; do
    port="${entry#*|}"
    port="${port%%|*}"
    PORTS+=("$port")
  done

  READY=0
  TOTAL=${#PORTS[@]}
  for port in "${PORTS[@]}"; do
    for i in $(seq 1 40); do
      if curl -sf "http://localhost:${port}/health" >/dev/null 2>&1 || \
         curl -sf "http://localhost:${port}/" >/dev/null 2>&1; then
        READY=$((READY + 1))
        printf "\r  "
        progress_bar $READY $TOTAL
        break
      fi
      sleep 0.5
    done
  done
  echo -e " ${G}✓${NC}"
fi

# ─── Scan ───────────────────────────────────────────────────────────────────
rm -rf "$RESULTS"; mkdir -p "$RESULTS"
echo -e "\n${B}▶ Scanning ${#TARGETS[@]} targets (parallel=$PARALLEL)${NC}\n"

SCAN_START=$(date +%s)
COMPLETED=0
TOTAL_TARGETS=${#TARGETS[@]}
TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_CHECKS=0

# Track PIDs for parallel execution
declare -a PIDS=()
declare -a SCAN_NAMES=()

scan_target() {
  local name=$1 port=$2 expected=$3
  local url="http://localhost:${port}"
  local outdir="${RESULTS}/${name}"
  local t_start=$(date +%s)

  mkdir -p "$outdir"
  "$APEX" "$url" --threads 50 --timeout 8 --output "$outdir" --report json > "$outdir/stdout.log" 2>&1
  echo "$(($(date +%s) - t_start))" > "$outdir/.elapsed"
}

# Launch scans in batches
for ((i=0; i<TOTAL_TARGETS; i+=PARALLEL)); do
  batch_pids=()
  batch_names=()

  for ((j=i; j<i+PARALLEL && j<TOTAL_TARGETS; j++)); do
    entry="${TARGETS[$j]}"
    name="${entry%%|*}"
    rest="${entry#*|}"
    port="${rest%%|*}"
    expected="${rest#*|}"

    scan_target "$name" "$port" "$expected" &
    batch_pids+=($!)
    batch_names+=("$name")
  done

  # Wait for batch with progress
  for k in "${!batch_pids[@]}"; do
    pid=${batch_pids[$k]}
    name=${batch_names[$k]}
    spinner "$pid" "$name"
    wait "$pid" 2>/dev/null || true
    COMPLETED=$((COMPLETED + 1))

    # Show result inline
    outdir="${RESULTS}/${name}"
    secs=$(cat "$outdir/.elapsed" 2>/dev/null || echo "?")
    findings=$(grep -c '"type"' "$outdir/report.json" 2>/dev/null || echo "0")
    printf "  ${G}✓${NC} %-14s ${DIM}%3ss${NC}  %s findings\n" "$name" "$secs" "$findings"
  done
done

SCAN_ELAPSED=$(elapsed $SCAN_START)

# ─── Validate expected findings ─────────────────────────────────────────────
echo -e "\n${B}▶ Validating expected findings${NC}\n"

for entry in "${TARGETS[@]}"; do
  name="${entry%%|*}"
  rest="${entry#*|}"
  port="${rest%%|*}"
  expected="${rest#*|}"
  outdir="${RESULTS}/${name}"

  IFS=',' read -ra PATTERNS <<< "$expected"
  local_pass=0
  local_fail=0

  for pattern in "${PATTERNS[@]}"; do
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if grep -rqi "$pattern" "$outdir/" 2>/dev/null; then
      local_pass=$((local_pass + 1))
      TOTAL_PASS=$((TOTAL_PASS + 1))
    else
      local_fail=$((local_fail + 1))
      TOTAL_FAIL=$((TOTAL_FAIL + 1))
      printf "  ${R}✗${NC} ${name}: missing ${Y}%s${NC}\n" "$pattern"
    fi
  done

  if [ $local_fail -eq 0 ]; then
    printf "  ${G}✓${NC} %-14s %d/%d patterns found\n" "$name" "$local_pass" "$((local_pass + local_fail))"
  fi
done

# ─── Summary ────────────────────────────────────────────────────────────────
RATE=$((TOTAL_PASS * 100 / TOTAL_CHECKS))
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "  Targets scanned:  ${B}${TOTAL_TARGETS}${NC}"
echo -e "  Total time:       ${B}${SCAN_ELAPSED}${NC}"
echo -e "  Detection rate:   ${B}${TOTAL_PASS}/${TOTAL_CHECKS}${NC} (${RATE}%)"
if [ $RATE -ge 80 ]; then
  echo -e "  Status:           ${G}✓ EXCELLENT (≥80%)${NC}"
elif [ $RATE -ge 70 ]; then
  echo -e "  Status:           ${G}✓ GOOD (≥70%)${NC}"
elif [ $RATE -ge 50 ]; then
  echo -e "  Status:           ${Y}⚠ NEEDS WORK (≥50%)${NC}"
else
  echo -e "  Status:           ${R}✗ POOR (<50%)${NC}"
fi
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "  Results:  ${RESULTS}/"
echo -e "  Teardown: $0 --teardown"
echo ""

[ $RATE -lt 50 ] && exit 1 || exit 0
