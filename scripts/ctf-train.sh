#!/usr/bin/env bash
# ctf-train.sh — Train apex-cli against HTB-style CTF challenges and validate findings.
#
# Usage:
#   ./scripts/ctf-train.sh              # scan all challenges
#   ./scripts/ctf-train.sh lvl2-sqli    # single challenge
#   ./scripts/ctf-train.sh --up         # start containers only
#   ./scripts/ctf-train.sh --down       # stop containers
#   ./scripts/ctf-train.sh --validate   # validate last results (no scan)
#   ./scripts/ctf-train.sh --level 3    # only level 3 challenges
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
APEX="$ROOT_DIR/build/apex-cli"
CTF_COMPOSE="$ROOT_DIR/ctf/docker-compose.yml"
RESULTS_DIR="$ROOT_DIR/data/training/ctf"

# Challenge definitions: port|level|expected_scanners
declare -A CHALLENGES=(
  [lvl1-html]="5001|1|info-disclosure"
  [lvl1-robots]="5002|1|info-disclosure"
  [lvl1-headers]="5003|1|headers"
  [lvl2-sqli]="5004|2|sqli"
  [lvl2-lfi]="5005|2|lfi"
  [lvl2-git]="5006|2|info-disclosure"
  [lvl3-xss]="5007|3|xss"
  [lvl3-ssrf]="5008|3|ssrf"
  [lvl3-jwt]="5009|3|jwt"
  [lvl4-idor]="5010|4|idor"
  [lvl4-ssti]="5011|4|ssti"
  [lvl4-chain]="5012|4|redirect,mass-assignment"
  [lvl5-headless]="5013|5|info-disclosure,ssrf,cmdi"
  [lvl5-sau]="5014|5|ssrf,cmdi"
  [lvl5-clicker]="5015|5|jwt,race-condition"
  [lvl5-codify]="5016|5|rce,lfi"
  [lvl5-megacorp]="5017|5|idor,cmdi"
)

up() {
  echo "  → Starting CTF challenges..."
  docker compose -f "$CTF_COMPOSE" up -d --build 2>&1 | tail -5
  echo "  → Waiting for containers..."
  sleep 5
  local ready=0
  for key in "${!CHALLENGES[@]}"; do
    IFS='|' read -r port _ _ <<< "${CHALLENGES[$key]}"
    if curl -s --max-time 2 "http://localhost:$port" >/dev/null 2>&1; then
      ((ready++))
    fi
  done
  echo "  ✓ $ready/${#CHALLENGES[@]} challenges ready"
}

down() {
  docker compose -f "$CTF_COMPOSE" down -v 2>/dev/null || true
  echo "  ✓ CTF containers stopped"
}

scan_challenge() {
  local key="$1"
  IFS='|' read -r port level expected <<< "${CHALLENGES[$key]}"
  local url="http://localhost:$port"
  local output="$RESULTS_DIR/$key"

  if ! curl -s --max-time 2 "$url" >/dev/null 2>&1; then
    echo "  ✗ $key (port $port) — not running"
    return 1
  fi

  echo "  → [$key] lvl$level scanning localhost:$port (expect: $expected)..."
  mkdir -p "$output"

  $APEX "localhost:$port" \
    --threads 10 \
    --timeout 5 \
    --deep \
    --output "$output" \
    --report json 2>&1 | tail -3

  # Count findings
  if [ -f "$output/report.json" ]; then
    local total
    total=$(jq '.findings | length' "$output/report.json" 2>/dev/null || echo 0)
    echo "    Found: $total findings"
  fi
}

validate() {
  echo ""
  echo "╔══════════════════════════════════════════════════════════════════╗"
  echo "║  CTF CHALLENGE VALIDATION — HTB Training Results               ║"
  echo "╚══════════════════════════════════════════════════════════════════╝"
  echo ""
  printf "  %-14s %-5s %-6s %-22s %s\n" "Challenge" "Lvl" "Finds" "Expected" "Status"
  echo "  ──────────────────────────────────────────────────────────────────"

  local pass=0 fail=0 skip=0

  for key in $(echo "${!CHALLENGES[@]}" | tr ' ' '\n' | sort); do
    IFS='|' read -r port level expected <<< "${CHALLENGES[$key]}"
    local report="$RESULTS_DIR/$key/report.json"

    if [ ! -f "$report" ]; then
      printf "  %-14s %-5s %-6s %-22s %s\n" "$key" "$level" "-" "$expected" "⏭ no scan"
      ((skip++))
      continue
    fi

    local total
    total=$(jq '.findings | length' "$report" 2>/dev/null || echo 0)

    # Check if expected scanner types were found
    local status="✓"
    for vuln in ${expected//,/ }; do
      if ! jq -e ".findings[] | select(.scanner | ascii_downcase | contains(\"$vuln\"))" "$report" >/dev/null 2>&1; then
        # Also check type field
        if ! jq -e ".findings[] | select(.type | ascii_downcase | contains(\"$vuln\"))" "$report" >/dev/null 2>&1; then
          status="✗"
        fi
      fi
    done

    if [ "$status" = "✓" ]; then
      ((pass++))
      printf "  %-14s %-5s %-6s %-22s \033[32m✓ PASS\033[0m\n" "$key" "$level" "$total" "$expected"
    else
      ((fail++))
      printf "  %-14s %-5s %-6s %-22s \033[31m✗ MISS\033[0m\n" "$key" "$level" "$total" "$expected"
    fi
  done

  echo "  ──────────────────────────────────────────────────────────────────"
  echo "  Results: $pass passed, $fail missed, $skip skipped"
  echo ""

  # Write summary JSONL
  mkdir -p "$RESULTS_DIR"
  echo "{\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"pass\":$pass,\"fail\":$fail,\"skip\":$skip,\"total\":${#CHALLENGES[@]}}" >> "$RESULTS_DIR/history.jsonl"

  [ "$fail" -eq 0 ] && [ "$skip" -eq 0 ]
}

# Main
echo "╔══════════════════════════════════════╗"
echo "║  APEX-CLI CTF TRAINING (HTB-style)  ║"
echo "╚══════════════════════════════════════╝"
echo ""

LEVEL_FILTER=""
TARGET="${1:-all}"

case "$TARGET" in
  --up)      up; exit 0 ;;
  --down)    down; exit 0 ;;
  --validate) validate; exit $? ;;
  --level)   LEVEL_FILTER="${2:?Usage: $0 --level <1-4>}"; TARGET="all" ;;
esac

# Ensure binary exists
if [ ! -x "$APEX" ]; then
  echo "  ✗ apex-cli not found. Run: make build"
  exit 1
fi

mkdir -p "$RESULTS_DIR"

if [ "$TARGET" = "all" ]; then
  for key in $(echo "${!CHALLENGES[@]}" | tr ' ' '\n' | sort); do
    IFS='|' read -r _ level _ <<< "${CHALLENGES[$key]}"
    if [ -n "$LEVEL_FILTER" ] && [ "$level" != "$LEVEL_FILTER" ]; then
      continue
    fi
    scan_challenge "$key" || true
    echo ""
  done
  validate
else
  if [[ -v "CHALLENGES[$TARGET]" ]]; then
    scan_challenge "$TARGET"
  else
    echo "Unknown challenge: $TARGET"
    echo "Available: $(echo "${!CHALLENGES[@]}" | tr ' ' '\n' | sort | tr '\n' ' ')"
    exit 1
  fi
fi
