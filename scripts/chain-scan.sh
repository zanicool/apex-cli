#!/bin/bash
# Apex CLI — Vulnerability Chain Scanner
# Scans for individual weaknesses AND detects when they combine into exploits.
# A "warning" + "warning" that chain together = "critical" finding.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CHAIN_DB="$SCRIPT_DIR/../data/vuln-chains.db"
TARGET="${1:?Usage: $0 <repo-path-or-url>}"
OUTDIR="./output/chain-scan-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTDIR"
LOG="$OUTDIR/scan.log"

log()  { echo -e "\033[1;34m[*]\033[0m $*" | tee -a "$LOG"; }
ok()   { echo -e "\033[1;32m[+]\033[0m $*" | tee -a "$LOG"; }
warn() { echo -e "\033[1;33m[!]\033[0m $*" | tee -a "$LOG"; }
crit() { echo -e "\033[1;31m[!]\033[0m $*" | tee -a "$LOG"; }

echo ""
echo "  ╔═══════════════════════════════════════════════╗"
echo "  ║  APEX — Vulnerability Chain Scanner           ║"
echo "  ╚═══════════════════════════════════════════════╝"
echo ""

# Clone if URL
SCAN_DIR="$TARGET"
if [[ "$TARGET" == http* ]] || [[ "$TARGET" == git@* ]]; then
  SCAN_DIR="$OUTDIR/repo"
  log "Cloning $TARGET..."
  git clone --depth 1 "$TARGET" "$SCAN_DIR" 2>/dev/null || { echo "Clone failed"; exit 1; }
fi

log "Target: $SCAN_DIR"
log "Chains: $CHAIN_DB ($(grep -c "^[A-Z]" "$CHAIN_DB") patterns)"
echo ""

# ═══ Phase 1: Scan all patterns ═══
log "Phase 1: Pattern matching..."
echo ""

declare -A FOUND_PATTERNS=()  # pattern_id → count
declare -A FOUND_FILES=()    # pattern_id → file:line

while IFS='|' read -r pid severity chain_with desc pattern glob; do
  # Skip comments and empty lines
  [[ "$pid" =~ ^#.*$ ]] && continue
  [ -z "$pid" ] && continue

  # Search for pattern
  hits=$(grep -rnE "$pattern" --include="$glob" \
    --exclude-dir=node_modules --exclude-dir=vendor --exclude-dir=test \
    --exclude-dir=tests --exclude-dir=__tests__ --exclude-dir=spec \
    --exclude-dir=.git --exclude-dir=dist --exclude-dir=build \
    "$SCAN_DIR" 2>/dev/null | head -5)

  if [ -n "$hits" ]; then
    count=$(echo "$hits" | wc -l | tr -d ' ')
    FOUND_PATTERNS["$pid"]="$count"
    FOUND_FILES["$pid"]="$(echo "$hits" | head -1)"

    case "$severity" in
      critical) crit "  $pid ($count hits) — $desc" ;;
      error)    warn "  $pid ($count hits) — $desc" ;;
      *)        echo "  · $pid ($count hits) — $desc" | tee -a "$LOG" ;;
    esac

    # Log details
    echo "$hits" | while read -r hit; do
      echo "$pid|$severity|$chain_with|$hit" >> "$OUTDIR/raw-findings.txt"
    done
  fi
done < <(grep "^[A-Z]" "$CHAIN_DB")

TOTAL_PATTERNS="${#FOUND_PATTERNS[@]}"
echo ""
ok "Found $TOTAL_PATTERNS unique pattern types"
echo ""

# ═══ Phase 2: Chain detection ═══
log "Phase 2: Detecting vulnerability chains..."
echo ""

CHAINS_FOUND=0
{
  echo "=== VULNERABILITY CHAINS DETECTED ==="
  echo ""

  # For each found pattern, check if its chain partner is also found
  for pid in "${!FOUND_PATTERNS[@]}"; do
    chain_with=$(grep "^$pid|" "$CHAIN_DB" | cut -d'|' -f3)
    [ -z "$chain_with" ] && continue
    [ "$chain_with" = "*" ] && continue  # Multiplier, chains with anything

    # Check if chain partner exists
    if [ -n "${FOUND_PATTERNS[$chain_with]:-}" ]; then
      CHAINS_FOUND=$((CHAINS_FOUND + 1))
      desc1=$(grep "^$pid|" "$CHAIN_DB" | cut -d'|' -f4)
      desc2=$(grep "^$chain_with|" "$CHAIN_DB" | cut -d'|' -f4)

      crit "  CHAIN #$CHAINS_FOUND: $pid + $chain_with"
      echo "    ├─ $pid: $desc1" | tee -a "$LOG"
      echo "    │  ${FOUND_FILES[$pid]:-}" | tee -a "$LOG"
      echo "    └─ $chain_with: $desc2" | tee -a "$LOG"
      echo "       ${FOUND_FILES[$chain_with]:-}" | tee -a "$LOG"
      echo "" | tee -a "$LOG"

      echo "CHAIN|$pid|$chain_with|$desc1|$desc2" >> "$OUTDIR/chains.txt"
    fi
  done

  # Check multipliers (patterns that amplify any other finding)
  for pid in "${!FOUND_PATTERNS[@]}"; do
    chain_with=$(grep "^$pid|" "$CHAIN_DB" | cut -d'|' -f3)
    if [ "$chain_with" = "*" ] && [ "$TOTAL_PATTERNS" -gt 1 ]; then
      desc=$(grep "^$pid|" "$CHAIN_DB" | cut -d'|' -f4)
      echo "  ⚡ MULTIPLIER: $pid amplifies all other findings" | tee -a "$LOG"
      echo "    $desc" | tee -a "$LOG"
      echo "" | tee -a "$LOG"
    fi
  done
} >> "$OUTDIR/chain-report.txt"

# ═══ Phase 3: Exploitability assessment ═══
echo ""
log "Phase 3: Exploitability assessment..."
echo ""

python3 << PYTHON "$OUTDIR"
import sys, os
from collections import defaultdict

outdir = sys.argv[1]
findings_file = os.path.join(outdir, "raw-findings.txt")
if not os.path.exists(findings_file):
    print("  No findings to assess")
    sys.exit(0)

severity_score = {"critical": 10, "error": 7, "warning": 3}
findings = defaultdict(list)

with open(findings_file) as f:
    for line in f:
        parts = line.strip().split("|", 3)
        if len(parts) >= 4:
            pid, sev, chain, detail = parts
            findings[pid].append({"severity": sev, "chain": chain, "detail": detail})

# Calculate risk score
total_score = 0
for pid, items in findings.items():
    base = severity_score.get(items[0]["severity"], 1)
    count_bonus = min(len(items), 5)  # More instances = more likely real
    total_score += base * count_bonus

# Chain bonus
chains_file = os.path.join(outdir, "chains.txt")
if os.path.exists(chains_file):
    with open(chains_file) as f:
        chain_count = sum(1 for _ in f)
    total_score += chain_count * 20  # Chains are high value

print(f"  Risk Score: {total_score}")
print(f"  Patterns:   {len(findings)}")
print(f"  Chains:     {chain_count if os.path.exists(chains_file) else 0}")
print()

if total_score > 100:
    print("  🔴 HIGH — Multiple exploitable chains. Report immediately.")
elif total_score > 50:
    print("  🟡 MEDIUM — Exploitable patterns found. Verify and report.")
elif total_score > 20:
    print("  🟢 LOW — Minor issues, may chain with future findings.")
else:
    print("  ⚪ MINIMAL — No significant attack surface detected.")

# Write summary
with open(os.path.join(outdir, "summary.txt"), "w") as out:
    out.write(f"Risk Score: {total_score}\n")
    out.write(f"Patterns: {len(findings)}\n")
    for pid, items in sorted(findings.items(), key=lambda x: -severity_score.get(x[1][0]["severity"], 0)):
        out.write(f"\n{pid} ({items[0]['severity']}, {len(items)} hits, chains with: {items[0]['chain']})\n")
        for item in items[:3]:
            out.write(f"  {item['detail'][:120]}\n")
PYTHON

# ═══ Summary ═══
echo ""
echo "  ╔═══════════════════════════════════════════════╗"
echo "  ║           CHAIN SCAN COMPLETE                 ║"
echo "  ╚═══════════════════════════════════════════════╝"
echo ""
ok "Patterns found: $TOTAL_PATTERNS"
ok "Chains found:   $CHAINS_FOUND"
ok "Output:         $OUTDIR/"
echo "    raw-findings.txt  — all pattern matches"
echo "    chains.txt        — detected chains"
echo "    chain-report.txt  — chain analysis"
echo "    summary.txt       — risk assessment"
