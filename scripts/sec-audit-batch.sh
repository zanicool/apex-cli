#!/bin/bash
# Apex CLI — Batch Security Audit (Phase 1: find untested security code)
# Scans all repos for security-critical code without running tests.
# Fast triage: which repos have the most security-relevant code to investigate?
set -uo pipefail

SCAN_DIR="${1:-$HOME/git/hub/topx}"
OUTDIR="./output/secaudit-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTDIR"
LOG="$OUTDIR/audit.log"

log() { echo -e "\033[1;34m[*]\033[0m $*" | tee -a "$LOG"; }
ok()  { echo -e "\033[1;32m[+]\033[0m $*" | tee -a "$LOG"; }

SEC_PATTERNS='if.*(isAuth|authenticated|authorized|session\b|token\b)|if.*(req\.user|currentUser|ctx\.user)|middleware.*(auth|guard|protect)|if.*(role|permission|isAdmin|canAccess|owner)|if.*(valid|sanitize)|rateLimit|throttle|if.*attempts|if.*(origin|referer|x-forwarded)|verify.*(token|signature)|if.*(expired|hash|hmac)'

echo ""
echo "  ╔═══════════════════════════════════════════════╗"
echo "  ║  APEX — Batch Security Audit                  ║"
echo "  ╚═══════════════════════════════════════════════╝"
echo ""
log "Scanning: $SCAN_DIR"
echo ""

REPOS=$(find "$SCAN_DIR" -maxdepth 1 -type d | tail -n +2 | sort)
TOTAL=$(echo "$REPOS" | wc -l | tr -d ' ')
CURRENT=0

printf "  %-35s %6s %6s %s\n" "REPO" "SEC" "AUTH" "TOP FINDING" | tee -a "$LOG"
printf "  %-35s %6s %6s %s\n" "───────────────────────────────────" "──────" "──────" "────────────────────────" | tee -a "$LOG"

while read -r repo_path; do
  [ -d "$repo_path" ] || continue
  name=$(basename "$repo_path")
  CURRENT=$((CURRENT + 1))

  # Count security-relevant lines
  sec_count=$(grep -rlE "$SEC_PATTERNS" --include="*.js" --include="*.ts" --include="*.py" --include="*.go" --include="*.java" --include="*.rb" --include="*.php" "$repo_path" 2>/dev/null \
    | grep -v "node_modules\|vendor\|test\|spec\|__test__\|dist\|build\|\.min\." | wc -l | tr -d ' ')

  # Count auth-specific patterns (higher signal)
  auth_count=$(grep -rlE 'if.*(isAuth|authenticated|authorized|session|token|req\.user|currentUser)' --include="*.js" --include="*.ts" --include="*.py" --include="*.go" --include="*.java" --include="*.rb" --include="*.php" "$repo_path" 2>/dev/null \
    | grep -v "node_modules\|vendor\|test\|spec\|__test__\|dist\|build\|\.min\." | wc -l | tr -d ' ')

  # Get top finding (first match)
  top=""
  if [ "$sec_count" -gt 0 ]; then
    top=$(grep -rE "$SEC_PATTERNS" --include="*.js" --include="*.ts" --include="*.py" --include="*.go" --include="*.java" --include="*.rb" --include="*.php" "$repo_path" 2>/dev/null \
      | grep -v "node_modules\|vendor\|test\|spec\|__test__\|dist\|build\|\.min\." | head -1 | sed 's/.*://' | cut -c1-40)
  fi

  printf "  %-35s %6s %6s %s\n" "$name" "$sec_count" "$auth_count" "$top" | tee -a "$LOG"
  echo "$name|$sec_count|$auth_count" >> "$OUTDIR/scores.txt"

  # Progress indicator every 10 repos
  if [ $((CURRENT % 50)) -eq 0 ]; then
    echo "  --- $CURRENT/$TOTAL ---" | tee -a "$LOG"
  fi
done <<< "$REPOS"

echo ""
echo "  ═══════════════════════════════════════════════" | tee -a "$LOG"
echo "" | tee -a "$LOG"
log "Top targets (most security-critical code):"
echo ""
sort -t'|' -k2 -rn "$OUTDIR/scores.txt" | head -20 | while IFS='|' read -r name sec auth; do
  [ "$sec" -gt 0 ] && printf "  %-35s sec=%s auth=%s\n" "$name" "$sec" "$auth" | tee -a "$LOG"
done

echo ""
ok "Scanned $TOTAL repos"
ok "Results: $OUTDIR/scores.txt"
ok "Next: ./scripts/sec-mutate.sh ~/git/hub/topx/<target> to deep-test"
