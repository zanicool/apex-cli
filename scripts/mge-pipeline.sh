#!/bin/bash
# Apex CLI — Maturity-Guided Exploitation Pipeline
# Phase 1: cpm scan → rank by security findings
# Phase 2: auth-boundary-scan on lowest-maturity repos
# See: docs/adr/adr-008-maturity-guided-exploitation.md
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_DIR="${1:-$HOME/git/hub/topx}"
CPM_FINDINGS="${CPM_FINDINGS:-$HOME/.local/share/cpm/scan-findings.jsonl}"
OUTDIR="./output/mge-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTDIR"
LOG="$OUTDIR/pipeline.log"

log()  { echo -e "\033[1;34m[*]\033[0m $*" | tee -a "$LOG"; }
ok()   { echo -e "\033[1;32m[+]\033[0m $*" | tee -a "$LOG"; }
warn() { echo -e "\033[1;33m[!]\033[0m $*" | tee -a "$LOG"; }
crit() { echo -e "\033[1;31m[!!]\033[0m $*" | tee -a "$LOG"; }

echo ""
echo "  ╔═══════════════════════════════════════════════╗"
echo "  ║  APEX — Maturity-Guided Exploitation          ║"
echo "  ╚═══════════════════════════════════════════════╝"
echo ""

# ═══ Phase 1: Rank repos by security findings from cpm ═══
log "Phase 1: Ranking repos by cpm security findings..."

if [[ ! -f "$CPM_FINDINGS" ]]; then
  warn "No cpm findings at $CPM_FINDINGS — run: cpm scan $TARGET_DIR --depth 1"
  warn "Falling back to scanning all repos with web frameworks..."
  # Find repos with FastAPI/Flask/Express/Django
  TARGETS=$(find "$TARGET_DIR" -maxdepth 1 -type d | while read -r d; do
    grep -rl "FastAPI\|APIRouter\|flask\|Flask\|express\|@Controller\|urlpatterns" "$d" --include="*.py" --include="*.ts" --include="*.js" 2>/dev/null | grep -v node_modules | head -1 | grep -q . && echo "$d"
  done)
else
  # Rank: repos with most error-level findings = lowest maturity = highest priority
  log "Using cpm findings: $CPM_FINDINGS ($(wc -l < "$CPM_FINDINGS" | tr -d ' ') findings)"
  
  # Get repos sorted by error count (descending)
  PRIORITY_REPOS=$(grep '"severity":"error"' "$CPM_FINDINGS" | \
    sed 's/.*"repo":"\([^"]*\)".*/\1/' | \
    sort | uniq -c | sort -rn | awk '{print $2}' | head -20)
  
  # Map repo names to paths
  TARGETS=""
  for repo in $PRIORITY_REPOS; do
    local_path="$TARGET_DIR/$repo"
    if [[ -d "$local_path" ]]; then
      # Only include if it has a web framework
      if grep -rl "FastAPI\|APIRouter\|flask\|Flask\|express\|@Controller\|urlpatterns" "$local_path" --include="*.py" --include="*.ts" --include="*.js" 2>/dev/null | grep -v node_modules | head -1 | grep -q .; then
        TARGETS="$TARGETS $local_path"
      fi
    fi
  done
  
  # Add repos with security-related warnings too
  MORE_REPOS=$(grep '"check":"security\|"rule":"no-security\|"rule":"no-auth' "$CPM_FINDINGS" 2>/dev/null | \
    sed 's/.*"repo":"\([^"]*\)".*/\1/' | sort -u | head -10)
  for repo in $MORE_REPOS; do
    local_path="$TARGET_DIR/$repo"
    if [[ -d "$local_path" ]] && ! echo "$TARGETS" | grep -q "$local_path"; then
      if grep -rl "FastAPI\|APIRouter\|flask\|Flask\|express\|@Controller\|urlpatterns" "$local_path" --include="*.py" --include="*.ts" --include="*.js" 2>/dev/null | grep -v node_modules | head -1 | grep -q .; then
        TARGETS="$TARGETS $local_path"
      fi
    fi
  done
fi

TARGET_COUNT=$(echo "$TARGETS" | wc -w | tr -d ' ')
log "Priority targets: $TARGET_COUNT repos"
echo ""

# ═══ Phase 2: Auth boundary scan on each target ═══
log "Phase 2: Auth boundary scanning..."
echo ""

TOTAL_FINDINGS=0
TOTAL_BOLA=0
RESULTS_SUMMARY="$OUTDIR/summary.txt"

for target in $TARGETS; do
  repo_name=$(basename "$target")
  log "[$repo_name] scanning..."
  
  # Run auth-boundary-scan, capture output
  SCAN_OUT=$("$SCRIPT_DIR/auth-boundary-scan.sh" "$target" 2>&1)
  
  # Extract findings file from output
  SCAN_FINDINGS=$(echo "$SCAN_OUT" | grep "Results:" | sed 's/.*Results: *//')
  
  if [[ -f "$SCAN_FINDINGS" ]]; then
    COUNT=$(wc -l < "$SCAN_FINDINGS" | tr -d ' ')
    BOLA=$(grep -c '"risk":"HIGH"' "$SCAN_FINDINGS" || echo 0)
    TOTAL_FINDINGS=$((TOTAL_FINDINGS + COUNT))
    TOTAL_BOLA=$((TOTAL_BOLA + BOLA))
    
    if [[ $BOLA -gt 0 ]]; then
      crit "[$repo_name] $COUNT findings, $BOLA BOLA candidates"
      echo "$repo_name: $COUNT findings, $BOLA BOLA" >> "$RESULTS_SUMMARY"
      # Copy findings to our output
      cp "$SCAN_FINDINGS" "$OUTDIR/${repo_name}-findings.jsonl"
    else
      ok "[$repo_name] $COUNT findings (no BOLA)"
    fi
  else
    ok "[$repo_name] clean"
  fi
done

# ═══ Summary ═══
echo ""
echo "  ╔═══════════════════════════════════════════════╗"
echo "  ║           PIPELINE COMPLETE                   ║"
echo "  ╚═══════════════════════════════════════════════╝"
echo ""
ok "Repos scanned:   $TARGET_COUNT"
ok "Total findings:  $TOTAL_FINDINGS"
ok "BOLA candidates: $TOTAL_BOLA"
ok "Results:         $OUTDIR/"
ok "Log:             $LOG"

if [[ -f "$RESULTS_SUMMARY" ]]; then
  echo ""
  log "Repos with BOLA candidates:"
  cat "$RESULTS_SUMMARY" | tee -a "$LOG"
fi
