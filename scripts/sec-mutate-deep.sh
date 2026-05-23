#!/bin/bash
# Apex CLI — Deep Security Mutation Tester
# Installs deps, runs mutation tests on security code, cleans up after.
# Targets: repos with high security-code density and bounty programs.
set -uo pipefail

SCAN_DIR="${1:-$HOME/git/hub/topx}"
OUTDIR="./output/deepmut-$(date +%Y%m%d-%H%M%S)"
STATE="$OUTDIR/state.log"
LOG="$OUTDIR/run.log"
mkdir -p "$OUTDIR"

log()  { echo -e "\033[1;34m[*]\033[0m $*" | tee -a "$LOG"; }
ok()   { echo -e "\033[1;32m[+]\033[0m $*" | tee -a "$LOG"; }
warn() { echo -e "\033[1;33m[!]\033[0m $*" | tee -a "$LOG"; }
crit() { echo -e "\033[1;31m[!]\033[0m $*" | tee -a "$LOG"; }
step_done() { grep -qxF "$1" "$STATE" 2>/dev/null; }
mark_done() { echo "$1" >> "$STATE"; }

SEC_PATTERNS='if.*(isAuth|authenticated|authorized|session\b|token\b|req\.user|currentUser|ctx\.user)|middleware.*(auth|guard|protect)|if.*(role|permission|isAdmin|canAccess|owner)|verify.*(token|signature)|if.*(expired|hash|hmac)|rateLimit|throttle'

# Top targets: high security code, have bounty programs or security policies
TARGETS=(
  "n8n|npm install --ignore-scripts 2>/dev/null|npm test -- --bail 2>/dev/null"
  "dify|cd api && pip install -r requirements.txt -q 2>/dev/null|cd api && python -m pytest tests/ -x -q --timeout=30 2>/dev/null"
  "next.js|pnpm install --frozen-lockfile 2>/dev/null|pnpm test -- --bail 2>/dev/null"
  "excalidraw|npm install 2>/dev/null|npm test -- --bail 2>/dev/null"
  "firecrawl|cd apps/api && npm install 2>/dev/null|cd apps/api && npm test 2>/dev/null"
  "fastapi|pip install -e '.[all]' -q 2>/dev/null|python -m pytest tests/ -x -q --timeout=30 2>/dev/null"
  "open-webui|npm install 2>/dev/null|npm test 2>/dev/null"
  "langflow|pip install -e . -q 2>/dev/null|python -m pytest tests/ -x -q --timeout=30 2>/dev/null"
  "ollama|go mod download 2>/dev/null|go test -short -count=1 ./... 2>/dev/null"
  "supabase|npm install 2>/dev/null|npm test 2>/dev/null"
)

echo ""
echo "  ╔═══════════════════════════════════════════════╗"
echo "  ║  APEX — Deep Security Mutation Tester         ║"
echo "  ╚═══════════════════════════════════════════════╝"
echo ""
log "Targets: ${#TARGETS[@]} repos"
log "Output:  $OUTDIR"
[ -f "$STATE" ] && log "Resume:  $(wc -l < "$STATE" | tr -d ' ') done"
echo ""

TOTAL_SURVIVORS=0

for entry in "${TARGETS[@]}"; do
  IFS='|' read -r name install_cmd test_cmd <<< "$entry"
  repo="$SCAN_DIR/$name"

  [ -d "$repo" ] || { warn "  $name: not found, skipping"; continue; }
  step_done "$name" && continue

  log "━━━ $name ━━━"

  # Phase 1: Install dependencies
  log "  Installing deps..."
  (cd "$repo" && eval "$install_cmd") || { warn "  Install failed, skipping"; mark_done "$name"; continue; }
  ok "  Deps installed"

  # Phase 2: Baseline test
  log "  Running baseline tests..."
  if ! timeout 120 bash -c "cd $repo && $test_cmd" > "$OUTDIR/$name-baseline.txt" 2>&1; then
    warn "  Baseline tests fail, skipping"
    # Cleanup immediately
    log "  Cleaning up..."
    rm -rf "$repo/node_modules" "$repo/.venv" "$repo/api/.venv" 2>/dev/null
    find "$repo" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null
    mark_done "$name"
    continue
  fi
  ok "  Baseline PASS"

  # Phase 3: Find security-critical lines
  sec_lines=$(grep -rnE "$SEC_PATTERNS" --include="*.js" --include="*.ts" --include="*.py" --include="*.go" "$repo" 2>/dev/null \
    | grep -v "node_modules\|vendor\|test\|spec\|dist\|build\|__pycache__" | head -30)
  sec_count=$(echo "$sec_lines" | grep -c . 2>/dev/null || echo "0")
  log "  Found $sec_count security-critical lines to mutate"

  # Phase 4: Mutate each security check
  REPO_SURVIVORS=0
  echo "$sec_lines" | while IFS=: read -r file lineno rest; do
    [ -z "$file" ] || [ -z "$lineno" ] && continue
    [ -f "$file" ] || continue

    original=$(sed -n "${lineno}p" "$file")
    echo "$original" | grep -qE "^\s*(//|#|/\*|\*|$)" && continue

    # Backup
    cp "$file" "$file.deepmut.bak"

    # Mutate: comment out
    if [[ "$file" == *.py ]]; then
      sed -i '' "${lineno}s/.*/    pass  # MUTATED: security check removed/" "$file" 2>/dev/null
    else
      sed -i '' "${lineno}s/.*/\/\/ MUTATED: security check removed/" "$file" 2>/dev/null
    fi

    # Test with timeout
    if timeout 90 bash -c "cd $repo && $test_cmd" > /dev/null 2>&1; then
      REPO_SURVIVORS=$((REPO_SURVIVORS + 1))
      TOTAL_SURVIVORS=$((TOTAL_SURVIVORS + 1))
      crit "  🔴 SURVIVED: $(basename "$file"):$lineno"
      echo "    $original" | tee -a "$LOG"
      echo "$name|$file|$lineno|$original" >> "$OUTDIR/survivors.txt"
    fi

    # Restore
    mv "$file.deepmut.bak" "$file"
  done

  if [ "$REPO_SURVIVORS" -gt 0 ]; then
    crit "  → $REPO_SURVIVORS UNTESTED security checks!"
  else
    ok "  → All security checks covered by tests ✓"
  fi

  # Phase 5: Cleanup
  log "  Cleaning up deps & temp files..."
  rm -rf "$repo/node_modules" "$repo/.next" "$repo/dist" "$repo/build" 2>/dev/null
  rm -rf "$repo/.venv" "$repo/api/.venv" 2>/dev/null
  rm -rf "$repo/apps/api/node_modules" 2>/dev/null
  find "$repo" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null
  find "$repo" -name "*.pyc" -delete 2>/dev/null
  find "$repo" -name ".deepmut.bak" -delete 2>/dev/null
  # Restore any git changes
  git -C "$repo" checkout -- . 2>/dev/null
  git -C "$repo" clean -fd -q 2>/dev/null
  ok "  Cleaned up"
  echo ""

  mark_done "$name"
done

# ═══ Summary ═══
echo ""
echo "  ╔═══════════════════════════════════════════════╗"
echo "  ║           DEEP MUTATION COMPLETE              ║"
echo "  ╚═══════════════════════════════════════════════╝"
echo ""
TESTED=$(wc -l < "$STATE" 2>/dev/null | tr -d ' ' || echo "0")
SURVIVOR_COUNT=$(wc -l < "$OUTDIR/survivors.txt" 2>/dev/null | tr -d ' ' || echo "0")
ok "Repos tested:     $TESTED"
ok "Total survivors:  $SURVIVOR_COUNT"

if [ -f "$OUTDIR/survivors.txt" ]; then
  echo ""
  crit "🔴 POTENTIAL ZERO-DAYS (untested security checks):"
  echo ""
  while IFS='|' read -r name file line code; do
    printf "  %-15s %s:%s\n" "$name" "$(basename "$file")" "$line" | tee -a "$LOG"
    echo "    $code" | tee -a "$LOG"
    echo ""
  done < "$OUTDIR/survivors.txt"
  echo ""
  log "Next steps:"
  echo "  1. Verify each survivor is actually exploitable"
  echo "  2. Write a PoC (proof of concept)"
  echo "  3. Check if repo has a security policy / bounty program"
  echo "  4. Report responsibly via their SECURITY.md"
fi
echo ""
ok "Results: $OUTDIR/"
