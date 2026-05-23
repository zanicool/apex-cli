#!/bin/bash
# Apex CLI — Batch Security Mutation Runner
# Runs sec-mutate on top targets from sec-audit-batch results.
# Focuses on repos with test suites and high security-code density.
set -uo pipefail

SCAN_DIR="${1:-$HOME/git/hub/topx}"
OUTDIR="./output/secmut-batch-$(date +%Y%m%d-%H%M%S)"
STATE="$OUTDIR/state.log"
LOG="$OUTDIR/run.log"
mkdir -p "$OUTDIR"

log()  { echo -e "\033[1;34m[*]\033[0m $*" | tee -a "$LOG"; }
ok()   { echo -e "\033[1;32m[+]\033[0m $*" | tee -a "$LOG"; }
warn() { echo -e "\033[1;33m[!]\033[0m $*" | tee -a "$LOG"; }
crit() { echo -e "\033[1;31m[!]\033[0m $*" | tee -a "$LOG"; }
step_done() { grep -qxF "$1" "$STATE" 2>/dev/null; }
mark_done() { echo "$1" >> "$STATE"; }

echo ""
echo "  ╔═══════════════════════════════════════════════╗"
echo "  ║  APEX — Batch Security Mutation Runner        ║"
echo "  ╚═══════════════════════════════════════════════╝"
echo ""
log "Scan dir: $SCAN_DIR"
log "Output:   $OUTDIR"
[ -f "$STATE" ] && log "Resuming: $(wc -l < "$STATE" | tr -d ' ') done"
echo ""

# Detect test command for a repo
detect_test_cmd() {
  local repo="$1"
  if [ -f "$repo/package.json" ] && grep -q '"test"' "$repo/package.json" 2>/dev/null; then
    echo "cd $repo && npm test --silent 2>/dev/null"
  elif [ -f "$repo/Makefile" ] && grep -q "^test:" "$repo/Makefile" 2>/dev/null; then
    echo "make -C $repo test 2>/dev/null"
  elif [ -f "$repo/go.mod" ]; then
    echo "cd $repo && go test -short -count=1 ./... 2>/dev/null"
  elif [ -d "$repo/tests" ] && { [ -f "$repo/setup.py" ] || [ -f "$repo/pyproject.toml" ]; }; then
    echo "cd $repo && python -m pytest -x -q --timeout=30 2>/dev/null"
  else
    echo ""
  fi
}

# Security patterns to mutate
SEC_PATTERNS='if.*(isAuth|authenticated|authorized|session\b|token\b|req\.user|currentUser|ctx\.user)|middleware.*(auth|guard|protect)|if.*(role|permission|isAdmin|canAccess|owner)|verify.*(token|signature)|if.*(expired|hash|hmac)|rateLimit|throttle'

# Get repos sorted by security-code density (from previous audit or re-scan)
log "Finding repos with security code + test suites..."
echo ""

TARGETS=()
REPO_LIST=$(find "$SCAN_DIR" -maxdepth 1 -type d | tail -n +2 | sort)
SCAN_TOTAL=$(echo "$REPO_LIST" | wc -l | tr -d ' ')
SCAN_I=0

while read -r repo_path; do
  [ -d "$repo_path" ] || continue
  name=$(basename "$repo_path")
  SCAN_I=$((SCAN_I + 1))
  printf "\r  [%d/%d] checking %s...          " "$SCAN_I" "$SCAN_TOTAL" "$name"

  # Skip huge repos (>50MB .git = too slow)
  git_size=$(du -sm "$repo_path/.git" 2>/dev/null | cut -f1)
  [ "${git_size:-0}" -gt 200 ] && continue

  # Must have security-relevant code (timeout 5s per repo)
  sec=$(timeout 5 grep -rlE "$SEC_PATTERNS" --include="*.js" --include="*.ts" --include="*.py" --include="*.go" --include="*.java" "$repo_path" 2>/dev/null \
    | grep -v "node_modules\|vendor\|test\|spec\|dist\|build" | wc -l | tr -d ' ')
  [ "$sec" -lt 5 ] && continue

  # Must have a test suite
  test_cmd=$(detect_test_cmd "$repo_path")
  [ -z "$test_cmd" ] && continue

  TARGETS+=("$repo_path|$sec|$test_cmd")
done <<< "$REPO_LIST"
printf "\r                                                    \n"

TOTAL=${#TARGETS[@]}
ok "Found $TOTAL repos with security code + tests"
echo ""

# Run mutation on each target
CURRENT=0
TOTAL_SURVIVORS=0

for entry in "${TARGETS[@]}"; do
  IFS='|' read -r repo_path sec test_cmd <<< "$entry"
  name=$(basename "$repo_path")
  CURRENT=$((CURRENT + 1))

  step_done "$name" && continue

  log "[$CURRENT/$TOTAL] $name (sec=$sec)"

  # Find security-critical lines
  sec_files=$(grep -rlE "$SEC_PATTERNS" --include="*.js" --include="*.ts" --include="*.py" --include="*.go" --include="*.java" "$repo_path" 2>/dev/null \
    | grep -v "node_modules\|vendor\|test\|spec\|dist\|build" | head -20)

  [ -z "$sec_files" ] && { mark_done "$name"; continue; }

  # Run baseline test (timeout 60s)
  if ! timeout 60 bash -c "$test_cmd" > /dev/null 2>&1; then
    warn "  Tests already failing, skipping"
    mark_done "$name"
    continue
  fi

  # Mutate each security-critical file
  REPO_SURVIVORS=0
  for file in $sec_files; do
    # Get security lines in this file
    lines=$(grep -nE "$SEC_PATTERNS" "$file" 2>/dev/null | grep -v "^\s*//" | head -5 | cut -d: -f1)
    
    for lineno in $lines; do
      original=$(sed -n "${lineno}p" "$file")
      echo "$original" | grep -qE "^\s*(//|#|/\*|\*|$)" && continue

      # Mutate: comment out
      cp "$file" "$file.secmut.bak"
      if [[ "$file" == *.py ]]; then
        sed -i '' "${lineno}s/.*/    pass  # MUTATED/" "$file" 2>/dev/null
      else
        sed -i '' "${lineno}s/.*/\/\/ MUTATED: removed/" "$file" 2>/dev/null
      fi

      # Test (timeout 60s)
      if timeout 60 bash -c "$test_cmd" > /dev/null 2>&1; then
        REPO_SURVIVORS=$((REPO_SURVIVORS + 1))
        TOTAL_SURVIVORS=$((TOTAL_SURVIVORS + 1))
        crit "  SURVIVED: $file:$lineno"
        echo "    $original" | tee -a "$LOG"
        echo "$name|$file|$lineno|$original" >> "$OUTDIR/survivors.txt"
      fi

      # Restore
      mv "$file.secmut.bak" "$file"
    done
  done

  if [ "$REPO_SURVIVORS" -gt 0 ]; then
    crit "  → $REPO_SURVIVORS untested security checks in $name"
  else
    ok "  → All security checks covered"
  fi
  echo ""
  mark_done "$name"
done

# ═══ Summary ═══
echo ""
echo "  ╔═══════════════════════════════════════════════╗"
echo "  ║           MUTATION RUN COMPLETE               ║"
echo "  ╚═══════════════════════════════════════════════╝"
echo ""
ok "Repos tested:    $CURRENT"
ok "Total survivors: $TOTAL_SURVIVORS"
if [ -f "$OUTDIR/survivors.txt" ]; then
  echo ""
  crit "Untested security checks (potential zero-days):"
  echo ""
  sort "$OUTDIR/survivors.txt" | while IFS='|' read -r name file line code; do
    printf "  %-20s %s:%s\n" "$name" "$(basename "$file")" "$line" | tee -a "$LOG"
    echo "    $code" | tee -a "$LOG"
  done
fi
echo ""
ok "Full results: $OUTDIR/survivors.txt"
ok "Resume: $0 $SCAN_DIR"
