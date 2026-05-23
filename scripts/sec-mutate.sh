#!/bin/bash
# Apex CLI — Security Mutation Tester
# Finds security gaps by mutating auth/security code and checking if tests catch it.
# If removing a security check doesn't break any test → you found a vulnerability.
set -uo pipefail

TARGET="${1:?Usage: $0 <repo-path> [test-command]}"
TEST_CMD="${2:-}"
OUTDIR="./output/secmut-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTDIR"
LOG="$OUTDIR/mutations.log"

log()  { echo -e "\033[1;34m[*]\033[0m $*" | tee -a "$LOG"; }
ok()   { echo -e "\033[1;32m[+]\033[0m $*" | tee -a "$LOG"; }
crit() { echo -e "\033[1;31m[!]\033[0m $*" | tee -a "$LOG"; }
warn() { echo -e "\033[1;33m[!]\033[0m $*" | tee -a "$LOG"; }

echo ""
echo "  ╔═══════════════════════════════════════════════╗"
echo "  ║  APEX — Security Mutation Tester              ║"
echo "  ╚═══════════════════════════════════════════════╝"
echo ""
log "Target: $TARGET"

# Auto-detect test command
if [ -z "$TEST_CMD" ]; then
  if [ -f "$TARGET/package.json" ]; then
    TEST_CMD="npm test --prefix $TARGET"
  elif [ -f "$TARGET/Makefile" ]; then
    TEST_CMD="make -C $TARGET test"
  elif [ -f "$TARGET/pytest.ini" ] || [ -d "$TARGET/tests" ]; then
    TEST_CMD="cd $TARGET && python -m pytest -x -q"
  elif [ -f "$TARGET/go.mod" ]; then
    TEST_CMD="cd $TARGET && go test ./..."
  else
    warn "No test command detected. Specify as 2nd argument."
    exit 1
  fi
fi
log "Test cmd: $TEST_CMD"
echo ""

# ═══ Phase 1: Find security-critical code ═══
log "Phase 1: Finding security-critical code..."
echo ""

# Patterns that indicate security-relevant logic
SEC_PATTERNS=(
  # Auth checks
  'if.*isAuth|if.*authenticated|if.*authorized|if.*session|if.*token'
  'if.*req\.user|if.*currentUser|if.*ctx\.user'
  'middleware.*auth|guard.*auth|protect.*route'
  # Permission checks
  'if.*role|if.*permission|if.*isAdmin|if.*canAccess'
  'if.*owner|if.*belongsTo|if.*hasPermission'
  # Input validation
  'if.*valid|sanitize|escape|encode'
  'if.*\.includes\("\.\."\)|if.*path.*traversal'
  # Rate limiting
  'rateLimit|throttle|if.*attempts|if.*locked'
  # Header/origin checks
  'if.*origin|if.*referer|if.*x-forwarded|if.*host'
  'cors.*origin|allowedOrigins|if.*header'
  # Crypto/token validation
  'verify.*token|verify.*signature|if.*expired'
  'if.*hash|if.*hmac|compare.*hash'
)

# Find all security-relevant lines
true > "$OUTDIR/sec-lines.txt"
for pattern in "${SEC_PATTERNS[@]}"; do
  grep -rn --include="*.{js,ts,py,rb,go,java,php}" -iE "$pattern" "$TARGET" 2>/dev/null \
    | grep -v "node_modules\|vendor\|test\|spec\|__test__\|\.min\." \
    >> "$OUTDIR/sec-lines.txt" || true
done

SEC_COUNT=$(sort -u "$OUTDIR/sec-lines.txt" | wc -l | tr -d ' ')
ok "Found $SEC_COUNT security-critical lines"
echo ""

# ═══ Phase 2: Run baseline tests ═══
log "Phase 2: Running baseline tests..."
if eval "$TEST_CMD" > "$OUTDIR/baseline.txt" 2>&1; then
  ok "Baseline tests PASS"
else
  warn "Baseline tests already failing — results may be unreliable"
fi
echo ""

# ═══ Phase 3: Mutate and test ═══
log "Phase 3: Mutating security checks..."
echo ""

SURVIVED=0
KILLED=0
TOTAL_MUTATIONS=0

# Group by file for efficiency
sort -u "$OUTDIR/sec-lines.txt" | cut -d: -f1 | sort -u | while read -r file; do
  [ -f "$file" ] || continue
  
  # Get security lines in this file
  lines=$(grep "^$file:" "$OUTDIR/sec-lines.txt" | cut -d: -f2 | sort -un | head -10)
  
  for lineno in $lines; do
    TOTAL_MUTATIONS=$((TOTAL_MUTATIONS + 1))
    original=$(sed -n "${lineno}p" "$file")
    
    # Skip if line is a comment
    echo "$original" | grep -qE "^\s*(//|#|/\*|\*)" && continue
    
    # Mutation: comment out the security check
    cp "$file" "$file.bak"
    sed -i.mut "${lineno}s/.*/ \/\/ MUTATED: security check removed/" "$file" 2>/dev/null || \
    sed -i '' "${lineno}s/.*/ \/\/ MUTATED: security check removed/" "$file"
    
    # Run tests
    if eval "$TEST_CMD" > /dev/null 2>&1; then
      # Tests still pass with security check removed = VULNERABILITY
      SURVIVED=$((SURVIVED + 1))
      crit "  SURVIVED: $file:$lineno"
      echo "    $original" | tee -a "$LOG"
      echo "$file|$lineno|survived|$original" >> "$OUTDIR/survivors.txt"
    else
      KILLED=$((KILLED + 1))
    fi
    
    # Restore
    mv "$file.bak" "$file"
    rm -f "$file.mut" "${file}.mut"
  done
done

echo ""

# ═══ Phase 4: Analysis ═══
log "Phase 4: Results"
echo ""

SURVIVOR_COUNT=$(wc -l < "$OUTDIR/survivors.txt" 2>/dev/null | tr -d ' ' || echo "0")

if [ "${SURVIVOR_COUNT:-0}" -gt 0 ]; then
  crit "═══ SECURITY GAPS FOUND ═══"
  echo ""
  crit "$SURVIVOR_COUNT security checks can be removed without any test failing!"
  echo ""
  crit "These are potential vulnerabilities:"
  while IFS='|' read -r file line _ code; do
    printf "  %s:%s\n    %s\n\n" "$file" "$line" "$code" | tee -a "$LOG"
  done < "$OUTDIR/survivors.txt"
  echo ""
  crit "Each survivor = a security check with NO test coverage."
  crit "An attacker who finds a way to bypass it has a zero-day."
else
  ok "All security checks are covered by tests. Good."
fi

echo ""
echo "  ╔═══════════════════════════════════════════════╗"
echo "  ║           MUTATION TEST COMPLETE              ║"
echo "  ╚═══════════════════════════════════════════════╝"
echo ""
ok "Security lines:  $SEC_COUNT"
ok "Mutations run:   $TOTAL_MUTATIONS"
ok "Killed (good):   $KILLED"
ok "Survived (BAD):  $SURVIVOR_COUNT"
ok "Output:          $OUTDIR/"
