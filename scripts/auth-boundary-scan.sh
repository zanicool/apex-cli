#!/bin/bash
# Apex CLI — Auth Boundary Scanner
# Finds routes WITHOUT auth middleware that DO access data = BOLA candidates
# See: docs/adr/adr-008-maturity-guided-exploitation.md
set -uo pipefail

TARGET="${1:?Usage: $0 <repo-path>}"
OUTDIR="./output/authscan-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTDIR"
LOG="$OUTDIR/scan.log"
FINDINGS="$OUTDIR/findings.jsonl"

log()  { echo -e "\033[1;34m[*]\033[0m $*" | tee -a "$LOG"; }
ok()   { echo -e "\033[1;32m[+]\033[0m $*" | tee -a "$LOG"; }
warn() { echo -e "\033[1;33m[!]\033[0m $*" | tee -a "$LOG"; }
crit() { echo -e "\033[1;31m[!!]\033[0m $*" | tee -a "$LOG"; }

echo ""
echo "  ╔═══════════════════════════════════════════════╗"
echo "  ║  APEX — Auth Boundary Scanner                 ║"
echo "  ╚═══════════════════════════════════════════════╝"
echo ""

# Resolve path
SCAN_DIR="$TARGET"
if [[ "$TARGET" == http* ]] || [[ "$TARGET" == git@* ]]; then
  SCAN_DIR="$OUTDIR/repo"
  log "Cloning $TARGET..."
  git clone --depth 1 "$TARGET" "$SCAN_DIR" 2>>"$LOG" || { crit "Clone failed"; exit 1; }
fi

REPO_NAME=$(basename "$SCAN_DIR")
log "Target: $SCAN_DIR ($REPO_NAME)"
log "Output: $OUTDIR"

# ═══ Detect framework ═══
detect_framework() {
  local dir="$1"
  # Check Python frameworks first (most common in our targets)
  if grep -rl "FastAPI\|APIRouter" "$dir" --include="*.py" 2>/dev/null | grep -v node_modules | head -1 | grep -q .; then
    echo "fastapi"; return
  fi
  if grep -rl "flask\|Flask" "$dir" --include="*.py" 2>/dev/null | grep -v node_modules | head -1 | grep -q .; then
    echo "flask"; return
  fi
  if grep -rl "urlpatterns" "$dir" --include="*.py" 2>/dev/null | grep -v node_modules | head -1 | grep -q .; then
    echo "django"; return
  fi
  # JS/TS frameworks
  if grep -rl "@Controller" "$dir" --include="*.ts" 2>/dev/null | grep -v node_modules | grep -v dist | head -1 | grep -q .; then
    echo "nestjs"; return
  fi
  if grep -rl "express\(\)\|Router()" "$dir" --include="*.js" --include="*.ts" 2>/dev/null | grep -v node_modules | grep -v dist | head -1 | grep -q .; then
    echo "express"; return
  fi
  # Java
  if grep -rl "@GetMapping\|@PostMapping\|@RequestMapping" "$dir" --include="*.java" 2>/dev/null | head -1 | grep -q .; then
    echo "spring"; return
  fi
  echo "unknown"
}

FRAMEWORK=$(detect_framework "$SCAN_DIR")
log "Framework: $FRAMEWORK"

# ═══ Auth patterns per framework ═══
AUTH_PATTERNS_FASTAPI='Depends\(get_current_user\|Depends\(get_admin\|Depends\(get_verified\|Security(\|oauth2_scheme\|HTTPBearer'
AUTH_PATTERNS_FLASK='@login_required\|@jwt_required\|@auth_required\|@token_required\|verify_token\|current_user'
AUTH_PATTERNS_DJANGO='@login_required\|@permission_required\|IsAuthenticated\|IsAdminUser\|@staff_member_required'
AUTH_PATTERNS_EXPRESS='authenticate\|requireAuth\|isAuthenticated\|passport\.\|verifyToken\|authMiddleware\|jwt\.\|protect'
AUTH_PATTERNS_NESTJS='@UseGuards\|AuthGuard\|@ApiBearerAuth\|JwtAuthGuard\|RolesGuard'
AUTH_PATTERNS_SPRING='@PreAuthorize\|@Secured\|@RolesAllowed\|SecurityFilterChain\|hasRole\|hasAuthority'

# ═══ Data access patterns ═══
DATA_ACCESS='db\.\|\.query\|\.find\|\.findOne\|\.select\|\.execute\|\.fetch\|session\.\|cursor\.\|collection\.\|repository\.\|\.save\|\.delete\|\.update\|\.create\|\.remove\|readFile\|writeFile'

# ═══ Scan routes ═══

scan_fastapi() {
  local dir="$1"
  log "Scanning FastAPI routes..."
  local route_files
  route_files=$(grep -rl "@router\.\|@app\." "$dir" --include="*.py" 2>/dev/null | grep -v node_modules | grep -v __pycache__)
  
  for f in $route_files; do
    grep -n "@router\.\(get\|post\|put\|delete\|patch\)\|@app\.\(get\|post\|put\|delete\|patch\)" "$f" 2>/dev/null | while IFS=: read -r line_num line_content; do
      # Extract route path (between first pair of quotes)
      local route
      route=$(echo "$line_content" | sed -n "s/.*['\"]\(\/[^'\"]*\)['\"].*/\1/p")
      [[ -z "$route" ]] && route="/"
      local method
      method=$(echo "$line_content" | sed -n 's/.*@[a-z_]*\.\(get\|post\|put\|delete\|patch\).*/\1/p' | tr '[:lower:]' '[:upper:]')
      [[ -z "$method" ]] && method="GET"
      
      # Check next 8 lines for auth dependency
      local context
      context=$(sed -n "${line_num},$((line_num + 8))p" "$f")
      local has_auth=0
      if echo "$context" | grep -q "Depends.get_current_user\|Depends.get_admin\|Depends.get_verified\|Security.\|oauth2_scheme\|HTTPBearer\|CurrentActiveUser\|CurrentUser\|current_user:\|api_key_security\|get_current_user_optional\|Depends.get_user\|Depends.auth"; then
        has_auth=1
      fi
      
      # Check handler body (next 30 lines) for data access
      local body
      body=$(sed -n "${line_num},$((line_num + 30))p" "$f")
      local has_data=0
      if echo "$body" | grep -q "db\.\|\.query\|\.find\|\.execute\|\.fetch\|session\.\|cursor\.\|\.save\|\.delete\|\.update\|\.create"; then
        has_data=1
      fi
      
      if [[ $has_auth -eq 0 ]]; then
        local risk="LOW"
        if [[ $has_data -eq 1 ]]; then
          risk="HIGH"
          crit "BOLA: $method $route in $f:$line_num (no auth + data access)"
        else
          warn "NO_AUTH: $method $route in $f:$line_num"
        fi
        local rel_file="${f#$dir/}"
        echo "{\"repo\":\"$REPO_NAME\",\"file\":\"$rel_file\",\"line\":$line_num,\"route\":\"$method $route\",\"auth\":\"MISSING\",\"data_access\":$has_data,\"risk\":\"$risk\",\"framework\":\"fastapi\"}" >> "$FINDINGS"
      fi
    done
  done
}

scan_flask() {
  local dir="$1"
  log "Scanning Flask routes..."
  local route_files
  route_files=$(grep -rl "@.*\.route\|@app\.route" "$dir" --include="*.py" 2>/dev/null | grep -v node_modules | grep -v __pycache__)
  
  for f in $route_files; do
    grep -n "@.*\.route\|@.*_ns\.route" "$f" 2>/dev/null | while IFS=: read -r line_num line_content; do
      local route
      route=$(echo "$line_content" | sed "s/.*['\"]\\(\/[^'\"]*\\)['\"].*/\\1/" | grep "^/" || echo "/unknown")
      local method="GET"
      echo "$line_content" | grep -qi "methods.*POST" && method="POST"
      
      # Check surrounding lines for auth decorators
      local context
      context=$(sed -n "$((line_num > 3 ? line_num - 3 : 1)),$((line_num + 5))p" "$f")
      local has_auth=0
      if echo "$context" | grep -q "login_required\|jwt_required\|auth_required\|token_required\|verify_token\|current_user"; then
        has_auth=1
      fi
      # Check method_decorators on class
      if sed -n "1,${line_num}p" "$f" | grep -q "method_decorators.*login_required\|method_decorators.*auth"; then
        has_auth=1
      fi
      
      local body
      body=$(sed -n "${line_num},$((line_num + 30))p" "$f")
      local has_data=0
      echo "$body" | grep -q "db\.\|\.query\|\.find\|\.execute\|\.fetch\|session\.\|cursor\.\|\.save\|\.delete\|\.update\|\.create" && has_data=1
      
      if [[ $has_auth -eq 0 ]]; then
        local risk="LOW"
        if [[ $has_data -eq 1 ]]; then
          risk="HIGH"
          crit "BOLA: $method $route in $f:$line_num (no auth + data access)"
        else
          warn "NO_AUTH: $method $route in $f:$line_num"
        fi
        local rel_file="${f#$dir/}"
        echo "{\"repo\":\"$REPO_NAME\",\"file\":\"$rel_file\",\"line\":$line_num,\"route\":\"$method $route\",\"auth\":\"MISSING\",\"data_access\":$has_data,\"risk\":\"$risk\",\"framework\":\"flask\"}" >> "$FINDINGS"
      fi
    done
  done
}

scan_express() {
  local dir="$1"
  log "Scanning Express/Koa routes..."
  local route_files
  route_files=$(grep -rl "router\.\(get\|post\|put\|delete\|patch\)\|app\.\(get\|post\|put\|delete\)" "$dir" --include="*.js" --include="*.ts" 2>/dev/null | grep -v node_modules | grep -v dist)
  
  for f in $route_files; do
    grep -n "router\.\(get\|post\|put\|delete\|patch\)\|app\.\(get\|post\|put\|delete\|patch\)" "$f" 2>/dev/null | while IFS=: read -r line_num line_content; do
      local route
      route=$(echo "$line_content" | sed "s/.*['\"]\\(\/[^'\"]*\\)['\"].*/\\1/" | grep "^/" || echo "/unknown")
      local method
      method=$(echo "$line_content" | sed 's/.*\.\(get\|post\|put\|delete\|patch\).*/\1/' | tr '[:lower:]' '[:upper:]')
      
      # Express middleware is in the same line between route and handler
      local has_auth=0
      if echo "$line_content" | grep -qi "authenticate\|requireAuth\|isAuthenticated\|passport\|verifyToken\|authMiddleware\|jwt\|protect"; then
        has_auth=1
      fi
      # Check file-level middleware
      if head -30 "$f" | grep -q "router\.use.*auth\|app\.use.*auth"; then
        has_auth=1
      fi
      
      local body
      body=$(sed -n "${line_num},$((line_num + 20))p" "$f")
      local has_data=0
      echo "$body" | grep -q "db\.\|\.query\|\.find\|\.findOne\|\.select\|\.execute\|\.fetch\|\.save\|\.delete\|\.update\|\.create" && has_data=1
      
      if [[ $has_auth -eq 0 ]]; then
        local risk="LOW"
        if [[ $has_data -eq 1 ]]; then
          risk="HIGH"
          crit "BOLA: $method $route in $f:$line_num (no auth + data access)"
        else
          warn "NO_AUTH: $method $route in $f:$line_num"
        fi
        local rel_file="${f#$dir/}"
        echo "{\"repo\":\"$REPO_NAME\",\"file\":\"$rel_file\",\"line\":$line_num,\"route\":\"$method $route\",\"auth\":\"MISSING\",\"data_access\":$has_data,\"risk\":\"$risk\",\"framework\":\"express\"}" >> "$FINDINGS"
      fi
    done
  done
}

scan_django() {
  local dir="$1"
  log "Scanning Django views..."
  local view_files
  view_files=$(find "$dir" -name "views.py" -o -name "viewsets.py" | grep -v node_modules | grep -v __pycache__)
  
  for f in $view_files; do
    grep -n "^class \|^def " "$f" 2>/dev/null | while IFS=: read -r line_num line_content; do
      local name
      name=$(echo "$line_content" | sed 's/.*\(class\|def\) \([a-zA-Z_]*\).*/\2/')
      
      # Check decorators above (4 lines up)
      local context
      context=$(sed -n "$((line_num > 4 ? line_num - 4 : 1)),$((line_num))p" "$f")
      local has_auth=0
      echo "$context" | grep -q "login_required\|permission_required\|IsAuthenticated\|IsAdminUser\|staff_member_required" && has_auth=1
      # Check class-level permission_classes
      local body
      body=$(sed -n "${line_num},$((line_num + 30))p" "$f")
      echo "$body" | grep -q "permission_classes.*IsAuthenticated\|authentication_classes" && has_auth=1
      
      local has_data=0
      echo "$body" | grep -q "\.objects\.\|queryset\|\.filter\|\.get\|\.save\|\.delete\|\.create" && has_data=1
      
      if [[ $has_auth -eq 0 ]]; then
        local risk="LOW"
        if [[ $has_data -eq 1 ]]; then
          risk="HIGH"
          crit "BOLA: $name in $f:$line_num (no auth + data access)"
        else
          warn "NO_AUTH: $name in $f:$line_num"
        fi
        local rel_file="${f#$dir/}"
        echo "{\"repo\":\"$REPO_NAME\",\"file\":\"$rel_file\",\"line\":$line_num,\"route\":\"$name\",\"auth\":\"MISSING\",\"data_access\":$has_data,\"risk\":\"$risk\",\"framework\":\"django\"}" >> "$FINDINGS"
      fi
    done
  done
}

scan_nestjs() {
  local dir="$1"
  log "Scanning NestJS controllers..."
  local ctrl_files
  ctrl_files=$(find "$dir" -name "*.controller.ts" | grep -v node_modules | grep -v dist)
  
  for f in $ctrl_files; do
    grep -n "@Get\|@Post\|@Put\|@Delete\|@Patch" "$f" 2>/dev/null | while IFS=: read -r line_num line_content; do
      local route
      route=$(echo "$line_content" | sed "s/.*['\"]\\(\/[^'\"]*\\)['\"].*/\\1/" | grep "^/" || echo "/")
      local method
      method=$(echo "$line_content" | sed 's/.*@\(Get\|Post\|Put\|Delete\|Patch\).*/\1/' | tr '[:lower:]' '[:upper:]')
      
      # Check for guards (class-level or method-level)
      local context
      context=$(sed -n "$((line_num > 3 ? line_num - 3 : 1)),$((line_num))p" "$f")
      local has_auth=0
      echo "$context" | grep -q "@UseGuards\|AuthGuard\|@ApiBearerAuth\|JwtAuthGuard\|RolesGuard" && has_auth=1
      # Class-level guard
      head -20 "$f" | grep -q "@UseGuards\|AuthGuard\|@ApiBearerAuth" && has_auth=1
      
      local body
      body=$(sed -n "${line_num},$((line_num + 20))p" "$f")
      local has_data=0
      echo "$body" | grep -q "this\..*Service\|this\..*Repository\|\.find\|\.save\|\.delete\|\.update\|\.create" && has_data=1
      
      if [[ $has_auth -eq 0 ]]; then
        local risk="LOW"
        if [[ $has_data -eq 1 ]]; then
          risk="HIGH"
          crit "BOLA: $method $route in $f:$line_num (no auth + data access)"
        else
          warn "NO_AUTH: $method $route in $f:$line_num"
        fi
        local rel_file="${f#$dir/}"
        echo "{\"repo\":\"$REPO_NAME\",\"file\":\"$rel_file\",\"line\":$line_num,\"route\":\"$method $route\",\"auth\":\"MISSING\",\"data_access\":$has_data,\"risk\":\"$risk\",\"framework\":\"nestjs\"}" >> "$FINDINGS"
      fi
    done
  done
}

# ═══ Run ═══
case "$FRAMEWORK" in
  fastapi) scan_fastapi "$SCAN_DIR" ;;
  flask)   scan_flask "$SCAN_DIR" ;;
  express) scan_express "$SCAN_DIR" ;;
  django)  scan_django "$SCAN_DIR" ;;
  nestjs)  scan_nestjs "$SCAN_DIR" ;;
  *)
    warn "Unknown framework — trying all scanners"
    scan_fastapi "$SCAN_DIR"
    scan_flask "$SCAN_DIR"
    scan_express "$SCAN_DIR"
    scan_django "$SCAN_DIR"
    scan_nestjs "$SCAN_DIR"
    ;;
esac

# ═══ Summary ═══
echo ""
echo "  ╔═══════════════════════════════════════════════╗"
echo "  ║           SCAN COMPLETE                       ║"
echo "  ╚═══════════════════════════════════════════════╝"
echo ""
FINDING_COUNT=0
BOLA_COUNT=0
if [[ -f "$FINDINGS" ]]; then
  FINDING_COUNT=$(wc -l < "$FINDINGS" | tr -d ' ')
  BOLA_COUNT=$(grep -c '"risk":"HIGH"' "$FINDINGS" || echo 0)
fi
ok "Findings:        $FINDING_COUNT"
ok "BOLA candidates: $BOLA_COUNT"
ok "Results:         $FINDINGS"
ok "Log:             $LOG"

[[ -f "$FINDINGS" && $BOLA_COUNT -gt 0 ]] && echo "" && log "Top BOLA candidates:" && grep '"risk":"HIGH"' "$FINDINGS" | head -10
