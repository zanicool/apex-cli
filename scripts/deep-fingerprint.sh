#!/bin/bash
# Apex CLI — Deep Fingerprint + Validate
# 1. Detects versions via JS chunks, build hashes, meta tags, error pages
# 2. Validates BOLA findings directly against live targets
# Usage:
#   ./scripts/deep-fingerprint.sh version <url>     — detect stack + version
#   ./scripts/deep-fingerprint.sh validate <url>    — validate BOLA on live target
#   ./scripts/deep-fingerprint.sh enrich            — enrich all DB targets with versions
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DB="$SCRIPT_DIR/../data/bounty-targets.db"
OUTDIR="$SCRIPT_DIR/../output/deepfp-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTDIR"
LOG="$OUTDIR/deep.log"

log()  { echo -e "\033[1;34m[*]\033[0m $*" | tee -a "$LOG"; }
ok()   { echo -e "\033[1;32m[+]\033[0m $*" | tee -a "$LOG"; }
warn() { echo -e "\033[1;33m[!]\033[0m $*" | tee -a "$LOG"; }
crit() { echo -e "\033[1;31m[!!]\033[0m $*" | tee -a "$LOG"; }

# ═══ Version detection techniques ═══
detect_version() {
  local url="$1"
  log "Deep fingerprint: $url"
  
  local html headers
  html=$(curl -sk --max-time 8 "$url" 2>/dev/null)
  headers=$(curl -sk --max-time 5 -I "$url" 2>/dev/null)
  
  # 1. Next.js version from _buildManifest.js or chunk naming
  if echo "$html" | grep -q "_next/static"; then
    local build_id=$(echo "$html" | grep -o '_next/static/[^/"]*' | head -1 | sed 's|_next/static/||')
    # Next.js exposes version in /_next/static/chunks/webpack-*.js
    local webpack_chunk=$(curl -sk --max-time 5 "$url/_next/static/$build_id/_buildManifest.js" 2>/dev/null | head -5)
    # Check package.json via source map or known paths
    local next_ver=$(curl -sk --max-time 3 "$url/_next/static/$build_id/_ssgManifest.js" -I 2>/dev/null | grep -i "x-nextjs-version\|x-powered-by" | grep -o "[0-9]*\.[0-9]*\.[0-9]*" | head -1)
    [[ -z "$next_ver" ]] && next_ver="build:$build_id"
    echo "nextjs|$next_ver|buildid"
  fi
  
  # 2. React version from JS bundle comments or __REACT_DEVTOOLS_GLOBAL_HOOK__
  local react_ver=$(echo "$html" | grep -o 'react@[0-9.]*\|"react":"[^"]*"\|react/[0-9.]*' | grep -o '[0-9]*\.[0-9]*\.[0-9]*' | head -1)
  [[ -n "$react_ver" ]] && echo "react|$react_ver|html"
  
  # 3. GraphQL introspection → engine version
  local gql_resp=$(curl -sk --max-time 5 "$url/graphql" -H "Content-Type: application/json" -d '{"query":"{__typename}"}' 2>/dev/null)
  if echo "$gql_resp" | grep -q "data\|typename"; then
    # Try introspection for schema info
    local intro=$(curl -sk --max-time 5 "$url/graphql" -H "Content-Type: application/json" -d '{"query":"{ __schema { queryType { name } mutationType { name } types { name } } }"}' 2>/dev/null)
    local type_count=$(echo "$intro" | grep -o '"name"' | wc -l | tr -d ' ')
    # Apollo exposes version in extensions
    local apollo_ver=$(echo "$gql_resp" | grep -o '"apollo[^"]*":"[^"]*"' | head -1)
    echo "graphql|types:$type_count|introspection"
    [[ -n "$apollo_ver" ]] && echo "apollo|$apollo_ver|extension"
    # Check if introspection is enabled (security issue!)
    if [[ $type_count -gt 5 ]]; then
      echo "graphql-introspection|enabled:${type_count}_types|security"
    fi
  fi
  
  # 4. Express/Koa version from error page or x-powered-by
  local powered=$(echo "$headers" | grep -i "x-powered-by" | tr -d '\r')
  [[ -n "$powered" ]] && echo "$(echo "$powered" | sed 's/.*: //')|from-header|header"
  
  # 5. FastAPI/Starlette from /docs or /openapi.json
  local openapi=$(curl -sk --max-time 5 "$url/openapi.json" 2>/dev/null | head -50)
  if echo "$openapi" | grep -q "openapi\|info"; then
    local api_ver=$(echo "$openapi" | grep -o '"version":"[^"]*"' | head -1 | cut -d'"' -f4)
    local api_title=$(echo "$openapi" | grep -o '"title":"[^"]*"' | head -1 | cut -d'"' -f4)
    [[ -n "$api_ver" ]] && echo "api:$api_title|$api_ver|openapi"
  fi
  
  # 6. Nuxt.js from __NUXT__ or _nuxt/ paths
  if echo "$html" | grep -q "__NUXT__\|/_nuxt/"; then
    local nuxt_build=$(echo "$html" | grep -o '/_nuxt/[^"]*\.js' | head -1)
    echo "nuxtjs|detected|html"
  fi
  
  # 7. Server header version
  local server=$(echo "$headers" | grep -i "^server:" | sed 's/server: *//i' | tr -d '\r')
  [[ -n "$server" && "$server" != "cloudflare" ]] && echo "server|$server|header"
  
  # 8. Webpack chunk hash pattern → can identify framework version ranges
  local chunks=$(echo "$html" | grep -o 'src="[^"]*chunk[^"]*"' | head -5)
  if [[ -n "$chunks" ]]; then
    # Modern Next.js uses specific chunk naming: chunks/[hash].js
    # Older uses: _next/static/chunks/pages/...
    if echo "$chunks" | grep -q "chunks/app/"; then
      echo "nextjs-app-router|v13+|chunk-pattern"
    elif echo "$chunks" | grep -q "chunks/pages/"; then
      echo "nextjs-pages-router|v12-|chunk-pattern"
    fi
  fi
  
  # 9. n8n specific
  if echo "$html" | grep -q "n8n\|N8N"; then
    local n8n_ver=$(echo "$html" | grep -o 'n8n@[0-9.]*\|"version":"[0-9.]*"' | grep -o '[0-9]*\.[0-9]*\.[0-9]*' | head -1)
    [[ -n "$n8n_ver" ]] && echo "n8n|$n8n_ver|html"
  fi
  
  # 10. Hoppscotch specific
  if echo "$html" | grep -q "hoppscotch\|Hoppscotch"; then
    echo "hoppscotch|detected|html"
  fi
}

# ═══ Direct BOLA validation ═══
validate_bola() {
  local url="$1"
  log "Validating BOLA on: $url"
  echo ""
  
  # Test 1: GraphQL introspection (info disclosure)
  log "Test 1: GraphQL introspection"
  local intro=$(curl -sk --max-time 5 "$url/graphql" -H "Content-Type: application/json" \
    -d '{"query":"{ __schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind } } }"}' 2>/dev/null)
  if echo "$intro" | grep -q '"types"'; then
    local types=$(echo "$intro" | grep -o '"name":"[^"]*"' | wc -l | tr -d ' ')
    crit "  INTROSPECTION ENABLED — $types types exposed"
    # Look for sensitive types
    echo "$intro" | grep -oi '"name":"[^"]*user[^"]*"\|"name":"[^"]*auth[^"]*"\|"name":"[^"]*admin[^"]*"\|"name":"[^"]*token[^"]*"\|"name":"[^"]*secret[^"]*"\|"name":"[^"]*password[^"]*"' | sort -u | while read -r t; do
      warn "    Sensitive type: $t"
    done
  else
    ok "  Introspection disabled or no GraphQL"
  fi
  
  # Test 2: Unauthenticated API access
  log "Test 2: Unauthenticated API endpoints"
  local endpoints=("/api/v1/users" "/api/users" "/api/v1/me" "/api/config" "/api/v1/flows" "/api/v1/workspaces" "/users" "/admin")
  for ep in "${endpoints[@]}"; do
    local resp=$(curl -sk --max-time 3 -o /dev/null -w "%{http_code}|%{size_download}" "$url$ep" 2>/dev/null)
    local code="${resp%%|*}"
    local size="${resp##*|}"
    if [[ "$code" == "200" && "$size" -gt 50 ]]; then
      crit "  OPEN: $ep → $code (${size}B)"
    elif [[ "$code" == "401" || "$code" == "403" ]]; then
      ok "  Protected: $ep → $code"
    fi
  done
  
  # Test 3: IDOR on sequential IDs
  log "Test 3: IDOR probe (sequential IDs)"
  local id_endpoints=("/api/v1/users/1" "/api/v1/users/2" "/api/users/1" "/api/v1/flows/1")
  for ep in "${id_endpoints[@]}"; do
    local resp=$(curl -sk --max-time 3 -o /dev/null -w "%{http_code}|%{size_download}" "$url$ep" 2>/dev/null)
    local code="${resp%%|*}"
    local size="${resp##*|}"
    if [[ "$code" == "200" && "$size" -gt 50 ]]; then
      crit "  IDOR: $ep → $code (${size}B) — data returned without auth!"
    fi
  done
  
  # Test 4: Debug/docs endpoints
  log "Test 4: Debug/documentation exposure"
  local debug_eps=("/docs" "/swagger" "/openapi.json" "/_debug" "/graphql" "/playground" "/graphiql" "/.env" "/debug/vars" "/actuator")
  for ep in "${debug_eps[@]}"; do
    local resp=$(curl -sk --max-time 3 -o /dev/null -w "%{http_code}|%{size_download}" "$url$ep" 2>/dev/null)
    local code="${resp%%|*}"
    local size="${resp##*|}"
    if [[ "$code" == "200" && "$size" -gt 100 ]]; then
      warn "  EXPOSED: $ep → $code (${size}B)"
    fi
  done
  
  # Test 5: CORS misconfiguration
  log "Test 5: CORS check"
  local cors=$(curl -sk --max-time 3 -H "Origin: https://evil.com" -I "$url/api" 2>/dev/null | grep -i "access-control-allow-origin")
  if echo "$cors" | grep -qi "evil.com\|\*"; then
    crit "  CORS MISCONFIGURED: $cors"
  else
    ok "  CORS OK"
  fi
}

# ═══ Enrich DB with versions ═══
enrich_db() {
  log "Enriching DB targets with version info..."
  local targets=$(sqlite3 "$DB" "
    SELECT DISTINCT t.id, t.domain, f.stack 
    FROM targets t 
    JOIN fingerprints f ON f.target_id = t.id 
    WHERE f.stack IN ('graphql','nextjs','Express','fastapi','Next.js')
    AND (f.version IS NULL OR f.version = '')
    LIMIT 50;")
  
  local total=$(echo "$targets" | grep -c "." || echo 0)
  log "Targets to enrich: $total"
  local i=0
  
  echo "$targets" | while IFS='|' read -r tid domain stack; do
    [[ -z "$tid" ]] && continue
    i=$((i + 1))
    printf "\r  [%d/%d] %s" "$i" "$total" "$domain"
    
    local url="https://$domain"
    local results=$(detect_version "$url" 2>/dev/null)
    
    echo "$results" | while IFS='|' read -r det_stack det_ver det_source; do
      [[ -z "$det_stack" || -z "$det_ver" ]] && continue
      sqlite3 "$DB" "INSERT INTO fingerprints (target_id, stack, version, source, confidence)
        VALUES ($tid, '$det_stack', '$det_ver', '$det_source', 'high')
        ON CONFLICT(target_id, stack) DO UPDATE SET
          version = '$det_ver',
          source = '$det_source',
          last_seen = datetime('now');" 2>/dev/null
    done
  done
  echo ""
  
  local versioned=$(sqlite3 "$DB" "SELECT COUNT(*) FROM fingerprints WHERE version != '' AND version IS NOT NULL;")
  ok "Fingerprints with version: $versioned"
}

# ═══ Main ═══
CMD="${1:-help}"

case "$CMD" in
  version)
    URL="${2:?Usage: $0 version <url>}"
    detect_version "$URL" | while IFS='|' read -r stack ver source; do
      printf "  %-25s %-20s %s\n" "$stack" "$ver" "($source)"
    done
    ;;
  validate)
    URL="${2:?Usage: $0 validate <url>}"
    validate_bola "$URL"
    ;;
  enrich)
    enrich_db
    ;;
  *)
    echo "Usage: $0 <command> [args]"
    echo ""
    echo "Commands:"
    echo "  version <url>    Detect stack + version of a target"
    echo "  validate <url>   Run BOLA/IDOR validation checks"
    echo "  enrich           Enrich all DB targets with version info"
    ;;
esac
