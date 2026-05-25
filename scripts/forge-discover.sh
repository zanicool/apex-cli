#!/usr/bin/env bash
#
# forge-discover.sh — Discover and clone repos from multiple forges.
# Supports: GitHub, GitLab, Codeberg (Forgejo), Bitbucket, SourceHut.
#
# Usage:
#   ./scripts/forge-discover.sh search <query>     — search all forges
#   ./scripts/forge-discover.sh trending           — trending repos per forge
#   ./scripts/forge-discover.sh clone <forge/repo> — clone for analysis
#   ./scripts/forge-discover.sh scan <path>        — scan cloned repos into dep-tree
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLONE_DIR="${FORGE_CLONE_DIR:-$HOME/git/hub/forge-repos}"
DB="$SCRIPT_DIR/../data/dep-tree.db"
LOG="$SCRIPT_DIR/../output/forge-discover.log"
mkdir -p "$CLONE_DIR" "$(dirname "$LOG")"

log()  { echo -e "\033[1;34m[*]\033[0m $*" | tee -a "$LOG"; }
ok()   { echo -e "\033[1;32m[+]\033[0m $*" | tee -a "$LOG"; }
warn() { echo -e "\033[1;33m[!]\033[0m $*" | tee -a "$LOG"; }

# ═══ Search APIs ═══

search_github() {
  local query="$1"
  curl -s "https://api.github.com/search/repositories?q=$query&sort=stars&per_page=20" 2>/dev/null | \
    python3 -c "
import json, sys
data = json.load(sys.stdin)
for r in data.get('items', [])[:20]:
    print(f\"github|{r['full_name']}|{r['stargazers_count']}|{r.get('language','?')}|{r['html_url']}\")
" 2>/dev/null
}

search_gitlab() {
  local query="$1"
  curl -s "https://gitlab.com/api/v4/projects?search=$query&order_by=stars&per_page=20" 2>/dev/null | \
    python3 -c "
import json, sys
data = json.load(sys.stdin)
for r in data[:20]:
    print(f\"gitlab|{r['path_with_namespace']}|{r.get('star_count',0)}|{r.get('language','?') or '?'}|{r['web_url']}\")
" 2>/dev/null
}

search_codeberg() {
  local query="$1"
  curl -s "https://codeberg.org/api/v1/repos/search?q=$query&sort=stars&limit=20" 2>/dev/null | \
    python3 -c "
import json, sys
data = json.load(sys.stdin)
for r in data.get('data', [])[:20]:
    print(f\"codeberg|{r['full_name']}|{r.get('stars_count',0)}|{r.get('language','?') or '?'}|{r['html_url']}\")
" 2>/dev/null
}

search_sourcehut() {
  # SourceHut doesn't have a public search API, use known projects
  local query="$1"
  warn "SourceHut has no public search API — use https://sr.ht/projects?search=$query"
}

search_all() {
  local query="$1"
  log "Searching all forges for: $query"
  echo ""
  printf "  %-10s %-35s %-6s %-12s %s\n" "Forge" "Repo" "Stars" "Language" "URL"
  printf "  %-10s %-35s %-6s %-12s %s\n" "─────" "────" "─────" "────────" "───"
  
  {
    search_github "$query"
    search_gitlab "$query"
    search_codeberg "$query"
  } | sort -t'|' -k3 -rn | while IFS='|' read -r forge repo stars lang url; do
    printf "  %-10s %-35s %-6s %-12s %s\n" "$forge" "$repo" "$stars" "$lang" "$url"
  done
}

# ═══ Trending / popular ═══

trending() {
  log "Trending security-relevant repos across forges:"
  echo ""
  
  # GitHub: security-related trending
  log "GitHub (security):"
  search_github "security+language:python+pushed:>$(date -v-7d +%Y-%m-%d 2>/dev/null || date -d '7 days ago' +%Y-%m-%d 2>/dev/null || echo '2026-05-17')" | head -10 | while IFS='|' read -r f r s l u; do
    printf "  %-35s ⭐%-6s %s\n" "$r" "$s" "$l"
  done
  
  echo ""
  log "GitLab (security):"
  search_gitlab "security" | head -10 | while IFS='|' read -r f r s l u; do
    printf "  %-35s ⭐%-6s %s\n" "$r" "$s" "$l"
  done
  
  echo ""
  log "Codeberg (security):"
  search_codeberg "security" | head -10 | while IFS='|' read -r f r s l u; do
    printf "  %-35s ⭐%-6s %s\n" "$r" "$s" "$l"
  done
}

# ═══ Clone ═══

clone_repo() {
  local spec="$1"
  local forge repo url
  
  if [[ "$spec" == *"gitlab.com"* ]]; then
    forge="gitlab"; url="$spec"
    repo=$(echo "$spec" | sed 's|https://gitlab.com/||;s|.git$||')
  elif [[ "$spec" == *"codeberg.org"* ]]; then
    forge="codeberg"; url="$spec"
    repo=$(echo "$spec" | sed 's|https://codeberg.org/||;s|.git$||')
  elif [[ "$spec" == *"github.com"* ]]; then
    forge="github"; url="$spec"
    repo=$(echo "$spec" | sed 's|https://github.com/||;s|.git$||')
  elif [[ "$spec" == *"/"* ]]; then
    # Assume github if just owner/repo
    forge="github"; repo="$spec"; url="https://github.com/$spec"
  else
    warn "Can't parse: $spec"; return 1
  fi
  
  local name=$(basename "$repo")
  local dest="$CLONE_DIR/$forge/$name"
  
  if [[ -d "$dest" ]]; then
    log "Already cloned: $dest (pulling...)"
    git -C "$dest" pull --ff-only 2>/dev/null
  else
    log "Cloning $forge/$repo → $dest"
    mkdir -p "$(dirname "$dest")"
    git clone --depth 1 "$url" "$dest" 2>/dev/null
  fi
  ok "Ready: $dest"
}

# ═══ Scan cloned forge repos into dep-tree ═══

scan_forges() {
  local path="${1:-$CLONE_DIR}"
  log "Scanning forge repos at $path..."
  bash "$SCRIPT_DIR/dep-tree-db.sh" build "$path"
}

# ═══ Main ═══
CMD="${1:-help}"
case "$CMD" in
  search)   search_all "${2:?Usage: $0 search <query>}" ;;
  trending) trending ;;
  clone)    clone_repo "${2:?Usage: $0 clone <url-or-owner/repo>}" ;;
  scan)     scan_forges "${2:-$CLONE_DIR}" ;;
  *)
    echo "Usage: $0 <command> [args]"
    echo ""
    echo "Commands:"
    echo "  search <query>   Search GitHub + GitLab + Codeberg"
    echo "  trending         Show trending security repos"
    echo "  clone <repo>     Clone from any forge (auto-detects)"
    echo "  scan [path]      Scan cloned repos into dep-tree DB"
    echo ""
    echo "Supported forges:"
    echo "  GitHub     — api.github.com"
    echo "  GitLab     — gitlab.com/api/v4"
    echo "  Codeberg   — codeberg.org/api/v1 (Forgejo)"
    echo "  SourceHut  — sr.ht (manual, no search API)"
    echo "  Bitbucket  — (planned)"
    echo ""
    echo "Clone dir: $CLONE_DIR"
    ;;
esac
