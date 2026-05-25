#!/bin/bash
# Apex CLI — Release Watcher
# Monitors GitHub releases of bounty targets. On new release → re-validate.
# Persists state in data/watch-state.json so it survives restarts.
# Usage:
#   ./scripts/watch-releases.sh              — check all watched repos once
#   ./scripts/watch-releases.sh add <owner/repo> — add repo to watchlist
#   ./scripts/watch-releases.sh list         — show watchlist + last known version
#   ./scripts/watch-releases.sh daemon       — loop every 6h (background)
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
STATE="$SCRIPT_DIR/../data/watch-state.json"
LOG="$SCRIPT_DIR/../output/watch-releases.log"
mkdir -p "$(dirname "$STATE")" "$(dirname "$LOG")"

log()  { echo -e "\033[1;34m[*]\033[0m $(date +%H:%M) $*" | tee -a "$LOG"; }
ok()   { echo -e "\033[1;32m[+]\033[0m $(date +%H:%M) $*" | tee -a "$LOG"; }
crit() { echo -e "\033[1;31m[!!]\033[0m $(date +%H:%M) $*" | tee -a "$LOG"; }

# Initialize state if missing
[[ ! -f "$STATE" ]] && echo '{}' > "$STATE"

# Default watchlist (our bounty targets with open source repos)
DEFAULTS=(
  "langflow-ai/langflow"
  "open-webui/open-webui"
  "langgenius/dify"
  "hoppscotch/hoppscotch"
  "n8n-io/n8n"
  "FlowiseAI/Flowise"
  "calcom/cal.com"
  "nocodb/nocodb"
  "directus/directus"
  "strapi/strapi"
  "makeplane/plane"
  "twentyhq/twenty"
  "appsmithorg/appsmith"
)

add_repo() {
  local repo="$1"
  local current=$(cat "$STATE")
  if echo "$current" | grep -q "\"$repo\""; then
    log "$repo already watched"
    return
  fi
  # Get current latest release as baseline
  local ver=$(curl -s "https://api.github.com/repos/$repo/releases/latest" 2>/dev/null | grep -o '"tag_name":"[^"]*"' | cut -d'"' -f4)
  [[ -z "$ver" ]] && ver="unknown"
  # Add to state
  echo "$current" | python3 -c "
import json, sys
state = json.load(sys.stdin)
state['$repo'] = {'version': '$ver', 'checked': '$(date -u +%Y-%m-%dT%H:%M:%SZ)'}
json.dump(state, sys.stdout, indent=2)
" > "${STATE}.tmp" && mv "${STATE}.tmp" "$STATE"
  ok "Added $repo (current: $ver)"
}

list_repos() {
  log "Watched repos:"
  echo ""
  printf "  %-35s %-15s %s\n" "Repo" "Version" "Last Checked"
  printf "  %-35s %-15s %s\n" "────" "───────" "────────────"
  python3 -c "
import json
state = json.load(open('$STATE'))
for repo, info in sorted(state.items()):
    print(f\"  {repo:<35} {info.get('version','?'):<15} {info.get('checked','never')}\")
"
}

check_all() {
  log "Checking releases..."
  local repos=$(python3 -c "import json; [print(r) for r in json.load(open('$STATE')).keys()]")
  [[ -z "$repos" ]] && log "No repos watched. Run: $0 add <owner/repo>" && return
  
  echo "$repos" | while read -r repo; do
    [[ -z "$repo" ]] && continue
    local known_ver=$(python3 -c "import json; print(json.load(open('$STATE')).get('$repo',{}).get('version',''))")
    local latest=$(curl -s "https://api.github.com/repos/$repo/releases/latest" 2>/dev/null | grep -o '"tag_name":"[^"]*"' | cut -d'"' -f4)
    [[ -z "$latest" ]] && continue
    
    if [[ "$latest" != "$known_ver" && -n "$known_ver" && "$known_ver" != "unknown" ]]; then
      crit "NEW RELEASE: $repo $known_ver → $latest"
      # Update state
      python3 -c "
import json
state = json.load(open('$STATE'))
state['$repo']['version'] = '$latest'
state['$repo']['previous'] = '$known_ver'
state['$repo']['checked'] = '$(date -u +%Y-%m-%dT%H:%M:%SZ)'
state['$repo']['new_release'] = True
json.dump(state, open('$STATE','w'), indent=2)
"
      # Trigger re-validation if we have a live target
      trigger_rescan "$repo" "$latest"
    else
      # Update checked timestamp
      python3 -c "
import json
state = json.load(open('$STATE'))
state.setdefault('$repo',{})['version'] = '$latest'
state['$repo']['checked'] = '$(date -u +%Y-%m-%dT%H:%M:%SZ)'
state['$repo'].pop('new_release', None)
json.dump(state, open('$STATE','w'), indent=2)
"
    fi
  done
  ok "Check complete"
}

trigger_rescan() {
  local repo="$1" version="$2"
  local name=$(basename "$repo")
  log "  Triggering re-scan for $name ($version)..."
  
  # Check if we have a live target in bounty DB
  local db="$SCRIPT_DIR/../data/bounty-targets.db"
  if [[ -f "$db" ]]; then
    local domain=$(sqlite3 "$db" "SELECT t.domain FROM targets t JOIN programs p ON t.program_id = p.id WHERE p.name LIKE '%$name%' LIMIT 1;" 2>/dev/null)
    if [[ -n "$domain" ]]; then
      log "  Live target: $domain — running validate..."
      bash "$SCRIPT_DIR/deep-fingerprint.sh" validate "https://$domain" >> "$LOG" 2>&1
    fi
  fi
  
  # Check if we have the source cloned
  local src="$HOME/git/hub/topx/$name"
  if [[ -d "$src" ]]; then
    log "  Source available: $src — running auth-boundary-scan..."
    bash "$SCRIPT_DIR/auth-boundary-scan.sh" "$src" >> "$LOG" 2>&1
  fi
}

daemon() {
  local interval="${1:-21600}" # 6 hours default
  log "Daemon mode: checking every ${interval}s"
  while true; do
    check_all
    log "Sleeping ${interval}s..."
    sleep "$interval"
  done
}

# ═══ Main ═══
CMD="${1:-check}"

case "$CMD" in
  add)
    REPO="${2:?Usage: $0 add <owner/repo>}"
    add_repo "$REPO"
    ;;
  list)
    list_repos
    ;;
  check)
    check_all
    ;;
  daemon)
    daemon "${2:-21600}"
    ;;
  init)
    log "Initializing watchlist with defaults..."
    for repo in "${DEFAULTS[@]}"; do
      add_repo "$repo"
    done
    ;;
  *)
    echo "Usage: $0 <command>"
    echo ""
    echo "Commands:"
    echo "  check          Check all watched repos for new releases"
    echo "  add <repo>     Add owner/repo to watchlist"
    echo "  list           Show watchlist"
    echo "  init           Seed watchlist with default bounty targets"
    echo "  daemon [secs]  Loop forever (default: every 6h)"
    ;;
esac
