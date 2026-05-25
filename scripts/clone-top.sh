#!/bin/bash
# Clone/update top X most starred GitHub repos into a target folder.
# - Moves existing repos from ~/git/hub/ if already cloned
# - Pulls latest for repos already present
# - Clones missing repos (shallow)
set -uo pipefail

COUNT="${1:-500}"
DEST="${2:-$HOME/git/hub/topx}"
SOURCE="$HOME/git/hub"
LOG="$DEST/.clone.log"
mkdir -p "$DEST"

log() { echo -e "\033[1;34m[*]\033[0m $*" | tee -a "$LOG"; }
ok()  { echo -e "\033[1;32m[+]\033[0m $*" | tee -a "$LOG"; }

echo ""
echo "  ╔═══════════════════════════════════════════════╗"
echo "  ║  Top $COUNT GitHub Repos — sync to $DEST"
echo "  ╚═══════════════════════════════════════════════╝"
echo ""

# Fetch repo list
REPOS_FILE="$DEST/.repos.txt"
if [ ! -f "$REPOS_FILE" ] || [ "$(wc -l < "$REPOS_FILE" | tr -d ' ')" -lt "$COUNT" ]; then
  log "Fetching top $COUNT repos from GitHub API..."
  true > "$REPOS_FILE"
  PAGES=$(( (COUNT + 99) / 100 ))
  for page in $(seq 1 "$PAGES"); do
    printf "\r  page %d/%d" "$page" "$PAGES"
    gh api "search/repositories?q=stars:>10000&sort=stars&order=desc&per_page=100&page=$page" \
      --jq '.items[] | "\(.full_name)|\(.stargazers_count)|\(.name)"' >> "$REPOS_FILE" 2>/dev/null
    sleep 2
  done
  echo ""
  ok "Got $(wc -l < "$REPOS_FILE" | tr -d ' ') repos"
fi
echo ""

# Process each repo
TOTAL=$(head -n "$COUNT" "$REPOS_FILE" | wc -l | tr -d ' ')
MOVED=0; PULLED=0; CLONED=0; FAILED=0; CURRENT=0

while IFS='|' read -r repo stars name; do
  [ -z "$repo" ] && continue
  CURRENT=$((CURRENT + 1))
  printf "  [%d/%d] %-35s ⭐%-6s " "$CURRENT" "$TOTAL" "$name" "$stars"

  # Already in dest → pull
  if [ -d "$DEST/$name/.git" ]; then
    git -C "$DEST/$name" pull --ff-only -q 2>/dev/null && echo "↑ pulled" || echo "= current"
    PULLED=$((PULLED + 1))
  # Exists in source → move then pull
  elif [ -d "$SOURCE/$name/.git" ]; then
    mv "$SOURCE/$name" "$DEST/$name"
    git -C "$DEST/$name" pull --ff-only -q 2>/dev/null || true
    echo "→ moved+pulled"
    MOVED=$((MOVED + 1))
  # Not present → clone
  else
    if git clone --depth 1 --single-branch "https://github.com/$repo.git" "$DEST/$name" 2>/dev/null; then
      echo "✓ cloned"
      CLONED=$((CLONED + 1))
    else
      echo "✗ failed"
      FAILED=$((FAILED + 1))
    fi
  fi
done < <(head -n "$COUNT" "$REPOS_FILE")

echo ""
ok "Done: $MOVED moved, $PULLED pulled, $CLONED cloned, $FAILED failed"
ok "Location: $DEST/ ($TOTAL repos)"
