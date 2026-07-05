#!/bin/bash
DOMAIN="${1:?Usage: github-dork.sh <domain>}"
DORKS=("password" "secret" "api_key" "token" "AWS_SECRET" "PRIVATE_KEY")
for dork in "${DORKS[@]}"; do
    RESULTS=$(curl -sk "https://github.com/search?q=$DOMAIN+$dork&type=code" 2>/dev/null | grep -c "code-list-item" 2>/dev/null)
    [ "$RESULTS" -gt 0 ] 2>/dev/null && echo "[!] GitHub: '$dork' found ($RESULTS results)"
done
