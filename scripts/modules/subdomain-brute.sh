#!/bin/bash
DOMAIN="${1:?Usage: subdomain-brute.sh <domain>}"
WORDLIST="${2:-/home/zani/git/apex-cli/wordlists/subdomains-10000.txt}"
[ ! -f "$WORDLIST" ] && exit 0
while IFS= read -r sub; do
    IP=$(getent hosts "$sub.$DOMAIN" 2>/dev/null | awk '{print $1}')
    [ -n "$IP" ] && echo "$sub.$DOMAIN → $IP"
done < <(head -1000 "$WORDLIST") 2>/dev/null
