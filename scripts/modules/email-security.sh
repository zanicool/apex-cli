#!/bin/bash
DOMAIN="${1:?Usage: email-security.sh <domain>}"
echo "=== SPF ===" && host -t txt "$DOMAIN" 2>/dev/null | grep "spf" || echo "  NO SPF!"
echo "=== DMARC ===" && host -t txt "_dmarc.$DOMAIN" 2>/dev/null | grep "dmarc" || echo "  NO DMARC!"
echo "=== DKIM ===" && for sel in default google selector1 selector2 k1; do
  R=$(host -t txt "${sel}._domainkey.$DOMAIN" 2>/dev/null | grep "DKIM")
  [ -n "$R" ] && echo "  $sel: found" && break
done
