#!/bin/bash
DOMAIN="${1:?Usage: dns-transfer.sh <domain>}"
for NS in $(host -t ns "$DOMAIN" 2>/dev/null | awk '{print $NF}' | sed 's/\.$//'); do
    RESULT=$(host -l "$DOMAIN" "$NS" 2>/dev/null)
    if echo "$RESULT" | grep -qv "Transfer failed"; then
        echo "[!] Zone transfer SUCCESS on $NS"
        echo "$RESULT" | head -20
        exit 0
    fi
done
echo "Zone transfer failed (expected)"
