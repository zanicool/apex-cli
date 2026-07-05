#!/bin/bash
DOMAIN="${1:?Usage: wayback.sh <domain>}"
curl -sk "https://web.archive.org/cdx/search/cdx?url=*.$DOMAIN/*&output=text&fl=original&collapse=urlkey&limit=200" 2>/dev/null | sort -u | grep -iE "api|admin|login|token|key|config|backup|\.env|\.git" | head -30
