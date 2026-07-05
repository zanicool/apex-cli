#!/bin/bash
# Extracts API endpoints from APK (requires apktool)
APK="${1:?Usage: apk-endpoints.sh <apk-file>}"
[ ! -f "$APK" ] && echo "File not found" && exit 1
TMPDIR=$(mktemp -d)
apktool d "$APK" -o "$TMPDIR" -f 2>/dev/null
grep -rhoP 'https?://[a-zA-Z0-9._/-]+' "$TMPDIR" | sort -u | grep -v "google\|android\|schema" | head -50
rm -rf "$TMPDIR"
