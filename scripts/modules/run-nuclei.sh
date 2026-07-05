#!/bin/bash
TARGET="${1:?Usage: run-nuclei.sh <target>}"
which nuclei >/dev/null 2>&1 || exit 0
echo "[*] Running Nuclei on $TARGET..."
nuclei -u "$TARGET" -severity critical,high -silent -no-color -c 50 -timeout 5 2>/dev/null | head -20
