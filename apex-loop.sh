#!/bin/bash
# Apex CLI — continuous bug bounty auto-scanner
cd "$(dirname "$0")"
while true; do
    echo "[$(date)] Starting bounty scan pass..."
    python3 apex-auto.py --bounty --skip ""
    echo "[$(date)] Pass complete. Sleeping 10s before next round..."
    sleep 10
done
