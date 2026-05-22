#!/usr/bin/env python3
"""Extract cookies from Chromium for a target domain.
Usage: ./scripts/grab-cookies.py hilton.com
"""
import sys, os, sqlite3, shutil, tempfile

if len(sys.argv) < 2:
    print("Usage: grab-cookies.py <domain>", file=sys.stderr)
    sys.exit(1)

domain = sys.argv[1]

# Find cookie DB
paths = [
    os.path.expanduser("~/.config/chromium/Default/Cookies"),
    os.path.expanduser("~/.config/google-chrome/Default/Cookies"),
]
cookie_db = None
for p in paths:
    if os.path.exists(p):
        cookie_db = p
        break

if not cookie_db:
    print("ERROR: No Chromium/Chrome cookie database found", file=sys.stderr)
    sys.exit(1)

# Copy DB (locked while browser open)
tmp = tempfile.mktemp(suffix=".db")
shutil.copy2(cookie_db, tmp)

conn = sqlite3.connect(tmp)
cursor = conn.cursor()

cursor.execute(
    "SELECT name, value, host_key FROM cookies WHERE host_key LIKE ? OR host_key LIKE ?",
    (f"%{domain}%", f"%.{domain}%")
)

cookies = []
for name, value, host in cursor.fetchall():
    if value:
        cookies.append(f"{name}={value}")

conn.close()
os.unlink(tmp)

if cookies:
    print("; ".join(cookies))
else:
    print(f"No readable cookies for {domain}. Chromium encrypts cookies - close browser and retry.", file=sys.stderr)
    sys.exit(1)
