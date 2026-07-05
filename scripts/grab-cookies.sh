#!/bin/bash
# Extract cookies from Chromium for a target domain.
# Usage: ./scripts/grab-cookies.sh hilton.com
#
# Requires: python3, chromium must have visited the site while logged in.

DOMAIN="${1:?Usage: $0 <domain>}"

python3 -c "
import sys, os, sqlite3, shutil, tempfile

domain = '$DOMAIN'

# Chromium cookie DB path
cookie_db = os.path.expanduser("~/.config/chromium/Default/Cookies")
if not os.path.exists(cookie_db):
    cookie_db = os.path.expanduser("~/.config/google-chrome/Default/Cookies")
if not os.path.exists(cookie_db):
    print("ERROR: No Chromium/Chrome cookie database found", file=sys.stderr)
    sys.exit(1)

# Copy DB (it's locked while browser is open)
tmp = tempfile.mktemp(suffix=".db")
shutil.copy2(cookie_db, tmp)

conn = sqlite3.connect(tmp)
cursor = conn.cursor()

# Query cookies for the domain
cursor.execute("""
    SELECT name, value, host_key FROM cookies 
    WHERE host_key LIKE ? OR host_key LIKE ?
""", (f"%{domain}%", f"%.{domain}%"))

cookies = []
for name, value, host in cursor.fetchall():
    if value:  # Only unencrypted cookies (some are encrypted)
        cookies.append(f"{name}={value}")

conn.close()
os.unlink(tmp)

if cookies:
    print("; ".join(cookies))
else:
    print(f"No readable cookies for {domain}. Try: close Chromium, or login first.", file=sys.stderr)
    sys.exit(1)
"
