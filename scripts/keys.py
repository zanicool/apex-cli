#!/usr/bin/env python3
"""Manage API keys for apex-api."""

import hashlib
import json
import secrets
import sys
from pathlib import Path

KEYS_FILE = Path(__file__).parent.parent / "server/keys.json"


def load():
    if KEYS_FILE.exists():
        return json.loads(KEYS_FILE.read_text())
    return {}


def save(keys):
    KEYS_FILE.write_text(json.dumps(keys, indent=2))


def add_client(name: str):
    keys = load()
    raw_key = secrets.token_urlsafe(32)
    h = hashlib.sha256(raw_key.encode()).hexdigest()
    keys[h] = {"client": name, "active": True}
    save(keys)
    print(f"Client: {name}")
    print(f"API Key: {raw_key}")
    print("(Save this key — it cannot be recovered)")


def list_clients():
    keys = load()
    for h, info in keys.items():
        status = "✓" if info["active"] else "✗"
        print(f"  {status} {info['client']} ({h[:8]}...)")


def revoke(name: str):
    keys = load()
    for h, info in keys.items():
        if info["client"] == name:
            keys[h]["active"] = False
            save(keys)
            print(f"Revoked: {name}")
            return
    print(f"Not found: {name}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: keys.py [add|list|revoke] [name]")
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "add":
        add_client(sys.argv[2])
    elif cmd == "list":
        list_clients()
    elif cmd == "revoke":
        revoke(sys.argv[2])
