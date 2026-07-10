#!/usr/bin/env python3
"""apex-h1.py — HackerOne integration for Apex-CLI.

Usage:
    python3 apex-h1.py --list                    # List your programs
    python3 apex-h1.py --program <handle>        # Scan a specific program
    python3 apex-h1.py --all                     # Scan all eligible programs
    python3 apex-h1.py --program <handle> --pentest  # Full pentest mode
"""

import json
import subprocess
import sys
import os
import time
import argparse
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError
import base64

CONFIG_DIR = Path.home() / ".config" / "apex"
H1_USER = (CONFIG_DIR / "h1_username").read_text().strip()
H1_TOKEN = (CONFIG_DIR / "h1_token").read_text().strip()
APEX_BIN = Path.home() / "git" / "apex-cli" / "build" / "apex-cli"

def h1_api(endpoint, params=None):
    """Make authenticated H1 API request."""
    url = f"https://api.hackerone.com/v1/{endpoint}"
    if params:
        url += "?" + "&".join(f"{k}={v}" for k, v in params.items())
    
    creds = base64.b64encode(f"{H1_USER}:{H1_TOKEN}".encode()).decode()
    req = Request(url)
    req.add_header("Authorization", f"Basic {creds}")
    req.add_header("Accept", "application/json")
    
    try:
        resp = urlopen(req)
        return json.loads(resp.read())
    except HTTPError as e:
        print(f"[!] API error {e.code}: {e.read().decode()[:200]}")
        return None

def list_programs():
    """List all accessible programs."""
    data = h1_api("hackers/programs", {"page[size]": "100"})
    if not data or "data" not in data:
        print("[!] Could not fetch programs")
        return []
    
    programs = []
    for p in data["data"]:
        attrs = p.get("attributes", {})
        handle = attrs.get("handle", "")
        name = attrs.get("name", "")
        state = attrs.get("state", "")
        offers_bounties = attrs.get("offers_bounties", False)
        
        programs.append({
            "handle": handle,
            "name": name,
            "state": state,
            "bounty": offers_bounties
        })
    
    return programs

def get_program_scope(handle):
    """Get in-scope assets for a program."""
    data = h1_api(f"hackers/programs/{handle}/structured_scopes", {"page[size]": "100"})
    if not data or "data" not in data:
        print(f"[!] Could not fetch scope for: {handle}")
        return [], []
    
    in_scope = []
    out_scope = []
    
    for scope in data["data"]:
        attrs = scope.get("attributes", {})
        asset = attrs.get("asset_identifier", "")
        asset_type = attrs.get("asset_type", "")
        eligible = attrs.get("eligible_for_bounty", False)
        eligible_submission = attrs.get("eligible_for_submission", True)
        
        if asset_type in ("URL", "WILDCARD", "DOMAIN"):
            if eligible_submission:
                in_scope.append({
                    "target": asset,
                    "type": asset_type,
                    "bounty": eligible
                })
            else:
                out_scope.append(asset)
    
    return in_scope, out_scope

def scan_target(target, pentest=False, quick=True):
    """Run Apex-CLI on a target."""
    cmd = [str(APEX_BIN), target, "--threads", "10"]
    
    if quick:
        cmd.append("--quick")
    if pentest:
        cmd.append("--pentest")
    
    # Add bounty mode for H1-ready reports
    cmd.append("--bounty")
    
    print(f"\n{'='*60}")
    print(f"[SCAN] {target}")
    print(f"{'='*60}\n")
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        output = result.stdout
        
        # Count findings
        findings = output.count("[CRITICAL]") + output.count("[HIGH]") + output.count("[MEDIUM]")
        criticals = output.count("[CRITICAL]")
        highs = output.count("[HIGH]")
        
        print(output[-2000:] if len(output) > 2000 else output)
        
        return {
            "target": target,
            "findings": findings,
            "criticals": criticals,
            "highs": highs,
            "output": output
        }
    except subprocess.TimeoutExpired:
        print(f"[!] Timeout on {target}")
        return {"target": target, "findings": 0, "criticals": 0, "highs": 0, "output": "TIMEOUT"}
    except Exception as e:
        print(f"[!] Error scanning {target}: {e}")
        return {"target": target, "findings": 0, "criticals": 0, "highs": 0, "output": str(e)}

def expand_wildcard(wildcard):
    """Expand wildcard scope to concrete targets."""
    # Remove *. prefix
    domain = wildcard.replace("*.", "").strip()
    # Return base domain — subdomain enum happens inside Apex
    return [f"https://{domain}"]

def scan_program(handle, pentest=False):
    """Scan all in-scope targets for a program."""
    print(f"\n[H1] Fetching scope for: {handle}")
    in_scope, out_scope = get_program_scope(handle)
    
    if not in_scope:
        print(f"[!] No scannable targets in scope for {handle}")
        return
    
    print(f"[H1] In-scope targets: {len(in_scope)}")
    for s in in_scope:
        bounty_str = "💰" if s["bounty"] else "  "
        print(f"  {bounty_str} [{s['type']}] {s['target']}")
    
    if out_scope:
        print(f"[H1] Out-of-scope: {', '.join(out_scope[:5])}")
    
    # Build target list
    targets = []
    for scope in in_scope:
        target = scope["target"]
        if scope["type"] == "WILDCARD":
            targets.extend(expand_wildcard(target))
        elif scope["type"] in ("URL", "DOMAIN"):
            if not target.startswith("http"):
                target = f"https://{target}"
            targets.append(target)
    
    # Deduplicate
    targets = list(set(targets))
    
    print(f"\n[H1] Scanning {len(targets)} targets...")
    print(f"[H1] Rate limit: 3s between targets\n")
    
    results = []
    for i, target in enumerate(targets):
        print(f"[{i+1}/{len(targets)}] {target}")
        result = scan_target(target, pentest=pentest)
        results.append(result)
        
        # Rate limit between targets
        if i < len(targets) - 1:
            time.sleep(3)
    
    # Summary
    print(f"\n{'='*60}")
    print(f"[H1] SCAN COMPLETE — {handle}")
    print(f"{'='*60}")
    total_findings = sum(r["findings"] for r in results)
    total_criticals = sum(r["criticals"] for r in results)
    total_highs = sum(r["highs"] for r in results)
    
    print(f"  Targets scanned: {len(results)}")
    print(f"  Total findings:  {total_findings}")
    print(f"  Criticals:       {total_criticals}")
    print(f"  Highs:           {total_highs}")
    
    if total_criticals > 0 or total_highs > 0:
        print(f"\n  🎯 SUBMIT-WORTHY FINDINGS DETECTED!")
        for r in results:
            if r["criticals"] > 0 or r["highs"] > 0:
                print(f"    → {r['target']}: {r['criticals']}C / {r['highs']}H")

def main():
    parser = argparse.ArgumentParser(description="Apex-CLI HackerOne Integration")
    parser.add_argument("--list", action="store_true", help="List available programs")
    parser.add_argument("--program", type=str, help="Program handle to scan")
    parser.add_argument("--all", action="store_true", help="Scan all bounty programs")
    parser.add_argument("--pentest", action="store_true", help="Enable pentest mode")
    parser.add_argument("--scope", type=str, help="Show scope for a program")
    args = parser.parse_args()
    
    if args.list:
        programs = list_programs()
        print(f"\n[H1] {len(programs)} programs accessible:\n")
        for p in sorted(programs, key=lambda x: x["bounty"], reverse=True):
            bounty = "💰" if p["bounty"] else "  "
            state = "✓" if p["state"] == "public_mode" else "○"
            print(f"  {bounty} {state} {p['handle']:30s} {p['name']}")
    
    elif args.scope:
        in_scope, out_scope = get_program_scope(args.scope)
        print(f"\n[H1] Scope for {args.scope}:\n")
        print("  IN SCOPE:")
        for s in in_scope:
            b = "💰" if s["bounty"] else "  "
            print(f"    {b} [{s['type']}] {s['target']}")
        if out_scope:
            print("\n  OUT OF SCOPE:")
            for s in out_scope:
                print(f"    ✗ {s}")
    
    elif args.program:
        scan_program(args.program, pentest=args.pentest)
    
    elif args.all:
        programs = list_programs()
        bounty_programs = [p for p in programs if p["bounty"]]
        print(f"[H1] Scanning {len(bounty_programs)} bounty programs...")
        for p in bounty_programs:
            scan_program(p["handle"], pentest=args.pentest)
            time.sleep(5)  # Rate limit between programs
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
