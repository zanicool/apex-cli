#!/usr/bin/env python3
"""Apex Auto-Scanner — Private bug bounty automation. DO NOT PUBLISH."""

import json
import os
import sys
import time
import threading
from datetime import datetime
from pathlib import Path

import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

# Import apex-cli's scanner
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from apex import ApexCLI, validate_target, show_banner, TOOLS, DEFAULT_WORDLIST
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

console = Console()

NTFY_TOPIC = "apex-a3219f8742dd"  # Subscribe to this in the ntfy app

def notify(title, msg, priority="urgent", tags="rotating_light"):
    """Send push notification via ntfy.sh + email via Gmail SMTP."""
    try:
        requests.post(f"https://ntfy.sh/{NTFY_TOPIC}", data=msg.encode(),
                      headers={"Title": title, "Priority": priority, "Tags": tags}, timeout=10)
    except Exception:
        pass
    try:
        import smtplib
        from email.mime.text import MIMEText
        email_to = "zanicoolen1337@gmail.com"
        m = MIMEText(msg)
        m["Subject"] = title
        m["From"] = email_to
        m["To"] = email_to
        with smtplib.SMTP("smtp.gmail.com", 587) as s:
            s.starttls()
            s.login(email_to, os.environ.get("GMAIL_APP_PASSWORD", ""))
            s.send_message(m)
    except Exception:
        pass

RESULTS_DIR = os.path.expanduser("~/apex-auto-results")
SCANNED_FILE = os.path.join(RESULTS_DIR, "scanned.txt")
HITS_FILE = os.path.join(RESULTS_DIR, "hits.json")

# ---------------------------------------------------------------------------
# Target sources
# ---------------------------------------------------------------------------

def load_targets_from_file(path):
    with open(path) as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]


def fetch_bounty_targets():
    """Fetch public bug bounty program scopes, prioritizing recent programs."""
    targets = []
    seen = set()
    console.print("[bold blue][+][/bold blue] Fetching bug bounty targets (recent first)...")

    # Recent HackerOne programs (updated frequently)
    try:
        r = requests.get("https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/hackerone_data.json", timeout=15)
        programs = r.json()
        # Sort by most recently updated
        programs.sort(key=lambda p: p.get("updated_at", ""), reverse=True)
        for prog in programs:
            for t in prog.get("targets", {}).get("in_scope", []):
                if t.get("asset_type") in ("URL", "WILDCARD", "DOMAIN"):
                    d = t.get("asset_identifier", "").lower().replace("*.", "").replace("https://", "").replace("http://", "").split("/")[0]
                    if d and "." in d and d not in seen:
                        seen.add(d)
                        targets.append(d)
        console.print(f"[green][✓][/green] HackerOne: {len(targets)} domains (recent first)")
    except Exception as e:
        console.print(f"[yellow][!] HackerOne fetch failed: {e}[/yellow]")

    # Recent Bugcrowd programs
    try:
        r = requests.get("https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/bugcrowd_data.json", timeout=15)
        programs = r.json()
        programs.sort(key=lambda p: p.get("updated_at", ""), reverse=True)
        for prog in programs:
            for t in prog.get("targets", {}).get("in_scope", []):
                if t.get("type") in ("website", "api"):
                    d = t.get("target", "").lower().replace("*.", "").replace("https://", "").replace("http://", "").split("/")[0]
                    if d and "." in d and d not in seen:
                        seen.add(d)
                        targets.append(d)
        console.print(f"[green][✓][/green] Bugcrowd: {len(targets)} total (recent first)")
    except Exception as e:
        console.print(f"[yellow][!] Bugcrowd fetch failed: {e}[/yellow]")

    # Recent Intigriti programs
    try:
        r = requests.get("https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/intigriti_data.json", timeout=15)
        programs = r.json()
        for prog in programs:
            for t in prog.get("targets", {}).get("in_scope", []):
                if t.get("type") in ("url", "wildcard"):
                    d = t.get("endpoint", "").lower().replace("*.", "").replace("https://", "").replace("http://", "").split("/")[0]
                    if d and "." in d and d not in seen:
                        seen.add(d)
                        targets.append(d)
        console.print(f"[green][✓][/green] Intigriti: {len(targets)} total")
    except Exception as e:
        console.print(f"[yellow][!] Intigriti fetch failed: {e}[/yellow]")

    # Fallback: plain domains list
    if len(targets) < 100:
        try:
            r = requests.get("https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/domains.txt", timeout=15)
            for line in r.text.splitlines():
                d = line.strip().lower()
                if d and "." in d and not d.startswith("*") and d not in seen:
                    seen.add(d)
                    targets.append(d)
        except Exception:
            pass

    console.print(f"[green][✓][/green] {len(targets)} targets total (recent programs first)")
    return targets


def load_scanned():
    if os.path.isfile(SCANNED_FILE):
        with open(SCANNED_FILE) as f:
            return set(l.strip() for l in f)
    return set()


def mark_scanned(target):
    with open(SCANNED_FILE, "a") as f:
        f.write(target + "\n")


def save_hit(target, vulns):
    hits = []
    if os.path.isfile(HITS_FILE):
        with open(HITS_FILE) as f:
            hits = json.load(f)
    hits.append({
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "vulnerabilities": vulns,
    })
    with open(HITS_FILE, "w") as f:
        json.dump(hits, f, indent=2)

# ---------------------------------------------------------------------------
# Auto-scan engine
# ---------------------------------------------------------------------------

def auto_scan(target, skip=None):
    """Run full scan using the complete run_scan engine."""
    from apex import run_scan as _run_scan
    skip = skip or ["oob ssrf", "oob cmdi", "oob sqli",
                    "subdomain brute-force", "passive recon",
                    "subdomain permutation"]
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = os.path.join(RESULTS_DIR, f"scan_{target}_{ts}")

    # Quick alive check before full scan
    alive = False
    for proto in ["https", "http"]:
        try:
            r = requests.get(f"{proto}://{target}", timeout=6, verify=False,
                             headers={"User-Agent": "Mozilla/5.0"})
            if r.status_code < 500:
                alive = True
                break
        except Exception:
            continue
    if not alive:
        console.print(f"[dim]Dead — no response[/dim]")
        return [], [], []

    # Run full engine
    try:
        _run_scan(target, dry_run=False, deep=False,
                  report_formats=["json", "html"],
                  skip=skip, resume_dir=None, scope=None,
                  output_dir=output_dir)
    except Exception as e:
        console.print(f"[red]Scan error: {e}[/red]")
        return [], [], []

    # Read results
    report_path = os.path.join(output_dir, "report.json")
    if not os.path.isfile(report_path):
        return [], [], []

    data = json.load(open(report_path))
    vulns = [v for v in data.get("vulnerabilities", [])
             if v.get("severity") in ("critical", "high", "medium")]
    return vulns, data.get("technologies", []), data.get("waf", [])


def prioritize_targets(targets, scanned):
    """Prioritize targets likely to have vulnerabilities — newer programs, smaller companies."""
    # High-value indicators (smaller companies = less security budget)
    high_value_tlds = [".io", ".dev", ".app", ".co", ".ai", ".xyz"]
    # Deprioritize (big companies with mature security)
    low_value = ["google.com", "facebook.com", "microsoft.com", "apple.com",
                 "amazon.com", "cloudflare.com", "github.com"]

    scored = []
    for t in targets:
        if t in scanned:
            continue
        score = 50  # base
        # Boost newer/smaller TLDs
        if any(t.endswith(tld) for tld in high_value_tlds):
            score += 20
        # Boost subdomains (more likely to have vulns)
        if t.count(".") >= 2:
            score += 10
        # Deprioritize known-hardened targets
        if any(lv in t for lv in low_value):
            score -= 30
        # Boost API/staging/dev subdomains
        if any(x in t for x in ["api.", "staging.", "dev.", "test.", "beta.", "uat."]):
            score += 25
        scored.append((score, t))

    scored.sort(reverse=True)
    return [t for _, t in scored]


def run_auto(source="bounty", target_file=None, max_targets=0, skip=None):
    """Main auto-scan loop."""
    os.makedirs(RESULTS_DIR, exist_ok=True)
    show_banner()
    console.print(Panel("[bold red]⚡ AUTO-SCAN MODE[/bold red]\n[dim]Private — not for distribution[/dim]",
                        border_style="red"), justify="center")

    # Load targets
    if source == "file" and target_file:
        targets = load_targets_from_file(target_file)
        console.print(f"[cyan]Loaded {len(targets)} targets from {target_file}[/cyan]")
    else:
        targets = fetch_bounty_targets()

    scanned = load_scanned()
    remaining = prioritize_targets(targets, scanned)
    if max_targets > 0:
        remaining = remaining[:max_targets]

    console.print(f"[bold white]Targets:[/bold white] {len(remaining)} remaining ({len(scanned)} already scanned)")
    console.print(f"[bold white]Results:[/bold white] {RESULTS_DIR}")
    console.print()

    total_hits = 0
    from concurrent.futures import ThreadPoolExecutor, as_completed
    lock = threading.Lock()

    def scan_one(i, target, total):
        console.print(f"\n[bold cyan]━━━ [{i+1}/{total}] {target} ━━━[/bold cyan]")
        try:
            target = validate_target(target)
        except SystemExit:
            console.print(f"[yellow]Skipping invalid target: {target}[/yellow]")
            with lock: mark_scanned(target)
            return 0
        try:
            vulns, tech, waf = auto_scan(target, skip=skip)
            with lock: mark_scanned(target)
            if vulns:
                with lock: save_hit(target, vulns)
                console.print(f"[bold red]🎯 HIT! {len(vulns)} vulns on {target}[/bold red]")
                crits = [v for v in vulns if v["severity"] in ("critical", "high")]
                if crits:
                    details = "\n".join(f'{v["severity"].upper()}: {v["type"]} @ {v["url"][:80]}' for v in crits[:5])
                    notify(f"🚨 {len(crits)} critical/high on {target}", details)
                for v in vulns:
                    console.print(f"  [red]{v['severity']:>8}[/red] | {v['type'][:50]} | {v['url'][:60]}")
                return 1
            else:
                console.print(f"[dim]Clean — no vulns found[/dim]")
                return 0
        except Exception as e:
            console.print(f"[red]Error scanning {target}: {e}[/red]")
            with lock: mark_scanned(target)
            return 0

    WORKERS = int(os.environ.get("APEX_WORKERS", 4))
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = {pool.submit(scan_one, i, t, len(remaining)): t for i, t in enumerate(remaining)}
        try:
            for f in as_completed(futures):
                total_hits += f.result()
        except KeyboardInterrupt:
            console.print("\n[yellow]Stopped by user.[/yellow]")

    # Summary
    console.print(f"\n[bold green]━━━ AUTO-SCAN COMPLETE ━━━[/bold green]")
    console.print(f"Scanned: {len(remaining)} targets")
    console.print(f"Hits: {total_hits}")
    console.print(f"Results: {RESULTS_DIR}")
    if os.path.isfile(HITS_FILE):
        console.print(f"All hits: {HITS_FILE}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(prog="apex-auto", description="Apex Auto-Scanner — Bug Bounty Automation")
    parser.add_argument("--file", "-f", type=str, help="Scan targets from file (one domain per line)")
    parser.add_argument("--bounty", "-b", action="store_true", help="Fetch and scan public bug bounty targets")
    parser.add_argument("--max", "-m", type=int, default=0, help="Max targets to scan (0 = unlimited)")
    parser.add_argument("--skip", nargs="+", default=["nuclei", "sqli"],
                        help="Skip phases (default: nuclei sqli)")
    parser.add_argument("--hits", action="store_true", help="Show all saved hits and exit")
    parser.add_argument("--reset", action="store_true", help="Clear scanned history")
    args = parser.parse_args()

    if args.hits:
        if os.path.isfile(HITS_FILE):
            hits = json.load(open(HITS_FILE))
            t = Table(title=f"All Hits ({len(hits)})")
            t.add_column("Target", style="cyan")
            t.add_column("Vulns", style="red")
            t.add_column("Date")
            for h in hits:
                t.add_row(h["target"], str(len(h["vulnerabilities"])), h["timestamp"][:16])
            console.print(t)
        else:
            console.print("[yellow]No hits yet.[/yellow]")
        sys.exit(0)

    if args.reset:
        os.makedirs(RESULTS_DIR, exist_ok=True)
        open(SCANNED_FILE, "w").close()
        console.print("[green]Scanned history cleared.[/green]")
        sys.exit(0)

    if args.file:
        run_auto(source="file", target_file=args.file, max_targets=args.max, skip=args.skip)
    elif args.bounty:
        run_auto(source="bounty", max_targets=args.max, skip=args.skip)
    else:
        parser.print_help()
        print("\nExamples:")
        print("  apex-auto --bounty --max 50        # Scan 50 bug bounty targets")
        print("  apex-auto -f targets.txt           # Scan from file")
        print("  apex-auto --hits                   # View all findings")
        print("  apex-auto --reset                  # Clear scan history")
