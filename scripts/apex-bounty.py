#!/usr/bin/env python3
"""
Apex Bounty Orchestrator — Mass-scan entire bug bounty programs.

Given a program name or scope file, it:
1. Discovers all in-scope assets (subdomains, APIs, apps)
2. Probes for live hosts
3. Runs the full Apex scanner on each in parallel
4. Deduplicates and ranks findings by bounty potential
5. Generates H1-ready reports

This is how top bounty hunters operate — they don't scan one URL,
they scan THOUSANDS and pick the weakest target.

Usage:
    apex-bounty yahoo                    # Auto-discover Yahoo's scope
    apex-bounty --scope scope.txt        # Custom scope file (one domain per line)
    apex-bounty --scope scope.txt -j 10  # 10 parallel scans
"""

import sys
import os
import json
import time
import subprocess
import threading
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

APEX_BIN = Path(__file__).parent.parent / "build" / "apex-cli"
OUTPUT_DIR = Path(__file__).parent.parent / "bounty-results"


@dataclass
class Target:
    url: str
    source: str  # "scope", "subdomain", "crt.sh", etc.
    live: bool = False
    findings: list = field(default_factory=list)


@dataclass 
class BountyResult:
    program: str
    targets_total: int = 0
    targets_live: int = 0
    targets_scanned: int = 0
    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    findings: list = field(default_factory=list)
    duration: float = 0


def discover_subdomains(domain: str) -> list:
    """Enumerate subdomains using multiple sources."""
    subs = set()
    
    # crt.sh (Certificate Transparency)
    try:
        result = subprocess.run(
            ["curl", "-s", f"https://crt.sh/?q=%.{domain}&output=json"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0 and result.stdout:
            for entry in json.loads(result.stdout):
                names = entry.get("name_value", "").split("\n")
                for name in names:
                    name = name.strip().lower()
                    if name.endswith(domain) and "*" not in name:
                        subs.add(name)
    except Exception:
        pass
    
    # subfinder (if installed)
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode == 0:
            for line in result.stdout.strip().split("\n"):
                if line.strip():
                    subs.add(line.strip().lower())
    except FileNotFoundError:
        pass
    
    # Common subdomains brute
    common = [
        "www", "api", "app", "dev", "staging", "test", "beta", "admin",
        "portal", "dashboard", "internal", "mail", "docs", "shop", "store",
        "cdn", "static", "assets", "media", "img", "auth", "login",
        "sso", "id", "accounts", "my", "m", "mobile", "ws", "socket",
        "graphql", "gql", "rest", "v1", "v2", "old", "new", "legacy",
        "demo", "sandbox", "qa", "uat", "preprod", "stage", "stg"
    ]
    for sub in common:
        subs.add(f"{sub}.{domain}")
    
    return list(subs)


def probe_live(targets: list, threads: int = 20) -> list:
    """Check which targets are actually live."""
    live = []
    
    def check(target):
        for proto in ["https", "http"]:
            url = f"{proto}://{target}"
            try:
                result = subprocess.run(
                    ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                     "--max-time", "5", "-k", url],
                    capture_output=True, text=True, timeout=10
                )
                code = int(result.stdout.strip()) if result.stdout.strip().isdigit() else 0
                if code > 0 and code != 0:
                    return Target(url=url, source="probe", live=True)
            except Exception:
                continue
        return None
    
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(check, t): t for t in targets}
        for future in as_completed(futures):
            result = future.result()
            if result and result.live:
                live.append(result)
    
    return live


def scan_target(target: Target, timeout: int = 300) -> Target:
    """Run apex-cli against a single target."""
    try:
        result = subprocess.run(
            [str(APEX_BIN), target.url, "--no-color", "--threads", "2", "--json"],
            capture_output=True, text=True, timeout=timeout
        )
        
        # Parse findings from output
        for line in result.stdout.split("\n"):
            line = line.strip()
            if line.startswith("{") and "type" in line:
                try:
                    finding = json.loads(line)
                    target.findings.append(finding)
                except json.JSONDecodeError:
                    pass
        
        # Also check scan directory for results
        scan_dirs = sorted(Path("scans").glob("scan_*"), key=os.path.getmtime, reverse=True)
        if scan_dirs:
            vuln_file = scan_dirs[0] / "vuln_recon.jsonl"
            if vuln_file.exists():
                for line in vuln_file.read_text().split("\n"):
                    if line.strip():
                        try:
                            target.findings.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
    except subprocess.TimeoutExpired:
        pass
    except Exception as e:
        pass
    
    return target


def rank_findings(findings: list) -> list:
    """Rank findings by bounty potential."""
    severity_score = {"critical": 100, "high": 70, "medium": 40, "low": 10, "info": 0}
    
    # Deduplicate by type+detail
    seen = set()
    unique = []
    for f in findings:
        key = f.get("type", "") + "|" + f.get("detail", "")[:50]
        if key not in seen:
            seen.add(key)
            unique.append(f)
    
    # Sort by severity
    unique.sort(key=lambda f: severity_score.get(f.get("severity", "info"), 0), reverse=True)
    return unique


def generate_report(result: BountyResult) -> str:
    """Generate a markdown report of findings."""
    OUTPUT_DIR.mkdir(exist_ok=True)
    report_path = OUTPUT_DIR / f"{result.program}_{int(time.time())}.md"
    
    report = f"""# Bounty Hunt Report: {result.program}

**Date:** {time.strftime("%Y-%m-%d %H:%M")}
**Duration:** {result.duration:.0f}s
**Targets discovered:** {result.targets_total}
**Targets live:** {result.targets_live}
**Targets scanned:** {result.targets_scanned}

## Summary

| Severity | Count |
|----------|-------|
| Critical | {result.critical} |
| High | {result.high} |
| Medium | {result.medium} |
| **Total** | **{result.total_findings}** |

## Findings (ranked by bounty potential)

"""
    for i, f in enumerate(result.findings[:50], 1):
        sev = f.get("severity", "?").upper()
        ftype = f.get("type", "Unknown")
        url = f.get("url", "")
        detail = f.get("detail", "")[:100]
        report += f"### {i}. [{sev}] {ftype}\n"
        report += f"- **URL:** {url}\n"
        report += f"- **Detail:** {detail}\n"
        if f.get("evidence"):
            report += f"- **Evidence:** {f['evidence'][:150]}\n"
        report += "\n"
    
    report_path.write_text(report)
    return str(report_path)


def main():
    if len(sys.argv) < 2:
        print("Usage: apex-bounty <program> or apex-bounty --scope <file>")
        print("Examples:")
        print("  apex-bounty yahoo")
        print("  apex-bounty --scope domains.txt")
        print("  apex-bounty --scope domains.txt -j 10")
        sys.exit(1)
    
    # Parse args
    threads = 5
    scope_file = None
    program = None
    
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--scope":
            scope_file = args[i + 1]
            i += 2
        elif args[i] == "-j":
            threads = int(args[i + 1])
            i += 2
        else:
            program = args[i]
            i += 1
    
    if not program:
        program = Path(scope_file).stem if scope_file else "unknown"
    
    start_time = time.time()
    print(f"\n{'='*60}")
    print(f"  APEX BOUNTY ORCHESTRATOR")
    print(f"  Program: {program}")
    print(f"  Threads: {threads}")
    print(f"{'='*60}\n")
    
    # Step 1: Get scope
    domains = []
    if scope_file:
        domains = [l.strip() for l in open(scope_file) if l.strip() and not l.startswith("#")]
        print(f"[1/5] Loaded {len(domains)} domains from scope file")
    else:
        # Use program name as domain
        domains = [f"{program}.com"]
        print(f"[1/5] Using domain: {domains[0]}")
    
    # Step 2: Subdomain enumeration
    print(f"[2/5] Enumerating subdomains...")
    all_subs = set()
    for domain in domains:
        subs = discover_subdomains(domain)
        all_subs.update(subs)
        print(f"       {domain}: {len(subs)} subdomains")
    
    all_targets = list(all_subs)
    print(f"       Total unique targets: {len(all_targets)}")
    
    # Step 3: Probe for live hosts
    print(f"[3/5] Probing for live hosts ({threads} threads)...")
    live_targets = probe_live(all_targets, threads=threads)
    print(f"       Live targets: {len(live_targets)}")
    
    # Step 4: Scan each live target
    print(f"[4/5] Scanning {len(live_targets)} targets ({threads} parallel)...")
    scanned = []
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(scan_target, t): t for t in live_targets[:50]}  # Cap at 50
        for i, future in enumerate(as_completed(futures), 1):
            target = future.result()
            scanned.append(target)
            n_findings = len(target.findings)
            status = f"✓ {n_findings} findings" if n_findings else "○ clean"
            print(f"       [{i}/{len(futures)}] {target.url} — {status}")
    
    # Step 5: Compile results
    print(f"[5/5] Compiling results...")
    all_findings = []
    for t in scanned:
        all_findings.extend(t.findings)
    
    ranked = rank_findings(all_findings)
    
    result = BountyResult(
        program=program,
        targets_total=len(all_targets),
        targets_live=len(live_targets),
        targets_scanned=len(scanned),
        total_findings=len(ranked),
        critical=sum(1 for f in ranked if f.get("severity") == "critical"),
        high=sum(1 for f in ranked if f.get("severity") == "high"),
        medium=sum(1 for f in ranked if f.get("severity") == "medium"),
        findings=ranked,
        duration=time.time() - start_time,
    )
    
    report_path = generate_report(result)
    
    # Print summary
    print(f"\n{'='*60}")
    print(f"  RESULTS: {program}")
    print(f"{'='*60}")
    print(f"  Targets: {result.targets_total} discovered → {result.targets_live} live → {result.targets_scanned} scanned")
    print(f"  Findings: {result.total_findings} total")
    print(f"    🔴 Critical: {result.critical}")
    print(f"    🟠 High:     {result.high}")
    print(f"    🟡 Medium:   {result.medium}")
    print(f"  Duration: {result.duration:.0f}s")
    print(f"  Report: {report_path}")
    print(f"{'='*60}\n")
    
    if result.critical > 0:
        print("  🚨 CRITICAL FINDINGS — submit these first!")
        for f in ranked[:5]:
            if f.get("severity") == "critical":
                print(f"     → {f.get('type')}: {f.get('url')}")


if __name__ == "__main__":
    main()
