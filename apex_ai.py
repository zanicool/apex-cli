#!/usr/bin/env python3
"""Apex AI — Post-scan reasoning engine that continues finding bugs after automated scan."""

import json, os, sys, subprocess, time, re
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
import requests

console = Console()
OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3.1:8b"  # Use llama3.1 — faster, fits in VRAM
RESULTS_DIR = Path.home() / "apex-auto-results"

SYSTEM_PROMPT = """You are an elite bug bounty hunter with 10 years experience. You think like a human attacker, not a scanner.

Your job after an automated scan:
1. Read what the scanner found and what it DIDN'T find
2. Reason about the application's business logic
3. Generate SPECIFIC follow-up tests that automated scanners can't do
4. Prioritize by bounty value
5. Write exact curl/Python commands to test each hypothesis

Rules:
- Be extremely specific. No generic advice.
- Every suggestion must be testable with a single command
- Focus on what makes money: criticals and highs
- Think about what the app DOES, not just what it IS"""


def ask_ai(prompt, stream=True):
    """Query local Ollama — stream output for real-time display."""
    try:
        if stream:
            r = requests.post(OLLAMA_URL, json={
                "model": MODEL, "prompt": prompt, "system": SYSTEM_PROMPT,
                "stream": True, "options": {"temperature": 0.4, "num_predict": 3000}
            }, stream=True, timeout=180)
            result = ""
            for line in r.iter_lines():
                if line:
                    try:
                        chunk = json.loads(line).get("response", "")
                        print(chunk, end="", flush=True)
                        result += chunk
                    except Exception:
                        pass
            print()
            return result
        else:
            r = requests.post(OLLAMA_URL, json={
                "model": MODEL, "prompt": prompt, "system": SYSTEM_PROMPT,
                "stream": False, "options": {"temperature": 0.4, "num_predict": 3000}
            }, timeout=180)
            return r.json().get("response", "")
    except Exception as e:
        return f"[AI unavailable: {e}]"


def load_scan(scan_dir):
    """Load scan results from a directory."""
    report = Path(scan_dir) / "report.json"
    if not report.exists():
        return None
    return json.load(open(report))


def ai_continue_scan(scan_dir, auto_test=False):
    """
    Main function: read scan results, reason about what to test next,
    optionally run follow-up tests automatically.
    """
    data = load_scan(scan_dir)
    if not data:
        console.print(f"[red]No report.json in {scan_dir}[/red]")
        return
    # Run AI even with 0 vulns — scanner may have missed things

    target = data.get("target", "unknown")
    vulns = data.get("vulnerabilities", [])
    tech = data.get("technologies", [])
    waf = data.get("waf", [])
    subdomains = data.get("subdomains", [])
    web_targets = data.get("web_targets", [])
    phases = data.get("phases", [])

    # What the scanner found
    found_types = [v["type"] for v in vulns]
    found_severities = {v["severity"] for v in vulns}
    skipped_phases = [p["phase"] for p in phases if p["status"] == "skipped"]
    error_phases = [p["phase"] for p in phases if p["status"] == "error"]

    # What the scanner didn't find (no params = no injection testing)
    crawl_file = Path(scan_dir) / "crawl.json"
    crawl_data = json.load(open(crawl_file)) if crawl_file.exists() else {}
    params_found = len(crawl_data.get("params", {}))
    forms_found = len(crawl_data.get("forms", []))
    pages_found = len(crawl_data.get("pages", []))

    console.print(Panel(
        f"[bold cyan]{target}[/bold cyan]\n"
        f"[dim]Tech: {', '.join(tech) or 'unknown'} | WAF: {', '.join(waf) or 'none'}[/dim]\n"
        f"[dim]Pages: {pages_found} | Forms: {forms_found} | Params: {params_found}[/dim]\n"
        f"[dim]Subdomains: {len(subdomains)} | Web targets: {len(web_targets)}[/dim]",
        title="[bold red]☠ APEX AI — Continuing the Hunt[/bold red]",
        border_style="red"
    ))

    # Build context for AI
    vuln_summary = "\n".join([
        f"- [{v['severity'].upper()}] {v['type']}: {v.get('url','')[:80]}"
        + (f"\n  Detail: {v.get('detail','')[:100]}" if v.get('detail') else "")
        for v in sorted(vulns, key=lambda x: x.get('cvss_score', 0), reverse=True)[:20]
    ]) or "None found"

    prompt = f"""I just ran an automated security scan on {target}. Here's what happened:

TARGET INFO:
- Technologies: {', '.join(tech) or 'unknown'}
- WAF: {', '.join(waf) or 'none'}
- Subdomains found: {len(subdomains)} ({', '.join(subdomains[:5])})
- Web targets: {', '.join(web_targets[:3])}
- Pages crawled: {pages_found}
- Forms found: {forms_found}
- Parameterized URLs: {params_found}

WHAT THE SCANNER FOUND:
{vuln_summary}

WHAT THE SCANNER COULDN'T TEST (skipped/failed):
{', '.join(skipped_phases[:10]) or 'none'}

GAPS I NEED YOU TO FILL:
{"- Very few params/forms found — likely a SPA or API-first app" if params_found < 5 else ""}
{"- No crawl data — scanner couldn't reach authenticated pages" if pages_found < 3 else ""}
{"- WAF present — some payloads may have been blocked" if waf else ""}
{"- No criticals found — need to look harder" if 'critical' not in found_severities else ""}

Based on this, give me:

1. **WHAT TO TEST NEXT** — 5 specific hypotheses about bugs the scanner missed, based on the tech stack and what was found. For each hypothesis, explain WHY you think it exists.

2. **EXACT COMMANDS** — For each hypothesis, write the exact curl/Python command to test it. Make them copy-paste ready.

3. **BUSINESS LOGIC ATTACKS** — Based on what {target} does as a business, what business logic bugs should I test? Be specific to this company.

4. **ATTACK CHAINS** — Can any of the found vulnerabilities be chained for higher impact? Show the exact chain.

5. **PRIORITY ORDER** — Which test should I run first for maximum bounty value?"""

    console.print("\n[bold red]AI Analysis:[/bold red]")
    ai_response = ask_ai(prompt)

    # Parse AI response for executable commands
    if auto_test:
        console.print("\n[bold yellow]Auto-testing AI suggestions...[/bold yellow]")
        _auto_test_suggestions(ai_response, target, web_targets, scan_dir)

    # Save AI analysis to scan directory
    ai_report = Path(scan_dir) / "ai_analysis.md"
    with open(ai_report, "w") as f:
        f.write(f"# AI Analysis: {target}\n\n")
        f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(ai_response)
    console.print(f"\n[green][✓][/green] AI analysis saved → {ai_report}")

    return ai_response


def _auto_test_suggestions(ai_response, target, web_targets, scan_dir):
    """Extract curl commands from AI response and run them."""
    # Find curl commands in AI response
    curl_commands = re.findall(r'`(curl [^`]+)`', ai_response)
    curl_commands += re.findall(r'```(?:bash|sh)?\n(curl [^\n]+)\n```', ai_response)

    if not curl_commands:
        console.print("[dim]No executable commands found in AI response[/dim]")
        return

    console.print(f"[cyan]Found {len(curl_commands)} commands to test:[/cyan]")
    results = []
    for i, cmd in enumerate(curl_commands[:5]):  # Max 5 auto-tests
        # Replace placeholder domains with actual target
        cmd = cmd.replace("example.com", target).replace("TARGET", target)
        if web_targets:
            cmd = cmd.replace("https://TARGET", web_targets[0])
        console.print(f"\n[dim]Running: {cmd[:80]}...[/dim]")
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=15
            )
            output = (result.stdout + result.stderr)[:500]
            results.append({"cmd": cmd, "output": output, "returncode": result.returncode})
            # Check for interesting output
            interesting = any(x in output.lower() for x in
                            ["root:", "admin", "token", "secret", "password", "error",
                             "sql", "exception", "traceback", "internal"])
            if interesting:
                console.print(f"[bold red]  🎯 INTERESTING OUTPUT:[/bold red] {output[:200]}")
            else:
                console.print(f"[dim]  → {output[:100]}[/dim]")
        except subprocess.TimeoutExpired:
            console.print("[yellow]  → Timeout[/yellow]")
        except Exception as e:
            console.print(f"[red]  → Error: {e}[/red]")

    # Save auto-test results
    if results:
        with open(Path(scan_dir) / "ai_autotests.json", "w") as f:
            json.dump(results, f, indent=2)


def ai_watch_and_continue(target, interval_hours=1):
    """Watch for new scan results and automatically run AI analysis."""
    console.print(f"[bold cyan]AI Watch Mode: monitoring {target} every {interval_hours}h[/bold cyan]")
    seen_scans = set()
    while True:
        # Find latest scan for this target
        scan_dirs = sorted(
            Path(".").glob(f"scan_{target}_*"),
            key=lambda p: p.stat().st_mtime, reverse=True
        )
        for scan_dir in scan_dirs:
            if str(scan_dir) not in seen_scans and (scan_dir / "report.json").exists():
                seen_scans.add(str(scan_dir))
                console.print(f"\n[green]New scan found: {scan_dir}[/green]")
                ai_continue_scan(str(scan_dir), auto_test=True)
        time.sleep(interval_hours * 3600)


def ai_generate_custom_payloads(target, tech_stack):
    """Generate custom payloads based on tech stack — goes beyond static payload lists."""
    prompt = f"""Generate custom security test payloads for {target} running {tech_stack}.

I need payloads that are SPECIFIC to this tech stack, not generic ones.

For each vulnerability class relevant to {tech_stack}, give me:
1. The most effective payload for this specific framework
2. Why this payload works on {tech_stack} specifically
3. The exact HTTP request to send (method, headers, body)
4. What a successful response looks like

Focus on: RCE, auth bypass, IDOR, injection. Skip generic XSS/SQLi."""

    console.print(f"\n[bold red]☠ APEX AI — Custom Payload Generation[/bold red]")
    return ask_ai(prompt)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(prog="apex-ai",
                                     description="Apex AI — continues finding bugs after automated scan")
    parser.add_argument("scan_dir", nargs="?", help="Scan directory to analyze")
    parser.add_argument("--auto", action="store_true", help="Auto-run AI-suggested tests")
    parser.add_argument("--watch", type=str, metavar="TARGET", help="Watch for new scans on target")
    parser.add_argument("--payloads", nargs=2, metavar=("TARGET","TECH"), help="Generate custom payloads")
    parser.add_argument("--chains", action="store_true", help="Cross-target chain analysis")
    args = parser.parse_args()

    if args.watch:
        ai_watch_and_continue(args.watch)
    elif args.payloads:
        ai_generate_custom_payloads(args.payloads[0], args.payloads[1])
    elif args.chains:
        # Legacy chain analysis
        hits_file = RESULTS_DIR / "hits.json"
        if hits_file.exists():
            hits = json.load(open(hits_file))
            all_vulns = [f"[{h['target']}] [{v['severity']}] {v['type']}: {v.get('detail','')[:80]}"
                        for h in hits for v in h["vulnerabilities"]]
            if all_vulns:
                prompt = f"Analyze these findings for attack chains and bounty value:\n" + "\n".join(all_vulns[:50])
                ask_ai(prompt)
    elif args.scan_dir:
        ai_continue_scan(args.scan_dir, auto_test=args.auto)
    else:
        # Find most recent scan and analyze it
        scan_dirs = sorted(Path(".").glob("scan_*"), key=lambda p: p.stat().st_mtime, reverse=True)
        if scan_dirs and (scan_dirs[0] / "report.json").exists():
            console.print(f"[dim]Analyzing most recent scan: {scan_dirs[0]}[/dim]")
            ai_continue_scan(str(scan_dirs[0]), auto_test=args.auto)
        else:
            parser.print_help()
            print("\nExamples:")
            print("  apex-ai scan_bancoplata.mx_20260502/     # Analyze specific scan")
            print("  apex-ai scan_bancoplata.mx_20260502/ --auto  # Auto-run suggestions")
            print("  apex-ai --watch bancoplata.mx            # Watch + auto-analyze new scans")
            print("  apex-ai --payloads target.com Laravel    # Custom payloads for tech stack")
