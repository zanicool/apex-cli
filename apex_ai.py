#!/usr/bin/env python3
"""Apex AI — Post-scan reasoning engine that continues finding bugs after automated scan."""

import json, os, sys, subprocess, time, re
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
import requests

console = Console()

# --- Multi-backend LLM configuration ---
AI_BACKEND = os.environ.get("APEX_AI_BACKEND", "ollama")  # ollama | openai | anthropic
OLLAMA_URL = os.environ.get("APEX_OLLAMA_URL", "http://localhost:11434/api/generate")
OPENAI_URL = os.environ.get("APEX_OPENAI_URL", "https://api.openai.com/v1/chat/completions")
ANTHROPIC_URL = os.environ.get("APEX_ANTHROPIC_URL", "https://api.anthropic.com/v1/messages")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
MODEL = os.environ.get("APEX_AI_MODEL", "llama3.1:8b")
AI_WORKERS = 3
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
    """Query LLM backend — supports Ollama, OpenAI API, and Anthropic."""
    backend = AI_BACKEND.lower()
    if backend == "openai":
        return _ask_openai(prompt, stream)
    elif backend == "anthropic":
        return _ask_anthropic(prompt, stream)
    else:
        return _ask_ollama(prompt, stream)


def _ask_ollama(prompt, stream=True):
    """Query local Ollama."""
    try:
        if stream:
            r = requests.post(OLLAMA_URL, json={
                "model": MODEL, "prompt": prompt, "system": SYSTEM_PROMPT,
                "stream": True, "options": {"temperature": 0.4, "num_predict": 1500}
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
        return f"[AI unavailable (Ollama): {e}]"


def _ask_openai(prompt, stream=True):
    """Query OpenAI-compatible API (works with OpenAI, Together, Groq, etc.)."""
    if not OPENAI_API_KEY:
        return "[AI unavailable: OPENAI_API_KEY not set]"
    headers = {"Authorization": f"Bearer {OPENAI_API_KEY}", "Content-Type": "application/json"}
    body = {
        "model": MODEL if "/" in MODEL or "gpt" in MODEL else "gpt-4o-mini",
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.4,
        "max_tokens": 3000,
        "stream": stream,
    }
    try:
        if stream:
            r = requests.post(OPENAI_URL, json=body, headers=headers, stream=True, timeout=180)
            result = ""
            for line in r.iter_lines():
                if line:
                    line = line.decode("utf-8").removeprefix("data: ")
                    if line == "[DONE]":
                        break
                    try:
                        chunk = json.loads(line)["choices"][0]["delta"].get("content", "")
                        print(chunk, end="", flush=True)
                        result += chunk
                    except Exception:
                        pass
            print()
            return result
        else:
            r = requests.post(OPENAI_URL, json=body, headers=headers, timeout=180)
            return r.json()["choices"][0]["message"]["content"]
    except Exception as e:
        return f"[AI unavailable (OpenAI): {e}]"


def _ask_anthropic(prompt, stream=True):
    """Query Anthropic Claude API."""
    if not ANTHROPIC_API_KEY:
        return "[AI unavailable: ANTHROPIC_API_KEY not set]"
    headers = {
        "x-api-key": ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
        "Content-Type": "application/json",
    }
    body = {
        "model": MODEL if "claude" in MODEL else "claude-sonnet-4-20250514",
        "max_tokens": 3000,
        "system": SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": prompt}],
        "stream": stream,
    }
    try:
        if stream:
            r = requests.post(ANTHROPIC_URL, json=body, headers=headers, stream=True, timeout=180)
            result = ""
            for line in r.iter_lines():
                if line:
                    line = line.decode("utf-8").removeprefix("data: ")
                    try:
                        event = json.loads(line)
                        if event.get("type") == "content_block_delta":
                            chunk = event["delta"].get("text", "")
                            print(chunk, end="", flush=True)
                            result += chunk
                    except Exception:
                        pass
            print()
            return result
        else:
            r = requests.post(ANTHROPIC_URL, json=body, headers=headers, timeout=180)
            data = r.json()
            return data["content"][0]["text"] if data.get("content") else ""
    except Exception as e:
        return f"[AI unavailable (Anthropic): {e}]"


def load_scan(scan_dir):
    """Load scan results from a directory."""
    report = Path(scan_dir) / "report.json"
    if not report.exists():
        return None
    return json.load(open(report))


def ai_continue_scan(scan_dir, auto_test=False):
    """Generate a bug bounty report from scan findings — streams to CLI."""
    data = load_scan(scan_dir)
    if not data:
        console.print(f"[red]No report.json in {scan_dir}[/red]")
        return

    target = data.get("target", "unknown")
    vulns = data.get("vulnerabilities", [])

    # Deduplicate, keep only reportable severities
    seen = set()
    reportable = []
    for v in sorted(vulns, key=lambda x: x.get("cvss_score", 0), reverse=True):
        if v.get("severity") not in ("critical", "high", "medium"):
            continue
        key = f"{v['type']}|{v.get('url','').split('?')[0]}"
        if key not in seen:
            seen.add(key)
            reportable.append(v)

    if not reportable:
        console.print("[dim]No reportable findings — skipping AI report[/dim]")
        return

    findings_str = "\n".join(
        f"- [{v['severity'].upper()}] {v['type']}: {v.get('url','')[:80]}"
        + (f"\n  Detail: {v.get('detail','')[:100]}" if v.get('detail') else "")
        for v in reportable[:15]
    )

    prompt = f"""Write a professional HackerOne bug bounty report for these findings on {target}:

{findings_str}

For each real vulnerability write:
TITLE: (one line)
SEVERITY: critical/high/medium
DESCRIPTION: (2-3 sentences)
STEPS TO REPRODUCE: (numbered, copy-paste ready curl commands)
IMPACT: (one paragraph)
REMEDIATION: (bullet points)

Skip missing headers and informational findings. Only include exploitable vulnerabilities."""

    console.print(f"\n[bold red]☠ APEX AI — Bug Bounty Report[/bold red]")
    console.print(f"[dim]{len(reportable)} findings → generating report...\n[/dim]")

    report_text = ask_ai(prompt, stream=True)

    ai_report = Path(scan_dir) / "ai_report.md"
    ai_report.write_text(f"# Bug Bounty Report: {target}\nGenerated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n{report_text}")
    console.print(f"\n[green][✓][/green] Report saved → {ai_report}")
    return report_text

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



def generate_h1_reports(scan_dir):
    """Generate ready-to-submit HackerOne reports for each high/critical finding."""
    data = load_scan(scan_dir)
    if not data:
        return
    target = data.get("target", "unknown")
    vulns = [v for v in data.get("vulnerabilities", [])
             if v.get("severity") in ("critical", "high")
             and v.get("template") not in ("apex-headers", "apex-hsts",
                                            "apex-clickjack", "apex-mime")]

    if not vulns:
        console.print("[dim]No high/critical findings to generate reports for[/dim]")
        return

    # Deduplicate by type+base_url
    seen = set()
    unique = []
    for v in vulns:
        key = f"{v['type']}|{v.get('url','').split('?')[0]}"
        if key not in seen:
            seen.add(key)
            unique.append(v)

    reports_dir = Path(scan_dir) / "h1_reports"
    reports_dir.mkdir(exist_ok=True)

    _CVSS = {
        "apex-takeover": ("9.3", "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N", "CWE-350"),
        "apex-takeover-deep": ("9.3", "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N", "CWE-350"),
        "apex-ns-takeover": ("9.3", "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N", "CWE-350"),
        "apex-s3": ("7.5", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "CWE-200"),
        "apex-gcs": ("7.5", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "CWE-200"),
        "apex-azure": ("7.5", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "CWE-200"),
        "apex-ssrf": ("9.8", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CWE-918"),
        "apex-sqli": ("9.8", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CWE-89"),
        "apex-xss": ("6.1", "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "CWE-79"),
        "apex-lfi": ("7.5", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "CWE-22"),
        "apex-cmdi": ("9.8", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CWE-78"),
        "apex-ssti": ("9.8", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CWE-94"),
        "apex-cors": ("8.1", "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N", "CWE-942"),
        "apex-idor": ("8.1", "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", "CWE-639"),
        "apex-secrets": ("9.8", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CWE-540"),
        "apex-sensitive": ("7.5", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "CWE-200"),
    }

    _REMEDIATION = {
        "CWE-350": "Remove the dangling DNS record immediately. Audit all DNS records regularly for dangling CNAMEs/NS records.",
        "CWE-200": "Restrict bucket/storage access to authorized users only. Enable public access prevention at the organization level.",
        "CWE-918": "Validate and allowlist URLs before fetching. Block requests to RFC1918 addresses and cloud metadata endpoints.",
        "CWE-89": "Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
        "CWE-79": "Encode all user-supplied output using context-appropriate escaping. Implement a strict Content-Security-Policy.",
        "CWE-22": "Never use user input in file paths. Use a whitelist of allowed files.",
        "CWE-78": "Never pass user input to shell commands. Use language-native APIs instead.",
        "CWE-94": "Never render user input as a template. Use sandboxed template engines.",
        "CWE-942": "Set Access-Control-Allow-Origin to specific trusted origins only. Never reflect the Origin header.",
        "CWE-639": "Implement object-level authorization checks on every request. Use indirect references.",
        "CWE-540": "Rotate the exposed credential immediately. Use a secrets manager. Add pre-commit hooks.",
    }

    generated = []
    for i, v in enumerate(unique[:10]):  # Max 10 reports
        template = v.get("template", "")
        cvss_score, cvss_vector, cwe = _CVSS.get(template, ("7.5", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "CWE-200"))
        sev = v["severity"].capitalize()
        vtype = v["type"]
        url = v.get("url", "")
        detail = v.get("detail", "")
        remediation = _REMEDIATION.get(cwe, "Review and fix the vulnerability following OWASP guidelines.")

        # Generate PoC command
        poc = f'curl -sk "{url}"'
        if "takeover" in template.lower():
            poc = f'curl -sk "{url}"\n# Observe: returns third-party service error page indicating dangling DNS'
        elif "s3" in template.lower() or "gcs" in template.lower() or "azure" in template.lower():
            poc = f'curl -sk "{url}"\n# Observe: returns XML bucket listing without authentication'

        report = f"""# {vtype}

**Target:** {target}
**Asset:** {url}
**Severity:** {sev}
**CVSS Score:** {cvss_score}
**CVSS Vector:** {cvss_vector}
**Weakness:** {cwe}

---

## Summary

{vtype} was identified on `{url}`. {detail}

---

## Steps to Reproduce

1. Send a request to the affected URL:
```
{poc}
```

2. Observe the response confirming the vulnerability:
```
{detail}
```

---

## Impact

{detail}. This vulnerability affects the confidentiality and/or integrity of DoorDash's systems and user data.

---

## Remediation

{remediation}

---

*Report generated by Apex CLI v8.x*
"""
        fname = reports_dir / f"report_{i+1}_{template.replace('-','_')[:30]}.md"
        fname.write_text(report)
        generated.append(str(fname))
        console.print(f"[green][✓][/green] H1 report → {fname.name}")

    console.print(f"\n[bold green]{len(generated)} HackerOne reports saved to {reports_dir}/[/bold green]")
    return generated


def generate_h1_reports(scan_dir):
    """Generate full HackerOne-ready reports for each real finding."""
    data = load_scan(scan_dir)
    if not data:
        console.print(f"[red]No report.json in {scan_dir}[/red]")
        return

    target = data.get("target", "unknown")
    vulns = data.get("vulnerabilities", [])

    # Filter to reportable findings only
    reportable = [v for v in vulns
                  if v.get("severity") in ("critical", "high", "medium")
                  and v.get("template") not in ("apex-headers", "apex-hsts",
                                                  "apex-clickjack", "apex-mime",
                                                  "apex-policy", "apex-csp")]

    # Deduplicate by type
    seen = set()
    unique = []
    for v in reportable:
        if v["type"] not in seen:
            seen.add(v["type"])
            unique.append(v)

    if not unique:
        console.print("[yellow]No reportable findings found[/yellow]")
        return

    console.print(f"[bold red]☠ APEX AI — Generating {len(unique)} HackerOne reports[/bold red]\n")

    reports_dir = Path(scan_dir) / "h1_reports"
    reports_dir.mkdir(exist_ok=True)

    for i, vuln in enumerate(unique[:10], 1):
        ftype = vuln["type"]
        severity = vuln["severity"].upper()
        url = vuln.get("url", "")
        detail = vuln.get("detail", "")
        template = vuln.get("template", "")

        console.print(f"[cyan]Generating report {i}/{min(len(unique),10)}: {ftype[:50]}...[/cyan]")

        prompt = f"""Write a professional HackerOne bug bounty report for this vulnerability found on {target}.

FINDING:
- Type: {ftype}
- Severity: {severity}
- URL: {url}
- Detail: {detail}
- Template: {template}

Write the complete report with these exact sections:

**Title:** (concise, specific title)

**Asset:** (the affected URL/domain)

**Weakness:** (CWE number and name, e.g. CWE-942 — Permissive Cross-domain Policy)

**Severity:** {severity}

**CVSS 4.0 Score:** (calculate and show the vector string and numeric score)
- Attack Vector: 
- Attack Complexity:
- Privileges Required:
- User Interaction:
- Scope:
- Confidentiality:
- Integrity:
- Availability:
- Score: X.X

**Description:**
(2-3 paragraphs explaining the vulnerability technically)

**Steps to Reproduce:**
(numbered steps with exact curl commands)

**Impact:**
(specific business impact for this company)

**Remediation:**
(specific fix recommendations)

Be specific to {target} and this exact finding. No generic advice."""

        report = ask_ai(prompt, stream=False)

        # Save report
        safe_name = re.sub(r'[^\w]', '_', ftype)[:40].lower()
        report_file = reports_dir / f"report_{i}_{safe_name}.md"
        report_file.write_text(f"# HackerOne Report: {ftype}\n\n{report}")
        console.print(f"[green][✓][/green] {report_file.name}")
        console.print()

    console.print(f"\n[bold green]{min(len(unique),10)} reports saved to {reports_dir}/[/bold green]")
    return reports_dir


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(prog="apex-ai",
                                     description="Apex AI — continues finding bugs after automated scan")
    parser.add_argument("scan_dir", nargs="?", help="Scan directory to analyze")
    parser.add_argument("--auto", action="store_true", help="Auto-run AI-suggested tests")
    parser.add_argument("--watch", type=str, metavar="TARGET", help="Watch for new scans on target")
    parser.add_argument("--payloads", nargs=2, metavar=("TARGET","TECH"), help="Generate custom payloads")
    parser.add_argument("--chains", action="store_true", help="Cross-target chain analysis")
    parser.add_argument("--reports", action="store_true", help="Generate full HackerOne reports for all findings")
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
    elif args.reports and args.scan_dir:
        generate_h1_reports(args.scan_dir)
    elif args.scan_dir:
        if args.reports:
            generate_h1_reports(args.scan_dir)
        else:
            ai_continue_scan(args.scan_dir, auto_test=args.auto)
    else:
        # Find most recent scan and analyze it
        scan_dirs = sorted(Path(".").glob("scan_*"), key=lambda p: p.stat().st_mtime, reverse=True)
        if scan_dirs and (scan_dirs[0] / "report.json").exists():
            console.print(f"[dim]Analyzing most recent scan: {scan_dirs[0]}[/dim]")
            if args.reports:
                generate_h1_reports(str(scan_dirs[0]))
            else:
                ai_continue_scan(str(scan_dirs[0]), auto_test=args.auto)
        else:
            parser.print_help()
            print("\nExamples:")
            print("  apex-ai scan_bancoplata.mx_20260502/     # Analyze specific scan")
            print("  apex-ai scan_bancoplata.mx_20260502/ --auto  # Auto-run suggestions")
            print("  apex-ai --watch bancoplata.mx            # Watch + auto-analyze new scans")
            print("  apex-ai --payloads target.com Laravel    # Custom payloads for tech stack")
