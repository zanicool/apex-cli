#!/usr/bin/env python3
"""Apex AI Reasoning Engine — analyzes scan results, discovers attack chains, predicts exploitability."""

import json, os, requests, sys
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()
OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3.2:latest"  # Fast, fits in 6GB VRAM
RESULTS_DIR = Path.home() / "apex-auto-results"

SYSTEM_PROMPT = """You are an elite penetration tester and security researcher. You analyze vulnerability scan results and:

1. ATTACK CHAIN DISCOVERY: Find how multiple low/medium findings can be chained into critical exploits
2. EXPLOITABILITY ASSESSMENT: Rate each finding's real-world exploitability (not just theoretical)
3. FALSE POSITIVE DETECTION: Identify likely false positives based on patterns
4. BUSINESS IMPACT: Assess actual business impact of each finding
5. NEXT STEPS: Suggest manual testing steps that automated scanners can't do

Be specific, technical, and actionable. No fluff. Think like a bug bounty hunter who needs to write a report."""


def ask_ai(prompt, model=MODEL):
    """Query local Ollama LLM."""
    try:
        r = requests.post(OLLAMA_URL, json={
            "model": model,
            "prompt": prompt,
            "system": SYSTEM_PROMPT,
            "stream": False,
            "options": {"temperature": 0.3, "num_predict": 2000}
        }, timeout=120)
        return r.json().get("response", "")
    except Exception as e:
        return f"AI error: {e}"


def analyze_target(target_data):
    """Analyze a single target's findings with AI."""
    vulns = target_data.get("vulnerabilities", [])
    if not vulns:
        return "No vulnerabilities to analyze."

    vuln_summary = "\n".join([
        f"- [{v['severity'].upper()}] {v['type']}: {v.get('url','')[:80]} — {v.get('detail','')[:100]}"
        for v in vulns[:30]
    ])

    prompt = f"""Analyze these scan findings for {target_data['target']}:

{vuln_summary}

Provide:
1. Which findings are likely REAL vs FALSE POSITIVE (and why)
2. Any ATTACK CHAINS you can construct from combining these findings
3. The single most valuable finding to report for a bug bounty
4. Specific manual testing steps to confirm the top findings
5. Estimated bounty value if confirmed real"""

    return ask_ai(prompt)


def analyze_all_hits():
    """Analyze all hits across all machines."""
    hits_file = RESULTS_DIR / "hits.json"
    if not hits_file.exists():
        console.print("[yellow]No hits file found.[/yellow]")
        return

    with open(hits_file) as f:
        hits = json.load(f)

    if not hits:
        console.print("[yellow]No hits to analyze.[/yellow]")
        return

    console.print(f"\n[bold red]☠ APEX AI REASONING ENGINE[/bold red]")
    console.print(f"[dim]Analyzing {len(hits)} targets with local LLM ({MODEL})...[/dim]\n")

    for hit in hits:
        console.print(Panel(f"[bold cyan]{hit['target']}[/bold cyan] — {len(hit['vulnerabilities'])} findings",
                           border_style="red"))
        console.print("[dim]Thinking...[/dim]")
        analysis = analyze_target(hit)
        console.print(analysis)
        console.print()


def analyze_single(target):
    """Deep AI analysis of a single target — suggest what to test manually."""
    prompt = f"""I'm doing a bug bounty on {target}. I've already run automated scans.

Now I need to find bugs that scanners CAN'T find. Give me:

1. Top 10 specific manual tests to try on this target
2. Common business logic bugs for this type of application
3. API endpoints to look for that scanners miss
4. Authentication/authorization edge cases to test
5. Specific payloads or techniques for this target's likely tech stack

Be extremely specific and actionable. I want to find a critical bug."""

    console.print(f"\n[bold red]☠ APEX AI — Deep Target Analysis[/bold red]")
    console.print(f"[dim]Analyzing {target}...[/dim]\n")
    result = ask_ai(prompt)
    console.print(result)


def chain_analysis():
    """Cross-target attack chain discovery."""
    hits_file = RESULTS_DIR / "hits.json"
    if not hits_file.exists():
        return

    with open(hits_file) as f:
        hits = json.load(f)

    all_vulns = []
    for h in hits:
        for v in h["vulnerabilities"]:
            all_vulns.append(f"[{h['target']}] [{v['severity']}] {v['type']}: {v.get('detail','')[:80]}")

    if not all_vulns:
        return

    prompt = f"""I found these vulnerabilities across multiple targets in bug bounty programs:

{chr(10).join(all_vulns[:50])}

Analyze:
1. Which of these are REAL vulnerabilities vs false positives?
2. Can any be CHAINED together for higher impact?
3. Which single finding should I report FIRST for maximum bounty?
4. For each real finding, what's the estimated bounty payout?
5. Write a brief proof-of-concept for the most valuable finding."""

    console.print(f"\n[bold red]☠ APEX AI — Cross-Target Chain Analysis[/bold red]")
    console.print(f"[dim]Analyzing {len(all_vulns)} findings across {len(hits)} targets...[/dim]\n")
    result = ask_ai(prompt)
    console.print(result)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "--chains":
            chain_analysis()
        else:
            analyze_single(sys.argv[1])
    else:
        analyze_all_hits()
