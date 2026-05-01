#!/usr/bin/env python3
"""Apex CLI v3.0 — Automated Pen-Test Orchestrator."""

import argparse
import subprocess
import os
import sys
import json
import re
import shutil
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.panel import Panel
from jinja2 import Template

# Built-in scanners (no external tools needed)
from scanners import (
    crawl, scan_xss, scan_cmdi, scan_idor, scan_open_redirect,
    scan_headers, fingerprint, detect_waf, scan_sensitive_files,
)

console = Console()

# ---------------------------------------------------------------------------
# Tool discovery
# ---------------------------------------------------------------------------

def find_tool(name):
    """Return absolute path for *name* or None."""
    return shutil.which(name)

def find_httpx():
    """Find ProjectDiscovery's httpx, not the Python pip httpx."""
    path = find_tool("httpx")
    if not path:
        return None
    try:
        r = subprocess.run([path, "-version"], capture_output=True, text=True, timeout=5)
        output = (r.stdout + r.stderr).lower()
        if "projectdiscovery" in output or "current" in output:
            return path
    except Exception:
        pass
    return None

TOOLS = {
    "subfinder": find_tool("subfinder"),
    "amass": find_tool("amass"),
    "assetfinder": find_tool("assetfinder"),
    "nmap": find_tool("nmap"),
    "httpx": find_httpx(),
    "ffuf": find_tool("ffuf"),
    "nuclei": find_tool("nuclei"),
    "sqlmap": find_tool("sqlmap"),
}

# Wordlist discovery — try common locations, fall back to a tiny built-in list.
WORDLIST_CANDIDATES = [
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/dirbuster/wordlists/directory-list-2.3-small.txt",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "wordlist.txt"),
]

def find_wordlist():
    for wl in WORDLIST_CANDIDATES:
        if os.path.isfile(wl):
            return wl
    return None

DEFAULT_WORDLIST = find_wordlist()

# ---------------------------------------------------------------------------
# Target validation
# ---------------------------------------------------------------------------

_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)
_IP_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

def validate_target(target: str) -> str:
    """Strip protocol/path and validate as domain, IP, or localhost."""
    t = re.sub(r"^https?://", "", target).split("/")[0].split(":")[0].strip().lower()
    if not t:
        console.print("[bold red][!] Empty target.[/bold red]")
        sys.exit(1)
    if t == "localhost":
        return t
    if not (_DOMAIN_RE.match(t) or _IP_RE.match(t)):
        console.print(f"[bold red][!] Invalid target: {t}[/bold red]")
        sys.exit(1)
    return t

# ---------------------------------------------------------------------------
# Core scanner
# ---------------------------------------------------------------------------

class ApexCLI:
    def __init__(self, target, output_dir, dry_run=False, deep=False):
        self.target = target
        self.output_dir = output_dir
        self.dry_run = dry_run
        self.deep = deep
        self.subdomains: list[str] = []
        self.web_targets: list[str] = []
        self.vulnerabilities: list[dict] = []
        self.phase_results: list[dict] = []
        self.crawl_data: dict = {}
        self.technologies: list[str] = []
        self.waf_detected: list[str] = []
        os.makedirs(self.output_dir, exist_ok=True)

    # -- helpers -----------------------------------------------------------

    def _tool(self, name):
        return TOOLS.get(name)

    def _require(self, name):
        path = self._tool(name)
        if not path:
            console.print(f"[yellow][!] {name} not found — skipping.[/yellow]")
        return path

    def run_command(self, cmd, desc, log_file=None):
        if self.dry_run:
            cmd_str = " ".join(cmd)
            console.print(f"[bold yellow][DRY RUN][/bold yellow] {cmd_str}")
            return "dry-run", "", 0

        console.print(f"[bold blue][+][/bold blue] {desc}")
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=1800
            )
            if log_file:
                out_path = os.path.join(self.output_dir, log_file)
                with open(out_path, "w") as f:
                    f.write(proc.stdout)
                    if proc.stderr:
                        f.write("\n--- STDERR ---\n")
                        f.write(proc.stderr)
            return proc.stdout, proc.stderr, proc.returncode
        except subprocess.TimeoutExpired:
            console.print(f"[red][!] {desc} timed out (600s limit).[/red]")
            return "", "timeout", 1
        except Exception as e:
            console.print(f"[red][!] Error in {desc}: {e}[/red]")
            return "", str(e), 1

    def _dedup_subdomains(self):
        seen = set()
        deduped = []
        for s in self.subdomains:
            s = s.strip().lower()
            if s and s not in seen:
                seen.add(s)
                deduped.append(s)
        self.subdomains = deduped

    def _log_phase(self, name, status, detail=""):
        self.phase_results.append({"phase": name, "status": status, "detail": detail})

    # -- phases ------------------------------------------------------------

    def phase_recon_subfinder(self):
        path = self._require("subfinder")
        if not path:
            self._log_phase("Subfinder", "skipped", "not installed")
            return
        cmd = [path, "-d", self.target, "-silent"]
        stdout, _, code = self.run_command(cmd, f"Subfinder on {self.target}", "subfinder.txt")
        found = [l.strip() for l in stdout.splitlines() if l.strip()]
        self.subdomains.extend(found)
        self._log_phase("Subfinder", "ok" if code == 0 else "error", f"{len(found)} subdomains")

    def phase_recon_amass(self):
        path = self._require("amass")
        if not path:
            self._log_phase("Amass", "skipped", "not installed")
            return
        cmd = [path, "enum", "-d", self.target, "-passive", "-silent"]
        stdout, _, code = self.run_command(cmd, f"Amass on {self.target}", "amass.txt")
        found = [l.strip() for l in stdout.splitlines() if l.strip()]
        self.subdomains.extend(found)
        self._log_phase("Amass", "ok" if code == 0 else "error", f"{len(found)} subdomains")

    def phase_recon_assetfinder(self):
        path = self._require("assetfinder")
        if not path:
            self._log_phase("Assetfinder", "skipped", "not installed")
            return
        cmd = [path, self.target]
        stdout, _, code = self.run_command(cmd, f"Assetfinder on {self.target}", "assetfinder.txt")
        found = [l.strip() for l in stdout.splitlines() if l.strip()]
        self.subdomains.extend(found)
        self._log_phase("Assetfinder", "ok" if code == 0 else "error", f"{len(found)} subdomains")

    def phase_recon(self):
        """Run all recon tools, then deduplicate."""
        self.phase_recon_subfinder()
        if self.deep:
            self.phase_recon_amass()
            self.phase_recon_assetfinder()
        self._dedup_subdomains()
        if not self.subdomains:
            self.subdomains = [self.target]
            console.print("[yellow][!] No subdomains found — using base target.[/yellow]")
        console.print(f"[green][✓][/green] {len(self.subdomains)} unique subdomains after dedup.")
        # Save consolidated list
        with open(os.path.join(self.output_dir, "subdomains.txt"), "w") as f:
            f.write("\n".join(self.subdomains) + "\n")

    def phase_probe(self):
        """Probe for live web services using httpx (preferred) or nmap."""
        httpx_path = self._tool("httpx")
        nmap_path = self._tool("nmap")

        if httpx_path:
            self._probe_httpx(httpx_path)
        elif nmap_path:
            self._probe_nmap(nmap_path)
        else:
            console.print("[yellow][!] Neither httpx (ProjectDiscovery) nor nmap found — probing with curl.[/yellow]")
            self._probe_curl()

        self.web_targets = list(dict.fromkeys(self.web_targets))  # dedup, preserve order
        console.print(f"[green][✓][/green] {len(self.web_targets)} live web targets.")

    def _probe_httpx(self, path):
        subs_file = os.path.join(self.output_dir, "subdomains.txt")
        cmd = [path, "-l", subs_file, "-silent", "-no-color"]
        if self.deep:
            cmd.extend(["-ports", "80,443,8080,8443,8000,3000"])
        stdout, _, code = self.run_command(cmd, "httpx probing for live hosts", "httpx.txt")
        if self.dry_run:
            self.web_targets = [f"https://{s}" for s in self.subdomains]
        else:
            # Only keep lines that look like URLs
            self.web_targets = [l.strip() for l in stdout.splitlines()
                                if l.strip().startswith(("http://", "https://"))]
        self._log_phase("httpx", "ok" if self.web_targets else "error",
                        f"{len(self.web_targets)} live")

    def _probe_nmap(self, path):
        targets_file = os.path.join(self.output_dir, "subdomains.txt")
        ports = "80,443,8080,8443,8000,3000" if self.deep else "80,443,8080,8443"
        cmd = [path, "-iL", targets_file, "-p", ports, "--open", "-oG",
               os.path.join(self.output_dir, "nmap.gnmap")]
        stdout, _, code = self.run_command(cmd, "Nmap port scan", "nmap.txt")
        # Parse gnmap
        for line in stdout.splitlines():
            if "/open/" not in line:
                continue
            m = re.search(r"Host:\s+(\S+)\s+\(([^)]*)\)", line)
            if not m:
                continue
            ip, hostname = m.group(1), m.group(2)
            host = hostname if hostname else ip
            for port in re.findall(r"(\d+)/open/tcp", line):
                proto = "https" if port in ("443", "8443") else "http"
                self.web_targets.append(f"{proto}://{host}:{port}")
        self._log_phase("Nmap", "ok" if code == 0 else "error", f"{len(self.web_targets)} services")

    def _probe_curl(self):
        """Fallback: check http/https with curl for each subdomain."""
        if self.dry_run:
            self.web_targets = [f"https://{s}" for s in self.subdomains]
            self._log_phase("Probe (curl)", "ok", f"{len(self.web_targets)} assumed")
            return
        ports = [("https", 443), ("http", 80), ("http", 8080), ("http", 5000), ("http", 3000)]
        for sub in self.subdomains:
            for proto, port in ports:
                url = f"{proto}://{sub}:{port}" if port not in (80, 443) else f"{proto}://{sub}"
                try:
                    proc = subprocess.run(
                        ["curl", "-sIo", "/dev/null", "-w", "%{http_code}", "--max-time", "3", url],
                        capture_output=True, text=True, timeout=8,
                    )
                    if proc.stdout.strip() not in ("000", ""):
                        self.web_targets.append(url)
                except Exception:
                    continue
        self._log_phase("Probe (curl)", "ok", f"{len(self.web_targets)} live")

    def phase_fuzz(self):
        path = self._require("ffuf")
        if not path:
            self._log_phase("Ffuf", "skipped", "not installed")
            return
        if not DEFAULT_WORDLIST:
            console.print("[yellow][!] No wordlist found — skipping fuzzing.[/yellow]")
            self._log_phase("Ffuf", "skipped", "no wordlist")
            return
        if not self.web_targets:
            console.print("[yellow][!] No web targets — skipping fuzzing.[/yellow]")
            self._log_phase("Ffuf", "skipped", "no targets")
            return

        discovered = []
        for target in self.web_targets:
            safe_name = re.sub(r"[^\w]", "_", target)
            log_name = f"ffuf_{safe_name}.json"
            out_path = os.path.join(self.output_dir, log_name)
            cmd = [
                path, "-u", f"{target}/FUZZ", "-w", DEFAULT_WORDLIST,
                "-mc", "200,301,302,403", "-o", out_path,
                "-of", "json", "-s", "-t", "150",
            ]
            self.run_command(cmd, f"Ffuf → {target}")
            # Collect discovered URLs to feed into nuclei/sqlmap
            if not self.dry_run and os.path.isfile(out_path):
                try:
                    with open(out_path) as f:
                        data = json.load(f)
                    for r in data.get("results", []):
                        url = r.get("url", "")
                        if url and r.get("status") in (200, 301, 302):
                            discovered.append(url)
                except (json.JSONDecodeError, KeyError):
                    pass

        if discovered:
            self.web_targets.extend(discovered)
            self.web_targets = list(dict.fromkeys(self.web_targets))
            # Update targets file for nuclei
            with open(os.path.join(self.output_dir, "web_targets.txt"), "w") as f:
                f.write("\n".join(self.web_targets) + "\n")
            console.print(f"[green][✓][/green] Ffuf discovered {len(discovered)} paths → fed into nuclei/sqlmap.")
        self._log_phase("Ffuf", "ok", f"{len(discovered)} paths found")

    def phase_nuclei(self):
        path = self._require("nuclei")
        if not path:
            self._log_phase("Nuclei", "skipped", "not installed")
            return
        if not self.web_targets:
            console.print("[yellow][!] No web targets — skipping nuclei.[/yellow]")
            self._log_phase("Nuclei", "skipped", "no targets")
            return

        targets_file = os.path.join(self.output_dir, "web_targets.txt")
        with open(targets_file, "w") as f:
            f.write("\n".join(self.web_targets) + "\n")

        json_out = os.path.join(self.output_dir, "nuclei.json")
        cmd = [
            path, "-l", targets_file, "-jsonl", "-o", json_out,
            "-silent", "-no-color",
            "-c", "50",              # concurrent templates
            "-bs", "50",             # bulk size (hosts per template)
            "-rl", "300",            # max requests/sec
            "-timeout", "8",
        ]
        if self.deep:
            cmd.extend(["-severity", "info,low,medium,high,critical"])
        else:
            cmd.extend(["-severity", "medium,high,critical"])

        stdout, _, code = self.run_command(cmd, "Nuclei vulnerability scan", "nuclei_log.txt")

        # Parse JSON lines output
        if os.path.isfile(json_out):
            with open(json_out) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        finding = json.loads(line)
                        self.vulnerabilities.append({
                            "type": finding.get("info", {}).get("name", "Unknown"),
                            "severity": finding.get("info", {}).get("severity", "unknown"),
                            "url": finding.get("matched-at", finding.get("host", "")),
                            "template": finding.get("template-id", ""),
                            "status": "VULNERABLE",
                        })
                    except json.JSONDecodeError:
                        continue

        self._log_phase("Nuclei", "ok" if code == 0 else "error",
                        f"{len(self.vulnerabilities)} findings")

    def phase_sqli(self):
        path = self._require("sqlmap")
        if not path:
            self._log_phase("SQLMap", "skipped", "not installed")
            return
        if not self.web_targets:
            self._log_phase("SQLMap", "skipped", "no targets")
            return

        for target in self.web_targets:
            safe = re.sub(r"[^\w]", "_", target)
            cmd = [
                sys.executable, path, "-u", target,
                "--batch", "--crawl", "3" if self.deep else "1",
                "--random-agent", "--forms",
            ]
            if self.deep:
                cmd.extend(["--level", "3", "--risk", "2"])
            stdout, _, _ = self.run_command(cmd, f"SQLMap → {target}", f"sqlmap_{safe}.txt")
            if "is vulnerable" in stdout.lower():
                self.vulnerabilities.append({
                    "type": "SQL Injection",
                    "severity": "critical",
                    "url": target,
                    "template": "sqlmap",
                    "status": "VULNERABLE",
                })

        self._log_phase("SQLMap", "ok", f"tested {len(self.web_targets)} targets")

    # -- built-in scanners (no external tools) -----------------------------

    def phase_crawl(self):
        """Crawl all web targets to discover pages, forms, params."""
        if self.dry_run:
            self._log_phase("Crawler", "skipped", "dry-run")
            return
        if not self.web_targets:
            self._log_phase("Crawler", "skipped", "no targets")
            return
        all_pages, all_forms, all_params, all_links = [], [], {}, set()
        max_pages = 100 if self.deep else 50
        # Crawl from each base target
        base_targets = [t for t in self.web_targets if t.count("/") <= 3]
        for target in base_targets or self.web_targets[:3]:
            console.print(f"[bold blue][+][/bold blue] Crawling {target}...")
            data = crawl(target, max_pages=max_pages)
            all_pages.extend(data["pages"])
            all_forms.extend(data["forms"])
            all_params.update(data["params"])
            all_links.update(data["links"])
        # Also add ffuf-discovered URLs as pages so scanners can test them
        crawled_urls = {p["url"].split("?")[0] for p in all_pages}
        for target in self.web_targets:
            base = target.split("?")[0]
            if base not in crawled_urls:
                all_pages.append({"url": target, "status": 200, "length": 0})
        self.crawl_data = {
            "pages": all_pages, "forms": all_forms,
            "params": all_params, "links": list(all_links),
        }
        with open(os.path.join(self.output_dir, "crawl.json"), "w") as f:
            json.dump(self.crawl_data, f, indent=2)
        console.print(f"[green][✓][/green] Crawled {len(all_pages)} pages, "
                       f"{len(all_forms)} forms, {len(all_params)} parameterized URLs.")
        self._log_phase("Crawler", "ok",
                        f"{len(all_pages)} pages, {len(all_forms)} forms")

    def phase_fingerprint(self):
        """Detect technologies and WAF."""
        if self.dry_run:
            self._log_phase("Fingerprint", "skipped", "dry-run")
            return
        for target in self.web_targets:
            self.technologies.extend(fingerprint(target))
            self.waf_detected.extend(detect_waf(target))
        self.technologies = list(set(self.technologies))
        self.waf_detected = list(set(self.waf_detected))
        if self.technologies:
            console.print(f"[green][✓][/green] Tech: {', '.join(self.technologies)}")
        if self.waf_detected:
            console.print(f"[yellow][!] WAF detected: {', '.join(self.waf_detected)}[/yellow]")
        self._log_phase("Fingerprint", "ok",
                        f"{len(self.technologies)} tech, {len(self.waf_detected)} WAF")

    def phase_headers(self):
        """Check security headers on all targets."""
        if self.dry_run:
            self._log_phase("Headers", "skipped", "dry-run")
            return
        for target in self.web_targets:
            findings = scan_headers(target)
            self.vulnerabilities.extend(
                {**f, "status": "VULNERABLE"} for f in findings)
        count = sum(1 for f in self.vulnerabilities if f["template"] == "apex-headers")
        self._log_phase("Headers", "ok", f"{count} issues")

    def phase_sensitive_files(self):
        """Scan for sensitive files and directories."""
        if self.dry_run:
            self._log_phase("Sensitive Files", "skipped", "dry-run")
            return
        for target in self.web_targets:
            console.print(f"[bold blue][+][/bold blue] Scanning sensitive files on {target}...")
            findings = scan_sensitive_files(target)
            self.vulnerabilities.extend(
                {**f, "status": "VULNERABLE"} for f in findings)
        count = sum(1 for f in self.vulnerabilities if f["template"] == "apex-sensitive")
        self._log_phase("Sensitive Files", "ok", f"{count} found")

    def phase_xss(self):
        """Scan for reflected XSS."""
        if self.dry_run or not self.crawl_data:
            self._log_phase("XSS", "skipped", "dry-run" if self.dry_run else "no crawl data")
            return
        console.print("[bold blue][+][/bold blue] Testing for reflected XSS...")
        findings = scan_xss(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)
        self._log_phase("XSS", "ok", f"{len(findings)} found")

    def phase_cmdi(self):
        """Scan for command injection."""
        if self.dry_run or not self.crawl_data:
            self._log_phase("CMDi", "skipped", "dry-run" if self.dry_run else "no crawl data")
            return
        console.print("[bold blue][+][/bold blue] Testing for command injection...")
        findings = scan_cmdi(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)
        self._log_phase("CMDi", "ok", f"{len(findings)} found")

    def phase_idor(self):
        """Scan for IDOR."""
        if self.dry_run or not self.crawl_data:
            self._log_phase("IDOR", "skipped", "dry-run" if self.dry_run else "no crawl data")
            return
        console.print("[bold blue][+][/bold blue] Testing for IDOR...")
        findings = scan_idor(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)
        self._log_phase("IDOR", "ok", f"{len(findings)} found")

    def phase_redirect(self):
        """Scan for open redirects."""
        if self.dry_run or not self.crawl_data:
            self._log_phase("Open Redirect", "skipped",
                            "dry-run" if self.dry_run else "no crawl data")
            return
        console.print("[bold blue][+][/bold blue] Testing for open redirects...")
        findings = scan_open_redirect(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)
        self._log_phase("Open Redirect", "ok", f"{len(findings)} found")

    # -- reporting ---------------------------------------------------------

    def report_terminal(self):
        console.print()
        console.print(Panel("[bold green]Scan Complete[/bold green]", expand=False))

        # Phase summary
        pt = Table(title="Phase Summary")
        pt.add_column("Phase", style="cyan")
        pt.add_column("Status", style="green")
        pt.add_column("Detail")
        for p in self.phase_results:
            st = p["status"]
            style = "red" if st == "error" else ("yellow" if st == "skipped" else "green")
            pt.add_row(p["phase"], f"[{style}]{st}[/{style}]", p["detail"])
        console.print(pt)

        # Tech & WAF
        if self.technologies:
            console.print(f"\n[bold cyan]Technologies:[/bold cyan] {', '.join(self.technologies)}")
        if self.waf_detected:
            console.print(f"[bold yellow]WAF:[/bold yellow] {', '.join(self.waf_detected)}")

        # Vulnerabilities
        if not self.vulnerabilities:
            console.print("[bold yellow][!] No vulnerabilities found.[/bold yellow]")
        else:
            vt = Table(title=f"Vulnerabilities ({len(self.vulnerabilities)})")
            vt.add_column("Severity", style="red")
            vt.add_column("Type", style="cyan")
            vt.add_column("URL", style="magenta")
            for v in self.vulnerabilities:
                sev = v.get("severity", "unknown").upper()
                sev_style = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow",
                             "LOW": "blue"}.get(sev, "white")
                vt.add_row(f"[{sev_style}]{sev}[/{sev_style}]", v["type"], v["url"])
            console.print(vt)

        console.print(f"\n[bold blue]Logs:[/bold blue] {self.output_dir}/")

    def report_json(self):
        data = {
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "technologies": self.technologies,
            "waf": self.waf_detected,
            "subdomains": self.subdomains,
            "web_targets": self.web_targets,
            "phases": self.phase_results,
            "vulnerabilities": self.vulnerabilities,
        }
        out = os.path.join(self.output_dir, "report.json")
        with open(out, "w") as f:
            json.dump(data, f, indent=2)
        console.print(f"[green][✓][/green] JSON report → {out}")

    def report_html(self):
        template_path = Path(__file__).parent / "report_template.html"
        if not template_path.is_file():
            console.print("[yellow][!] report_template.html not found — skipping HTML report.[/yellow]")
            return
        tmpl = Template(template_path.read_text())
        html = tmpl.render(
            target=self.target,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            technologies=self.technologies,
            waf=self.waf_detected,
            subdomains=self.subdomains,
            web_targets=self.web_targets,
            phases=self.phase_results,
            vulnerabilities=self.vulnerabilities,
        )
        out = os.path.join(self.output_dir, "report.html")
        with open(out, "w") as f:
            f.write(html)
        console.print(f"[green][✓][/green] HTML report → {out}")

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

SKULL_ASCII = r"""[bold red]
                     ______
                  .-"      "-.
                 /            \
                |              |
                |,  .-.  .-.  ,|
                | )(__/  \__)( |
                |/     /\     \|
                (_     ^^     _)
                 \__|IIIIII|__/
                  | \IIIIII/ |
                  \          /
                   `--------`
[/bold red][bold white]
                 A P E X  C L I
[/bold white]"""


def show_banner():
    console.print(SKULL_ASCII, justify="center")
    console.print(Panel.fit(
        "[bold white]Apex CLI v3.0[/bold white]\n"
        "[dim]Automated Pen-Test Orchestrator[/dim]",
        border_style="red",
    ), justify="center")


def show_tools():
    """Print which tools are available."""
    table = Table(title="Tool Status")
    table.add_column("Tool")
    table.add_column("Status")
    table.add_column("Path")
    for name, path in TOOLS.items():
        if path:
            table.add_row(name, "[green]found[/green]", path)
        else:
            table.add_row(name, "[red]missing[/red]", "—")
    wl = DEFAULT_WORDLIST or "[red]none found[/red]"
    table.add_row("wordlist", "[green]found[/green]" if DEFAULT_WORDLIST else "[red]missing[/red]", wl or "—")
    console.print(table)


def run_scan(target, dry_run=False, deep=False, report_formats=None, skip=None):
    report_formats = report_formats or ["terminal"]
    skip = [s.lower() for s in (skip or [])]
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = f"scan_{target}_{ts}"
    apex = ApexCLI(target, output_dir, dry_run=dry_run, deep=deep)

    phases = [
        ("Recon", apex.phase_recon),
        ("Probe", apex.phase_probe),
        ("Fingerprint", apex.phase_fingerprint),
        ("Fuzz", apex.phase_fuzz),
        ("Crawl", apex.phase_crawl),
        ("Headers", apex.phase_headers),
        ("Sensitive Files", apex.phase_sensitive_files),
        ("Nuclei", apex.phase_nuclei),
        ("SQLi", apex.phase_sqli),
        ("XSS", apex.phase_xss),
        ("CMDi", apex.phase_cmdi),
        ("IDOR", apex.phase_idor),
        ("Open Redirect", apex.phase_redirect),
    ]

    with Progress(
        SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
        BarColumn(), TimeElapsedColumn(), console=console,
    ) as progress:
        for label, fn in phases:
            if label.lower() in skip:
                apex._log_phase(label, "skipped", "user --skip")
                continue
            task = progress.add_task(f"[cyan]{label}...", total=1)
            try:
                fn()
            except Exception as e:
                console.print(f"[red][!] {label} failed: {e}[/red]")
                apex._log_phase(label, "error", str(e))
            progress.update(task, completed=1)

    # Reports
    apex.report_terminal()
    if "json" in report_formats:
        apex.report_json()
    if "html" in report_formats:
        apex.report_html()
    # Always save JSON for records
    apex.report_json()


def main():
    parser = argparse.ArgumentParser(
        prog="apex-cli",
        description="Apex CLI v3.0 — Automated Pen-Test Orchestrator",
    )
    parser.add_argument("target", nargs="?", help="Target domain or IP (e.g. example.com)")
    parser.add_argument("--dry-run", action="store_true", help="Preview commands without executing")
    parser.add_argument("--deep", action="store_true", help="Deep scan: more tools, higher intensity")
    parser.add_argument("--report", nargs="+", choices=["terminal", "json", "html"],
                        default=["terminal"], help="Report formats (default: terminal)")
    parser.add_argument("--tools", action="store_true", help="Show available tools and exit")
    parser.add_argument("--skip", nargs="+", default=[],
                        help="Skip phases (e.g. --skip nuclei sqli)")

    args = parser.parse_args()

    show_banner()

    if args.tools:
        show_tools()
        sys.exit(0)

    if not args.target:
        target = console.input("[bold cyan]Enter target domain/IP: [/bold cyan]").strip()
    else:
        target = args.target

    target = validate_target(target)
    console.print(f"[bold white]Target:[/bold white] {target}")
    console.print(f"[bold white]Mode:[/bold white] {'deep' if args.deep else 'standard'} | "
                  f"{'DRY RUN' if args.dry_run else 'LIVE'}")
    console.print()

    run_scan(target, dry_run=args.dry_run, deep=args.deep,
            report_formats=args.report, skip=args.skip)


if __name__ == "__main__":
    main()
