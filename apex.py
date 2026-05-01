#!/usr/bin/env python3
"""Apex CLI v5.0 — Automated Pen-Test Orchestrator."""

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
    _extract_from_js,
    _test_idor,
    _test_redirect,
    _test_redirect_form,
    ajax_spider,
    authenticated_scan,
    crawl,
    detect_waf,
    extract_js_endpoints,
    fingerprint,
    get_cert_transparency_subdomains,
    scan_2fa_bypass,
    scan_403_bypass,
    scan_account_enumeration,
    scan_api_fuzzing,
    scan_api_keys_in_js,
    scan_auth_bypass,
    scan_billion_laughs,
    scan_broken_auth,
    scan_business_logic,
    scan_cache_poisoning,
    scan_clickjacking,
    scan_client_side_template_injection,
    scan_cloud_metadata_variants,
    scan_cloud_storage,
    scan_cmdi,
    scan_cookie_security,
    scan_cors,
    scan_crlf_injection,
    scan_csp_analysis,
    scan_csrf,
    scan_css_injection,
    scan_dangling_markup,
    scan_deep_sqli,
    scan_deep_xss,
    scan_devops_exposure,
    scan_dns_zone_transfer,
    scan_email_injection,
    scan_etag_tracking,
    scan_file_upload,
    scan_firebase_misconfig,
    scan_graphql,
    scan_graphql_advanced,
    scan_headers,
    scan_hop_by_hop,
    scan_host_header_injection,
    scan_hsts,
    scan_http2_attacks,
    scan_http_verb_tampering,
    scan_idor,
    scan_info_disclosure,
    scan_insecure_deserialization,
    scan_ip_header_spoofing,
    scan_jwt_issues,
    scan_log4shell,
    scan_log_injection,
    scan_mass_assignment,
    scan_mime_sniffing,
    scan_nosql_injection,
    scan_null_byte,
    scan_oauth_issues,
    scan_open_ports_web,
    scan_open_redirect,
    scan_origin_reflection,
    scan_param_bruteforce,
    scan_password_reset_poisoning,
    scan_path_traversal,
    scan_permissions_policy,
    scan_postmessage_abuse,
    scan_prototype_pollution,
    scan_range_amplification,
    scan_rate_limit,
    scan_redos,
    scan_request_smuggling,
    scan_rfi,
    scan_robots_sitemap,
    scan_s3_buckets,
    scan_sensitive_files,
    scan_session_weakness,
    scan_shellshock,
    scan_smart,
    scan_source_map_exposure,
    scan_spring4shell,
    scan_ssi_injection,
    scan_ssrf,
    scan_ssrf_via_upload,
    scan_ssti,
    scan_staging_exposure,
    scan_subdomain_takeover,
    scan_svg_xss,
    scan_time_based_sqli,
    scan_tls_info,
    scan_token_race_conditions,
    scan_trace_options,
    scan_user_agent_fuzzing,
    scan_wayback,
    scan_websocket,
    scan_websocket_injection,
    scan_with_browser,
    scan_workflow_bypass,
    scan_xpath_injection,
    scan_xslt_injection,
    scan_xss,
    scan_xxe,
    # Elite scanners
    scan_jwt_alg_confusion,
    scan_blind_xss,
    scan_http_parameter_pollution,
    scan_web_cache_deception,
    scan_jsonp_injection,
    scan_dependency_confusion,
    scan_graphql_depth_attack,
    scan_path_normalization_bypass,
    scan_nginx_off_by_slash,
    scan_second_order_injection,
    scan_cors_preflight_bypass,
    scan_prototype_pollution_json,
    scan_account_takeover_response_manipulation,
    scan_api_mass_exposure,
    scan_oauth_token_leakage,
    scan_blind_sqli_oob,
    scan_idor_uuid_prediction,
    scan_http2_rapid_reset,
    scan_saml_injection,
    scan_dns_rebinding_ssrf,
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
    def __init__(self, target, output_dir, dry_run=False, deep=False, auth=None):
        self.target = target
        self.output_dir = output_dir
        self.dry_run = dry_run
        self.deep = deep
        self.auth = auth
        self.oob = None
        self.subdomains: list[str] = []
        self.web_targets: list[str] = []
        self.vulnerabilities: list[dict] = []
        self.phase_results: list[dict] = []
        self.crawl_data: dict = {}
        self.technologies: list[str] = []
        self.waf_detected: list[str] = []
        self._vuln_lock = __import__("threading").Lock()
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
        # Always add cert transparency subdomains
        try:
            ct_subs = get_cert_transparency_subdomains(self.target)
            self.subdomains.extend(ct_subs)
            if ct_subs:
                console.print(f"[green][✓][/green] Cert transparency: {len(ct_subs)} subdomains")
        except Exception:
            pass
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
        self.web_targets = prioritize_targets(self.web_targets, self.technologies)
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
                "-of", "json", "-s", "-t", "300",
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
            "-c", "100",             # concurrent templates
            "-bs", "100",            # bulk size (hosts per template)
            "-rl", "1000",           # max requests/sec
            "-timeout", "5",
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
                path, "-u", target,
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
        """Crawl all web targets — use AJAX spider if Playwright available."""
        if self.dry_run:
            self._log_phase("Crawler", "skipped", "dry-run")
            return
        if not self.web_targets:
            self._log_phase("Crawler", "skipped", "no targets")
            return

        # Try AJAX spider first (finds JS-rendered content like ZAP)
        try:
            from playwright.sync_api import sync_playwright
            console.print("[bold blue][+][/bold blue] AJAX spider (headless browser crawl)...")
            base_targets = [t for t in self.web_targets if t.count("/") <= 3]
            for target in (base_targets or self.web_targets)[:2]:
                data = ajax_spider(target, max_pages=50 if self.deep else 25)
                self.crawl_data["pages"] = self.crawl_data.get("pages", []) + data["pages"]
                self.crawl_data["forms"] = self.crawl_data.get("forms", []) + data["forms"]
                self.crawl_data.setdefault("params", {}).update(data["params"])
                self.crawl_data.setdefault("links", []).extend(data["links"])
                # Add API calls discovered by browser as pages
                for call in data.get("api_calls", []):
                    self.crawl_data["pages"].append({"url": call["url"], "status": 200, "length": 0})
            console.print(f"[green][✓][/green] AJAX spider: {len(self.crawl_data.get('pages',[]))} pages, "
                          f"{len(self.crawl_data.get('forms',[]))} forms")
            self._log_phase("AJAX Spider", "ok", f"{len(self.crawl_data.get('pages',[]))} pages")
            return
        except ImportError:
            pass  # Fall back to basic crawler
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

    def phase_ssrf(self):
        if self.dry_run or not self.crawl_data: return
        console.print("[bold blue][+][/bold blue] Testing for SSRF...")
        findings = scan_ssrf(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)
        self._log_phase("SSRF", "ok", f"{len(findings)} found")

    def phase_ssti(self):
        if self.dry_run or not self.crawl_data: return
        console.print("[bold blue][+][/bold blue] Testing for SSTI...")
        findings = scan_ssti(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)
        self._log_phase("SSTI", "ok", f"{len(findings)} found")

    def phase_lfi(self):
        if self.dry_run or not self.crawl_data: return
        console.print("[bold blue][+][/bold blue] Testing for path traversal/LFI...")
        findings = scan_path_traversal(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)
        self._log_phase("LFI", "ok", f"{len(findings)} found")

    def phase_broken_auth(self):
        if self.dry_run or not self.crawl_data: return
        console.print("[bold blue][+][/bold blue] Testing for broken auth...")
        findings = scan_broken_auth(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)
        self._log_phase("Broken Auth", "ok", f"{len(findings)} found")

    def phase_cors(self):
        if self.dry_run or not self.crawl_data: return
        console.print("[bold blue][+][/bold blue] Testing for CORS misconfig...")
        findings = scan_cors(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)
        self._log_phase("CORS", "ok", f"{len(findings)} found")

    def phase_graphql(self):
        if self.dry_run or not self.crawl_data: return
        console.print("[bold blue][+][/bold blue] Testing GraphQL endpoints...")
        findings = scan_graphql(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_rate_limit(self):
        if self.dry_run or not self.crawl_data: return
        console.print("[bold blue][+][/bold blue] Testing rate limiting...")
        findings = scan_rate_limit(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_info_disclosure(self):
        if self.dry_run or not self.crawl_data: return
        console.print("[bold blue][+][/bold blue] Testing for info disclosure...")
        findings = scan_info_disclosure(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_js_endpoints(self):
        if self.dry_run or not self.crawl_data: return
        console.print("[bold blue][+][/bold blue] Extracting hidden API endpoints from JS...")
        findings = extract_js_endpoints(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_wayback(self):
        if self.dry_run: return
        console.print(f"[bold blue][+][/bold blue] Wayback Machine recon on {self.target}...")
        findings = scan_wayback(self.target)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)
        self._log_phase("Wayback", "ok", f"{len(findings)} found")

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
            vt.add_column("Score", style="red")
            vt.add_column("Severity", style="red")
            vt.add_column("Type", style="cyan")
            vt.add_column("Exploitability")
            vt.add_column("URL", style="magenta")
            for v in self.vulnerabilities:
                sev = v.get("severity", "unknown").upper()
                sev_style = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow",
                             "LOW": "blue"}.get(sev, "white")
                score = str(v.get("cvss_score", ""))
                expl = v.get("exploitability", "")
                vt.add_row(score, f"[{sev_style}]{sev}[/{sev_style}]", v["type"], expl, v["url"][:60])
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

    def phase_path_traversal(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_path_traversal(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_prototype_pollution(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_prototype_pollution(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_host_header_injection(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_host_header_injection(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_crlf_injection(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_crlf_injection(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_jwt_issues(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_jwt_issues(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_subdomain_takeover(self):
        if self.dry_run: return
        findings = scan_subdomain_takeover(self.subdomains)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_api_keys_in_js(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_api_keys_in_js(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_websocket(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_websocket(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_param_bruteforce(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_param_bruteforce(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_oauth_issues(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_oauth_issues(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_xxe(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_xxe(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_business_logic(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_business_logic(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_cache_poisoning(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_cache_poisoning(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_smart(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_smart(self.crawl_data, self.technologies, self.web_targets)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_s3_buckets(self):
        if self.dry_run: return
        findings = scan_s3_buckets(self.target, self.subdomains)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_request_smuggling(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_request_smuggling(self.web_targets)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_email_injection(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_email_injection(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_open_ports_web(self):
        if self.dry_run: return
        findings = scan_open_ports_web(self.subdomains)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_dns_zone_transfer(self):
        if self.dry_run: return
        findings = scan_dns_zone_transfer(self.target)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_api_fuzzing(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_api_fuzzing(self.web_targets)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_2fa_bypass(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_2fa_bypass(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_insecure_deserialization(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_insecure_deserialization(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_nosql_injection(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_nosql_injection(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_mass_assignment(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_mass_assignment(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_file_upload(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_file_upload(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_csrf(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_csrf(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_clickjacking(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_clickjacking(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_cookie_security(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_cookie_security(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_account_enumeration(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_account_enumeration(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_password_reset_poisoning(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_password_reset_poisoning(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_http_verb_tampering(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_http_verb_tampering(self.web_targets)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_log_injection(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_log_injection(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_source_map_exposure(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_source_map_exposure(self.web_targets)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_redos(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_redos(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_hsts(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_hsts(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_dangling_markup(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_dangling_markup(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_css_injection(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_css_injection(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_postmessage_abuse(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_postmessage_abuse(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_mime_sniffing(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_mime_sniffing(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_null_byte(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_null_byte(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_ssrf_via_upload(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_ssrf_via_upload(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_ip_header_spoofing(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_ip_header_spoofing(self.web_targets)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_hop_by_hop(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_hop_by_hop(self.web_targets)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_robots_sitemap(self):
        if self.dry_run: return
        findings = scan_robots_sitemap(self.target)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_staging_exposure(self):
        if self.dry_run: return
        findings = scan_staging_exposure(self.target, self.subdomains)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_cloud_metadata_variants(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_cloud_metadata_variants(self.web_targets)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_origin_reflection(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_origin_reflection(self.web_targets)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_time_based_sqli(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_time_based_sqli(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_rfi(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_rfi(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_ssi_injection(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_ssi_injection(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_shellshock(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_shellshock(self.web_targets)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_log4shell(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_log4shell(self.web_targets)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_spring4shell(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_spring4shell(self.web_targets)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_xslt_injection(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_xslt_injection(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_xpath_injection(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_xpath_injection(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_user_agent_fuzzing(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_user_agent_fuzzing(self.web_targets)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_billion_laughs(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_billion_laughs(self.web_targets)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_with_browser(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_with_browser(self.target, self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_deep_sqli(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_deep_sqli(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_deep_xss(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_deep_xss(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_auth_bypass(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_auth_bypass(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_http2_attacks(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_http2_attacks(self.web_targets)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_trace_options(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_trace_options(self.web_targets)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_range_amplification(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_range_amplification(self.web_targets)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_etag_tracking(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_etag_tracking(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_token_race_conditions(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_token_race_conditions(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_tls_info(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_tls_info(self.web_targets)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_client_side_template_injection(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_client_side_template_injection(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_svg_xss(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_svg_xss(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_csp_analysis(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_csp_analysis(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_firebase_misconfig(self):
        if self.dry_run: return
        findings = scan_firebase_misconfig(self.target)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_devops_exposure(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_devops_exposure(self.web_targets)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_cloud_storage(self):
        if self.dry_run: return
        findings = scan_cloud_storage(self.target)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_graphql_advanced(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_graphql_advanced(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_websocket_injection(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_websocket_injection(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_session_weakness(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_session_weakness(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_permissions_policy(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_permissions_policy(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_workflow_bypass(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_workflow_bypass(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    # -- elite phase methods -----------------------------------------------

    def phase_jwt_alg_confusion(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_jwt_alg_confusion(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_blind_xss(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_blind_xss(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_http_parameter_pollution(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_http_parameter_pollution(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_web_cache_deception(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_web_cache_deception(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_jsonp_injection(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_jsonp_injection(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_dependency_confusion(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_dependency_confusion(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_graphql_depth_attack(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_graphql_depth_attack(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_path_normalization_bypass(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_path_normalization_bypass(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_nginx_off_by_slash(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_nginx_off_by_slash(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_second_order_injection(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_second_order_injection(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_cors_preflight_bypass(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_cors_preflight_bypass(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_prototype_pollution_json(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_prototype_pollution_json(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_account_takeover_response_manipulation(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_account_takeover_response_manipulation(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_api_mass_exposure(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_api_mass_exposure(self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_oauth_token_leakage(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_oauth_token_leakage(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_blind_sqli_oob(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_blind_sqli_oob(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_idor_uuid_prediction(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_idor_uuid_prediction(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_http2_rapid_reset(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_http2_rapid_reset(self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_saml_injection(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_saml_injection(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_dns_rebinding_ssrf(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_dns_rebinding_ssrf(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    # -- OOB phases --------------------------------------------------------

    def phase_oob_ssrf(self):
        if self.dry_run or not self.crawl_data or not self.oob: return
        findings = scan_blind_ssrf_oob(self.crawl_data, self.oob)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_oob_cmdi(self):
        if self.dry_run or not self.crawl_data or not self.oob: return
        findings = scan_blind_cmdi_oob(self.crawl_data, self.oob)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_oob_sqli(self):
        if self.dry_run or not self.crawl_data or not self.oob: return
        findings = scan_blind_sqli_oob_confirmed(self.crawl_data, self.oob)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    # -- context-aware phases ----------------------------------------------

    def phase_context_xss(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_context_aware_xss(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_context_sqli(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_context_aware_sqli(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    # -- authenticated scan phase ------------------------------------------

    def phase_authenticated(self):
        if self.dry_run or not self.auth or not self.web_targets: return
        username, password = self.auth
        console.print(f"[bold blue][+][/bold blue] Authenticated scan as {username}...")
        for target in self.web_targets[:3]:
            findings = authenticated_scan(target, username, password, self.crawl_data)
            with self._vuln_lock:
                self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)
        self._log_phase("Authenticated Scan", "ok", f"as {username}")

    # -- elite phase methods -----------------------------------------------

    def phase_jwt_alg_confusion(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_jwt_alg_confusion(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_blind_xss(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_blind_xss(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_http_parameter_pollution(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_http_parameter_pollution(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_web_cache_deception(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_web_cache_deception(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_jsonp_injection(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_jsonp_injection(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_dependency_confusion(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_dependency_confusion(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_graphql_depth_attack(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_graphql_depth_attack(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_path_normalization_bypass(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_path_normalization_bypass(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_nginx_off_by_slash(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_nginx_off_by_slash(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_second_order_injection(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_second_order_injection(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_cors_preflight_bypass(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_cors_preflight_bypass(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_prototype_pollution_json(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_prototype_pollution_json(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_account_takeover_response_manipulation(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_account_takeover_response_manipulation(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_api_mass_exposure(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_api_mass_exposure(self.web_targets)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_oauth_token_leakage(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_oauth_token_leakage(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_blind_sqli_oob(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_blind_sqli_oob(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_idor_uuid_prediction(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_idor_uuid_prediction(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_http2_rapid_reset(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_http2_rapid_reset(self.web_targets)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_saml_injection(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_saml_injection(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_dns_rebinding_ssrf(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_dns_rebinding_ssrf(self.crawl_data)
        self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)


    def phase_subdomain_bruteforce(self):
        if self.dry_run: return
        _, found = scan_subdomain_bruteforce(self.target)
        self.subdomains = list(dict.fromkeys(self.subdomains + found))
        self._log_phase("Subdomain Brute-Force", "ok", f"{len(found)} found")

    def phase_response_diff_auth_bypass(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_response_diff_auth_bypass(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_nextjs_react_vulns(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_nextjs_react_vulns(self.crawl_data, self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_graphql_mutation_fuzzing(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_graphql_mutation_fuzzing(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_te_cl_smuggling(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_te_cl_smuggling(self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_idor_pagination(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_idor_pagination(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_race_condition_registration(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_race_condition_registration(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_timing_user_enumeration(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_timing_user_enumeration(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_css_exfil(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_css_exfil(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_open_redirect_oauth_chain(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_open_redirect_oauth_chain(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_ssrf_pdf_generation(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_ssrf_pdf_generation(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_ns_takeover(self):
        if self.dry_run or not self.subdomains: return
        findings = scan_ns_takeover(self.target, self.subdomains)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)


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
        "[bold white]Apex CLI v5.0[/bold white]\n"
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


def run_scan(target, dry_run=False, deep=False, report_formats=None, skip=None, auth=None):
    report_formats = report_formats or ["terminal"]
    skip = [s.lower() for s in (skip or [])]
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = f"scan_{target}_{ts}"
    apex = ApexCLI(target, output_dir, dry_run=dry_run, deep=deep, auth=auth)

    # Start OOB server
    if not dry_run:
        console.print("[dim]Starting OOB server (interactsh)...[/dim]")
        apex.oob = oob_start()
        if apex.oob:
            console.print(f"[green][✓][/green] OOB active: {apex.oob.domain}")
        else:
            console.print("[yellow][!] OOB unavailable — blind vulns won't be confirmed[/yellow]")

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
        ("SSRF", apex.phase_ssrf),
        ("SSTI", apex.phase_ssti),
        ("LFI", apex.phase_lfi),
        ("Broken Auth", apex.phase_broken_auth),
        ("CORS", apex.phase_cors),
        ("GraphQL", apex.phase_graphql),
        ("Rate Limit", apex.phase_rate_limit),
        ("Info Disclosure", apex.phase_info_disclosure),
        ("JS Endpoints", apex.phase_js_endpoints),
        ("Wayback Recon", apex.phase_wayback),
        ("Path Traversal", apex.phase_path_traversal),
        ("Prototype Pollution", apex.phase_prototype_pollution),
        ("Host Header Injection", apex.phase_host_header_injection),
        ("Crlf Injection", apex.phase_crlf_injection),
        ("Jwt Issues", apex.phase_jwt_issues),
        ("Subdomain Takeover", apex.phase_subdomain_takeover),
        ("Api Keys In Js", apex.phase_api_keys_in_js),
        ("Websocket", apex.phase_websocket),
        ("Param Bruteforce", apex.phase_param_bruteforce),
        ("Oauth Issues", apex.phase_oauth_issues),
        ("Xxe", apex.phase_xxe),
        ("Business Logic", apex.phase_business_logic),
        ("Cache Poisoning", apex.phase_cache_poisoning),
        ("Smart", apex.phase_smart),
        ("S3 Buckets", apex.phase_s3_buckets),
        ("Request Smuggling", apex.phase_request_smuggling),
        ("Email Injection", apex.phase_email_injection),
        ("Open Ports Web", apex.phase_open_ports_web),
        ("Dns Zone Transfer", apex.phase_dns_zone_transfer),
        ("Api Fuzzing", apex.phase_api_fuzzing),
        ("2Fa Bypass", apex.phase_2fa_bypass),
        ("Insecure Deserialization", apex.phase_insecure_deserialization),
        ("Nosql Injection", apex.phase_nosql_injection),
        ("Mass Assignment", apex.phase_mass_assignment),
        ("File Upload", apex.phase_file_upload),
        ("Csrf", apex.phase_csrf),
        ("Clickjacking", apex.phase_clickjacking),
        ("Cookie Security", apex.phase_cookie_security),
        ("Account Enumeration", apex.phase_account_enumeration),
        ("Password Reset Poisoning", apex.phase_password_reset_poisoning),
        ("Http Verb Tampering", apex.phase_http_verb_tampering),
        ("Log Injection", apex.phase_log_injection),
        ("Source Map Exposure", apex.phase_source_map_exposure),
        ("Redos", apex.phase_redos),
        ("Hsts", apex.phase_hsts),
        ("Dangling Markup", apex.phase_dangling_markup),
        ("Css Injection", apex.phase_css_injection),
        ("Postmessage Abuse", apex.phase_postmessage_abuse),
        ("Mime Sniffing", apex.phase_mime_sniffing),
        ("Null Byte", apex.phase_null_byte),
        ("Ssrf Via Upload", apex.phase_ssrf_via_upload),
        ("Ip Header Spoofing", apex.phase_ip_header_spoofing),
        ("Hop By Hop", apex.phase_hop_by_hop),
        ("Robots Sitemap", apex.phase_robots_sitemap),
        ("Staging Exposure", apex.phase_staging_exposure),
        ("Cloud Metadata Variants", apex.phase_cloud_metadata_variants),
        ("Origin Reflection", apex.phase_origin_reflection),
        ("Time Based Sqli", apex.phase_time_based_sqli),
        ("Rfi", apex.phase_rfi),
        ("Ssi Injection", apex.phase_ssi_injection),
        ("Shellshock", apex.phase_shellshock),
        ("Log4Shell", apex.phase_log4shell),
        ("Spring4Shell", apex.phase_spring4shell),
        ("Xslt Injection", apex.phase_xslt_injection),
        ("Xpath Injection", apex.phase_xpath_injection),
        ("User Agent Fuzzing", apex.phase_user_agent_fuzzing),
        ("Billion Laughs", apex.phase_billion_laughs),
        ("With Browser", apex.phase_with_browser),
        ("Deep Sqli", apex.phase_deep_sqli),
        ("Deep Xss", apex.phase_deep_xss),
        ("Auth Bypass", apex.phase_auth_bypass),
        ("Http2 Attacks", apex.phase_http2_attacks),
        ("Trace Options", apex.phase_trace_options),
        ("Range Amplification", apex.phase_range_amplification),
        ("Etag Tracking", apex.phase_etag_tracking),
        ("Token Race Conditions", apex.phase_token_race_conditions),
        ("Tls Info", apex.phase_tls_info),
        ("Client Side Template Injection", apex.phase_client_side_template_injection),
        ("Svg Xss", apex.phase_svg_xss),
        ("Csp Analysis", apex.phase_csp_analysis),
        ("Firebase Misconfig", apex.phase_firebase_misconfig),
        ("Devops Exposure", apex.phase_devops_exposure),
        ("Cloud Storage", apex.phase_cloud_storage),
        ("Graphql Advanced", apex.phase_graphql_advanced),
        ("Websocket Injection", apex.phase_websocket_injection),
        ("Session Weakness", apex.phase_session_weakness),
        ("Permissions Policy", apex.phase_permissions_policy),
        ("Workflow Bypass", apex.phase_workflow_bypass),
        # Elite phases
        ("JWT Alg Confusion", apex.phase_jwt_alg_confusion),
        ("Blind XSS", apex.phase_blind_xss),
        ("HTTP Param Pollution", apex.phase_http_parameter_pollution),
        ("Web Cache Deception", apex.phase_web_cache_deception),
        ("JSONP Injection", apex.phase_jsonp_injection),
        ("Dependency Confusion", apex.phase_dependency_confusion),
        ("GraphQL Depth Attack", apex.phase_graphql_depth_attack),
        ("Path Normalization Bypass", apex.phase_path_normalization_bypass),
        ("Nginx Off-by-Slash", apex.phase_nginx_off_by_slash),
        ("Second-Order Injection", apex.phase_second_order_injection),
        ("CORS Preflight Bypass", apex.phase_cors_preflight_bypass),
        ("Prototype Pollution JSON", apex.phase_prototype_pollution_json),
        ("ATO Response Manipulation", apex.phase_account_takeover_response_manipulation),
        ("API Mass Exposure", apex.phase_api_mass_exposure),
        ("OAuth Token Leakage", apex.phase_oauth_token_leakage),
        ("Blind SQLi OOB", apex.phase_blind_sqli_oob),
        ("IDOR UUID Prediction", apex.phase_idor_uuid_prediction),
        ("HTTP/2 Rapid Reset", apex.phase_http2_rapid_reset),
        ("SAML Injection", apex.phase_saml_injection),
        ("DNS Rebinding SSRF", apex.phase_dns_rebinding_ssrf),
        # OOB confirmed
        ("OOB SSRF", apex.phase_oob_ssrf),
        ("OOB CMDi", apex.phase_oob_cmdi),
        ("OOB SQLi", apex.phase_oob_sqli),
        # Context-aware
        ("Context XSS", apex.phase_context_xss),
        ("Context SQLi", apex.phase_context_sqli),
        # Authenticated
        ("Authenticated Scan", apex.phase_authenticated),
        # Elite batch 5+6
        ("Subdomain Brute-Force", apex.phase_subdomain_bruteforce),
        ("Response Diff Auth Bypass", apex.phase_response_diff_auth_bypass),
        ("Next.js/React Vulns", apex.phase_nextjs_react_vulns),
        ("GraphQL Mutation Fuzzing", apex.phase_graphql_mutation_fuzzing),
        ("TE.CL Smuggling", apex.phase_te_cl_smuggling),
        ("IDOR Pagination", apex.phase_idor_pagination),
        ("Race Condition Registration", apex.phase_race_condition_registration),
        ("Timing User Enumeration", apex.phase_timing_user_enumeration),
        ("CSS Exfil", apex.phase_css_exfil),
        ("Open Redirect OAuth Chain", apex.phase_open_redirect_oauth_chain),
        ("SSRF PDF Generation", apex.phase_ssrf_pdf_generation),
        ("NS Takeover", apex.phase_ns_takeover),
    ]

    SEQUENTIAL = {"Recon", "Subdomain Brute-Force", "Probe", "Fingerprint", "Fuzz", "Crawl"}
    seq_phases = [(l, f) for l, f in phases if l in SEQUENTIAL]
    par_phases = [(l, f) for l, f in phases if l not in SEQUENTIAL]

    from concurrent.futures import ThreadPoolExecutor, as_completed

    def run_phase(label, fn):
        if label.lower() in skip:
            apex._log_phase(label, "skipped", "user --skip")
            return label, None
        try:
            fn()
            return label, None
        except Exception as e:
            apex._log_phase(label, "error", str(e))
            return label, str(e)

    with Progress(
        SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
        BarColumn(), TimeElapsedColumn(), console=console,
    ) as progress:
        for label, fn in seq_phases:
            task = progress.add_task(f"[cyan]{label}...", total=1)
            _, err = run_phase(label, fn)
            if err:
                console.print(f"[red][!] {label} failed: {err}[/red]")
            progress.update(task, completed=1)

        workers = min(8, len(par_phases))
        tasks_map = {}
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for label, fn in par_phases:
                t = progress.add_task(f"[cyan]{label}...", total=1)
                tasks_map[pool.submit(run_phase, label, fn)] = (label, t)
            for future in as_completed(tasks_map):
                label, task_id = tasks_map[future]
                _, err = future.result()
                if err:
                    console.print(f"[red][!] {label} failed: {err}[/red]")
                progress.update(task_id, completed=1)

    if apex.oob:
        apex.oob.stop()

    # Intelligence engine: dedup → verify → score → chain detection
    console.print("[dim]Running intelligence engine...[/dim]")
    apex.vulnerabilities = deduplicate_findings(apex.vulnerabilities)
    if not dry_run:
        verified = []
        for f in apex.vulnerabilities:
            if verify_finding(f):
                verified.append(f)
        dropped = len(apex.vulnerabilities) - len(verified)
        if dropped:
            console.print(f"[yellow][!] Dropped {dropped} false positives[/yellow]")
        apex.vulnerabilities = verified
    apex.vulnerabilities = score_findings(apex.vulnerabilities)
    chains = detect_attack_chains(apex.vulnerabilities)
    if chains:
        console.print(f"[bold red]🔗 {len(chains)} attack chain(s) detected![/bold red]")
        apex.vulnerabilities = chains + apex.vulnerabilities

    # Reports
    apex.report_terminal()
    if "json" in report_formats:
        apex.report_json()
    if "html" in report_formats:
        apex.report_html()


def interactive_menu():
    """Full interactive TUI when apex-cli is run with no arguments."""
    from rich.prompt import Prompt, Confirm
    from rich.columns import Columns

    show_banner()

    while True:
        console.print()
        console.print(Panel.fit(
            "[bold red]1[/bold red] Scan a target\n"
            "[bold red]2[/bold red] Auto-scan bug bounty targets\n"
            "[bold red]3[/bold red] View scan results / hits\n"
            "[bold red]4[/bold red] Show installed tools\n"
            "[bold red]5[/bold red] Scanner status\n"
            "[bold red]6[/bold red] Exit",
            title="[bold white]☠ APEX CLI MENU[/bold white]",
            border_style="red"
        ))

        choice = Prompt.ask("[bold cyan]Select[/bold cyan]", choices=["1","2","3","4","5","6"], default="1")

        if choice == "1":
            target = Prompt.ask("[bold cyan]Target domain/IP[/bold cyan]").strip()
            if not target: continue
            deep = Confirm.ask("Deep scan?", default=False)
            report_fmt = Prompt.ask("Report format", choices=["terminal","json","html"], default="terminal")
            try:
                target = validate_target(target)
            except SystemExit:
                continue
            console.print()
            run_scan(target, deep=deep, report_formats=[report_fmt])

        elif choice == "2":
            console.print("[bold yellow]Starting auto-scan of bug bounty targets...[/bold yellow]")
            console.print("[dim]Press Ctrl+C to stop[/dim]")
            try:
                subprocess.run([sys.executable,
                    str(Path(__file__).parent / "apex-auto.py"), "--bounty"])
            except KeyboardInterrupt:
                console.print("\n[yellow]Stopped.[/yellow]")

        elif choice == "3":
            hits_file = Path.home() / "apex-auto-results" / "hits.json"
            if not hits_file.exists():
                console.print("[yellow]No hits file found. Run auto-scan first.[/yellow]")
                continue
            with open(hits_file) as f:
                hits = json.load(f)
            if not hits:
                console.print("[yellow]No verified hits yet.[/yellow]")
                continue
            t = Table(title=f"Verified Hits ({len(hits)})")
            t.add_column("Target", style="cyan")
            t.add_column("Vulns", style="red")
            t.add_column("Top Finding")
            t.add_column("Time")
            for h in hits:
                vulns = h.get("vulnerabilities", [])
                top = vulns[0]["type"][:50] if vulns else "—"
                sev = vulns[0]["severity"].upper() if vulns else ""
                sev_color = {"CRITICAL":"bold red","HIGH":"red","MEDIUM":"yellow"}.get(sev,"white")
                t.add_row(h["target"], str(len(vulns)),
                          f"[{sev_color}]{sev}[/{sev_color}] {top}",
                          h.get("timestamp","")[:16])
            console.print(t)

        elif choice == "4":
            show_tools()

        elif choice == "5":
            console.print()
            for svc in ["apex-auto", "apex-auto2"]:
                result = subprocess.run(["systemctl","--user","status",svc],
                                       capture_output=True, text=True)
                active = "active (running)" in result.stdout
                color = "green" if active else "red"
                status = "● RUNNING" if active else "○ STOPPED"
                console.print(f"[{color}]{status}[/{color}] {svc}")
            scanned_file = Path.home() / "apex-auto-results" / "scanned.txt"
            if scanned_file.exists():
                count = len(scanned_file.read_text().splitlines())
                console.print(f"[white]Targets scanned:[/white] {count}")

        elif choice == "6":
            console.print("[bold red]Goodbye.[/bold red]")
            break


def main():
    parser = argparse.ArgumentParser(
        prog="apex-cli",
        description="Apex CLI v5.0 — Automated Pen-Test Orchestrator",
    )
    parser.add_argument("target", nargs="?", help="Target domain or IP (e.g. example.com)")
    parser.add_argument("--auto", type=str, metavar="FILE",
                        help="Auto-scan targets from file (one domain per line) or 'bounty' for live bug bounty targets")
    parser.add_argument("--dry-run", action="store_true", help="Preview commands without executing")
    parser.add_argument("--deep", action="store_true", help="Deep scan: more tools, higher intensity")
    parser.add_argument("--report", nargs="+", choices=["terminal", "json", "html"],
                        default=["terminal"], help="Report formats (default: terminal)")
    parser.add_argument("--tools", action="store_true", help="Show available tools and exit")
    parser.add_argument("--skip", nargs="+", default=[],
                        help="Skip phases (e.g. --skip nuclei sqli)")
    parser.add_argument("--auth", nargs=2, metavar=("USER", "PASS"),
                        help="Credentials for authenticated scanning")

    args = parser.parse_args()

    # No arguments = interactive menu
    if len(sys.argv) == 1:
        interactive_menu()
        return

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
            report_formats=args.report, skip=args.skip,
            auth=tuple(args.auth) if args.auth else None)


if __name__ == "__main__":
    main()
