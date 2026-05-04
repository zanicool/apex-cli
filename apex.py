#!/usr/bin/env python3
"""Apex CLI v9.0 — Automated Pen-Test Orchestrator."""

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
    # OOB
    OOBServer,
    oob_start,
    scan_blind_ssrf_oob,
    scan_blind_cmdi_oob,
    scan_blind_sqli_oob_confirmed,
    # Context-aware
    scan_context_aware_xss,
    scan_context_aware_sqli,
    # New scanners v6.6+
    passive_recon,
    scan_cors_null_origin,
    scan_method_override,
    scan_cookie_injection,
    scan_host_override_chain,
    set_rate_limit,
    parse_openapi_spec,
    authenticated_crawl,
    # Batch 5+6
    scan_subdomain_bruteforce,
    scan_response_diff_auth_bypass,
    scan_nextjs_react_vulns,
    scan_graphql_mutation_fuzzing,
    scan_te_cl_smuggling,
    scan_idor_pagination,
    scan_race_condition_registration,
    scan_timing_user_enumeration,
    scan_css_exfil,
    scan_open_redirect_oauth_chain,
    scan_ssrf_pdf_generation,
    scan_ns_takeover,
    # Batch 7
    scan_vhost_fuzzing,
    scan_subdomain_permutation,
    scan_h2c_smuggling,
    scan_expression_language_injection,
    scan_php_object_injection,
    scan_cache_key_injection,
    scan_link_injection,
    # Batch 8 — logic bugs
    scan_price_manipulation,
    scan_payment_flow_bypass,
    scan_account_state_manipulation,
    scan_forced_browsing,
    scan_parameter_tampering,
    scan_multi_step_race,
    # Batch 9
    scan_multi_step_auth_flow,
    scan_graphql_field_enumeration,
    scan_api_version_enumeration,
    scan_legacy_endpoints,
    scan_idor_horizontal_vertical,
    # Batch 14
    scan_http_desync_te_te,
    scan_idor_batch_api,
    scan_graphql_persisted_query,
    scan_xxe_parameter_entity,
    scan_open_redirect_meta,
    scan_cors_with_credentials,
    scan_clickjacking_advanced,
    scan_subdomain_ns_takeover,
    set_proxy,
    # Batch 16 — Final
    scan_account_prehijacking,
    scan_http_request_splitting,
    scan_xs_leaks,
    scan_oauth_token_fixation,
    scan_api_key_in_headers,
    scan_idor_graphql,
    scan_subdomain_a_record_takeover,
    scan_insecure_deserialization_patterns,
    scan_http2_push_abuse,
    scan_saml_replay,
    scan_iframe_injection,
    # Batch 17 — v9.0
    scan_csti_angular,
    scan_server_prototype_pollution,
    scan_http3_quic_probe,
    scan_graphql_subscription_abuse,
    scan_graphql_batching_rate_bypass,
    scan_bola_uuid_v1_timestamp,
    # Batch 18 — Power
    waf_bypass_test,
    scan_differential_auth,
    scan_param_discovery,
    scan_response_manipulation_ato,
    scan_race_condition_critical,
    scan_second_order_detection,
    # Batch 19 — Elite
    scan_dom_xss_browser,
    scan_postmessage_browser,
    scan_tech_specific,
    scan_exploit_chain_ssrf_to_cloud,
    # Batch 20 — Enhanced core
    scan_xss_browser_confirmed,
    scan_sqli_error_pattern,
    scan_blind_sqli_timing,
    scan_open_redirect_chain_oauth,
    # Batch 21 — SPA/API/JWT/WS
    crawl_spa,
    scan_openapi_fuzz,
    scan_jwt_full_attack,
    scan_websocket_inject,
    scan_email_header_inject,
    # Batch 22 — Takeover/GraphQL/Cookie
    scan_subdomain_takeover_v2,
    scan_graphql_field_suggest,
    scan_cookie_tossing,
    # Batch 23 — Smart SSTI/IDOR/LFI
    scan_ssti_smart,
    scan_idor_auto,
    scan_path_traversal_bypass,
    # Batch 24 — Smuggling/Privesc/API version
    scan_http_smuggling_detect,
    scan_privilege_escalation,
    scan_api_versioning_bypass,
    # Batch 25 — CORS PoC/JS secrets/HPP/Cache/CRLF/403/PII
    scan_cors_generate_poc,
    scan_js_secrets_deep,
    scan_hpp,
    scan_cache_poisoning_unkeyed,
    scan_crlf_advanced,
    scan_403_bypass_advanced,
    scan_sensitive_data_exposure,
    # Batch 26 — BFLA/Discovery/Timing
    scan_bfla,
    scan_endpoint_discovery,
    scan_content_type_confusion,
    scan_timing_attacks,
    # Batch 27 — Feedback loop
    feedback_loop_attack,
    # Batch 28 — Business logic deep
    scan_payment_logic_deep,
    scan_registration_abuse,
    scan_api_abuse_patterns,
    scan_account_takeover_flows,
    # Batch 29 — Upload/Deser/Host/GraphQL
    scan_file_upload_bypass,
    scan_deserialization_rce,
    scan_host_header_poison,
    scan_graphql_deep_exploit,
    # Batch 30 — Oracle/Mutation/ACL/Flow
    scan_response_oracle,
    scan_mutation_fuzzer,
    scan_access_control_matrix,
    scan_business_flow_abuse,
    # Batch 31 — Theoretical limits
    scan_entropy_analysis,
    scan_state_machine_inference,
    scan_information_leakage_differential,
    scan_race_window_exploitation,
    # Batch 32 — Absolute limits
    scan_compression_oracle,
    scan_cache_timing_oracle,
    scan_polynomial_fingerprint,
    scan_markov_prediction,
    # Batch 33 — OOB exploitation
    scan_blind_xss_oob,
    scan_ssrf_via_oob_redirect,
    scan_dns_exfil_sqli,
    # Batch 34 — OOB deep
    scan_xxe_oob_exfil,
    scan_ssrf_port_scan_oob,
    scan_blind_rce_oob,
    scan_log4shell_oob,
    # Batch 35 — Crawl improvements
    infer_api_endpoints,
    extract_js_routes,
    scan_auth_chain_test,
    # Batch 36 — NoSQL/PP/CL.0/CT
    scan_nosql_deep,
    scan_prototype_pollution_exploit,
    scan_cl0_smuggling,
    scan_subdomain_ct_realtime,
    # Batch 37 — LDAP/XML/H2/Token
    scan_ldap_deep,
    scan_xml_injection,
    scan_http2_exclusive,
    scan_token_manipulation,
    # Batch 38 — Webhook/S3/Length/GraphQL DoS
    scan_webhook_abuse,
    scan_s3_bucket_takeover,
    scan_input_length_overflow,
    scan_graphql_dos,
    # Batch 40 — Todo #1-#10
    scan_oauth2_full_exploit,
    scan_graphql_batch_mutation,
    scan_pdf_ssrf,
    scan_markdown_xss,
    scan_password_reset_prediction,
    scan_api_key_scope,
    # Batch 41 — Todo #6-#30
    scan_cswsh,
    scan_svg_xss_upload,
    scan_idor_graphql_node,
    scan_mass_assignment_patch,
    scan_race_2fa,
    # Batch 42 — Todo #50-#96
    scan_git_exposure,
    scan_env_leak,
    scan_firebase_misconfig_deep,
    scan_terraform_state,
    scan_docker_registry,
    scan_k8s_dashboard,
    scan_cicd_exposure,
    scan_jupyter_exposure,
    scan_wp_user_enum,
    # Safe exploitation engine
    llm_safe_exploit,
    # Batch 39 — Deep crawl + auto-auth
    crawl_deep,
    auto_register_account,
    crawl_authenticated,
    # Batch 15
    scan_password_spray,
    scan_graphql_injection,
    scan_broken_function_level_auth,
    scan_mass_user_enumeration,
    scan_cors_vary_origin,
    scan_insecure_jwt_storage,
    scan_2fa_bypass_response,
    # Batch 13
    scan_ldap_injection,
    scan_template_injection_twig,
    scan_websocket_origin_bypass,
    scan_server_timing_oracle,
    scan_csp_bypass_jsonp,
    scan_api_key_rotation_bypass,
    scan_graphql_circular_fragment,
    # Batch 12
    scan_jwt_kid_injection,
    scan_rate_limit_bypass_headers,
    scan_idor_json_body,
    scan_auth_bypass_content_type,
    scan_ssrf_via_svg,
    scan_unkeyed_cache_poisoning,
    scan_graphql_alias_introspection,
    scan_nosql_operator_injection,
    # Batch 11
    scan_subdomain_takeover_deep,
    scan_account_takeover_vectors,
    scan_oauth_deep,
    scan_xxe_file_upload,
    scan_ssrf_redirect_chain,
    # Batch 10
    scan_jwt_secret_bruteforce,
    scan_cors_subdomain_wildcard,
    scan_bopla,
    scan_api_key_in_url,
    scan_insecure_file_download,
    scan_prototype_pollution_path,
    scan_mass_assignment_patch,
    # WAF bypass + tech helpers
    _run_wp_enum,
    _run_spring_deep,
    _run_laravel_secrets,
    # Intelligence engine
    deduplicate_findings,
    score_findings,
    detect_attack_chains,
    verify_finding,
    prioritize_targets,
    filter_exploitable_only,
    enrich_findings_with_poc,
)

console = Console()

# ---------------------------------------------------------------------------
# Tool discovery
# ---------------------------------------------------------------------------

def find_tool(name):
    """Return absolute path for *name* or None — checks PATH and ~/go/bin."""
    import os as _os
    path = shutil.which(name)
    if path:
        return path
    # Also check ~/go/bin (Go tools installed by user)
    go_path = _os.path.expanduser(f"~/go/bin/{name}")
    if _os.path.isfile(go_path) and _os.access(go_path, _os.X_OK):
        return go_path
    return None

def find_httpx():
    """Find ProjectDiscovery's httpx, not the Python pip httpx."""
    import os as _os
    # Check go/bin first (PD httpx is usually here)
    candidates = [
        _os.path.expanduser("~/go/bin/httpx"),
        "/usr/local/bin/httpx",
        shutil.which("httpx") or "",
    ]
    for path in candidates:
        if not path or not _os.path.isfile(path):
            continue
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
    "katana": find_tool("katana"),
    "dalfox": find_tool("dalfox"),
    "gau": find_tool("gau"),
    "dnsx": find_tool("dnsx"),
    "gospider": find_tool("gospider"),
    "crlfuzz": find_tool("crlfuzz"),
}

# Wordlist discovery — try common locations, fall back to a tiny built-in list.
WORDLIST_CANDIDATES = [
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/dirbuster/wordlists/directory-list-2.3-small.txt",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "wordlists", "seclists", "Discovery", "Web-Content", "common.txt"),
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "wordlists", "seclists", "Discovery", "Web-Content", "directory-list-2.3-medium.txt"),
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
        self.scope = []
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
        self._save_state()
        # Incremental: print new findings immediately + notify on criticals
        new_vulns = [v for v in self.vulnerabilities
                     if v.get("severity") in ("critical", "high")
                     and not v.get("_reported")]
        for v in new_vulns:
            v["_reported"] = True
            sev = v["severity"].upper()
            color = "bold red" if sev == "CRITICAL" else "red"
            console.print(f"[{color}]  🎯 {sev}[/{color}] {v['type'][:60]} → {v.get('url','')[:60]}")
            # Push notification for criticals
            if sev == "CRITICAL":
                try:
                    import requests as _nr
                    _nr.post("https://ntfy.sh/apex-findings",
                             data=f"🚨 CRITICAL: {v['type']}\n{v.get('url','')[:80]}\n{v.get('detail','')[:100]}".encode(),
                             headers={"Title": f"Apex: Critical on {self.target}", "Priority": "urgent"},
                             timeout=3)
                except Exception:
                    pass

    def _save_state(self):
        """Persist scan state so it can be resumed after a crash."""
        state = {
            "target": self.target,
            "subdomains": self.subdomains,
            "web_targets": self.web_targets,
            "technologies": self.technologies,
            "waf_detected": self.waf_detected,
            "phase_results": self.phase_results,
            "vulnerabilities": self.vulnerabilities,
        }
        try:
            state_file = os.path.join(self.output_dir, ".apex_state.json")
            with open(state_file, "w") as f:
                json.dump(state, f)
        except Exception:
            pass

    def _load_state(self):
        """Load previous scan state for resume."""
        state_file = os.path.join(self.output_dir, ".apex_state.json")
        if not os.path.isfile(state_file):
            return False
        try:
            with open(state_file) as f:
                state = json.load(f)
            self.subdomains = state.get("subdomains", [])
            self.web_targets = state.get("web_targets", [])
            self.technologies = state.get("technologies", [])
            self.waf_detected = state.get("waf_detected", [])
            self.phase_results = state.get("phase_results", [])
            self.vulnerabilities = state.get("vulnerabilities", [])
            return True
        except Exception:
            return False

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
        # Always include the base target itself
        if self.target not in self.subdomains:
            self.subdomains.insert(0, self.target)
        if len(self.subdomains) == 1:
            console.print("[yellow][!] No additional subdomains found.[/yellow]")
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
        if self.scope:
            self.web_targets = [t for t in self.web_targets
                                if any(s in t for s in self.scope)]
            console.print(f"[dim]Scope filter: {len(self.web_targets)} targets match {self.scope}[/dim]")
        console.print(f"[green][✓][/green] {len(self.web_targets)} live web targets.")

    def _probe_httpx(self, path):
        subs_file = os.path.join(self.output_dir, "subdomains.txt")
        cmd = [path, "-l", subs_file, "-silent", "-no-color",
               "-threads", os.environ.get("APEX_HTTPX_T", "50")]
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
        cmd = [path, f"-{os.environ.get('APEX_NMAP_T','T3')}", "-iL", targets_file, "-p", ports, "--open", "-oG",
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
        # Always try the base target on standard ports first
        ports = [("https", 443), ("http", 80), ("http", 8080), ("http", 5000), ("http", 3000)]
        subs = list(self.subdomains)
        if self.target not in subs:
            subs.insert(0, self.target)
        for sub in subs:
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
                "-of", "json", "-s", "-t", os.environ.get("APEX_FFUF_T", "100"),
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

        # Auto-update templates (background, non-blocking)
        import threading as _nt
        def _update_templates():
            try:
                subprocess.run([path, "-update-templates", "-silent"],
                               capture_output=True, timeout=60)
            except Exception:
                pass
        _nt.Thread(target=_update_templates, daemon=True).start()

        # Find nuclei templates directory
        import shutil as _shutil
        templates_dir = os.path.expanduser("~/nuclei-templates")
        if not os.path.isdir(templates_dir):
            templates_dir = os.path.join(os.path.expanduser("~"), ".local", "nuclei-templates")
        if not os.path.isdir(templates_dir):
            # Let nuclei use its default
            templates_dir = None

        # High-value template categories to always run
        template_tags = [
            "cve", "rce", "sqli", "xss", "ssrf", "lfi", "rfi", "xxe",
            "ssti", "idor", "auth-bypass", "default-login", "exposed-panel",
            "misconfig", "takeover", "token", "secret", "exposure",
            "injection", "traversal", "redirect", "cors", "jwt",
        ]
        # Override with user-specified tags if provided
        if hasattr(self, "nuclei_tags") and self.nuclei_tags:
            template_tags = self.nuclei_tags

        cmd = [
            path, "-l", targets_file, "-jsonl", "-o", json_out,
            "-silent", "-no-color",
            "-c", os.environ.get("APEX_NUCLEI_C", "50"),
            "-bs", os.environ.get("APEX_NUCLEI_BS", "50"),
            "-rl", os.environ.get("APEX_NUCLEI_RL", "500"),
            "-timeout", "8",
            "-retries", "1",
            "-tags", ",".join(template_tags),
        ]

        # Add explicit template dirs if available
        if templates_dir:
            for subdir in ["http/cves", "http/exposed-panels", "http/default-logins",
                           "http/misconfigurations", "http/exposures", "http/vulnerabilities",
                           "http/takeovers", "http/fuzzing", "dns"]:
                full = os.path.join(templates_dir, subdir)
                if os.path.isdir(full):
                    cmd.extend(["-t", full])

        if self.deep:
            cmd.extend(["-severity", "info,low,medium,high,critical"])
        else:
            cmd.extend(["-severity", "medium,high,critical"])

        # Also run DAST templates if available (nuclei v3+)
        dast_dir = os.path.join(templates_dir or "", "dast")
        if os.path.isdir(dast_dir):
            cmd.extend(["-t", dast_dir])

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
                        info = finding.get("info", {})
                        self.vulnerabilities.append({
                            "type": info.get("name", "Unknown"),
                            "severity": info.get("severity", "unknown"),
                            "url": finding.get("matched-at", finding.get("host", "")),
                            "template": finding.get("template-id", ""),
                            "detail": info.get("description", "") or str(finding.get("extracted-results", "")),
                            "cvss_score": info.get("classification", {}).get("cvss-score", ""),
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
            cmd.extend(["--level", os.environ.get("APEX_SQLMAP_L","2"),
                         "--risk", os.environ.get("APEX_SQLMAP_R","1")])
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
                data = ajax_spider(target, max_pages=100 if self.deep else 50)
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
        max_pages = 200 if self.deep else 100
        # Crawl from each base target — use deep crawler
        base_targets = [t for t in self.web_targets if t.count("/") <= 3]
        for target in base_targets or self.web_targets[:3]:
            console.print(f"[bold blue][+][/bold blue] Deep crawling {target}...")
            data = crawl_deep(target, max_pages=max_pages)
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
        # Auto-register + auto-login: get authenticated access automatically
        if not self.auth and not self.dry_run and self.web_targets:
            base = "/".join(self.web_targets[0].split("/", 3)[:3])
            # Try auto-registration first
            console.print("[dim]Attempting auto-registration for authenticated scanning...[/dim]")
            auth_result = auto_register_account(base)
            if auth_result:
                console.print(f"[bold green][+][/bold green] Auto-registered as {auth_result.get('email','?')} — authenticated scanning enabled")
                self.auth = (auth_result.get("email", ""), auth_result.get("password", ""))
                # Do authenticated crawl with the new account
                auth_crawl = crawl_authenticated(base, auth_result, max_pages=100)
                if auth_crawl:
                    new_pages = len(auth_crawl["pages"])
                    all_pages.extend(auth_crawl["pages"])
                    all_forms.extend(auth_crawl["forms"])
                    for u, ps in auth_crawl["params"].items():
                        all_params[u] = list(set(all_params.get(u, [])) | set(ps))
                    console.print(f"[green][✓][/green] Authenticated crawl: +{new_pages} pages behind login")
            else:
                # Fall back to auto-login with test creds
                session, email, pwd = auto_login_attempt(base, {"forms": all_forms, "pages": all_pages})
                if session and email:
                    console.print(f"[bold green][+][/bold green] Auto-login succeeded as {email}")
                    self.auth = (email, pwd)

        # Authenticated crawl — merge pages/forms/params found behind login
        if self.auth and not self.dry_run:
            username, password = self.auth
            for target in (self.web_targets or [f"https://{self.target}"])[:2]:
                base = "/".join(target.split("/", 3)[:3])
                console.print(f"[bold blue][+][/bold blue] Authenticated crawl as {username}...")
                auth_data = authenticated_crawl(base, username, password,
                                                max_pages=50 if self.deep else 25)
                if auth_data:
                    all_pages.extend(auth_data["pages"])
                    all_forms.extend(auth_data["forms"])
                    for u, ps in auth_data["params"].items():
                        all_params[u] = list(set(all_params.get(u, [])) | set(ps))
                    all_links.update(auth_data["links"])
                    console.print(f"[green][✓][/green] Auth crawl: {len(auth_data['pages'])} pages, {len(auth_data['forms'])} forms")
                else:
                    console.print(f"[yellow][!] Auth crawl: login failed[/yellow]")

        # Parse OpenAPI/Swagger spec — merges all discovered endpoints
        for target in (self.web_targets or [f"https://{self.target}"])[:3]:
            spec_base = "/".join(target.split("/", 3)[:3])
            spec_data = parse_openapi_spec(spec_base)
            if spec_data:
                console.print(f"[bold green][✓][/bold green] OpenAPI spec found: {spec_data['total_endpoints']} endpoints → {spec_data.get('spec_url','')}")
                all_pages.extend(spec_data["pages"])
                all_forms.extend(spec_data["forms"])
                for u, ps in spec_data["params"].items():
                    all_params[u] = list(set(all_params.get(u, [])) | set(ps))
                all_links.update(spec_data["links"])
                break  # one spec is enough

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

        # Executive summary
        crits = [v for v in self.vulnerabilities if v.get("severity") == "critical"]
        highs = [v for v in self.vulnerabilities if v.get("severity") == "high"]
        meds = [v for v in self.vulnerabilities if v.get("severity") == "medium"]
        if crits or highs:
            console.print()
            console.print(Panel.fit(
                f"[bold red]☠ {len(crits)} CRITICAL[/bold red] | "
                f"[red]{len(highs)} HIGH[/red] | "
                f"[yellow]{len(meds)} MEDIUM[/yellow] | "
                f"[dim]{len(self.vulnerabilities)} total[/dim]",
                title="[bold white]FINDINGS SUMMARY[/bold white]",
                border_style="red"
            ))

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

            # Show PoC commands for critical/high findings
            crit_high = [v for v in self.vulnerabilities if v.get("severity") in ("critical", "high")]
            if crit_high:
                console.print(f"\n[bold red]☠ Proof of Concept — {len(crit_high)} exploitable findings:[/bold red]")
                for v in crit_high[:10]:
                    poc = v.get("poc", "")
                    if poc:
                        console.print(f"\n  [bold cyan]{v['type']}[/bold cyan] → {v['url'][:70]}")
                        console.print(f"  [dim]{poc.split(chr(10))[0]}[/dim]")

        console.print(f"\n[bold blue]Logs:[/bold blue] {self.output_dir}/")

    def report_json(self):
        crits = [v for v in self.vulnerabilities if v.get("severity") == "critical"]
        highs = [v for v in self.vulnerabilities if v.get("severity") == "high"]
        meds = [v for v in self.vulnerabilities if v.get("severity") == "medium"]
        data = {
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "scan_duration_phases": len(self.phase_results),
            "summary": {
                "critical": len(crits),
                "high": len(highs),
                "medium": len(meds),
                "total": len(self.vulnerabilities),
                "top_finding": crits[0]["type"] if crits else (highs[0]["type"] if highs else None),
            },
            "technologies": self.technologies,
            "waf": self.waf_detected,
            "subdomains": self.subdomains,
            "web_targets": self.web_targets,
            "phases": self.phase_results,
            "vulnerabilities": self.vulnerabilities,
        }
        out = os.path.join(self.output_dir, "report.json")
        with open(out, "w") as f:
            json.dump(data, f, indent=2, default=str)
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
        if self.dry_run or not self.subdomains: return
        subs = list(self.subdomains)  # snapshot to avoid race condition
        if not subs: return
        findings = scan_subdomain_takeover(subs)
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


    def phase_passive_recon(self):
        if self.dry_run: return
        console.print(f"[bold blue][+][/bold blue] Passive recon on {self.target}...")
        subs, findings = passive_recon(self.target)
        self.subdomains = list(dict.fromkeys(self.subdomains + subs))
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)
        self._log_phase("Passive Recon", "ok", f"{len(subs)} subdomains, {len(findings)} findings")

    def phase_cors_null_origin(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_cors_null_origin(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_method_override(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_method_override(self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_cookie_injection(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_cookie_injection(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_host_override_chain(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_host_override_chain(self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)


    def phase_vhost_fuzzing(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_vhost_fuzzing(self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_subdomain_permutation(self):
        if self.dry_run: return
        findings, found = scan_subdomain_permutation(self.target, self.subdomains)
        self.subdomains = list(dict.fromkeys(self.subdomains + found))
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)
        self._log_phase("Subdomain Permutation", "ok", f"{len(found)} new subdomains")

    def phase_h2c_smuggling(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_h2c_smuggling(self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_expression_language_injection(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_expression_language_injection(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_php_object_injection(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_php_object_injection(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_cache_key_injection(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_cache_key_injection(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_link_injection(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_link_injection(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)


    def phase_price_manipulation(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_price_manipulation(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_payment_flow_bypass(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_payment_flow_bypass(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_account_state_manipulation(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_account_state_manipulation(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_forced_browsing(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_forced_browsing(self.crawl_data, self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_parameter_tampering(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_parameter_tampering(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_multi_step_race(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_multi_step_race(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)


    def phase_multi_step_auth_flow(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_multi_step_auth_flow(self.crawl_data, self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_graphql_field_enumeration(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_graphql_field_enumeration(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_api_version_enumeration(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_api_version_enumeration(self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_legacy_endpoints(self):
        if self.dry_run: return
        findings = scan_legacy_endpoints(self.target, self.subdomains)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_idor_horizontal_vertical(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_idor_horizontal_vertical(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)


    def phase_jwt_secret_bruteforce(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_jwt_secret_bruteforce(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_cors_subdomain_wildcard(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_cors_subdomain_wildcard(self.crawl_data, self.subdomains)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_bopla(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_bopla(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_api_key_in_url(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_api_key_in_url(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_insecure_file_download(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_insecure_file_download(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_prototype_pollution_path(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_prototype_pollution_path(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_mass_assignment_patch(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_mass_assignment_patch(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)


    def phase_subdomain_takeover_deep(self):
        if self.dry_run or not self.subdomains: return
        findings = scan_subdomain_takeover_deep(self.subdomains)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_account_takeover_vectors(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_account_takeover_vectors(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_oauth_deep(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_oauth_deep(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_xxe_file_upload(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_xxe_file_upload(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_ssrf_redirect_chain(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_ssrf_redirect_chain(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)


    def phase_jwt_kid_injection(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_jwt_kid_injection(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_rate_limit_bypass_headers(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_rate_limit_bypass_headers(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_idor_json_body(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_idor_json_body(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_auth_bypass_content_type(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_auth_bypass_content_type(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_ssrf_via_svg(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_ssrf_via_svg(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_unkeyed_cache_poisoning(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_unkeyed_cache_poisoning(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_graphql_alias_introspection(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_graphql_alias_introspection(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_nosql_operator_injection(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_nosql_operator_injection(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)


    def phase_ldap_injection(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_ldap_injection(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_template_injection_twig(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_template_injection_twig(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_websocket_origin_bypass(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_websocket_origin_bypass(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_server_timing_oracle(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_server_timing_oracle(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_csp_bypass_jsonp(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_csp_bypass_jsonp(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_api_key_rotation_bypass(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_api_key_rotation_bypass(self.crawl_data, self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_graphql_circular_fragment(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_graphql_circular_fragment(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)


    def phase_http_desync_te_te(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_http_desync_te_te(self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_idor_batch_api(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_idor_batch_api(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_graphql_persisted_query(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_graphql_persisted_query(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_xxe_parameter_entity(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_xxe_parameter_entity(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_open_redirect_meta(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_open_redirect_meta(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_cors_with_credentials(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_cors_with_credentials(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_clickjacking_advanced(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_clickjacking_advanced(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_subdomain_ns_takeover(self):
        if self.dry_run or not self.subdomains: return
        findings = scan_subdomain_ns_takeover(self.target, self.subdomains)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)


    def phase_password_spray(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_password_spray(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_graphql_injection(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_graphql_injection(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_broken_function_level_auth(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_broken_function_level_auth(self.crawl_data, self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_mass_user_enumeration(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_mass_user_enumeration(self.crawl_data, self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_cors_vary_origin(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_cors_vary_origin(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_insecure_jwt_storage(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_insecure_jwt_storage(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_2fa_bypass_response(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_2fa_bypass_response(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)


    def phase_account_prehijacking(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_account_prehijacking(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_http_request_splitting(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_http_request_splitting(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_xs_leaks(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_xs_leaks(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_oauth_token_fixation(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_oauth_token_fixation(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_api_key_in_headers(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_api_key_in_headers(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_idor_graphql(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_idor_graphql(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_subdomain_a_record_takeover(self):
        if self.dry_run or not self.subdomains: return
        findings = scan_subdomain_a_record_takeover(self.subdomains)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_insecure_deserialization_patterns(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_insecure_deserialization_patterns(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_http2_push_abuse(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_http2_push_abuse(self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_saml_replay(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_saml_replay(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_iframe_injection(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_iframe_injection(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    # Batch 17 — v9.0 phases
    def phase_csti_angular(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_csti_angular(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_server_prototype_pollution(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_server_prototype_pollution(self.crawl_data or {}, self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_http3_quic_probe(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_http3_quic_probe(self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_graphql_subscription_abuse(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_graphql_subscription_abuse(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_graphql_batching_rate_bypass(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_graphql_batching_rate_bypass(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_bola_uuid_v1_timestamp(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_bola_uuid_v1_timestamp(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    # Batch 18 — Power phases
    def phase_differential_auth(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_differential_auth(self.crawl_data, self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_param_discovery(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_param_discovery(self.crawl_data or {}, self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_response_manipulation_ato(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_response_manipulation_ato(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_race_condition_critical(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_race_condition_critical(self.crawl_data, self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_second_order_detection(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_second_order_detection(self.crawl_data, self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    # Batch 19 — Elite phases
    def phase_dom_xss_browser(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_dom_xss_browser(self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_postmessage_browser(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_postmessage_browser(self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_tech_specific(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_tech_specific(self.crawl_data or {}, self.web_targets, self.technologies)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_exploit_chain_ssrf_to_cloud(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_exploit_chain_ssrf_to_cloud(self.crawl_data, self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    # Batch 20 — Enhanced core
    def phase_xss_browser_confirmed(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_xss_browser_confirmed(self.crawl_data, self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_sqli_error_pattern(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_sqli_error_pattern(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_blind_sqli_timing(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_blind_sqli_timing(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_open_redirect_chain_oauth(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_open_redirect_chain_oauth(self.crawl_data, self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    # Batch 21
    def phase_crawl_spa(self):
        """Crawl with Playwright for SPA/JS-rendered content."""
        if self.dry_run or not self.web_targets: return
        spa_data = crawl_spa(self.web_targets[0])
        # Merge SPA crawl data into main crawl_data
        if spa_data and spa_data.get("pages"):
            if not self.crawl_data:
                self.crawl_data = {"pages": [], "forms": [], "params": {}, "links": []}
            self.crawl_data["pages"].extend(spa_data["pages"])
            self.crawl_data["forms"].extend(spa_data["forms"])
            for url, params in spa_data["params"].items():
                if url in self.crawl_data["params"]:
                    existing = set(self.crawl_data["params"][url])
                    existing.update(params)
                    self.crawl_data["params"][url] = list(existing)
                else:
                    self.crawl_data["params"][url] = params
            self.crawl_data["links"].extend(spa_data.get("links", []))
            console.print(f"[green][✓][/green] SPA crawl: +{len(spa_data['pages'])} pages, +{len(spa_data['params'])} param endpoints")
        self._log_phase("SPA Crawl", "ok", f"{len(spa_data.get('pages',[]))} pages")

    def phase_openapi_fuzz(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_openapi_fuzz(self.web_targets[0], self.crawl_data or {})
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_jwt_full_attack(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_jwt_full_attack(self.crawl_data, self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_websocket_inject(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_websocket_inject(self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_email_header_inject(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_email_header_inject(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    # Batch 22
    def phase_subdomain_takeover_v2(self):
        if self.dry_run or not self.subdomains: return
        findings = scan_subdomain_takeover_v2(self.subdomains, self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_graphql_field_suggest(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_graphql_field_suggest(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_cookie_tossing(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_cookie_tossing(self.crawl_data or {}, self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    # Batch 23
    def phase_ssti_smart(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_ssti_smart(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_idor_auto(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_idor_auto(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_path_traversal_bypass(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_path_traversal_bypass(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    # Batch 24
    def phase_http_smuggling_detect(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_http_smuggling_detect(self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_privilege_escalation(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_privilege_escalation(self.crawl_data or {}, self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_api_versioning_bypass(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_api_versioning_bypass(self.crawl_data, self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    # Batch 25
    def phase_cors_generate_poc(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_cors_generate_poc(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)
        # Save PoC HTML files
        for f in findings:
            if f.get("poc_html"):
                poc_path = os.path.join(self.output_dir, f"cors_poc_{len(self.vulnerabilities)}.html")
                with open(poc_path, "w") as fp:
                    fp.write(f["poc_html"])

    def phase_js_secrets_deep(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_js_secrets_deep(self.crawl_data, self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_hpp(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_hpp(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_cache_poisoning_unkeyed(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_cache_poisoning_unkeyed(self.crawl_data or {}, self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_crlf_advanced(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_crlf_advanced(self.crawl_data or {}, self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_403_bypass_advanced(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_403_bypass_advanced(self.crawl_data or {}, self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_sensitive_data_exposure(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_sensitive_data_exposure(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    # Batch 26
    def phase_bfla(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_bfla(self.crawl_data or {}, self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_endpoint_discovery(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_endpoint_discovery(self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_content_type_confusion(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_content_type_confusion(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_timing_attacks(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_timing_attacks(self.crawl_data or {}, self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    # Batch 28
    def phase_payment_logic_deep(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_payment_logic_deep(self.crawl_data, self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_registration_abuse(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_registration_abuse(self.crawl_data or {}, self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_api_abuse_patterns(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_api_abuse_patterns(self.crawl_data or {}, self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_account_takeover_flows(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_account_takeover_flows(self.crawl_data or {}, self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    # Batch 29
    def phase_file_upload_bypass(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_file_upload_bypass(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_deserialization_rce(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_deserialization_rce(self.crawl_data, self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_host_header_poison(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_host_header_poison(self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_graphql_deep_exploit(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_graphql_deep_exploit(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    # Batch 30
    def phase_response_oracle(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_response_oracle(self.crawl_data, self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_mutation_fuzzer(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_mutation_fuzzer(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_access_control_matrix(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_access_control_matrix(self.crawl_data, self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_business_flow_abuse(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_business_flow_abuse(self.crawl_data or {}, self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    # Batch 31
    def phase_entropy_analysis(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_entropy_analysis(self.crawl_data or {}, self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_state_machine_inference(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_state_machine_inference(self.crawl_data or {}, self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_information_leakage_differential(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_information_leakage_differential(self.crawl_data or {}, self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_race_window_exploitation(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_race_window_exploitation(self.crawl_data or {}, self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    # Batch 32
    def phase_compression_oracle(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_compression_oracle(self.crawl_data, self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_cache_timing_oracle(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_cache_timing_oracle(self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_polynomial_fingerprint(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_polynomial_fingerprint(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_markov_prediction(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_markov_prediction(self.crawl_data or {}, self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    # Batch 33 — OOB
    def phase_blind_xss_oob(self):
        if self.dry_run or not self.oob or not self.crawl_data: return
        findings = scan_blind_xss_oob(self.crawl_data, self.oob)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_ssrf_via_oob_redirect(self):
        if self.dry_run or not self.oob or not self.crawl_data: return
        findings = scan_ssrf_via_oob_redirect(self.crawl_data, self.oob)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_dns_exfil_sqli(self):
        if self.dry_run or not self.oob or not self.crawl_data: return
        findings = scan_dns_exfil_sqli(self.crawl_data, self.oob)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    # Batch 34
    def phase_xxe_oob_exfil(self):
        if self.dry_run or not self.oob or not self.crawl_data: return
        findings = scan_xxe_oob_exfil(self.crawl_data, self.oob)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_ssrf_port_scan_oob(self):
        if self.dry_run or not self.oob or not self.crawl_data: return
        findings = scan_ssrf_port_scan_oob(self.crawl_data, self.oob, self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_blind_rce_oob(self):
        if self.dry_run or not self.oob or not self.crawl_data: return
        findings = scan_blind_rce_oob(self.crawl_data, self.oob)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_log4shell_oob(self):
        if self.dry_run or not self.oob or not self.web_targets: return
        findings = scan_log4shell_oob(self.web_targets, self.oob)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    # Batch 35 — Crawl improvements (run early to feed other scanners)
    def phase_infer_api_endpoints(self):
        if self.dry_run or not self.crawl_data: return
        live = infer_api_endpoints(self.crawl_data, self.web_targets)
        if live:
            console.print(f"[green][✓][/green] Inferred {len(live)} hidden API endpoints")
        self._log_phase("API Inference", "ok", f"{len(live)} endpoints")

    def phase_extract_js_routes(self):
        if self.dry_run or not self.crawl_data: return
        result = extract_js_routes(self.crawl_data, self.web_targets)
        routes = result.get("routes", [])
        apis = result.get("api_endpoints", [])
        if routes or apis:
            console.print(f"[green][✓][/green] JS routes: {len(routes)} pages, {len(apis)} API endpoints")
        self._log_phase("JS Route Extraction", "ok", f"{len(routes)} routes, {len(apis)} APIs")

    def phase_auth_chain_test(self):
        if self.dry_run or not self.auth or not self.web_targets: return
        findings = scan_auth_chain_test(self.crawl_data or {}, self.web_targets, self.auth)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    # Batch 36
    def phase_nosql_deep(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_nosql_deep(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_prototype_pollution_exploit(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_prototype_pollution_exploit(self.crawl_data or {}, self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_cl0_smuggling(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_cl0_smuggling(self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_subdomain_ct_realtime(self):
        if self.dry_run: return
        findings, new_subs = scan_subdomain_ct_realtime(self.target)
        for sub in new_subs:
            if sub not in self.subdomains:
                self.subdomains.append(sub)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)
        if new_subs:
            self._log_phase("CT Realtime", "ok", f"+{len(new_subs)} subdomains")

    # Batch 37
    def phase_ldap_deep(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_ldap_deep(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_xml_injection(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_xml_injection(self.crawl_data or {}, self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_http2_exclusive(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_http2_exclusive(self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_token_manipulation(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_token_manipulation(self.crawl_data or {}, self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    # Batch 38
    def phase_webhook_abuse(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_webhook_abuse(self.crawl_data or {}, self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_s3_bucket_takeover(self):
        if self.dry_run: return
        findings = scan_s3_bucket_takeover(self.target, self.subdomains)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_input_length_overflow(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_input_length_overflow(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_graphql_dos(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_graphql_dos(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    # Todo #1-#10
    def phase_oauth2_full_exploit(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_oauth2_full_exploit(self.crawl_data or {}, self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_graphql_batch_mutation(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_graphql_batch_mutation(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_pdf_ssrf(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_pdf_ssrf(self.crawl_data or {}, self.web_targets, self.oob)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_markdown_xss(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_markdown_xss(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_password_reset_prediction(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_password_reset_prediction(self.crawl_data or {}, self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_api_key_scope(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_api_key_scope(self.crawl_data, self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    # Batch 41
    def phase_cswsh(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_cswsh(self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_svg_xss_upload(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_svg_xss_upload(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_idor_graphql_node(self):
        if self.dry_run or not self.crawl_data: return
        findings = scan_idor_graphql_node(self.crawl_data)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_mass_assignment_patch(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_mass_assignment_patch(self.crawl_data or {}, self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_race_2fa(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_race_2fa(self.crawl_data or {}, self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    # Batch 42
    def phase_git_exposure(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_git_exposure(self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_env_leak(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_env_leak(self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_firebase_misconfig_deep(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_firebase_misconfig_deep(self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_terraform_state(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_terraform_state(self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_docker_registry(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_docker_registry(self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_k8s_dashboard(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_k8s_dashboard(self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_cicd_exposure(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_cicd_exposure(self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_jupyter_exposure(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_jupyter_exposure(self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    def phase_wp_user_enum(self):
        if self.dry_run or not self.web_targets: return
        findings = scan_wp_user_enum(self.web_targets)
        with self._vuln_lock:
            self.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)

    # External tool phases
    def phase_katana_crawl(self):
        """Katana — ProjectDiscovery's headless crawler. Finds 3-5x more endpoints."""
        path = self._tool("katana")
        if not path or self.dry_run or not self.web_targets:
            return
        targets_file = os.path.join(self.output_dir, "web_targets.txt")
        out_file = os.path.join(self.output_dir, "katana_urls.txt")
        cmd = [path, "-list", targets_file, "-silent", "-no-color",
               "-jc",  # JS crawling
               "-d", "5",  # depth 5
               "-o", out_file]
        if self.deep:
            cmd.extend(["-headless", "-known-files", "all"])
        stdout, _, code = self.run_command(cmd, "Katana JS-aware crawl", "katana_log.txt")
        # Parse discovered URLs into crawl_data
        if os.path.isfile(out_file):
            with open(out_file) as f:
                new_urls = [l.strip() for l in f if l.strip().startswith("http")]
            for url in new_urls:
                parsed = urllib.parse.urlparse(url)
                base = url.split("?")[0]
                if parsed.query:
                    if not self.crawl_data:
                        self.crawl_data = {"pages": [], "forms": [], "params": {}, "links": []}
                    params = list(urllib.parse.parse_qs(parsed.query).keys())
                    if base in self.crawl_data.get("params", {}):
                        self.crawl_data["params"][base] = list(set(self.crawl_data["params"][base] + params))
                    else:
                        self.crawl_data.setdefault("params", {})[base] = params
                self.crawl_data.setdefault("links", []).append(url)
            console.print(f"[green][✓][/green] Katana: {len(new_urls)} URLs discovered")
            self._log_phase("Katana", "ok", f"{len(new_urls)} URLs")

    def phase_gau(self):
        """GAU — Get All URLs from Wayback Machine, CommonCrawl, AlienVault."""
        path = self._tool("gau")
        if not path or self.dry_run:
            return
        out_file = os.path.join(self.output_dir, "gau_urls.txt")
        cmd = [path, self.target, "--o", out_file, "--threads", "5", "--timeout", "30"]
        self.run_command(cmd, f"GAU historical URLs for {self.target}", "gau_log.txt")
        if os.path.isfile(out_file):
            with open(out_file) as f:
                urls = [l.strip() for l in f if l.strip().startswith("http")]
            # Extract params from historical URLs
            if not self.crawl_data:
                self.crawl_data = {"pages": [], "forms": [], "params": {}, "links": []}
            for url in urls:
                parsed = urllib.parse.urlparse(url)
                if parsed.query:
                    base = url.split("?")[0]
                    params = list(urllib.parse.parse_qs(parsed.query).keys())
                    existing = self.crawl_data.get("params", {}).get(base, [])
                    self.crawl_data.setdefault("params", {})[base] = list(set(existing + params))
            console.print(f"[green][✓][/green] GAU: {len(urls)} historical URLs ({len(self.crawl_data.get('params',{}))} param endpoints)")
            self._log_phase("GAU", "ok", f"{len(urls)} URLs")

    def phase_dalfox(self):
        """Dalfox — advanced XSS scanner with DOM analysis and WAF bypass."""
        path = self._tool("dalfox")
        if not path or self.dry_run or not self.crawl_data:
            return
        # Feed all parameterized URLs to dalfox
        param_urls = list(self.crawl_data.get("params", {}).keys())[:50]
        if not param_urls:
            return
        urls_file = os.path.join(self.output_dir, "dalfox_urls.txt")
        out_file = os.path.join(self.output_dir, "dalfox_results.json")
        with open(urls_file, "w") as f:
            f.write("\n".join(param_urls))
        cmd = [path, "file", urls_file, "--silence", "--format", "json",
               "--output", out_file, "--worker", "10", "--timeout", "10"]
        self.run_command(cmd, "Dalfox XSS scan", "dalfox_log.txt")
        if os.path.isfile(out_file):
            try:
                with open(out_file) as f:
                    for line in f:
                        if not line.strip():
                            continue
                        result = json.loads(line)
                        self.vulnerabilities.append({
                            "type": f"XSS (Dalfox: {result.get('type','reflected')})",
                            "severity": "high",
                            "url": result.get("data", result.get("proof", "")),
                            "detail": f"Dalfox confirmed XSS: {result.get('payload','')}",
                            "template": "apex-dalfox-xss",
                            "status": "VULNERABLE",
                        })
            except Exception:
                pass
            console.print(f"[green][✓][/green] Dalfox: scan complete")
            self._log_phase("Dalfox", "ok", "XSS scan")

    def phase_gospider(self):
        """GoSpider — fast web spider with JS parsing."""
        path = self._tool("gospider")
        if not path or self.dry_run or not self.web_targets:
            return
        out_dir = os.path.join(self.output_dir, "gospider")
        os.makedirs(out_dir, exist_ok=True)
        for target in self.web_targets[:3]:
            cmd = [path, "-s", target, "-d", "3", "-c", "10", "-t", "5",
                   "--js", "--sitemap", "--robots", "-o", out_dir, "-q"]
            self.run_command(cmd, f"GoSpider on {target[:40]}", "gospider_log.txt")
        # Parse output files
        new_urls = 0
        for fname in os.listdir(out_dir):
            fpath = os.path.join(out_dir, fname)
            if not os.path.isfile(fpath):
                continue
            with open(fpath) as f:
                for line in f:
                    # GoSpider output: [type] - URL
                    m = re.search(r'https?://\S+', line)
                    if m:
                        url = m.group()
                        parsed = urllib.parse.urlparse(url)
                        if parsed.query:
                            base = url.split("?")[0]
                            params = list(urllib.parse.parse_qs(parsed.query).keys())
                            if not self.crawl_data:
                                self.crawl_data = {"pages": [], "forms": [], "params": {}, "links": []}
                            existing = self.crawl_data.get("params", {}).get(base, [])
                            self.crawl_data.setdefault("params", {})[base] = list(set(existing + params))
                            new_urls += 1
        if new_urls:
            console.print(f"[green][✓][/green] GoSpider: {new_urls} parameterized URLs")
        self._log_phase("GoSpider", "ok", f"{new_urls} URLs")

    def phase_crlfuzz(self):
        """CRLFuzz — dedicated CRLF injection scanner."""
        path = self._tool("crlfuzz")
        if not path or self.dry_run or not self.web_targets:
            return
        targets_file = os.path.join(self.output_dir, "web_targets.txt")
        out_file = os.path.join(self.output_dir, "crlfuzz_results.txt")
        cmd = [path, "-l", targets_file, "-o", out_file, "-s"]
        self.run_command(cmd, "CRLFuzz scan", "crlfuzz_log.txt")
        if os.path.isfile(out_file):
            with open(out_file) as f:
                results = [l.strip() for l in f if l.strip()]
            for url in results:
                self.vulnerabilities.append({
                    "type": "CRLF Injection (CRLFuzz Confirmed)",
                    "severity": "high",
                    "url": url,
                    "detail": "CRLFuzz confirmed header injection",
                    "template": "apex-crlfuzz",
                    "status": "VULNERABLE",
                })
            if results:
                console.print(f"[green][✓][/green] CRLFuzz: {len(results)} CRLF injections found")
        self._log_phase("CRLFuzz", "ok", f"{len(results) if os.path.isfile(out_file) else 0} findings")

    def phase_dnsx(self):
        """DNSx — fast DNS resolution + wildcard detection for subdomains."""
        path = self._tool("dnsx")
        if not path or self.dry_run or not self.subdomains:
            return
        subs_file = os.path.join(self.output_dir, "subdomains.txt")
        out_file = os.path.join(self.output_dir, "dnsx_resolved.txt")
        cmd = [path, "-l", subs_file, "-o", out_file, "-silent", "-a", "-resp",
               "-wd"]  # wildcard detection
        self.run_command(cmd, "DNSx resolution", "dnsx_log.txt")
        if os.path.isfile(out_file):
            with open(out_file) as f:
                resolved = [l.strip().split()[0] for l in f if l.strip()]
            # Update subdomains with only resolved ones
            if resolved:
                console.print(f"[green][✓][/green] DNSx: {len(resolved)} subdomains resolve (wildcard filtered)")
        self._log_phase("DNSx", "ok", f"resolved")


SKULL_ASCII = r"""[bold red]
        ______________                    ______________
    ,===:'.,        `-.                .-'        ,.:===,
         `:.`---.___  `-.            .-'  ___,---':.`
           `:.      `--. `-.      .-' .--'      .:`
             `\.       `-.  `-..-'  .-'       ./'
      (,,(,   `\.        `-.    .-'        ./'   ,),),
    (,'  `\    `\.          `--'          ./'   /'  `,

    ██████████████████████████████████████████████████████
    ██                                                  ██
    ██    ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░    ██
    ██    ░   ▄████████████████████████████████▄   ░    ██
    ██    ░   ██  ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄  ██   ░    ██
    ██    ░   ██  ██  ╔══════════════════╗  ██  ██   ░    ██
    ██    ░   ██  ██  ║  ☠  APEX  CLI  ☠ ║  ██  ██   ░    ██
    ██    ░   ██  ██  ╚══════════════════╝  ██  ██   ░    ██
    ██    ░   ██  ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀  ██   ░    ██
    ██    ░   ▀████████████████████████████████▀   ░    ██
    ██    ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░    ██
    ██                                                  ██
    ██████████████████████████████████████████████████████

    (,'  `\    ./'   /'  `,        (,'  `\    ./'   /'  `,
      (,,(,   `\.        .--..--        ./'   ,),),
             ./'       .-'  .-'  `-.  `-.       `\.
           .:`      .--' .-'          `-. `--.      `:.`
         ,.:===,  .-'  ___,---':.`  `:.`---.___ `-.  ,===:'.,
        ______________                    ______________
[/bold red]
"""

_SCAN_DRAGON = [
    "                 /===-_---~~~~~~~~~------____                          ",
    "                |===-~___                _,-'                          ",
    "   -==/          `//~\\   ~~~~`---.___.-~~                             ",
    "______-==|         | |  \\           _-~`                              ",
    "  __--~~~  ,-/-==/  | |   `\\        ,'                                ",
    "_-~       /'    |  \\ / /      \\      /                                ",
    ".'        /       |   \\/' /        \\   /                              ",
    "/  ____  /         |    `.__/-~~ ~ \\ _ _/'  /          \\/'            ",
    "/-'~    ~~~~~---__  |     ~-/~         ( )   /'        _--~`           ",
    "                 \\_|      /        _) | ;  ),   __--~~                 ",
    "                   '~~--_/      _-~/- |/ \\   '-~ \\                    ",
    "                  {\\__--_/}    / \\_>-|)<__\\      \\                   ",
    "                  /'   (_/  _-~  | |__>--<__|      |                   ",
    "                 |0  0 _/) )-~     | |__>--<__|     |                  ",
    "                 / /~ ,_/       / /__>---<__/      |                   ",
    "                o o _//        /-~_>---<__-~      /                    ",
    "                (^(~          /~_>---<__-      _-~                     ",
    "               ,/|           /__>--<__/     _-~                        ",
    "            ,//('(          |__>--<__|     /                           ",
    "           ( ( '))          |__>--<__|    |                            ",
]
_dragon_line = 0


def show_banner():
    console.print(SKULL_ASCII, justify="center")
    console.print(Panel.fit(
        "[bold white]Apex CLI v9.0[/bold white]\n"
        "[dim]288 phases • Browser-confirmed • Zero false positives[/dim]\n"
        "[bold red]\"We don't knock.\"[/bold red]",
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
    # Check playwright
    table.add_row("playwright", "[green]found[/green]" if _has_playwright() else "[red]missing[/red]",
                  "pip install playwright" if not _has_playwright() else "chromium")
    console.print(table)


def _has_playwright():
    try:
        import playwright
        return True
    except ImportError:
        return False


def _has_ollama():
    try:
        import requests as _r
        _r.get("http://localhost:11434/api/tags", timeout=1)
        return True
    except Exception:
        return False


def take_screenshots(vulnerabilities, output_dir, console):
    """Take Playwright screenshots of every finding URL."""
    urls = list({v["url"] for v in vulnerabilities
                 if v.get("url","").startswith("http") and v.get("severity") in ("critical","high","medium")})
    if not urls:
        return {}
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return {}

    screenshots = {}
    screenshot_dir = os.path.join(output_dir, "screenshots")
    os.makedirs(screenshot_dir, exist_ok=True)

    console.print(f"[dim]Taking screenshots of {len(urls)} finding URLs...[/dim]")
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=["--no-sandbox","--disable-dev-shm-usage"])
            ctx = browser.new_context(ignore_https_errors=True, viewport={"width":1280,"height":800})
            page = ctx.new_page()
            for url in urls[:20]:  # Max 20 screenshots
                try:
                    safe = re.sub(r"[^\w]", "_", url)[:60]
                    path = os.path.join(screenshot_dir, f"{safe}.png")
                    page.goto(url, timeout=8000, wait_until="domcontentloaded")
                    page.screenshot(path=path, full_page=False)
                    screenshots[url] = path
                except Exception:
                    continue
            browser.close()
    except Exception:
        pass

    console.print(f"[green][✓][/green] {len(screenshots)} screenshots saved → {screenshot_dir}/")
    return screenshots


def report_sarif(vulnerabilities, output_dir, target):
    """Generate SARIF 2.1.0 output for CI/CD integration (GitHub Actions, Azure DevOps, etc.)."""
    _SEVERITY_MAP = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    rules = []
    results = []
    rule_ids = set()

    for v in vulnerabilities:
        rule_id = v.get("template", "") or re.sub(r'[^\w-]', '-', v.get("type", "unknown")).lower()
        if rule_id not in rule_ids:
            rule_ids.add(rule_id)
            rules.append({
                "id": rule_id,
                "name": v.get("type", "Unknown"),
                "shortDescription": {"text": v.get("type", "Unknown")},
                "fullDescription": {"text": v.get("detail", v.get("type", ""))[:500]},
                "defaultConfiguration": {"level": _SEVERITY_MAP.get(v.get("severity", "info"), "note")},
                "properties": {"security-severity": str(v.get("cvss_score", "5.0"))},
            })
        results.append({
            "ruleId": rule_id,
            "level": _SEVERITY_MAP.get(v.get("severity", "info"), "note"),
            "message": {"text": v.get("detail", v.get("type", "Finding"))[:1000]},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": v.get("url", target)}}}],
        })

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "apex-cli",
                    "version": "9.0",
                    "informationUri": "https://github.com/zanicool/apex-cli",
                    "rules": rules,
                }
            },
            "results": results,
        }],
    }

    out = os.path.join(output_dir, "report.sarif")
    with open(out, "w") as f:
        json.dump(sarif_doc, f, indent=2)
    console.print(f"[green][✓][/green] SARIF report → {out}")


def run_scan(target, dry_run=False, deep=False, report_formats=None, skip=None, auth=None, resume_dir=None, scope=None, workers=0, output_dir="", severity_filter=None, nuclei_tags=None, recon_only=False, no_recon=False, sarif=False):
    # Auto-tune on first run
    try:
        from benchmark import get_settings, apply_settings
        bm = get_settings()
        apply_settings(bm)
        # Use benchmark workers if not overridden by user
        if workers == 0 and bm.get("workers"):
            workers = bm["workers"]
        # Use benchmark AI model
        if bm.get("ai_model"):
            try:
                import apex_ai as _ai
                _ai.MODEL = bm["ai_model"]
                _ai.AI_WORKERS = bm.get("ai_workers", 3)
            except Exception:
                pass
    except Exception:
        pass
    report_formats = report_formats or ["terminal"]
    skip = [s.lower() for s in (skip or [])]
    severity_filter = severity_filter or []
    nuclei_tags = nuclei_tags or []
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    scan_output_dir = output_dir if output_dir else f"scan_{target}_{ts}"
    if resume_dir:
        scan_output_dir = resume_dir
    global _dragon_line; _dragon_line = 0
    apex = ApexCLI(target, scan_output_dir, dry_run=dry_run, deep=deep, auth=auth)
    apex.scope = scope or []
    apex.nuclei_tags = nuclei_tags or []
    if resume_dir and apex._load_state():
        completed_phases = {p["phase"] for p in apex.phase_results}
        console.print(f"[green][✓][/green] Resumed — {len(completed_phases)} phases already done")
    else:
        completed_phases = set()

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
        ("Passive Recon", apex.phase_passive_recon),
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
        ("CORS Null Origin", apex.phase_cors_null_origin),
        ("Method Override", apex.phase_method_override),
        ("Cookie Injection", apex.phase_cookie_injection),
        ("Host Override Chain", apex.phase_host_override_chain),
        ("VHost Fuzzing", apex.phase_vhost_fuzzing),
        ("Subdomain Permutation", apex.phase_subdomain_permutation),
        ("H2C Smuggling", apex.phase_h2c_smuggling),
        ("EL Injection", apex.phase_expression_language_injection),
        ("PHP Object Injection", apex.phase_php_object_injection),
        ("Cache Key Injection", apex.phase_cache_key_injection),
        ("Link Injection", apex.phase_link_injection),
        ("Price Manipulation", apex.phase_price_manipulation),
        ("Payment Flow Bypass", apex.phase_payment_flow_bypass),
        ("Account State Manipulation", apex.phase_account_state_manipulation),
        ("Forced Browsing", apex.phase_forced_browsing),
        ("Parameter Tampering", apex.phase_parameter_tampering),
        ("Multi-Step Race", apex.phase_multi_step_race),
        ("Multi-Step Auth Flow", apex.phase_multi_step_auth_flow),
        ("GraphQL Field Enumeration", apex.phase_graphql_field_enumeration),
        ("API Version Enumeration", apex.phase_api_version_enumeration),
        ("Legacy Endpoints", apex.phase_legacy_endpoints),
        ("IDOR Horizontal/Vertical", apex.phase_idor_horizontal_vertical),
        ("JWT Secret Bruteforce", apex.phase_jwt_secret_bruteforce),
        ("CORS Subdomain Wildcard", apex.phase_cors_subdomain_wildcard),
        ("BOPLA", apex.phase_bopla),
        ("API Key in URL", apex.phase_api_key_in_url),
        ("Insecure File Download", apex.phase_insecure_file_download),
        ("Prototype Pollution Path", apex.phase_prototype_pollution_path),
        ("Mass Assignment PATCH", apex.phase_mass_assignment_patch),
        ("Subdomain Takeover Deep", apex.phase_subdomain_takeover_deep),
        ("Account Takeover Vectors", apex.phase_account_takeover_vectors),
        ("OAuth Deep", apex.phase_oauth_deep),
        ("XXE File Upload", apex.phase_xxe_file_upload),
        ("SSRF Redirect Chain", apex.phase_ssrf_redirect_chain),
        ("JWT kid Injection", apex.phase_jwt_kid_injection),
        ("Rate Limit Bypass Headers", apex.phase_rate_limit_bypass_headers),
        ("IDOR JSON Body", apex.phase_idor_json_body),
        ("Auth Bypass Content-Type", apex.phase_auth_bypass_content_type),
        ("SSRF via SVG", apex.phase_ssrf_via_svg),
        ("Unkeyed Cache Poisoning", apex.phase_unkeyed_cache_poisoning),
        ("GraphQL Alias Introspection", apex.phase_graphql_alias_introspection),
        ("NoSQL Operator Injection", apex.phase_nosql_operator_injection),
        ("LDAP Injection", apex.phase_ldap_injection),
        ("Template Injection Twig", apex.phase_template_injection_twig),
        ("WebSocket Origin Bypass", apex.phase_websocket_origin_bypass),
        ("Server Timing Oracle", apex.phase_server_timing_oracle),
        ("CSP Bypass JSONP", apex.phase_csp_bypass_jsonp),
        ("API Key Rotation Bypass", apex.phase_api_key_rotation_bypass),
        ("GraphQL Circular Fragment", apex.phase_graphql_circular_fragment),
        ("HTTP Desync TE.TE", apex.phase_http_desync_te_te),
        ("IDOR Batch API", apex.phase_idor_batch_api),
        ("GraphQL Persisted Query", apex.phase_graphql_persisted_query),
        ("XXE Parameter Entity", apex.phase_xxe_parameter_entity),
        ("Open Redirect Meta", apex.phase_open_redirect_meta),
        ("CORS With Credentials", apex.phase_cors_with_credentials),
        ("Clickjacking Advanced", apex.phase_clickjacking_advanced),
        ("Subdomain NS Takeover", apex.phase_subdomain_ns_takeover),
        ("Password Spray", apex.phase_password_spray),
        ("GraphQL Injection", apex.phase_graphql_injection),
        ("Broken Function Level Auth", apex.phase_broken_function_level_auth),
        ("Mass User Enumeration", apex.phase_mass_user_enumeration),
        ("CORS Vary Origin", apex.phase_cors_vary_origin),
        ("Insecure JWT Storage", apex.phase_insecure_jwt_storage),
        ("2FA Bypass Response", apex.phase_2fa_bypass_response),
        ("Account Pre-Hijacking", apex.phase_account_prehijacking),
        ("HTTP Request Splitting", apex.phase_http_request_splitting),
        ("XS-Leaks", apex.phase_xs_leaks),
        ("OAuth Token Fixation", apex.phase_oauth_token_fixation),
        ("API Key in Headers", apex.phase_api_key_in_headers),
        ("IDOR GraphQL", apex.phase_idor_graphql),
        ("Subdomain A Record Takeover", apex.phase_subdomain_a_record_takeover),
        ("Insecure Deserialization Patterns", apex.phase_insecure_deserialization_patterns),
        ("HTTP/2 Push Abuse", apex.phase_http2_push_abuse),
        ("SAML Replay", apex.phase_saml_replay),
        ("Iframe Injection", apex.phase_iframe_injection),
        # Batch 17 — v9.0
        ("CSTI Angular", apex.phase_csti_angular),
        ("Server Prototype Pollution", apex.phase_server_prototype_pollution),
        ("HTTP/3 QUIC Probe", apex.phase_http3_quic_probe),
        ("GraphQL Subscription Abuse", apex.phase_graphql_subscription_abuse),
        ("GraphQL Batching Rate Bypass", apex.phase_graphql_batching_rate_bypass),
        ("BOLA UUID v1 Prediction", apex.phase_bola_uuid_v1_timestamp),
        # Batch 18 — Power
        ("Differential Auth Analysis", apex.phase_differential_auth),
        ("Hidden Param Discovery", apex.phase_param_discovery),
        ("Response Manipulation ATO", apex.phase_response_manipulation_ato),
        ("Race Condition Critical", apex.phase_race_condition_critical),
        ("Second-Order Detection", apex.phase_second_order_detection),
        # Batch 19 — Elite
        ("DOM XSS Browser", apex.phase_dom_xss_browser),
        ("postMessage Browser", apex.phase_postmessage_browser),
        ("Tech-Specific Attacks", apex.phase_tech_specific),
        ("SSRF → Cloud Credential Chain", apex.phase_exploit_chain_ssrf_to_cloud),
        # Batch 20 — Enhanced core
        ("XSS Browser Confirmed", apex.phase_xss_browser_confirmed),
        ("SQLi Error Pattern", apex.phase_sqli_error_pattern),
        ("Blind SQLi Timing", apex.phase_blind_sqli_timing),
        ("Open Redirect → OAuth Chain", apex.phase_open_redirect_chain_oauth),
        # Batch 21 — SPA/API/JWT/WS
        ("SPA Crawl", apex.phase_crawl_spa),
        ("OpenAPI Fuzz", apex.phase_openapi_fuzz),
        ("JWT Full Attack", apex.phase_jwt_full_attack),
        ("WebSocket Inject", apex.phase_websocket_inject),
        ("Email Header Inject", apex.phase_email_header_inject),
        # Batch 22
        ("Subdomain Takeover v2", apex.phase_subdomain_takeover_v2),
        ("GraphQL Field Suggest", apex.phase_graphql_field_suggest),
        ("Cookie Tossing", apex.phase_cookie_tossing),
        # Batch 23
        ("SSTI Smart", apex.phase_ssti_smart),
        ("IDOR Auto", apex.phase_idor_auto),
        ("Path Traversal Bypass", apex.phase_path_traversal_bypass),
        # Batch 24
        ("HTTP Smuggling Detect", apex.phase_http_smuggling_detect),
        ("Privilege Escalation", apex.phase_privilege_escalation),
        ("API Version Bypass", apex.phase_api_versioning_bypass),
        # Batch 25
        ("CORS PoC Generator", apex.phase_cors_generate_poc),
        ("JS Secrets Deep", apex.phase_js_secrets_deep),
        ("HTTP Param Pollution", apex.phase_hpp),
        ("Cache Poisoning Unkeyed", apex.phase_cache_poisoning_unkeyed),
        ("CRLF Advanced", apex.phase_crlf_advanced),
        ("403 Bypass Advanced", apex.phase_403_bypass_advanced),
        ("Sensitive Data Exposure", apex.phase_sensitive_data_exposure),
        # Batch 26
        ("BFLA", apex.phase_bfla),
        ("Endpoint Discovery", apex.phase_endpoint_discovery),
        ("Content-Type Confusion", apex.phase_content_type_confusion),
        ("Timing Attacks", apex.phase_timing_attacks),
        # Batch 28
        ("Payment Logic Deep", apex.phase_payment_logic_deep),
        ("Registration Abuse", apex.phase_registration_abuse),
        ("API Abuse Patterns", apex.phase_api_abuse_patterns),
        ("Account Takeover Flows", apex.phase_account_takeover_flows),
        # Batch 29
        ("File Upload Bypass", apex.phase_file_upload_bypass),
        ("Deserialization RCE", apex.phase_deserialization_rce),
        ("Host Header Poison", apex.phase_host_header_poison),
        ("GraphQL Deep Exploit", apex.phase_graphql_deep_exploit),
        # Batch 30
        ("Response Oracle", apex.phase_response_oracle),
        ("Mutation Fuzzer", apex.phase_mutation_fuzzer),
        ("Access Control Matrix", apex.phase_access_control_matrix),
        ("Business Flow Abuse", apex.phase_business_flow_abuse),
        # Batch 31
        ("Entropy Analysis", apex.phase_entropy_analysis),
        ("State Machine Inference", apex.phase_state_machine_inference),
        ("Information Leakage Differential", apex.phase_information_leakage_differential),
        ("Race Window Exploitation", apex.phase_race_window_exploitation),
        # Batch 32
        ("Compression Oracle", apex.phase_compression_oracle),
        ("Cache Timing Oracle", apex.phase_cache_timing_oracle),
        ("Polynomial Fingerprint", apex.phase_polynomial_fingerprint),
        ("Markov Prediction", apex.phase_markov_prediction),
        # Batch 33 — OOB
        ("Blind XSS OOB", apex.phase_blind_xss_oob),
        ("SSRF via OOB Redirect", apex.phase_ssrf_via_oob_redirect),
        ("DNS Exfil SQLi", apex.phase_dns_exfil_sqli),
        # Batch 34
        ("XXE OOB Exfil", apex.phase_xxe_oob_exfil),
        ("SSRF Port Scan OOB", apex.phase_ssrf_port_scan_oob),
        ("Blind RCE OOB", apex.phase_blind_rce_oob),
        ("Log4Shell OOB", apex.phase_log4shell_oob),
        # Batch 35 — Crawl improvements
        ("API Inference", apex.phase_infer_api_endpoints),
        ("JS Route Extraction", apex.phase_extract_js_routes),
        ("Auth Chain Test", apex.phase_auth_chain_test),
        # Batch 36
        ("NoSQL Deep", apex.phase_nosql_deep),
        ("Prototype Pollution Exploit", apex.phase_prototype_pollution_exploit),
        ("CL.0 Smuggling", apex.phase_cl0_smuggling),
        ("CT Realtime Subdomains", apex.phase_subdomain_ct_realtime),
        # Batch 37
        ("LDAP Deep", apex.phase_ldap_deep),
        ("XML Injection", apex.phase_xml_injection),
        ("HTTP/2 Exclusive", apex.phase_http2_exclusive),
        ("Token Manipulation", apex.phase_token_manipulation),
        # Batch 38
        ("Webhook Abuse", apex.phase_webhook_abuse),
        ("S3 Bucket Takeover", apex.phase_s3_bucket_takeover),
        ("Input Length Overflow", apex.phase_input_length_overflow),
        ("GraphQL DoS", apex.phase_graphql_dos),
        # Todo #1-#10
        ("OAuth2 Full Exploit", apex.phase_oauth2_full_exploit),
        ("GraphQL Batch Mutation", apex.phase_graphql_batch_mutation),
        ("PDF SSRF", apex.phase_pdf_ssrf),
        ("Markdown XSS", apex.phase_markdown_xss),
        ("Password Reset Prediction", apex.phase_password_reset_prediction),
        ("API Key Scope Test", apex.phase_api_key_scope),
        # Batch 41
        ("CSWSH", apex.phase_cswsh),
        ("SVG XSS Upload", apex.phase_svg_xss_upload),
        ("IDOR GraphQL Node", apex.phase_idor_graphql_node),
        ("Mass Assignment PATCH Deep", apex.phase_mass_assignment_patch),
        ("Race 2FA", apex.phase_race_2fa),
        # Batch 42
        ("Git Exposure", apex.phase_git_exposure),
        ("Env Leak", apex.phase_env_leak),
        ("Firebase Misconfig Deep", apex.phase_firebase_misconfig_deep),
        ("Terraform State", apex.phase_terraform_state),
        ("Docker Registry", apex.phase_docker_registry),
        ("K8s Dashboard", apex.phase_k8s_dashboard),
        ("CI/CD Exposure", apex.phase_cicd_exposure),
        ("Jupyter Exposure", apex.phase_jupyter_exposure),
        ("WP User Enum", apex.phase_wp_user_enum),
        # External tools
        ("Katana Crawl", apex.phase_katana_crawl),
        ("GAU", apex.phase_gau),
        ("Dalfox", apex.phase_dalfox),
        # More external tools
        ("GoSpider", apex.phase_gospider),
        ("CRLFuzz", apex.phase_crlfuzz),
        ("DNSx Resolve", apex.phase_dnsx),
    ]

    # Print dragon art before scan starts
    console.print()
    for line in _SCAN_DRAGON:
        console.print(f"[bold red]{line}[/bold red]", justify="center")
    console.print()

    # Measure target response time and adapt concurrency
    workers = workers if workers > 0 else 15  # default (up from 8)
    if not dry_run and apex.web_targets:
        import time as _t
        try:
            t0 = _t.time()
            requests.get(apex.web_targets[0], timeout=5, verify=False)
            resp_time = _t.time() - t0
            if resp_time < 0.2:
                workers = 25   # very fast target — max parallelism
            elif resp_time < 0.5:
                workers = 18   # fast target
            elif resp_time < 1.0:
                workers = 12   # normal
            elif resp_time < 3.0:
                workers = 6    # slow target
            else:
                workers = 3    # very slow — be gentle
            console.print(f"[dim]Target response: {resp_time:.2f}s → {workers} parallel workers[/dim]")
        except Exception:
            pass

    SEQUENTIAL = {"Recon", "Passive Recon", "Subdomain Brute-Force", "Subdomain Permutation", "Probe", "Fingerprint", "Fuzz", "Crawl", "SPA Crawl", "API Inference", "JS Route Extraction", "Katana Crawl", "GAU"}
    seq_phases = [(l, f) for l, f in phases if l in SEQUENTIAL]
    par_phases = [(l, f) for l, f in phases if l not in SEQUENTIAL]

    # --recon-only: only run sequential recon phases
    if recon_only:
        par_phases = []
        console.print("[dim]Recon-only mode: skipping active scanning[/dim]")

    # --no-recon: skip recon, go straight to scanning
    if no_recon:
        seq_phases = [(l, f) for l, f in seq_phases if l not in {"Recon", "Passive Recon", "Subdomain Brute-Force", "Subdomain Permutation"}]
        # Add target directly as web target
        if not apex.web_targets:
            apex.web_targets = [f"https://{target}"]
        console.print("[dim]No-recon mode: scanning target directly[/dim]")

    from concurrent.futures import ThreadPoolExecutor, as_completed

    def run_phase(label, fn):
        if label.lower() in skip:
            apex._log_phase(label, "skipped", "user --skip")
            return label, None
        if label in completed_phases:
            return label, None  # already done in previous run
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
        # Load dragon ASCII art
        try:
            from dragon import DRAGON
        except ImportError:
            DRAGON = []
        _dragon_idx = 0

        for label, fn in seq_phases:
            task = progress.add_task(f"[cyan]{label}...", total=1)
            _, err = run_phase(label, fn)
            if err:
                console.print(f"[red][!] {label} failed: {err}[/red]")
            progress.update(task, completed=1)
            # Reveal dragon line by line as phases complete
            if DRAGON and _dragon_idx < len(DRAGON):
                console.print(f"[bold red]{DRAGON[_dragon_idx]}[/bold red]")
                _dragon_idx += 1
            # After fingerprint: smart skip irrelevant phases + inject tech-specific
            if label == "Fingerprint":
                tech = " ".join(apex.technologies).lower()
                waf = " ".join(apex.waf_detected).lower()

                # WAF detected → enable bypass mode
                if waf:
                    import scanners as _sc
                    _sc._WAF_BYPASS_MODE = True
                    console.print(f"[yellow][!][/yellow] WAF bypass mode enabled for: {', '.join(apex.waf_detected)}")

                # React/Next.js → prioritize DOM XSS, prototype pollution
                if any(x in tech for x in ["react","next.js","nextjs","vue","angular","nuxt"]):
                    console.print(f"[green][+][/green] SPA detected — prioritizing client-side attacks")
                    priority = {"Context XSS", "Deep XSS", "Prototype Pollution JSON",
                                "Prototype Pollution Path", "Next.js/React Vulns",
                                "DOM XSS Browser", "postMessage Browser",
                                "XSS Browser Confirmed", "CSTI Angular",
                                "Postmessage Abuse", "SPA Crawl"}
                    par_phases[:] = (
                        [(l,f) for l,f in par_phases if l in priority] +
                        [(l,f) for l,f in par_phases if l not in priority]
                    )

            if label == "Fingerprint" and apex.technologies:
                tech = " ".join(apex.technologies).lower()
                extra = []
                if "wordpress" in tech:
                    extra += [("WP User Enum", lambda: _run_wp_enum(apex))]
                if any(x in tech for x in ["spring", "java", "tomcat"]):
                    extra += [("Spring Actuator Deep", lambda: _run_spring_deep(apex))]
                if any(x in tech for x in ["laravel", "php"]):
                    extra += [("Laravel Secrets", lambda: _run_laravel_secrets(apex))]
                if "graphql" in tech or any("/graphql" in t for t in apex.web_targets):
                    extra += [("GraphQL Deep", apex.phase_graphql_advanced)]
                if extra:
                    console.print(f"[bold green][+][/bold green] Tech detected: {', '.join(apex.technologies)} — adding {len(extra)} targeted phases")
                    par_phases.extend(extra)
            # After WAF detection: switch to bypass payloads
            if label == "Fingerprint" and apex.waf_detected:
                console.print(f"[bold yellow][!][/bold yellow] WAF detected: {', '.join(apex.waf_detected)} — enabling bypass encodings")
                import scanners as _sc
                _sc._WAF_BYPASS_MODE = True

        workers = min(workers, len(par_phases))
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
                # Continue revealing dragon
                if DRAGON and _dragon_idx < len(DRAGON):
                    console.print(f"[bold red]{DRAGON[_dragon_idx]}[/bold red]")
                    _dragon_idx += 1

    # Feedback loop: findings from earlier phases feed into targeted follow-up
    sqli_urls = [v["url"] for v in apex.vulnerabilities
                 if "sql" in v.get("type","").lower()
                 and v.get("url","").startswith("http")
                 and "?" in v.get("url","")  # Only URLs with actual params
                 and v.get("severity") == "critical"]  # Only confirmed criticals
    if sqli_urls and not dry_run:
        sqlmap_path = apex._tool("sqlmap")
        if sqlmap_path:
            console.print(f"[bold red][+][/bold red] SQLi confirmed on {len(sqli_urls)} URLs — running sqlmap for exploitation")
            for url in sqli_urls[:3]:
                safe = re.sub(r"[^\w]", "_", url)
                cmd = [sqlmap_path, "-u", url, "--batch", "--dbs",
                       "--random-agent", "--level", "3", "--risk", "2",
                       "--output-dir", apex.output_dir]
                apex.run_command(cmd, f"SQLMap exploitation → {url[:50]}", f"sqlmap_exploit_{safe[:30]}.txt")

    ssrf_urls = [v["url"] for v in apex.vulnerabilities
                 if "ssrf" in v.get("type","").lower() and v.get("url","").startswith("http")]
    if ssrf_urls and apex.oob and not dry_run:
        console.print(f"[bold red][+][/bold red] SSRF found — running OOB confirmation on {len(ssrf_urls)} URLs")
        from scanners import scan_blind_ssrf_oob
        oob_findings = scan_blind_ssrf_oob({"params": {u: ["url","src","dest"] for u in ssrf_urls},
                                             "forms": []}, apex.oob)
        with apex._vuln_lock:
            apex.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in oob_findings)

    if apex.oob:
        apex.oob.stop()

    # Intelligence engine: dedup → filter theoretical → verify → score → chain detection
    console.print("[dim]Running intelligence engine...[/dim]")
    apex.vulnerabilities = deduplicate_findings(apex.vulnerabilities)
    # Remove theoretical/informational findings that aren't exploitable
    before_filter = len(apex.vulnerabilities)
    apex.vulnerabilities = filter_exploitable_only(apex.vulnerabilities)
    theoretical_dropped = before_filter - len(apex.vulnerabilities)
    if theoretical_dropped:
        console.print(f"[dim]Dropped {theoretical_dropped} theoretical/informational findings[/dim]")
    if not dry_run:
        verified = []
        for f in apex.vulnerabilities:
            if verify_finding(f):
                verified.append(f)
        dropped = len(apex.vulnerabilities) - len(verified)
        if dropped:
            console.print(f"[yellow][!] Dropped {dropped} unverified/false positives[/yellow]")
        apex.vulnerabilities = verified
    apex.vulnerabilities = score_findings(apex.vulnerabilities,
                                          technologies=apex.technologies,
                                          waf_detected=apex.waf_detected)
    # Add reproducible PoC commands to every finding
    apex.vulnerabilities = enrich_findings_with_poc(apex.vulnerabilities)
    chains = detect_attack_chains(apex.vulnerabilities)
    if chains:
        console.print(f"[bold red]🔗 {len(chains)} attack chain(s) detected![/bold red]")
        apex.vulnerabilities = chains + apex.vulnerabilities

    # Feedback loop: use confirmed findings to launch deeper attacks
    if not dry_run and apex.vulnerabilities:
        console.print("[bold red]⚡ Feedback loop — pivoting through confirmed findings...[/bold red]")
        pivot_findings = feedback_loop_attack(apex.vulnerabilities, apex.crawl_data or {}, apex.web_targets)
        if pivot_findings:
            console.print(f"[bold red]🎯 {len(pivot_findings)} new findings from pivoting![/bold red]")
            verified_pivots = [f for f in pivot_findings if verify_finding(f)]
            apex.vulnerabilities.extend(verified_pivots)
            apex.vulnerabilities = score_findings(apex.vulnerabilities,
                                                  technologies=apex.technologies,
                                                  waf_detected=apex.waf_detected)
            apex.vulnerabilities = enrich_findings_with_poc(apex.vulnerabilities)

    # Safe exploitation: prove criticals are real without causing harm
    if not dry_run and apex.vulnerabilities:
        criticals = [v for v in apex.vulnerabilities if v.get("severity") in ("critical", "high")]
        if criticals:
            console.print(f"[bold red]🔓 Safe exploitation — proving {len(criticals)} critical/high findings...[/bold red]")
            exploited = llm_safe_exploit(apex.vulnerabilities, apex.web_targets)
            if exploited:
                console.print(f"[bold green]✓ {len(exploited)} findings PROVEN exploitable:[/bold green]")
                for e in exploited:
                    console.print(f"  [bold red]EXPLOITED[/bold red] {e['type'][:50]}")
                    console.print(f"    [dim]Proof: {e.get('exploit_proof', '')[:80]}[/dim]")
                # Update findings with exploitation proof
                for e in exploited:
                    for v in apex.vulnerabilities:
                        if v.get("url") == e.get("url") and v.get("type") == e.get("type"):
                            v["exploited"] = True
                            v["exploit_proof"] = e.get("exploit_proof", "")
                            v["impact_proven"] = e.get("impact_proven", "")
                            break

    # Screenshots of all medium+ findings
    screenshots = {}
    if not dry_run:
        screenshots = take_screenshots(apex.vulnerabilities, scan_output_dir, console)
        # Attach screenshot paths to findings for HTML report
        for v in apex.vulnerabilities:
            if v.get("url") in screenshots:
                v["screenshot"] = screenshots[v["url"]]

    # Filter by severity if requested
    if severity_filter:
        apex.vulnerabilities = [v for v in apex.vulnerabilities
                                if v.get("severity") in severity_filter]

    # Reports
    apex.report_terminal()
    if "json" in report_formats:
        apex.report_json()
    if "html" in report_formats:
        apex.report_html()
    if sarif:
        report_sarif(apex.vulnerabilities, scan_output_dir, target)

    # AI analysis — runs inline, streams to terminal
    if not dry_run:
        try:
            import requests as _r
            _r.get("http://localhost:11434/api/tags", timeout=2)
            sys.path.insert(0, str(Path(__file__).parent))
            import apex_ai as _ai
            _ai.ai_continue_scan(scan_output_dir, auto_test=False)
        except Exception:
            pass  # Ollama not running — skip silently




def interactive_menu():
    """Full interactive TUI when apex-cli is run with no arguments."""
    from rich.prompt import Prompt, Confirm
    from rich.columns import Columns

    show_banner()

    while True:
        console.print()
        console.print(Panel.fit(
            "[bold red]1[/bold red] Scan a target\n"
            "[bold red]2[/bold red] Deep scan (all 288 phases + browser)\n"
            "[bold red]3[/bold red] Auto-scan bug bounty targets\n"
            "[bold red]4[/bold red] View scan results / hits\n"
            "[bold red]5[/bold red] Scan history\n"
            "[bold red]6[/bold red] Resume last scan\n"
            "[bold red]7[/bold red] Compare two scans (diff)\n"
            "[bold red]8[/bold red] Scan APK file\n"
            "[bold red]9[/bold red] Show installed tools\n"
            "[bold red]0[/bold red] Exit",
            title="[bold white]☠ APEX CLI v9.0[/bold white]",
            border_style="red"
        ))

        choice = Prompt.ask("[bold cyan]Select[/bold cyan]", choices=["1","2","3","4","5","6","7","8","9","0"], default="1")

        if choice == "1":
            target = Prompt.ask("[bold cyan]Target domain/IP[/bold cyan]").strip()
            if not target: continue
            try:
                target = validate_target(target)
            except SystemExit:
                continue
            report_fmt = Prompt.ask("Report format", choices=["terminal","json","html","all"], default="all")
            formats = ["terminal", "json", "html"] if report_fmt == "all" else [report_fmt]
            console.print()
            run_scan(target, deep=False, report_formats=formats, auth=None, scope=[], sarif=True)

        elif choice == "2":
            target = Prompt.ask("[bold cyan]Target domain/IP[/bold cyan]").strip()
            if not target: continue
            try:
                target = validate_target(target)
            except SystemExit:
                continue
            auth = None
            if Confirm.ask("Authenticated scan?", default=False):
                user = Prompt.ask("Username/email")
                pwd = Prompt.ask("Password", password=True)
                auth = (user, pwd)
            console.print()
            run_scan(target, deep=True, report_formats=["terminal", "json", "html"],
                     auth=auth, scope=[], sarif=True)

        elif choice == "3":
            console.print("[bold yellow]Starting auto-scan of bug bounty targets...[/bold yellow]")
            console.print("[dim]Press Ctrl+C to stop[/dim]")
            try:
                subprocess.run([sys.executable,
                    str(Path(__file__).parent / "apex-auto.py"), "--bounty"])
            except KeyboardInterrupt:
                console.print("\n[yellow]Stopped.[/yellow]")

        elif choice == "4":
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

        elif choice == "5":
            # Scan history — list all scan directories
            import glob as _g
            scan_dirs = sorted(_g.glob("scan_*"), key=os.path.getmtime, reverse=True)
            if not scan_dirs:
                scan_dirs = sorted(_g.glob(str(Path.home() / "apex-auto-results" / "scan_*")),
                                   key=os.path.getmtime, reverse=True)
            if not scan_dirs:
                console.print("[yellow]No scan history found.[/yellow]")
                continue
            t = Table(title=f"Scan History ({len(scan_dirs)} scans)")
            t.add_column("#", style="dim")
            t.add_column("Target", style="cyan")
            t.add_column("Date", style="dim")
            t.add_column("Findings", style="red")
            for i, d in enumerate(scan_dirs[:20], 1):
                name = os.path.basename(d)
                parts = name.replace("scan_", "").rsplit("_", 2)
                target_name = parts[0] if parts else name
                report = os.path.join(d, "report.json")
                vuln_count = "—"
                if os.path.isfile(report):
                    try:
                        data = json.load(open(report))
                        vuln_count = str(len(data.get("vulnerabilities", [])))
                    except Exception:
                        pass
                mtime = datetime.fromtimestamp(os.path.getmtime(d)).strftime("%Y-%m-%d %H:%M")
                t.add_row(str(i), target_name[:40], mtime, vuln_count)
            console.print(t)

        elif choice == "6":
            # Resume last scan
            import glob as _g
            scan_dirs = sorted(_g.glob("scan_*"), key=os.path.getmtime, reverse=True)
            if not scan_dirs:
                console.print("[yellow]No scans to resume.[/yellow]")
                continue
            last = scan_dirs[0]
            state_file = os.path.join(last, ".apex_state.json")
            if not os.path.isfile(state_file):
                console.print(f"[yellow]No state file in {last}[/yellow]")
                continue
            state = json.load(open(state_file))
            target = state["target"]
            completed = len(state.get("phase_results", []))
            console.print(f"[bold yellow]Resuming {target} from {last} ({completed} phases done)[/bold yellow]")
            run_scan(target, report_formats=["terminal", "json", "html"],
                     resume_dir=last, sarif=True)

        elif choice == "7":
            # Diff two scans
            import glob as _g
            scan_dirs = sorted(_g.glob("scan_*"), key=os.path.getmtime, reverse=True)
            if len(scan_dirs) < 2:
                console.print("[yellow]Need at least 2 scans to compare.[/yellow]")
                continue
            console.print("[dim]Recent scans:[/dim]")
            for i, d in enumerate(scan_dirs[:10], 1):
                console.print(f"  {i}. {os.path.basename(d)}")
            s1 = Prompt.ask("First scan #", default="2")
            s2 = Prompt.ask("Second scan #", default="1")
            try:
                dir1 = scan_dirs[int(s1)-1]
                dir2 = scan_dirs[int(s2)-1]
                diff_scans(dir1, dir2, console)
            except (IndexError, ValueError):
                console.print("[red]Invalid selection.[/red]")

        elif choice == "8":
            apk_path = Prompt.ask("[bold cyan]APK file path[/bold cyan]").strip()
            if apk_path:
                scan_apk(apk_path, console)

        elif choice == "9":
            show_tools()
            # Also show scan stats
            console.print()
            console.print(f"[bold white]Scanner Stats:[/bold white]")
            console.print(f"  Phases: 288")
            console.print(f"  Scanners: 250+")
            console.print(f"  Browser: {'[green]Playwright + Chromium[/green]' if _has_playwright() else '[red]Not installed[/red]'}")
            console.print(f"  AI: {'[green]Available[/green]' if _has_ollama() else '[yellow]Ollama not running[/yellow]'}")

        elif choice == "0":
            console.print("[bold red]Goodbye.[/bold red]")
            break


def scan_apk(apk_path, console):
    """Decompile APK with jadx and extract endpoints, API keys, hardcoded secrets."""
    import subprocess as _sp, tempfile, shutil

    if not os.path.isfile(apk_path):
        console.print(f"[red]APK not found: {apk_path}[/red]")
        return

    jadx = shutil.which("jadx") or shutil.which("jadx-gui")
    if not jadx:
        console.print("[yellow]jadx not found. Install: https://github.com/skylot/jadx/releases[/yellow]")
        console.print("[dim]Trying strings-based extraction instead...[/dim]")
        _apk_strings_scan(apk_path, console)
        return

    console.print(f"[bold red]☠ APK SCAN: {os.path.basename(apk_path)}[/bold red]")
    with tempfile.TemporaryDirectory() as tmpdir:
        console.print(f"[dim]Decompiling with jadx...[/dim]")
        result = _sp.run([jadx, "-d", tmpdir, apk_path], capture_output=True, timeout=120)
        if result.returncode != 0:
            console.print("[yellow]jadx decompilation had errors, scanning partial output[/yellow]")

        findings = []
        patterns = {
            "API Key (AWS)": re.compile(r"AKIA[0-9A-Z]{16}"),
            "API Key (Google)": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
            "API Key (Stripe)": re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
            "GitHub Token": re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"),
            "Private Key": re.compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----"),
            "JWT Secret": re.compile(r'(?:secret|SECRET|jwt_secret)["\'\s]*[:=]["\'\s]*([A-Za-z0-9+/=_\-]{16,})'),
            "Hardcoded Password": re.compile(r'(?:password|passwd|pwd)["\'\s]*[:=]["\'\s]*["\'"]([^"\']{8,})["\'"]'),
            "API Endpoint": re.compile(r'https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:/[^\s"\'<>]{3,60})?'),
            "Internal URL": re.compile(r'https?://(?:localhost|127\.0\.0\.1|10\.|192\.168\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[01]\.)[^\s"\'<>]+'),
        }

        seen = set()
        for root, _, files in os.walk(tmpdir):
            for fname in files:
                if not fname.endswith((".java", ".kt", ".xml", ".json", ".properties", ".gradle")):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    content = open(fpath, errors="ignore").read()
                    for pname, pattern in patterns.items():
                        for match in pattern.finditer(content):
                            val = match.group()[:80]
                            key = f"{pname}:{val[:30]}"
                            if key not in seen:
                                seen.add(key)
                                findings.append({"type": pname, "value": val,
                                                 "file": os.path.relpath(fpath, tmpdir)})
                except Exception:
                    continue

        # Display results
        from rich.table import Table
        t = Table(title=f"APK Findings: {os.path.basename(apk_path)}")
        t.add_column("Type", style="red")
        t.add_column("Value", style="cyan")
        t.add_column("File", style="dim")
        for f in findings[:50]:
            t.add_row(f["type"], f["value"][:60], f["file"][:50])
        console.print(t)
        console.print(f"[green][✓][/green] {len(findings)} findings in APK")

        # Save report
        out = apk_path + "_apex_scan.json"
        import json as _j
        _j.dump(findings, open(out, "w"), indent=2)
        console.print(f"[green][✓][/green] Saved → {out}")


def _apk_strings_scan(apk_path, console):
    """Fallback: extract strings from APK without jadx."""
    import subprocess as _sp, zipfile
    findings = []
    patterns = {
        "API Key (AWS)": re.compile(r"AKIA[0-9A-Z]{16}"),
        "API Key (Google)": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        "API Endpoint": re.compile(r"https?://[a-zA-Z0-9.-]+[.][a-zA-Z]{2,}/[^\s<>]{3,60}"),
        "Private Key": re.compile(r"-----BEGIN.*PRIVATE KEY-----"),
    }
    try:
        with zipfile.ZipFile(apk_path) as z:
            for name in z.namelist():
                if name.endswith(".dex") or name.endswith(".xml"):
                    try:
                        content = z.read(name).decode("utf-8", errors="ignore")
                        for pname, pat in patterns.items():
                            for m in pat.finditer(content):
                                findings.append({"type": pname, "value": m.group()[:80]})
                    except Exception:
                        continue
    except Exception as e:
        console.print(f"[red]Failed to read APK: {e}[/red]")
        return

    for f in findings[:20]:
        console.print(f"  [red]{f['type']}[/red]: {f['value'][:70]}")
    console.print(f"[green][✓][/green] {len(findings)} findings (strings-only scan)")


def diff_scans(scan1_dir, scan2_dir, console):
    """Compare two scan directories, show only new findings in scan2."""
    import json as _j

    def load_vulns(d):
        r = os.path.join(d, "report.json")
        if not os.path.isfile(r):
            return []
        return _j.load(open(r)).get("vulnerabilities", [])

    vulns1 = load_vulns(scan1_dir)
    vulns2 = load_vulns(scan2_dir)

    if not vulns2:
        console.print(f"[red]No report.json in {scan2_dir}[/red]")
        return

    # Fingerprint each finding by type + base URL
    def fingerprint(v):
        return f"{v.get('type','')}|{v.get('url','').split('?')[0]}"

    old_fps = {fingerprint(v) for v in vulns1}
    new_findings = [v for v in vulns2 if fingerprint(v) not in old_fps]
    fixed_findings = [v for v in vulns1 if fingerprint(v) not in {fingerprint(v2) for v2 in vulns2}]

    console.print(f"\n[bold red]☠ SCAN DIFF[/bold red]")
    console.print(f"[dim]Old: {scan1_dir}[/dim]")
    console.print(f"[dim]New: {scan2_dir}[/dim]\n")

    if new_findings:
        console.print(f"[bold green]🆕 {len(new_findings)} NEW findings:[/bold green]")
        from rich.table import Table
        t = Table()
        t.add_column("Severity", style="red")
        t.add_column("Type", style="cyan")
        t.add_column("URL", style="magenta")
        for v in sorted(new_findings, key=lambda x: x.get("cvss_score",0), reverse=True):
            sev = v.get("severity","").upper()
            t.add_row(sev, v.get("type","")[:50], v.get("url","")[:70])
        console.print(t)
    else:
        console.print("[green]No new findings — attack surface unchanged[/green]")

    if fixed_findings:
        console.print(f"\n[bold blue]✅ {len(fixed_findings)} FIXED/GONE findings[/bold blue]")

    # Save diff report
    diff_out = os.path.join(scan2_dir, "diff_report.json")
    import json as _j2
    _j2.dump({"new": new_findings, "fixed": fixed_findings}, open(diff_out, "w"), indent=2)
    console.print(f"\n[green][✓][/green] Diff saved → {diff_out}")


def main():
    parser = argparse.ArgumentParser(
        prog="apex-cli",
        description="Apex CLI v9.0 — Automated Pen-Test Orchestrator",
    )
    parser.add_argument("target", nargs="?", help="Target domain or IP (e.g. example.com)")
    parser.add_argument("--auto", "-a", type=str, metavar="FILE",
                        help="Auto-scan targets from file (one domain per line) or 'bounty' for live bug bounty targets")
    parser.add_argument("--dry-run", "-n", action="store_true", help="Preview commands without executing")
    parser.add_argument("--deep", "-d", action="store_true", help="Deep scan: more tools, higher intensity")
    parser.add_argument("--quick", "-q", action="store_true",
                        help="Quick scan: only high-value phases (SQLi, XSS, SSRF, RCE, takeover)")
    parser.add_argument("--report", "-r", nargs="+", choices=["terminal", "json", "html"],
                        default=["terminal"], help="Report formats (default: terminal)")
    parser.add_argument("--tools", action="store_true", help="Show available tools and exit")
    parser.add_argument("--skip", nargs="+", default=[],
                        help="Skip phases (e.g. --skip nuclei sqli)")
    parser.add_argument("--auth", nargs=2, metavar=("USER", "PASS"),
                        help="Credentials for authenticated scanning")
    parser.add_argument("--resume", type=str, metavar="SCAN_DIR",
                        help="Resume a previous scan from its output directory")
    parser.add_argument("--rate", type=float, default=0.0, metavar="SECONDS",
                        help="Delay between requests per thread (e.g. 0.1 for 10 req/s)")
    parser.add_argument("--workers", type=int, default=0, metavar="N",
                        help="Number of parallel workers (default: auto based on response time)")
    parser.add_argument("--proxy", type=str, default="",
                        help="Proxy URL (e.g. http://127.0.0.1:8080 for Burp Suite)")
    parser.add_argument("--wordlist", type=str, default="",
                        help="Custom wordlist for directory fuzzing")
    parser.add_argument("--watch", type=int, default=0, metavar="HOURS",
                        help="Rescan every N hours, alert on new findings (e.g. --watch 24)")
    parser.add_argument("--apk", type=str, default="", metavar="FILE",
                        help="Scan an APK file for endpoints, keys, and hardcoded secrets")
    parser.add_argument("--diff", nargs=2, metavar=("SCAN1","SCAN2"),
                        help="Compare two scan directories, show only new findings")
    parser.add_argument("--scope", nargs="+", default=[],
                        help="Restrict scan to these subdomains/paths (e.g. --scope api.example.com /api)")
    parser.add_argument("--output-dir", type=str, default="",
                        help="Custom output directory for scan results")
    parser.add_argument("--severity-filter", nargs="+", default=[],
                        choices=["critical", "high", "medium", "low", "info"],
                        help="Only report findings at these severity levels")
    parser.add_argument("--nuclei-tags", nargs="+", default=[],
                        help="Filter Nuclei templates by tags (e.g. --nuclei-tags cve rce)")
    parser.add_argument("--timeout", type=int, default=0,
                        help="Global request timeout in seconds (default: 10)")
    parser.add_argument("--recon-only", action="store_true",
                        help="Only run recon/probe phases, skip active scanning")
    parser.add_argument("--no-recon", action="store_true",
                        help="Skip recon, scan the target directly")
    parser.add_argument("--sarif", action="store_true",
                        help="Output findings in SARIF format for CI/CD integration")

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

    if args.resume:
        # Resume mode: load state from existing scan dir
        resume_dir = args.resume
        state_file = os.path.join(resume_dir, ".apex_state.json")
        if not os.path.isfile(state_file):
            console.print(f"[red]No state file found in {resume_dir}[/red]")
            sys.exit(1)
        import json as _j
        state = _j.load(open(state_file))
        target = state["target"]
        console.print(f"[bold yellow]Resuming scan of {target} from {resume_dir}[/bold yellow]")
        completed = {p["phase"] for p in state.get("phase_results", [])}
        console.print(f"[dim]{len(completed)} phases already completed[/dim]")
        run_scan(target, dry_run=args.dry_run, deep=args.deep,
                report_formats=args.report, skip=args.skip,
                auth=tuple(args.auth) if args.auth else None,
                resume_dir=resume_dir)
        return

    if args.rate > 0:
        set_rate_limit(args.rate)
        console.print(f"[dim]Rate limit: {args.rate}s between requests[/dim]")
    if hasattr(args, "proxy") and args.proxy:
        set_proxy(args.proxy)
        console.print(f"[dim]Proxy: {args.proxy}[/dim]")
    if hasattr(args, "wordlist") and args.wordlist:
        import scanners as _sc
        _sc.WORDLIST_CANDIDATES.insert(0, args.wordlist)
    if args.timeout > 0:
        import scanners as _sc2
        _sc2._TIMEOUT = args.timeout
        _sc2._TIMEOUT_SHORT = max(3, args.timeout // 2)
        _sc2._TIMEOUT_LONG = args.timeout + 5
        console.print(f"[dim]Timeout: {args.timeout}s[/dim]")

    target = validate_target(target)
    console.print(f"[bold white]Target:[/bold white] {target}")
    mode = "deep" if args.deep else ("quick" if args.quick else "standard")
    console.print(f"[bold white]Mode:[/bold white] {mode} | "
                  f"{'DRY RUN' if args.dry_run else 'LIVE'}")
    console.print()

    # Quick mode: skip low-value phases
    if args.quick:
        quick_skip = [
            "headers", "hsts", "mime sniffing", "clickjacking", "cookie security",
            "permissions policy", "robots sitemap", "etag tracking", "range amplification",
            "trace options", "user agent fuzzing", "dangling markup", "css injection",
            "log injection", "source map exposure", "redos", "hop by hop",
            "ip header spoofing", "null byte", "staging exposure", "tls info",
            "http/3 quic probe", "timing attacks", "cache timing oracle",
        ]
        args.skip = list(set((args.skip or []) + quick_skip))
        console.print(f"[dim]Quick mode: skipping {len(quick_skip)} low-value phases[/dim]")

    # APK scanning mode
    if hasattr(args, "apk") and args.apk:
        scan_apk(args.apk, console)
        return

    # Scan diff mode
    if hasattr(args, "diff") and args.diff:
        diff_scans(args.diff[0], args.diff[1], console)
        return

    watch_hours = args.watch if hasattr(args, "watch") else 0
    if watch_hours > 0:
        console.print(f"[bold cyan]Watch mode: rescanning every {watch_hours}h[/bold cyan]")
        known_vulns = set()
        while True:
            run_scan(target, dry_run=args.dry_run, deep=args.deep,
                    report_formats=args.report, skip=args.skip,
                    auth=tuple(args.auth) if args.auth else None,
                    scope=args.scope,
                    workers=args.workers if hasattr(args, "workers") else 0)
            # Check for new findings
            import glob as _glob, json as _wj
            latest = sorted(_glob.glob(f"scan_{target}_*/report.json"))
            if latest:
                data = _wj.load(open(latest[-1]))
                for v in data.get("vulnerabilities", []):
                    key = f"{v.get('type','')}|{v.get('url','').split('?')[0]}"
                    if key not in known_vulns and v.get("severity") in ("critical","high"):
                        known_vulns.add(key)
                        console.print(f"[bold red]🚨 NEW: {v['severity'].upper()} {v['type']} @ {v.get('url','')[:60]}[/bold red]")
                        # Send notification
                        try:
                            import requests as _nr
                            _nr.post("https://ntfy.sh/apex-watch",
                                    data=f"NEW {v['severity'].upper()}: {v['type']} @ {v.get('url','')}".encode(),
                                    headers={"Title": f"Apex: New finding on {target}"}, timeout=5)
                        except Exception:
                            pass
            console.print(f"[dim]Next scan in {watch_hours}h...[/dim]")
            import time as _wt; _wt.sleep(watch_hours * 3600)
    else:
        run_scan(target, dry_run=args.dry_run, deep=args.deep,
                report_formats=args.report, skip=args.skip,
                auth=tuple(args.auth) if args.auth else None,
                scope=args.scope,
                workers=args.workers if hasattr(args, "workers") else 0,
                output_dir=args.output_dir if args.output_dir else "",
                severity_filter=args.severity_filter,
                nuclei_tags=args.nuclei_tags,
                recon_only=args.recon_only,
                no_recon=args.no_recon,
                sarif=args.sarif)


if __name__ == "__main__":
    main()
