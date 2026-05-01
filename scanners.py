"""Apex CLI v3.0 — Built-in scanners (no external tool dependencies)."""

import re
import time
import urllib.parse
from collections import defaultdict

import requests
from bs4 import BeautifulSoup

requests.packages.urllib3.disable_warnings()
_S = requests.Session()
_S.headers.update({"User-Agent": "ApexCLI/3.0"})
_S.verify = False
_TIMEOUT = 10

# ---------------------------------------------------------------------------
# Crawler
# ---------------------------------------------------------------------------

def crawl(base_url, max_pages=50):
    """Crawl a site, return dict with pages, forms, links, params."""
    visited = set()
    to_visit = [base_url]
    pages = []
    forms = []
    params_found = defaultdict(set)  # url -> set of param names
    links = set()

    while to_visit and len(visited) < max_pages:
        url = to_visit.pop(0)
        norm = url.split("?")[0].split("#")[0]
        if norm in visited:
            continue
        visited.add(norm)

        try:
            r = _S.get(url, timeout=_TIMEOUT, allow_redirects=True)
        except Exception:
            continue

        pages.append({"url": url, "status": r.status_code, "length": len(r.text)})
        soup = BeautifulSoup(r.text, "lxml")

        # Extract links
        for tag in soup.find_all("a", href=True):
            href = tag["href"]
            full = urllib.parse.urljoin(url, href)
            parsed = urllib.parse.urlparse(full)
            # Stay on same host
            base_parsed = urllib.parse.urlparse(base_url)
            if parsed.netloc and parsed.netloc != base_parsed.netloc:
                continue
            clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if parsed.query:
                for k, _ in urllib.parse.parse_qsl(parsed.query):
                    params_found[clean].add(k)
            links.add(full)
            if clean not in visited:
                to_visit.append(full)

        # Extract forms
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "get").upper()
            action_url = urllib.parse.urljoin(url, action)
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name:
                    inputs.append({
                        "name": name,
                        "type": inp.get("type", "text"),
                        "value": inp.get("value", ""),
                    })
            forms.append({"url": url, "action": action_url, "method": method, "inputs": inputs})

    return {
        "pages": pages,
        "forms": forms,
        "params": {u: list(p) for u, p in params_found.items()},
        "links": list(links),
    }

# ---------------------------------------------------------------------------
# XSS Scanner
# ---------------------------------------------------------------------------

_XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    "'-alert(1)-'",
    '<svg/onload=alert(1)>',
    '{{7*7}}',
]
_XSS_CANARY = "apex" + str(int(time.time()))[-6:]

def scan_xss(crawl_data):
    """Test reflected XSS on GET params and form inputs."""
    findings = []

    # GET params
    for url, params in crawl_data["params"].items():
        for param in params:
            for payload in _XSS_PAYLOADS:
                test_url = f"{url}?{urllib.parse.urlencode({param: payload})}"
                try:
                    r = _S.get(test_url, timeout=_TIMEOUT)
                    if payload in r.text:
                        findings.append({
                            "type": "Reflected XSS",
                            "severity": "high",
                            "url": test_url,
                            "detail": f"Param '{param}' reflects payload unescaped",
                            "template": "apex-xss",
                        })
                        break  # one payload enough per param
                except Exception:
                    continue

    # Forms (GET and POST)
    for form in crawl_data["forms"]:
        for inp in form["inputs"]:
            if inp["type"] in ("submit", "hidden", "button"):
                continue
            for payload in _XSS_PAYLOADS:
                data = {i["name"]: i["value"] or "test" for i in form["inputs"]}
                data[inp["name"]] = payload
                try:
                    if form["method"] == "GET":
                        r = _S.get(form["action"], params=data, timeout=_TIMEOUT)
                    else:
                        r = _S.post(form["action"], data=data, timeout=_TIMEOUT)
                    if payload in r.text:
                        findings.append({
                            "type": "Reflected XSS",
                            "severity": "high",
                            "url": form["action"],
                            "detail": f"Form input '{inp['name']}' reflects payload",
                            "template": "apex-xss-form",
                        })
                        break
                except Exception:
                    continue

    return findings

# ---------------------------------------------------------------------------
# Command Injection Scanner
# ---------------------------------------------------------------------------

_CMDI_PAYLOADS = [
    (";sleep 5", 4.5),
    ("|sleep 5", 4.5),
    ("$(sleep 5)", 4.5),
    ("`sleep 5`", 4.5),
]
_CMDI_BLIND_PAYLOADS = [
    (";echo apex_cmdi_test", "apex_cmdi_test"),
    ("|id", "uid="),
    ("$(whoami)", None),  # time-based only
]

def scan_cmdi(crawl_data):
    """Test command injection on form inputs using time-based and output-based detection."""
    findings = []

    for form in crawl_data["forms"]:
        if form["method"] != "POST":
            continue
        for inp in form["inputs"]:
            if inp["type"] in ("submit", "hidden", "button", "password"):
                continue

            # Time-based detection
            for payload, min_delay in _CMDI_PAYLOADS:
                data = {i["name"]: i["value"] or "127.0.0.1" for i in form["inputs"]}
                data[inp["name"]] = "127.0.0.1" + payload
                try:
                    start = time.time()
                    r = _S.post(form["action"], data=data, timeout=15)
                    elapsed = time.time() - start
                    if elapsed >= min_delay:
                        findings.append({
                            "type": "Command Injection (time-based)",
                            "severity": "critical",
                            "url": form["action"],
                            "detail": f"Input '{inp['name']}' — {elapsed:.1f}s delay with '{payload}'",
                            "template": "apex-cmdi",
                        })
                        break
                except Exception:
                    continue

            # Output-based detection
            for payload, marker in _CMDI_BLIND_PAYLOADS:
                if marker is None:
                    continue
                data = {i["name"]: i["value"] or "127.0.0.1" for i in form["inputs"]}
                data[inp["name"]] = "127.0.0.1" + payload
                try:
                    r = _S.post(form["action"], data=data, timeout=_TIMEOUT)
                    if marker in r.text:
                        findings.append({
                            "type": "Command Injection (output-based)",
                            "severity": "critical",
                            "url": form["action"],
                            "detail": f"Input '{inp['name']}' — found '{marker}' in response",
                            "template": "apex-cmdi",
                        })
                        break
                except Exception:
                    continue

    return findings

# ---------------------------------------------------------------------------
# IDOR Scanner
# ---------------------------------------------------------------------------

def scan_idor(crawl_data):
    """Test IDOR by enumerating numeric IDs on endpoints with id-like params."""
    findings = []
    id_params = ("id", "uid", "user_id", "userid", "account", "doc", "file", "note", "item", "order")

    # Check params found by crawler
    for url, params in crawl_data["params"].items():
        for param in params:
            if param.lower() not in id_params:
                continue
            findings.extend(_test_idor(url, param))

    # Also probe discovered pages with common id params
    tested = set()
    for page in crawl_data["pages"]:
        base = page["url"].split("?")[0]
        if base in tested:
            continue
        tested.add(base)
        for param in ("id", "uid", "user_id"):
            # Quick check: does the endpoint accept this param?
            try:
                r = _S.get(f"{base}?{param}=1", timeout=_TIMEOUT)
                if r.status_code == 200 and len(r.text) > 20:
                    findings.extend(_test_idor(base, param))
            except Exception:
                continue

    # Deduplicate
    seen = set()
    unique = []
    for f in findings:
        key = f"{f['url']}|{f['detail']}"
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def _test_idor(url, param):
    """Test a single URL+param for IDOR by enumerating IDs 1-5."""
    findings = []
    responses = {}
    for test_id in range(1, 6):
        try:
            r = _S.get(f"{url}?{urllib.parse.urlencode({param: test_id})}", timeout=_TIMEOUT)
            if r.status_code == 200 and len(r.text) > 20:
                responses[test_id] = r.text[:200]
        except Exception:
            continue
    unique = set(responses.values())
    if len(unique) > 1:
        findings.append({
            "type": "IDOR (Insecure Direct Object Reference)",
            "severity": "high",
            "url": f"{url}?{param}=<id>",
            "detail": f"Param '{param}' returns different data for IDs {list(responses.keys())} without auth",
            "template": "apex-idor",
        })
    return findings

# ---------------------------------------------------------------------------
# Open Redirect Scanner
# ---------------------------------------------------------------------------

_REDIRECT_PARAMS = ("url", "redirect", "next", "return", "returnto", "goto", "dest",
                     "destination", "redir", "redirect_uri", "continue", "target", "link")
_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https://evil.com%00",
]

def scan_open_redirect(crawl_data):
    """Test open redirect on URL-like parameters."""
    findings = []

    # Check params found by crawler
    for url, params in crawl_data["params"].items():
        for param in params:
            if param.lower() not in _REDIRECT_PARAMS:
                continue
            findings.extend(_test_redirect(url, param))

    # Probe discovered pages with common redirect params
    tested = set()
    for page in crawl_data["pages"]:
        base = page["url"].split("?")[0]
        if base in tested:
            continue
        tested.add(base)
        for param in ("url", "redirect", "next", "goto"):
            try:
                r = _S.get(f"{base}?{param}=https://evil.com",
                           timeout=_TIMEOUT, allow_redirects=False)
                if "evil.com" in r.headers.get("Location", ""):
                    findings.append({
                        "type": "Open Redirect",
                        "severity": "medium",
                        "url": f"{base}?{param}=https://evil.com",
                        "detail": f"Redirects to: {r.headers.get('Location', '')}",
                        "template": "apex-redirect",
                    })
                    break
            except Exception:
                continue

    # Check forms too
    for form in crawl_data["forms"]:
        for inp in form["inputs"]:
            if inp["name"].lower() not in _REDIRECT_PARAMS:
                continue
            findings.extend(_test_redirect_form(form, inp))

    # Deduplicate
    seen = set()
    unique = []
    for f in findings:
        key = f["url"]
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def _test_redirect(url, param):
    findings = []
    for payload in _REDIRECT_PAYLOADS:
        try:
            r = _S.get(f"{url}?{urllib.parse.urlencode({param: payload})}",
                       timeout=_TIMEOUT, allow_redirects=False)
            if "evil.com" in r.headers.get("Location", ""):
                findings.append({
                    "type": "Open Redirect",
                    "severity": "medium",
                    "url": f"{url}?{param}={payload}",
                    "detail": f"Redirects to: {r.headers.get('Location', '')}",
                    "template": "apex-redirect",
                })
                break
        except Exception:
            continue
    return findings


def _test_redirect_form(form, inp):
    findings = []
    for payload in _REDIRECT_PAYLOADS:
        data = {i["name"]: i["value"] or "/" for i in form["inputs"]}
        data[inp["name"]] = payload
        try:
            if form["method"] == "GET":
                r = _S.get(form["action"], params=data, timeout=_TIMEOUT, allow_redirects=False)
            else:
                r = _S.post(form["action"], data=data, timeout=_TIMEOUT, allow_redirects=False)
            if "evil.com" in r.headers.get("Location", ""):
                findings.append({
                    "type": "Open Redirect",
                    "severity": "medium",
                    "url": form["action"],
                    "detail": f"Input '{inp['name']}' redirects to: {r.headers.get('Location', '')}",
                    "template": "apex-redirect",
                })
                break
        except Exception:
            continue
    return findings

# ---------------------------------------------------------------------------
# Security Headers Analyzer
# ---------------------------------------------------------------------------

_SECURITY_HEADERS = {
    "Strict-Transport-Security": ("HSTS missing — no HTTPS enforcement", "medium"),
    "Content-Security-Policy": ("CSP missing — XSS risk", "medium"),
    "X-Frame-Options": ("X-Frame-Options missing — clickjacking risk", "low"),
    "X-Content-Type-Options": ("X-Content-Type-Options missing — MIME sniffing risk", "low"),
    "X-XSS-Protection": ("X-XSS-Protection missing", "info"),
    "Referrer-Policy": ("Referrer-Policy missing — info leakage risk", "low"),
    "Permissions-Policy": ("Permissions-Policy missing", "info"),
}

def scan_headers(base_url):
    """Check for missing security headers."""
    findings = []
    try:
        r = _S.get(base_url, timeout=_TIMEOUT)
    except Exception:
        return findings

    for header, (msg, severity) in _SECURITY_HEADERS.items():
        if header.lower() not in {k.lower(): v for k, v in r.headers.items()}:
            findings.append({
                "type": f"Missing Header: {header}",
                "severity": severity,
                "url": base_url,
                "detail": msg,
                "template": "apex-headers",
            })

    # Check for info-leaking headers
    for bad_header in ("Server", "X-Powered-By", "X-AspNet-Version"):
        val = r.headers.get(bad_header)
        if val:
            findings.append({
                "type": f"Info Disclosure: {bad_header}",
                "severity": "info",
                "url": base_url,
                "detail": f"{bad_header}: {val}",
                "template": "apex-headers",
            })

    return findings

# ---------------------------------------------------------------------------
# Tech Fingerprinting
# ---------------------------------------------------------------------------

_TECH_SIGNATURES = [
    ("Flask", [r"Werkzeug", r"flask", r"Set-Cookie:.*session="]),
    ("Django", [r"csrfmiddlewaretoken", r"django", r"__admin"]),
    ("Express", [r"X-Powered-By:\s*Express", r"express"]),
    ("PHP", [r"X-Powered-By:\s*PHP", r"\.php", r"PHPSESSID"]),
    ("ASP.NET", [r"X-AspNet-Version", r"__VIEWSTATE", r"\.aspx"]),
    ("WordPress", [r"wp-content", r"wp-includes", r"wordpress"]),
    ("Joomla", [r"joomla", r"/administrator"]),
    ("Drupal", [r"drupal", r"sites/default"]),
    ("Nginx", [r"Server:\s*nginx"]),
    ("Apache", [r"Server:\s*Apache"]),
    ("Cloudflare", [r"Server:\s*cloudflare", r"cf-ray"]),
    ("React", [r"react", r"_reactRoot", r"__NEXT_DATA__"]),
    ("Vue", [r"vue", r"v-app", r"nuxt"]),
    ("Bootstrap", [r"bootstrap\.min\.(css|js)"]),
    ("jQuery", [r"jquery\.min\.js", r"jquery"]),
]

def fingerprint(base_url):
    """Detect technologies from headers and response body."""
    detected = []
    try:
        r = _S.get(base_url, timeout=_TIMEOUT)
    except Exception:
        return detected

    headers_str = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
    combined = headers_str + "\n" + r.text[:50000]

    for tech, patterns in _TECH_SIGNATURES:
        for pat in patterns:
            if re.search(pat, combined, re.IGNORECASE):
                detected.append(tech)
                break

    return list(set(detected))

# ---------------------------------------------------------------------------
# WAF Detection
# ---------------------------------------------------------------------------

_WAF_SIGNATURES = {
    "Cloudflare": [r"cf-ray", r"Server:\s*cloudflare", r"__cfduid"],
    "AWS WAF": [r"awselb", r"x-amzn-requestid"],
    "Akamai": [r"akamai", r"x-akamai"],
    "Sucuri": [r"sucuri", r"x-sucuri"],
    "Imperva": [r"incapsula", r"x-iinfo", r"visid_incap"],
    "ModSecurity": [r"mod_security", r"modsecurity"],
    "Wordfence": [r"wordfence"],
    "F5 BIG-IP": [r"BigIP", r"F5"],
    "Barracuda": [r"barracuda", r"barra_counter"],
    "Fortinet": [r"fortigate", r"fortiWeb"],
}

def detect_waf(base_url):
    """Detect WAF by checking headers and sending a malicious-looking request."""
    detected = []

    # Normal request
    try:
        r = _S.get(base_url, timeout=_TIMEOUT)
        headers_str = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        cookies_str = str(r.cookies.get_dict())
        combined = headers_str + cookies_str
    except Exception:
        return detected

    for waf, patterns in _WAF_SIGNATURES.items():
        for pat in patterns:
            if re.search(pat, combined, re.IGNORECASE):
                detected.append(waf)
                break

    # Trigger WAF with malicious payload
    try:
        r2 = _S.get(f"{base_url}/?id=1' OR 1=1--", timeout=_TIMEOUT)
        if r2.status_code in (403, 406, 429, 503):
            if not detected:
                detected.append("Unknown WAF (blocked SQLi probe)")
    except Exception:
        pass

    return list(set(detected))

# ---------------------------------------------------------------------------
# Sensitive File Scanner
# ---------------------------------------------------------------------------

_SENSITIVE_PATHS = [
    ("/.env", "Environment file with credentials"),
    ("/.git/HEAD", "Git repository exposed"),
    ("/.git/config", "Git config exposed"),
    ("/.svn/entries", "SVN repository exposed"),
    ("/.DS_Store", "macOS directory metadata"),
    ("/robots.txt", "Robots file (may reveal hidden paths)"),
    ("/sitemap.xml", "Sitemap"),
    ("/.htaccess", "Apache config"),
    ("/web.config", "IIS config"),
    ("/wp-config.php.bak", "WordPress config backup"),
    ("/config.php.bak", "Config backup"),
    ("/debug", "Debug endpoint"),
    ("/server-status", "Apache server status"),
    ("/server-info", "Apache server info"),
    ("/phpinfo.php", "PHP info page"),
    ("/info.php", "PHP info page"),
    ("/elmah.axd", "ASP.NET error log"),
    ("/trace.axd", "ASP.NET trace"),
    ("/backup.sql", "Database backup"),
    ("/dump.sql", "Database dump"),
    ("/database.sql", "Database export"),
    ("/db.sql", "Database file"),
    ("/.bash_history", "Bash history"),
    ("/.ssh/id_rsa", "SSH private key"),
    ("/id_rsa", "SSH private key"),
    ("/admin", "Admin panel"),
    ("/administrator", "Admin panel"),
    ("/console", "Debug console"),
    ("/swagger.json", "API documentation"),
    ("/api-docs", "API documentation"),
    ("/graphql", "GraphQL endpoint"),
    ("/actuator", "Spring Boot actuator"),
    ("/actuator/env", "Spring Boot env"),
    ("/actuator/health", "Spring Boot health"),
    ("/.well-known/security.txt", "Security contact"),
    ("/crossdomain.xml", "Flash cross-domain policy"),
    ("/clientaccesspolicy.xml", "Silverlight policy"),
]

def scan_sensitive_files(base_url):
    """Check for common sensitive files and directories."""
    findings = []
    for path, desc in _SENSITIVE_PATHS:
        url = base_url.rstrip("/") + path
        try:
            r = _S.get(url, timeout=_TIMEOUT, allow_redirects=False)
            if r.status_code == 200 and len(r.text) > 0:
                # Filter out generic error pages
                if any(x in r.text.lower() for x in ("not found", "404", "error")):
                    continue
                severity = "high"
                if path in ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt"):
                    severity = "info"
                elif path in ("/admin", "/administrator", "/console"):
                    severity = "medium"
                findings.append({
                    "type": f"Sensitive File: {path}",
                    "severity": severity,
                    "url": url,
                    "detail": f"{desc} ({len(r.text)} bytes)",
                    "template": "apex-sensitive",
                })
        except Exception:
            continue

    return findings
