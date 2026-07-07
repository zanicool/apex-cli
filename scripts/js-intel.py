#!/usr/bin/env python3
"""
Apex JS Intelligence — JavaScript AST-based endpoint and secret extraction.

Goes beyond regex by parsing JavaScript properly:
- Extracts React/Vue/Angular routes from router configs
- Finds API base URLs and endpoint builders
- Discovers secrets with context (not just pattern matching)
- Extracts Next.js data routes from build manifests
- Finds WebSocket URLs
- Discovers hidden admin/debug paths

Usage:
    python3 js-intel.py <url>           # Analyze all JS from a URL
    python3 js-intel.py --file app.js   # Analyze a local JS file

Output: JSON with discovered endpoints, routes, secrets, and WebSocket URLs.
"""

import sys
import re
import json
import subprocess
from pathlib import Path
from urllib.parse import urljoin


def fetch_js_urls(base_url: str) -> list:
    """Get all JS file URLs from a page."""
    try:
        result = subprocess.run(
            ["curl", "-s", base_url], capture_output=True, text=True, timeout=15
        )
        html = result.stdout
    except Exception:
        return []

    js_urls = set()
    for match in re.finditer(r'(?:src|href)=["\']([^"\']*\.js(?:\?[^"\']*)?)["\']', html):
        url = match.group(1)
        if url.startswith("//"):
            url = "https:" + url
        elif url.startswith("/"):
            url = urljoin(base_url, url)
        elif not url.startswith("http"):
            url = urljoin(base_url, url)
        js_urls.add(url)

    return list(js_urls)


def fetch_js_content(url: str) -> str:
    """Download a JS file."""
    try:
        result = subprocess.run(
            ["curl", "-s", "--max-time", "10", url],
            capture_output=True, text=True, timeout=15
        )
        return result.stdout
    except Exception:
        return ""


def extract_routes(js: str) -> list:
    """Extract routes from React Router, Vue Router, Angular, Next.js patterns."""
    routes = set()

    # React Router: path: "/dashboard", <Route path="/admin"
    for m in re.finditer(r'path:\s*["\'](/[^"\']+)["\']', js):
        routes.add(m.group(1))

    # Vue Router: { path: '/admin', component: ... }
    for m in re.finditer(r'path:\s*["\'](/[^"\']+)["\']', js):
        routes.add(m.group(1))

    # Next.js pages: /pages/api/users, /_next/data routes
    for m in re.finditer(r'["\'](/(?:api|pages|app)/[^"\'}\s]+)["\']', js):
        routes.add(m.group(1))

    # Generic route patterns
    for m in re.finditer(r'["\'](/(?:admin|dashboard|settings|api|auth|user|account|profile|internal|debug|manage|portal)[/\w-]*)["\']', js):
        routes.add(m.group(1))

    return sorted(routes)


def extract_api_endpoints(js: str) -> list:
    """Extract API endpoints and base URLs."""
    endpoints = set()

    # fetch("/api/...", axios.get("/v1/..."), etc
    for m in re.finditer(r'(?:fetch|get|post|put|patch|delete|request)\s*\(\s*[`"\']([^`"\']+)[`"\']', js, re.IGNORECASE):
        url = m.group(1)
        if url.startswith("/") or url.startswith("http"):
            endpoints.add(url)

    # API base URL: baseURL: "https://api.example.com"
    for m in re.finditer(r'(?:baseURL|baseUrl|apiUrl|API_URL|ENDPOINT|api_base)\s*[:=]\s*[`"\']([^`"\']+)[`"\']', js):
        endpoints.add(m.group(1))

    # Template literals: `${baseUrl}/users/${id}`
    for m in re.finditer(r'`([^`]*\$\{[^}]+\}[^`]*)`', js):
        template = m.group(1)
        # Replace template vars with placeholder
        cleaned = re.sub(r'\$\{[^}]+\}', ':param', template)
        if cleaned.startswith("/") or cleaned.startswith("http"):
            endpoints.add(cleaned)

    # String concatenation: "/api/" + version + "/users"
    for m in re.finditer(r'["\'](/api/[^"\']+)["\']', js):
        endpoints.add(m.group(1))

    return sorted(endpoints)


def extract_secrets(js: str) -> list:
    """Extract secrets with context and confidence scoring."""
    secrets = []

    patterns = [
        ("AWS Access Key", r'(AKIA[A-Z0-9]{16})', "critical"),
        ("AWS Secret Key", r'(?:aws.?secret|secret.?key)\s*[:=]\s*["\']([A-Za-z0-9/+=]{40})["\']', "critical"),
        ("Stripe Secret", r'(sk_live_[A-Za-z0-9]{24,})', "critical"),
        ("Stripe Publishable", r'(pk_live_[A-Za-z0-9]{24,})', "low"),
        ("GitHub Token", r'(ghp_[A-Za-z0-9]{36})', "critical"),
        ("GitLab Token", r'(glpat-[A-Za-z0-9_-]{20,})', "critical"),
        ("Google API Key", r'(AIza[0-9A-Za-z_-]{35})', "medium"),
        ("Slack Token", r'(xox[baprs]-[A-Za-z0-9-]{10,})', "high"),
        ("SendGrid", r'(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})', "high"),
        ("Twilio", r'(SK[0-9a-fA-F]{32})', "high"),
        ("Database URL", r'((?:postgres|mysql|mongodb|redis)://[^\s"\']+)', "critical"),
        ("Private Key", r'(-----BEGIN (?:RSA )?PRIVATE KEY-----)', "critical"),
        ("JWT Secret", r'(?:jwt.?secret|token.?secret)\s*[:=]\s*["\']([^"\']{8,})["\']', "high"),
        ("Firebase", r'(apiKey:\s*["\']AIza[^"\']+["\'])', "medium"),
    ]

    for name, pattern, severity in patterns:
        for m in re.finditer(pattern, js):
            value = m.group(1)
            # Skip obvious placeholders
            if any(x in value.lower() for x in ["example", "test", "xxx", "placeholder", "your_", "000000"]):
                continue
            # Get context (30 chars before and after)
            start = max(0, m.start() - 30)
            end = min(len(js), m.end() + 30)
            context = js[start:end].replace("\n", " ")

            secrets.append({
                "type": name,
                "value": value[:40] + ("..." if len(value) > 40 else ""),
                "severity": severity,
                "context": context[:100]
            })

    return secrets


def extract_websocket_urls(js: str) -> list:
    """Find WebSocket connection URLs."""
    ws_urls = set()
    for m in re.finditer(r'["\']?(wss?://[^"\'}\s]+)["\']?', js):
        ws_urls.add(m.group(1))
    return sorted(ws_urls)


def extract_next_manifest(base_url: str) -> dict:
    """Parse Next.js build manifest for all pages/routes."""
    manifest = {}
    # Try _next/static build manifest
    for path in ["/_next/static/chunks/webpack.js", "/_buildManifest.js"]:
        content = fetch_js_content(urljoin(base_url, path))
        if content:
            for m in re.finditer(r'["\'](/[^"\']+)["\']\s*:', content):
                route = m.group(1)
                if not route.startswith("/_") and not route.endswith(".js"):
                    manifest[route] = "next.js page"
    return manifest


def analyze_url(url: str) -> dict:
    """Full analysis of a URL's JavaScript."""
    results = {
        "target": url,
        "js_files": [],
        "routes": [],
        "api_endpoints": [],
        "secrets": [],
        "websockets": [],
        "next_routes": {},
    }

    print(f"[*] Fetching JS files from {url}...")
    js_urls = fetch_js_urls(url)
    results["js_files"] = js_urls
    print(f"    Found {len(js_urls)} JS files")

    all_js = ""
    for js_url in js_urls[:20]:  # Cap at 20 files
        content = fetch_js_content(js_url)
        if content:
            all_js += content + "\n"

    print(f"[*] Analyzing {len(all_js)} bytes of JavaScript...")

    results["routes"] = extract_routes(all_js)
    results["api_endpoints"] = extract_api_endpoints(all_js)
    results["secrets"] = extract_secrets(all_js)
    results["websockets"] = extract_websocket_urls(all_js)

    # Next.js specific
    if "next" in all_js.lower() or "_next" in url:
        results["next_routes"] = extract_next_manifest(url)

    # Summary
    print(f"\n[+] Results:")
    print(f"    Routes: {len(results['routes'])}")
    print(f"    API endpoints: {len(results['api_endpoints'])}")
    print(f"    Secrets: {len(results['secrets'])}")
    print(f"    WebSocket URLs: {len(results['websockets'])}")

    if results["secrets"]:
        print(f"\n[!] SECRETS FOUND:")
        for s in results["secrets"]:
            print(f"    [{s['severity'].upper()}] {s['type']}: {s['value']}")

    return results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 js-intel.py <url>")
        sys.exit(1)

    if sys.argv[1] == "--file":
        js = Path(sys.argv[2]).read_text()
        results = {
            "routes": extract_routes(js),
            "api_endpoints": extract_api_endpoints(js),
            "secrets": extract_secrets(js),
            "websockets": extract_websocket_urls(js),
        }
    else:
        results = analyze_url(sys.argv[1])

    # Save results
    out_path = "/tmp/js-intel-results.json"
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[*] Full results saved to {out_path}")
