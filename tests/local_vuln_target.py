#!/usr/bin/env python3
"""Local intentionally-vulnerable target for apex-cli detection testing.

LEGAL / SAFETY: binds to 127.0.0.1 only. This is a deliberately insecure app
used solely to measure the scanner against KNOWN planted bugs on the local
machine. Never expose it to a network.

Planted vulnerabilities (mirrors tests/vulnerability_battery vuln-web:8081):
  /users?id=          -> error-based SQLi (reflects a SQL error string)
  /search?q=          -> reflected XSS (reflects input unescaped)
  /ping?host=         -> command injection (reflects marker without executing)
  /template?name=     -> SSTI (evaluates {{7*7}} -> 49)
  /file?path=         -> LFI/path traversal (reflects /etc/passwd-like content)
  /redirect?url=      -> open redirect (302 to attacker URL)
  /fetch?url=         -> SSRF (reflects internal metadata marker)
  /header?lang=       -> CRLF/header injection (reflects into a header)
  /                   -> links page so the crawler discovers all endpoints
"""
import html
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

HOST, PORT = "127.0.0.1", 8091

LINKS = """<html><body><h1>vuln-web (local test)</h1>
<a href="/users?id=1">users</a>
<a href="/search?q=hello">search</a>
<a href="/ping?host=127.0.0.1">ping</a>
<a href="/template?name=guest">template</a>
<a href="/file?path=readme.txt">file</a>
<a href="/redirect?url=/home">redirect</a>
<a href="/fetch?url=http://example.com">fetch</a>
<a href="/header?lang=en">header</a>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass  # quiet

    def _send(self, code, body, headers=None):
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body is not None:
            self.wfile.write(body.encode("utf-8", "replace"))

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        path = u.path

        if path == "/":
            return self._send(200, LINKS)

        if path == "/users":
            v = q.get("id", [""])[0]
            # Error-based SQLi: single quote triggers a SQL error string.
            if "'" in v:
                return self._send(
                    200,
                    "You have an error in your SQL syntax; check the manual "
                    "that corresponds to your MySQL server version near '%s'"
                    % html.escape(v),
                )
            return self._send(200, "<p>user id=%s</p>" % html.escape(v))

        if path == "/search":
            v = q.get("q", [""])[0]
            # Reflected XSS: input echoed WITHOUT escaping.
            return self._send(200, "<div>results for: %s</div>" % v)

        if path == "/ping":
            v = q.get("host", [""])[0]
            # Command injection sim: emulate a shell running `ping <host>` where
            # <host> is unsanitized. If the value contains a shell separator
            # followed by a known command, emit that command's output — exactly
            # what a vulnerable `os.system("ping " + host)` would leak. Does NOT
            # actually execute anything.
            import re as _re
            m = _re.search(r"[;|`]|\$\(", v)
            if m:
                tail = v[m.start():]
                out = "PING output\n"
                if "id" in tail:
                    out += "uid=0(root) gid=0(root) groups=0(root)\n"
                em = _re.search(r"echo\s+(\S+)", tail)
                if em:
                    out += em.group(1) + "\n"
                return self._send(200, out)
            return self._send(200, "PING %s: 64 bytes\n" % html.escape(v))

        if path == "/template":
            v = q.get("name", [""])[0]
            # SSTI: evaluate a tiny {{a*b}} expression like a template engine.
            out = v
            if v.startswith("{{") and v.endswith("}}"):
                expr = v[2:-2].strip()
                try:
                    if all(c in "0123456789*+-/ " for c in expr) and expr:
                        out = str(eval(expr))  # noqa: S307 (test sandbox only)
                except Exception:
                    out = v
            return self._send(200, "<p>Hello %s</p>" % out)

        if path == "/file":
            v = q.get("path", [""])[0]
            # LFI/traversal: ../etc/passwd style returns passwd-like content.
            if "etc/passwd" in v or "../" in v:
                return self._send(200, "root:x:0:0:root:/root:/bin/bash\n")
            return self._send(200, "file contents of %s" % html.escape(v))

        if path == "/redirect":
            v = q.get("url", [""])[0]
            # Open redirect: 302 to arbitrary user-controlled Location.
            return self._send(302, None, {"Location": v})

        if path == "/fetch":
            v = q.get("url", [""])[0]
            # SSRF: fetching the cloud metadata IP returns an internal marker.
            if "169.254.169.254" in v or "localhost" in v or "127.0.0.1" in v:
                return self._send(200, "ami-id: ami-1234\nAccessKeyId: AKIA...\n")
            return self._send(200, "fetched: %s" % html.escape(v))

        if path == "/header":
            v = q.get("lang", [""])[0]
            # CRLF/header injection: split on %0d%0a already decoded by client.
            extra = {}
            if "\r" in v or "\n" in v:
                extra["X-Injected"] = "yes"
            return self._send(200, "lang set", extra)

        if path == "/.git/config":
            # Exposed git config — a real, commonly-reported misconfiguration
            # that Nuclei's `git-config` template detects. Lets us verify the
            # Nuclei engine integration end-to-end.
            return self._send(
                200,
                "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n"
                "[remote \"origin\"]\n\turl = https://github.com/example/repo.git\n",
            )

        return self._send(404, "not found")


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else PORT
    print("vuln-web local test target on http://%s:%d (Ctrl+C to stop)"
          % (HOST, port))
    HTTPServer((HOST, port), Handler).serve_forever()
