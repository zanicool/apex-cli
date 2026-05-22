"""HTB Headless-inspired challenge: Multi-step exploitation.

Attack chain:
1. Find /debug endpoint (info disclosure → stack trace leaks internal paths)
2. Stack trace reveals /api/internal with API key in env var
3. /api/internal has blind SSRF via 'webhook' parameter
4. SSRF to http://127.0.0.1:9090/admin reveals admin panel
5. Admin panel has command injection via 'backup' parameter
6. Execute command to read /flag.txt

Difficulty: HTB Medium (like Headless, CozyHosting)
"""
import os
import subprocess
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from flask import Flask, request, jsonify
import requests

app = Flask(__name__)
FLAG = "FLAG{headless_chain_ssrf_to_rce_pwned}"
API_KEY = "sk-internal-4f8a2b1c9d3e"
ADMIN_SECRET = "X-Admin: true"

# --- Internal admin service on port 9090 ---
class AdminHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/admin":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'''<h1>Internal Admin</h1>
<form method="POST" action="/admin/backup">
<input name="path" value="/var/www/html">
<button>Create Backup</button></form>''')
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/admin/backup":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode()
            # Vulnerable: command injection in path parameter
            path = ""
            for param in body.split("&"):
                if param.startswith("path="):
                    path = param[5:]
            # Intentionally vulnerable
            try:
                result = subprocess.check_output(
                    f"tar -czf /tmp/backup.tar.gz {path}",
                    shell=True, stderr=subprocess.STDOUT, timeout=5
                ).decode()
            except subprocess.CalledProcessError as e:
                result = e.output.decode()
            except subprocess.TimeoutExpired:
                result = "timeout"
            self.send_response(200)
            self.end_headers()
            self.wfile.write(f"<pre>{result}</pre>".encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *a):
        pass

def run_admin():
    HTTPServer(("127.0.0.1", 9090), AdminHandler).serve_forever()

threading.Thread(target=run_admin, daemon=True).start()

# Write flag file
os.makedirs("/tmp", exist_ok=True)
with open("/tmp/flag.txt", "w") as f:
    f.write(FLAG)

# --- Main web app ---
@app.route("/")
def index():
    return '''<html><head><title>CozyDash v3.2</title></head><body>
<h1>CozyDash — Server Monitoring</h1>
<nav>
  <a href="/status">Status</a> |
  <a href="/logs">Logs</a> |
  <a href="/settings">Settings</a>
</nav>
<p>Welcome to the monitoring dashboard.</p>
<p><small>Build: 3.2.1-beta | &copy; 2026 CozyTech</small></p>
</body></html>'''

@app.route("/status")
def status():
    return jsonify({"status": "healthy", "uptime": "14d 3h", "version": "3.2.1-beta"})

@app.route("/logs")
def logs():
    return '''<h1>Application Logs</h1>
<pre>
[2026-05-22 10:00:01] INFO  Server started on :5000
[2026-05-22 10:00:02] INFO  Connected to database
[2026-05-22 10:00:03] INFO  Internal API ready on :9090
[2026-05-22 10:15:44] WARN  Rate limit exceeded for 192.168.1.50
</pre>'''

@app.route("/settings")
def settings():
    return "<h1>Settings</h1><p>You must be logged in to view settings.</p>", 401

@app.route("/debug")
def debug():
    """Simulated stack trace that leaks internal info."""
    return '''<h1>Debug Information</h1>
<p>This page is for development only.</p>
<pre class="stacktrace">
Traceback (most recent call last):
  File "/app/server.py", line 142, in handle_request
    response = internal_api.call(endpoint, key=os.environ["INTERNAL_API_KEY"])
  File "/app/lib/api_client.py", line 58, in call
    headers = {"X-Api-Key": "''' + API_KEY + '''", "X-Internal": "true"}
    resp = requests.post(f"http://127.0.0.1:9090{endpoint}", headers=headers)
  File "/usr/lib/python3/requests/api.py", line 59, in post
    return request("POST", url, **kwargs)
KeyError: 'WEBHOOK_URL'
</pre>
<p>Environment: production | PID: 1842 | Memory: 128MB</p>'''

@app.route("/api/internal", methods=["GET", "POST"])
def internal_api():
    """Internal API - requires API key, has SSRF via webhook."""
    key = request.headers.get("X-Api-Key", "")
    if key != API_KEY:
        return jsonify({"error": "unauthorized", "hint": "X-Api-Key header required"}), 401

    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        webhook = data.get("webhook", "")
        if webhook:
            try:
                r = requests.get(webhook, timeout=3)
                return jsonify({"status": "delivered", "response": r.text[:2000]})
            except Exception as e:
                return jsonify({"status": "failed", "error": str(e)})
        return jsonify({"error": "provide 'webhook' URL in JSON body"})

    return jsonify({
        "service": "internal-api",
        "endpoints": ["/admin", "/admin/backup"],
        "note": "Use POST with {'webhook': 'url'} to test callbacks"
    })

@app.route("/health")
def health():
    return "ok"

@app.route("/robots.txt")
def robots():
    return "User-agent: *\nDisallow: /debug\nDisallow: /api/\n"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
