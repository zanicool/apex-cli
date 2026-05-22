"""HTB Sau-inspired challenge: Service proxy SSRF → internal app → auth bypass → RCE.

Attack chain:
1. Port scan reveals /api/proxy endpoint (or find via JS source)
2. /api/proxy has SSRF - can reach internal services
3. Internal service on :3000 is a "request basket" clone
4. Request basket has known CVE: path traversal in basket name
5. Use traversal to access internal Maltrail on :8338
6. Maltrail login has OS command injection in 'username' field
7. Inject command to read /flag.txt

Difficulty: HTB Medium (like Sau)
"""
import os
import subprocess
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import unquote
from flask import Flask, request, jsonify
import requests as req_lib

app = Flask(__name__)
FLAG = "FLAG{sau_proxy_chain_traversal_rce}"

# --- Internal "Maltrail" on port 8338 ---
class MaltrailHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'''<html><body>
<h1>Maltrail v0.53</h1>
<form method="POST" action="/login">
<input name="username" placeholder="admin">
<input name="password" type="password">
<button>Login</button>
</form></body></html>''')

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        username = ""
        for param in body.split("&"):
            if param.startswith("username="):
                username = unquote(param[9:])
        # CVE-2023-27163 inspired: OS command injection in username
        try:
            result = subprocess.check_output(
                f"echo 'Login attempt: {username}' >> /tmp/trail.log",
                shell=True, stderr=subprocess.STDOUT, timeout=5
            ).decode()
        except subprocess.CalledProcessError as e:
            result = e.output.decode()
        except subprocess.TimeoutExpired:
            result = ""
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"<h1>Login failed</h1><p>Invalid credentials.</p>")

    def log_message(self, *a):
        pass

# --- Internal "Request Baskets" on port 3000 ---
class BasketHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path
        # Path traversal: /baskets/../../internal routes to maltrail
        if "../" in path or "8338" in path:
            try:
                r = req_lib.get("http://127.0.0.1:8338", timeout=2)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(r.content)
                return
            except:
                pass
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'''{"name":"request-baskets","version":"1.2.1",
"baskets":["test","webhook-debug"],"note":"Create baskets at POST /api/baskets/<name>"}''')

    def do_POST(self):
        path = self.path
        if "../" in path or "8338" in path:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode()
            try:
                r = req_lib.post("http://127.0.0.1:8338/login", data=body, timeout=2)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(r.content)
                return
            except:
                pass
        self.send_response(201)
        self.end_headers()
        self.wfile.write(b'{"token":"abc123"}')

    def log_message(self, *a):
        pass

def run_maltrail():
    HTTPServer(("127.0.0.1", 8338), MaltrailHandler).serve_forever()

def run_baskets():
    HTTPServer(("127.0.0.1", 3000), BasketHandler).serve_forever()

threading.Thread(target=run_maltrail, daemon=True).start()
threading.Thread(target=run_baskets, daemon=True).start()

# Write flag
os.makedirs("/tmp", exist_ok=True)
with open("/tmp/flag.txt", "w") as f:
    f.write(FLAG)

# --- Public web app ---
@app.route("/")
def index():
    return '''<html><head><title>NetMonitor Pro</title></head><body>
<h1>NetMonitor Pro</h1>
<p>Network monitoring and traffic analysis platform.</p>
<ul>
  <li><a href="/dashboard">Dashboard</a></li>
  <li><a href="/api/status">API Status</a></li>
</ul>
<p><small>v2.4.1 | Powered by Request Baskets + Maltrail</small></p>
</body></html>'''

@app.route("/dashboard")
def dashboard():
    return '''<html><body><h1>Dashboard</h1>
<p>Active monitors: 3</p>
<script src="/static/app.js"></script>
</body></html>'''

@app.route("/static/app.js")
def app_js():
    return '''// NetMonitor Pro v2.4.1
const API_BASE = "/api";
async function checkProxy(url) {
  const resp = await fetch(API_BASE + "/proxy?url=" + encodeURIComponent(url));
  return resp.json();
}
// Internal services: baskets(:3000), maltrail(:8338)
// TODO: remove debug endpoints before production
''', 200, {"Content-Type": "application/javascript"}

@app.route("/api/status")
def api_status():
    return jsonify({"status": "ok", "services": {"baskets": 3000, "maltrail": 8338}})

@app.route("/api/proxy")
def proxy():
    """SSRF: proxy any internal URL."""
    url = request.args.get("url", "")
    if not url:
        return jsonify({"error": "provide ?url= parameter"}), 400
    # Only allow internal URLs (but this is bypassable)
    if not url.startswith("http://127.0.0.1") and not url.startswith("http://localhost"):
        return jsonify({"error": "only internal URLs allowed"}), 403
    try:
        r = req_lib.get(url, timeout=3)
        return jsonify({"status": r.status_code, "body": r.text[:3000]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/proxy", methods=["POST"])
def proxy_post():
    """SSRF POST: forward POST requests internally."""
    url = request.args.get("url", "")
    if not url:
        return jsonify({"error": "provide ?url= parameter"}), 400
    if not url.startswith("http://127.0.0.1") and not url.startswith("http://localhost"):
        return jsonify({"error": "only internal URLs allowed"}), 403
    try:
        r = req_lib.post(url, data=request.get_data(), timeout=3)
        return jsonify({"status": r.status_code, "body": r.text[:3000]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/health")
def health():
    return "ok"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
