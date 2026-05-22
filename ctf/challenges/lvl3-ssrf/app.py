import threading
from flask import Flask, request
from http.server import HTTPServer, BaseHTTPRequestHandler
import requests

app = Flask(__name__)
FLAG = "FLAG{ssrf_internal_service_pwned}"

# Internal service on port 6379 (simulates Redis/internal API)
class InternalHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(f"INTERNAL SERVICE\n{FLAG}\n".encode())
    def log_message(self, *a): pass

def run_internal():
    HTTPServer(("127.0.0.1", 6379), InternalHandler).serve_forever()

threading.Thread(target=run_internal, daemon=True).start()

@app.route("/")
def index():
    return '''<h1>URL Preview Tool</h1>
    <form action="/fetch"><input name="url" placeholder="https://example.com" size="40">
    <button>Fetch</button></form>
    <p>Preview any URL!</p>'''

@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    if not url:
        return "Provide a URL", 400
    try:
        r = requests.get(url, timeout=3)
        return f"<pre>{r.text[:500]}</pre>"
    except Exception as e:
        return f"Error: {e}", 500

@app.route("/health")
def health():
    return "ok"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
