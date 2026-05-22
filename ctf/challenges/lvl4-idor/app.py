"""HTB Cap-inspired challenge: IDOR → credential leak → flag.

The app is a "Security Dashboard" that shows network captures.
Each user has their own capture at /data/<id>.
The IDOR: user is assigned id=5, but id=0 contains admin's capture
with plaintext credentials. Use those creds at /admin to get the flag.
"""
from flask import Flask, request, jsonify
import json, os

app = Flask(__name__)
FLAG = "FLAG{idor_pcap_credential_leak}"
ADMIN_PASSWORD = "S3cur1ty_C4ptur3!"

# Simulated captures
CAPTURES = {
    0: {"user": "admin", "packets": 42, "data": f"FTP LOGIN: admin:{ADMIN_PASSWORD}"},
    1: {"user": "nathan", "packets": 7, "data": "HTTP GET /index.html 200 OK"},
    2: {"user": "nathan", "packets": 3, "data": "DNS query: google.com"},
    3: {"user": "nathan", "packets": 12, "data": "TLS handshake with api.github.com"},
    4: {"user": "nathan", "packets": 1, "data": "ICMP ping 8.8.8.8"},
    5: {"user": "nathan", "packets": 5, "data": "HTTP GET /dashboard 200 OK"},
}

@app.route("/")
def index():
    return '''<html><head><title>Security Dashboard</title></head><body>
    <h1>🛡️ Security Dashboard</h1>
    <p>Welcome, <b>nathan</b> | <a href="/logout">Logout</a></p>
    <ul>
      <li><a href="/data/5">Your Network Capture</a></li>
      <li><a href="/admin">Admin Panel</a> (restricted)</li>
    </ul>
    <p><small>Dashboard v2.1 | Captures: 6 total</small></p>
    </body></html>'''

@app.route("/data/<int:capture_id>")
def data(capture_id):
    cap = CAPTURES.get(capture_id)
    if cap is None:
        return "Capture not found", 404
    return f'''<html><body>
    <h1>Capture #{capture_id}</h1>
    <p>User: {cap["user"]}</p>
    <p>Packets: {cap["packets"]}</p>
    <h3>Capture Data:</h3>
    <pre>{cap["data"]}</pre>
    <p><a href="/">Back to Dashboard</a></p>
    </body></html>'''

@app.route("/admin", methods=["GET", "POST"])
def admin():
    if request.method == "POST":
        password = request.form.get("password", "")
        if password == ADMIN_PASSWORD:
            return f"<h1>🏆 Admin Access Granted!</h1><p>{FLAG}</p>"
        return "<h1>❌ Wrong password</h1><a href='/admin'>Try again</a>", 401
    return '''<html><body>
    <h1>Admin Panel</h1>
    <form method="POST">
    <input name="password" type="password" placeholder="Admin password">
    <button>Login</button>
    </form></body></html>'''

@app.route("/health")
def health():
    return "ok"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
