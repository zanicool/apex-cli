"""HTB-inspired BOSS challenge: Full attack chain simulation.

This is the final boss. Multiple attack paths, red herrings, and real-world complexity.

Attack chain (intended path):
1. Homepage leaks employee names in HTML comments
2. /careers page has a file upload (resume) with unrestricted type
3. Upload a .html file → stored XSS at /uploads/<file>
4. But that's a rabbit hole. Real path: /api/v1/docs reveals Swagger
5. Swagger shows /api/v1/users/{id} endpoint (IDOR)
6. User id=1 (admin) response includes "reset_token" field
7. Use reset_token at /api/v1/auth/reset to change admin password
8. Login as admin → /api/v1/admin/exec endpoint
9. Exec has WAF blocking common commands (cat, ls, whoami)
10. Bypass WAF: use base64 decode or wildcard (c?t /flag.txt)

Difficulty: HTB Hard
Points: 250
"""
import os
import uuid
import hashlib
import base64
import re
from flask import Flask, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename

app = Flask(__name__)
FLAG = "FLAG{boss_idor_reset_waf_bypass_rce}"
UPLOAD_DIR = "/tmp/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Write flag
with open("/tmp/flag.txt", "w") as f:
    f.write(FLAG)

# User database
users_db = {
    1: {"id": 1, "username": "admin", "email": "admin@megacorp.local",
        "role": "admin", "password": hashlib.sha256(b"Sup3rS3cr3t!").hexdigest(),
        "reset_token": "rst_" + uuid.uuid4().hex[:16]},
    2: {"id": 2, "username": "j.smith", "email": "john.smith@megacorp.local",
        "role": "user", "password": hashlib.sha256(b"john2026").hexdigest(),
        "reset_token": "rst_" + uuid.uuid4().hex[:16]},
    3: {"id": 3, "username": "s.jones", "email": "sarah.jones@megacorp.local",
        "role": "user", "password": hashlib.sha256(b"sarah!23").hexdigest(),
        "reset_token": "rst_" + uuid.uuid4().hex[:16]},
}
sessions = {}

def get_current_user():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    return sessions.get(token)

# --- Public pages ---
@app.route("/")
def index():
    return '''<html><head><title>MegaCorp Industries</title></head><body>
<h1>MegaCorp Industries</h1>
<nav><a href="/about">About</a> | <a href="/careers">Careers</a> | <a href="/contact">Contact</a></nav>
<p>Leading provider of enterprise solutions since 2019.</p>
<!-- Team: j.smith (dev), s.jones (hr), admin (ops) -->
<!-- TODO: remove debug API docs before launch -->
<footer><small>Powered by MegaCorp API v1.2.3</small></footer>
</body></html>'''

@app.route("/about")
def about():
    return '''<h1>About Us</h1><p>Founded by John Smith and Sarah Jones.</p>
<p>Tech stack: Python, PostgreSQL, Redis, Docker</p>'''

@app.route("/careers")
def careers():
    return '''<html><body><h1>Careers at MegaCorp</h1>
<p>Upload your resume to apply:</p>
<form method="POST" action="/careers/apply" enctype="multipart/form-data">
<input name="name" placeholder="Full name"><br>
<input name="resume" type="file"><br>
<button>Apply</button></form></body></html>'''

@app.route("/careers/apply", methods=["POST"])
def apply():
    f = request.files.get("resume")
    if not f:
        return "No file uploaded", 400
    filename = secure_filename(f.filename) or "resume.pdf"
    # Unrestricted upload (rabbit hole - XSS possible but not the flag path)
    path = os.path.join(UPLOAD_DIR, filename)
    f.save(path)
    return f'''<h1>Thanks!</h1><p>Resume uploaded: <a href="/uploads/{filename}">{filename}</a></p>'''

@app.route("/uploads/<path:filename>")
def uploads(filename):
    return send_from_directory(UPLOAD_DIR, filename)

# --- API ---
@app.route("/api/v1/docs")
def api_docs():
    return jsonify({
        "openapi": "3.0.0",
        "info": {"title": "MegaCorp API", "version": "1.2.3"},
        "paths": {
            "/api/v1/auth/login": {"post": {"summary": "Login", "parameters": ["username", "password"]}},
            "/api/v1/auth/reset": {"post": {"summary": "Reset password", "parameters": ["token", "new_password"]}},
            "/api/v1/users/{id}": {"get": {"summary": "Get user profile"}},
            "/api/v1/admin/exec": {"post": {"summary": "Execute maintenance command (admin only)"}},
        }
    })

@app.route("/api/v1/auth/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    for uid, user in users_db.items():
        if user["username"] == username and user["password"] == pw_hash:
            token = uuid.uuid4().hex
            sessions[token] = user
            return jsonify({"token": token, "role": user["role"]})
    return jsonify({"error": "invalid credentials"}), 401

@app.route("/api/v1/auth/reset", methods=["POST"])
def reset_password():
    data = request.get_json(silent=True) or {}
    token = data.get("token", "")
    new_password = data.get("new_password", "")
    if not token or not new_password:
        return jsonify({"error": "token and new_password required"}), 400
    for uid, user in users_db.items():
        if user["reset_token"] == token:
            user["password"] = hashlib.sha256(new_password.encode()).hexdigest()
            return jsonify({"status": "password reset successful", "username": user["username"]})
    return jsonify({"error": "invalid reset token"}), 401

@app.route("/api/v1/users/<int:user_id>")
def get_user(user_id):
    """IDOR: no auth check, exposes reset_token."""
    user = users_db.get(user_id)
    if not user:
        return jsonify({"error": "user not found"}), 404
    # Leaks too much info including reset_token
    return jsonify({
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
        "reset_token": user["reset_token"],
        "last_login": "2026-05-22T10:00:00Z"
    })

@app.route("/api/v1/admin/exec", methods=["POST"])
def admin_exec():
    user = get_current_user()
    if not user or user["role"] != "admin":
        return jsonify({"error": "admin access required"}), 403
    data = request.get_json(silent=True) or {}
    cmd = data.get("cmd", "")
    if not cmd:
        return jsonify({"error": "provide 'cmd' parameter"}), 400
    # WAF: block common commands
    blocked = ["cat", "ls", "whoami", "id", "pwd", "env", "printenv",
               "wget", "curl", "nc", "bash", "sh", "python"]
    cmd_lower = cmd.lower()
    for b in blocked:
        if b in cmd_lower:
            return jsonify({"error": f"WAF: '{b}' is blocked"}), 403
    # But bypassable: c?t, ca$@t, base64, head, tail, less, more, tac, etc.
    import subprocess
    try:
        result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=5).decode()
        return jsonify({"output": result})
    except subprocess.CalledProcessError as e:
        return jsonify({"output": e.output.decode()})
    except subprocess.TimeoutExpired:
        return jsonify({"error": "timeout"})

@app.route("/health")
def health():
    return "ok"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
