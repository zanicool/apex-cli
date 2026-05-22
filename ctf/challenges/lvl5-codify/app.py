"""HTB Codify-inspired challenge: Sandbox escape + credential extraction.

Attack chain:
1. App is a "code sandbox" that runs user JavaScript
2. The sandbox (vm2-style) has a known escape via Error.prepareStackTrace
3. Escape sandbox to get Node.js access → read /app/.env
4. .env contains MONGO_URI with credentials
5. Use credentials at /api/admin/login
6. Admin panel at /api/admin/backup has path traversal
7. Read /flag.txt via backup download

Simplified for CTF: Python sandbox with escape via __import__
"""
import os
import re
import json
from flask import Flask, request, jsonify

app = Flask(__name__)
FLAG = "FLAG{sandbox_escape_env_leak_privesc}"
DB_PASSWORD = "m0ng0_s3cr3t_2026"

# Write flag and env
os.makedirs("/tmp", exist_ok=True)
with open("/tmp/flag.txt", "w") as f:
    f.write(FLAG)
with open("/tmp/.env", "w") as f:
    f.write(f"MONGO_URI=mongodb://admin:{DB_PASSWORD}@localhost:27017/app\nSECRET_KEY=changeme\n")

@app.route("/")
def index():
    return '''<html><head><title>CodeBox — Online Python Sandbox</title></head><body>
<h1>🐍 CodeBox</h1>
<p>Run Python code safely in our sandbox. No file access, no imports!</p>
<form method="POST" action="/api/run">
<textarea name="code" rows="10" cols="60" placeholder="print('Hello, World!')"></textarea><br>
<button>Run Code</button>
</form>
<p><small>Restricted: no import, no open, no eval, no exec</small></p>
<hr>
<p><a href="/api/admin/login">Admin Login</a></p>
</body></html>'''

@app.route("/api/run", methods=["POST"])
def run_code():
    code = request.form.get("code") or (request.get_json(silent=True) or {}).get("code", "")
    if not code:
        return jsonify({"error": "provide 'code' parameter"}), 400

    # "Sandbox" - blocks obvious dangerous patterns
    blocked = ["import os", "import sys", "import subprocess", "open(", "__import__",
               "eval(", "exec(", "compile("]
    for b in blocked:
        if b in code:
            return jsonify({"error": f"blocked: '{b}' is not allowed in sandbox"}), 403

    # But the bypass: using getattr + globals or __builtins__
    # e.g.: getattr(__builtins__, '__im'+'port__')('os').popen('cat /tmp/.env').read()
    try:
        # Intentionally vulnerable: restricted exec but bypassable
        sandbox_globals = {"__builtins__": __builtins__}
        exec_result = {}
        exec(f"import io, sys\n_out = io.StringIO()\nsys.stdout = _out\n{code}\nsys.stdout = sys.__stdout__\n_result = _out.getvalue()", sandbox_globals, exec_result)
        output = exec_result.get("_result", "")
        return jsonify({"output": output[:5000]})
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route("/api/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "GET":
        return '''<form method="POST">
<input name="username" placeholder="admin">
<input name="password" type="password">
<button>Login</button></form>'''
    password = request.form.get("password") or (request.get_json(silent=True) or {}).get("password", "")
    if password == DB_PASSWORD:
        return jsonify({"status": "ok", "token": "admin-session-xyz", "endpoints": ["/api/admin/backup?path="]})
    return jsonify({"error": "invalid credentials"}), 401

@app.route("/api/admin/backup")
def admin_backup():
    auth = request.headers.get("X-Admin-Token", "") or request.args.get("token", "")
    if auth != "admin-session-xyz":
        return jsonify({"error": "admin token required"}), 401
    path = request.args.get("path", "/app")
    # Path traversal in backup
    try:
        if os.path.isfile(path):
            with open(path) as f:
                return jsonify({"file": path, "content": f.read()})
        elif os.path.isdir(path):
            return jsonify({"dir": path, "files": os.listdir(path)})
        return jsonify({"error": "not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route("/health")
def health():
    return "ok"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
