#!/usr/bin/env python3
"""Vulnerable target for apex-cli vs Burp Suite Pro benchmark."""

import os, subprocess, sqlite3, json
from flask import Flask, request, redirect as flask_redirect, jsonify

app = Flask(__name__)

# --- Vulnerability 1: SQL Injection (login) ---
USERS_DB_PATH = "/tmp/vuln_users.db"

def init_db():
    conn = sqlite3.connect(USERS_DB_PATH)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER, username TEXT, password TEXT)")
    try:
        c.execute("INSERT INTO users VALUES (1,'admin','password123'), (2,'user','secret')")
        conn.commit()
    except Exception:
        pass
    conn.close()

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return "<html><body><h1>Login</h1>" \
               '<form method="post"><input name="user" placeholder="Username">' \
               '<input type="password" name="pass" placeholder="Password">' \
               '<button>Submit</button></form></body></html>'
    user = request.form.get("user", "")
    password = request.form.get("pass", "")
    # Vulnerable: string concatenation in SQL query
    conn = sqlite3.connect(USERS_DB_PATH)
    c = conn.cursor()
    query = f"SELECT * FROM users WHERE username='{user}' AND password='{password}'"
    try:
        c.execute(query)
        rows = c.fetchall()
        if rows:
            return {"status": "ok", "user": user}
        else:
            return {"status": "fail"}, 401
    except Exception as e:
        return {"error": str(e)}, 500
    finally:
        conn.close()

# --- Vulnerability 2: XSS (reflected) ---
@app.route("/search")
def search():
    q = request.args.get("q", "")
    # Vulnerable: reflected user input without escaping
    return f"<html><body><h1>Search results for {q}</h1></body></html>"

# --- Vulnerability 3: IDOR (notes) ---
NOTES = {1: "Secret project plan - DO NOT SHARE", 2: "Personal diary entry", 999: "Public note"}

@app.route("/notes")
def notes():
    nid = request.args.get("id", 0, type=int)
    # Vulnerable: no auth check, direct object reference
    if nid in NOTES:
        return {"note": NOTES[nid]}
    return {"error": "not found"}, 404

# --- Vulnerability 4: Command Injection ---
@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    # Vulnerable: passes user input to shell command
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
    return {"output": result.stdout}

# --- Vulnerability 5: Info Disclosure ---
@app.route("/debug")
def debug():
    # Vulnerable: exposes internal details
    info = {
        "version": "1.0.3",
        "database_path": USERS_DB_PATH,
        "python_version": os.popen("python3 --version").read().strip(),
        "env_vars": dict(os.environ).get("SECRET_KEY", "hidden"),
        "config": json.dumps({"debug": True, "verbose": True}),
    }
    return jsonify(info)

# --- Vulnerability 6: Open Redirect ---
@app.route("/redirect")
def redirect():
    url = request.args.get("url", "")
    # Vulnerable: unvalidated redirect parameter
    return flask_redirect(url if url else "/")

# --- Vulnerability 7: Sensitive File Exposure (.env) ---
ENV_CONTENT = """SECRET_KEY=my-super-secret-key-12345
DB_PASSWORD=admin_pass_42
AWS_ACCESS_KEY=AKIAIOSFODNEEXAMPLE
"""

@app.route("/.env", methods=["GET"])
def env_file():
    # Vulnerable: exposes .env file content directly
    return ENV_CONTENT, 200, {"Content-Type": "text/plain"}

# --- Vulnerability 8: Hardcoded Secret in JSON response ---
@app.route("/api/config")
def api_config():
    # Vulnerable: hardcoded secrets returned to client
    config = {
        "app_name": "VulnApp",
        "jwt_secret": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dico",
        "api_key": "sk-proj-abc123secret456def789ghi",
        "db_url": "postgresql://admin:password@localhost/vulnapp",
    }
    return jsonify(config)

# --- Health endpoint ---
@app.route("/health")
def health():
    return "ok"

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)
