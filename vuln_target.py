#!/usr/bin/env python3
"""Vulnerable test target for Apex CLI practice. DO NOT expose to the internet."""

from flask import Flask, request, render_template_string, redirect, jsonify
import sqlite3
import os

app = Flask(__name__)
app.secret_key = "super_secret_key_123"  # Vuln: hardcoded secret

DB_PATH = "/tmp/vuln_app.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            role TEXT DEFAULT 'user'
        );
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            title TEXT,
            content TEXT
        );
    """)
    # Seed data
    db.execute("DELETE FROM users")
    db.execute("DELETE FROM notes")
    db.execute("INSERT INTO users (username, password, role) VALUES ('admin', 'admin123', 'admin')")
    db.execute("INSERT INTO users (username, password, role) VALUES ('guest', 'guest', 'user')")
    db.execute("INSERT INTO notes (user_id, title, content) VALUES (1, 'Flag', 'CTF{sql_injection_master}')")
    db.execute("INSERT INTO notes (user_id, title, content) VALUES (1, 'Credentials', 'AWS key: AKIA...')")
    db.execute("INSERT INTO notes (user_id, title, content) VALUES (2, 'Welcome', 'Hello guest!')")
    db.commit()
    db.close()

# ── Pages ──────────────────────────────────────────────

HOME_HTML = """<!DOCTYPE html>
<html><head><title>VulnCorp Internal</title></head><body>
<h1>VulnCorp Internal Portal</h1>
<ul>
  <li><a href="/login">Login</a></li>
  <li><a href="/search">Search Users</a></li>
  <li><a href="/notes">Notes</a></li>
  <li><a href="/ping">Server Ping</a></li>
</ul>
<!-- TODO: remove debug endpoint before production -->
</body></html>"""

@app.route("/")
def index():
    return HOME_HTML

# ── Vuln 1: SQL Injection on login ────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    msg = ""
    if request.method == "POST":
        user = request.form.get("username", "")
        pwd = request.form.get("password", "")
        db = get_db()
        # Vuln: string formatting in SQL query
        query = f"SELECT * FROM users WHERE username='{user}' AND password='{pwd}'"
        try:
            result = db.execute(query).fetchone()
            if result:
                msg = f"Welcome {result['username']}! Role: {result['role']}"
            else:
                msg = "Invalid credentials."
        except Exception as e:
            msg = f"Error: {e}"
        db.close()
    return render_template_string("""<!DOCTYPE html>
<html><head><title>Login</title></head><body>
<h2>Login</h2>
<form method="POST"><input name="username" placeholder="Username">
<input name="password" type="password" placeholder="Password">
<button type="submit">Login</button></form>
<p>{{ msg }}</p></body></html>""", msg=msg)

# ── Vuln 2: Reflected XSS on search ──────────────────

@app.route("/search")
def search():
    q = request.args.get("q", "")
    db = get_db()
    results = db.execute("SELECT username, role FROM users WHERE username LIKE ?", (f"%{q}%",)).fetchall()
    db.close()
    # Vuln: unescaped user input rendered directly
    html = f"""<!DOCTYPE html>
<html><head><title>Search</title></head><body>
<h2>User Search</h2>
<form><input name="q" value="{q}"><button>Search</button></form>
<p>Results for: {q}</p><ul>"""
    for r in results:
        html += f"<li>{r['username']} ({r['role']})</li>"
    html += "</ul></body></html>"
    return html

# ── Vuln 3: IDOR on notes ────────────────────────────

@app.route("/notes")
def notes():
    # Vuln: no auth check, direct object reference
    note_id = request.args.get("id", "1")
    db = get_db()
    note = db.execute("SELECT * FROM notes WHERE id=?", (note_id,)).fetchone()
    db.close()
    if note:
        return jsonify({"id": note["id"], "title": note["title"], "content": note["content"]})
    return jsonify({"error": "not found"}), 404

# ── Vuln 4: Command injection on ping ────────────────

@app.route("/ping", methods=["GET", "POST"])
def ping():
    output = ""
    if request.method == "POST":
        host = request.form.get("host", "")
        # Vuln: unsanitized shell command
        output = os.popen(f"ping -c 1 {host} 2>&1").read()
    return render_template_string("""<!DOCTYPE html>
<html><head><title>Ping</title></head><body>
<h2>Server Ping Utility</h2>
<form method="POST"><input name="host" placeholder="hostname or IP">
<button>Ping</button></form>
<pre>{{ output }}</pre></body></html>""", output=output)

# ── Vuln 5: Info disclosure / debug endpoint ─────────

@app.route("/debug")
def debug():
    # Vuln: exposed debug info
    return jsonify({
        "app": "VulnCorp Internal",
        "version": "0.1-dev",
        "secret_key": app.secret_key,
        "db_path": DB_PATH,
        "env": dict(os.environ),
    })

# ── Vuln 6: Open redirect ────────────────────────────

@app.route("/redirect")
def open_redirect():
    url = request.args.get("url", "/")
    # Vuln: no validation on redirect target
    return redirect(url)

# ── Decoy safe endpoints (to make fuzzing interesting) ─

@app.route("/about")
def about():
    return "<h1>VulnCorp</h1><p>We take security seriously.</p>"

@app.route("/robots.txt")
def robots():
    return "User-agent: *\nDisallow: /debug\nDisallow: /admin\n", 200, {"Content-Type": "text/plain"}

@app.route("/admin")
def admin():
    return "Forbidden", 403

@app.route("/.env")
def env_file():
    # Vuln: exposed env file
    return "DB_HOST=localhost\nDB_PASS=vulncorp2024\nAWS_SECRET=wJalrXUtnFEMI/K7MDENG/bPxRfiCY\n", 200, {"Content-Type": "text/plain"}

if __name__ == "__main__":
    init_db()
    print("\n🎯 Vulnerable target running at http://localhost:5000")
    print("   Scan it with: apex-cli localhost --dry-run")
    print("   Or for real:  apex-cli localhost\n")
    app.run(host="127.0.0.1", port=5000, debug=False)
