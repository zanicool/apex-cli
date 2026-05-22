"""Multi-step chain challenge:
1. Find the open redirect at /redirect?url=
2. Notice /api/user leaks role info
3. Use /api/user?role=admin (mass assignment) to escalate
4. Access /flag with admin role
"""
from flask import Flask, request, redirect, session, jsonify
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
FLAG = "FLAG{chain_redirect_massassign_escalate}"

@app.route("/")
def index():
    role = session.get("role", "guest")
    return f'''<html><body>
    <h1>ChainApp v1.0</h1>
    <p>Role: {role}</p>
    <ul>
      <li><a href="/login">Login</a></li>
      <li><a href="/profile">Profile</a></li>
      <li><a href="/flag">Flag</a> (admin only)</li>
      <li><a href="/redirect?url=/">Home redirect</a></li>
    </ul></body></html>'''

@app.route("/login")
def login():
    session["user"] = "zani"
    session["role"] = "user"
    return redirect(request.args.get("next", "/"))

@app.route("/redirect")
def redir():
    url = request.args.get("url", "/")
    # Vulnerable: open redirect
    return redirect(url)

@app.route("/profile")
def profile():
    return jsonify({"user": session.get("user", "guest"), "role": session.get("role", "guest")})

@app.route("/api/user", methods=["GET", "POST"])
def api_user():
    if request.method == "POST":
        # Vulnerable: mass assignment - accepts any field including 'role'
        data = request.get_json(silent=True) or request.form.to_dict()
        for key, val in data.items():
            session[key] = val
        return jsonify({"status": "updated", "user": session.get("user"), "role": session.get("role")})
    return jsonify({"user": session.get("user", "guest"), "role": session.get("role", "guest")})

@app.route("/flag")
def flag():
    if session.get("role") == "admin":
        return f"<h1>🏆 {FLAG}</h1>"
    return "<h1>❌ Admin only</h1><p>Your role: " + session.get("role", "guest") + "</p>", 403

@app.route("/health")
def health():
    return "ok"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
