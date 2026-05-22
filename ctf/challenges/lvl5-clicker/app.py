"""HTB Clicker-inspired challenge: Race condition + parameter pollution + priv esc.

Attack chain:
1. Register account at /register
2. Notice /api/profile returns role=user, credits=0
3. /api/click increments credits (1 per click)
4. Race condition: send 100 concurrent /api/click → get 1000+ credits
5. /api/shop shows "Admin Role" costs 1000 credits
6. Buy admin role, but server checks role via JWT claim
7. JWT uses weak secret "password123" — forge token with role=admin
8. Access /api/admin/flag with forged admin JWT

Difficulty: HTB Medium-Hard (like Clicker)
"""
import jwt
import json
import time
import hashlib
from flask import Flask, request, jsonify, make_response
from threading import Lock

app = Flask(__name__)
FLAG = "FLAG{race_condition_jwt_forge_privesc}"
JWT_SECRET = "password123"  # Intentionally weak

# In-memory user store
users = {}
users_lock = Lock()

def get_user_from_token():
    token = request.cookies.get("session") or request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        return None
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except:
        return None

@app.route("/")
def index():
    return '''<html><head><title>ClickerGame</title></head><body>
<h1>🎮 ClickerGame Pro</h1>
<p>Click to earn credits. Buy upgrades in the shop!</p>
<ul>
  <li><a href="/register">Register</a></li>
  <li><a href="/login">Login</a></li>
  <li><a href="/game">Play</a></li>
  <li><a href="/api/shop">Shop</a></li>
</ul>
<script>
// Game logic
async function click() {
  const r = await fetch("/api/click", {method: "POST"});
  const d = await r.json();
  document.getElementById("credits").textContent = d.credits;
}
</script>
</body></html>'''

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return '''<form method="POST">
<input name="username" placeholder="username">
<input name="password" type="password" placeholder="password">
<button>Register</button></form>'''
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    if not username or not password:
        return "Missing fields", 400
    with users_lock:
        if username in users:
            return "User exists", 409
        users[username] = {
            "password": hashlib.sha256(password.encode()).hexdigest(),
            "credits": 0,
            "role": "user",
            "clicks": 0
        }
    token = jwt.encode({"user": username, "role": "user"}, JWT_SECRET, algorithm="HS256")
    resp = make_response(jsonify({"status": "registered", "token": token}))
    resp.set_cookie("session", token)
    return resp

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return '''<form method="POST">
<input name="username"><input name="password" type="password">
<button>Login</button></form>'''
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    with users_lock:
        user = users.get(username)
        if not user or user["password"] != pw_hash:
            return "Invalid credentials", 401
    token = jwt.encode({"user": username, "role": user["role"]}, JWT_SECRET, algorithm="HS256")
    resp = make_response(jsonify({"status": "ok", "token": token}))
    resp.set_cookie("session", token)
    return resp

@app.route("/api/profile")
def profile():
    payload = get_user_from_token()
    if not payload:
        return jsonify({"error": "login required"}), 401
    with users_lock:
        user = users.get(payload["user"], {})
    return jsonify({
        "user": payload["user"],
        "role": payload["role"],
        "credits": user.get("credits", 0),
        "clicks": user.get("clicks", 0)
    })

@app.route("/api/click", methods=["POST"])
def click():
    """Vulnerable to race condition: no atomic increment."""
    payload = get_user_from_token()
    if not payload:
        return jsonify({"error": "login required"}), 401
    username = payload["user"]
    # Intentionally vulnerable: read-modify-write without lock
    user = users.get(username)
    if not user:
        return jsonify({"error": "user not found"}), 404
    current = user["credits"]
    time.sleep(0.01)  # Amplify race window
    user["credits"] = current + 1
    user["clicks"] = user.get("clicks", 0) + 1
    return jsonify({"credits": user["credits"], "clicks": user["clicks"]})

@app.route("/api/shop")
def shop():
    payload = get_user_from_token()
    if not payload:
        return jsonify({"error": "login required"}), 401
    with users_lock:
        user = users.get(payload["user"], {})
    return jsonify({
        "items": [
            {"name": "Double Click", "cost": 100, "id": "double"},
            {"name": "Auto Clicker", "cost": 500, "id": "auto"},
            {"name": "Admin Role", "cost": 1000, "id": "admin_role"},
        ],
        "your_credits": user.get("credits", 0)
    })

@app.route("/api/shop/buy", methods=["POST"])
def buy():
    payload = get_user_from_token()
    if not payload:
        return jsonify({"error": "login required"}), 401
    data = request.get_json(silent=True) or {}
    item_id = data.get("item", "")
    username = payload["user"]
    with users_lock:
        user = users.get(username)
        if not user:
            return jsonify({"error": "user not found"}), 404
        costs = {"double": 100, "auto": 500, "admin_role": 1000}
        cost = costs.get(item_id, 0)
        if user["credits"] < cost:
            return jsonify({"error": f"need {cost} credits, have {user['credits']}"}), 402
        user["credits"] -= cost
        if item_id == "admin_role":
            user["role"] = "admin"
            token = jwt.encode({"user": username, "role": "admin"}, JWT_SECRET, algorithm="HS256")
            resp = make_response(jsonify({"status": "purchased", "new_role": "admin", "token": token}))
            resp.set_cookie("session", token)
            return resp
    return jsonify({"status": "purchased", "item": item_id})

@app.route("/api/admin/flag")
def admin_flag():
    payload = get_user_from_token()
    if not payload:
        return jsonify({"error": "login required"}), 401
    if payload.get("role") != "admin":
        return jsonify({"error": "admin only", "your_role": payload.get("role")}), 403
    return jsonify({"flag": FLAG})

@app.route("/game")
def game():
    return '''<html><body><h1>🎮 Click!</h1>
<p>Credits: <span id="credits">0</span></p>
<button onclick="click()">CLICK</button>
<script>
async function click(){
  const r = await fetch("/api/click",{method:"POST"});
  const d = await r.json();
  document.getElementById("credits").textContent = d.credits;
}
</script></body></html>'''

@app.route("/health")
def health():
    return "ok"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
