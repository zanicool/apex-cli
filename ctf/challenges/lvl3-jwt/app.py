import jwt, json, base64
from flask import Flask, request, make_response

app = Flask(__name__)
SECRET = "super-secret-key-123"
FLAG = "FLAG{jwt_none_algorithm_bypass}"

@app.route("/")
def index():
    return '''<h1>JWT Auth System</h1>
    <p><a href="/login">Login as guest</a></p>
    <p><a href="/admin">Admin panel</a> (admin only)</p>'''

@app.route("/login")
def login():
    token = jwt.encode({"user": "guest", "role": "user"}, SECRET, algorithm="HS256")
    resp = make_response(f'<h1>Logged in as guest</h1><p>Your token: <code>{token}</code></p><p>Now try accessing <a href="/admin">/admin</a></p>')
    resp.set_cookie("token", token)
    return resp

@app.route("/admin")
def admin():
    token = request.cookies.get("token") or request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        return "No token provided. <a href='/login'>Login first</a>", 401
    try:
        # Vulnerable: accepts 'none' algorithm
        header = json.loads(base64.b64decode(token.split('.')[0] + '=='))
        if header.get('alg') == 'none':
            payload = json.loads(base64.b64decode(token.split('.')[1] + '=='))
        else:
            payload = jwt.decode(token, SECRET, algorithms=["HS256"])
        if payload.get("role") == "admin":
            return f"<h1>Welcome Admin!</h1><p>{FLAG}</p>"
        return f"<h1>Access Denied</h1><p>Role '{payload.get('role')}' is not admin</p>", 403
    except Exception as e:
        return f"Invalid token: {e}", 401

@app.route("/health")
def health():
    return "ok"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
