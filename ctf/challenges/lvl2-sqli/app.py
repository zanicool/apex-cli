from flask import Flask, request
app = Flask(__name__)

FLAG = "FLAG{sql_injection_master}"

@app.route("/")
def index():
    return '''<h1>Login</h1>
    <form method="POST" action="/login">
    <input name="username" placeholder="username"><br>
    <input name="password" type="password" placeholder="password"><br>
    <button>Login</button></form>'''

@app.route("/login", methods=["POST"])
def login():
    user = request.form.get("username", "")
    pwd = request.form.get("password", "")
    # Vulnerable: string concatenation in "query"
    query = f"SELECT * FROM users WHERE username='{user}' AND password='{pwd}'"
    if "' OR '" in query or "'=''" in query or "OR 1=1" in query.upper():
        return f"<h1>Welcome admin!</h1><p>{FLAG}</p>"
    if user == "admin" and pwd == "supersecretpassword123":
        return f"<h1>Welcome admin!</h1><p>{FLAG}</p>"
    return "<h1>Access Denied</h1><p>Wrong credentials</p>", 401

@app.route("/health")
def health():
    return "ok"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
