from flask import Flask, request
app = Flask(__name__)

@app.route("/")
def index():
    return '<h1>File Viewer</h1><p>Try: <a href="/view?file=welcome.txt">/view?file=welcome.txt</a></p>'

@app.route("/view")
def view():
    filename = request.args.get("file", "welcome.txt")
    try:
        with open(f"/app/files/{filename}") as f:
            return f"<pre>{f.read()}</pre>"
    except:
        return "File not found", 404

@app.route("/health")
def health():
    return "ok"

if __name__ == "__main__":
    import os
    os.makedirs("/app/files", exist_ok=True)
    with open("/app/files/welcome.txt", "w") as f:
        f.write("Welcome! Try reading other files on the system...")
    app.run(host="0.0.0.0", port=5000)
