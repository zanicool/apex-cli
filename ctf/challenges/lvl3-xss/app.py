"""Stored XSS challenge:
Post a comment with XSS. The "admin bot" visits every 5 seconds.
The admin's cookie contains the flag. Steal it.
"""
import threading, time
from flask import Flask, request, make_response

app = Flask(__name__)
FLAG = "FLAG{stored_xss_cookie_theft}"
COMMENTS = []
STOLEN = []

@app.route("/")
def index():
    comments_html = "".join(f"<div class='comment'>{c}</div>" for c in COMMENTS)
    return f'''<html><body>
    <h1>💬 Guestbook</h1>
    <form method="POST" action="/comment">
    <input name="msg" placeholder="Leave a comment" size="40">
    <button>Post</button></form>
    <h3>Comments:</h3>{comments_html}
    <hr><p><small>Admin reviews all comments periodically.</small></p>
    <p><a href="/stolen">Check stolen data</a></p>
    </body></html>'''

@app.route("/comment", methods=["POST"])
def comment():
    msg = request.form.get("msg", "")
    if msg:
        COMMENTS.append(msg)
    return '<script>location="/"</script>'

@app.route("/steal")
def steal():
    """Endpoint where XSS payload sends stolen cookies"""
    data = request.args.get("c", "")
    if data:
        STOLEN.append(data)
    return "ok"

@app.route("/stolen")
def show_stolen():
    if not STOLEN:
        return "<h1>Nothing stolen yet</h1><p>Hint: make the admin visit a URL that sends their cookie to /steal?c=...</p>"
    return "<h1>Stolen Data:</h1><pre>" + "\n".join(STOLEN) + "</pre>"

@app.route("/health")
def health():
    return "ok"

# Simulate admin bot visiting comments
def admin_bot():
    """Simulates admin viewing comments - their cookie contains the flag"""
    import urllib.request
    while True:
        time.sleep(5)
        try:
            req = urllib.request.Request("http://127.0.0.1:5000/")
            req.add_header("Cookie", f"session={FLAG}")
            urllib.request.urlopen(req, timeout=2)
            # If any comment contains a script that fetches /steal, it "works"
            for c in COMMENTS:
                if "steal" in c.lower() or "script" in c.lower():
                    # Simulate the XSS executing
                    steal_url = f"http://127.0.0.1:5000/steal?c={FLAG}"
                    urllib.request.urlopen(steal_url, timeout=2)
                    break
        except:
            pass

threading.Thread(target=admin_bot, daemon=True).start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
