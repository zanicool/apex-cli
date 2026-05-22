from flask import Flask, request, render_template_string
app = Flask(__name__)

@app.route("/")
def index():
    return '''<h1>Greeting Card Generator</h1>
    <form action="/greet"><input name="name" placeholder="Your name">
    <button>Generate</button></form>'''

@app.route("/greet")
def greet():
    name = request.args.get("name", "World")
    # Vulnerable: user input directly in template
    template = f"<h1>Hello {name}!</h1><p>Your greeting card is ready.</p>"
    return render_template_string(template)

@app.route("/health")
def health():
    return "ok"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
