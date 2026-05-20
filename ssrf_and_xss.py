import requests
import urllib.request
from flask import Flask, request, render_template_string

app = Flask(__name__)

# SSRF: user-controlled URL fetched directly
@app.route("/fetch")
def fetch_url():
    url = request.args.get("url")
    response = requests.get(url)
    return response.text

# SSRF via urllib
@app.route("/proxy")
def proxy():
    target = request.args.get("target")
    with urllib.request.urlopen(target) as resp:
        return resp.read()

# SSRF: webhook delivery to user-supplied endpoint
def send_webhook(payload, endpoint):
    requests.post(endpoint, json=payload)

# SSRF: image fetch from user-provided URL
@app.route("/avatar")
def fetch_avatar():
    image_url = request.args.get("image_url")
    r = requests.get(image_url, timeout=5)
    return r.content, 200, {"Content-Type": "image/png"}

# XSS: user input reflected directly into HTML response
@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    return "<html><body>Hello, " + name + "!</body></html>"

# XSS via render_template_string with user input
@app.route("/search")
def search():
    query = request.args.get("q", "")
    template = f"<h1>Results for: {query}</h1>"
    return render_template_string(template)

# XSS: error message reflected back
@app.route("/error")
def show_error():
    msg = request.args.get("msg", "Unknown error")
    return f"<p class='error'>{msg}</p>"

# Reflected XSS in redirect
@app.route("/redirect")
def unsafe_redirect():
    next_url = request.args.get("next", "/")
    return f'<script>window.location="{next_url}"</script>'

# Open redirect
@app.route("/login_redirect")
def login_redirect():
    dest = request.args.get("redirect")
    from flask import redirect
    return redirect(dest)
