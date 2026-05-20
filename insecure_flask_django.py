import os
from flask import Flask, request, session, make_response
import django
from django.conf import settings

app = Flask(__name__)

# Flask: hardcoded secret key
app.secret_key = "dev_secret_key_12345"

# Flask: debug mode enabled in production code
app.debug = True

# Flask: session cookie without secure flag
@app.route("/set_session")
def set_session():
    session["user_id"] = request.args.get("id")
    return "Session set"

# Flask: no CSRF protection on state-changing route
@app.route("/transfer", methods=["POST"])
def transfer_funds():
    amount = request.form.get("amount")
    to_account = request.form.get("to")
    # No CSRF token validation
    return f"Transferred {amount} to {to_account}"

# Flask: cookie set without httponly or secure
@app.route("/setcookie")
def set_cookie():
    resp = make_response("Cookie set")
    resp.set_cookie("auth_token", "abc123", httponly=False, secure=False)
    return resp

# Flask: permissive CORS
@app.route("/api/data")
def api_data():
    from flask import jsonify
    resp = make_response(jsonify({"data": "sensitive"}))
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp

# Django: DEBUG=True in settings
def configure_django_insecure():
    settings.configure(
        DEBUG=True,
        SECRET_KEY="django-insecure-hardcoded-key-abc123xyz",
        ALLOWED_HOSTS=["*"],
        DATABASES={
            "default": {
                "ENGINE": "django.db.backends.sqlite3",
                "NAME": "db.sqlite3",
            }
        },
        SESSION_COOKIE_SECURE=False,
        CSRF_COOKIE_SECURE=False,
        SECURE_SSL_REDIRECT=False,
        SECURE_HSTS_SECONDS=0,
    )

# Flask: host header injection
@app.route("/reset_password")
def reset_password():
    host = request.headers.get("Host")
    user_email = request.args.get("email")
    reset_link = f"http://{host}/reset?token=abc123"
    # Would send email with attacker-controlled host
    return f"Reset link: {reset_link}"

# Flask: verbose error messages exposed
@app.errorhandler(Exception)
def handle_error(e):
    import traceback
    return traceback.format_exc(), 500
