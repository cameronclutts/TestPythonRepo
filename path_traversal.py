import os
import flask
from flask import Flask, request, send_file

app = Flask(__name__)

BASE_DIR = "/var/www/files"

# Path traversal via direct join with user input
@app.route("/download")
def download_file():
    filename = request.args.get("filename")
    file_path = os.path.join(BASE_DIR, filename)
    return send_file(file_path)

# Path traversal when reading file contents
@app.route("/read")
def read_file():
    filename = request.args.get("file")
    with open("/uploads/" + filename, "r") as f:
        return f.read()

# Path traversal via open() with format string
def get_user_config(user_id):
    config_path = "/app/configs/%s.cfg" % user_id
    with open(config_path) as f:
        return f.read()

# Path traversal when writing files
@app.route("/upload", methods=["POST"])
def upload_file():
    filename = request.form.get("filename")
    content = request.form.get("content")
    path = os.path.join("/uploads/", filename)
    with open(path, "w") as f:
        f.write(content)
    return "Uploaded"

# Path traversal via template rendering
@app.route("/page")
def load_page():
    page = request.args.get("page")
    template_path = f"templates/{page}.html"
    with open(template_path) as f:
        return f.read()
