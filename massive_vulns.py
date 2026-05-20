"""
Intentionally vulnerable file for Semgrep testing.
Contains 200+ distinct vulnerability instances across multiple categories.
DO NOT USE IN PRODUCTION.
"""

import os
import sys
import ssl
import time
import hmac
import math
import json
import math
import random
import base64
import pickle
import socket
import shutil
import struct
import shelve
import hashlib
import marshal
import logging
import sqlite3
import tempfile
import subprocess
import xml.etree.ElementTree as ET
from http import server
from urllib import request as urllib_request
from flask import Flask, request, session, redirect, make_response, render_template_string, send_file, jsonify
from jinja2 import Template, Environment
import requests
import yaml

app = Flask(__name__)

# ===========================================================================
# SECTION 1: HARDCODED SECRETS (30 instances)
# ===========================================================================

SECRET_KEY_1       = "hardcoded_flask_secret_abc123"
SECRET_KEY_2       = "another_secret_key_xyz789"
SECRET_KEY_3       = "jwt_signing_secret_do_not_share"
SECRET_KEY_4       = "session_encryption_key_12345"
SECRET_KEY_5       = "api_signing_hmac_secret_key"

AWS_ACCESS_KEY     = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET         = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
AWS_ACCESS_KEY_2   = "AKIAI44QH8DHBEXAMPLE"
AWS_SECRET_2       = "je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY"

DB_PASSWORD_1      = "Passw0rd!Prod2024"
DB_PASSWORD_2      = "SuperSecret#Database99"
DB_CONN_STR_1      = "postgresql://admin:Passw0rd!Prod2024@prod.db.internal:5432/appdb"
DB_CONN_STR_2      = "mysql://root:SuperSecret#Database99@mysql.internal/users"
DB_CONN_STR_3      = "mongodb://admin:MongoPass123@mongo.internal:27017/analytics"

STRIPE_KEY_LIVE    = "sk_live_EXAMPLE_FAKE_KEY_FOR_TESTING"
STRIPE_KEY_TEST    = "sk_test_EXAMPLE_FAKE_KEY_FOR_TESTING"
SENDGRID_KEY       = "SG.abc123def456ghi789jkl012mno345pqr678"
TWILIO_TOKEN       = "AC_EXAMPLE_TWILIO_SID_00000000000000"
GITHUB_TOKEN       = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456"
GITHUB_TOKEN_2     = "github_pat_11ABCDE_longPatternHere1234567890"
SLACK_TOKEN        = "xoxb-EXAMPLE-SLACK-TOKEN-REPLACE-ME-0000000"
GOOGLE_API_KEY     = "AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI"
PAYPAL_SECRET      = "EBWKjlELKMYqRNQ6sYvFo64uoqKcgwoy"
MAILCHIMP_KEY      = "abc123def456ghi789jkl-us1"

PRIVATE_KEY_PEM    = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2a2rwplBQLzHPZe5RJr9vKCBDXHUMBuNPB7NNx1EH9FAKE
-----END RSA PRIVATE KEY-----"""

ENCRYPTION_KEY_1   = "0123456789abcdef0123456789abcdef"
ENCRYPTION_KEY_2   = "aabbccddeeff00112233445566778899"
STATIC_IV          = b"\x00" * 16
STATIC_SALT        = b"staticsalt1234"

app.secret_key     = "flask_insecure_secret_key_hardcoded"
app.config["SECRET_KEY"] = "another_hardcoded_config_secret"


# ===========================================================================
# SECTION 2: SQL INJECTION (35 instances)
# ===========================================================================

def sqli_01(username):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = '" + username + "'")
    return cur.fetchall()

def sqli_02(user_id):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = %s" % user_id)
    return cur.fetchall()

def sqli_03(user_id):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute(f"DELETE FROM users WHERE id = {user_id}")
    conn.commit()

def sqli_04(username, password):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE username='{username}' AND password='{password}'")
    return cur.fetchone()

def sqli_05(search):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM products WHERE name LIKE '%" + search + "%'")
    return cur.fetchall()

def sqli_06(order_id):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    query = "SELECT * FROM orders WHERE id = " + str(order_id)
    cur.execute(query)
    return cur.fetchone()

def sqli_07(column, value):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM records WHERE {} = '{}'".format(column, value))
    return cur.fetchall()

def sqli_08(email):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("UPDATE users SET active=0 WHERE email='" + email + "'")
    conn.commit()

def sqli_09(table, user_id):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM {table} WHERE owner = {user_id}")
    return cur.fetchall()

def sqli_10(start_date, end_date):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM logs WHERE date BETWEEN '" + start_date + "' AND '" + end_date + "'")
    return cur.fetchall()

@app.route("/sqli_11")
def sqli_11():
    uid = request.args.get("id")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = " + uid)
    return str(cur.fetchone())

@app.route("/sqli_12")
def sqli_12():
    name = request.args.get("name")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute(f"SELECT email FROM users WHERE name = '{name}'")
    return str(cur.fetchone())

@app.route("/sqli_13")
def sqli_13():
    category = request.args.get("cat")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM items WHERE category = '" + category + "' ORDER BY price")
    return str(cur.fetchall())

@app.route("/sqli_14")
def sqli_14():
    sort_col = request.args.get("sort")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM products ORDER BY " + sort_col)
    return str(cur.fetchall())

@app.route("/sqli_15")
def sqli_15():
    limit = request.args.get("limit", "10")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM logs LIMIT " + limit)
    return str(cur.fetchall())

def sqli_16(first, last):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("INSERT INTO users (first_name, last_name) VALUES ('" + first + "', '" + last + "')")
    conn.commit()

def sqli_17(role, user_id):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("UPDATE users SET role = '" + role + "' WHERE id = " + str(user_id))
    conn.commit()

def sqli_18(tag):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT post_id FROM tags WHERE tag_name = '%s'" % tag)
    return cur.fetchall()

def sqli_19(ip_addr):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute(f"INSERT INTO audit_log (ip) VALUES ('{ip_addr}')")
    conn.commit()

def sqli_20(search):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    query = "SELECT * FROM articles WHERE title LIKE '%" + search + "%' OR body LIKE '%" + search + "%'"
    cur.execute(query)
    return cur.fetchall()

def sqli_21(group_name):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT user_id FROM group_members WHERE group_name = '" + group_name + "'")
    return [row[0] for row in cur.fetchall()]

def sqli_22(status, user_id):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute(f"UPDATE orders SET status='{status}' WHERE user_id={user_id}")
    conn.commit()

def sqli_23(promo_code):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT discount FROM promos WHERE code = '" + promo_code + "'")
    return cur.fetchone()

def sqli_24(filename):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM uploads WHERE filename = '" + filename + "'")
    return cur.fetchone()

def sqli_25(country):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE country = '" + country + "' AND active = 1")
    return cur.fetchall()

def sqli_26(event_type):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM events WHERE type = '%s'" % event_type)
    return cur.fetchone()[0]

def sqli_27(session_token):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute(f"SELECT user_id FROM sessions WHERE token = '{session_token}'")
    return cur.fetchone()

def sqli_28(col, direction):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM employees ORDER BY " + col + " " + direction)
    return cur.fetchall()

def sqli_29(dept):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT salary FROM employees WHERE department = '" + dept + "'")
    return cur.fetchall()

def sqli_30(key, value):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM settings WHERE `" + key + "` = '" + value + "'")
    return cur.fetchone()

def sqli_31(user_ids):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id IN (" + ",".join(user_ids) + ")")
    return cur.fetchall()

def sqli_32(subdomain):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT tenant_id FROM tenants WHERE subdomain = '" + subdomain + "'")
    return cur.fetchone()

def sqli_33(token):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("DELETE FROM password_resets WHERE token = '" + token + "'")
    conn.commit()

def sqli_34(name, age):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM contacts WHERE name='" + name + "' AND age>" + str(age))
    return cur.fetchall()

def sqli_35(product_id):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM reviews WHERE product_id = {product_id} ORDER BY created_at DESC")
    return cur.fetchall()


# ===========================================================================
# SECTION 3: COMMAND INJECTION (25 instances)
# ===========================================================================

@app.route("/cmdi_01")
def cmdi_01():
    host = request.args.get("host")
    os.system("ping -c 1 " + host)
    return "done"

@app.route("/cmdi_02")
def cmdi_02():
    domain = request.args.get("domain")
    result = subprocess.run("nslookup " + domain, shell=True, capture_output=True, text=True)
    return result.stdout

@app.route("/cmdi_03")
def cmdi_03():
    host = request.args.get("host")
    proc = subprocess.Popen("traceroute " + host, shell=True, stdout=subprocess.PIPE)
    return proc.communicate()[0]

@app.route("/cmdi_04")
def cmdi_04():
    domain = request.args.get("domain")
    return os.popen(f"whois {domain}").read()

@app.route("/cmdi_05")
def cmdi_05():
    path = request.args.get("path")
    return os.popen("ls -la " + path).read()

def cmdi_06(filename):
    subprocess.call("gzip " + filename, shell=True)

def cmdi_07(path):
    return subprocess.check_output("file " + path, shell=True)

@app.route("/cmdi_08", methods=["POST"])
def cmdi_08():
    archive = request.form.get("archive")
    files = request.form.get("files")
    os.system(f"zip {archive} {files}")
    return "ok"

def cmdi_09(domain):
    return subprocess.check_output(f"dig {domain}", shell=True)

def cmdi_10(ip):
    output = os.popen("arp -n " + ip).read()
    return output

def cmdi_11(src, dst):
    subprocess.run(f"cp {src} {dst}", shell=True)

def cmdi_12(filepath):
    os.system("chmod 777 " + filepath)

def cmdi_13(pkg):
    subprocess.run("pip install " + pkg, shell=True)

def cmdi_14(url):
    os.system("wget " + url + " -O /tmp/downloaded")

def cmdi_15(filename):
    result = subprocess.Popen("cat " + filename, shell=True, stdout=subprocess.PIPE)
    return result.stdout.read()

def cmdi_16(host, port):
    os.system(f"nc -zv {host} {port}")

def cmdi_17(log_file):
    return os.popen("tail -n 100 " + log_file).read()

def cmdi_18(search_term, directory):
    return subprocess.check_output("grep -r '" + search_term + "' " + directory, shell=True)

def cmdi_19(image_path):
    subprocess.run("convert " + image_path + " -resize 100x100 thumb.jpg", shell=True)

def cmdi_20(interface):
    return os.popen("ifconfig " + interface).read()

def cmdi_21(filename):
    os.system("rm -f /tmp/" + filename)

def cmdi_22(host):
    return subprocess.check_output("ssh-keyscan " + host, shell=True)

def cmdi_23(db_name, output_file):
    os.system(f"mysqldump {db_name} > {output_file}")

def cmdi_24(video_url):
    subprocess.Popen(f"youtube-dl {video_url} -o /tmp/%(title)s.%(ext)s", shell=True)

def cmdi_25(script_name):
    subprocess.call("/scripts/" + script_name + ".sh", shell=True)


# ===========================================================================
# SECTION 4: PATH TRAVERSAL (20 instances)
# ===========================================================================

@app.route("/pt_01")
def pt_01():
    filename = request.args.get("file")
    return send_file("/uploads/" + filename)

@app.route("/pt_02")
def pt_02():
    filename = request.args.get("f")
    with open("/var/www/" + filename) as fh:
        return fh.read()

@app.route("/pt_03")
def pt_03():
    path = request.args.get("path")
    full = os.path.join("/data/", path)
    with open(full) as fh:
        return fh.read()

@app.route("/pt_04")
def pt_04():
    filename = request.args.get("name")
    return send_file(os.path.join("/static/", filename))

@app.route("/pt_05", methods=["POST"])
def pt_05():
    name = request.form.get("filename")
    content = request.form.get("content")
    with open("/uploads/" + name, "w") as fh:
        fh.write(content)
    return "saved"

def pt_06(user_id):
    with open(f"/home/{user_id}/.profile") as fh:
        return fh.read()

def pt_07(config_name):
    path = "/app/configs/" + config_name + ".yaml"
    with open(path) as fh:
        return yaml.safe_load(fh)

def pt_08(report_name):
    return open("/reports/" + report_name, "rb").read()

def pt_09(log_name):
    with open("/var/log/" + log_name) as fh:
        return fh.read()

@app.route("/pt_10")
def pt_10():
    page = request.args.get("page")
    with open(f"templates/{page}.html") as fh:
        return render_template_string(fh.read())

def pt_11(backup_name):
    shutil.copy("/backups/" + backup_name, "/tmp/restore")

def pt_12(user_id):
    dest = "/exports/" + user_id + ".csv"
    with open(dest, "w") as fh:
        fh.write("id,name")
    return dest

def pt_13(module_name):
    path = "/plugins/" + module_name + ".py"
    with open(path) as fh:
        exec(fh.read())

def pt_14(attachment):
    return open(os.path.join("/attachments", attachment), "rb").read()

def pt_15(skin):
    css_path = "/themes/" + skin + "/style.css"
    with open(css_path) as fh:
        return fh.read()

@app.route("/pt_16")
def pt_16():
    filename = request.args.get("export")
    filepath = os.path.join("/exports", filename)
    return send_file(filepath, as_attachment=True)

def pt_17(cert_name):
    with open("/certs/" + cert_name) as fh:
        return fh.read()

def pt_18(name):
    img = "/images/%s.png" % name
    with open(img, "rb") as fh:
        return fh.read()

def pt_19(user, filename):
    path = f"/home/{user}/uploads/{filename}"
    os.remove(path)

def pt_20(locale):
    with open("/locales/" + locale + ".json") as fh:
        return json.load(fh)


# ===========================================================================
# SECTION 5: INSECURE DESERIALIZATION (20 instances)
# ===========================================================================

@app.route("/deser_01", methods=["POST"])
def deser_01():
    return str(pickle.loads(request.get_data()))

@app.route("/deser_02")
def deser_02():
    cookie = request.cookies.get("session_data")
    return str(pickle.loads(base64.b64decode(cookie)))

@app.route("/deser_03", methods=["POST"])
def deser_03():
    return str(yaml.load(request.get_data(as_text=True)))

@app.route("/deser_04", methods=["POST"])
def deser_04():
    import jsonpickle
    return str(jsonpickle.decode(request.get_data(as_text=True)))

@app.route("/deser_05", methods=["POST"])
def deser_05():
    return str(marshal.loads(request.get_data()))

def deser_06(filepath):
    with open(filepath, "rb") as fh:
        return pickle.load(fh)

def deser_07(data):
    return pickle.loads(data)

def deser_08(yaml_str):
    return yaml.load(yaml_str)

def deser_09(key):
    db = shelve.open("data.db")
    return db[key]

def deser_10(data):
    return marshal.loads(data)

@app.route("/deser_11", methods=["POST"])
def deser_11():
    raw = request.get_data()
    obj = pickle.loads(raw)
    return jsonify({"type": str(type(obj))})

@app.route("/deser_12")
def deser_12():
    token = request.args.get("token")
    data = base64.b64decode(token)
    return str(pickle.loads(data))

def deser_13(filepath):
    with open(filepath) as fh:
        return yaml.load(fh.read())

def deser_14(blob):
    import jsonpickle
    return jsonpickle.decode(blob)

def deser_15(raw_bytes):
    return pickle.loads(raw_bytes)

@app.route("/deser_16", methods=["POST"])
def deser_16():
    body = request.get_json(force=True)
    obj = pickle.loads(base64.b64decode(body.get("data", "")))
    return str(obj)

def deser_17(yaml_file):
    with open(yaml_file) as fh:
        return yaml.load(fh)

def deser_18(data):
    import jsonpickle
    result = jsonpickle.decode(data)
    return result

def deser_19(filepath):
    with open(filepath, "rb") as fh:
        while True:
            try:
                yield pickle.load(fh)
            except EOFError:
                break

def deser_20(raw):
    return pickle.loads(base64.urlsafe_b64decode(raw + "=="))


# ===========================================================================
# SECTION 6: SSRF (20 instances)
# ===========================================================================

@app.route("/ssrf_01")
def ssrf_01():
    url = request.args.get("url")
    return requests.get(url).text

@app.route("/ssrf_02")
def ssrf_02():
    target = request.args.get("target")
    with urllib_request.urlopen(target) as resp:
        return resp.read()

@app.route("/ssrf_03")
def ssrf_03():
    endpoint = request.args.get("endpoint")
    return requests.post(endpoint, json={"ping": True}).text

@app.route("/ssrf_04")
def ssrf_04():
    img_url = request.args.get("image")
    r = requests.get(img_url, timeout=5)
    return r.content

@app.route("/ssrf_05")
def ssrf_05():
    feed_url = request.args.get("feed")
    return requests.get(feed_url).text

def ssrf_06(webhook_url, payload):
    requests.post(webhook_url, json=payload)

def ssrf_07(avatar_url):
    return requests.get(avatar_url).content

def ssrf_08(metadata_url):
    return urllib_request.urlopen(metadata_url).read()

def ssrf_09(callback):
    requests.get(callback + "?status=done")

def ssrf_10(url):
    return requests.head(url).headers

@app.route("/ssrf_11")
def ssrf_11():
    proxy = request.args.get("proxy")
    return requests.get("http://internal-api/data", proxies={"http": proxy}).text

@app.route("/ssrf_12")
def ssrf_12():
    logo_url = request.args.get("logo")
    resp = requests.get(logo_url)
    return resp.content, 200, {"Content-Type": resp.headers.get("Content-Type", "image/png")}

def ssrf_13(import_url):
    return requests.get(import_url).json()

def ssrf_14(schema_url):
    return urllib_request.urlopen(schema_url).read().decode()

def ssrf_15(health_url):
    try:
        r = requests.get(health_url, timeout=2)
        return r.status_code == 200
    except Exception:
        return False

@app.route("/ssrf_16")
def ssrf_16():
    url = request.form.get("url")
    return requests.put(url, data=request.get_data()).text

def ssrf_17(url):
    return requests.get(url, verify=False).text

def ssrf_18(notify_url):
    requests.post(notify_url, data={"event": "signup"})

@app.route("/ssrf_19")
def ssrf_19():
    url = request.args.get("check")
    s = socket.socket()
    host, port = url.split(":")
    s.connect((host, int(port)))
    return "open"

def ssrf_20(url):
    import http.client
    from urllib.parse import urlparse
    parsed = urlparse(url)
    conn = http.client.HTTPConnection(parsed.netloc)
    conn.request("GET", parsed.path)
    return conn.getresponse().read()


# ===========================================================================
# SECTION 7: XSS & TEMPLATE INJECTION (20 instances)
# ===========================================================================

@app.route("/xss_01")
def xss_01():
    name = request.args.get("name", "")
    return "<html><body>Hello, " + name + "</body></html>"

@app.route("/xss_02")
def xss_02():
    q = request.args.get("q", "")
    return render_template_string(f"<h1>Results for: {q}</h1>")

@app.route("/xss_03")
def xss_03():
    msg = request.args.get("msg", "")
    return f"<p class='error'>{msg}</p>"

@app.route("/xss_04")
def xss_04():
    next_url = request.args.get("next", "/")
    return f'<script>window.location="{next_url}"</script>'

@app.route("/xss_05")
def xss_05():
    value = request.args.get("value", "")
    return f'<input type="text" value="{value}">'

@app.route("/xss_06")
def xss_06():
    color = request.args.get("color", "red")
    return f'<div style="color: {color}">Text</div>'

@app.route("/xss_07")
def xss_07():
    user_template = request.args.get("t", "Hello World")
    return render_template_string(user_template)

@app.route("/xss_08")
def xss_08():
    src = request.args.get("src", "")
    tmpl = Template(src)
    return tmpl.render()

@app.route("/xss_09")
def xss_09():
    source = request.args.get("tpl", "")
    env = Environment()
    return env.from_string(source).render()

@app.route("/xss_10")
def xss_10():
    name = request.args.get("name", "User")
    tpl = "Dear {{ name }}, welcome!"
    return render_template_string(tpl, name=name)

@app.route("/xss_11")
def xss_11():
    alert_msg = request.args.get("alert", "")
    return render_template_string("<div>" + alert_msg + "</div>")

@app.route("/xss_12")
def xss_12():
    username = request.args.get("user", "")
    return "<title>Profile: " + username + "</title>"

@app.route("/xss_13")
def xss_13():
    callback = request.args.get("callback", "cb")
    data = json.dumps({"status": "ok"})
    return f"{callback}({data})"

@app.route("/xss_14")
def xss_14():
    query = request.args.get("q", "")
    tmpl = Template("You searched for: " + query)
    return tmpl.render()

@app.route("/xss_15")
def xss_15():
    tpl_str = request.args.get("template", "Hello!")
    env = Environment(autoescape=False)
    return env.from_string(tpl_str).render()

def ssti_01(user_input):
    return render_template_string(user_input)

def ssti_02(user_input):
    t = Template(user_input)
    return t.render()

def ssti_03(user_template):
    env = Environment()
    return env.from_string(user_template).render()

def ssti_04(prefix, user_content):
    tmpl = prefix + user_content
    return render_template_string(tmpl)

def ssti_05(user_name):
    return render_template_string("<h1>Welcome " + user_name + "</h1>")


# ===========================================================================
# SECTION 8: WEAK CRYPTOGRAPHY & INSECURE RANDOM (25 instances)
# ===========================================================================

def crypto_01(password):
    return hashlib.md5(password.encode()).hexdigest()

def crypto_02(password):
    return hashlib.sha1(password.encode()).hexdigest()

def crypto_03(data):
    return hashlib.md5(data).hexdigest()

def crypto_04(data):
    return hashlib.sha1(data).hexdigest()

def crypto_05():
    return random.randint(100000, 999999)

def crypto_06():
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(random.choice(chars) for _ in range(32))

def crypto_07():
    return str(random.random())

def crypto_08():
    return base64.b64encode(str(random.getrandbits(128)).encode()).decode()

def crypto_09():
    return hex(random.randint(0, 2**256))

def crypto_10(data):
    return base64.b64encode(data.encode()).decode()

def crypto_11(url):
    return requests.get(url, verify=False).text

def crypto_12(url):
    return requests.post(url, json={}, verify=False).text

def crypto_13():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def crypto_14():
    ctx = ssl._create_unverified_context()
    return ctx

def crypto_15(data, key):
    from Crypto.Cipher import DES
    cipher = DES.new(key[:8], DES.MODE_ECB)
    return cipher.encrypt(data)

def crypto_16(data, key):
    from Crypto.Cipher import ARC4
    cipher = ARC4.new(key)
    return cipher.encrypt(data)

def crypto_17(data, key):
    from Crypto.Cipher import AES
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)

def crypto_18(data, key):
    from Crypto.Cipher import AES
    cipher = AES.new(key, AES.MODE_CBC, iv=STATIC_IV)
    return cipher.encrypt(data)

def crypto_19(password, salt=STATIC_SALT):
    return hashlib.pbkdf2_hmac("sha1", password.encode(), salt, 1000)

def crypto_20(password):
    return hashlib.md5(password.encode() + b"pepper").hexdigest()

def crypto_21():
    random.seed(int(time.time()))
    return random.getrandbits(64)

def crypto_22(token):
    expected = "secrettoken123"
    return token == expected

def crypto_23(a, b):
    return a == b

def crypto_24(password):
    h = hashlib.new("md4")
    h.update(password.encode())
    return h.hexdigest()

def crypto_25(data):
    from Crypto.Cipher import Blowfish
    cipher = Blowfish.new(b"weakkey!", Blowfish.MODE_ECB)
    pad_len = 8 - len(data) % 8
    return cipher.encrypt(data + bytes([pad_len] * pad_len))


# ===========================================================================
# SECTION 9: CODE EXECUTION (eval/exec/import) (15 instances)
# ===========================================================================

@app.route("/eval_01")
def eval_01():
    expr = request.args.get("expr")
    return str(eval(expr))

@app.route("/eval_02")
def eval_02():
    code = request.args.get("code")
    exec(code)
    return "ok"

@app.route("/eval_03")
def eval_03():
    formula = request.args.get("formula")
    result = eval(formula, {"__builtins__": {}})
    return str(result)

def exec_01(script):
    exec(script)

def exec_02(code, context):
    exec(code, context)

def exec_03(user_code):
    exec(compile(user_code, "<string>", "exec"))

def eval_04(expression):
    return eval(expression)

def eval_05(data):
    return eval("dict(" + data + ")")

@app.route("/import_01")
def import_01():
    module = request.args.get("module")
    mod = __import__(module)
    return str(dir(mod))

def dynamic_import(module_name):
    return __import__(module_name)

@app.route("/exec_04")
def exec_04():
    body = request.get_data(as_text=True)
    exec(body)
    return "executed"

def exec_05(filepath):
    with open(filepath) as fh:
        exec(fh.read())

@app.route("/eval_06")
def eval_06():
    q = request.args.get("q", "1+1")
    ns = {}
    exec(f"result = {q}", ns)
    return str(ns.get("result"))

def eval_07(template_str, context):
    return eval(f'f"""{template_str}"""', context)

def exec_06(user_code):
    local_vars = {}
    exec(user_code, {"__builtins__": __builtins__}, local_vars)
    return local_vars


# ===========================================================================
# SECTION 10: XXE (10 instances)
# ===========================================================================

@app.route("/xxe_01", methods=["POST"])
def xxe_01():
    import lxml.etree
    xml_data = request.get_data()
    parser = lxml.etree.XMLParser(resolve_entities=True, no_network=False)
    tree = lxml.etree.fromstring(xml_data, parser)
    return lxml.etree.tostring(tree)

@app.route("/xxe_02", methods=["POST"])
def xxe_02():
    xml_content = request.get_data(as_text=True)
    root = ET.fromstring(xml_content)
    return root.tag

def xxe_03(filepath):
    import lxml.etree
    tree = lxml.etree.parse(filepath)
    return tree.getroot()

def xxe_04(xml_string):
    root = ET.fromstring(xml_string)
    return ET.tostring(root)

@app.route("/xxe_05", methods=["POST"])
def xxe_05():
    import lxml.etree
    data = request.get_data()
    parser = lxml.etree.XMLParser(load_dtd=True, no_network=False)
    doc = lxml.etree.fromstring(data, parser)
    return doc.tag

def xxe_06(xml_data):
    import lxml.etree
    return lxml.etree.fromstring(xml_data)

def xxe_07(xml_bytes):
    import xml.dom.minidom
    return xml.dom.minidom.parseString(xml_bytes)

@app.route("/xxe_08", methods=["POST"])
def xxe_08():
    xml_data = request.get_data(as_text=True)
    import xml.dom.minidom
    doc = xml.dom.minidom.parseString(xml_data)
    return doc.documentElement.tagName

def xxe_09(filepath):
    tree = ET.parse(filepath)
    return tree.getroot()

@app.route("/xxe_10", methods=["POST"])
def xxe_10():
    import lxml.etree
    xml_bytes = request.get_data()
    parser = lxml.etree.XMLParser(resolve_entities=True)
    root = lxml.etree.XML(xml_bytes, parser)
    return root.text or ""


# ===========================================================================
# SECTION 11: INSECURE FLASK CONFIG & MISC (20 instances)
# ===========================================================================

app.debug = True
app.config["DEBUG"] = True
app.config["TESTING"] = True
app.config["WTF_CSRF_ENABLED"] = False
app.config["SESSION_COOKIE_SECURE"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = False
app.config["SESSION_COOKIE_SAMESITE"] = None
app.config["REMEMBER_COOKIE_SECURE"] = False

@app.route("/open_redirect")
def open_redirect():
    dest = request.args.get("next", "/")
    return redirect(dest)

@app.route("/open_redirect_2")
def open_redirect_2():
    url = request.args.get("return_to")
    return redirect(url)

@app.route("/set_insecure_cookie")
def set_insecure_cookie():
    resp = make_response("ok")
    resp.set_cookie("auth", "token123", httponly=False, secure=False)
    return resp

@app.route("/permissive_cors")
def permissive_cors():
    resp = make_response(jsonify({"data": "secret"}))
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp

@app.route("/host_header_injection")
def host_header_injection():
    host = request.headers.get("Host")
    email = request.args.get("email")
    reset_link = f"http://{host}/reset?token=abc"
    return reset_link

@app.errorhandler(Exception)
def verbose_error(e):
    import traceback
    return traceback.format_exc(), 500

@app.route("/log_injection")
def log_injection():
    username = request.args.get("username", "")
    logging.info("User logged in: " + username)
    return "ok"

@app.route("/mass_assignment", methods=["POST"])
def mass_assignment():
    data = request.get_json()
    user = {}
    user.update(data)
    return jsonify(user)

@app.route("/unvalidated_redirect")
def unvalidated_redirect():
    url = request.form.get("redirect_url")
    return redirect(url)

def insecure_temp_file():
    tmp = tempfile.mktemp(suffix=".tmp")
    with open(tmp, "w") as fh:
        fh.write("sensitive data")
    return tmp

def timing_attack_compare(user_input, secret):
    return user_input == secret

def predictable_filename(username):
    return f"/tmp/{username}_export.csv"

def log_sensitive_data(user, password):
    logging.debug(f"Auth attempt: user={user} password={password}")

@app.route("/arbitrary_file_delete", methods=["POST"])
def arbitrary_file_delete():
    filename = request.form.get("filename")
    os.remove("/uploads/" + filename)
    return "deleted"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
