import os
import subprocess
from flask import Flask, request

app = Flask(__name__)

# Command injection via os.system with user input
@app.route("/ping")
def ping_host():
    host = request.args.get("host")
    os.system("ping -c 1 " + host)
    return "Pinged"

# Command injection via subprocess.run with shell=True
@app.route("/nslookup")
def nslookup():
    domain = request.args.get("domain")
    result = subprocess.run(f"nslookup {domain}", shell=True, capture_output=True, text=True)
    return result.stdout

# Command injection via subprocess.Popen with shell=True
@app.route("/traceroute")
def traceroute():
    host = request.args.get("host")
    proc = subprocess.Popen("traceroute " + host, shell=True, stdout=subprocess.PIPE)
    return proc.communicate()[0]

# Command injection via os.popen
@app.route("/whois")
def whois():
    domain = request.args.get("domain")
    output = os.popen(f"whois {domain}").read()
    return output

# Command injection via subprocess.call
def compress_file(filename):
    subprocess.call("gzip " + filename, shell=True)

# Command injection via backtick-equivalent
def get_file_info(path):
    return os.popen("file " + path).read()

# Command injection in archiving utility
@app.route("/zip", methods=["POST"])
def zip_files():
    archive_name = request.form.get("archive")
    files = request.form.get("files")
    os.system(f"zip {archive_name} {files}")
    return "Archived"

# Command injection via subprocess.check_output
@app.route("/dig")
def dns_lookup():
    domain = request.args.get("domain")
    result = subprocess.check_output("dig " + domain, shell=True)
    return result
