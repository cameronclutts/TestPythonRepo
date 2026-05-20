import xml.etree.ElementTree as ET
import lxml.etree
from flask import Flask, request, render_template_string
from jinja2 import Template, Environment
import defusedxml

app = Flask(__name__)

# XXE: lxml with external entity resolution enabled
@app.route("/parse_xml", methods=["POST"])
def parse_xml():
    xml_data = request.get_data()
    parser = lxml.etree.XMLParser(resolve_entities=True, no_network=False)
    tree = lxml.etree.fromstring(xml_data, parser)
    return lxml.etree.tostring(tree)

# XXE: standard xml.etree (vulnerable in older Python versions, flagged by Semgrep)
@app.route("/xml_upload", methods=["POST"])
def xml_upload():
    xml_content = request.get_data(as_text=True)
    root = ET.fromstring(xml_content)
    return root.tag

# XXE via lxml without safe parser
def process_xml_file(filepath):
    tree = lxml.etree.parse(filepath)
    return tree.getroot()

# Server-Side Template Injection via render_template_string with user input
@app.route("/template")
def render_user_template():
    user_template = request.args.get("t", "")
    return render_template_string(user_template)

# SSTI via Jinja2 Template from user input
@app.route("/render")
def render_jinja():
    user_input = request.args.get("input", "")
    tmpl = Template(user_input)
    return tmpl.render()

# SSTI via Environment with user-controlled template string
@app.route("/compile")
def compile_template():
    source = request.args.get("src", "")
    env = Environment()
    tmpl = env.from_string(source)
    return tmpl.render(user="world")

# SSTI via format string on template
@app.route("/email_preview")
def email_preview():
    name = request.args.get("name", "User")
    template_str = "Dear {name}, welcome to our platform!".format(name=name)
    return render_template_string(template_str)

# LDAP injection
def ldap_search(username):
    import ldap
    conn = ldap.initialize("ldap://internal-ldap:389")
    search_filter = f"(uid={username})"
    return conn.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE, search_filter)
