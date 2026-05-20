import pickle
import yaml
import marshal
import shelve
import jsonpickle
from flask import Flask, request

app = Flask(__name__)

# Insecure pickle deserialization from user input
@app.route("/load", methods=["POST"])
def load_object():
    data = request.get_data()
    obj = pickle.loads(data)
    return str(obj)

# Insecure pickle from cookie
@app.route("/profile")
def profile():
    import base64
    session_data = request.cookies.get("session")
    obj = pickle.loads(base64.b64decode(session_data))
    return str(obj)

# Insecure YAML load (allows arbitrary Python object instantiation)
@app.route("/config", methods=["POST"])
def load_config():
    config_data = request.get_data(as_text=True)
    config = yaml.load(config_data)
    return str(config)

# yaml.load without Loader argument
def parse_yaml_file(filepath):
    with open(filepath) as f:
        return yaml.load(f.read())

# Insecure marshal deserialization
def deserialize_marshal(data):
    return marshal.loads(data)

# jsonpickle decode from user input
@app.route("/decode", methods=["POST"])
def decode_json():
    payload = request.get_data(as_text=True)
    obj = jsonpickle.decode(payload)
    return str(obj)

# shelve with user-controlled key (can trigger pickle deserialization)
def load_from_shelf(key):
    db = shelve.open("data.db")
    return db[key]

# Pickle from file with no validation
def restore_session(session_file):
    with open(session_file, "rb") as f:
        return pickle.load(f)
