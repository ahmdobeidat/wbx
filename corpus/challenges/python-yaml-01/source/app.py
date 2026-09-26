import yaml
from flask import Flask, request
app = Flask(__name__)

@app.route("/cfg", methods=["POST"])
def cfg():
    data = request.form["cfg"]
    parsed = yaml.load(data)   # unsafe yaml.load -> RCE
    return str(parsed)
