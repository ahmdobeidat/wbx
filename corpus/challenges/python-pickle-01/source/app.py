import base64, pickle
from flask import Flask, request
app = Flask(__name__)

@app.route("/load", methods=["POST"])
def load():
    blob = request.form["data"]
    raw = base64.b64decode(blob)
    obj = pickle.loads(raw)   # pickle deserialization sink
    return "ok"
