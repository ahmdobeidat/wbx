from flask import Flask, request, session, jsonify
app = Flask(__name__)

class Invoice:
    query = None

@app.route("/invoice")
def invoice():
    if not session.get("user_id"):
        return "login first", 401
    inv = Invoice.query.get(request.args.get("id"))   # IDOR: no ownership check on id
    return jsonify(inv)
