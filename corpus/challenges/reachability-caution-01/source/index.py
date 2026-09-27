from flask import Flask, request
import sqlite3
app = Flask(__name__)

@app.route("/search")
def search():
    q = request.args.get("q")
    con = sqlite3.connect("app.db")
    con.execute("SELECT * FROM items WHERE name = '" + q + "'")  # reachable SQLi (intended)
    return "ok"
