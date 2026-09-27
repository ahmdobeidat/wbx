from flask import Flask, request, render_template_string
app = Flask(__name__)

def compose(name):
    return "Hello " + name

@app.route("/hi")
def hi():
    tpl = compose(request.args.get("name", ""))
    return render_template_string(tpl)
