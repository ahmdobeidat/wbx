from flask import Flask, request, render_template_string
app = Flask(__name__)

@app.route("/hello")
def hello():
    name = request.args.get("name", "world")
    tpl = "<h1>Hello " + name + "</h1>"   # user input into template string
    return render_template_string(tpl)     # SSTI sink

if __name__ == "__main__":
    app.run()
