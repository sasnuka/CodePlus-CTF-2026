from flask import Flask, request, make_response

app = Flask(__name__)

@app.route("/")
def home():
    return """
    <html>
    <head>
        <title>CodePlus Competition Portal</title>
    </head>

    <body style="font-family:Arial; text-align:center; margin-top:80px;">

        <h1>CodePlus Competition Portal</h1>

        <p>Campus Breach Investigation Portal</p>

        <a href="/login">Student Login</a>
        <br><br>

        <a href="/admin">Admin Portal</a>

    </body>
    </html>
    """


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username")

        response = make_response(f"""
        <html>
        <body style="font-family:Arial; text-align:center; margin-top:80px;">

        <h2>Welcome {username}</h2>

        <p>You are logged in as a normal user.</p>

        <a href="/admin">Go to Admin Portal</a>

        </body>
        </html>
        """)

        response.set_cookie("role", "user")

        return response

    return """
    <html>
    <body style="font-family:Arial; text-align:center; margin-top:80px;">

        <h2>CodePlus Login</h2>

        <form method="POST">

            <input name="username" placeholder="Username">
            <br><br>

            <input name="password" type="password" placeholder="Password">
            <br><br>

            <button type="submit">Login</button>

        </form>

    </body>
    </html>
    """


@app.route("/admin")
def admin():

    role = request.cookies.get("role")

    if role == "admin":

        return """
        <html>
        <body style="font-family:Arial; text-align:center; margin-top:80px;">

        <h1>Admin Portal</h1>

        <h2>Access Granted</h2>

        <p>Stage 03 Flag:</p>

        <h2>CODEPLUS{portal_access_granted}</h2>

        <hr>

        <h3>Investigation Evidence</h3>

        <p>Incident logs were recovered from the compromised portal.</p>

        <p><b>NEXT:</b> Continue to Stage 04 - The Missing Logs.</p>
 
        <p>Download evidence.zip and investigate the suspicious session activity.</p>

        </body>
        </html>
        """

    return """
    <html>
    <body style="font-family:Arial; text-align:center; margin-top:80px;">

        <h1>Access Denied</h1>

        <p>Administrator access required.</p>

    </body>
    </html>
    """


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)