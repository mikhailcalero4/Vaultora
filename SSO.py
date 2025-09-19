#single sign-on
pip install Flask-Dance[all]

from flask import Flask, redirect, url_for, session
from flask_dance.contrib.google import make_google_blueprint, google
import os

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "supersekrit") #set real secret

#set these up in your google cloud console project OAuth
app.config["GOOGLE_OAUTH_CLIENT_ID"] = "YOUR-GOOGLE-CLIENT-ID"
app.config['GOOGLE_OAUTH_CLIENT_SECRET'] = "YOUR-GOOGLE-CLIENT-SECRET"

google_bp = make_google_blueprint(
    client_id=app.config["GOOGLE_OAUTH_CLIENT_ID"],
    client_secret=app.config["GOOGLE_OAUTH_CLIENT_SECRET"],
    scope=["profile", "email"]
)
app.register_blueprint(google_bp, url_prefix="/login")

@app.route("/")
def index():
    if not google.authorized:
        return redirect(url_for("google.login"))
    resp = google.get("/oauth2/v2/userinfo")
    assert resp.ok, resp.text
    user_data = resp.json()
    session["user_email"] = user_data["email"]
    return f"Hello, {user_data['email']}!"

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(debug=True)