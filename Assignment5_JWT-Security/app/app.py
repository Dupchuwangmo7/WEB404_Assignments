import logging, os
from functools import wraps
from flask import Flask, flash, jsonify, make_response, redirect, render_template, request, url_for
from flask_wtf import CSRFProtect
import jwt as pyjwt
from config import FLASK_SECRET, JWT_EXPIRY_SECONDS
from auth import authenticate, create_token, verify_token, revoke_token

def create_app(testing=False):
    app = Flask(__name__)
    app.config["SECRET_KEY"] = FLASK_SECRET
    app.config["TESTING"] = testing
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    csrf = CSRFProtect(app)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s"))
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)

    def jwt_required(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = request.cookies.get("jwt_token")
            if not token:
                if request.accept_mimetypes.best == "application/json":
                    return jsonify({"error": "Missing token"}), 401
                flash("Please log in first.", "warning")
                return redirect(url_for("login"))
            try:
                payload = verify_token(token)
            except pyjwt.ExpiredSignatureError:
                if request.accept_mimetypes.best == "application/json":
                    return jsonify({"error": "Token expired"}), 401
                flash("Session expired. Please log in again.", "danger")
                resp = redirect(url_for("login"))
                resp.delete_cookie("jwt_token")
                return resp
            except pyjwt.InvalidTokenError as exc:
                if request.accept_mimetypes.best == "application/json":
                    return jsonify({"error": f"Invalid token: {exc}"}), 401
                flash("Invalid token. Please log in.", "danger")
                resp = redirect(url_for("login"))
                resp.delete_cookie("jwt_token")
                return resp
            request.jwt_payload = payload
            return f(*args, **kwargs)
        return decorated

    @app.route("/")
    def index():
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            user = authenticate(username, password)
            if user is None:
                flash("Invalid credentials.", "danger")
                return render_template("login.html"), 401
            token = create_token(user["username"], user["role"])
            resp = make_response(redirect(url_for("dashboard")))
            resp.set_cookie("jwt_token", token, httponly=True,
                            samesite="Lax", max_age=JWT_EXPIRY_SECONDS, path="/")
            flash(f"Welcome, {username}!", "success")
            return resp
        return render_template("login.html")

    @app.route("/dashboard")
    @jwt_required
    def dashboard():
        p = request.jwt_payload
        return render_template("dashboard.html", username=p["sub"], role=p["role"])

    @csrf.exempt
    @app.route("/api/profile")
    @jwt_required
    def api_profile():
        p = request.jwt_payload
        return jsonify({"username": p["sub"], "role": p["role"], "message": "Token is valid."})

    @app.route("/logout")
    def logout():
        token = request.cookies.get("jwt_token")
        if token: revoke_token(token)
        resp = make_response(redirect(url_for("login")))
        resp.delete_cookie("jwt_token")
        flash("Logged out.", "info")
        return resp

    @app.errorhandler(404)
    def not_found(e): return "Page not found.", 404
    return app

if __name__ == "__main__":
    create_app().run(debug=False, port=5003)
