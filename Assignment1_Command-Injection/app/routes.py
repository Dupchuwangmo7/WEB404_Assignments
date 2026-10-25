"""
WEB404 Assignment 1 — Flask Routes
====================================
Only the SECURE implementation is exposed as a web endpoint.
The vulnerable function exists only in security.py for test-suite use.
"""

import logging
import os

from flask import Flask, flash, render_template, request
from flask_wtf import CSRFProtect

from app.security import safe_lookup, validate_hostname


def create_app(testing=False):
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-key")
    app.config["TESTING"] = testing

    csrf = CSRFProtect(app)

    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(
        "[%(asctime)s] %(levelname)s: %(message)s"))
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)

    @app.route("/", methods=["GET", "POST"])
    def index():
        result = None
        hostname = ""
        if request.method == "POST":
            hostname = request.form.get("hostname", "").strip()

            if not hostname:
                flash("Please enter a hostname.", "danger")
            else:
                result = safe_lookup(hostname)
                if result["success"]:
                    flash(
                        f"Resolved {result['hostname']} → {result['ip']}",
                        "success",
                    )
                else:
                    flash(result["error"], "danger")

        return render_template("index.html", result=result, hostname=hostname)

    @app.errorhandler(404)
    def not_found(e):
        return "Page not found.", 404

    return app
