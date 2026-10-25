"""
WEB404 Assignment 3 – SQL Injection Lab Application
/vulnerable/ routes use string concatenation (UNSAFE)
/secure/     routes use parameterised queries (SAFE)
"""
import logging
import os
import re

from flask import Flask, flash, redirect, render_template, request, url_for
from flask_wtf import CSRFProtect

from database import (
    init_db, vulnerable_login, vulnerable_search,
    secure_login, secure_search, get_all_users, get_all_products,
)


def create_app(testing=False):
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "lab-key-do-not-reuse")
    app.config["TESTING"] = testing
    csrf = CSRFProtect(app)

    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s"))
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)

    init_db()

    @app.route("/")
    def index():
        users = get_all_users()
        products = get_all_products()
        return render_template("index.html", users=users, products=products)

    # --- VULNERABLE routes ---
    @app.route("/vulnerable/login", methods=["GET", "POST"])
    def vuln_login():
        results = None
        query_used = None
        if request.method == "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            results = vulnerable_login(username, password)
            query_used = (
                f"SELECT id, username, role FROM users "
                f"WHERE username = '{username}' AND password = '{password}'"
            )
        return render_template("login.html", mode="vulnerable",
                               results=results, query_used=query_used)

    @app.route("/vulnerable/search", methods=["GET", "POST"])
    def vuln_search():
        results = None
        query_used = None
        if request.method == "POST":
            term = request.form.get("term", "")
            results = vulnerable_search(term)
            query_used = (
                f"SELECT id, name, category, price FROM products "
                f"WHERE name LIKE '%{term}%'"
            )
        return render_template("search.html", mode="vulnerable",
                               results=results, query_used=query_used)

    # --- SECURE routes ---
    @app.route("/secure/login", methods=["GET", "POST"])
    def safe_login():
        results = None
        query_used = None
        if request.method == "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            if not re.match(r"^[a-zA-Z0-9_]{1,50}$", username):
                flash("Username contains invalid characters.", "danger")
                return render_template("login.html", mode="secure",
                                       results=None, query_used=None)
            results = secure_login(username, password)
            query_used = (
                "SELECT id, username, role FROM users "
                "WHERE username = ? AND password = ?  "
                f"-- params: ('{username}', '****')"
            )
        return render_template("login.html", mode="secure",
                               results=results, query_used=query_used)

    @app.route("/secure/search", methods=["GET", "POST"])
    def safe_search():
        results = None
        query_used = None
        if request.method == "POST":
            term = request.form.get("term", "")[:100]
            results = secure_search(term)
            query_used = (
                "SELECT id, name, category, price FROM products "
                f"WHERE name LIKE ?  -- param: ('%{term}%')"
            )
        return render_template("search.html", mode="secure",
                               results=results, query_used=query_used)

    @app.errorhandler(404)
    def not_found(e):
        return "Page not found.", 404

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(debug=False, port=5001)
