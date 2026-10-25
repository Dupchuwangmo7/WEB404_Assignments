"""
WEB404 Assignment 4 – CSRF Lab Application
/vulnerable/transfer  — CSRF check explicitly disabled (educational demo)
/secure/transfer      — Flask-WTF CSRF token required and validated
/attacker             — simulated malicious page that auto-submits a forged transfer

WHY AUTHENTICATION ALONE DOES NOT STOP CSRF
    The session cookie proves *who* the user is, but not *whether they
    intended* the request. The browser attaches the cookie to every
    request to this origin, including one forged by a third-party page.
    A secret, session-bound CSRF token is what proves intent, because the
    attacker's page cannot read or guess it.

HOW CSRF DIFFERS FROM XSS
    XSS runs attacker script *inside* the target site (an output-encoding
    failure). CSRF runs no code on the target — it tricks the browser into
    sending a request *to* the target, riding the user's existing session.
"""
import logging
import os
from functools import wraps

from flask import (Flask, flash, redirect, render_template,
                   request, session, url_for)
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError

# In-memory "database" of fictional accounts — no real money, no external calls.
ACCOUNTS = {
    "alice": {"balance": 1000.00, "password": "password123"},
    "bob":   {"balance": 500.00,  "password": "letmein"},
    "admin": {"balance": 5000.00, "password": "supersecret"},
}
TRANSFER_LOG = []  # every transfer, for display and test assertions


def create_app(testing=False):
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "csrf-lab-key-do-not-reuse")
    app.config["TESTING"] = testing

    # Secondary, browser-enforced defences (see report section 7).
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_HTTPONLY"] = True

    # CSRFProtect guards every POST by default; /vulnerable/* is exempted below.
    csrf = CSRFProtect(app)

    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s"))
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)

    def login_required(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if "user" not in session:
                flash("Please log in first.", "warning")
                return redirect(url_for("login"))
            return f(*args, **kwargs)
        return decorated

    def do_transfer(user, protected):
        """Shared transfer logic. Returns (flash_message, category)."""
        recipient = request.form.get("recipient", "").strip()
        try:
            amount = float(request.form.get("amount", 0))
        except ValueError:
            return "Invalid amount.", "danger"
        if recipient not in ACCOUNTS:
            return "Recipient does not exist.", "danger"
        if recipient == user:
            return "Cannot transfer to yourself.", "danger"
        if amount <= 0:
            return "Amount must be positive.", "danger"
        if amount > ACCOUNTS[user]["balance"]:
            return "Insufficient balance.", "danger"
        ACCOUNTS[user]["balance"] -= amount
        ACCOUNTS[recipient]["balance"] += amount
        TRANSFER_LOG.append({"from": user, "to": recipient,
                             "amount": amount, "protected": protected})
        return f"Transferred ${amount:.2f} to {recipient}.", "success"

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            acct = ACCOUNTS.get(username)
            if acct and acct["password"] == password:
                session["user"] = username
                app.logger.info("User '%s' logged in.", username)
                flash(f"Logged in as {username}.", "success")
                return redirect(url_for("index"))
            flash("Invalid credentials.", "danger")
        return render_template("login.html")

    @app.route("/logout")
    def logout():
        session.pop("user", None)
        flash("Logged out.", "info")
        return redirect(url_for("login"))

    # --- VULNERABLE route: no CSRF token required ---
    @app.route("/vulnerable/transfer", methods=["GET", "POST"])
    @csrf.exempt
    @login_required
    def vuln_transfer():
        user = session["user"]
        if request.method == "POST":
            msg, cat = do_transfer(user, protected=False)
            if cat == "success":
                app.logger.warning("VULNERABLE transfer by %s: %s", user, msg)
                msg += " (NO CSRF protection!)"
            flash(msg, cat)
            return redirect(url_for("vuln_transfer"))
        return render_template("transfer.html", mode="vulnerable", user=user,
                               balance=ACCOUNTS[user]["balance"], log=TRANSFER_LOG)

    # --- Simulated attacker page (hosted same-origin for this local lab) ---
    @app.route("/attacker")
    def attacker_page():
        return render_template("attacker.html")

    # --- SECURE route: Flask-WTF validates csrf_token on every POST ---
    @app.route("/secure/transfer", methods=["GET", "POST"])
    @login_required
    def safe_transfer():
        user = session["user"]
        if request.method == "POST":
            # Execution only reaches here if the CSRF token was valid;
            # Flask-WTF raises CSRFError (400) before this on a bad/absent token.
            msg, cat = do_transfer(user, protected=True)
            if cat == "success":
                app.logger.info("SECURE transfer by %s: %s", user, msg)
                msg += " (CSRF token validated)"
            flash(msg, cat)
            return redirect(url_for("safe_transfer"))
        return render_template("transfer.html", mode="secure", user=user,
                               balance=ACCOUNTS[user]["balance"], log=TRANSFER_LOG)

    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        app.logger.warning("CSRF validation failed: %s", e.description)
        flash("Request rejected — CSRF token missing or invalid.", "danger")
        if "user" in session:
            return redirect(url_for("safe_transfer"))
        return redirect(url_for("login"))

    @app.errorhandler(404)
    def not_found(e):
        return "Page not found.", 404

    return app


def reset_accounts():
    """Restore starting balances and clear the log (used by the test suite)."""
    ACCOUNTS["alice"]["balance"] = 1000.00
    ACCOUNTS["bob"]["balance"] = 500.00
    ACCOUNTS["admin"]["balance"] = 5000.00
    TRANSFER_LOG.clear()


if __name__ == "__main__":
    create_app().run(debug=False, port=5002)
