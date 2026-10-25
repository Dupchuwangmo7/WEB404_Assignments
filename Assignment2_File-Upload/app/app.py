"""
WEB404 Practical Assignment 3 – Secure File Upload Application
==============================================================
Implements defence-in-depth against malicious file uploads:

1.  Extension allowlisting
2.  File-size limit (server-enforced)
3.  MIME-type + magic-byte validation
4.  Safe filename handling (Werkzeug secure_filename + UUID rename)
5.  Storage outside the web-accessible static/ directory
6.  Randomised server-side filenames
7.  Simple session-based authentication gate
8.  Safe error messages (no internal paths leaked) + logging
9.  CSRF protection via Flask-WTF / CSRFProtect
10. Uploaded files are never executed (served as attachments only)
"""

import logging
import os
import uuid
from datetime import datetime
from functools import wraps

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from flask_wtf import CSRFProtect
from werkzeug.utils import secure_filename

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
# Store uploads ONE level above app/ so they are never inside static/
UPLOAD_FOLDER = os.path.join(BASE_DIR, os.pardir, "uploads")
UPLOAD_FOLDER = os.path.abspath(UPLOAD_FOLDER)

# Security control 2 – hard cap at 2 MB
MAX_CONTENT_LENGTH = 2 * 1024 * 1024  # 2 MB

# Security control 1 – extension allowlist
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "pdf", "txt"}

# Security control 3 – expected magic bytes for validated types
# Maps extensions to (mime_type, magic_bytes) pairs.
# magic_bytes is a list of possible signatures (some formats have several).
MAGIC_SIGNATURES = {
    "png": {
        "mimes": {"image/png"},
        "signatures": [b"\x89PNG\r\n\x1a\n"],
    },
    "jpg": {
        "mimes": {"image/jpeg"},
        "signatures": [b"\xff\xd8\xff"],
    },
    "jpeg": {
        "mimes": {"image/jpeg"},
        "signatures": [b"\xff\xd8\xff"],
    },
    "gif": {
        "mimes": {"image/gif"},
        "signatures": [b"GIF87a", b"GIF89a"],
    },
    "pdf": {
        "mimes": {"application/pdf"},
        "signatures": [b"%PDF"],
    },
    "txt": {
        "mimes": {"text/plain"},
        "signatures": [],  # no fixed magic bytes – validated differently
    },
}

# Demo credentials (never use plaintext passwords in production)
DEMO_USER = "admin"
DEMO_PASS = "secure123"


def create_app(testing: bool = False) -> Flask:
    """Application factory – makes the app easy to test."""
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-key-change-me")
    app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
    app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
    app.config["TESTING"] = testing

    # Security control 9 – CSRF protection
    csrf = CSRFProtect(app)

    # Ensure the upload directory exists
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)

    # -----------------------------------------------------------------------
    # Logging – security control 8
    # -----------------------------------------------------------------------
    handler = logging.StreamHandler()
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter(
        "[%(asctime)s] %(levelname)s in %(module)s: %(message)s"
    )
    handler.setFormatter(formatter)
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    def allowed_file(filename: str) -> bool:
        """Security control 1 – only accept files with an allowed extension."""
        return (
            "." in filename
            and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
        )

    def validate_content(file_storage, extension: str) -> tuple[bool, str]:
        """Security control 3 – validate MIME type AND file magic bytes.

        WHY THIS MATTERS
        ================
        The browser-supplied Content-Type header is trivially spoofed by an
        attacker.  Checking only the filename extension is equally unreliable
        because a file named ``safe.png`` can contain PHP or shell code.
        Defence-in-depth therefore demands we also inspect the first few bytes
        of the actual file content (the "magic number / file signature") to
        confirm the file is really what the extension claims.
        """
        sig_info = MAGIC_SIGNATURES.get(extension)
        if sig_info is None:
            return False, "No validation rule for this extension."

        # Check MIME type reported by the browser (first layer – advisory only)
        if file_storage.content_type not in sig_info["mimes"]:
            return False, "MIME type does not match the file extension."

        # Check magic bytes (second layer – authoritative)
        if sig_info["signatures"]:
            header = file_storage.read(8)
            file_storage.seek(0)  # rewind so the file can be saved later
            if not any(header.startswith(sig) for sig in sig_info["signatures"]):
                return False, "File content does not match the expected format."

        # For .txt we simply verify the whole file is decodable as UTF-8
        if extension == "txt":
            try:
                raw = file_storage.read()
                raw.decode("utf-8")
                file_storage.seek(0)
            except UnicodeDecodeError:
                return False, "Text file contains invalid characters."

        return True, "OK"

    def generate_safe_name(original_filename: str) -> str:
        """Security controls 4 + 6 – neutralise the original name.

        1. ``secure_filename`` strips path separators, null bytes, etc.
        2. We then REPLACE the entire base name with a UUID so no
           user-controlled string ever reaches the filesystem.
        """
        safe = secure_filename(original_filename)
        ext = safe.rsplit(".", 1)[1].lower() if "." in safe else ""
        return f"{uuid.uuid4().hex}.{ext}"

    # -----------------------------------------------------------------------
    # Auth helpers – security control 7
    # -----------------------------------------------------------------------

    def login_required(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not session.get("logged_in"):
                flash("Please log in first.", "warning")
                return redirect(url_for("login"))
            return f(*args, **kwargs)
        return decorated

    # -----------------------------------------------------------------------
    # Routes
    # -----------------------------------------------------------------------

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            if username == DEMO_USER and password == DEMO_PASS:
                session["logged_in"] = True
                app.logger.info("User '%s' logged in.", username)
                flash("Logged in successfully.", "success")
                return redirect(url_for("upload_page"))
            app.logger.warning("Failed login attempt for user '%s'.", username)
            flash("Invalid credentials.", "danger")
        return render_template("login.html")

    @app.route("/logout")
    def logout():
        session.pop("logged_in", None)
        flash("Logged out.", "info")
        return redirect(url_for("login"))

    @app.route("/", methods=["GET", "POST"])
    @login_required
    def upload_page():
        if request.method == "POST":
            # --- no file part? ------------------------------------------------
            if "file" not in request.files:
                flash("No file part in the request.", "danger")
                app.logger.warning("Upload attempt with no file part.")
                return redirect(request.url)

            file = request.files["file"]

            # --- empty filename? (user hit submit without choosing a file) ----
            if file.filename == "" or file.filename is None:
                flash("No file selected.", "danger")
                app.logger.warning("Upload attempt with empty filename.")
                return redirect(request.url)

            # --- extension allowlist ------------------------------------------
            if not allowed_file(file.filename):
                flash(
                    "File type not allowed. Permitted: "
                    + ", ".join(sorted(ALLOWED_EXTENSIONS)) + ".",
                    "danger",
                )
                app.logger.warning(
                    "Blocked upload of disallowed extension: %s",
                    secure_filename(file.filename),
                )
                return redirect(request.url)

            extension = file.filename.rsplit(".", 1)[1].lower()

            # --- MIME + magic-byte validation ---------------------------------
            valid, reason = validate_content(file, extension)
            if not valid:
                flash(f"File rejected: {reason}", "danger")
                app.logger.warning(
                    "Content validation failed for '%s': %s",
                    secure_filename(file.filename),
                    reason,
                )
                return redirect(request.url)

            # --- generate a safe server-side filename -------------------------
            server_name = generate_safe_name(file.filename)
            save_path = os.path.join(app.config["UPLOAD_FOLDER"], server_name)

            # --- final path-traversal guard -----------------------------------
            # Even after UUID-renaming, verify the resolved path is still
            # inside the upload folder (belt-and-suspenders).
            if not os.path.abspath(save_path).startswith(
                os.path.abspath(app.config["UPLOAD_FOLDER"])
            ):
                flash("Invalid file path.", "danger")
                app.logger.error("Path traversal attempt detected!")
                return redirect(request.url)

            file.save(save_path)
            app.logger.info("File saved as %s (original: %s)", server_name,
                            secure_filename(file.filename))
            flash("File uploaded successfully!", "success")
            return redirect(request.url)

        # List already-uploaded files for display
        uploaded = []
        if os.path.isdir(app.config["UPLOAD_FOLDER"]):
            uploaded = [
                f for f in sorted(os.listdir(app.config["UPLOAD_FOLDER"]))
                if f != ".gitkeep"
            ]
        return render_template("upload.html", uploaded=uploaded)

    # Security control 10 – serve uploads as attachments, never inline.
    # This prevents the browser from executing HTML/SVG/JS disguised as
    # an image.
    @app.route("/download/<filename>")
    @login_required
    def download_file(filename):
        safe = secure_filename(filename)
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], safe)
        if not os.path.isfile(filepath):
            flash("File not found.", "danger")
            return redirect(url_for("upload_page"))
        return send_from_directory(
            app.config["UPLOAD_FOLDER"],
            safe,
            as_attachment=True,  # <-- forces download, never rendered
        )

    # -----------------------------------------------------------------------
    # Error handlers – security control 8 (safe messages)
    # -----------------------------------------------------------------------

    @app.errorhandler(413)
    def file_too_large(e):
        flash(
            f"File exceeds the {MAX_CONTENT_LENGTH // (1024*1024)} MB limit.",
            "danger",
        )
        return redirect(url_for("upload_page"))

    @app.errorhandler(404)
    def not_found(e):
        return "Page not found.", 404

    return app


# ---------------------------------------------------------------------------
# Dev server entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app = create_app()
    app.run(debug=True, port=5000)
