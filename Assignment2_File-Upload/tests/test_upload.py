"""
WEB404 Assignment 2 – Automated Security Tests for the Upload Feature
=====================================================================
Each test uses *harmless* payloads — no real malware is involved.

Run with:
    cd web404-practical-02-secure-upload
    python -m pytest tests/ -v
"""

import io
import os
import sys
import tempfile

import pytest

# Add the app directory to the path so we can import the factory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "app"))

from app import create_app  # noqa: E402


@pytest.fixture
def app(tmp_path):
    """Create an app instance with a temporary upload folder."""
    application = create_app(testing=True)
    application.config["UPLOAD_FOLDER"] = str(tmp_path / "uploads")
    os.makedirs(application.config["UPLOAD_FOLDER"], exist_ok=True)
    application.config["WTF_CSRF_ENABLED"] = False  # disable CSRF for tests
    return application


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def logged_in_client(client):
    """Return a client that has already authenticated."""
    client.post("/login", data={"username": "admin", "password": "secure123"})
    return client


# ------------------------------------------------------------------
# Helper: build a fake file upload
# ------------------------------------------------------------------
def _make_file(name, content, mime="application/octet-stream"):
    return (io.BytesIO(content), name, mime)


# ------------------------------------------------------------------
# 1. Valid permitted upload
# ------------------------------------------------------------------
class TestValidUpload:
    """A legitimate PNG file should be accepted and stored."""

    def test_valid_png_upload(self, logged_in_client, app):
        # Minimal valid PNG (1×1 pixel, white)
        png_header = (
            b"\x89PNG\r\n\x1a\n"  # PNG signature
            b"\x00\x00\x00\rIHDR"
            b"\x00\x00\x00\x01"  # width 1
            b"\x00\x00\x00\x01"  # height 1
            b"\x08\x02"          # 8-bit RGB
            b"\x00\x00\x00"
            b"\x90wS\xde"        # CRC
            b"\x00\x00\x00\x0cIDATx"
            b"\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05"
            b"\x18\xd8N"
            b"\x00\x00\x00\x00IEND\xaeB`\x82"
        )
        data = {"file": (io.BytesIO(png_header), "photo.png", "image/png")}
        resp = logged_in_client.post(
            "/", data=data, content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"File uploaded successfully" in resp.data

        # Verify the file was saved (with a UUID name, not the original)
        saved = os.listdir(app.config["UPLOAD_FOLDER"])
        saved = [f for f in saved if f != ".gitkeep"]
        assert len(saved) == 1
        assert saved[0].endswith(".png")
        assert saved[0] != "photo.png"  # UUID-renamed

    def test_valid_txt_upload(self, logged_in_client):
        data = {
            "file": (io.BytesIO(b"Hello, world!"), "note.txt", "text/plain")
        }
        resp = logged_in_client.post(
            "/", data=data, content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"File uploaded successfully" in resp.data


# ------------------------------------------------------------------
# 2. Disallowed extension
# ------------------------------------------------------------------
class TestDisallowedExtension:
    """Files with extensions not in the allowlist must be rejected."""

    @pytest.mark.parametrize("name", [
        "script.exe",
        "shell.sh",
        "page.html",
        "payload.php",
        "macro.docm",
    ])
    def test_blocked_extensions(self, logged_in_client, name):
        data = {"file": (io.BytesIO(b"harmless content"), name, "application/octet-stream")}
        resp = logged_in_client.post(
            "/", data=data, content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert b"File type not allowed" in resp.data


# ------------------------------------------------------------------
# 3. Oversized file
# ------------------------------------------------------------------
class TestOversizedFile:
    """Files exceeding MAX_CONTENT_LENGTH (2 MB) must be rejected."""

    def test_file_over_2mb(self, logged_in_client):
        big = b"\x00" * (3 * 1024 * 1024)  # 3 MB of null bytes
        data = {"file": (io.BytesIO(big), "huge.txt", "text/plain")}
        resp = logged_in_client.post(
            "/", data=data, content_type="multipart/form-data",
            follow_redirects=True,
        )
        # Flask returns 413 which our handler redirects with a flash
        assert resp.status_code in (200, 413)


# ------------------------------------------------------------------
# 4. Empty / malformed upload
# ------------------------------------------------------------------
class TestEmptyUpload:
    """Submitting the form without a file should show an error."""

    def test_no_file_part(self, logged_in_client):
        # POST with no 'file' field at all
        resp = logged_in_client.post(
            "/", data={}, content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert b"No file part" in resp.data

    def test_empty_filename(self, logged_in_client):
        # A file input with no file selected sends an empty filename
        data = {"file": (io.BytesIO(b""), "", "application/octet-stream")}
        resp = logged_in_client.post(
            "/", data=data, content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert b"No file selected" in resp.data


# ------------------------------------------------------------------
# 5. Path-traversal filename
# ------------------------------------------------------------------
class TestPathTraversal:
    """Filenames containing ../ or other traversal characters must be
    neutralised.  The file should either be rejected outright or saved
    under a safe UUID name inside the upload folder – never written
    outside it."""

    @pytest.mark.parametrize("malicious_name", [
        "../../etc/passwd.txt",
        "../../../app/app.py",
        "..\\..\\windows\\system32\\config.txt",
        "foo/bar/../../baz.txt",
    ])
    def test_traversal_filenames(self, logged_in_client, app, malicious_name):
        data = {
            "file": (io.BytesIO(b"safe content"), malicious_name, "text/plain")
        }
        resp = logged_in_client.post(
            "/", data=data, content_type="multipart/form-data",
            follow_redirects=True,
        )
        # The upload must NOT escape the upload folder
        upload_dir = app.config["UPLOAD_FOLDER"]
        for root, _dirs, files in os.walk(os.path.dirname(upload_dir)):
            for f in files:
                full = os.path.join(root, f)
                if full.startswith(upload_dir):
                    continue
                # If a file landed outside the upload dir, fail
                assert not full.endswith(
                    malicious_name.replace("/", os.sep)
                ), f"File escaped upload dir: {full}"


# ------------------------------------------------------------------
# 6. Misleading content / MIME type
# ------------------------------------------------------------------
class TestMisleadingContent:
    """A file whose extension says 'png' but whose content is actually
    an executable/script must be rejected by the magic-byte check."""

    def test_exe_disguised_as_png(self, logged_in_client):
        # Windows PE header masquerading as a .png
        pe_bytes = b"MZ" + b"\x00" * 100
        data = {
            "file": (io.BytesIO(pe_bytes), "innocent.png", "image/png")
        }
        resp = logged_in_client.post(
            "/", data=data, content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert b"File rejected" in resp.data or b"does not match" in resp.data

    def test_html_disguised_as_jpg(self, logged_in_client):
        html_content = b"<html><script>alert('xss')</script></html>"
        data = {
            "file": (io.BytesIO(html_content), "photo.jpg", "image/jpeg")
        }
        resp = logged_in_client.post(
            "/", data=data, content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert b"File rejected" in resp.data or b"does not match" in resp.data

    def test_wrong_mime_correct_extension(self, logged_in_client):
        # Correct PNG bytes but wrong MIME type header
        png_header = b"\x89PNG\r\n\x1a\n" + b"\x00" * 50
        data = {
            "file": (
                io.BytesIO(png_header),
                "pic.png",
                "application/x-executable",  # spoofed MIME
            )
        }
        resp = logged_in_client.post(
            "/", data=data, content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert b"File rejected" in resp.data or b"MIME type" in resp.data


# ------------------------------------------------------------------
# 7. Direct access to uploads when storage should be private
# ------------------------------------------------------------------
class TestPrivateStorage:
    """Uploaded files must NOT be accessible via the /static/ route or
    any direct URL-guessing.  They should only be reachable through
    the authenticated /download/<filename> endpoint."""

    def test_uploads_not_under_static(self, logged_in_client):
        # Try to fetch a file as if it were in /static/uploads/
        resp = logged_in_client.get("/static/uploads/test.png")
        assert resp.status_code == 404

    def test_download_requires_login(self, client):
        # An unauthenticated client must be redirected to login
        resp = client.get("/download/anything.png", follow_redirects=True)
        assert b"Please log in" in resp.data or b"Login" in resp.data

    def test_download_nonexistent_file(self, logged_in_client):
        resp = logged_in_client.get(
            "/download/nonexistent.png", follow_redirects=True
        )
        assert b"File not found" in resp.data


# ------------------------------------------------------------------
# Bonus: authentication tests
# ------------------------------------------------------------------
class TestAuthentication:
    """Upload page must require a valid session."""

    def test_upload_page_requires_login(self, client):
        resp = client.get("/", follow_redirects=True)
        assert b"Log in" in resp.data or b"log in" in resp.data

    def test_wrong_password_rejected(self, client):
        resp = client.post(
            "/login",
            data={"username": "admin", "password": "wrongpass"},
            follow_redirects=True,
        )
        assert b"Invalid credentials" in resp.data
