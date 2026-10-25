"""
WEB404 Assignment 5 — JWT Security Test Suite
===============================================
Tests cover:
  1. Valid authentication and token issuance
  2. Invalid credentials rejected
  3. Expired token rejected
  4. Tampered / modified payload rejected
  5. Missing token → 401
  6. Invalid signature rejected
  7. Algorithm confusion / alg:none blocked
  8. Missing required claims rejected
  9. Token revocation (blacklist)
  10. Protected route access control

Run: python -m pytest tests/ -v
"""

import datetime
import os
import sys
import time

import jwt as pyjwt
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "app"))

from auth import (
    authenticate, create_token, verify_token,
    revoke_token, decode_without_verification, BLACKLIST,
)
from config import JWT_SECRET, JWT_ALGORITHM
from app import create_app


@pytest.fixture(autouse=True)
def clear_blacklist():
    BLACKLIST.clear()
    yield
    BLACKLIST.clear()


@pytest.fixture
def app():
    application = create_app(testing=True)
    application.config["WTF_CSRF_ENABLED"] = False
    return application


@pytest.fixture
def client(app):
    return app.test_client()


# ===================================================================
# 1. Valid authentication
# ===================================================================
class TestValidAuth:
    def test_correct_credentials_return_user(self):
        user = authenticate("alice", "password123")
        assert user is not None
        assert user["username"] == "alice"
        assert user["role"] == "user"

    def test_create_and_verify_token(self):
        token = create_token("alice", "user")
        payload = verify_token(token)
        assert payload["sub"] == "alice"
        assert payload["role"] == "user"
        assert "exp" in payload
        assert "iat" in payload

    def test_login_sets_cookie(self, client):
        resp = client.post("/login", data={
            "username": "alice", "password": "password123",
        })
        assert resp.status_code == 302  # redirect to dashboard
        # Check Set-Cookie header in the response
        cookie_header = resp.headers.get("Set-Cookie", "")
        assert "jwt_token" in cookie_header

    def test_dashboard_accessible_with_token(self, client):
        client.post("/login", data={
            "username": "alice", "password": "password123",
        })
        resp = client.get("/dashboard")
        assert resp.status_code == 200
        assert b"alice" in resp.data


# ===================================================================
# 2. Invalid credentials
# ===================================================================
class TestInvalidCredentials:
    def test_wrong_password(self):
        assert authenticate("alice", "wrong") is None

    def test_nonexistent_user(self):
        assert authenticate("hacker", "pass") is None

    def test_login_returns_401(self, client):
        resp = client.post("/login", data={
            "username": "alice", "password": "wrong",
        })
        assert resp.status_code == 401
        assert b"Invalid credentials" in resp.data


# ===================================================================
# 3. Expired token
# ===================================================================
class TestExpiredToken:
    def test_expired_token_rejected(self):
        # Create a token that expires in 1 second
        token = create_token("alice", "user", expires_seconds=1)
        time.sleep(2)
        with pytest.raises(pyjwt.ExpiredSignatureError):
            verify_token(token)

    def test_expired_cookie_redirects(self, client):
        token = create_token("alice", "user", expires_seconds=1)
        client.set_cookie("jwt_token", token, domain="localhost")
        time.sleep(2)
        resp = client.get("/dashboard", follow_redirects=True)
        assert b"expired" in resp.data.lower() or b"log in" in resp.data.lower()


# ===================================================================
# 4. Tampered / modified payload
# ===================================================================
class TestTamperedToken:
    def test_modified_payload_rejected(self):
        """Change the 'role' claim from 'user' to 'admin' without re-signing."""
        token = create_token("alice", "user")
        # Decode without verification, modify, re-encode with WRONG key
        parts = token.split(".")
        import base64, json
        # Decode payload
        padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))
        payload["role"] = "admin"  # privilege escalation attempt
        # Re-encode payload (but keep original signature → mismatch)
        new_payload = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).rstrip(b"=").decode()
        tampered = f"{parts[0]}.{new_payload}.{parts[2]}"
        with pytest.raises(pyjwt.InvalidSignatureError):
            verify_token(tampered)

    def test_tampered_cookie_rejected(self, client):
        token = create_token("alice", "user")
        # Flip a character in the signature
        tampered = token[:-3] + "XXX"
        client.set_cookie("jwt_token", tampered, domain="localhost")
        resp = client.get("/api/profile",
                          headers={"Accept": "application/json"})
        assert resp.status_code == 401


# ===================================================================
# 5. Missing token
# ===================================================================
class TestMissingToken:
    def test_no_cookie_returns_401(self, client):
        resp = client.get("/api/profile",
                          headers={"Accept": "application/json"})
        assert resp.status_code == 401
        data = resp.get_json()
        assert "Missing token" in data["error"]

    def test_dashboard_redirects_to_login(self, client):
        resp = client.get("/dashboard", follow_redirects=True)
        assert b"Log in" in resp.data or b"log in" in resp.data


# ===================================================================
# 6. Invalid signature (signed with wrong key)
# ===================================================================
class TestInvalidSignature:
    def test_wrong_key_rejected(self):
        payload = {
            "sub": "alice", "role": "admin",
            "iat": datetime.datetime.now(datetime.timezone.utc),
            "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1),
        }
        fake_token = pyjwt.encode(payload, "attacker-secret", algorithm="HS256")
        with pytest.raises(pyjwt.InvalidSignatureError):
            verify_token(fake_token)


# ==================================================================
# 7. Algorithm confusion / alg:none
# ==================================================================
class TestAlgorithmConfusion:
    def test_none_algorithm_rejected(self):
        """A token with alg:none must be rejected."""
        payload = {
            "sub": "admin", "role": "admin",
            "iat": datetime.datetime.now(datetime.timezone.utc),
            "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1),
        }
        # Craft a token with algorithm=none
        # PyJWT >=2.4 refuses to encode with none, so build manually
        import base64, json, hmac
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "typ": "JWT"}).encode()
        ).rstrip(b"=").decode()
        pay = base64.urlsafe_b64encode(
            json.dumps(payload, default=str).encode()
        ).rstrip(b"=").decode()
        none_token = f"{header}.{pay}."
        with pytest.raises((pyjwt.exceptions.DecodeError,
                            pyjwt.exceptions.InvalidAlgorithmError)):
            verify_token(none_token)

    def test_hs384_rejected(self):
        """A token signed with HS384 must be rejected (only HS256 is allowed)."""
        payload = {
            "sub": "alice", "role": "user",
            "iat": datetime.datetime.now(datetime.timezone.utc),
            "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1),
        }
        token = pyjwt.encode(payload, JWT_SECRET, algorithm="HS384")
        with pytest.raises(pyjwt.InvalidAlgorithmError):
            verify_token(token)


# ==================================================================
# 8. Missing required claims
# ==================================================================
class TestMissingClaims:
    def test_missing_sub_rejected(self):
        payload = {
            "role": "user",
            "iat": datetime.datetime.now(datetime.timezone.utc),
            "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1),
        }
        token = pyjwt.encode(payload, JWT_SECRET, algorithm="HS256")
        with pytest.raises(pyjwt.MissingRequiredClaimError):
            verify_token(token)

    def test_missing_role_rejected(self):
        payload = {
            "sub": "alice",
            "iat": datetime.datetime.now(datetime.timezone.utc),
            "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1),
        }
        token = pyjwt.encode(payload, JWT_SECRET, algorithm="HS256")
        with pytest.raises(pyjwt.MissingRequiredClaimError):
            verify_token(token)


# ==================================================================
# 9. Token revocation (blacklist)
# ===================================================================
class TestTokenRevocation:
    def test_revoked_token_rejected(self):
        token = create_token("alice", "user")
        # Valid before revocation
        assert verify_token(token)["sub"] == "alice"
        # Revoke
        revoke_token(token)
        with pytest.raises(pyjwt.InvalidTokenError, match="revoked"):
            verify_token(token)

    def test_logout_clears_cookie(self, client):
        client.post("/login", data={
            "username": "alice", "password": "password123",
        })
        resp = client.get("/logout", follow_redirects=True)
        assert b"Logged out" in resp.data


# ===================================================================
# 10. Protected route access
# ==================================================================
class TestProtectedRoute:
    def test_api_returns_json_with_valid_token(self, client):
        client.post("/login", data={
            "username": "admin", "password": "supersecret",
        })
        resp = client.get("/api/profile",
                          headers={"Accept": "application/json"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["username"] == "admin"
        assert data["role"] == "admin"
