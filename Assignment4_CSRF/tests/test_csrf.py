"""
WEB404 Assignment 4 – CSRF Test Suite
Part A: the SECURE route accepts valid tokens and rejects forged/missing ones.
Part B: the VULNERABLE route accepts a forged (token-less) request, proving the
        attack is possible without protection.

Limitation: Flask's test client is not a browser, so it exercises the server-side
token check (the primary defence). SameSite and Origin enforcement are applied by
the browser and would need Selenium or Burp Suite to verify end-to-end.
"""
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "app"))
from app import create_app, reset_accounts, ACCOUNTS, TRANSFER_LOG  # noqa: E402


@pytest.fixture(autouse=True)
def clean_state():
    """Restore fictional balances before every test."""
    reset_accounts()


@pytest.fixture
def app():
    application = create_app(testing=True)
    application.config["WTF_CSRF_ENABLED"] = True  # keep CSRF ON while testing
    return application


@pytest.fixture
def client(app):
    return app.test_client()


def _csrf_token(client, url):
    """Pull the hidden csrf_token value out of a rendered form."""
    html = client.get(url).data.decode()
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    return match.group(1) if match else None


def login(client, username="alice", password="password123"):
    """Log in the way a browser would: fetch the token, then submit it."""
    token = _csrf_token(client, "/login")
    return client.post(
        "/login",
        data={"username": username, "password": password, "csrf_token": token},
        follow_redirects=True,
    )


# === PART A — SECURE ROUTE ===

class TestSecureRoute:
    def test_form_contains_csrf_token(self, client):
        login(client)
        html = client.get("/secure/transfer").data.decode()
        assert 'name="csrf_token"' in html

    def test_valid_transfer_with_token(self, client):
        login(client)
        token = _csrf_token(client, "/secure/transfer")
        resp = client.post(
            "/secure/transfer",
            data={"recipient": "bob", "amount": "50", "csrf_token": token},
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"Transferred" in resp.data
        assert ACCOUNTS["alice"]["balance"] == 950.00
        assert ACCOUNTS["bob"]["balance"] == 550.00

    def test_missing_token_rejected(self, client):
        login(client)
        resp = client.post(
            "/secure/transfer",
            data={"recipient": "bob", "amount": "100"},  # no csrf_token
            follow_redirects=True,
        )
        assert b"rejected" in resp.data or b"CSRF" in resp.data
        assert ACCOUNTS["alice"]["balance"] == 1000.00  # unchanged
        assert TRANSFER_LOG == []

    def test_empty_token_rejected(self, client):
        login(client)
        resp = client.post(
            "/secure/transfer",
            data={"recipient": "bob", "amount": "100", "csrf_token": ""},
            follow_redirects=True,
        )
        assert b"rejected" in resp.data or b"CSRF" in resp.data
        assert ACCOUNTS["alice"]["balance"] == 1000.00

    def test_forged_token_rejected(self, client):
        login(client)
        resp = client.post(
            "/secure/transfer",
            data={"recipient": "bob", "amount": "100",
                  "csrf_token": "forged-token-from-attacker"},
            follow_redirects=True,
        )
        assert b"rejected" in resp.data or b"CSRF" in resp.data
        assert ACCOUNTS["alice"]["balance"] == 1000.00

    def test_get_does_not_transfer(self, client):
        login(client)
        client.get("/secure/transfer")
        assert ACCOUNTS["alice"]["balance"] == 1000.00
        assert TRANSFER_LOG == []


# === PART B — VULNERABLE ROUTE ===

class TestVulnerableRoute:
    def test_forged_request_without_token_succeeds(self, client):
        """The whole point of the lab: no token check means the attack works."""
        login(client)
        resp = client.post(
            "/vulnerable/transfer",
            data={"recipient": "bob", "amount": "100"},  # no csrf_token
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"Transferred" in resp.data
        assert ACCOUNTS["alice"]["balance"] == 900.00
        assert ACCOUNTS["bob"]["balance"] == 600.00
        assert TRANSFER_LOG[-1]["protected"] is False

    def test_get_does_not_transfer(self, client):
        login(client)
        client.get("/vulnerable/transfer")
        assert ACCOUNTS["alice"]["balance"] == 1000.00


# === SUPPORTING CHECKS ===

class TestAuthAndAttackerPage:
    def test_transfer_requires_login(self, client):
        resp = client.get("/secure/transfer", follow_redirects=True)
        assert b"login" in resp.data.lower()

    def test_attacker_page_targets_vulnerable_route(self, client):
        resp = client.get("/attacker")
        assert resp.status_code == 200
        assert b"/vulnerable/transfer" in resp.data  # hidden-form action


class TestCookieSettings:
    def test_session_cookie_httponly(self, app):
        assert app.config["SESSION_COOKIE_HTTPONLY"] is True

    def test_session_cookie_samesite(self, app):
        assert app.config.get("SESSION_COOKIE_SAMESITE") in ("Lax", "Strict")
