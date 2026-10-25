"""
WEB404 Assignment 3 – SQL Injection Test Suite
Part A: Prove vulnerable functions ARE exploitable
Part B: Prove secure functions RESIST the same payloads
"""
import os, sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "app"))
from database import (init_db, vulnerable_login, vulnerable_search,
                       secure_login, secure_search)


@pytest.fixture(autouse=True)
def fresh_db(tmp_path, monkeypatch):
    db_path = str(tmp_path / "test_lab.db")
    monkeypatch.setattr("database.DB_PATH", db_path)
    init_db()


# === PART A — VULNERABLE ===

class TestVulnerableLogin:
    def test_normal_login_works(self):
        result = vulnerable_login("alice", "password123")
        assert len(result) == 1
        assert result[0]["username"] == "alice"

    def test_wrong_password_fails(self):
        assert len(vulnerable_login("alice", "wrong")) == 0

    def test_auth_bypass_with_or_true(self):
        """' OR '1'='1' -- bypasses authentication."""
        result = vulnerable_login("' OR '1'='1' --", "anything")
        assert len(result) >= 1

    def test_auth_bypass_via_password_field(self):
        result = vulnerable_login("admin", "' OR '1'='1")
        assert len(result) >= 1

    def test_error_based_injection(self):
        result = vulnerable_login("'", "test")
        assert len(result) >= 1
        assert "error" in result[0]


class TestVulnerableSearch:
    def test_normal_search_works(self):
        result = vulnerable_search("Mouse")
        assert len(result) == 1
        assert result[0]["name"] == "Wireless Mouse"

    def test_union_extract_usernames(self):
        payload = "' UNION SELECT id, username, password, role FROM users --"
        result = vulnerable_search(payload)
        assert any("admin" in str(v) for r in result for v in r.values())

    def test_boolean_blind_true(self):
        assert len(vulnerable_search("' OR 1=1 --")) >= 1

    def test_boolean_blind_false(self):
        assert len(vulnerable_search("' AND 1=2 --")) == 0


# === PART B — SECURE ===

class TestSecureLogin:
    def test_normal_login_works(self):
        result = secure_login("alice", "password123")
        assert len(result) == 1
        assert result[0]["username"] == "alice"

    def test_wrong_password_fails(self):
        assert len(secure_login("alice", "wrong")) == 0

    def test_auth_bypass_blocked(self):
        assert len(secure_login("' OR '1'='1' --", "anything")) == 0

    def test_auth_bypass_via_password_blocked(self):
        assert len(secure_login("admin", "' OR '1'='1")) == 0

    def test_error_injection_blocked(self):
        result = secure_login("'", "test")
        assert len(result) == 0


class TestSecureSearch:
    def test_normal_search_works(self):
        result = secure_search("Mouse")
        assert len(result) == 1

    def test_union_injection_blocked(self):
        payload = "' UNION SELECT id, username, password, role FROM users --"
        result = secure_search(payload)
        assert not any("admin" in str(v) for r in result for v in r.values())

    def test_boolean_true_blocked(self):
        assert len(secure_search("' OR 1=1 --")) == 0

    def test_boolean_false_blocked(self):
        assert len(secure_search("' AND 1=2 --")) == 0
