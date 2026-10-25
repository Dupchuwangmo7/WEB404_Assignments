"""
WEB404 Assignment 3 – Database Layer
Provides VULNERABLE and SECURE query functions side by side.
"""
import logging
import os
import sqlite3

logger = logging.getLogger(__name__)

DB_DIR = os.path.join(os.path.dirname(__file__), os.pardir, "database")
DB_PATH = os.path.abspath(os.path.join(DB_DIR, "lab.db"))


def get_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    conn.executescript("""
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS products;

        CREATE TABLE users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role     TEXT NOT NULL DEFAULT 'user'
        );

        CREATE TABLE products (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL,
            category    TEXT NOT NULL,
            price       REAL NOT NULL,
            secret_note TEXT NOT NULL DEFAULT ''
        );

        INSERT INTO users (username, password, role) VALUES
            ('alice',   'password123', 'user'),
            ('bob',     'letmein',     'user'),
            ('charlie', 'qwerty',      'user'),
            ('admin',   'supersecret', 'admin');

        INSERT INTO products (name, category, price, secret_note) VALUES
            ('Wireless Mouse',      'Electronics', 29.99, 'Bulk discount available'),
            ('Mechanical Keyboard', 'Electronics', 89.50, 'Supplier: KeyTech Ltd'),
            ('Desk Lamp',           'Office',      34.00, 'Discontinued next quarter'),
            ('USB-C Hub',           'Electronics', 45.00, 'Margin: 42%'),
            ('Notebook A5',         'Stationery',   5.99, 'Min order: 100 units'),
            ('Ergonomic Chair',     'Office',     299.00, 'Warranty: 5 years');
    """)
    conn.commit()
    conn.close()
    logger.info("Database initialised at %s", DB_PATH)


# === VULNERABLE FUNCTIONS (educational only) ===

def vulnerable_login(username, password):
    conn = get_connection()
    query = f"SELECT id, username, role FROM users WHERE username = '{username}' AND password = '{password}'"
    logger.warning("VULNERABLE query: %s", query)
    try:
        rows = conn.execute(query).fetchall()
    except sqlite3.OperationalError as exc:
        logger.error("SQL error: %s", exc)
        conn.close()
        return [{"error": str(exc)}]
    conn.close()
    return [dict(r) for r in rows]


def vulnerable_search(term):
    conn = get_connection()
    query = f"SELECT id, name, category, price FROM products WHERE name LIKE '%{term}%'"
    logger.warning("VULNERABLE query: %s", query)
    try:
        rows = conn.execute(query).fetchall()
    except sqlite3.OperationalError as exc:
        logger.error("SQL error: %s", exc)
        conn.close()
        return [{"error": str(exc)}]
    conn.close()
    return [dict(r) for r in rows]


# === SECURE FUNCTIONS (parameterised queries) ===

def secure_login(username, password):
    conn = get_connection()
    query = "SELECT id, username, role FROM users WHERE username = ? AND password = ?"
    rows = conn.execute(query, (username, password)).fetchall()
    conn.close()
    logger.info("Secure login for user: %s", username)
    return [dict(r) for r in rows]


def secure_search(term):
    conn = get_connection()
    query = "SELECT id, name, category, price FROM products WHERE name LIKE ?"
    rows = conn.execute(query, (f"%{term}%",)).fetchall()
    conn.close()
    logger.info("Secure search for: %s", term)
    return [dict(r) for r in rows]


def get_all_users():
    conn = get_connection()
    rows = conn.execute("SELECT id, username, role FROM users").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_all_products():
    conn = get_connection()
    rows = conn.execute("SELECT id, name, category, price FROM products").fetchall()
    conn.close()
    return [dict(r) for r in rows]
