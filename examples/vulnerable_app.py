#!/usr/bin/env python3
"""
Vulnerable Flask application for testing TOTAL Analyzer.
DO NOT USE IN PRODUCTION – contains intentional security flaws.
"""

from flask import Flask, request
import sqlite3
import hashlib
import hmac

app = Flask(__name__)

# Fake database connection
def get_db():
    return sqlite3.connect(":memory:")

# ------------------------------------------------------------
# SQL Injection examples (should be detected by TOTAL Analyzer)
# ------------------------------------------------------------

@app.route("/user/fstring")
def user_fstring():
    """Vulnerable: f-string formatting"""
    user_id = request.args.get("id")
    db = get_db()
    cursor = db.cursor()
    # CRITICAL: tainted data directly in f-string
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return "ok"

@app.route("/user/concat")
def user_concat():
    """Vulnerable: string concatenation"""
    user_id = request.args.get("id")
    db = get_db()
    # CRITICAL: tainted data via '+'
    query = "SELECT * FROM users WHERE id = " + user_id
    db.execute(query)
    return "ok"

@app.route("/user/raw")
def user_raw():
    """Vulnerable: raw SQLAlchemy style"""
    user_id = request.args.get("id")
    db = get_db()
    # CRITICAL: .raw() sink
    db.raw(f"SELECT * FROM users WHERE id = {user_id}")
    return "ok"

@app.route("/user/executemany")
def user_executemany():
    """Vulnerable: executemany with tainted data"""
    user_ids = request.args.getlist("ids")
    db = get_db()
    # CRITICAL: executemany with tainted list element
    db.executemany("INSERT INTO logs VALUES (?)", [(x,) for x in user_ids])
    return "ok"

# ------------------------------------------------------------
# Safe patterns that should NOT trigger alerts
# ------------------------------------------------------------

@app.route("/user/safe")
def user_safe():
    """Safe: parameterized query"""
    user_id = request.args.get("id")
    db = get_db()
    # Should NOT be flagged because bindparam sanitizes
    db.execute("SELECT * FROM users WHERE id = :id", {"id": user_id})
    return "ok"

@app.route("/user/intcast")
def user_intcast():
    """Safe: int() sanitizer"""
    user_id = request.args.get("id")
    clean_id = int(user_id)
    db = get_db()
    db.execute(f"SELECT * FROM users WHERE id = {clean_id}")
    return "ok"

# ------------------------------------------------------------
# Crypto operations (Sentinel Guard will flag as software crypto)
# ------------------------------------------------------------

@app.route("/crypto/sign")
def crypto_sign():
    """Should trigger Sentinel Guard: software signing"""
    private_key = b"fake_key_123"
    message = request.args.get("msg").encode()
    # LOW severity: software crypto detected
    signature = hmac.new(private_key, message, hashlib.sha256).digest()
    return signature.hex()

@app.route("/crypto/encrypt")
def crypto_encrypt():
    """Should trigger Sentinel Guard: software encryption"""
    from cryptography.fernet import Fernet
    key = Fernet.generate_key()
    cipher = Fernet(key)
    data = request.args.get("data").encode()
    encrypted = cipher.encrypt(data)
    return encrypted.decode()

# ------------------------------------------------------------
# False positive test (should not alert)
# ------------------------------------------------------------

@app.route("/false/positive")
def false_positive():
    """Completely safe – no DB at all"""
    return "Hello, " + request.args.get("name")

if __name__ == "__main__":
    app.run(debug=False)  # debug=False for "production" test
