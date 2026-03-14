"""
Intentionally vulnerable Flask application for demonstration purposes.

DO NOT deploy this code. It contains deliberate security vulnerabilities
to demonstrate ai-sec-scan's detection capabilities.
"""

import os
import sqlite3
import subprocess

from flask import Flask, redirect, request, send_file

app = Flask(__name__)

# VULNERABILITY: Hardcoded secret key (CWE-798)
SECRET_KEY = "super_secret_key_12345"
DATABASE_PASSWORD = "admin123"
API_TOKEN = "sk-proj-abc123def456ghi789"


def get_db():
    """Get database connection."""
    return sqlite3.connect("app.db")


@app.route("/login", methods=["POST"])
def login():
    """VULNERABILITY: SQL Injection (CWE-89)."""
    username = request.form["username"]
    password = request.form["password"]

    db = get_db()
    # BAD: Direct string interpolation in SQL query
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    result = db.execute(query).fetchone()

    if result:
        return "Login successful"
    return "Invalid credentials", 401


@app.route("/search")
def search():
    """VULNERABILITY: Cross-Site Scripting / XSS (CWE-79)."""
    query = request.args.get("q", "")
    # BAD: User input rendered directly in HTML without escaping
    return f"<html><body><h1>Search results for: {query}</h1></body></html>"


@app.route("/file")
def get_file():
    """VULNERABILITY: Path Traversal (CWE-22)."""
    filename = request.args.get("name", "")
    # BAD: No validation allows ../../etc/passwd
    file_path = os.path.join("/var/data", filename)
    return send_file(file_path)


@app.route("/ping")
def ping():
    """VULNERABILITY: Command Injection (CWE-78)."""
    host = request.args.get("host", "localhost")
    # BAD: Shell injection through user-controlled input
    result = subprocess.run(
        f"ping -c 1 {host}",
        shell=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


@app.route("/redirect")
def open_redirect():
    """VULNERABILITY: Open Redirect (CWE-601)."""
    url = request.args.get("url", "/")
    # BAD: No validation of redirect target
    return redirect(url)


@app.route("/debug")
def debug_info():
    """VULNERABILITY: Information Disclosure (CWE-200)."""
    return {
        "secret_key": SECRET_KEY,
        "database_password": DATABASE_PASSWORD,
        "env": dict(os.environ),
        "python_path": os.sys.path,
    }


if __name__ == "__main__":
    # VULNERABILITY: Debug mode enabled, binding to all interfaces
    app.run(debug=True, host="0.0.0.0")
