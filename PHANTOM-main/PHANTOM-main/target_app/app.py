"""
PHANTOM demo target — intentionally vulnerable Flask app.
Contains: SSTI, hardcoded secret, debug mode, SQL injection, command injection.
USE ONLY FOR DEMO. Never deploy this.
"""

from flask import Flask, request, render_template_string
import sqlite3
import os
import subprocess

app = Flask(__name__)
app.secret_key = "hardcoded_secret_12345"  # Bandit will flag this
app.debug = True                            # Bandit will flag this


@app.route("/")
def index():
    return """<h1>Demo App</h1>
    <p>Target for PHANTOM security assessment.</p>
    <ul>
        <li><a href="/render?template=Hello">/render</a> — Template rendering</li>
        <li><a href="/user?id=1">/user</a> — User lookup</li>
        <li><a href="/search?q=test">/search</a> — Search</li>
        <li><a href="/admin/ping?host=127.0.0.1">/admin/ping</a> — System ping</li>
        <li><a href="/health">/health</a> — Health check</li>
    </ul>"""


# Intentional SSTI vulnerability
@app.route("/render")
def render_page():
    template = request.args.get("template", "Hello World")
    return render_template_string(template)  # SSTI: user input as template


# Intentional SQL injection pattern
@app.route("/user")
def get_user():
    uid = request.args.get("id", "1")
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER, name TEXT)")
    cursor.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin')")
    query = f"SELECT * FROM users WHERE id = {uid}"  # SQLi
    try:
        cursor.execute(query)
        result = cursor.fetchall()
        return f"User: {result}"
    except Exception as e:
        return f"Error: {e}"


# Intentional XSS pattern
@app.route("/search")
def search():
    q = request.args.get("q", "")
    return f"<h1>Search results for: {q}</h1>"  # Reflected XSS


# Intentional command injection
@app.route("/admin/ping")
def admin_ping():
    host = request.args.get("host", "127.0.0.1")
    result = subprocess.getoutput(f"ping -c 1 {host}")  # Command injection
    return f"<pre>{result}</pre>"


@app.route("/health")
def health():
    return {"status": "ok", "debug": app.debug}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
