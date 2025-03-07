from flask import Flask, request, render_template_string, session, redirect, url_for
import sqlite3
import os
from datetime import datetime
from secrets import token_hex  # For CSRF tokens

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Your CSS, unchanged
BASE_STYLE = """
    <head>
        <title>Resolved PSVWA</title>
    </head>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f9f9f9; display: flex; }
        .container { display: flex; width: 100%; }
        .sidebar { width: 200px; padding: 10px; background-color: #e0e0e0; border-right: 1px solid #ccc; }
        .sidebar a { display: block; padding: 8px; margin: 5px 0; background-color: #007bff; color: white; text-decoration: none; border-radius: 4px; text-align: center; }
        .sidebar a:hover { background-color: #0056b3; }
        .content { flex-grow: 1; padding: 20px; }
        h1 { color: #444; text-align: center; }
        .nav-center { text-align: center; margin: 20px 0; }
        .nav-center a { margin: 0 15px; color: #007bff; text-decoration: none; font-weight: bold; }
        .nav-center a:hover { text-decoration: underline; }
        form { margin: 20px auto; max-width: 400px; }
        input, textarea { width: 100%; padding: 8px; margin: 5px 0; box-sizing: border-box; }
        input[type="submit"] { background-color: #007bff; color: white; border: none; padding: 10px; cursor: pointer; }
        input[type="submit"]:hover { background-color: #0056b3; }
        ul { list-style: none; padding: 0; max-width: 400px; margin: 20px auto; }
        li { background-color: white; padding: 10px; margin: 5px 0; border: 1px solid #ddd; }
        pre { background-color: #f0f0f0; padding: 10px; border: 1px solid #ddd; }
        .error { color: red; text-align: center; }
    </style>
"""

# Your database setup with updated users
def init_db():
    conn = sqlite3.connect("vuln_app.db")
    c = conn.cursor()
    c.execute("DROP TABLE IF EXISTS users")
    c.execute("DROP TABLE IF EXISTS tickets")
    c.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT DEFAULT 'user')")
    c.execute("CREATE TABLE tickets (id INTEGER PRIMARY KEY, user_id INTEGER, content TEXT, created_at TEXT)")
    c.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)", ("admin", "admin123", "admin"))
    c.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", ("user", "user123"))
    conn.commit()
    conn.close()

# CSRF token functions
def generate_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = token_hex(16)
    return session["csrf_token"]

def validate_csrf_token(token):
    return token == session.get("csrf_token")

# Your home page with custom title
@app.route("/")
def home():
    return render_template_string(BASE_STYLE + """
        <div class="container">
            <div class="sidebar">
                <a href="/login">Login</a>
                <a href="/logout">Logout</a>
                <a href="/profile">Profile</a>
            </div>
            <div class="content">
                <h1>Pretty Simple Vulnerable Web Application (PSVWA)</h1>
                <h1>By TP068579</h1>
                <p style="text-align: center;">Welcome, {{ session.get('username', 'Guest') }}</p>
                <div class="nav-center">
                    <a href="/tickets">Tickets</a>
                    <a href="/search">Search</a>
                    <a href="/commands">Commands</a>
                </div>
            </div>
        </div>
    """)

# Your login with failed login message
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        conn = sqlite3.connect("vuln_app.db")
        c = conn.cursor()
        c.execute("SELECT id, role, username FROM users WHERE username = ? AND password = ?", (username, password))
        user = c.fetchone()
        if user:
            session["logged_in"] = True
            session["user_id"] = user[0]
            session["role"] = user[1]
            session["username"] = user[2]
            conn.close()
            return redirect(url_for("home"))
        conn.close()
        return render_template_string(BASE_STYLE + """
            <div class="container">
                <div class="sidebar">
                    <a href="/login">Login</a>
                    <a href="/logout">Logout</a>
                    <a href="/profile">Profile</a>
                </div>
                <div class="content">
                    <h1>Login</h1>
                    <p class="error">Login failed</p>
                    <form method="POST">
                        <input name="username" placeholder="Username" required>
                        <input name="password" type="password" placeholder="Password" required>
                        <input type="submit" value="Login">
                    </form>
                    <div class="nav-center">
                        <a href="/">Home</a>
                    </div>
                </div>
            </div>
        """)
    return render_template_string(BASE_STYLE + """
        <div class="container">
            <div class="sidebar">
                <a href="/login">Login</a>
                <a href="/logout">Logout</a>
                <a href="/profile">Profile</a>
            </div>
            <div class="content">
                <h1>Login</h1>
                <form method="POST">
                    <input name="username" placeholder="Username" required>
                    <input name="password" type="password" placeholder="Password" required>
                    <input type="submit" value="Login">
                </form>
                <div class="nav-center">
                    <a href="/">Home</a>
                </div>
            </div>
        </div>
    """)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

# 1. XSS Fixed - Tickets
@app.route("/tickets", methods=["GET", "POST"])
def tickets():
    conn = sqlite3.connect("vuln_app.db")
    c = conn.cursor()
    if request.method == "POST" and "logged_in" in session:
        content = request.form["content"]
        c.execute("INSERT INTO tickets (user_id, content, created_at) VALUES (?, ?, ?)",
                  (session["user_id"], content, datetime.now().isoformat()))
        conn.commit()
    c.execute("SELECT content FROM tickets")
    tickets = c.fetchall()
    conn.close()
    return render_template_string(BASE_STYLE + """
        <div class="container">
            <div class="sidebar">
                <a href="/login">Login</a>
                <a href="/logout">Logout</a>
                <a href="/profile">Profile</a>
            </div>
            <div class="content">
                <h1>Tickets</h1>
                <ul>{% for ticket in tickets %}<li>{{ ticket[0] }}</li>{% endfor %}</ul>
                {% if session.logged_in %}
                <form method="POST">
                    <textarea name="content" placeholder="Post a ticket"></textarea>
                    <input type="submit" value="Submit">
                </form>
                {% endif %}
                <div class="nav-center">
                    <a href="/">Home</a>
                </div>
            </div>
        </div>
    """, tickets=tickets)

# 2. SQL Injection Fixed - Search
@app.route("/search", methods=["GET", "POST"])
def search():
    conn = sqlite3.connect("vuln_app.db")
    c = conn.cursor()
    if request.method == "POST":
        term = request.form["term"]
        c.execute("SELECT username FROM users WHERE username LIKE ?", (f"%{term}%",))
        results = c.fetchall()
        conn.close()
        return render_template_string(BASE_STYLE + """
            <div class="container">
                <div class="sidebar">
                    <a href="/login">Login</a>
                    <a href="/logout">Logout</a>
                    <a href="/profile">Profile</a>
                </div>
                <div class="content">
                    <h1>Search Results</h1>
                    <ul>{% for result in results %}<li>{{ result[0] }}</li>{% endfor %}</ul>
                    <div class="nav-center">
                        <a href="/search">Back</a>
                        <a href="/">Home</a>
                    </div>
                </div>
            </div>
        """, results=results)
    conn.close()
    return render_template_string(BASE_STYLE + """
        <div class="container">
            <div class="sidebar">
                <a href="/login">Login</a>
                <a href="/logout">Logout</a>
                <a href="/profile">Profile</a>
            </div>
            <div class="content">
                <h1>Search Users</h1>
                <form method="POST">
                    <input name="term" placeholder="Search usernames">
                    <input type="submit" value="Search">
                </form>
                <div class="nav-center">
                    <a href="/">Home</a>
                </div>
            </div>
        </div>
    """)

# 3. Command Injection Fixed - Denies All Commands, No Result
@app.route("/commands", methods=["GET", "POST"])
def commands():
    if "logged_in" not in session or session["role"] != "admin":
        return "Admin access required", 403
    if request.method == "POST":
        command = request.form["command"]
        # Fixed: Accept input but deny execution, return empty result
        result = ""  # No command is executed, no output
        return render_template_string(BASE_STYLE + """
            <div class="container">
                <div class="sidebar">
                    <a href="/login">Login</a>
                    <a href="/logout">Logout</a>
                    <a href="/profile">Profile</a>
                </div>
                <div class="content">
                    <h1>Command Output</h1>
                    <pre>{{ result }}</pre>
                    <div class="nav-center">
                        <a href="/commands">Back</a>
                        <a href="/">Home</a>
                    </div>
                </div>
            </div>
        """, result=result)
    return render_template_string(BASE_STYLE + """
        <div class="container">
            <div class="sidebar">
                <a href="/login">Login</a>
                <a href="/logout">Logout</a>
                <a href="/profile">Profile</a>
            </div>
            <div class="content">
                <h1>Run Commands (Admin)</h1>
                <form method="POST">
                    <input name="command" placeholder="Enter command (All denied)">
                    <input type="submit" value="Run">
                </form>
                <div class="nav-center">
                    <a href="/">Home</a>
                </div>
            </div>
        </div>
    """)

# 4. CSRF Fixed - Profile
@app.route("/profile", methods=["GET", "POST"])
def profile():
    if "logged_in" not in session:
        return redirect(url_for("login"))
    conn = sqlite3.connect("vuln_app.db")
    c = conn.cursor()
    csrf_token = generate_csrf_token()
    if request.method == "POST":
        if not validate_csrf_token(request.form["csrf_token"]):
            return "CSRF validation failed", 403
        password = request.form["password"]
        c.execute("UPDATE users SET password = ? WHERE id = ?", (password, session["user_id"]))
        conn.commit()
    c.execute("SELECT username, password FROM users WHERE id = ?", (session["user_id"],))
    user = c.fetchone()
    conn.close()
    return render_template_string(BASE_STYLE + """
        <div class="container">
            <div class="sidebar">
                <a href="/login">Login</a>
                <a href="/logout">Logout</a>
                <a href="/profile">Profile</a>
            </div>
            <div class="content">
                <h1>Profile</h1>
                <p>Username: {{ user[0] }}</p>
                <p>Password: {{ user[1] }}</p>
                <form method="POST">
                    <input name="password" type="password" placeholder="New Password" required>
                    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                    <input type="submit" value="Update">
                </form>
                <div class="nav-center">
                    <a href="/">Home</a>
                </div>
            </div>
        </div>
    """, user=user, csrf_token=csrf_token)

if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5888, debug=True)