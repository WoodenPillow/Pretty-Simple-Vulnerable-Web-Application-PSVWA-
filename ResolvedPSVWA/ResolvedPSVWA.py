from flask import Flask, request, render_template_string, session, redirect, url_for, abort
import sqlite3
import os
from datetime import datetime, timedelta
from secrets import token_hex
import bleach  # For sanitizing user input
from flask_bcrypt import Bcrypt  # For secure password hashing
from flask_limiter import Limiter  # For rate limiting
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.permanent_session_lifetime = timedelta(minutes=15)

# Initialize Bcrypt and Limiter
bcrypt = Bcrypt(app)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

BASE_STYLE = """
    <head>
        <title>Resolved PSVWA</title>
    </head>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f9f9f9; display: flex; }}
        .container {{ display: flex; width: 100%; }}
        .sidebar {{ width: 200px; padding: 10px; background-color: #e0e0e0; border-right: 1px solid #ccc; }}
        .sidebar a {{ display: block; padding: 8px; margin: 5px 0; background-color: #007bff; color: white; text-decoration: none; border-radius: 4px; text-align: center; }}
        .sidebar a:hover {{ background-color: #0056b3; }}
        .content {{ flex-grow: 1; padding: 20px; }}
        h1 {{ color: #444; text-align: center; }}
        .nav-center {{ text-align: center; margin: 20px 0; }}
        .nav-center a {{ margin: 0 15px; color: #007bff; text-decoration: none; font-weight: bold; }}
        .nav-center a:hover {{ text-decoration: underline; }}
        form {{ margin: 20px auto; max-width: 400px; }}
        input, textarea {{ width: 100%; padding: 8px; margin: 5px 0; box-sizing: border-box; }}
        input[type="submit"] {{ background-color: #007bff; color: white; border: none; padding: 10px; cursor: pointer; }}
        input[type="submit"]:hover {{ background-color: #0056b3; }}
        ul {{ list-style: none; padding: 0; max-width: 400px; margin: 20px auto; }}
        li {{ background-color: white; padding: 10px; margin: 5px 0; border: 1px solid #ddd; }}
        pre {{ background-color: #f0f0f0; padding: 10px; border: 1px solid #ddd; }}
        .error {{ color: red; text-align: center; }}
    </style>
"""

CONTAINER = BASE_STYLE + """
    <div class="container">
        <div class="sidebar">
            <a href="/login">Login</a>
            <a href="/logout">Logout</a>
            <a href="/profile">Profile</a>
        </div>
        <div class="content">
            {content}
            <div class="nav-center">
                <a href="/">Home</a>
                {extra_nav}
            </div>
        </div>
    </div>
"""

# Database setup
def init_db():
    conn = sqlite3.connect("vuln_app.db")
    c = conn.cursor()
    c.execute("DROP TABLE IF EXISTS users")
    c.execute("DROP TABLE IF EXISTS tickets")
    c.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT DEFAULT 'user')")
    c.execute("CREATE TABLE tickets (id INTEGER PRIMARY KEY, user_id INTEGER, content TEXT, created_at TEXT)")
    # Hash passwords using bcrypt
    admin_password = bcrypt.generate_password_hash("admin123").decode('utf-8')
    user_password = bcrypt.generate_password_hash("user123").decode('utf-8')
    c.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)",
              ("admin", admin_password, "admin"))
    c.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)",
              ("user", user_password))
    conn.commit()
    conn.close()

# Security decorators for login and admin access
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "logged_in" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "role" not in session or session["role"] != "admin":
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

# CSRF token management
def generate_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = token_hex(16)
    return session["csrf_token"]

def validate_csrf_token(token):
    return token == session.get("csrf_token")

# Routes
@app.route("/")
def home():
    content = """
        <h1>Pretty Simple Vulnerable Web Application (PSVWA)</h1>
        <h1>By TP068579</h1>
        <p style="text-align: center;">Welcome, {{ session.get('username', 'Guest') }}</p>
        <div class="nav-center">
            <a href="/tickets">Tickets</a>
            <a href="/search">Search</a>
            {% if session.get('role') == 'admin' %}
            <a href="/commands">Commands</a>
            {% endif %}
        </div>
    """
    return render_template_string(CONTAINER.format(content=content, extra_nav=""))

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5/minute")  # Rate limiting for login attempts
def login():
    if request.method == "POST":
        username = bleach.clean(request.form["username"])
        with sqlite3.connect("vuln_app.db") as conn:
            c = conn.cursor()
            c.execute("SELECT id, role, username, password FROM users WHERE username = ?", (username,))
            user = c.fetchone()
            if user and bcrypt.check_password_hash(user[3], request.form["password"]):
                session.clear()  # Regenerate session ID
                session.permanent = True
                session["logged_in"] = True
                session["user_id"] = user[0]
                session["role"] = user[1]
                session["username"] = user[2]
                return redirect(url_for("home"))
        content = '<h1>Login</h1><p class="error">Login failed</p>' + LOGIN_FORM
    else:
        content = "<h1>Login</h1>" + LOGIN_FORM
    return render_template_string(CONTAINER.format(content=content, extra_nav=""))

LOGIN_FORM = """
    <form method="POST">
        <input name="username" placeholder="Username" required>
        <input name="password" type="password" placeholder="Password" required>
        <input type="submit" value="Login">
    </form>
"""

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

@app.route("/tickets", methods=["GET", "POST"])
@login_required
def tickets():
    with sqlite3.connect("vuln_app.db") as conn:
        c = conn.cursor()
        if request.method == "POST":
            content_clean = bleach.clean(request.form["content"], tags=["p", "br"], attributes={})
            c.execute("INSERT INTO tickets (user_id, content, created_at) VALUES (?, ?, ?)",
                      (session["user_id"], content_clean, datetime.now().isoformat()))
            conn.commit()
        c.execute("SELECT content FROM tickets")
        tickets = c.fetchall()
    content = """
        <h1>Tickets</h1>
        <ul>{% for ticket in tickets %}<li>{{ ticket[0] }}</li>{% endfor %}</ul>
        <form method="POST">
            <textarea name="content" placeholder="Post a ticket"></textarea>
            <input type="submit" value="Submit">
        </form>
    """
    return render_template_string(CONTAINER.format(content=content, extra_nav=""), tickets=tickets)

@app.route("/search", methods=["GET", "POST"])
def search():
    with sqlite3.connect("vuln_app.db") as conn:
        c = conn.cursor()
        if request.method == "POST":
            term = bleach.clean(request.form["term"])
            c.execute("SELECT username FROM users WHERE username LIKE ?", (f"%{term}%",))
            results = c.fetchall()
            content = """
                <h1>Search Results</h1>
                <ul>{% for result in results %}<li>{{ result[0] }}</li>{% endfor %}</ul>
            """
            return render_template_string(CONTAINER.format(content=content, extra_nav='<a href="/search">Back</a>'), results=results)
        content = """
            <h1>Search Users</h1>
            <form method="POST">
                <input name="term" placeholder="Search usernames">
                <input type="submit" value="Search">
            </form>
        """
    return render_template_string(CONTAINER.format(content=content, extra_nav=""))

@app.route("/commands", methods=["GET", "POST"])
@login_required
@admin_required
def commands():
    if request.method == "POST":
        command_input = bleach.clean(request.form["command"])
        result = "Command execution is disabled for security reasons."
        content = '<h1>Command Output</h1><pre>{{ result }}</pre>'
        return render_template_string(CONTAINER.format(content=content, extra_nav='<a href="/commands">Back</a>'), result=result)
    content = """
        <h1>Run Commands (Admin)</h1>
        <form method="POST">
            <input name="command" placeholder="Enter command (Disabled)">
            <input type="submit" value="Run">
        </form>
    """
    return render_template_string(CONTAINER.format(content=content, extra_nav=""))

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    with sqlite3.connect("vuln_app.db") as conn:
        c = conn.cursor()
        csrf_token = generate_csrf_token()
        if request.method == "POST":
            if not validate_csrf_token(request.form["csrf_token"]):
                abort(403)
            new_password = request.form["password"]
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            c.execute("UPDATE users SET password = ? WHERE id = ?", (hashed_password, session["user_id"]))
            conn.commit()
        c.execute("SELECT username FROM users WHERE id = ?", (session["user_id"],))
        user = c.fetchone()
    content = """
        <h1>Profile</h1>
        <p>Username: {{ user[0] }}</p>
        <p>Password: Set</p>
        <form method="POST">
            <input name="password" type="password" placeholder="New Password" required>
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <input type="submit" value="Update">
        </form>
    """
    return render_template_string(CONTAINER.format(content=content, extra_nav=""), user=user, csrf_token=csrf_token)

if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5888, debug=True)  # Set debug=False in production