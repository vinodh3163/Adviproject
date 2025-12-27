from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
from functools import wraps

app = Flask(__name__)
app.secret_key = "advi-secret-key"

# ===============================
# DATABASE (Render safe)
# ===============================
DB_PATH = os.path.join("/tmp", "users.db")

def get_db():
    return sqlite3.connect(DB_PATH)

def init_db():
    conn = get_db()
    c = conn.cursor()

    # Create table
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    # Create default user ONLY if not exists
    c.execute("SELECT * FROM users WHERE email = ?", ("likithacloud@gmail.com",))
    if not c.fetchone():
        c.execute(
            "INSERT INTO users (email, password) VALUES (?, ?)",
            (
                "likithacloud@gmail.com",
                generate_password_hash("advi##123")
            )
        )
        conn.commit()

    conn.close()

init_db()

# ===============================
# LOGIN REQUIRED
# ===============================
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

# ===============================
# ROUTES
# ===============================

@app.route("/")
def home():
    return redirect(url_for("login"))

# ---------- LOGIN ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            session["user_id"] = user[0]
            session["email"] = user[1]
            flash("Login successful", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid email or password", "error")

    return render_template("login.html")

# ---------- DASHBOARD ----------
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", email=session["email"])

# ---------- LOGOUT ----------
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)
