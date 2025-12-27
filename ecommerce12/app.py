from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import subprocess
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'

# ===============================
# KUBERNETES CONFIG
# ⚠️ kubectl will NOT work on Render
# ===============================
POD_NAME = "mypod"
DATA_PATH = "/opt/ecommerce_project"

# ===============================
# DATABASE CONFIG (RENDER SAFE)
# ===============================
DB_PATH = os.path.join("/tmp", "users.db")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

init_db()

# ===============================
# LOGIN REQUIRED DECORATOR
# ===============================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ===============================
# ROUTES
# ===============================

@app.route('/')
def index():
    return render_template('index.html')

# ---------- LOGIN ----------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE email = ?', (email,)
        ).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password', 'error')

    return render_template('login.html')

# ---------- REGISTER ----------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('register.html')

        hashed_password = generate_password_hash(password)

        try:
            conn = get_db_connection()
            conn.execute(
                'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                (username, email, hashed_password)
            )
            conn.commit()
            conn.close()

            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))

        except sqlite3.IntegrityError:
            flash('Username or email already exists', 'error')

    return render_template('register.html')

# ---------- DASHBOARD ----------
@app.route('/dashboard')
@login_required
def dashboard():

    # ⚠️ kubectl DOES NOT WORK on Render
    # So we safely handle failures

    try:
        status_cmd = subprocess.check_output(
            ["kubectl", "get", "pod", POD_NAME, "-o", "jsonpath={.status.phase}"],
            stderr=subprocess.STDOUT,
            timeout=2
        )
        pod_status = status_cmd.decode().strip()
    except Exception:
        pod_status = "Kubernetes not available on Render"

    try:
        files_cmd = subprocess.check_output(
            ["kubectl", "exec", POD_NAME, "--", "ls", DATA_PATH],
            stderr=subprocess.STDOUT,
            timeout=2
        )
        files = files_cmd.decode().split()
    except Exception:
        files = []

    return render_template(
        'dashboard.html',
        username=session.get('username'),
        pod_name=POD_NAME,
        pod_status=pod_status,
        files=files
    )

# ---------- LOGOUT ----------
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'success')
    return redirect(url_for('index'))

# ===============================
# RUN APP (LOCAL ONLY)
# ===============================
if __name__ == '__main__':
    app.run(debug=True)
