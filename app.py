from flask import Flask, request, jsonify, render_template, redirect, url_for, session
import sqlite3
import logging
from phase4_realtime_threat_intel_scan import scan_url

app = Flask(__name__)
app.secret_key = "supersecretkey"
DB_FILE = "database.db"

# =======================
# LOGGING
# =======================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

# =======================
# INIT DATABASE
# =======================
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT,
        verdict TEXT,
        source TEXT,
        ml_risk REAL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT,
        comment TEXT,
        status TEXT DEFAULT 'pending',
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS internal_threats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT UNIQUE,
        source TEXT
    )
    """)

    conn.commit()
    conn.close()

init_db()

# =======================
# HOME
# =======================
@app.route("/")
def home():
    return render_template("dashboard.html")

# =======================
# SCAN URL
# =======================
@app.route("/scan-url", methods=["POST"])
def scan():
    data = request.get_json(force=True)
    url = data.get("url")

    scan_result = scan_url(url)
    logging.info(f"Scanned URL: {url} | Verdict: {scan_result['verdict']}")

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO scans (url, verdict, source, ml_risk)
        VALUES (?, ?, ?, ?)
    """, (
        url,
        scan_result["verdict"],
        scan_result["source"],
        scan_result["ml_risk"]
    ))
    conn.commit()
    conn.close()

    return jsonify(scan_result)

# =======================
# REPORT URL
# =======================
@app.route("/report-url", methods=["POST"])
def report_url():
    data = request.get_json(force=True)
    url = data.get("url")

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO reports (url, comment) VALUES (?, ?)",
        (url, "Reported by user")
    )
    conn.commit()
    conn.close()

    return jsonify({"status": "reported"})

# =======================
# ADMIN LOGIN
# =======================
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "GET":
        return render_template("admin_login.html")

    data = request.get_json(force=True)
    username = data.get("username")
    password = data.get("password")

    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        session["admin_logged_in"] = True
        return jsonify({"redirect": "/admin/dashboard"})

    return jsonify({"error": "Invalid username or password"}), 401

# =======================
# ADMIN DASHBOARD
# =======================
@app.route("/admin/dashboard")
def admin_dashboard():
    if not session.get("admin_logged_in"):
        return redirect("/admin/login")

    return render_template("admin_dashboard.html")

# =======================
# ADMIN REPORTS
# =======================
@app.route("/admin/reports")
def admin_reports():
    if not session.get("admin_logged_in"):
        return jsonify({"error": "Unauthorized"}), 403

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, url, comment, status, timestamp
        FROM reports
        WHERE status='pending'
    """)
    rows = cursor.fetchall()
    conn.close()

    return jsonify([
        {
            "report_id": r[0],
            "url": r[1],
            "comment": r[2],
            "status": r[3],
            "timestamp": r[4]
        }
        for r in rows
    ])

# =======================
# RUN SERVER (RENDER SAFE)
# =======================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
