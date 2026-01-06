from flask import Flask, request, jsonify, render_template, redirect, url_for
import sqlite3
import logging
from phase4_realtime_threat_intel_scan import scan_url

app = Flask(__name__)
app.secret_key = "supersecretkey"  # required for sessions later
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
    data = request.get_json()
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
# REPORT URL (USER)
# =======================
@app.route("/report-url", methods=["POST"])
def report_url():
    data = request.get_json()
    url = data.get("url")

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO reports (url, comment)
        VALUES (?, 'Reported by user')
    """, (url,))
    conn.commit()
    conn.close()

    logging.warning(f"User reported URL: {url}")
    return jsonify({"status": "reported"})

# =======================
# ADMIN LOGIN (FIXED)
# =======================
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "GET":
        return render_template("admin_login.html")

    data = request.get_json(silent=True)

    if not data:
        return jsonify({"error": "Invalid request"}), 400

    username = data.get("username")
    password = data.get("password")

    if username == "admin" and password == "admin123":
        logging.info("Admin logged in")
        return jsonify({"redirect": "/admin/dashboard"})

    return jsonify({"message": "Invalid credentials"}), 401

# =======================
# ADMIN DASHBOARD
# =======================
@app.route("/admin/dashboard")
def admin_dashboard():
    return render_template("admin_dashboard.html")

# =======================
# ADMIN SCANS
# =======================
@app.route("/admin/scans")
def admin_scans():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT url, verdict, source, ml_risk, timestamp
        FROM scans
        ORDER BY timestamp DESC
    """)
    rows = cursor.fetchall()
    conn.close()

    return jsonify([
        {
            "url": r[0],
            "verdict": r[1],
            "source": r[2],
            "ml_risk": r[3],
            "timestamp": r[4]
        }
        for r in rows
    ])

# =======================
# ADMIN REPORTS
# =======================
@app.route("/admin/reports")
def admin_reports():
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
# ADMIN APPROVE / REJECT
# =======================
@app.route("/admin/approve", methods=["POST"])
def approve_report():
    data = request.get_json()
    report_id = data.get("report_id")
    status = data.get("status")

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute(
        "UPDATE reports SET status=? WHERE id=?",
        (status, report_id)
    )

    if status == "approved":
        cursor.execute("""
            INSERT OR IGNORE INTO internal_threats (url, source)
            SELECT url, 'User Report'
            FROM reports WHERE id=?
        """, (report_id,))

    conn.commit()
    conn.close()

    logging.warning(f"Admin updated report {report_id} → {status}")
    return jsonify({"status": status})

# =======================
# RUN SERVER (RENDER SAFE)
# =======================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
