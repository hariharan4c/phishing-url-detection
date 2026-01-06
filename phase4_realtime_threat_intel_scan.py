import re
import os
import time
import socket
import ssl
import whois
import joblib
import pandas as pd
import requests
import sqlite3
from datetime import datetime
from urllib.parse import urlparse
from difflib import SequenceMatcher

# =========================
# CONFIG
# =========================

VT_API_KEY = os.getenv("VT_API_KEY")

if not VT_API_KEY:
    print("⚠️ VirusTotal API key NOT found. Using ML fallback if available.")
else:
    print("✅ VirusTotal API key loaded successfully.")

VT_TIMEOUT = 5
ML_THRESHOLD = 0.6
DB_FILE = "database.db"

# =========================
# LOAD ML MODEL (SAFE)
# =========================

model = None
MODEL_PATH = "models/phishing_model.pkl"

if os.path.exists(MODEL_PATH):
    try:
        model = joblib.load(MODEL_PATH)
        print("✅ ML model loaded")
    except Exception as e:
        print("⚠️ ML model failed to load:", e)
        model = None
else:
    print("ℹ️ ML model not present (cloud-safe mode)")

# =========================
# UTILS
# =========================

def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        return "http://" + url
    return url

# =========================
# INTERNAL THREAT DB
# =========================

def check_internal_threats(url):
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT 1 FROM internal_threats WHERE url = ?",
            (url,)
        )
        found = cursor.fetchone()
        conn.close()
        return found is not None
    except:
        return False

# =========================
# FEATURE EXTRACTION (ML)
# =========================

def extract_features(url):
    url_norm = normalize_url(url)
    domain = urlparse(url_norm).netloc

    return pd.DataFrame([{
        "url_length": len(url),
        "special_char_count": len(re.findall(r"[@?=-]", url)),
        "dot_count": url.count("."),
        "has_https": 1 if url_norm.startswith("https") else 0,
        "has_ip": 1 if re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", url) else 0,
        "subdomain_count": max(domain.count(".") - 1, 0),
        "domain_age_days": 0,
        "domain_expiry_days": 0,
        "has_dns": 0
    }])

# =========================
# DNS + WHOIS
# =========================

def dns_whois_analysis(url):
    domain_age_days = 0
    has_dns = 0

    try:
        domain = urlparse(normalize_url(url)).netloc
        try:
            socket.gethostbyname(domain)
            has_dns = 1
        except:
            has_dns = 0

        try:
            w = whois.whois(domain)
            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            if creation:
                domain_age_days = (datetime.now() - creation).days
        except:
            domain_age_days = 0
    except:
        pass

    return domain_age_days, has_dns

# =========================
# SSL CHECK
# =========================

def ssl_certificate_analysis(url):
    try:
        domain = urlparse(normalize_url(url)).netloc
        context = ssl.create_default_context()
        with context.wrap_socket(socket.socket(), server_hostname=domain) as sock:
            sock.settimeout(5)
            sock.connect((domain, 443))
            return 1, "Valid SSL"
    except:
        return 0, "Invalid SSL"

# =========================
# HOMOGRAPH
# =========================

def homograph_detection(url):
    popular = [
        "google.com", "paypal.com", "amazon.com",
        "facebook.com", "apple.com", "microsoft.com",
        "github.com"
    ]

    domain = urlparse(normalize_url(url)).netloc.lower().replace("www.", "")
    for legit in popular:
        score = SequenceMatcher(None, domain, legit).ratio()
        if 0.85 <= score < 1.0:
            return True, legit
    return False, None

# =========================
# PAGE CONTENT
# =========================

def page_content_analysis(url):
    keywords = ["login", "verify", "password", "urgent", "confirm", "account"]
    count = 0
    try:
        r = requests.get(normalize_url(url), timeout=5)
        text = r.text.lower()
        for k in keywords:
            count += text.count(k)
    except:
        pass
    return count

# =========================
# VIRUSTOTAL
# =========================

def submit_url_to_vt(url):
    if not VT_API_KEY:
        return None
    try:
        headers = {"x-apikey": VT_API_KEY}
        res = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=VT_TIMEOUT
        )
        if res.status_code == 200:
            return res.json()["data"]["id"]
    except:
        pass
    return None

def get_vt_result(analysis_id):
    try:
        headers = {"x-apikey": VT_API_KEY}
        res = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers,
            timeout=VT_TIMEOUT
        )
        stats = res.json()["data"]["attributes"]["stats"]
        if stats.get("malicious", 0) > 0:
            return "malicious"
        if stats.get("harmless", 0) > 0:
            return "clean"
    except:
        pass
    return "unknown"

# =========================
# FINAL SCAN ENGINE ✅
# =========================

def scan_url(url):
    print("🔵 Running secure scan...")

    # 1️⃣ Internal DB
    if check_internal_threats(url):
        return {
            "verdict": "KNOWN MALICIOUS",
            "source": "Internal DB",
            "ml_risk": None
        }

    # 2️⃣ VirusTotal
    vt_id = submit_url_to_vt(url)
    if vt_id:
        time.sleep(3)
        vt = get_vt_result(vt_id)
        if vt == "clean":
            return {
                "verdict": "KNOWN CLEAN",
                "source": "VirusTotal",
                "ml_risk": None
            }
        if vt == "malicious":
            return {
                "verdict": "KNOWN MALICIOUS",
                "source": "VirusTotal",
                "ml_risk": None
            }

    # 3️⃣ ML fallback (ONLY if model exists)
    if model is None:
        return {
            "verdict": "UNKNOWN",
            "source": "No ML / No VT",
            "ml_risk": None
        }

    features = extract_features(url)
    risk = model.predict_proba(features)[0][1]

    domain_age, has_dns = dns_whois_analysis(url)
    ssl_valid, _ = ssl_certificate_analysis(url)
    is_homo, _ = homograph_detection(url)
    suspicious_words = page_content_analysis(url)

    if domain_age < 30: risk += 0.15
    if has_dns == 0: risk += 0.15
    if ssl_valid == 0: risk += 0.15
    if is_homo: risk += 0.30
    if suspicious_words >= 3: risk += 0.20

    risk = min(risk, 1.0)

    if risk >= ML_THRESHOLD:
        return {
            "verdict": "HIGH RISK",
            "source": "ML",
            "ml_risk": round(risk, 2)
        }

    return {
        "verdict": "LOW RISK",
        "source": "ML",
        "ml_risk": round(risk, 2)
    }
