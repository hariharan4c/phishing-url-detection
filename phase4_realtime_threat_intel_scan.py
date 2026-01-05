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
    print("⚠️ VirusTotal API key NOT found. Using ML fallback.")
else:
    print("✅ VirusTotal API key loaded successfully.")



VT_TIMEOUT = 5
ML_THRESHOLD = 0.6
DB_FILE = "database.db"

model = joblib.load("models/phishing_model.pkl")

# =========================
# UTILS
# =========================

def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        return "http://" + url
    return url

# =========================
# 🔐 PHASE 8 — INTERNAL THREAT DB
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
# PHASE 5.1 — DNS & WHOIS
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
# PHASE 5.2 — SSL
# =========================

def ssl_certificate_analysis(url):
    try:
        domain = urlparse(normalize_url(url)).netloc
        context = ssl.create_default_context()

        with context.wrap_socket(socket.socket(), server_hostname=domain) as sock:
            sock.settimeout(5)
            sock.connect((domain, 443))
            cert = sock.getpeercert()
            issuer = dict(x[0] for x in cert.get("issuer", []))
            return 1, issuer.get("organizationName", "Unknown")

    except:
        return 0, "Invalid SSL"

# =========================
# PHASE 5.3 — HOMOGRAPH
# =========================

def homograph_detection(url):
    popular_domains = [
        "google.com", "paypal.com", "amazon.com",
        "facebook.com", "apple.com", "microsoft.com",
        "flipkart.com", "github.com"
    ]

    domain = urlparse(normalize_url(url)).netloc.lower().replace("www.", "")

    for legit in popular_domains:
        score = SequenceMatcher(None, domain, legit).ratio()
        if 0.85 <= score < 1.0:
            return True, legit

    return False, None

# =========================
# PHASE 5.4 — CONTENT
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
# PHASE 4 — VIRUSTOTAL
# =========================

def submit_url_to_vt(url):
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
    print("\n🔵 Running Phase 4 + Phase 5 + Phase 8 Scan...")

    # 🔐 INTERNAL THREAT DB CHECK (FIRST)
    if check_internal_threats(url):
        return {
            "verdict": "KNOWN MALICIOUS",
            "source": "Internal Threat DB",
            "ml_risk": None
        }

    # 🌐 VIRUSTOTAL CHECK
    vt_id = submit_url_to_vt(url)
    if vt_id:
        time.sleep(3)
        vt_result = get_vt_result(vt_id)

        if vt_result == "clean":
            return {
                "verdict": "KNOWN CLEAN",
                "source": "VirusTotal",
                "ml_risk": None
            }

        if vt_result == "malicious":
            return {
                "verdict": "KNOWN MALICIOUS",
                "source": "VirusTotal",
                "ml_risk": None
            }

    # 🤖 ML FALLBACK
    features = extract_features(url)
    risk = model.predict_proba(features)[0][1]

    domain_age, has_dns = dns_whois_analysis(url)
    ssl_valid, _ = ssl_certificate_analysis(url)
    is_homo, brand = homograph_detection(url)
    suspicious_words = page_content_analysis(url)

    if domain_age < 30:
        risk += 0.15
    if has_dns == 0:
        risk += 0.15
    if ssl_valid == 0:
        risk += 0.15
    if is_homo:
        risk += 0.30
    if suspicious_words >= 3:
        risk += 0.20

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
