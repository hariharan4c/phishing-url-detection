import re
import time
import joblib
import pandas as pd
import requests
from urllib.parse import urlparse

# ==============================
# CONFIGURATION
# ==============================

VT_API_KEY = "PASTE_YOUR_VIRUSTOTAL_API_KEY_HERE"
VT_TIMEOUT = 5
ML_THRESHOLD = 0.6

# Load trained ML model
model = joblib.load("models/phishing_model.pkl")

# ==============================
# FEATURE EXTRACTION (SAFE)
# ==============================

def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        return "http://" + url
    return url

def extract_features(url):
    url_norm = normalize_url(url)
    domain = urlparse(url_norm).netloc

    features = {
        "url_length": len(url),
        "special_char_count": len(re.findall(r"[@\-?=]", url)),
        "dot_count": url.count("."),
        "has_https": 1 if url_norm.startswith("https") else 0,
        "has_ip": 1 if re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", url) else 0,
        "subdomain_count": domain.count(".") - 1 if domain else 0,
        "domain_age_days": 0,       # safe placeholder
        "domain_expiry_days": 0,    # safe placeholder
        "has_dns": 0                # safe placeholder
    }

    return pd.DataFrame([features])

# ==============================
# VIRUSTOTAL – STEP 1: SUBMIT URL
# ==============================

def submit_url_to_virustotal(url):
    try:
        headers = {"x-apikey": VT_API_KEY}
        data = {"url": url}

        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data=data,
            timeout=VT_TIMEOUT
        )

        if response.status_code == 200:
            return response.json()["data"]["id"]

        return None
    except:
        return None

# ==============================
# VIRUSTOTAL – STEP 2: GET RESULT
# ==============================

def get_vt_analysis(analysis_id):
    try:
        headers = {"x-apikey": VT_API_KEY}

        response = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers,
            timeout=VT_TIMEOUT
        )

        if response.status_code != 200:
            return "unknown"

        stats = response.json()["data"]["attributes"]["stats"]

        if stats.get("malicious", 0) > 0:
            return "malicious"

        if stats.get("suspicious", 0) > 0:
            return "suspicious"

        if stats.get("harmless", 0) > 0:
            return "clean"

        return "unknown"
    except:
        return "unknown"

# ==============================
# REAL-TIME SCAN LOGIC (FINAL)
# ==============================

def is_likely_legit_domain(url):
    url_norm = normalize_url(url)
    parsed = urlparse(url_norm)
    domain = parsed.netloc

    return (
        url_norm.startswith("https") and
        not re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", url) and
        domain.count(".") <= 2 and
        len(url) < 75
    )

def scan_url(url):
    print("\n🔍 Checking URL in real-time...")

    # 1️⃣ VirusTotal check
    analysis_id = submit_url_to_virustotal(url)

    if analysis_id:
        time.sleep(3)
        vt_result = get_vt_analysis(analysis_id)

        if vt_result == "malicious":
            return "🚨 MALICIOUS URL (VirusTotal Confirmed)"

        if vt_result == "clean":
            return "✅ LEGITIMATE URL (VirusTotal Verified)"

    # 2️⃣ ML fallback
    features_df = extract_features(url)
    risk_score = model.predict_proba(features_df)[0][1]

    # 3️⃣ Final heuristic correction
    if risk_score >= ML_THRESHOLD:
        if is_likely_legit_domain(url):
            return f"⚠️ SUSPICIOUS BUT LIKELY LEGIT (ML Risk: {risk_score:.2f})"
        return f"⚠️ SUSPICIOUS URL (ML Risk Score: {risk_score:.2f})"

    return f"✅ LEGITIMATE URL (ML Risk Score: {risk_score:.2f})"


# ==============================
# CLI ENTRY POINT
# ==============================

if __name__ == "__main__":
    user_url = input("Enter URL to scan: ").strip()
    result = scan_url(user_url)
    print(result)
