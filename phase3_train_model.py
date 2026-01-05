import re
import joblib
import pandas as pd
from urllib.parse import urlparse

# Load trained model
model = joblib.load("models/phishing_model.pkl")

# -----------------------------
# Trusted domain whitelist
# -----------------------------
TRUSTED_DOMAINS = [
    "google.com",
    "www.google.com",
    "gmail.com",
    "youtube.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "facebook.com",
    "github.com"
]

# -----------------------------
# Helper functions
# -----------------------------
def normalize_url(url):
    if not url.startswith(('http://', 'https://')):
        return 'http://' + url
    return url

def extract_features(url):
    url_norm = normalize_url(url)
    domain = urlparse(url_norm).netloc

    features = {
        'url_length': len(url),
        'special_char_count': len(re.findall(r'[@\-?=]', url)),
        'dot_count': url.count('.'),
        'has_https': 1 if url_norm.startswith('https') else 0,
        'has_ip': 1 if re.search(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', url) else 0,
        'subdomain_count': domain.count('.') - 1 if domain else 0,
        'domain_age_days': 0,        # safe placeholder
        'domain_expiry_days': 0,     # safe placeholder
        'has_dns': 0                 # safe placeholder
    }

    return pd.DataFrame([features])

# -----------------------------
# Real-time scan logic
# -----------------------------
def scan_url(url):
    domain = urlparse(normalize_url(url)).netloc

    # ✅ Whitelist check
    if domain in TRUSTED_DOMAINS:
        return "✅ LEGITIMATE URL (Trusted Domain)"

    features_df = extract_features(url)
    proba = model.predict_proba(features_df)[0][1]

    # Balanced threshold for demo & interview
    if proba >= 0.6:
        return f"🚨 PHISHING DETECTED (Risk Score: {proba:.2f})"
    else:
        return f"✅ LEGITIMATE URL (Risk Score: {proba:.2f})"

# -----------------------------
# Run from CLI
# -----------------------------
if __name__ == "__main__":
    url = input("Enter URL to scan: ")
    result = scan_url(url)
    print(result)
