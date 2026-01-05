import pandas as pd
import re
from urllib.parse import urlparse

# ==========================================
# PHASE 2 – FEATURE ENGINEERING (SAFE VERSION)
# ==========================================

# Load cleaned dataset from Phase 1
df = pd.read_csv("data/processed/clean_phishing_urls.csv")

print("Sample data:")
print(df.head())

# -------------------------------------------------
# Helper functions
# -------------------------------------------------
def normalize_url(url):
    if not url.startswith(('http://', 'https://')):
        return 'http://' + url
    return url

def extract_domain(url):
    url = normalize_url(url)
    return urlparse(url).netloc

# -------------------------------------------------
# Feature 1: URL Length
# -------------------------------------------------
df['url_length'] = df['url'].apply(len)

# -------------------------------------------------
# Feature 2: Special Character Count
# -------------------------------------------------
df['special_char_count'] = df['url'].apply(
    lambda x: len(re.findall(r'[@\-?=]', x))
)

# -------------------------------------------------
# Feature 3: Dot Count
# -------------------------------------------------
df['dot_count'] = df['url'].apply(lambda x: x.count('.'))

# -------------------------------------------------
# Feature 4: HTTPS Presence
# -------------------------------------------------
df['has_https'] = df['url'].apply(
    lambda x: 1 if x.lower().startswith('https') else 0
)

# -------------------------------------------------
# Feature 5: IP Address in URL
# -------------------------------------------------
def has_ip(url):
    return 1 if re.search(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', url) else 0

df['has_ip'] = df['url'].apply(has_ip)

# -------------------------------------------------
# Feature 6: Subdomain Count (SAFE)
# -------------------------------------------------
def count_subdomains(url):
    try:
        domain = extract_domain(url)
        return domain.count('.') - 1 if domain else 0
    except:
        return 0

df['subdomain_count'] = df['url'].apply(count_subdomains)

# -------------------------------------------------
# SAFE DOMAIN-BASED PLACEHOLDER FEATURES
# (No WHOIS / DNS network calls)
# -------------------------------------------------

# Feature 7: Domain Age (Placeholder)
df['domain_age_days'] = 0

# Feature 8: Domain Expiry Days (Placeholder)
df['domain_expiry_days'] = 0

# Feature 9: Registrar (Placeholder)
df['registrar'] = "Unknown"

# Feature 10: DNS Record Existence (Placeholder)
df['has_dns'] = 0

# -------------------------------------------------
# Review final feature set
# -------------------------------------------------
print("\nFinal feature columns:")
print(df.columns)

print("\nSample feature rows:")
print(df.head())

# -------------------------------------------------
# Save Phase 2 output
# -------------------------------------------------
df.to_csv("data/processed/phishing_features_phase2.csv", index=False)
print("\nPhase 2 SAFE feature dataset saved successfully!")


print(df[['url',
          'url_length',
          'special_char_count',
          'dot_count',
          'has_https',
          'has_ip',
          'subdomain_count']].head())
