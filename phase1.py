import pandas as pd

df = pd.read_csv("data/raw/phishing_urls.csv")

# standardize column names
df.columns = df.columns.str.lower()

# remove missing URLs
df = df.dropna(subset=['url'])

# remove duplicate URLs
df = df.drop_duplicates(subset=['url'])

# label encoding
df['label'] = df['label'].map({
    'good': 0,
    'bad': 1
})

# verify
print(df['label'].value_counts())

# save cleaned dataset
df.to_csv("data/processed/clean_phishing_urls.csv", index=False)
print("Cleaned dataset saved successfully!")
