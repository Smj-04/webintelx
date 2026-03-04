import pandas as pd
import tldextract
import Levenshtein
import os

# Load dataset
file_path = "data/raw/PhiUSIIL_Phishing_URL_Dataset.csv"
raw_df = pd.read_csv(file_path)

print("✅ Original Dataset Shape:", raw_df.shape)

# Show columns
print("\n📌 Columns in Dataset:\n", raw_df.columns)

# Detect URL column automatically
possible_cols = ["URL", "url", "Url", "website", "domain"]
url_col = None
for col in possible_cols:
    if col in raw_df.columns:
        url_col = col
        break

if url_col is None:
    raise Exception("❌ URL column not found in RAW dataset!")

print(f"✅ Using URL column: {url_col}")

# Load brand list (from data/brands.txt if present)
def load_brands():
    path = "data/brands.txt"
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return [b.strip().lower() for b in f.readlines() if b.strip()]
    # fallback list
    return [
        "google", "facebook", "paypal", "amazon", "apple", "microsoft",
        "netflix", "instagram", "twitter", "linkedin", "whatsapp",
        "bank", "sbi", "hdfc", "icici", "axis", "phonepe", "paytm"
    ]

BRANDS = load_brands()

# helpers
def get_domain(url):
    try:
        ext = tldextract.extract(url)
        return ext.domain.lower()
    except:
        return ""

def brand_similarity(domain):
    if not domain:
        return 0.0
    max_score = 0.0
    for brand in BRANDS:
        try:
            score = Levenshtein.ratio(domain, brand)
        except:
            score = 0.0
        if score > max_score:
            max_score = score
    return float(max_score)

print("\n⚙️ Calculating BrandSimilarity for all URLs...")

# compute domain and similarity
raw_df["DomainName"] = raw_df[url_col].apply(get_domain)
raw_df["BrandSimilarity"] = raw_df["DomainName"].apply(brand_similarity)

# Drop non-numeric & unnecessary columns (not useful for ML)
drop_columns = ["FILENAME", url_col, "Domain", "Title", "DomainName"]
df = raw_df.drop(columns=drop_columns, errors="ignore")

print("\n✅ After Dropping Columns Shape:", df.shape)

# Check missing values
print("\n📌 Missing Values:\n", df.isnull().sum())

# Fill missing values with 0
df = df.fillna(0)

# Save cleaned dataset
output_path = "data/processed/cleaned_phishing.csv"
df.to_csv(output_path, index=False)

print("\n✅ Cleaned Dataset Saved Successfully!")
print("📁 Location:", output_path)
