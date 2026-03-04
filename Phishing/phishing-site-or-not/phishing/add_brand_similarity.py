import pandas as pd
import tldextract
import Levenshtein

print("📥 Loading RAW dataset...")

RAW_PATH = "data/raw/PhiUSIIL_Phishing_URL_Dataset.csv"
CLEAN_PATH = "data/processed/cleaned_phishing.csv"

raw_df = pd.read_csv(RAW_PATH)
clean_df = pd.read_csv(CLEAN_PATH)

print("📊 RAW columns:", raw_df.columns.tolist())

# ✅ Detect URL column automatically
possible_cols = ["URL", "url", "Url", "website", "domain"]

url_col = None
for col in possible_cols:
    if col in raw_df.columns:
        url_col = col
        break

if url_col is None:
    raise Exception("❌ URL column not found in RAW dataset!")

print(f"✅ Using URL column: {url_col}")

# ==========================
# Brand List
# ==========================
brands = [
    "google", "facebook", "paypal", "amazon", "apple", "microsoft",
    "netflix", "instagram", "twitter", "linkedin", "whatsapp",
    "bank", "sbi", "hdfc", "icici", "axis", "phonepe", "paytm"
]

def get_domain(url):
    try:
        ext = tldextract.extract(url)
        return ext.domain.lower()
    except:
        return ""

def brand_similarity(domain):
    max_score = 0
    for brand in brands:
        score = Levenshtein.ratio(domain, brand)
        if score > max_score:
            max_score = score
    return max_score

print("⚙️ Calculating BrandSimilarity...")

raw_df["DomainName"] = raw_df[url_col].apply(get_domain)
raw_df["BrandSimilarity"] = raw_df["DomainName"].apply(brand_similarity)

# ✅ Add BrandSimilarity to cleaned dataset
clean_df["BrandSimilarity"] = raw_df["BrandSimilarity"]

OUTPUT_PATH = "data/processed/cleaned_phishing_with_brand.csv"
clean_df.to_csv(OUTPUT_PATH, index=False)

print("✅ BrandSimilarity added successfully!")
print("💾 Saved to:", OUTPUT_PATH)
