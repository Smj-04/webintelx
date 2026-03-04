import pandas as pd

# Load cleaned dataset (prefer file with BrandSimilarity if available)
import os

preferred = "data/processed/cleaned_phishing_with_brand.csv"
fallback = "data/processed/cleaned_phishing.csv"
path = preferred if os.path.exists(preferred) else fallback
df = pd.read_csv(path)

# ================================
# 1️⃣ URL ANALYSIS FEATURES
# ================================
url_features = [
    "URLLength", "IsDomainIP", "NoOfSubDomain", "IsHTTPS",
    "NoOfOtherSpecialCharsInURL", "SpacialCharRatioInURL",
    "NoOfLettersInURL", "LetterRatioInURL", "NoOfDegitsInURL",
    "DegitRatioInURL", "NoOfEqualsInURL", "NoOfQMarkInURL",
    "NoOfAmpersandInURL"
]

# ================================
# 2️⃣ DOMAIN ANALYSIS FEATURES
# ================================
domain_features = [
    "DomainLength", "TLDLength", "TLDLegitimateProb",
    "URLSimilarityIndex", "CharContinuationRate", "URLCharProb"
]

# ⚠️ Add BrandSimilarity ONLY if it exists in dataset
if "BrandSimilarity" in df.columns:
    domain_features.append("BrandSimilarity")

# ================================
# 3️⃣ CONTENT ANALYSIS FEATURES
# ================================
content_features = [
    "HasTitle", "HasFavicon", "Robots", "IsResponsive",
    "NoOfURLRedirect", "NoOfPopup", "NoOfiFrame",
    "HasExternalFormSubmit", "HasHiddenFields",
    "HasPasswordField", "NoOfExternalRef", "NoOfJS",
    "NoOfCSS", "NoOfImage"
]

# Combine all features
all_features = url_features + domain_features + content_features

print("✅ URL Features Count:", len(url_features))
print("✅ Domain Features Count:", len(domain_features))
print("✅ Content Features Count:", len(content_features))
print("✅ Total Features Used:", len(all_features))

# Save selected features dataset
X = df[all_features]
y = df["label"]

final_df = pd.concat([X, y], axis=1)
final_df.to_csv("data/processed/final_features.csv", index=False)

print("\n✅ Final feature dataset created successfully!")
