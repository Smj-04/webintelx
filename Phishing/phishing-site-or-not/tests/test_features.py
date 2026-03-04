import joblib
import pandas as pd
import os
import phishing
from phishing.features.realtime_features import brand_similarity
import tldextract

model_path = os.path.join(os.path.dirname(phishing.__file__), "models", "phishing_model.pkl")
model = joblib.load(model_path)

# Test BrandSimilarity computation
test_domains = [
    ("paypal", "paypal"),    # Exact match
    ("paypaI", "paypal"),    # Typo (capital I)
    ("paypa1", "paypal"),    # Typo (1 instead of l)
    ("google", "paypal"),    # Different
]

print("Testing BrandSimilarity calculation:")
print("=" * 60)

for domain, expected_match in test_domains:
    score = brand_similarity(domain)
    print(f"Domain: '{domain}' -> BrandSimilarity: {score:.3f}")

print("\n" + "=" * 60)
print("\nModel feature names (from training):")
print(list(model.feature_names_in_))
print(f"\nTotal features: {len(model.feature_names_in_)}")

# Check if BrandSimilarity is in the model's features
if "BrandSimilarity" in model.feature_names_in_:
    print("\n✅ BrandSimilarity IS in model features")
else:
    print("\n❌ BrandSimilarity NOT in model features")

# Print feature importance (if available)
if hasattr(model, "feature_importances_"):
    importances = model.feature_importances_
    feature_import = list(zip(model.feature_names_in_, importances))
    feature_import.sort(key=lambda x: x[1], reverse=True)
    
    print("\n📊 Top 10 Most Important Features:")
    for name, importance in feature_import[:10]:
        print(f"  {name}: {importance:.4f}")
