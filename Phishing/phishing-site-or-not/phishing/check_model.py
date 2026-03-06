#this is check_model.py, a script to load the trained phishing detection model and verify if the "BrandSimilarity" feature is included. It prints the model's features and their importance, helping to confirm that the new feature is integrated correctly into the model.

import joblib
import pandas as pd

print("Loading model...")
model = joblib.load("models/phishing_model.pkl")

print("\n✅ Model loaded successfully")
print(f"\nModel features ({len(model.feature_names_in_)}):")
for i, feat in enumerate(model.feature_names_in_, 1):
    print(f"  {i}. {feat}")

if "BrandSimilarity" in model.feature_names_in_:
    print("\n✅ BrandSimilarity IS in the model")
    idx = list(model.feature_names_in_).index("BrandSimilarity")
    importance = model.feature_importances_[idx]
    print(f"   Feature importance rank: {importance:.4f}")
else:
    print("\n❌ BrandSimilarity NOT in the model")
