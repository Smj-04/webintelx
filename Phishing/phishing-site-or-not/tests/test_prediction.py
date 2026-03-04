import joblib
import pandas as pd
import os
import phishing
from phishing.features.realtime_features import extract_realtime_features

model_path = os.path.join(os.path.dirname(phishing.__file__), "models", "phishing_model.pkl")
model = joblib.load(model_path)

test_urls = [
    "https://paypaI.com",       # Typo (should be phishing)
    "https://google.com",        # Legitimate
    "https://paypa1.com",        # Another PayPal typo
]

for url in test_urls:
    print(f"\n{'='*60}")
    print(f"Testing: {url}")
    print(f"{'='*60}")
    
    features = extract_realtime_features(url)
    df = pd.DataFrame([features])
    
    # Align with model's expected features
    if hasattr(model, "feature_names_in_"):
        expected = list(model.feature_names_in_)
        df = df.reindex(columns=expected, fill_value=0)
    
    print("\n📊 Features extracted:")
    for col in df.columns:
        print(f"  {col}: {df[col].values[0]}")
    
    print(f"\n🔍 Features count: {df.shape[1]}")
    
    prediction = model.predict(df)[0]
    confidence = model.predict_proba(df)[0]
    
    print(f"\n🎯 Prediction: {prediction}")
    print(f"📈 Confidence [Legitimate, Phishing]: {confidence}")
    
    if prediction == 1:
        print("⚠️ PHISHING WEBSITE DETECTED!")
    else:
        print("✅ LEGITIMATE WEBSITE")
