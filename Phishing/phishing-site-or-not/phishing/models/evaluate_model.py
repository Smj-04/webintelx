import joblib
import pandas as pd
from phishing.features.realtime_features import extract_realtime_features

model = joblib.load("models/phishing_model.pkl")

url = input("www.google.com")

features = extract_realtime_features(url)
df = pd.DataFrame([features])

prediction = model.predict(df)[0]

print("\n==============================")
if prediction == 1:
    print("⚠️ PHISHING WEBSITE DETECTED!")
else:
    print("✅ LEGITIMATE WEBSITE")
print("==============================")
