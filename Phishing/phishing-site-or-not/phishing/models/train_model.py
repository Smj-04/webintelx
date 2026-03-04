import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib
import os
import seaborn as sns
import matplotlib.pyplot as plt


def train():
    """Train the phishing detection model and persist it."""

    # Load dataset
    df = pd.read_csv("data/processed/final_features.csv")
    X = df.drop("label", axis=1)
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("✅ Training data shape:", X_train.shape)
    print("✅ Testing data shape:", X_test.shape)

    model = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        random_state=42,
        n_jobs=-1
    )

    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)

    accuracy = accuracy_score(y_test, y_pred)
    print("\n🎯 Accuracy:", accuracy)
    print("\n📊 Classification Report:\n", classification_report(y_test, y_pred))

    cm = confusion_matrix(y_test, y_pred)
    print("\n🧩 Confusion Matrix:\n", cm)

    model_path = os.path.join(os.path.dirname(__file__), "phishing_model.pkl")
    joblib.dump(model, model_path)
    print(f"\n✅ Model saved successfully: {model_path}")

    return model


if __name__ == "__main__":
    train()
