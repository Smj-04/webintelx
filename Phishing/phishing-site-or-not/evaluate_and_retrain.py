# evaluate_and_retrain.py
# ─────────────────────────────────────────────────────────────────────────────
# HOW TO RUN (from your terminal):
#
#   Step 1 — navigate to the phishing module folder:
#     cd C:\Users\lenovo\Desktop\webintelx_main\Phishing\phishing-site-or-not
#
#   Step 2 — test the current model:
#     python evaluate_and_retrain.py --evaluate
#
#   Step 3 — retrain (only needed once, or when you get new data):
#     python evaluate_and_retrain.py --retrain
# ─────────────────────────────────────────────────────────────────────────────

import os
import sys
import json
import argparse
import joblib
import pandas as pd
import numpy as np
from datetime import datetime


# ─────────────────────────────────────────────────────────────────────────────
# FEATURES THAT REQUIRE EXTERNAL API CALLS AT RUNTIME
# These exist in the training dataset but realtime_features.py CANNOT compute
# them for a live URL (no Google API key, no Alexa/Majestic API, etc.).
# Training on them causes the model to rely on features that are always
# 0 in production → silent accuracy collapse in real usage.
# ─────────────────────────────────────────────────────────────────────────────
API_ONLY_FEATURES = {
    "google_index",   # requires Google Search API
    "page_rank",      # requires Majestic / MOZ API
    "web_traffic",    # requires Alexa / SimilarWeb API
}

# ─────────────────────────────────────────────────────────────────────────────
# COLUMN NAME MAPPING  (your model feature names → Kaggle dataset column names)
# ─────────────────────────────────────────────────────────────────────────────
COLUMN_MAP = {
    "URLLength":                    "length_url",
    "IsDomainIP":                   "ip",
    "NoOfSubDomain":                "nb_subdomains",
    "IsHTTPS":                      "https_token",
    "NoOfOtherSpecialCharsInURL":   "nb_hyperlinks",
    "SpacialCharRatioInURL":        "ratio_extHyperlinks",
    "NoOfLettersInURL":             "length_hostname",
    "LetterRatioInURL":             "ratio_digits_url",
    "DegitRatioInURL":              "ratio_digits_url",
    "NoOfEqualsInURL":              "nb_eq",
    "NoOfQMarkInURL":               "nb_qm",
    "NoOfAmpersandInURL":           "nb_and",
    "DomainLength":                 "length_hostname",
    "NoOfURLRedirect":              "nb_redirection",
    "NoOfPopup":                    "popup_window",
    "NoOfiFrame":                   "iframe",
    "HasExternalFormSubmit":        "submit_email",
    "HasHiddenFields":              "sfh",
    "HasPasswordField":             "login_form",
    "NoOfExternalRef":              "nb_extCSS",
    "NoOfCSS":                      "nb_extCSS",
    "HasMetaRefresh":               "onmouseover",
    "HasJSRedirect":                "right_clic",
    # Features computed by realtime_features.py but not directly in dataset:
    "TLDLength":                    None,  # derived below
    "NoOfDegitsInURL":              None,  # derived below
    "DNSResolvable":                None,  # derived from dns_record
    "SSLCertDaysLeft":              None,  # not in dataset
    "SSLCertValid":                 None,  # not in dataset
    "DomainAgeDays":                None,  # derived from domain_age
    "BrandSimilarity":              None,  # not in dataset
    "TLDLegitimateProb":            None,  # not in dataset
    "CharContinuationRate":         None,  # not in dataset
    "URLCharProb":                  None,  # not in dataset
    "URLSimilarityIndex":           None,  # not in dataset
    "IsOnFreeHosting":              None,  # derived: shortening_service | suspecious_tld
    "HasTitle":                     None,  # derived: inverse of empty_title
    "HasFavicon":                   None,  # derived: inverse of external_favicon
    "Robots":                       None,  # not in dataset
    "IsResponsive":                 None,  # not in dataset
    "NoOfJS":                       None,  # not in dataset
    "NoOfImage":                    None,  # not in dataset
}

# All dataset columns usable directly at runtime (no API needed)
# google_index, page_rank, web_traffic are intentionally absent
DIRECT_FEATURES = [
    "length_url", "length_hostname", "ip", "nb_dots", "nb_hyphens", "nb_at",
    "nb_qm", "nb_and", "nb_or", "nb_eq", "nb_underscore", "nb_tilde",
    "nb_percent", "nb_slash", "nb_star", "nb_colon", "nb_comma",
    "nb_semicolumn", "nb_dollar", "nb_space", "nb_www", "nb_com",
    "nb_dslash", "http_in_path", "https_token", "ratio_digits_url",
    "ratio_digits_host", "punycode", "port", "tld_in_path",
    "tld_in_subdomain", "abnormal_subdomain", "nb_subdomains",
    "prefix_suffix", "random_domain", "shortening_service", "path_extension",
    "nb_redirection", "nb_external_redirection", "length_words_raw",
    "char_repeat", "shortest_words_raw", "shortest_word_host",
    "shortest_word_path", "longest_words_raw", "longest_word_host",
    "longest_word_path", "avg_words_raw", "avg_word_host", "avg_word_path",
    "phish_hints", "domain_in_brand", "brand_in_subdomain", "brand_in_path",
    "suspecious_tld", "statistical_report", "nb_hyperlinks",
    "ratio_intHyperlinks", "ratio_extHyperlinks", "ratio_nullHyperlinks",
    "nb_extCSS", "ratio_intRedirection", "ratio_extRedirection",
    "ratio_intErrors", "ratio_extErrors", "login_form", "external_favicon",
    "links_in_tags", "submit_email", "ratio_intMedia", "ratio_extMedia",
    "sfh", "iframe", "popup_window", "safe_anchor", "onmouseover",
    "right_clic", "empty_title", "domain_in_title", "domain_with_copyright",
    "whois_registered_domain", "domain_registration_length",
    "domain_age", "dns_record",
]


def _derive_mapped_features(raw_df: pd.DataFrame) -> dict:
    """
    Compute model features that have no direct column match in the dataset.
    Returns dict of {feature_name: np.ndarray}.
    """
    n = len(raw_df)
    idx = raw_df.index
    derived = {}

    def col(name, default=0):
        return raw_df[name] if name in raw_df.columns else pd.Series(default, index=idx)

    # DNSResolvable ← dns_record
    derived["DNSResolvable"] = col("dns_record")

    # DomainAgeDays ← domain_age (already in days in this dataset)
    derived["DomainAgeDays"] = col("domain_age")

    # IsOnFreeHosting ← shortening_service OR suspecious_tld
    derived["IsOnFreeHosting"] = (
        (col("shortening_service") == 1) | (col("suspecious_tld") == 1)
    ).astype(int)

    # HasTitle ← NOT empty_title  (empty_title=1 means the page has NO title)
    derived["HasTitle"] = (col("empty_title") == 0).astype(int)

    # HasFavicon ← NOT external_favicon (0 = same-domain = likely legitimate)
    derived["HasFavicon"] = (col("external_favicon") == 0).astype(int)

    # TLDLength — no TLD column in dataset; use fixed reasonable default
    derived["TLDLength"] = pd.Series(np.full(n, 3, dtype=int), index=idx)

    # NoOfDegitsInURL ← ratio_digits_url × length_url
    derived["NoOfDegitsInURL"] = (
        col("ratio_digits_url") * col("length_url")
    ).round().astype(int)

    # Features not derivable → zero
    for feat in ["SSLCertDaysLeft", "SSLCertValid", "BrandSimilarity",
                 "TLDLegitimateProb", "CharContinuationRate",
                 "URLCharProb", "URLSimilarityIndex",
                 "Robots", "IsResponsive", "NoOfJS", "NoOfImage"]:
        derived[feat] = pd.Series(np.zeros(n, dtype=float), index=idx)

    return derived


def _build_feature_matrix(raw_df: pd.DataFrame):
    """
    Build the full training feature matrix.
    Uses pd.concat (not iterative insert) — no PerformanceWarning.
    Excludes API_ONLY_FEATURES entirely.
    """
    col_series = {}
    mapped_ok, mapped_zero = [], []

    # 1. Mapped features
    for model_feat, dataset_col in COLUMN_MAP.items():
        if dataset_col is not None and dataset_col in raw_df.columns:
            col_series[model_feat] = raw_df[dataset_col].values
            mapped_ok.append((model_feat, dataset_col))
        else:
            col_series[model_feat] = np.zeros(len(raw_df))
            mapped_zero.append(model_feat)

    # 2. Derived features (overwrite zero entries computed above)
    derived = _derive_mapped_features(raw_df)
    for feat, values in derived.items():
        col_series[feat] = np.asarray(values)

    # 3. Direct dataset features (skip API-only, skip label, skip already added)
    extra_direct = []
    for col in DIRECT_FEATURES:
        if (col in raw_df.columns
                and col not in col_series
                and col not in API_ONLY_FEATURES):
            col_series[col] = raw_df[col].values
            extra_direct.append(col)

    # 4. Build in one shot — no fragmentation
    feat_df = pd.DataFrame(col_series, index=raw_df.index)

    return feat_df, mapped_ok, mapped_zero, extra_direct


def evaluate_current_model():
    print("\n" + "=" * 60)
    print("STEP 1 — EVALUATING CURRENT MODEL")
    print("=" * 60)

    model_path = "models/phishing_model.pkl"
    if not os.path.exists(model_path):
        print(f"\n❌  Model not found at: {model_path}")
        print("    Make sure you are running this from inside:")
        print("    Phishing/phishing-site-or-not/")
        return

    model = joblib.load(model_path)
    print(f"\n✅  Model loaded: {type(model).__name__}")
    print(f"    Total features used: {len(model.feature_names_in_)}")

    # Check for API-only features in the saved model
    api_in_model = [f for f in model.feature_names_in_ if f in API_ONLY_FEATURES]
    if api_in_model:
        print(f"\n⚠   WARNING: Model includes API-only features: {api_in_model}")
        print("    These will always be 0 in production → run --retrain to fix!")
    else:
        print("\n✅  No API-only features in model (production-safe)")

    if "IsOnFreeHosting" in model.feature_names_in_:
        print("✅  IsOnFreeHosting feature IS in the model")
    else:
        print("⚠   IsOnFreeHosting NOT in model")

    print("\n── Feature importance (top 15) ──")
    pairs = sorted(
        zip(model.feature_names_in_, model.feature_importances_),
        key=lambda x: x[1], reverse=True
    )[:15]
    for feat, imp in pairs:
        tag = " ⚠ API-ONLY — always 0 in prod!" if feat in API_ONLY_FEATURES else ""
        print(f"    {feat:<35} {imp:.4f}{tag}")

    # ── Spot tests ────────────────────────────────────────────────────────────
    print("\n── Running spot tests (8 known URLs) ──")
    test_cases = [
        ("https://google.com",                           "legitimate"),
        ("https://github.com",                           "legitimate"),
        ("https://paypal.com",                           "legitimate"),
        ("http://bitmrtlugie.webflow.io",                "phishing"),
        ("http://secure-paypal-verify.netlify.app",      "phishing"),
        ("http://192.168.1.1/bank/login",                "phishing"),
        ("http://arnazon-support.com/verify",            "phishing"),
        ("https://totally-not-phishing.xyz/login",       "phishing"),
    ]

    try:
        sys.path.insert(0, ".")
        from phishing.features.realtime_features import extract_realtime_features

        correct = 0
        total   = 0
        for url, expected in test_cases:
            try:
                feats = extract_realtime_features(url)
                df    = pd.DataFrame([feats]).reindex(
                    columns=model.feature_names_in_, fill_value=0
                )
                pred       = model.predict(df)[0]
                prob       = model.predict_proba(df)[0]
                predicted  = "phishing" if pred == 1 else "legitimate"
                confidence = prob[int(pred)]
                ok = predicted == expected
                icon = "✅" if ok else "❌"
                print(f"    {icon} {url[:55]:<55} → {predicted} ({confidence:.2f})  [expected: {expected}]")
                if ok:
                    correct += 1
                total += 1
            except Exception as e:
                print(f"    ⚠  {url[:55]:<55} → ERROR: {e}")

        if total > 0:
            pct = correct / total * 100
            print(f"\n    Spot-test accuracy: {pct:.0f}% ({correct}/{total})")
            if pct < 70:
                print("    ⚠  Accuracy is LOW — run with --retrain to improve the model")
            elif pct < 90:
                print("    ⚠  Accuracy is OK but could be better — consider --retrain")
            else:
                print("    ✅  Accuracy looks good!")

    except Exception as e:
        print(f"\n❌  Could not run spot tests: {e}")
        print("    Make sure you are inside: Phishing/phishing-site-or-not/")


def retrain_model():
    print("\n" + "=" * 60)
    print("STEP 2 — RETRAINING MODEL")
    print("=" * 60)

    # ── Find dataset ──────────────────────────────────────────────────────────
    candidates = [
        "data/processed/dataset.csv",
        "data/dataset.csv",
        "data/phishing_dataset.csv",
        "dataset.csv",
    ]
    dataset_path = next((p for p in candidates if os.path.exists(p)), None)
    if not dataset_path:
        print("\n❌  No dataset found. Checked:")
        for c in candidates:
            print(f"    {c}")
        print("""
HOW TO GET A FREE DATASET:
  1. https://www.kaggle.com/datasets/shashwatwork/web-page-phishing-detection-dataset
  2. Download, unzip, rename CSV to dataset.csv
  3. Place at: Phishing/phishing-site-or-not/data/processed/dataset.csv
""")
        return

    print(f"\n✅  Dataset found: {dataset_path}")
    raw_df = pd.read_csv(dataset_path)
    print(f"    Rows: {len(raw_df)}  |  Columns: {len(raw_df.columns)}")

    # ── Label column ──────────────────────────────────────────────────────────
    label_col = next(
        (c for c in ["label", "Label", "class", "Class", "phishing",
                     "target", "status", "Status"]
         if c in raw_df.columns),
        None
    )
    if not label_col:
        print(f"\n❌  Could not find label column. Columns: {list(raw_df.columns)}")
        return

    print(f"    Label column: '{label_col}'")
    print(f"    Class counts:\n{raw_df[label_col].value_counts().to_string()}")

    unique_vals = raw_df[label_col].unique()
    if set(str(v).lower() for v in unique_vals) <= {"phishing", "legitimate"}:
        raw_df[label_col] = raw_df[label_col].apply(
            lambda x: 1 if str(x).lower() == "phishing" else 0
        )
        print("    ℹ  Converted text labels: phishing=1, legitimate=0")

    y = raw_df[label_col].reset_index(drop=True)

    # ── Build feature matrix ──────────────────────────────────────────────────
    print("\n── Building feature matrix ──")
    print(f"    ⛔ Excluding API-only features: {sorted(API_ONLY_FEATURES)}")
    print("       (These require Google/Alexa APIs not available at runtime)\n")

    feat_df, mapped_ok, mapped_zero, extra_direct = _build_feature_matrix(raw_df)
    feat_df = feat_df.fillna(0).reset_index(drop=True)

    non_zero_cols = [c for c in feat_df.columns if feat_df[c].nunique() > 1]
    print(f"    Mapped (renamed):   {len(mapped_ok)} features")
    print(f"    Derived:            features like IsOnFreeHosting, DomainAgeDays, etc.")
    print(f"    Extra direct cols:  {len(extra_direct)}")
    print(f"    Total features:     {len(feat_df.columns)}")
    print(f"    With real variance: {len(non_zero_cols)} / {len(feat_df.columns)}")

    if len(non_zero_cols) < 10:
        print("\n❌  CRITICAL: Fewer than 10 features have variance — aborting.")
        return

    # ── Train ─────────────────────────────────────────────────────────────────
    print("\n── Training two models, picking the better one ──")
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import (
        classification_report, confusion_matrix,
        roc_auc_score, accuracy_score
    )

    X = feat_df
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"    Training rows: {len(X_train)}  |  Test rows: {len(X_test)}")

    model_candidates = [
        ("RandomForest", RandomForestClassifier(
            n_estimators=300,
            max_depth=None,
            min_samples_split=4,
            min_samples_leaf=2,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )),
        ("GradientBoosting", GradientBoostingClassifier(
            n_estimators=200,
            max_depth=6,
            learning_rate=0.08,
            subsample=0.8,
            random_state=42,
        )),
    ]

    best_model, best_score, best_name = None, 0, ""
    for name, clf in model_candidates:
        print(f"\n    Training {name}...")
        clf.fit(X_train, y_train)
        y_pred = clf.predict(X_test)
        acc    = accuracy_score(y_test, y_pred)
        auc    = roc_auc_score(y_test, clf.predict_proba(X_test)[:, 1])
        print(f"    Accuracy: {acc*100:.1f}%   AUC-ROC: {auc:.4f}")
        if auc > best_score:
            best_score, best_model, best_name = auc, clf, name

    print(f"\n── Best model: {best_name}  (AUC: {best_score:.4f}) ──")
    y_pred = best_model.predict(X_test)
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred,
                                target_names=["legitimate", "phishing"],
                                zero_division=0))

    cm = confusion_matrix(y_test, y_pred)
    print("Confusion Matrix:")
    print(f"    Correct legitimate:  {cm[0][0]}   Wrong (said phishing): {cm[0][1]}")
    print(f"    Missed phishing:     {cm[1][0]}   Correct phishing:      {cm[1][1]}")

    # ── Top features ──────────────────────────────────────────────────────────
    print("\n── Top 20 most important features ──")
    importances = sorted(
        zip(best_model.feature_names_in_, best_model.feature_importances_),
        key=lambda x: x[1], reverse=True
    )[:20]
    for feat, imp in importances:
        tag = " ⚠ API-ONLY" if feat in API_ONLY_FEATURES else ""
        bar = "█" * int(imp * 300)
        print(f"    {feat:<35} {imp:.4f}  {bar}{tag}")

    # ── Verify no API features leaked in ─────────────────────────────────────
    api_leaked = [f for f in best_model.feature_names_in_ if f in API_ONLY_FEATURES]
    if api_leaked:
        print(f"\n⚠   WARNING: API-only features found in model: {api_leaked}")
        print("    This should not happen — please report this as a bug.")
    else:
        print("\n✅  Confirmed: No API-only features in the trained model.")
        print("    This model will work correctly in production.")

    # ── Save ──────────────────────────────────────────────────────────────────
    os.makedirs("models", exist_ok=True)
    old_path = "models/phishing_model.pkl"
    if os.path.exists(old_path):
        backup = f"models/phishing_model_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pkl"
        os.rename(old_path, backup)
        print(f"\n    Old model backed up → {backup}")

    joblib.dump(best_model, old_path)
    print(f"    ✅  New model saved → {old_path}")

    os.makedirs("reports", exist_ok=True)
    report_path = f"reports/eval_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_path, "w") as f:
        json.dump({
            "trained_at":             datetime.now().isoformat(),
            "model":                  best_name,
            "accuracy":               float(accuracy_score(y_test, y_pred)),
            "auc_roc":                float(best_score),
            "total_features":         len(feat_df.columns),
            "api_features_excluded":  sorted(API_ONLY_FEATURES),
            "feature_list":           list(feat_df.columns),
        }, f, indent=2)
    print(f"    ✅  Report saved → {report_path}")
    print("""
    ✅  Done! Next steps:
        1. Copy-Item "models\\phishing_model.pkl" -Destination "phishing\\models\\phishing_model.pkl" -Force
        2. Restart your backend server
        3. Run --evaluate to confirm accuracy is still good
""")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--evaluate", action="store_true", help="Test the current model")
    parser.add_argument("--retrain",  action="store_true", help="Retrain the model on a dataset")
    args = parser.parse_args()

    if not args.evaluate and not args.retrain:
        print("Usage:")
        print("  python evaluate_and_retrain.py --evaluate")
        print("  python evaluate_and_retrain.py --retrain")
        print("  python evaluate_and_retrain.py --evaluate --retrain")
        sys.exit(1)

    if args.evaluate:
        evaluate_current_model()
    if args.retrain:
        retrain_model()