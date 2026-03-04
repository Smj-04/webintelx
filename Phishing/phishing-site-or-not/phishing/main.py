import joblib
import pandas as pd
import sys
import json
import warnings
import os

from phishing.features.realtime_features import extract_realtime_features
import tldextract
import requests

from phishing.features.utils import validator, rate_limiter, check_dependencies
from phishing.features.domain_checks import resolve_domain

# suppress noisy sklearn.parallel UserWarning about delayed/Parallel usage
warnings.filterwarnings("ignore", message=".*delayed.*Parallel.*", category=UserWarning)

# perform dependency checks (logs emitted to stderr)
deps = check_dependencies()

MODEL_PATH = os.path.join(os.path.dirname(__file__), "models", "phishing_model.pkl")

try:
    model = joblib.load(MODEL_PATH)
except Exception as e:
    payload = {"error": f"Model initialization failed: {str(e)}"}
    sys.stdout.write(json.dumps(payload))
    sys.exit(1)


def analyze_phishing_comprehensive(url, features):
    """Compute URL/domain/content scores without printing.

    Returns the same dictionary as the original implementation.
    """

    unreachable = False

    # ---------- URL analysis ----------
    url_risks = 0
    url_checks = 6

    if features.get("URLLength", 0) > 75:
        url_risks += 1
    if features.get("IsDomainIP", 0) == 1:
        url_risks += 2
    if features.get("NoOfOtherSpecialCharsInURL", 0) > 2:
        url_risks += 1
    if features.get("NoOfSubDomain", 0) > 3:
        url_risks += 1
    if features.get("IsHTTPS", 0) == 0:
        url_risks += 1
    if features.get("DegitRatioInURL", 0) > 0.3:
        url_risks += 1

    url_score = (url_risks / (url_checks * 2)) * 100

    # ---------- domain analysis ----------
    domain_risks = 0
    domain_checks = 4

    ext = tldextract.extract(url)
    domain = ext.domain.lower()

    brand_sim = features.get("BrandSimilarity", 0)
    if brand_sim > 0.7:
        domain_risks += 2
    elif brand_sim > 0.5:
        domain_risks += 1

    tld_prob = features.get("TLDLegitimateProb", 0.5)
    if tld_prob < 0.3:
        domain_risks += 1

    char_cont = features.get("CharContinuationRate", 0.5)
    if char_cont > 0.8:
        domain_risks += 1

    url_sim = features.get("URLSimilarityIndex", 0.5)
    if url_sim < 0.3:
        domain_risks += 1

    dns_ok = features.get("DNSResolvable", 1)
    if dns_ok == 0:
        domain_risks += 1
        unreachable = True

    ssl_valid = features.get("SSLCertValid", 0)
    ssl_days = features.get("SSLCertDaysLeft", -1)
    if ssl_valid == 0:
        domain_risks += 1
    else:
        if ssl_days >= 0 and ssl_days < 30:
            domain_risks += 1

    age_days = features.get("DomainAgeDays", -1)
    if age_days != -1 and age_days < 90:
        domain_risks += 1

    domain_score = (domain_risks / (domain_checks * 2)) * 100

    # ---------- content analysis ----------
    content_risks = 0
    content_checks = 8

    has_content = features.get("HasTitle", 0) or features.get("HasFavicon", 0)
    if not has_content:
        content_risks += 2
        unreachable = True
    else:
        if features.get("HasExternalFormSubmit", 0) == 1:
            content_risks += 2
        if features.get("HasHiddenFields", 0) > 0:
            content_risks += 1
        if features.get("HasPasswordField", 0) > 0:
            content_risks += 1

        ext_refs = features.get("NoOfExternalRef", 0)
        if ext_refs > 50:
            content_risks += 1
        elif ext_refs > 20:
            content_risks += 1

        if features.get("NoOfiFrame", 0) > 0:
            content_risks += 1

        if features.get("NoOfURLRedirect", 0) > 2:
            content_risks += 1

        if features.get("HasTitle", 0) == 1 and features.get("HasFavicon", 0) == 1:
            pass
        else:
            content_risks += 0.5

        if features.get("IsResponsive", 0) == 1:
            pass
        else:
            content_risks += 0.5

        if features.get("HasMetaRefresh", 0) == 1:
            content_risks += 1

        if features.get("HasJSRedirect", 0) == 1:
            content_risks += 1

    content_score = (content_risks / (content_checks * 2)) * 100

    overall_score = (
        url_score * 0.20
        + domain_score * 0.30
        + content_score * 0.50
    )

    return {
        "overall_score": overall_score,
        "url_score": url_score,
        "domain_score": domain_score,
        "content_score": content_score,
        "indicators_count": url_risks + domain_risks + content_risks,
        "total_checks": (url_checks + domain_checks + content_checks) * 2,
        "unreachable": unreachable,
    }


def _risk_level_from_score(score):
    if score is None:
        return "LOW"
    if score > 70:
        return "CRITICAL"
    elif score > 55:
        return "HIGH"
    elif score > 35:
        return "MODERATE"
    else:
        return "LOW"


def run_cli():
    try:
        args = sys.argv[1:]
        if len(args) != 1:
            sys.stdout.write(json.dumps({"error": "No URL provided"}))
            return

        url = args[0].strip()
        url = validator.validate(url)
        if not url:
            sys.stdout.write(json.dumps({"error": "Invalid URL"}))
            return

        if not rate_limiter.is_allowed():
            sys.stdout.write(json.dumps({"error": "Rate limit exceeded"}))
            return

        # ---------- Hosting checks (DNS + HTTP reachability) ----------
        try:
            ext = tldextract.extract(url)
            domain_to_check = ext.registered_domain or (ext.domain + "." + ext.suffix)
        except Exception:
            domain_to_check = None

        if not domain_to_check or not resolve_domain(domain_to_check):
            sys.stdout.write(json.dumps({"url": url, "message": "No such site exists."}))
            return

        # Quick HTTP probe to verify site responds
        try:
            # prefer HEAD to reduce bandwidth, follow redirects
            resp = requests.head(url, timeout=5, allow_redirects=True)
            status = resp.status_code
            # treat 2xx and 3xx as reachable
            if status >= 400:
                # fallback to GET in case HEAD is not supported
                resp = requests.get(url, timeout=5, allow_redirects=True)
                status = resp.status_code

            if status >= 400:
                sys.stdout.write(json.dumps({"url": url, "message": "Site not reachable."}))
                return
        except Exception:
            sys.stdout.write(json.dumps({"url": url, "message": "Site not reachable."}))
            return

        features = extract_realtime_features(url)
        df = pd.DataFrame([features])
        if hasattr(model, "feature_names_in_"):
            expected = list(model.feature_names_in_)
            df = df.reindex(columns=expected, fill_value=0)

        model_pred = model.predict(df)[0]
        model_confidence = model.predict_proba(df)[0]

        analysis = analyze_phishing_comprehensive(url, features)
        url_score = analysis["url_score"]
        domain_score = analysis["domain_score"]
        content_score = analysis["content_score"]
        overall_risk = analysis["overall_score"]
        unreachable = analysis.get("unreachable", False)

        # apply escalation rules
        has_content = features.get("HasTitle", 0) or features.get("HasFavicon", 0)
        brand_sim = features.get("BrandSimilarity", 0)

        if brand_sim > 0.7 and brand_sim < 1.0 and not has_content:
            overall_risk = max(overall_risk, 75)
        elif domain_score > 40 and not has_content:
            overall_risk = max(overall_risk, 60)
        elif content_score >= 30 and url_score < 10 and domain_score < 10:
            overall_risk = max(overall_risk, 60)
        elif not has_content:
            overall_risk = max(overall_risk, 60)

        # ML escalation
        if model_pred == 1 and model_confidence[int(model_pred)] > 0.80:
            overall_risk = max(overall_risk, 75)

        risk_level = _risk_level_from_score(overall_risk)
        prediction = "phishing" if model_pred == 1 else "legitimate"
        ml_prob = float(model_confidence[int(model_pred)])

        # Determine final human-friendly classification combining ML + rule-based scores
        is_phishing_ml = (model_pred == 1 and ml_prob > 0.6)
        is_risky_rules = (overall_risk >= 50)
        # Conservative decision: if either ML or rules indicate risk, mark as potential phishing
        if is_phishing_ml or is_risky_rules or (model_pred == 1 and overall_risk >= 40):
            classification = "Potential Phishing Website"
        else:
            classification = "Legitimate Website"

        output = {
            "url": url,
            "prediction": prediction,
            "classification": classification,
            "risk_level": risk_level,
            "ml_probability": ml_prob,
            "scores": {
                "url_score": url_score,
                "domain_score": domain_score,
                "content_score": content_score,
                "final_weighted_score": overall_risk
            },
            "flags": {
                "unreachable": unreachable,
                "brand_similarity": brand_sim,
                "ssl_valid": bool(features.get("SSLCertValid", 0))
            },
            "details": (
                f"{risk_level} ({overall_risk:.1f}%) – ML predicted "
                f"{prediction} ({ml_prob:.2f}) – {classification}"
            )
        }

        sys.stdout.write(json.dumps(output))

    except Exception as exc:
        sys.stdout.write(json.dumps({"error": str(exc)}))


if __name__ == "__main__":
    run_cli()
