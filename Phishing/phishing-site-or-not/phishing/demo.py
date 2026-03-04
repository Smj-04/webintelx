import joblib
import pandas as pd
import re
from phishing.features.realtime_features import extract_realtime_features
import tldextract

import os
MODEL_PATH = os.path.join(os.path.dirname(__file__), "models", "phishing_model.pkl")
model = joblib.load(MODEL_PATH)

def analyze_phishing_comprehensive(url, features):
    """
    Comprehensive phishing detection with three analysis categories.
    """
    risk_indicators = []
    unreachable = False
    
    # ================================
    # 1️⃣ URL ANALYSIS
    # ================================
    print("\n1️⃣ URL ANALYSIS:")
    print("   " + "="*50)
    
    url_risks = 0
    url_checks = 6
    
    if features.get("URLLength", 0) > 75:
        print("   ⚠️  Long URL detected (>75 chars) - suspicious")
        url_risks += 1
    else:
        print("   ✅ URL length reasonable")
    
    if features.get("IsDomainIP", 0) == 1:
        print("   ⚠️  IP address used instead of domain - HIGHLY SUSPICIOUS")
        url_risks += 2
    else:
        print("   ✅ Uses domain name (not IP)")
    
    if features.get("NoOfOtherSpecialCharsInURL", 0) > 2:
        print("   ⚠️  Multiple special characters (@, -, //) detected - suspicious")
        url_risks += 1
    else:
        print("   ✅ Minimal suspicious special characters")
    
    if features.get("NoOfSubDomain", 0) > 3:
        print("   ⚠️  Multiple subdomains detected - suspicious")
        url_risks += 1
    else:
        print("   ✅ Subdomain count normal")
    
    if features.get("IsHTTPS", 0) == 0:
        print("   ⚠️  No HTTPS - NOT SECURE")
        url_risks += 1
    else:
        print("   ✅ HTTPS enabled")
    
    if features.get("DegitRatioInURL", 0) > 0.3:
        print("   ⚠️  High digit ratio in URL - suspicious")
        url_risks += 1
    else:
        print("   ✅ Digit ratio normal")
    
    url_score = (url_risks / (url_checks * 2)) * 100
    print(f"\n   URL Risk Score: {url_score:.1f}%")
    
    # ================================
    # 2️⃣ DOMAIN ANALYSIS
    # ================================
    print("\n2️⃣ DOMAIN ANALYSIS:")
    print("   " + "="*50)
    
    domain_risks = 0
    domain_checks = 4
    
    ext = tldextract.extract(url)
    brand_sim = features.get("BrandSimilarity", 0)
    if brand_sim > 0.7:
        print(f"   ⚠️  High brand similarity ({brand_sim:.0%}) - POTENTIAL TYPO ATTACK")
        domain_risks += 2
    elif brand_sim > 0.5:
        print(f"   ⚠️  Moderate brand similarity ({brand_sim:.0%}) - possible typo")
        domain_risks += 1
    else:
        print(f"   ✅ Brand similarity low ({brand_sim:.0%})")
    
    tld_prob = features.get("TLDLegitimateProb", 0.5)
    if tld_prob < 0.3:
        print(f"   ⚠️  Suspicious TLD - rarely legitimate")
        domain_risks += 1
    else:
        print(f"   ✅ TLD likely legitimate ({tld_prob:.0%})")
    
    char_cont = features.get("CharContinuationRate", 0.5)
    if char_cont > 0.8:
        print(f"   ⚠️  High character continuation - possible homograph attack")
        domain_risks += 1
    else:
        print(f"   ✅ Normal character patterns")
    
    url_sim = features.get("URLSimilarityIndex", 0.5)
    if url_sim < 0.3:
        print(f"   ⚠️  Low URL similarity to known legitimate sites")
        domain_risks += 1
    else:
        print(f"   ✅ URL similarity reasonable ({url_sim:.0%})")

    # DNS resolution check (mirror main logic)
    dns_ok = features.get("DNSResolvable", 1)
    if dns_ok == 0:
        print("   ⚠️  Domain does not resolve")
        domain_risks += 1
        unreachable = True
    else:
        print("   ✅ Domain resolves via DNS")

    domain_score = (domain_risks / (domain_checks * 2)) * 100
    print(f"\n   Domain Risk Score: {domain_score:.1f}%")
    
    # ================================
    # 3️⃣ WEBSITE CONTENT ANALYSIS
    # ================================
    print("\n3️⃣ WEBSITE CONTENT ANALYSIS:")
    print("   " + "="*50)
    
    content_risks = 0
    content_checks = 8
    
    has_content = features.get("HasTitle", 0) or features.get("HasFavicon", 0)
    
    if not has_content:
        print("   ⚠️  Content not accessible - site unreachable or blocked")
        print("       (Cannot verify: forms, links, iframes, redirects)")
        content_risks += 2
        unreachable = True
    else:
        if features.get("HasExternalFormSubmit", 0) == 1:
            print("   ⚠️  External form submission detected - credential theft risk")
            content_risks += 2
        else:
            print("   ✅ No external form submissions detected")
        
        if features.get("HasHiddenFields", 0) > 0:
            print(f"   ⚠️  Hidden form fields detected - suspicious")
            content_risks += 1
        else:
            print("   ✅ No hidden form fields")
        
        if features.get("HasPasswordField", 0) > 0:
            print(f"   ⚠️  Password fields detected - verify legitimacy")
            content_risks += 1
        else:
            print("   ✅ No password fields detected")
        
        ext_refs = features.get("NoOfExternalRef", 0)
        if ext_refs > 50:
            print(f"   ⚠️  Excessive external links ({ext_refs}) - suspicious")
            content_risks += 1
        elif ext_refs > 20:
            print(f"   ⚠️  Many external links ({ext_refs}) - check carefully")
            content_risks += 1
        else:
            print(f"   ✅ External links reasonable ({ext_refs})")
        
        if features.get("NoOfiFrame", 0) > 0:
            print(f"   ⚠️  iframes detected - content embedding")
            content_risks += 1
        else:
            print("   ✅ No iframes detected")
        
        if features.get("NoOfURLRedirect", 0) > 2:
            print(f"   ⚠️  Multiple redirects - suspicious")
            content_risks += 1
        else:
            print("   ✅ Minimal redirects")
        
        if features.get("HasTitle", 0) == 1 and features.get("HasFavicon", 0) == 1:
            print("   ✅ Has title & favicon (legitimate effort)")
        else:
            print("   ⚠️  Missing title or favicon - low effort clone")
            content_risks += 0.5
        
        if features.get("IsResponsive", 0) == 1:
            print("   ✅ Responsive design (modern site)")
        else:
            print("   ⚠️  Not mobile responsive - outdated site")
            content_risks += 0.5
    
    content_score = (content_risks / (content_checks * 2)) * 100
    print(f"\n   Content Risk Score: {content_score:.1f}%")
    
    # weighted overall score (URL 20%, Domain 30%, Content 50%)
    overall_score = (
        url_score * 0.20
        + domain_score * 0.30
        + content_score * 0.50
    )
    # escalation rules mirror main.py
    has_content = features.get("HasTitle", 0) or features.get("HasFavicon", 0)
    brand_sim = features.get("BrandSimilarity", 0)

    # handle unreachable case specially
    if unreachable and features.get("DNSResolvable", 1) == 0:
        print("   🚫 Domain unreachable; cannot compute reliable score")
        # leave overall_score as-is but note unknown
    elif brand_sim > 0.7 and not has_content:
        overall_score = max(overall_score, 75)
        print("   [ESCALATION] High brand similarity + unreachable = PHISHING risk")
    elif domain_score > 40 and not has_content:
        overall_score = max(overall_score, 60)
        print("   [ESCALATION] High domain risk + unreachable content")
    elif content_score >= 30 and url_score < 10 and domain_score < 10:
        overall_score = max(overall_score, 60)
        print("   [ESCALATION] Content risk high despite clean URL/domain")
    elif not has_content:
        overall_score = max(overall_score, 60)
        print("   [ESCALATION] Content unreachable – raising to moderate risk")
    
    return {
        "overall_score": overall_score,
        "url_score": url_score,
        "domain_score": domain_score,
        "content_score": content_score,
        "indicators_count": url_risks + domain_risks + content_risks,
        "total_checks": (url_checks + domain_checks + content_checks) * 2,
        "unreachable": unreachable,
    }


# Test URLs
test_urls = [
    "https://paypaI.com",       # Typo phishing
    "www.mmsdose.com",          # Content‑heavy phishing example
    "https://google.com",       # Legitimate
]

print("\n" + "="*70)
print("🔍 COMPREHENSIVE PHISHING SITE DETECTION SYSTEM - DEMO")
print("="*70)

for test_url in test_urls:
    print(f"\n\n{'#'*70}")
    print(f"Testing: {test_url}")
    print(f"{'#'*70}")
    
    # Extract features
    features = extract_realtime_features(test_url)
    df = pd.DataFrame([features])
    
    # Align with model
    if hasattr(model, "feature_names_in_"):
        expected = list(model.feature_names_in_)
        df = df.reindex(columns=expected, fill_value=0)
    
    # Get model prediction
    model_pred = model.predict(df)[0]
    model_confidence = model.predict_proba(df)[0]
    
    # Comprehensive analysis
    analysis = analyze_phishing_comprehensive(test_url, features)
    
    # Final verdict
    print("\n" + "="*70)
    print("📊 FINAL RISK ASSESSMENT")
    print("="*70)
    
    overall_risk = analysis["overall_score"]
    # ML escalation
    if model_pred == 1 and model_confidence[int(model_pred)] > 0.80:
        if overall_risk < 75:
            print("   [ML ESCALATION] Classifier strongly predicts phishing; overriding score")
        overall_risk = max(overall_risk, 75)
    print(f"\nOverall Risk Score: {overall_risk:.1f}%")
    print(f"  • URL Analysis Risk: {analysis['url_score']:.1f}%")
    print(f"  • Domain Analysis Risk: {analysis['domain_score']:.1f}%")
    print(f"  • Content Analysis Risk: {analysis['content_score']:.1f}%")
    
    print(f"\nSuspicious Indicators: {analysis['indicators_count']:.0f} / {analysis['total_checks']:.0f} checks failed")
    
    # Classification
    if overall_risk > 70:
        verdict = "🚨 PHISHING SITE - DO NOT VISIT"
        confidence_level = "CRITICAL"
    elif overall_risk > 50:
        verdict = "⚠️  SUSPICIOUS SITE - PROCEED WITH CAUTION"
        confidence_level = "HIGH"
    elif overall_risk > 30:
        verdict = "⚡ POTENTIALLY RISKY - USE CAUTION"
        confidence_level = "MODERATE"
    else:
        verdict = "✅ LIKELY LEGITIMATE"
        confidence_level = "LOW"
    
    print(f"\n{verdict}")
    print(f"Confidence: {confidence_level}")
    print(f"ML Model: {'PHISHING' if model_pred == 1 else 'LEGITIMATE'} ({model_confidence[int(model_pred)]:.1%})")

print(f"\n\n{'='*70}")
print("Demo Complete")
print(f"{'='*70}\n")
