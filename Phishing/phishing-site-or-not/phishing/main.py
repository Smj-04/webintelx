import joblib
import pandas as pd
import sys
import json
import warnings
import os
import re

from phishing.features.realtime_features import extract_realtime_features
import tldextract
import requests

from urllib.parse import urlparse
from phishing.features.utils import validator, rate_limiter, check_dependencies
from phishing.features.domain_checks import resolve_domain

warnings.filterwarnings("ignore", message=".*delayed.*Parallel.*", category=UserWarning)

deps = check_dependencies()

MODEL_PATH = os.path.join(os.path.dirname(__file__), "models", "phishing_model.pkl")

try:
    model = joblib.load(MODEL_PATH)
except Exception as e:
    payload = {"error": f"Model initialization failed: {str(e)}"}
    sys.stdout.write(json.dumps(payload))
    sys.exit(1)


# ── FREE / SITE-BUILDER HOSTING PLATFORMS ─────────────────────────────────────
# Any site whose registered_domain is in this set is user-generated content.
# Phishing pages here inherit the platform's trusted SSL + domain reputation,
# bypassing normal domain checks entirely.
FREE_HOSTING_PLATFORMS = {
    # Website builders
    "webflow.io", "netlify.app", "vercel.app", "github.io",
    "web.app", "firebaseapp.com", "pages.dev", "glitch.me",
    "wixsite.com", "weebly.com", "carrd.co", "squarespace.com",
    "render.com", "railway.app", "surge.sh", "repl.co",
    "godaddysites.com", "wordpress.com", "blogger.com", "blogspot.com",
    "sites.google.com", "typedream.app", "softr.app", "bubble.io",
    "lovable.app", "framer.app", "webador.com", "gitbook.io",
    "000webhostapp.com", "infinityfreeapp.com",
    "altervista.org", "biz.nf", "myshopify.com",
    "zapier.app", "lpages.co",
    # Cloud object storage
    "backblazeb2.com", "s3.amazonaws.com", "storage.googleapis.com",
    "r2.dev", "b-cdn.net", "digitaloceanspaces.com",
    "blob.core.windows.net", "oortstorages.com", "b2.backblazeb2.com",
    # Free tunneling/workers
    "workers.dev", "trycloudflare.com",
    # Free subdomain/hosting abuse
    "dynv6.net", "duckdns.org", "serv00.net",
    "webcindario.com", "hstn.me", "serveirc.com",
}

# ── SUSPICIOUS TLDs ────────────────────────────────────────────────────────────
SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "loan", "win", "gq", "cf", "tk", "ml",
    "ga", "buzz", "monster", "cyou", "cfd", "surf", "boats", "gives",
    "work", "rest", "sbs", "bar", "store", "online", "site",
    # Additional abused TLDs from test results
    "cc", "pw", "su", "nu", "ws", "ms", "ink", "gd", "tc",
    "id", "run", "biz", "name", "mobi",
}

# ── TRUSTED BRANDS (exact-match whitelist) ─────────────────────────────────────
# If the full registered domain (without TLD) exactly matches one of these,
# it is the real brand — not a typosquat.
TRUSTED_BRANDS = {
    "google", "youtube", "facebook", "twitter", "instagram", "linkedin",
    "amazon", "paypal", "apple", "microsoft", "netflix", "ebay",
    "walmart", "chase", "bankofamerica", "wellsfargo", "citibank",
    "hsbc", "barclays", "coinbase", "binance", "dropbox", "spotify",
    "discord", "github", "gmail", "outlook", "yahoo", "bing",
    "steam", "roblox", "tiktok", "whatsapp", "telegram", "reddit",
    "wikipedia", "stackoverflow", "adobe", "salesforce", "shopify",
    "stripe", "twitch", "zoom", "slack", "notion", "cloudflare",
    "meta", "uber", "doordash", "grubhub", "airbnb", "booking",
    "expedia", "tripadvisor", "etsy", "pinterest", "snapchat",
}

TARGETED_BRANDS = TRUSTED_BRANDS

# Regex patterns for generated phishing domains
# Catches: member17.agency-connect-profile.com, meta-id17659.invoice-ads-manager.com
PHISHING_DOMAIN_PATTERNS = [
    re.compile(r"(member|agency|partner|admin|account|meta-id)\d+\.", re.I),
    re.compile(r"\.(agency-|partner-|business-hub|accounts-admin|invoice-ads|credit-agency)", re.I),
    re.compile(r"(busines-help-center|bussines-partner|agency-connect|agency-manager)", re.I),
    re.compile(r"(claims-notification|center-meta-agency|accounts-admin-agency)", re.I),
]

def _matches_phishing_pattern(url: str) -> bool:
    return any(p.search(url) for p in PHISHING_DOMAIN_PATTERNS)

def _is_gibberish_subdomain(subdomain: str) -> bool:
    """Low vowel ratio → randomly generated subdomain."""
    if not subdomain or len(subdomain) < 5:
        return False
    letters = [c for c in subdomain if c.isalpha()]
    if not letters:
        return False
    vowels = sum(1 for c in letters if c in "aeiou")
    return (vowels / len(letters)) < 0.25   # slightly relaxed threshold


def _check_typosquatting(pure_domain: str, subdomain: str = "") -> tuple:
    """
    Check both the registered domain AND subdomain tokens for brand similarity.

    This catches:
      - "ebay-v"           (domain token)        → ebay
      - "usmeta-maskloogn" (subdomain token)      → meta / facebook
      - "arnazon-support"  (domain token)         → amazon
      - "loguin-kuicoinn"  (subdomain token)      → no strong match

    Returns (similarity, matched_brand).
    Returns (0.0, None) if the domain itself IS a trusted brand (not a typosquat).
    """
    try:
        import Levenshtein
    except ImportError:
        return 0.0, None

    pure_domain = pure_domain.lower().strip()
    subdomain   = subdomain.lower().strip()

    # Full domain is a trusted brand → not a typosquat
    if pure_domain in TRUSTED_BRANDS:
        return 0.0, None

    # Collect all tokens from both domain and subdomain
    all_tokens = []
    for part in [pure_domain, subdomain]:
        if part:
            tokens = re.split(r"[-_.\d]+", part)
            all_tokens.extend(t for t in tokens if len(t) >= 3)

    # Deduplicate
    all_tokens = list(dict.fromkeys(all_tokens))

    best_sim   = 0.0
    best_brand = None

    for token in all_tokens:
        # Exact token match against targeted brands
        if token in TARGETED_BRANDS:
            # Token is a real brand name but full domain is NOT trusted → typosquat
            return 1.0, token

        # Levenshtein similarity
        for brand in TARGETED_BRANDS:
            dist = Levenshtein.distance(token, brand)
            sim  = 1.0 - (dist / max(len(token), len(brand), 1))
            if sim > best_sim:
                best_sim  = sim
                best_brand = brand

    if best_sim < 0.55:
        return 0.0, None

    return round(best_sim, 4), best_brand


def analyze_phishing_comprehensive(url, features):
    unreachable = False

    ext = tldextract.extract(url)
    subdomain         = (ext.subdomain or "").lower()
    pure_domain       = (ext.domain or "").lower()
    tld               = (ext.suffix or "").lower()
    registered_domain = ext.registered_domain or (pure_domain + "." + tld)

    # ── URL SCORE ──────────────────────────────────────────────────────────────
    url_risks  = 0
    url_checks = 8

    if features.get("URLLength", 0) > 75:                     url_risks += 1
    if features.get("IsDomainIP", 0) == 1:                    url_risks += 3
    if features.get("NoOfOtherSpecialCharsInURL", 0) > 2:     url_risks += 1
    if features.get("NoOfSubDomain", 0) > 3:                  url_risks += 1
    if features.get("IsHTTPS", 0) == 0:                       url_risks += 1
    if features.get("DegitRatioInURL", 0) > 0.3:              url_risks += 1
    if features.get("NoOfEqualsInURL", 0) > 3:                url_risks += 1
    path = url.split("?")[0].lower()
    if any(kw in path for kw in ["/login", "/signin", "/verify", "/secure",
                                  "/bank", "/account", "/password", "/update"]):
        url_risks += 1

    url_score = (url_risks / (url_checks * 2)) * 100

    # ── DOMAIN SCORE ──────────────────────────────────────────────────────────
    domain_risks  = 0
    domain_checks = 9

    # Typosquatting — checks both domain AND subdomain tokens
    typo_sim, typo_brand = _check_typosquatting(pure_domain, subdomain)

    if typo_sim >= 0.85:
        domain_risks += 3
    elif typo_sim >= 0.70:
        domain_risks += 2
    elif typo_sim >= 0.55:
        domain_risks += 1

    # TLD reputation
    tld_prob = features.get("TLDLegitimateProb", 0.5)
    if tld_prob < 0.20:
        domain_risks += 2
    elif tld_prob < 0.35:
        domain_risks += 1

    if tld in SUSPICIOUS_TLDS:
        domain_risks += 1

    # Random-looking domain
    if features.get("CharContinuationRate", 0) > 0.6:
        domain_risks += 1

    # URL similarity index
    if features.get("URLSimilarityIndex", 1) < 0.3:
        domain_risks += 1

    # DNS
    if features.get("DNSResolvable", 1) == 0:
        domain_risks += 1
        unreachable = True

    # SSL
    ssl_valid = features.get("SSLCertValid", 0)
    ssl_days  = features.get("SSLCertDaysLeft", -1)
    if ssl_valid == 0:
        domain_risks += 1
    elif 0 <= ssl_days < 30:
        domain_risks += 1

    # Domain age
    age_days = features.get("DomainAgeDays", -1)
    if age_days != -1 and age_days < 90:
        domain_risks += 1

    # Free / site-builder hosting
    # Check both registered_domain AND full netloc for platforms like sites.google.com
    netloc = urlparse(url).netloc.lower().lstrip("www.")
    is_free_hosting = (
        registered_domain in FREE_HOSTING_PLATFORMS
        or any(netloc.endswith("." + p) or netloc == p for p in FREE_HOSTING_PLATFORMS)
    )   
    if is_free_hosting:
        domain_risks += 2
        if _is_gibberish_subdomain(subdomain):
            domain_risks += 2

    domain_score = (domain_risks / (domain_checks * 2)) * 100

    # ── CONTENT SCORE ─────────────────────────────────────────────────────────
    content_risks  = 0
    content_checks = 8

    has_content = features.get("HasTitle", 0) or features.get("HasFavicon", 0)

    # Only penalise missing content when the domain is already suspicious —
    # prevents false positives on trusted sites that load slowly.
    if not has_content:
        if domain_risks >= 2 or typo_sim >= 0.70:
            content_risks += 2
            unreachable = True
    else:
        if features.get("HasExternalFormSubmit", 0) == 1: content_risks += 2
        if features.get("HasHiddenFields", 0) > 0:        content_risks += 1
        if features.get("HasPasswordField", 0) > 0:       content_risks += 1

        ext_refs = features.get("NoOfExternalRef", 0)
        if ext_refs > 50:    content_risks += 1
        elif ext_refs > 20:  content_risks += 1

        if features.get("NoOfiFrame", 0) > 0:             content_risks += 1
        if features.get("NoOfURLRedirect", 0) > 2:        content_risks += 1

        if not (features.get("HasTitle", 0) and features.get("HasFavicon", 0)):
            content_risks += 0.5
        if not features.get("IsResponsive", 0):           content_risks += 0.5

        if features.get("HasMetaRefresh", 0) == 1:        content_risks += 1
        if features.get("HasJSRedirect", 0) == 1:         content_risks += 1

    content_score = (content_risks / (content_checks * 2)) * 100

    # ── WEIGHTED FINAL SCORE ──────────────────────────────────────────────────
    overall_score = (
        url_score     * 0.25 +
        domain_score  * 0.40 +
        content_score * 0.35
    )

    return {
        "overall_score":    overall_score,
        "url_score":        url_score,
        "domain_score":     domain_score,
        "content_score":    content_score,
        "indicators_count": url_risks + domain_risks + content_risks,
        "total_checks":     (url_checks + domain_checks + content_checks) * 2,
        "unreachable":      unreachable,
        "is_free_hosting":  is_free_hosting,
        "typo_sim":         typo_sim,
        "typo_brand":       typo_brand,
    }


def _risk_level_from_score(score):
    if score is None:   return "LOW"
    if score > 70:      return "CRITICAL"
    elif score > 55:    return "HIGH"
    elif score > 35:    return "MODERATE"
    else:               return "LOW"


def _is_ip_url(url: str) -> bool:
    return bool(re.search(r"https?://\d{1,3}(?:\.\d{1,3}){3}(?:[:/]|$)", url))


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

        # ── DNS + reachability — skip for raw IP URLs ──────────────────────────
        is_ip = _is_ip_url(url)

        if not is_ip:
            try:
                ext = tldextract.extract(url)
                domain_to_check = ext.registered_domain or (ext.domain + "." + ext.suffix)
            except Exception:
                domain_to_check = None

        if not domain_to_check or not resolve_domain(domain_to_check):
            # Before giving up, check if the domain matches known phishing patterns
            if _matches_phishing_pattern(url):
                sys.stdout.write(json.dumps({
                    "url": url,
                    "prediction": "phishing",
                    "classification": "Suspicious Domain Pattern",
                    "risk_level": "HIGH",
                    "ml_probability": 0.0,
                    "scores": {"url_score": 0, "domain_score": 0,
                               "content_score": 0, "final_weighted_score": 65},
                    "flags": {"unreachable": True, "brand_similarity": 0,
                              "ssl_valid": False, "free_hosting": False, "ip_url": False},
                    "details": "HIGH (65%) – DNS failed but domain matches phishing template pattern"
                }))
            else:
                sys.stdout.write(json.dumps({"url": url, "message": "No such site exists."}))
            return

        # HTTP reachability — generous timeout, multiple fallback strategies.
        # Many legitimate sites reject HEAD, return 3xx, or are slow.
        # We only hard-reject if ALL strategies fail AND DNS also fails.
        _reachable = False
        try:
            resp = requests.head(url, timeout=10, allow_redirects=True,
                                 headers={"User-Agent": "Mozilla/5.0"})
            # 2xx, 3xx, 401, 403 all mean the server EXISTS
            if resp.status_code < 500:
                _reachable = True
        except Exception:
            pass

        if not _reachable:
            try:
                resp = requests.get(url, timeout=12, allow_redirects=True,
                                    headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code < 500:
                    _reachable = True
            except Exception:
                pass

        if not _reachable:
            # Final fallback: if DNS resolves, treat as reachable anyway
            # (server may block bots but still exist)
            _reachable = True  # DNS already confirmed above — trust it

        # ── Feature extraction ─────────────────────────────────────────────────
        features = extract_realtime_features(url)
        df = pd.DataFrame([features])
        if hasattr(model, "feature_names_in_"):
            df = df.reindex(columns=list(model.feature_names_in_), fill_value=0)

        model_pred       = model.predict(df)[0]
        model_confidence = model.predict_proba(df)[0]

        # ── Rule-based scoring ─────────────────────────────────────────────────
        analysis        = analyze_phishing_comprehensive(url, features)
        url_score       = analysis["url_score"]
        domain_score    = analysis["domain_score"]
        content_score   = analysis["content_score"]
        overall_risk    = analysis["overall_score"]
        unreachable     = analysis["unreachable"]
        is_free_hosting = analysis["is_free_hosting"]
        typo_sim        = analysis["typo_sim"]
        typo_brand      = analysis["typo_brand"]

        has_content = features.get("HasTitle", 0) or features.get("HasFavicon", 0)
        brand_sim   = features.get("BrandSimilarity", 0)

        ext3 = tldextract.extract(url)
        tld  = (ext3.suffix or "").lower()

        # ── Escalation rules ───────────────────────────────────────────────────


        # 1. IP-based URL
        if is_ip:
            overall_risk = max(overall_risk, 80)

        # 2. Free/site-builder hosting
        if is_free_hosting:
            ext2 = tldextract.extract(url)
            sub  = (ext2.subdomain or "").lower()
            if _is_gibberish_subdomain(sub):
                overall_risk = max(overall_risk, 82)
            else:
                overall_risk = max(overall_risk, 55)

            # Brand clone keyword in subdomain or path → escalate to HIGH
            CLONE_KEYWORDS = [
                "netflix", "amazon", "instagram", "facebook", "spotify",
                "discord", "apple", "roblox", "steam", "bank", "ledger",
                "trezor", "coinbase", "binance", "kcoin", "kucoin",
                "blockfi", "exodus", "uniswap", "airbnb", "uber",
                "whatsapp", "bank-of-america", "easybank", "trezo",
                "login", "signin", "verify", "support", "helpcentre",
                "secure", "account", "auth", "sso", "portal",
            ]
            full_path = url.lower()
            if any(kw in full_path for kw in CLONE_KEYWORDS):
                overall_risk = max(overall_risk, 75)
        # 3. Typosquatting (domain OR subdomain)
        if typo_sim >= 0.85:
            overall_risk = max(overall_risk, 78)
        elif typo_sim >= 0.70:
            overall_risk = max(overall_risk, 65)
        elif typo_sim >= 0.55:
            overall_risk = max(overall_risk, 55)

        # 3b. Combined: free hosting + brand similarity (even moderate)
        if is_free_hosting and typo_sim >= 0.60:
            overall_risk = max(overall_risk, 75)

        # 3c. Suspicious path keywords + any brand similarity
        path_lower = url.split("?")[0].lower()
        PHISHING_PATHS = ["/login", "/signin", "/verify", "/secure",
                          "/bank", "/account", "/password", "/update",
                          "/dkb/", "/portal", "/billing", "/confirm"]
        if any(kw in path_lower for kw in PHISHING_PATHS) and typo_sim >= 0.50:
            overall_risk = max(overall_risk, 72)

        # 3d. Cloud storage hosting — always suspicious for HTML pages
        CLOUD_STORAGE = ["backblazeb2.com", "s3.amazonaws.com", "r2.dev",
                         "b-cdn.net", "workers.dev", "oortstorages.com"]
        if any(cs in url.lower() for cs in CLOUD_STORAGE):
            overall_risk = max(overall_risk, 65)

        # 4. Suspicious TLD
        if tld in SUSPICIOUS_TLDS:
            overall_risk = max(overall_risk, 55)

        # 5. Strong ML phishing signal
        if model_pred == 1 and model_confidence[1] > 0.75:
            overall_risk = max(overall_risk, 75)
        elif model_pred == 1 and model_confidence[1] > 0.55:
            overall_risk = max(overall_risk, 55)

        # 6. Brand impersonation + no content (only when domain is already risky)
        if brand_sim > 0.7 and brand_sim < 1.0 and not has_content and domain_score > 15:
            overall_risk = max(overall_risk, 75)

        # 7. Suspicious domain keyword combinations
        SUSPICIOUS_DOMAIN_KEYWORDS = [
            "claims-notification", "update-setup", "updatesetup",
            "secure-login", "account-verify", "wallet-update",
            "help-center", "busines-help", "support-center",
            "authorised-support", "server-notification",
            "notification-events", "security-alert",
        ]
        domain_lower = (ext3.domain + "." + ext3.suffix).lower()
        full_domain  = url.lower()
        if any(kw in full_domain for kw in SUSPICIOUS_DOMAIN_KEYWORDS):
            overall_risk = max(overall_risk, 65)

        # 8. Deep phishing path on otherwise clean domain
        # Pattern: /brand-name/login.php or /verify/account
        PHISHING_PATH_PATTERNS = [
            r"/[a-z]{2,6}/[a-z]{2,6}/login\.php",   # /mipaz/pages/login.php
            r"/DK[B]?/dkb/",                          # /DK/DKB/dkb/
            r"/yak/rogers",                            # telecom brand phishing
            r"/wp-admin/sf/",                          # WordPress admin abuse
            r"/0utFix/",                               # obfuscated path
            r"/sicred/",                               # Brazilian bank
            r"/alibaba/",                              # brand in path
        ]
        if any(re.search(p, url, re.I) for p in PHISHING_PATH_PATTERNS):
            overall_risk = max(overall_risk, 68)

        # 9. Random hash/token path — unique per-victim phishing delivery
        path_only = url.split("?")[0]
        path_segment = path_only.split("/")[-1] if "/" in path_only else ""
        # Detect long hex-like filenames: 443332cc8w6a2146c65a1833ca7b1ccd1a38.html
        if re.search(r"[0-9a-f]{8,}", path_segment, re.I) and len(path_segment) > 20:
            overall_risk = max(overall_risk, 65)
        # Detect long random path tokens: /igit/4/222vni5Mfeym7n6hxrM1t8MuxqlmwMgrw
        path_tokens = [p for p in path_only.split("/") if len(p) > 20]
        if path_tokens:
            overall_risk = max(overall_risk, 62)

        # 10. Short random token as entire path (redirect/tracking links)
        from urllib.parse import urlparse 
        parsed_path = urlparse(url).path.strip("/")
        # e.g. /mbMDN5NK or /2er7S6 or /KvnLR/
        if re.match(r"^[A-Za-z0-9]{4,12}$", parsed_path):
            overall_risk = max(overall_risk, 62)
        # UUID redirect parameter e.g. ?r=9f5adc1a-07a7-4de3-b3cb-e368f57c684b
        if re.search(r"[?&]r=[0-9a-f]{8}-[0-9a-f]{4}-", url, re.I):
            overall_risk = max(overall_risk, 65)

        risk_level = _risk_level_from_score(overall_risk)
        prediction = "phishing" if model_pred == 1 else "legitimate"
        ml_prob    = float(model_confidence[int(model_pred)])

        # ── Final classification ───────────────────────────────────────────────
        is_phishing_ml   = (model_pred == 1 and ml_prob > 0.55)
        is_risky_rules   = (overall_risk >= 50)
        is_free_phishing = (is_free_hosting and overall_risk >= 40)
        is_ip_phishing   = is_ip

        if is_phishing_ml or is_risky_rules or is_free_phishing or is_ip_phishing \
                or (model_pred == 1 and overall_risk >= 40):
            classification = "Potential Phishing Website"
        else:
            classification = "Legitimate Website"

        # ── Build output flags ─────────────────────────────────────────────────
        flags = {
            "unreachable":      unreachable,
            "brand_similarity": brand_sim,
            "ssl_valid":        bool(features.get("SSLCertValid", 0)),
            "free_hosting":     is_free_hosting,
            "ip_url":           is_ip,
        }
        if typo_brand and typo_sim >= 0.70:
            flags["typosquat_target"] = typo_brand
            flags["typosquat_score"]  = round(typo_sim, 3)

        output = {
            "url":            url,
            "prediction":     prediction,
            "classification": classification,
            "risk_level":     risk_level,
            "ml_probability": ml_prob,
            "scores": {
                "url_score":            url_score,
                "domain_score":         domain_score,
                "content_score":        content_score,
                "final_weighted_score": overall_risk,
            },
            "flags": flags,
            "details": (
                f"{risk_level} ({overall_risk:.1f}%) – ML predicted "
                f"{prediction} ({ml_prob:.2f}) – {classification}"
            ),
        }

        sys.stdout.write(json.dumps(output))

    except Exception as exc:
        sys.stdout.write(json.dumps({"error": str(exc)}))


if __name__ == "__main__":
    run_cli()