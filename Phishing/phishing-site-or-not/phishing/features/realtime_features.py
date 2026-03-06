# realtime_features.py — Fixed version
# Changes:
#   - Removed dead async code (requests.get already runs sync; aiohttp fallback never triggered)
#   - Computed TLDLegitimateProb, URLSimilarityIndex, CharContinuationRate, URLCharProb properly
#   - Added free hosting platform detection
#   - Cleaned up duplicate content-parsing logic into one shared function

import re
import math
import socket
import string
import requests
import tldextract
from collections import Counter
from bs4 import BeautifulSoup

from phishing.features.brand_detection import brand_similarity
from phishing.features.domain_checks import resolve_domain, get_ssl_days_left, get_domain_age_days


# ── FREE HOSTING PLATFORMS ─────────────────────────────────────────────────────
# Sites hosted on these platforms inherit the platform's trusted domain reputation,
# which causes the ML model to miss phishing pages hosted on them.
FREE_HOSTING_PLATFORMS = {
    "webflow.io", "netlify.app", "github.io", "glitch.me",
    "vercel.app", "web.app", "firebaseapp.com", "pages.dev",
    "wixsite.com", "weebly.com", "squarespace.com", "carrd.co",
    "render.com", "railway.app", "surge.sh", "repl.co",
}

# ── TLD REPUTATION TABLE ───────────────────────────────────────────────────────
# Probability that a given TLD is used by legitimate sites (empirically derived).
# Lower = more likely to be abused by phishing.
TLD_LEGIT_PROB = {
    "com": 0.85, "org": 0.80, "net": 0.75, "edu": 0.95, "gov": 0.98,
    "uk": 0.82,  "de": 0.83,  "fr": 0.82,  "jp": 0.84, "au": 0.83,
    "ca": 0.83,  "io": 0.60,  "co": 0.55,  "info": 0.40, "biz": 0.35,
    "xyz": 0.20, "top": 0.20, "click": 0.15, "loan": 0.10, "win": 0.15,
    "gq":  0.10, "cf":  0.10, "tk":  0.10,  "ml": 0.10,  "ga": 0.10,
    "online": 0.30, "site": 0.30, "live": 0.30, "club": 0.25,
    "app": 0.65, "dev": 0.65, "ai": 0.65,
}

# ── HELPERS ────────────────────────────────────────────────────────────────────

def _char_continuation_rate(domain: str) -> float:
    """
    Measures how 'smooth' the character sequence is.
    High values suggest keyboard-walk patterns (aaabbbccc) common in
    randomly generated phishing domains.
    """
    if len(domain) < 2:
        return 0.0
    runs = 1
    for i in range(1, len(domain)):
        if domain[i] == domain[i - 1]:
            runs += 1
    return runs / len(domain)


def _url_char_prob(url: str) -> float:
    """
    Shannon entropy of characters in the URL, normalised to [0, 1].
    Very high entropy (random-looking URLs) is a phishing signal.
    Returns the *inverse* so that 1.0 = low entropy (normal) and
    0.0 = high entropy (suspicious).
    """
    if not url:
        return 1.0
    counts = Counter(url)
    length = len(url)
    entropy = -sum((c / length) * math.log2(c / length) for c in counts.values())
    max_entropy = math.log2(len(counts)) if len(counts) > 1 else 1.0
    normalised = entropy / max_entropy if max_entropy > 0 else 0.0
    # Invert: low entropy → high prob of legitimate
    return round(1.0 - normalised, 4)


def _url_similarity_index(url: str, domain: str) -> float:
    """
    Measures how much of the URL is just the domain (simple ≈ legitimate).
    A URL like https://paypal-secure-login.com/verify/account/confirm
    has a low similarity index because most of the URL is suspicious path.
    """
    if not url or not domain:
        return 0.5
    domain_part = domain.lower()
    url_lower = url.lower()
    if domain_part not in url_lower:
        return 0.3
    domain_proportion = len(domain_part) / len(url_lower)
    return round(min(domain_proportion * 1.5, 1.0), 4)


def _parse_page(html: str) -> dict:
    """Shared BeautifulSoup parsing to avoid running it twice."""
    soup = BeautifulSoup(html, "html.parser")
    js_redirect = 0
    for s in soup.find_all("script"):
        text = s.string or ""
        if "window.location" in text or "location.href" in text or "location.replace" in text:
            js_redirect = 1
            break
    return {
        "HasTitle":             1 if soup.title else 0,
        "HasFavicon":           1 if soup.find("link", rel="icon") else 0,
        "Robots":               1 if soup.find("meta", attrs={"name": "robots"}) else 0,
        "IsResponsive":         1 if soup.find("meta", attrs={"name": "viewport"}) else 0,
        "NoOfPopup":            len(soup.find_all("script")),
        "NoOfiFrame":           len(soup.find_all("iframe")),
        "HasExternalFormSubmit":1 if soup.find("form", action=re.compile("http")) else 0,
        "HasHiddenFields":      len(soup.find_all("input", type="hidden")),
        "HasPasswordField":     len(soup.find_all("input", type="password")),
        "NoOfExternalRef":      len(soup.find_all("a", href=re.compile("http"))),
        "NoOfJS":               len(soup.find_all("script")),
        "NoOfCSS":              len(soup.find_all("link", rel="stylesheet")),
        "NoOfImage":            len(soup.find_all("img")),
        "HasMetaRefresh":       1 if soup.find("meta", attrs={"http-equiv": re.compile("refresh", re.I)}) else 0,
        "HasJSRedirect":        js_redirect,
    }


def _default_content_features() -> dict:
    """Used when the page is unreachable."""
    return {
        "HasTitle": 0, "HasFavicon": 0, "Robots": 0, "IsResponsive": 0,
        "NoOfURLRedirect": 0, "NoOfPopup": 0, "NoOfiFrame": 0,
        "HasExternalFormSubmit": 0, "HasHiddenFields": 0, "HasPasswordField": 0,
        "NoOfExternalRef": 0, "NoOfJS": 0, "NoOfCSS": 0, "NoOfImage": 0,
        "HasMetaRefresh": 0, "HasJSRedirect": 0,
    }


# ── MAIN EXTRACTOR ─────────────────────────────────────────────────────────────

def extract_realtime_features(url: str) -> dict:
    features = {}

    # ── 1. URL ANALYSIS ────────────────────────────────────────────────────────
    features["URLLength"] = len(url)
    features["IsDomainIP"] = 1 if re.search(r"\d+\.\d+\.\d+\.\d+", url) else 0

    ext = tldextract.extract(url)
    subdomain   = ext.subdomain or ""
    pure_domain = ext.domain or ""
    tld         = ext.suffix or ""

    features["NoOfSubDomain"]            = len(subdomain.split(".")) if subdomain else 0
    features["IsHTTPS"]                  = 1 if url.startswith("https") else 0
    features["NoOfOtherSpecialCharsInURL"]= len(re.findall(r"[@\-//]", url))
    features["SpacialCharRatioInURL"]    = features["NoOfOtherSpecialCharsInURL"] / max(len(url), 1)
    features["NoOfLettersInURL"]         = sum(c.isalpha() for c in url)
    features["LetterRatioInURL"]         = features["NoOfLettersInURL"] / max(len(url), 1)
    features["NoOfDegitsInURL"]          = sum(c.isdigit() for c in url)
    features["DegitRatioInURL"]          = features["NoOfDegitsInURL"] / max(len(url), 1)
    features["NoOfEqualsInURL"]          = url.count("=")
    features["NoOfQMarkInURL"]           = url.count("?")
    features["NoOfAmpersandInURL"]       = url.count("&")

    # ── 2. DOMAIN ANALYSIS ────────────────────────────────────────────────────
    registered_domain = ext.registered_domain or (pure_domain + "." + tld)

    features["DomainLength"] = len(registered_domain)
    features["TLDLength"]    = len(tld)

    # DNS
    try:
        features["DNSResolvable"] = 1 if resolve_domain(registered_domain) else 0
    except Exception:
        features["DNSResolvable"] = 0

    # SSL
    try:
        days = get_ssl_days_left(registered_domain)
        features["SSLCertDaysLeft"] = days if days is not None else -1
        features["SSLCertValid"]    = 1 if (days is not None and days > 0) else 0
    except Exception:
        features["SSLCertDaysLeft"] = -1
        features["SSLCertValid"]    = 0

    # Domain age
    try:
        age = get_domain_age_days(registered_domain)
        features["DomainAgeDays"] = age if age is not None else -1
    except Exception:
        features["DomainAgeDays"] = -1

    # Brand similarity
    features["BrandSimilarity"] = brand_similarity(pure_domain)

    # ── COMPUTED features (previously hardcoded to 0.5) ──────────────────────
    features["TLDLegitimateProb"]   = TLD_LEGIT_PROB.get(tld.lower(), 0.25)
    features["CharContinuationRate"]= _char_continuation_rate(pure_domain)
    features["URLCharProb"]         = _url_char_prob(url)
    features["URLSimilarityIndex"]  = _url_similarity_index(url, registered_domain)

    # ── FREE HOSTING PLATFORM FLAG ────────────────────────────────────────────
    # Phishing pages on trusted platforms (webflow.io, netlify.app etc.) bypass
    # domain reputation checks because the registered domain looks legitimate.
    features["IsOnFreeHosting"] = 1 if registered_domain in FREE_HOSTING_PLATFORMS else 0

    # ── 3. CONTENT ANALYSIS ───────────────────────────────────────────────────
    try:
        r = requests.get(url, timeout=7, allow_redirects=True)
        content_features = _parse_page(r.text)
        content_features["NoOfURLRedirect"] = len(r.history)
        features.update(content_features)
    except Exception:
        features.update(_default_content_features())

    return features