import Levenshtein
import tldextract
import re
import requests
from bs4 import BeautifulSoup
import socket
import ssl
import asyncio
try:
    import aiohttp
except Exception:
    aiohttp = None

from phishing.features.brand_detection import brand_similarity
from phishing.features.domain_checks import resolve_domain, get_ssl_days_left, get_domain_age_days


async def _fetch_content_async(url, timeout=5):
    if aiohttp is None:
        # fallback to requests in sync mode
        try:
            r = requests.get(url, timeout=timeout)
            return r.text, len(r.history)
        except Exception:
            return None, 0

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=timeout) as resp:
                text = await resp.text()
                # aiohttp exposes history via resp.history
                history_len = len(getattr(resp, "history", []))
                return text, history_len
    except Exception:
        return None, 0


def extract_realtime_features(url):
    """Sync wrapper that runs async fetch internally to avoid blocking main flow."""
    return asyncio.run(extract_realtime_features_async(url))


async def extract_realtime_features_async(url):
    features = {}

    # =========================
    # 1. URL ANALYSIS
    # =========================
    features["URLLength"] = len(url)
    features["IsDomainIP"] = 1 if re.search(r"\d+\.\d+\.\d+\.\d+", url) else 0

    ext = tldextract.extract(url)
    subdomain = ext.subdomain
    features["NoOfSubDomain"] = len(subdomain.split(".")) if subdomain else 0
    features["IsHTTPS"] = 1 if url.startswith("https") else 0

    features["NoOfOtherSpecialCharsInURL"] = len(re.findall(r"[@\-//]", url))
    features["SpacialCharRatioInURL"] = features["NoOfOtherSpecialCharsInURL"] / max(len(url), 1)

    features["NoOfLettersInURL"] = sum(c.isalpha() for c in url)
    features["LetterRatioInURL"] = features["NoOfLettersInURL"] / max(len(url), 1)

    features["NoOfDegitsInURL"] = sum(c.isdigit() for c in url)
    features["DegitRatioInURL"] = features["NoOfDegitsInURL"] / max(len(url), 1)

    features["NoOfEqualsInURL"] = url.count("=")
    features["NoOfQMarkInURL"] = url.count("?")
    features["NoOfAmpersandInURL"] = url.count("&")

    # =========================
    # 2. DOMAIN ANALYSIS
    # =========================
    domain = ext.domain + "." + ext.suffix
    pure_domain = ext.domain

    features["DomainLength"] = len(domain)
    features["TLDLength"] = len(ext.suffix)

    # DNS availability
    try:
        features["DNSResolvable"] = 1 if resolve_domain(ext.registered_domain) else 0
    except Exception:
        features["DNSResolvable"] = 0

    # SSL certificate validity (days left)
    try:
        days = get_ssl_days_left(ext.registered_domain)
        features["SSLCertDaysLeft"] = days if days is not None else -1
        features["SSLCertValid"] = 1 if (days is not None and days > 0) else 0
    except Exception:
        features["SSLCertDaysLeft"] = -1
        features["SSLCertValid"] = 0

    # Domain age via WHOIS (days). None if whois lib not installed or lookup fails
    try:
        age_days = get_domain_age_days(ext.registered_domain)
        features["DomainAgeDays"] = age_days if age_days is not None else -1
    except Exception:
        features["DomainAgeDays"] = -1

    # NEW FEATURE: TYPO / BRAND ATTACK DETECTION
    features["BrandSimilarity"] = brand_similarity(pure_domain)

    # Dummy values (advanced features require WHOIS / DNS)
    features["TLDLegitimateProb"] = 0.5
    features["URLSimilarityIndex"] = 0.5
    features["CharContinuationRate"] = 0.5
    features["URLCharProb"] = 0.5

    # =========================
    # 3. CONTENT ANALYSIS
    # =========================
    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.text, "html.parser")

        features["HasTitle"] = 1 if soup.title else 0
        features["HasFavicon"] = 1 if soup.find("link", rel="icon") else 0
        features["Robots"] = 1 if soup.find("meta", attrs={"name": "robots"}) else 0
        features["IsResponsive"] = 1 if soup.find("meta", attrs={"name": "viewport"}) else 0

        features["NoOfURLRedirect"] = len(r.history)
        features["NoOfPopup"] = len(soup.find_all("script"))
        features["NoOfiFrame"] = len(soup.find_all("iframe"))
        features["HasExternalFormSubmit"] = 1 if soup.find("form", action=re.compile("http")) else 0
        features["HasHiddenFields"] = len(soup.find_all("input", type="hidden"))
        features["HasPasswordField"] = len(soup.find_all("input", type="password"))

        features["NoOfExternalRef"] = len(soup.find_all("a", href=re.compile("http")))
        features["NoOfJS"] = len(soup.find_all("script"))
        features["NoOfCSS"] = len(soup.find_all("link", rel="stylesheet"))
        features["NoOfImage"] = len(soup.find_all("img"))
        # Meta refresh
        features["HasMetaRefresh"] = 1 if soup.find("meta", attrs={"http-equiv": re.compile("refresh", re.I)}) else 0
        # Basic JS redirection detection (search script tags for location assignment)
        js_redirect = 0
        for s in soup.find_all("script"):
            text = s.string or ""
            if "window.location" in text or "location.href" in text or "location.replace" in text:
                js_redirect = 1
                break
        features["HasJSRedirect"] = js_redirect
        return features

    except:
        # If site not reachable, set default values
        # fetch page content asynchronously
        content, history_len = await _fetch_content_async(url)
        if content is None:
            # set defaults when unreachable
            for key in [
                "HasTitle","HasFavicon","Robots","IsResponsive","NoOfURLRedirect",
                "NoOfPopup","NoOfiFrame","HasExternalFormSubmit","HasHiddenFields",
                "HasPasswordField","NoOfExternalRef","NoOfJS","NoOfCSS","NoOfImage",
                "HasMetaRefresh","HasJSRedirect"
            ]:
                features[key] = 0
            features["NoOfURLRedirect"] = history_len
            return features

        soup = BeautifulSoup(content, "html.parser")
        features["HasTitle"] = 1 if soup.title else 0
        features["HasFavicon"] = 1 if soup.find("link", rel="icon") else 0
        features["Robots"] = 1 if soup.find("meta", attrs={"name": "robots"}) else 0
        features["IsResponsive"] = 1 if soup.find("meta", attrs={"name": "viewport"}) else 0

        features["NoOfURLRedirect"] = history_len
        features["NoOfPopup"] = len(soup.find_all("script"))
        features["NoOfiFrame"] = len(soup.find_all("iframe"))
        features["HasExternalFormSubmit"] = 1 if soup.find("form", action=re.compile("http")) else 0
        features["HasHiddenFields"] = len(soup.find_all("input", type="hidden"))
        features["HasPasswordField"] = len(soup.find_all("input", type="password"))

        features["NoOfExternalRef"] = len(soup.find_all("a", href=re.compile("http")))
        features["NoOfJS"] = len(soup.find_all("script"))
        features["NoOfCSS"] = len(soup.find_all("link", rel="stylesheet"))
        features["NoOfImage"] = len(soup.find_all("img"))

        # Meta refresh
        features["HasMetaRefresh"] = 1 if soup.find("meta", attrs={"http-equiv": re.compile("refresh", re.I)}) else 0
        # Basic JS redirection detection
        js_redirect = 0
        for s in soup.find_all("script"):
            text = s.string or ""
            if "window.location" in text or "location.href" in text or "location.replace" in text:
                js_redirect = 1
                break
        features["HasJSRedirect"] = js_redirect

        return features
