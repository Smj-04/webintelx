import os
import re
import requests
import threading
from collections import defaultdict, Counter
import Levenshtein

DATA_FILE = os.path.join("data", "brands.txt")
_BRANDS = None
_TRIGRAM_INDEX = None
_INDEX_LOCK = threading.Lock()

TOP_DOMAINS_CSV = "https://datahub.io/core/top-domains/r/top-1m.csv"


def _read_local_brands():
    if not os.path.exists(DATA_FILE):
        return []
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        lines = [l.strip().lower() for l in f if l.strip()]
    return lines


def _fetch_top_domains(limit=1000):
    try:
        resp = requests.get(TOP_DOMAINS_CSV, timeout=5)
        resp.raise_for_status()
        lines = resp.text.splitlines()
        domains = []
        for line in lines:
            parts = line.split(",")
            if len(parts) == 2 and parts[1]:
                domains.append(parts[1].strip().lower())
        return domains[:limit]
    except Exception:
        return []


FALLBACK_BRANDS = [
    "google","youtube","facebook","twitter","instagram","linkedin","wikipedia","amazon",
    "yahoo","reddit","netflix","microsoft","apple","paypal","bing","ebay","stackoverflow",
    "github","gmail","wordpress","pinterest","tumblr","quora","imgur","aws","azure","dropbox",
    "slack","spotify","twitch","etsy","indeed","booking","airbnb","uber","alibaba",
    "wechat","whatsapp","zoom","skype","cnn","bbc","nytimes","forbes","medium","hulu",
    "discord","soundcloud","dribbble","behance","adobe","salesforce","shopify","mailchimp",
    "trello","notion","asana","bitbucket","digitalocean","heroku","stripe","mozilla",
    "oracle","intel","nvidia","yelp","tripadvisor","foursquare","bitly","slideshare",
    "scribd","ikea","target","walmart","bestbuy","homedepot","costco","dell","hp","lenovo",
    "asus","sony","samsung","xiaomi","huawei","coursera","edx","khanacademy",
    "stackexchange","docker","kubernetes","gitlab","medium","bankofamerica","chase",
    "wellsfargo","citibank","hsbc","barclays","coinbase","binance","kraken",
    "coinmarketcap","coindesk","techcrunch","wired","engadget","verge","gizmodo",
    "arstechnica","cnet","aliexpress","flipkart","paytm","zara","adidas","nike",
    "booking","expedia","agoda","trivago","hotels","airbnb","steam","roblox",
    "tiktok","telegram","snapchat","twitch","linkedin","pinterest",
]


def load_brands(min_count=1000, try_fetch=True):
    """Load brands from disk; fall back to built-in list if needed."""
    global _BRANDS
    if _BRANDS is not None:
        return _BRANDS

    brands = list(_read_local_brands())

    if try_fetch and len(brands) < min_count:
        fetched = _fetch_top_domains(limit=min_count)
        if fetched:
            combined = list(dict.fromkeys(brands + fetched))
            brands = combined[:min_count]
            try:
                with open(DATA_FILE, "w", encoding="utf-8") as f:
                    for d in brands:
                        f.write(d + "\n")
            except Exception:
                pass

    if len(brands) < min_count:
        for b in FALLBACK_BRANDS:
            if b not in brands:
                brands.append(b)

    # Normalise
    seen, cleaned = set(), []
    for b in brands:
        b = b.lower().strip()
        if b and b not in seen:
            seen.add(b)
            cleaned.append(b)

    _BRANDS = cleaned
    _build_trigram_index(_BRANDS)
    return _BRANDS


def _trigrams(s):
    s = f"  {s}  "
    return {s[i:i+3] for i in range(len(s) - 2)}


def _build_trigram_index(brands):
    global _TRIGRAM_INDEX
    with _INDEX_LOCK:
        index = defaultdict(list)
        for i, b in enumerate(brands):
            for t in _trigrams(b):
                index[t].append(i)
        _TRIGRAM_INDEX = index


def _candidate_indices_for(domain, top_k=20):
    if not _TRIGRAM_INDEX:
        return []
    counts = Counter()
    for t in _trigrams(domain):
        for idx in _TRIGRAM_INDEX.get(t, []):
            counts[idx] += 1
    if not counts:
        return []
    return [i for i, _ in counts.most_common(top_k)]


def brand_similarity(domain: str) -> float:
    """
    Return similarity score in [0, 1] between `domain` and the closest brand.

    KEY FIX: The domain is first split on hyphens, underscores, and digits.
    Each token is checked independently. This correctly handles:
      - "arnazon-support" → checks "arnazon" → 0.86 vs "amazon"
      - "ebay-v"          → checks "ebay"    → 1.0 exact match
      - "paypal-secure"   → checks "paypal"  → 1.0 exact match

    Without splitting, "arnazon-support" (15 chars) vs "amazon" (6 chars)
    gives similarity = 1 - 9/15 = 0.40, which misses the typosquat entirely.
    """
    global _BRANDS
    if _BRANDS is None:
        load_brands()

    domain = domain.lower().strip()

    # Exact full match
    if domain in _BRANDS:
        return 1.0

    # Split domain into meaningful tokens (drop tiny noise tokens like "v", "1")
    tokens = re.split(r"[-_.\d]+", domain)
    tokens = [t for t in tokens if len(t) >= 3]

    # Include the full domain as one of the tokens to check
    if domain not in tokens:
        tokens.append(domain)

    best_sim = 0.0

    for token in tokens:
        if token in _BRANDS:
            return 1.0  # exact token match

        candidates = _candidate_indices_for(token, top_k=50)
        if not candidates:
            candidates = range(len(_BRANDS))

        for i in candidates:
            b = _BRANDS[i]
            dist = Levenshtein.distance(token, b)
            sim = 1.0 - (dist / max(len(token), len(b), 1))
            if sim > best_sim:
                best_sim = sim

    return round(max(0.0, min(1.0, best_sim)), 4)


if __name__ == "__main__":
    # Quick tests
    tests = [
        ("arnazon-support", "amazon"),
        ("ebay-v",          "ebay"),
        ("paypal-secure",   "paypal"),
        ("secure-paypal-verify", "paypal"),
        ("google",          "google"),
        ("totally-not-phishing", None),
    ]
    load_brands()
    print("brand_similarity tests:")
    for domain, expected_brand in tests:
        sim = brand_similarity(domain)
        print(f"  {domain:<30} → {sim:.3f}  (expected match: {expected_brand})")