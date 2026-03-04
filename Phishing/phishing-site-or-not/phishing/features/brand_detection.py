import os
import requests
import threading
from collections import defaultdict, Counter
import Levenshtein

DATA_FILE = os.path.join("data", "brands.txt")
_BRANDS = None
_TRIGRAM_INDEX = None
_INDEX_LOCK = threading.Lock()

# Public source to try if local brands list is small (CSV of domains)
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
        # CSV contains rank,domain; skip header if present
        domains = []
        for line in lines:
            parts = line.split(",")
            if len(parts) == 2 and parts[1]:
                domains.append(parts[1].strip().lower())
        return domains[:limit]
    except Exception:
        return []


def load_brands(min_count=1000, try_fetch=True):
    """Load brands from disk; if not enough entries and `try_fetch` is True,
    attempt to download a public top-domains CSV and persist the top `min_count`.
    Returns the list of brands (lowercased, unique).
    """
    global _BRANDS
    if _BRANDS is not None:
        return _BRANDS

    brands = []
    brands.extend(_read_local_brands())

    # Built-in fallback (200 common domains) used when fetch/network unavailable
    FALLBACK_BRANDS = [
        "google","youtube","facebook","twitter","instagram","linkedin","wikipedia","amazon",
        "yahoo","reddit","netflix","microsoft","apple","paypal","bing","ebay","stackoverflow",
        "github","gmail","wordpress","pinterest","tumblr","quora","imgur","aws","azure","dropbox",
        "slack","spotify","twitch","etsy","indeed","booking","airbnb","uber","paypal","alibaba",
        "wechat","whatsapp","zoom","skype","cnn","bbc","nytimes","forbes","medium","hulu",
        "discord","soundcloud","dribbble","behance","adobe","salesforce","shopify","mailchimp",
        "trello","notion","asana","bitbucket","digitalocean","heroku","stripe","mozilla","mozilla.org",
        "oracle","intel","nvidia","intel","cnn","bbc","theguardian","msn","msnbc","yelp",
        "tripadvisor","foursquare","yahoo.co.jp","t.co","bitly","slideshare","scribd","etsy",
        "ebay.co.uk","ikea","target","walmart","bestbuy","homedepot","costco","sears","dell",
        "hp","lenovo","asus","sony","samsung","xiaomi","huawei","htc","nokia","motorola",
        "play.google","apps.apple","britannica","nih","cdc","who","irs","gov","state","edu",
        "mit","stanford","harvard","ox.ac.uk","cam.ac.uk","coursera","edx","khanacademy",
        "stackexchange","superuser","serverfault","stackoverflow.com","pypi","npmjs","packagist",
        "composer","rubygems","cratesio","githubusercontent","rawgithubusercontent","gist.github.com",
        "docker","kubernetes","jenkins","travis-ci","circleci","gitlab","bitly","tinyurl",
        "medium.com","news.google","apple.com","microsoft.com","amazon.co.uk","amazon.de","ebay.de",
        "paypal.com","bankofamerica","chase","wellsfargo","citibank","hsbc","barclays","lendingclub",
        "mint","robinhood","coinbase","binance","kraken","bitstamp","coinmarketcap","coindesk",
        "timesofindia","hindustantimes","ndtv","zomato","swiggy","ubereats","grubhub","doordash",
        "indeed.com","monster","glassdoor","careers","angel.co","startup","techcrunch","thenextweb",
        "wired","engadget","verge","gizmodo","arstechnica","mashable","lifehacker","cnet",
        "etsy.com","craigslist","mercari","offerup","olx","gumtree","jd.com","taobao","tmall",
        "aliexpress","flipkart.com","snapdeal","paytm.com","phonepe.com","myntra","zara","hm","uniqlo",
        "adidas","nike","puma","louisvuitton","gucci","hermes","chanel","prada","burberry","ikea.com",
        "booking.com","expedia","agoda","trivago","hotels.com","airbnb.com","vrbo","orbitz",
    ]

    if try_fetch and len(brands) < min_count:
        fetched = _fetch_top_domains(limit=min_count)
        if fetched:
            # prefer local unique entries first, then fetched
            combined = list(dict.fromkeys(brands + fetched))
            brands = combined[:min_count]
            # persist to local file for future runs
            try:
                with open(DATA_FILE, "w", encoding="utf-8") as f:
                    for d in brands:
                        f.write(d + "\n")
            except Exception:
                pass
        # If still not enough brands, use fallback list and persist
        if len(brands) < min_count:
            for b in FALLBACK_BRANDS:
                if b not in brands:
                    brands.append(b)
                if len(brands) >= min_count:
                    break
            try:
                with open(DATA_FILE, "w", encoding="utf-8") as f:
                    for d in brands:
                        f.write(d + "\n")
            except Exception:
                pass

    # ensure uniqueness and lowercase
    seen = set()
    cleaned = []
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
    """Return candidate brand indices likely similar to domain using trigram overlap."""
    if not _TRIGRAM_INDEX:
        return []
    counts = Counter()
    for t in _trigrams(domain):
        for idx in _TRIGRAM_INDEX.get(t, []):
            counts[idx] += 1
    if not counts:
        return []
    # highest overlap candidates
    return [i for i, _ in counts.most_common(top_k)]


def brand_similarity(domain):
    """Return similarity score in [0,1] between `domain` and the closest brand.
    Uses trigram candidate filtering and Levenshtein distance on best candidates.
    """
    global _BRANDS
    if _BRANDS is None:
        load_brands()

    domain = domain.lower().strip()
    # exact checks
    if domain in _BRANDS:
        return 1.0

    # quick length-based filter
    candidates = _candidate_indices_for(domain, top_k=50)
    if not candidates:
        # fallback to checking all (small cost for ~1000 brands)
        candidates = range(len(_BRANDS))

    min_dist = None
    closest = None
    for i in candidates:
        b = _BRANDS[i]
        dist = Levenshtein.distance(domain, b)
        if min_dist is None or dist < min_dist:
            min_dist = dist
            closest = b

    if min_dist is None or closest is None:
        return 0.0

    # normalize similarity
    sim = 1 - (min_dist / max(len(domain), len(closest), 1))
    return max(0.0, min(1.0, sim))


if __name__ == "__main__":
    # quick test loader
    b = load_brands()
    print(f"Loaded {len(b)} brands")
