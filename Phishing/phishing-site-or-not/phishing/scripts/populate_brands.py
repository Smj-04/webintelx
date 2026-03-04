"""Fetch top domains and populate data/brands.txt with top N entries.

Usage: python scripts/populate_brands.py
"""
import os
import requests

# Candidate sources (mirrors) for top domain lists
TOP_DOMAINS_CSV_CANDIDATES = [
    "https://datahub.io/core/top-domains/r/top-1m.csv",
    "https://raw.githubusercontent.com/varunmalhotra/Top-1M-domains/master/top-1m.csv",
    "https://raw.githubusercontent.com/joelosh/top-1m/master/top-1m.csv",
    "https://s3.amazonaws.com/alexa-static/top-1m.csv",
]
OUT_FILE = os.path.join("..", "data", "brands.txt")
LIMIT = 1000


def fetch_top_domains(limit=LIMIT):
    last_exc = None
    for src in TOP_DOMAINS_CSV_CANDIDATES:
        try:
            resp = requests.get(src, timeout=10)
            resp.raise_for_status()
            lines = resp.text.splitlines()
            domains = []
            for line in lines:
                parts = line.split(",")
                if len(parts) == 2 and parts[1]:
                    domains.append(parts[1].strip().lower())
                if len(domains) >= limit:
                    break
            if domains:
                return domains
        except Exception as e:
            last_exc = e
            continue
    # if all sources failed, raise last exception
    if last_exc:
        raise last_exc
    return []


def write_brands(domains, path=OUT_FILE):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for d in domains:
            f.write(d + "\n")


def main():
    try:
        print(f"Fetching top {LIMIT} domains...")
        domains = fetch_top_domains(LIMIT)
        print(f"Fetched {len(domains)} domains. Writing to {OUT_FILE}")
        write_brands(domains)
        print("Done.")
    except Exception as e:
        print("Failed:", e)


if __name__ == "__main__":
    main()
