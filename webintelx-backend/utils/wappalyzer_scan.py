#utils/wappalyzer_scan.py

from Wappalyzer import Wappalyzer, WebPage
import json
import sys
import requests
import re

url = sys.argv[1]

try:
    # -----------------------------
    # Wappalyzer detection
    # -----------------------------
    wappalyzer = Wappalyzer.latest()
    webpage = WebPage.new_from_url(url)

    results = wappalyzer.analyze_with_versions(webpage)

    cleaned = {}

    for tech, data in results.items():
        versions = data.get("versions", [])
        cleaned[tech] = versions[0] if versions else "Unknown"

    # -----------------------------
    # Fetch HTML
    # -----------------------------
    response = requests.get(url, timeout=10)
    html = response.text.lower()

    # -----------------------------
    # Technology regex patterns
    # -----------------------------
    patterns = {
        "jQuery": r"jquery[-.]([0-9]+\.[0-9]+(\.[0-9]+)?)",
        "Bootstrap": r"bootstrap[-.]([0-9]+\.[0-9]+(\.[0-9]+)?)",
        "React": r"react[-.]([0-9]+\.[0-9]+(\.[0-9]+)?)",
        "Angular": r"angular[-.]([0-9]+\.[0-9]+(\.[0-9]+)?)",
        "Vue.js": r"vue[-.]([0-9]+\.[0-9]+(\.[0-9]+)?)",
        "Next.js": r"next[-.]([0-9]+\.[0-9]+(\.[0-9]+)?)",
        "Nuxt.js": r"nuxt[-.]([0-9]+\.[0-9]+(\.[0-9]+)?)",
        "Ember.js": r"ember[-.]([0-9]+\.[0-9]+(\.[0-9]+)?)",
        "Backbone.js": r"backbone[-.]([0-9]+\.[0-9]+(\.[0-9]+)?)",
        "OWL Carousel": r"owl\.carousel[-.]([0-9]+\.[0-9]+(\.[0-9]+)?)",
        "Font Awesome": r"font[-]?awesome[-.]([0-9]+\.[0-9]+(\.[0-9]+)?)",
        "Swiper": r"swiper[-.]([0-9]+\.[0-9]+(\.[0-9]+)?)",
        "GSAP": r"gsap[-.]([0-9]+\.[0-9]+(\.[0-9]+)?)",
        "D3.js": r"d3[-.]([0-9]+\.[0-9]+(\.[0-9]+)?)",
        "Three.js": r"three[-.]([0-9]+\.[0-9]+(\.[0-9]+)?)",
        "Lodash": r"lodash[-.]([0-9]+\.[0-9]+(\.[0-9]+)?)",
        "Moment.js": r"moment[-.]([0-9]+\.[0-9]+(\.[0-9]+)?)",
        "Axios": r"axios[-.]([0-9]+\.[0-9]+(\.[0-9]+)?)",
        "Chart.js": r"chart[-.]([0-9]+\.[0-9]+(\.[0-9]+)?)",
        "Tailwind CSS": r"tailwind[-.]([0-9]+\.[0-9]+(\.[0-9]+)?)",
        "Material UI": r"material[-.]([0-9]+\.[0-9]+(\.[0-9]+)?)"
    }

    # -----------------------------
    # Search HTML for technologies
    # -----------------------------
    for tech, pattern in patterns.items():
        match = re.search(pattern, html)
        if match:
            cleaned[tech] = match.group(1)

    print(json.dumps(cleaned))

except Exception as e:
    print(json.dumps({"error": str(e)}))