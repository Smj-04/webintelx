# Phishing Detection Module (Python)

## Overview
Machine learning–assisted phishing detector combining real-time feature extraction with rule-based scoring. Provides a CLI that prints strict JSON and is invoked by the Node backend for /api/phishing-check.

## Setup
```
cd Phishing/phishing-site-or-not
pip install -r requirements.txt
```
Ensure the model file exists at phishing/models/phishing_model.pkl (joblib). The repository includes a model by default.

## Usage (CLI)
```
python main.py https://example.com
```
Outputs a JSON object with:
- prediction, risk_level, classification
- ml_probability and score breakdowns
- flags (unreachable, ssl_valid, free_hosting, ip_url, typosquat_target)

## How It Works
- Validates and normalizes the input URL; enforces simple rate limiting.
- Resolves DNS and reachability (skipped for IP-only URLs).
- Extracts URL, domain, and content features, then aligns with model feature names.
- Produces ML prediction and probability.
- Applies rule-based scoring:
  - Typosquatting across domain and subdomain tokens
  - Suspicious TLDs, domain age, SSL validity and days left
  - Free hosting/site builders (e.g., webflow.io, netlify.app, github.io)
  - Unresponsive content, external form submissions, hidden fields, redirects
- Combines into a weighted final score and outputs a clear classification.

## Tests
```
python -m unittest discover -s tests -p "test_*.py"
```
Includes tests for brand similarity, domain/SSL checks, URL validation, rate limiting, JSON output, and basic integration.

## Integration (Backend)
The Express backend spawns the CLI in phishingCheckRoute with a 50s timeout and supports PHISHING_PYTHON_BIN on Windows. It parses strict JSON from stdout and returns it to the frontend.

## Troubleshooting
- Import errors: ensure requirements are installed in the active environment.
- Network-restricted environments may cause DNS/HTTP checks to be skipped; the tool guards and returns sensible messages.
- For Windows, set PHISHING_PYTHON_BIN to py if python is not on PATH.

