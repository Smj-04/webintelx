# 🔍 Phishing Detection ML System

A machine learning-based phishing detection system that analyzes URLs across three dimensions: **URL Analysis**, **Domain Analysis**, and **Website Content Analysis**.

---

## 📊 System Overview

The system uses a **Random Forest classifier** (99.99% accuracy) combined with **rule-based heuristics** to comprehensively detect phishing websites.

### Key Features:
- **34 engineered features** across URL, domain, and content categories
- **Brand similarity detection** for typo-squatting attacks (e.g., `paypaI.com` → `paypal`)
- **WHOIS domain-age and SSL certificate validation** to catch newly registered or expired domains
- **Real-time feature extraction** from URLs and webpage content
- **Risk scoring system** (0-100%) with detailed indicator breakdown
- **Interactive demo** for testing suspicious URLs

---

## 🎯 Detection Categories

### 1️⃣ URL ANALYSIS
Examines suspicious patterns in the URL itself:

| Check | Indicator | Risk |
|-------|-----------|------|
| **Length** | URLs > 75 chars | Phishers often use long URLs to hide real domain |
| **IP Address** | IP instead of domain (e.g., 192.168.1.1) | CRITICAL - direct IP is highly suspicious |
| **Special Characters** | @ - // symbols | Used to confuse URL parsing (@gmail.com@phishing.com) |
| **Subdomains** | >3 subdomains | Excessive subdomains indicate obfuscation |
| **HTTPS** | Missing protocol | No SSL/TLS encryption |
| **Digit Ratio** | > 30% digits | Phishers use numeric obfuscation |

**Feature Columns**: `URLLength`, `IsDomainIP`, `NoOfSubDomain`, `IsHTTPS`, `DegitRatioInURL`, etc.

---

### 2️⃣ DOMAIN ANALYSIS
Examines domain characteristics and registration patterns:

| Check | Indicator | Risk |
|-------|-----------|------|
| **Brand Similarity** | Typos matching known brands | CRITICAL - `paypaI` (capital I) vs `paypal` |
| **TLD Legitimacy** | Suspicious TLDs (.tk, .ml, etc.) | Lesser-known TLDs are riskier |
| **Homograph Attacks** | Similar-looking characters | Using Cyrillic 'а' instead of Latin 'a' |
| **URL Similarity** | Low match to known legitimate sites | Should match original brand URLs |

**Feature Columns**: `BrandSimilarity`, `TLDLegitimateProb`, `URLSimilarityIndex`, `CharContinuationRate`

---

### 3️⃣ WEBSITE CONTENT ANALYSIS
Analyzes webpage HTML/behavior for phishing tactics:

| Check | Indicator | Risk |
|-------|-----------|------|
| **External Forms** | Forms submit to external servers | Credential theft - sends data elsewhere |
| **Hidden Fields** | Invisible form inputs | Steals user info without visibility |
| **Password Fields** | Unexpected login forms | Credential phishing indicators |
| **External Links** | >50 links to external sites | Redirect attacks, malware distribution |
| **iframes** | Embedded content from other origins | Can hide phishing forms or redirects |
| **Redirects** | >2 HTTP redirects | Chain redirects hide true destination |
| **Effort Indicators** | Missing title/favicon | Low-effort clones lack proper structure |
| **Responsive Design** | Not mobile-responsive | Legitimate sites support mobile |

**Feature Columns**: `HasExternalFormSubmit`, `HasHiddenFields`, `HasPasswordField`, `NoOfExternalRef`, `NoOfiFrame`, `NoOfURLRedirect`, etc.

### 🌐 Live Site Access for Content Features

The system fetches content **in real-time** from target URLs to extract website analysis features. This is the foundation of detecting sophisticated phishing clones that duplicate legitimate site structures.

**How it works**:
1. **Async HTTP Fetch**: Makes a non-blocking request to fetch webpage HTML (default timeout: **5 seconds**)
2. **HTML Parsing**: BeautifulSoup parses the response to identify forms, scripts, links, images, iframes, redirects
3. **Feature Extraction**: Computes ~14 content-specific indicators from the DOM

**Content feature examples**:
```
✅ Forms detected: 2
   └─ Submission target: external (paymentprocessor.com) ⚠️ SUSPICIOUS
✅ Hidden fields: 3  ← Silently capture user data
✅ Password fields: 1
✅ External links: 21 (out of 35 total)
✅ JavaScript: 6 files
✅ iframes: 0
✅ Redirect chain: 1 hop
⚠️ No mobile responsive meta tag
```

**Timeout & error handling**:
- **Site unreachable** (5s timeout, DNS fail, SSL error): Content features treated as `0` (suspicious)
- **Escalation triggered**: Unreachable sites automatically raise risk score to ≥60% (indicates intentional blocking)

**Supported content detections**:
| Feature | Method | Risk Signal |
|---------|--------|-------------|
| **External Forms** | Regex: `<form ... action="http"` | Credential theft to 3rd party |\n| **Hidden Inputs** | Find: `type="hidden"` | Covert data capture |\n| **Password Fields** | Find: `type="password"` | Unexpected login attempt |\n| **JS Redirects** | Regex in `<script>`: `window.location\|location.href` | Auto-redirect to phishing |\n| **Meta Refresh** | Find: `<meta http-equiv="refresh">` | Server-side redirect mask |\n| **Favicon** | Find: `<link rel="icon">` | Low-effort clones skip favicon |\n| **Title Tag** | Find: `<title>` | Completely fake sites omit titles |\n| **Mobile Responsive** | Find: `<meta name="viewport">` | Legitimate sites support mobile |\n| **External Links** | Regex: Total `<a href="http">` count | Malware distribution |\n| **iframes** | Find: `<iframe>` count | Frame-based phishing |\n| **HTTP Redirects** | HTTP response `.history` length | Chain redirects hide destination |\n\n---

## 📈 Risk Scoring

The system calculates risk in three stages:

1. **Individual Scores**: Each category (URL, Domain, Content) gets 0-100% based on failed checks
2. **Overall Risk**: Weighted average of three scores (URL 20 %, Domain 30 %, Content 50 %).
   - **Escalation rules**: In certain cases the computed score is bumped – for example non‑resolvable content, high brand similarity with no content, or excessive content warnings even when URL/domain look clean.
3. **Classification**:
   - **> 70%**: 🚨 **CRITICAL** - Phishing site detected, do not visit
   - **50-70%**: ⚠️ **HIGH** - Suspicious, proceed with caution
   - **30-50%**: ⚡ **MODERATE** - Potentially risky
   - **< 30%**: ✅ **LOW** - Likely legitimate

---

## 🚀 Quick Start

### Install Dependencies
```bash
python -m venv .venv
.\.venv\Scripts\Activate.ps1  # Windows
source .venv/bin/activate      # Linux/Mac

pip install -r requirements.txt
```

### Train the Model (Optional
```bash
python -m phishing.scripts.data_preprocessing
python -m phishing.features.feature_combiner
python -m phishing.models.train_model
```

### Run Interactive Demo
You can execute the CLI from the project root or via multiple methods:
```bash
# Convenience: run from project root
python main.py

# Or use the package directly
python -m phishing

# Or invoke the internal module
python phishing/main.py
```
When prompted, enter a URL to analyze (e.g., `https://paypaI.com`)

### Run Batch Demo
```bash
python -m phishing.demo
# or
python phishing/demo.py
```
### 🧪 Running the Test Suite
```bash
python -m unittest discover -v tests   # only run the tests folder
```The CLI (`main.py`) is now structured to allow import without executing argument parsing, which lets tests invoke
`analyze_phishing_comprehensive()` directly and even verify the ML escalation logic (the phishing prediction
check will be skipped if the model does not flag the chosen URL with high confidence).


---

## 📋 Datasets & Features

### Raw Data
- **File**: `data/raw/PhiUSIIL_Phishing_URL_Dataset.csv`
- **Size**: 235,795 URLs
- **Balance**: ~45% phishing, ~55% legitimate

### Processed Features
- **Cleaned Data**: `data/processed/cleaned_phishing.csv` (with BrandSimilarity)
- **Final Features**: `data/processed/final_features.csv` (34 features, ready for training)

### Feature Engineering
- **URL Features**: 13 features (length, protocols, special chars, ratio)
- **Domain Features**: 7 features (TLD, similarity, brand matching, homographs)
- **Content Features**: 14 features (forms, links, design, structure)

---

## 🤖 Model Performance

**Algorithm**: Random Forest Classifier
- **N Estimators**: 300 trees
- **Features**: 34
- **Test Accuracy**: **99.99%**
- **Precision**: 100% (Phishing)
- **Recall**: 100% (Phishing)
- **Confusion Matrix**:
  ```
  Predicted →   Legitimate  Phishing
  Actual ↓
  Legitimate:      20,187        2
  Phishing:             0    26,970
  ```

**Top 5 Important Features**:
1. `URLSimilarityIndex` (26.95%)
2. `NoOfExternalRef` (18.85%)
3. `NoOfImage` (12.71%)
4. `NoOfJS` (10.38%)
5. `NoOfCSS` (8.36%)

---

## 📁 Project Structure

```
phishing-site-or-not/
├── data/                        # raw & processed datasets
│   ├── raw/
│   │   └── PhiUSIIL_Phishing_URL_Dataset.csv
│   ├── processed/
│   │   ├── cleaned_phishing.csv
│   │   ├── cleaned_phishing_with_brand.csv
│   │   └── final_features.csv
│   └── brands.txt
├── phishing/                    # main application package
│   ├── __init__.py
│   ├── main.py                  # interactive CLI
│   ├── demo.py                  # batch/demo runner
│   ├── check_model.py           # model inspection utilities
│   ├── features/                # feature extraction subpackage
│   │   ├── __init__.py
│   │   ├── url_features.py
│   │   ├── domain_features.py
│   │   ├── content_features.py
│   │   ├── realtime_features.py
│   │   └── feature_combiner.py
│   ├── models/                  # training & serialized model
│   │   ├── __init__.py
│   │   ├── train_model.py
│   │   ├── evaluate_model.py
│   │   └── phishing_model.pkl
│   └── scripts/                 # utility scripts
│       ├── __init__.py
│       ├── data_preprocessing.py
│       ├── generate_brands_1000.py
│       └── populate_brands.py
├── tests/                       # unit tests
│   ├── test_comprehensive.py
│   ├── test_features.py
│   ├── test_fix.py
│   └── test_prediction.py
├── requirements.txt
└── README_SYSTEM.md
```

---

## 🔧 Technologies Used

| Component | Technology |
|-----------|-----------|
| ML Framework | scikit-learn (Random Forest) |
| Data Processing | pandas, numpy |
| Feature Extraction | regex, tldextract, python-Levenshtein |
| Web Content | requests, BeautifulSoup4 |
| Visualization | matplotlib, seaborn |
| Model Serialization | joblib |

---

## 💡 How to Use

### Example 1: Test a Single URL
```bash
python main.py
# When prompted, enter: https://paypaI.com
```
**Sample Output**:
```
🔍 COMPREHENSIVE PHISHING SITE DETECTION SYSTEM
============================================================

Analyzing: https://paypaI.com

1️⃣ URL ANALYSIS:
   ✅ URL length reasonable
   ✅ Uses domain name (not IP)
   ...
   URL Risk Score: 16.7%

2️⃣ DOMAIN ANALYSIS:
   ⚠️  High brand similarity (83%) - POTENTIAL TYPO ATTACK
   ...
   Domain Risk Score: 41.7%

3️⃣ WEBSITE CONTENT ANALYSIS:
   ⚠️  Content not accessible - site unreachable
   ...
   Content Risk Score: 50.0%

📊 FINAL RISK ASSESSMENT
Overall Risk Score: 36.1%
Suspicious Indicators: 3 / 48 checks failed

⚡ POTENTIALLY RISKY - USE CAUTION
Confidence: MODERATE
ML Model: LEGITIMATE (52.1% confidence)
```

### Example 2: Batch Testing
```bash
python demo.py
```

Tests multiple URLs and shows comparative risk scores:
- `https://paypaI.com` → Phishing (typo attack)
- `https://google.com` → Legitimate

---

## 🛡️ Key Insights

### Common Phishing Tactics Detected:
1. **Typo Squatting**: `paypaI.com`, `amaz0n.com` (high BrandSimilarity)
2. **URL Obfuscation**: Long URLs with special chars, IPs
3. **Credential Harvesting**: Hidden password fields, external form submission
4. **Content Injection**: Excessive iframes, external scripts
5. **Homograph Attacks**: Cyrillic/Latin character substitution

### Real-World Effectiveness:
- Model identifies 99.99% of phishing sites in test dataset
- Typo-based attacks caught by BrandSimilarity scoring
- Content analysis prevents false negatives on sophisticated clones

---

## 🔐 Limitations & Future Work

**Current Limitations**:
- Content features depend on **live site accessibility** (unreachable sites are flagged as suspicious; see [Live Site Access](#-live-site-access-for-content-features) section)
- **Sites that don't resolve or are unreachable**: System returns `[UNKNOWN] SITE UNREACHABLE` verdict instead of guessing as phishing
  - This includes: non-existent domains, offline sites, and sites blocked by government/ISP
  - Critical distinction: *Blocked by government ≠ Phishing*
- BrandSimilarity depends on pre-loaded brand list (can be expanded)
- Network-dependent lookups (DNS, SSL, WHOIS) may fail in restricted environments

### 📍 How the System Handles Unreachable Sites

This detector makes an **important distinction** between sites that are simply unreachable and actual phishing sites:

**When DNS resolution fails AND content unreachable**:
```
πŸ'« Domain does not resolve and content unavailable.
   Site may be offline, unregistered, or blocked.
   Risk assessment cannot be completed accurately.
   
[UNKNOWN] SITE UNREACHABLE
```

**This is NOT automatically classified as phishing because**:
- Legitimate sites go offline temporarily (maintenance, DDoS, server failure)
- New domains take time for DNS propagation (12-48 hours)
- Government/ISP blocking doesn't mean phishing (political sites, content control)
- Deleted/unregistered domains have no DNS entry

**Example scenarios**:
1. `paypal.com` (established, resolves, has content) → Legitimate
2. `paypaI.com` (typo, no DNS, no content) → Could be unregistered phishing attempt
3. `blocked-site.example.com` (government blocks DNS) → Cannot verify, but not necessarily phishing

**Best practice**: If unsure, check additional signals:
- Is it a brand domain? Verify official registrant in WHOIS
- Unknown domain? Avoid clicking until confirmed legitimate
- Service temporarily down? Check brand's status page

**Current Features Already Implemented** ✅:
- ✅ WHOIS domain age lookup (days since registration)
- ✅ SSL certificate validation & expiration tracking
- ✅ DNS resolution checks
- ✅ Real-time HTML content analysis
- ✅ Meta-refresh & JS redirect detection

**Future Enhancements**:
1. Page screenshot comparison with original brand
2. Reputation scoring from external services (Google Safe Browsing, etc.)
3. User feedback loop for model retraining
4. REST API deployment for integration

---

## 📧 Contact & License

**Project**: Phishing Detection ML System  
**Date**: February 2026  
**License**: MIT  

For questions or improvements, refer to the documentation or code comments.

---

## 📚 References

- Dataset: PhiUSIIL Phishing URL Dataset
- Technique: Random Forest Classification
- Feature Engineering: URL/Domain/Content Analysis
- Comparison: Similar to VisualPhish, URLNet projects

