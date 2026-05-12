# Phishing Detection Module Documentation

**Location**: `Phishing/phishing-site-or-not/` (Python module)  
**Backend Integration**: `webintelx-backend/routes/phishingCheckRoute.js`  
**API Endpoint**: `POST /phishing-check`  
**Language**: Python 3.8+  
**ML Model**: Gradient Boosting Classifier

---

## Overview

The Phishing Detection module uses **machine learning** (95%+ accuracy) combined with **rule-based heuristics** to identify phishing websites in real-time. It analyzes URLs across three dimensions:

1. **URL Analysis** - URL structure and patterns (13 features)
2. **Domain Analysis** - Registration and reputation (8 features)
3. **Content Analysis** - Website HTML/behavior (15 features)

---

## Architecture

### ML Pipeline

```
User Input (URL)
    ↓
[URL Validation & Rate Limiting]
    ↓
[DNS Resolution]
    ↓
[Real-time Feature Extraction (34+ features)]
├─ URL Features (13)
├─ Domain Features (8)
└─ Content Features (15)
    ↓
[Gradient Boosting ML Prediction]
    ↓
[Rule-Based Risk Scoring]
    ↓
[Escalation Rules & Risk Adjustment]
    ↓
[Classification (Phishing vs Legitimate)]
    ↓
[JSON Output]
```

---

## Component Breakdown

### 1. URL Analysis (13 Features)

**What It Checks**:
- Overall URL structure and patterns
- Presence of suspicious elements
- Length-based obfuscation

| Feature | Suspicious Indicator | Score |
|---------|---------------------|-------|
| `URLLength` | > 75 characters | +1 |
| `IsDomainIP` | 192.168.1.1 format | +3 (CRITICAL) |
| `NoOfSubDomain` | > 3 subdomains | +1 |
| `IsHTTPS` | HTTP (no S) | +1 |
| `NoOfSpecialChars` | > 2 (@, -, //) | +1 |
| `DegitRatioInURL` | > 30% digits | +1 |
| `NoOfEqualsInURL` | > 3 equals signs | +1 |
| `Suspicious Path` | /login, /verify, /bank | +1 |

**Example**:
```
URL: https://paypal-secure-verify.com/login/account/confirm?token=ABC123
Issues:
  - Contains suspicious path: /login/verify
  - Has unusual subdomain structure
  - Long URL (71 chars)
Risk Score: +3
```

---

### 2. Domain Analysis (8 Features)

#### A. Brand Typo-Squatting Detection
```
Algorithm: Levenshtein Distance + Trigram Matching
Trusted Brands: 465 (Google, Amazon, PayPal, Microsoft, Netflix, etc.)
Similarity Threshold: ≥0.55
Critical Threshold: ≥0.85
```

**Examples**:
```
Domain           → Detected Match    → Similarity
paypaI.com       → paypal            → 0.85+ (CRITICAL)
arnazon.com      → amazon            → 0.75+ (HIGH)
m1crosof.com     → microsoft         → 0.68+ (MEDIUM)
google.com       → google            → 1.0 (LEGITIMATE)
```

#### B. TLD Reputation
```
Legitimate TLDs: .com (0.85), .org (0.80), .edu (0.95), .gov (0.98)
Suspicious TLDs: .xyz (0.20), .tk (0.10), .ml (0.10), .click (0.15)
```

#### C. Domain Age
- Domain < 90 days old → RED FLAG (startup phishing sites)
- Domain 1-5 years old → NORMAL
- Domain > 10 years old → TRUSTED

#### D. SSL Certificate Validation
- **Valid & >30 days:** +0 risk
- **Missing or Invalid:** +1 risk
- **Expires <30 days:** +1 risk (warning)

#### E. DNS Resolution
- **Resolves:** Confirmed legitimate infrastructure
- **Fails:** Site doesn't exist or is offline → SUSPICIOUS

#### F. Free Hosting Platform Detection

**Platforms** (25 total):
```
webflow.io, netlify.app, github.io, vercel.app, godaddysites.com,
wordpress.com, blogger.com, sites.google.com, wixsite.com, ...
```

**Risk**: Phishing pages on trusted platforms inherit high reputation
- Free hosting + gibberish subdomain → Score +2, CRITICAL

---

### 3. Content Analysis (15 Features)

**How It Works**: Fetches website HTML and parses for suspicious elements

#### A. Form Analysis
```javascript
// Checks for credential-stealing forms
HasExternalFormSubmit:  Form action != same domain → +2 risk
  Example: <form action="https://evil.com/steal">
           
HasHiddenFields:        Hidden inputs capture data silently → +1 risk
  Example: <input type="hidden" name="user_id" value="123">
  
HasPasswordField:       Login form on phishing page → +1 risk
  Example: <input type="password" name="password">
```

#### B. Redirect Detection
```javascript
NoOfURLRedirect:        HTTP redirect chain > 2 → +1 risk
  Why: Phishers chain redirects to hide destination
  
HasMetaRefresh:        <meta http-equiv="refresh"> → +1 risk
  Why: Server-side auto-redirect
  
HasJSRedirect:         window.location in script → +1 risk
  Why: JavaScript-based redirect to phishing site
```

#### C. Effort Indicators (Low-effort clones)
```javascript
HasTitle:              Missing <title> tag → +1 risk
HasFavicon:            Missing favicon → +1 risk
IsResponsive:          No mobile meta viewport → +0.5 risk
  Why: Legitimate sites support mobile devices
```

#### D. External References
```javascript
NoOfExternalRef:       > 50 external links → +1 risk
  Why: Malware distribution, credential harvesting
  
NoOfiFrame:            iframes present → +1 risk
  Why: Frame-based phishing, hidden content
  
NoOfJS:                Multiple script tags → +1 risk
  Why: Malicious scripts, tracking, credential theft
```

---

## Feature Extraction Process

### Real-time Feature Extraction

```python
def extract_realtime_features(url: str) -> dict:
    # 1. URL PARSING & ANALYSIS (13 features)
    URLLength = len(url)
    IsDomainIP = 1 if "192.168.1.1" format in url else 0
    NoOfSubDomain = count subdomains
    IsHTTPS = 1 if url.startswith("https") else 0
    DegitRatioInURL = digits / total characters
    # ... (10 more URL features)
    
    # 2. DOMAIN ANALYSIS (8 features)
    DNSResolvable = 1 if DNS resolves else 0
    SSLCertValid = 1 if certificate valid else 0
    SSLCertDaysLeft = days until expiry
    DomainAgeDays = days since registration
    BrandSimilarity = Levenshtein.distance(domain, known_brands)
    TLDLegitimateProb = lookup table probability
    # ... (2 more domain features)
    
    # 3. CONTENT ANALYSIS (15 features)
    # Fetch HTML (7-second timeout)
    html = requests.get(url, timeout=7)
    soup = BeautifulSoup(html)
    
    HasExternalFormSubmit = 1 if <form action="http..."> else 0
    HasHiddenFields = count of <input type="hidden">
    HasPasswordField = 1 if <input type="password"> else 0
    NoOfURLRedirect = len(response.history)
    HasMetaRefresh = 1 if meta refresh present else 0
    HasJSRedirect = 1 if window.location in scripts else 0
    NoOfiFrame = count of iframes
    # ... (8 more content features)
    
    return features_dict
```

---

## ML Model Details

### Model Type
- **Algorithm**: Gradient Boosting Classifier (scikit-learn)
- **Training Data**: 235,795 URLs
  - Phishing: 134,850 (57.19%)
  - Legitimate: 100,945 (42.81%)
- **Features**: 125 (3 API-only excluded)
- **Accuracy**: 95.98%
- **AUC-ROC**: 98.89%

### Model Output
```python
model_prediction = [0 or 1]  # 0=legitimate, 1=phishing
model_confidence = [prob_legit, prob_phishing]  # e.g., [0.15, 0.85]
```

---

## Risk Scoring & Escalation

### Weighted Scoring
```
Overall Risk = (URL Score × 0.25) + (Domain Score × 0.40) + (Content Score × 0.35)

URL Score = (url_risks / 16) × 100
Domain Score = (domain_risks / 18) × 100
Content Score = (content_risks / 16) × 100
```

### Escalation Rules
```python
# 1. Direct IP address
if is_ip_url:
    overall_risk = max(overall_risk, 80)  # CRITICAL

# 2. Free hosting + gibberish subdomain
if free_hosting and gibberish_subdomain:
    overall_risk = max(overall_risk, 82)  # CRITICAL

# 3. Typo-squatting
if typo_similarity >= 0.85:
    overall_risk = max(overall_risk, 78)  # CRITICAL
elif typo_similarity >= 0.70:
    overall_risk = max(overall_risk, 62)  # HIGH

# 4. ML strong phishing signal
if ml_prediction == 1 and confidence > 0.75:
    overall_risk = max(overall_risk, 75)  # HIGH

# 5. Brand impersonation + unreachable
if brand_similarity > 0.70 and no_content:
    overall_risk = max(overall_risk, 75)  # HIGH
```

---

## Classification Thresholds

| Risk Score | Level | Classification | Color |
|-----------|-------|-----------------|-------|
| > 70% | CRITICAL | 🚨 Phishing | Red |
| 55-70% | HIGH | ⚠️ Suspicious | Orange |
| 35-55% | MODERATE | ⚠️ Risky | Yellow |
| < 35% | LOW | ✅ Likely Legitimate | Green |

---

## Special Cases & Handling

### Unreachable Sites
```
If DNS fails AND content unavailable:
  → Return [UNKNOWN] SITE UNREACHABLE
  → Don't force phishing classification
  → User informed site may be offline/blocked
```

### IP-Based URLs
```
URL: http://192.168.1.1/admin
Risk: CRITICAL (direct IP addresses are highly suspicious)
Escalation: Force to 80% minimum
```

### Content Fetch Timeout
```
If page takes >7 seconds to load:
  → Assume unreachable
  → Mark content features as 0 (suspicious)
  → Falls back to URL + domain scoring
```

---

## API Request/Response

### Request
```bash
POST /phishing-check
{
  "url": "https://paypal-verify.com/login"
}
```

### Response
```json
{
  "url": "https://paypal-verify.com/login",
  "prediction": "phishing",
  "classification": "Potential Phishing Website",
  "risk_level": "CRITICAL",
  "ml_probability": 0.89,
  "scores": {
    "url_score": 35.0,
    "domain_score": 52.5,
    "content_score": 25.0,
    "final_weighted_score": 42.5
  },
  "flags": {
    "unreachable": false,
    "brand_similarity": 0.85,
    "ssl_valid": false,
    "free_hosting": false,
    "ip_url": false,
    "typosquat_target": "paypal",
    "typosquat_score": 0.85
  },
  "details": "CRITICAL (75.0%) – ML predicted phishing (0.89) – Potential Phishing Website"
}
```

---

## Backend Integration

### Flow
```javascript
// phishingCheckRoute.js
router.post("/phishing-check", (req, res) => {
  const url = req.body.url;
  
  // Spawn Python process
  const pythonBin = process.env.PHISHING_PYTHON_BIN || "python";
  const child = spawn(pythonBin, ["main.py", url], {
    cwd: "/path/to/phishing-site-or-not"
  });
  
  // Capture stdout (JSON output)
  let stdout = "";
  child.stdout.on("data", (data) => {
    stdout += data.toString();
  });
  
  child.on("close", (code) => {
    // Parse JSON and return to frontend
    const result = JSON.parse(stdout);
    res.json(result);
  });
  
  // Timeout after 50 seconds
  setTimeout(() => { child.kill(); }, 50000);
});
```

### Python CLI
```bash
python main.py https://example.com
# Outputs: {"url": "...", "prediction": "...", ...}
```

---

## Dataset & Training

### Dataset
- **Source**: PhiUSIIL Phishing URL Dataset
- **Size**: 235,795 samples
- **Class Distribution**: 57% phishing, 43% legitimate
- **Features**: 51 base + 10+ computed

### Training Process
```python
# evaluate_and_retrain.py
python evaluate_and_retrain.py --evaluate   # Test model
python evaluate_and_retrain.py --retrain    # Retrain from scratch
```

---

## Known Issues & Limitations

### 1. Hardcoded Paths
- Model path: `phishing/models/phishing_model.pkl`
- Brands path: `data/brands.txt`
- Breaks if directory structure changes

### 2. Content Fetching
- 7-second timeout (may miss slow sites)
- Static HTML only (no JavaScript rendering)
- Bot detection (legitimate sites may reject)

### 3. Brand Detection
- 465 hardcoded brands (misses new brands)
- English-only (doesn't detect Cyrillic homoglyphs)
- Levenshtein threshold (0.55) may miss sophisticated typos

### 4. Rate Limiting
- 10 requests/60 seconds (insufficient for enterprise)
- No caching (every check runs fresh)

### 5. Windows Support
- Requires `PHISHING_PYTHON_BIN=py` environment variable
- Python not on PATH defaults to `py`

---

## Feature Importance

Top features contributing to predictions (from model):
1. `BrandSimilarity` - Typo-squatting detection
2. `HasExternalFormSubmit` - Credential theft indicators
3. `DNSResolvable` - Domain legitimacy
4. `SSLCertValid` - HTTPS/security indicators
5. `IsDomainIP` - Direct IP usage
6. `TLDLegitimateProb` - Domain reputation
7. `URLLength` - Obfuscation patterns
8. `HasPasswordField` - Login form presence
9. `DomainAgeDays` - Domain age
10. `NoOfExternalRef` - External link count

---

## Remediation & False Positives

### False Positive Handling
```
If legitimate site flagged as phishing:

1. Check for recently created domain (<90 days)
   → Normal for new businesses
   
2. Check for free hosting platform
   → Startups on GitHub Pages, Netlify etc. are legitimate
   
3. Check if content unreachable
   → May be temporarily down or blocked by firewall
   
4. Review typo-squatting score
   → Random domain names won't match brands
   
5. Verify SSL certificate
   → Let's Encrypt = legitimate (free SSL provider)
```

---

## Security Considerations

### Rate Limiting
- **Current**: 10 req/60s
- **Bypass Risk**: Distributed requests from multiple IPs
- **Mitigation**: Implement IP-based throttling in frontend

### DNS Cache Poisoning
- Uses TTL cache (300s) for DNS lookups
- Safe against immediate attacks but caches bad data

### SSRF Risk
- Python fetches arbitrary URLs
- Mitigated by URL validation and timeout
- Firewall should block internal IP ranges

---

## Use Cases

✅ **Ideal For**:
- Email security filtering
- Browser extension warnings
- User-reported URL verification
- Suspicious link detection
- Security awareness training

❌ **Not Suitable For**:
- Zero-day vulnerability detection
- Real-time threat feeds
- Advanced evasion techniques
- Encrypted phishing content
