# Custom Scan Module Documentation

**Location**: `webintelx-backend/controllers/customScanController.js` & `routes/customScanRoute.js`  
**Purpose**: Advanced, modular security scanning with user-selected checks  
**Time Complexity**: Variable (5 minutes to 2+ hours depending on selected modules)  
**API Endpoints**:
- `POST /customscan` - Start custom scan
- `POST /customscan/stop` - Stop running scan

---

## Overview

The Custom Scan module allows users to **select specific security checks** to perform on a target, enabling deep, comprehensive security assessments. Scans run sequentially with **progress tracking** and **stop capability**.

---

## Supported Scan Modules

### 1. **URL/Headers Scanner**
- HTTP headers analysis
- Security header validation
- Cookie analysis (Secure, HttpOnly, SameSite flags)

### 2. **DNS Enumeration**
- A, MX, NS records
- DNS resolver information
- Nameserver configuration

### 3. **Port Scanner**
- Network port enumeration
- Service identification (via banner grabbing)
- Open/closed port detection

### 4. **Ping/Reachability**
- ICMP echo requests
- Network latency measurement
- Availability verification

### 5. **Traceroute**
- Hop-by-hop network path
- Latency analysis
- Gateway/ISP identification

### 6. **SSL/TLS Certificate Analysis**
- Certificate validity
- Expiration tracking
- Chain validation
- Issuer/subject information

### 7. **Subdomain Enumeration**
- HackerTarget API (primary)
- Certificate Transparency (crt.sh fallback)
- Large-scale subdomain discovery

### 8. **WHOIS/RDAP Domain Lookup**
- Registrar information
- Domain dates (creation, expiration, updated)
- Nameserver details
- DNSSEC status
- Registrant organization

### 9. **Shodan Integration** (Optional, requires API key)
- Host-level vulnerability data
- Open port enumeration
- Known exploits (CVE data)
- KE​V (Known Exploited Vulnerabilities)
- Cloud provider detection

### 10. **Google Safe Browsing** (Optional, requires API key)
- Malware detection
- Phishing detection
- Unwanted software detection
- PHA (Potentially Harmful Application)

### 11. **VirusTotal Scanning** (Optional, requires API key)
- Multi-engine malware analysis
- AV engine verdicts
- Community score
- Known threats/categories

### 12. **Email Intelligence / DNSBL**
- DNS blocklist checks
- Spam reputation
- Email infrastructure validation

### 13. **ASN/Geolocation Lookup**
- IP geolocation (city, country, region)
- ASN information
- Cloud provider detection
- ISP identification

### 14. **Wappalyzer Technology Detection**
- Framework identification (React, Angular, Vue)
- Server technology (Apache, Nginx, IIS)
- Version detection
- Vulnerability correlation

### 15. **Cookie Security Analysis**
- Secure flag validation
- HttpOnly flag validation
- SameSite policy validation
- CSRF vulnerability detection

### 16. **Green Web Check**
- Renewable energy hosting verification
- Sustainability scoring

---

## Scan Configuration

### Custom Scan Request
```json
{
  "target": "example.com",
  "checks": [
    "dns",
    "ssl",
    "headers",
    "subdomain",
    "whois",
    "headers",
    "traceroute"
  ],
  "aggressiveness": "medium",
  "scanId": "scan-12345"
}
```

### Aggressiveness Levels
- **light**: DNS, SSL, headers only (~1-2 min)
- **medium**: + subdomain, WHOIS, email intel (~5-10 min)
- **aggressive**: + Shodan, VirusTotal, port scan (~15+ min)
- **extreme**: All checks including deep subdomain enumeration (~30+ min)

---

## Detailed Scan Modules

### DNS Module

**What It Does**:
- Resolves domain to IP addresses
- Retrieves mail exchange (MX) records
- Lists nameservers (NS records)
- Validates DNS infrastructure

**Output**:
```json
{
  "A": ["1.2.3.4", "5.6.7.8"],
  "MX": ["mail.example.com"],
  "NS": ["ns1.example.com", "ns2.example.com"],
  "primaryIP": "1.2.3.4",
  "resolvedSuccessfully": true
}
```

**Risks Detected**:
- DNS failures → Target unreachable
- Missing MX records → Email infrastructure problems
- Misconfigured NS → Domain transfer risk

---

### SSL/TLS Module

**What It Does**:
- Validates SSL certificate chain
- Checks certificate expiration
- Extracts issuer and subject
- Verifies signing algorithm
- Detects self-signed certificates

**Output**:
```json
{
  "valid": true,
  "validFrom": "2023-01-01",
  "validTo": "2026-01-01",
  "daysRemaining": 500,
  "issuer": "Let's Encrypt Authority X3",
  "subject": "example.com",
  "signatureAlgorithm": "sha256WithRSAEncryption"
}
```

**Risks Detected**:
- Invalid certificate → Score +3, CRITICAL
- Expiration <30 days → Score +2, HIGH
- Self-signed → RED FLAG
- Mismatched domain → CRITICAL

---

### Subdomain Enumeration Module

**What It Does**:
- Discovers ALL subdomains of a target domain
- Uses Certificate Transparency logs (crt.sh)
- HackerTarget API for rapid enumeration
- Identifies subdomains not listed in DNS

**Methods**:
1. **Certificate Transparency (crt.sh)**: Scans public SSL certificate logs
2. **HackerTarget API**: Queries passive DNS database
3. **DNS Wildcard Detection**: Checks for *.example.com

**Output**:
```json
{
  "subdomains": [
    "api.example.com",
    "admin.example.com",
    "mail.example.com",
    "dev.example.com",
    "staging.example.com"
  ],
  "count": 5,
  "source": "HackerTarget",
  "wildcardEnabled": false
}
```

**Risks Detected**:
- >30 subdomains → Score +2, HIGH (large attack surface)
- Exposed dev/admin subdomains → CRITICAL
- Wildcard subdomains → Information disclosure

---

### Port Scanning Module

**What It Does**:
- Probes common ports (21, 22, 23, 25, 53, 80, 443, 3306, 5432, 8080, etc.)
- Identifies open/closed/filtered ports
- Attempts service banner grabbing
- Maps service names

**Dangerous Ports**:
- **FTP (21)**: Unencrypted file transfer
- **Telnet (23)**: Unencrypted remote access
- **SMTP (25)**: Mail server (open relay risk)
- **MySQL (3306)**: Exposed database
- **PostgreSQL (5432)**: Exposed database

**Output**:
```json
{
  "openPorts": [
    {"port": 22, "name": "SSH", "status": "open"},
    {"port": 80, "name": "HTTP", "status": "open"},
    {"port": 443, "name": "HTTPS", "status": "open"},
    {"port": 3306, "name": "MySQL", "status": "open"}
  ],
  "closedPorts": [{"port": 21, "name": "FTP"}],
  "filteredPorts": [{"port": 23, "name": "Telnet"}]
}
```

**Risks Detected**:
- Open FTP/Telnet → Score +3, CRITICAL
- MySQL/PostgreSQL exposed → Score +3, CRITICAL
- >10 open ports → Larger attack surface
- Services running on non-standard ports → Obfuscation attempt

---

### WHOIS Module

**What It Does**:
- Retrieves domain registration data
- Extracts registrar information
- Shows domain creation/expiration dates
- Lists authoritative nameservers
- Checks DNSSEC status

**Data Sources**:
- RDAP.org (primary, free)
- IANA RDAP (fallback)

**Output**:
```json
{
  "registrar": "GoDaddy Inc.",
  "creationDate": "2015-03-20",
  "expiryDate": "2026-03-20",
  "updatedDate": "2025-01-15",
  "nameservers": ["ns1.example.com", "ns2.example.com"],
  "registrantOrg": "ACME Corporation",
  "country": "US",
  "dnssec": "signedDelegation"
}
```

**Risks Detected**:
- Domain expiring soon → RENEWAL ALERT
- Recently created domain (<90 days) → SUSPICIOUS
- DNSSEC unsigned → DNS hijacking risk
- Registrant privacy hidden → EVASION INDICATOR

---

### Shodan Module (Requires API Key)

**What It Does**:
- Queries Shodan database for host information
- Returns known vulnerabilities (CVE)
- Lists open ports and services
- Detects KEV (Known Exploited Vulnerabilities)
- Identifies cloud hosting

**Output**:
```json
{
  "available": true,
  "ip": "1.2.3.4",
  "org": "Example Corporation",
  "asn": "AS12345",
  "country": "US",
  "city": "San Francisco",
  "ports": [22, 80, 443, 3306],
  "portCount": 4,
  "vulnCount": 3,
  "vulnDetails": [
    {"id": "CVE-2021-1234", "cvss": 7.5, "kev": true},
    {"id": "CVE-2020-5678", "cvss": 9.1, "kev": true}
  ],
  "kevCount": 2,
  "criticalCount": 1,
  "risk": "CRITICAL"
}
```

**Special Cases**:
- **Cloudflare Detected**: Note that data reflects Cloudflare infrastructure, not origin server
- **Cloud Provider**: Identifies AWS, Google Cloud, Azure, DigitalOcean, etc.
- **Not Indexed**: Host may not yet be in Shodan database

---

### VirusTotal Module (Requires API Key)

**What It Does**:
- Scans domain with 70+ antivirus engines
- Returns malware detection verdicts
- Shows community score
- Tracks detected threat categories

**Output**:
```json
{
  "available": true,
  "malicious": 2,
  "suspicious": 1,
  "harmless": 67,
  "total": 70,
  "communityScore": -15,
  "lastAnalysis": "2026-05-10",
  "categories": ["trojan", "potentially_unwanted_application"],
  "risk": "HIGH"
}
```

**Verdicts**:
- **Malicious**: >5 AV engines flag → Score +3, CRITICAL
- **Suspicious**: 1-5 engines flag → Score +2, HIGH
- **Clean**: 0 malicious verdicts → LOW risk

---

### Headers/Security Module

**What It Does**:
- Fetches HTTP response headers
- Validates presence of security headers
- Detects exposed server information
- Checks for CORS misconfigurations

**Security Headers Checked**:
- `Strict-Transport-Security` (HSTS) - Force HTTPS
- `X-Frame-Options` - Clickjacking protection
- `Content-Security-Policy` - XSS/injection prevention
- `Referrer-Policy` - Privacy control
- `X-XSS-Protection` - Legacy XSS protection
- `X-Content-Type-Options` - MIME-sniffing prevention

**Exposed Information**:
- Server version (e.g., `Apache/2.4.41`)
- X-Powered-By (e.g., `PHP/7.4`)
- CMS info (WordPress, Drupal, etc.)

**Output**:
```json
{
  "server": "Apache/2.4.41 (Ubuntu)",
  "poweredBy": "PHP/7.4.3",
  "strictTransport": "max-age=31536000; includeSubDomains",
  "xFrameOptions": "DENY",
  "csp": "default-src 'self'; script-src 'self' cdn.example.com",
  "referrer": "no-referrer",
  "cors": null,
  "missingSecurityHeaders": ["X-XSS-Protection"],
  "exposedInfo": ["Server: Apache/2.4.41"]
}
```

---

### Traceroute Module

**What It Does**:
- Maps network path to target (hop-by-hop)
- Measures latency at each hop
- Identifies gateways and intermediaries
- Shows ISP/network backbone

**Output**:
```json
{
  "hops": [
    {"hop": 1, "ip": "192.168.1.1", "hostname": "gateway.local", "latency": 2.5},
    {"hop": 2, "ip": "10.0.0.1", "hostname": null, "latency": 15.3},
    {"hop": 3, "ip": "1.2.3.4", "hostname": "isp.net", "latency": 28.4}
  ],
  "totalHops": 11,
  "reachableHops": 10,
  "finalHop": "1.2.3.4",
  "avgLatency": 24.5
}
```

**Risks Detected**:
- >20 hops → Distant/poorly routed server
- High latency → Performance degradation
- Intermittent timeouts → Network stability issues

---

## Risk Scoring Algorithm

```
BASE SCORE = 0

// SSL Risks
IF no valid SSL: +3
ELSE IF expires <30 days: +2

// Header Risks
IF missing >=3 headers: +2
IF outdated PHP (v5/v4): +3
IF wildcard CORS (*): +2

// Technology Risks
IF outdated frameworks (CRITICAL): +3
ELSE IF outdated frameworks (HIGH): +2

// Port Risks
IF dangerous ports open: +2
IF >10 open ports: +1

// Subdomain Risks
IF >30 subdomains: +2
ELSE IF >10 subdomains: +1

// Shodan Risks
IF KEV (Known Exploited Vulnerabilities): +3
IF CVEs found: +3

// Malware Risks
IF Google Safe Browsing threat: +4
IF VirusTotal >5 malicious: +3
ELSE IF VirusTotal >0 malicious: +2

// Email/Blocklist Risks
IF domain on >1 DNSBL: +3
ELSE IF domain on DNSBL: +2

// Cookie Risks
IF >4 insecure cookies: +1

FINAL_RISK = 
  CRITICAL if score >= 10
  HIGH if score >= 7
  MEDIUM if score >= 4
  LOW if score < 4
```

---

## Scan Execution Flow

```
User Selects Checks
    ↓
Start Custom Scan (scanId generated)
    ↓
[Target Validation]
    ↓
[Execute Selected Checks Sequentially]
├─ DNS
├─ SSL
├─ Headers
├─ WHOIS
├─ Subdomain Enum
├─ Traceroute
├─ Port Scan
├─ Shodan (if key available)
├─ VirusTotal (if key available)
└─ Technology Detection
    ↓
[Calculate Risk Score]
    ↓
[Generate Findings & Remediation Steps]
    ↓
[Return Results with Stop Capability]
```

---

## Stop Scan Feature

Users can **stop a running scan** at any time:

```javascript
// Request
POST /customscan/stop
{
  "scanId": "scan-12345"
}

// Response
{
  "status": "stopped",
  "scanId": "scan-12345",
  "completedChecks": ["dns", "ssl", "headers"],
  "skippedChecks": ["subdomain", "shodan"]
}
```

---

## API Response Structure

```json
{
  "target": "example.com",
  "scanId": "scan-12345",
  "timestamp": "2026-05-12T10:30:00Z",
  "status": "completed",
  "duration": 240,
  "results": {
    "dns": { /* ... */ },
    "ssl": { /* ... */ },
    "headers": { /* ... */ },
    "whois": { /* ... */ },
    "subdomains": { /* ... */ },
    "shodan": { /* ... */ }
  },
  "risk": {
    "overall": "HIGH",
    "score": 8,
    "findings": [
      "SSL certificate expires in 45 days",
      "Missing Content-Security-Policy header",
      "2 CVEs detected via Shodan"
    ],
    "recommendations": [
      "Renew SSL certificate immediately",
      "Implement CSP header",
      "Patch known vulnerabilities"
    ]
  }
}
```

---

## Technologies & APIs

**Local Tools**:
- DNS (Node.js native)
- Ping/Traceroute (system commands)

**Free APIs**:
- RDAP.org - WHOIS data
- HackerTarget - Subdomain enumeration
- crt.sh - Certificate Transparency
- ip-api.com - Geolocation

**Paid APIs** (Optional):
- Shodan (requires API key)
- VirusTotal (requires API key)
- Google Safe Browsing (requires API key)

---

## Performance Considerations

| Module | Execution Time | CPU | Network |
|--------|----------------|-----|---------|
| DNS | 2-5s | Low | Low |
| SSL | 3-8s | Low | Medium |
| Ping | 5-10s | Low | Medium |
| Traceroute | 10-30s | Low | High |
| Subdomain Enum | 10-60s | Medium | High |
| Port Scan | 30-120s | Medium | High |
| Shodan | 2-5s | Low | Low |
| VirusTotal | 3-8s | Low | Low |

**Total Time**: 2-5 minutes (light) to 30+ minutes (extreme)

---

## Limitations & Considerations

- **API Rate Limits**: Free APIs may throttle requests
- **Network Blocked**: Scans may timeout if target blocks scanning
- **False Positives**: Some tools may flag legitimate infrastructure
- **API Keys**: Shodan, VirusTotal, Safe Browsing require paid keys
- **Accuracy**: Passive scanning; no active exploitation attempts
- **Time**: Comprehensive scans take significant time

---

## Use Cases

✅ **Ideal For**:
- Pre-deployment security verification
- Vendor security due diligence
- Incident response investigation
- Security hardening assessment
- Attack surface mapping
- Compliance auditing

❌ **Not Suitable For**:
- Real-time threat detection
- Zero-day exploitation
- Deep web application testing
- Authenticated vulnerability scanning
