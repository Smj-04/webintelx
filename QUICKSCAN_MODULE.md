# Quick Scan Module Documentation

**Location**: `webintelx-backend/controllers/quickScanController.js` & `routes/quickScanRoute.js`  
**Purpose**: Rapid reconnaissance scan of a target domain/URL  
**Time Complexity**: ~30-60 seconds per target  
**API Endpoint**: `POST /quickscan`

---

## Overview

The Quick Scan module provides a fast, automated security reconnaissance scan of a website. It performs **parallel API calls** to gather information across multiple dimensions and returns a comprehensive risk assessment with actionable findings.

---

## Scan Components

### 1. **Target Validation**
```javascript
- Checks if hostname is reachable
- Validates DNS resolution
- Attempts both HTTPS and HTTP connections
- Returns early if target doesn't exist
```

### 2. **DNS Records Analysis**
- **A Records**: IPv4 addresses
- **MX Records**: Mail exchange servers (email infrastructure)
- **NS Records**: Nameservers
- **Resolution Success**: Confirms domain exists

**Parser Output**:
```json
{
  "A": ["1.2.3.4", "5.6.7.8"],
  "MX": ["mail.example.com"],
  "NS": ["ns1.example.com"],
  "primaryIP": "1.2.3.4",
  "resolvedSuccessfully": true
}
```

### 3. **Ping/Reachability Test**
- Sends ICMP echo requests (4 packets by default)
- Measures response times and packet loss
- Tests network accessibility

**Parser Output**:
```json
{
  "reachable": true,
  "avgTime": "42.5",
  "packetLoss": "0%",
  "sent": 4,
  "received": 4
}
```

### 4. **SSL/TLS Certificate Check**
- Validates certificate chain
- Checks expiration date
- Extracts issuer and subject information
- Calculates days remaining

**Parser Output**:
```json
{
  "valid": true,
  "validFrom": "2023-01-01",
  "validTo": "2026-01-01",
  "daysRemaining": 500,
  "issuer": "Let's Encrypt Authority X3",
  "subject": "example.com"
}
```

### 5. **HTTP Security Headers Analysis**
Detects presence/absence of critical security headers:
- **Strict-Transport-Security (HSTS)**: Force HTTPS
- **X-Frame-Options**: Clickjacking protection
- **Content-Security-Policy**: XSS/injection prevention
- **Referrer-Policy**: Privacy control
- **X-XSS-Protection**: Legacy XSS mitigation
- **Access-Control-Allow-Origin**: CORS policy

**Missing Headers Risk**:
- 3+ missing → Score +2, HIGH risk
- Any missing → Score +1, MEDIUM risk

**Exposed Information**:
- Server version (e.g., `Apache/2.4.41`)
- X-Powered-By (e.g., `PHP/7.4.3`)
- Used for fingerprinting attacks

**Parser Output**:
```json
{
  "server": "Apache/2.4.41 (Ubuntu)",
  "poweredBy": "Express.js",
  "strictTransport": "max-age=31536000",
  "xFrameOptions": "DENY",
  "csp": "default-src 'self'",
  "referrer": "no-referrer",
  "cors": null,
  "missingSecurityHeaders": ["Referrer-Policy"],
  "exposedInfo": ["Server: Apache/2.4.41 (Ubuntu)"]
}
```

### 6. **Traceroute Analysis**
- Maps network hops to destination
- Measures latency at each hop
- Identifies intermediary servers

**Parser Output**:
```json
{
  "hops": [
    {"hop": 1, "ip": "192.168.1.1", "hostname": "gateway.local", "latency": 2.5},
    {"hop": 2, "ip": "10.0.0.1", "hostname": "isp-router.com", "latency": 15.3}
  ],
  "totalHops": 12,
  "reachableHops": 11,
  "finalHop": "1.2.3.4",
  "avgLatency": 28.5
}
```

### 7. **WHOIS/RDAP Lookup**
- Domain registration details
- Registrar information
- Registrant organization
- Nameserver configuration
- DNSSEC status
- Domain creation/expiration dates

**Uses**: RDAP.org (free, no API key required)

**Parser Output**:
```json
{
  "registrar": "GoDaddy Inc",
  "creationDate": "2015-03-20",
  "expiryDate": "2026-03-20",
  "updatedDate": "2025-01-15",
  "nameservers": ["ns1.example.com", "ns2.example.com"],
  "registrantOrg": "ACME Corporation",
  "country": "US",
  "dnssec": "signedDelegation"
}
```

### 8. **Subdomain Enumeration**
- Discovers subdomains of target domain
- Uses HackerTarget API (primary)
- Falls back to crt.sh (Certificate Transparency logs)

**Data**:
- Count of discovered subdomains
- List of subdomains
- Source of data

**Parser Output**:
```json
{
  "subdomains": ["api.example.com", "mail.example.com", "admin.example.com"],
  "count": 3,
  "source": "HackerTarget"
}
```

### 9. **Email Intelligence / DNSBL Checks**
- Checks domain reputation on spam blacklists
- DNSBL (DNS Blocklist) lookups
- Email infrastructure security

**Scoring**:
- Listed on >1 DNSBL → Score +3, CRITICAL risk
- Listed on any DNSBL → Score +2, HIGH risk

### 10. **Port Scanning** (if available)
- Identifies open ports
- Detects dangerous ports (FTP:21, Telnet:23, SMTP:25, MySQL:3306)
- Maps services to ports

**Dangerous Ports Risk**:
- Open dangerous ports → Score +2, HIGH risk

---

## Risk Scoring System

### Scoring Mechanism

| Finding | Risk Added | Severity |
|---------|-----------|----------|
| No valid SSL certificate | +3 | CRITICAL |
| SSL expires <30 days | +2 | HIGH |
| 3+ missing security headers | +2 | HIGH |
| Outdated PHP (v5 or v4) | +3 | CRITICAL |
| Wildcard CORS policy (*) | +2 | HIGH |
| >30 exposed endpoints | +2 | HIGH |
| Dangerous ports open | +2 | HIGH |
| >30 subdomains (large attack surface) | +2 | HIGH |
| Domain on DNS blocklists | +3 | CRITICAL |

### Risk Levels

- **CRITICAL** (Score ≥10): Severe security issues
- **HIGH** (Score ≥7): Major vulnerabilities
- **MEDIUM** (Score ≥4): Moderate risks
- **LOW** (Score <4): Minimal security concerns

---

## Data Flow

```
POST /quickscan
    ↓
[Target Validation]
    ↓
[Parallel API Calls]
├── DNS lookup
├── SSL certificate check
├── HTTP headers fetch
├── Traceroute
├── WHOIS/RDAP lookup
├── Subdomain enumeration
└── Email intelligence check
    ↓
[Parse Results]
    ↓
[Calculate Risk Score]
    ↓
[Generate Findings & Recommendations]
    ↓
[Return JSON Response]
```

---

## API Request/Response

### Request
```json
{
  "target": "example.com"
}
```

### Response
```json
{
  "target": "example.com",
  "timestamp": "2026-05-12T10:30:00Z",
  "dns": {
    "A": ["1.2.3.4"],
    "MX": ["mail.example.com"],
    "NS": ["ns1.example.com"],
    "primaryIP": "1.2.3.4",
    "resolvedSuccessfully": true
  },
  "ping": {
    "reachable": true,
    "avgTime": "42.5",
    "packetLoss": "0%"
  },
  "ssl": {
    "valid": true,
    "daysRemaining": 500,
    "validFrom": "2023-01-01",
    "validTo": "2026-01-01"
  },
  "headers": {
    "server": "Apache/2.4.41",
    "missingSecurityHeaders": ["Referrer-Policy"],
    "exposedInfo": ["Server: Apache/2.4.41"]
  },
  "whois": {
    "registrar": "GoDaddy Inc",
    "expiryDate": "2026-03-20",
    "country": "US"
  },
  "subdomains": {
    "count": 3,
    "subdomains": ["api.example.com", "mail.example.com"]
  },
  "risk": {
    "risk": "MEDIUM",
    "score": 5,
    "findings": [
      "Missing Referrer-Policy header",
      "SSL expires in 500 days (within acceptable range)"
    ]
  }
}
```

---

## Technologies Used

- **Node.js/Express**: Backend framework
- **axios**: HTTP client for API calls
- **dns module**: Native DNS resolution
- **RDAP.org API**: WHOIS data (free)
- **HackerTarget API**: Subdomain enumeration (free)
- **crt.sh**: Certificate Transparency fallback

---

## Performance Characteristics

- **Execution Time**: 30-60 seconds per target
- **Timeout Per Request**: 5-10 seconds (varies by component)
- **Parallelization**: All checks run concurrently
- **Failure Handling**: Graceful degradation (if one API fails, others continue)

---

## Limitations

- Requires active network access
- Rate limited by free APIs (HackerTarget: 100/day limit)
- Cannot penetrate firewalls/IDS systems
- Port scanning limited to banner grabbing
- No JavaScript rendering for dynamic content
- Depends on external API availability

---

## Use Cases

✅ **Suitable For**:
- Quick security posture assessment
- CI/CD pipeline integration
- Competitive domain analysis
- Vulnerability scanning baseline
- Incident response triage

❌ **Not Suitable For**:
- Deep penetration testing
- Zero-day vulnerability detection
- Dynamic application security testing (DAST)
- Real-time threat monitoring
