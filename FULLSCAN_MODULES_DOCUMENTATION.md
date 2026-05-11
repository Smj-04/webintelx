# WebIntelX Full Scan - Detailed Module Documentation

## Table of Contents
1. [Overview](#overview)
2. [Architecture & Execution Flow](#architecture--execution-flow)
3. [QuickScan Integration](#quickscan-integration)
4. [Vulnerability Detection Modules](#vulnerability-detection-modules)
5. [OSINT & Reputation Modules](#osint--reputation-modules)
6. [Risk Assessment & Scoring](#risk-assessment--scoring)
7. [Output & Reporting](#output--reporting)

---

## Overview

The **Full Scan** is a comprehensive security assessment that combines:
- **Recon phase**: Passive intelligence gathering (QuickScan)
- **Vulnerability scanning**: 11 active vulnerability modules
- **Reputation checking**: Blacklist, malware, and threat detection
- **Risk aggregation**: Summarized severity metrics

**Execution Model**: All modules run **in parallel** after endpoint discovery, with configurable timeouts to prevent hanging.

**Scan Duration**: ~3-5 minutes for typical sites (varies by complexity)

---

## Architecture & Execution Flow

### Phase 1: Target Validation
```
Input URL → Normalize → DNS Lookup → HTTP Connectivity Test → Valid?
```
- Ensures target is reachable before starting scan
- Catches unreachable domains early
- Returns error if DNS fails or host is down

### Phase 2: QuickScan Execution (180s timeout)
Runs the quick reconnaissance module to gather baseline intelligence:
- DNS records, WHOIS, SSL/TLS
- HTTP headers, open ports
- Subdomains, endpoints, technology stack
- OSINT data (Shodan, VirusTotal, Google Safe Browsing, ASN/Geo)

**Output**: `fullResult.quickscan` (structured data object)

### Phase 3: Endpoint Discovery
Two-stage crawling process:
1. **Active crawl**: Discovers URLs with dynamic endpoints (depth 2)
2. **Parameter extraction**: Identifies numeric parameters for SQLi testing
3. **Fallback scanning**: If crawl yields no parameterized endpoints, runs `endpointScanner`

**Used by**: SQLMap, CSRF scanner, Reflected XSS

### Phase 4: Parallel Vulnerability Scanning (11 modules)
All modules execute simultaneously with individual timeouts:

```javascript
Promise.allSettled([
  sqlInjection (90s per endpoint, 7m total cap),
  domXss       (180s),
  storedXss    (180s),
  reflectedXss (180s),
  clickjacking (180s),
  commandInjection (180s),
  csrf         (180s),
  sensitiveFiles (180s),
  openRedirect (60s),
  cors         (60s),
  wordpress    (60s),
])
```

**Timeout Strategy**:
- Each module has a hard timeout to prevent stalling
- Long-running modules (XSS, CSRF) get 3 minutes
- Quick checks (CORS, open redirect) get 1 minute
- SQLMap has 7-minute overall budget split across endpoints

### Phase 5: Results Aggregation
All results collected, filtered for false positives, and severity-rated.

### Phase 6: PDF Report Generation
Professional report document with findings, statistics, and recommendations.

---

## QuickScan Integration

QuickScan provides the baseline for the full scan. Results are mapped into structured sections:

### 1. **Attack Surface**
```javascript
{
  subdomainCount:  number,        // Enumerated via crt.sh CT logs
  subdomains:      string[],      // List of discovered subdomains
  endpointCount:   number,        // Crawled endpoints
  endpoints:       object[],      // Parameterized endpoints
  openPorts:       number,        // Count of open ports
  formCount:       number,        // Forms detected
  exposedPanels:   string[],      // Admin panels, dashboards found
}
```

### 2. **Technology Fingerprint** (Wappalyzer)
```javascript
{
  server:      string,           // Apache, Nginx, IIS, etc.
  poweredBy:   string,           // X-Powered-By header
  ssl:         boolean,          // Valid SSL/TLS present?
  cms:         string,           // WordPress, Drupal, Joomla, etc.
  frameworks:  string[],         // React, Vue, Django, Laravel, etc.
  cdn:         string,           // Cloudflare, Akamai, Fastly, etc.
  waf:         string,           // WAF detection (Cloudflare WAF, Sucuri, etc.)
}
```

**Wappalyzer Detection**:
- Runs Python script analyzing HTTP headers, HTML, JS patterns
- Identifies framework versions (often revealing outdated software)

### 3. **SSL/TLS Certificate**
```javascript
{
  valid:         boolean,
  issuer:        string,         // Certificate authority
  subject:       string,         // Domain in certificate
  validFrom:     ISO8601,        // Issue date
  validTo:       ISO8601,        // Expiration date
  daysRemaining: number,         // Days until expiration
  enabled:       boolean,
}
```

### 4. **DNS Records**
```javascript
{
  A:        string[],           // IPv4 addresses
  MX:       string[],           // Mail exchangers
  NS:       string[],           // Nameservers
  primaryIP: string,            // Primary IP
  resolved: boolean,            // Resolution successful?
  spf:      boolean,            // SPF record present?
  dmarc:    boolean,            // DMARC record present?
}
```

### 5. **WHOIS Data** (RDAP)
```javascript
{
  registrar:     string,        // Domain registrar
  registrantOrg: string,        // Organization name
  country:       string,        // Registrant country
  createdDate:   date,          // Domain creation date
  expiresDate:   date,          // Domain expiration date
  updatedDate:   date,          // Last update date
  nameServers:   string[],      // Authoritative nameservers
  dnssec:        string,        // DNSSEC status
}
```

### 6. **HTTP Security Headers**
```javascript
{
  "Strict-Transport-Security":  string,  // HSTS policy
  "X-Frame-Options":            string,  // Clickjacking protection
  "Content-Security-Policy":    string,  // XSS protection
  "Referrer-Policy":            string,  // Referrer leakage control
  "X-XSS-Protection":           string,  // Legacy XSS filter
  "X-Content-Type-Options":     string,  // MIME type sniffing protection
  "Permissions-Policy":         string,  // Feature/API restrictions
  "CORS (Access-Control)":      string,  // Cross-origin resource sharing
  "Server":                     string,  // Server information disclosure
  "X-Powered-By":               string,  // Tech stack disclosure
}
```

### 7. **Open Ports**
```javascript
{
  ip:       string,             // IP address
  asn:      string,             // AS number
  org:      string,             // Organization name
  country:  string,             // Geographic location
  open: [
    { port: number, service: string, banner: string },
    ...
  ],
  ports:    number[],           // Array of port numbers
}
```

### 8. **OSINT / Reputation**
```javascript
{
  reputation: {
    score:       number,        // 0-100 (100 = clean)
    blacklisted: boolean,
    blacklists:  string[],      // Blocklist names
  },
  emails:       string[],       // Domain emails from Hunter
  blacklisted:  boolean,        // DNSBL blacklist status
  blacklistHits: string[],      // Specific blocklists (Spamhaus, SURBL, etc.)
  virusTotal: {
    malicious:   number,        // AV engines flagging as malware
    suspicious:  number,
    harmless:    number,
    total:       number,        // Total AV engines scanning
    score:       number,        // Reputation score
    categories:  string[],      // Malware categories
  },
  safeBrowsing: {
    safe:        boolean,
    threats:     string[],      // MALWARE, PHISHING, etc.
  },
  cves: {
    count:       number,        // Total CVEs found
    critical:    number,        // CVSS >= 9.0
    kev:         number,        // Known exploited vulnerabilities
    details:     object[],      // Full CVE details
  }
}
```

### 9. **Geolocation**
```javascript
{
  ip:        string,            // Resolved IP
  city:      string,
  region:    string,
  country:   string,
  isp:       string,
  asn:       string,
  hosting:   boolean,           // Cloud hosted?
  provider:  string,            // AWS, Google Cloud, Cloudflare, etc.
}
```

---

## Vulnerability Detection Modules

### 1. SQL Injection (SQLMap)
**Endpoint**: `/api/sqlmap`  
**Timeout**: 90s per endpoint, 7m total cap  
**Tool**: SQLMap (command-line)

#### How It Works:
1. Takes discovered endpoints with numeric/string parameters
2. Injects SQL payloads (UNION-based, blind, time-based)
3. Analyzes responses for data exfiltration

#### Findings Structure:
```javascript
{
  vulnerable: boolean,
  url:        string,           // Vulnerable URL
  param:      string,           // Vulnerable parameter
  databases:  string[],         // Extracted database names
  tables:     object[],         // Table schemas
  data:       object[],         // Dumped records (if db() accessible)
}
```

#### Risk Scoring:
- **HIGH**: Database access confirmed
- **MEDIUM**: Blind SQLi (time-based)
- **LOW**: Detection string found but no data extracted

#### Budget Management:
- Scans up to 10 endpoints with discovered parameters
- Stops immediately if vulnerability found
- Hard timeout at 7 minutes

---

### 2. DOM-based XSS
**Endpoint**: `/api/dom-xss`  
**Timeout**: 180s  
**Method**: Headless browser simulation + JavaScript execution

#### How It Works:
1. Loads target in headless browser (Puppeteer)
2. Injects XSS test payloads into JavaScript-accessible input vectors
3. Monitors DOM for `alert()` execution (proof of code execution)
4. Checks for unsanitized `innerHTML`, `eval()`, `document.write()`

#### Findings:
```javascript
{
  vulnerable: boolean,
  sinks:      string[],        // Vulnerable sinks (innerHTML, eval, etc.)
  sources:    string[],        // Input sources (URL params, hash, storage)
  payload:    string,          // Successful payload
  context:    string,          // Where in HTML it was reflected
}
```

#### Detection Vectors:
- Query parameters: `?search=<img src=x onerror="alert(1)">`
- Fragment/hash: `#search=<svg onload="alert(1)">`
- LocalStorage/SessionStorage manipulation
- DOM mutation observation

---

### 3. Stored XSS
**Endpoint**: `/api/stored-xss`  
**Timeout**: 180s  
**Method**: Form submission + response analysis

#### How It Works:
1. Discovers forms via crawling
2. Submits XSS payloads in form fields (name, email, comment, etc.)
3. Retrieves stored data (profile, comments section, etc.)
4. Verifies payload persists in returned HTML without encoding

#### Findings:
```javascript
{
  vulnerable: boolean,
  payload:    string,          // Payload stored successfully
  storedIn:   string,          // Field where stored (comment, profile, etc.)
  retrievedIn: string,         // Page where reflected (comments feed, profile)
  severity:   "HIGH",          // Stored XSS is always high severity
}
```

#### Risk: **HIGH** (Always)
- Stored XSS affects all users visiting affected page
- No user interaction required for exploitation
- Can steal session cookies if HttpOnly not set

---

### 4. Reflected XSS (Auto XSS)
**Endpoint**: `/api/autoxss`  
**Timeout**: 180s  
**Input**: Crawled endpoints

#### How It Works:
1. Tests each discovered endpoint with context-aware payloads
2. HTML context: `<img src=x onerror="alert(1)">`
3. JavaScript context: `'}; alert(1); var x={`
4. Analyzes response for unencoded payload reflection
5. Grades confidence (High/Medium/Low)

#### Findings:
```javascript
{
  vulnerable: boolean,
  vulnerableEndpoints: [
    {
      url:        string,
      param:      string,
      payload:    string,
      context:    "HTML | JavaScript | HTML Attribute",
      confidence: "High | Medium | Low",
      encoded:    boolean,
    }
  ],
  testedEndpoints: number,       // Total endpoints tested
  base:           string,        // Base URL for relative links
}
```

#### Confidence Grading:
- **High**: Unencoded payload reflected, executable context
- **Medium**: Partially encoded or ambiguous context
- **Low**: Unlikely to be exploitable (full entity encoding, etc.)

---

### 5. Clickjacking (UI Redressing)
**Endpoint**: `/api/clickjacking`  
**Timeout**: 180s  
**Detection**: Header analysis + frame embedding test

#### How It Works:
1. Checks for `X-Frame-Options` header
2. Checks for `Content-Security-Policy` with `frame-ancestors`
3. Attempts to embed page in `<iframe>` and monitors
4. Detects if page can be framed

#### Findings:
```javascript
{
  vulnerable: boolean,          // Can be framed?
  issue:      string,           // Missing header description
  headers: {
    "X-Frame-Options":          string,
    "Content-Security-Policy":  string,
  },
  framed:     boolean,          // Successfully framed in test
}
```

#### Risk: **LOW** to **MEDIUM**
- LOW if only informational pages can be framed
- MEDIUM if sensitive operations (payments, transfers) can be framed

---

### 6. Command Injection (OS Command Injection)
**Endpoint**: `/api/command-injection`  
**Timeout**: 180s  
**Method**: Payload injection + time-based/output-based detection

#### How It Works:
1. Discovers endpoints that accept user input
2. Injects OS command separators: `; id`, `| whoami`, `&& echo`, backticks
3. Analyzes response for command output
4. Time-based blind detection: `sleep 5`

#### Payloads Tested:
```
Linux/Mac:
  ; id
  | whoami
  & whoami
  `id`
  $(id)

Windows:
  ; whoami
  | whoami
  & whoami
  dir
```

#### Findings:
```javascript
{
  vulnerable: boolean,
  payload:    string,           // Working payload
  output:     string,           // Command output (uid=0, etc.)
  type:       "blind | error | output-based",
}
```

#### Risk: **HIGH** (Always)
- Full OS command execution capability
- Can lead to complete server compromise

---

### 7. CSRF (Cross-Site Request Forgery)
**Endpoint**: `/api/csrf`  
**Timeout**: 180s  
**Input**: Crawled endpoints with forms

#### How It Works:
1. Finds all forms (POST, PUT, DELETE)
2. Checks for CSRF token presence in form
3. Verifies token validation:
   - Same token used multiple times? (Weak validation)
   - Token bound to session? (Header/cookie matching)
   - Token regenerated per request? (Strong)
4. Simulates CSRF attack by replaying request with manipulated token

#### Findings:
```javascript
{
  summary: {
    vulnerable:     number,     // Count of vulnerable forms
    testedForms:    number,
  },
  findings: [
    {
      url:          string,
      method:       "POST | PUT | DELETE",
      tokenField:   string,     // Name of CSRF token field
      vulnerable:   boolean,
      issue:        string,     // "Missing token", "Token not validated", etc.
      bypassMethod: string,     // How token validation was bypassed
    }
  ]
}
```

#### Vulnerability Indicators:
- No token in form
- Token not validated
- Same token used for all users
- Token not session-bound

#### Risk: **HIGH**
- Allows attacker to perform actions on behalf of victim
- No user notification of action

---

### 8. Sensitive Files Detection
**Endpoint**: `/api/sensitive-files`  
**Timeout**: 180s  
**Dictionary**: 1000+ common sensitive file paths

#### How It Works:
1. Tests common sensitive file locations:
   - `.env` (environment variables)
   - `.git/config` (source code exposure)
   - `/admin`, `/wp-admin` (admin panels)
   - `web.config`, `config.php` (configuration)
   - `.well-known/` (OAuth, SSL verification)
   - Backup files: `.tar.gz`, `.zip`, `.bak`
   - Database exports: `.sql`, `.mdb`
2. HTTP HEAD/GET request with timeout
3. Checks response status and content

#### Findings:
```javascript
{
  vulnerable: boolean,
  summary: {
    critical: number,          // Secrets, source code
    high:     number,          // Admin panels, configs
    medium:   number,          // Backup files
  },
  found: [
    {
      path:       string,       // e.g., "/.env"
      status:     number,       // HTTP status code
      size:       number,       // Content length
      severity:   "CRITICAL | HIGH | MEDIUM",
      type:       string,       // "Environment Variables", "Source Code", etc.
      content:    string,       // First 200 chars (if sensitive)
    }
  ]
}
```

#### Severity Breakdown:
- **CRITICAL**: `.env`, `.git`, database backups (contain secrets)
- **HIGH**: Admin panels, config files (auth bypass)
- **MEDIUM**: Backup files, logs (information leakage)

---

### 9. Open Redirect
**Endpoint**: `/api/open-redirect`  
**Timeout**: 60s  
**Detection**: Redirect chain analysis

#### How It Works:
1. Finds parameters commonly used in redirects: `redirect`, `url`, `return`, `target`, `back`, `goto`
2. Injects malicious redirect: `?redirect=http://evil.com`
3. Follows redirect and checks final destination
4. Tests URL encoding, protocol bypass

#### Payloads:
```
redirect=http://evil.com
url=javascript:alert(1)
next=//evil.com
return=data:text/html,<script>alert(1)</script>
```

#### Findings:
```javascript
{
  vulnerable: boolean,
  redirects: [
    {
      param:      string,
      payload:    string,
      redirectTo: string,       // Where it actually redirected
      dangerous:  boolean,
    }
  ]
}
```

#### Risk: **MEDIUM** to **HIGH**
- Can be used for phishing attacks
- Can bypass SSRF protections

---

### 10. CORS Misconfiguration
**Endpoint**: `/api/cors`  
**Timeout**: 60s  
**Detection**: Header validation + exploit simulation

#### How It Works:
1. Makes request with `Origin: http://attacker.com`
2. Checks response headers for wildcard CORS
3. Verifies if sensitive data/methods exposed
4. Tests credential-bearing requests

#### Findings:
```javascript
{
  vulnerable: boolean,
  corsEnabled: boolean,
  summary: {
    critical: number,          // Credentials + wildcard
    high:     number,          // Wildcard without credentials
    medium:   number,          // Overly permissive origin
  },
  headers: {
    "Access-Control-Allow-Origin":      string,
    "Access-Control-Allow-Credentials": boolean,
    "Access-Control-Allow-Methods":     string[],
    "Access-Control-Expose-Headers":    string[],
  },
  issues: [
    {
      issue:      string,       // "Wildcard origin with credentials"
      severity:   string,       // CRITICAL | HIGH
      impact:     string,       // "Any origin can access sensitive data"
    }
  ]
}
```

#### Risk Assessment:
- **CRITICAL**: Wildcard origin (`*`) + credentials allowed
- **HIGH**: Wildcard origin allowing sensitive data
- **MEDIUM**: Overly permissive origin validation

---

### 11. WordPress Security Scan
**Endpoint**: `/api/wordpress/scan`  
**Timeout**: 60s  
**Target**: WordPress-specific vulnerabilities

#### How It Works:
1. Checks if site is WordPress (by looking for `/wp-content/`, version detection)
2. Enumerates WordPress version
3. Checks for known vulnerable plugins/themes
4. Tests for:
   - User enumeration
   - XML-RPC access (brute force vector)
   - Weak admin paths
   - Outdated core version
5. Uses WPScan database or similar

#### Findings:
```javascript
{
  isWordPress: boolean,
  version:     string,          // e.g., "6.2.3"
  vulnerable: boolean,
  riskScore: {
    level:      "CRITICAL | HIGH | MEDIUM | LOW",
    score:      number,         // 0-100
  },
  findings: {
    outdatedCore: boolean,      // WordPress version < 2 releases old
    vulnerablePlugins: [
      {
        name:       string,
        version:    string,
        cve:        string[],   // CVEs affecting this version
        severity:   string,
      }
    ],
    vulnerableThemes: [
      { name: string, version: string, cve: string[] }
    ],
    userEnumeration: boolean,   // Author endpoints exposed?
    xmlrpc:         boolean,    // XML-RPC enabled?
  }
}
```

#### Risk Scenarios:
- **CRITICAL**: Outdated core + known public exploits
- **HIGH**: Vulnerable plugins with active exploits
- **MEDIUM**: Outdated theme, user enumeration possible
- **LOW**: Current version with no known vulns

---

## OSINT & Reputation Modules

These are included from the QuickScan integration:

### Shodan Lookup
- Queries Shodan database for IP/hostname
- Returns open ports, banners, services
- Lists known CVEs affecting exposed services
- Detects cloud hosting (Cloudflare proxy, AWS)
- Risk: Based on CVE count and KEV (Known Exploited Vulnerabilities) presence

### Google Safe Browsing
- Checks against Google's threat database
- Detects: MALWARE, PHISHING, SOCIAL_ENGINEERING, UNWANTED_SOFTWARE
- Real-time detection
- Risk: **CRITICAL** if flagged

### VirusTotal
- Scans domain against 70+ antivirus engines
- Returns: malicious count, suspicious count, harmless count
- Community reputation score
- Malware/phishing categories
- Risk: Based on detection ratio

### ASN & Geolocation
- IP-based geolocation via `ip-api.com`
- Returns: country, region, city, timezone, ISP, ASN
- Detects cloud hosting providers
- Risk: LOW (informational)

### Email Security (DNSBL)
- Checks domain against 7 public blocklists
- Spamhaus DBL, SURBL, URIBL, ZEN
- Barracuda, SpamCop
- Risk: **MEDIUM** if listed on 1+ lists, **HIGH** if 2+

### Green Web Check
- Verifies green energy hosting via Green Web Foundation API
- Risk: LOW (environmental indicator)

---

## Risk Assessment & Scoring

### Severity Levels

| Level | CVSS Range | Examples |
|-------|-----------|----------|
| CRITICAL | 9.0-10.0 | Remote code execution, SQLi with DB dump, CORS + creds |
| HIGH | 7.0-8.9 | Stored XSS, Unsafe redirects, Command injection, CSRF |
| MEDIUM | 4.0-6.9 | DOM XSS, Reflected XSS (high confidence), Weak headers, DNSBL listing |
| LOW | 0.1-3.9 | Clickjacking, Missing optional headers, Low confidence findings |

### Overall Risk Calculation

```javascript
const score = 
  (critical.count * 4) +    // 4 points per CRITICAL
  (high.count * 2) +        // 2 points per HIGH
  (medium.count * 1) +      // 1 point per MEDIUM
  (low.count * 0.5);        // 0.5 points per LOW

if (score >= 10) risk = "CRITICAL";
else if (score >= 7) risk = "HIGH";
else if (score >= 4) risk = "MEDIUM";
else risk = "LOW";
```

### Vulnerability Summary
```javascript
{
  critical: number,           // Count of CRITICAL findings
  high:     number,           // Count of HIGH findings
  medium:   number,           // Count of MEDIUM findings
  low:      number,           // Count of LOW findings
}
```

---

## Output & Reporting

### JSON Response Structure
```javascript
{
  success:   boolean,
  target:    string,          // Hostname
  scanType:  "FULL",
  scanId:    string,          // Unique scan identifier (for pause/resume)
  meta: {
    startedAt:   ISO8601,
    completedAt: ISO8601,
    duration:    number,      // Milliseconds
  },
  summary: {
    critical: number,
    high:     number,
    medium:   number,
    low:      number,
  },
  quickscan: {
    // Detailed reconnaissance data (see QuickScan Integration section)
  },
  vulnerabilities: {
    sqlInjection:     { found: boolean, details: object },
    domXss:           { found: boolean, details: object },
    storedXss:        { found: boolean, details: object },
    reflectedXss:     { found: boolean, details: object },
    clickjacking:     { vulnerable: boolean, details: object },
    commandInjection: { found: boolean, details: object },
    csrf:             { found: boolean, details: object },
    sensitiveFiles:   { found: boolean, details: object },
    openRedirect:     { found: boolean, details: object },
    cors:             { found: boolean, details: object },
    wordpress:        { found: boolean, details: object },
  }
}
```

### PDF Report Generation

The system generates a professional PDF report containing:

1. **Cover Page**: Target, scan date, scan type
2. **Executive Summary**: Risk overview, key findings
3. **Risk Breakdown**: Critical/High/Medium/Low counts with visualization
4. **Technology Stack**: Server, frameworks, CMS, CDN, WAF detected
5. **Vulnerability Findings**: Detailed writeup of each vulnerability found
6. **OSINT Results**: Reputation, blacklist status, threat intelligence
7. **Recommendations**: Remediation steps for each vulnerability
8. **Appendix**: Full technical details, headers, port list, etc.

### Scan Control Endpoints

#### Pause Scan
```bash
POST /api/full-scan/pause
{ "scanId": "1234567890" }
```
Pauses running scan at next module checkpoint.

#### Resume Scan
```bash
POST /api/full-scan/resume
{ "scanId": "1234567890" }
```
Resumes paused scan from last checkpoint.

---

## Module Timeout Strategy

| Module | Timeout | Rationale |
|--------|---------|-----------|
| SQLMap | 90s/endpoint, 7m cap | Brute-force intensive, early termination if found |
| XSS (all variants) | 180s | Browser simulation needed, rendering takes time |
| CSRF | 180s | Deep form crawling and session validation |
| Sensitive Files | 180s | Potentially 1000+ requests |
| Clickjacking | 180s | Frame embedding and measurement |
| Command Injection | 180s | Multiple payload types + timing |
| Open Redirect | 60s | Limited endpoints tested |
| CORS | 60s | Quick header check + simple requests |
| WordPress | 60s | Version detection + quick plugin check |

---

## Performance Optimization

1. **Endpoint Reuse**: Crawled URLs used by multiple modules (SQLi, CSRF, XSS)
2. **Parallel Execution**: All modules run simultaneously (11x speedup vs sequential)
3. **Early Termination**: SQLMap stops at first finding
4. **Timeout Management**: No single module can exceed budget
5. **Result Caching**: QuickScan results reused (not re-scanned)

---

## Error Handling

Each module has fallback behavior:
- **Module timeout**: Returns empty findings, scan continues
- **Network error**: Module marked as unavailable, logged
- **Invalid input**: Returns error message, other modules unaffected
- **Partial results**: Scan completes with partial data (marked in output)

---

## Security Considerations

1. **Rate Limiting**: Built-in delays in email enumeration to avoid triggering WAF
2. **Timeout Caps**: Prevents DOS via maliciously slow responses
3. **Sensitive Data**: Credentials/API keys stored in `.env`, never logged
4. **Results Storage**: JSON results stored temporarily, PDF generated on-demand
5. **Session Isolation**: Scans are stateless, no cross-scan data leakage

---

## Common Findings & Remediation

| Finding | Risk | Fix |
|---------|------|-----|
| Missing HSTS | MEDIUM | Add `Strict-Transport-Security: max-age=31536000` header |
| Wildcard CORS | CRITICAL | Replace `*` with specific origin |
| Outdated WordPress | HIGH | Update WordPress core and plugins |
| Missing CSP | HIGH | Add `Content-Security-Policy: default-src 'self'` |
| SQL Injection | HIGH | Use parameterized queries, input validation |
| Stored XSS | HIGH | HTML-encode user input before display |
| Reflected XSS | MEDIUM | URL-encode output based on context |
| DNSBL Listed | MEDIUM | Contact blocklist maintainer, improve email reputation |
| Exposed .env | CRITICAL | Remove from web root, add to `.gitignore` |
| Clickjacking | LOW | Add `X-Frame-Options: DENY` header |

---

## Glossary

- **DNSBL**: DNS Blocklist (checks if IP/domain listed for spam)
- **CVSS**: Common Vulnerability Scoring System (0-10 scale)
- **KEV**: Known Exploited Vulnerabilities (in active use by attackers)
- **CT Logs**: Certificate Transparency Logs (public SSL cert database)
- **WAF**: Web Application Firewall (detects/blocks attacks)
- **RDAP**: Registration Data Access Protocol (modern WHOIS)
- **XSS**: Cross-Site Scripting (inject JavaScript)
- **CSRF**: Cross-Site Request Forgery (trick user into action)
- **CORS**: Cross-Origin Resource Sharing (browser same-origin policy)
- **SQLi**: SQL Injection (database query manipulation)

---

## Related Documentation

- [QuickScan Modules](./QUICKSCAN_MODULES_DOCUMENTATION.md)
- [API Routes Reference](./webintelx-backend/routes/fullScanRoute.js)
- [Controller Implementation](./webintelx-backend/controllers/fullScanController.js)
