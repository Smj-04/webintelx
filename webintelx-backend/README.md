# WebIntelX Backend (Express)

## Overview
Express 5 API that orchestrates reconnaissance and vulnerability scanning. Provides Quick Scan and Full Scan flows, integrates phishing classification (Python), and can generate AI summaries. Runs on port 5000.

## Setup
```
cd webintelx-backend
npm install
```
Optional environment variables:
- GEMINI_API_KEY — enable AI report generation
- SHODAN_API_KEY — enrich Quick Scan with Shodan data
- PHISHING_PYTHON_BIN — specify Python binary (e.g., py on Windows)

## Running
From repo root:
```
npm start
```
Or directly:
```
node server.js
```
Server logs display route mounts and whether Gemini key is present.

## Key Endpoints
- POST /api/quickscan { url }
  - Aggregates DNS, WHOIS (RDAP), SSL, headers, subdomains, ports, endpoints; builds risk score and findings.
- POST /api/fullscan { url }
  - Runs Quick Scan first, maps results, discovers parameterized endpoints, then triggers:
    - /api/sqlmap, /api/dom-xss, /api/stored-xss, /api/autoxss, /api/clickjacking
    - /api/command-injection, /api/csrf, /api/sensitive-files, /api/open-redirect, /api/cors, /api/wordpress/scan
  - Pause/Resume:
    - POST /api/fullscan/pause
    - POST /api/fullscan/resume
- POST /api/phishing-check { url }
  - Spawns Python CLI and returns strict JSON with risk level, classification, and flags.
- Recon:
  - /api/nslookup, /api/whois, /api/ping, /api/traceroute, /api/portscan, /api/headers, /api/ssl, /api/whatweb
- AI Report:
  - /api/ai-report — summarizes scan results (requires GEMINI_API_KEY)

## Implementation Notes
- server.js registers routes under /api and sets a generous server timeout for long scans.
- quickScanController parses platform-agnostic command output and computes a consolidated risk score.
- fullScanController normalizes Quick Scan output for the frontend and coordinates vulnerability modules; supports pause/resume loops for SQLMap.
- phishingCheckRoute tries PHISHING_PYTHON_BIN → python → py with a 50s timeout and JSON parsing tolerant to extra stdout lines.

## Security
- Validate and normalize all URLs before scan.
- Restrict CORS origins in production (development is permissive).
- Avoid logging secrets; only presence checks are logged.
- External command execution uses timeouts and narrowed parsing, but review any changes to command lines for injection risk.

## Troubleshooting
- Phishing route fails: install Python deps and set PHISHING_PYTHON_BIN if necessary.
- Shodan unavailable: ensure SHODAN_API_KEY is set; Cloudflare-proxied IPs return minimal origin data by design.

