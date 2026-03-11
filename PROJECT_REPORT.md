# WebIntelX Project Report

## Overview
WebIntelX is a modular web security toolkit that provides fast reconnaissance, deep vulnerability scanning, phishing detection with ML, a password strength hardener, and AI-generated summaries. The repository hosts four collaborating apps:
- webintelx-backend (Node/Express): scanning orchestration and vulnerability modules (REST API on port 5000)
- webintelx-frontend (React): main UI for quick/full scans and results
- Phishing/phishing-site-or-not (Python): phishing classifier CLI used by the backend
- Password-hardener (Vite React + Node): password strength analysis and hardening suggestions

## Architecture
- Backend (Node/Express 5)
  - Exposes /api endpoints for DNS, ping, traceroute, headers, SSL, subdomain enumeration, and vulnerability checks (XSS, SQLi, CSRF, open-redirect, CORS, clickjacking, WordPress).
  - Orchestrates quick scans and full scans, consolidates results
  - Spawns the Python phishing CLI for URL classification.
- Frontend (CRA + Tailwind)
  - Interactive dashboards for Quick Scan and Full Scan.
  - Dedicated Phishing module UI and password checker route.
- Phishing Module (Python)
  - Real-time feature extraction, rule-based scoring, and ML classifier (joblib .pkl).
  - Handles typosquatting, suspicious TLDs, free-hosting heuristics, SSL/domain-age/DNS, and IP-only URL detection.
- Password Hardener (Vite React + small Express API)
  - Entropy analysis, pattern detection, crack-time estimation, and guided hardening.

## Repository Layout
- webintelx-backend: Express app, controllers, routes, utils, AI runner
- webintelx-frontend: CRA app with pages for quick/full scans, phishing, password checker
- Phishing/phishing-site-or-not: Python package, model, tests, scripts
- Password-hardener/Password-hardener: Backend (Express) and Frontend (Vite React)
- Root package.json orchestrates all services via concurrently

## Setup & Running
1) Node dependencies (root)
```
npm install
```
2) Python dependencies (phishing)
```
cd Phishing/phishing-site-or-not
pip install -r requirements.txt
```
3) Start all services
```
npm start
```
This launches:
- Main backend on http://localhost:5000
- Main frontend (CRA dev server)
- Password tool backend and frontend (Vite on port 3001)

## Environment Variables
- SHODAN_API_KEY (optional) — enriches quick scan OSINT via Shodan
- PHISHING_PYTHON_BIN (optional) — set the Python binary for Windows (e.g., py or full path)

## Key Endpoints (Backend)
- Quick Scan: POST /api/quickscan { url }
- Full Scan: POST /api/fullscan { url }, and /api/fullscan/pause, /api/fullscan/resume
- Recon: /api/nslookup, /api/whois, /api/ping, /api/traceroute, /api/portscan, /api/headers, /api/ssl, /api/whatweb
- Vulns: /api/dom-xss, /api/stored-xss, /api/autoxss, /api/sqlmap, /api/command-injection, /api/csrf, /api/sensitive-files, /api/open-redirect, /api/cors, /api/wordpress/scan
- Phishing: POST /api/phishing-check { url }
- AI Report: /api/ai-report

## Phishing Detection
- Combines ML prediction (scikit-learn model) and rules (URL/domain/content scores).
- Flags include: unreachable, brand_similarity, ssl_valid, free_hosting, ip_url, typosquat_target.
- Backend spawns the Python CLI and parses strict JSON with a 50s timeout and multi-interpreter fallback.

## Password Hardener
- Detects weak patterns, common passwords, character diversity and structure.
- Provides crack-time heuristics and a hardened suggestion if needed.
- Runs a small Express API and Vite React UI (port 3001).

## Security Notes
- CORS is permissive in development; restrict origins in production.
- External command execution is time-limited; continue to validate and sanitize inputs.
- Never log API keys or secrets; only presence checks are logged.
- Long-running scans support pausing; server timeout configured generously.

## Suggested Improvements
- Add backend unit/integration tests for parsers and endpoints.
- Containerize Node and Python services for reproducible deployments.
- Add request rate limiting and structured logging.
- Consider aligning React versions or migrating main UI to Vite for consistency.

## Troubleshooting
- Phishing route errors: ensure Python deps installed and model file present; set PHISHING_PYTHON_BIN if needed.
- Shodan data empty with Cloudflare proxied sites — expected (origin IP hidden).
- CRA proxy is set to http://localhost:5000 in webintelx-frontend/package.json.

