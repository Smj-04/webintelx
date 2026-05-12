// fullScanController.js - Orchestrates the entire full scan process: runs quickscan, maps results, discovers endpoints, runs all vulnerability modules in parallel, and compiles everything into a comprehensive report for the frontend. Also handles pause/resume functionality for long-running scans.

const cleanUrl = require("../utils/cleanUrl");
const endpointScanner = require("../utils/endpointScanner");
const axios = require("axios");
const dns = require("dns").promises;
const PDFDocument = require("pdfkit");
console.log("🔥 fullScanController.js LOADED");
const sensitiveFileCheck = require("../utils/sensitiveFileCheck");
const openRedirectCheck = require("../utils/openRedirectCheck");
const corsCheck = require("../utils/corsCheck");

// Helper: safe axios POST wrapper that returns settled result
async function safePost(url, body, opts = {}) {
  try {
    const r = await axios.post(url, body, opts);
    return { ok: true, data: r.data };
  } catch (err) {
    return { ok: false, error: err.message || String(err), details: err.response?.data || null };
  }
}

const scanStates = {};

async function waitIfPaused(scanId) {
  while (scanStates[scanId] === 'paused') {
    await new Promise(r => setTimeout(r, 500));
  }
}

// ==========================
// 🔹 TARGET VALIDATION
// ==========================

async function validateTarget(url) {
  try {
    const formatted = url.startsWith("http") ? url : `http://${url}`;
    const hostname = new URL(formatted).hostname;
    await dns.lookup(hostname);
    try {
      await axios.get(`https://${hostname}`, { timeout: 5000 });
    } catch {
      await axios.get(`http://${hostname}`, { timeout: 5000 });
    }
    return { valid: true };
  } catch (err) {
    return { valid: false, error: "Target is not reachable or does not exist" };
  }
}

// ==========================
// 🔹 MAP QUICKSCAN → FULLRESULT
// ─────────────────────────────
// Takes the full quickscan `data` object (qs) and maps every field
// into the structured quickscan block that the frontend expects.
// ==========================

function mapQuickscanData(qs) {
  if (!qs || typeof qs !== "object") return buildEmptyQuickscan();

  return {
    // ── Attack Surface ──────────────────────────────────────────
    attackSurface: {
      subdomainCount:  qs.securityTrails?.subdomainCount ?? 0,
      subdomains:      qs.securityTrails?.subdomains     ?? [],
      endpointCount:   Array.isArray(qs.endpoints) ? qs.endpoints.length : 0,
      endpoints:       Array.isArray(qs.endpoints) ? qs.endpoints        : [],
      openPorts:       Array.isArray(qs.openPorts) ? qs.openPorts.length : 0,
      formCount:       0,
      exposedPanels:   [],
    },

    // ── Technology Fingerprint ──────────────────────────────────
    technology: {
      server:       qs.headers?.server      || qs.headers?.raw?.server      || null,
      poweredBy:    qs.headers?.poweredBy   || qs.headers?.raw?.["x-powered-by"] || null,
      ssl:          !!(qs.ssl && qs.ssl.valid && !qs.ssl.error),
      cms:          qs.wappalyzer?.CMS      || qs.wappalyzer?.cms            || null,
      frameworks:   buildFrameworkList(qs.wappalyzer),
      cdn:          detectCdn(qs.wappalyzer, qs.headers?.raw || {}),
      waf:          detectWaf(qs.headers?.raw || {}),
    },

    // ── SSL / TLS ────────────────────────────────────────────────
    ssl: qs.ssl && !qs.ssl.error ? {
      valid:         qs.ssl.valid         ?? false,
      issuer:        qs.ssl.issuer        ?? null,
      subject:       qs.ssl.subject       ?? null,
      validFrom:     qs.ssl.validFrom     ?? null,
      validTo:       qs.ssl.validTo       ?? null,
      daysRemaining: qs.ssl.daysRemaining ?? null,
      enabled:       !!(qs.ssl.valid),
    } : null,

    // ── DNS Records ──────────────────────────────────────────────
    dns: qs.dns ? {
      A:          qs.dns.A  ?? [],
      MX:         qs.dns.MX ?? [],
      NS:         qs.dns.NS ?? [],
      primaryIP:  qs.dns.primaryIP ?? null,
      resolved:   qs.dns.resolvedSuccessfully ?? false,
      spf:        !!(qs.dns.TXT?.some?.(t => t.includes("v=spf"))),
      dmarc:      !!(qs.dns.TXT?.some?.(t => t.includes("v=DMARC"))),
    } : null,

    // ── WHOIS ────────────────────────────────────────────────────
    whois: qs.whois ? {
      registrar:     qs.whois.registrar     ?? "Unknown",
      registrantOrg: qs.whois.registrantOrg ?? "Unknown",
      country:       qs.whois.country       ?? "Unknown",
      createdDate:   qs.whois.creationDate  ?? null,
      expiresDate:   qs.whois.expiryDate    ?? null,
      updatedDate:   qs.whois.updatedDate   ?? null,
      nameServers:   qs.whois.nameservers   ?? [],
      dnssec:        qs.whois.dnssec        ?? "Unknown",
    } : null,

    // ── HTTP Security Headers ────────────────────────────────────
    headers: buildHeadersMap(qs.headers),

    // ── Open Ports ───────────────────────────────────────────────
    ports: buildPortsMap(qs.openPorts, qs.asnGeo, qs.dns),

    // ── OSINT / Reputation ───────────────────────────────────────
    osint: buildOsintMap(qs),

    // ── Geolocation ──────────────────────────────────────────────
    geo: qs.asnGeo?.available ? {
      ip:       qs.asnGeo.ip      ?? null,
      city:     qs.asnGeo.city    ?? null,
      region:   qs.asnGeo.region  ?? null,
      country:  qs.asnGeo.country ?? null,
      isp:      qs.asnGeo.isp     ?? null,
      asn:      qs.asnGeo.asn     ?? null,
      hosting:  qs.asnGeo.isCloud ?? false,
      provider: qs.asnGeo.cloudProvider ?? null,
    } : null,
  };
}

// ── Helper: build full headers map ───────────────────────────────────────────
// Quickscan returns: { server, poweredBy, strictTransport, xFrameOptions,
//   xssProtection, csp, referrer, cors, missingSecurityHeaders[], raw{} }
function buildHeadersMap(h) {
  if (!h || typeof h !== "object") return null;
  const raw = h.raw || {};
  // A header is "present" if the parsed key is non-null OR the raw header exists
  const get = (...keys) => {
    for (const k of keys) {
      const v = h[k] ?? raw[k];
      if (v !== null && v !== undefined) return v;
    }
    return false;
  };
  return {
    "Strict-Transport-Security": get("strictTransport", "strict-transport-security"),
    "X-Frame-Options":           get("xFrameOptions",   "x-frame-options"),
    "Content-Security-Policy":   get("csp",             "content-security-policy"),
    "Referrer-Policy":           get("referrer",        "referrer-policy"),
    "X-XSS-Protection":          get("xssProtection",   "x-xss-protection"),
    "X-Content-Type-Options":    get("x-content-type-options"),
    "Permissions-Policy":        get("permissions-policy"),
    "CORS (Access-Control)":     get("cors",            "access-control-allow-origin"),
    "Server":                    get("server"),
    "X-Powered-By":              get("poweredBy",       "x-powered-by"),
  };
}

// ── Helper: build ports map ───────────────────────────────────────────────────
function buildPortsMap(openPorts, asnGeo, dns) {
  if (!Array.isArray(openPorts) || openPorts.length === 0) return null;
  return {
    ip:      asnGeo?.ip || dns?.primaryIP || (dns?.A?.[0]) || null,
    asn:     asnGeo?.asn     || null,
    org:     asnGeo?.org     || null,
    country: asnGeo?.country || null,
    open: openPorts.map(p =>
      typeof p === "object"
        ? { port: p.port, service: p.name || p.service || null, banner: p.banner || null }
        : { port: p, service: null, banner: null }
    ),
    list:  openPorts,
    ports: openPorts.map(p => typeof p === "object" ? p.port : p),
  };
}

// ── Helper: build OSINT / reputation map ─────────────────────────────────────
function buildOsintMap(qs) {
  const hasData = qs.emailIntelligence || qs.virusTotal?.available
    || qs.safeBrowsing?.available || qs.shodan?.available;
  if (!hasData) return null;

  return {
    // Blacklist / reputation
    reputation: qs.virusTotal?.available ? {
      score:       Math.max(0, 100 - (qs.virusTotal.malicious || 0) * 10),
      blacklisted: (qs.virusTotal.malicious || 0) > 0,
      blacklists:  [], // VirusTotal doesn't give list names in free tier
    } : null,

    // Email intel from Hunter + DNSBL
    emails: qs.emailIntelligence?.hunter?.emails?.map(e => e.email || e) ?? [],

    // DNSBL blacklists
    blacklisted:  qs.emailIntelligence?.dnsbl?.listed  ?? false,
    blacklistHits: qs.emailIntelligence?.dnsbl?.listedOn ?? [],

    // VirusTotal summary
    virusTotal: qs.virusTotal?.available ? {
      malicious:  qs.virusTotal.malicious  ?? 0,
      suspicious: qs.virusTotal.suspicious ?? 0,
      harmless:   qs.virusTotal.harmless   ?? 0,
      total:      qs.virusTotal.total      ?? 0,
      score:      qs.virusTotal.communityScore ?? 0,
      categories: qs.virusTotal.categories ?? [],
    } : null,

    // Safe Browsing
    safeBrowsing: qs.safeBrowsing?.available ? {
      safe:     qs.safeBrowsing.safe ?? true,
      threats:  qs.safeBrowsing.threats ?? [],
    } : null,

    // Shodan CVEs
    cves: qs.shodan?.vulnDetails?.length > 0 ? {
      count:    qs.shodan.vulnCount ?? 0,
      critical: qs.shodan.criticalCount ?? 0,
      kev:      qs.shodan.kevCount ?? 0,
      details:  qs.shodan.vulnDetails.slice(0, 10),
    } : null,
  };
}

// ── Helper: build frameworks list from wappalyzer output ─────────────────────
function buildFrameworkList(wappalyzer) {
  if (!wappalyzer || typeof wappalyzer !== "object") return [];
  const skip = new Set(["CMS", "cms", "Server", "server"]);
  return Object.entries(wappalyzer)
    .filter(([k]) => !skip.has(k))
    .map(([k, v]) => v && v !== "Unknown" ? `${k} ${v}`.trim() : k)
    .slice(0, 12);
}

// ── Helper: detect CDN from wappalyzer / headers ──────────────────────────────
function detectCdn(wappalyzer, headers) {
  const cdnKeys = ["Cloudflare", "Fastly", "Akamai", "CloudFront", "jsDelivr", "Netlify", "Vercel"];
  if (wappalyzer) {
    const found = cdnKeys.find(k => wappalyzer[k]);
    if (found) return found;
  }
  const via = headers["via"] || headers["x-served-by"] || headers["x-cache"] || "";
  const cfRay = headers["cf-ray"];
  if (cfRay) return "Cloudflare";
  if (via.toLowerCase().includes("varnish")) return "Varnish";
  return null;
}

// ── Helper: detect WAF from headers ──────────────────────────────────────────
function detectWaf(headers) {
  if (headers["x-sucuri-id"])    return "Sucuri";
  if (headers["x-fw-hash"])      return "Wordfence";
  if (headers["cf-ray"])         return "Cloudflare WAF";
  if (headers["x-cdn"])          return headers["x-cdn"];
  return null;
}

// ── Fallback empty quickscan block ───────────────────────────────────────────
function buildEmptyQuickscan() {
  return {
    attackSurface: { subdomainCount: 0, subdomains: [], endpointCount: 0, endpoints: [], openPorts: 0, formCount: 0, exposedPanels: [] },
    technology:    { backend: null, server: null, poweredBy: null, ssl: false, cms: null, frameworks: [], cdn: null, waf: null },
    ssl:           null, dns: null, whois: null, headers: null, ports: null, osint: null, geo: null,
  };
}

// ==========================
// 🔹 MAIN EXPORT
// ==========================

exports.fullScan = async (req, res) => {
  console.log("🔥 FULLSCAN CONTROLLER LOADED");

  const { url } = req.body;
  if (!url) return res.status(400).json({ error: "URL required" });

  const startedAt = new Date().toISOString();
  const baseUrl = cleanUrl(url);
  const scanId = Date.now().toString();
  scanStates[scanId] = 'running';

  const validation = await validateTarget(baseUrl);
  if (!validation.valid) {
    delete scanStates[scanId];
    return res.status(400).json({ success: false, error: validation.error });
  }

  const fullResult = {
    success: true,
    target: null,
    scanType: "FULL",
    meta: { startedAt, completedAt: null },
    summary: { critical: 0, high: 0, medium: 0, low: 0 },
    quickscan: buildEmptyQuickscan(),   // ← starts empty, gets replaced below
    vulnerabilities: {
      sqlInjection:    { found: false, details: null },
      domXss:          { found: false, details: null },
      storedXss:       { found: false, details: null },
      reflectedXss:    { found: false, details: null },
      clickjacking:    { vulnerable: false, headers: {} },
      commandInjection:{ found: false, details: null },
      csrf:            { found: false, details: null },
      sensitiveFiles:  { found: false, details: null },
      openRedirect:    { found: false, details: null },
      cors:            { found: false, details: null },
      wordpress:       { found: false, details: null },
    }
  };

  try {
    // ─────────────────────────────────────────────────────────────
    // 1) Run QuickScan and map ALL fields into fullResult.quickscan
    // ─────────────────────────────────────────────────────────────
    const quick = await safePost("http://localhost:5000/api/quickscan", { url: baseUrl }, { timeout: 180000 });

   if (quick.ok && quick.data?.success) {
      const qs = quick.data.data || {};

      try {
        fullResult.target = new URL(baseUrl).hostname;
      } catch {
        fullResult.target = baseUrl;
      }

      fullResult.quickscan = mapQuickscanData(qs);
      fullResult._rawHeaders = qs.headers || {};

    } else {
      try { fullResult.target = new URL(baseUrl).hostname; }
      catch { fullResult.target = baseUrl; }
      console.warn("QuickScan returned error or was unreachable:", quick.error);
      // ⛔ DO NOT return early here — must continue to vulnerability modules
    }

    // ✅ Safety guard — ensure no accidental early response was sent
    if (res.headersSent) {
      console.error("❌ Response already sent before vulnerability scan — aborting");
      return;
    }

    // ─────────────────────────────────────────────────────────────
    // 2) Discover endpoints for SQLMap
    // ─────────────────────────────────────────────────────────────
    // Crawl the site ONCE and reuse discovered links for all scanners
    let crawledLinks = [];
    try {
      const { discoverEndpoints } = require("../utils/endpointDiscovery");
      crawledLinks = await discoverEndpoints(baseUrl, 2); // depth 2 to get behind nav links
    } catch {}

    // Build SQLi endpoint list: crawled links with params + endpointScanner probes
    let endpoints = [];
    try {
      // Extract any crawled URLs that already have numeric query params
      const seen = new Set();
      for (const link of crawledLinks) {
        try {
          const u = new URL(link);
          for (const [param, value] of u.searchParams.entries()) {
            if (/^\d+$/.test(value)) {
              const key = `${link}::${param}`;
              if (!seen.has(key)) {
                seen.add(key);
                endpoints.push({ url: link, param });
              }
            }
          }
        } catch {}
      }

      // Also run endpointScanner for sites where crawl finds nothing with params
      if (endpoints.length === 0) {
        const scanned = await endpointScanner(baseUrl);
        for (const e of scanned) {
          const key = `${e.url}::${e.param}`;
          if (!seen.has(key)) {
            seen.add(key);
            endpoints.push(e);
          }
        }
      }

      console.log(`[SQLi] Discovered ${endpoints.length} endpoint(s) to test:`, endpoints.map(e => `${e.url} [${e.param}]`));
    } catch {
      endpoints = [];
    }

    // Also add any crawled URLs that have query parameters — these are prime SQLi targets
    // ─────────────────────────────────────────────────────────────
    // 3) Run all vulnerability modules in parallel
    // ─────────────────────────────────────────────────────────────
    const [sqlResult, ...moduleResults] = await Promise.allSettled([

     // SQLMap with pause support + 7-minute overall cap
      (async () => {
        const SQL_TOTAL_TIMEOUT = 7 * 60 * 1000; // 7 minutes hard cap for entire SQLi phase
        const sqlStart = Date.now();
 
        const sqlFindings = [];
        for (const target of endpoints) {
          // ── Hard cap: if 7 mins elapsed since SQLi started, stop immediately ──
          if (Date.now() - sqlStart >= SQL_TOTAL_TIMEOUT) {
            console.log(`[SQLi] Overall timeout reached (${SQL_TOTAL_TIMEOUT / 60000}m) — stopping endpoint loop`);
            break;
          }
 
          await waitIfPaused(scanId);
 
          // Per-endpoint timeout = whichever is smaller:
          // remaining budget OR 90s cap so one endpoint can't eat the whole budget
          const remaining = SQL_TOTAL_TIMEOUT - (Date.now() - sqlStart);
          const perEndpointTimeout = Math.min(90000, remaining);
 
          if (perEndpointTimeout <= 0) break; // budget exhausted
 
          const resSql = await safePost(
            "http://localhost:5000/api/sqlmap",
            { url: target.url, param: target.param },
            { timeout: perEndpointTimeout }
          );
 
          if (resSql.ok && resSql.data?.vulnerable) {
            console.log("SQLMap response data:", JSON.stringify(resSql.data));
            sqlFindings.push({
              url:       resSql.data.url       || target.url,
              param:     resSql.data.param     || target.param,
              databases: resSql.data.databases || resSql.data.dbs || resSql.data.extractedDatabases || [],
            });
            console.log("🔥 SQLi found — stopping endpoint loop early");
            break;
          }
        }
        return sqlFindings;
      })(),

      axios.post("http://localhost:5000/api/dom-xss",          { url: baseUrl }, { timeout: 180000 }),
      axios.post("http://localhost:5000/api/stored-xss",       { url: baseUrl }, { timeout: 180000 }),
      axios.post("http://localhost:5000/api/autoxss", { url: baseUrl, endpoints: crawledLinks }, { timeout: 180000 }),
      axios.post("http://localhost:5000/api/clickjacking",     { url: baseUrl }, { timeout: 180000 }),
      axios.post("http://localhost:5000/api/command-injection",{ url: baseUrl }, { timeout: 180000 }),
      axios.post("http://localhost:5000/api/csrf",    { url: baseUrl, deep: true, endpoints: crawledLinks }, { timeout: 180000 }),      axios.post("http://localhost:5000/api/sensitive-files",  { url: baseUrl }, { timeout: 180000 }),
      axios.post("http://localhost:5000/api/open-redirect",    { url: baseUrl }, { timeout: 60000  }),
      axios.post("http://localhost:5000/api/cors",             { url: baseUrl }, { timeout: 60000  }),
      axios.post("http://localhost:5000/api/wordpress/scan",   { url: baseUrl }, { timeout: 60000  }),
    ]);

    // ─────────────────────────────────────────────────────────────
    // 4) Process results
    // ─────────────────────────────────────────────────────────────
    if (sqlResult.status === "fulfilled") {
      const sqlFindings = sqlResult.value;
      if (sqlFindings.length > 0) {
        fullResult.vulnerabilities.sqlInjection.found = true;
        fullResult.vulnerabilities.sqlInjection.details = { findings: sqlFindings };
        fullResult.summary.high += 1;
      }
    }

    const safeModule = (settled) => {
      if (!settled) return { ok: false };
      if (settled.status === "fulfilled") return { ok: true, data: settled.value.data };
      return { ok: false, error: settled.reason?.message || String(settled.reason) };
    };

    const domRes          = safeModule(moduleResults[0]);
    const storedRes       = safeModule(moduleResults[1]);
    const reflectedRes    = safeModule(moduleResults[2]);
    const clickRes        = safeModule(moduleResults[3]);
    const cmdRes          = safeModule(moduleResults[4]);
    const csrfRes         = safeModule(moduleResults[5]);
    const sensitiveRes    = safeModule(moduleResults[6]);
    const openRedirectRes = safeModule(moduleResults[7]);
    const corsRes         = safeModule(moduleResults[8]);
    const wordpressRes    = safeModule(moduleResults[9]);

    if (domRes.ok && domRes.data) {
      fullResult.vulnerabilities.domXss.found   = !!domRes.data.vulnerable;
      fullResult.vulnerabilities.domXss.details = domRes.data || null;
      if (domRes.data.vulnerable) fullResult.summary.medium += 1;
    }

    if (storedRes.ok && storedRes.data) {
      fullResult.vulnerabilities.storedXss.found   = !!storedRes.data.vulnerable;
      fullResult.vulnerabilities.storedXss.details = storedRes.data || null;
      if (storedRes.data.vulnerable) fullResult.summary.high += 1;
    }

    if (reflectedRes.ok && reflectedRes.data) {
      const vulnEps = reflectedRes.data.vulnerableEndpoints || [];
      // Only count as found if there are High confidence results
      // (Low confidence = encoded chars = likely safe)
      const confirmed = vulnEps.filter(ep =>
        ep.confidence === "High" ||
        ep.findings?.some(f => f.confidence === "High")
      );
      fullResult.vulnerabilities.reflectedXss.found   = confirmed.length > 0;
      fullResult.vulnerabilities.reflectedXss.details = {
        testedEndpoints:     reflectedRes.data.testedEndpoints || 0,
        vulnerableEndpoints: confirmed,
        base:                reflectedRes.data.base || null,
      };
      if (confirmed.length > 0) fullResult.summary.medium += 1;
    }

    if (clickRes.ok && clickRes.data) {
      fullResult.vulnerabilities.clickjacking = {
        vulnerable: !!clickRes.data.vulnerable,
        details: {
          issue:   clickRes.data.issue || "Missing X-Frame-Options / CSP frame-ancestors",
          headers: fullResult._rawHeaders || {},
        },
      };
      if (clickRes.data.vulnerable) fullResult.summary.low += 1;
    }

    if (cmdRes.ok && cmdRes.data) {
      fullResult.vulnerabilities.commandInjection.found   = !!cmdRes.data.vulnerable;
      fullResult.vulnerabilities.commandInjection.details = cmdRes.data || null;
      if (cmdRes.data.vulnerable) fullResult.summary.high += 1;
    }

    if (csrfRes.ok && csrfRes.data) {
      const csrfVuln = (csrfRes.data.summary?.vulnerable || 0) > 0;
      fullResult.vulnerabilities.csrf.found   = csrfVuln;
      fullResult.vulnerabilities.csrf.details = csrfRes.data || null;
      if (csrfVuln) fullResult.summary.high += 1;
    }

    if (sensitiveRes.ok && sensitiveRes.data) {
      fullResult.vulnerabilities.sensitiveFiles.found   = !!sensitiveRes.data.vulnerable;
      fullResult.vulnerabilities.sensitiveFiles.details = sensitiveRes.data || null;
      if      (sensitiveRes.data.summary?.critical > 0) fullResult.summary.critical += 1;
      else if (sensitiveRes.data.summary?.high     > 0) fullResult.summary.high     += 1;
      else if (sensitiveRes.data.vulnerable)            fullResult.summary.medium   += 1;
    }

    if (openRedirectRes.ok && openRedirectRes.data) {
      fullResult.vulnerabilities.openRedirect.found   = !!openRedirectRes.data.vulnerable;
      fullResult.vulnerabilities.openRedirect.details = openRedirectRes.data || null;
      if (openRedirectRes.data.vulnerable) fullResult.summary.high += 1;
    }

    if (corsRes.ok && corsRes.data) {
      fullResult.vulnerabilities.cors.found   = !!corsRes.data.vulnerable;
      fullResult.vulnerabilities.cors.details = corsRes.data || null;
      if (corsRes.data.vulnerable) {
        if      (corsRes.data.summary?.critical > 0) fullResult.summary.critical += 1;
        else if (corsRes.data.summary?.high     > 0) fullResult.summary.high     += 1;
        else                                         fullResult.summary.medium   += 1;
      }
    }

    if (wordpressRes.ok && wordpressRes.data?.isWordPress) {
      const wp    = wordpressRes.data;
      const score = wp.riskScore?.level;
      fullResult.vulnerabilities.wordpress.found   = true;
      fullResult.vulnerabilities.wordpress.details = wp;
      if      (score === "CRITICAL") fullResult.summary.critical += 1;
      else if (score === "HIGH")     fullResult.summary.high     += 1;
      else if (score === "MEDIUM")   fullResult.summary.medium   += 1;
      else                           fullResult.summary.low      += 1;
    }

    // Clean up internal temp key before sending
    delete fullResult._rawHeaders;

    fullResult.meta.completedAt = new Date().toISOString();
    delete scanStates[scanId];

    return res.json({ ...fullResult, scanId });

  } catch (err) {
    console.error("FullScan orchestration failed:", err);
    fullResult.meta.completedAt = new Date().toISOString();
    delete scanStates[scanId];
    return res.status(500).json({
      success: false,
      error: "FullScan failed to complete",
      details: err.message,
      partial: fullResult,
    });
  }
};

// ==========================
// 🔹 PAUSE / RESUME
// ==========================

exports.pauseScan = (req, res) => {
  const { scanId } = req.body;
  if (scanId && scanStates[scanId] !== undefined) {
    scanStates[scanId] = "paused";
    console.log(`⏸ Scan ${scanId} paused`);
    return res.json({ status: "paused", scanId });
  }
  return res.status(404).json({ error: "Scan not found or already completed" });
};

exports.resumeScan = (req, res) => {
  const { scanId } = req.body;
  if (scanId && scanStates[scanId] !== undefined) {
    scanStates[scanId] = "running";
    console.log(`▶ Scan ${scanId} resumed`);
    return res.json({ status: "running", scanId });
  }
  return res.status(404).json({ error: "Scan not found or already completed" });
};

// ==========================
// 🔹 PDF GENERATOR  (drop-in replacement)
// ==========================

exports.generateFullScanPDF = async (scanData, target, res) => {
  try {
    const PDFDocument = require("pdfkit");
    const doc = new PDFDocument({ size: "A4", margin: 50, bufferPages: true });
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="FullScan-${target}.pdf"`);
    doc.pipe(res);

    // ── Colour palette ────────────────────────────────────────────────────────
    const C = {
      brand:    "#1e40af",
      heading:  "#111827",
      subhead:  "#1f2937",
      body:     "#111111",
      muted:    "#6b7280",
      critical: "#dc2626",
      high:     "#ea580c",
      medium:   "#d97706",
      low:      "#2563eb",
      safe:     "#16a34a",
      border:   "#e5e7eb",
      rowBg:    "#f9fafb",
    };

    // ── Layout constants ──────────────────────────────────────────────────────
    const L = 50;           // left margin
    const R = 545;          // right edge
    const W = R - L;        // usable width
    const LABEL_W  = 160;   // label column width
    const VALUE_X  = L + LABEL_W + 10;  // where value text starts
    const VALUE_W  = R - VALUE_X;       // value column width
    const IND      = 65;    // indented left margin (inside numbered items)
    const IND_V_X  = IND + LABEL_W + 5; // indented value X
    const IND_V_W  = R - IND_V_X;

    // ── Guard: new page if not enough room ───────────────────────────────────
    const ensureSpace = (needed = 40) => {
      if (doc.y > doc.page.height - doc.page.margins.bottom - needed) {
        doc.addPage();
      }
    };

    // ── Divider line ─────────────────────────────────────────────────────────
    const divider = (top = 0.5, bottom = 0.5) => {
      doc.moveDown(top);
      doc.moveTo(L, doc.y).lineTo(R, doc.y).strokeColor(C.border).lineWidth(0.5).stroke();
      doc.moveDown(bottom);
    };

    // ── Section title ─────────────────────────────────────────────────────────
    const sectionTitle = (text, color = C.heading) => {
      ensureSpace(30);
      doc.moveDown(0.6);
      doc.fontSize(13).fillColor(color).font("Helvetica-Bold").text(text);
      doc.font("Helvetica");
      doc.moveDown(0.4);
    };

    // ── Two-column key/value row (top-level, L=50) ────────────────────────────
    const field = (label, value, valueColor = C.body, leftX = L) => {
      const raw     = String(value ?? "N/A");
      const display = raw.length > 90 ? raw.substring(0, 90) + "…" : raw;
      const valX    = leftX + LABEL_W + 10;
      const valW    = R - valX;
      ensureSpace(18);
      const y = doc.y;
      doc.fontSize(9).fillColor(C.muted).font("Helvetica")
        .text(label, leftX, y, { width: LABEL_W, lineBreak: false });
      doc.fontSize(9).fillColor(valueColor).font("Helvetica")
        .text(display, valX, y, { width: valW });
      // moveDown already handled by PDFKit's text() — just add a tiny gap
      doc.moveDown(0.15);
    };

    // ── Indented sub-field (inside numbered items, leftX = IND) ──────────────
    const subField = (label, value, valueColor = C.body) =>
      field(label, value, valueColor, IND);

    // ── Numbered finding header (bold url / title line) ───────────────────────
    const findingHeader = (n, text, color = C.body) => {
      ensureSpace(20);
      const clipped = text.length > 80 ? text.substring(0, 80) + "…" : text;
      doc.fontSize(9).fillColor(color).font("Helvetica-Bold")
        .text(`${n}.  ${clipped}`, L, doc.y, { width: W });
      doc.font("Helvetica");
      doc.moveDown(0.2);
    };

    // ── Vuln block wrapper ────────────────────────────────────────────────────
    const sevColor = (s) =>
      s === "CRITICAL" ? C.critical : s === "HIGH" ? C.high : s === "MEDIUM" ? C.medium : C.low;

    const vulnBlock = (title, severity, children) => {
      ensureSpace(50);
      doc.moveDown(0.7);
      // Thin coloured left bar
      const barY = doc.y;
      // Title + badge on same line
      doc.fontSize(11).fillColor(C.subhead).font("Helvetica-Bold")
        .text(title, L, doc.y, { width: 310, lineBreak: false, continued: true });
      doc.fontSize(8).fillColor(sevColor(severity)).font("Helvetica")
        .text(`  [${severity}]`, { lineBreak: false, continued: false });
      doc.font("Helvetica");
      doc.moveDown(0.4);
      // draw left accent bar retroactively
      doc.save()
        .rect(L - 8, barY, 3, doc.y - barY)
        .fill(sevColor(severity))
        .restore();
      children();
      doc.moveDown(0.5);
    };

    // =========================================================================
    // COVER PAGE
    // =========================================================================
    doc.fontSize(22).fillColor(C.brand).font("Helvetica-Bold")
      .text("WebIntelX", { align: "center" });
    doc.font("Helvetica");
    doc.fontSize(11).fillColor(C.muted).text("Full Scan Security Report", { align: "center" });
    doc.moveDown(1.5);

    [
      ["Target",        target],
      ["Scan Type",     "Full Scan"],
      ["Generated On",  new Date().toUTCString()],
      ["Started",       scanData.meta?.startedAt   || "—"],
      ["Completed",     scanData.meta?.completedAt || "—"],
    ].forEach(([k, v]) => field(k, v));

    divider();

    // =========================================================================
    // RISK SCORE SUMMARY
    // =========================================================================
    sectionTitle("Risk Score Summary");
    const s = scanData.summary || {};
    const riskItems = [
      { label: "CRITICAL", val: s.critical ?? 0, color: C.critical },
      { label: "HIGH",     val: s.high     ?? 0, color: C.high     },
      { label: "MEDIUM",   val: s.medium   ?? 0, color: C.medium   },
      { label: "LOW",      val: s.low      ?? 0, color: C.low      },
    ];

    // Draw coloured pill badges side by side
    let pillX = L;
    const pillY = doc.y;
    riskItems.forEach(r => {
      const label = `${r.label}: ${r.val}`;
      doc.save()
        .roundedRect(pillX, pillY, 100, 20, 4)
        .fillAndStroke("#f3f4f6", r.color)
        .restore();
      doc.fontSize(9).fillColor(r.color).font("Helvetica-Bold")
        .text(label, pillX + 6, pillY + 5, { width: 88, lineBreak: false });
      pillX += 112;
    });
    doc.font("Helvetica");
    doc.y = pillY + 28;
    doc.moveDown(0.4);

    const totalFound = riskItems.reduce((a, r) => a + r.val, 0);
    doc.fontSize(9).fillColor(C.muted)
      .text(`${totalFound} issue${totalFound !== 1 ? "s" : ""} detected across all vulnerability modules.`);
    divider();

    // =========================================================================
    // ATTACK SURFACE
    // =========================================================================
    sectionTitle("Attack Surface Summary");
    const atk  = scanData.quickscan?.attackSurface || {};
    const tech  = scanData.quickscan?.technology   || {};
    const hdrs  = scanData.quickscan?.headers      || {};
    const ports = scanData.quickscan?.ports;

    field("Subdomains Discovered",     atk.subdomainCount ?? 0);
    field("Parameterized Endpoints",   atk.endpointCount  ?? 0);
    field("Open Ports",                atk.openPorts      ?? 0);
    if (atk.formCount) field("Forms Detected", atk.formCount);

    if (tech.server || tech.poweredBy || tech.cms || tech.cdn || tech.waf) {
      doc.moveDown(0.5);
      doc.fontSize(10).fillColor(C.muted).font("Helvetica-Bold").text("Technology Stack");
      doc.font("Helvetica");
      doc.moveDown(0.25);
      if (tech.server)              field("Web Server",   tech.server);
      if (tech.poweredBy)           field("Powered By",   tech.poweredBy);
      if (tech.cms)                 field("CMS",          tech.cms);
      if (tech.cdn)                 field("CDN",          tech.cdn);
      if (tech.waf)                 field("WAF",          tech.waf);
      if (tech.frameworks?.length)  field("Frameworks",   tech.frameworks.join(", "));
      field("SSL / HTTPS", tech.ssl ? "Enabled" : "Not Enabled", tech.ssl ? C.safe : C.high);
    }

    const missingHdrs = Object.entries(hdrs)
      .filter(([, v]) => !v || v === false)
      .map(([k]) => k);
    if (missingHdrs.length > 0) {
      doc.moveDown(0.5);
      doc.fontSize(10).fillColor(C.muted).font("Helvetica-Bold").text("Missing Security Headers");
      doc.font("Helvetica");
      doc.moveDown(0.25);
      missingHdrs.forEach(h => {
        ensureSpace(14);
        doc.fontSize(9).fillColor(C.high).text(`  ✗  ${h}`);
      });
    }

    if (ports?.open?.length > 0) {
      doc.moveDown(0.5);
      doc.fontSize(10).fillColor(C.muted).font("Helvetica-Bold")
        .text(`Open Ports  (IP: ${ports.ip || "—"})`);
      doc.font("Helvetica");
      doc.moveDown(0.25);
      ports.open.forEach(p => {
        const sensitive = [21,22,23,25,3306,5432,6379,27017,8080,8443,1433,3389]
          .includes(Number(p.port));
        ensureSpace(14);
        doc.fontSize(9)
          .fillColor(sensitive ? C.high : C.body)
          .text(`  ${p.port}${p.service ? `  —  ${p.service}` : ""}${sensitive ? "  ⚠ Sensitive" : ""}`);
      });
    }

    divider();

    // =========================================================================
    // VULNERABILITY ASSESSMENT TABLE
    // =========================================================================
    sectionTitle("Vulnerability Assessment Results");
    const vuln = scanData.vulnerabilities || {};

    const vulnRows = [
      { name: "SQL Injection",           sev: "HIGH",     found: vuln.sqlInjection?.found      },
      { name: "DOM XSS",                 sev: "MEDIUM",   found: vuln.domXss?.found            },
      { name: "Stored XSS",              sev: "HIGH",     found: vuln.storedXss?.found         },
      { name: "Reflected XSS",           sev: "MEDIUM",   found: vuln.reflectedXss?.found      },
      { name: "Clickjacking",            sev: "LOW",      found: vuln.clickjacking?.vulnerable },
      { name: "Command Injection",       sev: "CRITICAL", found: vuln.commandInjection?.found  },
      { name: "CSRF",                    sev: "HIGH",     found: vuln.csrf?.found              },
      { name: "Sensitive File Exposure", sev: "HIGH",     found: vuln.sensitiveFiles?.found    },
      { name: "Open Redirect",           sev: "HIGH",     found: vuln.openRedirect?.found      },
      { name: "CORS Misconfiguration",   sev: "HIGH",     found: vuln.cors?.found              },
      { name: "WordPress Security",      sev: "MEDIUM",   found: vuln.wordpress?.found         },
    ];

    // Column X positions for the table
    const COL = { num: L, name: L + 18, sev: L + 255, status: L + 350 };

    // Header row
    ensureSpace(24);
    const thY = doc.y;
    doc.save().rect(L, thY, W, 18).fill("#e5e7eb").restore();
    doc.fontSize(8).fillColor(C.subhead).font("Helvetica-Bold");
    doc.text("#",          COL.num,    thY + 5, { width: 16,  lineBreak: false });
    doc.text("Vulnerability",  COL.name,   thY + 5, { width: 230, lineBreak: false });
    doc.text("Severity",   COL.sev,    thY + 5, { width: 90,  lineBreak: false });
    doc.text("Status",     COL.status, thY + 5, { width: 130, lineBreak: false });
    doc.font("Helvetica");
    doc.y = thY + 22;

    vulnRows.forEach((r, i) => {
      ensureSpace(18);
      const rowY = doc.y;
      if (i % 2 === 0) {
        doc.save().rect(L, rowY, W, 16).fill(C.rowBg).restore();
      }
      const sc = sevColor(r.sev);
      const statusTxt   = r.found ? "DETECTED"  : "NOT FOUND";
      const statusColor = r.found ? C.high       : C.safe;

      doc.fontSize(8).fillColor(C.muted).font("Helvetica")
        .text(`${i + 1}`, COL.num, rowY + 4, { width: 16, lineBreak: false });
      doc.fillColor(C.body)
        .text(r.name,     COL.name,   rowY + 4, { width: 230, lineBreak: false });
      doc.fillColor(sc)
        .text(r.sev,      COL.sev,    rowY + 4, { width: 90,  lineBreak: false });
      doc.fillColor(statusColor).font("Helvetica-Bold")
        .text(statusTxt,  COL.status, rowY + 4, { width: 130, lineBreak: false });
      doc.font("Helvetica");
      doc.y = rowY + 18;
    });

    divider();

    // =========================================================================
    // DETAILED FINDINGS
    // =========================================================================
    sectionTitle("Detailed Findings");

    // ── SQL Injection ─────────────────────────────────────────────────────────
    if (vuln.sqlInjection?.found) {
      vulnBlock("SQL Injection", "HIGH", () => {
        const findings = vuln.sqlInjection.details?.findings || [];
        if (findings.length === 0) {
          doc.fontSize(9).fillColor(C.muted).text("No detailed findings available.", IND);
        } else {
          findings.forEach((f, idx) => {
            findingHeader(idx + 1, `${f.url || "Unknown URL"}`, C.body);
            subField("Parameter", f.param    || "Unknown");
            subField("Databases", (f.databases || []).join(", ") || "N/A");
            doc.moveDown(0.3);
          });
        }
      });
    }

    // ── DOM XSS ───────────────────────────────────────────────────────────────
    if (vuln.domXss?.found) {
      vulnBlock("DOM-Based XSS", "MEDIUM", () => {
        const evidence = vuln.domXss.details?.evidence;
        if (Array.isArray(evidence) && evidence.length > 0) {
          evidence.forEach((item, idx) => {
            findingHeader(idx + 1, `Type: ${item.type || "Unknown"}`);
            subField("Location",   item.location   || "Unknown");
            subField("Evidence",   item.evidence   || "N/A");
            subField("Confidence", item.confidence || "Unknown",
              (item.confidence || "").toLowerCase() === "high" ? C.high : C.muted);
            doc.moveDown(0.3);
          });
        } else {
          doc.fontSize(9).fillColor(C.muted)
            .text(vuln.domXss.details?.notes || "DOM-based XSS payload detected.", IND);
        }
      });
    }

    // ── Stored XSS ────────────────────────────────────────────────────────────
    if (vuln.storedXss?.found) {
      vulnBlock("Stored XSS", "HIGH", () => {
        const evidence = vuln.storedXss.details?.evidence;
        if (Array.isArray(evidence) && evidence.length > 0) {
          evidence.forEach((item, idx) => {
            findingHeader(idx + 1, `Location: ${item.location || "Unknown"}`);
            subField("Payload",    (item.payload    || "N/A").substring(0, 80));
            subField("Evidence",   (item.evidence   || "N/A").substring(0, 80));
            subField("Confidence", item.confidence  || "Unknown",
              (item.confidence || "").toLowerCase() === "high" ? C.high : C.muted);
            doc.moveDown(0.3);
          });
        } else {
          doc.fontSize(9).fillColor(C.muted)
            .text(vuln.storedXss.details?.notes || "Stored XSS payload persisted and reflected.", IND);
        }
      });
    }

    // ── Reflected XSS ─────────────────────────────────────────────────────────
    if (vuln.reflectedXss?.found) {
      vulnBlock("Reflected XSS", "MEDIUM", () => {
        const d    = vuln.reflectedXss.details || {};
        const eps  = d.vulnerableEndpoints || [];
        field("Endpoints Tested",     d.testedEndpoints ?? 0, C.body, L);
        field("Vulnerable Endpoints", eps.length,             C.high, L);
        doc.moveDown(0.3);
        eps.slice(0, 10).forEach((ep, idx) => {
          findingHeader(idx + 1, ep.url || "Unknown URL");
          (ep.findings || []).slice(0, 3).forEach(f => {
            subField(f.type || "Finding",
              `${(f.evidence || "Detected").substring(0, 60)}  (${f.confidence || "unknown"})`);
          });
          doc.moveDown(0.25);
        });
      });
    }

    // ── Clickjacking ──────────────────────────────────────────────────────────
    if (vuln.clickjacking?.vulnerable) {
      vulnBlock("Clickjacking", "LOW", () => {
        const d = vuln.clickjacking.details || {};
        field("Issue",          d.issue || "Missing X-Frame-Options / CSP frame-ancestors", C.high, L);
        field("Recommendation", "Add X-Frame-Options: DENY  or  Content-Security-Policy: frame-ancestors 'none'", C.body, L);
      });
    }

    // ── Command Injection ─────────────────────────────────────────────────────
    if (vuln.commandInjection?.found) {
      vulnBlock("Command Injection", "CRITICAL", () => {
        const d = vuln.commandInjection.details || {};
        field("Confidence", d.confidence || "Unknown", C.critical, L);
        field("Notes",      (d.notes || "OS command injection vulnerability confirmed.").substring(0, 100), C.body, L);
        const evidence = Array.isArray(d.evidence) ? d.evidence : [];
        if (evidence.length > 0) {
          doc.moveDown(0.35);
          evidence.slice(0, 5).forEach((item, idx) => {
            findingHeader(idx + 1, `Parameter: ${item.parameter || "Unknown"}`, C.critical);
            subField("Payload",  (item.payload  || "N/A").substring(0, 80));
            subField("Evidence", (item.evidence || "N/A").substring(0, 80));
            doc.moveDown(0.3);
          });
        }
      });
    }

    // ── CSRF ──────────────────────────────────────────────────────────────────
    if (vuln.csrf?.found) {
      vulnBlock("CSRF (Cross-Site Request Forgery)", "HIGH", () => {
        const d   = vuln.csrf.details || {};
        const sum = d.summary || {};
        field("Endpoints Tested", sum.totalEndpoints ?? 0, C.body, L);
        field("Vulnerable",       sum.vulnerable     ?? 0, C.high, L);
        field("Safe",             sum.safe           ?? 0, C.safe, L);
        doc.moveDown(0.35);
        const vulnEps = d.vulnerableEndpoints || [];
        if (vulnEps.length > 0) {
          doc.fontSize(9).fillColor(C.muted).text("Vulnerable Endpoints:", L);
          doc.moveDown(0.2);
          vulnEps.slice(0, 10).forEach((ep, idx) => {
            findingHeader(idx + 1, `${ep.endpoint || "Unknown"}  [${ep.method || "POST"}]`);
            subField("Status",     ep.status     || "—");
            subField("Confidence", ep.confidence || "—");
            subField("Risk",       ep.risk       || "—",
              (ep.risk || "").toLowerCase() === "high" ? C.high : C.body);
            doc.moveDown(0.25);
          });
        }
      });
    }

    // ── Sensitive Files ───────────────────────────────────────────────────────
    if (vuln.sensitiveFiles?.found) {
      vulnBlock("Sensitive File Exposure", "HIGH", () => {
        const d   = vuln.sensitiveFiles.details || {};
        const sum = d.summary || {};
        if (sum.critical) field("Critical Files",   sum.critical, C.critical, L);
        if (sum.high)     field("High Risk Files",  sum.high,     C.high,     L);
        const files = d.exposedFiles || d.files || [];
        if (files.length > 0) {
          doc.moveDown(0.35);
          doc.fontSize(9).fillColor(C.muted).text("Exposed Files:", L);
          doc.moveDown(0.2);
          files.slice(0, 15).forEach((f, idx) => {
            const url  = typeof f === "object" ? (f.url || f.path || f.file) : f;
            const risk = typeof f === "object" ? (f.risk || f.severity || "") : "";
            const urlSafe = (url || "Unknown").substring(0, 70);
            ensureSpace(16);
            doc.fontSize(9)
              .fillColor(risk === "CRITICAL" ? C.critical : C.high)
              .text(`${idx + 1}.  ${urlSafe}${risk ? "  [" + risk + "]" : ""}`, IND);
          });
        }
      });
    }

    // ── Open Redirect ─────────────────────────────────────────────────────────
    if (vuln.openRedirect?.found) {
      vulnBlock("Open Redirect", "HIGH", () => {
        const d        = vuln.openRedirect.details || {};
        const findings = d.findings || d.vulnerableEndpoints || [];
        if (findings.length > 0) {
          findings.slice(0, 10).forEach((f, idx) => {
            const url   = typeof f === "object" ? (f.url   || f.endpoint) : f;
            const param = typeof f === "object" ? (f.param || f.parameter) : "";
            findingHeader(idx + 1, `${(url || "Unknown").substring(0, 75)}`);
            if (param) subField("Parameter", param);
            doc.moveDown(0.25);
          });
        } else {
          doc.fontSize(9).fillColor(C.muted)
            .text(d.notes || "Open redirect vulnerability confirmed.", IND);
        }
      });
    }

    // ── CORS ──────────────────────────────────────────────────────────────────
    if (vuln.cors?.found) {
      vulnBlock("CORS Misconfiguration", "HIGH", () => {
        const d   = vuln.cors.details || {};
        const sum = d.summary || {};
        if (sum.critical) field("Critical Issues", sum.critical, C.critical, L);
        if (sum.high)     field("High Issues",     sum.high,     C.high,     L);
        const findings = d.findings || d.vulnerableEndpoints || [];
        if (findings.length > 0) {
          doc.moveDown(0.35);
          findings.slice(0, 10).forEach((f, idx) => {
            const url   = typeof f === "object" ? (f.url || f.endpoint || f.origin) : f;
            const issue = typeof f === "object" ? (f.issue || f.type || "") : "";
            findingHeader(idx + 1, (url || "Unknown").substring(0, 70));
            if (issue) subField("Issue", issue, C.high);
            doc.moveDown(0.25);
          });
        } else {
          doc.fontSize(9).fillColor(C.muted)
            .text(d.notes || "CORS misconfiguration — overly permissive origin policy.", IND);
        }
      });
    }

    // ── WordPress ─────────────────────────────────────────────────────────────
    if (vuln.wordpress?.found) {
      const wp    = vuln.wordpress.details || {};
      const wpSev = wp.riskScore?.level || "MEDIUM";
      vulnBlock("WordPress Security", wpSev, () => {
        if (wp.version)          field("WP Version",   wp.version,          C.body, L);
        if (wp.riskScore?.score) field("Risk Score",   wp.riskScore.score,  C.high, L);
        if (wp.theme)            field("Active Theme",  wp.theme,           C.body, L);
        const plugins = wp.vulnerablePlugins || wp.plugins || [];
        if (plugins.length > 0) {
          doc.moveDown(0.35);
          doc.fontSize(9).fillColor(C.muted).text("Vulnerable Plugins:", L);
          doc.moveDown(0.2);
          plugins.slice(0, 10).forEach((p, idx) => {
            const name = typeof p === "object" ? (p.name || p.plugin || JSON.stringify(p)) : p;
            ensureSpace(14);
            doc.fontSize(9).fillColor(C.high).text(`${idx + 1}.  ${name}`, IND);
          });
        }
        const cves = wp.cves || [];
        if (cves.length > 0) {
          doc.moveDown(0.35);
          doc.fontSize(9).fillColor(C.muted).text("CVEs:", L);
          doc.moveDown(0.2);
          cves.slice(0, 5).forEach(c => {
            ensureSpace(14);
            doc.fontSize(9).fillColor(C.critical)
              .text(`  ${typeof c === "object" ? c.id || c.cve : c}`, IND);
          });
        }
      });
    }

    divider();

    // =========================================================================
    // REMEDIATION RECOMMENDATIONS
    // =========================================================================
    sectionTitle("Remediation Recommendations");
    const recs = [];
    if (vuln.sqlInjection?.found)       recs.push(["SQL Injection",           "HIGH",     "Use parameterized queries / prepared statements. Never interpolate user input into SQL."]);
    if (vuln.domXss?.found)             recs.push(["DOM XSS",                 "MEDIUM",   "Avoid innerHTML/document.write with user-controlled data. Use textContent or DOMPurify."]);
    if (vuln.storedXss?.found)          recs.push(["Stored XSS",              "HIGH",     "Sanitize and encode all stored user input before rendering. Implement a strict CSP."]);
    if (vuln.reflectedXss?.found)       recs.push(["Reflected XSS",           "MEDIUM",   "Encode all reflected user input. Implement Content-Security-Policy headers."]);
    if (vuln.clickjacking?.vulnerable)  recs.push(["Clickjacking",            "LOW",      "Add X-Frame-Options: DENY or Content-Security-Policy: frame-ancestors 'none'."]);
    if (vuln.commandInjection?.found)   recs.push(["Command Injection",       "CRITICAL", "Never pass user input to shell commands. Use safe APIs and strict input validation."]);
    if (vuln.csrf?.found)               recs.push(["CSRF",                    "HIGH",     "Implement CSRF tokens on all state-changing requests. Use SameSite cookie attribute."]);
    if (vuln.sensitiveFiles?.found)     recs.push(["Sensitive File Exposure", "HIGH",     "Remove or restrict access to backup files, config files and admin panels."]);
    if (vuln.openRedirect?.found)       recs.push(["Open Redirect",           "HIGH",     "Validate and whitelist redirect destinations. Avoid user-controlled redirect URLs."]);
    if (vuln.cors?.found)               recs.push(["CORS Misconfiguration",   "HIGH",     "Restrict Access-Control-Allow-Origin to trusted domains only. Avoid wildcard (*)."]);
    if (missingHdrs.length > 0)         recs.push(["Missing Security Headers","MEDIUM",   `Add: ${missingHdrs.slice(0, 4).join(", ")}${missingHdrs.length > 4 ? "…" : ""}.`]);

    if (recs.length === 0) {
      doc.fontSize(9).fillColor(C.safe)
        .text("No critical issues detected. Continue monitoring and re-scan periodically.");
    } else {
      recs.forEach((r, i) => {
        ensureSpace(28);
        const sc = sevColor(r[1]);
        doc.fontSize(9).fillColor(sc).font("Helvetica-Bold")
          .text(`${i + 1}.  [${r[1]}]  ${r[0]}`, L, doc.y, { width: W });
        doc.font("Helvetica").fillColor(C.body)
          .text(`   ${r[2]}`, L, doc.y, { width: W });
        doc.moveDown(0.45);
      });
    }

    divider();

    // =========================================================================
    // FOOTER
    // =========================================================================
    doc.fontSize(8).fillColor(C.muted)
      .text(
        "Generated by WebIntelX  —  For authorised security assessment purposes only  —  Handle with confidentiality.",
        { align: "center" }
      );

    doc.end();

  } catch (err) {
    console.error("FullScan PDF generation failed:", err);
    try { res.status(500).json({ error: "PDF generation failed" }); } catch (e) {}
  }
};