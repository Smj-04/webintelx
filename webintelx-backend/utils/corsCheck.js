/**
 * CORS Misconfiguration Detection Module
 *
 * Tests for 4 types of CORS issues:
 * 1. Wildcard Access-Control-Allow-Origin: *
 * 2. Origin reflection (server echoes back whatever Origin header you send)
 * 3. Credentials + wildcard (critical — browsers block this but misconfigured servers allow it)
 * 4. Null origin allowed (allows sandboxed iframes / file:// to access API)
 *
 * Also crawls API-like endpoints since CORS issues are most dangerous on /api/* routes
 */

const axios = require("axios");
const cheerio = require("cheerio");
const { URL } = require("url");

const USER_AGENT = "WebIntelX-CORS-Scanner/1.0";
const TIMEOUT = 10000;

// Evil origin we use to test reflection
const EVIL_ORIGIN = "https://evil-attacker.com";
const NULL_ORIGIN = "null";

function normalizeUrl(input) {
  if (!input.startsWith("http://") && !input.startsWith("https://")) {
    return "http://" + input;
  }
  return input;
}

/**
 * Send a CORS preflight/simple request and analyze the response headers
 */
async function testCorsOnUrl(targetUrl, originToSend) {
  try {
    const response = await axios.get(targetUrl, {
      timeout: TIMEOUT,
      headers: {
        "User-Agent": USER_AGENT,
        "Origin": originToSend,
      },
      validateStatus: () => true,
    });

    const acao = response.headers["access-control-allow-origin"] || "";
    const acac = response.headers["access-control-allow-credentials"] || "";
    const acam = response.headers["access-control-allow-methods"] || "";

    return {
      url: targetUrl,
      status: response.status,
      acao,
      acac: acac.toLowerCase() === "true",
      acam,
      sentOrigin: originToSend,
    };
  } catch (err) {
    return null;
  }
}

/**
 * Discover API-like endpoints from the page
 * CORS issues are most critical on /api/, /v1/, /graphql etc.
 */
async function discoverEndpoints(url) {
  const endpoints = new Set([url]); // Always test root
  const base = new URL(url);

  try {
    const res = await axios.get(url, {
      timeout: TIMEOUT,
      headers: { "User-Agent": USER_AGENT },
      validateStatus: () => true,
    });

    if (res.status !== 200) return [...endpoints];

    const $ = cheerio.load(res.data);

    // Collect links — prioritize API-looking paths
    $("a[href]").each((_, el) => {
      try {
        const resolved = new URL($(el).attr("href"), url);
        if (resolved.origin === base.origin) {
          resolved.search = "";
          resolved.hash = "";
          endpoints.add(resolved.toString());
        }
      } catch {}
    });

    // Also look for API URLs in script tags
    const scriptContent = [];
    $("script:not([src])").each((_, el) => {
      scriptContent.push($(el).text());
    });

    const allScriptText = scriptContent.join("\n");
    const apiMatches = allScriptText.match(/["'`](\/(?:api|v\d|graphql|rest|auth|user|account|data|endpoint)[^"'`\s]*)/g) || [];
    apiMatches.forEach(match => {
      try {
        const path = match.replace(/["'`]/g, "");
        const fullUrl = new URL(path, url).toString();
        endpoints.add(fullUrl);
      } catch {}
    });

  } catch {}

  // Manually add common API paths
  const commonApiPaths = ["/api", "/api/v1", "/api/v2", "/graphql", "/rest", "/auth", "/user", "/users", "/account", "/me", "/profile"];
  commonApiPaths.forEach(path => {
    try {
      endpoints.add(new URL(path, url).toString());
    } catch {}
  });

  return [...endpoints].slice(0, 15); // Cap at 15 endpoints
}

/**
 * Analyze a single endpoint for all 4 CORS issues
 */
async function analyzeEndpoint(endpointUrl) {
  const issues = [];

  // Test 1: Wildcard ACAO
  const wildcardTest = await testCorsOnUrl(endpointUrl, EVIL_ORIGIN);
  if (wildcardTest) {
    if (wildcardTest.acao === "*") {
      issues.push({
        type: "Wildcard CORS",
        severity: "MEDIUM",
        description: "Access-Control-Allow-Origin: * allows any origin to read responses",
        header: `Access-Control-Allow-Origin: ${wildcardTest.acao}`,
        url: endpointUrl,
        exploitable: !wildcardTest.acac, // Wildcard + no credentials = medium risk
      });
    }

    // Test 2: Origin reflection
    if (wildcardTest.acao === EVIL_ORIGIN) {
      const severity = wildcardTest.acac ? "CRITICAL" : "HIGH";
      issues.push({
        type: wildcardTest.acac ? "CORS Origin Reflection + Credentials" : "CORS Origin Reflection",
        severity,
        description: wildcardTest.acac
          ? "Server reflects arbitrary Origin AND allows credentials — attacker can make authenticated requests cross-origin"
          : "Server reflects arbitrary Origin header — attacker can read responses from any origin",
        header: `Access-Control-Allow-Origin: ${wildcardTest.acao}${wildcardTest.acac ? "\nAccess-Control-Allow-Credentials: true" : ""}`,
        url: endpointUrl,
        exploitable: true,
      });
    }

    // Test 3: Wildcard + Credentials (misconfiguration — browsers block but server is wrong)
    if (wildcardTest.acao === "*" && wildcardTest.acac) {
      issues.push({
        type: "Wildcard + Credentials Misconfiguration",
        severity: "HIGH",
        description: "Server sets both ACAO: * and ACAC: true — browsers block this but it indicates a misconfiguration that may be bypassed",
        header: "Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true",
        url: endpointUrl,
        exploitable: false, // Browsers block, but still a misconfiguration
      });
    }
  }

  // Test 4: Missing CORS headers on API-like endpoints
  // Only flag this for paths that look like APIs — not for regular pages
  const isApiEndpoint = /\/(api|v\d|graphql|rest|auth|user|users|account|me|profile|data|endpoint)/i.test(endpointUrl);
  if (isApiEndpoint && wildcardTest && wildcardTest.status < 500 && !wildcardTest.acao) {
    issues.push({
      type: "Missing CORS Headers on API Endpoint",
      severity: "LOW",
      description: "API endpoint does not return any CORS headers — cross-origin requests will be blocked by browsers, which may break legitimate integrations or indicate CORS is not considered",
      header: "Access-Control-Allow-Origin: (not set)",
      url: endpointUrl,
      exploitable: false,
    });
  }

  // Test 5: Null origin allowed
  const nullTest = await testCorsOnUrl(endpointUrl, NULL_ORIGIN);
  if (nullTest && (nullTest.acao === "null" || nullTest.acao === NULL_ORIGIN)) {
    issues.push({
      type: "Null Origin Allowed",
      severity: nullTest.acac ? "HIGH" : "MEDIUM",
      description: "Server allows null origin — attackers can use sandboxed iframes or file:// pages to make cross-origin requests",
      header: `Access-Control-Allow-Origin: null${nullTest.acac ? "\nAccess-Control-Allow-Credentials: true" : ""}`,
      url: endpointUrl,
      exploitable: true,
    });
  }

  return issues;
}

/**
 * Main CORS scanner
 */
async function scanCORS(inputUrl) {
  const url = normalizeUrl(inputUrl);
  console.log(`[CORS] Starting scan for: ${url}`);

  const allIssues = [];

  try {
    const endpoints = await discoverEndpoints(url);
    console.log(`[CORS] Testing ${endpoints.length} endpoint(s)`);

    for (const endpoint of endpoints) {
      const issues = await analyzeEndpoint(endpoint);
      if (issues.length > 0) {
        console.log(`[CORS] ⚠️ Found ${issues.length} issue(s) on ${endpoint}`);
        allIssues.push(...issues);
      }
    }

  } catch (err) {
    console.error("[CORS] Scan error:", err.message);
    return {
      module: "CORS Misconfiguration",
      target: url,
      vulnerable: false,
      evidence: "Scan failed due to error",
      notes: `Error: ${err.message}`,
    };
  }

  // Deduplicate by type (same issue on different endpoints — keep most severe)
  const seen = new Set();
  const dedupedIssues = allIssues.filter(issue => {
    const key = `${issue.type}:${issue.url}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  // Sort by severity
  const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  dedupedIssues.sort((a, b) => (severityOrder[a.severity] ?? 4) - (severityOrder[b.severity] ?? 4));

  const vulnerable = dedupedIssues.length > 0;
  const summary = {
    total: dedupedIssues.length,
    critical: dedupedIssues.filter(i => i.severity === "CRITICAL").length,
    high: dedupedIssues.filter(i => i.severity === "HIGH").length,
    medium: dedupedIssues.filter(i => i.severity === "MEDIUM").length,
    exploitable: dedupedIssues.filter(i => i.exploitable).length,
  };

  console.log(`[CORS] Scan complete. Issues found: ${dedupedIssues.length}`);

  return {
    module: "CORS Misconfiguration",
    target: url,
    vulnerable,
    summary,
    evidence: vulnerable
      ? dedupedIssues.map(i => ({
          type: i.type,
          severity: i.severity,
          url: i.url,
          description: i.description,
          header: i.header,
          exploitable: i.exploitable,
        }))
      : "No CORS misconfigurations detected",
    notes: vulnerable
      ? `CORS misconfiguration detected. ${summary.exploitable} exploitable issue(s) found. Highest severity: ${dedupedIssues[0]?.severity}`
      : "No CORS misconfigurations detected. All tested endpoints appear to have proper CORS policy.",
  };
}

module.exports = { scanCORS };