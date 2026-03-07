/**
 * Open Redirect Detection Module
 *
 * Tests if the site redirects to attacker-controlled URLs via common redirect params.
 * Strategy:
 * 1. Test root URL with common redirect parameter names
 * 2. Crawl linked pages and extract any params that look like redirect params
 * 3. Test each discovered redirect param with external URL payloads
 * 4. Verify actual redirect occurred (not just reflection)
 */

const axios = require("axios");
const cheerio = require("cheerio");
const { URL } = require("url");

const USER_AGENT = "WebIntelX-OpenRedirect-Scanner/1.0";
const TIMEOUT = 10000;

// Most common redirect parameter names across frameworks
const REDIRECT_PARAMS = [
  "url", "redirect", "redirect_url", "redirect_uri", "redirectUrl", "redirectUri",
  "next", "return", "return_url", "returnUrl", "returnTo", "return_to",
  "goto", "go", "target", "dest", "destination", "continue",
  "forward", "location", "link", "ref", "referer", "referrer",
  "callback", "callback_url", "callbackUrl", "success_url", "cancel_url",
  "from", "from_url", "login_redirect", "logout_redirect", "after_login",
];

// External URLs to use as redirect targets
const REDIRECT_PAYLOADS = [
  "https://evil.com",
  "//evil.com",
  "https://evil.com/",
  "//evil.com/",
  "https:evil.com",
  "/\\evil.com",
  "/%09/evil.com",
  "https://xss-game.appspot.com@evil.com", // URL confusion
];

function normalizeUrl(input) {
  if (!input.startsWith("http://") && !input.startsWith("https://")) {
    return "http://" + input;
  }
  return input;
}

/**
 * Check if a response indicates a redirect to an external site
 */
function isExternalRedirect(response, payload) {
  // Check Location header
  const location = response.headers["location"] || "";
  if (location) {
    // Direct match
    if (location.includes("evil.com")) return { redirected: true, location };
    // Protocol-relative
    if (location.startsWith("//evil.com")) return { redirected: true, location };
    // Any non-relative redirect (starts with http and goes outside)
    if (location.startsWith("http") && !location.includes(new URL(payload).hostname || "")) {
      // Check if it's going to our evil domain
      if (location.includes("evil.com")) return { redirected: true, location };
    }
  }
  return { redirected: false };
}

/**
 * Test a single URL + param combination for open redirect
 */
async function testRedirectParam(baseUrl, param, payload) {
  const testUrl = `${baseUrl}?${param}=${encodeURIComponent(payload)}`;

  try {
    const response = await axios.get(testUrl, {
      timeout: TIMEOUT,
      headers: { "User-Agent": USER_AGENT },
      maxRedirects: 0, // Don't follow redirects — we want to catch the redirect itself
      validateStatus: (status) => status < 500,
    });

    const check = isExternalRedirect(response, testUrl);
    if (check.redirected) {
      return {
        vulnerable: true,
        param,
        payload,
        url: testUrl,
        redirectLocation: check.location,
        statusCode: response.status,
      };
    }

    // Also check for meta refresh redirects in body (less common)
    if (response.data && typeof response.data === "string") {
      const metaRefresh = response.data.match(/meta[^>]*http-equiv[^>]*refresh[^>]*content[^>]*url=([^"'\s>]+)/i);
      if (metaRefresh && metaRefresh[1] && metaRefresh[1].includes("evil.com")) {
        return {
          vulnerable: true,
          param,
          payload,
          url: testUrl,
          redirectLocation: metaRefresh[1],
          statusCode: response.status,
          type: "meta-refresh",
        };
      }
    }

  } catch (err) {
    // maxRedirects: 0 causes axios to throw on 3xx — catch and check
    if (err.response) {
      const check = isExternalRedirect(err.response, testUrl);
      if (check.redirected) {
        return {
          vulnerable: true,
          param,
          payload,
          url: testUrl,
          redirectLocation: check.location,
          statusCode: err.response.status,
        };
      }
    }
  }

  return { vulnerable: false };
}

/**
 * Extract redirect-like parameters from page links and forms
 */
function extractRedirectParams(html, baseUrl) {
  const params = new Set();
  const $ = cheerio.load(html);

  // Check all links for redirect params
  $("a[href]").each((_, el) => {
    try {
      const href = $(el).attr("href");
      const resolved = new URL(href, baseUrl);
      resolved.searchParams.forEach((_, key) => {
        if (REDIRECT_PARAMS.includes(key.toLowerCase()) || 
            /redirect|url|return|next|goto|dest|forward|continue/i.test(key)) {
          params.add(key);
        }
      });
    } catch {}
  });

  // Check forms
  $("input[name]").each((_, el) => {
    const name = $(el).attr("name") || "";
    if (/redirect|url|return|next|goto|dest|forward|continue/i.test(name)) {
      params.add(name);
    }
  });

  return [...params];
}

/**
 * Crawl internal pages to find redirect parameters in use
 */
async function discoverRedirectParams(url) {
  const allParams = new Set(REDIRECT_PARAMS); // Start with known params

  try {
    const res = await axios.get(url, {
      timeout: TIMEOUT,
      headers: { "User-Agent": USER_AGENT },
      validateStatus: () => true,
    });

    if (res.status === 200) {
      const discovered = extractRedirectParams(res.data, url);
      discovered.forEach(p => allParams.add(p));

      // Check linked pages too (shallow)
      const $ = cheerio.load(res.data);
      const base = new URL(url);
      const linkedUrls = [];

      $("a[href]").each((_, el) => {
        try {
          const resolved = new URL($(el).attr("href"), url);
          if (resolved.origin === base.origin && resolved.search) {
            linkedUrls.push(resolved.toString());
          }
        } catch {}
      });

      // Check up to 5 linked pages for redirect params
      for (const linkedUrl of linkedUrls.slice(0, 5)) {
        try {
          const linkRes = await axios.get(linkedUrl, {
            timeout: TIMEOUT,
            headers: { "User-Agent": USER_AGENT },
            validateStatus: () => true,
          });
          if (linkRes.status === 200) {
            extractRedirectParams(linkRes.data, linkedUrl).forEach(p => allParams.add(p));
          }
        } catch {}
      }
    }
  } catch {}

  return [...allParams];
}

/**
 * Main open redirect scanner
 */
async function scanOpenRedirect(inputUrl) {
  const url = normalizeUrl(inputUrl);
  const base = url.replace(/\/$/, "");
  console.log(`[OpenRedirect] Starting scan for: ${url}`);

  const findings = [];
  const tested = new Set();

  try {
    // Discover all redirect params (known + crawled)
    const params = await discoverRedirectParams(url);
    console.log(`[OpenRedirect] Testing ${params.length} redirect parameter(s)`);

    // Test each param with each payload — stop early per param on first hit
    for (const param of params) {
      if (findings.length >= 5) break; // Cap findings

      for (const payload of REDIRECT_PAYLOADS) {
        const key = `${param}:${payload}`;
        if (tested.has(key)) continue;
        tested.add(key);

        const result = await testRedirectParam(base, param, payload);

        if (result.vulnerable) {
          console.log(`[OpenRedirect] ✅ FOUND: ${param}=${payload} → ${result.redirectLocation}`);
          findings.push({
            parameter: param,
            payload,
            url: result.url,
            redirectsTo: result.redirectLocation,
            statusCode: result.statusCode,
            type: result.type || "header-redirect",
            severity: "HIGH",
          });
          break; // One confirmed finding per param is enough
        }
      }
    }

  } catch (err) {
    console.error("[OpenRedirect] Scan error:", err.message);
    return {
      module: "Open Redirect",
      target: url,
      vulnerable: false,
      evidence: "Scan failed due to error",
      notes: `Error: ${err.message}`,
    };
  }

  const vulnerable = findings.length > 0;
  console.log(`[OpenRedirect] Scan complete. Vulnerable: ${vulnerable}`);

  return {
    module: "Open Redirect",
    target: url,
    vulnerable,
    summary: {
      total: findings.length,
      parameters: findings.map(f => f.parameter),
    },
    evidence: vulnerable
      ? findings.map(f => ({
          parameter: f.parameter,
          payload: f.payload,
          url: f.url,
          redirectsTo: f.redirectsTo,
          statusCode: f.statusCode,
          type: f.type,
          severity: f.severity,
        }))
      : "No open redirect vulnerabilities detected",
    notes: vulnerable
      ? `Open redirect confirmed. Attacker can redirect users from your domain to malicious sites. Affected parameters: ${findings.map(f => f.parameter).join(", ")}`
      : "No open redirect vulnerabilities detected in tested parameters.",
  };
}

module.exports = { scanOpenRedirect };