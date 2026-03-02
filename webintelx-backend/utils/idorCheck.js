/**
 * IDOR (Insecure Direct Object Reference) Detection Module
 * Tests for IDOR vulnerabilities by accessing object references
 * with authenticated context.
 */

const axios = require("axios");
const { wrapper } = require("axios-cookiejar-support");
const tough = require("tough-cookie");
const cheerio = require("cheerio");
const { URL } = require("url");

// --------------------------------------------------------------------------
// Constants
// --------------------------------------------------------------------------

const PUBLIC_OBJECT_KEYWORDS = [
  "category", "cat", "product", "item", "search", "list", "page",
  "filter", "artist", "artists", "gallery", "browse", "public",
];

const SENSITIVE_KEYWORDS = [
  "email", "username", "user", "account", "profile", "role",
  "address", "password", "order", "invoice", "id",
];

const USER_AGENT = "WebIntelX-IDOR-Scanner/1.0";
const TIMEOUT = 40000;
const REQUEST_DELAY_MS = 300;

// --------------------------------------------------------------------------
// HTTP client with cookie jar (persists session across requests)
// --------------------------------------------------------------------------

function createClient() {
  const cookieJar = new tough.CookieJar();
  const client = wrapper(
    axios.create({
      jar: cookieJar,
      withCredentials: true,
      timeout: TIMEOUT,
      maxRedirects: 5,
      headers: { "User-Agent": USER_AGENT },
    })
  );
  return { client, cookieJar };
}

// --------------------------------------------------------------------------
// Authentication
// --------------------------------------------------------------------------

async function authenticate(client, cookieJar, auth) {
  console.log("[AUTH] Authenticating for IDOR scan...");

  if (auth.type === "form") {
    const formData = new URLSearchParams({
      [auth.usernameField]: auth.username,
      [auth.passwordField]: auth.password,
      submit: "login",
    });

    const res = await client.post(auth.loginUrl, formData.toString(), {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      validateStatus: () => true,
    });

    console.log("[DEBUG] Login status:", res.status);
    console.log("[DEBUG] Login response snippet:", String(res.data).slice(0, 300));

    const origin = new URL(auth.loginUrl).origin;
    const cookies = await cookieJar.getCookies(origin);
    console.log("[DEBUG] Session cookies:", cookies.map((c) => `${c.key}=${c.value}`));

    // Check for session-like cookie
    const sessionCookie = cookies.find((c) =>
      /sess|token|auth|jwt|sid/i.test(c.key)
    );

    if (!cookies.length) {
      throw new Error("Authentication failed: no cookies set after login");
    }

    // Warn if no obvious session cookie but don't block — some apps use non-standard names
    if (!sessionCookie) {
      console.warn("[AUTH] Warning: no obvious session cookie found, proceeding anyway");
    }

    console.log("[AUTH] Authentication successful (FORM)");
    return;
  }

  if (auth.type === "json") {
    const res = await client.post(auth.loginUrl, {
      [auth.usernameField || "username"]: auth.username,
      [auth.passwordField || "password"]: auth.password,
    });

    const token = res.data?.token || res.data?.access_token || res.data?.accessToken;
    if (!token) {
      throw new Error("Authentication failed: no token in response");
    }

    client.defaults.headers.common["Authorization"] = `Bearer ${token}`;
    console.log("[AUTH] Authentication successful (JWT)");
    return;
  }

  throw new Error(`Unsupported auth type: ${auth.type}. Use "form" or "json".`);
}

// --------------------------------------------------------------------------
// URL utilities
// --------------------------------------------------------------------------

function normalizeUrl(input) {
  if (!input.startsWith("http://") && !input.startsWith("https://")) {
    return "http://" + input;
  }
  return input;
}

function extractIdsFromUrl(url) {
  const ids = [];
  const urlObj = new URL(url);
  const pathParts = urlObj.pathname.split("/").filter(Boolean);

  for (let i = 0; i < pathParts.length; i++) {
    if (/^\d+$/.test(pathParts[i])) {
      ids.push({ type: "path", value: pathParts[i], position: i });
    }
  }

  for (const [key, value] of urlObj.searchParams.entries()) {
    if (/^\d+$/.test(value)) {
      ids.push({ type: "query", key, value });
    }
  }

  return ids;
}

function replaceIdInUrl(targetUrl, id, testId) {
  const urlObj = new URL(targetUrl);

  if (id.type === "path") {
    const pathParts = urlObj.pathname.split("/").filter(Boolean);
    const idx = pathParts.findIndex((p) => p === id.value);
    if (idx === -1) return null;
    pathParts[idx] = testId;
    urlObj.pathname = "/" + pathParts.join("/");
    return urlObj.toString();
  }

  if (id.type === "query") {
    urlObj.searchParams.set(id.key, testId);
    return urlObj.toString();
  }

  return null;
}

// --------------------------------------------------------------------------
// URL discovery (crawl for pages with numeric IDs)
// --------------------------------------------------------------------------

async function discoverUrlsWithIds(client, baseUrl, maxPages = 15) {
  const urlsWithIds = [];
  const visited = new Set();
  const queue = [{ url: baseUrl, depth: 0 }];
  const maxDepth = 2;
  const baseOrigin = new URL(baseUrl).origin;

  while (queue.length > 0 && visited.size < maxPages * 3) {
    const { url, depth } = queue.shift();
    if (depth > maxDepth || visited.has(url)) continue;
    visited.add(url);

    try {
      console.log(`[CRAWL] ${url} (depth: ${depth})`);
      const response = await client.get(url, {
        timeout: TIMEOUT,
        validateStatus: () => true,
      });

      if (response.status !== 200) continue;

      const ids = extractIdsFromUrl(url);
      if (ids.length > 0 && !urlsWithIds.some((u) => u.url === url)) {
        urlsWithIds.push({ url, ids });
        console.log(`[CRAWL] Found URL with IDs: ${url}`);
        if (urlsWithIds.length >= maxPages) break;
      }

      const $ = cheerio.load(response.data);
      $("a[href]").each((_, link) => {
        try {
          const href = $(link).attr("href");
          if (!href || href.startsWith("#") || href.startsWith("javascript:")) return;
          const fullUrl = new URL(href, url).toString();
          if (!fullUrl.startsWith(baseOrigin)) return;

          const linkIds = extractIdsFromUrl(fullUrl);
          if (linkIds.length > 0 && !urlsWithIds.some((u) => u.url === fullUrl)) {
            urlsWithIds.push({ url: fullUrl, ids: linkIds });
            console.log(`[CRAWL] Found linked URL with IDs: ${fullUrl}`);
          }

          if (depth < maxDepth && !visited.has(fullUrl)) {
            queue.push({ url: fullUrl, depth: depth + 1 });
          }
        } catch (_) {}
      });
    } catch (error) {
      console.error(`[CRAWL] Error on ${url}: ${error.message}`);
    }
  }

  console.log(`[CRAWL] Discovery complete. Found ${urlsWithIds.length} URLs with IDs.`);
  return urlsWithIds;
}

// --------------------------------------------------------------------------
// Response analysis
// --------------------------------------------------------------------------

/**
 * Try JSON owner field mismatch detection.
 */
function detectOwnerMismatch(originalBody, testBody, currentUsername) {
  try {
    const o = JSON.parse(originalBody);
    const t = JSON.parse(testBody);
    const ownerKeys = ["owner", "ownerId", "user", "userId", "accountId", "createdBy", "author"];

    function extractOwner(obj) {
      if (!obj || typeof obj !== "object") return null;
      for (const key of ownerKeys) {
        if (obj[key] !== undefined) return obj[key];
      }
      for (const k of Object.keys(obj)) {
        const found = extractOwner(obj[k]);
        if (found !== null) return found;
      }
      return null;
    }

    const normalize = (v) =>
      v && typeof v === "object" && v.id ? String(v.id) : String(v);

    const oOwner = extractOwner(o);
    const tOwner = extractOwner(t);

    // If test response has different owner than original — IDOR
    if (oOwner && tOwner && normalize(oOwner) !== normalize(tOwner)) {
      return { detected: true, reason: "owner_field_mismatch", oOwner, tOwner };
    }

    // If test response has a different username than the authenticated user
    if (currentUsername && tOwner) {
      const tOwnerStr = normalize(tOwner).toLowerCase();
      if (tOwnerStr !== currentUsername.toLowerCase() && tOwnerStr !== "null") {
        return { detected: true, reason: "owner_differs_from_current_user", tOwner };
      }
    }

    return { detected: false };
  } catch {
    return { detected: false };
  }
}

/**
 * HTML-level content change detection:
 * Checks if the page changed meaningfully between original and test IDs.
 * Used when both responses are HTML (not JSON).
 */
function detectContentChange(originalBody, testBody) {
  if (!originalBody || !testBody) return false;

  // Both should have substantial content
  if (testBody.length < 200) return false;

  // If test body is very similar in length to original, it might be same template
  const lengthRatio = testBody.length / (originalBody.length || 1);
  if (lengthRatio < 0.3 || lengthRatio > 3) return true; // Significantly different

  // Check for sensitive data fields in the response
  const sensitivePatternFound = SENSITIVE_KEYWORDS.some((kw) =>
    testBody.toLowerCase().includes(kw)
  );

  // Check if the test response has user-specific data that differs from original
  const originalTextSample = originalBody.slice(0, 5000).toLowerCase();
  const testTextSample = testBody.slice(0, 5000).toLowerCase();

  // Look for email patterns in test response (common PII leak)
  const emailPattern = /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi;
  const testEmails = testBody.match(emailPattern) || [];
  const originalEmails = originalBody.match(emailPattern) || [];

  if (testEmails.length > 0 && JSON.stringify(testEmails) !== JSON.stringify(originalEmails)) {
    return true;
  }

  return false;
}

/**
 * Determine if a URL points to a clearly public/non-sensitive object.
 */
function isPublicEndpoint(testUrl, idKey = "") {
  const lower = testUrl.toLowerCase();
  return PUBLIC_OBJECT_KEYWORDS.some(
    (kw) => lower.includes(`/${kw}`) || lower.includes(`${kw}=`) || (idKey || "").toLowerCase().includes(kw)
  );
}

/**
 * Determine if a URL points to a sensitive/user-specific object.
 */
function isSensitiveEndpoint(testUrl) {
  return /\/(user|profile|account|order|invoice|admin|settings|dashboard|me|member)/i.test(testUrl);
}

// --------------------------------------------------------------------------
// Core IDOR test
// --------------------------------------------------------------------------

async function testIDOR(client, targetUrl, id, currentUsername) {
  const findings = [];

  console.log(`[IDOR] Testing: ${targetUrl} | id=${id.value} (${id.type})`);
  await sleep(REQUEST_DELAY_MS);

  // Fetch the original response for comparison
  let originalBody = "";
  try {
    const originalRes = await client.get(targetUrl, {
      timeout: TIMEOUT,
      validateStatus: () => true,
    });
    originalBody = String(originalRes.data || "");
  } catch (e) {
    console.error(`[IDOR] Could not fetch original URL: ${e.message}`);
    return findings;
  }

  const testIds = generateTestIds(id.value);

  for (const testId of testIds) {
    try {
      const testUrl = replaceIdInUrl(targetUrl, id, testId);
      if (!testUrl) continue;

      // Never treat homepage as IDOR
      const parsedPath = new URL(testUrl).pathname;
      if (parsedPath === "/" || parsedPath === "/index.php") continue;

      await sleep(REQUEST_DELAY_MS);

      const response = await client.get(testUrl, {
        timeout: TIMEOUT,
        validateStatus: () => true,
      });

      if (response.status !== 200) continue;

      const testBody = String(response.data || "");

      // Skip if response body is too short (likely error page)
      if (testBody.length < 100) continue;

      // Skip if it redirected back to login (means we hit auth wall — not IDOR)
      if (isLoginRedirect(testBody)) continue;

      // Detection method 1: JSON owner field mismatch
      const ownerCheck = detectOwnerMismatch(originalBody, testBody, currentUsername);

      // Detection method 2: HTML content change with sensitive data
      const contentChanged = detectContentChange(originalBody, testBody);

      // Detection method 3: Sensitive endpoint returned different data
      const sensitiveEndpoint = isSensitiveEndpoint(testUrl);

      const isConfirmed = ownerCheck.detected;
      const isSuspected = !isConfirmed && sensitiveEndpoint && contentChanged;

      if (isConfirmed || isSuspected) {
        const finding = {
          originalId: id.value,
          testId,
          url: testUrl,
          method: "GET",
          status: response.status,
          responseLength: testBody.length,
          authenticatedUser: currentUsername,
          confidence: isConfirmed ? "High" : "Medium",
          classification: isConfirmed ? "Confirmed IDOR" : "Suspected IDOR",
          evidence: isConfirmed
            ? `Owner field mismatch: original=${ownerCheck.oOwner}, accessed=${ownerCheck.tOwner}`
            : `Sensitive endpoint returned different content for ID ${testId}`,
        };

        console.log(`[IDOR] ${finding.classification} found at: ${testUrl}`);
        findings.push(finding);
        break; // One finding per URL is enough
      }
    } catch (error) {
      console.error(`[IDOR] Error testing id=${testId}: ${error.message}`);
    }
  }

  return findings;
}

/**
 * Test IDOR via POST requests (e.g. editing another user's object)
 */
async function testIDORPost(client, targetUrl, id, currentUsername) {
  const findings = [];
  console.log(`[IDOR POST] Testing: ${targetUrl} | key=${id.key}, value=${id.value}`);
  await sleep(REQUEST_DELAY_MS);

  // First fetch original to establish baseline
  let originalBody = "";
  try {
    const originalRes = await client.get(targetUrl, {
      timeout: TIMEOUT,
      validateStatus: () => true,
    });
    originalBody = String(originalRes.data || "");
  } catch (_) {}

  const testIds = generateTestIds(id.value);

  for (const testId of testIds) {
    try {
      await sleep(REQUEST_DELAY_MS);

      const response = await client.post(
        targetUrl,
        { [id.key]: testId },
        {
          timeout: TIMEOUT,
          headers: { "Content-Type": "application/json" },
          validateStatus: () => true,
        }
      );

      if (response.status < 200 || response.status >= 300) continue;

      const testBody = String(response.data || "");
      const ownerCheck = detectOwnerMismatch(originalBody, testBody, currentUsername);

      if (ownerCheck.detected) {
        findings.push({
          originalId: id.value,
          testId,
          url: targetUrl,
          method: "POST",
          status: response.status,
          authenticatedUser: currentUsername,
          confidence: "High",
          classification: "Confirmed IDOR",
          evidence: `POST: owner mismatch — original=${ownerCheck.oOwner}, accessed=${ownerCheck.tOwner}`,
        });
        break;
      }
    } catch (error) {
      console.error(`[IDOR POST] Error: ${error.message}`);
    }
  }

  return findings;
}

// --------------------------------------------------------------------------
// Pattern detection (informational)
// --------------------------------------------------------------------------

function detectPredictablePatterns(url) {
  const ids = extractIdsFromUrl(url);
  const patterns = [];

  for (const id of ids) {
    const n = parseInt(id.value);
    if (n > 0 && n < 1000) {
      patterns.push({ id, pattern: "Sequential/Small", risk: "High", description: "ID is small/sequential — easy to enumerate" });
    } else if (n > 1_000_000_000 && n < 9_999_999_999) {
      patterns.push({ id, pattern: "Timestamp-like", risk: "Medium", description: "ID may be timestamp-based" });
    }
  }

  return patterns;
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function generateTestIds(idValue) {
  const n = parseInt(idValue);
  return [
    String(n + 1),
    String(n - 1),
    String(n + 10),
    "1",
    "2",
    "999",
  ].filter((id) => parseInt(id) > 0 && id !== idValue);
}

function isLoginRedirect(body) {
  const lower = (body || "").toLowerCase();
  return (
    lower.includes("login") &&
    (lower.includes("please log in") ||
      lower.includes("you must be logged in") ||
      lower.includes("sign in to continue") ||
      lower.includes("redirected to login"))
  );
}

// --------------------------------------------------------------------------
// Main scan entry point
// --------------------------------------------------------------------------

async function scanIDOR(url, options = {}) {
  const { auth } = options;
  url = normalizeUrl(url);

  console.log(`[IDOR] Scan started for: ${url}`);
  console.log("[IDOR] Auth config received:", auth ? { type: auth.type, username: auth.username, loginUrl: auth.loginUrl } : "none");

  if (!auth) {
    return {
      module: "IDOR",
      target: url,
      skipped: true,
      vulnerable: false,
      evidence: "Authentication required",
      notes: "IDOR requires an authenticated context. Provide test account credentials.",
    };
  }

  const { client, cookieJar } = createClient();

  try {
    await authenticate(client, cookieJar, auth);
  } catch (e) {
    return {
      module: "IDOR",
      target: url,
      vulnerable: false,
      evidence: "Login failed",
      notes: e.message,
    };
  }

  const currentUsername = auth.username;

  try {
    // Step 1: Collect URLs to test
    let urlsToTest = [];
    const directIds = extractIdsFromUrl(url);

    if (directIds.length > 0) {
      urlsToTest.push({ url, ids: directIds });
      console.log(`[IDOR] Provided URL has ${directIds.length} ID(s) — testing directly`);
    } else {
      console.log(`[IDOR] No IDs in provided URL — crawling for URLs with IDs`);
      urlsToTest = await discoverUrlsWithIds(client, url, 15);

      if (urlsToTest.length === 0) {
        const baseOrigin = new URL(url).origin;
        if (url !== baseOrigin) {
          console.log(`[IDOR] Retrying crawl from origin: ${baseOrigin}`);
          urlsToTest = await discoverUrlsWithIds(client, baseOrigin, 15);
        }
      }
    }

    if (urlsToTest.length === 0) {
      return {
        module: "IDOR",
        target: url,
        vulnerable: false,
        evidence: "No numeric IDs found",
        notes: "No testable URLs found. Try providing a URL with a numeric ID (e.g. /user/123 or ?id=456).",
      };
    }

    console.log(`[IDOR] Testing ${urlsToTest.length} URL(s)`);

    const findings = [];
    const allPatterns = [];

    for (const { url: testUrl, ids } of urlsToTest.slice(0, 8)) {
      const patterns = detectPredictablePatterns(testUrl);
      allPatterns.push(...patterns);

      for (const id of ids.slice(0, 2)) {
        // Skip clearly public endpoints
        if (isPublicEndpoint(testUrl, id.key)) {
          console.log(`[SKIP] Public endpoint: ${testUrl}`);
          continue;
        }

        const idorFindings = await testIDOR(client, testUrl, id, currentUsername);
        findings.push(...idorFindings);

        // POST test only for sensitive-looking endpoints
        if (id.type === "query" && isSensitiveEndpoint(testUrl)) {
          const postFindings = await testIDORPost(client, testUrl, id, currentUsername);
          findings.push(...postFindings);
        }

        if (findings.length > 0) break;
      }

      if (findings.length > 0) break;
    }

    // Add informational pattern findings if no confirmed IDOR
    const hasConfirmedIDOR = findings.some((f) => f.classification === "Confirmed IDOR");
    const hasSuspectedIDOR = findings.some((f) => f.classification === "Suspected IDOR");
    const highRiskPatterns = allPatterns.filter((p) => p.risk === "High");

    if (!hasConfirmedIDOR && !hasSuspectedIDOR && highRiskPatterns.length > 0) {
      findings.push({
        type: "Predictable Pattern",
        patterns: highRiskPatterns,
        confidence: "Info",
        classification: "Informational",
        evidence: "IDs appear to be sequential or easily enumerable",
      });
    }

    const vulnerable = hasConfirmedIDOR || hasSuspectedIDOR;

    return {
      module: "IDOR",
      target: url,
      vulnerable,
      evidence: vulnerable
        ? {
            findings: findings
              .filter((f) => f.classification !== "Informational")
              .map((f) => ({
                originalId: f.originalId,
                testId: f.testId,
                url: f.url || url,
                method: f.method || "GET",
                evidence: f.evidence,
                confidence: f.confidence,
                classification: f.classification,
              })),
            patterns: allPatterns.slice(0, 5),
          }
        : "No IDOR vulnerabilities detected",
      notes: hasConfirmedIDOR
        ? "Confirmed IDOR: Unauthorized access to objects owned by another user was successful."
        : hasSuspectedIDOR
        ? "Suspected IDOR: Sensitive endpoint returned different data for another user's ID. Manual verification recommended."
        : highRiskPatterns.length > 0
        ? "No IDOR detected. Sequential/predictable IDs found — consider using UUIDs."
        : "No IDOR vulnerabilities detected.",
    };
  } catch (error) {
    console.error("[IDOR] Scan error:", error);
    return {
      module: "IDOR",
      target: url,
      vulnerable: false,
      evidence: "Scan error",
      notes: `Error: ${error.message}`,
    };
  } finally {
    // Clean up auth state
    try {
      cookieJar.removeAllCookiesSync();
      delete client.defaults.headers.common["Authorization"];
    } catch (_) {}
  }
}

module.exports = { scanIDOR };
