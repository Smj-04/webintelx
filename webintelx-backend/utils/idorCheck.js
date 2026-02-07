/**
 * IDOR (Insecure Direct Object Reference) Detection Module
 * Tests for IDOR vulnerabilities by accessing object references
 */

const axios = require("axios");
const { wrapper } = require("axios-cookiejar-support");
const tough = require("tough-cookie");


const cheerio = require("cheerio");
const { URL } = require("url");

const PUBLIC_OBJECT_KEYWORDS = [
  "category",
  "cat",
  "product",
  "item",
  "search",
  "list",
  "page",
  "filter",
  "artist",
  "artists",
  "gallery",
  "browse",
  "public"
];


const SENSITIVE_KEYWORDS = [
  "email",
  "username",
  "user",
  "account",
  "profile",
  "role",
  "address",
  "password",
  "order",
];

const USER_AGENT = "WebIntelX-IDOR-Scanner/1.0";
const TIMEOUT = 40000; // Increased timeout for crawling

const cookieJar = new tough.CookieJar();
const client = wrapper(
  axios.create({
    jar: cookieJar,
    withCredentials: true,
    timeout: TIMEOUT,
    headers: { "User-Agent": USER_AGENT },
  })
);
async function loginIfNeeded(baseUrl) {
  try {
    console.log("[AUTH] Logging in for IDOR test...");
    await client.get(`${baseUrl}/login`);
  } catch (e) {
    console.log("[AUTH] Login failed or not required");
  }
}

function normalizeUrl(input) {
  if (!input.startsWith("http://") && !input.startsWith("https://")) {
    return "http://" + input;
  }
  return input;
}
/**
 * Extracts numeric IDs from URL
 */
function extractIdsFromUrl(url) {
  const ids = [];
  const urlObj = new URL(url);

  // Extract from path segments
  const pathParts = urlObj.pathname.split("/").filter((p) => p);
  for (const part of pathParts) {
    // Check if it's numeric
    if (/^\d+$/.test(part)) {
      ids.push({
        type: "path",
        value: part,
        position: pathParts.indexOf(part),
      });
    }
  }

  // Extract from query parameters
  for (const [key, value] of urlObj.searchParams.entries()) {
    if (/^\d+$/.test(value)) {
      ids.push({
        type: "query",
        key: key,
        value: value,
      });
    }
  }

  return ids;
}

/**
 * Discovers URLs with numeric IDs from a base URL
 */
async function discoverUrlsWithIds(baseUrl, maxPages = 15) {
  const urlsWithIds = [];
  const visited = new Set();
  const queue = [{ url: baseUrl, depth: 0 }];
  const maxDepth = 2; // Increased depth for better discovery
  const baseOrigin = new URL(baseUrl).origin;

  while (queue.length > 0 && urlsWithIds.length < maxPages && visited.size < maxPages * 3) {
    const { url, depth } = queue.shift();

    if (depth > maxDepth || visited.has(url)) continue;
    visited.add(url);

    try {
      console.log(`Discovering URLs with IDs: ${url} (depth: ${depth})`);
      const response = await client.get(url, {
        timeout: TIMEOUT,
        headers: { "User-Agent": USER_AGENT },
        validateStatus: () => true,
      });

      if (response.status !== 200) continue;

      // Extract IDs from current URL
      const ids = extractIdsFromUrl(url);
      if (ids.length > 0 && !urlsWithIds.some((u) => u.url === url)) {
        urlsWithIds.push({ url, ids });
        console.log(`Found URL with IDs: ${url}`);
      }

      // Extract links from page
      try {
        const $ = cheerio.load(response.data);
        $("a[href]").each((_, link) => {
          try {
            const href = $(link).attr("href");
            if (!href || href.startsWith("#") || href.startsWith("javascript:")) return;

            const fullUrl = new URL(href, url).toString();

            // Only process URLs from the same domain
            if (fullUrl.startsWith(baseOrigin)) {
              const linkIds = extractIdsFromUrl(fullUrl);
              if (linkIds.length > 0 && !urlsWithIds.some((u) => u.url === fullUrl)) {
                urlsWithIds.push({ url: fullUrl, ids: linkIds });
                console.log(`Found URL with IDs from link: ${fullUrl}`);
              }

              // Add to queue for further crawling
              if (depth < maxDepth && !visited.has(fullUrl) && urlsWithIds.length < maxPages) {
                queue.push({ url: fullUrl, depth: depth + 1 });
              }
            }
          } catch (e) {
            // Invalid URL, skip
          }
        });
      } catch (parseError) {
        console.error(`Error parsing HTML: ${parseError.message}`);
      }
    } catch (error) {
      console.error(`Error discovering URLs ${url}: ${error.message}`);
      continue;
    }
  }

  console.log(`Discovery complete: Found ${urlsWithIds.length} URLs with IDs`);
  return urlsWithIds;
}

/**
 * Tests IDOR by accessing different object IDs
 */
async function testIDOR(targetUrl, idValue, idType, idKey = null) {
  try {
    console.log(`Testing IDOR: ${idValue} (${idType}${idKey ? `, key: ${idKey}` : ""})`);

        // Fetch original object response for comparison
    let originalResponseBody = "";
    let originalResponseLength = 0;

    try {
      const originalRes = await client.get(targetUrl, {
        timeout: TIMEOUT,
        headers: { "User-Agent": USER_AGENT },
        validateStatus: () => true,
      });

      originalResponseBody = String(originalRes.data || "");
      originalResponseLength = originalResponseBody.length;
    } catch {}

    // Generate test IDs (increment, decrement, sequential)
    const testIds = [
      String(parseInt(idValue) + 1), // Next ID
      String(parseInt(idValue) - 1), // Previous ID
      String(parseInt(idValue) + 10), // Higher ID
      String(parseInt(idValue) * 2), // Multiplied ID
      "1", // First ID
      "999", // High ID
    ].filter((id) => parseInt(id) > 0);

    const findings = [];

    for (const testId of testIds) {
      try {
        let testUrl;

        if (idType === "path") {
          // Replace in path
          const urlObj = new URL(targetUrl);
          const pathParts = urlObj.pathname.split("/").filter((p) => p);
          const idIndex = pathParts.findIndex((p) => p === idValue);
          if (idIndex !== -1) {
            pathParts[idIndex] = testId;
            urlObj.pathname = "/" + pathParts.join("/");
            testUrl = urlObj.toString();
          } else {
            continue;
          }
        } else if (idType === "query") {
          // Replace in query parameter
          const urlObj = new URL(targetUrl);
          urlObj.searchParams.set(idKey, testId);
          testUrl = urlObj.toString();
        } else {
          continue;
        }

        console.log(`Testing IDOR with ID: ${testId} (${testUrl})`);

        const parsedTestUrl = new URL(testUrl);
        const pathname = parsedTestUrl.pathname;

        /**
         * RULE: Never treat homepage or index as IDOR
         */
        if (pathname === "/" || pathname === "/index.php") {
          continue;
        }

        const response = await client.get(testUrl, {
          timeout: TIMEOUT,
          headers: { "User-Agent": USER_AGENT },
          validateStatus: () => true,
        });

        // Check if we got a successful response (not 404, 403, 401)
        if (response.status === 200) {
          // Check if response is different from original (not just same error page)
          const responseBody = String(response.data || "");
          const responseLength = responseBody.length;
          const lengthDifference = Math.abs(responseLength - originalResponseLength);
          const significantDifference = lengthDifference > 50;

          const contentLooksSame =
            responseBody.slice(0, 200) === originalResponseBody.slice(0, 200);

            const containsSensitiveData = SENSITIVE_KEYWORDS.some((kw) =>
              responseBody.toLowerCase().includes(kw));
            const looksLikePublicObject = PUBLIC_OBJECT_KEYWORDS.some((kw) =>
              (idKey || "").toLowerCase().includes(kw) ||
              targetUrl.toLowerCase().includes(kw)
            );

          // Indicators of successful access
          const successIndicators = [
            !responseBody.toLowerCase().includes("not found"),
            !responseBody.toLowerCase().includes("forbidden"),
            !responseBody.toLowerCase().includes("unauthorized"),
            !responseBody.toLowerCase().includes("access denied"),
            !responseBody.toLowerCase().includes("404"),
            !responseBody.toLowerCase().includes("403"),
            !responseBody.toLowerCase().includes("401"),
          ];
            let ownerMismatch = false;

            try {
              const json = JSON.parse(responseBody);

              // LAB-SPECIFIC LOGIC
              if (
                json.accessedBy &&
                json.data &&
                json.data.id !== undefined &&
                String(json.data.id) !== String(idValue)
              ) {
                ownerMismatch = true;
              }
            } catch {}


          const isSuccessful =
          successIndicators.filter((ind) => ind).length >= 3 &&
          (
            containsSensitiveData ||
            (significantDifference && !contentLooksSame)
          ) &&
          !looksLikePublicObject;



        if (isSuccessful) {
        const isConfirmedIDOR =
          ownerMismatch ||
          (
            response.status === 200 &&
            String(testId) !== String(idValue)
          );


        console.log("[IDOR] Owner mismatch detected:", {
          originalId: idValue,
          accessedId: testId
        });


          findings.push({
            originalId: idValue,
            testId: testId,
            url: testUrl,
            status: response.status,
            evidence: `Successfully accessed object with ID ${testId}`,
            responseLength: responseLength,
            confidence: containsSensitiveData
              ? "High"
              : significantDifference
              ? "Medium"
              : "Low",
            classification: isConfirmedIDOR
              ? "Confirmed IDOR"
              : "Possible IDOR (Manual Review Recommended)",
          });
        }

        }
      } catch (error) {
        console.error(`Error testing IDOR with ID ${testId}:`, error.message);
        continue;
      }
    }

    return findings;
  } catch (error) {
    console.error(`Error testing IDOR:`, error.message);
    return [];
  }
}

/**
 * Tests IDOR via POST/PUT requests
 */
async function testIDORPost(targetUrl, idValue, idKey) {
  try {
    console.log(`Testing IDOR via POST: ${idKey} = ${idValue}`);

    const testIds = [
      String(parseInt(idValue) + 1),
      String(parseInt(idValue) - 1),
      String(parseInt(idValue) + 10),
      "1",
    ].filter((id) => parseInt(id) > 0);

    const findings = [];

    for (const testId of testIds) {
      try {
        const response = await client.post(
          targetUrl,
          { [idKey]: testId },
          {
            timeout: TIMEOUT,
            headers: {
              "User-Agent": USER_AGENT,
              "Content-Type": "application/json",
            },
            validateStatus: () => true,
          }
        );

        if (response.status === 200 || response.status === 201) {
          const responseBody = String(response.data || "");
          const successIndicators = [
            !responseBody.toLowerCase().includes("not found"),
            !responseBody.toLowerCase().includes("forbidden"),
            !responseBody.toLowerCase().includes("unauthorized"),
            responseBody.length > 50,
          ];

          const isSuccessful = successIndicators.filter((ind) => ind).length >= 2;

          if (isSuccessful) {
            const containsSensitiveData = SENSITIVE_KEYWORDS.some((kw) =>
              responseBody.toLowerCase().includes(kw)
            );

          const isConfirmedIDOR =
            containsSensitiveData &&
            String(testId) !== String(idValue);


            findings.push({
              originalId: idValue,
              testId: testId,
              method: "POST",
              status: response.status,
              evidence: `Successfully accessed/modified object with ID ${testId}`,
              confidence: containsSensitiveData ? "High" : "Medium",
              classification: isConfirmedIDOR
                ? "Confirmed IDOR"
                : "Possible IDOR (Manual Review Recommended)",
            });
          }
        }
      } catch (error) {
        console.error(`Error testing IDOR POST with ID ${testId}:`, error.message);
        continue;
      }
    }

    return findings;
  } catch (error) {
    console.error(`Error testing IDOR POST:`, error.message);
    return [];
  }
}

/**
 * Detects predictable ID patterns
 */
function detectPredictablePatterns(url) {
  const urlObj = new URL(url);
  const ids = extractIdsFromUrl(url);

  const patterns = [];

  for (const id of ids) {
    const idNum = parseInt(id.value);

    // Check if it's sequential (1, 2, 3, ...)
    if (idNum > 0 && idNum < 1000) {
      patterns.push({
        id: id,
        pattern: "Sequential",
        risk: "High",
        description: "ID appears to be sequential (predictable)",
      });
    }

    // Check if it's timestamp-like
    if (idNum > 1000000000 && idNum < 9999999999) {
      patterns.push({
        id: id,
        pattern: "Timestamp-like",
        risk: "Medium",
        description: "ID appears to be timestamp-based (may be predictable)",
      });
    }

    // Check if it's a small number
    if (idNum > 0 && idNum < 100) {
      patterns.push({
        id: id,
        pattern: "Small ID",
        risk: "High",
        description: "ID is a small number (easy to enumerate)",
      });
    }
  }

  return patterns;
}

/**
 * Main function to scan for IDOR vulnerabilities
 */
async function scanIDOR(url) {
   url = normalizeUrl(url);
   const baseOrigin = new URL(url).origin;

    // 🔐 AUTHENTICATE FIRST
    await loginIfNeeded(baseOrigin);

  console.log(`Starting IDOR scan for: ${url}`);

  try {
    const urlObj = new URL(url);
    // Use origin directly for base URL - simpler and more reliable
    const baseOrigin = urlObj.origin;
    const baseUrl = urlObj.origin; // Use origin as base for crawling

    // First check if the provided URL itself has IDs
    let urlsToTest = [];
    const providedIds = extractIdsFromUrl(url);

    if (providedIds.length > 0) {
      urlsToTest.push({ url, ids: providedIds });
      console.log(`Provided URL contains ${providedIds.length} IDs`);
    } else {
      // Discover URLs with IDs by crawling from the provided URL
      console.log(`No IDs in provided URL, discovering URLs with IDs from: ${url}`);
      let discovered = [];
      
      try {
        discovered = await discoverUrlsWithIds(url, 15);
      } catch (error) {
        console.error(`Error during discovery: ${error.message}`);
      }
      
      urlsToTest = discovered;

      // If still no URLs found, try crawling from origin
      if (urlsToTest.length === 0 && url !== baseOrigin) {
        console.log(`No URLs with IDs found from provided URL, trying base origin: ${baseOrigin}`);
        try {
          discovered = await discoverUrlsWithIds(baseOrigin, 15);
          urlsToTest = discovered;
        } catch (error) {
          console.error(`Error discovering from origin: ${error.message}`);
        }
      }

      // As fallback, try common patterns
      if (urlsToTest.length === 0) {
        console.log(`No URLs with IDs discovered, testing common ID patterns`);
        const commonPaths = ["/user/", "/user", "/profile/", "/profile", "/id/", "/id", "/item/", "/item", "/product/", "/product"];
        for (const path of commonPaths.slice(0, 5)) {
          const testUrl = new URL(path + "1", baseOrigin).toString();
          try {
            const response = await client.get(testUrl, {
              timeout: TIMEOUT,
              headers: { "User-Agent": USER_AGENT },
              validateStatus: () => true,
            });
            if (response.status === 200) {
              const testIds = extractIdsFromUrl(testUrl);
              if (testIds.length > 0) {
                urlsToTest.push({ url: testUrl, ids: testIds });
                console.log(`Found URL with ID pattern: ${testUrl}`);
              }
            }
          } catch (e) {
            // Continue
          }
        }
      }
    }

    if (urlsToTest.length === 0) {
      return {
        module: "IDOR",
        target: url,
        vulnerable: false,
        evidence: "No URLs with numeric IDs found",
        notes: "Unable to test IDOR - no URLs with numeric IDs detected. Try providing a URL with a numeric ID (e.g., /user/123 or /item?id=456).",
      };
    }

    console.log(`Testing ${urlsToTest.length} URLs for IDOR`);

    // Test each URL with IDs
    const findings = [];
    const allPatterns = [];

    for (const { url: testUrl, ids } of urlsToTest.slice(0, 5)) {
      console.log(`Testing URL: ${testUrl} (${ids.length} IDs)`);

      // Detect predictable patterns
      const patterns = detectPredictablePatterns(testUrl);
      allPatterns.push(...patterns);

      // Test each ID for IDOR
    for (const id of ids.slice(0, 2)) {

      // 🚫 Skip PUBLIC objects → NOT IDOR
      const isPublicEndpoint = PUBLIC_OBJECT_KEYWORDS.some((kw) =>
        testUrl.toLowerCase().includes(kw) ||
        (id.key || "").toLowerCase().includes(kw)
      );

      if (isPublicEndpoint) {
        console.log(`[SKIP] Public object endpoint → ${testUrl}`);
        continue;
      }

      console.log(`Testing IDOR for ID: ${id.value} (${id.type})`);

      if (id.type === "path") {
        const idorFindings = await testIDOR(testUrl, id.value, id.type);
        findings.push(...idorFindings);

      } else if (id.type === "query") {
        const idorFindings = await testIDOR(
          testUrl,
          id.value,
          id.type,
          id.key
        );
        findings.push(...idorFindings);

        // 🔐 POST IDOR only for sensitive object endpoints
        const isObjectEndpoint =
          /\/(user|profile|account|order|invoice|admin)/i.test(testUrl);

        if (isObjectEndpoint) {
          const postFindings = await testIDORPost(
            testUrl,
            id.value,
            id.key
          );
          findings.push(...postFindings);
        }
      }

      // Stop after first confirmed issue
      if (findings.length > 0) break;
    }


      // Stop after first vulnerable URL
      if (findings.length > 0) break;
    }

    // Add pattern findings
    const highRiskPatterns = allPatterns.filter((p) => p.risk === "High");
    if (highRiskPatterns.length > 0 && findings.length === 0) {
      findings.push({
        type: "Predictable Pattern",
        patterns: highRiskPatterns,
        evidence: "IDs appear to be predictable/sequential",
        confidence: "Info",
        classification: "Informational",
      });
    }

    const hasOnlyLowConfidence =
      findings.length > 0 &&
      findings.every((f) => f.confidence === "Low");

    const hasConfirmedIDOR = findings.some(
      (f) => f.classification === "Confirmed IDOR"
    );

    const vulnerable = hasConfirmedIDOR;

    return {
      module: "IDOR",
      target: url,
      vulnerable: vulnerable,
      evidence: vulnerable
        ? {
            findings: findings.map((f) => ({
              originalId: f.originalId,
              testId: f.testId,
              url: f.url || url,
              evidence: f.evidence,
              confidence: f.confidence || "Unknown",
              classification: f.classification || "Unclassified",
              patterns: f.patterns || null,
            })),

            patterns: allPatterns.slice(0, 5),
          }
        : "No IDOR vulnerabilities detected",
            notes: hasConfirmedIDOR
              ? "IDOR vulnerabilities detected. Unauthorized access to restricted objects confirmed."
              : allPatterns.length > 0
              ? "No IDOR detected. Predictable object identifiers found (informational only)."
              : "No IDOR vulnerabilities detected. Object references appear to be properly protected.",

    };
  } catch (error) {
    console.error("IDOR scan error:", error);
    return {
      module: "IDOR",
      target: url,
      vulnerable: false,
      evidence: "Scan failed due to error",
      notes: `Error: ${error.message}`,
    };
  }
}

module.exports = { scanIDOR };
