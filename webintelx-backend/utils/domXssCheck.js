/**
 * DOM-Based XSS Detection Module
 * Analyzes JavaScript for client-side sinks and unsafe data flow
 */

const axios = require("axios");
const { JSDOM } = require("jsdom");
const { URL } = require("url");

const USER_AGENT = "WebIntelX-DOMXSS-Scanner/1.0";
const TIMEOUT = 40000; // Increased timeout

// DOM-based XSS sinks (dangerous functions)
const DOM_SINKS = [
  /document\.write\s*\(/gi,
  /document\.writeln\s*\(/gi,
  /\.innerHTML\s*=/gi,
  /\.outerHTML\s*=/gi,
  /\.insertAdjacentHTML\s*\(/gi,
  /eval\s*\(/gi,
  /Function\s*\(/gi,
  /setTimeout\s*\(/gi,
  /setInterval\s*\(/gi,
  /location\s*=/gi,
  /location\.href\s*=/gi,
  /location\.replace\s*\(/gi,
  /location\.assign\s*\(/gi,
  /\.src\s*=/gi,
  /\.setAttribute\s*\(/gi,
];

// DOM-based XSS sources (user-controlled data)
const DOM_SOURCES = [
  /location\.search/gi,
  /location\.hash/gi,
  /location\.href/gi,
  /document\.URL/gi,
  /document\.location/gi,
  /document\.referrer/gi,
  /window\.name/gi,
  /document\.cookie/gi,
  /window\.location/gi,
  /location\.pathname/gi,
  /URLSearchParams/gi,
];

/* =========================
   ADDED (REQUIRED)
========================= */
function normalizeUrl(input) {
  if (!input.startsWith("http://") && !input.startsWith("https://")) {
    return "http://" + input;
  }
  return input;
}

/**
 * Analyzes JavaScript code for DOM XSS vulnerabilities
 */
function analyzeJavaScript(code, fileUrl) {
  const findings = [];

  if (!code || typeof code !== "string") {
    return findings;
  }

  const hasSink = DOM_SINKS.some((pattern) => pattern.test(code));
  const hasSource = DOM_SOURCES.some((pattern) => pattern.test(code));

  if (hasSink && hasSource) {
    findings.push({
      type: "DOM XSS - Source to Sink",
      location: fileUrl,
      evidence: "Dangerous DOM manipulation functions used with user-controlled data sources",
      confidence: "High",
    });
  } else if (hasSink) {
    findings.push({
      type: "DOM XSS - Potential Sink",
      location: fileUrl,
      evidence: "Dangerous DOM manipulation functions detected (requires manual review)",
      confidence: "Medium",
    });
  }

  const dangerousPatterns = [
    {
      pattern: /eval\s*\(\s*location/gi,
      description: "eval() with location object",
      confidence: "High",
    },
    {
      pattern: /innerHTML\s*=\s*location/gi,
      description: "innerHTML assignment with location object",
      confidence: "High",
    },
    {
      pattern: /document\.write\s*\(\s*location/gi,
      description: "document.write() with location object",
      confidence: "High",
    },
    {
      pattern: /\.innerHTML\s*=\s*.*location\.(search|hash)/gi,
      description: "innerHTML assignment with location.search/hash",
      confidence: "High",
    },
  ];

  for (const check of dangerousPatterns) {
    if (check.pattern.test(code)) {
      findings.push({
        type: "DOM XSS - Specific Pattern",
        location: fileUrl,
        evidence: check.description,
        confidence: check.confidence,
      });
    }
  }

  return findings;
}

/**
 * Fetches and analyzes a page for DOM XSS vulnerabilities
 */
async function scanDOMXSS(inputUrl) {
  /* =========================
     ADDED (REQUIRED)
  ========================= */
  const url = normalizeUrl(inputUrl);

  console.log(`Starting DOM-Based XSS scan for: ${url}`);

  const findings = [];
  const urlObj = new URL(url);

  try {
    console.log(`Fetching page: ${url}`);
    const response = await axios.get(url, {
      timeout: TIMEOUT,
      headers: { "User-Agent": USER_AGENT },
      validateStatus: () => true,
    });

    if (response.status !== 200) {
      console.error(`Failed to fetch page: HTTP ${response.status}`);
      return {
        module: "DOM-Based XSS",
        target: url,
        vulnerable: false,
        evidence: `Failed to fetch page: HTTP ${response.status}`,
        notes: "Unable to analyze page for DOM XSS vulnerabilities",
      };
    }

    const html = response.data;
    const dom = new JSDOM(html, { url: url, runScripts: "outside-only" });

    // Analyze inline scripts
    const inlineScripts = dom.window.document.querySelectorAll("script:not([src])");
    console.log(`Found ${inlineScripts.length} inline scripts`);

    for (const script of inlineScripts) {
      const code = script.textContent || "";
      if (code.trim()) {
        const scriptFindings = analyzeJavaScript(code, "Inline Script");
        findings.push(...scriptFindings);
      }
    }

    // Analyze external scripts
    const externalScripts = dom.window.document.querySelectorAll("script[src]");
    console.log(`Found ${externalScripts.length} external scripts`);

    for (const script of externalScripts) {
      const src = script.getAttribute("src");
      if (!src) continue;

      try {
        const scriptUrl = new URL(src, url).toString();
        console.log(`Fetching external script: ${scriptUrl}`);

        const scriptResponse = await axios.get(scriptUrl, {
          timeout: TIMEOUT,
          headers: { "User-Agent": USER_AGENT },
          validateStatus: () => true,
        });

        if (scriptResponse.status === 200) {
          const scriptCode = scriptResponse.data || "";
          const scriptFindings = analyzeJavaScript(scriptCode, scriptUrl);
          findings.push(...scriptFindings);
        }
      } catch (error) {
        console.error(`Error fetching script ${src}:`, error.message);
      }
    }

    // ⚠️ PAYLOAD TESTING LEFT UNCHANGED (AS REQUESTED)
    // (fragment + query param testing remains exactly the same)

    const testPayloads = [
      "<img src=x onerror=alert('DOMXSS')>",
      "<script>alert('DOMXSS')</script>",
      "javascript:alert('DOMXSS')",
      "'\"><img src=x onerror=alert('DOMXSS')>",
    ];

    for (const payload of testPayloads) {
      try {
        const testUrlFragment = new URL(url);
        testUrlFragment.hash = payload;

        const fragmentResponse = await axios.get(testUrlFragment.toString(), {
          timeout: TIMEOUT,
          headers: { "User-Agent": USER_AGENT },
          validateStatus: () => true,
        });

        const fragmentHtml = String(fragmentResponse.data || "");
        if (fragmentHtml.includes(payload) && !fragmentHtml.includes(encodeURIComponent(payload))) {
          findings.push({
            type: "DOM XSS - URL Fragment",
            location: "URL Fragment",
            evidence: `Payload "${payload}" reflected in response without encoding`,
            confidence: "Medium",
          });
        }
      } catch (error) {
        console.error(`Error testing URL fragment:`, error.message);
      }

      if (urlObj.searchParams.toString()) {
        for (const [paramName] of urlObj.searchParams.entries()) {
          try {
            const testUrlParam = new URL(url);
            testUrlParam.searchParams.set(paramName, payload);

            const paramResponse = await axios.get(testUrlParam.toString(), {
              timeout: TIMEOUT,
              headers: { "User-Agent": USER_AGENT },
              validateStatus: () => true,
            });

            const paramHtml = String(paramResponse.data || "");
            if (paramHtml.includes(payload) && !paramHtml.includes(encodeURIComponent(payload))) {
              findings.push({
                type: "DOM XSS - Query Parameter",
                location: `Parameter: ${paramName}`,
                evidence: `Payload "${payload}" reflected in response without encoding`,
                confidence: "Medium",
              });
            }
          } catch (error) {
            console.error(`Error testing query parameter:`, error.message);
          }
        }
      }
    }
  } catch (error) {
    console.error("DOM XSS scan error:", error);
    return {
      module: "DOM-Based XSS",
      target: url,
      vulnerable: false,
      evidence: "Scan failed due to error",
      notes: `Error: ${error.message}`,
    };
  }

  const vulnerable = findings.length > 0;

  return {
    module: "DOM-Based XSS",
    target: url,
    vulnerable: vulnerable,
    evidence: vulnerable
      ? findings.map((f) => ({
          type: f.type,
          location: f.location,
          evidence: f.evidence,
          confidence: f.confidence,
        }))
      : "No DOM-based XSS vulnerabilities detected",
    notes: vulnerable
      ? "DOM-based XSS vulnerabilities detected. JavaScript code uses dangerous DOM manipulation functions with user-controlled data sources. This can lead to client-side code injection."
      : "No DOM-based XSS vulnerabilities detected in analyzed JavaScript code.",
  };
}

module.exports = { scanDOMXSS };
