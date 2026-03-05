//this is the domXssCheck.js file in the utils folder

/**
 * DOM-Based XSS Detection Module (Refactored)
 * Analyzes JavaScript for client-side sinks with proper source-to-sink tracking
 * Reduces false positives by:
 * - Ignoring third-party and minified libraries
 * - Validating source-to-sink data flows
 * - Detecting sanitization functions
 * - Improving confidence scoring
 */

const axios = require("axios");
const { JSDOM } = require("jsdom");
const { URL } = require("url");

const USER_AGENT = "WebIntelX-DOMXSS-Scanner/1.0";
const TIMEOUT = 40000;

// === THIRD-PARTY LIBRARY PATTERNS ===
const THIRD_PARTY_PATTERNS = [
  /jquery\.min\.js/i,
  /jquery-migrate\.min\.js/i,
  /bootstrap\.min\.js/i,
  /mootools-core\.js/i,
  /mootools-more\.js/i,
  /google.*maps.*api/i,
  /\.min\.js$/i, // Any minified JS file
  /cdnjs\.cloudflare\.com/i,
  /cdn\.jsdelivr\.net/i,
  /unpkg\.com/i,
  /jsdelivr\.net/i,
];

// === SANITIZATION & ENCODING FUNCTIONS ===
const SANITIZATION_FUNCTIONS = [
  /encodeURI(?:Component)?\s*\(/gi,
  /escape\s*\(/gi,
  /htmlEscape\s*\(/gi,
  /sanitize\s*\(/gi,
  /DOMPurify\.sanitize\s*\(/gi,
  /xss\s*\(/gi,
  /escape(?:HTML)?\s*\(/gi,
  /strip(?:Tags|HTML)\s*\(/gi,
  /textContent\s*=/gi, // textContent is safe (doesn't parse HTML)
];

// === DANGEROUS SINKS ===
const DANGEROUS_SINKS = [
  { pattern: /document\.write\s*\(/gi, name: "document.write()", severity: "high" },
  { pattern: /document\.writeln\s*\(/gi, name: "document.writeln()", severity: "high" },
  { pattern: /\.innerHTML\s*=/gi, name: ".innerHTML =", severity: "high" },
  { pattern: /\.outerHTML\s*=/gi, name: ".outerHTML =", severity: "high" },
  { pattern: /\.insertAdjacentHTML\s*\(/gi, name: ".insertAdjacentHTML()", severity: "high" },
  { pattern: /eval\s*\(/gi, name: "eval()", severity: "critical" },
  { pattern: /Function\s*\(/gi, name: "Function()", severity: "high" },
  { pattern: /setTimeout\s*\(/gi, name: "setTimeout()", severity: "medium" },
  { pattern: /setInterval\s*\(/gi, name: "setInterval()", severity: "medium" },
  { pattern: /\.src\s*=/gi, name: ".src =", severity: "medium" },
  { pattern: /\.setAttribute\s*\(/gi, name: ".setAttribute()", severity: "medium" },
];

// === USER-CONTROLLED SOURCES ===
const USER_SOURCES = [
  { pattern: /location\.search/gi, name: "location.search", type: "url" },
  { pattern: /location\.hash/gi, name: "location.hash", type: "url" },
  { pattern: /location\.href/gi, name: "location.href", type: "url" },
  { pattern: /document\.URL/gi, name: "document.URL", type: "url" },
  { pattern: /document\.location/gi, name: "document.location", type: "url" },
  { pattern: /document\.referrer/gi, name: "document.referrer", type: "url" },
  { pattern: /window\.name/gi, name: "window.name", type: "storage" },
  { pattern: /document\.cookie/gi, name: "document.cookie", type: "storage" },
  { pattern: /window\.location/gi, name: "window.location", type: "url" },
  { pattern: /URLSearchParams/gi, name: "URLSearchParams", type: "url" },
];

function normalizeUrl(input) {
  if (!input.startsWith("http://") && !input.startsWith("https://")) {
    return "http://" + input;
  }
  return input;
}

/**
 * Check if file is a third-party library or minified
 */
function isThirdPartyLibrary(fileUrl) {
  return THIRD_PARTY_PATTERNS.some(pattern => pattern.test(fileUrl));
}

/**
 * Detect if value passes through sanitization/encoding
 */
function hasSanitization(code) {
  return SANITIZATION_FUNCTIONS.some(pattern => pattern.test(code));
}

/**
 * Track source to sink data flow
 * Returns: { hasDirect: boolean, sources: [], sinks: [], flowConfidence: string }
 */
function analyzeDataFlow(code) {
  const sources = [];
  const sinks = [];
  
  // Find all sources
  USER_SOURCES.forEach(src => {
    if (src.pattern.test(code)) {
      src.pattern.lastIndex = 0; // Reset regex
      sources.push(src.name);
    }
  });
  
  // Find all sinks
  DANGEROUS_SINKS.forEach(sink => {
    if (sink.pattern.test(code)) {
      sink.pattern.lastIndex = 0; // Reset regex
      sinks.push({ name: sink.name, severity: sink.severity });
    }
  });
  
  // Analyze direct source->sink flow
  let flowConfidence = "low";
  let hasDirect = false;
  
  if (sources.length > 0 && sinks.length > 0) {
    // Look for direct assignments/flows: source → variable → sink
    const directFlowPatterns = [
      // eval(location.search)
      /eval\s*\(\s*location\.(search|hash|href)/gi,
      // innerHTML = location.search
      /\.innerHTML\s*=\s*location\.(search|hash|href)/gi,
      // document.write(location.search)
      /document\.write(?:ln)?\s*\(\s*location\.(search|hash|href)/gi,
      // .src = location.search
      /\.src\s*=\s*location\.(search|hash|href)/gi,
      // .setAttribute with location
      /\.setAttribute\s*\(\s*['"](src|href|onclick|on\w+)['"]\s*,\s*location\.(search|hash|href)/gi,
    ];
    
    hasDirect = directFlowPatterns.some(pattern => {
      const result = pattern.test(code);
      pattern.lastIndex = 0;
      return result;
    });
    
    if (hasDirect) {
      flowConfidence = hasSanitization(code) ? "medium" : "high";
    } else {
      flowConfidence = "medium"; // Sources and sinks exist but not directly connected
    }
  }
  
  return {
    hasDirect,
    sources,
    sinks,
    flowConfidence,
    hasSanitization: hasSanitization(code)
  };
}

/**
 * Analyzes JavaScript code for DOM XSS vulnerabilities (with reduced false positives)
 */
function analyzeJavaScript(code, fileUrl) {
  const findings = [];
  
  if (!code || typeof code !== "string") {
    return findings;
  }
  
  // SKIP THIRD-PARTY LIBRARIES
  if (isThirdPartyLibrary(fileUrl)) {
    console.log(`[DOM XSS] Skipping third-party library: ${fileUrl}`);
    return findings;
  }
  
  const flow = analyzeDataFlow(code);
  
  // === CASE 1: Direct source-to-sink flow without sanitization ===
  if (flow.hasDirect && !flow.hasSanitization) {
    findings.push({
      type: "DOM XSS - Confirmed Source to Sink",
      location: fileUrl,
      evidence: `Direct data flow from ${flow.sources.join(", ")} → ${flow.sinks.map(s => s.name).join(", ")} without sanitization`,
      confidence: "High",
      sources: flow.sources,
      sinks: flow.sinks
    });
    return findings;
  }
  
  // === CASE 2: Source and sink exist, but unclear flow (with or without sanitization) ===
  if (flow.hasDirect && flow.hasSanitization) {
    findings.push({
      type: "DOM XSS - Sanitized Flow",
      location: fileUrl,
      evidence: `Data flow detected but sanitization functions present. Manual review recommended.`,
      confidence: "Medium",
      sources: flow.sources,
      sinks: flow.sinks
    });
    return findings;
  }
  
  // === CASE 3: Sources and sinks present but not directly connected ===
  if (flow.sources.length > 0 && flow.sinks.length > 0) {
    findings.push({
      type: "DOM XSS - Source and Sink Detected",
      location: fileUrl,
      evidence: `Sources (${flow.sources.join(", ")}) and sinks (${flow.sinks.map(s => s.name).join(", ")}) present but data flow unclear. May require manual inspection.`,
      confidence: "Low",
      sources: flow.sources,
      sinks: flow.sinks
    });
    return findings;
  }
  
  // === CASE 4: Sink only (no source detected) ===
  if (flow.sinks.length > 0 && flow.sources.length === 0) {
    findings.push({
      type: "DOM XSS - Potential Sink",
      location: fileUrl,
      evidence: `Dangerous sink found (${flow.sinks.map(s => s.name).join(", ")}) but no user-controlled source detected in this file. Manual review recommended.`,
      confidence: "Low",
      sinks: flow.sinks
    });
    return findings;
  }
  
  return findings;
}

/**
 * Fetches and analyzes a page for DOM XSS vulnerabilities (improved)
 */
async function scanDOMXSS(inputUrl) {
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
    
    // Analyze inline scripts (application code)
    const inlineScripts = dom.window.document.querySelectorAll("script:not([src])");
    console.log(`Found ${inlineScripts.length} inline scripts`);
    
    for (const script of inlineScripts) {
      const code = script.textContent || "";
      if (code.trim()) {
        const scriptFindings = analyzeJavaScript(code, "Inline Application Script");
        findings.push(...scriptFindings);
      }
    }
    
    // Analyze external scripts (only if not third-party)
    const externalScripts = dom.window.document.querySelectorAll("script[src]");
    console.log(`Found ${externalScripts.length} external scripts`);
    
    for (const script of externalScripts) {
      const src = script.getAttribute("src");
      if (!src) continue;
      
      // SKIP THIRD-PARTY LIBRARIES
      if (isThirdPartyLibrary(src)) {
        console.log(`[DOM XSS] Skipping third-party library: ${src}`);
        continue;
      }
      
      try {
        const scriptUrl = new URL(src, url).toString();
        console.log(`Fetching custom external script: ${scriptUrl}`);
        
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
    
    // === RUNTIME PAYLOAD TESTING ===
    // Test if user input actually reaches the DOM
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
        // Payload must be present AND unencoded
        if (fragmentHtml.includes(payload) && !fragmentHtml.includes(encodeURIComponent(payload))) {
          findings.push({
            type: "DOM XSS - Runtime Fragment Injection",
            location: "URL Fragment (#)",
            evidence: `Unencoded payload "${payload.substring(0, 30)}..." reflected in response`,
            confidence: "High",
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
                type: "DOM XSS - Runtime Query Parameter Injection",
                location: `Parameter: ${paramName}`,
                evidence: `Unencoded payload "${payload.substring(0, 30)}..." reflected in response without encoding`,
                confidence: "High",
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
          sources: f.sources,
          sinks: f.sinks,
        }))
      : "No DOM-based XSS vulnerabilities detected",
    notes: vulnerable
      ? "DOM-based XSS vulnerabilities detected. Verify that user input reaches vulnerable code paths and consider additional mitigation."
      : "No DOM-based XSS vulnerabilities detected in application code.",
  };
}

module.exports = { scanDOMXSS };
