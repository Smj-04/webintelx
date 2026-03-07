/**
 * DOM-Based XSS Detection Module — Puppeteer Edition
 *
 * Uses a real headless Chrome browser to:
 * 1. Inject payloads into URL sources (location.search, location.hash, query params)
 * 2. Detect actual alert()/confirm()/prompt() execution in the browser
 * 3. Monitor DOM mutations caused by injected payloads
 * 4. Fall back to static JS analysis for source/sink pattern detection
 *
 * This approach eliminates false positives from static analysis and
 * correctly handles location.hash (which axios-based scanners cannot test).
 */

const puppeteer = require("puppeteer");
const axios = require("axios");
const { JSDOM } = require("jsdom");
const { URL } = require("url");

const USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36";
const PAGE_TIMEOUT = 8000;   // 8s per page — fast enough, generous enough
const SCAN_TIMEOUT = 150000; // 2.5 min total — covers crawler + multi-page puppeteer

// Focused payload list — best coverage, minimal count
// Each tests a different sink type
const DOM_XSS_PAYLOADS = [
  `<img src=x onerror=alert('DOMXSS')>`,  // innerHTML / document.write
  `<svg onload=alert('DOMXSS')>`,          // innerHTML variant
  `javascript:alert('DOMXSS')`,            // href/src sinks
  `'onmouseover='alert('DOMXSS')`,         // attribute injection
];

// Static analysis patterns (fallback)
const THIRD_PARTY_PATTERNS = [
  /jquery[.-](\d+\.)*\d+(\.min)?\.js/i,
  /bootstrap[.-](\d+\.)*\d+(\.min)?\.js/i,
  /cdnjs\.cloudflare\.com/i,
  /cdn\.jsdelivr\.net/i,
  /unpkg\.com/i,
  /ajax\.googleapis\.com/i,
  /code\.jquery\.com/i,
];

const DANGEROUS_SINKS = [
  { pattern: /document\.write\s*\(/i, name: "document.write()", severity: "high" },
  { pattern: /\.innerHTML\s*=/i, name: ".innerHTML =", severity: "high" },
  { pattern: /\.outerHTML\s*=/i, name: ".outerHTML =", severity: "high" },
  { pattern: /\.insertAdjacentHTML\s*\(/i, name: ".insertAdjacentHTML()", severity: "high" },
  { pattern: /\beval\s*\(/i, name: "eval()", severity: "critical" },
  { pattern: /\bFunction\s*\(/i, name: "Function()", severity: "high" },
  { pattern: /\.src\s*=/i, name: ".src =", severity: "medium" },
  { pattern: /\.setAttribute\s*\(\s*['"](?:src|href|on\w+)['"]/i, name: ".setAttribute()", severity: "medium" },
];

const USER_SOURCES = [
  { pattern: /location\.search/i, name: "location.search" },
  { pattern: /location\.hash/i, name: "location.hash" },
  { pattern: /location\.href/i, name: "location.href" },
  { pattern: /document\.URL/i, name: "document.URL" },
  { pattern: /document\.referrer/i, name: "document.referrer" },
  { pattern: /window\.name/i, name: "window.name" },
  { pattern: /document\.cookie/i, name: "document.cookie" },
  { pattern: /window\.location/i, name: "window.location" },
  { pattern: /URLSearchParams/i, name: "URLSearchParams" },
];

const DIRECT_FLOW_PATTERNS = [
  /eval\s*\(\s*(?:window\.|document\.)?location[\.\w]*/i,
  /\.innerHTML\s*=\s*(?:window\.|document\.)?location[\.\w]*/i,
  /document\.write(?:ln)?\s*\(\s*(?:window\.|document\.)?location[\.\w]*/i,
  /\.src\s*=\s*(?:window\.|document\.)?location[\.\w]*/i,
  /\.outerHTML\s*=\s*(?:window\.|document\.)?location[\.\w]*/i,
  /\.insertAdjacentHTML\s*\([^,]+,\s*(?:window\.|document\.)?location[\.\w]*/i,
];

function normalizeUrl(input) {
  if (!input.startsWith("http://") && !input.startsWith("https://")) {
    return "http://" + input;
  }
  return input;
}

function isThirdParty(url) {
  return THIRD_PARTY_PATTERNS.some(p => p.test(url));
}

function staticAnalyze(code, label) {
  if (!code || code.trim().length < 10) return [];
  if (isThirdParty(label)) return [];

  const sources = USER_SOURCES.filter(s => s.pattern.test(code)).map(s => s.name);
  const sinks = DANGEROUS_SINKS.filter(s => s.pattern.test(code)).map(s => ({ name: s.name, severity: s.severity }));
  const hasDirect = DIRECT_FLOW_PATTERNS.some(p => p.test(code));

  if (hasDirect) {
    return [{
      type: "DOM XSS - Direct Source to Sink (Static)",
      location: label,
      evidence: `Direct flow: ${sources.join(", ")} → ${sinks.map(s => s.name).join(", ")}`,
      confidence: "Medium", // Static analysis — needs browser confirmation
      sources,
      sinks,
    }];
  }

  if (sources.length > 0 && sinks.length > 0) {
    return [{
      type: "DOM XSS - Source and Sink Present (Static)",
      location: label,
      evidence: `Sources (${sources.join(", ")}) and sinks (${sinks.map(s => s.name).join(", ")}) found — indirect flow, manual review needed.`,
      confidence: "Low",
      sources,
      sinks,
    }];
  }

  return [];
}

/**
 * Build a FOCUSED set of test URLs — hash + top 4 params only
 * Keeps total page loads manageable (4 payloads × 5 URLs = 20 max)
 */
function buildTestUrls(baseUrl, payload) {
  const urls = [];
  const base = baseUrl.replace(/\/$/, "");

  // Hash injection — most common DOM XSS vector
  urls.push(`${base}/#${payload}`);

  // Top 4 most common reflected params only
  const commonParams = ["q", "search", "input", "query"];
  for (const param of commonParams) {
    urls.push(`${base}/?${param}=${encodeURIComponent(payload)}`);
  }

  return urls; // 5 URLs per payload max
}

/**
 * Core Puppeteer-based DOM XSS scanner
 * Launches real Chrome, injects payloads, listens for alert() execution
 */
async function puppeteerScan(url) {
  const findings = [];
  let browser = null;

  console.log(`[DOM XSS] Launching headless Chrome for: ${url}`);

  try {
    browser = await puppeteer.launch({
      headless: "new",
      timeout: 30000,
      args: [
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-dev-shm-usage",
        "--disable-gpu",
        "--no-first-run",
        "--no-zygote",
        "--disable-extensions",
      ],
    });

    // === TEST 1: Payload injection — ONE page reused per payload ===
    // Strategy: open one page, test all URLs for a payload via goto(), reuse page
    // This is ~5x faster than opening a new page per URL
    const page = await browser.newPage();
    await page.setUserAgent(USER_AGENT);
    await page.setDefaultTimeout(PAGE_TIMEOUT);

    for (const payload of DOM_XSS_PAYLOADS) {
      if (findings.length >= 2) break; // Stop early once we have confirmed findings

      const testUrls = buildTestUrls(url, payload);

      for (const testUrl of testUrls) {
        if (findings.length >= 2) break;

        try {
          let dialogTriggered = false;
          let dialogMessage = "";

          // Re-attach dialog handler each navigation
          const dialogHandler = async (dialog) => {
            const msg = dialog.message();
            if (msg.includes("DOMXSS") || msg === "1" || msg === "true") {
              dialogTriggered = true;
              dialogMessage = msg;
            }
            await dialog.dismiss().catch(() => {});
          };
          page.on("dialog", dialogHandler);

          try {
            await page.goto(testUrl, {
              waitUntil: "domcontentloaded",
              timeout: PAGE_TIMEOUT,
            });
            await new Promise(r => setTimeout(r, 1000));
          } catch (navErr) {
            // Navigation errors ok — dialog may still have fired
          }

          page.off("dialog", dialogHandler);

          if (dialogTriggered) {
            console.log(`[DOM XSS] ✅ CONFIRMED: alert('${dialogMessage}') at ${testUrl}`);
            const source = testUrl.includes("#") ? "location.hash"
              : testUrl.includes("?") ? "URL query parameter"
              : "URL path";
            findings.push({
              type: "DOM XSS - Confirmed Execution",
              location: testUrl,
              evidence: `alert('${dialogMessage}') executed — payload injected via ${source}`,
              confidence: "High",
              payload,
              source,
            });
            break; // Move to next payload
          }
        } catch (err) {
          console.log(`[DOM XSS] Page error for ${testUrl}: ${err.message}`);
        }
      }
    }

    await page.close().catch(() => {});

    // === TEST 2: Check existing page params ===
    // If the URL already has query params, test those too
    try {
      const urlObj = new URL(url);
      if (urlObj.searchParams.toString()) {
        for (const [paramName] of urlObj.searchParams.entries()) {
          for (const payload of DOM_XSS_PAYLOADS.slice(0, 4)) {
            let page = null;
            try {
              page = await browser.newPage();
              await page.setUserAgent(USER_AGENT);
              await page.setDefaultTimeout(PAGE_TIMEOUT);

              let dialogTriggered = false;
              let dialogMessage = "";

              page.on("dialog", async (dialog) => {
                const msg = dialog.message();
                if (msg.includes("DOMXSS") || msg === "1") {
                  dialogTriggered = true;
                  dialogMessage = msg;
                }
                await dialog.dismiss();
              });

              const testUrl = new URL(url);
              testUrl.searchParams.set(paramName, payload);

              await page.goto(testUrl.toString(), {
                waitUntil: "domcontentloaded",
                timeout: PAGE_TIMEOUT,
              }).catch(() => {});

              await new Promise(r => setTimeout(r, 1500));

              if (dialogTriggered) {
                findings.push({
                  type: "DOM XSS - Confirmed via Query Param",
                  location: testUrl.toString(),
                  evidence: `alert('${dialogMessage}') triggered via parameter "${paramName}"`,
                  confidence: "High",
                  payload,
                  source: `URL parameter: ${paramName}`,
                });
                break;
              }
            } catch {}
            finally {
              if (page && !page.isClosed()) await page.close().catch(() => {});
            }
          }
        }
      }
    } catch {}

  } catch (err) {
    console.error("[DOM XSS] Puppeteer error:", err.message);
    throw err;
  } finally {
    if (browser) {
      await browser.close().catch(() => {});
      console.log("[DOM XSS] Browser closed");
    }
  }

  return findings;
}

/**
 * Static analysis fallback — analyzes JS files without browser
 */
async function staticScan(url) {
  const findings = [];

  try {
    const response = await axios.get(url, {
      timeout: 20000,
      headers: { "User-Agent": USER_AGENT },
      validateStatus: () => true,
    });

    if (response.status !== 200) return findings;

    const html = response.data;
    const dom = new JSDOM(html, { url, runScripts: "outside-only" });

    // Inline scripts
    for (const script of dom.window.document.querySelectorAll("script:not([src])")) {
      const code = script.textContent || "";
      findings.push(...staticAnalyze(code, "Inline Script"));
    }

    // External scripts
    for (const script of dom.window.document.querySelectorAll("script[src]")) {
      const src = script.getAttribute("src");
      if (!src) continue;
      let resolvedUrl;
      try { resolvedUrl = new URL(src, url).toString(); } catch { continue; }
      if (isThirdParty(resolvedUrl)) continue;

      try {
        const res = await axios.get(resolvedUrl, { timeout: 10000, validateStatus: () => true });
        if (res.status === 200 && typeof res.data === "string") {
          findings.push(...staticAnalyze(res.data, resolvedUrl));
        }
      } catch {}
    }
  } catch {}

  return findings;
}

/**
 * Discovers linked pages from a page (same origin, shallow crawl)
 * Used to find subpages like /level1/frame that have actual XSS
 */
async function discoverLinkedPages(url) {
  const pages = new Set();
  try {
    const res = await axios.get(url, { timeout: 10000, validateStatus: () => true });
    if (res.status !== 200) return [];
    const dom = new JSDOM(res.data, { url });
    const base = new URL(url);

    // Collect <a href> links
    dom.window.document.querySelectorAll("a[href]").forEach(el => {
      try {
        const resolved = new URL(el.getAttribute("href"), url);
        if (resolved.origin === base.origin) {
          resolved.search = "";
          resolved.hash = "";
          pages.add(resolved.toString());
        }
      } catch {}
    });

    // Also collect <iframe src> — many XSS labs embed vulnerable pages in iframes
    dom.window.document.querySelectorAll("iframe[src]").forEach(el => {
      try {
        const resolved = new URL(el.getAttribute("src"), url);
        if (resolved.origin === base.origin) {
          pages.add(resolved.toString()); // Keep query/hash for iframes — they matter
        }
      } catch {}
    });

    // For each discovered page, also check its iframe sources (one level deep)
    const firstLevel = [...pages].slice(0, 6);
    for (const pageUrl of firstLevel) {
      try {
        const pageRes = await axios.get(pageUrl, { timeout: 8000, validateStatus: () => true });
        if (pageRes.status !== 200) continue;
        const pageDom = new JSDOM(pageRes.data, { url: pageUrl });
        pageDom.window.document.querySelectorAll("iframe[src]").forEach(el => {
          try {
            const resolved = new URL(el.getAttribute("src"), pageUrl);
            if (resolved.origin === base.origin) {
              pages.add(resolved.toString());
            }
          } catch {}
        });
      } catch {}
    }

  } catch {}

  const root = url.replace(/\/$/, "");
  return [...pages]
    .filter(p => p !== root && p !== root + "/")
    .slice(0, 6);
}

/**
 * Main DOM XSS scanner — tries Puppeteer first, falls back to static analysis
 * Also crawls linked pages to find vulnerable subpages
 */
async function scanDOMXSS(inputUrl) {
  const url = normalizeUrl(inputUrl);
  console.log(`[DOM XSS] Starting scan: ${url}`);

  let puppeteerFindings = [];
  let staticFindings = [];
  let puppeteerFailed = false;

  // Discover linked subpages to scan (e.g. /level1/frame, /app, /search)
  const linkedPages = await discoverLinkedPages(url);
  const allTargets = [url, ...linkedPages];
  console.log(`[DOM XSS] Will test ${allTargets.length} page(s): ${allTargets.join(", ")}`);

  // === PRIMARY: Puppeteer browser-based scan ===
  try {
    const timeoutPromise = new Promise((_, reject) =>
      setTimeout(() => reject(new Error("Puppeteer scan timeout")), SCAN_TIMEOUT)
    );
    // Run puppeteer on all discovered pages
    const allPuppeteerFindings = [];
    for (const target of allTargets) {
      if (allPuppeteerFindings.length >= 2) break; // Stop once we have confirmed findings
      const findings = await Promise.race([puppeteerScan(target), timeoutPromise]);
      allPuppeteerFindings.push(...findings);
    }
    puppeteerFindings = allPuppeteerFindings;
    console.log(`[DOM XSS] Puppeteer scan complete. Confirmed findings: ${puppeteerFindings.length}`);
  } catch (err) {
    console.warn(`[DOM XSS] Puppeteer scan failed: ${err.message}. Falling back to static analysis.`);
    puppeteerFailed = true;
  }

  // === FALLBACK: Static analysis (always runs to supplement) ===
  try {
    for (const target of allTargets.slice(0, 3)) { // Static scan top 3 pages
      const findings = await staticScan(target);
      staticFindings.push(...findings);
    }
    console.log(`[DOM XSS] Static analysis complete. Pattern findings: ${staticFindings.length}`);
  } catch (err) {
    console.warn(`[DOM XSS] Static scan error: ${err.message}`);
  }

  // Merge: confirmed Puppeteer findings take priority
  // Only include static findings if Puppeteer found nothing (or failed)
  let allFindings = [];

  if (puppeteerFindings.length > 0) {
    // Confirmed findings — only return these, ignore noisy static results
    allFindings = puppeteerFindings;
  } else if (puppeteerFailed && staticFindings.length > 0) {
    // Puppeteer unavailable — use static as fallback
    allFindings = staticFindings;
  } else {
    // Puppeteer ran but found nothing — still add static Low findings as informational
    allFindings = staticFindings.filter(f => f.confidence === "Medium" || f.confidence === "High");
  }

  // Deduplicate by base URL (strip payload from query to group same endpoint)
  const seen = new Set();
  const dedupedFindings = allFindings.filter(f => {
    try {
      const u = new URL(f.location);
      // Key = origin + pathname (ignores the injected payload in params/hash)
      const key = u.origin + u.pathname;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    } catch {
      return !seen.has(f.location) && seen.add(f.location);
    }
  });
  allFindings = dedupedFindings;

  const vulnerable = allFindings.length > 0;

  return {
    module: "DOM-Based XSS",
    target: url,
    vulnerable,
    evidence: vulnerable
      ? allFindings.map(f => ({
          type: f.type,
          location: f.location,
          evidence: f.evidence,
          confidence: f.confidence,
          sources: f.sources || [],
          sinks: f.sinks || [],
          payload: f.payload || null,
        }))
      : "No DOM-based XSS vulnerabilities detected",
    notes: vulnerable
      ? puppeteerFindings.length > 0
        ? "DOM XSS confirmed via real browser execution — these are verified vulnerabilities, not just patterns."
        : "DOM XSS patterns detected via static analysis. Browser-based verification recommended."
      : "No DOM-based XSS vulnerabilities detected.",
    scanMethod: puppeteerFailed ? "static-analysis" : "browser+static",
  };
}

module.exports = { scanDOMXSS };