/**
 * Command Injection Detection Module
 * FullScan-only active vulnerability scanner
 * Includes recursive endpoint crawling with depth control
 */

const axios = require("axios");
const cheerio = require("cheerio");
const { URL } = require("url");
const qs = require("qs");

const USER_AGENT = "WebIntelX-CommandInjection-Scanner/1.2";
const TIMEOUT = 40000;

/* =========================
   CONFIG
========================= */

const CRAWL_DEPTH = 2;              // FullScan depth
const MAX_ENDPOINTS = 25;           // Safety cap

const COMMON_GUESS_ENDPOINTS = [
  "/command",
  "/exec",
  "/run",
  "/shell",
  "/api/command",
  "/api/exec",
];

/* =========================
   PAYLOADS & MARKERS
========================= */

const COMMAND_PAYLOADS = [
  "; echo COMMAND_INJECTION_TEST",
  "&& echo COMMAND_INJECTION_TEST",
  "| echo COMMAND_INJECTION_TEST",
  "`echo COMMAND_INJECTION_TEST`",
  "$(echo COMMAND_INJECTION_TEST)",
  "; id",
  "&& id",
  "| id",
  "; whoami",
  "&& whoami",
];

const STRONG_MARKERS = [
  "command_injection_test",
  "uid=",
  "gid=",
];

const WEAK_MARKERS = [
  "whoami",
];

/* =========================
   HELPER FUNCTIONS
========================= */

function detectMarkers(responseText) {
  for (const marker of STRONG_MARKERS) {
    if (responseText.includes(marker)) {
      return { hit: true, confidence: "high", marker };
    }
  }
  for (const marker of WEAK_MARKERS) {
    if (responseText.includes(marker)) {
      return { hit: true, confidence: "medium", marker };
    }
  }
  return { hit: false };
}

function normalizeUrl(input) {
  if (!input.startsWith("http://") && !input.startsWith("https://")) {
    return "http://" + input;
  }
  return input;
}

function buildTestUrl(originalUrl, targetParam, payload) {
  const testUrl = new URL(originalUrl);
  for (const [key, value] of testUrl.searchParams.entries()) {
    testUrl.searchParams.set(
      key,
      key === targetParam ? payload : value
    );
  }
  return testUrl.toString();
}

function guessEndpoints(baseUrl) {
  const guessed = [];
  const base = new URL(baseUrl);

  for (const path of COMMON_GUESS_ENDPOINTS) {
    try {
      const guessedUrl = new URL(path, base.origin).toString();
      guessed.push(guessedUrl);
    } catch {}
  }

  return guessed;
}

/* =========================
   RECURSIVE CRAWLER
========================= */

async function crawlEndpoints(startUrl, maxDepth = 2) {
  const visited = new Set();
  const endpoints = new Set();
  const baseOrigin = new URL(startUrl).origin;

  async function crawl(url, depth) {
    if (depth > maxDepth) return;
    if (visited.has(url)) return;
    if (endpoints.size >= MAX_ENDPOINTS) return;

    visited.add(url);

    let response;
    try {
      response = await axios.get(url, {
        timeout: TIMEOUT,
        headers: { "User-Agent": USER_AGENT },
        validateStatus: () => true,
      });
    } catch {
      return;
    }

    const contentType = response.headers["content-type"] || "";
    if (!contentType.includes("text/html")) return;

    const $ = cheerio.load(response.data);

    $("a[href]").each((_, el) => {
      try {
        const resolved = new URL($(el).attr("href"), url);
        if (resolved.origin === baseOrigin) {
          const clean = resolved.origin + resolved.pathname;
          if (!endpoints.has(clean)) {
            endpoints.add(clean);
            crawl(resolved.toString(), depth + 1);
          }
        }
      } catch {}
    });

    $("form[action]").each((_, el) => {
      try {
        const resolved = new URL($(el).attr("action"), url);
        if (resolved.origin === baseOrigin) {
          endpoints.add(resolved.origin + resolved.pathname);
        }
      } catch {}
    });
  }

  await crawl(startUrl, 0);
  console.log("[Crawler] Discovered endpoints:", Array.from(endpoints));

  return Array.from(endpoints);
}

/* =========================
   GET & POST TESTING
========================= */

async function testCommandInjection(targetUrl, paramName, payload) {
  try {
    const testUrl = buildTestUrl(targetUrl, paramName, payload);

    const response = await axios.get(testUrl, {
      timeout: TIMEOUT,
      headers: { "User-Agent": USER_AGENT },
      validateStatus: () => true,
    });

    const body = String(response.data || "").toLowerCase();
    const marker = detectMarkers(body);

    if (marker.hit) {
      return {
        vulnerable: true,
        confidence: marker.confidence,
        payload,
        parameter: paramName,
        evidence: `Execution marker detected: ${marker.marker}`,
      };
    }
    return { vulnerable: false };
  } catch {
    return { vulnerable: false };
  }
}

async function testPostCommandInjection(targetUrl, paramName, payload) {
  try {
    const response = await axios.post(
      targetUrl,
      qs.stringify({ [paramName]: payload }),
      {
        timeout: TIMEOUT,
        headers: {
          "User-Agent": USER_AGENT,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        validateStatus: () => true,
      }
    );

    const body = String(response.data || "").toLowerCase();
    const marker = detectMarkers(body);

    if (marker.hit) {
      return {
        vulnerable: true,
        confidence: marker.confidence,
        payload,
        parameter: paramName,
        evidence: `Execution marker detected: ${marker.marker}`,
      };
    }
    return { vulnerable: false };
  } catch {
    return { vulnerable: false };
  }
}

/* =========================
   FORM & PARAM EXTRACTION
========================= */

function extractFormsAndParams(html, baseUrl) {
  const forms = [];
  const params = new Set();
  const $ = cheerio.load(html);

  $("form").each((_, form) => {
    const action = $(form).attr("action") || baseUrl;
    const method = ($(form).attr("method") || "get").toLowerCase();
    const formUrl = new URL(action, baseUrl).toString();

    const fields = {};
    $(form).find("input, textarea, select").each((_, field) => {
      const name = $(field).attr("name");
      const type = $(field).attr("type") || "text";
      if (name && !["submit", "button", "hidden"].includes(type)) {
        fields[name] = "test";
        params.add(name);
      }
    });

    if (Object.keys(fields).length) {
      forms.push({ url: formUrl, method, fields });
    }
  });

  return { forms, params: Array.from(params) };
}

/* =========================
   MAIN SCAN FUNCTION
========================= */

async function scanCommandInjection(inputUrl) {
  const normalizedUrl = normalizeUrl(inputUrl);
  const findings = [];

  // 1️⃣ Discover endpoints recursively
  let endpoints = await crawlEndpoints(normalizedUrl, CRAWL_DEPTH);

  // If crawler finds very few endpoints, enable guessing (FullScan only)
  if (endpoints.length < 3) {
    const guessed = guessEndpoints(normalizedUrl);
    endpoints = Array.from(new Set([...endpoints, ...guessed]));
  }

  // Always include original URL
  endpoints.unshift(normalizedUrl);

  for (const endpoint of endpoints) {
    let response;
    try {
      response = await axios.get(endpoint, {
        timeout: TIMEOUT,
        headers: { "User-Agent": USER_AGENT },
        validateStatus: () => true,
      });
    } catch {
      continue;
    }

    const contentType = response.headers["content-type"] || "";
    if (!contentType.includes("text/html")) continue;

    const { params, forms } = extractFormsAndParams(response.data, endpoint);
    const urlObj = new URL(endpoint);

    /* Existing query params */
    for (const [param] of urlObj.searchParams.entries()) {
      for (const payload of COMMAND_PAYLOADS.slice(0, 5)) {
        const res = await testCommandInjection(endpoint, param, payload);
        if (res.vulnerable) return buildResult(normalizedUrl, res);
      }
    }

    /* Discovered GET params */
    for (const param of params.slice(0, 5)) {
      const testUrl = new URL(endpoint);
      testUrl.searchParams.set(param, "test");
      for (const payload of COMMAND_PAYLOADS.slice(0, 5)) {
        const res = await testCommandInjection(testUrl.toString(), param, payload);
        if (res.vulnerable) return buildResult(normalizedUrl, res);
      }
    }

    /* POST forms */
    for (const form of forms) {
      if (form.method !== "post") continue;
      for (const param of Object.keys(form.fields).slice(0, 3)) {
        for (const payload of COMMAND_PAYLOADS.slice(0, 5)) {
          const res = await testPostCommandInjection(form.url, param, payload);
          if (res.vulnerable) return buildResult(normalizedUrl, res);
        }
      }
    }
  }

  return {
    module: "Command Injection",
    target: normalizedUrl,
    vulnerable: false,
    confidence: "none",
    evidence: [],
    notes: "No command injection vulnerabilities detected in tested endpoints.",
  };
}

/* =========================
   RESULT BUILDER
========================= */

function buildResult(target, finding) {
  return {
    module: "Command Injection",
    target,
    vulnerable: true,
    confidence: finding.confidence,
    evidence: [finding],
    notes: "Command injection vulnerability confirmed. User input reaches system command execution.",
  };
}

module.exports = { scanCommandInjection };
