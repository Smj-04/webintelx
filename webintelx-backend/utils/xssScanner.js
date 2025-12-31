/**
 * WebIntelX – Lightweight XSS Scanner
 * Scope: Reflected XSS + Basic DOM XSS
 * Use only with authorization
 */

const axios = require("axios");
const cheerio = require("cheerio");
const { URL } = require("url");

// ---- CONFIG ----
const USER_AGENT = "WebIntelX-XSS-Scanner/1.0";
const TIMEOUT = 10000;

// Non-executing payloads
const PAYLOADS = [
  "<xss_test>",
  "\"><xss_test>",
  "'><xss_test>",
];

// DOM detection patterns
const DOM_SINKS =
  /(innerHTML|outerHTML|document\.write|eval|setTimeout|setInterval)\s*\(/i;
const DOM_SOURCES =
  /(location\.search|location\.hash|document\.URL|document\.location)/i;

// ---- HELPERS ----
function isCandidate(url) {
  return url.includes("?");
}

function isEscaped(body, payload) {
  const escaped = payload
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#x27;");
  return body.includes(escaped);
}

async function httpGet(url) {
  return axios.get(url, {
    timeout: TIMEOUT,
    headers: { "User-Agent": USER_AGENT },
    validateStatus: () => true,
  });
}

// ---- REFLECTED XSS ----
async function scanReflectedXSS(targetUrl) {
  const findings = [];
  if (!isCandidate(targetUrl)) return findings;

  const u = new URL(targetUrl);

  for (const [key] of u.searchParams.entries()) {
    for (const payload of PAYLOADS) {
      const testUrl = new URL(targetUrl);
      testUrl.searchParams.set(key, payload);

      const res = await httpGet(testUrl.toString());
      const body = res.data || "";

      if (typeof body === "string" && body.includes(payload)) {
        findings.push({
          type: "Reflected XSS",
          parameter: key,
          payload,
          url: testUrl.toString(),
          confidence: isEscaped(body, payload) ? "Low" : "High",
        });
      }
    }
  }

  return findings;
}

// ---- DOM XSS (STATIC ANALYSIS) ----
async function scanDomXSS(pageUrl) {
  const findings = [];
  const res = await httpGet(pageUrl);
  if (!res.data) return findings;

  const $ = cheerio.load(res.data);

  $("script:not([src])").each((_, el) => {
    const code = $(el).html() || "";
    if (DOM_SINKS.test(code) && DOM_SOURCES.test(code)) {
      findings.push({
        type: "DOM XSS",
        location: "Inline Script",
        confidence: "Medium",
      });
    }
  });

  $("script[src]").each(async (_, el) => {
    try {
      const src = $(el).attr("src");
      if (!src) return;
      const jsUrl = new URL(src, pageUrl).toString();
      const jsRes = await httpGet(jsUrl);
      const code = jsRes.data || "";
      if (DOM_SINKS.test(code) && DOM_SOURCES.test(code)) {
        findings.push({
          type: "DOM XSS",
          location: jsUrl,
          confidence: "Medium",
        });
      }
    } catch {}
  });

  return findings;
}

// ---- MAIN API ----
async function scanXSS(url) {
  const results = [];
  results.push(...(await scanReflectedXSS(url)));
  results.push(...(await scanDomXSS(url.split("?")[0])));
  return results;
}

module.exports = { scanXSS };
