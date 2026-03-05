/**
 * WebIntelX – Lightweight XSS Scanner
 * Scope: Reflected XSS + Basic DOM XSS
 */

const axios = require("axios");
const cheerio = require("cheerio");
const { URL } = require("url");
const qs = require("querystring")

// ---- CONFIG ----
const USER_AGENT = "WebIntelX-XSS-Scanner/1.0";
const TIMEOUT = 10000;

// Phase 1: alphanumeric marker — cannot be HTML-encoded, confirms reflection
const REFLECTION_MARKER = "xss9probe9marker";

// Phase 2: if marker reflects, test if these characters survive unencoded
const BREAK_PAYLOADS = [
  { chars: "<>",          payload: `<img src=x onerror=alert('${REFLECTION_MARKER}')>` },
  { chars: "\"",          payload: `"><img src=x onerror=alert('${REFLECTION_MARKER}')>` },
  { chars: "'",           payload: `'><svg onload=alert('${REFLECTION_MARKER}')>` },
  { chars: "javascript:", payload: `javascript:alert('${REFLECTION_MARKER}')` },
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

function isEncoded(body, chars) {
  const encodingMap = { "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#x27;" };
  return chars.split("").every(c => {
    const encoded = encodingMap[c];
    return encoded ? body.includes(encoded) : false;
  });
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

    const basePageUrl = targetUrl.split("?")[0];

    // Step 0: fetch the page and extract real form field names
    let formParams = [];
    try {
      const pageRes = await httpGet(basePageUrl);
      if (pageRes.data) {
        const $ = cheerio.load(pageRes.data);
        $("form").each((_, form) => {
          $(form).find("input[name], textarea[name], select[name]").each((_, field) => {
            const name = $(field).attr("name");
            const type = $(field).attr("type") || "text";
            if (name && type !== "submit" && type !== "button" && type !== "hidden") {
              formParams.push(name);
            }
          });
        });
      }
    } catch {}

    // Build a combined param list: URL params first, then form params, deduped
    const urlParams = [];
    if (targetUrl.includes("?")) {
      try {
        const u = new URL(targetUrl);
        for (const [key] of u.searchParams.entries()) {
          urlParams.push(key);
        }
      } catch {}
    }

    const allParams = [...new Set([...urlParams, ...formParams])];

    if (allParams.length === 0) return findings;



    // For each param, build the test URL using basePageUrl
    for (const key of allParams) {
      // Phase 1: probe with alphanumeric marker — confirms reflection
      const probeUrl = new URL(basePageUrl);
      probeUrl.searchParams.set(key, REFLECTION_MARKER);

      let probeRes;
      try {
        probeRes = await httpGet(probeUrl.toString());
      } catch {
        continue;
      }

      const probeBody = typeof probeRes.data === "string"
        ? probeRes.data
        : JSON.stringify(probeRes.data || "");

      if (!probeBody.includes(REFLECTION_MARKER)) {
        continue; // Param doesn't reflect — skip
      }

      console.log(`[XSS] Parameter "${key}" reflects input — testing payloads...`);




      // Phase 2: test if dangerous chars survive unencoded
      for (const { chars, payload } of BREAK_PAYLOADS) {
        const testUrl = new URL(basePageUrl);
        testUrl.searchParams.set(key, payload);

        let res;
        try {
          res = await httpGet(testUrl.toString());
        } catch {
          continue;
        }

        const body = typeof res.data === "string"
          ? res.data
          : JSON.stringify(res.data || "");

        if (!body.includes(REFLECTION_MARKER)) continue;

        const encoded = isEncoded(body, chars);

        findings.push({
          type: "Reflected XSS",
          parameter: key,
          payload,
          url: testUrl.toString(),
          evidence: encoded
            ? `Marker reflected but special chars (${chars}) are HTML-encoded — likely safe`
            : `Payload reflected without encoding — characters (${chars}) appear raw in response`,
          confidence: encoded ? "Low" : "High",
        });

        if (!encoded) break;
      }
    }

    return findings;
  }


  // ---- POST FORM XSS ----

async function scanFormXSS(pageUrl, testedFormFields) {
  const findings = [];
  let pageRes;
  try {
    pageRes = await httpGet(pageUrl);
  } catch {
    return findings;
  }

  if (!pageRes.data) return findings;

  const $ = cheerio.load(pageRes.data);

  for (const formEl of $("form").toArray()) {
    const $form = $(formEl);
    const action = $form.attr("action") || pageUrl;
    const method = ($form.attr("method") || "get").toLowerCase();

    // Build submit URL
    let submitUrl;
    try {
      submitUrl = new URL(action, pageUrl).toString();
    } catch {
      continue;
    }

    // Collect field names
    const fields = {};
    $form.find("input[name], textarea[name], select[name]").each((_, field) => {
      const name = $(field).attr("name");
      const type = $(field).attr("type") || "text";
      if (name && type !== "submit" && type !== "button" && type !== "hidden") {
        fields[name] = "test";
      }
    });

    if (Object.keys(fields).length === 0) continue;

    for (const fieldName of Object.keys(fields)) {
      // Skip if we already tested this exact form+field combination
      const comboKey = `${submitUrl}|${fieldName}`;
      if (testedFormFields.has(comboKey)) continue;
      testedFormFields.add(comboKey);

      // Phase 1: probe reflection with marker
      const probeData = { ...fields, [fieldName]: REFLECTION_MARKER };

      let probeRes;
      try {
        if (method === "post") {
         probeRes = await axios.post(submitUrl, qs.stringify(probeData), {
            timeout: TIMEOUT,
            headers: {
              "User-Agent": USER_AGENT,
              "Content-Type": "application/x-www-form-urlencoded",
            },
            validateStatus: () => true,
          });
        } else {
          const probeUrl = new URL(submitUrl);
          probeUrl.searchParams.set(fieldName, REFLECTION_MARKER);
          probeRes = await httpGet(probeUrl.toString());
        }
      } catch {
        continue;
      }

      const probeBody = typeof probeRes.data === "string"
        ? probeRes.data
        : JSON.stringify(probeRes.data || "");

      if (!probeBody.includes(REFLECTION_MARKER)) continue;

      console.log(`[XSS] Form field "${fieldName}" at ${submitUrl} reflects input — testing payloads...`);

      // Phase 2: test payloads
      for (const { chars, payload } of BREAK_PAYLOADS) {
        const payloadData = { ...fields, [fieldName]: payload };

        let res;
        try {
          if (method === "post") {
            res = await axios.post(submitUrl, qs.stringify(probeData), {
              timeout: TIMEOUT,
              headers: {
                "User-Agent": USER_AGENT,
                "Content-Type": "application/x-www-form-urlencoded",
              },
              validateStatus: () => true,
            });
          } else {
            const testUrl = new URL(submitUrl);
            testUrl.searchParams.set(fieldName, payload);
            res = await httpGet(testUrl.toString());
          }
        } catch {
          continue;
        }

        const body = typeof res.data === "string"
          ? res.data
          : JSON.stringify(res.data || "");

        if (!body.includes(REFLECTION_MARKER)) continue;

        const encoded = isEncoded(body, chars);

        findings.push({
          type: "Reflected XSS (Form)",
          parameter: fieldName,
          payload,
          url: submitUrl,
          evidence: encoded
            ? `Marker reflected but special chars (${chars}) are HTML-encoded`
            : `Payload reflected without encoding via ${method.toUpperCase()} form`,
          confidence: encoded ? "Low" : "High",
        });

        if (!encoded) break;
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


// ---- MAIN API (updated) ----
async function scanXSS(url) {
  const results = [];
  const basePageUrl = url.split("?")[0];
  const testedFormFields = new Set();
  results.push(...(await scanReflectedXSS(url)));    
  results.push(...(await scanFormXSS(basePageUrl, testedFormFields)));
  results.push(...(await scanDomXSS(basePageUrl)));   
  return results;
}

module.exports = { scanXSS };