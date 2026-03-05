// utils/csrf/csrfScanner.js

const enumerateEndpoints = require("./endpointEnum");
const testCSRF = require("./csrfTester");
const classifyRisk = require("./riskClassifier");

async function runCSRFScan(targetUrl) {
  if (!targetUrl) {
    throw new Error("Base URL is required");
  }

  const endpoints = await enumerateEndpoints(targetUrl);

  const vulnerable = [];
  const safe = [];

  for (const ep of endpoints) {
    const test = await testCSRF(ep);
    const risk = classifyRisk(ep);

    const result = {
      endpoint: ep.url,
      method: ep.method,
      status: test.status,
      confidence: test.confidence,
      risk
    };

    if (test.status === "VULNERABLE") {
      vulnerable.push(result);
    } else {
      safe.push(result);
    }
  }

  return {
    module: "csrf",
    target: targetUrl,
    summary: {
      totalEndpoints: endpoints.length,
      vulnerable: vulnerable.length,
      safe: safe.length
    },
    vulnerableEndpoints: vulnerable,
    safeEndpoints: safe
  };
}

module.exports = { runCSRFScan };

