// ✅ IMPORT REQUIRED SERVICES
const enumerateEndpoints = require("../utils/endpointEnum");
const testCSRF = require("../utils/csrfTester");
const classifyRisk = require("../utils/riskClassifier");

exports.scanCSRF = async (req, res) => {
  try {
    const { url } = req.body;

    if (!url) {
      return res.status(400).json({ error: "Base URL is required" });
    }

    // 🔍 Crawl site & enumerate endpoints
    const endpoints = await enumerateEndpoints(url);

    const vulnerable = [];
    const safe = [];

    // 🧪 Test each endpoint
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

    // 📊 Final response
    res.json({
      target: url,
      summary: {
        totalEndpoints: endpoints.length,
        vulnerable: vulnerable.length,
        safe: safe.length
      },
      vulnerableEndpoints: vulnerable,
      safeEndpoints: safe
    });

  } catch (err) {
    console.error("CSRF scan error:", err.message);
    res.status(500).json({ error: "CSRF scan failed" });
  }
};

