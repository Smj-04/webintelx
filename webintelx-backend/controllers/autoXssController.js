const cleanUrl = require("../utils/cleanUrl");
const { discoverEndpoints } = require("../utils/endpointDiscovery");
const endpointScan = require("../utils/endpointScanner");
const { scanXSS } = require("../utils/xssScanner");

const XSS_PARAMS = ["q", "search", "s", "id", "page", "test"];
const MAX_TESTS = 50;

exports.runAutoXSSScan = async (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({
      success: false,
      error: "URL is required",
    });
  }

  try {
    const inputUrl = url.trim();
    const base = cleanUrl(inputUrl);

    const baseUrl = inputUrl.startsWith("http")
      ? inputUrl
      : `http://${base}`;

    const endpoints = new Set();

    // 1️⃣ Seed endpoints
    endpoints.add(baseUrl);
    endpoints.add(`${baseUrl}/search.php`);
    endpoints.add(`${baseUrl}/index.php`);

    // 2️⃣ Crawl
    try {
      const discovered = await discoverEndpoints(baseUrl, 1);
      discovered.forEach((e) => endpoints.add(e));
    } catch {}

    // 3️⃣ Common endpoints
    try {
      const epResult = await endpointScan(baseUrl);
      epResult.discoveredEndpoints.forEach((e) => {
        endpoints.add(baseUrl + e.endpoint);
      });
    } catch {}

    // 4️⃣ Generate test URLs
    const testUrls = [];
    for (const ep of endpoints) {
      for (const param of XSS_PARAMS) {
        testUrls.push(`${ep}?${param}=xss_test`);
      }
    }

    // 5️⃣ Scan
    const vulnerableEndpoints = [];
    let testedEndpoints = 0;

    for (const testUrl of testUrls) {
      if (testedEndpoints >= MAX_TESTS) break;

      // skip non-html endpoints
      if (!testUrl.match(/\.(php|html|htm|asp|aspx|jsp)?(\?|$)/i)) continue;

      testedEndpoints++;

      try {
        const findings = await scanXSS(testUrl);
        if (findings.length > 0) {
          vulnerableEndpoints.push({
            url: testUrl,
            findings,
          });
        }
      } catch {}
    }

    return res.json({
      success: true,
      base,
      testedEndpoints,
      vulnerableEndpoints,
    });
  } catch (err) {
    console.error("Auto XSS Scan Error:", err);
    return res.status(500).json({
      success: false,
      error: "Auto XSS scan failed",
    });
  }
};
