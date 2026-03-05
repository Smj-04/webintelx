//this is the autoXssController.js file in the controllers folder

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
      : `http://${inputUrl}`;

    const endpoints = new Set();

    // 1️⃣ Seed endpoints
    endpoints.add(baseUrl);
    endpoints.add(`${baseUrl}/search.php`);
    endpoints.add(`${baseUrl}/index.php`);

  // 2️⃣ Crawl — adds URLs (some may have params already)
      try {
        const discovered = await discoverEndpoints(baseUrl, 1);
        discovered.forEach((e) => endpoints.add(e));
      } catch {}

      // 3️⃣ Common endpoints — endpointScanner returns [{ url, param }]
      // Extract the full URLs (which already include ?param=1)
      try {
        const epResults = await endpointScan(baseUrl);
        // epResults is a flat array of { url, param } — just grab the url directly
        epResults.forEach((e) => {
          if (e && e.url) endpoints.add(e.url);
        });
      } catch {}

      // 4️⃣ Generate test URLs
      // URLs from endpointScanner already have params (e.g. listproducts.php?cat=1)
      // URLs from endpointDiscovery may or may not — fall back to XSS_PARAMS for those
      const testUrls = [];
      for (const ep of endpoints) {
        try {
          const epUrl = new URL(ep);
          if (epUrl.searchParams.toString()) {
            // Already has real params — use directly
            testUrls.push(ep);
          } else {
            // No params found — try common XSS param names as fallback
            for (const param of XSS_PARAMS) {
              testUrls.push(`${ep}?${param}=test`);
            }
          }
        } catch {
          for (const param of XSS_PARAMS) {
            testUrls.push(`${ep}?${param}=test`);
          }
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
          // Use the actual vulnerable URL from findings, not the test URL
          // Group findings by their actual submit URL
          const byActualUrl = {};
          for (const finding of findings) {
            const actualUrl = finding.url || testUrl;
            if (!byActualUrl[actualUrl]) {
              byActualUrl[actualUrl] = [];
            }
            byActualUrl[actualUrl].push(finding);
          }

          for (const [actualUrl, urlFindings] of Object.entries(byActualUrl)) {
            // Check if this actual URL was already reported
            const alreadyReported = vulnerableEndpoints.some(e => e.url === actualUrl);
            if (!alreadyReported) {
              vulnerableEndpoints.push({
                url: actualUrl,
                findings: urlFindings,
              });
            }
          }
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
