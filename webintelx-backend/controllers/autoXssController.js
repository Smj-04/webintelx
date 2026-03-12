//this is the autoXssController.js file in the controllers folder

const cleanUrl = require("../utils/cleanUrl");
const { discoverEndpoints } = require("../utils/endpointDiscovery");
const endpointScan = require("../utils/endpointScanner");
const { scanXSS } = require("../utils/xssScanner");

const XSS_PARAMS = ["q", "search", "s", "id", "page", "test"];
const MAX_TESTS = 50;

// Pages that are known false positives or irrelevant for XSS
const FALSE_POSITIVE_PATHS = [
  /phpinfo/i, /phpmyadmin/i, /adminer/i,
  /logout/i,  /setup/i,     /install/i,
  /about/i,   /readme/i,    /license/i,
  /\.css$/i,  /\.js$/i,     /\.png$/i,
  /\.jpg$/i,  /\.gif$/i,    /\.ico$/i,
];

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

      // skip known false-positive pages
      if (FALSE_POSITIVE_PATHS.some(p => p.test(testUrl))) continue;

      testedEndpoints++;

      try {
        const findings = await scanXSS(testUrl);

        // Only care about High confidence findings — Low = likely safe (encoded chars)
        const highFindings = findings.filter(f => f.confidence === "High");

        if (highFindings.length > 0) {
          // Group by base URL (strip payload) + param to avoid duplicates
          for (const finding of highFindings) {
            const actualUrl = finding.url || testUrl;

            // Build a clean dedup key: base path + param name only
            let dedupKey;
            try {
              const u = new URL(actualUrl);
              dedupKey = `${u.origin}${u.pathname}::${finding.parameter}`;
            } catch {
              dedupKey = `${actualUrl}::${finding.parameter}`;
            }

            // Skip if we already reported this endpoint+param combo
            const alreadyReported = vulnerableEndpoints.some(e => e._dedupKey === dedupKey);
            if (alreadyReported) continue;

            vulnerableEndpoints.push({
              url: actualUrl,
              param: finding.parameter,
              payload: finding.payload,
              confidence: finding.confidence,
              evidence: finding.evidence,
              findings: [finding],
              _dedupKey: dedupKey,
            });
          }
        }
      } catch {}
    }

    // Strip internal dedup key before sending to frontend
    const cleanEndpoints = vulnerableEndpoints.map(({ _dedupKey, ...rest }) => rest);

    return res.json({
      success: true,
      base,
      testedEndpoints,
      vulnerableEndpoints: cleanEndpoints,
    });
  } catch (err) {
    console.error("Auto XSS Scan Error:", err);
    return res.status(500).json({
      success: false,
      error: "Auto XSS scan failed",
    });
  }
};
