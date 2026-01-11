const cleanUrl = require("../utils/cleanUrl");
const endpointScanner = require("../utils/endpointScanner");
const axios = require("axios");

exports.fullScan = async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: "URL required" });

  const baseUrl = cleanUrl(url);
  const endpoints = await endpointScanner(baseUrl);

  for (const target of endpoints) {
    console.log(`🧪 Testing: ${target.url}`);

    try {
      const result = await axios.post(
        "http://localhost:5000/api/sqlmap",
        {
          url: target.url,
          param: target.param
        },
        {
          timeout: 35000 // Slightly longer than SQLMap timeout (30s) to account for network overhead
        }
      );

      if (result.data && result.data.vulnerable) {
        console.log("🔥 SQL Injection FOUND:", target.url);

        return res.json({
          success: true,
          vulnerable: true,
          endpoint: target.url,
          parameter: target.param,
          databases: result.data.databases || []
        });
      }
    } catch (err) {
      // Handle timeout and other errors gracefully
      if (err.code === 'ECONNABORTED') {
        console.error("⏱️ Timeout scanning:", target.url);
      } else if (err.response) {
        // HTTP error response (4xx, 5xx)
        console.error("❌ HTTP error scanning:", target.url, err.response.status);
      } else {
        console.error("❌ Error scanning:", target.url, err.message);
      }
      // Continue to next endpoint
    }
  }

  return res.json({
    success: true,
    vulnerable: false,
    message: "No SQL Injection found"
  });
};
