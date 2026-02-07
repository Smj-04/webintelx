const { scanTokenAuth } = require("../utils/tokenAuthCheck");

exports.scanTokenAuth = async (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({
      success: false,
      error: "URL is required",
    });
  }

  try {
    console.log(`Token Authentication scan requested for: ${url}`);
    const result = await scanTokenAuth(url);

    console.log(`Token Authentication scan completed. Vulnerable: ${result.vulnerable}`);

    return res.json(result);
  } catch (err) {
    console.error("Token Authentication Scan Error:", err);
    return res.status(500).json({
      module: "Token Authentication",
      target: url || "unknown",
      vulnerable: false,
      evidence: "Scan failed due to error",
      notes: `Error: ${err.message}`,
    });
  }
};
