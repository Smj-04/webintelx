const { scanCSRFToken } = require("../utils/csrfTokenCheck");

exports.scanCSRFToken = async (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({
      success: false,
      error: "URL is required",
    });
  }

  try {
    console.log(`CSRF Token scan requested for: ${url}`);
    const result = await scanCSRFToken(url);

    console.log(`CSRF Token scan completed. Vulnerable: ${result.vulnerable}`);

    return res.json(result);
  } catch (err) {
    console.error("CSRF Token Scan Error:", err);
    return res.status(500).json({
      module: "CSRF Token",
      target: url || "unknown",
      vulnerable: false,
      evidence: "Scan failed due to error",
      notes: `Error: ${err.message}`,
    });
  }
};
