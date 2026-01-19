const { scanDOMXSS } = require("../utils/domXssCheck");

exports.scanDOMXSS = async (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({
      success: false,
      error: "URL is required",
    });
  }

  try {
    console.log(`DOM-Based XSS scan requested for: ${url}`);
    const result = await scanDOMXSS(url);

    console.log(`DOM-Based XSS scan completed. Vulnerable: ${result.vulnerable}`);

    return res.json(result);
  } catch (err) {
    console.error("DOM-Based XSS Scan Error:", err);
    return res.status(500).json({
      module: "DOM-Based XSS",
      target: url || "unknown",
      vulnerable: false,
      evidence: "Scan failed due to error",
      notes: `Error: ${err.message}`,
    });
  }
};
