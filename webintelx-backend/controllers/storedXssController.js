const { scanStoredXSS } = require("../utils/storedXssCheck");

exports.scanStoredXSS = async (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({
      success: false,
      error: "URL is required",
    });
  }

  try {
    console.log(`Stored XSS scan requested for: ${url}`);
    const result = await scanStoredXSS(url);

    console.log(`Stored XSS scan completed. Vulnerable: ${result.vulnerable}`);

    return res.json(result);
  } catch (err) {
    console.error("Stored XSS Scan Error:", err);
    return res.status(500).json({
      module: "Stored XSS",
      target: url || "unknown",
      vulnerable: false,
      evidence: "Scan failed due to error",
      notes: `Error: ${err.message}`,
    });
  }
};
