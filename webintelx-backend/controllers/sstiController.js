const { scanSSTI } = require("../utils/sstiCheck");

exports.scanSSTI = async (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({
      success: false,
      error: "URL is required",
    });
  }

  try {
    console.log(`SSTI scan requested for: ${url}`);
    const result = await scanSSTI(url);

    console.log(`SSTI scan completed. Vulnerable: ${result.vulnerable}`);

    return res.json(result);
  } catch (err) {
    console.error("SSTI Scan Error:", err);
    return res.status(500).json({
      module: "Server-Side Template Injection",
      target: url || "unknown",
      vulnerable: false,
      evidence: "Scan failed due to error",
      notes: `Error: ${err.message}`,
    });
  }
};
