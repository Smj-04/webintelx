const { scanIDOR } = require("../utils/idorCheck");

exports.scanIDOR = async (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({
      success: false,
      error: "URL is required",
    });
  }

  try {
    console.log(`IDOR scan requested for: ${url}`);
    const result = await scanIDOR(url);

    console.log(`IDOR scan completed. Vulnerable: ${result.vulnerable}`);

    return res.json(result);
  } catch (err) {
    console.error("IDOR Scan Error:", err);
    return res.status(500).json({
      module: "IDOR",
      target: url || "unknown",
      vulnerable: false,
      evidence: "Scan failed due to error",
      notes: `Error: ${err.message}`,
    });
  }
};
