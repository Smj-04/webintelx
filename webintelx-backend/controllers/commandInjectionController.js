const { scanCommandInjection } = require("../utils/commandInjectionCheck");

exports.scanCommandInjection = async (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({
      success: false,
      error: "URL is required",
    });
  }

  try {
    console.log(`Command Injection scan requested for: ${url}`);
    const result = await scanCommandInjection(url);

    console.log(`Command Injection scan completed. Vulnerable: ${result.vulnerable}`);

    return res.json(result);
  } catch (err) {
    console.error("Command Injection Scan Error:", err);
    return res.status(500).json({
      module: "Command Injection",
      target: url || "unknown",
      vulnerable: false,
      evidence: "Scan failed due to error",
      notes: `Error: ${err.message}`,
    });
  }
};
