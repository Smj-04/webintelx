const cleanUrl = require("../utils/cleanUrl");
const sensitiveFileCheck = require("../utils/sensitiveFileCheck");

exports.scanSensitiveFiles = async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: "URL required" });

  const baseUrl = cleanUrl(url);

  try {
    const result = await sensitiveFileCheck(baseUrl);
    return res.json(result);
  } catch (err) {
    console.error("Sensitive file scan error:", err);
    return res.status(500).json({ error: "Sensitive file scan failed", details: err.message });
  }
};