const { scanOpenRedirect } = require("../utils/openRedirectCheck");

async function openRedirectScan(req, res) {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: "URL is required" });

  console.log(`Open Redirect scan requested for: ${url}`);
  try {
    const result = await scanOpenRedirect(url);
    return res.json(result);
  } catch (err) {
    console.error("[OpenRedirect] Controller error:", err.message);
    return res.status(500).json({ error: "Open Redirect scan failed", details: err.message });
  }
}

module.exports = { openRedirectScan };