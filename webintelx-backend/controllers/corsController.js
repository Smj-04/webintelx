const { scanCORS } = require("../utils/corsCheck");

async function corsScan(req, res) {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: "URL is required" });

  console.log(`CORS scan requested for: ${url}`);
  try {
    const result = await scanCORS(url);
    return res.json(result);
  } catch (err) {
    console.error("[CORS] Controller error:", err.message);
    return res.status(500).json({ error: "CORS scan failed", details: err.message });
  }
}

module.exports = { corsScan };