const clickjackingCheck = require("../utils/clickjackingCheck");

exports.checkClickjacking = async (req, res) => {
    console.log("🔥 clickjackingController HIT");

    
  const { url } = req.body;

  if (!url || typeof url !== "string") {
    return res.status(400).json({ error: "URL required" });
  }

  // ✅ SAFE URL NORMALIZATION
  let target;
  try {
    target = new URL(url).href;
  } catch (err) {
    return res.status(400).json({ error: "Invalid URL format" });
  }

  const result = await clickjackingCheck(target);

  return res.json({
    module: "Clickjacking",
    url: target,
    ...result
  });
};
