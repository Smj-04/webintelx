const scanner = require("../utils/scanner");

exports.runXSSScan = async (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({
      success: false,
      error: "URL is required",
    });
  }

  try {
    // ❗ DO NOT clean URL for XSS (query params required)
    const result = await scanner.xssScan(url);

    return res.json({
      success: true,
      message: "XSS scan completed",
      data: result,
    });
  } catch (err) {
    console.error("XSS Scan Error:", err);
    return res.status(500).json({
      success: false,
      error: "XSS scan failed",
    });
  }
};
