const scanner = require("../utils/scanner");
const cleanUrl = require("../utils/cleanUrl");

exports.whatwebScan = async (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({
      success: false,
      error: "URL is required",
    });
  }

  const target = cleanUrl(url);

  try {
    const result = await scanner.whatweb(target);

    return res.json({
      success: true,
      message: "WhatWeb scan completed",
      data: result,
    });
  } catch (err) {
    console.error("WhatWeb Error:", err);
    return res.status(500).json({
      success: false,
      error: "WhatWeb scan failed",
    });
  }
};
