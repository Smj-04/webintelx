const scanner = require("../utils/scanner");
const cleanUrl = require("../utils/cleanUrl");

exports.quickScan = async (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({
      success: false,
      error: "URL is required",
    });
  }

  const target = cleanUrl(url); // ✔ FIXED

  try {
    const [dnsResult, pingResult, headersResult, portResult, sslResult] =
      await Promise.all([
        scanner.nslookup(target),
        scanner.ping(target),
        scanner.headers(target),
        scanner.portScan(target),
        scanner.ssl(target),
      ]);

    const output = {
      dns: dnsResult,
      ping: pingResult,
      headers: headersResult,
      openPorts: portResult,
      ssl: sslResult,
    };

    return res.json({
      success: true,
      message: "Quick scan completed successfully",
      data: output,
    });
  } catch (err) {
    console.error("QuickScan Error:", err);
    return res.status(500).json({
      success: false,
      error: "Quick Scan failed: " + err.toString(),
    });
  }
};
