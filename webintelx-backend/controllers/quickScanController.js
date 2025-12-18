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

  const target = cleanUrl(url);

  try {
    // ✅ Run all scans safely
    const results = await Promise.allSettled([
      scanner.nslookup(target),
      scanner.ping(target),
      scanner.headers(target),
      scanner.portScan(target),
      scanner.ssl(target),
      scanner.whatweb(target),
    ]);

    // ✅ Helper: return value OR error string
    const safe = (r) =>
      r.status === "fulfilled"
        ? r.value
        : `Scan failed: ${r.reason}`;

    const output = {
      dns: safe(results[0]),
      ping: safe(results[1]),
      headers: safe(results[2]),
      openPorts: safe(results[3]),
      ssl: safe(results[4]),
      whatweb: safe(results[5]),
    };

    return res.json({
      success: true,
      message: "Quick scan completed (partial results possible)",
      data: output,
    });
  } catch (err) {
    console.error("QuickScan Fatal Error:", err);
    return res.status(500).json({
      success: false,
      error: "Quick Scan crashed",
    });
  }
};
