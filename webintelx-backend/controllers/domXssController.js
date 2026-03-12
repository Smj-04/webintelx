// This is the domXssController.js file in the controllers folder


const { scanDOMXSS } = require("../utils/domXssCheck");

exports.scanDOMXSS = async (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({
      success: false,
      error: "URL is required",
    });
  }

  try {
    console.log(`DOM-Based XSS scan requested for: ${url}`);

    const timeoutPromise = new Promise((_, reject) =>
      setTimeout(() => reject(new Error("DOM XSS scan exceeded 4 minute limit")), 240000)
    );

    const result = await Promise.race([scanDOMXSS(url), timeoutPromise]);

    console.log(`DOM-Based XSS scan completed. Vulnerable: ${result.vulnerable}`);

    return res.json(result);
  } catch (err) {
    console.error("DOM-Based XSS Scan Error:", err);
    return res.status(500).json({
      module: "DOM-Based XSS",
      target: url || "unknown",
      vulnerable: false,
      evidence: "Scan failed due to error",
      notes: `Error: ${err.message}`,
    });
  }
};
