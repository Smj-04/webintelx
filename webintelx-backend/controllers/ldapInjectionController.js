const { scanLDAPInjection } = require("../utils/ldapInjectionCheck");

exports.scanLDAPInjection = async (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({
      success: false,
      error: "URL is required",
    });
  }

  try {
    console.log(`LDAP Injection scan requested for: ${url}`);
    const result = await scanLDAPInjection(url);

    console.log(`LDAP Injection scan completed. Vulnerable: ${result.vulnerable}`);

    return res.json(result);
  } catch (err) {
    console.error("LDAP Injection Scan Error:", err);
    return res.status(500).json({
      module: "LDAP Injection",
      target: url || "unknown",
      vulnerable: false,
      evidence: "Scan failed due to error",
      notes: `Error: ${err.message}`,
    });
  }
};
