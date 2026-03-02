const { scanIDOR } = require("../utils/idorCheck");

exports.scanIDOR = async (req, res) => {
  const { url, options } = req.body;

  console.log("[DEBUG] Raw body received:", JSON.stringify(req.body, null, 2));

  // --- Input validation ---
  if (!url) {
    return res.status(400).json({
      success: false,
      error: "URL is required",
    });
  }

  const auth = options?.auth;

  if (!auth) {
    return res.status(400).json({
      success: false,
      error: "Authentication config is required for IDOR scanning",
      notes: "Provide options.auth with type, loginUrl, usernameField, passwordField, username, password",
    });
  }

  const requiredAuthFields = ["type", "loginUrl", "username", "password"];
  const missingFields = requiredAuthFields.filter((f) => !auth[f]);
  if (missingFields.length > 0) {
    return res.status(400).json({
      success: false,
      error: `Missing required auth fields: ${missingFields.join(", ")}`,
    });
  }

  if (!["form", "json"].includes(auth.type)) {
    return res.status(400).json({
      success: false,
      error: `Invalid auth type "${auth.type}". Must be "form" or "json"`,
    });
  }

  // --- Extra validation for form auth ---
  if (auth.type === "form") {
    const missingFormFields = ["usernameField", "passwordField"].filter((f) => !auth[f]);
    if (missingFormFields.length > 0) {
      return res.status(400).json({
        success: false,
        error: `Form auth requires: ${missingFormFields.join(", ")}`,
        notes: "Check the HTML source of the login page for the exact input name attributes. e.g. for testphp.vulnweb.com use usernameField: 'uname', passwordField: 'pass'",
      });
    }
  }

  console.log(`[IDOR] Scan requested for: ${url}`);
  console.log(`[IDOR] Auth type: ${auth.type} | Login URL: ${auth.loginUrl} | User: ${auth.username}`);

  // --- Scan with timeout guard (60s max) ---
  try {
    const SCAN_TIMEOUT_MS = 60000;

    const result = await Promise.race([
      scanIDOR(url, { auth }),
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error("IDOR scan timed out after 60 seconds")), SCAN_TIMEOUT_MS)
      ),
    ]);

    console.log(`[IDOR] Scan complete. Vulnerable: ${result.vulnerable}`);
    return res.json(result);

  } catch (err) {
    console.error("[IDOR] Scan error:", err.message);
    return res.status(500).json({
      module: "IDOR",
      target: url,
      vulnerable: false,
      evidence: "Scan failed",
      notes: `Error: ${err.message}`,
    });
  }
};
