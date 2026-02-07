const scanner = require("../utils/scanner");
const cleanUrl = require("../utils/cleanUrl");
const { getSecurityTrailsData } = require("../utils/securitytrails");

exports.quickScan = async (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({
      success: false,
      error: "URL is required",
    });
  }

  // 🔹 Normalize URL
  const cleanedUrl = cleanUrl(url);

  let hostname;
  try {
    const parsed = new URL(cleanedUrl);
    hostname = parsed.hostname;
  } catch (e) {
    return res.status(400).json({
      success: false,
      error: "Invalid URL format",
    });
  }

  try {
    // 🔹 Run ACTIVE / LOCAL scanners (hostname where required)
    const results = await Promise.allSettled([
      scanner.nslookup(hostname),        // 0
      scanner.ping(hostname),            // 1
      scanner.headers(cleanedUrl),       // 2
      scanner.portScan(hostname),        // 3
      scanner.ssl(cleanedUrl),           // 4
      scanner.endpointScan(cleanedUrl),  // 5
      scanner.whatweb(cleanedUrl),       // 6
      scanner.whois(hostname),           // 7 
      scanner.traceroute(hostname),      // 8 
      scanner.emailReputation(hostname), // 9 
    ]);


    // 🔹 Run SecurityTrails (PASSIVE, HOSTNAME ONLY)
    let securityTrailsResult = null;
    let securityTrailsRisk = "LOW";

    try {
      securityTrailsResult = await getSecurityTrailsData(hostname);

      const subCount = securityTrailsResult.subdomains.length;

      if (subCount > 30) securityTrailsRisk = "HIGH";
      else if (subCount > 10) securityTrailsRisk = "MEDIUM";
    } catch (e) {
      securityTrailsResult = {
        error: "SecurityTrails unavailable or plan restricted",
      };
    }

    // 🔹 Helper: safe extraction
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
      endpoints: safe(results[5]),
      whatweb: safe(results[6]),
      whois: safe(results[7]),
      traceroute: safe(results[8]),
      emailReputation: safe(results[9]),
      // 🆕 SecurityTrails block
      securityTrails: {
        scanType: "passive",
        risk: securityTrailsRisk,
        subdomainCount: securityTrailsResult?.subdomains?.length || 0,
        subdomains: securityTrailsResult?.subdomains || [],
        note: "Passive DNS intelligence (SecurityTrails)",
      },
    };

    return res.json({
      success: true,
      message: "Quick scan completed (partial results possible)",
      target: hostname,
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
