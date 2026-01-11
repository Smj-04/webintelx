const axios = require("axios");

async function clickjackingCheck(url) {
  try {
    const res = await axios.get(url, {
      timeout: 5000,
      maxRedirects: 5,
      validateStatus: () => true
    });

    const headers = res.headers;

    const xFrame = headers["x-frame-options"];
    const csp = headers["content-security-policy"];

    // ✅ Check X-Frame-Options
    if (xFrame) {
      const value = xFrame.toLowerCase();
      if (value.includes("deny") || value.includes("sameorigin")) {
        return {
          vulnerable: false,
          protection: "X-Frame-Options",
          value: xFrame
        };
      }
    }

    // ✅ Check CSP frame-ancestors
    if (csp && csp.includes("frame-ancestors")) {
      if (
        csp.includes("'none'") ||
        csp.includes("'self'")
      ) {
        return {
          vulnerable: false,
          protection: "Content-Security-Policy",
          value: csp
        };
      }
    }

    // ❌ No protection found
    return {
      vulnerable: true,
      issue: "Missing X-Frame-Options and CSP frame-ancestors"
    };

  } catch (err) {
    return {
      vulnerable: false,
      error: "Unable to fetch headers"
    };
  }
}

module.exports = clickjackingCheck;
