const axios = require("axios");

async function emailRepCheck(email) {
  console.log("🔍 [EmailRep] Checking:", email);

  try {
    const res = await axios.get(
      `https://emailrep.io/${encodeURIComponent(email)}`,
      {
        timeout: 8000,
        headers: {
          "User-Agent": "WebIntelX"
        }
      }
    );

    console.log("✅ [EmailRep] Response received");

    return {
      success: true,
      reputation: res.data.reputation,
      suspicious: res.data.suspicious,
      references: res.data.references,
      details: {
        blacklisted: res.data.details.blacklisted,
        malicious_activity: res.data.details.malicious_activity,
        credentials_leaked: res.data.details.credentials_leaked,
        disposable: res.data.details.disposable,
        spoofable: res.data.details.spoofable
      }
    };

  } catch (err) {
    console.error("❌ [EmailRep] Error:", err.message);

    return {
      success: false,
      error: "EmailRep request failed"
    };
  }
}

module.exports = emailRepCheck;
