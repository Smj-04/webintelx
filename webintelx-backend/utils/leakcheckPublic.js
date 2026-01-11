const axios = require("axios");

async function leakcheckPublic(value) {
  console.log("🔍 [LeakCheck] Checking:", value);

  try {
    const res = await axios.get(
      "https://leakcheck.io/api/public",
      {
        params: { check: value },
        timeout: 8000
      }
    );

    console.log("✅ [LeakCheck] Response received");

    return {
      success: true,
      found: res.data.found || false,
      sources: res.data.sources || []
    };

  } catch (err) {
    console.error("❌ [LeakCheck] Error:", err.message);

    return {
      success: false,
      error: "LeakCheck request failed"
    };
  }
}

module.exports = leakcheckPublic;
