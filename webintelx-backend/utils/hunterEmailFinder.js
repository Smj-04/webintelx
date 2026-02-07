const axios = require("axios");

async function hunterEmailFinder(domain) {
  console.log("🕵️ [Hunter] Searching emails for:", domain);

  const apiKey = process.env.HUNTER_API_KEY;

  if (!apiKey) {
    console.error("❌ Hunter API key missing");
    return { success: false, error: "Hunter API key not set" };
  }

  try {
    const res = await axios.get("https://api.hunter.io/v2/domain-search", {
      params: {
        domain,
        api_key: apiKey
      },
      timeout: 8000
    });

    const emails = res.data.data.emails.map(e => e.value);

    console.log(`✅ [Hunter] Found ${emails.length} emails`);

    return { success: true, emails };

  } catch (err) {
    console.error("❌ [Hunter] Error:", err.message);
    return { success: false, error: "Hunter request failed" };
  }
}

module.exports = hunterEmailFinder;
