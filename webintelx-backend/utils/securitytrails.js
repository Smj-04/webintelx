const axios = require("axios");

const BASE_URL = "https://api.securitytrails.com/v1";

async function getSecurityTrailsData(domain) {
  const headers = {
    apikey: process.env.SECURITYTRAILS_API_KEY,
    Accept: "application/json"
  };

  const response = await axios.get(
    `${BASE_URL}/domain/${domain}/subdomains`,
    { headers }
  );

  return {
    subdomains: response.data.subdomains || [],
    count: response.data.record_count || 0
  };
}

module.exports = { getSecurityTrailsData };
