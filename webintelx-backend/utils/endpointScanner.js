const axios = require("axios");

// Common sensitive / vulnerable endpoints
const commonEndpoints = [
  "/login",
  "/admin",
  "/admin/login",
  "/dashboard",
  "/wp-admin",
  "/wp-login.php",
  "/phpmyadmin",
  "/user",
  "/users",
  "/account",
  "/search",
  "/product",
  "/products",
  "/api",
  "/api/v1",
  "/test",
  "/debug"
];

// SQLi-prone parameter patterns
const sqlParams = ["id", "uid", "user", "product", "item", "cat", "page"];

async function endpointScan(target) {
  const baseUrl = target.startsWith("http")
    ? target
    : `http://${target}`;

  const discovered = [];

  for (const endpoint of commonEndpoints) {
    const url = baseUrl + endpoint;

    try {
      const res = await axios.get(url, {
        timeout: 3000,
        validateStatus: () => true, // accept all status codes
      });

      if ([200, 301, 302, 401, 403].includes(res.status)) {
        discovered.push({
          endpoint,
          status: res.status,
          suspicious: endpoint.includes("admin") || endpoint.includes("login"),
        });
      }
    } catch (err) {
      // ignore unreachable endpoints
    }
  }

  // SQLi endpoint suggestions
  const sqlCandidates = sqlParams.map(
    (p) => `/index.php?${p}=1`
  );

  return {
    discoveredEndpoints: discovered,
    sqlmapCandidates: sqlCandidates,
  };
}

module.exports = endpointScan;
