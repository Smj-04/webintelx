// services/apiDiscovery.js

const axios = require("axios");

const commonAPIPaths = [
  "/api",
  "/api/login",
  "/api/user",
  "/api/users",
  "/api/auth",
  "/api/account",
  "/api/profile",
  "/api/cart",
  "/api/order",
  "/rest",
  "/rest/user",
  "/rest/products",
  "/graphql",
  "/v1",
  "/v1/user",
  "/v1/account"
];

module.exports = async function discoverAPIEndpoints(baseUrl) {

  const endpoints = [];

  for (let path of commonAPIPaths) {

    const url = baseUrl.replace(/\/$/, "") + path;

    try {

      const res = await axios.get(url, {
        validateStatus: () => true
      });

      if (![404, 500].includes(res.status)) {

        endpoints.push({
          url,
          method: "POST"
        });

      }

    } catch {}

  }

  return endpoints;

};