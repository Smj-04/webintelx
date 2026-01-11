const axios = require("axios");
const { URL } = require("url");

const COMMON_ENDPOINTS = [
  "/index.php",
  "/listproducts.php",   
  "/product.php",
  "/products.php",
  "/search.php",
  "/category.php",
  "/admin"
];


// ONLY params that commonly hit SQL queries
const SQL_PARAMS = [
  "id",
  "cat",
  "category",
  "product",
  "item",
  "uid"
];

async function endpointScanner(baseUrl) {
  const results = [];

  for (const ep of COMMON_ENDPOINTS) {
    try {
      const res = await axios.get(baseUrl + ep, {
        timeout: 3000,
        validateStatus: () => true
      });

      if ([200, 301, 302].includes(res.status)) {
        for (const param of SQL_PARAMS) {
          results.push({
            url: `${baseUrl}${ep}?${param}=1`,
            param
          });
        }
      }
    } catch {}
  }

  return results;
}

module.exports = endpointScanner;
