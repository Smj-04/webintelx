// This is the endpointScanner.js file in the utils folder

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

const SQL_PARAMS = [
  "id",
  "cat",
  "category",
  "product",
  "item",
  "uid"
];

// Crawl the base page and extract links that have numeric query params
// These are the most reliable SQLi candidates

async function endpointScanner(baseUrl, crawledLinks = []) {
  const results = [];
  const seen = new Set();

  // First: extract SQLi candidates from pre-crawled links (passed in from fullScanController)
  for (const link of crawledLinks) {
    try {
      const u = new URL(link);
      for (const [param, value] of u.searchParams.entries()) {
        if (/^\d+$/.test(value)) {
          const key = `${link}::${param}`;
          if (!seen.has(key)) {
            seen.add(key);
            results.push({ url: link, param });
          }
        }
      }
    } catch {}
  }

  // Second: only probe common endpoints if crawled links had nothing useful
  if (results.length === 0) {
    for (const ep of COMMON_ENDPOINTS) {
      try {
        const res = await axios.get(baseUrl + ep, {
          timeout: 3000,
          validateStatus: () => true
        });

        if ([200, 301, 302].includes(res.status)) {
          for (const param of SQL_PARAMS) {
            const key = `${baseUrl}${ep}?${param}=1::${param}`;
            if (!seen.has(key)) {
              seen.add(key);
              results.push({ url: `${baseUrl}${ep}?${param}=1`, param });
            }
          }
        }
      } catch {}
    }
  }

  return results;
}

module.exports = endpointScanner;
