// services/endpointEnum.js

const fetch = (...args) =>
  import("node-fetch").then(({ default: fetch }) => fetch(...args));

const { JSDOM } = require("jsdom");

/* =====================================================
   COMMON API PATHS USED BY MODERN APPLICATIONS
===================================================== */
const commonAPIPaths = [
  "/api",
  "/api/login",
  "/api/user",
  "/api/users",
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

/**
 * Advanced endpoint enumeration
 * - Crawls entire site
 * - Finds forms
 * - Extracts JS API calls
 * - Guesses common API endpoints
 */
module.exports = async function enumerateEndpoints(baseUrl) {

  const visitedPages = new Set();
  const discoveredEndpoints = [];

  /* =====================================================
     HELPER: ADD UNIQUE ENDPOINT
  ===================================================== */
  function addEndpoint(url, method = "POST") {

    if (
      !discoveredEndpoints.some(
        ep => ep.url === url && ep.method === method
      )
    ) {
      discoveredEndpoints.push({ url, method });
    }

  }

  /* =====================================================
     1️⃣ DISCOVER API PATHS (MODERN APPS)
  ===================================================== */
  async function discoverCommonAPIs() {

    for (const path of commonAPIPaths) {

      const url = baseUrl.replace(/\/$/, "") + path;

      try {

        const res = await fetch(url, {
          method: "GET",
          redirect: "follow"
        });

        if (![404, 500].includes(res.status)) {
          addEndpoint(url, "POST");
        }

      } catch {}

    }

  }

  /* =====================================================
     2️⃣ CRAWLER
  ===================================================== */
  async function crawl(pageUrl) {

    if (visitedPages.has(pageUrl)) return;
    visitedPages.add(pageUrl);

    let html;

    try {

      html = await fetch(pageUrl, {
        redirect: "follow"
      }).then(r => r.text());

    } catch {
      return;
    }

    const dom = new JSDOM(html);
    const document = dom.window.document;

    /* =====================================================
       2.1 FIND STATE-CHANGING FORMS
    ===================================================== */
    document.querySelectorAll("form").forEach(form => {

      const method = (form.method || "GET").toUpperCase();

      if (!["POST", "PUT", "DELETE"].includes(method)) return;

      let action = form.getAttribute("action");

      if (!action || action.trim() === "") {
        action = pageUrl;
      }

      try {

        const fullUrl = new URL(action, pageUrl).href;

        addEndpoint(fullUrl, method);

      } catch {}

    });

    /* =====================================================
       2.2 EXTRACT API CALLS FROM JAVASCRIPT
    ===================================================== */
    const scripts = document.querySelectorAll("script");

    scripts.forEach(script => {

      const content = script.textContent || "";

      const regex = /\/(api|rest|v1)\/[a-zA-Z0-9_\-/]+/g;

      const matches = content.match(regex);

      if (matches) {

        matches.forEach(endpoint => {

          try {

            const fullUrl = new URL(endpoint, baseUrl).href;

            addEndpoint(fullUrl, "POST");

          } catch {}

        });

      }

    });

    /* =====================================================
       2.3 FOLLOW INTERNAL LINKS
    ===================================================== */
    document.querySelectorAll("a").forEach(anchor => {

      const href = anchor.getAttribute("href");

      if (!href) return;

      try {

        const link = new URL(href, pageUrl).href;

        if (link.startsWith(baseUrl)) {
          crawl(link);
        }

      } catch {}

    });

  }

  /* =====================================================
     EXECUTION PIPELINE
  ===================================================== */

  await discoverCommonAPIs();
  await crawl(baseUrl);

  return discoveredEndpoints;

};