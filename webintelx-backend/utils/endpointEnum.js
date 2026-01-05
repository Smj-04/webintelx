const fetch = (...args) =>
  import("node-fetch").then(({ default: fetch }) => fetch(...args));
const { JSDOM } = require("jsdom");

/**
 * Site-wide endpoint enumeration for CSRF detection
 * Input  : Base URL only (e.g. http://testphp.vulnweb.com)
 * Output : Array of CSRF-relevant endpoints
 */
module.exports = async function enumerateEndpoints(baseUrl) {
  const visitedPages = new Set();
  const discoveredEndpoints = [];

  async function crawl(pageUrl) {
    if (visitedPages.has(pageUrl)) return;
    visitedPages.add(pageUrl);

    let html;
    try {
      html = await fetch(pageUrl, { redirect: "follow" }).then(r => r.text());
    } catch {
      return;
    }

    const dom = new JSDOM(html);
    const document = dom.window.document;

    /* =====================================================
       1️⃣ FIND CSRF-RELEVANT ENDPOINTS (STATE-CHANGING FORMS)
    ====================================================== */
    document.querySelectorAll("form").forEach(form => {
      const method = (form.method || "GET").toUpperCase();

      // CSRF applies only to state-changing requests
      if (!["POST", "PUT", "DELETE"].includes(method)) return;

      // Handle missing action → submit to same page
      let action = form.getAttribute("action");
      if (!action || action.trim() === "") {
        action = pageUrl;
      }

      // Resolve relative URLs safely
      let fullUrl;
      try {
        fullUrl = new URL(action, pageUrl).href;
      } catch {
        return;
      }

      // Avoid duplicate endpoint entries
      if (
        !discoveredEndpoints.some(
          ep => ep.url === fullUrl && ep.method === method
        )
      ) {
        discoveredEndpoints.push({
          url: fullUrl,
          method
        });
      }
    });

    /* =====================================================
       2️⃣ CRAWL INTERNAL LINKS (SITE-WIDE DISCOVERY)
    ====================================================== */
    document.querySelectorAll("a").forEach(anchor => {
      if (!anchor.href) return;

      try {
        const link = new URL(anchor.href, pageUrl).href;

        // Stay strictly within target base URL
        if (link.startsWith(baseUrl)) {
          crawl(link);
        }
      } catch {
        // Ignore malformed URLs
      }
    });
  }

  // Start crawling from base URL
  await crawl(baseUrl);

  return discoveredEndpoints;
};
