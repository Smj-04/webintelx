const axios = require("axios");
const cheerio = require("cheerio");
const { URL } = require("url");

const USER_AGENT = "WebIntelX-Crawler/1.0";
const TIMEOUT = 20000;

/**
 * Recursive crawler with depth control
 * @param {string} startUrl
 * @param {number} maxDepth
 */
async function crawl(startUrl, maxDepth = 2) {
  const visited = new Set();
  const discoveredEndpoints = new Set();
  const baseOrigin = new URL(startUrl).origin;

  async function crawlPage(currentUrl, depth) {
    if (depth > maxDepth) return;
    if (visited.has(currentUrl)) return;

    visited.add(currentUrl);

    let response;
    try {
      response = await axios.get(currentUrl, {
        timeout: TIMEOUT,
        headers: { "User-Agent": USER_AGENT },
        validateStatus: () => true,
      });
    } catch {
      return;
    }

    const contentType = response.headers["content-type"] || "";
    if (!contentType.includes("text/html")) return;

    const $ = cheerio.load(response.data);

    // Extract links
    $("a[href]").each((_, el) => {
      try {
        const href = $(el).attr("href");
        const resolved = new URL(href, currentUrl);

        if (resolved.origin === baseOrigin) {
          const cleanUrl = resolved.origin + resolved.pathname;
          discoveredEndpoints.add(cleanUrl);
          crawlPage(resolved.toString(), depth + 1);
        }
      } catch {}
    });

    // Extract form actions
    $("form[action]").each((_, el) => {
      try {
        const action = $(el).attr("action");
        const resolved = new URL(action, currentUrl);

        if (resolved.origin === baseOrigin) {
          const cleanUrl = resolved.origin + resolved.pathname;
          discoveredEndpoints.add(cleanUrl);
        }
      } catch {}
    });
  }

  await crawlPage(startUrl, 0);

  return Array.from(discoveredEndpoints);
}

module.exports = { crawl };
