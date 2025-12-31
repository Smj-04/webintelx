const axios = require("axios");
const cheerio = require("cheerio");
const { URL } = require("url");

async function discoverEndpoints(baseUrl, maxDepth = 1) {
  const discovered = new Set();
  const queue = [{ url: baseUrl, depth: 0 }];

  while (queue.length) {
    const { url, depth } = queue.shift();
    if (depth > maxDepth) continue;

    try {
      const res = await axios.get(url, { timeout: 8000 });
      const $ = cheerio.load(res.data);

      $("a[href], form[action]").each((_, el) => {
        const link = $(el).attr("href") || $(el).attr("action");
        if (!link) return;

        try {
          const fullUrl = new URL(link, baseUrl).toString();
          if (fullUrl.startsWith(baseUrl)) {
            if (!discovered.has(fullUrl)) {
              discovered.add(fullUrl);
              queue.push({ url: fullUrl, depth: depth + 1 });
            }
          }
        } catch {}
      });
    } catch {}
  }

  return Array.from(discovered);
}

module.exports = { discoverEndpoints };
