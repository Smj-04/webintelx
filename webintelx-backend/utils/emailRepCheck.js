/**
 * emailRepCheck.js — Email & Domain Intelligence
 * Replaces the old emailrep.io module.
 * Combines DNSBL blocklist checks + Hunter.io email discovery.
 * No rate limits. No mandatory API key (Hunter is optional).
 */

const axios = require("axios");
const { promises: dns } = require("dns");

// ==========================
// 🔹 DNSBL CHECKS
// ==========================
async function dnsblCheck(hostname) {
  // Resolve IP for reverse-lookup blocklists
  let ip = null;
  try {
    const addrs = await dns.resolve4(hostname);
    ip = addrs[0];
  } catch { /* unresolvable */ }

  const reversedIp = ip ? ip.split(".").reverse().join(".") : null;

  const blocklists = [
    // Domain-based
    { name: "Spamhaus DBL",  host: `${hostname}.dbl.spamhaus.org` },
    { name: "SURBL",         host: `${hostname}.multi.surbl.org` },
    { name: "URIBL",         host: `${hostname}.black.uribl.com` },
    // IP-based (only if we resolved an IP)
    ...(reversedIp ? [
      { name: "Spamhaus ZEN",  host: `${reversedIp}.zen.spamhaus.org` },
      { name: "Barracuda",     host: `${reversedIp}.b.barracudacentral.org` },
      { name: "SpamCop",       host: `${reversedIp}.bl.spamcop.net` },
    ] : []),
  ];

  const results = await Promise.allSettled(
    blocklists.map(bl =>
      dns.resolve4(bl.host)
        .then(() => ({ name: bl.name, listed: true }))
        .catch(() => ({ name: bl.name, listed: false }))
    )
  );

  const checked = results
    .filter(r => r.status === "fulfilled")
    .map(r => r.value);

  const listedOn = checked.filter(r => r.listed).map(r => r.name);

  return {
    ip,
    listed: listedOn.length > 0,
    listCount: listedOn.length,
    listedOn,
    checkedCount: checked.length,
    clean: listedOn.length === 0,
  };
}

// ==========================
// 🔹 HUNTER.IO
// ==========================
async function hunterLookup(hostname) {
  const apiKey = process.env.HUNTER_API_KEY;
  if (!apiKey) {
    return { available: false, note: "HUNTER_API_KEY not set in .env" };
  }

  try {
    const res = await axios.get(
      `https://api.hunter.io/v2/domain-search?domain=${hostname}&api_key=${apiKey}&limit=6`,
      { timeout: 10000 }
    );

    const d = res.data?.data || {};
    const meta = res.data?.meta || {};

    const emails = (d.emails || []).slice(0, 6).map(e => ({
      email: e.value,
      type: e.type,           // "personal" or "generic"
      confidence: e.confidence,
      firstName: e.first_name || null,
      lastName: e.last_name || null,
      position: e.position || null,
      linkedIn: e.linkedin || null,
      sources: e.sources?.length || 0,
    }));

    return {
      available: true,
      domain: d.domain,
      organization: d.organization || null,
      emailCount: emails.length,
      totalEmails: meta.results || d.emails?.length || 0,
      pattern: d.pattern || null,
      mxRecord: d.mx_record || null,
      webmail: d.webmail || false,
      acceptAll: d.accept_all || false,
      disposable: d.disposable || false,
      emails,
    };
  } catch (err) {
    if (err.response?.status === 401) return { available: false, note: "Invalid Hunter API key" };
    if (err.response?.status === 429) return { available: false, note: "Hunter API rate limit reached" };
    if (err.response?.status === 400) return { available: false, note: "Invalid domain for Hunter lookup" };
    return { available: false, note: `Hunter lookup failed: ${err.message}` };
  }
}

// ==========================
// 🔹 MAIN EXPORT
// ==========================
async function emailIntelligence(hostname) {
  const [dnsblRes, hunterRes] = await Promise.allSettled([
    dnsblCheck(hostname),
    hunterLookup(hostname),
  ]);

  const dnsbl = dnsblRes.status === "fulfilled"
    ? dnsblRes.value
    : { listed: false, listedOn: [], listCount: 0, clean: true, ip: null, checkedCount: 0 };

  const hunter = hunterRes.status === "fulfilled"
    ? hunterRes.value
    : { available: false, note: "Hunter lookup failed" };

  const risk = dnsbl.listCount > 1 ? "HIGH"
    : dnsbl.listed ? "MEDIUM"
    : "LOW";

  return {
    dnsbl,
    hunter,
    risk,
    blacklisted: dnsbl.listed,
  };
}

module.exports = emailIntelligence;