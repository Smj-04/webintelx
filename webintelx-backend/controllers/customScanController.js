const scanner           = require("../utils/scanner");
const cleanUrl          = require("../utils/cleanUrl");
const emailIntelligence = require("../utils/emailRepCheck");
const dns               = require("dns").promises;
const axios             = require("axios");
const { exec }          = require("child_process");

// ── Active scan state tracker ─────────────────────────────────────────────────
const scanStates = {}; // scanId → 'running' | 'stopped'

exports.stopCustomScan = (req, res) => {
  const { scanId } = req.body;
  if (scanId && scanStates[scanId] !== undefined) {
    scanStates[scanId] = "stopped";
    console.log(`⏹ Custom scan ${scanId} stop requested`);
    return res.json({ status: "stopped", scanId });
  }
  return res.status(404).json({ error: "Scan not found or already completed" });
};

// ── Target validation ──────────────────────────────────────────────────────────
async function validateTarget(url) {
  try {
    const formatted = url.startsWith("http") ? url : `http://${url}`;
    const hostname  = new URL(formatted).hostname;
    await dns.lookup(hostname);
    try { await axios.get(`https://${hostname}`, { timeout: 5000 }); }
    catch { await axios.get(`http://${hostname}`, { timeout: 5000 }); }
    return { valid: true };
  } catch {
    return { valid: false, error: "Target is not reachable or does not exist" };
  }
}

// ── DNS parser ─────────────────────────────────────────────────────────────────
function parseDns(raw) {
  if (!raw || typeof raw !== "string") return null;
  const lines = raw.split("\n").map(l => l.trim()).filter(Boolean);
  const aRecords = [], mxRecords = [], nsRecords = [];
  let resolverIP = null, seenName = false;
  for (const t of lines) {
    if (/^server:/i.test(t)) { resolverIP = t.split(":")[1]?.trim(); continue; }
    if (/^name:/i.test(t)) { seenName = true; continue; }
    if (/^non-authoritative/i.test(t)) continue;
    const addrMatch = t.match(/^Address(?:es)?:\s*([\d.]+)/);
    if (addrMatch) {
      const ip = addrMatch[1];
      if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) continue;
      if (!seenName) { resolverIP = ip; } else { if (ip !== resolverIP) aRecords.push(ip); }
      continue;
    }
    if (seenName) {
      const bareIP = t.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
      if (bareIP && bareIP[1] !== resolverIP) aRecords.push(bareIP[1]);
    }
  }
  const uniqueA = [...new Set(aRecords)];
  return { A: uniqueA, MX: mxRecords, NS: nsRecords, primaryIP: uniqueA[0] || null, resolvedSuccessfully: uniqueA.length > 0 };
}

// ── Ping parser ────────────────────────────────────────────────────────────────
function parsePing(raw) {
  if (!raw || typeof raw !== "string") return null;
  const avgMatch   = raw.match(/Average = (\d+)ms/) || raw.match(/avg\s*=\s*([\d.]+)/);
  const lossMatch  = raw.match(/(\d+)%\s+packet loss/) || raw.match(/(\d+)%\s+loss/);
  const sentMatch  = raw.match(/Sent = (\d+)/);
  const recvMatch  = raw.match(/Received = (\d+)/);
  const packetLoss = lossMatch ? parseInt(lossMatch[1]) : 0;
  return {
    reachable: packetLoss < 100,
    avgTime: avgMatch ? `${parseFloat(avgMatch[1])}` : "N/A",
    packetLoss: `${packetLoss}%`,
    sent: sentMatch ? parseInt(sentMatch[1]) : 4,
    received: recvMatch ? parseInt(recvMatch[1]) : null,
  };
}

// ── Headers parser ─────────────────────────────────────────────────────────────
function parseHeaders(raw) {
  if (!raw || typeof raw !== "object") return { missingSecurityHeaders: [], exposedInfo: [], raw: {} };
  const headers = raw;
  const get = (k) => headers[k] || headers[k.toLowerCase()] || null;
  const server          = get("server");
  const poweredBy       = get("x-powered-by");
  const strictTransport = get("strict-transport-security");
  const xFrameOptions   = get("x-frame-options");
  const csp             = get("content-security-policy");
  const referrer        = get("referrer-policy");
  const cors            = get("access-control-allow-origin");
  const xssProtection   = get("x-xss-protection");
  const missingHeaders  = [];
  if (!strictTransport) missingHeaders.push("Strict-Transport-Security (HSTS)");
  if (!xFrameOptions)   missingHeaders.push("X-Frame-Options");
  if (!csp)             missingHeaders.push("Content-Security-Policy");
  if (!referrer)        missingHeaders.push("Referrer-Policy");
  return { server, poweredBy, strictTransport, xFrameOptions, csp, referrer, cors, xssProtection, missingSecurityHeaders: missingHeaders, exposedInfo: [], raw: headers };
}

// ── SSL parser ─────────────────────────────────────────────────────────────────
function parseSSL(raw) {
  if (!raw || raw.error) return { valid: false, error: raw?.error || "SSL check failed" };
  return {
    valid: raw.valid === true,
    validFrom: raw.validFrom || null,
    validTo:   raw.validTo   || null,
    daysRemaining: raw.daysRemaining ?? null,
    issuer:  raw.issuer  || null,
    subject: raw.subject || null,
  };
}

// ── Traceroute parser ──────────────────────────────────────────────────────────
function parseTraceroute(raw) {
  if (!raw || typeof raw !== "string") return null;
  const lines = raw.split("\n");
  const hops = [];
  for (const line of lines) {
    const m = line.match(/^\s*(\d+)\s+(?:\*\s*\*\s*\*|([\d.]+)(?:\s+\(([^)]+)\))?\s+([\d.]+)\s*ms)/);
    if (!m) continue;
    if (m[2]) {
      hops.push({ hop: parseInt(m[1]), ip: m[2], hostname: m[3] || null, latency: m[4] ? parseFloat(m[4]) : null });
    } else {
      hops.push({ hop: parseInt(m[1]), ip: "*", hostname: null, latency: null });
    }
  }
  const reachableHops = hops.filter(h => h.ip && h.ip !== "*" && /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h.ip));
  const lastReachable = reachableHops[reachableHops.length - 1];
  const latencies = reachableHops.filter(h => h.latency !== null).map(h => h.latency);
  return {
    hops, totalHops: hops.length, reachableHops: reachableHops.length,
    finalHop: lastReachable?.ip || "Unknown", finalHostname: lastReachable?.hostname || null,
    avgLatency: latencies.length ? Math.round((latencies.reduce((a, b) => a + b, 0) / latencies.length) * 10) / 10 : null,
  };
}

// ── WHOIS/RDAP ─────────────────────────────────────────────────────────────────
async function fetchWhoisRDAP(hostname) {
  const parts = hostname.split(".");
  const registrableDomain = parts.length > 2 ? parts.slice(-2).join(".") : hostname;
  try {
    const r = await axios.get(`https://rdap.org/domain/${registrableDomain}`, { timeout: 8000, headers: { Accept: "application/json" } });
    return { source: "rdap", data: r.data };
  } catch {
    return null;
  }
}

function parseWhois(raw) {
  if (!raw) return null;
  if (raw?.source === "rdap" && raw?.data) {
    const d = raw.data;
    const vcardField = (entity, field) => {
      if (!entity?.vcardArray?.[1]) return null;
      const row = entity.vcardArray[1].find(r => r[0] === field);
      return Array.isArray(row?.[3]) ? row[3][0] : row?.[3] || null;
    };
    const getEvent = (type) => d.events?.find(e => e.eventAction === type)?.eventDate?.split("T")[0] || null;
    const registrarEntity  = d.entities?.find(e => e.roles?.includes("registrar"));
    const registrantEntity = d.entities?.find(e => e.roles?.includes("registrant"));
    const nameservers = (d.nameservers || []).map(n => n.ldhName?.toLowerCase()).filter(Boolean);
    const country = vcardField(registrantEntity, "adr")?.[6] || null;
    const dnssec  = d.secureDNS?.delegationSigned ? "signedDelegation" : d.secureDNS ? "unsigned" : "Unknown";
    return {
      registrar: vcardField(registrarEntity, "fn") || registrarEntity?.handle || "Unknown",
      creationDate: getEvent("registration"),
      expiryDate:   getEvent("expiration"),
      updatedDate:  getEvent("last changed"),
      nameservers, registrantOrg: vcardField(registrantEntity, "org") || "Unknown",
      country, dnssec,
    };
  }
  return null;
}

// ── Subdomain enumeration ──────────────────────────────────────────────────────
async function crtshSubdomains(hostname) {
  const parts = hostname.split(".");
  const secondLevelTLDs = ["ac", "co", "com", "org", "net", "gov", "edu", "sch"];
  let rootDomain;
  if (parts.length > 2 && secondLevelTLDs.includes(parts[parts.length - 2])) {
    rootDomain = parts.slice(-3).join(".");
  } else {
    rootDomain = parts.length > 2 ? parts.slice(-2).join(".") : hostname;
  }
  try {
    const res = await axios.get(`https://api.hackertarget.com/hostsearch/?q=${rootDomain}`, { timeout: 10000, headers: { "User-Agent": "Mozilla/5.0 (compatible; WebIntelX/1.0)" } });
    const text = res.data || "";
    if (typeof text !== "string" || text.includes("API count exceeded") || text.includes("error detected")) throw new Error("HackerTarget limit");
    const subdomainSet = new Set();
    text.split("\n").forEach(line => {
      const subdomain = line.split(",")[0]?.trim().toLowerCase();
      if (subdomain && subdomain.endsWith(rootDomain) && subdomain !== rootDomain) subdomainSet.add(subdomain);
    });
    const subdomains = [...subdomainSet].sort();
    return { subdomains, count: subdomains.length, source: "HackerTarget" };
  } catch {
    return { subdomains: [], count: 0, error: "Subdomain lookup failed" };
  }
}

// ── Shodan ─────────────────────────────────────────────────────────────────────
async function shodanLookup(hostname) {
  const apiKey = process.env.SHODAN_API_KEY;
  if (!apiKey) return { available: false, note: "SHODAN_API_KEY not set" };
  try {
    const dnsRes = await axios.get(`https://dns.google/resolve?name=${hostname}&type=A`, { timeout: 5000 });
    const ip = dnsRes.data?.Answer?.[0]?.data;
    if (!ip) return { available: false, note: "Could not resolve IP for Shodan" };
    const cfRanges = ["104.16.","104.17.","104.18.","104.19.","104.20.","104.21.","104.22.","104.23.","172.64.","172.65.","172.66.","172.67.","172.68.","172.69.","172.70.","172.71."];
    if (cfRanges.some(r => ip.startsWith(r))) return { available: true, ip, note: "Origin IP hidden behind Cloudflare proxy — Shodan data reflects Cloudflare infrastructure, not origin server", ports: [], vulns: [], vulnDetails: [], vulnCount: 0, kevCount: 0, criticalCount: 0, tags: ["cloudflare-proxy"], org: "Cloudflare, Inc.", risk: "LOW" };
    const res = await axios.get(`https://api.shodan.io/shodan/host/${ip}?key=${apiKey}`, { timeout: 8000 });
    const d = res.data;
    const ports   = d.ports || [];
    const vulnIds = Array.isArray(d.vulns) ? d.vulns : Object.keys(d.vulns || {});
    const mergedVulnMap = {};
    (d.data || []).forEach(service => { if (service.vulns && typeof service.vulns === "object") Object.assign(mergedVulnMap, service.vulns); });
    const vulnDetails    = vulnIds.map(id => { const v = mergedVulnMap[id] || {}; return { id, cvss: v.cvss || null, epss: v.epss || null, kev: !!(v.kev || v.epss?.kev), summary: v.summary || null }; });
    const kevCount       = vulnDetails.filter(v => v.kev).length;
    const criticalCount  = vulnDetails.filter(v => v.cvss >= 9).length;
    const isCloud        = ["Amazon","AWS","Google","DigitalOcean","Azure","Microsoft","Cloudflare","Linode","Vultr"].some(p => (d.org || "").includes(p));
    return { available: true, ip, org: d.org || null, asn: d.asn || null, isp: d.isp || null, country: d.country_name || null, city: d.city || null, ports, portCount: ports.length, vulnCount: vulnIds.length, kevCount, criticalCount, vulnDetails, lastSeen: d.last_update || null, tags: d.tags || [], isCloud, risk: kevCount > 0 ? "CRITICAL" : vulnIds.length > 0 ? "HIGH" : ports.length > 10 ? "MEDIUM" : "LOW" };
  } catch (err) {
    if (err.response?.status === 404) return { available: true, ip: null, note: "Host not indexed by Shodan", ports: [], vulns: [], vulnDetails: [], vulnCount: 0, kevCount: 0, criticalCount: 0, risk: "LOW" };
    if (err.response?.status === 401) return { available: false, note: "Invalid Shodan API key" };
    return { available: false, note: err.response?.data?.error || err.message };
  }
}

// ── Google Safe Browsing ───────────────────────────────────────────────────────
async function googleSafeBrowsing(url) {
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_KEY;
  if (!apiKey) return { available: false, note: "GOOGLE_SAFE_BROWSING_KEY not set" };
  try {
    const res = await axios.post(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`, { client: { clientId: "webintelx", clientVersion: "1.0" }, threatInfo: { threatTypes: ["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION"], platformTypes: ["ANY_PLATFORM"], threatEntryTypes: ["URL"], threatEntries: [{ url }] } }, { timeout: 8000 });
    const matches = res.data?.matches || [];
    return { available: true, safe: matches.length === 0, threatCount: matches.length, threats: [...new Set(matches.map(m => m.threatType))], risk: matches.length > 0 ? "CRITICAL" : "LOW" };
  } catch {
    return { available: false, note: "Safe Browsing check failed" };
  }
}

// ── VirusTotal ─────────────────────────────────────────────────────────────────
async function virusTotalScan(domain) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) return { available: false, note: "VIRUSTOTAL_API_KEY not set" };
  try {
    const res = await axios.get(`https://www.virustotal.com/api/v3/domains/${domain}`, { headers: { "x-apikey": apiKey }, timeout: 10000 });
    const attr  = res.data?.data?.attributes || {};
    const stats = attr.last_analysis_stats || {};
    const total = Object.values(stats).reduce((a, b) => a + b, 0);
    const malicious = stats.malicious || 0;
    const popularityRankings = attr.popularity_ranks || {};
    const popularity = Object.entries(popularityRankings).map(([src, obj]) => `${src}: #${obj.rank}`);
    return { available: true, malicious, suspicious: stats.suspicious || 0, harmless: stats.harmless || 0, total, communityScore: attr.total_votes?.malicious ? -(attr.total_votes.malicious) : 0, lastAnalysis: attr.last_analysis_date ? new Date(attr.last_analysis_date * 1000).toISOString().split("T")[0] : null, categories: Object.values(attr.categories || {}).slice(0, 3), popularity, risk: malicious > 5 ? "CRITICAL" : malicious > 0 ? "HIGH" : "LOW" };
  } catch (err) {
    if (err.response?.status === 404) return { available: true, malicious: 0, suspicious: 0, harmless: 0, total: 0, risk: "LOW", note: "Domain not in VirusTotal database" };
    if (err.response?.status === 403) return { available: false, note: "VirusTotal API quota exceeded or domain restricted", warn: true };
    if (err.response?.status === 429) return { available: false, note: "VirusTotal rate limit reached — free tier allows 4 requests/min", warn: true };
    return { available: false, note: `VirusTotal scan failed: ${err.message}` };
  }
}

// ── ASN / Geolocation ──────────────────────────────────────────────────────────
async function asnGeoLookup(hostname) {
  try {
    let lookupTarget = hostname;
    try {
      const dnsRes = await axios.get(`https://dns.google/resolve?name=${hostname}&type=A`, { timeout: 5000 });
      const ipv4 = dnsRes.data?.Answer?.[0]?.data;
      if (ipv4 && /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ipv4)) lookupTarget = ipv4;
    } catch {}
    const res = await axios.get(`http://ip-api.com/json/${lookupTarget}?fields=status,message,country,countryCode,region,regionName,city,lat,lon,timezone,isp,org,as,query`, { timeout: 8000 });
    const d = res.data;
    if (d.status !== "success") return { available: false, note: "Geolocation lookup failed" };
    const orgStr = `${d.org || ""} ${d.isp || ""} ${d.as || ""}`;
    const cloudProviders = ["Amazon","AWS","Google","Microsoft","Azure","Cloudflare","DigitalOcean","Linode","Vultr","OVH","Hetzner","Fastly"];
    const matchedProvider = cloudProviders.find(p => orgStr.includes(p));
    return { available: true, ip: d.query, city: d.city || null, region: d.regionName || null, country: d.country || null, countryCode: d.countryCode || null, latitude: d.lat || null, longitude: d.lon || null, org: d.org || null, asn: d.as || null, isp: d.isp || null, timezone: d.timezone || null, isCloud: !!matchedProvider, cloudProvider: matchedProvider ? (d.org || d.isp || matchedProvider) : null, risk: "LOW" };
  } catch {
    return { available: false, note: "Geolocation lookup failed" };
  }
}

// ── Cookies ────────────────────────────────────────────────────────────────────
async function cookiesAnalysis(url) {
  try {
    const res = await axios.get(url, { timeout: 8000, maxRedirects: 5, validateStatus: () => true });
    const setCookieHeaders = res.headers["set-cookie"] || [];
    if (!setCookieHeaders.length) return { available: true, cookieCount: 0, cookies: [], issues: [], risk: "LOW" };
    const cookies = setCookieHeaders.map(raw => {
      const parts = raw.split(";").map(p => p.trim());
      const [nameVal, ...directives] = parts;
      const [name] = nameVal.split("=");
      const dirs = directives.map(d => d.toLowerCase());
      return { name: name.trim(), secure: dirs.some(d => d === "secure"), httpOnly: dirs.some(d => d === "httponly"), sameSite: dirs.find(d => d.startsWith("samesite"))?.split("=")[1] || null };
    });
    const issues = [];
    cookies.forEach(c => {
      if (!c.secure)   issues.push(`"${c.name}" missing Secure flag — sent over HTTP`);
      if (!c.httpOnly) issues.push(`"${c.name}" missing HttpOnly — accessible via JavaScript`);
      if (!c.sameSite) issues.push(`"${c.name}" missing SameSite — vulnerable to CSRF`);
    });
    return { available: true, cookieCount: cookies.length, cookies, issues, risk: issues.length > 4 ? "HIGH" : issues.length > 0 ? "MEDIUM" : "LOW" };
  } catch {
    return { available: false, note: "Cookie analysis failed" };
  }
}

// ── Green Web ──────────────────────────────────────────────────────────────────
async function greenWebCheck(hostname) {
  try {
    const res = await axios.get(`https://api.thegreenwebfoundation.org/api/v3/greencheck/${hostname}`, { timeout: 8000 });
    return { available: true, green: res.data?.green === true, hostedBy: res.data?.hosted_by || null, partnerUrl: res.data?.hosted_by_website || null, risk: "LOW" };
  } catch {
    return { available: false, green: false, note: "Green web check failed" };
  }
}

// ── Known latest versions table ────────────────────────────────────────────────
const LATEST_VERSIONS = {
  "jQuery": { latest: "3.7.1", majorSafe: 3 }, "Bootstrap": { latest: "5.3.3", majorSafe: 5 },
  "React": { latest: "18.3.1", majorSafe: 18 }, "Angular": { latest: "18.0.0", majorSafe: 18 },
  "Vue.js": { latest: "3.4.27", majorSafe: 3 }, "Next.js": { latest: "14.2.3", majorSafe: 14 },
  "Nuxt.js": { latest: "3.12.3", majorSafe: 3 }, "Ember.js": { latest: "5.9.0", majorSafe: 5 },
  "Backbone.js": { latest: "1.6.0", majorSafe: 1 }, "Lodash": { latest: "4.17.21", majorSafe: 4 },
  "Moment.js": { latest: "2.30.1", majorSafe: 2 }, "Axios": { latest: "1.7.2", majorSafe: 1 },
  "Chart.js": { latest: "4.4.3", majorSafe: 4 }, "D3.js": { latest: "7.9.0", majorSafe: 7 },
  "Three.js": { latest: "0.166.0", majorSafe: 0 }, "Swiper": { latest: "11.1.4", majorSafe: 11 },
  "GSAP": { latest: "3.12.5", majorSafe: 3 }, "Tailwind CSS": { latest: "3.4.4", majorSafe: 3 },
  "Font Awesome": { latest: "6.5.2", majorSafe: 6 }, "WordPress": { latest: "6.5.5", majorSafe: 6 },
  "Drupal": { latest: "10.3.0", majorSafe: 10 }, "Joomla": { latest: "5.1.2", majorSafe: 5 },
  "PHP": { latest: "8.3.0", majorSafe: 8 }, "nginx": { latest: "1.27.0", majorSafe: 1 },
  "Apache": { latest: "2.4.62", majorSafe: 2 }, "OpenSSL": { latest: "3.3.1", majorSafe: 3 },
  "jQuery UI": { latest: "1.13.3", majorSafe: 1 }, "jQuery Migrate": { latest: "3.4.1", majorSafe: 3 },
};

function parseVersion(v) {
  if (!v || v === "Unknown") return null;
  const parts = v.split(".").map(Number);
  return { major: parts[0] || 0, minor: parts[1] || 0, patch: parts[2] || 0, raw: v };
}

function compareVersions(a, b) {
  if (a.major !== b.major) return a.major - b.major;
  if (a.minor !== b.minor) return a.minor - b.minor;
  return a.patch - b.patch;
}

function analyzeVersions(wappalyzerRaw) {
  const result = {};
  for (const [tech, version] of Object.entries(wappalyzerRaw)) {
    const knownInfo = LATEST_VERSIONS[tech] || LATEST_VERSIONS[tech.split(" ")[0]];
    const detected  = parseVersion(version);
    if (!knownInfo || !detected) { result[tech] = { version: version || "Unknown", outdated: false, latest: null, severity: null }; continue; }
    const latest = parseVersion(knownInfo.latest);
    const isOld  = compareVersions(detected, latest) < 0;
    let severity = null;
    if (isOld) {
      if (detected.major < knownInfo.majorSafe) severity = "CRITICAL";
      else if (detected.major < latest.major)   severity = "HIGH";
      else if (detected.minor < latest.minor)   severity = "HIGH";
      else                                       severity = "LOW";
    }
    result[tech] = { version, latest: knownInfo.latest, outdated: isOld, severity };
  }
  return result;
}

// ── Wappalyzer ─────────────────────────────────────────────────────────────────
function runWappalyzer(url) {
  return new Promise((resolve) => {
    exec(`python utils/wappalyzer_scan.py ${url}`, (err, stdout) => {
      if (err) return resolve({});
      try { resolve(JSON.parse(stdout)); } catch { resolve({}); }
    });
  });
}

// ── Risk scoring ───────────────────────────────────────────────────────────────
function calculateRisk(output) {
  let score = 0;
  const findings = [];
  if (output.ssl && !output.ssl.valid)                        { score += 3; findings.push("No valid SSL/TLS certificate"); }
  else if (output.ssl?.daysRemaining < 30)                    { score += 2; findings.push(`SSL expires in ${output.ssl.daysRemaining} days`); }
  const mh = output.headers?.missingSecurityHeaders || [];
  if (mh.length >= 3)                                         { score += 2; findings.push(`${mh.length} critical security headers missing`); }
  if (output.headers?.poweredBy?.includes("PHP/5"))           { score += 3; findings.push("Outdated PHP version exposed"); }
  const outdatedCritical = Object.entries(output.wappalyzer || {}).filter(([,v]) => v.outdated && v.severity === "CRITICAL");
  const outdatedHigh     = Object.entries(output.wappalyzer || {}).filter(([,v]) => v.outdated && v.severity === "HIGH");
  if (outdatedCritical.length > 0) { score += 3; findings.push(`${outdatedCritical.length} critically outdated technolog${outdatedCritical.length>1?"ies":"y"}: ${outdatedCritical.map(([t])=>t).join(", ")}`); }
  else if (outdatedHigh.length > 0){ score += 2; findings.push(`${outdatedHigh.length} outdated technolog${outdatedHigh.length>1?"ies":"y"} detected: ${outdatedHigh.map(([t])=>t).join(", ")}`); }
  if (output.headers?.cors === "*")                           { score += 2; findings.push("Wildcard CORS policy detected"); }
  if ((output.endpoints || []).length > 30)                   { score += 2; findings.push(`${output.endpoints.length} parameterized endpoints exposed`); }
  const dangerousPorts = [21, 23, 25, 3306];
  const openDangerous  = (output.openPorts || []).filter(p => dangerousPorts.includes(p.port));
  if (openDangerous.length > 0)                               { score += 2; findings.push(`Dangerous ports open: ${openDangerous.map(p => p.name).join(", ")}`); }
  if (output.securityTrails?.subdomainCount > 30)             { score += 2; findings.push("Large attack surface via subdomains"); }
  if (output.emailIntelligence?.dnsbl?.listCount > 1)         { score += 3; findings.push(`Domain blacklisted on ${output.emailIntelligence.dnsbl.listCount} DNS blocklists`); }
  if (output.shodan?.vulnCount > 0)                           { score += 3; findings.push(`${output.shodan.vulnCount} CVEs found via Shodan`); }
  if (output.safeBrowsing?.threatCount > 0)                   { score += 4; findings.push(`Flagged by Google Safe Browsing`); }
  if (output.virusTotal?.malicious > 5)                       { score += 3; findings.push(`${output.virusTotal.malicious} AV engines flagged domain`); }
  else if (output.virusTotal?.malicious > 0)                  { score += 2; findings.push(`${output.virusTotal.malicious} AV engine(s) flagged domain`); }
  // Vuln modules
  if (output.vulnerabilities?.sqlInjection?.found)            { score += 4; findings.push("SQL Injection vulnerability detected"); }
  if (output.vulnerabilities?.xss?.found)                     { score += 3; findings.push("XSS vulnerability detected"); }
  if (output.vulnerabilities?.commandInjection?.found)        { score += 4; findings.push("Command Injection vulnerability detected"); }
  if (output.vulnerabilities?.csrf?.found)                    { score += 2; findings.push("CSRF vulnerability detected"); }
  if (output.vulnerabilities?.clickjacking?.vulnerable)       { score += 2; findings.push("Clickjacking vulnerability detected"); }
  if (output.vulnerabilities?.openRedirect?.found)            { score += 2; findings.push("Open Redirect vulnerability detected"); }
  if (output.vulnerabilities?.sensitiveFiles?.found)          { score += 3; findings.push("Sensitive files exposed"); }
  // ── NEW: CORS + WordPress ──────────────────────────────────────────────────
  if (output.vulnerabilities?.cors?.found) {
    const s = output.vulnerabilities.cors.details?.summary;
    if (s?.critical > 0) { score += 4; findings.push("Critical CORS misconfiguration detected"); }
    else { score += 2; findings.push("CORS misconfiguration detected"); }
  }
  if (output.vulnerabilities?.wordpress?.found) {
    const lvl = output.vulnerabilities.wordpress.details?.riskScore?.level;
    if (lvl === "CRITICAL" || lvl === "HIGH") { score += 3; findings.push("High-risk WordPress vulnerabilities detected"); }
    else { score += 1; findings.push("WordPress security issues detected"); }
  }
  const risk = score >= 12 ? "CRITICAL" : score >= 8 ? "HIGH" : score >= 4 ? "MEDIUM" : "LOW";
  return { risk, score, findings };
}

// ─── MAIN HANDLER ─────────────────────────────────────────────────────────────
exports.customScan = async (req, res) => {
  const { url, modules: selectedModules = [] } = req.body;
  if (!url || selectedModules.length === 0) {
    return res.status(400).json({ error: "Target URL and at least one module required" });
  }

  const has = (m) => selectedModules.includes(m);

  const formatted = url.startsWith("http") ? url : `http://${url}`;
  let hostname;
  try { hostname = new URL(formatted).hostname; }
  catch { return res.status(400).json({ error: "Invalid URL" }); }
  const cleanedUrl = cleanUrl(url);

  const validation = await validateTarget(url);
  if (!validation.valid) return res.status(400).json({ error: validation.error });

  const scanId = Date.now().toString();
  scanStates[scanId] = "running";
  const isStopped = () => scanStates[scanId] === "stopped";

  res.setHeader("X-Scan-Id", scanId);

// ── Replace buildAndRespond ────────────────────────────────────────────────
const buildAndRespond = (output, stopped = false) => {
  const riskAssessment = calculateRisk(output);
  delete scanStates[scanId];
  return res.json({
    success: true,
    stopped,
    message: stopped ? "Scan stopped — partial results returned" : "Custom scan completed",
    scanId,
    target:      hostname,
    modulesRun:  selectedModules,
    riskAssessment,
    ...output,
  });
};

  // ── Core modules (all parallel) ───────────────────────────────────────────────
  const corePromises = {
    dns:        has("dns")        ? scanner.nslookup(hostname)      : null,
    ping:       has("ping")       ? scanner.ping(hostname)           : null,
    headers:    has("headers")    ? scanner.headers(cleanedUrl)      : null,
    ports:      has("ports")      ? scanner.portScan(hostname)       : null,
    ssl:        has("ssl")        ? scanner.ssl(hostname)            : null,
    endpoints:  has("endpoints")  ? scanner.endpointScan(cleanedUrl) : null,
    traceroute: has("traceroute") ? scanner.traceroute(hostname)     : null,
    whois:      has("whois")      ? fetchWhoisRDAP(hostname)         : null,
    emailIntel: has("email")      ? emailIntelligence(hostname)      : null,
  };

  const coreKeys    = Object.keys(corePromises);
  const coreResults = await Promise.allSettled(coreKeys.map(k => corePromises[k] || Promise.resolve(null)));
  const coreData    = {};
  coreKeys.forEach((k, i) => {
    coreData[k] = coreResults[i].status === "fulfilled" ? coreResults[i].value : null;
  });

  const parsedDns        = parseDns(coreData.dns);
  const parsedPing       = parsePing(coreData.ping);
  const parsedHeaders    = parseHeaders(coreData.headers);
  const parsedPorts      = Array.isArray(coreData.ports) ? coreData.ports : [];
  const parsedSSL        = parseSSL(coreData.ssl);
  const parsedEndpoints  = Array.isArray(coreData.endpoints) ? coreData.endpoints : [];
  const parsedTraceroute = parseTraceroute(coreData.traceroute);
  const parsedWhois      = parseWhois(coreData.whois);

  let wappalyzerResult = {};
  if (has("wappalyzer")) {
    const raw = await runWappalyzer(cleanedUrl);
    wappalyzerResult = analyzeVersions(raw);
  }

// ── Replace your existing buildOutput function ─────────────────────────────
const buildOutput = (osintData = {}, vulnerabilities = {}, vulnKeys = []) => {
  const output = {
    ...(has("dns")        && { dns:               parsedDns        }),
    ...(has("ping")       && { ping:              parsedPing       }),
    ...(has("headers")    && { headers:           parsedHeaders    }),
    ...(has("ports")      && { openPorts:         parsedPorts      }),
    ...(has("ssl")        && { ssl:               parsedSSL        }),
    ...(has("endpoints")  && { endpoints:         parsedEndpoints  }),
    ...(has("wappalyzer") && { wappalyzer:        wappalyzerResult }),
    ...(has("traceroute") && { traceroute:        parsedTraceroute }),
    ...(has("whois")      && { whois:             parsedWhois      }),
    ...(has("email")      && { emailIntelligence: coreData.emailIntel || { risk: "LOW", dnsbl: { listed: false }, hunter: { available: false } } }),
    ...(has("subdomains") && osintData.subdomains && {
      securityTrails: {
        scanType:       "passive",
        subdomainCount: osintData.subdomains.subdomains?.length || 0,
        subdomains:     osintData.subdomains.subdomains || [],
        note:           `Subdomain enumeration via ${osintData.subdomains.source || "passive DNS"}`,
        risk:           (osintData.subdomains.subdomains?.length || 0) > 30 ? "HIGH"
                      : (osintData.subdomains.subdomains?.length || 0) > 10 ? "MEDIUM" : "LOW",
      },
    }),
    ...(has("shodan")       && { shodan:       osintData.shodan       }),
    ...(has("safeBrowsing") && { safeBrowsing: osintData.safeBrowsing }),
    ...(has("virusTotal")   && { virusTotal:   osintData.virusTotal   }),
    ...(has("asnGeo")       && { asnGeo:       osintData.asnGeo       }),
    ...(has("cookies")      && { cookies:      osintData.cookies      }),
    ...(has("greenWeb")     && { greenWeb:     osintData.greenWeb     }),
    ...(vulnKeys.length > 0 && { vulnerabilities }),
    selectedModules,
  };
  return output;
};

  if (isStopped()) return buildAndRespond(buildOutput(), true);

  // ── OSINT modules (all parallel) ──────────────────────────────────────────────
  const osintPromises = {
    shodan:       has("shodan")       ? shodanLookup(hostname)         : null,
    safeBrowsing: has("safeBrowsing") ? googleSafeBrowsing(cleanedUrl) : null,
    virusTotal:   has("virusTotal")   ? virusTotalScan(hostname)       : null,
    asnGeo:       has("asnGeo")       ? asnGeoLookup(hostname)         : null,
    cookies:      has("cookies")      ? cookiesAnalysis(cleanedUrl)    : null,
    greenWeb:     has("greenWeb")     ? greenWebCheck(hostname)        : null,
    subdomains:   has("subdomains")   ? crtshSubdomains(hostname)      : null,
  };

  const osintKeys    = Object.keys(osintPromises);
  const osintResults = await Promise.allSettled(osintKeys.map(k => osintPromises[k] || Promise.resolve(null)));
  const osintData    = {};
  osintKeys.forEach((k, i) => {
    osintData[k] = osintResults[i].status === "fulfilled" ? osintResults[i].value : null;
  });

  if (isStopped()) return buildAndRespond(buildOutput(osintData), true);

  // ── Vuln modules ──────────────────────────────────────────────────────────────
  const safePost = async (endpoint, body, timeout = 180000) => {
    try {
      const r = await axios.post(endpoint, body, { timeout });
      return { ok: true, data: r.data };
    } catch { return { ok: false, data: null }; }
  };

  const vulnPromises = {};

  if (has("sqlInjection"))
    vulnPromises.sqlInjection = safePost("http://localhost:5000/api/sqlmap", { url: cleanedUrl });

  if (has("xss"))
    vulnPromises.xss = (async () => {
      const [reflected, dom, stored] = await Promise.allSettled([
        safePost("http://localhost:5000/api/autoxss",    { url: cleanedUrl }, 180000),
        safePost("http://localhost:5000/api/dom-xss",    { url: cleanedUrl }, 60000),   // ← updated timeout
        safePost("http://localhost:5000/api/stored-xss", { url: cleanedUrl }, 180000),
      ]);
      const rData = reflected.status === "fulfilled" ? reflected.value?.data : null;
      const dData = dom.status       === "fulfilled" ? dom.value?.data       : null;
      const sData = stored.status    === "fulfilled" ? stored.value?.data    : null;
      const reflectedEndpoints = rData?.vulnerableEndpoints || [];
      const domVuln    = !!(dData?.vulnerable);
      const storedVuln = !!(sData?.vulnerable);
      const found = reflectedEndpoints.length > 0 || domVuln || storedVuln;
      return { ok: true, data: { vulnerable: found, reflected: { found: reflectedEndpoints.length > 0, vulnerableEndpoints: reflectedEndpoints, testedEndpoints: rData?.testedEndpoints || 0 }, dom: { found: domVuln, details: dData || null }, stored: { found: storedVuln, details: sData || null } } };
    })();

  if (has("csrf"))
    vulnPromises.csrf = safePost("http://localhost:5000/api/csrf", { url: cleanedUrl });

  if (has("clickjacking"))
    vulnPromises.clickjacking = safePost("http://localhost:5000/api/clickjacking", { url: cleanedUrl });

  if (has("commandInjection"))
    vulnPromises.commandInjection = safePost("http://localhost:5000/api/command-injection", { url: cleanedUrl });

  if (has("sensitiveFiles"))
    vulnPromises.sensitiveFiles = safePost("http://localhost:5000/api/sensitive-files", { url: cleanedUrl });

  if (has("openRedirect"))
    vulnPromises.openRedirect = safePost("http://localhost:5000/api/open-redirect", { url: cleanedUrl }, 60000);

  // ── NEW: CORS ──────────────────────────────────────────────────────────────
  if (has("cors"))
    vulnPromises.cors = safePost("http://localhost:5000/api/cors", { url: cleanedUrl }, 60000);

  // ── NEW: WordPress ────────────────────────────────────────────────────────
  if (has("wordpress"))
    vulnPromises.wordpress = safePost("http://localhost:5000/api/wordpress/scan", { url: cleanedUrl }, 60000);

  const vulnKeys    = Object.keys(vulnPromises);
  const vulnResults = await Promise.allSettled(vulnKeys.map(k => vulnPromises[k]));
  const vulnerabilities = {};

  vulnKeys.forEach((k, i) => {
    const r = vulnResults[i].status === "fulfilled" ? vulnResults[i].value : { ok: false };

    // WordPress needs special handling — it's only "found" if it IS WordPress
    if (k === "wordpress") {
      vulnerabilities[k] = r.ok
        ? { found: !!(r.data?.isWordPress), details: r.data }
        : { found: false, details: null };
      return;
    }

    vulnerabilities[k] = r.ok
      ? { found: !!(r.data?.vulnerable || r.data?.found), details: r.data }
      : { found: false, details: null };
  });

  return buildAndRespond(buildOutput(osintData, vulnerabilities, vulnKeys));
};