const scanner = require("../utils/scanner");
const cleanUrl = require("../utils/cleanUrl");
// SecurityTrails replaced by crt.sh (free, no API key)
const emailIntelligence = require("../utils/emailRepCheck");
const dns = require("dns").promises;
const axios = require("axios");
const { exec } = require("child_process");

// ==========================
// 🔹 TARGET VALIDATION
// ==========================
async function validateTarget(url) {
  try {
    const formatted = url.startsWith("http") ? url : `http://${url}`;
    const hostname = new URL(formatted).hostname;
    await dns.lookup(hostname);
    try {
      await axios.get(`https://${hostname}`, { timeout: 5000 });
    } catch {
      await axios.get(`http://${hostname}`, { timeout: 5000 });
    }
    return { valid: true };
  } catch {
    return { valid: false, error: "Target is not reachable or does not exist" };
  }
}

// ==========================
// 🔹 RAW OUTPUT PARSERS
// ==========================

function parseDns(raw) {
  if (!raw || typeof raw !== "string") return null;

  const lines = raw.replace(/\r/g, "").split("\n");
  const mxRecords = [];
  const nsRecords = [];
  const aRecords = [];
  let resolverIP = null;
  let seenName = false;

  for (const line of lines) {
    const t = line.trim();
    if (!t) continue;

    if (/^Name:/i.test(t)) {
      seenName = true;
      continue;
    }

    const addrMatch = t.match(/^Address(?:es)?:\s+([\d.]+)/);
    if (addrMatch) {
      const ip = addrMatch[1];
      // Skip IPv6 addresses and non-IPv4
      if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) continue;
      if (!seenName) {
        resolverIP = ip;
      } else {
        if (ip !== resolverIP) aRecords.push(ip);
      }
      continue;
    }

    if (seenName) {
      const bareIP = t.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
      if (bareIP && bareIP[1] !== resolverIP) aRecords.push(bareIP[1]);
    }

    const mxMatch = t.match(/mail exchanger = (.+)/);
    if (mxMatch) mxRecords.push(mxMatch[1].trim());
    const nsMatch = t.match(/nameserver = (.+)/);
    if (nsMatch) nsRecords.push(nsMatch[1].trim());
  }

  const uniqueA = [...new Set(aRecords)];
  return {
    A: uniqueA,
    MX: mxRecords,
    NS: nsRecords,
    primaryIP: uniqueA[0] || null,
    resolvedSuccessfully: uniqueA.length > 0,
  };
}

function parsePing(raw) {
  if (!raw || typeof raw !== "string") return null;

  const avgMatch =
    raw.match(/rtt min\/avg\/max.*?=\s*[\d.]+\/([\d.]+)\/[\d.]+/) ||
    raw.match(/Average = (\d+)ms/) ||
    raw.match(/avg\s*=\s*([\d.]+)/);

  const lossMatch =
    raw.match(/(\d+)%\s+packet loss/) ||
    raw.match(/(\d+)%\s+loss/);

  const sentMatch = raw.match(/(\d+)\s+packets transmitted/) || raw.match(/Sent = (\d+)/);
  const receivedMatch = raw.match(/(\d+)\s+received/) || raw.match(/Received = (\d+)/);

  const avgTime = avgMatch ? parseFloat(avgMatch[1]) : null;
  const packetLoss = lossMatch ? parseInt(lossMatch[1]) : 0;

  return {
    reachable: packetLoss < 100,
    avgTime: avgTime !== null ? `${avgTime}` : "N/A",
    packetLoss: `${packetLoss}%`,
    sent: sentMatch ? parseInt(sentMatch[1]) : 4,
    received: receivedMatch ? parseInt(receivedMatch[1]) : null,
    raw: raw.substring(0, 300),
  };
}

// ==========================
// 🔹 RDAP WHOIS (no install)
// ==========================
async function fetchWhoisRDAP(hostname) {
  const parts = hostname.split(".");
  const registrableDomain = parts.length > 2 ? parts.slice(-2).join(".") : hostname;
  try {
    const response = await axios.get(
      `https://rdap.org/domain/${registrableDomain}`,
      { timeout: 8000, headers: { Accept: "application/json" } }
    );
    return { source: "rdap", data: response.data };
  } catch {
    try {
      const response = await axios.get(
        `https://rdap.iana.org/domain/${registrableDomain}`,
        { timeout: 6000, headers: { Accept: "application/json" } }
      );
      return { source: "iana", data: response.data };
    } catch {
      return null;
    }
  }
}

function parseWhois(raw) {
  if (raw && raw.source && raw.data) {
    const d = raw.data;

    const vcardField = (entity, fieldName) => {
      try {
        const arr = entity?.vcardArray?.[1];
        if (!Array.isArray(arr)) return null;
        const field = arr.find(v => Array.isArray(v) && v[0] === fieldName);
        return field ? field[field.length - 1] : null;
      } catch { return null; }
    };

    const getEvent = (action) => {
      const ev = d.events?.find(e =>
        e.eventAction?.toLowerCase().includes(action.toLowerCase())
      );
      return ev?.eventDate ? ev.eventDate.split("T")[0] : "N/A";
    };

    const allEntities = [...(d.entities || [])];
    d.entities?.forEach(e => { if (e.entities) allEntities.push(...e.entities); });

    const registrarEntity = allEntities.find(e => e.roles?.includes("registrar"));
    const registrar = vcardField(registrarEntity, "fn")
      || registrarEntity?.handle
      || "Unknown";

    const registrantEntity = allEntities.find(e => e.roles?.includes("registrant"));
    const registrantOrg = vcardField(registrantEntity, "org")
      || vcardField(registrantEntity, "fn")
      || "Unknown";

    let country = "Unknown";
    try {
      const adr = registrantEntity?.vcardArray?.[1]?.find(v => Array.isArray(v) && v[0] === "adr");
      if (adr) {
        country = adr[1]?.["country-name"] || adr[3]?.[6] || "Unknown";
      }
    } catch {}

    const nameservers = (d.nameservers || [])
      .map(ns => (ns.ldhName || ns.unicodeName || "").toLowerCase())
      .filter(Boolean)
      .slice(0, 6);

    const dnssec = d.secureDNS?.delegationSigned
      ? "signedDelegation"
      : d.secureDNS
        ? "unsigned"
        : "Unknown";

    return {
      registrar,
      creationDate: getEvent("registration"),
      expiryDate: getEvent("expiration"),
      updatedDate: getEvent("last changed"),
      nameservers,
      registrantOrg,
      country,
      dnssec,
      status: Array.isArray(d.status) ? d.status : [],
    };
  }
  if (!raw || typeof raw !== "string") return null;
  const extract = (pats) => { for (const p of pats) { const m = raw.match(p); if (m?.[1]?.trim()) return m[1].trim(); } return null; };
  return {
    registrar: extract([/Registrar:\s*(.+)/i]) || "Unknown",
    creationDate: extract([/Creation Date:\s*(.+)/i, /Created:\s*(.+)/i])?.split("T")[0] || "N/A",
    expiryDate: extract([/Registry Expiry Date:\s*(.+)/i, /Expir\w+ Date:\s*(.+)/i])?.split("T")[0] || "N/A",
    updatedDate: extract([/Updated Date:\s*(.+)/i])?.split("T")[0] || "N/A",
    nameservers: [...raw.matchAll(/Name Server:\s*(.+)/gi)].map(m => m[1].trim().toLowerCase()).slice(0, 4),
    registrantOrg: extract([/Registrant Organization:\s*(.+)/i]) || "Unknown",
    country: extract([/Registrant Country:\s*(.+)/i]) || "Unknown",
    dnssec: extract([/DNSSEC:\s*(.+)/i]) || "Unknown",
    status: [],
  };
}

function parseTraceroute(raw) {
  if (!raw || typeof raw !== "string") return null;

  const hops = [];
  const lines = raw.split("\n");

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    const winHopMatch = trimmed.match(/^(\d+)\s+(?:(<?\d+)\s*ms\s+(<?\d+)\s*ms\s+(<?\d+)\s*ms|\*[\s*]+)\s*(.*)$/);
    const linuxHopMatch = trimmed.match(/^(\d+)\s+(?:(\S+)\s+\((\d{1,3}(?:\.\d{1,3}){3})\)|(\d{1,3}(?:\.\d{1,3}){3}))\s+([\d.]+)\s*ms/);

    if (winHopMatch) {
      const hopNum = parseInt(winHopMatch[1]);
      const destination = winHopMatch[5]?.trim() || "";
      const isTimeout = destination.toLowerCase().includes("request timed out") || destination === "*";

      const ipFromBracket = destination.match(/\[(\d{1,3}(?:\.\d{1,3}){3})\]/);
      const plainIP = destination.match(/^(\d{1,3}(?:\.\d{1,3}){3})$/);
      const ip = ipFromBracket ? ipFromBracket[1] : plainIP ? plainIP[1] : (isTimeout ? "*" : destination);
      const hostname = ipFromBracket ? destination.replace(/\s*\[.*\]/, "").trim() : null;

      let latency = null;
      if (winHopMatch[2] && winHopMatch[3] && winHopMatch[4]) {
        const times = [winHopMatch[2], winHopMatch[3], winHopMatch[4]]
          .map(t => parseInt(t.replace("<", "")))
          .filter(t => !isNaN(t));
        if (times.length) latency = Math.round(times.reduce((a, b) => a + b, 0) / times.length);
      }

      hops.push({ hop: hopNum, ip, hostname, latency });

    } else if (linuxHopMatch) {
      hops.push({
        hop: parseInt(linuxHopMatch[1]),
        ip: linuxHopMatch[3] || linuxHopMatch[4] || "Unknown",
        hostname: linuxHopMatch[2] || null,
        latency: parseFloat(linuxHopMatch[5]),
      });
    }
  }

  if (hops.length === 0) return null;

  // Filter to only hops with valid IPs (not timeouts, not raw latency text)
  const reachableHops = hops.filter(h =>
    h.ip && h.ip !== "*" &&
    !h.ip.toLowerCase().includes("request") &&
    /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h.ip)
  );
  const lastReachable = reachableHops[reachableHops.length - 1];
  const hopsWithLatency = reachableHops.filter(h => h.latency !== null);

  return {
    hops,
    totalHops: hops.length,
    reachableHops: reachableHops.length,
    finalHop: lastReachable?.ip || "Unknown",
    finalHostname: lastReachable?.hostname || null,
    avgLatency: hopsWithLatency.length
      ? (hopsWithLatency.reduce((a, b) => a + b.latency, 0) / hopsWithLatency.length).toFixed(1)
      : null,
  };
}

function parseSSL(raw) {
  if (!raw || raw.error) return { valid: false, error: raw?.error || "SSL check failed" };
  return {
    valid: raw.valid || false,
    daysRemaining: raw.daysRemaining || null,
    validFrom: raw.validFrom || null,
    validTo: raw.validTo || null,
    issuer: raw.issuer || null,
    subject: raw.subject || null,
    error: null,
  };
}

function parseHeaders(raw) {
  if (!raw || raw.error) return { error: raw?.error || "Could not fetch headers" };

  const headers = raw;
  const server = headers["server"] || headers["Server"] || null;
  const poweredBy = headers["x-powered-by"] || headers["X-Powered-By"] || null;
  const contentType = headers["content-type"] || null;
  const strictTransport = headers["strict-transport-security"] || null;
  const xFrameOptions = headers["x-frame-options"] || null;
  const xssProtection = headers["x-xss-protection"] || null;
  const csp = headers["content-security-policy"] || null;
  const referrer = headers["referrer-policy"] || null;
  const cors = headers["access-control-allow-origin"] || null;

  const missingHeaders = [];
  if (!strictTransport) missingHeaders.push("Strict-Transport-Security (HSTS)");
  if (!xFrameOptions) missingHeaders.push("X-Frame-Options");
  if (!csp) missingHeaders.push("Content-Security-Policy");
  if (!referrer) missingHeaders.push("Referrer-Policy");

  const exposedInfo = [];
  if (server) exposedInfo.push(`Server: ${server}`);
  if (poweredBy) exposedInfo.push(`X-Powered-By: ${poweredBy}`);

  return {
    server, poweredBy, contentType, strictTransport, xFrameOptions,
    xssProtection, csp, referrer, cors,
    missingSecurityHeaders: missingHeaders,
    exposedInfo,
    raw: headers,
  };
}

function parseOpenPorts(raw) {
  if (!Array.isArray(raw)) return [];
  return raw;
}

function parseEndpoints(raw) {
  if (!Array.isArray(raw)) return [];
  return raw;
}

// ==========================
// 🔹 RISK SCORING
// ==========================
function calculateRisk(output) {
  let score = 0;
  const findings = [];

  // SSL
  if (!output.ssl.valid) { score += 3; findings.push("No valid SSL/TLS certificate"); }
  else if (output.ssl.daysRemaining < 30) { score += 2; findings.push(`SSL expires in ${output.ssl.daysRemaining} days`); }

  // Headers
  const mh = output.headers.missingSecurityHeaders || [];
  if (mh.length >= 3) { score += 2; findings.push(`${mh.length} critical security headers missing`); }
  else if (mh.length > 0) { score += 1; }

  if (output.headers.poweredBy?.includes("PHP/5") || output.headers.poweredBy?.includes("PHP/4")) {
    score += 3; findings.push("Outdated PHP version exposed");
  }
  if (output.headers.cors === "*") { score += 2; findings.push("Wildcard CORS policy detected"); }

  // Endpoints
  if (output.endpoints.length > 30) { score += 2; findings.push(`${output.endpoints.length} parameterized endpoints exposed`); }
  else if (output.endpoints.length > 15) { score += 1; }

  // Ports
  const dangerousPorts = [21, 23, 25, 3306];
  const openDangerous = output.openPorts.filter(p => dangerousPorts.includes(p.port));
  if (openDangerous.length > 0) { score += 2; findings.push(`Dangerous ports open: ${openDangerous.map(p => p.name).join(", ")}`); }

  // SecurityTrails
  if (output.securityTrails.subdomainCount > 30) { score += 2; findings.push("Large attack surface via subdomains"); }
  else if (output.securityTrails.subdomainCount > 10) { score += 1; }

  // Email Intelligence — DNSBL
  if (output.emailIntelligence?.dnsbl?.listCount > 1) { score += 3; findings.push(`Domain blacklisted on ${output.emailIntelligence.dnsbl.listCount} DNS blocklists`); }
  else if (output.emailIntelligence?.blacklisted) { score += 2; findings.push(`Domain listed on ${output.emailIntelligence.dnsbl.listedOn?.[0]}`); }

  // Traceroute
  if (output.traceroute && output.traceroute.totalHops > 20) { score += 1; }

  // Shodan CVEs
  if (output.shodan?.vulnCount > 0) { score += 3; findings.push(`${output.shodan.vulnCount} CVEs found via Shodan`); }
  else if (output.shodan?.portCount > 10) { score += 1; }

  // Google Safe Browsing
  if (output.safeBrowsing?.threatCount > 0) { score += 4; findings.push(`Flagged by Google Safe Browsing: ${output.safeBrowsing.threats?.join(", ")}`); }

  // VirusTotal
  if (output.virusTotal?.malicious > 5) { score += 3; findings.push(`${output.virusTotal.malicious} AV engines flagged domain`); }
  else if (output.virusTotal?.malicious > 0) { score += 2; findings.push(`${output.virusTotal.malicious} AV engine(s) flagged domain`); }

  // Cookies
  if (output.cookies?.issues?.length > 4) { score += 1; findings.push("Multiple insecure cookie flags detected"); }

  let risk;
  if (score >= 10) risk = "CRITICAL";
  else if (score >= 7) risk = "HIGH";
  else if (score >= 4) risk = "MEDIUM";
  else risk = "LOW";

  return { risk, score, findings };
}

// ==========================
// 🔹 SUBDOMAIN ENUMERATION
// ==========================
async function crtshSubdomains(hostname) {
  const parts = hostname.split(".");
  // Handle multi-part TLDs: .ac.in, .co.uk, .com.au, .org.uk etc.
  // If the second-to-last part is a known SLD (ac, co, org, net, gov, edu), use last 3 parts
  const secondLevelTLDs = ["ac", "co", "com", "org", "net", "gov", "edu", "sch", "nhs", "police", "mod"];
  let rootDomain;
  if (parts.length > 2 && secondLevelTLDs.includes(parts[parts.length - 2])) {
    // e.g. cek.ac.in -> rootDomain = cek.ac.in (scan for subdomains OF this)
    rootDomain = parts.slice(-3).join(".");
  } else {
    rootDomain = parts.length > 2 ? parts.slice(-2).join(".") : hostname;
  }

  // Primary: HackerTarget — fast, no key, returns CSV "subdomain,ip"
  try {
    const res = await axios.get(
      `https://api.hackertarget.com/hostsearch/?q=${rootDomain}`,
      { timeout: 10000, headers: { "User-Agent": "Mozilla/5.0 (compatible; WebIntelX/1.0)" } }
    );
    const text = res.data || "";
    if (typeof text !== "string" || text.includes("API count exceeded") || text.includes("error detected")) {
      throw new Error("HackerTarget limit reached");
    }
    const subdomainSet = new Set();
    text.split("\n").forEach(line => {
      const subdomain = line.split(",")[0]?.trim().toLowerCase();
      if (subdomain && subdomain.endsWith(rootDomain) && subdomain !== rootDomain) {
        subdomainSet.add(subdomain);
      }
    });
    const subdomains = [...subdomainSet].sort();
    return { subdomains, count: subdomains.length, source: "HackerTarget" };
  } catch {
    // Fallback: crt.sh Certificate Transparency
    try {
      const res = await axios.get(
        `https://crt.sh/?q=%25.${rootDomain}&output=json`,
        { timeout: 8000, headers: { "User-Agent": "Mozilla/5.0 (compatible; WebIntelX/1.0)", "Accept": "application/json" } }
      );
      const entries = Array.isArray(res.data) ? res.data : [];
      const subdomainSet = new Set();
      entries.forEach(entry => {
        (entry.name_value || "").split("\n").forEach(name => {
          const cleaned = name.trim().toLowerCase().replace(/^\*\./, "");
          if (cleaned && cleaned.endsWith(rootDomain) && cleaned !== rootDomain && !cleaned.includes(" ")) {
            subdomainSet.add(cleaned);
          }
        });
      });
      const subdomains = [...subdomainSet].sort();
      return { subdomains, count: subdomains.length, source: "crt.sh" };
    } catch {
      return { subdomains: [], count: 0, error: "Subdomain lookup failed" };
    }
  }
}

// ==========================
// 🔹 SHODAN LOOKUP
// ==========================
async function shodanLookup(hostname) {
  const apiKey = process.env.SHODAN_API_KEY;
  if (!apiKey) return { available: false, note: "SHODAN_API_KEY not set" };
  try {
    const dnsRes = await axios.get(`https://dns.google/resolve?name=${hostname}&type=A`, { timeout: 5000 });
    const ip = dnsRes.data?.Answer?.[0]?.data;
    if (!ip) return { available: false, note: "Could not resolve IP for Shodan" };

    // Detect Cloudflare proxy IPs — Shodan won't have origin server data for these
    const cfRanges = ["104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.", "104.22.", "104.23.", "172.64.", "172.65.", "172.66.", "172.67.", "172.68.", "172.69.", "172.70.", "172.71."];
    const isCFProxy = cfRanges.some(r => ip.startsWith(r));
    if (isCFProxy) {
      return {
        available: true,
        ip,
        note: "Origin IP hidden behind Cloudflare proxy — Shodan data reflects Cloudflare infrastructure, not origin server",
        ports: [], vulns: [], vulnDetails: [], vulnCount: 0, kevCount: 0, criticalCount: 0,
        tags: ["cloudflare-proxy"], org: "Cloudflare, Inc.", risk: "LOW",
      };
    }

    const res = await axios.get(`https://api.shodan.io/shodan/host/${ip}?key=${apiKey}`, { timeout: 8000 });
    const d = res.data;
    const ports = d.ports || [];

    const vulnIds = Array.isArray(d.vulns) ? d.vulns : Object.keys(d.vulns || {});

    const mergedVulnMap = {};
    (d.data || []).forEach(service => {
      if (service.vulns && typeof service.vulns === "object") {
        Object.assign(mergedVulnMap, service.vulns);
      }
    });

    const vulnDetails = vulnIds.map(cveId => {
      const v = mergedVulnMap[cveId] || {};
      return {
        id: cveId,
        cvss: v.cvss || null,
        epss: v.epss ? (v.epss * 100).toFixed(1) : null,
        kev: v.kev || false,
        summary: v.summary ? v.summary.substring(0, 180) : null,
      };
    }).sort((a, b) => (b.cvss || 0) - (a.cvss || 0));

    const kevCount = vulnDetails.filter(v => v.kev).length;
    const criticalCVEs = vulnDetails.filter(v => v.cvss >= 9.0);
    const highCVEs = vulnDetails.filter(v => v.cvss >= 7.0 && v.cvss < 9.0);

    const banners = (d.data || []).slice(0, 5).map(s => ({
      port: s.port,
      transport: s.transport,
      product: s.product || null,
      version: s.version || null,
    }));

    const orgStr = `${d.org || ""} ${d.isp || ""} ${d.asn || ""}`;
    const isCloud = ["Amazon", "AWS", "Google", "Microsoft", "Azure", "Cloudflare",
      "DigitalOcean", "Linode", "Vultr", "OVH", "Hetzner", "Fastly"].some(p => orgStr.includes(p));

    return {
      available: true,
      ip,
      org: d.org || "Unknown",
      isp: d.isp || "Unknown",
      asn: d.asn || null,
      country: d.country_name || null,
      city: d.city || null,
      os: d.os || null,
      ports,
      portCount: ports.length,
      vulns: vulnIds,
      vulnDetails,
      vulnCount: vulnIds.length,
      kevCount,
      criticalCount: criticalCVEs.length,
      highCount: highCVEs.length,
      banners,
      lastSeen: d.last_update || null,
      tags: d.tags || [],
      hostnames: (d.hostnames || []).slice(0, 3),
      isCloud,
      risk: kevCount > 0 ? "CRITICAL" : vulnIds.length > 0 ? "HIGH" : ports.length > 10 ? "MEDIUM" : "LOW",
    };
  } catch (err) {
    if (err.response?.status === 404) return { available: true, ip: null, note: "Host not indexed by Shodan", ports: [], vulns: [], vulnDetails: [], vulnCount: 0, kevCount: 0, criticalCount: 0, risk: "LOW" };
    if (err.response?.status === 401) return { available: false, note: "Invalid Shodan API key" };
    if (err.response?.status === 429) return { available: false, note: "Shodan API rate limit reached" };
    // Clean error message — don't expose raw axios error
    const msg = err.response?.data?.error || err.message || "Shodan lookup failed";
    return { available: false, note: msg };
  }
}

// ==========================
// 🔹 GOOGLE SAFE BROWSING
// ==========================
async function googleSafeBrowsing(url) {
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_KEY;
  if (!apiKey) return { available: false, note: "GOOGLE_SAFE_BROWSING_KEY not set" };
  try {
    const res = await axios.post(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
      {
        client: { clientId: "webintelx", clientVersion: "1.0" },
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url }],
        },
      },
      { timeout: 8000 }
    );
    const matches = res.data?.matches || [];
    const threats = matches.map(m => m.threatType);
    return {
      available: true,
      safe: threats.length === 0,
      threats,
      threatCount: threats.length,
      risk: threats.length > 0 ? "CRITICAL" : "LOW",
      note: threats.length > 0 ? `Flagged for: ${threats.join(", ")}` : "No threats detected by Google Safe Browsing",
    };
  } catch {
    return { available: false, note: "Google Safe Browsing check failed" };
  }
}

// ==========================
// 🔹 VIRUSTOTAL
// ==========================
async function virusTotalScan(domain) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) return { available: false, note: "VIRUSTOTAL_API_KEY not set" };
  try {
    const res = await axios.get(
      `https://www.virustotal.com/api/v3/domains/${domain}`,
      { headers: { "x-apikey": apiKey }, timeout: 10000 }
    );
    const attr = res.data?.data?.attributes || {};
    const stats = attr.last_analysis_stats || {};
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const harmless = stats.harmless || 0;
    const total = malicious + suspicious + harmless + (stats.undetected || 0);
    const categories = attr.categories ? Object.values(attr.categories) : [];
    const uniqueCats = [...new Set(categories)].slice(0, 6);
    return {
      available: true,
      malicious, suspicious, harmless, total,
      communityScore: attr.reputation || 0,
      categories: uniqueCats,
      lastAnalysis: attr.last_analysis_date
        ? new Date(attr.last_analysis_date * 1000).toISOString().split("T")[0]
        : null,
      popularity: attr.popularity_ranks
        ? Object.entries(attr.popularity_ranks).map(([k, v]) => `${k}: #${v.rank}`).slice(0, 3)
        : [],
      risk: malicious > 5 ? "CRITICAL" : malicious > 0 || suspicious > 3 ? "HIGH" : suspicious > 0 ? "MEDIUM" : "LOW",
    };
  } catch (err) {
    if (err.response?.status === 404) return { available: true, malicious: 0, suspicious: 0, harmless: 0, total: 0, risk: "LOW", note: "Domain not in VirusTotal database" };
    if (err.response?.status === 403) return { available: false, note: "VirusTotal API quota exceeded or domain restricted — check your API key plan", warn: true };
    if (err.response?.status === 429) return { available: false, note: "VirusTotal rate limit reached — free tier allows 4 requests/min", warn: true };
    return { available: false, note: `VirusTotal scan failed: ${err.message}` };
  }
}

// ==========================
// 🔹 ASN & GEOLOCATION
// ==========================
async function asnGeoLookup(hostname) {
  try {
    // Resolve to IPv4 first — ip-api.com may return IPv6 geolocation if hostname resolves to AAAA
    let lookupTarget = hostname;
    try {
      const dnsRes = await axios.get(`https://dns.google/resolve?name=${hostname}&type=A`, { timeout: 5000 });
      const ipv4 = dnsRes.data?.Answer?.[0]?.data;
      if (ipv4 && /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ipv4)) {
        lookupTarget = ipv4;
      }
    } catch { /* fallback to hostname */ }

    const res = await axios.get(
      `http://ip-api.com/json/${lookupTarget}?fields=status,message,country,countryCode,region,regionName,city,lat,lon,timezone,isp,org,as,query`,
      { timeout: 8000 }
    );
    const d = res.data;
    if (d.status === "fail") throw new Error(d.message || "Lookup failed");
    const orgStr = `${d.org || ""} ${d.isp || ""} ${d.as || ""}`;
    const cloudProviders = ["Amazon", "AWS", "Google", "Microsoft", "Azure", "Cloudflare",
      "DigitalOcean", "Linode", "Vultr", "OVH", "Hetzner", "Fastly"];
    const matchedProvider = cloudProviders.find(p => orgStr.includes(p));
    const isCloud = !!matchedProvider;
    // Use org name directly instead of concatenating strings (avoids duplication)
    const cloudProvider = isCloud ? (d.org || d.isp || matchedProvider) : null;
    return {
      available: true,
      ip: d.query,
      city: d.city || null,
      region: d.regionName || null,
      country: d.country || null,
      countryCode: d.countryCode || null,
      latitude: d.lat || null,
      longitude: d.lon || null,
      org: d.org || null,
      asn: d.as || null,
      isp: d.isp || null,
      timezone: d.timezone || null,
      isCloud,
      cloudProvider,
      risk: "LOW",
    };
  } catch {
    return { available: false, note: "Geolocation lookup failed" };
  }
}

// ==========================
// 🔹 HTTP COOKIES ANALYSIS
// ==========================
async function cookiesAnalysis(url) {
  try {
    const res = await axios.get(url, {
      timeout: 8000,
      maxRedirects: 3,
      validateStatus: () => true,
    });
    const setCookieHeaders = res.headers["set-cookie"] || [];
    if (!setCookieHeaders.length) {
      return { available: true, cookieCount: 0, cookies: [], issues: [], risk: "LOW", note: "No cookies set by server" };
    }
    const cookies = setCookieHeaders.map(raw => {
      const parts = raw.split(";").map(p => p.trim());
      const [nameVal, ...directives] = parts;
      const [name] = nameVal.split("=");
      const dirs = directives.map(d => d.toLowerCase());
      return {
        name: name.trim(),
        secure: dirs.some(d => d === "secure"),
        httpOnly: dirs.some(d => d === "httponly"),
        sameSite: dirs.find(d => d.startsWith("samesite"))?.split("=")[1] || null,
        path: dirs.find(d => d.startsWith("path="))?.split("=")[1] || "/",
        expires: dirs.find(d => d.startsWith("expires="))?.substring(8) || null,
      };
    });
    const issues = [];
    cookies.forEach(c => {
      if (!c.secure) issues.push(`"${c.name}" missing Secure flag — sent over HTTP`);
      if (!c.httpOnly) issues.push(`"${c.name}" missing HttpOnly — accessible via JavaScript`);
      if (!c.sameSite) issues.push(`"${c.name}" missing SameSite — vulnerable to CSRF`);
    });
    return {
      available: true,
      cookieCount: cookies.length,
      cookies,
      issues,
      risk: issues.length > 4 ? "HIGH" : issues.length > 0 ? "MEDIUM" : "LOW",
    };
  } catch {
    return { available: false, note: "Cookie analysis failed" };
  }
}

// ==========================
// 🔹 GREEN WEB / CARBON
// ==========================
async function greenWebCheck(hostname) {
  try {
    const res = await axios.get(
      `https://api.thegreenwebfoundation.org/api/v3/greencheck/${hostname}`,
      { timeout: 8000 }
    );
    const d = res.data;
    return {
      available: true,
      green: d.green === true,
      hostedBy: d.hosted_by || null,
      hostedByWebsite: d.hosted_by_website || null,
      note: d.green
        ? `Hosted on green energy by ${d.hosted_by || "verified provider"}`
        : "Not verified as green hosted",
      risk: "LOW",
    };
  } catch {
    return { available: false, note: "Green web check failed" };
  }
}

// ==========================
// 🔹 WAPPALYZER
// ==========================
function runWappalyzer(url) {
  return new Promise((resolve) => {
    exec(`python utils/wappalyzer_scan.py ${url}`, (err, stdout) => {
      if (err) return resolve({});
      try { resolve(JSON.parse(stdout)); } catch { resolve({}); }
    });
  });
}

// ==========================
// 🔹 MAIN EXPORT
// ==========================
exports.quickScan = async (req, res) => {
  const { url } = req.body;

  const validation = await validateTarget(url);
  if (!validation.valid) {
    return res.json({ success: false, error: validation.error });
  }

  if (!url) {
    return res.status(400).json({ success: false, error: "URL is required" });
  }

  const cleanedUrl = cleanUrl(url);

  let hostname;
  try {
    hostname = new URL(cleanedUrl).hostname;
  } catch {
    return res.status(400).json({ success: false, error: "Invalid URL format" });
  }

  try {
    // Run core scanners in parallel
    const results = await Promise.allSettled([
      scanner.nslookup(hostname),        // 0
      scanner.ping(hostname),            // 1
      scanner.headers(cleanedUrl),       // 2
      scanner.portScan(hostname),        // 3
      scanner.ssl(hostname),             // 4 — ssl-checker needs bare hostname
      scanner.endpointScan(cleanedUrl),  // 5
      scanner.whatweb(cleanedUrl),       // 6
      fetchWhoisRDAP(hostname),          // 7
      scanner.traceroute(hostname),      // 8
      emailIntelligence(hostname),       // 9 — DNSBL + Hunter
    ]);

    // OSINT modules in parallel
    const osintResults = await Promise.allSettled([
      shodanLookup(hostname),            // 0
      googleSafeBrowsing(cleanedUrl),    // 1
      virusTotalScan(hostname),          // 2
      asnGeoLookup(hostname),            // 3
      cookiesAnalysis(cleanedUrl),       // 4
      greenWebCheck(hostname),           // 5
    ]);
    const safeOsint = (r) => r.status === "fulfilled" ? r.value : { available: false, note: "Module failed" };

    const wappalyzerResult = await runWappalyzer(cleanedUrl);

    // Subdomain enumeration via crt.sh (Certificate Transparency — free, no key)
    let securityTrailsResult = { subdomains: [], count: 0 };
    let securityTrailsRisk = "LOW";
    try {
      securityTrailsResult = await crtshSubdomains(hostname);
      const subCount = securityTrailsResult.subdomains.length;
      if (subCount > 30) securityTrailsRisk = "HIGH";
      else if (subCount > 10) securityTrailsRisk = "MEDIUM";
    } catch {
      securityTrailsResult = { subdomains: [], count: 0, error: "crt.sh unavailable" };
    }

    const safe = (r) => r.status === "fulfilled" ? r.value : null;

    const parsedDns       = parseDns(safe(results[0]));
    const parsedPing      = parsePing(safe(results[1]));
    const parsedHeaders   = parseHeaders(safe(results[2]));
    const parsedPorts     = parseOpenPorts(safe(results[3]));
    const parsedSSL       = parseSSL(safe(results[4]));
    const parsedEndpoints = parseEndpoints(safe(results[5]));
    const rawWhatweb      = safe(results[6]);
    const parsedWhois     = parseWhois(safe(results[7]));
    const parsedTraceroute = parseTraceroute(safe(results[8]));
    const emailIntel      = safe(results[9]);

    const securityTrails = {
      scanType: "passive",
      risk: securityTrailsRisk,
      subdomainCount: securityTrailsResult?.subdomains?.length || 0,
      subdomains: securityTrailsResult?.subdomains || [],
      note: `Subdomain enumeration via ${securityTrailsResult?.source || "passive DNS"}`,
    };

    const output = {
      dns: parsedDns,
      ping: parsedPing,
      headers: parsedHeaders,
      openPorts: parsedPorts,
      ssl: parsedSSL,
      endpoints: parsedEndpoints,
      whatweb: rawWhatweb,
      whois: parsedWhois,
      traceroute: parsedTraceroute,
      emailIntelligence: emailIntel || { risk: "LOW", dnsbl: { listed: false, listedOn: [] }, hunter: { available: false } },
      wappalyzer: wappalyzerResult,
      securityTrails,
      // OSINT modules
      shodan:       safeOsint(osintResults[0]),
      safeBrowsing: safeOsint(osintResults[1]),
      virusTotal:   safeOsint(osintResults[2]),
      asnGeo:       safeOsint(osintResults[3]),
      cookies:      safeOsint(osintResults[4]),
      greenWeb:     safeOsint(osintResults[5]),
    };

    const riskAssessment = calculateRisk(output);

    return res.json({
      success: true,
      message: "Quick scan completed",
      target: hostname,
      riskAssessment,
      data: output,
    });

  } catch (err) {
    console.error("QuickScan Fatal Error:", err);
    return res.status(500).json({ success: false, error: "Quick Scan crashed" });
  }
};