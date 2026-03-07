// controllers/wordpressController.js

const axios = require("axios");
const { exec } = require("child_process");
const path = require("path");

// ─── Wappalyzer via Python script ────────────────────────────────────────────

function runWappalyzer(url) {
  return new Promise((resolve) => {
    const scriptPath = path.join(__dirname, "../utils/wappalyzer_scan.py");
    exec(`python "${scriptPath}" "${url}"`, { timeout: 30000 }, (err, stdout) => {
      if (err || !stdout) return resolve({});
      try { resolve(JSON.parse(stdout.trim())); }
      catch { resolve({}); }
    });
  });
}

// ─── Known vulnerable plugin versions (manually maintained) ─────────────────
const KNOWN_VULNERABLE_PLUGINS = {
  "contact-form-7": { vulnerableBelow: "5.3.2", issue: "Unrestricted file upload (CVE-2020-35489)", severity: "CRITICAL" },
  "woocommerce": { vulnerableBelow: "5.5.1", issue: "SQL Injection vulnerability", severity: "HIGH" },
  "elementor": { vulnerableBelow: "3.1.4", issue: "Stored XSS vulnerability", severity: "HIGH" },
  "wpforms-lite": { vulnerableBelow: "1.6.2", issue: "Reflected XSS vulnerability", severity: "MEDIUM" },
  "wordfence": { vulnerableBelow: "7.4.9", issue: "Authentication bypass vulnerability", severity: "HIGH" },
  "yoast-seo": { vulnerableBelow: "15.2", issue: "Stored XSS via SEO fields", severity: "MEDIUM" },
  "akismet": { vulnerableBelow: "4.1.6", issue: "XSS in comment fields", severity: "MEDIUM" },
  "jetpack": { vulnerableBelow: "9.4", issue: "Information disclosure", severity: "MEDIUM" },
  "really-simple-ssl": { vulnerableBelow: "5.0.5", issue: "Privilege escalation", severity: "HIGH" },
  "wp-super-cache": { vulnerableBelow: "1.7.2", issue: "RCE via cache directory", severity: "CRITICAL" },
  "updraftplus": { vulnerableBelow: "1.16.69", issue: "CSRF in backup settings", severity: "MEDIUM" },
  "wpml": { vulnerableBelow: "4.4.0", issue: "Remote Code Execution", severity: "CRITICAL" },
  "wp-file-manager": { vulnerableBelow: "6.9", issue: "Unauthenticated RCE (CVE-2020-25213)", severity: "CRITICAL" },
  "duplicator": { vulnerableBelow: "1.3.28", issue: "Directory traversal vulnerability", severity: "HIGH" },
  "wp-fastest-cache": { vulnerableBelow: "0.9.5", issue: "SQL injection via cookie", severity: "HIGH" },
};

// ─── Known vulnerable WP core versions ──────────────────────────────────────
const VULNERABLE_WP_VERSIONS = {
  "6.3": { issue: "XSS via post links", severity: "MEDIUM", fixedIn: "6.3.2" },
  "6.2": { issue: "Multiple XSS vulnerabilities", severity: "HIGH", fixedIn: "6.2.2" },
  "6.1": { issue: "SQL Injection in WP_Query", severity: "HIGH", fixedIn: "6.1.2" },
  "6.0": { issue: "Open Redirect vulnerability", severity: "MEDIUM", fixedIn: "6.0.3" },
  "5.9": { issue: "Stored XSS in Gutenberg blocks", severity: "HIGH", fixedIn: "5.9.3" },
  "5.8": { issue: "Object injection in PHPMailer", severity: "HIGH", fixedIn: "5.8.3" },
  "5.7": { issue: "SSRF via pingback", severity: "HIGH", fixedIn: "5.7.2" },
  "5.6": { issue: "Auth bypass in REST API", severity: "CRITICAL", fixedIn: "5.6.2" },
  "5.5": { issue: "XXE in post import", severity: "HIGH", fixedIn: "5.5.3" },
  "5.4": { issue: "Stored XSS in customizer", severity: "MEDIUM", fixedIn: "5.4.2" },
  "5.3": { issue: "Privilege escalation", severity: "HIGH", fixedIn: "5.3.4" },
  "5.2": { issue: "XSS in admin", severity: "MEDIUM", fixedIn: "5.2.4" },
  "5.1": { issue: "CSRF to XSS in comments", severity: "HIGH", fixedIn: "5.1.2" },
  "5.0": { issue: "Path traversal in unzip", severity: "HIGH", fixedIn: "5.0.4" },
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

function normalizeUrl(url) {
  if (!url.startsWith("http://") && !url.startsWith("https://")) url = "https://" + url;
  return url.replace(/\/$/, "");
}

function compareVersions(v1, v2) {
  const p1 = v1.split(".").map(Number);
  const p2 = v2.split(".").map(Number);
  for (let i = 0; i < Math.max(p1.length, p2.length); i++) {
    const a = p1[i] || 0, b = p2[i] || 0;
    if (a < b) return -1;
    if (a > b) return 1;
  }
  return 0;
}

async function fetchPage(url, timeout = 10000) {
  try {
    return await axios.get(url, {
      timeout,
      maxRedirects: 3,
      headers: { "User-Agent": "Mozilla/5.0 (WebIntelX Security Scanner)" },
      validateStatus: () => true,
    });
  } catch {
    return null;
  }
}

// ─── 1. Detect WordPress ─────────────────────────────────────────────────────

async function isWordPress(baseUrl) {
  const res = await fetchPage(baseUrl);
  const html = res?.data || "";
  const indicators = [];

  if (html.includes("wp-content")) indicators.push("wp-content path detected");
  if (html.includes("wp-includes")) indicators.push("wp-includes path detected");
  if (html.match(/content="WordPress/i)) indicators.push("WordPress meta generator tag found");

  const loginRes = await fetchPage(`${baseUrl}/wp-login.php`);
  if (loginRes?.status === 200 && loginRes.data.includes("wp-login"))
    indicators.push("wp-login.php is accessible");

  return { detected: indicators.length > 0, indicators };
}

// ─── 2. Core Version Detection ───────────────────────────────────────────────

async function detectCoreVersion(baseUrl) {
  const result = { version: null, source: null, vulnerabilities: [], recommendation: null };

  const sources = [
    { url: `${baseUrl}/readme.html`, regex: /Version\s+([\d.]+)/i, label: "readme.html (should be deleted)" },
    { url: `${baseUrl}/feed`, regex: /generator>.*?v=([\d.]+)/i, label: "RSS Feed" },
    { url: baseUrl, regex: /content="WordPress ([\d.]+)"/i, label: "HTML meta generator" },
    { url: `${baseUrl}/wp-includes/version.php`, regex: /\$wp_version\s*=\s*'([\d.]+)'/, label: "version.php (critical exposure!)" },
  ];

  for (const src of sources) {
    if (result.version) break;
    const res = await fetchPage(src.url);
    if (res?.status === 200) {
      const match = res.data.match(src.regex);
      if (match) { result.version = match[1]; result.source = src.label; }
    }
  }

  if (result.version) {
    const majorMinor = result.version.split(".").slice(0, 2).join(".");
    const vuln = VULNERABLE_WP_VERSIONS[majorMinor];
    if (vuln) {
      result.vulnerabilities.push({ issue: vuln.issue, severity: vuln.severity, fixedIn: vuln.fixedIn });
      result.recommendation = `Update WordPress to ${vuln.fixedIn} or later immediately.`;
    } else {
      result.recommendation = "WordPress version appears up to date. Keep it updated regularly.";
    }
  }

  return result;
}

// ─── 3. Plugin Enumeration ───────────────────────────────────────────────────

async function enumeratePlugins(baseUrl) {
  const found = new Set();

  const home = await fetchPage(baseUrl);
  if (home) {
    const regex = /wp-content\/plugins\/([\w-]+)\//g;
    let match;
    while ((match = regex.exec(home.data)) !== null) found.add(match[1]);
  }

  await Promise.all(
    Object.keys(KNOWN_VULNERABLE_PLUGINS).map(async (slug) => {
      if (!found.has(slug)) {
        const res = await fetchPage(`${baseUrl}/wp-content/plugins/${slug}/readme.txt`, 5000);
        if (res?.status === 200 && res.data.length > 50) found.add(slug);
      }
    })
  );

  const plugins = [];
  for (const slug of found) {
    const info = { slug, version: null, vulnerabilities: [], severity: "INFO", recommendation: null };

    const readme = await fetchPage(`${baseUrl}/wp-content/plugins/${slug}/readme.txt`, 5000);
    if (readme?.status === 200) {
      const verMatch = readme.data.match(/Stable tag:\s*([\d.]+)/i);
      if (verMatch) info.version = verMatch[1];
    }

    const known = KNOWN_VULNERABLE_PLUGINS[slug];
    if (known) {
      const isVulnerable = !info.version || compareVersions(info.version, known.vulnerableBelow) < 0;
      if (isVulnerable) {
        info.vulnerabilities.push({
          issue: info.version ? known.issue : `${known.issue} (version unknown)`,
          severity: info.version ? known.severity : "MEDIUM",
          affectedBelow: known.vulnerableBelow,
        });
        info.severity = info.version ? known.severity : "MEDIUM";
        info.recommendation = `Update ${slug} to version ${known.vulnerableBelow} or later.`;
      }
    }

    plugins.push(info);
  }

  return plugins;
}

// ─── 4. Theme Detection ──────────────────────────────────────────────────────

async function detectTheme(baseUrl) {
  const result = { name: null, version: null, author: null, vulnerabilities: [], recommendation: null };

  const home = await fetchPage(baseUrl);
  if (!home) return result;

  const match = home.data.match(/wp-content\/themes\/([\w-]+)\//);
  if (!match) return result;
  result.name = match[1];

  const style = await fetchPage(`${baseUrl}/wp-content/themes/${result.name}/style.css`, 5000);
  if (style?.status === 200) {
    const ver = style.data.match(/Version:\s*([\d.]+)/i);
    const author = style.data.match(/Author:\s*(.+)/i);
    if (ver) result.version = ver[1];
    if (author) result.author = author[1].trim();
  }

  const phpFile = await fetchPage(`${baseUrl}/wp-content/themes/${result.name}/functions.php`, 5000);
  if (phpFile?.status === 200 && phpFile.data.includes("<?php")) {
    result.vulnerabilities.push({ issue: "Theme PHP source files are publicly readable", severity: "HIGH" });
    result.recommendation = "Restrict access to PHP files via .htaccess rules.";
  }

  return result;
}

// ─── 5. User Enumeration ─────────────────────────────────────────────────────

async function enumerateUsers(baseUrl) {
  const users = [];

  const rest = await fetchPage(`${baseUrl}/wp-json/wp/v2/users`, 8000);
  if (rest?.status === 200) {
    try {
      const data = JSON.parse(rest.data);
      if (Array.isArray(data)) data.forEach((u) => users.push({ id: u.id, name: u.name, slug: u.slug, source: "REST API" }));
    } catch {}
  }

  for (let i = 1; i <= 5; i++) {
    const res = await fetchPage(`${baseUrl}/?author=${i}`, 5000);
    if (res?.status === 200) {
      const m = res.data.match(/class="author[^"]*"[^>]*>([^<]+)</i);
      if (m && !users.find((u) => u.name === m[1].trim()))
        users.push({ id: i, name: m[1].trim(), source: "Author archive" });
    }
  }

  const oembed = await fetchPage(`${baseUrl}/wp-json/oembed/1.0/embed?url=${baseUrl}`, 5000);
  if (oembed?.status === 200) {
    try {
      const d = JSON.parse(oembed.data);
      if (d.author_name && !users.find((u) => u.name === d.author_name))
        users.push({ name: d.author_name, source: "oEmbed API" });
    } catch {}
  }

  return {
    exposed: users.length > 0,
    users,
    risk: users.length > 0 ? "HIGH" : "LOW",
    recommendation: users.length > 0
      ? "Disable REST API user listing. Add 'remove_action(\"init\", \"rest_api_init\")' or restrict with a plugin."
      : "User enumeration not detected.",
  };
}

// ─── 6. Login Page Exposure ──────────────────────────────────────────────────

async function checkLoginExposure(baseUrl) {
  const loginRes = await fetchPage(`${baseUrl}/wp-login.php`);
  const adminRes = await fetchPage(`${baseUrl}/wp-admin`);

  const wpLoginExposed = loginRes?.status === 200 && loginRes.data.includes("wp-login");
  const wpAdminAccessible = adminRes && [200, 302].includes(adminRes.status);
  const noProtection = wpLoginExposed &&
    !loginRes.data.includes("locked") &&
    !loginRes.data.includes("captcha") &&
    !loginRes.data.includes("recaptcha");

  return {
    wpLoginExposed,
    wpAdminAccessible,
    bruteForceProtection: !noProtection,
    risk: wpLoginExposed ? "MEDIUM" : "LOW",
    recommendation: wpLoginExposed
      ? "Hide wp-login.php, enable 2FA, and add brute-force protection (e.g., Wordfence or Loginizer)."
      : "Login page is not directly exposed.",
  };
}

// ─── 7. XML-RPC Check ────────────────────────────────────────────────────────

async function checkXmlRpc(baseUrl) {
  const res = await fetchPage(`${baseUrl}/xmlrpc.php`);
  const enabled = res?.status === 200 &&
    (res.data.includes("XML-RPC server accepts POST requests only") || res.data.includes("xmlrpc"));

  let multicallEnabled = false;
  if (enabled) {
    try {
      const test = await axios.post(
        `${baseUrl}/xmlrpc.php`,
        `<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>`,
        { headers: { "Content-Type": "text/xml" }, timeout: 8000, validateStatus: () => true }
      );
      if (test.data.includes("system.multicall")) multicallEnabled = true;
    } catch {}
  }

  return {
    enabled,
    multicallEnabled,
    risk: enabled ? (multicallEnabled ? "CRITICAL" : "HIGH") : "LOW",
    recommendation: enabled
      ? "Disable XML-RPC in .htaccess: <Files xmlrpc.php><Order Deny,Allow><Deny from all></Files>"
      : "XML-RPC is disabled — good.",
  };
}

// ─── 8. Directory Listing ────────────────────────────────────────────────────

async function checkDirectoryListing(baseUrl) {
  const paths = ["/wp-content/uploads/", "/wp-content/plugins/", "/wp-content/themes/", "/wp-includes/"];
  const exposed = [];

  await Promise.all(paths.map(async (path) => {
    const res = await fetchPage(`${baseUrl}${path}`, 5000);
    if (res?.status === 200 &&
      (res.data.toLowerCase().includes("index of") ||
        res.data.includes("Parent Directory") ||
        res.data.includes("Last modified"))) {
      exposed.push(path);
    }
  }));

  return {
    exposed: exposed.length > 0,
    exposedPaths: exposed,
    risk: exposed.length > 0 ? "HIGH" : "LOW",
    recommendation: exposed.length > 0
      ? `Add 'Options -Indexes' to .htaccess. Exposed: ${exposed.join(", ")}`
      : "Directory listing is properly disabled.",
  };
}

// ─── 9. Sensitive File Exposure ──────────────────────────────────────────────

async function checkSensitiveFiles(baseUrl) {
  const files = [
    { path: "/wp-config.php.bak", risk: "CRITICAL", desc: "WordPress config backup" },
    { path: "/wp-config.php~", risk: "CRITICAL", desc: "WordPress config temp file" },
    { path: "/.env", risk: "CRITICAL", desc: "Environment variables file" },
    { path: "/.git/config", risk: "CRITICAL", desc: "Git repository config exposed" },
    { path: "/readme.html", risk: "LOW", desc: "WordPress readme (reveals version)" },
    { path: "/license.txt", risk: "LOW", desc: "License file (reveals version)" },
    { path: "/debug.log", risk: "HIGH", desc: "WordPress debug log exposed" },
    { path: "/wp-content/debug.log", risk: "HIGH", desc: "Debug log in wp-content" },
    { path: "/phpinfo.php", risk: "HIGH", desc: "PHP info page exposed" },
    { path: "/wp-json/wp/v2/users", risk: "HIGH", desc: "REST API user list exposed" },
  ];

  const found = [];
  await Promise.all(files.map(async (f) => {
    const res = await fetchPage(`${baseUrl}${f.path}`, 5000);
    if (res?.status === 200 && res.data.length > 10) found.push({ ...f });
  }));

  return {
    exposed: found.length > 0,
    files: found,
    risk: found.some((f) => f.risk === "CRITICAL") ? "CRITICAL" : found.length > 0 ? "HIGH" : "LOW",
    recommendation: found.length > 0
      ? "Immediately remove or restrict access to exposed sensitive files."
      : "No sensitive files publicly exposed.",
  };
}

// ─── 10. Security Headers ────────────────────────────────────────────────────

async function checkSecurityHeaders(baseUrl) {
  const res = await fetchPage(baseUrl);
  if (!res) return { checked: false };

  const headers = res.headers;
  const required = [
    { header: "x-frame-options", desc: "Prevents clickjacking attacks" },
    { header: "x-content-type-options", desc: "Prevents MIME type sniffing" },
    { header: "x-xss-protection", desc: "Browser XSS filter" },
    { header: "strict-transport-security", desc: "Enforces HTTPS (HSTS)" },
    { header: "content-security-policy", desc: "Prevents XSS and data injection" },
    { header: "referrer-policy", desc: "Controls referrer information leakage" },
  ];

  const present = [], missing = [];
  required.forEach((h) => {
    if (headers[h.header]) present.push({ header: h.header, value: headers[h.header] });
    else missing.push({ header: h.header, description: h.desc });
  });

  return {
    present,
    missing,
    risk: missing.length > 3 ? "HIGH" : missing.length > 1 ? "MEDIUM" : "LOW",
    recommendation: missing.length > 0
      ? `Add missing headers: ${missing.map((h) => h.header).join(", ")}`
      : "All key security headers are present.",
  };
}

// ─── Risk Score Calculator ───────────────────────────────────────────────────

function calculateRiskScore(results) {
  const w = { CRITICAL: 40, HIGH: 20, MEDIUM: 10, LOW: 2 };
  let score = 0;

  [
    results.userEnumeration?.risk,
    results.loginExposure?.risk,
    results.xmlRpc?.risk,
    results.directoryListing?.risk,
    results.sensitiveFiles?.risk,
    results.securityHeaders?.risk,
  ].forEach((r) => { if (r && w[r]) score += w[r]; });

  results.plugins?.forEach((p) => { if (p.severity && w[p.severity]) score += w[p.severity]; });
  if (results.coreVersion?.vulnerabilities?.length > 0) score += 30;

  const level = score >= 80 ? "CRITICAL" : score >= 50 ? "HIGH" : score >= 20 ? "MEDIUM" : "LOW";
  return { score: Math.min(score, 100), level };
}

// ─── Main Controller ─────────────────────────────────────────────────────────

exports.scanWordPress = async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: "URL is required." });

  const baseUrl = normalizeUrl(url);

  try {
    const wpCheck = await isWordPress(baseUrl);
    if (!wpCheck.detected) {
      return res.status(200).json({
        url: baseUrl,
        isWordPress: false,
        message: "This does not appear to be a WordPress site.",
        results: null,
      });
    }

    // Run all checks + Wappalyzer in parallel
    const [
      coreVersion,
      plugins,
      theme,
      userEnumeration,
      loginExposure,
      xmlRpc,
      directoryListing,
      sensitiveFiles,
      securityHeaders,
      techStack,
    ] = await Promise.all([
      detectCoreVersion(baseUrl),
      enumeratePlugins(baseUrl),
      detectTheme(baseUrl),
      enumerateUsers(baseUrl),
      checkLoginExposure(baseUrl),
      checkXmlRpc(baseUrl),
      checkDirectoryListing(baseUrl),
      checkSensitiveFiles(baseUrl),
      checkSecurityHeaders(baseUrl),
      runWappalyzer(baseUrl),   // ← Wappalyzer runs independently here
    ]);

    const results = {
      coreVersion,
      plugins,
      theme,
      userEnumeration,
      loginExposure,
      xmlRpc,
      directoryListing,
      sensitiveFiles,
      securityHeaders,
      techStack,              // ← attached to WP scan results
    };
    const riskScore = calculateRiskScore(results);

    return res.status(200).json({
      url: baseUrl,
      isWordPress: true,
      wpIndicators: wpCheck.indicators,
      riskScore,
      scannedAt: new Date().toISOString(),
      results,
    });
  } catch (err) {
    console.error("WordPress scan error:", err.message);
    return res.status(500).json({ error: "Scan failed.", details: err.message });
  }
};