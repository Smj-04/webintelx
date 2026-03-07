const PDFDocument = require("pdfkit");

// ─────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────
const riskColor = (r) => {
  if (r === "CRITICAL") return "#b91c1c";
  if (r === "HIGH")     return "#c2410c";
  if (r === "MEDIUM")   return "#b45309";
  return "#15803d";
};

const fmt = (v) => (v === undefined || v === null ? "N/A" : String(v));
const fmtDate = (v) => (v ? String(v).split("T")[0] : "N/A");

function sectionTitle(doc, title) {
  doc.moveDown(1)
    .fontSize(13)
    .fillColor("#1e3a5f")
    .text(title, { underline: true })
    .moveDown(0.4);
  doc.fontSize(10).fillColor("#111827");
}

function subTitle(doc, title) {
  doc.moveDown(0.6)
    .fontSize(11)
    .fillColor("#374151")
    .text(title)
    .moveDown(0.2);
  doc.fontSize(10).fillColor("#111827");
}

function row(doc, label, value, color) {
  doc.fontSize(10)
    .fillColor("#6b7280").text(`${label}:  `, { continued: true })
    .fillColor(color || "#111827").text(fmt(value));
}

function bullet(doc, text, color) {
  doc.fontSize(10).fillColor(color || "#111827").text(`• ${text}`);
}

function divider(doc) {
  doc.moveDown(0.5)
    .strokeColor("#e5e7eb")
    .lineWidth(0.5)
    .moveTo(50, doc.y)
    .lineTo(545, doc.y)
    .stroke()
    .moveDown(0.5);
}

function badge(doc, label, color) {
  const x = doc.x;
  const y = doc.y;
  doc.rect(x, y, label.length * 6.5 + 12, 14).fill(color || "#e5e7eb");
  doc.fontSize(8).fillColor("white").text(label, x + 6, y + 3, { lineBreak: false });
  doc.moveDown(1.2);
}

// ─────────────────────────────────────────────
// CLASSIFY FINDINGS
// ─────────────────────────────────────────────
function classifyFindings(scanData) {
  const findings = [];

  // SSL
  if (scanData.ssl?.valid) {
    findings.push({ title: "SSL/TLS Certificate Valid", classification: "Not a Vulnerability", type: "Informational", evidence: `Valid until ${fmtDate(scanData.ssl.validTo)}, ${scanData.ssl.daysRemaining} days remaining` });
  } else {
    findings.push({ title: "SSL/TLS Certificate Invalid or Missing", classification: "Vulnerability", type: "Security Misconfiguration", evidence: scanData.ssl?.error || "SSL check failed" });
  }

  // Security Headers
  const missing = scanData.headers?.missingSecurityHeaders || [];
  if (missing.length > 0) {
    findings.push({ title: "Missing Security Headers", classification: missing.length >= 3 ? "Security Weakness" : "Not a Vulnerability", type: "Security Misconfiguration", evidence: `Missing: ${missing.join(", ")}` });
  }

  // CORS
  if (scanData.headers?.cors === "*") {
    findings.push({ title: "Wildcard CORS Policy", classification: "Vulnerability", type: "Access Control", evidence: "Access-Control-Allow-Origin: * allows any origin" });
  }

  // Exposed Technology
  if (scanData.headers?.poweredBy) {
    findings.push({ title: "Backend Technology Disclosed", classification: "Security Weakness", type: "Information Disclosure", evidence: `X-Powered-By: ${scanData.headers.poweredBy}` });
  }

  // Open Ports
  const dangerousPorts = [21, 23, 25, 3306, 3389, 5432, 6379, 27017];
  const openDanger = (scanData.openPorts || []).filter(p => dangerousPorts.includes(p.port));
  if (openDanger.length > 0) {
    findings.push({ title: "Sensitive Ports Exposed", classification: "Vulnerability", type: "Network Exposure", evidence: `Open: ${openDanger.map(p => `${p.port}/${p.name}`).join(", ")}` });
  } else if ((scanData.openPorts || []).length > 0) {
    findings.push({ title: "Open Network Ports", classification: "Not a Vulnerability", type: "Exposure", evidence: `Ports open: ${scanData.openPorts.map(p => p.port).join(", ")}` });
  }

  // Subdomains
  const subCount = scanData.securityTrails?.subdomainCount || 0;
  if (subCount > 30) {
    findings.push({ title: "Large Attack Surface", classification: "Security Weakness", type: "Exposure", evidence: `${subCount} subdomains discovered` });
  } else if (subCount > 0) {
    findings.push({ title: "Subdomains Discovered", classification: "Not a Vulnerability", type: "Informational", evidence: `${subCount} subdomains via passive DNS` });
  }

  // Endpoints
  if ((scanData.endpoints || []).length > 0) {
    findings.push({ title: "Parameterized Endpoints Detected", classification: "Not a Vulnerability", type: "Informational", evidence: `${scanData.endpoints.length} URLs with parameters` });
  }

  // VirusTotal
  if (scanData.virusTotal?.available && scanData.virusTotal?.malicious > 0) {
    findings.push({ title: "Malicious Domain Flags", classification: "Vulnerability", type: "Threat Intelligence", evidence: `${scanData.virusTotal.malicious}/${scanData.virusTotal.total} engines flagged domain` });
  }

  // Google Safe Browsing
  if (scanData.safeBrowsing?.available && !scanData.safeBrowsing?.safe) {
    findings.push({ title: "Google Safe Browsing Threat", classification: "Vulnerability", type: "Threat Intelligence", evidence: `Threats: ${scanData.safeBrowsing.threats?.join(", ")}` });
  }

  // Shodan CVEs
  if (scanData.shodan?.vulnCount > 0) {
    findings.push({ title: "Known CVEs on Host", classification: "Vulnerability", type: "Vulnerability Intelligence", evidence: `${scanData.shodan.vulnCount} CVEs detected via Shodan${scanData.shodan.kevCount > 0 ? `, ${scanData.shodan.kevCount} CISA KEV` : ""}` });
  }

  // DNSBL
  if (scanData.emailIntelligence?.dnsbl?.listed) {
    findings.push({ title: "Domain on DNS Blocklist", classification: "Security Weakness", type: "Reputation Risk", evidence: `Listed on: ${(scanData.emailIntelligence.dnsbl.listedOn || []).join(", ")}` });
  }

  // Cookies
  if ((scanData.cookies?.issues || []).length > 0) {
    findings.push({ title: "Insecure Cookie Configuration", classification: "Security Weakness", type: "Session Security", evidence: `${scanData.cookies.issues.length} cookie security issue(s) detected` });
  }

  return findings;
}

// ─────────────────────────────────────────────
// MAIN EXPORT
// ─────────────────────────────────────────────
exports.generateQuickScanPDF = async (req, res) => {
  try {
    const { scanData, target, riskAssessment } = req.body;
    if (!scanData || !target) return res.status(400).json({ error: "Missing scan data" });

    const doc = new PDFDocument({ size: "A4", margin: 50, bufferPages: true });
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="QuickScan-${target}.pdf"`);
    doc.pipe(res);

    const risk    = riskAssessment?.risk  || "LOW";
    const score   = riskAssessment?.score ?? 0;
    const findings = riskAssessment?.findings || [];

    // ── COVER ──────────────────────────────────
    doc.fontSize(9).fillColor("#6b7280").text("WEBINTELX THREAT INTELLIGENCE", { align: "center" });
    doc.moveDown(0.3);
    doc.fontSize(22).fillColor("#1e3a5f").text("Quick Scan Security Report", { align: "center" });
    doc.moveDown(0.5);
    doc.fontSize(12).fillColor(riskColor(risk)).text(`Risk Level: ${risk}  (${score}/15)`, { align: "center" });
    doc.moveDown(0.5);
    doc.fontSize(10).fillColor("#6b7280")
      .text(`Target: ${target}`, { align: "center" })
      .text(`Generated: ${new Date().toUTCString()}`, { align: "center" });

    divider(doc);

    // ── EXECUTIVE SUMMARY ──────────────────────
    sectionTitle(doc, "Executive Summary");
    doc.text(
      "This Quick Scan provides a high-level security assessment using passive reconnaissance and OSINT modules. " +
      "It identifies exposed services, attack surface, technology stack, and threat intelligence signals. " +
      "No active exploitation was performed."
    );
    doc.moveDown(0.5);
    doc.text(`Risk Score: ${score}/15 — ${risk}`);
    if (findings.length > 0) {
      doc.moveDown(0.3).text("Key findings:");
      findings.forEach(f => bullet(doc, f));
    }

    divider(doc);

    // ── SSL / TLS ──────────────────────────────
    sectionTitle(doc, "SSL / TLS Certificate");
    const ssl = scanData.ssl || {};
    row(doc, "Status",        ssl.valid ? "[VALID]" : "[INVALID]", ssl.valid ? "#15803d" : "#b91c1c");
    row(doc, "Issuer",        ssl.issuer);
    row(doc, "Subject",       ssl.subject);
    row(doc, "Valid From",    fmtDate(ssl.validFrom));
    row(doc, "Valid To",      fmtDate(ssl.validTo));
    row(doc, "Days Remaining", ssl.daysRemaining ?? "N/A");
    if (!ssl.valid) bullet(doc, "HTTPS not enforced — data may be transmitted in plaintext", "#b91c1c");

    divider(doc);

    // ── SECURITY HEADERS ──────────────────────
    sectionTitle(doc, "Security Headers");
    const h = scanData.headers || {};
    row(doc, "Server",               h.server);
    row(doc, "X-Powered-By",         h.poweredBy || "Hidden");
    row(doc, "Strict-Transport-Sec", h.strictTransport || "MISSING", h.strictTransport ? "#15803d" : "#b91c1c");
    row(doc, "X-Frame-Options",      h.xFrameOptions  || "MISSING", h.xFrameOptions  ? "#15803d" : "#b91c1c");
    row(doc, "Content-Security-Policy", h.csp         || "MISSING", h.csp            ? "#15803d" : "#b91c1c");
    row(doc, "Referrer-Policy",      h.referrer       || "MISSING", h.referrer       ? "#15803d" : "#b91c1c");
    row(doc, "CORS",                 h.cors           || "Not set");
    row(doc, "XSS-Protection",       h.xssProtection  || "Not set");
    if ((h.missingSecurityHeaders || []).length > 0) {
      doc.moveDown(0.3);
      bullet(doc, `Missing headers: ${h.missingSecurityHeaders.join(", ")}`, "#b45309");
    }

    divider(doc);

    // ── TECHNOLOGY STACK ──────────────────────
    sectionTitle(doc, "Technology Stack (Wappalyzer)");
    const wap = scanData.wappalyzer || {};
    if (Object.keys(wap).length > 0) {
      Object.entries(wap).forEach(([tech, version]) => {
        bullet(doc, version && version !== "Unknown" ? `${tech} ${version}` : tech);
      });
    } else {
      doc.text("No technologies detected.");
    }

    divider(doc);

    // ── ATTACK SURFACE ────────────────────────
    sectionTitle(doc, "Attack Surface — Subdomains");
    const st = scanData.securityTrails || {};
    row(doc, "Subdomain Count", st.subdomainCount ?? 0);
    row(doc, "Source",          st.note || "Passive DNS");
    row(doc, "Risk",            st.risk || "LOW", riskColor(st.risk || "LOW"));
    if ((st.subdomains || []).length > 0) {
      doc.moveDown(0.3).text("Sample subdomains:");
      st.subdomains.slice(0, 10).forEach(s => bullet(doc, s));
      if (st.subdomains.length > 10) bullet(doc, `... and ${st.subdomains.length - 10} more`);
    }

    divider(doc);

    // ── ENDPOINTS ─────────────────────────────
    sectionTitle(doc, "Parameterized Endpoints");
    const eps = scanData.endpoints || [];
    row(doc, "Total Found", eps.length);
    if (eps.length > 0) {
      doc.moveDown(0.3).text("Sample endpoints:");
      eps.slice(0, 10).forEach(e => bullet(doc, e.url || fmt(e)));
      if (eps.length > 10) bullet(doc, `... and ${eps.length - 10} more`);
    }

    divider(doc);

    // ── OPEN PORTS ────────────────────────────
    sectionTitle(doc, "Network Ports");
    const ports = scanData.openPorts || [];
    if (ports.length > 0) {
      ports.forEach(p => bullet(doc, `${p.port} / ${p.name || "unknown"} — ${p.state || "open"}`));
    } else {
      doc.text("No common ports detected as open.");
    }

    divider(doc);

    // ── DNS ───────────────────────────────────
    sectionTitle(doc, "DNS Intelligence");
    const dns = scanData.dns || {};
    row(doc, "Resolved",    dns.resolvedSuccessfully ? "YES" : "NO", dns.resolvedSuccessfully ? "#15803d" : "#b91c1c");
    row(doc, "Primary IP",  dns.primaryIP);
    row(doc, "A Records",   (dns.A || []).join(", ") || "N/A");
    row(doc, "MX Records",  (dns.MX || []).length);
    row(doc, "NS Records",  (dns.NS || []).length);
    row(doc, "DNSSEC",      dns.dnssec);

    divider(doc);

    // ── WHOIS ─────────────────────────────────
    sectionTitle(doc, "WHOIS / Registration");
    const w = scanData.whois || {};
    row(doc, "Registrar",       w.registrar);
    row(doc, "Registrant Org",  w.registrantOrg);
    row(doc, "Created",         fmtDate(w.creationDate));
    row(doc, "Expires",         fmtDate(w.expiryDate));
    row(doc, "Last Updated",    fmtDate(w.updatedDate));
    row(doc, "DNSSEC",          w.dnssec);
    row(doc, "Nameservers",     (w.nameservers || []).slice(0, 4).join(", ") || "N/A");

    divider(doc);

    // ── TRACEROUTE / PING ─────────────────────
    sectionTitle(doc, "Network Reachability");
    const ping = scanData.ping || {};
    row(doc, "Reachable",     ping.reachable ? "YES" : "NO", ping.reachable ? "#15803d" : "#b91c1c");
    row(doc, "Avg Latency",   ping.avgTime && ping.avgTime !== "N/A" ? `${ping.avgTime} ms` : "N/A");
    row(doc, "Packet Loss",   ping.packetLoss || "0%");
    const tr = scanData.traceroute || {};
    row(doc, "Total Hops",    tr.totalHops ?? "N/A");
    row(doc, "Reachable Hops", tr.reachableHops ?? "N/A");
    row(doc, "Final Hop",     tr.finalHop || "Unknown");
    row(doc, "Avg Hop Latency", tr.avgLatency ? `${tr.avgLatency} ms` : "N/A");

    divider(doc);

    // ── ASN / GEOLOCATION ─────────────────────
    sectionTitle(doc, "Host Intelligence — ASN & Geolocation");
    const geo = scanData.asnGeo || {};
    row(doc, "IP Address",  geo.ip);
    row(doc, "Country",     geo.country ? `${geo.country} (${geo.countryCode})` : "N/A");
    row(doc, "City",        geo.city);
    row(doc, "ISP",         geo.isp);
    row(doc, "Org",         geo.org);
    row(doc, "ASN",         geo.asn);
    row(doc, "Cloud Hosted", geo.isCloud ? `YES — ${geo.cloudProvider}` : "NO", geo.isCloud ? "#b45309" : "#15803d");

    divider(doc);

    // ── COOKIES ───────────────────────────────
    sectionTitle(doc, "Cookie Security Analysis");
    const ck = scanData.cookies || {};
    row(doc, "Cookies Set",     ck.cookieCount ?? (ck.cookies || []).length);
    row(doc, "Security Issues", (ck.issues || []).length);
    if ((ck.cookies || []).length > 0) {
      doc.moveDown(0.3).text("Cookie flags:");
      ck.cookies.forEach(c => {
        bullet(doc, `${c.name}  Secure:${c.secure ? "YES" : "NO"}  HttpOnly:${c.httpOnly ? "YES" : "NO"}  SameSite:${c.sameSite || "MISSING"}`);
      });
    }
    if ((ck.issues || []).length > 0) {
      doc.moveDown(0.3).text("Issues:");
      ck.issues.forEach(i => bullet(doc, i, "#b45309"));
    }

    divider(doc);

    // ── GREEN HOSTING ─────────────────────────
    sectionTitle(doc, "Green / Sustainable Hosting");
    const gw = scanData.greenWeb || {};
    row(doc, "Green Verified", gw.green ? "[VERIFIED]" : "NOT VERIFIED", gw.green ? "#15803d" : "#6b7280");
    if (gw.hostedBy) row(doc, "Provider", gw.hostedBy);
    if (gw.partnerUrl) row(doc, "Provider Site", gw.partnerUrl);

    divider(doc);

    // ── EMAIL INTELLIGENCE ────────────────────
    sectionTitle(doc, "Email Intelligence");
    const ei = scanData.emailIntelligence || {};

    subTitle(doc, "DNS Blocklist (DNSBL)");
    row(doc, "Blacklisted",  ei.dnsbl?.listed ? "YES" : "NO", ei.dnsbl?.listed ? "#b91c1c" : "#15803d");
    row(doc, "Listed On",    (ei.dnsbl?.listedOn || []).join(", ") || "None");
    row(doc, "IP Checked",   ei.dnsbl?.ip || "N/A");

    if (ei.hunter?.available) {
      doc.moveDown(0.4);
      subTitle(doc, "Hunter.io Email Intelligence");
      row(doc, "Organization",    ei.hunter.organization);
      row(doc, "Total Emails",    ei.hunter.totalEmails);
      row(doc, "Email Pattern",   ei.hunter.pattern);
      row(doc, "MX Record",       ei.hunter.mxRecord || "None");
      row(doc, "Webmail",         ei.hunter.webmail ? "YES" : "NO");
      row(doc, "Accept-All",      ei.hunter.acceptAll ? "YES" : "NO");
      if ((ei.hunter.emails || []).length > 0) {
        doc.moveDown(0.3).text("Discovered emails:");
        ei.hunter.emails.slice(0, 6).forEach(e => {
          bullet(doc, `${e.email}  (${e.confidence}% confidence)  ${e.firstName || ""} ${e.lastName || ""}  ${e.position || ""}`);
        });
      }
    }

    divider(doc);

    // ── THREAT INTELLIGENCE ───────────────────
    sectionTitle(doc, "Threat Intelligence");

    subTitle(doc, "Google Safe Browsing");
    const sb = scanData.safeBrowsing || {};
    if (sb.available) {
      row(doc, "Status",       sb.safe ? "[CLEAN]" : "[FLAGGED]", sb.safe ? "#15803d" : "#b91c1c");
      row(doc, "Threats Found", sb.threatCount ?? 0);
      if ((sb.threats || []).length > 0) bullet(doc, `Threat types: ${sb.threats.join(", ")}`, "#b91c1c");
    } else {
      doc.text(`Not available: ${sb.note || "API key not configured"}`);
    }

    doc.moveDown(0.4);
    subTitle(doc, "VirusTotal Domain Report");
    const vt = scanData.virusTotal || {};
    if (vt.available) {
      row(doc, "Malicious Engines", vt.malicious, vt.malicious > 0 ? "#b91c1c" : "#15803d");
      row(doc, "Suspicious",        vt.suspicious);
      row(doc, "Harmless",          vt.harmless);
      row(doc, "Total Engines",     vt.total);
      row(doc, "Community Score",   vt.communityScore);
      row(doc, "Last Analysis",     fmtDate(vt.lastAnalysis));
      if ((vt.popularity || []).length > 0) row(doc, "Popularity", vt.popularity.join(", "));
    } else {
      doc.text(`Not available: ${vt.note || "API key not configured"}`);
    }

    doc.moveDown(0.4);
    subTitle(doc, "Shodan Host Intelligence");
    const sh = scanData.shodan || {};
    if (sh.available) {
      if (sh.note) {
        doc.text(sh.note);
      } else {
        row(doc, "IP",          sh.ip);
        row(doc, "Org",         sh.org);
        row(doc, "ASN",         sh.asn);
        row(doc, "Open Ports",  (sh.ports || []).join(", ") || "None");
        row(doc, "CVE Count",   sh.vulnCount ?? 0, sh.vulnCount > 0 ? "#b91c1c" : "#15803d");
        row(doc, "CISA KEV",    sh.kevCount ?? 0,  sh.kevCount  > 0 ? "#b91c1c" : "#15803d");
        if ((sh.vulnDetails || []).length > 0) {
          doc.moveDown(0.3).text("CVEs:");
          sh.vulnDetails.slice(0, 5).forEach(v => {
            bullet(doc, `${v.id}  CVSS:${v.cvss ?? "N/A"}${v.kev ? "  [CISA KEV]" : ""}  ${v.summary ? v.summary.substring(0, 80) + "..." : ""}`);
          });
        }
      }
    } else {
      doc.text(`Not available: ${sh.note || "API key not configured"}`);
    }

    divider(doc);

    // ── VULNERABILITY CLASSIFICATION ──────────
    sectionTitle(doc, "Vulnerability Classification");
    doc.fontSize(10).fillColor("#6b7280")
      .text("Automatically derived from scan results. Quick Scan does not perform exploitation or confirmation testing.")
      .moveDown(0.5);

    const classified = classifyFindings(scanData);
    classified.forEach((f, i) => {
      const color = f.classification === "Vulnerability" ? "#b91c1c"
                  : f.classification === "Security Weakness" ? "#b45309"
                  : "#374151";
      doc.fontSize(10).fillColor(color)
        .text(`${i + 1}. ${f.title}`)
        .fillColor("#6b7280")
        .text(`   Classification: ${f.classification}  |  Category: ${f.type}`)
        .fillColor("#374151")
        .text(`   Evidence: ${f.evidence}`)
        .moveDown(0.4);
    });

    divider(doc);

    // ── DATA-DRIVEN SUMMARY ───────────────────
    sectionTitle(doc, "Scan Summary");
    const sub = scanData.securityTrails?.subdomainCount ?? 0;
    const epLen = (scanData.endpoints || []).length;
    const portLen = (scanData.openPorts || []).length;
    [
      `${sub} subdomain(s) discovered via passive DNS reconnaissance.`,
      `${epLen} parameterized endpoint(s) identified during crawl.`,
      `${portLen} open port(s) detected on the target host.`,
      `SSL/TLS: ${scanData.ssl?.valid ? `Valid (${scanData.ssl.daysRemaining} days remaining)` : "Invalid or not enforced"}.`,
      `Google Safe Browsing: ${scanData.safeBrowsing?.available ? (scanData.safeBrowsing.safe ? "Clean" : "FLAGGED") : "Not checked"}.`,
      `VirusTotal: ${scanData.virusTotal?.available ? `${scanData.virusTotal.malicious}/${scanData.virusTotal.total} engines flagged` : "Not checked"}.`,
      `Shodan CVEs: ${scanData.shodan?.available && !scanData.shodan?.note ? `${scanData.shodan.vulnCount ?? 0} CVEs, ${scanData.shodan.kevCount ?? 0} CISA KEV` : "Not available (Cloudflare proxy or N/A)"}.`,
      `DNSBL: ${scanData.emailIntelligence?.dnsbl?.listed ? `BLACKLISTED on ${scanData.emailIntelligence.dnsbl.listedOn?.join(", ")}` : "Clean"}.`,
      `Green Hosting: ${scanData.greenWeb?.green ? `Verified (${scanData.greenWeb.hostedBy})` : "Not verified"}.`,
      `Insecure cookies: ${(scanData.cookies?.issues || []).length} issue(s) detected.`,
    ].forEach(line => bullet(doc, line));

    divider(doc);

    // ── FOOTER ────────────────────────────────
    doc.moveDown(1)
      .fontSize(9)
      .fillColor("#9ca3af")
      .text("Generated by WebIntelX — For authorized security assessment purposes only.", { align: "center" });

    doc.end();
  } catch (err) {
    console.error("PDF generation failed:", err);
    if (!res.headersSent) res.status(500).json({ error: "PDF generation failed", detail: err.message });
  }
};