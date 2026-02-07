const PDFDocument = require("pdfkit");

function detectDisclosedTechnology(headers = {}) {
  const headerText = Object.entries(headers)
    .map(([k, v]) => `${k}: ${v}`)
    .join(" ");

  return headerText.match(
    /(php\/[0-9]|joomla|wordpress|drupal|asp\.net)/i
  );
}

function classifyQuickScanFindings(scanData) {
  const findings = [];


    // -----------------------------
    // SSL / Transport Security
    // -----------------------------
    const hasHTTPSPort = scanData.openPorts?.some(
      (p) => p.port === 443
    );

    if (!hasHTTPSPort && scanData.ssl?.error) {
      findings.push({
        title: "SSL/TLS Not Detected",
        classification: "Vulnerability",
        type: "Security Misconfiguration",
        evidence: "No HTTPS service detected on the target",
      });
    } else if (hasHTTPSPort) {
      findings.push({
        title: "HTTPS Service Detected",
        classification: "Not a Vulnerability",
        type: "Informational",
        evidence: "HTTPS service detected (enforcement not validated in Quick Scan)",
      });
    } else {
      findings.push({
        title: "SSL/TLS Status Indeterminate",
        classification: "Not a Vulnerability",
        type: "Informational",
        evidence: "SSL/TLS could not be reliably assessed in Quick Scan",
      });
    }

  // -----------------------------
  // Outdated Technology
  // -----------------------------
    const techMatch = detectDisclosedTechnology(scanData.headers);

    if (techMatch) {
      findings.push({
        title: "Disclosed Application Technology",
        classification: "Security Weakness",
        type: "Technology Disclosure",
        evidence: techMatch[0],
      });
    }


  // -----------------------------
  // Attack Surface (Subdomains)
  // -----------------------------
  if (scanData.securityTrails?.subdomainCount > 0) {
    findings.push({
      title: "Expanded Attack Surface",
      classification: "Not a Vulnerability",
      type: "Exposure",
      evidence: `${scanData.securityTrails.subdomainCount} subdomains discovered`,
    });
  }

  // -----------------------------
  // Parameterized Endpoints
  // -----------------------------
  if (scanData.endpoints?.length > 0) {
    findings.push({
      title: "Parameterized Endpoints Detected",
      classification: "Not a Vulnerability",
      type: "Informational",
      evidence: `${scanData.endpoints.length} parameterized URLs identified`,
    });
  }

  // -----------------------------
  // Open Ports
  // -----------------------------
  if (scanData.openPorts?.length > 0) {
    findings.push({
      title: "Open Network Ports",
      classification: "Not a Vulnerability",
      type: "Exposure",
      evidence: `Open ports: ${scanData.openPorts
        .map((p) => p.port)
        .join(", ")}`,
    });
  }

  // -----------------------------
  // Infrastructure Intelligence
  // -----------------------------
  ["dns", "whois", "ping", "traceroute"].forEach((key) => {
    if (scanData[key]) {
      findings.push({
        title: key.toUpperCase(),
        classification: "Not a Vulnerability",
        type: "Informational",
        evidence: "Module executed successfully",
      });
    }
  });

  // -----------------------------
  // Email Reputation
  // -----------------------------
  if (scanData.emailReputation?.risk === "HIGH") {
    findings.push({
      title: "Domain Reputation Risk",
      classification: "Security Weakness",
      type: "Reputation Risk",
      evidence: "High-risk domain indicators detected",
    });
  } else if (scanData.emailReputation?.risk) {
    findings.push({
      title: "Domain Reputation",
      classification: "Not a Vulnerability",
      type: "Informational",
      evidence: `Risk level: ${scanData.emailReputation.risk}`,
    });
  }

  return findings;
}

exports.generateQuickScanPDF = async (req, res) => {
  try {
    const { scanData, target } = req.body;

    if (!scanData || !target) {
      return res.status(400).json({ error: "Missing scan data" });
    }

    const doc = new PDFDocument({
      size: "A4",
      margin: 50,
    });

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="QuickScan-${target}.pdf"`
    );

    doc.pipe(res);

    /* =========================
       🟦 COVER / TITLE
    ========================= */
    doc
      .fontSize(22)
      .fillColor("#1e40af")
      .text("WebIntelX – Quick Scan Security Report", {
        align: "center",
      });

    doc.moveDown(1.5);

    doc
      .fontSize(12)
      .fillColor("black")
      .text(`Target: ${target}`)
      .text(`Scan Type: Quick Scan`)
      .text(`Generated On: ${new Date().toUTCString()}`);

    doc.moveDown(2);

    /* =========================
       🧠 EXECUTIVE SUMMARY
    ========================= */
    doc
      .fontSize(16)
      .fillColor("#111827")
      .text("Executive Summary", { underline: true });

    doc.moveDown(0.5);

    doc
      .fontSize(11)
      .fillColor("black")
      .text(
        "This Quick Scan provides a high-level security assessment of the target application. " +
          "The scan focuses on identifying exposed services, attack surface expansion, " +
          "legacy technologies, and common misconfigurations that may introduce security risks."
      );

    doc.moveDown(1.5);

    /* =========================
       🚨 OVERALL RISK
    ========================= */
    const overallRisk = (() => {
      let score = 0;
      if (scanData.securityTrails?.risk === "HIGH") score += 3;
      if (scanData.endpoints?.length > 20) score += 3;
      if (scanData.headers?.["x-powered-by"]?.includes("PHP/5")) score += 2;
      if (scanData.ssl?.error) score += 1;

      if (score >= 7) return "CRITICAL";
      if (score >= 5) return "HIGH";
      if (score >= 3) return "MEDIUM";
      return "LOW";
    })();

    doc
      .fontSize(14)
      .fillColor("#b91c1c")
      .text(`Overall Risk Level: ${overallRisk}`);

    doc.moveDown(1.5);

    /* =========================
       🌐 ATTACK SURFACE
    ========================= */
    doc
      .fontSize(14)
      .fillColor("#1f2937")
      .text("Attack Surface (SecurityTrails)", { underline: true });

    doc.moveDown(0.5);

    doc.fontSize(11).fillColor("black").text(
      `• Subdomains discovered: ${scanData.securityTrails.subdomainCount}\n` +
        `• Risk Level: ${scanData.securityTrails.risk}`
    );

    if (scanData.securityTrails.subdomains.length > 0) {
      doc.moveDown(0.5);
      doc.text("Sample Subdomains:");
      scanData.securityTrails.subdomains.slice(0, 10).forEach((s) => {
        doc.text(`  - ${s}.${target}`);
      });
    }

    doc.moveDown(1.5);

    /* =========================
       🔓 EXPOSED ENDPOINTS
    ========================= */
    doc
      .fontSize(14)
      .fillColor("#1f2937")
      .text("Exposed Endpoints", { underline: true });

    doc.moveDown(0.5);

    doc
      .fontSize(11)
      .fillColor("black")
      .text(`• Parameterized URLs discovered: ${scanData.endpoints.length}`);

    scanData.endpoints.slice(0, 15).forEach((e) => {
      doc.text(`  - ${e.url}`);
    });

    doc.moveDown(1.5);

    /* =========================
       🧩 TECHNOLOGY STACK
    ========================= */
    doc
      .fontSize(14)
      .fillColor("#1f2937")
      .text("Technology Stack", { underline: true });

    doc.moveDown(0.5);

    Object.entries(scanData.headers).forEach(([key, value]) => {
      doc.fontSize(11).text(`• ${key}: ${value}`);
    });

    doc.moveDown(1.5);

    /* =========================
       🌍 NETWORK & TRANSPORT
    ========================= */
    doc
      .fontSize(14)
      .fillColor("#1f2937")
      .text("Network & Transport Security", { underline: true });

    doc.moveDown(0.5);

    doc.fontSize(11).fillColor("black").text(
      `• Open Ports: ${
        scanData.openPorts.length
          ? scanData.openPorts.map((p) => p.port).join(", ")
          : "None detected"
      }\n` +
        `• SSL/TLS: ${scanData.ssl.error ? "Not Enforced" : "Enabled"}`
    );

    doc.moveDown(1.5);

   /* =========================
   🌍 NETWORK & TRANSPORT
   ========================= */
    doc
      .fontSize(14)
      .fillColor("#1f2937")
      .text("Infrastructure Intelligence", { underline: true });

    doc.moveDown(0.8);

    doc.fontSize(12).text("DNS Intelligence");
    doc.moveDown(0.3);

    if (scanData.dns) {
      doc.fontSize(11).text(
        "DNS resolution completed successfully for the target domain."
      );
    } else {
      doc.fontSize(11).text(
        "DNS resolution could not be completed for the target domain."
      );
    }

    doc.moveDown(0.8);

    doc.fontSize(12).text("WHOIS Information");
    doc.moveDown(0.3);

    if (scanData.whois) {
      doc.fontSize(11).text(
        "WHOIS records were retrieved, providing domain registration metadata."
      );
    } else {
      doc.fontSize(11).text(
        "WHOIS information could not be retrieved for the target domain."
      );
    }

    doc.moveDown(0.8);

    doc.fontSize(12).text("Network Path Analysis (Traceroute)");
    doc.moveDown(0.3);

    if (Array.isArray(scanData.traceroute)) {
      const hops = scanData.traceroute.filter((l) =>
        /^\s*\d+/.test(l)
      ).length;

      findings.push({
        title: "Traceroute Analysis",
        classification: "Not a Vulnerability",
        type: "Informational",
        evidence:
          hops > 0
            ? `${hops} routing hops identified`
            : "Traceroute executed but no hops could be resolved",
      });
    }


    doc.moveDown(0.8);

    doc.fontSize(12).text("Host Reachability (Ping)");
    doc.moveDown(0.3);

    if (scanData.ping) {
      doc.fontSize(11).text(
        "The target host responded to ICMP echo requests, confirming network-level reachability."
      );
    } else {
      doc.fontSize(11).text(
        "The target host did not respond to ICMP echo requests."
      );
    }

    doc.moveDown(0.8);

    doc.fontSize(12).text("Email / Domain Reputation");
    doc.moveDown(0.3);

    if (scanData.emailReputation?.risk) {
      doc.fontSize(11).text(
        `Domain reputation assessment completed with a reported risk level of ${scanData.emailReputation.risk}.`
      );
    } else {
      doc.fontSize(11).text(
        "Domain reputation assessment could not be completed."
      );
    }

    doc.moveDown(1.2);


    doc
  .fontSize(14)
  .fillColor("#1f2937")
  .text("Data-Driven Scan Summary", { underline: true });

doc.moveDown(0.5);

doc.fontSize(11).fillColor("black").text(
  `• ${scanData.securityTrails.subdomainCount} subdomains were identified through passive DNS intelligence.\n` +
  `• ${scanData.endpoints.length} parameterized endpoints were discovered during endpoint enumeration.\n` +
  `• The application stack exposes ${
    scanData.headers?.["x-powered-by"] || "no disclosed backend technology"
  }.\n` +
  `• ${
    scanData.openPorts.length
      ? scanData.openPorts.length + " open network ports were detected."
      : "No common network ports were detected."
  }\n` +
  `• HTTPS service ${
    scanData.openPorts?.some((p) => p.port === 443)
      ? "was detected on the target"
      : "was not detected on the target"
  }.\n` +
  `• Infrastructure intelligence modules (DNS, WHOIS, traceroute, and ping) were executed as part of this Quick Scan.`
);



const classifiedFindings = classifyQuickScanFindings(scanData);

doc
  .fontSize(14)
  .fillColor("#1f2937")
  .text("Vulnerability Classification", { underline: true });

doc.moveDown(0.6);

doc.fontSize(11).fillColor("black").text(
  "The following classifications are automatically derived from scan results. " +
  "Quick Scan does not perform exploitation or confirmation testing."
);

doc.moveDown(0.8);

classifiedFindings.forEach((finding, index) => {
  doc
    .fontSize(11)
    .text(
      `${index + 1}. ${finding.title}\n` +
        `   Classification: ${finding.classification}\n` +
        `   Category: ${finding.type}\n` +
        `   Evidence: ${finding.evidence}`
    );
  doc.moveDown(0.6);
});

doc.moveDown(1.5);

    /* =========================
       📌 FOOTER
    ========================= */
    doc
      .fontSize(10)
      .fillColor("gray")
      .text(
        "Generated by WebIntelX – For security assessment purposes only",
        { align: "center" }
      );

    doc.end();
  } catch (err) {
    console.error("PDF generation failed:", err);
    res.status(500).json({ error: "PDF generation failed" });
  }
};
