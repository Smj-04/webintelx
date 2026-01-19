const PDFDocument = require("pdfkit");

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
       🛠 RECOMMENDATIONS
    ========================= */
    doc
      .fontSize(14)
      .fillColor("#1f2937")
      .text("Recommendations", { underline: true });

    doc.moveDown(0.5);

    doc.fontSize(11).fillColor("black").text(
      "• Enforce HTTPS and configure TLS securely\n" +
        "• Upgrade legacy server-side technologies\n" +
        "• Review exposed endpoints for injection vulnerabilities\n" +
        "• Reduce unnecessary subdomains and decommission unused services\n" +
        "• Perform a Full Scan for deeper vulnerability analysis"
    );

    doc.moveDown(2);

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
