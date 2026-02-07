const cleanUrl = require("../utils/cleanUrl");
const endpointScanner = require("../utils/endpointScanner");
const axios = require("axios");
const PDFDocument = require("pdfkit");
console.log("🔥 fullScanController.js LOADED");


/*
  FullScan orchestration controller
  - Runs a QuickScan (summary extraction only)
  - Runs SQLMap sequentially across discovered endpoints
  - Runs other vulnerability modules in parallel
  - Aggregates results into the required unified output schema
  - Exposes `generateFullScanPDF` for PDF generation (same style as QuickScan)
*/

// Helper: safe axios POST wrapper that returns settled result
async function safePost(url, body, opts = {}) {
  try {
    const r = await axios.post(url, body, opts);
    return { ok: true, data: r.data };
  } catch (err) {
    return { ok: false, error: err.message || String(err), details: err.response?.data || null };
  }
}

exports.fullScan = async (req, res) => {
  console.log("🔥 FULLSCAN CONTROLLER LOADED");

  const { url } = req.body;
  if (!url) return res.status(400).json({ error: "URL required" });

  const startedAt = new Date().toISOString();
  const baseUrl = cleanUrl(url);

  // Prepare the unified response skeleton
  const fullResult = {
    success: true,
    target: null,
    scanType: "FULL",
    meta: {
      startedAt,
      completedAt: null
    },
    summary: {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0
    },
    quickscan: {
      attackSurface: {
        subdomainCount: 0,
        endpointCount: 0,
        openPorts: 0
      },
      technology: {
        backend: null,
        ssl: false
      }
    },
    vulnerabilities: {
      sqlInjection: { found: false, details: null },
      domXss: { found: false, details: null },
      storedXss: { found: false, details: null },
      csrf: { found: false, details: null },
      clickjacking: { vulnerable: false, headers: {} },
      commandInjection: { found: false, details: null }
    }
  };

  try {
    // 1) Run QuickScan (summary only)
    const quick = await safePost("http://localhost:5000/api/quickscan", { url: baseUrl }, { timeout: 30000 });

    if (quick.ok && quick.data && quick.data.success) {
      const qs = quick.data.data || {};
      try {
        const parsedTarget = new URL(baseUrl).hostname;
        fullResult.target = parsedTarget;
      } catch (e) {
        fullResult.target = baseUrl;
      }

      fullResult.quickscan.attackSurface.subdomainCount = qs.securityTrails?.subdomainCount || 0;
      fullResult.quickscan.attackSurface.endpointCount = Array.isArray(qs.endpoints) ? qs.endpoints.length : 0;
      fullResult.quickscan.attackSurface.openPorts = Array.isArray(qs.openPorts) ? qs.openPorts.length : 0;

      // Backend technology from headers
      const headers = qs.headers && typeof qs.headers === 'object' ? qs.headers : {};
      fullResult.quickscan.technology.backend = headers['x-powered-by'] || headers['server'] || null;
      fullResult.quickscan.technology.ssl = !!(qs.ssl && !qs.ssl.error);

      // Keep clickjacking headers fallback
      fullResult.vulnerabilities.clickjacking.headers = headers;
    } else {
      // QuickScan failed: set target and continue
      try {
        fullResult.target = new URL(baseUrl).hostname;
      } catch (e) {
        fullResult.target = baseUrl;
      }
    }

    // 2) Discover endpoints for SQLMap
    let endpoints = [];
    try {
      endpoints = await endpointScanner(baseUrl);
    } catch (e) {
      endpoints = [];
    }

    // 3) Run SQLMap sequentially per endpoint (slow) and aggregate findings
    const sqlFindings = [];
    for (const target of endpoints) {
      // call internal SQLMap API sequentially
      const resSql = await safePost("http://localhost:5000/api/sqlmap", { url: target.url, param: target.param }, { timeout: 40000 });
      if (resSql.ok && resSql.data && resSql.data.vulnerable) {
        sqlFindings.push({ url: target.url, param: target.param, databases: resSql.data.databases || [] });
      }
      // continue to next endpoint regardless of result
    }

    if (sqlFindings.length > 0) {
      fullResult.vulnerabilities.sqlInjection.found = true;
      fullResult.vulnerabilities.sqlInjection.details = { findings: sqlFindings };
      fullResult.summary.high += 1; // SQLi counted once
    }


    // 4) Run other modules in parallel
    const moduleCalls = await Promise.allSettled([
      // DOM XSS
      axios.post("http://localhost:5000/api/dom-xss", { url: baseUrl }, { timeout: 20000 }),
      // Stored XSS
      axios.post("http://localhost:5000/api/stored-xss", { url: baseUrl }, { timeout: 20000 }),
      // CSRF (note: mounted under /api/csrf/scan)
      axios.post("http://localhost:5000/api/csrf/scan", { url: baseUrl }, { timeout: 30000 }),
      // Clickjacking
      axios.post("http://localhost:5000/api/clickjacking", { url: baseUrl }, { timeout: 10000 }),
      // Command Injection
      axios.post("http://localhost:5000/api/command-injection", { url: baseUrl }, { timeout: 20000 })
    ]);

    // Helper to safely extract module result
    const safeModule = (settled) => {
      if (!settled) return { ok: false };
      if (settled.status === 'fulfilled') return { ok: true, data: settled.value.data };
      return { ok: false, error: settled.reason?.message || String(settled.reason) };
    };

    const domRes = safeModule(moduleCalls[0]);
    const storedRes = safeModule(moduleCalls[1]);
    const csrfRes = safeModule(moduleCalls[2]);
    const clickRes = safeModule(moduleCalls[3]);
    const cmdRes = safeModule(moduleCalls[4]);

    if (domRes.ok && domRes.data) {
      fullResult.vulnerabilities.domXss.found = !!domRes.data.vulnerable;
      fullResult.vulnerabilities.domXss.details = domRes.data || null;
      if (domRes.data.vulnerable) {
        fullResult.summary.medium += 1;
      }
    }


    if (storedRes.ok && storedRes.data) {
      fullResult.vulnerabilities.storedXss.found = !!storedRes.data.vulnerable;
      fullResult.vulnerabilities.storedXss.details = storedRes.data || null;
      if (storedRes.data.vulnerable) {
        fullResult.summary.high += 1;
      }
    }


    if (csrfRes.ok && csrfRes.data) {
      const vulnerableCount = csrfRes.data.vulnerableEndpoints?.length || 0;
      fullResult.vulnerabilities.csrf.found = vulnerableCount > 0;
      fullResult.vulnerabilities.csrf.details = csrfRes.data || null;
      if (vulnerableCount > 0) {
        fullResult.summary.medium += 1;
      }
    }


    if (clickRes.ok && clickRes.data) {
      fullResult.vulnerabilities.clickjacking = {
        vulnerable: !!clickRes.data.vulnerable,
        details: {
          issue: clickRes.data.issue || "Missing X-Frame-Options / CSP frame-ancestors",
          headers: fullResult.vulnerabilities.clickjacking.headers || {}
        }
      };

      if (clickRes.data.vulnerable) {
        fullResult.summary.low += 1;
      }
    }


    if (cmdRes.ok && cmdRes.data) {
      fullResult.vulnerabilities.commandInjection.found = !!cmdRes.data.vulnerable;
      fullResult.vulnerabilities.commandInjection.details = cmdRes.data || null;
      if (cmdRes.data.vulnerable) {
        fullResult.summary.high += 1;
      }
    }

    // Finalize summary: no CRITICAL/LOW detector available in current heuristics
    // We'll keep critical and low as 0 unless future modules provide richer severity metadata

    fullResult.meta.completedAt = new Date().toISOString();

    return res.json(fullResult);
  } catch (err) {
    console.error("FullScan orchestration failed:", err);
    fullResult.meta.completedAt = new Date().toISOString();
    return res.status(500).json({
      success: false,
      error: "FullScan failed to complete",
      details: err.message,
      partial: fullResult
    });
  }
};

// Minimal FullScan PDF generator matching QuickScan style
exports.generateFullScanPDF = async (scanData, target, res) => {
  try {
    const doc = new PDFDocument({ size: 'A4', margin: 50 });
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="FullScan-${target}.pdf"`);
    doc.pipe(res);

    // Cover
    doc.fontSize(22).fillColor('#1e40af').text('WebIntelX – Full Scan Security Report', { align: 'center' });
    doc.moveDown(1.5);
    doc.fontSize(12).fillColor('black').text(`Target: ${target}`).text('Scan Type: Full Scan').text(`Generated On: ${new Date().toUTCString()}`);
    doc.moveDown(1.5);

    // Executive Summary
    doc.fontSize(16).fillColor('#111827').text('Executive Summary', { underline: true });
    doc.moveDown(0.5);
    doc.fontSize(11).fillColor('black').text('This Full Scan aggregates QuickScan reconnaissance and targeted vulnerability tests (SQLi, DOM XSS, Stored XSS, CSRF, Clickjacking, Command Injection). Findings are risk-classified for prioritization.');
    doc.moveDown(1);

    // Attack Surface Summary
    doc.fontSize(14).fillColor('#1f2937').text('Attack Surface Summary', { underline: true });
    doc.moveDown(0.5);
    doc.fontSize(11).fillColor('black').text(
      `• Subdomains discovered: ${scanData.quickscan.attackSurface.subdomainCount}\n` +
      `• Parameterized endpoints: ${scanData.quickscan.attackSurface.endpointCount}\n` +
      `• Open ports: ${scanData.quickscan.attackSurface.openPorts}`
    );
    doc.moveDown(1);

    // Vulnerability Summary Table (simple list)
    doc.fontSize(14).fillColor('#1f2937').text('Vulnerability Summary', { underline: true });
    doc.moveDown(0.6);
    const vuln = scanData.vulnerabilities;
    const rows = [
      { name: 'SQL Injection', found: vuln.sqlInjection.found },
      { name: 'DOM XSS', found: vuln.domXss.found },
      { name: 'Stored XSS', found: vuln.storedXss.found },
      { name: 'CSRF', found: vuln.csrf.found },
      { name: 'Clickjacking', found: vuln.clickjacking.vulnerable },
      { name: 'Command Injection', found: vuln.commandInjection.found }
    ];

    rows.forEach((r, i) => {
      doc.fontSize(11).text(`${i + 1}. ${r.name} — ${r.found ? 'Detected' : 'Not Detected'}`);
    });

    doc.moveDown(1);

    // Detailed Vulnerability Sections
    if (vuln.sqlInjection.found) {
      doc.fontSize(14).fillColor('#1f2937').text('SQL Injection — Details', { underline: true });
      doc.moveDown(0.5);
      const findings = vuln.sqlInjection.details?.findings || [];
      findings.forEach((f, idx) => {
        doc.fontSize(11).text(`${idx + 1}. ${f.url} [param=${f.param}] Databases: ${f.databases.join(', ') || 'N/A'}`);
      });
      doc.moveDown(0.8);
    }

    if (vuln.domXss.found) {
      doc.fontSize(14).fillColor('#1f2937').text('DOM XSS — Details', { underline: true });
      doc.moveDown(0.5);
      doc.fontSize(11).text(
        `Evidence: ${vuln.domXss.details?.evidence || "DOM-based payload reflection detected"}`
        );
      doc.moveDown(0.8);
    }

    if (vuln.storedXss.found) {
      doc.fontSize(14).fillColor('#1f2937').text('Stored XSS — Details', { underline: true });
      doc.moveDown(0.5);
      doc.fontSize(11).text(
        `Evidence: ${vuln.storedXss.details?.evidence || "Stored XSS payload detected"}`
      );
      doc.moveDown(0.8);
    }

    if (vuln.csrf.found) {
      doc.fontSize(14).fillColor('#1f2937').text('CSRF — Details', { underline: true });
      doc.moveDown(0.5);
      doc.fontSize(11).text(`Vulnerable endpoints: ${vuln.csrf.details?.vulnerableEndpoints?.length || 0}`);
      doc.moveDown(0.8);
    }

    if (vuln.clickjacking.vulnerable) {
      doc.fontSize(14).fillColor('#1f2937').text('Clickjacking — Details', { underline: true });
      doc.moveDown(0.5);
      doc.fontSize(11).text(
        "Missing X-Frame-Options or frame-ancestors protection detected."
      );
      doc.moveDown(0.8);
    }

    if (vuln.commandInjection.found) {
      doc.fontSize(14).fillColor('#1f2937').text('Command Injection — Details', { underline: true });
      doc.moveDown(0.5);
      doc.fontSize(11).text(JSON.stringify(vuln.commandInjection.details || {}, null, 2));
      doc.moveDown(0.8);
    }

    // Risk Classification
    doc.fontSize(14).fillColor('#1f2937').text('Risk Classification', { underline: true });
    doc.moveDown(0.6);
    doc.fontSize(11).fillColor('black').text(
      `Critical: ${scanData.summary.critical}  High: ${scanData.summary.high}  Medium: ${scanData.summary.medium}  Low: ${scanData.summary.low}`
    );

    doc.moveDown(1.2);
    doc.fontSize(10).fillColor('gray').text('Generated by WebIntelX – For security assessment purposes only', { align: 'center' });
    doc.end();
  } catch (err) {
    console.error('FullScan PDF generation failed:', err);
    try { res.status(500).json({ error: 'PDF generation failed' }); } catch(e){}
  }
};
