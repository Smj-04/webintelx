const cleanUrl = require("../utils/cleanUrl");
const endpointScanner = require("../utils/endpointScanner");
const axios = require("axios");
const dns = require("dns").promises;
const PDFDocument = require("pdfkit");
console.log("🔥 fullScanController.js LOADED");
const sensitiveFileCheck = require("../utils/sensitiveFileCheck");

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

// ==========================
// 🔹 TARGET VALIDATION
// ==========================

async function validateTarget(url) {
  try {
    const formatted = url.startsWith("http")
      ? url
      : `http://${url}`;

    const hostname = new URL(formatted).hostname;

    // 1️⃣ DNS resolution check
    await dns.lookup(hostname);

    // 2️⃣ Try HTTPS first, fallback to HTTP
    try {
      await axios.get(`https://${hostname}`, { timeout: 5000 });
    } catch {
      await axios.get(`http://${hostname}`, { timeout: 5000 });
    }

    return { valid: true };
  } catch (err) {
    return {
      valid: false,
      error: "Target is not reachable or does not exist",
    };
  }
}
exports.fullScan = async (req, res) => {
  console.log("🔥 FULLSCAN CONTROLLER LOADED");

  const { url } = req.body;
  if (!url) return res.status(400).json({ error: "URL required" });

  const startedAt = new Date().toISOString();
  const baseUrl = cleanUrl(url);

  // ==========================
// 🔹 VALIDATE TARGET HERE
// ==========================
const validation = await validateTarget(baseUrl);

if (!validation.valid) {
  return res.status(400).json({
    success: false,
    error: validation.error
  });
}
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
      reflectedXss: { found: false, details: null },
      clickjacking: { vulnerable: false, headers: {} },
      commandInjection: { found: false, details: null },
      csrf: { found: false, details: null },
      sensitiveFiles: { found: false, details: null }
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

    // 3) Run SQLMap AND all other modules in parallel simultaneously

      const [sqlResult, ...moduleResults] = await Promise.allSettled([

      //const moduleResults = await Promise.allSettled([
      // SQLMap — stops immediately on first vulnerability found
      
      (async () => {
        const sqlFindings = [];
        for (const target of endpoints) {
          const resSql = await safePost(
            "http://localhost:5000/api/sqlmap",
            { url: target.url, param: target.param },
            { timeout: 40000 }
          );
          if (resSql.ok && resSql.data && resSql.data.vulnerable) {
            sqlFindings.push({
              url: target.url,
              param: target.param,
              databases: resSql.data.databases || []
            });
            console.log(`🔥 SQLi found — stopping endpoint loop early`);
            break; // ← STOP after first vulnerability
          }
        }
        return sqlFindings;
      })(),

      // All other modules unchanged
      axios.post("http://localhost:5000/api/dom-xss", { url: baseUrl }, { timeout: 180000 }),
      axios.post("http://localhost:5000/api/stored-xss", { url: baseUrl }, { timeout: 180000 }),
      axios.post("http://localhost:5000/api/autoxss", { url: baseUrl }, { timeout: 180000 }),
      axios.post("http://localhost:5000/api/clickjacking", { url: baseUrl }, { timeout: 180000 }),
      axios.post("http://localhost:5000/api/command-injection", { url: baseUrl }, { timeout: 180000 }),
      axios.post("http://localhost:5000/api/csrf", { url: baseUrl }, { timeout: 180000 }),
      axios.post("http://localhost:5000/api/sensitive-files", { url: baseUrl }, { timeout: 180000 })
    ]);

      // Process SQLMap result
      if (sqlResult.status === 'fulfilled') {
        const sqlFindings = sqlResult.value;
        if (sqlFindings.length > 0) {
          fullResult.vulnerabilities.sqlInjection.found = true;
          fullResult.vulnerabilities.sqlInjection.details = { findings: sqlFindings };
          fullResult.summary.high += 1;
        }
      }

      // Process other modules (index shifted by 1 since sqlResult is index 0)
      const safeModule = (settled) => {
        if (!settled) return { ok: false };
        if (settled.status === 'fulfilled') return { ok: true, data: settled.value.data };
        return { ok: false, error: settled.reason?.message || String(settled.reason) };
      };

      const domRes      = safeModule(moduleResults[0]);
      const storedRes   = safeModule(moduleResults[1]);
      const reflectedRes = safeModule(moduleResults[2]);
      const clickRes    = safeModule(moduleResults[3]);
      const cmdRes      = safeModule(moduleResults[4]);
      const csrfRes     = safeModule(moduleResults[5]);
      const sensitiveRes = safeModule(moduleResults[6]);


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

    // Reflected / Auto XSS
    if (reflectedRes.ok && reflectedRes.data) {
      const vulnerableEndpoints = reflectedRes.data.vulnerableEndpoints || [];
      const vulnerableCount = Array.isArray(vulnerableEndpoints) ? vulnerableEndpoints.length : 0;
      fullResult.vulnerabilities.reflectedXss.found = vulnerableCount > 0;
      // Store all AutoXSS data: testedEndpoints, vulnerableEndpoints
      fullResult.vulnerabilities.reflectedXss.details = {
        testedEndpoints: reflectedRes.data.testedEndpoints || 0,
        vulnerableEndpoints: vulnerableEndpoints,
        base: reflectedRes.data.base || null
      };
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

     if (csrfRes.ok && csrfRes.data) {
      const csrfVulnerable = csrfRes.data.summary?.vulnerable > 0;
      fullResult.vulnerabilities.csrf.found = csrfVulnerable;
      fullResult.vulnerabilities.csrf.details = csrfRes.data || null;
      if (csrfVulnerable) {
        fullResult.summary.high += 1;
      }
    }

    if (sensitiveRes.ok && sensitiveRes.data) {
      fullResult.vulnerabilities.sensitiveFiles.found = !!sensitiveRes.data.vulnerable;
      fullResult.vulnerabilities.sensitiveFiles.details = sensitiveRes.data || null;
      if (sensitiveRes.data.summary?.critical > 0) {
        fullResult.summary.critical += 1;
      } else if (sensitiveRes.data.summary?.high > 0) {
        fullResult.summary.high += 1;
      } else if (sensitiveRes.data.vulnerable) {
        fullResult.summary.medium += 1;
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
    doc.fontSize(11).fillColor('black').text('This Full Scan aggregates QuickScan reconnaissance and targeted vulnerability tests (SQLi, DOM XSS, Stored XSS, Reflected XSS, Clickjacking, Command Injection). Findings are risk-classified for prioritization.');
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
      { name: 'Reflected XSS', found: vuln.reflectedXss?.found },
      { name: 'Clickjacking', found: vuln.clickjacking.vulnerable },
      { name: 'Command Injection', found: vuln.commandInjection.found },
      { name: 'CSRF', found: vuln.csrf?.found },
      { name: 'Sensitive File Exposure', found: vuln.sensitiveFiles?.found }

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
      const domEvidence = vuln.domXss.details?.evidence;
      if (Array.isArray(domEvidence)) {
        domEvidence.forEach((item, idx) => {
          doc.fontSize(10).text(`${idx + 1}. Type: ${item.type || 'Unknown'}`);
          doc.fontSize(10).text(`   Location: ${item.location || 'Unknown'}`);
          doc.fontSize(10).text(`   Evidence: ${item.evidence || 'N/A'}`);
          doc.fontSize(10).text(`   Confidence: ${item.confidence || 'Unknown'}`);
          doc.moveDown(0.3);
        });
      } else {
        doc.fontSize(11).text(vuln.domXss.details?.notes || "DOM-based payload reflection detected");
      }
      doc.moveDown(0.5);
    }

    if (vuln.storedXss.found) {
      doc.fontSize(14).fillColor('#1f2937').text('Stored XSS — Details', { underline: true });
      doc.moveDown(0.5);
      const storedEvidence = vuln.storedXss.details?.evidence;
      if (Array.isArray(storedEvidence)) {
        storedEvidence.forEach((item, idx) => {
          doc.fontSize(10).text(`${idx + 1}. Location: ${item.location || 'Unknown'}`);
          doc.fontSize(10).text(`   Payload: ${item.payload || 'N/A'} (truncated)`);
          doc.fontSize(10).text(`   Evidence: ${item.evidence || 'N/A'}`);
          doc.fontSize(10).text(`   Confidence: ${item.confidence || 'Unknown'}`);
          doc.moveDown(0.3);
        });
      } else {
        doc.fontSize(11).text(vuln.storedXss.details?.notes || "Stored XSS payload detected");
      }
      doc.moveDown(0.5);
    }

    if (vuln.reflectedXss && vuln.reflectedXss.found) {
      doc.fontSize(14).fillColor('#1f2937').text('Reflected XSS — Details', { underline: true });
      doc.moveDown(0.5);
      const refDetails = vuln.reflectedXss.details || {};
      doc.fontSize(11).text(`Endpoints tested: ${refDetails.testedEndpoints || 0}`);
      doc.fontSize(11).text(`Vulnerable endpoints found: ${(refDetails.vulnerableEndpoints || []).length || 0}`);
      doc.moveDown(0.5);
      const vulnEndpoints = refDetails.vulnerableEndpoints || [];
      if (vulnEndpoints.length > 0) {
        vulnEndpoints.slice(0, 10).forEach((ep, idx) => {
          doc.fontSize(10).text(`${idx + 1}. URL: ${ep.url || 'Unknown'}`);
          if (Array.isArray(ep.findings) && ep.findings.length > 0) {
            ep.findings.slice(0, 3).forEach((f) => {
              doc.fontSize(9).text(`   - ${f.type || 'Finding'}: ${f.evidence || 'Detected'} (${f.confidence || 'unknown'})`);
            });
          }
          doc.moveDown(0.2);
        });
      }
      doc.moveDown(0.5);
    }

    if (vuln.clickjacking.vulnerable) {
      doc.fontSize(14).fillColor('#1f2937').text('Clickjacking — Details', { underline: true });
      doc.moveDown(0.5);
      const clickDetails = vuln.clickjacking.details || {};
      doc.fontSize(11).text(`Issue: ${clickDetails.issue || 'Missing X-Frame-Options / CSP frame-ancestors'}`);
      doc.moveDown(0.3);
      if (clickDetails.headers && Object.keys(clickDetails.headers).length > 0) {
        doc.fontSize(10).text('Relevant headers:');
        Object.entries(clickDetails.headers).slice(0, 5).forEach(([k, v]) => {
          doc.fontSize(9).text(`• ${k}: ${String(v).substring(0, 50)}...`);
        });
      }
      doc.moveDown(0.5);
    }

    if (vuln.commandInjection.found) {
      doc.fontSize(14).fillColor('#1f2937').text('Command Injection — Details', { underline: true });
      doc.moveDown(0.5);
      const cmdDetails = vuln.commandInjection.details || {};
      doc.fontSize(11).text(`Confidence: ${cmdDetails.confidence || 'Unknown'}`);
      doc.fontSize(11).text(`Notes: ${cmdDetails.notes || 'Vulnerability confirmed'}`);
      doc.moveDown(0.3);
      const cmdEvidence = cmdDetails.evidence;
      if (Array.isArray(cmdEvidence)) {
        cmdEvidence.forEach((item, idx) => {
          doc.fontSize(10).text(`${idx + 1}. Parameter: ${item.parameter || 'Unknown'}`);
          doc.fontSize(10).text(`   Payload: ${item.payload || 'N/A'} (snippet)`);
          doc.fontSize(10).text(`   Evidence: ${item.evidence || 'N/A'}`);
          doc.moveDown(0.2);
        });
      } else if (cmdEvidence) {
        doc.fontSize(10).text(JSON.stringify(cmdEvidence, null, 2).substring(0, 200));
      }
      doc.moveDown(0.5);
    }

    if (vuln.csrf && vuln.csrf.found) {
          doc.fontSize(14).fillColor('#1f2937').text('CSRF — Details', { underline: true });
          doc.moveDown(0.5);
          const csrfDetails = vuln.csrf.details || {};
          const csrfSummary = csrfDetails.summary || {};
          doc.fontSize(11).text(`Total Endpoints Tested: ${csrfSummary.totalEndpoints || 0}`);
          doc.fontSize(11).text(`Vulnerable: ${csrfSummary.vulnerable || 0}`);
          doc.fontSize(11).text(`Safe: ${csrfSummary.safe || 0}`);
          doc.moveDown(0.4);
          const csrfVulnEndpoints = csrfDetails.vulnerableEndpoints || [];
          if (csrfVulnEndpoints.length > 0) {
            doc.fontSize(11).text('Vulnerable Endpoints:');
            csrfVulnEndpoints.slice(0, 10).forEach((ep, idx) => {
              doc.fontSize(10).text(`${idx + 1}. ${ep.endpoint || 'Unknown'} [${ep.method || 'POST'}]`);
              doc.fontSize(9).text(`   Status: ${ep.status}  Confidence: ${ep.confidence}  Risk: ${ep.risk}`);
              doc.moveDown(0.2);
            });
          }
          doc.moveDown(0.5);
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
