const { spawn } = require("child_process");
const cleanUrl = require("../utils/cleanUrl");
const { discoverEndpointsAndParams } = require("../utils/dynamicEndpointDiscovery");

// Cache the working SQLMap command so we don't re-probe on every call
let cachedSqlmapCommand = null;

// Probe once to find which sqlmap invocation works on this machine
async function resolveSqlmapCommand() {
  if (cachedSqlmapCommand) return cachedSqlmapCommand;

  const candidates = [
    { command: "sqlmap",  args: [] },
    { command: "python",  args: ["-m", "sqlmap"] },
    { command: "python3", args: ["-m", "sqlmap"] },
    { command: "py",      args: ["-m", "sqlmap"] },
  ];

  for (const candidate of candidates) {
    const found = await new Promise((resolve) => {
      const proc = spawn(candidate.command, [...candidate.args, "--version"], {
        shell: true,
        stdio: ["ignore", "pipe", "pipe"],
      });
      let out = "";
      proc.stdout.on("data", (d) => (out += d));
      proc.stderr.on("data", (d) => (out += d));
      proc.on("close", (code) => resolve(code === 0 || out.toLowerCase().includes("sqlmap")));
      proc.on("error", () => resolve(false));
    });

    if (found) {
      cachedSqlmapCommand = candidate;
      console.log(`✅ SQLMap resolved to: ${candidate.command}`);
      return candidate;
    }
  }

  throw new Error("SQLMap is not installed or not accessible");
}

// Test a single URL/param combination with SQLMap
function testSqlmapEndpoint(testUrl, param, sqlmapCmd) {
  return new Promise((resolve, reject) => {
    console.log(`🧪 Testing: ${testUrl} [param=${param}]`);

    const sqlmapArgs = [
      ...sqlmapCmd.args,       // e.g. ["-m", "sqlmap"] or []
      "-u", testUrl,
      "-p", param,
      "--batch",
      "--level=1",
      "--risk=1",
      "--technique=BET",       // Boolean-blind, Error-based, Time-blind — covers 95% of cases, faster than BEUST
      "--dbs",
      "--time-sec=3",
      "--threads=4",           // Slight bump; diminishing returns beyond 4 for a single endpoint
      "--timeout=8",
      "--retries=1",
      "--disable-coloring",
    ];

    let output = "";
    let errorOutput = "";
    let processKilled = false;

    const proc = spawn(sqlmapCmd.command, sqlmapArgs, {
      shell: true,
      stdio: ["pipe", "pipe", "pipe"],
      maxBuffer: 1024 * 1024 * 50,
    });

    // Dismiss any interactive prompts immediately
    const promptDismisser = setInterval(() => {
      if (!proc.killed) {
        try { proc.stdin.write("\n"); } catch (_) {}
      }
    }, 800);

    // Hard timeout — kill and resolve as not-vulnerable
    const timeout = setTimeout(() => {
      if (!processKilled) {
        processKilled = true;
        clearInterval(promptDismisser);
        console.log("⏱️ SQLMap scan timeout for this endpoint");

        if (process.platform === "win32") {
          try { spawn("taskkill", ["/pid", proc.pid, "/f", "/t"], { shell: true }); }
          catch (_) { proc.kill("SIGTERM"); }
        } else {
          proc.kill("SIGTERM");
        }

        resolve({ vulnerable: false, timeout: true });
      }
    }, 30000);

    proc.stdout.on("data", (data) => { output += data.toString(); });
    proc.stderr.on("data", (data) => { errorOutput += data.toString(); });

    proc.on("close", (code) => {
      clearTimeout(timeout);
      clearInterval(promptDismisser);

      if (processKilled) return resolve({ vulnerable: false, timeout: true });

      const fullOutput = output + errorOutput;
      const outputLower = fullOutput.toLowerCase();

      // Treat exit-code 127 / "not found" messages as a hard error
      if (
        code === 127 ||
        outputLower.includes("'sqlmap' is not recognized") ||
        outputLower.includes("command not found") ||
        outputLower.includes("no module named sqlmap") ||
        (code !== 0 && fullOutput.length === 0)
      ) {
        cachedSqlmapCommand = null; // Bust cache so next call re-probes
        return reject(new Error("SQLMap not found — cache busted"));
      }

      // Vulnerability detection (unchanged logic)
      const vulnerable =
        (outputLower.includes("parameter") &&
          (outputLower.includes("is vulnerable") ||
            outputLower.includes("is injectable") ||
            outputLower.includes("appears to be injectable") ||
            outputLower.includes("sql injection"))) ||
        (outputLower.includes("[*]") && outputLower.includes("database")) ||
        outputLower.includes("sqlmap identified the following injection point");

      if (!vulnerable) return resolve({ vulnerable: false });

      // Database extraction (unchanged logic)
      const falsePositives = ["starting", "ending", "available", "databases", "database", "name", "list", "found"];
      const dbs = [];
      const dbPatterns = [
        /\[\*\]\s+([a-z0-9_\-]+)/gi,
        /available databases\s*\[(\d+)\]:\s*([^\n]+)/gi,
        /database:\s*'?([a-z0-9_\-]+)'?/gi,
      ];

      for (const pattern of dbPatterns) {
        let match;
        while ((match = pattern.exec(fullOutput)) !== null) {
          if (match[2]) {
            match[2].split(",").forEach((db) => {
              const clean = db.trim().replace(/['"\[\]]/g, "").toLowerCase();
              if (clean && clean.length > 1 && !falsePositives.includes(clean) && !clean.startsWith("[*]")) {
                dbs.push(db.trim().replace(/['"\[\]]/g, ""));
              }
            });
          } else if (match[1]) {
            const clean = match[1].toLowerCase();
            if (clean && clean.length > 1 && !falsePositives.includes(clean) && !clean.startsWith("[*]")) {
              dbs.push(match[1]);
            }
          }
        }
      }

      const filteredDbs = [...new Set(dbs)]
        .map((db) => db.trim())
        .filter((db) => {
          const dbLower = db.toLowerCase();
          return (
            db &&
            db.length > 1 &&
            !db.startsWith("[") &&
            !db.endsWith("]") &&
            !db.includes("[*]") &&
            !falsePositives.includes(dbLower) &&
            /^[a-z0-9_\-]+$/i.test(db)
          );
        });

      resolve({ vulnerable: true, url: testUrl, param, databases: filteredDbs });
    });

    proc.on("error", (err) => {
      clearTimeout(timeout);
      clearInterval(promptDismisser);
      if (!processKilled) reject(err);
    });
  });
}

// Main controller
exports.runSqlmap = async (req, res) => {
  const { url, param } = req.body;

  if (!url) return res.status(400).json({ error: "URL required" });

  try {
    // Resolve sqlmap command once (cached after first call)
    const sqlmapCmd = await resolveSqlmapCommand();

    let inputUrl = url.trim();
    if (!inputUrl.startsWith("http://") && !inputUrl.startsWith("https://")) {
      inputUrl = "http://" + inputUrl;
    }

    const urlObj = new URL(inputUrl);
    const hasQueryParams = urlObj.searchParams.toString().length > 0;
    const cleanBaseUrl = cleanUrl(inputUrl);

    let endpoints = [];

    if (hasQueryParams || param) {
      console.log(`🎯 User provided specific endpoint: ${inputUrl}`);
      const paramsToTest = [];

      if (param) {
        paramsToTest.push({ url: inputUrl, param, source: "user_specified" });
      } else {
        urlObj.searchParams.forEach((value, key) => {
          paramsToTest.push({ url: inputUrl, param: key, source: "user_specified" });
        });
      }

      endpoints = paramsToTest.length > 0
        ? paramsToTest
        : await discoverEndpointsAndParams(cleanBaseUrl);
    } else {
      console.log(`🌐 Starting SQL injection scan for base URL: ${cleanBaseUrl}`);
      endpoints = await discoverEndpointsAndParams(cleanBaseUrl);
    }

    if (endpoints.length === 0) {
      return res.json({ vulnerable: false, message: "No testable endpoints found", scanned: 0 });
    }

    console.log(`📋 Found ${endpoints.length} endpoint/parameter combinations to test`);

    // Same priority sort as before
    const prioritizedEndpoints = endpoints.sort((a, b) => {
      const priority = { user_specified: 0, url_query: 1, link: 2, form: 3, pattern_test: 4 };
      const pa = priority[a.source] ?? 5;
      const pb = priority[b.source] ?? 5;
      return pa !== pb ? pa - pb : a.url.length - b.url.length;
    });

    const CONCURRENT_TESTS = 3;
    let scanned = 0;

    for (let i = 0; i < prioritizedEndpoints.length; i += CONCURRENT_TESTS) {
      const batch = prioritizedEndpoints.slice(i, i + CONCURRENT_TESTS);
      console.log(`\n[Batch ${Math.floor(i / CONCURRENT_TESTS) + 1}] Testing ${batch.length} endpoints in parallel...`);

      // Race: resolve as soon as ANY endpoint in the batch is vulnerable
      const batchResults = await Promise.allSettled(
        batch.map((ep) => testSqlmapEndpoint(ep.url, ep.param, sqlmapCmd))
      );

      for (let j = 0; j < batchResults.length; j++) {
        scanned++;
        const result = batchResults[j];
        const endpoint = batch[j];

        if (result.status === "fulfilled" && result.value.vulnerable) {
          console.log(`🔥 SQL Injection FOUND: ${endpoint.url} [param=${endpoint.param}]`);
          return res.json({
            vulnerable: true,
            url: endpoint.url,
            param: endpoint.param,
            databases: result.value.databases || [],
            scanned,
            total: endpoints.length,
          });
        } else if (result.status === "rejected") {
          console.error(`❌ Error testing ${endpoint.url}:`, result.reason?.message || "Unknown error");
        }
      }
    }

    return res.json({
      vulnerable: false,
      message: "No SQL injection vulnerabilities detected",
      scanned: endpoints.length,
      total: endpoints.length,
    });

  } catch (error) {
    console.error("❌ SQLMap scan error:", error);
    return res.status(500).json({ error: "SQLMap scan failed", vulnerable: false, details: error.message });
  }
};