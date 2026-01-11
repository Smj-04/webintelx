const { spawn } = require("child_process");
const cleanUrl = require("../utils/cleanUrl");
const { discoverEndpointsAndParams } = require("../utils/dynamicEndpointDiscovery");

// Internal function to test a specific URL/param combination with SQLMap
function testSqlmapEndpoint(testUrl, param) {
  return new Promise((resolve, reject) => {
    console.log(`🧪 Testing: ${testUrl} [param=${param}]`);

    // Build SQLMap command arguments
    const args = [
      "-u", testUrl,
      "-p", param,
      "--batch",
      "--level=1",     // Reduced from 2 to 1 for faster scanning
      "--risk=1",
      "--technique=BEUST", // Keep all techniques but with lower level
      "--dbs",
      "--time-sec=3",  // Reduced from 5 to 3 seconds
      "--threads=3",   // Increased from 2 to 3 threads
      "--timeout=8",   // Reduced from 10 to 8 seconds
      "--retries=1",
      "--disable-coloring"
    ];

    // Try different SQLMap commands based on installation method
    const sqlmapCommands = [
      { command: "sqlmap", args: args },
      { command: "python", args: ["-m", "sqlmap", ...args] },
      { command: "python3", args: ["-m", "sqlmap", ...args] },
      { command: "py", args: ["-m", "sqlmap", ...args] }
    ];

    let output = "";
    let errorOutput = "";
    let processKilled = false;
    let sqlmapProcess = null;
    let currentCommandIndex = 0;
    let timeout = null;

    // Function to try next command
    const tryNextCommand = () => {
      if (currentCommandIndex >= sqlmapCommands.length) {
        return reject(new Error("SQLMap is not installed or not accessible"));
      }

      // Clear any existing timeout
      if (timeout) {
        clearTimeout(timeout);
        timeout = null;
      }

      const { command, args: cmdArgs } = sqlmapCommands[currentCommandIndex];
      console.log(`📝 Trying SQLMap command: ${command} ${cmdArgs.join(" ")}`);

      // Spawn SQLMap process
      sqlmapProcess = spawn(command, cmdArgs, {
        maxBuffer: 1024 * 1024 * 50,
        shell: true,
        stdio: ['pipe', 'pipe', 'pipe']
      });

      // Send newline to handle any "Press Enter to continue" prompts
      setTimeout(() => {
        if (sqlmapProcess && !sqlmapProcess.killed) {
          try {
            sqlmapProcess.stdin.write('\n');
          } catch (e) {}
        }
      }, 1000);

      // Set timeout (30 seconds per endpoint - reduced for faster scanning)
      timeout = setTimeout(() => {
        if (!processKilled && sqlmapProcess) {
          processKilled = true;
          console.log("⏱️ SQLMap scan timeout for this endpoint");
          
          if (process.platform === "win32") {
            try {
              spawn("taskkill", ["/pid", sqlmapProcess.pid, "/f", "/t"], { shell: true });
            } catch (e) {
              sqlmapProcess.kill("SIGTERM");
            }
          } else {
            sqlmapProcess.kill("SIGTERM");
          }
          
          return resolve({ vulnerable: false, timeout: true });
        }
      }, 30000); // Reduced from 45s to 30s

      // Collect stdout
      sqlmapProcess.stdout.on("data", (data) => {
        const text = data.toString();
        output += text;
        
        if (text.includes("Press Enter") || text.includes("continue") || text.includes("[Y/n]")) {
          try {
            sqlmapProcess.stdin.write('\n');
          } catch (e) {}
        }
      });

      // Collect stderr
      sqlmapProcess.stderr.on("data", (data) => {
        const text = data.toString();
        errorOutput += text;
        
        if (text.includes("Press Enter") || text.includes("continue")) {
          try {
            sqlmapProcess.stdin.write('\n');
          } catch (e) {}
        }
      });

      // Handle process completion
      sqlmapProcess.on("close", (code) => {
        clearTimeout(timeout);

        if (processKilled) {
          return resolve({ vulnerable: false, timeout: true });
        }

        const fullOutput = output + errorOutput;
        const outputLower = fullOutput.toLowerCase();

        // Check if SQLMap is not found/installed - try next command
        if (code === 127 ||
            outputLower.includes("'sqlmap' is not recognized") ||
            outputLower.includes("command not found") ||
            outputLower.includes("sqlmap: command not found") ||
            outputLower.includes("no module named sqlmap") ||
            (code !== 0 && fullOutput.length === 0)) {
          
          currentCommandIndex++;
          output = "";
          errorOutput = "";
          return tryNextCommand();
        }

        // Check if SQLMap found injection
        const vulnerable =
          (outputLower.includes("parameter") &&
           (outputLower.includes("is vulnerable") ||
            outputLower.includes("is injectable") ||
            outputLower.includes("appears to be injectable") ||
            outputLower.includes("sql injection"))) ||
          (outputLower.includes("[*]") && outputLower.includes("database")) ||
          outputLower.includes("sqlmap identified the following injection point");

        if (!vulnerable) {
          return resolve({ vulnerable: false });
        }

        // Extract databases from SQLMap output
        const dbs = [];
        const dbPatterns = [
          /\[\*\]\s+([a-z0-9_\-]+)/gi,
          /available databases\s*\[(\d+)\]:\s*([^\n]+)/gi,
          /database:\s*'?([a-z0-9_\-]+)'?/gi,
        ];

        // False positives to filter out
        const falsePositives = [
          'starting', 'ending', 'available', 'databases', 
          'database', 'name', 'list', 'found'
        ];

        for (const pattern of dbPatterns) {
          let match;
          while ((match = pattern.exec(fullOutput)) !== null) {
            if (match[2]) {
              // Handle comma-separated list
              match[2].split(',').forEach(db => {
                const cleanDb = db.trim().replace(/['"\[\]]/g, '').toLowerCase();
                if (cleanDb && 
                    cleanDb.length > 1 && 
                    !falsePositives.includes(cleanDb) &&
                    !cleanDb.startsWith('[*]')) {
                  dbs.push(db.trim().replace(/['"\[\]]/g, ''));
                }
              });
            } else if (match[1]) {
              const cleanDb = match[1].toLowerCase();
              if (cleanDb && 
                  cleanDb.length > 1 && 
                  !falsePositives.includes(cleanDb) &&
                  !cleanDb.startsWith('[*]')) {
                dbs.push(match[1]);
              }
            }
          }
        }

        // Filter out false positives and clean database names
        const filteredDbs = [...new Set(dbs)]
          .map(db => db.trim())
          .filter(db => {
            const dbLower = db.toLowerCase();
            return db && 
                   db.length > 1 && 
                   !db.startsWith('[') && 
                   !db.endsWith(']') &&
                   !db.includes('[*]') &&
                   !falsePositives.includes(dbLower) &&
                   /^[a-z0-9_\-]+$/i.test(db); // Only alphanumeric, underscore, hyphen
          });

        return resolve({
          vulnerable: true,
          url: testUrl,
          param: param,
          databases: filteredDbs
        });
      });

      // Handle process errors
      sqlmapProcess.on("error", (err) => {
        clearTimeout(timeout);
        
        if (processKilled) {
          return resolve({ vulnerable: false });
        }

        // Check if SQLMap is not found - try next command
        if (err.code === 'ENOENT' ||
            (err.message.includes("spawn") && err.message.includes("ENOENT"))) {
          currentCommandIndex++;
          output = "";
          errorOutput = "";
          return tryNextCommand();
        }

        // If all commands failed, reject
        if (currentCommandIndex >= sqlmapCommands.length - 1) {
          return reject(err);
        }

        currentCommandIndex++;
        return tryNextCommand();
      });
    };

    // Start with first command
    tryNextCommand();
  });
}

// Main controller - accepts base URL OR full URL with endpoint
exports.runSqlmap = async (req, res) => {
  const { url, param } = req.body;

  if (!url) {
    return res.status(400).json({ error: "URL required" });
  }

  try {
    // Clean and prepare URL
    let inputUrl = url.trim();
    if (!inputUrl.startsWith("http://") && !inputUrl.startsWith("https://")) {
      inputUrl = "http://" + inputUrl;
    }

    const urlObj = new URL(inputUrl);
    const hasQueryParams = urlObj.searchParams.toString().length > 0;
    const cleanBaseUrl = cleanUrl(inputUrl);
    
    let endpoints = [];

    // Case 1: User provided full URL with parameters (specific endpoint)
    if (hasQueryParams || param) {
      console.log(`🎯 User provided specific endpoint: ${inputUrl}`);
      
      // Extract parameters from URL or use provided param
      const paramsToTest = [];
      
      if (param) {
        // User specified a parameter name
        paramsToTest.push({
          url: inputUrl,
          param: param,
          source: "user_specified"
        });
      } else {
        // Extract all parameters from URL query string
        urlObj.searchParams.forEach((value, key) => {
          paramsToTest.push({
            url: inputUrl,
            param: key,
            source: "user_specified"
          });
        });
      }

      if (paramsToTest.length > 0) {
        endpoints = paramsToTest;
        console.log(`📋 Testing ${endpoints.length} user-specified parameter(s)`);
      } else {
        // Fallback: discover endpoints from base URL
        console.log("🔍 No parameters found, discovering endpoints...");
        endpoints = await discoverEndpointsAndParams(cleanBaseUrl);
      }
    } 
    // Case 2: Base URL provided - discover endpoints automatically
    else {
      console.log(`🌐 Starting SQL injection scan for base URL: ${cleanBaseUrl}`);
      console.log("🔍 Discovering endpoints and parameters...");
      endpoints = await discoverEndpointsAndParams(cleanBaseUrl);
    }

    if (endpoints.length === 0) {
      return res.json({
        vulnerable: false,
        message: "No testable endpoints found",
        scanned: 0
      });
    }

    console.log(`📋 Found ${endpoints.length} endpoint/parameter combinations to test`);

    // Prioritize endpoints: User-specified first, then URL query params, 
    // then links, then forms, then pattern tests
    const prioritizedEndpoints = endpoints.sort((a, b) => {
      const priority = { 
        "user_specified": 0,  // Highest priority - user knows what they want
        "url_query": 1, 
        "link": 2, 
        "form": 3, 
        "pattern_test": 4 
      };
      const priorityA = priority[a.source] || 5;
      const priorityB = priority[b.source] || 5;
      
      // If same priority, prefer shorter URLs (often more important pages)
      if (priorityA === priorityB) {
        return a.url.length - b.url.length;
      }
      return priorityA - priorityB;
    });

    // Test endpoints in parallel (3 at a time for optimal speed)
    const CONCURRENT_TESTS = 3;
    let scanned = 0;
    let foundVulnerability = null;

    for (let i = 0; i < prioritizedEndpoints.length; i += CONCURRENT_TESTS) {
      const batch = prioritizedEndpoints.slice(i, i + CONCURRENT_TESTS);
      
      console.log(`\n[Batch ${Math.floor(i / CONCURRENT_TESTS) + 1}] Testing ${batch.length} endpoints in parallel...`);
      
      // Test batch in parallel
      const results = await Promise.allSettled(
        batch.map(endpoint => {
          console.log(`  🧪 Testing: ${endpoint.url}?${endpoint.param}=...`);
          return testSqlmapEndpoint(endpoint.url, endpoint.param);
        })
      );

      // Process results
      for (let j = 0; j < results.length; j++) {
        scanned++;
        const result = results[j];
        const endpoint = batch[j];

        if (result.status === 'fulfilled' && result.value.vulnerable) {
          foundVulnerability = {
            url: endpoint.url,
            param: endpoint.param,
            databases: result.value.databases || []
          };
          console.log(`🔥 SQL Injection FOUND: ${endpoint.url} [param=${endpoint.param}]`);
          break; // Exit batch loop
        } else if (result.status === 'rejected') {
          console.error(`❌ Error testing ${endpoint.url}:`, result.reason?.message || 'Unknown error');
        }
      }

      // If vulnerability found, return immediately (break out of outer loop)
      if (foundVulnerability) {
        return res.json({
          vulnerable: true,
          url: foundVulnerability.url,
          param: foundVulnerability.param,
          databases: foundVulnerability.databases,
          scanned: scanned,
          total: endpoints.length
        });
      }
    }

    // No vulnerabilities found
    return res.json({
      vulnerable: false,
      message: "No SQL injection vulnerabilities detected",
      scanned: endpoints.length,
      total: endpoints.length
    });

  } catch (error) {
    console.error("❌ SQLMap scan error:", error);
    return res.status(500).json({
      error: "SQLMap scan failed",
      vulnerable: false,
      details: error.message
    });
  }
};
