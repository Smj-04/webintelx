/**
 * Server-Side Template Injection (SSTI) Detection Module
 * Tests for template injection vulnerabilities in various template engines
 */

const axios = require("axios");
const { URL } = require("url");

const USER_AGENT = "WebIntelX-SSTI-Scanner/1.0";
const TIMEOUT = 40000; // Increased timeout

// SSTI payloads for different template engines
const SSTI_PAYLOADS = {
  // EJS / ERB (Node.js, Ruby)
  ejs: [
    "<%= 7*7 %>",
    "<%= 7*'7' %>",
  ],

  // Jinja2 (Python)
  jinja2: [
    "{{7*7}}",
    "{{7*'7'}}",
    "{{config}}",
    "{{self}}",
    "${7*7}",
    "#{7*7}",
  ],
  // Twig (PHP)
  twig: [
    "{{7*7}}",
    "{{7*'7'}}",
    "${7*7}",
    "#{7*7}",
  ],
  // Freemarker (Java)
  freemarker: [
    "${7*7}",
    "#{7*7}",
    "${7*'7'}",
  ],
  // Velocity (Java)
  velocity: [
    "#set($x=7*7)${x}",
    "${{7*7}}",
    "${{7*'7'}}",
  ],
  // Smarty (PHP)
  smarty: [
    "{7*7}",
    "{$smarty.version}",
    "${7*7}",
  ],
  // Generic - test multiple syntaxes
  generic: [
    "{{7*7}}",
    "${7*7}",
    "#{7*7}",
    "{7*7}",
    "${7*7}",
    "@{7*7}",
    "{{7*'7'}}",
    "${7*'7'}",
    "#{7*'7'}",
    "<%= 7*7 %>",  
    "<%= 7*'7' %>"
  ],
};

/**
 * Tests a URL parameter for SSTI
 */
function normalizeUrl(input) {
  if (!/^https?:\/\//i.test(input)) {
    return "http://" + input;
  }
  return input;
}

async function testSSTI(targetUrl, paramName, payload) {
  try {
  const testUrl = new URL(normalizeUrl(targetUrl));

  // 🔹 BASELINE REQUEST (ADD THIS BLOCK)
  const baselineUrl = new URL(normalizeUrl(targetUrl));
  baselineUrl.searchParams.set(paramName, "test");

  const baselineResponse = await axios.get(baselineUrl.toString(), {
    timeout: TIMEOUT,
    headers: { "User-Agent": USER_AGENT },
    validateStatus: () => true,
  });

  const baselineText = String(baselineResponse.data || "").toLowerCase();
  // 🔹 END BASELINE BLOCK

  testUrl.searchParams.set(paramName, payload);


    console.log(`Testing SSTI: ${testUrl.toString()}`);

    const response = await axios.get(testUrl.toString(), {
      timeout: TIMEOUT,
      headers: { "User-Agent": USER_AGENT },
      validateStatus: () => true,
    });

    const responseBody = String(response.data || "");
    const responseText = responseBody.toLowerCase();

    // Check if arithmetic expression was evaluated
    // 7*7 = 49, 7*'7' = '7777777' (7 times)
    const evaluationMarkers = ["49", "7777777"];

    for (const marker of evaluationMarkers) {
      if (responseText.includes(marker) && !baselineText.includes(marker)) {
        // Verify it's not just part of the payload
        if (!responseBody.includes(payload)) {
          return {
            vulnerable: true,
            payload: payload,
            parameter: paramName,
            evidence: `Template injection detected: Expression evaluated to "${marker}" in response`,
            responseSnippet: responseBody.substring(0, 500),
            templateEngine: detectTemplateEngine(payload),
          };
        }
      }
    }

    // Check for template-specific error messages
    const templateErrors = [
      "jinja2",
      "twig",
      "freemarker",
      "velocity",
      "smarty",
      "template",
      "syntax error",
      "template error",
      "parse error",
    ];

    for (const error of templateErrors) {
      if (responseText.includes(error)) {
       return {
        vulnerable: false,
        possible: true,
        payload: payload,
        parameter: paramName,
        evidence: `Possible SSTI: template error detected (${error})`,
        responseSnippet: responseBody.substring(0, 500),
        templateEngine: `Likely syntax: ${detectTemplateEngine(payload)}`,
      };

      }
    }

    return { vulnerable: false };
  } catch (error) {
    console.error(`Error testing SSTI payload ${payload}:`, error.message);
    return { vulnerable: false, error: error.message };
  }
}

/**
 * Tests POST data for SSTI
 */
async function testPostSSTI(targetUrl, paramName, payload) {
  try {
    console.log(`Testing POST SSTI: ${targetUrl} [${paramName}=${payload}]`);

    const response = await axios.post(
      targetUrl,
      { [paramName]: payload },
      {
        timeout: TIMEOUT,
        headers: {
          "User-Agent": USER_AGENT,
          "Content-Type": "application/json",
        },
        validateStatus: () => true,
      }
    );

    const responseBody = String(response.data || "");
    const responseText = responseBody.toLowerCase();

    const evaluationMarkers = ["49", "7777777"];

    for (const marker of evaluationMarkers) {
      if (responseText.includes(marker) && !responseBody.includes(payload)) {
        return {
          vulnerable: true,
          payload: payload,
          parameter: paramName,
          evidence: `Template injection detected: Expression evaluated to "${marker}" in response`,
          responseSnippet: responseBody.substring(0, 500),
          templateEngine: detectTemplateEngine(payload),
        };
      }
    }

    const templateErrors = [
      "jinja2",
      "twig",
      "freemarker",
      "velocity",
      "smarty",
      "template error",
    ];

    for (const error of templateErrors) {
      if (responseText.includes(error)) {
       return {
        vulnerable: false,
        possible: true,
        payload: payload,
        parameter: paramName,
        evidence: `Possible SSTI: template error detected (${error})`,
        responseSnippet: responseBody.substring(0, 500),
        templateEngine: `Likely syntax: ${detectTemplateEngine(payload)}`,
      };

      }
    }

    return { vulnerable: false };
  } catch (error) {
    console.error(`Error testing POST SSTI:`, error.message);
    return { vulnerable: false, error: error.message };
  }
}

/**
 * Detects template engine from payload syntax
 */
function detectTemplateEngine(payload) {
  if (payload.includes("{{") && payload.includes("}}")) {
    return "Jinja2/Twig";
  }
  if (payload.includes("${") && payload.includes("}")) {
    return "Freemarker/Velocity";
  }
  if (payload.includes("#{")) {
    return "Freemarker/Velocity";
  }
  if (payload.includes("{") && !payload.includes("{{")) {
    return "Smarty";
  }
  return "Unknown";
}

/**
 * Main function to scan for SSTI vulnerabilities
 */
async function scanSSTI(url) {
  console.log(`Starting SSTI scan for: ${url}`);

  const findings = [];
  url = normalizeUrl(url);
  const urlObj = new URL(url);


  // Test generic payloads first
  const payloadsToTest = SSTI_PAYLOADS.generic;

  // Test GET parameters
  if (urlObj.searchParams.toString()) {
    for (const [paramName, paramValue] of urlObj.searchParams.entries()) {
      console.log(`Testing GET parameter: ${paramName}`);

      for (const payload of payloadsToTest.slice(0, 6)) {
        const result = await testSSTI(url, paramName, payload);
        if (result.vulnerable) {
          findings.push(result);
          break; // Found vulnerability, move to next parameter
        }
      }
    }
  } else {
    // Test common parameter names
    const testParams = ["name", "template", "view", "page", "file", "input"];
    for (const paramName of testParams.slice(0, 3)) {
      console.log(`Testing GET parameter: ${paramName}`);

      for (const payload of payloadsToTest.slice(0, 4)) {
        const testUrl = new URL(url);
        testUrl.searchParams.set(paramName, payload);
        const result = await testSSTI(testUrl.toString(), paramName, payload);
        if (result.vulnerable) {
          findings.push(result);
          break;
        }
      }
    }
  }

  // Test POST data
  const postParams = ["name", "template", "view", "content", "input"];
  for (const paramName of postParams.slice(0, 3)) {
    console.log(`Testing POST parameter: ${paramName}`);

    for (const payload of payloadsToTest.slice(0, 4)) {
      const result = await testPostSSTI(urlObj.origin + urlObj.pathname, paramName, payload);
      if (result.vulnerable) {
        findings.push(result);
        break;
      }
    }
  }

  const vulnerable = findings.some(f => f.vulnerable === true);
  const possible = findings.some(f => f.possible === true);


return {
  module: "Server-Side Template Injection",
  target: url,
  vulnerable,
  possible,
  evidence: findings.length > 0 ? findings : "No SSTI indicators detected",
  notes: vulnerable
    ? "Confirmed SSTI: server-side template expressions were evaluated."
    : possible
    ? "Possible SSTI: template errors detected but no expression execution confirmed."
    : "No SSTI vulnerabilities detected.",
};

}

module.exports = { scanSSTI };
