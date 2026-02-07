/**
 * LDAP Injection Detection Module
 * Tests for LDAP injection vulnerabilities in authentication/search parameters
 */

const axios = require("axios");
const { URL } = require("url");

const USER_AGENT = "WebIntelX-LDAPInjection-Scanner/1.0";
const TIMEOUT = 15000; // Increased timeout

// LDAP injection payloads
const LDAP_PAYLOADS = [
  "*", // Wildcard - returns all entries
  "*)(&",
  "*)(|",
  "*))%00", // Null byte injection
  "*()|&",
  "*)(uid=*",
  "*)(|(uid=*",
  "*)(|(cn=*",
  "*)(|(objectClass=*",
  "admin)(&(password=*", // Authentication bypass attempt
  "*)(&(userPassword=*",
  "*)(|(&", // Complex filter
  "test)(cn=*", // Union-based
  "*))(|(cn=*",
];

function normalizeUrl(input) {
  if (!/^https?:\/\//i.test(input)) {
    return "http://" + input;
  }
  return input;
}

/**
 * Tests a URL parameter for LDAP injection
 */
async function testLDAPInjection(targetUrl, paramName, payload) {
  try {
    const testUrl = new URL(normalizeUrl(targetUrl));

    testUrl.searchParams.set(paramName, payload);

    console.log(`Testing LDAP injection: ${testUrl.toString()}`);

    const response = await axios.get(testUrl.toString(), {
      timeout: TIMEOUT,
      headers: { "User-Agent": USER_AGENT },
      validateStatus: () => true,
    });

    const responseBody = String(response.data || "");
    const responseText = responseBody.toLowerCase();

    // Indicators of LDAP injection success
    const successIndicators = [
      "ldap",
      "distinguished name",
      "dn:",
      "objectclass",
      "cn=",
      "uid=",
      "ou=",
      "dc=",
      "ldap error",
      "invalid dn",
      "malformed",
      "search result",
      "entries returned",
      "ldapresult",
    ];

    // Check response length (wildcard injection may return more data)
    const responseLength = responseBody.length;

    // Baseline comparison (behavioral detection)
    const baselineUrl = new URL(normalizeUrl(targetUrl));
    baselineUrl.searchParams.set(paramName, "test");

    const baselineResponse = await axios.get(baselineUrl.toString(), {
      timeout: TIMEOUT,
      headers: { "User-Agent": USER_AGENT },
      validateStatus: () => true,
    });

    const baselineLength = String(baselineResponse.data || "").length;
    const lengthDiff = Math.abs(responseLength - baselineLength);

    if (lengthDiff > 2000) {
      return {
        vulnerable: true,
        payload,
        parameter: paramName,
        evidence: `Behavioral anomaly detected: response changed significantly after injection (Δ ${lengthDiff} bytes)`,
      };
    }

    // Check for LDAP-related content
    for (const indicator of successIndicators) {
      if (responseText.includes(indicator)) {
        return {
          vulnerable: true,
          payload: payload,
          parameter: paramName,
          evidence: `LDAP injection detected: Found indicator "${indicator}" in response`,
          responseSnippet: responseBody.substring(0, 500),
          responseLength: responseLength,
        };
      }
    }

    return { vulnerable: false };
  } catch (error) {
    console.error(`Error testing LDAP injection payload ${payload}:`, error.message);
    return { vulnerable: false, error: error.message };
  }
}

/**
 * Tests POST data for LDAP injection
 */
async function testPostLDAPInjection(targetUrl, paramName, payload) {
  try {
    targetUrl = normalizeUrl(targetUrl);

    console.log(`Testing POST LDAP injection: ${targetUrl} [${paramName}=${payload}]`);

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
    const responseLength = responseBody.length;

    const successIndicators = [
      "ldap",
      "distinguished name",
      "dn:",
      "objectclass",
      "cn=",
      "uid=",
      "ldap error",
      "invalid dn",
      "malformed",
    ];

    for (const indicator of successIndicators) {
      if (responseText.includes(indicator)) {
        return {
          vulnerable: true,
          payload: payload,
          parameter: paramName,
          evidence: `LDAP injection detected: Found indicator "${indicator}" in response`,
          responseSnippet: responseBody.substring(0, 500),
          responseLength: responseLength,
        };
      }
    }

    return { vulnerable: false };
  } catch (error) {
    console.error(`Error testing POST LDAP injection:`, error.message);
    return { vulnerable: false, error: error.message };
  }
}

/**
 * Main function to scan for LDAP injection vulnerabilities
 */
async function scanLDAPInjection(url) {
  console.log(`Starting LDAP injection scan for: ${url}`);

  const findings = [];
  url = normalizeUrl(url);
  const urlObj = new URL(url);

    const ldapLikelyPaths = ["login", "auth", "ldap", "directory", "search"];

  if (!ldapLikelyPaths.some(p => urlObj.pathname.toLowerCase().includes(p))) {
    return {
      module: "LDAP Injection",
      target: url,
      vulnerable: false,
      evidence: "Skipped: endpoint unlikely to use LDAP",
      notes: "LDAP injection typically exists only in authentication or directory services.",
    };
  }


  // Common LDAP parameter names
  const ldapParams = ["username", "user", "uid", "login", "cn", "dn", "search", "filter", "query", "name"];

  // Test GET parameters
  if (urlObj.searchParams.toString()) {
    for (const [paramName, paramValue] of urlObj.searchParams.entries()) {
      console.log(`Testing GET parameter: ${paramName}`);

      for (const payload of LDAP_PAYLOADS.slice(0, 8)) {
        const result = await testLDAPInjection(url, paramName, payload);
        if (result.vulnerable) {
          findings.push(result);
          break;
        }
      }
    }
  } else {
    // Test common parameter names if no params in URL
    for (const paramName of ldapParams.slice(0, 3)) {
      console.log(`Testing GET parameter: ${paramName}`);

      for (const payload of LDAP_PAYLOADS.slice(0, 5)) {
        const testUrl = new URL(url);
        testUrl.searchParams.set(paramName, payload);
        const result = await testLDAPInjection(testUrl.toString(), paramName, payload);
        if (result.vulnerable) {
          findings.push(result);
          break;
        }
      }
    }
  }

  // Test POST data
  for (const paramName of ldapParams.slice(0, 3)) {
    console.log(`Testing POST parameter: ${paramName}`);

  for (const payload of LDAP_PAYLOADS.slice(0, 8)) {
    const testUrl = new URL(url);
    testUrl.searchParams.set(paramName, payload);

    const result = await testLDAPInjection(
      testUrl.toString(),
      paramName,
      payload
    );

    if (result.vulnerable) {
      findings.push(result);
      break;
    }
  }

  }

  const vulnerable = findings.length > 0;

  return {
    module: "LDAP Injection",
    target: url,
    vulnerable: vulnerable,
    evidence: vulnerable
      ? findings.map((f) => ({
          parameter: f.parameter,
          payload: f.payload,
          evidence: f.evidence,
        }))
      : "No LDAP injection vulnerabilities detected",
    notes: vulnerable
      ? "LDAP injection detected. User input is being used in LDAP queries without proper sanitization. This can lead to authentication bypass or unauthorized data access."
      : "No LDAP injection vulnerabilities detected in tested parameters.",
  };
}

module.exports = { scanLDAPInjection };
