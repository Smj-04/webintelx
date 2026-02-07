/**
 * Token Authentication Detection Module
 * Tests for JWT and token authentication vulnerabilities
 */

const axios = require("axios");
const { URL } = require("url");

const USER_AGENT = "WebIntelX-TokenAuth-Scanner/1.0";
const TIMEOUT = 40000; // Increased timeout

/**
 * Decodes base64 URL-encoded string
 */
function base64UrlDecode(str) {
  try {
    // Add padding if needed
    let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
    while (base64.length % 4) {
      base64 += "=";
    }
    return Buffer.from(base64, "base64").toString("utf8");
  } catch (error) {
    return null;
  }
}

/**
 * Extracts JWT from headers/cookies
 */
function extractJWT(headers, cookies) {
  const tokens = [];

  // Check Authorization header
  const authHeader = headers["authorization"] || headers["Authorization"];
  if (authHeader) {
    if (authHeader.startsWith("Bearer ")) {
      tokens.push({
        type: "Bearer Token",
        location: "Authorization Header",
        value: authHeader.substring(7),
      });
    } else if (authHeader.includes(".")) {
      tokens.push({
        type: "JWT (possible)",
        location: "Authorization Header",
        value: authHeader,
      });
    }
  }

  // Check cookies
  if (cookies) {
    for (const [name, value] of Object.entries(cookies)) {
      if (name.toLowerCase().includes("token") || name.toLowerCase().includes("jwt") || name.toLowerCase().includes("auth")) {
        if (value.includes(".")) {
          tokens.push({
            type: "JWT (possible)",
            location: `Cookie: ${name}`,
            value: value,
          });
        } else {
          tokens.push({
            type: "Token",
            location: `Cookie: ${name}`,
            value: value,
          });
        }
      }
    }
  }

  return tokens;
}

/**
 * Decodes and analyzes JWT
 */
function analyzeJWT(token) {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) {
      return { valid: false, reason: "Invalid JWT format (must have 3 parts)" };
    }

    const [headerB64, payloadB64, signatureB64] = parts;

    // Decode header
    const headerJson = base64UrlDecode(headerB64);
    if (!headerJson) {
      return { valid: false, reason: "Failed to decode header" };
    }

    const header = JSON.parse(headerJson);

    // Decode payload
    const payloadJson = base64UrlDecode(payloadB64);
    if (!payloadJson) {
      return { valid: false, reason: "Failed to decode payload" };
    }

    const payload = JSON.parse(payloadJson);

    const vulnerabilities = [];

    // Check for "alg": "none" vulnerability
    if (header.alg === "none" || header.alg === "None") {
      vulnerabilities.push({
        severity: "Critical",
        issue: "Algorithm 'none' - allows unsigned tokens",
        description: "Token uses 'none' algorithm which allows token forgery",
      });
    }

    // Check for missing expiration
    if (!payload.exp && !payload.iat) {
      vulnerabilities.push({
        severity: "High",
        issue: "Missing expiration (exp) or issued at (iat)",
        description: "Token has no expiration, allowing indefinite use",
      });
    }

    // Check expiration
    if (payload.exp) {
      const expTime = payload.exp * 1000; // Convert to milliseconds
      const now = Date.now();
      const daysUntilExpiry = (expTime - now) / (1000 * 60 * 60 * 24);

      if (daysUntilExpiry > 365) {
        vulnerabilities.push({
          severity: "Medium",
          issue: "Long-lived token",
          description: `Token expires in ${Math.round(daysUntilExpiry)} days (too long)`,
        });
      }

      if (expTime < now) {
        vulnerabilities.push({
          severity: "Low",
          issue: "Expired token",
          description: "Token has expired",
        });
      }
    }

    // Check for weak algorithms
    const weakAlgorithms = ["HS256", "HS384", "HS512"];
    if (weakAlgorithms.includes(header.alg)) {
      vulnerabilities.push({
        severity: "Medium",
        issue: `Weak algorithm: ${header.alg}`,
        description: "Symmetric key algorithm may be vulnerable if secret is weak",
      });
    }

    // Check for sensitive data in payload
    const sensitiveFields = ["password", "secret", "key", "private"];
    for (const field of sensitiveFields) {
      if (payload.hasOwnProperty(field)) {
        vulnerabilities.push({
          severity: "High",
          issue: `Sensitive data in token: ${field}`,
          description: "Token contains sensitive information in payload",
        });
      }
    }

    return {
      valid: true,
      header: header,
      payload: payload,
      vulnerabilities: vulnerabilities,
      signature: signatureB64,
    };
  } catch (error) {
    return { valid: false, reason: `JWT parsing error: ${error.message}` };
  }
}

/**
 * Tests token in Authorization header
 */
async function testTokenHeader(url, token) {
  try {
    console.log(`Testing token in Authorization header`);

    const response = await axios.get(url, {
      timeout: TIMEOUT,
      headers: {
        "User-Agent": USER_AGENT,
        Authorization: `Bearer ${token}`,
      },
      validateStatus: () => true,
    });

    return {
      status: response.status,
      authenticated: response.status !== 401 && response.status !== 403,
    };
  } catch (error) {
    console.error(`Error testing token header:`, error.message);
    return { error: error.message };
  }
}

/**
 * Tests token manipulation
 */
async function testTokenManipulation(url, originalToken) {
  const vulnerabilities = [];

  try {
    // Test with "none" algorithm
    const parts = originalToken.split(".");
    if (parts.length === 3) {
      const [headerB64, payloadB64, signatureB64] = parts;

      // Modify header to use "none" algorithm
      const headerJson = base64UrlDecode(headerB64);
      if (headerJson) {
        const header = JSON.parse(headerJson);
        header.alg = "none";

        const modifiedHeaderB64 = Buffer.from(JSON.stringify(header))
          .toString("base64")
          .replace(/\+/g, "-")
          .replace(/\//g, "_")
          .replace(/=/g, "");

        const modifiedToken = `${modifiedHeaderB64}.${payloadB64}.`;

        const testResponse = await axios.get(url, {
          timeout: TIMEOUT,
          headers: {
            "User-Agent": USER_AGENT,
            Authorization: `Bearer ${modifiedToken}`,
          },
          validateStatus: () => true,
        });

        if (testResponse.status !== 401 && testResponse.status !== 403) {
          vulnerabilities.push({
            severity: "Critical",
            issue: "Algorithm 'none' attack successful",
            description: "Server accepts tokens with 'none' algorithm",
          });
        }
      }
    }
  } catch (error) {
    console.error(`Error testing token manipulation:`, error.message);
  }

  return vulnerabilities;
}

/**
 * Main function to scan for token authentication vulnerabilities
 */
async function scanTokenAuth(url) {
  console.log(`Starting Token Authentication scan for: ${url}`);

  try {
    // Make initial request to get tokens
    console.log(`Making initial request to: ${url}`);
    const response = await axios.get(url, {
      timeout: TIMEOUT,
      headers: { "User-Agent": USER_AGENT },
      validateStatus: () => true,
    });

    // Extract tokens from response
    const tokens = extractJWT(response.headers, response.headers["set-cookie"] || []);

    // Also check for tokens in Set-Cookie headers
    const setCookieHeaders = response.headers["set-cookie"] || [];
    for (const cookieHeader of setCookieHeaders) {
      const cookieParts = cookieHeader.split(";")[0].split("=");
      if (cookieParts.length === 2) {
        const cookieName = cookieParts[0];
        const cookieValue = cookieParts[1];
        if (cookieValue.includes(".")) {
          tokens.push({
            type: "JWT (possible)",
            location: `Cookie: ${cookieName}`,
            value: cookieValue,
          });
        }
      }
    }

    console.log(`Found ${tokens.length} potential tokens`);

    const findings = [];
    const vulnerabilities = [];

    // Analyze each token
    for (const tokenInfo of tokens) {
      const tokenValue = tokenInfo.value;
      console.log(`Analyzing token from: ${tokenInfo.location}`);

      // Check if it's a JWT
      if (tokenValue.includes(".") && tokenValue.split(".").length === 3) {
        const analysis = analyzeJWT(tokenValue);
        if (analysis.valid) {
          findings.push({
            type: "JWT",
            location: tokenInfo.location,
            header: analysis.header,
            payload: analysis.payload,
            vulnerabilities: analysis.vulnerabilities,
          });

          if (analysis.vulnerabilities.length > 0) {
            vulnerabilities.push(...analysis.vulnerabilities);
          }

          // Test token manipulation
          const manipulationVulns = await testTokenManipulation(url, tokenValue);
          if (manipulationVulns.length > 0) {
            vulnerabilities.push(...manipulationVulns);
            findings[findings.length - 1].vulnerabilities.push(...manipulationVulns);
          }
        } else {
          findings.push({
            type: "Token (not JWT)",
            location: tokenInfo.location,
            note: analysis.reason || "Token format not recognized",
          });
        }
      } else {
        findings.push({
          type: "Token",
          location: tokenInfo.location,
          note: "Token format not recognized as JWT",
        });
      }
    }

    // If no tokens found, check for common token endpoints
    if (tokens.length === 0) {
      const tokenEndpoints = ["/api/auth", "/auth/token", "/login", "/api/login", "/oauth/token"];
      for (const endpoint of tokenEndpoints) {
        try {
          const endpointUrl = new URL(endpoint, url).toString();
          const endpointResponse = await axios.post(
            endpointUrl,
            { username: "test", password: "test" },
            {
              timeout: TIMEOUT,
              headers: { "User-Agent": USER_AGENT },
              validateStatus: () => true,
            }
          );

          const endpointTokens = extractJWT(endpointResponse.headers, {});
          if (endpointTokens.length > 0) {
            findings.push({
              type: "Token Endpoint",
              location: endpointUrl,
              tokens: endpointTokens,
            });
          }
        } catch (error) {
          // Endpoint doesn't exist or error
          continue;
        }
      }
    }

    const vulnerable = vulnerabilities.length > 0 || findings.length === 0;

    return {
      module: "Token Authentication",
      target: url,
      vulnerable: vulnerable,
      evidence: vulnerable
        ? {
            tokens: findings,
            vulnerabilities: vulnerabilities,
          }
        : "No token authentication vulnerabilities detected",
      notes: vulnerable
        ? "Token authentication vulnerabilities detected. JWTs may have weak algorithms, missing expiration, or other security issues."
        : "Token authentication appears to be properly implemented.",
    };
  } catch (error) {
    console.error("Token Authentication scan error:", error);
    return {
      module: "Token Authentication",
      target: url,
      vulnerable: false,
      evidence: "Scan failed due to error",
      notes: `Error: ${error.message}`,
    };
  }
}

module.exports = { scanTokenAuth };
