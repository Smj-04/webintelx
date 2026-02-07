/**
 * CSRF Token Detection Module
 * Tests for CSRF protection mechanisms (tokens, SameSite cookies, etc.)
 */

const axios = require("axios");
const cheerio = require("cheerio");
const { URL } = require("url");

const USER_AGENT = "WebIntelX-CSRFToken-Scanner/1.0";
const TIMEOUT = 40000; // Increased timeout

/**
 * Extracts CSRF token from HTML
 */
function extractCSRFToken(html) {
  const tokens = [];
  const $ = cheerio.load(html);

  // Check meta tags
  $('meta[name*="csrf"], meta[name*="token"], meta[name*="_token"]').each((_, el) => {
    tokens.push({
      type: "meta",
      name: $(el).attr("name"),
      value: $(el).attr("content"),
    });
  });

  // Check hidden input fields
  $('input[type="hidden"][name*="csrf"], input[type="hidden"][name*="token"], input[type="hidden"][name*="_token"]').each(
    (_, el) => {
      tokens.push({
        type: "input",
        name: $(el).attr("name"),
        value: $(el).attr("value"),
      });
    }
  );

  // Check headers in response
  // Note: We can't access response headers in cheerio, so we'll handle this separately

  return tokens;
}

/**
 * Parses Set-Cookie header
 */
function parseCookie(cookieString) {
  const cookie = {};
  const parts = cookieString.split(";");

  cookie.name = parts[0].split("=")[0].trim();
  cookie.value = parts[0].split("=")[1]?.trim() || "";

  for (let i = 1; i < parts.length; i++) {
    const part = parts[i].trim().toLowerCase();
    if (part === "httponly") {
      cookie.httpOnly = true;
    } else if (part === "secure") {
      cookie.secure = true;
    } else if (part.startsWith("samesite=")) {
      cookie.sameSite = part.split("=")[1];
    } else if (part.startsWith("domain=")) {
      cookie.domain = part.split("=")[1];
    } else if (part.startsWith("path=")) {
      cookie.path = part.split("=")[1];
    }
  }

  return cookie;
}

/**
 * Tests CSRF protection on a form
 */
async function testCSRFProtection(formUrl, baseUrl) {
  try {
    console.log(`Testing CSRF protection for form: ${formUrl}`);

    // Fetch the form page
    const formResponse = await axios.get(formUrl, {
      timeout: TIMEOUT,
      headers: { "User-Agent": USER_AGENT },
      validateStatus: () => true,
    });

    if (formResponse.status !== 200) {
      return { protected: false, reason: `Failed to fetch form: HTTP ${formResponse.status}` };
    }

    // Extract CSRF tokens
    const tokens = extractCSRFToken(formResponse.data);
    console.log(`Found ${tokens.length} CSRF tokens`);

    // Check cookies
    const cookies = [];
    const setCookieHeaders = formResponse.headers["set-cookie"] || [];
    for (const cookieHeader of setCookieHeaders) {
      const cookie = parseCookie(cookieHeader);
      cookies.push(cookie);
    }

    // Analyze cookies for SameSite attribute
    const cookieAnalysis = {
      hasSameSite: false,
      sameSiteValue: null,
      hasSecure: false,
      hasHttpOnly: false,
      vulnerableCookies: [],
    };

    for (const cookie of cookies) {
      if (cookie.sameSite) {
        cookieAnalysis.hasSameSite = true;
        cookieAnalysis.sameSiteValue = cookie.sameSite;
      } else {
        cookieAnalysis.vulnerableCookies.push({
          name: cookie.name,
          reason: "Missing SameSite attribute",
        });
      }

      if (cookie.secure) {
        cookieAnalysis.hasSecure = true;
      } else {
        cookieAnalysis.vulnerableCookies.push({
          name: cookie.name,
          reason: "Missing Secure attribute",
        });
      }

      if (cookie.httpOnly) {
        cookieAnalysis.hasHttpOnly = true;
      }
    }

    // Test if token is reusable (security issue)
    let tokenReusable = false;
    if (tokens.length > 0) {
      const firstToken = tokens[0];
      const secondResponse = await axios.get(formUrl, {
        timeout: TIMEOUT,
        headers: { "User-Agent": USER_AGENT },
        validateStatus: () => true,
      });

      const secondTokens = extractCSRFToken(secondResponse.data);
      if (secondTokens.length > 0 && secondTokens[0].value === firstToken.value) {
        tokenReusable = true;
        console.log("CSRF token appears to be reusable (security issue)");
      }
    }

    // Determine protection status
    let protected = false;
    let protectionType = [];
    let vulnerabilities = [];

    if (tokens.length > 0) {
      protected = true;
      protectionType.push("CSRF Token");
      if (tokenReusable) {
        vulnerabilities.push("CSRF token is reusable");
      }
    }

    if (cookieAnalysis.hasSameSite && cookieAnalysis.sameSiteValue === "strict") {
      protected = true;
      protectionType.push("SameSite=Strict cookie");
    } else if (cookieAnalysis.hasSameSite && cookieAnalysis.sameSiteValue === "lax") {
      protected = true;
      protectionType.push("SameSite=Lax cookie");
      vulnerabilities.push("SameSite=Lax provides partial protection (GET requests vulnerable)");
    } else if (cookieAnalysis.vulnerableCookies.length > 0) {
      vulnerabilities.push(...cookieAnalysis.vulnerableCookies.map((c) => `${c.name}: ${c.reason}`));
    }

    return {
      protected: protected,
      protectionType: protectionType,
      vulnerabilities: vulnerabilities,
      tokens: tokens,
      cookies: cookieAnalysis,
      tokenReusable: tokenReusable,
    };
  } catch (error) {
    console.error(`Error testing CSRF protection:`, error.message);
    return { protected: false, reason: `Error: ${error.message}` };
  }
}

/**
 * Tests form submission without CSRF token
 */
async function testFormSubmissionWithoutToken(formUrl, baseUrl) {
  try {
    console.log(`Testing form submission without token: ${formUrl}`);

    // Fetch form to get structure
    const formResponse = await axios.get(formUrl, {
      timeout: TIMEOUT,
      headers: { "User-Agent": USER_AGENT },
      validateStatus: () => true,
    });

    if (formResponse.status !== 200) {
      return { vulnerable: false };
    }

    const $ = cheerio.load(formResponse.data);
    const form = $("form").first();
    const action = form.attr("action") || formUrl;
    const method = (form.attr("method") || "post").toLowerCase();
    const actionUrl = new URL(action, baseUrl).toString();

    // Extract form fields (excluding CSRF token)
    const formData = {};
    form.find("input, textarea, select").each((_, field) => {
      const $field = $(field);
      const name = $field.attr("name");
      const type = $field.attr("type") || "text";
      const value = $field.attr("value") || "";

      if (name && !name.toLowerCase().includes("csrf") && !name.toLowerCase().includes("token") && type !== "submit") {
        formData[name] = value || "test";
      }
    });

    // Try to submit without CSRF token
    const submitResponse = await axios.post(
      actionUrl,
      formData,
      {
        timeout: TIMEOUT,
        headers: {
          "User-Agent": USER_AGENT,
          "Content-Type": "application/x-www-form-urlencoded",
          Origin: "https://evil.com",
          Referer: "https://evil.com",
        },
        validateStatus: () => true,
      }
    );

    // Check if submission was accepted
    if (submitResponse.status === 200) {
      // Check for error messages
      const responseText = String(submitResponse.data || "").toLowerCase();
      const errorIndicators = ["csrf", "token", "invalid", "forbidden", "unauthorized", "403", "401"];

      const hasError = errorIndicators.some((indicator) => responseText.includes(indicator));

      if (!hasError) {
        return { vulnerable: true, evidence: "Form accepted request without CSRF token" };
      }
    }

    if (submitResponse.status >= 400) {
      return { vulnerable: false, evidence: `Form rejected request (HTTP ${submitResponse.status})` };
    }

    return { vulnerable: false };
  } catch (error) {
    console.error(`Error testing form submission:`, error.message);
    return { vulnerable: false, error: error.message };
  }
}

/**
 * Main function to scan for CSRF protection
 */
async function scanCSRFToken(url) {
  console.log(`Starting CSRF Token scan for: ${url}`);

  try {
    // Fetch the page
    console.log(`Fetching page: ${url}`);
    const response = await axios.get(url, {
      timeout: TIMEOUT,
      headers: { "User-Agent": USER_AGENT },
      validateStatus: () => true,
    });

    if (response.status !== 200) {
      console.error(`Failed to fetch page: HTTP ${response.status}`);
      return {
        module: "CSRF Token",
        target: url,
        vulnerable: false,
        evidence: `Failed to fetch page: HTTP ${response.status}`,
        notes: "Unable to analyze page for CSRF protection",
      };
    }

    const $ = cheerio.load(response.data);
    const forms = [];

    // Extract forms
    $("form").each((_, form) => {
      const $form = $(form);
      const action = $form.attr("action") || url;
      const formUrl = new URL(action, url).toString();
      forms.push(formUrl);
    });

    console.log(`Found ${forms.length} forms`);

    // Test each form (or the page itself if no forms)
    const testUrls = forms.length > 0 ? forms : [url];
    const findings = [];

    for (const formUrl of testUrls.slice(0, 3)) {
      const protection = await testCSRFProtection(formUrl, url);
      const submissionTest = await testFormSubmissionWithoutToken(formUrl, url);

      if (!protection.protected || submissionTest.vulnerable || protection.vulnerabilities.length > 0) {
        findings.push({
          url: formUrl,
          protected: protection.protected,
          protectionType: protection.protectionType || [],
          vulnerabilities: [
            ...(protection.vulnerabilities || []),
            ...(submissionTest.vulnerable ? [submissionTest.evidence] : []),
            ...(protection.tokenReusable ? ["CSRF token is reusable"] : []),
          ],
          tokens: protection.tokens || [],
          cookies: protection.cookies || {},
        });
      }
    }

    const vulnerable = findings.length > 0 || testUrls.length === 0;

    return {
      module: "CSRF Token",
      target: url,
      vulnerable: vulnerable,
      evidence: vulnerable
        ? findings.map((f) => ({
            url: f.url,
            protected: f.protected,
            vulnerabilities: f.vulnerabilities,
            tokens: f.tokens,
            cookies: f.cookies,
          }))
        : "No CSRF vulnerabilities detected",
      notes: vulnerable
        ? "CSRF vulnerabilities detected. Forms may be missing CSRF tokens, tokens may be reusable, or cookies may lack SameSite protection."
        : "CSRF protection appears to be properly implemented with tokens and/or SameSite cookies.",
    };
  } catch (error) {
    console.error("CSRF Token scan error:", error);
    return {
      module: "CSRF Token",
      target: url,
      vulnerable: false,
      evidence: "Scan failed due to error",
      notes: `Error: ${error.message}`,
    };
  }
}

module.exports = { scanCSRFToken };
