module.exports = async function testCSRF(endpoint) {
  try {
    // Normal request
    const normal = await fetch(endpoint.url, {
      method: endpoint.method,
      credentials: "include"
    });

    // Forged CSRF request
    const forged = await fetch(endpoint.url, {
      method: endpoint.method,
      headers: {
        Origin: "https://evil.com",
        Referer: "https://evil.com"
      },
      credentials: "include"
    });

    // Decision logic
    if (normal.status === 200 && forged.status === 200) {
      return {
        status: "VULNERABLE",
        confidence: "90%"
      };
    }

    if ([401, 403].includes(forged.status)) {
      return {
        status: "PROTECTED",
        confidence: "90%"
      };
    }

    return {
      status: "INCONCLUSIVE",
      confidence: "60%"
    };

  } catch {
    return {
      status: "ERROR",
      confidence: "40%"
    };
  }
};
