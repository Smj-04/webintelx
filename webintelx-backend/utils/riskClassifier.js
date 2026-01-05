module.exports = function classifyRisk(endpoint) {
  // Handle both string and object safely
  const url =
    typeof endpoint === "string"
      ? endpoint
      : endpoint.url || "";

  const criticalKeywords = [
    "password",
    "email",
    "admin",
    "delete",
    "remove",
    "transfer",
    "update",
    "change"
  ];

  return criticalKeywords.some(k =>
    url.toLowerCase().includes(k)
  )
    ? "HIGH"
    : "MEDIUM";
};
