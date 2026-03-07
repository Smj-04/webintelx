const axios = require("axios");

const SENSITIVE_PATHS = [
  // Config & environment
  { path: "/.env", severity: "CRITICAL", desc: "Environment variables file" },
  { path: "/.env.local", severity: "CRITICAL", desc: "Local environment variables" },
  { path: "/.env.production", severity: "CRITICAL", desc: "Production environment variables" },
  { path: "/.env.backup", severity: "CRITICAL", desc: "Backup environment variables" },
  { path: "/config.php", severity: "CRITICAL", desc: "PHP configuration file" },
  { path: "/configuration.php", severity: "CRITICAL", desc: "PHP configuration file" },
  { path: "/config.yml", severity: "HIGH", desc: "YAML configuration file" },
  { path: "/config.json", severity: "HIGH", desc: "JSON configuration file" },
  { path: "/config.xml", severity: "HIGH", desc: "XML configuration file" },
  { path: "/settings.py", severity: "HIGH", desc: "Python settings file" },
  { path: "/local_settings.py", severity: "HIGH", desc: "Python local settings" },
  { path: "/wp-config.php", severity: "CRITICAL", desc: "WordPress config with DB credentials" },
  { path: "/application.properties", severity: "HIGH", desc: "Java application properties" },
  { path: "/application.yml", severity: "HIGH", desc: "Java application YAML config" },

  // Git & version control
  { path: "/.git/config", severity: "HIGH", desc: "Git repository config" },
  { path: "/.git/HEAD", severity: "MEDIUM", desc: "Git HEAD reference" },
  { path: "/.gitignore", severity: "LOW", desc: "Git ignore file (info disclosure)" },
  { path: "/.svn/entries", severity: "HIGH", desc: "SVN repository entries" },

  // Backup & temp files
  { path: "/backup.zip", severity: "CRITICAL", desc: "Site backup archive" },
  { path: "/backup.tar.gz", severity: "CRITICAL", desc: "Site backup archive" },
  { path: "/backup.sql", severity: "CRITICAL", desc: "Database backup" },
  { path: "/db.sql", severity: "CRITICAL", desc: "Database dump" },
  { path: "/database.sql", severity: "CRITICAL", desc: "Database dump" },
  { path: "/dump.sql", severity: "CRITICAL", desc: "Database dump" },
  { path: "/site.zip", severity: "CRITICAL", desc: "Site archive" },
  { path: "/www.zip", severity: "CRITICAL", desc: "Site archive" },

  // Log files
  { path: "/error.log", severity: "HIGH", desc: "Application error log" },
  { path: "/access.log", severity: "HIGH", desc: "Access log" },
  { path: "/debug.log", severity: "HIGH", desc: "Debug log" },
  { path: "/php_error.log", severity: "HIGH", desc: "PHP error log" },
  { path: "/logs/error.log", severity: "HIGH", desc: "Error log" },
  { path: "/storage/logs/laravel.log", severity: "HIGH", desc: "Laravel log" },

  // Credential & key files
  { path: "/id_rsa", severity: "CRITICAL", desc: "SSH private key" },
  { path: "/.ssh/id_rsa", severity: "CRITICAL", desc: "SSH private key" },
  { path: "/server.key", severity: "CRITICAL", desc: "SSL private key" },
  { path: "/private.key", severity: "CRITICAL", desc: "Private key file" },
  { path: "/credentials.json", severity: "CRITICAL", desc: "Credentials file" },
  { path: "/secrets.json", severity: "CRITICAL", desc: "Secrets file" },
  { path: "/.htpasswd", severity: "CRITICAL", desc: "Apache password file" },

  // Server & infra
  { path: "/.htaccess", severity: "MEDIUM", desc: "Apache access control file" },
  { path: "/web.config", severity: "MEDIUM", desc: "IIS configuration file" },
  { path: "/nginx.conf", severity: "MEDIUM", desc: "Nginx configuration" },
  { path: "/Dockerfile", severity: "MEDIUM", desc: "Docker build file" },
  { path: "/docker-compose.yml", severity: "MEDIUM", desc: "Docker compose config" },
  { path: "/.dockerenv", severity: "LOW", desc: "Docker environment indicator" },

  // Package & dependency files
  { path: "/package.json", severity: "LOW", desc: "Node.js package manifest" },
  { path: "/composer.json", severity: "LOW", desc: "PHP composer manifest" },
  { path: "/requirements.txt", severity: "LOW", desc: "Python dependencies" },
  { path: "/Gemfile", severity: "LOW", desc: "Ruby dependencies" },

  // Admin & sensitive endpoints
  { path: "/phpinfo.php", severity: "HIGH", desc: "PHP info disclosure" },
  { path: "/info.php", severity: "HIGH", desc: "PHP info disclosure" },
  { path: "/test.php", severity: "MEDIUM", desc: "Test PHP file" },
  { path: "/admin/", severity: "MEDIUM", desc: "Admin panel exposed" },
  { path: "/administrator/", severity: "MEDIUM", desc: "Administrator panel" },
  { path: "/.well-known/security.txt", severity: "LOW", desc: "Security contact info" },
  { path: "/robots.txt", severity: "LOW", desc: "Robots file (may reveal hidden paths)" },
  { path: "/sitemap.xml", severity: "LOW", desc: "Sitemap (endpoint enumeration)" },
];

const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

async function sensitiveFileCheck(baseUrl) {
  const base = baseUrl.replace(/\/$/, "");
  const exposed = [];

  const checks = SENSITIVE_PATHS.map(async ({ path, severity, desc }) => {
    const url = `${base}${path}`;
    try {
      const response = await axios.get(url, {
        timeout: 6000,
        maxRedirects: 2,
        validateStatus: null, // don't throw on any status
        headers: { "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)" },
      });

      const status = response.status;
      const contentLength = parseInt(response.headers["content-length"] || "0", 10);
      const contentType = response.headers["content-type"] || "";

      // Only flag if actually accessible (200) with non-trivial content
      // or forbidden (403) which still confirms existence
      if (status === 200 && contentLength !== 0) {
        exposed.push({
          url,
          path,
          status,
          severity,
          desc,
          contentType: contentType.split(";")[0].trim(),
          size: contentLength || null,
        });
      } else if (status === 403 && (severity === "CRITICAL" || severity === "HIGH")) {
        // 403 means file exists but access denied — still worth noting
        exposed.push({
          url,
          path,
          status,
          severity: severity === "CRITICAL" ? "HIGH" : "MEDIUM", // downgrade since not readable
          desc: `${desc} (exists but access denied)`,
          contentType: null,
          size: null,
        });
      }
    } catch {
      // Unreachable path — not exposed
    }
  });

  await Promise.allSettled(checks);

  // Sort by severity
  exposed.sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 4) - (SEVERITY_ORDER[b.severity] ?? 4));

  const summary = {
    total: exposed.length,
    critical: exposed.filter(e => e.severity === "CRITICAL").length,
    high: exposed.filter(e => e.severity === "HIGH").length,
    medium: exposed.filter(e => e.severity === "MEDIUM").length,
    low: exposed.filter(e => e.severity === "LOW").length,
  };

  return {
    vulnerable: exposed.length > 0,
    summary,
    exposedFiles: exposed,
  };
}

module.exports = sensitiveFileCheck;