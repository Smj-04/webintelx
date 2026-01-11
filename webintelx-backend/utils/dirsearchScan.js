const { exec } = require("child_process");

module.exports = function dirsearchScan(baseUrl) {
  return new Promise((resolve) => {
    const cmd = `
      dirsearch
      -u ${baseUrl}
      -e php,html,js
      --plain-text-report=dirsearch.txt
      --quiet
    `;

    console.log("📂 DIRSEARCH COMMAND:", cmd);

    exec(cmd, { maxBuffer: 1024 * 1024 * 20 }, () => {
      const fs = require("fs");

      if (!fs.existsSync("dirsearch.txt")) {
        return resolve([]);
      }

      const content = fs.readFileSync("dirsearch.txt", "utf-8");

      const endpoints = content
        .split("\n")
        .map(line => line.trim())
        .filter(line => line.startsWith("/"));

      resolve([...new Set(endpoints)]);
    });
  });
};
