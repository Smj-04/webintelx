const runCommand = require("./runCommand");
const net = require("net");
const axios = require("axios");
const sslChecker = require("ssl-checker");
const endpointScan = require("./endpointScanner");
const { scanXSS } = require("./xssScanner");

// ------------------------------------------------------
// PORT NAME MAPPING (for QuickScan)
// ------------------------------------------------------
const portNames = {
  21: "FTP",
  22: "SSH",
  23: "Telnet",
  25: "SMTP",
  53: "DNS",
  80: "HTTP",
  110: "POP3",
  123: "NTP",
  143: "IMAP",
  161: "SNMP",
  389: "LDAP",
  443: "HTTPS",
  445: "SMB",
  587: "SMTP TLS",
  631: "IPP",
  993: "IMAPS",
  995: "POP3S",
  3306: "MySQL",
  3389: "RDP",
  5432: "PostgreSQL",
  6379: "Redis",
  8080: "HTTP-Alt",
  8443: "HTTPS-Alt",
  27017: "MongoDB",
};

// ------------------------------------------------------
// EXPORT ALL SCAN MODULES
// ------------------------------------------------------
module.exports = {
  // -------------------------------------
  // DNS Lookup
  // -------------------------------------
  nslookup: (target) => runCommand(`nslookup ${target}`),

  // -------------------------------------
  // Ping Test (Windows)
  // -------------------------------------
  ping: (target) => runCommand(`ping -n 4 ${target}`),

  // -------------------------------------
  // WHOIS Lookup
  // -------------------------------------
  whois: (target) => runCommand(`whois ${target}`),

  // -------------------------------------
  // Traceroute / Tracert
  // -------------------------------------
  traceroute: (target) => {
    return new Promise((resolve) => {
      const { exec } = require("child_process");
      const cmd = process.platform === "win32"
        ? `tracert -h 15 -w 500 ${target}`
        : `traceroute -m 15 -w 1 ${target}`;
      exec(cmd, { timeout: 25000 }, (err, stdout) => {
        resolve(stdout || (err ? err.message : "Traceroute timed out"));
      });
    });
  },

  // -------------------------------------
  // Quick Port Scan — parallel, 3s timeout
  // -------------------------------------
  portScan: async (host) => {
    const ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995, 3306, 3389, 5432, 6379, 8080, 8443, 27017];

    const checkPort = (port) => {
      return new Promise((resolve) => {
        const socket = new net.Socket();
        let settled = false;

        const done = (open) => {
          if (settled) return;
          settled = true;
          socket.destroy();
          if (open) {
            resolve({ port, name: portNames[port] || "Unknown Service" });
          } else {
            resolve(null);
          }
        };

        socket.setTimeout(3000); // 3s — enough for remote hosts
        socket.on("connect", () => done(true));
        socket.on("timeout", () => done(false));
        socket.on("error", () => done(false));
        socket.connect(port, host);
      });
    };

    // Run ALL ports in parallel — much faster than sequential
    const results = await Promise.all(ports.map(checkPort));
    return results.filter(Boolean); // remove nulls (closed ports)
  },

  // -------------------------------------
  // HTTP Header Fetch
  // -------------------------------------
  headers: async (target) => {
    try {
      const url = target.startsWith("http") ? target : `https://${target}`;
      const res = await axios.get(url, { timeout: 5000 });
      return res.headers;
    } catch {
      return { error: "Could not retrieve headers" };
    }
  },

  // -------------------------------------
  // SSL Certificate Info
  // -------------------------------------
  ssl: async (domain) => {
    try {
      return await sslChecker(domain);
    } catch {
      return { error: "SSL scan failed" };
    }
  },

  // -------------------------------------
  // XSS Vulnerability Scan
  // -------------------------------------
  xssScan: async (target) => {
    try {
      const url = target.startsWith("http") ? target : `https://${target}`;
      return await scanXSS(url);
    } catch (err) {
      return { error: "XSS scan failed" };
    }
  },

  // -------------------------------------
  // WhatWeb (via WSL)
  // -------------------------------------
  whatweb: async (target) => {
    try {
      const command = `wsl whatweb ${target} --log-json=-`;
      return await runCommand(command);
    } catch (err) {
      return "WhatWeb scan failed";
    }
  },

  // -------------------------------------
  // Endpoint & SQLi Detection
  // -------------------------------------
  endpointScan: (target) => endpointScan(target),

  // -------------------------------------
  // Email / Domain Reputation (legacy stub — replaced by emailRepCheck.js)
  // -------------------------------------
  emailReputation: async (domain) => {
    try {
      const suspiciousTLDs = [".tk", ".ml", ".ga", ".cf"];
      const isSuspiciousTLD = suspiciousTLDs.some(tld => domain.endsWith(tld));
      return {
        domain,
        disposable: false,
        suspiciousTLD: isSuspiciousTLD,
        risk: isSuspiciousTLD ? "MEDIUM" : "LOW",
        note: "Heuristic-based domain reputation (QuickScan)",
      };
    } catch (err) {
      return { error: "Email reputation check failed" };
    }
  },
};