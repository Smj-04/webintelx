const runCommand = require("./runCommand");
const net = require("net");
const axios = require("axios");
const sslChecker = require("ssl-checker");

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
  traceroute: (target) => runCommand(`tracert ${target}`),

  // -------------------------------------
  // Quick Port Scan (returns PORT + NAME)
  // -------------------------------------
  portScan: async (host) => {
    const ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306];
    const results = [];

    const checkPort = (port) => {
      return new Promise((resolve) => {
        const socket = new net.Socket();
        socket.setTimeout(700);

        socket.on("connect", () => {
          results.push({
            port,
            name: portNames[port] || "Unknown Service",
          });
          socket.destroy();
          resolve();
        });

        socket.on("timeout", () => {
          socket.destroy();
          resolve();
        });

        socket.on("error", () => resolve());

        socket.connect(port, host);
      });
    };

    for (let p of ports) {
      await checkPort(p);
    }

    return results;
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
  // ✅ WHATWEB (RUNS VIA WSL)
  // -------------------------------------
  whatweb: async (target) => {
    try {
      // --log-json=- sends JSON output to stdout
      const command = `wsl whatweb ${target} --log-json=-`;
      return await runCommand(command);
    } catch (err) {
      return "WhatWeb scan failed";
    }
  },
};
