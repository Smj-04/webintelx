const scanner = require("../utils/scanner");
const cleanUrl = require("../utils/cleanUrl");
const { exec } = require("child_process");

exports.whatwebScan = async (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({
      success: false,
      error: "URL is required",
    });
  }

  const target = cleanUrl(url);

  try {

    const raw = await scanner.whatweb(target);

    let whatwebResult = raw;

    try {
      const jsonMatch = raw.match(/\[.*\]/s);
      if (jsonMatch) {
        whatwebResult = JSON.parse(jsonMatch[0]);
      }
    } catch (e) {
      console.log("WhatWeb JSON parse failed, returning raw output");
    }

    const pythonScript = "utils/wappalyzer_scan.py";

    exec(`python ${pythonScript} ${target}`, async (err, stdout, stderr) => {

      let techVersions = {};

      try {
        techVersions = JSON.parse(stdout);
      } catch {
        techVersions = { error: "Failed to parse Wappalyzer output" };
      }

      return res.json({
        success: true,
        message: "Technology scan completed",
        whatweb: whatwebResult,
        wappalyzer: techVersions
      });

    });

  } catch (err) {
    console.error("Scan Error:", err);

    return res.status(500).json({
      success: false,
      error: "Scan failed"
    });
  }
};