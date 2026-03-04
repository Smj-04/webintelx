const express = require("express");
const { spawn } = require("child_process");
const path = require("path");
const fs = require("fs");

const router = express.Router();

// Correct project-relative path
const PY_MAIN_PATH = path.join(
  __dirname,
  "..",
  "..",
  "Phishing",
  "phishing-site-or-not",
  "main.py"
);

if (!fs.existsSync(PY_MAIN_PATH)) {
  console.error("[PHISHING] main.py not found at:", PY_MAIN_PATH);
}

const PY_CWD = path.dirname(PY_MAIN_PATH);

const TIMEOUT_MS = 50_000;

console.log("[PHISHING] Route initialized", {
  PY_MAIN_PATH,
  PY_CWD,
});

function tryParseJsonFromStdout(stdout) {
  const trimmed = (stdout || "").trim();
  if (!trimmed) return null;

  try {
    return JSON.parse(trimmed);
  } catch {
    // If Python printed extra logs, try to parse the last JSON object-ish block.
    const match = trimmed.match(/\{[\s\S]*\}$/);
    if (!match) return null;
    return JSON.parse(match[0]);
  }
}

router.post("/phishing-check", (req, res) => {
  console.log("[PHISHING] Handler invoked");

  const url = req?.body?.url;
  if (typeof url !== "string" || !url.trim()) {
    console.error("[PHISHING] Error", "Missing or invalid url", { url });
    return res.status(400).json({ error: "Phishing analysis failed" });
  }

  let finished = false;

  const pythonBins = [];
  if (process.env.PHISHING_PYTHON_BIN) {
    pythonBins.push(process.env.PHISHING_PYTHON_BIN);
  }
  pythonBins.push("python", "py");
  console.log("[PHISHING] Using pythonBins", pythonBins);

  let attempt = 0;
  let child = null;
  let stdout = "";
  let stderr = "";

  const spawnNext = () => {
    const bin = pythonBins[attempt++];
    console.log("[PHISHING] Spawning python process", {
      bin,
      PY_MAIN_PATH,
      PY_CWD,
      url: url.trim(),
    });
    stdout = "";
    stderr = "";

    child = spawn(bin, [PY_MAIN_PATH, url.trim()], {
      cwd: PY_CWD,
      windowsHide: true,
    });

    child.stdout.on("data", (data) => {
      stdout += data.toString();
    });

    child.stderr.on("data", (data) => {
      stderr += data.toString();
    });

    child.on("error", (err) => {
      // If python isn't on PATH, retry using the next candidate (e.g., Windows `py`).
      if (!finished && err?.code === "ENOENT" && attempt < pythonBins.length) {
        console.error(
          "[PHISHING] Error",
          `${bin} not found (ENOENT), retrying`
        );
        return spawnNext();
      }

      if (finished) return;
      finished = true;
      clearTimeout(timeout);
      console.error("[PHISHING] Error spawn failure", err?.message || err);
      return res.status(500).json({ error: "Phishing analysis failed" });
    });

    child.on("close", (code) => {
      if (finished) return;
      finished = true;
      clearTimeout(timeout);

      console.log("[PHISHING] Process closed", {
        code,
        stdout: stdout.trim().slice(0, 500),
        stderr: stderr.trim().slice(0, 500),
      });

      if (code !== 0) {
        console.error(
          "[PHISHING] Error",
          `Python exited with code ${code}`,
          stderr ? `| stderr: ${stderr.trim()}` : ""
        );
        return res.status(500).json({ error: "Phishing analysis failed" });
      }

      try {
        const parsed = tryParseJsonFromStdout(stdout);
        if (!parsed) {
          console.error(
            "[PHISHING] Error",
            "Failed to parse JSON from stdout",
            stdout ? `| stdout: ${stdout.trim()}` : ""
          );
          return res.status(500).json({ error: "Phishing analysis failed" });
        }

        console.log("[PHISHING] Finished");
        return res.json(parsed);
      } catch (err) {
        console.error("[PHISHING] Error", err?.message || err);
        return res.status(500).json({ error: "Phishing analysis failed" });
      }
    });
  };

  const timeout = setTimeout(() => {
    if (finished) return;
    finished = true;
    console.error("[PHISHING] Error", "Timeout exceeded");
    try {
      child?.kill?.("SIGKILL");
    } catch {
      try {
        child?.kill?.();
      } catch {
        // ignore
      }
    }
    return res.status(500).json({ error: "Phishing analysis failed" });
  }, TIMEOUT_MS);

  spawnNext();
});

module.exports = router;

