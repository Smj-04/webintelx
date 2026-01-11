const { spawn } = require("child_process");
const path = require("path");

module.exports = function generateAIReport(scanType, scanData) {
  return new Promise((resolve, reject) => {
    const runnerPath = path.join(
      __dirname,
      "../ai/geminiRunner.mjs"
    );

    const child = spawn("node", [runnerPath], {
      env: process.env,
    });

    let output = "";
    let error = "";

    child.stdout.on("data", d => output += d.toString());
    child.stderr.on("data", d => error += d.toString());

    child.on("close", code => {
      if (code !== 0) {
        reject(error || "Gemini process failed");
      } else {
        resolve(output);
      }
    });

    child.stdin.write(JSON.stringify({ scanType, scanData }));
    child.stdin.end();
  });
};
