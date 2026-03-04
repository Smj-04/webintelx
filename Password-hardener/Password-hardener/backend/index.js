const express = require("express");
const cors = require("cors");

const { analyzePassword, generateOptions } = require("./helpers/hardener");
const { generatePassword } = require("./helpers/militaryGenerator");

const app = express();
const PORT = 4000;

app.use(cors());
app.use(express.json());

/* ===============================
   ANALYZE PASSWORD (NEVER 400)
   =============================== */
app.post("/api/analyze", (req, res) => {
  const password = String(req.body.password || "");

  try {
    const analysis = analyzePassword(password);
    const suggestions = generateOptions(password, analysis);

    return res.json({
      original: password,
      analysis,
      suggestions
    });
  } catch (e) {
    // Absolute fallback – frontend must NEVER break
    return res.json({
      original: password,
      analysis: {
        length: password.length,
        entropyBits: 0,
        crackTimeHuman: "Instant",
        warnings: {
          commonPassword: true,
          predictablePattern: true
        },
        strength: {
          label: "Weak",
          color: "#ea4335"
        }
      },
      suggestions: null
    });
  }
});

/* ===============================
   PASSWORD GENERATOR
   (Medium / Insane)
   =============================== */
app.post("/api/generate-password", (req, res) => {
  const { primary, secondary } = req.body;

  try {
    const result = generatePassword(primary, secondary || null);
    return res.json(result);
  } catch (e) {
    // Generator fallback
    return res.json({
      level: "Medium",
      password: primary,
      reason: ["Fallback generation used"]
    });
  }
});

/* ===============================
   START SERVER
   =============================== */
app.listen(PORT, () => {
  console.log(`Password Hardener API running on port ${PORT}`);
});
