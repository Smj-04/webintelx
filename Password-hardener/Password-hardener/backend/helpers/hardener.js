
const fs = require("fs");
const path = require("path");

const COMMON_PASSWORDS = new Set(
  fs.readFileSync(
    path.join(__dirname, "../wordlists/commonPasswords.txt"),
    "utf-8"
  )
    .split("\n")
    .map(p => p.trim().toLowerCase())
);

/* ---------- ENTROPY HELPERS ---------- */
function lengthEntropy(len) {
  if (len < 6) return 0;
  if (len < 8) return 10;
  if (len < 10) return 20;
  if (len < 12) return 30;
  if (len < 16) return 40;
  return 50;
}

function diversityEntropy(pw) {
  let bits = 0;
  if (/[a-z]/.test(pw)) bits += 10;
  if (/[A-Z]/.test(pw)) bits += 10;
  if (/\d/.test(pw)) bits += 10;
  if (/[^A-Za-z0-9]/.test(pw)) bits += 15;
  return bits;
}

function structureBonus(pw) {
  let bonus = 0;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) bonus += 10;
  if (/\d/.test(pw) && !/\d+$/.test(pw)) bonus += 10;
  if (/[^A-Za-z0-9]/.test(pw) && !/^[^A-Za-z0-9]|[^A-Za-z0-9]$/.test(pw))
    bonus += 10;
  if (pw.length >= 12) bonus += 10;
  return bonus;
}

/* ---------- PATTERNS ---------- */
function hasCatastrophicPattern(pw) {
  return (
    /^(\d)\1+$/.test(pw) ||           // 111111
    /^\d+$/.test(pw) ||               // only numbers
    /^[a-zA-Z]+$/.test(pw) ||         // only letters
    /12345|qwerty|asdf|zxcv/i.test(pw)
  );
}

function hasSoftPattern(pw) {
  return /^[A-Z][a-z]+[@#!$%&*]?\d{2,4}$/.test(pw);
}

/* ---------- CLASSIFICATION ---------- */
function classify(entropy) {
  if (entropy < 40) return { label: "Weak", color: "#ea4335" };
  if (entropy < 70) return { label: "Medium", color: "#fbbc04" };
  return { label: "Insane", color: "#0f9d58" };
}

/* ---------- ANALYSIS ---------- */
function analyzePassword(password = "") {
  const pw = String(password);

  let entropy =
    lengthEntropy(pw.length) +
    diversityEntropy(pw) +
    structureBonus(pw);

  if (COMMON_PASSWORDS.has(pw.toLowerCase())) entropy -= 40;
  if (hasCatastrophicPattern(pw)) entropy -= 40;
  if (hasSoftPattern(pw)) entropy -= 20;

  entropy = Math.max(0, entropy);

  return {
    length: pw.length,
    entropyBits: entropy,
    crackTimeHuman:
      entropy < 20 ? "Seconds"
      : entropy < 40 ? "Minutes"
      : entropy < 60 ? "Hours"
      : entropy < 80 ? "Months"
      : "Years",
    warnings: {
      commonPassword: COMMON_PASSWORDS.has(pw.toLowerCase()),
      predictablePattern: hasCatastrophicPattern(pw) || hasSoftPattern(pw)
    },
    strength: classify(entropy)
  };
}

/* ---------- HARDEN PASSWORD ---------- */
function generateHardened(pw) {
  const symbols = "!@#$%&*";
  return (
    pw[0].toUpperCase() +
    pw.slice(1) +
    symbols[Math.floor(Math.random() * symbols.length)] +
    Math.floor(100 + Math.random() * 900)
  );
}

module.exports = {
  analyzePassword,
  generateOptions: (pw, analysis) =>
    analysis.strength.label !== "Insane"
      ? { hardened: generateHardened(pw) }
      : null
};
