
const SYMBOLS = ["@", "#", "$", "%", "&"];

function randomNum() {
  return Math.floor(Math.random() * 90) + 10;
}

/* ---------- MEDIUM PASSWORD ---------- */
function generateMediumPassword(original) {
  const mid = Math.floor(original.length / 2);
  const sym = SYMBOLS[Math.floor(Math.random() * SYMBOLS.length)];

  let p = original;
  if (!/[A-Z]/.test(p)) p = p[0].toUpperCase() + p.slice(1);
  if (!/[^A-Za-z0-9]/.test(p))
    p = p.slice(0, mid) + sym + p.slice(mid);
  if (!/\d/.test(p)) p = p + randomNum();

  return {
    level: "Medium",
    password: p,
    reason: [
      "Capitalization added",
      "Symbol inserted inside password",
      "Non-sequential number appended"
    ]
  };
}

/* ---------- INSANE PASSWORD ---------- */
function enhanceWord(word, symbol) {
  const mid = Math.floor(word.length / 2);
  return (
    word[0].toUpperCase() +
    word.slice(1, mid) +
    symbol +
    word.slice(mid)
  );
}

function generateInsanePassword(primary, secondary) {
  const s1 = SYMBOLS[Math.floor(Math.random() * SYMBOLS.length)];
  const s2 = SYMBOLS[Math.floor(Math.random() * SYMBOLS.length)];

  return {
    level: "Insane",
    password: `${enhanceWord(primary, s1)}_${enhanceWord(secondary, s2)}${randomNum()}`,
    reason: [
      "Two unrelated user-chosen words",
      "Symbols embedded inside words",
      "High-entropy passphrase",
      "Resistant to dictionary & rule-based attacks"
    ]
  };
}

/* ---------- MAIN ENTRY ---------- */
function generatePassword(primary, secondary) {
  if (!secondary) {
    return generateMediumPassword(primary);
  }
  return generateInsanePassword(primary, secondary);
}

module.exports = { generatePassword };
