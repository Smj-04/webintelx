
// Utility helpers - improved entropy & crack time formatting
function hasLowercase(s) { return /[a-z]/.test(s); }
function hasUppercase(s) { return /[A-Z]/.test(s); }
function hasDigit(s) { return /[0-9]/.test(s); }
function hasSymbol(s) { return /[^A-Za-z0-9]/.test(s); }

function estimateCharsetSize(s) {
  let size = 0;
  if (hasLowercase(s)) size += 26;
  if (hasUppercase(s)) size += 26;
  if (hasDigit(s)) size += 10;
  if (hasSymbol(s)) size += 32; // rough estimate for symbols
  return size || 1;
}

function estimateEntropyBits(s) {
  const charset = estimateCharsetSize(s);
  if (charset <= 1 || !s) return 0;
  // bits = length * log2(charset)
  const bits = s.length * Math.log2(charset);
  return Math.max(0, bits);
}

function estimateCrackTimeSeconds(s, guessesPerSecond = 1e11) {
  // Using search space ≈ 2^bits, average guesses = 2^(bits-1)
  const bits = estimateEntropyBits(s);
  if (bits <= 0) return 0;
  const avgGuesses = Math.pow(2, bits - 1);
  // protect from overflow
  const seconds = avgGuesses / guessesPerSecond;
  return seconds;
}

function prettyTime(seconds) {
  // Always return a human-readable string. Handles extremely large values.
  if (!isFinite(seconds) || seconds <= 0) return 'instantly';
  const intervals = [
    { label: 'century', s: 31536000 * 100 },
    { label: 'year', s: 31536000 },
    { label: 'month', s: 2628000 },
    { label: 'day', s: 86400 },
    { label: 'hour', s: 3600 },
    { label: 'minute', s: 60 },
    { label: 'second', s: 1 }
  ];

  // If ridiculously large (> 10^9 years) show "beyond human age"
  const maxYears = seconds / 31536000;
  if (maxYears > 1e9) return 'beyond human age';

  let out = [];
  let remaining = Math.floor(seconds);
  for (const unit of intervals) {
    if (remaining >= unit.s) {
      const val = Math.floor(remaining / unit.s);
      out.push(`${val} ${unit.label}${val > 1 ? 's' : ''}`);
      remaining -= val * unit.s;
    }
    if (out.length >= 2) break;
  }
  return out.join(' ');
}

module.exports = {
  hasLowercase, hasUppercase, hasDigit, hasSymbol,
  estimateCharsetSize, estimateEntropyBits, estimateCrackTimeSeconds, prettyTime
};
