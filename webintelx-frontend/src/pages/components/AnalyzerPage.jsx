// Password-hardener/frontend/src/components/AnalyzerPage.jsx
// WHITE THEME VERSION

import { useState, useCallback } from "react";
import axios from "axios";

/* ── helpers ── */
const CHAR_COLORS = {
  upper:   { bg: "#eef3fc", border: "#1a4fa8", text: "#1a4fa8", label: "UPPER" },
  lower:   { bg: "#edf7f2", border: "#1a7f4b", text: "#1a7f4b", label: "LOWER" },
  digit:   { bg: "#fdf8ec", border: "#9a6c00", text: "#9a6c00", label: "DIGIT" },
  special: { bg: "#fdf1f0", border: "#c0392b", text: "#c0392b", label: "SPECIAL" },
  space:   { bg: "#f5f0fc", border: "#6b4fa8", text: "#6b4fa8", label: "SPACE" },
  other:   { bg: "#f0ede8", border: "#b0a898", text: "#7a7268", label: "OTHER" },
};

function charClass(c) {
  if (/[A-Z]/.test(c)) return "upper";
  if (/[a-z]/.test(c)) return "lower";
  if (/[0-9]/.test(c)) return "digit";
  if (/[^a-zA-Z0-9 ]/.test(c)) return "special";
  if (c === " ") return "space";
  return "other";
}

function localStrength(pwd) {
  if (!pwd) return { score: 0, label: "—", color: "var(--border-dark)" };
  let s = 0;
  if (pwd.length >= 8)  s++;
  if (pwd.length >= 12) s++;
  if (pwd.length >= 16) s++;
  if (/[A-Z]/.test(pwd)) s++;
  if (/[a-z]/.test(pwd)) s++;
  if (/[0-9]/.test(pwd)) s++;
  if (/[^a-zA-Z0-9]/.test(pwd)) s++;
  const score = Math.min(Math.round((s / 7) * 100), 100);
  if (score < 30) return { score, label: "CRITICAL", color: "#c0392b" };
  if (score < 55) return { score, label: "WEAK",     color: "#d35400" };
  if (score < 75) return { score, label: "FAIR",     color: "#9a6c00" };
  if (score < 90) return { score, label: "STRONG",   color: "#1a7f4b" };
  return              { score, label: "FORTRESS",  color: "#1a4fa8" };
}

/* ── EntropyVisualizer ── */
function EntropyVisualizer({ password, visible }) {
  if (!password) return null;
  const tokens = password.split("").map((c, i) => ({ c, cls: charClass(c), i }));
  const present = [...new Set(tokens.map(t => t.cls))];

  return (
    <div className="entropy-wrap">
      <div className="entropy-label">{"// CHAR_MAP"}</div>
      <div className="entropy-blocks">
        {tokens.map(({ c, cls, i }) => {
          const col = CHAR_COLORS[cls];
          return (
            <div
              key={i}
              className="entropy-block"
              style={{
                background: col.bg,
                border: `1px solid ${col.border}`,
                color: col.text,
                animation: `slideIn 0.15s ease ${i * 0.02}s both`,
              }}
              title={`${c} → ${col.label}`}
            >
              {!visible ? "•" : c === " " ? "·" : c}
            </div>
          );
        })}
      </div>
      <div className="entropy-legend">
        {present.map(cls => (
          <div key={cls} className="entropy-legend-item">
            <div className="entropy-legend-dot" style={{ background: CHAR_COLORS[cls].border }} />
            {CHAR_COLORS[cls].label}
          </div>
        ))}
      </div>
    </div>
  );
}

/* ── StrengthMeter ── */
function StrengthMeter({ score, label, color }) {
  const BARS = 20;
  const filled = Math.round((score / 100) * BARS);

  return (
    <div className="strength-wrap">
      <div className="strength-header">
        <span className="strength-label">{"// STRENGTH_INDEX"}</span>
        <span className="strength-score-val" style={{ color }}>
          {score}<span className="strength-score-unit">/100</span>
        </span>
      </div>
      <div className="strength-bars">
        {Array.from({ length: BARS }).map((_, i) => (
          <div
            key={i}
            className="strength-bar"
            style={i < filled ? {
              background: color,
              transition: `background 0.3s ease ${i * 0.025}s`,
            } : {
              transition: `background 0.3s ease ${i * 0.025}s`,
            }}
          />
        ))}
      </div>
      <div className="strength-verdict" style={{ color }}>{label}</div>
    </div>
  );
}

/* ── AnalyzerPage ── */
export default function AnalyzerPage() {
  const [password, setPassword] = useState("");
  const [visible,  setVisible]  = useState(false);
  const [loading,  setLoading]  = useState(false);
  const [result,   setResult]   = useState(null);
  const [error,    setError]    = useState(null);

  const local = localStrength(password);

  const analyze = useCallback(async () => {
    if (!password.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const { data } = await axios.post("http://localhost:4000/api/analyze", { password });
      const a = data.analysis;

      const classes = [
        /[a-z]/.test(password) && "lowercase",
        /[A-Z]/.test(password) && "uppercase",
        /\d/.test(password)    && "digits",
        /[^A-Za-z0-9]/.test(password) && "special",
      ].filter(Boolean);

      setResult({
        strength_label:     a.strength?.label      ?? "Unknown",
        entropy:            a.entropyBits           ?? null,
        crack_time_display: a.crackTimeHuman        ?? null,
        breach_count:       a.warnings?.commonPassword ? 1 : 0,
        character_classes:  `${classes.length} (${classes.join(", ")})`,
        feedback: [
          a.warnings?.commonPassword     && "⚠ This is a commonly used password",
          a.warnings?.predictablePattern && "⚠ Predictable pattern detected — avoid keyboard walks and repeated chars",
          a.entropyBits < 40             && "⚠ Add uppercase letters, symbols, or increase length",
        ].filter(Boolean),
      });
    } catch {
      setError("Analysis failed — check backend connection.");
    }
    setLoading(false);
  }, [password]);

  const accent = result
    ? (result.strength_label === "Strong" || result.strength_label === "Very Strong") ? "#1a4fa8"
      : result.strength_label === "Medium" ? "#9a6c00"
      : "#c0392b"
    : "#c0392b";

  return (
    <div className="page">
      <div className="page-header">
        <div className="page-eyebrow">{"// MODULE_02 / PASSWORD_ANALYZER"}</div>
        <h1 className="page-title">PASSWORD<br /><span>HARDENER</span></h1>
        <p className="page-desc">
          Deep entropy analysis, real-time character mapping, breach correlation,
          and crack-time estimation — know your true exposure.
        </p>
        <div className="page-rule" />
      </div>

      <div className="card">
        <div className="card-label">{"// TARGET_INPUT"}</div>
        <label className="field-label">PASSWORD</label>
        <div className="input-wrap" style={{ marginBottom: 0 }}>
          <input
            type={visible ? "text" : "password"}
            value={password}
            onChange={e => { setPassword(e.target.value); setResult(null); setError(null); }}
            onKeyDown={e => e.key === "Enter" && analyze()}
            placeholder="Enter password to analyze…"
            style={{ paddingRight: "44px" }}
            autoComplete="off"
            spellCheck={false}
          />
          <button
            className="eye-btn"
            onClick={() => setVisible(v => !v)}
            tabIndex={-1}
          >
            {visible ? "🙈" : "👁"}
          </button>
        </div>

        {password && (
          <>
            <EntropyVisualizer password={password} visible={visible} />
            <StrengthMeter score={local.score} label={local.label} color={local.color} />
          </>
        )}

        <div style={{ marginTop: 20 }}>
          <button onClick={analyze} disabled={loading || !password.trim()}>
            {loading ? <span className="spinner" /> : null}
            {loading ? "ANALYZING" : "▶ RUN ANALYSIS"}
          </button>
        </div>

        {error && (
          <div className="error-box">
            <span>✕</span><span>{error}</span>
          </div>
        )}
      </div>

      {result && (
        <div className="card" style={{ borderTopColor: accent, animation: "fadeUp 0.4s ease both" }}>
          <div className="card-label">{"// ANALYSIS_COMPLETE"}</div>

          <div style={{ marginBottom: 4 }}>
            <div style={{
              fontFamily: "var(--font-head)", fontWeight: 900,
              fontSize: "clamp(22px, 3vw, 36px)", letterSpacing: "0.06em",
              color: accent,
            }}>
              {(result.strength_label || "UNKNOWN").toUpperCase()}
            </div>
          </div>

          <div className="results-grid">
            {[
              { label: "ENTROPY",      val: result.entropy ? `${result.entropy.toFixed(1)} bits` : "N/A" },
              { label: "LENGTH",       val: `${password.length} chars` },
              { label: "CHAR_CLASSES", val: result.character_classes || "N/A" },
              { label: "BREACH_COUNT", val: result.breach_count != null ? (result.breach_count === 0 ? "CLEAN" : `${result.breach_count.toLocaleString()}×`) : "N/A" },
            ].map(({ label, val }) => (
              <div key={label} className="result-cell">
                <div className="result-cell-label">{label}</div>
                <div className="result-cell-val" style={{
                  color: label === "BREACH_COUNT" && result.breach_count > 0 ? "#c0392b" : accent
                }}>
                  {val}
                </div>
              </div>
            ))}
          </div>

          {result.crack_time_display && (
            <div className="crack-time">
              <div className="crack-time-label">EST_CRACK_TIME</div>
              <div className="crack-time-val">{result.crack_time_display}</div>
            </div>
          )}

          {result.feedback?.length > 0 && (
            <div className="feedback-list">
              <div className="card-label" style={{ marginBottom: 4, marginTop: 12 }}>{"// RECOMMENDATIONS"}</div>
              {result.feedback.map((f, i) => (
                <div key={i} className="feedback-item">
                  <span className="fi-icon" style={{ color: "#9a6c00" }}>›</span>
                  <span>{f}</span>
                </div>
              ))}
            </div>
          )}

          <div style={{ marginTop: 20 }}>
            <button className="btn-outline" onClick={() => { setResult(null); setPassword(""); }}>
              ← CLEAR
            </button>
          </div>
        </div>
      )}
    </div>
  );
}