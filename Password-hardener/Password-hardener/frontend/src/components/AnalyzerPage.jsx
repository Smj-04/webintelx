//this is Password-hardener/frontend/src/components/AnalyzerPage.jsx

import { useState, useCallback } from "react";
import axios from "axios";

/* ── helpers ── */
const CHAR_COLORS = {
  upper:   { bg: "#00d4ff22", border: "#00d4ff", text: "#00d4ff",  label: "UPPER" },
  lower:   { bg: "#00ff8822", border: "#00ff88", text: "#00ff88",  label: "LOWER" },
  digit:   { bg: "#fbbf2422", border: "#fbbf24", text: "#fbbf24",  label: "DIGIT" },
  special: { bg: "#ff6b3522", border: "#ff6b35", text: "#ff6b35",  label: "SPECIAL" },
  space:   { bg: "#b06aff22", border: "#b06aff", text: "#b06aff",  label: "SPACE" },
  other:   { bg: "#ffffff11", border: "#ffffff44", text: "#aaaaaa", label: "OTHER" },
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
  if (!pwd) return { score: 0, label: "—", color: "rgba(255,255,255,0.1)" };
  let s = 0;
  if (pwd.length >= 8)  s++;
  if (pwd.length >= 12) s++;
  if (pwd.length >= 16) s++;
  if (/[A-Z]/.test(pwd)) s++;
  if (/[a-z]/.test(pwd)) s++;
  if (/[0-9]/.test(pwd)) s++;
  if (/[^a-zA-Z0-9]/.test(pwd)) s++;
  const score = Math.min(Math.round((s / 7) * 100), 100);
  if (score < 30) return { score, label: "CRITICAL", color: "#ff4d6a" };
  if (score < 55) return { score, label: "WEAK",     color: "#ff6b35" };
  if (score < 75) return { score, label: "FAIR",     color: "#fbbf24" };
  if (score < 90) return { score, label: "STRONG",   color: "#00ff88" };
  return              { score, label: "FORTRESS",  color: "#00d4ff" };
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
                boxShadow: `0 0 4px ${col.border}40`,
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
              boxShadow: `0 0 6px ${color}60`,
              transition: `background 0.3s ease ${i * 0.025}s, box-shadow 0.3s ease ${i * 0.025}s`,
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
  const [password, setPassword]   = useState("");
  const [visible,  setVisible]    = useState(false);
  const [loading,  setLoading]    = useState(false);
  const [result,   setResult]     = useState(null);
  const [error,    setError]      = useState(null);

  const local = localStrength(password);

  const analyze = useCallback(async () => {
    if (!password.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const { data } = await axios.post("http://localhost:4000/api/analyze", { password });
      const a = data.analysis;

      // Count how many character classes are present
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
    ? (result.strength_label === "Strong" || result.strength_label === "Very Strong") ? "#00d4ff"
      : result.strength_label === "Medium" ? "#fbbf24"
      : "#ff4d6a"
    : "#00d4ff";

  return (
    <div className="page">
      {/* Header */}
      <div className="page-header">
        <div className="page-eyebrow">{"// MODULE_02 / PASSWORD_ANALYZER"}</div>
        <h1 className="page-title">PASSWORD<br /><span>HARDENER</span></h1>
        <p className="page-desc">
          Deep entropy analysis, real-time character mapping, breach correlation,
          and crack-time estimation — know your true exposure.
        </p>
        <div className="page-rule" />
      </div>

      {/* Input card */}
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
            style={{
              position: "absolute", right: 12, top: "50%",
              transform: "translateY(-50%)", background: "none",
              border: "none", width: "auto", padding: "4px",
              cursor: "pointer", color: "rgba(0,212,255,0.4)",
              fontSize: 14, display: "flex", alignItems: "center",
            }}
          >
            {visible ? "🙈" : "👁"}
          </button>
        </div>

        {/* Live entropy map */}
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
            <span>✕</span>
            <span>{error}</span>
          </div>
        )}
      </div>

      {/* Results */}
      {result && (
        <div className="card" style={{
          borderTopColor: accent,
          animation: "fadeUp 0.4s ease both",
        }}>
          <div className="card-label">{"// ANALYSIS_COMPLETE"}</div>

          {/* Verdict */}
          <div style={{ display: "flex", alignItems: "center", gap: 16, marginBottom: 4 }}>
            <div style={{
              fontFamily: "var(--font-head)", fontWeight: 900,
              fontSize: "clamp(22px, 3vw, 36px)", letterSpacing: "0.06em",
              color: accent, textShadow: `0 0 30px ${accent}60`,
            }}>
              {(result.strength_label || "UNKNOWN").toUpperCase()}
            </div>
          </div>

          {/* Stat grid */}
          <div className="results-grid">
            {[
              { label: "ENTROPY",      val: result.entropy ? `${result.entropy.toFixed(1)} bits` : "N/A" },
              { label: "LENGTH",       val: `${password.length} chars` },
              { label: "CHAR_CLASSES", val: result.character_classes || "N/A" },
              { label: "BREACH_COUNT", val: result.breach_count != null ? (result.breach_count === 0 ? "CLEAN" : `${result.breach_count.toLocaleString()}×`) : "N/A" },
            ].map(({ label, val }) => (
              <div key={label} className="result-cell">
                <div className="result-cell-label">{label}</div>
                <div className="result-cell-val" style={{ color: label === "BREACH_COUNT" && result.breach_count > 0 ? "#ff4d6a" : accent }}>
                  {val}
                </div>
              </div>
            ))}
          </div>

          {/* Crack time */}
          {result.crack_time_display && (
            <div className="crack-time">
              <div className="crack-time-label">EST_CRACK_TIME</div>
              <div className="crack-time-val" style={{ color: accent }}>{result.crack_time_display}</div>
            </div>
          )}

          {/* Feedback */}
          {result.feedback?.length > 0 && (
            <div className="feedback-list">
              <div className="card-label" style={{ marginBottom: 4, marginTop: 12 }}>{"// RECOMMENDATIONS"}</div>
              {result.feedback.map((f, i) => (
                <div key={i} className="feedback-item">
                  <span className="fi-icon" style={{ color: "#fbbf24" }}>›</span>
                  <span>{f}</span>
                </div>
              ))}
            </div>
          )}

          <div style={{ marginTop: 20 }}>
            <button
              className="btn-outline"
              style={{
                fontFamily: "var(--font-mono)", fontWeight: 400, fontSize: "9px",
                letterSpacing: "0.2em", color: "rgba(0,212,255,0.4)",
                background: "transparent", border: "1px solid rgba(255,255,255,0.06)",
                padding: "9px 16px",
              }}
              onClick={() => { setResult(null); setPassword(""); }}
            >
              ← CLEAR
            </button>
          </div>
        </div>
      )}
    </div>
  );
}