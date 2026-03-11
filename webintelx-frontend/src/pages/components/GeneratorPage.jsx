// Password-hardener/frontend/src/components/GeneratorPage.jsx
// WHITE THEME VERSION

import { useState, useEffect, useCallback, useRef } from "react";
import axios from "axios";

const CHAR_SETS = {
  uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  lowercase: "abcdefghijklmnopqrstuvwxyz",
  digits:    "0123456789",
  symbols:   "!@#$%^&*()_+-=[]{}|;:,.<>?",
};

function buildLocal(len, opts) {
  let pool = "";
  if (opts.uppercase) pool += CHAR_SETS.uppercase;
  if (opts.lowercase) pool += CHAR_SETS.lowercase;
  if (opts.digits)    pool += CHAR_SETS.digits;
  if (opts.symbols)   pool += CHAR_SETS.symbols;
  if (!pool) pool = CHAR_SETS.lowercase;
  return Array.from({ length: len }, () => pool[Math.floor(Math.random() * pool.length)]).join("");
}

function CharStream({ active, finalVal }) {
  const [display, setDisplay] = useState("");
  const poolRef  = useRef("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%");
  const frameRef = useRef(null);

  useEffect(() => {
    if (active) {
      const tick = () => {
        const len = 18 + Math.floor(Math.random() * 6);
        const str = Array.from({ length: len }, () => {
          const p = poolRef.current;
          return p[Math.floor(Math.random() * p.length)];
        }).join("");
        setDisplay(str);
        frameRef.current = requestAnimationFrame(tick);
      };
      frameRef.current = requestAnimationFrame(tick);
    } else {
      cancelAnimationFrame(frameRef.current);
      setDisplay(finalVal || "");
    }
    return () => cancelAnimationFrame(frameRef.current);
  }, [active, finalVal]);

  return (
    <span className="gen-output-text" style={{
      color: active ? "var(--ink-4)" : "var(--ink)",
      letterSpacing: active ? "0.12em" : "0.06em",
      transition: "color 0.3s",
      fontStyle: active ? "italic" : "normal",
    }}>
      {display}
    </span>
  );
}

export default function GeneratorPage() {
  const [mode,      setMode]      = useState("random");
  const [length,    setLength]    = useState(20);
  const [opts,      setOpts]      = useState({
    uppercase: true, lowercase: true, digits: true, symbols: true,
  });
  const [primary,   setPrimary]   = useState("");
  const [secondary, setSecondary] = useState("");
  const [loading,   setLoading]   = useState(false);
  const [password,  setPassword]  = useState("");
  const [reasons,   setReasons]   = useState([]);
  const [level,     setLevel]     = useState("");
  const [error,     setError]     = useState(null);
  const [toast,     setToast]     = useState(false);

  const toggleOpt = key => setOpts(o => ({ ...o, [key]: !o[key] }));

  const generate = useCallback(async () => {
    setLoading(true);
    setError(null);
    setReasons([]);
    setLevel("");

    if (mode === "keyword") {
      if (!primary.trim()) {
        setError("Enter at least one keyword.");
        setLoading(false);
        return;
      }
      try {
        const { data } = await axios.post("http://localhost:4000/api/generate-password", {
          primary: primary.trim(),
          secondary: secondary.trim() || null,
        });
        setPassword(data.password || "");
        setReasons(data.reason || []);
        setLevel(data.level || "");
      } catch {
        setError("Generation failed — check backend connection.");
      }
    } else {
      try {
        const { data } = await axios.post("http://localhost:4000/api/generate-password", {
          length,
          include_uppercase: opts.uppercase,
          include_lowercase: opts.lowercase,
          include_digits:    opts.digits,
          include_symbols:   opts.symbols,
        });
        setPassword(data.password || buildLocal(length, opts));
      } catch {
        setPassword(buildLocal(length, opts));
      }
    }
    setLoading(false);
  }, [mode, length, opts, primary, secondary]);

  const copyPwd = () => {
    if (!password) return;
    navigator.clipboard.writeText(password).then(() => {
      setToast(true);
      setTimeout(() => setToast(false), 2000);
    });
  };

  const OPT_LABELS = [
    { key: "uppercase", label: "A–Z  UPPERCASE", color: "#1a4fa8" },
    { key: "lowercase", label: "a–z  LOWERCASE", color: "#1a7f4b" },
    { key: "digits",    label: "0–9  DIGITS",    color: "#9a6c00" },
    { key: "symbols",   label: "!@#  SYMBOLS",   color: "#c0392b" },
  ];

  const levelColor =
    level === "Insane" ? "#1a7f4b" :
    level === "Medium" ? "#9a6c00" :
    "#1a4fa8";

  return (
    <div className="page">
      <div className="page-header">
        <div className="page-eyebrow">{"// MODULE_02 / PASSWORD_GENERATOR"}</div>
        <h1 className="page-title">PASSWORD<br /><span>GENERATOR</span></h1>
        <p className="page-desc">
          Cryptographically strong password generation with configurable character pools,
          entropy tuning, and instant clipboard delivery.
        </p>
        <div className="page-rule" />
      </div>

      {/* Mode toggle */}
      <div className="card">
        <div className="card-label">{"// GENERATION_MODE"}</div>
        <div style={{ display: "flex", gap: 10 }}>
          {[
            { id: "random",  label: "⬡  RANDOM",  desc: "Cryptographic character pool" },
            { id: "keyword", label: "◈  KEYWORD",  desc: "Built from your own words"   },
          ].map(({ id, label, desc }) => {
            const active = mode === id;
            return (
              <button
                key={id}
                onClick={() => { setMode(id); setPassword(""); setReasons([]); setLevel(""); setError(null); }}
                style={{
                  flex: 1,
                  fontFamily: "var(--font-head)",
                  fontWeight: 700,
                  fontSize: "11px",
                  letterSpacing: "0.18em",
                  padding: "14px 10px 10px",
                  cursor: "pointer",
                  border: `1.5px solid ${active ? "var(--ink)" : "var(--border)"}`,
                  background: active ? "var(--ink)" : "var(--surface-2)",
                  color: active ? "var(--surface)" : "var(--ink-3)",
                  boxShadow: active ? "var(--shadow-md)" : "none",
                  transition: "all 0.2s",
                  textAlign: "left",
                  borderRadius: "var(--radius)",
                  transform: "none",
                }}
              >
                {label}
                <div style={{
                  fontFamily: "var(--font-mono)",
                  fontWeight: 400,
                  fontSize: "8px",
                  letterSpacing: "0.1em",
                  marginTop: 6,
                  color: active ? "rgba(255,255,255,0.5)" : "var(--ink-4)",
                }}>
                  {desc}
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Config card */}
      <div className="card">
        <div className="card-label">{"// GENERATION_CONFIG"}</div>

        {/* RANDOM MODE */}
        {mode === "random" && (
          <>
            <label className="field-label">LENGTH</label>
            <div className="length-row">
              <span style={{ fontFamily: "var(--font-mono)", fontSize: "9px", color: "var(--ink-4)", letterSpacing: "0.15em" }}>MIN:8</span>
              <span className="length-val">{length}</span>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: "9px", color: "var(--ink-4)", letterSpacing: "0.15em" }}>MAX:64</span>
            </div>
            <input
              type="range"
              min={8} max={64}
              value={length}
              onChange={e => setLength(Number(e.target.value))}
              style={{ marginBottom: 24 }}
            />

            <label className="field-label">CHARACTER_POOLS</label>
            <div className="gen-options">
              {OPT_LABELS.map(({ key, label, color }) => (
                <label
                  key={key}
                  className="gen-option"
                  style={{
                    borderColor: opts[key] ? color : "var(--border)",
                    background: opts[key] ? `${color}0a` : "var(--surface-2)",
                  }}
                >
                  <input type="checkbox" checked={opts[key]} onChange={() => toggleOpt(key)} />
                  <span className="gen-option-label" style={{ color: opts[key] ? color : "var(--ink-3)" }}>{label}</span>
                </label>
              ))}
            </div>
          </>
        )}

        {/* KEYWORD MODE */}
        {mode === "keyword" && (
          <>
            <div style={{
              marginBottom: 20,
              padding: "12px 16px",
              background: "var(--surface-2)",
              border: "1px solid var(--border)",
              borderLeft: "3px solid var(--accent)",
              fontFamily: "var(--font-mono)",
              fontSize: "11px",
              color: "var(--ink-3)",
              lineHeight: 1.7,
            }}>
              {"// One keyword → MEDIUM strength (e.g. \"falcon\" → \"Fal#con72\")"}<br />
              {"// Two keywords → INSANE strength (e.g. \"falcon\" + \"storm\" → \"Fa#lcon_St@orm84\")"}
            </div>

            <label className="field-label">PRIMARY KEYWORD</label>
            <div className="input-wrap" style={{ marginBottom: 18 }}>
              <input
                type="text"
                value={primary}
                onChange={e => setPrimary(e.target.value)}
                onKeyDown={e => e.key === "Enter" && generate()}
                placeholder="e.g. falcon, thunder, matrix…"
                autoComplete="off"
                spellCheck={false}
              />
            </div>

            <label className="field-label" style={{ display: "flex", alignItems: "center", gap: 10 }}>
              SECONDARY KEYWORD
              <span style={{
                fontFamily: "var(--font-mono)", fontSize: "8px",
                color: "var(--ink-4)", letterSpacing: "0.15em", fontWeight: 400,
              }}>
                OPTIONAL — UNLOCKS INSANE MODE
              </span>
            </label>
            <div className="input-wrap" style={{ marginBottom: 0 }}>
              <input
                type="text"
                value={secondary}
                onChange={e => setSecondary(e.target.value)}
                onKeyDown={e => e.key === "Enter" && generate()}
                placeholder="e.g. storm, cipher, nexus…"
                autoComplete="off"
                spellCheck={false}
                style={{ borderColor: secondary ? "#1a7f4b" : undefined }}
              />
            </div>

            {(primary || secondary) && (
              <div style={{
                marginTop: 12,
                display: "flex", alignItems: "center", gap: 8,
                fontFamily: "var(--font-mono)", fontSize: "10px",
                color: secondary.trim() ? "#1a7f4b" : "#9a6c00",
                letterSpacing: "0.1em",
              }}>
                <div style={{
                  width: 6, height: 6, borderRadius: "50%",
                  background: secondary.trim() ? "#1a7f4b" : "#9a6c00",
                }} />
                {secondary.trim() ? "INSANE MODE — two-word passphrase" : "MEDIUM MODE — single keyword"}
              </div>
            )}
          </>
        )}

        {/* OUTPUT (shared) */}
        <div style={{ marginTop: 24 }}>
          <label className="field-label">OUTPUT</label>
          <div className="gen-output">
            {!password && !loading ? (
              <span className="gen-output-placeholder">AWAITING_GENERATION</span>
            ) : (
              <CharStream active={loading} finalVal={password} />
            )}
            {password && !loading && (
              <button className="copy-btn" onClick={copyPwd}>COPY</button>
            )}
          </div>
        </div>

        {/* Stats preview */}
        {password && !loading && (
          <div style={{
            marginTop: 12, padding: "12px 16px",
            background: "var(--surface-2)",
            border: "1px solid var(--border)",
            display: "flex", gap: 24, flexWrap: "wrap",
            borderRadius: "var(--radius)",
          }}>
            {mode === "random" ? (
              <>
                {[
                  { label: "LENGTH",  val: `${password.length}` },
                  { label: "ENTROPY", val: `~${Math.round(Math.log2(
                      (opts.uppercase ? 26 : 0) +
                      (opts.lowercase ? 26 : 0) +
                      (opts.digits    ? 10 : 0) +
                      (opts.symbols   ? 32 : 0) || 26
                    ) * password.length)} bits` },
                  { label: "POOLS",   val: `${Object.values(opts).filter(Boolean).length}/4` },
                ].map(({ label, val }) => (
                  <div key={label}>
                    <div style={{ fontFamily: "var(--font-mono)", fontSize: "8px", letterSpacing: "0.2em", color: "var(--ink-4)", marginBottom: 4 }}>{label}</div>
                    <div style={{ fontFamily: "var(--font-head)", fontWeight: 800, fontSize: "16px", color: "var(--ink)" }}>{val}</div>
                  </div>
                ))}
              </>
            ) : (
              <>
                <div>
                  <div style={{ fontFamily: "var(--font-mono)", fontSize: "8px", letterSpacing: "0.2em", color: "var(--ink-4)", marginBottom: 4 }}>LENGTH</div>
                  <div style={{ fontFamily: "var(--font-head)", fontWeight: 800, fontSize: "16px", color: "var(--ink)" }}>{password.length}</div>
                </div>
                {level && (
                  <div>
                    <div style={{ fontFamily: "var(--font-mono)", fontSize: "8px", letterSpacing: "0.2em", color: "var(--ink-4)", marginBottom: 4 }}>STRENGTH</div>
                    <div style={{ fontFamily: "var(--font-head)", fontWeight: 800, fontSize: "16px", color: levelColor }}>{level.toUpperCase()}</div>
                  </div>
                )}
              </>
            )}
          </div>
        )}

        {/* Keyword reasons */}
        {mode === "keyword" && reasons.length > 0 && password && !loading && (
          <div style={{ marginTop: 12 }}>
            <div className="card-label" style={{ marginBottom: 6 }}>{"// WHY_ITS_STRONG"}</div>
            {reasons.map((r, i) => (
              <div key={i} className="feedback-item">
                <span className="fi-icon" style={{ color: "#1a7f4b" }}>›</span>
                <span>{r}</span>
              </div>
            ))}
          </div>
        )}

        {error && (
          <div className="error-box" style={{ marginTop: 16 }}>
            <span>✕</span><span>{error}</span>
          </div>
        )}

        <div style={{ marginTop: 20, display: "flex", gap: 10, flexWrap: "wrap" }}>
          <button onClick={generate} disabled={loading}>
            {loading ? <span className="spinner" /> : null}
            {loading ? "GENERATING" : "▶ GENERATE"}
          </button>
          {password && (
            <button
              className="btn-outline"
              onClick={() => { setPassword(""); setReasons([]); setLevel(""); }}
            >
              CLEAR
            </button>
          )}
        </div>
      </div>

      {/* Tips card */}
      <div className="card" style={{ animation: "fadeUp 0.5s ease 0.3s both" }}>
        <div className="card-label">{"// SECURITY_NOTES"}</div>
        {[
          { text: "Use 16+ characters for high-security accounts — longer is always stronger." },
          { text: "Enable all four character pools to maximize entropy per character." },
          { text: "Never reuse passwords — a unique credential per service is non-negotiable." },
          { text: "Store generated passwords in an encrypted vault, not plain text." },
        ].map((t, i) => (
          <div key={i} className="feedback-item" style={{ marginBottom: i < 3 ? 0 : 0 }}>
            <span className="fi-icon" style={{ color: "var(--accent)" }}>›</span>
            <span>{t.text}</span>
          </div>
        ))}
      </div>

      {toast && <div className="toast">✓ COPIED TO CLIPBOARD</div>}
    </div>
  );
}