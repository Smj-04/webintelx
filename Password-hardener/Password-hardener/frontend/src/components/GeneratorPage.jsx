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
      color: active ? "rgba(0, 212, 255, 0.4)" : "#00d4ff",
      letterSpacing: active ? "0.12em" : "0.06em",
      transition: "color 0.3s",
    }}>
      {display}
    </span>
  );
}

export default function GeneratorPage() {
  // Mode: "random" | "keyword"
  const [mode,     setMode]     = useState("random");

  // Random mode state
  const [length,   setLength]   = useState(20);
  const [opts,     setOpts]     = useState({
    uppercase: true, lowercase: true, digits: true, symbols: true,
  });

  // Keyword mode state
  const [primary,   setPrimary]   = useState("");
  const [secondary, setSecondary] = useState("");

  // Shared state
  const [loading,  setLoading]  = useState(false);
  const [password, setPassword] = useState("");
  const [reasons,  setReasons]  = useState([]);
  const [level,    setLevel]    = useState("");
  const [error,    setError]    = useState(null);
  const [toast,    setToast]    = useState(false);

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
    { key: "uppercase", label: "A–Z  UPPERCASE",  color: "#00d4ff" },
    { key: "lowercase", label: "a–z  LOWERCASE",  color: "#00ff88" },
    { key: "digits",    label: "0–9  DIGITS",     color: "#fbbf24" },
    { key: "symbols",   label: "!@#  SYMBOLS",    color: "#ff6b35" },
  ];

  const levelColor = level === "Insane" ? "#00ff88" : level === "Medium" ? "#fbbf24" : "#00d4ff";

  return (
    <div className="page">
      {/* Header */}
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
        <div style={{ display: "flex", gap: 10, marginBottom: 0 }}>
          {[
            { id: "random",  label: "⬡  RANDOM",   desc: "Cryptographic character pool" },
            { id: "keyword", label: "◈  KEYWORD",   desc: "Built from your own words"   },
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
                  border: `1px solid ${active ? "#00d4ff" : "rgba(255,255,255,0.07)"}`,
                  background: active ? "rgba(0,212,255,0.07)" : "rgba(0,0,0,0.3)",
                  color: active ? "#00d4ff" : "rgba(255,255,255,0.3)",
                  boxShadow: active ? "0 0 20px rgba(0,212,255,0.12)" : "none",
                  transition: "all 0.25s",
                  textAlign: "left",
                }}
              >
                {label}
                <div style={{
                  fontFamily: "var(--font-mono)",
                  fontWeight: 400,
                  fontSize: "8px",
                  letterSpacing: "0.1em",
                  marginTop: 6,
                  color: active ? "rgba(0,212,255,0.5)" : "rgba(255,255,255,0.15)",
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

        {/* ── RANDOM MODE ── */}
        {mode === "random" && (
          <>
            <label className="field-label">LENGTH</label>
            <div className="length-row">
              <span style={{ fontFamily: "var(--font-mono)", fontSize: "11px", color: "rgba(0,212,255,0.35)", letterSpacing: "0.15em" }}>MIN:8</span>
              <span className="length-val">{length}</span>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: "11px", color: "rgba(0,212,255,0.35)", letterSpacing: "0.15em" }}>MAX:64</span>
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
                  style={{ borderColor: opts[key] ? `${color}40` : "rgba(255,255,255,0.05)", cursor: "pointer" }}
                >
                  <input type="checkbox" checked={opts[key]} onChange={() => toggleOpt(key)} />
                  <span className="gen-option-label" style={{ color: opts[key] ? color : undefined }}>{label}</span>
                </label>
              ))}
            </div>
          </>
        )}

        {/* ── KEYWORD MODE ── */}
        {mode === "keyword" && (
          <>
            {/* Explanation */}
            <div style={{
              marginBottom: 20,
              padding: "12px 16px",
              background: "rgba(0,212,255,0.04)",
              border: "1px solid rgba(0,212,255,0.1)",
              fontFamily: "var(--font-mono)",
              fontSize: "11px",
              color: "rgba(0,212,255,0.45)",
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
                color: "rgba(255,255,255,0.2)", letterSpacing: "0.15em",
                fontWeight: 400,
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
                style={{
                  borderColor: secondary ? "rgba(0,255,136,0.3)" : undefined,
                }}
              />
            </div>

            {/* Live mode indicator */}
            {(primary || secondary) && (
              <div style={{
                marginTop: 12,
                display: "flex", alignItems: "center", gap: 8,
                fontFamily: "var(--font-mono)", fontSize: "10px",
                color: secondary.trim() ? "#00ff88" : "#fbbf24",
              }}>
                <div style={{
                  width: 6, height: 6, borderRadius: "50%",
                  background: secondary.trim() ? "#00ff88" : "#fbbf24",
                  boxShadow: `0 0 8px ${secondary.trim() ? "#00ff88" : "#fbbf24"}`,
                }} />
                {secondary.trim() ? "INSANE MODE — two-word passphrase" : "MEDIUM MODE — single keyword"}
              </div>
            )}
          </>
        )}

        {/* ── OUTPUT (shared) ── */}
        <div style={{ marginTop: 24 }}>
          <label className="field-label">OUTPUT</label>
          <div className="gen-output">
            {!password && !loading ? (
              <span className="gen-output-placeholder">AWAITING_GENERATION</span>
            ) : (
              <CharStream active={loading} finalVal={password} />
            )}
            {password && !loading && (
              <button className="copy-btn" onClick={copyPwd}
                style={{ fontFamily: "var(--font-head)", fontWeight: 700, fontSize: "9px", letterSpacing: "0.15em", padding: "8px 14px" }}
              >
                COPY
              </button>
            )}
          </div>
        </div>

        {/* Entropy / stats preview */}
        {password && !loading && (
          <div style={{
            marginTop: 12, padding: "10px 14px",
            background: "rgba(0,0,0,0.4)",
            border: "1px solid rgba(0,212,255,0.08)",
            display: "flex", gap: 24, flexWrap: "wrap",
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
                    <div style={{ fontFamily: "var(--font-mono)", fontSize: "8px", letterSpacing: "0.2em", color: "rgba(255,255,255,0.2)", marginBottom: 4 }}>{label}</div>
                    <div style={{ fontFamily: "var(--font-head)", fontWeight: 700, fontSize: "14px", color: "#00d4ff" }}>{val}</div>
                  </div>
                ))}
              </>
            ) : (
              <>
                <div>
                  <div style={{ fontFamily: "var(--font-mono)", fontSize: "8px", letterSpacing: "0.2em", color: "rgba(255,255,255,0.2)", marginBottom: 4 }}>LENGTH</div>
                  <div style={{ fontFamily: "var(--font-head)", fontWeight: 700, fontSize: "14px", color: "#00d4ff" }}>{password.length}</div>
                </div>
                {level && (
                  <div>
                    <div style={{ fontFamily: "var(--font-mono)", fontSize: "8px", letterSpacing: "0.2em", color: "rgba(255,255,255,0.2)", marginBottom: 4 }}>STRENGTH</div>
                    <div style={{ fontFamily: "var(--font-head)", fontWeight: 700, fontSize: "14px", color: levelColor }}>{level.toUpperCase()}</div>
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
                <span className="fi-icon" style={{ color: "#00ff88" }}>›</span>
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
              style={{
                fontFamily: "var(--font-mono)", fontWeight: 400,
                fontSize: "9px", letterSpacing: "0.2em",
                color: "rgba(0,212,255,0.4)", background: "transparent",
                border: "1px solid rgba(255,255,255,0.06)", padding: "9px 16px",
              }}
              onClick={() => { setPassword(""); setReasons([]); setLevel(""); }}
            >
              CLEAR
            </button>
          )}
        </div>
      </div>

      {/* Tips card */}
      <div className="card" style={{ borderTopColor: "rgba(0,212,255,0.3)", animation: "fadeUp 0.5s ease 0.3s both" }}>
        <div className="card-label">{"// SECURITY_NOTES"}</div>
        {[
          { icon: "›", text: "Use 16+ characters for high-security accounts — longer is always stronger." },
          { icon: "›", text: "Enable all four character pools to maximize entropy per character." },
          { icon: "›", text: "Never reuse passwords — a unique credential per service is non-negotiable." },
          { icon: "›", text: "Store generated passwords in an encrypted vault, not plain text." },
        ].map((t, i) => (
          <div key={i} className="feedback-item" style={{ marginBottom: i < 3 ? 8 : 0 }}>
            <span className="fi-icon" style={{ color: "#00d4ff" }}>{t.icon}</span>
            <span>{t.text}</span>
          </div>
        ))}
      </div>

      {toast && <div className="toast">✓ COPIED TO CLIPBOARD</div>}
    </div>
  );
}