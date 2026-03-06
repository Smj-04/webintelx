import React, { useState, useEffect, useRef } from "react";
import axios from "axios";
import { FaShieldAlt, FaSearch, FaExclamationTriangle, FaCheckCircle, FaTimesCircle, FaLink } from "react-icons/fa";

const FONT_URL = "https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;600;700;900&family=Rajdhani:wght@300;400;500;600;700&display=swap";

// Parse a URL into colored token segments
function tokenizeURL(raw) {
  if (!raw) return [];
  try {
    const withProto = raw.startsWith("http") ? raw : `https://${raw}`;
    const u = new URL(withProto);
    const tokens = [];
    if (u.protocol) tokens.push({ text: u.protocol + "//", type: "protocol" });
    const hostParts = u.hostname.split(".");
    hostParts.forEach((p, i) => {
      tokens.push({ text: p, type: i === hostParts.length - 2 ? "domain" : i === hostParts.length - 1 ? "tld" : "subdomain" });
      if (i < hostParts.length - 1) tokens.push({ text: ".", type: "dot" });
    });
    if (u.port) tokens.push({ text: ":" + u.port, type: "port" });
    if (u.pathname && u.pathname !== "/") tokens.push({ text: u.pathname, type: "path" });
    if (u.search) tokens.push({ text: u.search, type: "query" });
    return tokens;
  } catch {
    return [{ text: raw, type: "plain" }];
  }
}

const TOKEN_COLORS = {
  protocol: "rgba(180,180,180,0.4)",
  subdomain: "#fbbf24",
  domain: "#f8fafc",
  tld: "rgba(248,250,252,0.55)",
  dot: "rgba(248,250,252,0.3)",
  port: "#ff6b35",
  path: "rgba(180,255,180,0.45)",
  query: "#f472b6",
  plain: "#f8fafc",
};

function URLTokenizer({ url }) {
  const tokens = tokenizeURL(url);
  if (!url) return null;
  return (
    <div style={{
      marginTop: "14px", padding: "12px 16px",
      background: "rgba(0,0,0,0.6)", border: "1px solid rgba(251,191,36,0.1)",
      fontFamily: "'Share Tech Mono', monospace", fontSize: "13px",
      letterSpacing: "0.03em", lineHeight: 1.5, wordBreak: "break-all",
      borderLeft: "2px solid rgba(251,191,36,0.25)",
    }}>
      <div style={{ fontSize: "8px", letterSpacing: "0.25em", color: "rgba(251,191,36,0.35)", marginBottom: "8px" }}>URL_BREAKDOWN</div>
      <div>
        {tokens.map((t, i) => (
          <span key={i} style={{ color: TOKEN_COLORS[t.type] || "#f8fafc" }}>{t.text}</span>
        ))}
      </div>
      <div style={{ marginTop: "10px", display: "flex", gap: "16px", flexWrap: "wrap" }}>
        {[
          { type: "protocol", label: "PROTOCOL" },
          { type: "subdomain", label: "SUBDOMAIN" },
          { type: "domain", label: "DOMAIN" },
          { type: "path", label: "PATH" },
          { type: "query", label: "QUERY" },
        ].filter(l => tokens.some(t => t.type === l.type)).map((l, i) => (
          <span key={i} style={{ fontSize: "8px", letterSpacing: "0.15em", color: TOKEN_COLORS[l.type], opacity: 0.7 }}>
            ▪ {l.label}
          </span>
        ))}
      </div>
    </div>
  );
}

function ThreatMeter({ probability, accent }) {
  const [animated, setAnimated] = useState(0);
  useEffect(() => {
    const t = setTimeout(() => setAnimated(probability), 80);
    return () => clearTimeout(t);
  }, [probability]);

  const pct = Math.round(animated * 100);
  const segments = 20;

  return (
    <div style={{ marginTop: "28px" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: "10px" }}>
        <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", letterSpacing: "0.25em", color: "rgba(0,255,136,0.35)" }}>THREAT_CONFIDENCE</span>
        <span style={{ fontFamily: "'Orbitron', monospace", fontWeight: 900, fontSize: "26px", color: accent, textShadow: `0 0 20px ${accent}60` }}>
          {pct}<span style={{ fontSize: "14px", opacity: 0.6 }}>%</span>
        </span>
      </div>
      <div style={{ display: "flex", gap: "3px", alignItems: "center" }}>
        {Array.from({ length: segments }).map((_, i) => {
          const threshold = (i + 1) / segments;
          const active = animated >= threshold;
          return (
            <div key={i} style={{
              flex: 1, height: "20px",
              background: active ? accent : "rgba(255,255,255,0.04)",
              boxShadow: active ? `0 0 6px ${accent}60` : "none",
              transition: `background 0.4s ease ${i * 0.03}s, box-shadow 0.4s ease ${i * 0.03}s`,
            }} />
          );
        })}
      </div>
      <div style={{ display: "flex", justifyContent: "space-between", marginTop: "6px" }}>
        <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "8px", color: "rgba(0,255,136,0.25)", letterSpacing: "0.15em" }}>SAFE</span>
        <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "8px", color: "rgba(255,107,53,0.4)", letterSpacing: "0.15em" }}>CRITICAL</span>
      </div>
    </div>
  );
}

const SIGNAL_CHECKS = [
  { label: "SSL", desc: "Certificate validity & CN mismatch", icon: "🔒" },
  { label: "DOMAIN AGE", desc: "WHOIS registration recency", icon: "📅" },
  { label: "TYPOSQUAT", desc: "Lookalike brand impersonation", icon: "🎭" },
  { label: "REDIRECTS", desc: "Suspicious forwarding chains", icon: "↪" },
  { label: "JS INJECT", desc: "Keyloggers, iframes, obfuscated scripts", icon: "⚡" },
  { label: "REPUTATION", desc: "Safe Browsing & threat intel feeds", icon: "🛡" },
];

const riskAccent = (risk) => {
  const r = (risk || "").toUpperCase();
  if (r === "HIGH" || r === "PHISHING") return "#ff6b35";
  if (r === "MEDIUM" || r === "SUSPICIOUS") return "#fbbf24";
  return "#00d4a0";
};

export default function PhishingDetection() {
  const [url, setUrl] = useState("");
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);

  const startScan = async () => {
    if (!url.trim()) return;
    setLoading(true);
    setResults(null);
    try {
      const response = await axios.post("http://localhost:5000/api/phishing-check", { url });
      setResults(response.data);
    } catch {
      setResults({ error: "Phishing analysis failed. Check the target URL and try again." });
    }
    setLoading(false);
  };

  const accent = results ? riskAccent(results.risk_level || results.prediction) : "#fbbf24";

  return (
    <div style={{ backgroundColor: "#0a0b0d", minHeight: "100vh", color: "#f0f4f0" }}>
      <link rel="stylesheet" href={FONT_URL} />
      <style>{`
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.35} }
        @keyframes fadeUp { from{opacity:0;transform:translateY(20px)} to{opacity:1;transform:translateY(0)} }
        @keyframes spin { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }
        @keyframes shimmer { 0%{left:-100%} 100%{left:200%} }
        * { box-sizing:border-box; margin:0; padding:0; }
        ::selection { background:rgba(251,191,36,0.2); color:#fbbf24; }
        ::-webkit-scrollbar { width:2px; }
        ::-webkit-scrollbar-track { background:#0a0b0d; }
        ::-webkit-scrollbar-thumb { background:#fbbf2440; }
        input::placeholder { color: rgba(251,191,36,0.25); }
      `}</style>

      {/* Subtle top gradient wash */}
      <div style={{ position: "fixed", top: 0, left: 0, right: 0, height: "280px", background: "radial-gradient(ellipse 80% 200px at 50% 0%, rgba(251,191,36,0.04) 0%, transparent 100%)", pointerEvents: "none", zIndex: 0 }} />

      {/* NAVBAR */}
      <nav style={{
        position: "fixed", top: 0, left: 0, right: 0, zIndex: 200,
        display: "flex", alignItems: "center", justifyContent: "space-between",
        padding: "0 48px", height: "60px",
        background: "rgba(10,11,13,0.96)",
        borderBottom: "1px solid rgba(255,255,255,0.05)",
        backdropFilter: "blur(20px)",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: "12px", cursor: "pointer" }} onClick={() => window.location.href = "/"}>
          <svg viewBox="0 0 36 36" width="28" height="28">
            <polygon points="18,2 34,11 34,25 18,34 2,25 2,11" fill="none" stroke="#00ff88" strokeWidth="1.5" />
            <polygon points="18,8 28,14 28,22 18,28 8,22 8,14" fill="none" stroke="#00ff88" strokeWidth="0.7" opacity="0.4" />
            <circle cx="18" cy="18" r="2.5" fill="#00ff88">
              <animate attributeName="opacity" values="1;0.5;1" dur="2.5s" repeatCount="indefinite" />
            </circle>
          </svg>
          <span style={{ fontFamily: "'Orbitron', monospace", fontWeight: 900, fontSize: "13px", letterSpacing: "0.14em", color: "#00ff88" }}>WEBINTELX</span>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", letterSpacing: "0.2em", color: "rgba(251,191,36,0.35)", padding: "4px 10px", border: "1px solid rgba(251,191,36,0.12)", }}>MODULE_03</span>
          <div style={{ width: "6px", height: "6px", borderRadius: "50%", background: loading ? "#fbbf24" : "#00ff88", boxShadow: `0 0 8px ${loading ? "#fbbf24" : "#00ff88"}`, animation: "pulse 2s ease-in-out infinite" }} />
          <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", color: loading ? "#fbbf24" : "rgba(0,255,136,0.5)", letterSpacing: "0.15em" }}>
            {loading ? "SCANNING" : "READY"}
          </span>
        </div>
      </nav>

      <div style={{ position: "relative", zIndex: 2, maxWidth: "860px", margin: "0 auto", padding: "96px 32px 80px" }}>

        {/* ── PAGE HEADER ── */}
        <div style={{ marginBottom: "56px", animation: "fadeUp 0.5s ease 0.1s both" }}>
          <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", letterSpacing: "0.35em", color: "rgba(251,191,36,0.4)", marginBottom: "16px" }}>
            {"// PHISHING_DETECTION"}
          </div>
          <h1 style={{ fontFamily: "'Orbitron', monospace", fontWeight: 900, fontSize: "clamp(30px, 4.5vw, 54px)", letterSpacing: "0.02em", lineHeight: 1, color: "#f0f4f0", marginBottom: "20px" }}>
            PHISHING<br />
            <span style={{ color: "#fbbf24", textShadow: "0 0 40px rgba(251,191,36,0.3)" }}>DETECTOR</span>
          </h1>
          <p style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: "16px", color: "rgba(200,220,200,0.45)", lineHeight: 1.8, maxWidth: "460px" }}>
            Paste any URL to run a multi-signal threat analysis — domain reputation, SSL anomalies, typosquatting patterns, and ML confidence scoring.
          </p>
        </div>

        {/* ── INPUT SECTION ── */}
        <div style={{ marginBottom: "48px", animation: "fadeUp 0.5s ease 0.2s both" }}>
          <label style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", letterSpacing: "0.3em", color: "rgba(251,191,36,0.45)", display: "block", marginBottom: "10px" }}>
            TARGET URL
          </label>

          <div style={{ display: "flex", gap: "10px" }}>
            <div style={{ flex: 1, position: "relative" }}>
              <FaLink style={{
                position: "absolute", left: "14px", top: "50%", transform: "translateY(-50%)",
                color: "rgba(251,191,36,0.3)", fontSize: "13px", pointerEvents: "none",
              }} />
              <input
                type="text"
                value={url}
                onChange={e => setUrl(e.target.value)}
                onKeyDown={e => e.key === "Enter" && startScan()}
                placeholder="https://suspicious-site.com/login"
                style={{
                  width: "100%", padding: "14px 16px 14px 40px",
                  background: "rgba(255,255,255,0.03)",
                  border: "1px solid rgba(255,255,255,0.08)",
                  borderBottom: "2px solid rgba(251,191,36,0.3)",
                  color: "#fbbf24", fontFamily: "'Share Tech Mono', monospace", fontSize: "13px",
                  outline: "none", letterSpacing: "0.03em", transition: "all 0.2s",
                }}
                onFocus={e => { e.target.style.borderBottomColor = "#fbbf24"; e.target.style.background = "rgba(251,191,36,0.03)"; }}
                onBlur={e => { e.target.style.borderBottomColor = "rgba(251,191,36,0.3)"; e.target.style.background = "rgba(255,255,255,0.03)"; }}
              />
            </div>
            <button
              onClick={startScan}
              disabled={loading || !url.trim()}
              style={{
                fontFamily: "'Orbitron', monospace", fontWeight: 700, fontSize: "10px",
                letterSpacing: "0.2em", color: loading ? "rgba(10,11,13,0.5)" : "#0a0b0d",
                background: loading ? "rgba(251,191,36,0.4)" : "#fbbf24",
                border: "none", padding: "14px 28px", cursor: loading ? "not-allowed" : "pointer",
                textTransform: "uppercase", transition: "all 0.2s",
                display: "flex", alignItems: "center", gap: "8px", whiteSpace: "nowrap",
              }}
              onMouseEnter={e => { if (!loading) e.currentTarget.style.background = "#fcd34d"; }}
              onMouseLeave={e => { if (!loading) e.currentTarget.style.background = "#fbbf24"; }}
            >
              {loading
                ? <div style={{ width: "14px", height: "14px", border: "2px solid rgba(10,11,13,0.3)", borderTop: "2px solid #0a0b0d", borderRadius: "50%", animation: "spin 0.7s linear infinite" }} />
                : <FaSearch style={{ fontSize: "11px" }} />
              }
              {loading ? "SCANNING" : "ANALYZE"}
            </button>
          </div>

          {/* Live URL tokenizer */}
          {url && <URLTokenizer url={url} />}
        </div>

        {/* ── SIGNAL GRID ── */}
        {!results && (
          <div style={{ marginBottom: "60px", animation: "fadeUp 0.5s ease 0.3s both" }}>
            <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", letterSpacing: "0.3em", color: "rgba(255,255,255,0.15)", marginBottom: "20px" }}>
              {"// ACTIVE_SIGNALS"}
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(240px, 1fr))", gap: "1px", background: "rgba(255,255,255,0.04)" }}>
              {SIGNAL_CHECKS.map((c, i) => (
                <div key={i} style={{
                  background: "#0a0b0d", padding: "20px 24px",
                  transition: "background 0.2s",
                  cursor: "default",
                }}
                  onMouseEnter={e => e.currentTarget.style.background = "rgba(251,191,36,0.03)"}
                  onMouseLeave={e => e.currentTarget.style.background = "#0a0b0d"}
                >
                  <div style={{ fontSize: "20px", marginBottom: "10px", lineHeight: 1 }}>{c.icon}</div>
                  <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", letterSpacing: "0.2em", color: "rgba(251,191,36,0.5)", marginBottom: "6px" }}>{c.label}</div>
                  <div style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: "14px", color: "rgba(200,220,200,0.35)", lineHeight: 1.5 }}>{c.desc}</div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ── RESULTS ── */}
        {results && !results.error && (
          <div style={{ animation: "fadeUp 0.5s ease both" }}>
            <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", letterSpacing: "0.3em", color: "rgba(255,255,255,0.15)", marginBottom: "20px" }}>
              {"// ANALYSIS_COMPLETE"}
            </div>

            {/* Main result card */}
            <div style={{
              background: "rgba(0,0,0,0.5)",
              border: `1px solid ${accent}20`,
              borderTop: `3px solid ${accent}`,
              padding: "36px",
              position: "relative", overflow: "hidden",
              marginBottom: "16px",
            }}>
              {/* Corner accent */}
              <div style={{ position: "absolute", top: 0, right: 0, width: 0, height: 0, borderStyle: "solid", borderWidth: "0 56px 56px 0", borderColor: `transparent ${accent}12 transparent transparent` }} />

              {/* Verdict row */}
              <div style={{ display: "flex", alignItems: "center", gap: "20px", marginBottom: "28px", flexWrap: "wrap" }}>
                <div>
                  {(results.prediction || "").toUpperCase() === "PHISHING" || (results.risk_level || "").toUpperCase() === "HIGH"
                    ? <FaTimesCircle style={{ fontSize: "28px", color: accent, filter: `drop-shadow(0 0 8px ${accent})` }} />
                    : <FaCheckCircle style={{ fontSize: "28px", color: accent, filter: `drop-shadow(0 0 8px ${accent})` }} />
                  }
                </div>
                <div>
                  <div style={{ fontFamily: "'Orbitron', monospace", fontWeight: 900, fontSize: "clamp(22px, 3vw, 36px)", color: accent, letterSpacing: "0.06em", lineHeight: 1 }}>
                    {(results.prediction || "UNKNOWN").toUpperCase()}
                  </div>
                  <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", color: "rgba(255,255,255,0.25)", letterSpacing: "0.15em", marginTop: "4px" }}>
                    {(results.risk_level || "").toUpperCase()} RISK LEVEL
                  </div>
                </div>
              </div>

              {/* Threat meter */}
              <ThreatMeter probability={results.ml_probability || 0} accent={accent} />

              {/* Stat row */}
              <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "1px", background: "rgba(255,255,255,0.04)", marginTop: "28px" }}>
                {[
                  { label: "ML CONFIDENCE", val: `${((results.ml_probability || 0) * 100).toFixed(1)}%` },
                  { label: "RISK LEVEL", val: results.risk_level || "N/A" },
                  { label: "VERDICT", val: results.prediction || "N/A" },
                ].map((item, i) => (
                  <div key={i} style={{ background: "#0a0b0d", padding: "16px 20px" }}>
                    <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "8px", letterSpacing: "0.2em", color: "rgba(255,255,255,0.2)", marginBottom: "6px" }}>{item.label}</div>
                    <div style={{ fontFamily: "'Orbitron', monospace", fontWeight: 700, fontSize: "16px", color: accent }}>{item.val.toUpperCase()}</div>
                  </div>
                ))}
              </div>

              {/* Notes */}
              {results.details && (
                <div style={{ marginTop: "24px", paddingTop: "20px", borderTop: "1px solid rgba(255,255,255,0.05)" }}>
                  <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "8px", letterSpacing: "0.25em", color: "rgba(255,255,255,0.2)", marginBottom: "10px" }}>ANALYST_NOTES</div>
                  <p style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: "15px", color: "rgba(200,220,200,0.5)", lineHeight: 1.8 }}>{results.details}</p>
                </div>
              )}
            </div>

            {/* Scan another */}
            <button
              onClick={() => { setResults(null); setUrl(""); }}
              style={{
                fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", letterSpacing: "0.2em",
                color: "rgba(255,255,255,0.3)", background: "transparent",
                border: "1px solid rgba(255,255,255,0.07)", padding: "10px 20px",
                cursor: "pointer", transition: "all 0.2s",
              }}
              onMouseEnter={e => { e.currentTarget.style.color = "#fbbf24"; e.currentTarget.style.borderColor = "rgba(251,191,36,0.3)"; }}
              onMouseLeave={e => { e.currentTarget.style.color = "rgba(255,255,255,0.3)"; e.currentTarget.style.borderColor = "rgba(255,255,255,0.07)"; }}
            >
              ← SCAN ANOTHER URL
            </button>
          </div>
        )}

        {/* Error */}
        {results?.error && (
          <div style={{
            padding: "20px 24px", background: "rgba(255,107,53,0.06)",
            border: "1px solid rgba(255,107,53,0.2)", borderLeft: "3px solid #ff6b35",
            fontFamily: "'Share Tech Mono', monospace", fontSize: "11px",
            color: "#ff8c66", letterSpacing: "0.08em", lineHeight: 1.6,
            display: "flex", gap: "12px", alignItems: "flex-start",
          }}>
            <FaExclamationTriangle style={{ color: "#ff6b35", flexShrink: 0, marginTop: "2px" }} />
            <span>{results.error}</span>
          </div>
        )}
      </div>
    </div>
  );
}