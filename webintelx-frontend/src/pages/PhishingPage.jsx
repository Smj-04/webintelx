// PhishingPage.jsx — WebIntelX Phishing Detection Module

import React, { useState, useEffect } from "react";
import axios from "axios";
import { FaSearch, FaExclamationTriangle, FaCheckCircle, FaTimesCircle, FaLink, FaExclamationCircle } from "react-icons/fa";

const FONT_URL = "https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;600;700;900&family=Rajdhani:wght@300;400;500;600;700&display=swap";

/* ── URL TOKENIZER ── */
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

/* ── THREAT METER ── */
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

/* ── SCORE BAR ── */
function ScoreBar({ label, value, accent }) {
  const [animated, setAnimated] = useState(0);
  useEffect(() => {
    const t = setTimeout(() => setAnimated(value), 120);
    return () => clearTimeout(t);
  }, [value]);
  return (
    <div style={{ marginBottom: 14 }}>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 5 }}>
        <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", letterSpacing: "0.18em", color: "rgba(255,255,255,0.3)" }}>{label}</span>
        <span style={{ fontFamily: "'Orbitron', monospace", fontSize: "11px", fontWeight: 700, color: accent }}>{Math.round(value)}%</span>
      </div>
      <div style={{ height: 4, background: "rgba(255,255,255,0.05)", borderRadius: 2 }}>
        <div style={{
          height: "100%", borderRadius: 2,
          width: `${animated}%`,
          background: accent,
          boxShadow: `0 0 8px ${accent}60`,
          transition: "width 0.8s cubic-bezier(0.23,1,0.32,1)",
        }} />
      </div>
    </div>
  );
}

/* ── SIGNAL GRID ── */
const SIGNAL_CHECKS = [
  { label: "SSL", desc: "Certificate validity & CN mismatch", icon: "🔒" },
  { label: "DOMAIN AGE", desc: "WHOIS registration recency", icon: "📅" },
  { label: "TYPOSQUAT", desc: "Lookalike brand impersonation", icon: "🎭" },
  { label: "REDIRECTS", desc: "Suspicious forwarding chains", icon: "↪" },
  { label: "JS INJECT", desc: "Keyloggers, iframes, obfuscated scripts", icon: "⚡" },
  { label: "REPUTATION", desc: "Safe Browsing & threat intel feeds", icon: "🛡" },
];

/* ── HELPERS ── */
const riskAccent = (riskLevel, prediction) => {
  const r = (riskLevel || "").toUpperCase();
  const p = (prediction || "").toUpperCase();
  if (r === "CRITICAL" || r === "HIGH" || p === "PHISHING") return "#ff6b35";
  if (r === "MODERATE" || r === "MEDIUM" || r === "SUSPICIOUS") return "#fbbf24";
  return "#00d4a0";
};

/**
 * THREAT PROBABILITY — always the phishing confidence score (0–1).
 *
 * The ML model may predict "legitimate" even when the rule engine overrides
 * to "Potential Phishing Website" (e.g. ebay-v.com: ML=legitimate 0.83,
 * but rules escalate to CRITICAL 78%).
 *
 * Strategy:
 *   - If classification IS phishing → use final_weighted_score / 100
 *     (reflects the full rule+ML decision, not just the raw ML value)
 *   - If classification is LEGITIMATE → use 1 - ml_probability
 *     (model's own phishing estimate for truly clean sites)
 *
 * This ensures ebay-v.com shows 78% threat (from weighted score),
 * not 17% (which was 1 - 0.83, the ML-only legitimate confidence).
 */
const phishingProbability = (results) => {
  if (!results || results.ml_probability == null) return 0;

  const isPhishingClassification =
    results.classification?.toLowerCase().includes("phishing") ||
    ["CRITICAL", "HIGH"].includes((results.risk_level || "").toUpperCase());

  if (isPhishingClassification) {
    // Use weighted score as the primary threat indicator
    const weightedScore = results.scores?.final_weighted_score ?? 0;
    return Math.min(weightedScore / 100, 1);
  }

  // Legitimate site: return the ML's own phishing estimate
  return results.prediction === "phishing"
    ? results.ml_probability
    : 1 - results.ml_probability;
};

/**
 * Build the flag rows to display.
 * Always shows: SSL, BRAND_SIMILARITY, REACHABLE
 * Conditionally adds: FREE_HOSTING, IP_URL, TYPOSQUAT_TARGET
 */
const buildFlagRows = (flags) => {
  if (!flags) return [];

  const rows = [
    {
      label: "SSL_VALID",
      val: flags.ssl_valid ? "✓ VALID" : "✗ INVALID",
      ok: flags.ssl_valid,
    },
    {
      label: "BRAND_SIMILARITY",
      val: `${((flags.brand_similarity ?? 0) * 100).toFixed(0)}%`,
      ok: (flags.brand_similarity ?? 0) < 0.5,
    },
    {
      label: "REACHABLE",
      val: flags.unreachable ? "✗ NO" : "✓ YES",
      ok: !flags.unreachable,
    },
  ];

  // FREE HOSTING — always show if present in response
  if (flags.free_hosting !== undefined) {
    rows.push({
      label: "FREE_HOSTING",
      val: flags.free_hosting ? "✗ YES" : "✓ NO",
      ok: !flags.free_hosting,
    });
  }

  // IP URL
  if (flags.ip_url) {
    rows.push({
      label: "IP_URL",
      val: "✗ DETECTED",
      ok: false,
    });
  }

  // TYPOSQUAT — show brand name if detected
  if (flags.typosquat_target) {
    const score = flags.typosquat_score != null
      ? ` (${(flags.typosquat_score * 100).toFixed(0)}%)`
      : "";
    rows.push({
      label: "TYPOSQUAT",
      val: `✗ ${flags.typosquat_target.toUpperCase()}${score}`,
      ok: false,
      highlight: true,  // extra visual emphasis
    });
  }

  return rows;
};

/* ── MAIN COMPONENT ── */
export default function PhishingDetection() {
  const [url, setUrl]         = useState("");
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

  const threatProb = phishingProbability(results);
  const accent = results && !results.error && !results.message
    ? riskAccent(results.risk_level, results.prediction)
    : "#fbbf24";

  const isPhishing = results?.classification?.toLowerCase().includes("phishing") ||
    ["CRITICAL", "HIGH"].includes((results?.risk_level || "").toUpperCase());

  const flagRows = buildFlagRows(results?.flags);

  // Dynamic grid columns based on how many flags we have
  const flagCols = flagRows.length <= 3
    ? "repeat(3, 1fr)"
    : flagRows.length === 4
    ? "repeat(4, 1fr)"
    : "repeat(3, 1fr)";  // 5-6: wrap to 2 rows of 3

  return (
    <div style={{ backgroundColor: "#0a0b0d", minHeight: "100vh", color: "#f0f4f0" }}>
      <link rel="stylesheet" href={FONT_URL} />
      <style>{`
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.35} }
        @keyframes fadeUp { from{opacity:0;transform:translateY(20px)} to{opacity:1;transform:translateY(0)} }
        @keyframes spin { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }
        * { box-sizing:border-box; margin:0; padding:0; }
        ::selection { background:rgba(251,191,36,0.2); color:#fbbf24; }
        ::-webkit-scrollbar { width:2px; }
        ::-webkit-scrollbar-track { background:#0a0b0d; }
        ::-webkit-scrollbar-thumb { background:#fbbf2440; }
        input::placeholder { color: rgba(251,191,36,0.25); }
      `}</style>

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
          <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", letterSpacing: "0.2em", color: "rgba(251,191,36,0.35)", padding: "4px 10px", border: "1px solid rgba(251,191,36,0.12)" }}>MODULE_03</span>
          <div style={{ width: "6px", height: "6px", borderRadius: "50%", background: loading ? "#fbbf24" : "#00ff88", boxShadow: `0 0 8px ${loading ? "#fbbf24" : "#00ff88"}`, animation: "pulse 2s ease-in-out infinite" }} />
          <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", color: loading ? "#fbbf24" : "rgba(0,255,136,0.5)", letterSpacing: "0.15em" }}>
            {loading ? "SCANNING" : "READY"}
          </span>
        </div>
      </nav>

      <div style={{ position: "relative", zIndex: 2, maxWidth: "860px", margin: "0 auto", padding: "96px 32px 80px" }}>

        {/* PAGE HEADER */}
        <div style={{ marginBottom: "56px", animation: "fadeUp 0.5s ease 0.1s both" }}>
          <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", letterSpacing: "0.35em", color: "rgba(251,191,36,0.4)", marginBottom: "16px" }}>{"// PHISHING_DETECTION"}</div>
          <h1 style={{ fontFamily: "'Orbitron', monospace", fontWeight: 900, fontSize: "clamp(30px, 4.5vw, 54px)", letterSpacing: "0.02em", lineHeight: 1, color: "#f0f4f0", marginBottom: "20px" }}>
            PHISHING<br />
            <span style={{ color: "#fbbf24", textShadow: "0 0 40px rgba(251,191,36,0.3)" }}>DETECTOR</span>
          </h1>
          <p style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: "16px", color: "rgba(200,220,200,0.45)", lineHeight: 1.8, maxWidth: "460px" }}>
            Paste any URL to run a multi-signal threat analysis — domain reputation, SSL anomalies, typosquatting patterns, and ML confidence scoring.
          </p>
        </div>

        {/* INPUT */}
        <div style={{ marginBottom: "48px", animation: "fadeUp 0.5s ease 0.2s both" }}>
          <label style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", letterSpacing: "0.3em", color: "rgba(251,191,36,0.45)", display: "block", marginBottom: "10px" }}>TARGET URL</label>
          <div style={{ display: "flex", gap: "10px" }}>
            <div style={{ flex: 1, position: "relative" }}>
              <FaLink style={{ position: "absolute", left: "14px", top: "50%", transform: "translateY(-50%)", color: "rgba(251,191,36,0.3)", fontSize: "13px", pointerEvents: "none" }} />
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
          {url && <URLTokenizer url={url} />}
        </div>

        {/* SIGNAL GRID — shown only before any result */}
        {!results && (
          <div style={{ marginBottom: "60px", animation: "fadeUp 0.5s ease 0.3s both" }}>
            <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", letterSpacing: "0.3em", color: "rgba(255,255,255,0.15)", marginBottom: "20px" }}>{"// ACTIVE_SIGNALS"}</div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(240px, 1fr))", gap: "1px", background: "rgba(255,255,255,0.04)" }}>
              {SIGNAL_CHECKS.map((c, i) => (
                <div key={i} style={{ background: "#0a0b0d", padding: "20px 24px", transition: "background 0.2s", cursor: "default" }}
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

        {/* ── "message" response — site unreachable / doesn't exist ── */}
        {results && results.message && !results.error && (
          <div style={{ animation: "fadeUp 0.4s ease both" }}>
            <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", letterSpacing: "0.3em", color: "rgba(255,255,255,0.15)", marginBottom: "20px" }}>{"// ANALYSIS_COMPLETE"}</div>
            <div style={{
              padding: "28px 32px",
              background: "rgba(251,191,36,0.04)",
              border: "1px solid rgba(251,191,36,0.15)",
              borderTop: "3px solid #fbbf24",
              display: "flex", alignItems: "flex-start", gap: "16px",
            }}>
              <FaExclamationCircle style={{ color: "#fbbf24", fontSize: "22px", flexShrink: 0, marginTop: "2px" }} />
              <div>
                <div style={{ fontFamily: "'Orbitron', monospace", fontWeight: 700, fontSize: "14px", color: "#fbbf24", letterSpacing: "0.08em", marginBottom: "8px" }}>SITE UNREACHABLE</div>
                <div style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: "15px", color: "rgba(200,220,200,0.55)", lineHeight: 1.7 }}>{results.message}</div>
                <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", color: "rgba(251,191,36,0.35)", marginTop: "10px", letterSpacing: "0.1em" }}>
                  TARGET: {results.url || url}
                </div>
              </div>
            </div>
            <button onClick={() => { setResults(null); setUrl(""); }} style={{ marginTop: "16px", fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", letterSpacing: "0.2em", color: "rgba(255,255,255,0.3)", background: "transparent", border: "1px solid rgba(255,255,255,0.07)", padding: "10px 20px", cursor: "pointer", transition: "all 0.2s" }}
              onMouseEnter={e => { e.currentTarget.style.color = "#fbbf24"; e.currentTarget.style.borderColor = "rgba(251,191,36,0.3)"; }}
              onMouseLeave={e => { e.currentTarget.style.color = "rgba(255,255,255,0.3)"; e.currentTarget.style.borderColor = "rgba(255,255,255,0.07)"; }}
            >← SCAN ANOTHER URL</button>
          </div>
        )}

        {/* ── FULL RESULTS ── */}
        {results && !results.error && !results.message && results.prediction && (
          <div style={{ animation: "fadeUp 0.5s ease both" }}>
            <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", letterSpacing: "0.3em", color: "rgba(255,255,255,0.15)", marginBottom: "20px" }}>{"// ANALYSIS_COMPLETE"}</div>

            {/* Main verdict card */}
            <div style={{
              background: "rgba(0,0,0,0.5)",
              border: `1px solid ${accent}20`,
              borderTop: `3px solid ${accent}`,
              padding: "36px",
              position: "relative", overflow: "hidden",
              marginBottom: "12px",
            }}>
              <div style={{ position: "absolute", top: 0, right: 0, width: 0, height: 0, borderStyle: "solid", borderWidth: "0 56px 56px 0", borderColor: `transparent ${accent}12 transparent transparent` }} />

              {/* Verdict row */}
              <div style={{ display: "flex", alignItems: "center", gap: "20px", marginBottom: "28px", flexWrap: "wrap" }}>
                <div>
                  {isPhishing
                    ? <FaTimesCircle style={{ fontSize: "28px", color: accent, filter: `drop-shadow(0 0 8px ${accent})` }} />
                    : <FaCheckCircle style={{ fontSize: "28px", color: accent, filter: `drop-shadow(0 0 8px ${accent})` }} />
                  }
                </div>
                <div>
                  <div style={{ fontFamily: "'Orbitron', monospace", fontWeight: 900, fontSize: "clamp(18px, 2.5vw, 28px)", color: accent, letterSpacing: "0.06em", lineHeight: 1.1 }}>
                    {results.classification || results.prediction.toUpperCase()}
                  </div>
                  <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", color: "rgba(255,255,255,0.25)", letterSpacing: "0.15em", marginTop: "6px" }}>
                    ML: {results.prediction.toUpperCase()} &nbsp;·&nbsp; RISK: {(results.risk_level || "N/A").toUpperCase()}
                  </div>
                </div>
              </div>

              {/* Threat meter — always shows phishing threat probability */}
              <ThreatMeter probability={threatProb} accent={accent} />

              {/* Stat grid */}
              <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "1px", background: "rgba(255,255,255,0.04)", marginTop: "28px" }}>
                {[
                  { label: "THREAT_PROB", val: `${(threatProb * 100).toFixed(1)}%` },
                  { label: "RISK_LEVEL",  val: results.risk_level || "N/A" },
                  { label: "ML_VERDICT",  val: results.prediction || "N/A" },
                ].map((item, i) => (
                  <div key={i} style={{ background: "#0a0b0d", padding: "16px 20px" }}>
                    <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "8px", letterSpacing: "0.2em", color: "rgba(255,255,255,0.2)", marginBottom: "6px" }}>{item.label}</div>
                    <div style={{ fontFamily: "'Orbitron', monospace", fontWeight: 700, fontSize: "16px", color: accent }}>{item.val.toUpperCase()}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Score breakdown card */}
            {results.scores && (
              <div style={{
                background: "rgba(0,0,0,0.4)", border: `1px solid ${accent}12`,
                padding: "28px 32px", marginBottom: "12px",
              }}>
                <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", letterSpacing: "0.25em", color: "rgba(255,255,255,0.2)", marginBottom: "18px" }}>{"// SCORE_BREAKDOWN"}</div>
                <ScoreBar label="URL_SCORE"      value={results.scores.url_score     ?? 0} accent={accent} />
                <ScoreBar label="DOMAIN_SCORE"   value={results.scores.domain_score  ?? 0} accent={accent} />
                <ScoreBar label="CONTENT_SCORE"  value={results.scores.content_score ?? 0} accent={accent} />
                <ScoreBar label="WEIGHTED_FINAL" value={results.scores.final_weighted_score ?? 0} accent={accent} />
              </div>
            )}

            {/* Flags card — dynamic, shows all available flags */}
            {flagRows.length > 0 && (
              <div style={{
                background: "rgba(0,0,0,0.4)", border: `1px solid ${accent}12`,
                padding: "24px 32px", marginBottom: "12px",
              }}>
                <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", letterSpacing: "0.25em", color: "rgba(255,255,255,0.2)", marginBottom: "18px" }}>{"// THREAT_FLAGS"}</div>
                <div style={{ display: "grid", gridTemplateColumns: flagCols, gap: "1px", background: "rgba(255,255,255,0.04)" }}>
                  {flagRows.map((f, i) => (
                    <div key={i} style={{
                      background: f.highlight ? `${accent}10` : "#0a0b0d",
                      padding: "14px 18px",
                      border: f.highlight ? `1px solid ${accent}30` : "none",
                    }}>
                      <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "8px", letterSpacing: "0.18em", color: "rgba(255,255,255,0.2)", marginBottom: "6px" }}>{f.label}</div>
                      <div style={{ fontFamily: "'Orbitron', monospace", fontWeight: 700, fontSize: "12px", color: f.ok ? "#00d4a0" : accent }}>
                        {f.val}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Analyst notes */}
            {results.details && (
              <div style={{
                background: "rgba(0,0,0,0.4)", border: `1px solid ${accent}12`,
                padding: "24px 32px", marginBottom: "16px",
              }}>
                <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "8px", letterSpacing: "0.25em", color: "rgba(255,255,255,0.2)", marginBottom: "10px" }}>ANALYST_NOTES</div>
                <p style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: "15px", color: "rgba(200,220,200,0.5)", lineHeight: 1.8 }}>{results.details}</p>
              </div>
            )}

            <button onClick={() => { setResults(null); setUrl(""); }} style={{
              fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", letterSpacing: "0.2em",
              color: "rgba(255,255,255,0.3)", background: "transparent",
              border: "1px solid rgba(255,255,255,0.07)", padding: "10px 20px",
              cursor: "pointer", transition: "all 0.2s",
            }}
              onMouseEnter={e => { e.currentTarget.style.color = "#fbbf24"; e.currentTarget.style.borderColor = "rgba(251,191,36,0.3)"; }}
              onMouseLeave={e => { e.currentTarget.style.color = "rgba(255,255,255,0.3)"; e.currentTarget.style.borderColor = "rgba(255,255,255,0.07)"; }}
            >← SCAN ANOTHER URL</button>
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