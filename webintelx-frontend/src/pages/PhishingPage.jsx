// PhishingPage.jsx — WebIntelX Phishing Detection Module

import React, { useState, useEffect } from "react";
import axios from "axios";
import { FaSearch, FaExclamationTriangle, FaCheckCircle, FaTimesCircle, FaLink, FaExclamationCircle } from "react-icons/fa";

const FONT_URL = "https://fonts.googleapis.com/css2?family=DM+Mono:ital,wght@0,300;0,400;0,500;1,400&family=Rajdhani:wght@500;600;700&family=Syne:wght@400;500;600;700;800&family=DM+Sans:ital,opsz,wght@0,9..40,300;0,9..40,400;0,9..40,500;0,9..40,600;1,9..40,400&display=swap";

// ─── DESIGN TOKENS ────────────────────────────────────────────────────────────
const C = {
  bg:            "#F7F8F9",
  white:         "#FFFFFF",
  border:        "#E4E8EC",
  borderDark:    "#CDD4DB",
  text:          "#0F1923",
  textSecondary: "#3A4A58",
  textMuted:     "#6B7C8D",
  textXMuted:    "#9BAAB7",
  accent:        "#D97706",   // amber — phishing module identity
  accentLight:   "#FFFBEB",
  accentBorder:  "#FDE68A",
  accentHover:   "#B45309",
  green:  "#0A6640", greenBg:  "#EAF4EE", greenBorder:  "#A7D7BC",
  amber:  "#92600A", amberBg:  "#FFFBEB", amberBorder:  "#FDE68A",
  orange: "#B54A0C", orangeBg: "#FFF7ED", orangeBorder: "#FED7AA",
  red:    "#C0312B", redBg:    "#FEF2F2", redBorder:    "#FECACA",
  blue:   "#2563AB", blueBg:   "#EFF6FF", blueBorder:   "#BFDBFE",
  purple: "#6D28D9", purpleBg: "#F5F3FF", purpleBorder: "#DDD6FE",
  // navbar
  sidebarBg:     "#0F1923",
  sidebarBorder: "#1E2A36",
  sidebarFaint:  "#3D4E5E",
  sidebarText:   "#E6EDF3",
};

// ─── HELPERS ─────────────────────────────────────────────────────────────────
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
  protocol:  C.textXMuted,
  subdomain: C.amber,
  domain:    C.text,
  tld:       C.textMuted,
  dot:       C.textXMuted,
  port:      C.orange,
  path:      C.blue,
  query:     C.purple,
  plain:     C.text,
};

const riskAccent = (riskLevel, prediction) => {
  const r = (riskLevel || "").toUpperCase();
  const p = (prediction || "").toUpperCase();
  if (r === "CRITICAL" || r === "HIGH" || p === "PHISHING") return C.red;
  if (r === "MODERATE" || r === "MEDIUM" || r === "SUSPICIOUS")  return C.amber;
  return C.green;
};

const riskBg = (a) => {
  if (a === C.red)   return C.redBg;
  if (a === C.amber) return C.amberBg;
  return C.greenBg;
};
const riskBorder = (a) => {
  if (a === C.red)   return C.redBorder;
  if (a === C.amber) return C.amberBorder;
  return C.greenBorder;
};

const phishingProbability = (results) => {
  if (!results || results.ml_probability == null) return 0;
  const isPhishingClassification =
    results.classification?.toLowerCase().includes("phishing") ||
    ["CRITICAL", "HIGH"].includes((results.risk_level || "").toUpperCase());
  if (isPhishingClassification) {
    const weightedScore = results.scores?.final_weighted_score ?? 0;
    return Math.min(weightedScore / 100, 1);
  }
  return results.prediction === "phishing" ? results.ml_probability : 1 - results.ml_probability;
};

const buildFlagRows = (flags) => {
  if (!flags) return [];
  const rows = [
    { label: "SSL_VALID",        val: flags.ssl_valid ? "✓ VALID" : "✗ INVALID",         ok: flags.ssl_valid },
    { label: "BRAND_SIMILARITY", val: `${((flags.brand_similarity ?? 0) * 100).toFixed(0)}%`, ok: (flags.brand_similarity ?? 0) < 0.5 },
    { label: "REACHABLE",        val: flags.unreachable ? "✗ NO" : "✓ YES",               ok: !flags.unreachable },
  ];
  if (flags.free_hosting !== undefined) rows.push({ label: "FREE_HOSTING", val: flags.free_hosting ? "✗ YES" : "✓ NO", ok: !flags.free_hosting });
  if (flags.ip_url)           rows.push({ label: "IP_URL",    val: "✗ DETECTED", ok: false });
  if (flags.typosquat_target) {
    const score = flags.typosquat_score != null ? ` (${(flags.typosquat_score * 100).toFixed(0)}%)` : "";
    rows.push({ label: "TYPOSQUAT", val: `✗ ${flags.typosquat_target.toUpperCase()}${score}`, ok: false, highlight: true });
  }
  return rows;
};

const SIGNAL_CHECKS = [
  { label: "SSL",        desc: "Certificate validity & CN mismatch",         icon: "🔒" },
  { label: "DOMAIN AGE", desc: "WHOIS registration recency",                 icon: "📅" },
  { label: "TYPOSQUAT",  desc: "Lookalike brand impersonation",               icon: "🎭" },
  { label: "REDIRECTS",  desc: "Suspicious forwarding chains",                icon: "↪"  },
  { label: "JS INJECT",  desc: "Keyloggers, iframes, obfuscated scripts",    icon: "⚡" },
  { label: "REPUTATION", desc: "Safe Browsing & threat intel feeds",          icon: "🛡"  },
];

// ─── URL TOKENIZER ────────────────────────────────────────────────────────────
function URLTokenizer({ url }) {
  const tokens = tokenizeURL(url);
  if (!url) return null;
  return (
    <div style={{
      marginTop: "12px", padding: "14px 18px",
      background: C.accentLight,
      border: `1px solid ${C.accentBorder}`,
      borderLeft: `3px solid ${C.accent}`,
      borderRadius: "0 6px 6px 0",
    }}>
      <div style={{ fontFamily: "'DM Mono', monospace", fontSize: "9px", letterSpacing: "0.2em", color: C.textXMuted, marginBottom: "8px" }}>URL_BREAKDOWN</div>
      <div style={{ fontFamily: "'DM Mono', monospace", fontSize: "13px", wordBreak: "break-all", lineHeight: 1.6 }}>
        {tokens.map((t, i) => (
          <span key={i} style={{ color: TOKEN_COLORS[t.type] || C.text }}>{t.text}</span>
        ))}
      </div>
      <div style={{ marginTop: "10px", display: "flex", gap: "14px", flexWrap: "wrap" }}>
        {[
          { type: "protocol",  label: "PROTOCOL"  },
          { type: "subdomain", label: "SUBDOMAIN" },
          { type: "domain",    label: "DOMAIN"    },
          { type: "path",      label: "PATH"      },
          { type: "query",     label: "QUERY"     },
        ].filter(l => tokens.some(t => t.type === l.type)).map((l, i) => (
          <span key={i} style={{ fontFamily: "'DM Mono', monospace", fontSize: "9px", letterSpacing: "0.12em", color: TOKEN_COLORS[l.type], opacity: 0.8 }}>
            ▪ {l.label}
          </span>
        ))}
      </div>
    </div>
  );
}

// ─── THREAT METER ─────────────────────────────────────────────────────────────
function ThreatMeter({ probability, accent }) {
  const [animated, setAnimated] = useState(0);
  useEffect(() => {
    const t = setTimeout(() => setAnimated(probability), 80);
    return () => clearTimeout(t);
  }, [probability]);

  const pct = Math.round(animated * 100);
  const segments = 20;

  return (
    <div style={{ marginTop: "24px" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: "10px" }}>
        <span style={{ fontFamily: "'DM Mono', monospace", fontSize: "10px", letterSpacing: "0.14em", color: C.textMuted }}>THREAT_CONFIDENCE</span>
        <span style={{ fontFamily: "'Rajdhani', sans-serif", fontWeight: 700, fontSize: "32px", color: accent, lineHeight: 1 }}>
          {pct}<span style={{ fontSize: "16px", opacity: 0.6, fontWeight: 500 }}>%</span>
        </span>
      </div>
      <div style={{ display: "flex", gap: "3px", alignItems: "center" }}>
        {Array.from({ length: segments }).map((_, i) => {
          const threshold = (i + 1) / segments;
          const active = animated >= threshold;
          return (
            <div key={i} style={{
              flex: 1, height: "18px",
              background: active ? accent : C.border,
              borderRadius: "1px",
              transition: `background 0.4s ease ${i * 0.03}s`,
            }} />
          );
        })}
      </div>
      <div style={{ display: "flex", justifyContent: "space-between", marginTop: "5px" }}>
        <span style={{ fontFamily: "'DM Mono', monospace", fontSize: "9px", color: C.green, letterSpacing: "0.1em" }}>SAFE</span>
        <span style={{ fontFamily: "'DM Mono', monospace", fontSize: "9px", color: C.red,   letterSpacing: "0.1em" }}>CRITICAL</span>
      </div>
    </div>
  );
}

// ─── SCORE BAR ────────────────────────────────────────────────────────────────
function ScoreBar({ label, value, accent }) {
  const [animated, setAnimated] = useState(0);
  useEffect(() => {
    const t = setTimeout(() => setAnimated(value), 120);
    return () => clearTimeout(t);
  }, [value]);
  return (
    <div style={{ marginBottom: "14px" }}>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "6px" }}>
        <span style={{ fontFamily: "'DM Mono', monospace", fontSize: "11px", color: C.textMuted, letterSpacing: "0.08em" }}>{label}</span>
        <span style={{ fontFamily: "'DM Mono', monospace", fontSize: "12px", fontWeight: 500, color: accent }}>{Math.round(value)}%</span>
      </div>
      <div style={{ height: "5px", background: C.border, borderRadius: "2px", overflow: "hidden" }}>
        <div style={{
          height: "100%", borderRadius: "2px",
          width: `${animated}%`,
          background: accent,
          transition: "width 0.8s cubic-bezier(0.23,1,0.32,1)",
        }} />
      </div>
    </div>
  );
}

// ─── MAIN COMPONENT ───────────────────────────────────────────────────────────
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
    : C.accent;

  const isPhishing = results?.classification?.toLowerCase().includes("phishing") ||
    ["CRITICAL", "HIGH"].includes((results?.risk_level || "").toUpperCase());

  const flagRows = buildFlagRows(results?.flags);
  const flagCols = flagRows.length <= 3 ? "repeat(3,1fr)" : flagRows.length === 4 ? "repeat(4,1fr)" : "repeat(3,1fr)";

  return (
    <div style={{ backgroundColor: C.bg, minHeight: "100vh", color: C.text, fontFamily: "'DM Sans', sans-serif" }}>
      <link rel="stylesheet" href={FONT_URL} />
      <style>{`
        @keyframes pulse   { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:0.35;transform:scale(0.75)} }
        @keyframes fadeUp  { from{opacity:0;transform:translateY(18px)} to{opacity:1;transform:translateY(0)} }
        @keyframes spin    { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }
        * { box-sizing:border-box; margin:0; padding:0; }
        ::selection { background:rgba(217,119,6,0.15); color:${C.accent}; }
        ::-webkit-scrollbar { width:4px; }
        ::-webkit-scrollbar-track { background:${C.bg}; }
        ::-webkit-scrollbar-thumb { background:${C.borderDark}; border-radius:2px; }
        input::placeholder { color:${C.textXMuted}; font-family:'DM Mono',monospace; }
        input:focus { outline:none; }
      `}</style>

      {/* ── NAVBAR (dark, matches system) ── */}
      <nav style={{
        position: "fixed", top: 0, left: 0, right: 0, zIndex: 200,
        display: "flex", alignItems: "center", justifyContent: "space-between",
        padding: "0 48px", height: "56px",
        background: C.sidebarBg, borderBottom: `1px solid ${C.sidebarBorder}`,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: "12px", cursor: "pointer" }} onClick={() => window.location.href = "/"}>
          <svg viewBox="0 0 36 36" width="26" height="26">
            <polygon points="18,2 34,11 34,25 18,34 2,25 2,11" fill="none" stroke={C.accent} strokeWidth="1.5" />
            <polygon points="18,8 28,14 28,22 18,28 8,22 8,14" fill="none" stroke={C.accent} strokeWidth="0.8" opacity="0.45" />
            <circle cx="18" cy="18" r="3" fill={C.accent}>
              <animate attributeName="r" values="3;4.2;3" dur="2.5s" repeatCount="indefinite" />
            </circle>
          </svg>
          <div>
            <div style={{ fontFamily: "'Syne', sans-serif", fontWeight: 800, fontSize: "14px", letterSpacing: "0.06em", color: C.sidebarText }}>WebIntelX</div>
            <div style={{ fontFamily: "'DM Mono', monospace", fontSize: "9px", color: C.sidebarFaint, letterSpacing: "0.12em", marginTop: "1px" }}>Threat Intelligence</div>
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          <span style={{ fontFamily: "'DM Mono', monospace", fontSize: "10px", color: C.sidebarFaint, background: "rgba(255,255,255,0.05)", border: `1px solid ${C.sidebarBorder}`, padding: "4px 12px", borderRadius: "20px" }}>
            phishing_detect · module_04
          </span>
          <div style={{ display: "flex", alignItems: "center", gap: "7px", background: loading ? "rgba(217,119,6,0.12)" : "rgba(255,255,255,0.04)", border: `1px solid ${loading ? C.accentBorder + "60" : C.sidebarBorder}`, padding: "4px 12px", borderRadius: "20px", transition: "all 0.3s" }}>
            <div style={{ width: "7px", height: "7px", borderRadius: "50%", background: loading ? C.accent : C.sidebarFaint, animation: loading ? "pulse 1.4s ease-in-out infinite" : "none", boxShadow: loading ? `0 0 8px ${C.accent}` : "none" }} />
            <span style={{ fontFamily: "'DM Mono', monospace", fontSize: "10px", color: loading ? C.accent : C.sidebarFaint }}>
              {loading ? "Scanning…" : "Ready"}
            </span>
          </div>
        </div>
      </nav>

      {/* ── MAIN CONTENT ── */}
      <div style={{ maxWidth: "860px", margin: "0 auto", padding: "88px 40px 80px" }}>

        {/* ── HEADER ── */}
        <div style={{ marginBottom: "48px", animation: "fadeUp 0.5s ease 0.1s both", maxWidth: "720px" }}>

          {/* Breadcrumb */}
          <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "22px" }}>
            <div style={{ width: "3px", height: "18px", background: C.accent, borderRadius: "1px", flexShrink: 0 }} />
            <span style={{ fontFamily: "'DM Mono', monospace", fontSize: "11px", color: C.accent, letterSpacing: "0.14em" }}>
              // MODULE_04 / PHISHING_DETECTION
            </span>
          </div>

          {/* Big Rajdhani heading */}
          <h1 style={{
            fontFamily: "'Rajdhani', sans-serif",
            fontWeight: 700,
            fontSize: "clamp(52px, 7vw, 88px)",
            color: C.text,
            lineHeight: 0.95,
            letterSpacing: "0.02em",
            textTransform: "uppercase",
            marginBottom: "22px",
          }}>
            PHISHING<br />
            <span style={{ color: C.accent }}>DETECTOR</span>
          </h1>

          <p style={{ fontFamily: "'DM Sans', sans-serif", fontSize: "15px", color: C.textMuted, lineHeight: 1.75, maxWidth: "500px", marginBottom: "24px" }}>
            Paste any URL to run a multi-signal threat analysis — domain reputation, SSL anomalies, typosquatting patterns, and ML confidence scoring.
          </p>
          <div style={{ width: "48px", height: "3px", background: C.accent, borderRadius: "1px" }} />
        </div>

        {/* ── INPUT CARD ── */}
        <div style={{
          background: C.white, border: `1px solid ${C.border}`,
          borderTop: `3px solid ${C.accent}`,
          borderRadius: "0 0 8px 8px",
          padding: "28px 32px", marginBottom: "36px",
          boxShadow: "0 2px 10px rgba(0,0,0,0.05)",
          animation: "fadeUp 0.5s ease 0.2s both",
        }}>
          <div style={{ fontFamily: "'DM Mono', monospace", fontSize: "10px", color: C.textXMuted, letterSpacing: "0.12em", marginBottom: "14px" }}>
            TARGET_INPUT // PASTE_SUSPICIOUS_URL
          </div>
          <div style={{ fontFamily: "'DM Mono', monospace", fontSize: "11px", fontWeight: 600, color: C.text, letterSpacing: "0.06em", marginBottom: "10px", textTransform: "uppercase" }}>
            TARGET URL
          </div>
          <div style={{ display: "flex", gap: "10px", flexWrap: "wrap" }}>
            <div style={{ flex: "1 1 220px", position: "relative" }}>
              <FaLink style={{ position: "absolute", left: "12px", top: "50%", transform: "translateY(-50%)", color: C.textXMuted, fontSize: "12px", pointerEvents: "none" }} />
              <input
                type="text" value={url}
                onChange={e => setUrl(e.target.value)}
                onKeyDown={e => e.key === "Enter" && startScan()}
                placeholder="https://suspicious-site.com/login"
                style={{
                  width: "100%", padding: "11px 14px 11px 36px",
                  background: C.bg, border: `1px solid ${C.border}`,
                  color: C.text, fontFamily: "'DM Mono', monospace", fontSize: "13px",
                  borderRadius: "4px", transition: "border-color 0.15s",
                }}
                onFocus={e => e.target.style.borderColor = C.accent}
                onBlur={e => e.target.style.borderColor = C.border}
              />
            </div>
            <button
              onClick={startScan}
              disabled={loading || !url.trim()}
              style={{
                fontFamily: "'Rajdhani', sans-serif", fontWeight: 700, fontSize: "15px",
                letterSpacing: "0.1em", textTransform: "uppercase",
                color: (loading || !url.trim()) ? C.textXMuted : C.white,
                background: (loading || !url.trim()) ? C.border : C.accent,
                border: "none", padding: "11px 28px", borderRadius: "4px",
                cursor: (loading || !url.trim()) ? "not-allowed" : "pointer",
                display: "flex", alignItems: "center", gap: "9px",
                boxShadow: (loading || !url.trim()) ? "none" : `0 2px 10px ${C.accent}50`,
                transition: "all 0.15s", whiteSpace: "nowrap", flexShrink: 0,
              }}
              onMouseEnter={e => { if (!loading && url.trim()) { e.currentTarget.style.background = C.accentHover; e.currentTarget.style.transform = "translateY(-1px)"; }}}
              onMouseLeave={e => { e.currentTarget.style.background = (loading || !url.trim()) ? C.border : C.accent; e.currentTarget.style.transform = "translateY(0)"; }}
            >
              {loading
                ? <div style={{ width: "13px", height: "13px", border: `2px solid ${C.border}`, borderTop: `2px solid ${C.white}`, borderRadius: "50%", animation: "spin 0.7s linear infinite" }} />
                : <FaSearch style={{ fontSize: "12px" }} />}
              {loading ? "Scanning…" : "Analyze"}
            </button>
          </div>
          {url && <URLTokenizer url={url} />}
        </div>

        {/* ── SIGNAL GRID (pre-scan) ── */}
        {!results && (
          <div style={{ animation: "fadeUp 0.5s ease 0.3s both" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "16px" }}>
              <span style={{ fontFamily: "'DM Mono', monospace", fontSize: "11px", color: C.textXMuted, letterSpacing: "0.08em" }}>// active_signals</span>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(240px, 1fr))", gap: "10px" }}>
              {SIGNAL_CHECKS.map((c, i) => (
                <div key={i} style={{
                  background: C.white, border: `1px solid ${C.border}`,
                  borderLeft: `3px solid ${C.accent}`,
                  borderRadius: "0 6px 6px 0",
                  padding: "18px 20px",
                  boxShadow: "0 1px 3px rgba(0,0,0,0.04)",
                  transition: "box-shadow 0.2s, transform 0.2s",
                }}
                  onMouseEnter={e => { e.currentTarget.style.boxShadow = "0 4px 12px rgba(0,0,0,0.08)"; e.currentTarget.style.transform = "translateY(-1px)"; }}
                  onMouseLeave={e => { e.currentTarget.style.boxShadow = "0 1px 3px rgba(0,0,0,0.04)"; e.currentTarget.style.transform = "translateY(0)"; }}
                >
                  <div style={{ fontSize: "18px", marginBottom: "10px", lineHeight: 1 }}>{c.icon}</div>
                  <div style={{ fontFamily: "'DM Mono', monospace", fontSize: "10px", letterSpacing: "0.14em", color: C.accent, marginBottom: "5px", fontWeight: 500 }}>{c.label}</div>
                  <div style={{ fontFamily: "'DM Sans', sans-serif", fontSize: "13px", color: C.textMuted, lineHeight: 1.5 }}>{c.desc}</div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ── SITE UNREACHABLE MESSAGE ── */}
        {results?.message && !results.error && (
          <div style={{ animation: "fadeUp 0.4s ease both" }}>
            <div style={{ fontFamily: "'DM Mono', monospace", fontSize: "11px", color: C.textXMuted, letterSpacing: "0.08em", marginBottom: "16px" }}>// analysis_complete</div>
            <div style={{
              background: C.white, border: `1px solid ${C.accentBorder}`,
              borderTop: `3px solid ${C.accent}`, borderRadius: "0 0 8px 8px",
              padding: "28px 32px", display: "flex", alignItems: "flex-start", gap: "16px",
              boxShadow: "0 2px 8px rgba(0,0,0,0.05)",
            }}>
              <FaExclamationCircle style={{ color: C.accent, fontSize: "22px", flexShrink: 0, marginTop: "2px" }} />
              <div>
                <div style={{ fontFamily: "'Rajdhani', sans-serif", fontWeight: 700, fontSize: "18px", letterSpacing: "0.06em", textTransform: "uppercase", color: C.accent, marginBottom: "8px" }}>SITE UNREACHABLE</div>
                <div style={{ fontFamily: "'DM Sans', sans-serif", fontSize: "15px", color: C.textMuted, lineHeight: 1.7 }}>{results.message}</div>
                <div style={{ fontFamily: "'DM Mono', monospace", fontSize: "11px", color: C.textXMuted, marginTop: "10px" }}>TARGET: {results.url || url}</div>
              </div>
            </div>
            <button onClick={() => { setResults(null); setUrl(""); }} style={{
              marginTop: "14px", fontFamily: "'DM Mono', monospace", fontSize: "11px", letterSpacing: "0.1em",
              color: C.textMuted, background: C.white, border: `1px solid ${C.border}`,
              padding: "9px 18px", borderRadius: "4px", cursor: "pointer", transition: "all 0.15s",
            }}
              onMouseEnter={e => { e.currentTarget.style.color = C.accent; e.currentTarget.style.borderColor = C.accentBorder; }}
              onMouseLeave={e => { e.currentTarget.style.color = C.textMuted; e.currentTarget.style.borderColor = C.border; }}
            >← Scan Another URL</button>
          </div>
        )}

        {/* ── FULL RESULTS ── */}
        {results && !results.error && !results.message && results.prediction && (
          <div style={{ animation: "fadeUp 0.5s ease both" }}>
            <div style={{ fontFamily: "'DM Mono', monospace", fontSize: "11px", color: C.textXMuted, letterSpacing: "0.08em", marginBottom: "16px" }}>// analysis_complete</div>

            {/* ── VERDICT CARD ── */}
            <div style={{
              background: C.white,
              border: `1px solid ${riskBorder(accent)}`,
              borderTop: `3px solid ${accent}`,
              borderRadius: "0 0 8px 8px",
              padding: "32px",
              marginBottom: "12px",
              boxShadow: "0 2px 10px rgba(0,0,0,0.06)",
              position: "relative", overflow: "hidden",
            }}>
              {/* Corner clip */}
              <div style={{ position: "absolute", top: 0, right: 0, width: 0, height: 0, borderStyle: "solid", borderWidth: "0 48px 48px 0", borderColor: `transparent ${accent}18 transparent transparent` }} />

              {/* Verdict row */}
              <div style={{ display: "flex", alignItems: "center", gap: "16px", marginBottom: "24px", flexWrap: "wrap" }}>
                <div style={{ padding: "10px", background: riskBg(accent), border: `1px solid ${riskBorder(accent)}`, borderRadius: "8px" }}>
                  {isPhishing
                    ? <FaTimesCircle style={{ fontSize: "24px", color: accent }} />
                    : <FaCheckCircle style={{ fontSize: "24px", color: accent }} />}
                </div>
                <div>
                  <div style={{ fontFamily: "'Rajdhani', sans-serif", fontWeight: 700, fontSize: "clamp(20px, 3vw, 30px)", color: accent, letterSpacing: "0.04em", textTransform: "uppercase", lineHeight: 1 }}>
                    {results.classification || results.prediction.toUpperCase()}
                  </div>
                  <div style={{ fontFamily: "'DM Mono', monospace", fontSize: "11px", color: C.textMuted, letterSpacing: "0.08em", marginTop: "5px" }}>
                    ML: {results.prediction.toUpperCase()} &nbsp;·&nbsp; RISK: {(results.risk_level || "N/A").toUpperCase()}
                  </div>
                </div>
              </div>

              {/* Threat meter */}
              <ThreatMeter probability={threatProb} accent={accent} />

              {/* Stat row */}
              <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: "10px", marginTop: "24px" }}>
                {[
                  { label: "THREAT_PROB", val: `${(threatProb * 100).toFixed(1)}%` },
                  { label: "RISK_LEVEL",  val: results.risk_level || "N/A" },
                  { label: "ML_VERDICT",  val: results.prediction || "N/A" },
                ].map((item, i) => (
                  <div key={i} style={{ background: riskBg(accent), border: `1px solid ${riskBorder(accent)}`, borderRadius: "6px", padding: "14px 16px" }}>
                    <div style={{ fontFamily: "'DM Mono', monospace", fontSize: "9px", color: C.textMuted, letterSpacing: "0.14em", marginBottom: "6px" }}>{item.label}</div>
                    <div style={{ fontFamily: "'Rajdhani', sans-serif", fontWeight: 700, fontSize: "18px", color: accent, textTransform: "uppercase" }}>{item.val}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* ── SCORE BREAKDOWN ── */}
            {results.scores && (
              <div style={{
                background: C.white, border: `1px solid ${C.border}`,
                borderLeft: `4px solid ${accent}`, borderRadius: "0 6px 6px 0",
                padding: "24px 28px", marginBottom: "12px",
                boxShadow: "0 1px 4px rgba(0,0,0,0.04)",
              }}>
                <div style={{ fontFamily: "'DM Mono', monospace", fontSize: "10px", letterSpacing: "0.14em", color: C.textMuted, marginBottom: "18px" }}>// score_breakdown</div>
                <ScoreBar label="URL_SCORE"      value={results.scores.url_score      ?? 0} accent={accent} />
                <ScoreBar label="DOMAIN_SCORE"   value={results.scores.domain_score   ?? 0} accent={accent} />
                <ScoreBar label="CONTENT_SCORE"  value={results.scores.content_score  ?? 0} accent={accent} />
                <ScoreBar label="WEIGHTED_FINAL" value={results.scores.final_weighted_score ?? 0} accent={accent} />
              </div>
            )}

            {/* ── THREAT FLAGS ── */}
            {flagRows.length > 0 && (
              <div style={{
                background: C.white, border: `1px solid ${C.border}`,
                borderLeft: `4px solid ${accent}`, borderRadius: "0 6px 6px 0",
                padding: "24px 28px", marginBottom: "12px",
                boxShadow: "0 1px 4px rgba(0,0,0,0.04)",
              }}>
                <div style={{ fontFamily: "'DM Mono', monospace", fontSize: "10px", letterSpacing: "0.14em", color: C.textMuted, marginBottom: "18px" }}>// threat_flags</div>
                <div style={{ display: "grid", gridTemplateColumns: flagCols, gap: "8px" }}>
                  {flagRows.map((f, i) => (
                    <div key={i} style={{
                      background: f.highlight ? riskBg(accent) : C.bg,
                      border: `1px solid ${f.highlight ? riskBorder(accent) : C.border}`,
                      borderRadius: "6px", padding: "12px 16px",
                    }}>
                      <div style={{ fontFamily: "'DM Mono', monospace", fontSize: "9px", letterSpacing: "0.14em", color: C.textMuted, marginBottom: "6px" }}>{f.label}</div>
                      <div style={{ fontFamily: "'DM Mono', monospace", fontSize: "12px", fontWeight: 500, color: f.ok ? C.green : accent }}>{f.val}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* ── ANALYST NOTES ── */}
            {results.details && (
              <div style={{
                background: C.white, border: `1px solid ${C.border}`,
                borderLeft: `4px solid ${C.blue}`, borderRadius: "0 6px 6px 0",
                padding: "20px 28px", marginBottom: "16px",
                boxShadow: "0 1px 4px rgba(0,0,0,0.04)",
              }}>
                <div style={{ fontFamily: "'DM Mono', monospace", fontSize: "10px", letterSpacing: "0.14em", color: C.textMuted, marginBottom: "10px" }}>// analyst_notes</div>
                <p style={{ fontFamily: "'DM Sans', sans-serif", fontSize: "15px", color: C.textSecondary, lineHeight: 1.75 }}>{results.details}</p>
              </div>
            )}

            <button onClick={() => { setResults(null); setUrl(""); }} style={{
              fontFamily: "'DM Mono', monospace", fontSize: "11px", letterSpacing: "0.1em",
              color: C.textMuted, background: C.white, border: `1px solid ${C.border}`,
              padding: "9px 18px", borderRadius: "4px", cursor: "pointer", transition: "all 0.15s",
            }}
              onMouseEnter={e => { e.currentTarget.style.color = C.accent; e.currentTarget.style.borderColor = C.accentBorder; }}
              onMouseLeave={e => { e.currentTarget.style.color = C.textMuted; e.currentTarget.style.borderColor = C.border; }}
            >← Scan Another URL</button>
          </div>
        )}

        {/* ── ERROR ── */}
        {results?.error && (
          <div style={{
            padding: "16px 20px", background: C.redBg,
            border: `1px solid ${C.redBorder}`, borderLeft: `4px solid ${C.red}`,
            borderRadius: "0 6px 6px 0",
            fontFamily: "'DM Mono', monospace", fontSize: "12px", color: C.red,
            display: "flex", gap: "12px", alignItems: "flex-start",
          }}>
            <FaExclamationTriangle style={{ color: C.red, flexShrink: 0, marginTop: "2px" }} />
            <span>{results.error}</span>
          </div>
        )}
      </div>
    </div>
  );
}