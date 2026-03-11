import React, { useState } from "react";
import { useNavigate } from "react-router-dom";

const FONT_URL = "https://fonts.googleapis.com/css2?family=DM+Mono:ital,wght@0,300;0,400;0,500;1,400&family=Rajdhani:wght@500;600;700&family=Syne:wght@400;500;600;700;800&family=DM+Sans:ital,opsz,wght@0,9..40,300;0,9..40,400;0,9..40,500;0,9..40,600;1,9..40,400&display=swap";

const C = {
  bg:            "#F7F8F9",
  white:         "#FFFFFF",
  border:        "#E4E8EC",
  borderDark:    "#CDD4DB",
  text:          "#0F1923",
  textSecondary: "#3A4A58",
  textMuted:     "#6B7C8D",
  textXMuted:    "#9BAAB7",
  accent:        "#6D28D9",
  accentLight:   "#F5F3FF",
  accentBorder:  "#DDD6FE",
  accentHover:   "#5B21B6",
  green:  "#16A34A", greenDim:  "#F0FDF4", greenBorder:  "#BBF7D0",
  orange: "#C2410C", orangeDim: "#FFF7ED", orangeBorder: "#FED7AA",
  purple: "#6D28D9", purpleDim: "#F5F3FF", purpleBorder: "#DDD6FE",
  // navbar
  sidebarBg:     "#0F1923",
  sidebarBorder: "#1E2A36",
  sidebarFaint:  "#3D4E5E",
  sidebarText:   "#E6EDF3",
};

const modes = [
  {
    num: "01",
    title: "QUICK SCAN",
    subtitle: "~2 minutes · Surface checks",
    desc: "Recon + OSINT — High-level security snapshot to identify immediate exposure. Ideal for rapid assessment of subdomains, endpoints, open ports and SSL.",
    accent: C.green, accentDim: C.greenDim, accentBorder: C.greenBorder,
    icon: (
      <svg width="24" height="24" viewBox="0 0 28 28" fill="none">
        <circle cx="14" cy="14" r="12" stroke={C.green} strokeWidth="1.5" />
        <circle cx="14" cy="14" r="7"  stroke={C.green} strokeWidth="1"   opacity="0.4" />
        <circle cx="14" cy="14" r="2.5" fill={C.green} />
        <line x1="14" y1="2"  x2="14" y2="6"  stroke={C.green} strokeWidth="1.5" />
        <line x1="14" y1="22" x2="14" y2="26" stroke={C.green} strokeWidth="1.5" />
        <line x1="2"  y1="14" x2="6"  y2="14" stroke={C.green} strokeWidth="1.5" />
        <line x1="22" y1="14" x2="26" y2="14" stroke={C.green} strokeWidth="1.5" />
      </svg>
    ),
    tags: ["WHOIS", "DNS", "PORTS", "SSL", "OSINT"],
    route: "/quick",
  },
  {
    num: "02",
    title: "FULL SCAN",
    subtitle: "2–15 minutes · Deep coverage",
    desc: "Active Vulnerability Scanning — Complete OSINT, recon and CVE-based assessment. SQLi, XSS, CSRF, command injection and full infrastructure mapping.",
    accent: C.orange, accentDim: C.orangeDim, accentBorder: C.orangeBorder,
    icon: (
      <svg width="24" height="24" viewBox="0 0 28 28" fill="none">
        <path d="M14 2L26 8V16C26 21.5 20.6 26.2 14 28C7.4 26.2 2 21.5 2 16V8L14 2Z" stroke={C.orange} strokeWidth="1.5" fill="none" />
        <path d="M14 8L20 11V16C20 18.8 17.3 21.1 14 22C10.7 21.1 8 18.8 8 16V11L14 8Z" stroke={C.orange} strokeWidth="1" opacity="0.4" fill="none" />
        <circle cx="14" cy="15" r="2.5" fill={C.orange} />
      </svg>
    ),
    tags: ["SQLi", "XSS", "CSRF", "CMD_INJECT", "CLICKJACK", "CVE"],
    route: "/full",
  },
  {
    num: "03",
    title: "CUSTOM SCAN",
    subtitle: "2–10 minutes · Your choice",
    desc: "Modular Assessment — Pick exactly which modules to run. Mix OSINT, infrastructure recon, and vulnerability checks. Full control over scope and depth.",
    accent: C.purple, accentDim: C.purpleDim, accentBorder: C.purpleBorder,
    icon: (
      <svg width="24" height="24" viewBox="0 0 28 28" fill="none">
        <rect x="3"  y="3"  width="9" height="9" stroke={C.purple} strokeWidth="1.5" fill="none"/>
        <rect x="16" y="3"  width="9" height="9" stroke={C.purple} strokeWidth="1.5" fill="none" opacity="0.45"/>
        <rect x="3"  y="16" width="9" height="9" stroke={C.purple} strokeWidth="1.5" fill="none" opacity="0.45"/>
        <rect x="16" y="16" width="9" height="9" stroke={C.purple} strokeWidth="1.5" fill="none"/>
        <line x1="7.5" y1="5.5" x2="7.5" y2="9.5" stroke={C.purple} strokeWidth="1.2"/>
        <line x1="5.5" y1="7.5" x2="9.5" y2="7.5" stroke={C.purple} strokeWidth="1.2"/>
        <line x1="19"  y1="20.5" x2="23"  y2="20.5" stroke={C.purple} strokeWidth="1.2"/>
        <line x1="21"  y1="18.5" x2="21"  y2="22.5" stroke={C.purple} strokeWidth="1.2"/>
      </svg>
    ),
    tags: ["CUSTOM", "OSINT", "VULN", "INFRA", "HOST", "MODULAR"],
    route: "/custom",
  },
];

export default function ScanSelection() {
  const navigate = useNavigate();
  const [hovered, setHovered] = useState(null);

  return (
    <div style={{ backgroundColor: C.bg, minHeight: "100vh", color: C.text, fontFamily: "'DM Sans', sans-serif" }}>
      <link rel="stylesheet" href={FONT_URL} />
      <style>{`
        @keyframes fadeUp { from{opacity:0;transform:translateY(18px)} to{opacity:1;transform:translateY(0)} }
        @keyframes pulse  { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:0.3;transform:scale(0.75)} }
        * { box-sizing:border-box; margin:0; padding:0; }
        ::selection { background:rgba(109,40,217,0.15); color:${C.accent}; }
        ::-webkit-scrollbar { width:4px; }
        ::-webkit-scrollbar-track { background:${C.bg}; }
        ::-webkit-scrollbar-thumb { background:${C.borderDark}; border-radius:2px; }
      `}</style>

      {/* ── NAVBAR (dark, matches CustomScan) ── */}
      <nav style={{
        position: "fixed", top: 0, left: 0, right: 0, zIndex: 200,
        display: "flex", alignItems: "center", justifyContent: "space-between",
        padding: "0 48px", height: "56px",
        background: C.sidebarBg,
        borderBottom: `1px solid ${C.sidebarBorder}`,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: "12px", cursor: "pointer" }} onClick={() => navigate("/")}>
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
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <div style={{ width: "7px", height: "7px", background: C.accent, borderRadius: "50%", boxShadow: `0 0 8px ${C.accent}`, animation: "pulse 2s ease-in-out infinite" }} />
          <span style={{ fontFamily: "'DM Mono', monospace", fontSize: "10px", color: C.sidebarFaint, letterSpacing: "0.12em" }}>SCANNER_IDLE</span>
        </div>
      </nav>

      {/* ── MAIN CONTENT ── */}
      <div style={{ maxWidth: "1160px", margin: "0 auto", padding: "96px 40px 80px" }}>

        {/* Header */}
        <div style={{ marginBottom: "52px", animation: "fadeUp 0.5s ease 0.1s both" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "20px" }}>
            <div style={{ width: "3px", height: "18px", background: C.accent, borderRadius: "1px", flexShrink: 0 }} />
            <span style={{ fontFamily: "'DM Mono', monospace", fontSize: "11px", color: C.accent, letterSpacing: "0.14em" }}>
              // SELECT_SCAN_MODE
            </span>
          </div>
          <h1 style={{
            fontFamily: "'Rajdhani', sans-serif",
            fontWeight: 700,
            fontSize: "clamp(48px, 6vw, 80px)",
            color: C.text,
            lineHeight: 0.95,
            letterSpacing: "0.02em",
            textTransform: "uppercase",
            marginBottom: "20px",
          }}>
            CHOOSE YOUR<br />
            <span style={{ color: C.accent }}>SCAN MODE</span>
          </h1>
          <p style={{ fontFamily: "'DM Sans', sans-serif", fontSize: "16px", color: C.textMuted, lineHeight: 1.75, maxWidth: "500px", marginBottom: "22px" }}>
            Select how deep you want WebIntelX to probe your target surface. Each mode is tuned for a different threat posture.
          </p>
          <div style={{ width: "48px", height: "3px", background: C.accent, borderRadius: "1px" }} />
        </div>

        {/* ── CARDS ── */}
        <div style={{ display: "flex", gap: "20px", flexWrap: "wrap", animation: "fadeUp 0.5s ease 0.25s both" }}>
          {modes.map((mode, i) => (
            <div
              key={i}
              onClick={() => navigate(mode.route)}
              onMouseEnter={() => setHovered(i)}
              onMouseLeave={() => setHovered(null)}
              style={{
                flex: "1 1 300px",
                background: hovered === i ? mode.accentDim : C.white,
                border: `1px solid ${hovered === i ? mode.accentBorder : C.border}`,
                borderTop: `3px solid ${mode.accent}`,
                borderRadius: "0 0 8px 8px",
                padding: "32px 28px",
                cursor: "pointer",
                position: "relative",
                overflow: "hidden",
                transition: "all 0.22s cubic-bezier(0.23,1,0.32,1)",
                transform: hovered === i ? "translateY(-5px)" : "translateY(0)",
                boxShadow: hovered === i
                  ? `0 16px 40px rgba(0,0,0,0.1), 0 0 0 1px ${mode.accentBorder}`
                  : "0 1px 4px rgba(0,0,0,0.05)",
              }}
            >
              {/* Icon + number row */}
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "20px" }}>
                <div style={{
                  padding: "10px",
                  background: mode.accentDim,
                  border: `1px solid ${mode.accentBorder}`,
                  borderRadius: "6px",
                }}>
                  {mode.icon}
                </div>
                <span style={{ fontFamily: "'DM Mono', monospace", fontSize: "11px", color: mode.accent, opacity: 0.5, letterSpacing: "0.2em" }}>[{mode.num}]</span>
              </div>

              {/* Mode label */}
              <div style={{ fontFamily: "'DM Mono', monospace", fontSize: "9px", color: mode.accent, letterSpacing: "0.22em", textTransform: "uppercase", marginBottom: "8px", opacity: 0.7 }}>
                MODE_{mode.num} //
              </div>

              {/* Title */}
              <h2 style={{ fontFamily: "'Rajdhani', sans-serif", fontWeight: 700, fontSize: "22px", color: C.text, letterSpacing: "0.05em", textTransform: "uppercase", marginBottom: "10px" }}>
                {mode.title}
              </h2>

              {/* Subtitle pill */}
              <div style={{
                display: "inline-block",
                fontFamily: "'DM Mono', monospace", fontSize: "10px",
                color: mode.accent,
                background: mode.accentDim,
                border: `1px solid ${mode.accentBorder}`,
                padding: "4px 12px", borderRadius: "20px",
                letterSpacing: "0.08em", marginBottom: "16px",
              }}>
                {mode.subtitle}
              </div>

              {/* Description */}
              <p style={{ fontFamily: "'DM Sans', sans-serif", fontSize: "14px", color: C.textMuted, lineHeight: 1.75, marginBottom: "22px" }}>
                {mode.desc}
              </p>

              {/* Tags */}
              <div style={{ display: "flex", flexWrap: "wrap", gap: "6px", marginBottom: "22px" }}>
                {mode.tags.map((tag, ti) => (
                  <span key={ti} style={{
                    fontFamily: "'DM Mono', monospace", fontSize: "9px",
                    letterSpacing: "0.1em", color: mode.accent,
                    background: mode.accentDim, border: `1px solid ${mode.accentBorder}`,
                    padding: "3px 10px", borderRadius: "3px",
                  }}>
                    {tag}
                  </span>
                ))}
              </div>

              {/* CTA row */}
              <div style={{ display: "flex", alignItems: "center", gap: "8px", paddingTop: "14px", borderTop: `1px solid ${C.border}` }}>
                <div style={{
                  width: "6px", height: "6px", background: mode.accent, borderRadius: "50%",
                  boxShadow: `0 0 6px ${mode.accent}`,
                  animation: hovered === i ? "none" : "pulse 2s ease-in-out infinite",
                  flexShrink: 0,
                }} />
                <span style={{ fontFamily: "'DM Mono', monospace", fontSize: "11px", color: mode.accent, letterSpacing: "0.1em" }}>
                  {hovered === i ? "LAUNCH →" : "STANDBY"}
                </span>
              </div>
            </div>
          ))}
        </div>

        {/* ── BOTTOM INFO STRIP ── */}
        <div style={{
          marginTop: "52px",
          padding: "18px 28px",
          background: C.white,
          border: `1px solid ${C.border}`,
          borderLeft: `3px solid ${C.accent}`,
          borderRadius: "0 6px 6px 0",
          display: "flex", alignItems: "center", gap: "14px",
          animation: "fadeUp 0.5s ease 0.4s both",
          boxShadow: "0 1px 4px rgba(0,0,0,0.04)",
        }}>
          <div style={{ width: "6px", height: "6px", background: C.accent, borderRadius: "50%", boxShadow: `0 0 6px ${C.accent}`, animation: "pulse 2s ease-in-out infinite", flexShrink: 0 }} />
          <p style={{ fontFamily: "'DM Mono', monospace", fontSize: "11px", color: C.textMuted, letterSpacing: "0.07em", lineHeight: 1.6 }}>
            All scans run through encrypted channels. Results are never stored beyond your session. For authorized testing only.
          </p>
        </div>
      </div>
    </div>
  );
}