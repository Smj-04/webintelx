import React, { useState } from "react";
import { useNavigate } from "react-router-dom";

const FONT_URL = "https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;600;700;900&family=Rajdhani:wght@300;400;500;600;700&display=swap";

function HexGrid() {
  const hexes = [];
  for (let r = 0; r < 8; r++) {
    for (let c = 0; c < 16; c++) {
      const w = 52, h = 46;
      const x = c * w * 0.75 + (r % 2 === 0 ? 0 : w * 0.375);
      const y = r * h * 0.87;
      hexes.push({ x, y, key: `${r}-${c}`, d: (r + c) * 0.08 });
    }
  }
  const hexPath = (x, y, s = 22) =>
    Array.from({ length: 6 }, (_, i) => {
      const a = (Math.PI / 180) * (60 * i - 30);
      return `${x + s * Math.cos(a)},${y + s * Math.sin(a)}`;
    }).join(" ");
  return (
    <svg style={{ position: "fixed", inset: 0, width: "100%", height: "100%", opacity: 0.04, pointerEvents: "none", zIndex: 0 }} viewBox="0 0 1300 500" preserveAspectRatio="xMidYMid slice">
      {hexes.map(h => (
        <polygon key={h.key} points={hexPath(h.x + 26, h.y + 26)} fill="none" stroke="#00ff88" strokeWidth="0.6">
          <animate attributeName="opacity" values="0.3;1;0.3" dur={`${4 + (h.d % 3)}s`} begin={`${h.d % 2}s`} repeatCount="indefinite" />
        </polygon>
      ))}
    </svg>
  );
}

function ScanLines() {
  return (
    <div style={{
      position: "fixed", inset: 0, pointerEvents: "none", zIndex: 1,
      background: "repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,255,136,0.012) 2px, rgba(0,255,136,0.012) 4px)"
    }} />
  );
}

const modes = [
  {
    num: "01",
    title: "QUICK SCAN",
    subtitle: "~2 minutes • Surface checks",
    desc: "Recon + OSINT — High-level security snapshot to identify immediate exposure. Ideal for rapid assessment of subdomains, endpoints, open ports and SSL.",
    accent: "#00ff88",
    icon: (
      <svg width="28" height="28" viewBox="0 0 28 28" fill="none">
        <circle cx="14" cy="14" r="12" stroke="#00ff88" strokeWidth="1.5" />
        <circle cx="14" cy="14" r="7" stroke="#00ff88" strokeWidth="1" opacity="0.5" />
        <circle cx="14" cy="14" r="2.5" fill="#00ff88" />
        <line x1="14" y1="2" x2="14" y2="6" stroke="#00ff88" strokeWidth="1.5" />
        <line x1="14" y1="22" x2="14" y2="26" stroke="#00ff88" strokeWidth="1.5" />
        <line x1="2" y1="14" x2="6" y2="14" stroke="#00ff88" strokeWidth="1.5" />
        <line x1="22" y1="14" x2="26" y2="14" stroke="#00ff88" strokeWidth="1.5" />
      </svg>
    ),
    tags: ["WHOIS", "DNS", "PORTS", "SSL", "OSINT"],
    route: "/quick",
  },
  {
    num: "02",
    title: "FULL SCAN",
    subtitle: "2–15 minutes • Deep coverage",
    desc: "Active Vulnerability Scanning — Complete OSINT, recon and CVE-based assessment. SQLi, XSS, CSRF, command injection and full infrastructure mapping.",
    accent: "#ff6b35",
    icon: (
      <svg width="28" height="28" viewBox="0 0 28 28" fill="none">
        <path d="M14 2L26 8V16C26 21.5 20.6 26.2 14 28C7.4 26.2 2 21.5 2 16V8L14 2Z" stroke="#ff6b35" strokeWidth="1.5" fill="none" />
        <path d="M14 8L20 11V16C20 18.8 17.3 21.1 14 22C10.7 21.1 8 18.8 8 16V11L14 8Z" stroke="#ff6b35" strokeWidth="1" opacity="0.5" fill="none" />
        <circle cx="14" cy="15" r="2.5" fill="#ff6b35" />
      </svg>
    ),
    tags: ["SQLi", "XSS", "CSRF", "CMD_INJECT", "CLICKJACK", "CVE"],
    route: "/full",
  },
];

export default function ScanSelection() {
  const navigate = useNavigate();
  const [hovered, setHovered] = useState(null);

  return (
    <div style={{ backgroundColor: "#020804", minHeight: "100vh", color: "#e8ffe8", overflowX: "hidden", cursor: "crosshair", fontFamily: "'Rajdhani', sans-serif" }}>
      <link rel="stylesheet" href={FONT_URL} />
      <style>{`
        @keyframes pulse { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:0.3;transform:scale(0.75)} }
        @keyframes fadeUp { from{opacity:0;transform:translateY(24px)} to{opacity:1;transform:translateY(0)} }
        @keyframes scanDown { 0%{top:0%} 100%{top:100%} }
        @keyframes flicker { 0%,89%,91%,96%,100%{opacity:1} 90%{opacity:0.5} 95%{opacity:0.75} }
        * { box-sizing:border-box; margin:0; padding:0; }
        ::selection { background:rgba(0,255,136,0.2); color:#00ff88; }
        ::-webkit-scrollbar { width:3px; }
        ::-webkit-scrollbar-track { background:#010502; }
        ::-webkit-scrollbar-thumb { background:#00ff8855; }
      `}</style>

      <HexGrid />
      <ScanLines />

      {/* NAVBAR */}
      <nav style={{
        position: "fixed", top: 0, left: 0, right: 0, zIndex: 200,
        display: "flex", alignItems: "center", justifyContent: "space-between",
        padding: "0 48px", height: "64px",
        background: "rgba(2,8,4,0.92)", borderBottom: "1px solid rgba(0,255,136,0.09)",
        backdropFilter: "blur(16px)", animation: "flicker 10s ease-in-out infinite",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: "12px", cursor: "pointer" }} onClick={() => navigate("/")}>
          <svg viewBox="0 0 36 36" width="32" height="32">
            <polygon points="18,2 34,11 34,25 18,34 2,25 2,11" fill="none" stroke="#00ff88" strokeWidth="1.5" />
            <polygon points="18,8 28,14 28,22 18,28 8,22 8,14" fill="none" stroke="#00ff88" strokeWidth="0.8" opacity="0.45" />
            <circle cx="18" cy="18" r="3" fill="#00ff88">
              <animate attributeName="r" values="3;4.2;3" dur="2.5s" repeatCount="indefinite" />
            </circle>
          </svg>
          <div>
            <div style={{ fontFamily: "'Orbitron', monospace", fontWeight: 900, fontSize: "14px", letterSpacing: "0.14em", color: "#00ff88" }}>WEBINTELX</div>
            <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "8px", color: "rgba(0,255,136,0.35)", letterSpacing: "0.2em", marginTop: "2px" }}>THREAT INTELLIGENCE SYS</div>
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <div style={{ width: "7px", height: "7px", background: "#00ff88", borderRadius: "50%", boxShadow: "0 0 10px #00ff88", animation: "pulse 2s ease-in-out infinite" }} />
          <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", color: "#00ff88", letterSpacing: "0.15em" }}>SCANNER_IDLE</span>
        </div>
      </nav>

      {/* MAIN CONTENT */}
      <div style={{ position: "relative", zIndex: 2, maxWidth: "1100px", margin: "0 auto", padding: "120px 40px 80px" }}>

        {/* Header */}
        <div style={{ marginBottom: "60px", animation: "fadeUp 0.6s ease 0.1s both" }}>
          <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", letterSpacing: "0.35em", color: "rgba(0,255,136,0.4)", marginBottom: "16px" }}>
            // SELECT_SCAN_MODE
          </div>
          <h1 style={{ fontFamily: "'Orbitron', monospace", fontWeight: 900, fontSize: "clamp(28px, 4vw, 48px)", color: "#e8ffe8", letterSpacing: "0.04em", lineHeight: 1.1, marginBottom: "16px" }}>
            CHOOSE YOUR<br /><span style={{ color: "#00ff88" }}>SCAN MODE</span>
          </h1>
          <p style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: "17px", color: "rgba(180,255,180,0.5)", lineHeight: 1.7, maxWidth: "520px" }}>
            Select how deep you want WebIntelX to probe your target surface. Each mode is tuned for a different threat posture.
          </p>
          <div style={{ width: "48px", height: "2px", background: "#00ff88", marginTop: "20px", boxShadow: "0 0 10px rgba(0,255,136,0.5)" }} />
        </div>

        {/* Cards */}
        <div style={{ display: "flex", gap: "24px", flexWrap: "wrap", animation: "fadeUp 0.6s ease 0.25s both" }}>
          {modes.map((mode, i) => (
            <div
              key={i}
              onClick={() => navigate(mode.route)}
              onMouseEnter={() => setHovered(i)}
              onMouseLeave={() => setHovered(null)}
              style={{
                flex: "1 1 380px",
                border: `1px solid ${hovered === i ? mode.accent : "rgba(0,255,136,0.1)"}`,
                borderLeft: `3px solid ${mode.accent}`,
                background: hovered === i ? "rgba(0,0,0,0.95)" : "rgba(0,0,0,0.55)",
                padding: "40px 36px",
                cursor: "pointer",
                position: "relative",
                overflow: "hidden",
                transition: "all 0.3s cubic-bezier(0.23,1,0.32,1)",
                transform: hovered === i ? "translateY(-6px)" : "translateY(0)",
                boxShadow: hovered === i ? `0 24px 60px ${mode.accent}12, 0 0 30px ${mode.accent}08` : "none",
              }}
            >
              {/* Corner clip */}
              <div style={{ position: "absolute", top: 0, right: 0, width: 0, height: 0, borderStyle: "solid", borderWidth: "0 36px 36px 0", borderColor: `transparent ${mode.accent}20 transparent transparent` }} />

              {/* Scan line on hover */}
              {hovered === i && (
                <div style={{ position: "absolute", left: 0, right: 0, height: "1px", background: `linear-gradient(90deg, transparent, ${mode.accent}, transparent)`, animation: "scanDown 1.2s linear infinite", top: 0 }} />
              )}

              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "24px" }}>
                <div style={{ filter: `drop-shadow(0 0 8px ${mode.accent})` }}>{mode.icon}</div>
                <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "11px", color: mode.accent, opacity: 0.45, letterSpacing: "0.2em" }}>[{mode.num}]</span>
              </div>

              <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", color: mode.accent, letterSpacing: "0.25em", textTransform: "uppercase", marginBottom: "10px", opacity: 0.6 }}>
                MODE_{mode.num} //
              </div>

              <h2 style={{ fontFamily: "'Orbitron', monospace", fontWeight: 700, fontSize: "20px", color: "#e8ffe8", letterSpacing: "0.06em", marginBottom: "8px" }}>
                {mode.title}
              </h2>

              <div style={{ display: "inline-block", fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", color: mode.accent, background: `${mode.accent}12`, border: `1px solid ${mode.accent}30`, padding: "4px 12px", letterSpacing: "0.1em", marginBottom: "20px" }}>
                {mode.subtitle}
              </div>

              <p style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: "15px", color: "rgba(180,255,180,0.5)", lineHeight: 1.75, marginBottom: "28px" }}>
                {mode.desc}
              </p>

              {/* Tags */}
              <div style={{ display: "flex", flexWrap: "wrap", gap: "8px", marginBottom: "28px" }}>
                {mode.tags.map((tag, ti) => (
                  <span key={ti} style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", letterSpacing: "0.15em", color: mode.accent, background: `${mode.accent}0a`, border: `1px solid ${mode.accent}25`, padding: "3px 10px" }}>
                    {tag}
                  </span>
                ))}
              </div>

              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <div style={{ width: "6px", height: "6px", background: mode.accent, borderRadius: "50%", boxShadow: `0 0 8px ${mode.accent}`, animation: hovered === i ? "none" : "pulse 2s ease-in-out infinite" }} />
                <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "11px", color: mode.accent, letterSpacing: "0.1em" }}>
                  {hovered === i ? "READY TO LAUNCH →" : "STANDBY"}
                </span>
              </div>
            </div>
          ))}
        </div>

        {/* Bottom info strip */}
        <div style={{ marginTop: "60px", padding: "24px 28px", background: "rgba(0,0,0,0.4)", border: "1px solid rgba(0,255,136,0.07)", display: "flex", alignItems: "center", gap: "16px", animation: "fadeUp 0.6s ease 0.4s both" }}>
          <div style={{ width: "7px", height: "7px", background: "#00ff88", borderRadius: "50%", boxShadow: "0 0 10px #00ff88", animation: "pulse 2s ease-in-out infinite", flexShrink: 0 }} />
          <p style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "11px", color: "rgba(0,255,136,0.4)", letterSpacing: "0.1em", lineHeight: 1.6 }}>
            All scans run through encrypted channels. Results are never stored beyond your session. For authorized testing only.
          </p>
        </div>
      </div>
    </div>
  );
}