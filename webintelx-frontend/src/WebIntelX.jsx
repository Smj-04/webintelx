import { useState, useEffect, useRef } from "react";

const FONT_URL = "https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;600;700;900&family=Rajdhani:wght@300;400;500;600;700&display=swap";

function RadarSweep() {
  return (
    <svg width="500" height="500" viewBox="0 0 320 320" style={{ position: "absolute", top: "50%", left: "50%", transform: "translate(-50%,-50%)", opacity: 0.18, pointerEvents: "none" }}>
      <defs>
        <radialGradient id="radarGlow" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor="#00ff88" stopOpacity="0.3" />
          <stop offset="100%" stopColor="#00ff88" stopOpacity="0" />
        </radialGradient>
        <filter id="glow">
          <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
          <feMerge><feMergeNode in="coloredBlur"/><feMergeNode in="SourceGraphic"/></feMerge>
        </filter>
      </defs>
      {[40, 80, 120, 160].map(r => (
        <circle key={r} cx="160" cy="160" r={r} fill="none" stroke="#00ff88" strokeWidth="0.5" opacity="0.4" />
      ))}
      <line x1="160" y1="0" x2="160" y2="320" stroke="#00ff88" strokeWidth="0.5" opacity="0.3" />
      <line x1="0" y1="160" x2="320" y2="160" stroke="#00ff88" strokeWidth="0.5" opacity="0.3" />
      <line x1="47" y1="47" x2="273" y2="273" stroke="#00ff88" strokeWidth="0.5" opacity="0.2" />
      <line x1="273" y1="47" x2="47" y2="273" stroke="#00ff88" strokeWidth="0.5" opacity="0.2" />
      <g filter="url(#glow)" style={{ transformOrigin: "160px 160px", animation: "radarSpin 4s linear infinite" }}>
        <path d="M160,160 L160,0 A160,160 0 0,1 320,160 Z" fill="url(#radarGlow)" opacity="0.6" />
        <line x1="160" y1="160" x2="160" y2="0" stroke="#00ff88" strokeWidth="1.5" />
      </g>
      {[[110,90],[200,130],[145,200],[220,80],[80,170]].map(([cx,cy],i) => (
        <circle key={i} cx={cx} cy={cy} r="3" fill="#00ff88" opacity="0.7">
          <animate attributeName="opacity" values="0.7;0.1;0.7" dur={`${2+i*0.7}s`} repeatCount="indefinite" />
        </circle>
      ))}
    </svg>
  );
}

function HexGrid() {
  const hexes = [];
  const cols = 18, rows = 10;
  const w = 52, h = 46;
  for (let r = 0; r < rows; r++) {
    for (let c = 0; c < cols; c++) {
      const x = c * w * 0.75 + (r % 2 === 0 ? 0 : w * 0.375);
      const y = r * h * 0.87;
      hexes.push({ x, y, key: `${r}-${c}`, delay: (r + c) * 0.08 });
    }
  }
  const hexPath = (x, y, s = 22) => {
    const pts = Array.from({ length: 6 }, (_, i) => {
      const a = (Math.PI / 180) * (60 * i - 30);
      return `${x + s * Math.cos(a)},${y + s * Math.sin(a)}`;
    });
    return pts.join(" ");
  };
  return (
    <svg style={{ position: "fixed", inset: 0, width: "100%", height: "100%", opacity: 0.045, pointerEvents: "none", zIndex: 0 }} viewBox="0 0 1300 500" preserveAspectRatio="xMidYMid slice">
      {hexes.map(h => (
        <polygon key={h.key} points={hexPath(h.x + 26, h.y + 26)} fill="none" stroke="#00ff88" strokeWidth="0.6">
          <animate attributeName="opacity" values="0.3;1;0.3" dur={`${4 + (h.delay % 3)}s`} begin={`${h.delay % 2}s`} repeatCount="indefinite" />
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

function Typewriter({ text, delay = 0, speed = 38 }) {
  const [displayed, setDisplayed] = useState("");
  const [started, setStarted] = useState(false);
  useEffect(() => {
    const t = setTimeout(() => setStarted(true), delay);
    return () => clearTimeout(t);
  }, [delay]);
  useEffect(() => {
    if (!started || displayed.length >= text.length) return;
    const t = setTimeout(() => setDisplayed(text.slice(0, displayed.length + 1)), speed);
    return () => clearTimeout(t);
  }, [started, displayed, text, speed]);
  return (
    <span>
      {displayed}
      {displayed.length < text.length && (
        <span style={{ animation: "blink 0.7s step-end infinite", color: "#00ff88" }}>█</span>
      )}
    </span>
  );
}


function ModuleCard({ num, title, desc, accent, icon, onClick }) {
  const [hovered, setHovered] = useState(false);
  return (
    <div
      onClick={onClick}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        flex: "1 1 300px",
        border: `1px solid ${hovered ? accent : "rgba(0,255,136,0.1)"}`,
        borderLeft: `3px solid ${accent}`,
        background: hovered ? `rgba(0,0,0,0.95)` : "rgba(0,0,0,0.55)",
        padding: "32px 28px",
        cursor: "pointer",
        position: "relative",
        overflow: "hidden",
        transition: "all 0.3s cubic-bezier(0.23,1,0.32,1)",
        transform: hovered ? "translateY(-6px)" : "translateY(0)",
        boxShadow: hovered ? `0 20px 60px ${accent}15, 0 0 30px ${accent}08` : "none",
      }}
    >
      <div style={{
        position: "absolute", top: 0, right: 0, width: "0", height: "0",
        borderStyle: "solid", borderWidth: "0 32px 32px 0",
        borderColor: `transparent ${accent}25 transparent transparent`,
      }} />
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "20px" }}>
        <div style={{ fontSize: "30px", lineHeight: 1, filter: `drop-shadow(0 0 8px ${accent})` }}>{icon}</div>
        <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "11px", color: accent, opacity: 0.5, letterSpacing: "0.2em" }}>[{num}]</span>
      </div>
      <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", color: accent, letterSpacing: "0.25em", textTransform: "uppercase", marginBottom: "10px", opacity: 0.6 }}>
        {`MODULE_${num} //`}
      </div>
      <h3 style={{ fontFamily: "'Orbitron', monospace", fontWeight: 700, fontSize: "14px", color: "#e8ffe8", marginBottom: "14px", letterSpacing: "0.05em", lineHeight: 1.4 }}>
        {title}
      </h3>
      <p style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: "15px", color: "rgba(180,255,180,0.45)", lineHeight: 1.7, marginBottom: "24px" }}>
        {desc}
      </p>
      <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
        <div style={{
          width: "6px", height: "6px", background: accent, borderRadius: "50%",
          boxShadow: `0 0 8px ${accent}`,
          animation: hovered ? "none" : "pulse 2s ease-in-out infinite"
        }} />
        <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "11px", color: accent, letterSpacing: "0.1em" }}>
          {hovered ? "INITIALIZING..." : "STANDBY"}
        </span>
      </div>
      {hovered && (
        <div style={{
          position: "absolute", left: 0, right: 0, height: "1px",
          background: `linear-gradient(90deg, transparent, ${accent}, transparent)`,
          animation: "scanDown 1.2s linear infinite", top: 0,
        }} />
      )}
    </div>
  );
}

function FeatureRow({ index, label, title, desc, accent }) {
  const [vis, setVis] = useState(false);
  const ref = useRef(null);
  useEffect(() => {
    const obs = new IntersectionObserver(([e]) => {
      if (e.isIntersecting) { setVis(true); obs.disconnect(); }
    }, { threshold: 0.2 });
    if (ref.current) obs.observe(ref.current);
    return () => obs.disconnect();
  }, []);
  return (
    <div ref={ref} style={{
      display: "grid", gridTemplateColumns: "64px 1fr",
      borderTop: "1px solid rgba(0,255,136,0.07)",
      padding: "36px 0",
      opacity: vis ? 1 : 0,
      transform: vis ? "translateX(0)" : "translateX(-24px)",
      transition: `opacity 0.6s ease ${index * 0.12}s, transform 0.6s ease ${index * 0.12}s`,
    }}>
      <div style={{ display: "flex", flexDirection: "column", alignItems: "center", paddingTop: "4px", gap: "12px" }}>
        <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "11px", color: accent, opacity: 0.5 }}>{String(index + 1).padStart(2, "0")}</span>
        <div style={{ width: "1px", flex: 1, background: `linear-gradient(to bottom, ${accent}40, transparent)` }} />
      </div>
      <div style={{ paddingLeft: "28px" }}>
        <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", color: accent, letterSpacing: "0.3em", textTransform: "uppercase", opacity: 0.6, display: "block", marginBottom: "10px" }}>
          {label}
        </span>
        <h3 style={{ fontFamily: "'Orbitron', monospace", fontWeight: 600, fontSize: "16px", color: "#e8ffe8", marginBottom: "12px", letterSpacing: "0.04em" }}>
          {title}
        </h3>
        <p style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: "16px", color: "rgba(180,255,180,0.48)", lineHeight: 1.8, maxWidth: "620px" }}>
          {desc}
        </p>
      </div>
    </div>
  );
}

function TerminalFeed() {
  const lines = [
    { text: "> SYSTEM ONLINE — WebIntelX v2.4.1", color: "#00ff88" },
    { text: "> CVE database synced: 247,832 entries loaded", color: "#00cc6a" },
    { text: "> OSINT modules: [WHOIS] [DNS] [SHODAN] [HIBP] READY", color: "#00cc6a" },
    { text: "> Phishing heuristics engine: ACTIVE", color: "#00cc6a" },
    { text: "> Vulnerability scanner: STANDBY", color: "#88ffcc" },
    { text: "> Awaiting target input...", color: "#00ff88" },
  ];
  return (
    <div style={{
      background: "rgba(0,0,0,0.9)", border: "1px solid rgba(0,255,136,0.18)",
      borderTop: "2px solid #00ff88", padding: "20px 24px",
      fontFamily: "'Share Tech Mono', monospace", fontSize: "12px",
      boxShadow: "0 0 40px rgba(0,255,136,0.07), inset 0 0 40px rgba(0,0,0,0.5)",
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "16px", borderBottom: "1px solid rgba(0,255,136,0.08)", paddingBottom: "12px" }}>
        {["#ff5f57","#febc2e","#28c840"].map((c, i) => (
          <div key={i} style={{ width: "10px", height: "10px", borderRadius: "50%", background: c }} />
        ))}
        <span style={{ marginLeft: "8px", color: "rgba(0,255,136,0.35)", fontSize: "10px", letterSpacing: "0.15em" }}>WEBINTELX — THREAT TERMINAL</span>
      </div>
      {lines.map((l, i) => (
        <div key={i} style={{ marginBottom: "7px", color: l.color, lineHeight: 1.6 }}>
          <Typewriter text={l.text} delay={i * 650} speed={20} />
        </div>
      ))}
    </div>
  );
}

export default function Home() {
  const scanRef = useRef(null);
  const [mousePos, setMousePos] = useState({ x: 0.5, y: 0.5 });
  const [navVisible, setNavVisible] = useState(true);
  const lastScrollRef = useRef(0);

  const navigate = (path) => { window.location.href = path; };

  useEffect(() => {
    const onScroll = () => {
      const y = window.scrollY;
      setNavVisible(y < lastScrollRef.current || y < 80);
      lastScrollRef.current = y;
    };
    const onMouse = (e) => setMousePos({ x: e.clientX / window.innerWidth, y: e.clientY / window.innerHeight });
    window.addEventListener("scroll", onScroll);
    window.addEventListener("mousemove", onMouse);
    return () => { window.removeEventListener("scroll", onScroll); window.removeEventListener("mousemove", onMouse); };
  }, []);

  const modules = [
    { num: "01", title: "SECURITY SCAN", desc: "Full-stack recon with subdomain enumeration, port scanning, and tech fingerprinting across your entire external attack surface.", accent: "#00ff88", icon: "⬡", onClick: () => navigate("/scan") },
    { num: "02", title: "PASSWORD HARDENER", desc: "Entropy analysis and real-time breach correlation against HIBP databases. Know your exposure before attackers do.", accent: "#00d4ff", icon: "◈", onClick: () => window.open("http://localhost:3001", "_blank") },
    { num: "03", title: "PHISHING DETECTOR", desc: "ML-driven heuristics identify spoofed and malicious domains with sub-second response time and confidence scoring.", accent: "#ff6b35", icon: "◉", onClick: () => navigate("/phishing") },
  ];

  const features = [
    { label: "RECON // SURFACE_MAP", title: "Reconnaissance & Attack Surface Mapping", desc: "Automated subdomain enumeration, directory discovery, port scanning and technology fingerprinting reveals your entire external exposure. Built to find what attackers find — before they exploit it.", accent: "#00ff88" },
    { label: "INTEL // OSINT_LAYER", title: "OSINT Intelligence Correlation", desc: "Deep aggregation across public records, breach dumps, and live threat feeds. Exposed credentials, leaked assets and publicly accessible data are cross-validated and scored for exploitability.", accent: "#00d4ff" },
    { label: "VULN // ASSESS_ENGINE", title: "Vulnerability Assessment Engine", desc: "Continuous CVE database testing against injection vectors, misconfigurations and known exploit patterns. Real-world exploitability validation eliminates noise and surfaces only true risk.", accent: "#b06aff" },
    { label: "THREAT // CORRELATE", title: "Cross-Validation & Threat Correlation", desc: "Recon, OSINT and vulnerability signals are automatically fused to identify high-risk choke points. Exploitable attack paths emerge from layered multi-source analysis.", accent: "#ff6b35" },
  ];

  return (
    <div style={{ backgroundColor: "#020804", minHeight: "100vh", color: "#e8ffe8", overflowX: "hidden", cursor: "crosshair" }}>
      <link rel="stylesheet" href={FONT_URL} />
      <style>{`
        @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0} }
        @keyframes radarSpin { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }
        @keyframes scanDown { 0%{top:0%} 100%{top:100%} }
        @keyframes pulse { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:0.3;transform:scale(0.75)} }
        @keyframes fadeUp { from{opacity:0;transform:translateY(32px)} to{opacity:1;transform:translateY(0)} }
        @keyframes flicker { 0%,89%,91%,96%,100%{opacity:1} 90%{opacity:0.5} 95%{opacity:0.7} }
        * { box-sizing:border-box; margin:0; padding:0; }
        html { scroll-behavior:smooth; }
        ::-webkit-scrollbar { width:3px; }
        ::-webkit-scrollbar-track { background:#010502; }
        ::-webkit-scrollbar-thumb { background:#00ff8855; border-radius:2px; }
        ::selection { background:rgba(0,255,136,0.2); color:#00ff88; }
        button:focus { outline: 1px solid #00ff88; }
      `}</style>

      <HexGrid />
      <ScanLines />

      {/* Mouse glow */}
      <div style={{
        position: "fixed", pointerEvents: "none", zIndex: 1,
        width: "700px", height: "700px", borderRadius: "50%",
        background: "radial-gradient(circle, rgba(0,255,136,0.04) 0%, transparent 65%)",
        left: `${mousePos.x * 100}%`, top: `${mousePos.y * 100}%`,
        transform: "translate(-50%, -50%)",
        transition: "left 0.5s ease, top 0.5s ease",
      }} />

      {/* ── NAVBAR ── */}
      <nav style={{
        position: "fixed", top: 0, left: 0, right: 0, zIndex: 200,
        display: "flex", alignItems: "center", justifyContent: "space-between",
        padding: "0 48px", height: "64px",
        background: "rgba(2,8,4,0.92)",
        borderBottom: "1px solid rgba(0,255,136,0.09)",
        backdropFilter: "blur(16px)",
        transform: navVisible ? "translateY(0)" : "translateY(-100%)",
        transition: "transform 0.4s cubic-bezier(0.23,1,0.32,1)",
        animation: "flicker 10s ease-in-out infinite",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: "12px", cursor: "pointer" }}
          onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })}>
          <svg viewBox="0 0 36 36" width="34" height="34">
            <polygon points="18,2 34,11 34,25 18,34 2,25 2,11" fill="none" stroke="#00ff88" strokeWidth="1.5" />
            <polygon points="18,8 28,14 28,22 18,28 8,22 8,14" fill="none" stroke="#00ff88" strokeWidth="0.8" opacity="0.45" />
            <circle cx="18" cy="18" r="3" fill="#00ff88">
              <animate attributeName="r" values="3;4.2;3" dur="2.5s" repeatCount="indefinite" />
              <animate attributeName="opacity" values="1;0.6;1" dur="2.5s" repeatCount="indefinite" />
            </circle>
          </svg>
          <div>
            <div style={{ fontFamily: "'Orbitron', monospace", fontWeight: 900, fontSize: "14px", letterSpacing: "0.14em", color: "#00ff88", lineHeight: 1 }}>WEBINTELX</div>
            <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "8px", color: "rgba(0,255,136,0.35)", letterSpacing: "0.2em", marginTop: "3px" }}>THREAT INTELLIGENCE SYS</div>
          </div>
        </div>

        <div style={{ display: "flex", gap: "36px" }}>
          {["DASHBOARD", "MODULES", "REPORTS", "DOCS"].map((item, i) => (
            <span key={i}
              onClick={() => {
                if (item === "MODULES") scanRef.current?.scrollIntoView({ behavior: "smooth" });
                if (item === "DASHBOARD") window.scrollTo({ top: 0, behavior: "smooth" });
              }}
              style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", letterSpacing: "0.2em", color: "rgba(0,255,136,0.45)", cursor: "pointer", transition: "color 0.2s", padding: "4px 0", borderBottom: "1px solid transparent" }}
              onMouseEnter={e => { e.target.style.color = "#00ff88"; e.target.style.borderBottomColor = "#00ff88"; }}
              onMouseLeave={e => { e.target.style.color = "rgba(0,255,136,0.45)"; e.target.style.borderBottomColor = "transparent"; }}
            >{item}</span>
          ))}
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <div style={{ width: "7px", height: "7px", background: "#00ff88", borderRadius: "50%", boxShadow: "0 0 10px #00ff88", animation: "pulse 2s ease-in-out infinite" }} />
          <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", color: "#00ff88", letterSpacing: "0.15em" }}>SYS_ONLINE</span>
        </div>
      </nav>

      {/* ── HERO ── */}
      <section style={{ minHeight: "100vh", display: "flex", flexDirection: "column", justifyContent: "center", alignItems: "center", padding: "100px 40px 60px", position: "relative", textAlign: "center" }}>
        <RadarSweep />

        <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", letterSpacing: "0.35em", color: "#00ff88", background: "rgba(0,255,136,0.055)", border: "1px solid rgba(0,255,136,0.18)", padding: "8px 22px", marginBottom: "48px", animation: "fadeUp 0.6s ease 0.15s both" }}>
          ▶ UNIFIED CYBER INTELLIGENCE PLATFORM ◀
        </div>

        <h1 style={{ fontFamily: "'Orbitron', monospace", fontWeight: 900, fontSize: "clamp(48px, 8vw, 96px)", lineHeight: 0.95, letterSpacing: "-0.01em", marginBottom: "10px", animation: "fadeUp 0.6s ease 0.3s both", textShadow: "0 0 60px rgba(0,255,136,0.45), 0 0 120px rgba(0,255,136,0.15)" }}>
          <span style={{ color: "#f0fff4" }}>WEB</span><span style={{ color: "#00ff88" }}>INTEL</span><span style={{ color: "#f0fff4" }}>X</span>
        </h1>

        <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "clamp(10px, 1.4vw, 13px)", letterSpacing: "0.45em", color: "rgba(0,255,136,0.35)", marginBottom: "36px", animation: "fadeUp 0.6s ease 0.54s both" }}>
          SCAN // DETECT // PROTECT
        </div>

        <p style={{ fontFamily: "'Rajdhani', sans-serif", fontWeight: 400, fontSize: "clamp(16px, 1.8vw, 19px)", color: "rgba(180,255,180,0.48)", lineHeight: 1.85, maxWidth: "560px", marginBottom: "48px", animation: "fadeUp 0.6s ease 0.65s both" }}>
          Automated reconnaissance, deep OSINT gathering, and continuous vulnerability scanning — one platform engineered for modern security operations.
        </p>

        <div style={{ display: "flex", gap: "14px", flexWrap: "wrap", justifyContent: "center", marginBottom: "64px", animation: "fadeUp 0.6s ease 0.76s both" }}>
          <button onClick={() => navigate("/scan")} style={{
            fontFamily: "'Orbitron', monospace", fontWeight: 700, fontSize: "11px",
            letterSpacing: "0.2em", color: "#020804", background: "#00ff88", border: "none",
            padding: "16px 36px", cursor: "pointer", textTransform: "uppercase",
            transition: "all 0.25s", boxShadow: "0 0 28px rgba(0,255,136,0.32)",
          }}
            onMouseEnter={e => { e.target.style.background="#33ffaa"; e.target.style.transform="translateY(-3px)"; e.target.style.boxShadow="0 0 50px rgba(0,255,136,0.5)"; }}
            onMouseLeave={e => { e.target.style.background="#00ff88"; e.target.style.transform="translateY(0)"; e.target.style.boxShadow="0 0 28px rgba(0,255,136,0.32)"; }}
          >▶ INITIATE SCAN</button>

          <button onClick={() => scanRef.current?.scrollIntoView({ behavior: "smooth" })} style={{
            fontFamily: "'Orbitron', monospace", fontWeight: 700, fontSize: "11px",
            letterSpacing: "0.2em", color: "#00ff88", background: "transparent",
            border: "1px solid rgba(0,255,136,0.3)", padding: "16px 36px", cursor: "pointer",
            textTransform: "uppercase", transition: "all 0.25s",
          }}
            onMouseEnter={e => { e.currentTarget.style.background="rgba(0,255,136,0.06)"; e.currentTarget.style.borderColor="#00ff88"; e.currentTarget.style.transform="translateY(-3px)"; }}
            onMouseLeave={e => { e.currentTarget.style.background="transparent"; e.currentTarget.style.borderColor="rgba(0,255,136,0.3)"; e.currentTarget.style.transform="translateY(0)"; }}
          >VIEW MODULES</button>
        </div>

        <div style={{ animation: "fadeUp 0.6s ease 0.9s both", width: "100%", maxWidth: "660px" }}>
          <TerminalFeed />
        </div>

        <div style={{ position: "absolute", bottom: "28px", left: "50%", transform: "translateX(-50%)", display: "flex", flexDirection: "column", alignItems: "center", gap: "8px", opacity: 0.28 }}>
          <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", letterSpacing: "0.3em", color: "#00ff88" }}>SCROLL</span>
          <div style={{ width: "1px", height: "36px", background: "linear-gradient(to bottom, #00ff88, transparent)", animation: "pulse 2s ease-in-out infinite" }} />
        </div>
      </section>

      {/* ── MODULES ── */}
      <section ref={scanRef} style={{ maxWidth: "1100px", margin: "0 auto", padding: "100px 40px" }}>
        <div style={{ marginBottom: "52px" }}>
          <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", letterSpacing: "0.3em", color: "rgba(0,255,136,0.38)", marginBottom: "14px" }}>{"// CORE_MODULES"}</div>
          <h2 style={{ fontFamily: "'Orbitron', monospace", fontWeight: 700, fontSize: "clamp(20px, 2.8vw, 30px)", color: "#e8ffe8", letterSpacing: "0.04em" }}>OPERATIONAL TOOLKIT</h2>
          <div style={{ width: "48px", height: "2px", background: "#00ff88", marginTop: "14px", boxShadow: "0 0 10px rgba(0,255,136,0.5)" }} />
        </div>
        <div style={{ display: "flex", gap: "16px", flexWrap: "wrap" }}>
          {modules.map((m, i) => <ModuleCard key={i} {...m} />)}
        </div>
      </section>

      {/* ── CAPABILITIES ── */}
      <section style={{ maxWidth: "1100px", margin: "0 auto", padding: "0 40px 100px" }}>
        <div style={{ marginBottom: "12px" }}>
          <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", letterSpacing: "0.3em", color: "rgba(0,255,136,0.38)", marginBottom: "14px" }}>{"// CAPABILITIES"}</div>
          <h2 style={{ fontFamily: "'Orbitron', monospace", fontWeight: 700, fontSize: "clamp(20px, 2.8vw, 30px)", color: "#e8ffe8", letterSpacing: "0.04em" }}>HOW IT WORKS</h2>
          <div style={{ width: "48px", height: "2px", background: "#00ff88", marginTop: "14px", boxShadow: "0 0 10px rgba(0,255,136,0.5)" }} />
        </div>
        {features.map((f, i) => <FeatureRow key={i} index={i} {...f} />)}
        <div style={{ borderTop: "1px solid rgba(0,255,136,0.07)" }} />
      </section>

      {/* ── CTA BANNER ── */}
      <div style={{ maxWidth: "1020px", margin: "0 auto 80px", padding: "0 40px" }}>
        <div style={{ background: "rgba(0,0,0,0.75)", border: "1px solid rgba(0,255,136,0.1)", padding: "44px 48px", position: "relative", overflow: "hidden" }}>
          <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: "2px", background: "linear-gradient(90deg, transparent, #00ff88, #00d4ff, #b06aff, transparent)" }} />
          <div style={{ position: "absolute", bottom: 0, left: 0, right: 0, height: "1px", background: "linear-gradient(90deg, transparent, rgba(0,255,136,0.2), transparent)" }} />
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: "28px" }}>
            <div>
              <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", letterSpacing: "0.3em", color: "rgba(0,255,136,0.4)", marginBottom: "14px" }}>{"// READY_TO_SCAN"}</div>
              <h3 style={{ fontFamily: "'Orbitron', monospace", fontWeight: 700, fontSize: "clamp(18px, 2.5vw, 24px)", color: "#e8ffe8", letterSpacing: "0.04em" }}>BEGIN THREAT ASSESSMENT</h3>
              <p style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: "16px", color: "rgba(180,255,180,0.42)", marginTop: "12px", lineHeight: 1.7, maxWidth: "480px" }}>
                Enter a target domain and launch a full intelligence sweep — recon, OSINT, and vulnerability analysis — in under 60 seconds.
              </p>
            </div>
            <button onClick={() => navigate("/scan")} style={{
              fontFamily: "'Orbitron', monospace", fontWeight: 700, fontSize: "11px",
              letterSpacing: "0.2em", color: "#020804", background: "#00ff88", border: "none",
              padding: "18px 40px", cursor: "pointer", textTransform: "uppercase",
              transition: "all 0.25s", boxShadow: "0 0 28px rgba(0,255,136,0.3)", whiteSpace: "nowrap",
            }}
              onMouseEnter={e => { e.target.style.transform="translateY(-3px)"; e.target.style.boxShadow="0 0 50px rgba(0,255,136,0.5)"; }}
              onMouseLeave={e => { e.target.style.transform="translateY(0)"; e.target.style.boxShadow="0 0 28px rgba(0,255,136,0.3)"; }}
            >▶ LAUNCH SCAN</button>
          </div>
        </div>
      </div>

      {/* ── FOOTER ── */}
      <footer style={{ borderTop: "1px solid rgba(0,255,136,0.07)", padding: "28px 48px" }}>
        <div style={{ maxWidth: "1100px", margin: "0 auto", display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: "16px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <div style={{ width: "7px", height: "7px", background: "#00ff88", borderRadius: "50%", boxShadow: "0 0 8px #00ff88", animation: "pulse 2s ease-in-out infinite" }} />
            <span style={{ fontFamily: "'Orbitron', monospace", fontWeight: 700, fontSize: "12px", color: "rgba(0,255,136,0.45)", letterSpacing: "0.1em" }}>WEBINTELX</span>
          </div>
          <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", color: "rgba(0,255,136,0.2)", letterSpacing: "0.1em" }}>
            © 2025 // BUILT FOR SECURITY PROFESSIONALS // ALL SYSTEMS NOMINAL
          </span>
        </div>
      </footer>
    </div>
  );
}