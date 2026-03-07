import { useState, useRef } from "react";
import {
  FaSearch, FaBug, FaShieldAlt, FaFileDownload,
  FaGlobe, FaServer, FaLock, FaUnlock, FaNetworkWired, FaEnvelope,
  FaRoute, FaFingerprint, FaChevronDown, FaChevronUp, FaCode,
  FaLeaf, FaBiohazard, FaSkull, FaMapMarkerAlt, FaCookieBite,
  FaVirus, FaRadiation, FaEye
} from "react-icons/fa";

const FONT_URL = "https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;600;700;900&family=Rajdhani:wght@300;400;500;600;700&display=swap";

/* ── RISK HELPERS ── */
const riskAccent = (risk) => {
  if (risk === "CRITICAL") return "#ff2222";
  if (risk === "HIGH") return "#ff6b35";
  if (risk === "MEDIUM") return "#fbbf24";
  return "#00ff88";
};
const riskBg = (risk) => {
  if (risk === "CRITICAL") return "rgba(255,34,34,0.08)";
  if (risk === "HIGH") return "rgba(255,107,53,0.08)";
  if (risk === "MEDIUM") return "rgba(251,191,36,0.08)";
  return "rgba(0,255,136,0.06)";
};

/* ── BACKGROUND ── */
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
  return <div style={{ position: "fixed", inset: 0, pointerEvents: "none", zIndex: 1, background: "repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,255,136,0.012) 2px, rgba(0,255,136,0.012) 4px)" }} />;
}



/* ── STAT ROW ── */
const StatRow = ({ label, value, accent = "rgba(0,255,136,0.7)", mono = true, icon }) => (
  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", padding: "7px 0", borderBottom: "1px solid rgba(0,255,136,0.06)", gap: "12px" }}>
    <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", color: "rgba(0,255,136,0.55)", letterSpacing: "0.08em", flexShrink: 0, display: "flex", alignItems: "center", gap: "6px" }}>
      {icon && <span style={{ fontSize: "9px" }}>{icon}</span>}{label}
    </span>
    <span style={{ fontFamily: mono ? "'Share Tech Mono', monospace" : "'Rajdhani', sans-serif", fontSize: mono ? "11px" : "13px", color: accent, textAlign: "right", wordBreak: "break-all" }}>
      {value ?? "N/A"}
    </span>
  </div>
);

/* ── ALERT ROW ── */
const AlertRow = ({ text, severity = "warn" }) => {
  const color = severity === "critical" ? "#ff4444" : severity === "warn" ? "#fbbf24" : "#00cc77";
  const prefix = severity === "critical" ? "✕" : severity === "warn" ? "⚠" : "✓";
  return (
    <div style={{ display: "flex", gap: "8px", padding: "5px 0", alignItems: "flex-start" }}>
      <span style={{ color, fontSize: "11px", flexShrink: 0, marginTop: "1px" }}>{prefix}</span>
      <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", color: `${color}cc`, letterSpacing: "0.05em", lineHeight: 1.5 }}>{text}</span>
    </div>
  );
};

/* ── EXPANDABLE MODULE CARD ── */
const ModuleCard = ({ title, icon, risk, summary, children, defaultOpen = false }) => {
  const [open, setOpen] = useState(defaultOpen);
  const accent = riskAccent(risk);
  return (
    <div style={{ background: "rgba(0,0,0,0.55)", border: `1px solid rgba(0,255,136,0.09)`, borderLeft: `3px solid ${accent}`, position: "relative", overflow: "hidden", animation: "fadeUp 0.5s ease both" }}>
      <div
        onClick={() => setOpen(o => !o)}
        style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "18px 24px", cursor: "pointer", userSelect: "none" }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
          <div style={{ fontSize: "16px", filter: `drop-shadow(0 0 5px ${accent})` }}>{icon}</div>
          <div>
            <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "8px", letterSpacing: "0.22em", color: "rgba(0,255,136,0.5)", marginBottom: "4px" }}>MODULE //</div>
            <h4 style={{ fontFamily: "'Orbitron', monospace", fontWeight: 600, fontSize: "12px", color: "#e8ffe8", letterSpacing: "0.04em" }}>{title}</h4>
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
          <span style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: "12px", color: "rgba(200,255,200,0.7)", maxWidth: "200px", textAlign: "right" }}>{summary}</span>
          <span style={{ fontFamily: "'Orbitron', monospace", fontWeight: 700, fontSize: "9px", letterSpacing: "0.15em", color: accent, background: riskBg(risk), border: `1px solid ${accent}40`, padding: "3px 10px", flexShrink: 0 }}>{risk}</span>
          <span style={{ color: "rgba(0,255,136,0.35)", fontSize: "11px" }}>{open ? <FaChevronUp /> : <FaChevronDown />}</span>
        </div>
      </div>
      {open && (
        <div style={{ borderTop: "1px solid rgba(0,255,136,0.07)", padding: "20px 24px" }}>
          {children}
        </div>
      )}
    </div>
  );
};

/* ── TAG LIST ── */
const TagList = ({ items, color = "#00ff88" }) => (
  <div style={{ display: "flex", flexWrap: "wrap", gap: "6px", marginTop: "8px" }}>
    {items.map((item, i) => (
      <span key={i} style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", color, border: `1px solid ${color}30`, background: `${color}0a`, padding: "3px 10px" }}>
        {item}
      </span>
    ))}
  </div>
);

/* ── MAIN ── */
export default function QuickScan() {
  const [input, setInput] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [scanDone, setScanDone] = useState(false);
  const [results, setResults] = useState(null);
  const [riskAssessment, setRiskAssessment] = useState(null);
  const [error, setError] = useState("");
  const [isDownloading, setIsDownloading] = useState(false);
  const loaderRef = useRef(null);
  const resultsRef = useRef(null);

  const isValidURL = (url) => {
    try { new URL(url.startsWith("http") ? url : `http://${url}`); return true; }
    catch { return false; }
  };

  const handleScan = async () => {
    if (!input.trim()) return alert("Please enter a URL");
    if (!isValidURL(input)) return alert("Invalid URL format");
    setIsScanning(true); setError(""); setResults(null); setScanDone(false); setRiskAssessment(null);
    setTimeout(() => loaderRef.current?.scrollIntoView({ behavior: "smooth" }), 100);
    try {
      const scanRes = await fetch("http://localhost:5000/api/quickscan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: input }),
      });
      const scanData = await scanRes.json();
      if (!scanData.success) { setError(scanData.error); setIsScanning(false); return; }
      setResults(scanData.data);
      setRiskAssessment(scanData.riskAssessment);
      setScanDone(true);
      setTimeout(() => resultsRef.current?.scrollIntoView({ behavior: "smooth" }), 200);
    } catch { setError("Server unreachable"); }
    setIsScanning(false);
  };

  const downloadPDF = async () => {
    if (!results) return;
    setIsDownloading(true);
    try {
      const res = await fetch("http://localhost:5000/api/report/quickscan/pdf", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: input, scanData: results, riskAssessment }),
      });
      if (!res.ok) throw new Error();
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = `QuickScan-${input.replace(/[^a-z0-9]/gi, "_")}.pdf`; a.click();
      window.URL.revokeObjectURL(url);
    } catch { alert("Failed to download PDF report"); }
    setIsDownloading(false);
  };

  /* ── DERIVED DATA ── */
  const r = results;
  const overallRisk = riskAssessment?.risk || "LOW";
  const techStack = r?.wappalyzer ? Object.entries(r.wappalyzer).map(([t, v]) => v !== "Unknown" ? `${t} ${v}` : t) : [];

  return (
    <div style={{ backgroundColor: "#020804", minHeight: "100vh", color: "#e8ffe8", overflowX: "hidden", cursor: "crosshair" }}>
      <link rel="stylesheet" href={FONT_URL} />
      <style>{`
        @keyframes pulse { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:0.3;transform:scale(0.75)} }
        @keyframes fadeUp { from{opacity:0;transform:translateY(20px)} to{opacity:1;transform:translateY(0)} }
        @keyframes spin { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }
        @keyframes scanPulse { 0%,100%{opacity:0.5} 50%{opacity:1} }
        @keyframes flicker { 0%,89%,91%,96%,100%{opacity:1} 90%{opacity:0.5} 95%{opacity:0.75} }
        @keyframes scanBar { 0%{width:0%} 100%{width:100%} }
        * { box-sizing:border-box; margin:0; padding:0; }
        ::selection { background:rgba(0,255,136,0.2); color:#00ff88; }
        ::-webkit-scrollbar { width:3px; }
        ::-webkit-scrollbar-track { background:#010502; }
        ::-webkit-scrollbar-thumb { background:#00ff8855; }
      `}</style>

      <HexGrid />
      <ScanLines />

      {/* NAVBAR */}
      <nav style={{ position: "fixed", top: 0, left: 0, right: 0, zIndex: 200, display: "flex", alignItems: "center", justifyContent: "space-between", padding: "0 48px", height: "64px", background: "rgba(2,8,4,0.92)", borderBottom: "1px solid rgba(0,255,136,0.09)", backdropFilter: "blur(16px)", animation: "flicker 10s ease-in-out infinite" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "12px", cursor: "pointer" }} onClick={() => window.location.href = "/"}>
          <svg viewBox="0 0 36 36" width="32" height="32">
            <polygon points="18,2 34,11 34,25 18,34 2,25 2,11" fill="none" stroke="#00ff88" strokeWidth="1.5" />
            <polygon points="18,8 28,14 28,22 18,28 8,22 8,14" fill="none" stroke="#00ff88" strokeWidth="0.8" opacity="0.45" />
            <circle cx="18" cy="18" r="3" fill="#00ff88"><animate attributeName="r" values="3;4.2;3" dur="2.5s" repeatCount="indefinite" /></circle>
          </svg>
          <div>
            <div style={{ fontFamily: "'Orbitron', monospace", fontWeight: 900, fontSize: "14px", letterSpacing: "0.14em", color: "#00ff88" }}>WEBINTELX</div>
            <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "8px", color: "rgba(0,255,136,0.35)", letterSpacing: "0.2em", marginTop: "2px" }}>THREAT INTELLIGENCE SYS</div>
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
          <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", color: "rgba(0,255,136,0.4)", letterSpacing: "0.15em" }}>{"QUICK_SCAN // MODULE_01"}</span>
          <div style={{ width: "7px", height: "7px", background: isScanning ? "#fbbf24" : "#00ff88", borderRadius: "50%", boxShadow: `0 0 10px ${isScanning ? "#fbbf24" : "#00ff88"}`, animation: "pulse 2s ease-in-out infinite" }} />
          <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", color: isScanning ? "#fbbf24" : "#00ff88", letterSpacing: "0.15em" }}>{isScanning ? "SCANNING..." : "READY"}</span>
        </div>
      </nav>

      <div style={{ position: "relative", zIndex: 2, maxWidth: "1100px", margin: "0 auto", padding: "120px 40px 100px" }}>

        {/* Header */}
        <div style={{ marginBottom: "52px", animation: "fadeUp 0.6s ease 0.1s both" }}>
          <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", letterSpacing: "0.35em", color: "rgba(0,255,136,0.4)", marginBottom: "14px" }}>{"// MODULE_01 / QUICK_SCAN"}</div>
          <h1 style={{ fontFamily: "'Orbitron', monospace", fontWeight: 900, fontSize: "clamp(28px,4vw,52px)", color: "#e8ffe8", letterSpacing: "0.04em", lineHeight: 1.1, marginBottom: "16px" }}>
            QUICK <span style={{ color: "#00ff88" }}>SCAN</span>
          </h1>
          <p style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: "17px", color: "rgba(200,255,200,0.75)", lineHeight: 1.7, maxWidth: "540px" }}>
            High-level security snapshot to identify immediate risks. Recon + OSINT surface analysis in approximately 2 minutes.
          </p>
          <div style={{ width: "48px", height: "2px", background: "#00ff88", marginTop: "18px", boxShadow: "0 0 10px rgba(0,255,136,0.5)" }} />
        </div>

        {/* Input Card */}
        <div style={{ background: "rgba(0,0,0,0.7)", border: "1px solid rgba(0,255,136,0.15)", borderTop: "2px solid #00ff88", padding: "36px", maxWidth: "600px", marginBottom: "40px", animation: "fadeUp 0.6s ease 0.2s both", position: "relative", overflow: "hidden" }}>
          <div style={{ position: "absolute", top: 0, right: 0, width: 0, height: 0, borderStyle: "solid", borderWidth: "0 40px 40px 0", borderColor: "transparent rgba(0,255,136,0.15) transparent transparent" }} />
          <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", color: "rgba(0,255,136,0.4)", letterSpacing: "0.25em", marginBottom: "20px" }}>{"TARGET_INPUT // ENTER_URL_OR_DOMAIN"}</div>
          <label style={{ fontFamily: "'Orbitron', monospace", fontSize: "12px", letterSpacing: "0.1em", color: "#e8ffe8", display: "block", marginBottom: "12px" }}>TARGET URL</label>
          <div style={{ display: "flex", gap: "12px", flexWrap: "wrap" }}>
            <input
              value={input} onChange={e => setInput(e.target.value)} onKeyDown={e => e.key === "Enter" && handleScan()}
              placeholder="example.com"
              style={{ flex: "1 1 240px", padding: "12px 16px", background: "rgba(0,0,0,0.8)", border: "1px solid rgba(0,255,136,0.2)", color: "#00ff88", fontFamily: "'Share Tech Mono', monospace", fontSize: "13px", outline: "none", letterSpacing: "0.05em" }}
              onFocus={e => e.target.style.borderColor = "#00ff88"}
              onBlur={e => e.target.style.borderColor = "rgba(0,255,136,0.2)"}
            />
            <button onClick={handleScan} style={{ fontFamily: "'Orbitron', monospace", fontWeight: 700, fontSize: "11px", letterSpacing: "0.18em", color: "#020804", background: "#00ff88", border: "none", padding: "12px 28px", cursor: "pointer", display: "flex", alignItems: "center", gap: "8px", boxShadow: "0 0 20px rgba(0,255,136,0.25)" }}
              onMouseEnter={e => { e.currentTarget.style.background = "#33ffaa"; e.currentTarget.style.transform = "translateY(-2px)"; }}
              onMouseLeave={e => { e.currentTarget.style.background = "#00ff88"; e.currentTarget.style.transform = "translateY(0)"; }}>
              <FaSearch style={{ fontSize: "12px" }} /> SCAN
            </button>
          </div>
          {error && <div style={{ marginTop: "14px", fontFamily: "'Share Tech Mono', monospace", fontSize: "11px", color: "#ff6b6b", letterSpacing: "0.1em" }}>✕ ERROR: {error}</div>}
        </div>

        {/* LOADER */}
        {isScanning && (
          <div ref={loaderRef} style={{ marginBottom: "40px", animation: "fadeUp 0.4s ease both" }}>
            <div style={{ background: "rgba(0,0,0,0.6)", border: "1px solid rgba(251,191,36,0.25)", borderLeft: "3px solid #fbbf24", padding: "28px 32px", maxWidth: "600px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "16px", marginBottom: "20px" }}>
                <div style={{ width: "20px", height: "20px", border: "2px solid rgba(0,255,136,0.2)", borderTop: "2px solid #00ff88", borderRadius: "50%", animation: "spin 0.8s linear infinite" }} />
                <span style={{ fontFamily: "'Orbitron', monospace", fontWeight: 700, fontSize: "14px", color: "#fbbf24", letterSpacing: "0.1em" }}>RUNNING SECURITY CHECKS</span>
              </div>
              {/* Progress bar */}
              <div style={{ height: "2px", background: "rgba(0,255,136,0.1)", marginBottom: "20px", overflow: "hidden" }}>
                <div style={{ height: "100%", background: "#00ff88", animation: "scanBar 90s linear forwards", boxShadow: "0 0 8px #00ff88" }} />
              </div>
              <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "11px", color: "rgba(0,255,136,0.4)", letterSpacing: "0.08em", lineHeight: 2 }}>
                {["› Enumerating subdomains via crt.sh (Certificate Transparency)...", "› Probing HTTP headers & security posture...", "› Scanning open ports...", "› Verifying SSL/TLS certificate...", "› Querying WHOIS registration data...", "› Running DNS resolution...", "› Analysing technology stack (Wappalyzer)...", "› Running traceroute...", "› Checking email / domain reputation..."].map((line, i) => (
                  <div key={i} style={{ animation: `scanPulse 2s ease ${i * 0.4}s infinite` }}>{line}</div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ═══════════════ RESULTS ═══════════════ */}
        {scanDone && r && (
          <div ref={resultsRef} style={{ animation: "fadeUp 0.6s ease both" }}>

            {/* ── RISK BANNER ── */}
            <div style={{ background: riskBg(overallRisk), border: `1px solid ${riskAccent(overallRisk)}40`, borderLeft: `4px solid ${riskAccent(overallRisk)}`, padding: "28px 32px", marginBottom: "32px", position: "relative", overflow: "hidden" }}>
              <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: "1px", background: `linear-gradient(90deg, ${riskAccent(overallRisk)}, transparent)` }} />
              <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", letterSpacing: "0.3em", color: "rgba(0,255,136,0.4)", marginBottom: "10px" }}>OVERALL_RISK_ASSESSMENT //</div>
              <div style={{ display: "flex", alignItems: "flex-start", gap: "32px", flexWrap: "wrap" }}>
                <div>
                  <span style={{ fontFamily: "'Orbitron', monospace", fontWeight: 900, fontSize: "clamp(22px,3vw,40px)", color: riskAccent(overallRisk), letterSpacing: "0.08em", textShadow: `0 0 30px ${riskAccent(overallRisk)}60` }}>
                    {overallRisk} RISK
                  </span>
                  <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "11px", color: "rgba(0,255,136,0.45)", letterSpacing: "0.1em", marginTop: "6px" }}>TARGET: {input}</div>
                  <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", color: "rgba(0,255,136,0.3)", marginTop: "2px" }}>RISK SCORE: {riskAssessment?.score ?? "—"}/15</div>
                </div>
                {/* Key findings */}
                {riskAssessment?.findings?.length > 0 && (
                  <div style={{ flex: 1, minWidth: "220px" }}>
                    <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", color: "rgba(0,255,136,0.6)", letterSpacing: "0.2em", marginBottom: "8px" }}>KEY FINDINGS //</div>
                    {riskAssessment.findings.map((f, i) => (
                      <AlertRow key={i} text={f} severity={overallRisk === "CRITICAL" || overallRisk === "HIGH" ? "critical" : "warn"} />
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* ── SECTION: CORE SECURITY ── */}
            <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", letterSpacing: "0.3em", color: "rgba(0,255,136,0.6)", marginBottom: "16px", marginTop: "40px" }}>
              {"// CORE_SECURITY_SIGNALS"}
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: "12px", marginBottom: "40px" }}>

              {/* SSL / TLS */}
              <ModuleCard
                title="SSL / TLS Certificate"
                icon={r.ssl?.valid ? <FaLock style={{ color: "#00ff88" }} /> : <FaUnlock style={{ color: "#ff6b35" }} />}
                risk={!r.ssl?.valid ? "HIGH" : r.ssl?.daysRemaining < 30 ? "MEDIUM" : "LOW"}
                summary={r.ssl?.valid ? `Valid · ${r.ssl?.daysRemaining ?? "?"} days remaining` : "Certificate invalid or missing"}
                defaultOpen={!r.ssl?.valid}
              >
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0 40px" }}>
                  <StatRow label="STATUS" value={r.ssl?.valid ? "✓ VALID" : "✕ INVALID"} accent={r.ssl?.valid ? "#00ff88" : "#ff6b35"} />
                  <StatRow label="DAYS REMAINING" value={r.ssl?.daysRemaining ?? "N/A"} accent={r.ssl?.daysRemaining < 30 ? "#fbbf24" : "#00ff88"} />
                  <StatRow label="VALID FROM" value={r.ssl?.validFrom ? r.ssl.validFrom.split("T")[0] : "N/A"} />
                  <StatRow label="VALID TO" value={r.ssl?.validTo ? r.ssl.validTo.split("T")[0] : "N/A"} />
                  <StatRow label="ISSUER" value={r.ssl?.issuer ?? "Unknown"} />
                  <StatRow label="SUBJECT" value={r.ssl?.subject ?? "N/A"} />
                </div>
                {!r.ssl?.valid && <AlertRow text="HTTPS not enforced — data transmitted in plaintext" severity="critical" />}
                {r.ssl?.daysRemaining < 30 && r.ssl?.valid && <AlertRow text={`Certificate expires in ${r.ssl.daysRemaining} days — renew immediately`} severity="warn" />}
              </ModuleCard>

              {/* HTTP Headers */}
              <ModuleCard
                title="HTTP Security Headers"
                icon={<FaShieldAlt style={{ color: "#00ff88" }} />}
                risk={r.headers?.missingSecurityHeaders?.length >= 3 ? "HIGH" : r.headers?.missingSecurityHeaders?.length > 0 ? "MEDIUM" : "LOW"}
                summary={`${r.headers?.missingSecurityHeaders?.length ?? 0} missing security headers`}
                defaultOpen={r.headers?.missingSecurityHeaders?.length >= 2}
              >
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0 40px", marginBottom: "16px" }}>
                  <StatRow label="SERVER" value={r.headers?.server ?? "Hidden"} accent={r.headers?.server ? "#fbbf24" : "#00ff88"} />
                  <StatRow label="X-POWERED-BY" value={r.headers?.poweredBy ?? "Hidden"} accent={r.headers?.poweredBy ? "#ff6b35" : "#00ff88"} />
                  <StatRow label="STRICT-TRANSPORT-SEC" value={r.headers?.strictTransport ? "Present" : "MISSING"} accent={r.headers?.strictTransport ? "#00ff88" : "#ff6b35"} />
                  <StatRow label="X-FRAME-OPTIONS" value={r.headers?.xFrameOptions ? r.headers.xFrameOptions : "MISSING"} accent={r.headers?.xFrameOptions ? "#00ff88" : "#ff6b35"} />
                  <StatRow label="CONTENT-SECURITY-POLICY" value={r.headers?.csp ? "Present" : "MISSING"} accent={r.headers?.csp ? "#00ff88" : "#ff6b35"} />
                  <StatRow label="REFERRER-POLICY" value={r.headers?.referrer ?? "MISSING"} accent={r.headers?.referrer ? "#00ff88" : "#ff6b35"} />
                  <StatRow label="CORS" value={r.headers?.cors ?? "Not set"} accent={r.headers?.cors === "*" ? "#ff2222" : "#00ff88"} />
                  <StatRow label="XSS-PROTECTION" value={r.headers?.xssProtection ?? "Not set"} />
                </div>
                {r.headers?.missingSecurityHeaders?.length > 0 && (
                  <>
                    <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", color: "rgba(255,107,53,0.6)", letterSpacing: "0.2em", marginBottom: "8px" }}>MISSING HEADERS //</div>
                    {r.headers.missingSecurityHeaders.map((h, i) => <AlertRow key={i} text={h} severity="warn" />)}
                  </>
                )}
                {r.headers?.cors === "*" && <AlertRow text="Wildcard CORS allows any origin to make cross-site requests" severity="critical" />}
                {r.headers?.poweredBy?.includes("PHP/5") && <AlertRow text="PHP 5.x is end-of-life and contains known vulnerabilities" severity="critical" />}
              </ModuleCard>

              {/* Technology Stack */}
              <ModuleCard
                title="Technology Stack"
                icon={<FaCode style={{ color: "#00d4ff" }} />}
                risk={r.headers?.poweredBy?.includes("PHP/5") || r.headers?.poweredBy?.includes("PHP/4") ? "HIGH" : techStack.length > 0 ? "MEDIUM" : "LOW"}
                summary={`${techStack.length} technologies detected`}
              >
                {techStack.length > 0 ? (
                  <>
                    <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", color: "rgba(0,255,136,0.6)", letterSpacing: "0.2em", marginBottom: "10px" }}>DETECTED STACK //</div>
                    <TagList items={techStack} color="#00d4ff" />
                    <div style={{ marginTop: "16px" }}>
                      <StatRow label="SERVER SOFTWARE" value={r.headers?.server ?? "Unknown"} />
                      <StatRow label="BACKEND LANGUAGE" value={r.headers?.poweredBy ?? "Unknown"} accent={r.headers?.poweredBy?.includes("PHP/5") ? "#ff6b35" : "#00ff88"} />
                    </div>
                    {r.headers?.poweredBy?.includes("PHP/5") && <AlertRow text="PHP 5.x reached EOL in Dec 2018 — upgrade to PHP 8.x" severity="critical" />}
                    {r.headers?.server?.toLowerCase().includes("apache/2.2") && <AlertRow text="Apache 2.2 is outdated and no longer receives security patches" severity="warn" />}
                  </>
                ) : (
                  <AlertRow text="No technology fingerprints detected" severity="info" />
                )}
              </ModuleCard>

              {/* Exposed Endpoints */}
              <ModuleCard
                title="Exposed Endpoints"
                icon={<FaBug style={{ color: "#ff6b35" }} />}
                risk={r.endpoints?.length > 20 ? "HIGH" : r.endpoints?.length > 10 ? "MEDIUM" : "LOW"}
                summary={`${r.endpoints?.length ?? 0} parameterized endpoints discovered`}
              >
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0 40px", marginBottom: "16px" }}>
                  <StatRow label="TOTAL ENDPOINTS" value={r.endpoints?.length ?? 0} accent={r.endpoints?.length > 20 ? "#ff6b35" : "#00ff88"} />
                  <StatRow label="UNIQUE PARAMS" value={r.endpoints ? new Set(r.endpoints.map(e => e.param)).size : 0} />
                </div>
                {r.endpoints?.length > 0 && (
                  <>
                    <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", color: "rgba(0,255,136,0.6)", letterSpacing: "0.2em", marginBottom: "10px" }}>SAMPLE ENDPOINTS //</div>
                    <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
                      {r.endpoints.slice(0, 8).map((ep, i) => (
                        <div key={i} style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", color: "rgba(0,255,136,0.8)", padding: "4px 8px", background: "rgba(0,255,136,0.03)", borderLeft: "2px solid rgba(0,255,136,0.15)" }}>
                          <span style={{ color: "#fbbf24" }}>[{ep.param?.toUpperCase() ?? "?"}]</span> {ep.url}
                        </div>
                      ))}
                      {r.endpoints.length > 8 && <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", color: "rgba(0,255,136,0.45)", marginTop: "4px" }}>+{r.endpoints.length - 8} more endpoints</div>}
                    </div>
                    {r.endpoints?.length > 20 && <AlertRow text="Large number of parameterized endpoints increases SQL injection attack surface" severity="warn" />}
                  </>
                )}
              </ModuleCard>

              {/* Open Ports */}
              <ModuleCard
                title="Network & Open Ports"
                icon={<FaNetworkWired style={{ color: "#fbbf24" }} />}
                risk={r.openPorts?.some(p => [21, 23, 3306].includes(p.port)) ? "HIGH" : r.openPorts?.length > 3 ? "MEDIUM" : "LOW"}
                summary={`${r.openPorts?.length ?? 0} open ports detected`}
              >
                {r.openPorts?.length > 0 ? (
                  <>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: "8px", marginBottom: "16px" }}>
                      {r.openPorts.map((p, i) => {
                        const danger = [21, 23, 25, 3306].includes(p.port);
                        const color = danger ? "#ff6b35" : p.port === 443 ? "#00ff88" : "#00d4ff";
                        return (
                          <div key={i} style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", color, border: `1px solid ${color}40`, background: `${color}08`, padding: "6px 14px", display: "flex", flexDirection: "column", alignItems: "center", gap: "2px" }}>
                            <span style={{ fontSize: "13px", fontWeight: "bold" }}>{p.port}</span>
                            <span style={{ fontSize: "8px", opacity: 0.7 }}>{p.name}</span>
                            {danger && <span style={{ fontSize: "7px", color: "#ff6b35" }}>⚠ RISK</span>}
                          </div>
                        );
                      })}
                    </div>
                    {r.openPorts.filter(p => [21, 23].includes(p.port)).map((p, i) => (
                      <AlertRow key={i} text={`Port ${p.port} (${p.name}) transmits credentials in plaintext — disable or restrict`} severity="critical" />
                    ))}
                    {r.openPorts.find(p => p.port === 3306) && <AlertRow text="MySQL port 3306 exposed to public — restrict to localhost only" severity="critical" />}
                    {!r.openPorts.find(p => p.port === 443) && <AlertRow text="HTTPS (port 443) not detected — traffic may be unencrypted" severity="warn" />}
                  </>
                ) : (
                  <AlertRow text="No common ports detected as open" severity="info" />
                )}
              </ModuleCard>

              {/* Attack Surface */}
              <ModuleCard
                title="Attack Surface (crt.sh)"
                icon={<FaSearch style={{ color: "#00ff88" }} />}
                risk={r.securityTrails?.risk ?? "LOW"}
                summary={`${r.securityTrails?.subdomainCount ?? 0} subdomains discovered`}
              >
                <StatRow label="SUBDOMAIN COUNT" value={r.securityTrails?.subdomainCount ?? 0} accent={r.securityTrails?.subdomainCount > 10 ? "#ff6b35" : "#00ff88"} />
                <StatRow label="SCAN TYPE" value={`PASSIVE — ${r.securityTrails?.note?.replace("Subdomain enumeration via ", "") || "crt.sh"} · ${r.securityTrails?.subdomains?.length ?? 0} unique subdomains`} />
                {r.securityTrails?.subdomains?.length > 0 && (
                  <>
                    <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", color: "rgba(0,255,136,0.6)", letterSpacing: "0.2em", margin: "12px 0 8px" }}>SAMPLE SUBDOMAINS //</div>
                    <TagList items={r.securityTrails.subdomains.slice(0, 12)} />
                    {r.securityTrails.subdomains.length > 12 && <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", color: "rgba(0,255,136,0.25)", marginTop: "8px" }}>+{r.securityTrails.subdomains.length - 12} more subdomains</div>}
                  </>
                )}
                {r.securityTrails?.subdomainCount > 30 && <AlertRow text="Large subdomain count indicates broad attack surface — audit each subdomain" severity="warn" />}
              </ModuleCard>
            </div>

            {/* ── SECTION: INFRASTRUCTURE ── */}
            <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", letterSpacing: "0.3em", color: "rgba(0,255,136,0.6)", marginBottom: "16px" }}>
              {"// INFRASTRUCTURE_INTELLIGENCE"}
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: "12px", marginBottom: "48px" }}>

              {/* DNS */}
              <ModuleCard
                title="DNS Intelligence"
                icon={<FaGlobe style={{ color: "#00d4ff" }} />}
                risk={!r.dns?.resolvedSuccessfully ? "MEDIUM" : "LOW"}
                summary={r.dns?.resolvedSuccessfully ? `Resolved · Primary IP: ${r.dns?.primaryIP ?? "N/A"}` : "DNS resolution failed"}
              >
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0 40px" }}>
                  <StatRow label="RESOLVED" value={r.dns?.resolvedSuccessfully ? "✓ YES" : "✕ NO"} accent={r.dns?.resolvedSuccessfully ? "#00ff88" : "#ff6b35"} />
                  <StatRow label="PRIMARY IP" value={r.dns?.primaryIP ?? "N/A"} />
                  <StatRow label="A RECORDS" value={r.dns?.A?.length ?? 0} />
                  <StatRow label="MX RECORDS" value={r.dns?.MX?.length ?? 0} />
                  <StatRow label="NS RECORDS" value={r.dns?.NS?.length ?? 0} />
                </div>
                {r.dns?.A?.length > 1 && (
                  <>
                    <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", color: "rgba(0,255,136,0.6)", letterSpacing: "0.2em", margin: "12px 0 8px" }}>IP ADDRESSES //</div>
                    <TagList items={r.dns.A} />
                  </>
                )}
                {r.dns?.MX?.length > 0 && (
                  <>
                    <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", color: "rgba(0,255,136,0.6)", letterSpacing: "0.2em", margin: "12px 0 8px" }}>MAIL SERVERS //</div>
                    <TagList items={r.dns.MX} color="#b06aff" />
                  </>
                )}
                {r.dns?.NS?.length > 0 && (
                  <>
                    <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", color: "rgba(0,255,136,0.6)", letterSpacing: "0.2em", margin: "12px 0 8px" }}>NAME SERVERS //</div>
                    <TagList items={r.dns.NS} color="#00d4ff" />
                  </>
                )}
              </ModuleCard>

              {/* WHOIS */}
              <ModuleCard
                title="WHOIS Registration"
                icon={<FaFingerprint style={{ color: "#b06aff" }} />}
                risk={!r.whois || r.whois.registrar === "Unknown" ? "MEDIUM" : "LOW"}
                summary={r.whois?.registrar !== "Unknown" ? `Registrar: ${r.whois?.registrar}` : "Registration data unavailable"}
              >
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0 40px" }}>
                  <StatRow label="REGISTRAR" value={r.whois?.registrar ?? "Unknown"} />
                  <StatRow label="REGISTRANT ORG" value={r.whois?.registrantOrg ?? "Unknown"} />
                  <StatRow label="CREATED" value={r.whois?.creationDate ?? "N/A"} />
                  <StatRow label="EXPIRES" value={r.whois?.expiryDate ?? "N/A"} />
                  <StatRow label="LAST UPDATED" value={r.whois?.updatedDate ?? "N/A"} />
                  <StatRow label="COUNTRY" value={r.whois?.country ?? "Unknown"} />
                  <StatRow label="DNSSEC" value={r.whois?.dnssec ?? "Unknown"} />
                  <StatRow label="NAMESERVERS" value={r.whois?.nameservers?.length ?? 0} />
                </div>
                {r.whois?.nameservers?.length > 0 && (
                  <>
                    <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", color: "rgba(0,255,136,0.6)", letterSpacing: "0.2em", margin: "12px 0 8px" }}>NAMESERVERS //</div>
                    <TagList items={r.whois.nameservers} color="#b06aff" />
                  </>
                )}
              </ModuleCard>

              {/* Ping */}
              <ModuleCard
                title="Host Reachability (Ping)"
                icon={<FaServer style={{ color: "#00ff88" }} />}
                risk={!r.ping?.reachable ? "HIGH" : r.ping?.packetLoss !== "0%" ? "MEDIUM" : "LOW"}
                summary={r.ping?.reachable ? `Reachable · ${r.ping?.avgTime !== "N/A" ? r.ping.avgTime + "ms avg" : "latency N/A"}` : "Host unreachable"}
              >
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0 40px" }}>
                  <StatRow label="REACHABLE" value={r.ping?.reachable ? "✓ YES" : "✕ NO"} accent={r.ping?.reachable ? "#00ff88" : "#ff6b35"} />
                  <StatRow label="AVG LATENCY" value={r.ping?.avgTime !== "N/A" ? `${r.ping.avgTime} ms` : "N/A"} accent={parseFloat(r.ping?.avgTime) > 200 ? "#fbbf24" : "#00ff88"} />
                  <StatRow label="PACKET LOSS" value={r.ping?.packetLoss ?? "0%"} accent={r.ping?.packetLoss !== "0%" ? "#fbbf24" : "#00ff88"} />
                  <StatRow label="PACKETS SENT" value={r.ping?.sent ?? 4} />
                  <StatRow label="PACKETS RECEIVED" value={r.ping?.received ?? "N/A"} />
                </div>
                {!r.ping?.reachable && <AlertRow text="Host not responding to ICMP — may have firewall blocking ping" severity="warn" />}
                {parseFloat(r.ping?.avgTime) > 300 && <AlertRow text="High latency detected — possible performance or routing issue" severity="warn" />}
              </ModuleCard>

              {/* Traceroute */}
              <ModuleCard
                title="Network Path (Traceroute)"
                icon={<FaRoute style={{ color: "#fbbf24" }} />}
                risk={r.traceroute?.totalHops > 20 ? "MEDIUM" : "LOW"}
                summary={r.traceroute ? `${r.traceroute.totalHops} hops · Final: ${r.traceroute.finalHop}` : "Traceroute unavailable"}
              >
                {r.traceroute ? (
                  <>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0 40px", marginBottom: "16px" }}>
                      <StatRow label="TOTAL HOPS" value={r.traceroute.totalHops} accent={r.traceroute.totalHops > 20 ? "#fbbf24" : "#00ff88"} />
                      <StatRow label="REACHABLE HOPS" value={r.traceroute.reachableHops} />
                      <StatRow label="FINAL HOP" value={r.traceroute.finalHop} />
                      <StatRow label="AVG LATENCY" value={r.traceroute.avgLatency ? `${r.traceroute.avgLatency} ms` : "N/A"} />
                    </div>
                    {/* Hop visualizer */}
                    {r.traceroute.hops?.length > 0 && (
                      <>
                        <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", color: "rgba(0,255,136,0.6)", letterSpacing: "0.2em", marginBottom: "10px" }}>NETWORK PATH //</div>
                        <div style={{ maxHeight: "200px", overflowY: "auto", display: "flex", flexDirection: "column", gap: "2px" }}>
                          {r.traceroute.hops.slice(0, 20).map((hop, i) => {
                            const isTimeout = hop.ip === "*" || hop.ip?.toLowerCase().includes("request");
                            return (
                              <div key={i} style={{ display: "flex", alignItems: "center", gap: "10px", fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", opacity: isTimeout ? 0.35 : 1 }}>
                                <span style={{ color: "rgba(0,255,136,0.5)", width: "24px", textAlign: "right", flexShrink: 0 }}>{hop.hop}</span>
                                <span style={{ width: "3px", height: "3px", background: isTimeout ? "rgba(0,255,136,0.2)" : "#00ff88", borderRadius: "50%", flexShrink: 0 }} />
                                <span style={{ color: isTimeout ? "rgba(0,255,136,0.4)" : "rgba(0,255,136,0.9)", fontStyle: isTimeout ? "italic" : "normal" }}>
                                  {isTimeout ? "* * *  (no response)" : hop.ip}
                                </span>
                                {hop.hostname && !isTimeout && (
                                  <span style={{ color: "rgba(0,255,136,0.4)", fontSize: "9px" }}>({hop.hostname})</span>
                                )}
                                {hop.latency && !isTimeout && (
                                  <span style={{ color: "rgba(0,255,136,0.5)", marginLeft: "auto" }}>{hop.latency}ms</span>
                                )}
                              </div>
                            );
                          })}
                        </div>
                      </>
                    )}
                  </>
                ) : (
                  <AlertRow text="Traceroute blocked or timed out" severity="info" />
                )}
              </ModuleCard>

                            {/* Email Intelligence — DNSBL + Hunter */}
              <ModuleCard
                title="Email & Domain Intelligence"
                icon={<FaEnvelope style={{ color: r.emailIntelligence?.blacklisted ? "#ff4444" : "#b06aff" }} />}
                risk={r.emailIntelligence?.risk ?? "LOW"}
                summary={(() => {
                  const d = r.emailIntelligence;
                  if (!d) return "Check unavailable";
                  const parts = [];
                  if (d.dnsbl?.listed) parts.push(`⚠ Listed on ${d.dnsbl.listCount} blocklist(s)`);
                  else parts.push("✓ Not blacklisted");
                  if (d.hunter?.available) parts.push(`${d.hunter.totalEmails} emails found`);
                  return parts.join(" · ");
                })()}
                defaultOpen={r.emailIntelligence?.blacklisted}
              >
                {/* DNSBL Section */}
                <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", color: "rgba(0,255,136,0.6)", letterSpacing: "0.2em", marginBottom: "10px" }}>DNS BLOCKLIST CHECK //</div>
                <StatRow label="BLACKLISTED" value={r.emailIntelligence?.dnsbl?.listed ? `YES — ${r.emailIntelligence.dnsbl.listCount} list(s)` : "NO ✓"} accent={r.emailIntelligence?.dnsbl?.listed ? "#ff4444" : "#00ff88"} />
                <StatRow label="IP ADDRESS" value={r.emailIntelligence?.dnsbl?.ip ?? "N/A"} />
                {r.emailIntelligence?.dnsbl?.listedOn?.length > 0 && (
                  <>
                    <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", color: "rgba(255,68,68,0.7)", letterSpacing: "0.2em", margin: "10px 0 6px" }}>LISTED ON //</div>
                    <TagList items={r.emailIntelligence.dnsbl.listedOn} color="#ff4444" />
                    <AlertRow text={`Domain/IP is listed on ${r.emailIntelligence.dnsbl.listCount} DNS blocklist(s) — likely associated with spam or malicious activity`} severity="critical" />
                  </>
                )}
                {r.emailIntelligence?.dnsbl?.clean && (
                  <AlertRow text="Domain and IP are clean across Spamhaus, SURBL, URIBL, Barracuda, and SpamCop" severity="info" />
                )}

                {/* Hunter.io Section */}
                {r.emailIntelligence?.hunter?.available ? (
                  <>
                    <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", color: "rgba(176,106,255,0.8)", letterSpacing: "0.2em", margin: "18px 0 10px" }}>HUNTER.IO EMAIL INTELLIGENCE //</div>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0 40px", marginBottom: "12px" }}>
                      <StatRow label="ORGANIZATION" value={r.emailIntelligence.hunter.organization ?? "Unknown"} />
                      <StatRow label="TOTAL EMAILS FOUND" value={r.emailIntelligence.hunter.totalEmails} accent="#b06aff" />
                      <StatRow label="EMAIL PATTERN" value={r.emailIntelligence.hunter.pattern ?? "Unknown"} accent="#00d4ff" />
                      <StatRow label="MX RECORD" value={r.emailIntelligence.hunter.mxRecord ?? "None"} />
                      <StatRow label="WEBMAIL" value={r.emailIntelligence.hunter.webmail ? "YES" : "NO"} />
                      <StatRow label="ACCEPT-ALL" value={r.emailIntelligence.hunter.acceptAll ? "YES ⚠" : "NO"} accent={r.emailIntelligence.hunter.acceptAll ? "#fbbf24" : "#00ff88"} />
                    </div>
                    {r.emailIntelligence.hunter.emails?.length > 0 && (
                      <>
                        <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", color: "rgba(176,106,255,0.7)", letterSpacing: "0.2em", margin: "12px 0 8px" }}>DISCOVERED EMAILS //</div>
                        {r.emailIntelligence.hunter.emails.map((e, i) => (
                          <div key={i} style={{ padding: "8px 12px", background: "rgba(176,106,255,0.04)", borderLeft: "2px solid rgba(176,106,255,0.2)", marginBottom: "6px" }}>
                            <div style={{ display: "flex", alignItems: "center", gap: "12px", flexWrap: "wrap" }}>
                              <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "11px", color: "#b06aff" }}>{e.email}</span>
                              <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", color: "rgba(0,255,136,0.5)", border: "1px solid rgba(0,255,136,0.15)", padding: "1px 6px" }}>{e.confidence}% confidence</span>
                              {e.type && <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", color: "rgba(0,212,255,0.6)" }}>{e.type}</span>}
                            </div>
                            {(e.firstName || e.position) && (
                              <div style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: "11px", color: "rgba(200,200,255,0.5)", marginTop: "4px" }}>
                                {[e.firstName, e.lastName].filter(Boolean).join(" ")}{e.position ? ` — ${e.position}` : ""}
                              </div>
                            )}
                          </div>
                        ))}
                        {r.emailIntelligence.hunter.totalEmails > 6 && (
                          <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", color: "rgba(176,106,255,0.5)", padding: "6px 12px" }}>
                            +{r.emailIntelligence.hunter.totalEmails - 6} more emails on Hunter.io
                          </div>
                        )}
                      </>
                    )}
                    {r.emailIntelligence.hunter.totalEmails === 0 && (
                      <AlertRow text="No email addresses indexed for this domain on Hunter.io" severity="info" />
                    )}
                  </>
                ) : (
                  <AlertRow text={r.emailIntelligence?.hunter?.note || "Add HUNTER_API_KEY to .env to enable email discovery"} severity="info" />
                )}
              </ModuleCard>
            </div>

            {/* ── SECTION: THREAT INTELLIGENCE ── */}
            <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", letterSpacing: "0.3em", color: "rgba(0,255,136,0.6)", marginBottom: "16px", marginTop: "40px" }}>
              {"// THREAT_INTELLIGENCE"}
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: "12px", marginBottom: "40px" }}>

              {/* Google Safe Browsing */}
              <ModuleCard
                title="Google Safe Browsing"
                icon={<FaShieldAlt style={{ color: r.safeBrowsing?.safe === false ? "#ff2222" : "#00ff88" }} />}
                risk={r.safeBrowsing?.risk ?? "LOW"}
                summary={!r.safeBrowsing?.available ? "API key not configured" : r.safeBrowsing?.safe === false ? `${r.safeBrowsing.threatCount} threat(s) detected` : "No threats detected"}
                defaultOpen={r.safeBrowsing?.safe === false}
              >
                {r.safeBrowsing?.available ? (
                  <>
                    <StatRow label="STATUS" value={r.safeBrowsing.safe ? "✓ CLEAN" : "✕ FLAGGED"} accent={r.safeBrowsing.safe ? "#00ff88" : "#ff2222"} />
                    <StatRow label="THREATS FOUND" value={r.safeBrowsing.threatCount ?? 0} accent={r.safeBrowsing.threatCount > 0 ? "#ff2222" : "#00ff88"} />
                    {r.safeBrowsing.threats?.length > 0 && (
                      <>
                        <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", color: "rgba(255,34,34,0.7)", letterSpacing: "0.2em", margin: "12px 0 8px" }}>THREAT TYPES //</div>
                        <TagList items={r.safeBrowsing.threats} color="#ff4444" />
                        <AlertRow text="Domain flagged by Google Safe Browsing — high risk to visitors" severity="critical" />
                      </>
                    )}
                    {r.safeBrowsing.safe && <AlertRow text="Domain is not flagged in Google's threat database" severity="info" />}
                  </>
                ) : <AlertRow text={r.safeBrowsing?.note || "Add GOOGLE_SAFE_BROWSING_KEY to .env to enable"} severity="info" />}
              </ModuleCard>

              {/* VirusTotal */}
              <ModuleCard
                title="VirusTotal Domain Report"
                icon={<FaVirus style={{ color: r.virusTotal?.malicious > 0 ? "#ff6b35" : "#00ff88" }} />}
                risk={r.virusTotal?.risk ?? "LOW"}
                summary={!r.virusTotal?.available ? "API key not configured" : `${r.virusTotal?.malicious ?? 0}/${r.virusTotal?.total ?? 0} engines flagged`}
                defaultOpen={r.virusTotal?.malicious > 0}
              >
                {r.virusTotal?.available ? (
                  <>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0 40px", marginBottom: "16px" }}>
                      <StatRow label="MALICIOUS" value={r.virusTotal.malicious} accent={r.virusTotal.malicious > 0 ? "#ff4444" : "#00ff88"} />
                      <StatRow label="SUSPICIOUS" value={r.virusTotal.suspicious} accent={r.virusTotal.suspicious > 0 ? "#fbbf24" : "#00ff88"} />
                      <StatRow label="HARMLESS" value={r.virusTotal.harmless} accent="#00ff88" />
                      <StatRow label="TOTAL ENGINES" value={r.virusTotal.total} />
                      <StatRow label="COMMUNITY SCORE" value={r.virusTotal.communityScore} accent={r.virusTotal.communityScore < 0 ? "#ff6b35" : "#00ff88"} />
                      <StatRow label="LAST ANALYSIS" value={r.virusTotal.lastAnalysis ?? "N/A"} />
                    </div>
                    {r.virusTotal.categories?.length > 0 && (
                      <>
                        <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", color: "rgba(0,255,136,0.6)", letterSpacing: "0.2em", margin: "12px 0 8px" }}>CATEGORIES //</div>
                        <TagList items={r.virusTotal.categories} color="#00d4ff" />
                      </>
                    )}
                    {r.virusTotal.popularity?.length > 0 && (
                      <>
                        <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", color: "rgba(0,255,136,0.6)", letterSpacing: "0.2em", margin: "12px 0 8px" }}>POPULARITY RANKINGS //</div>
                        <TagList items={r.virusTotal.popularity} color="#b06aff" />
                      </>
                    )}
                    {r.virusTotal.malicious > 0 && <AlertRow text={`${r.virusTotal.malicious} security vendors flagged this domain as malicious`} severity="critical" />}
                  </>
                ) : <AlertRow text={r.virusTotal?.note || "Add VIRUSTOTAL_API_KEY to .env to enable"} severity={r.virusTotal?.warn ? "warn" : "info"} />}
              </ModuleCard>

              {/* Shodan */}
              <ModuleCard
                title="Shodan Intelligence"
                icon={<FaEye style={{ color: r.shodan?.kevCount > 0 ? "#ff2222" : r.shodan?.vulnCount > 0 ? "#ff6b35" : "#00d4ff" }} />}
                risk={r.shodan?.risk ?? "LOW"}
                summary={!r.shodan?.available ? (r.shodan?.note || "API key not configured") : r.shodan?.note ? r.shodan.note.substring(0, 60) + "..." : `${r.shodan?.portCount ?? 0} ports · ${r.shodan?.vulnCount ?? 0} CVEs${r.shodan?.kevCount > 0 ? ` · ${r.shodan.kevCount} KEV` : ""}`}
                defaultOpen={r.shodan?.vulnCount > 0}
              >
                {r.shodan?.available && !r.shodan?.note ? (
                  <>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0 40px", marginBottom: "16px" }}>
                      <StatRow label="IP" value={r.shodan.ip ?? "N/A"} />
                      <StatRow label="ORG" value={r.shodan.org ?? "Unknown"} />
                      <StatRow label="ISP" value={r.shodan.isp ?? "Unknown"} />
                      <StatRow label="ASN" value={r.shodan.asn ?? "N/A"} />
                      <StatRow label="LOCATION" value={r.shodan.city && r.shodan.country ? `${r.shodan.city}, ${r.shodan.country}` : "Unknown"} />
                      <StatRow label="LAST SEEN" value={r.shodan.lastSeen?.split("T")[0] ?? "N/A"} />
                      <StatRow label="OPEN PORTS" value={r.shodan.portCount} accent={r.shodan.portCount > 5 ? "#fbbf24" : "#00ff88"} />
                      <StatRow label="TOTAL CVEs" value={r.shodan.vulnCount} accent={r.shodan.vulnCount > 0 ? "#ff4444" : "#00ff88"} />
                      <StatRow label="CRITICAL CVEs (9+)" value={r.shodan.criticalCount ?? 0} accent={r.shodan.criticalCount > 0 ? "#ff2222" : "#00ff88"} />
                      <StatRow label="CISA KEV COUNT" value={r.shodan.kevCount ?? 0} accent={r.shodan.kevCount > 0 ? "#ff2222" : "#00ff88"} />
                    </div>
                    {r.shodan.tags?.length > 0 && (
                      <>
                        <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", color: "rgba(0,255,136,0.6)", letterSpacing: "0.2em", margin: "8px 0 6px" }}>SHODAN TAGS //</div>
                        <TagList items={r.shodan.tags} color="#b06aff" />
                      </>
                    )}
                    {r.shodan.hostnames?.length > 0 && (
                      <>
                        <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", color: "rgba(0,255,136,0.6)", letterSpacing: "0.2em", margin: "12px 0 6px" }}>HOSTNAMES //</div>
                        <TagList items={r.shodan.hostnames} color="#00d4ff" />
                      </>
                    )}
                    {r.shodan.ports?.length > 0 && (
                      <>
                        <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", color: "rgba(0,255,136,0.6)", letterSpacing: "0.2em", margin: "12px 0 6px" }}>OPEN PORTS //</div>
                        <TagList items={r.shodan.ports.map(String)} color="#00d4ff" />
                      </>
                    )}
                    {r.shodan.vulnDetails?.length > 0 && (
                      <>
                        <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", color: "rgba(255,68,68,0.9)", letterSpacing: "0.2em", margin: "16px 0 10px" }}>CVE DETAILS //</div>
                        <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                          {r.shodan.vulnDetails.map((cve, i) => {
                            const cvssColor = cve.cvss >= 9 ? "#ff2222" : cve.cvss >= 7 ? "#ff6b35" : "#fbbf24";
                            return (
                              <div key={i} style={{ padding: "10px 14px", background: "rgba(255,34,34,0.04)", border: "1px solid rgba(255,34,34,0.12)", borderLeft: `3px solid ${cvssColor}` }}>
                                <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "6px", flexWrap: "wrap" }}>
                                  <span style={{ fontFamily: "'Orbitron', monospace", fontSize: "11px", color: cvssColor, fontWeight: 700 }}>{cve.id}</span>
                                  {cve.cvss && <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", color: cvssColor, border: `1px solid ${cvssColor}40`, padding: "1px 6px" }}>CVSS {cve.cvss}</span>}
                                  {cve.epss && <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", color: "#fbbf24", border: "1px solid rgba(251,191,36,0.3)", padding: "1px 6px" }}>EPSS {cve.epss}%</span>}
                                  {cve.kev && <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", color: "#ff2222", border: "1px solid rgba(255,34,34,0.4)", padding: "1px 6px", background: "rgba(255,34,34,0.1)" }}>⚠ CISA KEV</span>}
                                </div>
                                {cve.summary && <div style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: "12px", color: "rgba(200,255,200,0.6)", lineHeight: 1.5 }}>{cve.summary}{cve.summary.length >= 180 ? "..." : ""}</div>}
                              </div>
                            );
                          })}
                        </div>
                        {r.shodan.kevCount > 0 && <AlertRow text={`${r.shodan.kevCount} CVE(s) are on CISA's Known Exploited Vulnerabilities catalog — actively exploited in the wild`} severity="critical" />}
                      </>
                    )}
                    {r.shodan.banners?.length > 0 && (
                      <>
                        <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", color: "rgba(0,255,136,0.6)", letterSpacing: "0.2em", margin: "12px 0 6px" }}>SERVICE BANNERS //</div>
                        {r.shodan.banners.map((b, i) => (
                          <div key={i} style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", color: "rgba(0,255,136,0.7)", padding: "6px 10px", background: "rgba(0,255,136,0.03)", borderLeft: "2px solid rgba(0,255,136,0.15)", marginBottom: "4px" }}>
                            <span style={{ color: "#00d4ff" }}>:{b.port}</span>
                            {b.product && <span style={{ color: "#fbbf24", marginLeft: "8px" }}>{b.product} {b.version}</span>}
                          </div>
                        ))}
                      </>
                    )}
                  </>
                ) : <AlertRow text={r.shodan?.note || "Add SHODAN_API_KEY to .env to enable"} severity="info" />}
              </ModuleCard>

              
            </div>

            {/* ── SECTION: HOST INTELLIGENCE ── */}
            <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", letterSpacing: "0.3em", color: "rgba(0,255,136,0.6)", marginBottom: "16px" }}>
              {"// HOST_INTELLIGENCE"}
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: "12px", marginBottom: "48px" }}>

              {/* ASN & Geolocation */}
              <ModuleCard
                title="ASN & IP Geolocation"
                icon={<FaMapMarkerAlt style={{ color: "#00d4ff" }} />}
                risk={r.asnGeo?.risk ?? "LOW"}
                summary={r.asnGeo?.available ? `${r.asnGeo.city ?? "Unknown city"}, ${r.asnGeo.country ?? "Unknown country"} · ${r.asnGeo.org ?? "Unknown org"}` : "Geolocation unavailable"}
              >
                {r.asnGeo?.available ? (
                  <>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0 40px", marginBottom: "12px" }}>
                      <StatRow label="IP ADDRESS" value={r.asnGeo.ip ?? "N/A"} />
                      <StatRow label="COUNTRY" value={r.asnGeo.country ? `${r.asnGeo.country} (${r.asnGeo.countryCode})` : "Unknown"} />
                      <StatRow label="CITY" value={r.asnGeo.city ?? "Unknown"} />
                      <StatRow label="REGION" value={r.asnGeo.region ?? "Unknown"} />
                      <StatRow label="ISP" value={r.asnGeo.isp ?? "Unknown"} />
                      <StatRow label="ORG" value={r.asnGeo.org ?? "Unknown"} />
                      <StatRow label="ASN" value={r.asnGeo.asn ?? "N/A"} />
                      <StatRow label="TIMEZONE" value={r.asnGeo.timezone ?? "Unknown"} />
                      <StatRow label="CLOUD HOSTED" value={r.asnGeo.isCloud ? `YES — ${r.asnGeo.cloudProvider}` : "NO"} accent={r.asnGeo.isCloud ? "#00d4ff" : "rgba(0,255,136,0.7)"} />
                      <StatRow label="COORDINATES" value={r.asnGeo.latitude ? `${r.asnGeo.latitude}, ${r.asnGeo.longitude}` : "N/A"} />
                    </div>
                    {r.asnGeo.isCloud && <AlertRow text={`Hosted on cloud infrastructure (${r.asnGeo.cloudProvider}) — shared IP space possible`} severity="info" />}
                  </>
                ) : <AlertRow text={r.asnGeo?.note || "Geolocation lookup failed"} severity="info" />}
              </ModuleCard>

              {/* HTTP Cookies */}
              <ModuleCard
                title="HTTP Cookies Analysis"
                icon={<FaCookieBite style={{ color: r.cookies?.issues?.length > 0 ? "#fbbf24" : "#00ff88" }} />}
                risk={r.cookies?.risk ?? "LOW"}
                summary={r.cookies?.available ? `${r.cookies.cookieCount} cookie(s) · ${r.cookies.issues?.length ?? 0} security issue(s)` : "Analysis unavailable"}
                defaultOpen={r.cookies?.issues?.length > 0}
              >
                {r.cookies?.available ? (
                  <>
                    <StatRow label="COOKIES SET" value={r.cookies.cookieCount} />
                    <StatRow label="SECURITY ISSUES" value={r.cookies.issues?.length ?? 0} accent={r.cookies.issues?.length > 0 ? "#fbbf24" : "#00ff88"} />
                    {r.cookies.cookies?.length > 0 && (
                      <>
                        <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", color: "rgba(0,255,136,0.6)", letterSpacing: "0.2em", margin: "12px 0 8px" }}>COOKIE FLAGS //</div>
                        {r.cookies.cookies.map((c, i) => (
                          <div key={i} style={{ padding: "8px 12px", background: "rgba(0,255,136,0.03)", borderLeft: "2px solid rgba(0,255,136,0.1)", marginBottom: "6px", display: "flex", gap: "16px", flexWrap: "wrap", alignItems: "center" }}>
                            <span style={{ fontFamily: "'Orbitron', monospace", fontSize: "10px", color: "#e8ffe8" }}>{c.name}</span>
                            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", color: c.secure ? "#00ff88" : "#ff4444" }}>SECURE:{c.secure ? "✓" : "✕"}</span>
                            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", color: c.httpOnly ? "#00ff88" : "#ff4444" }}>HTTPONLY:{c.httpOnly ? "✓" : "✕"}</span>
                            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", color: c.sameSite ? "#00ff88" : "#fbbf24" }}>SAMESITE:{c.sameSite ?? "✕"}</span>
                          </div>
                        ))}
                      </>
                    )}
                    {r.cookies.issues?.length > 0 && (
                      <>
                        <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", color: "rgba(251,191,36,0.7)", letterSpacing: "0.2em", margin: "12px 0 8px" }}>ISSUES //</div>
                        {r.cookies.issues.slice(0, 6).map((issue, i) => <AlertRow key={i} text={issue} severity="warn" />)}
                      </>
                    )}
                    {r.cookies.cookieCount === 0 && <AlertRow text="No cookies set by server on initial request" severity="info" />}
                  </>
                ) : <AlertRow text={r.cookies?.note || "Cookie analysis failed"} severity="info" />}
              </ModuleCard>

              {/* Green Web Check */}
              <ModuleCard
                title="Carbon / Green Hosting"
                icon={<FaLeaf style={{ color: r.greenWeb?.green ? "#00ff88" : "rgba(0,255,136,0.3)" }} />}
                risk="LOW"
                summary={r.greenWeb?.available ? (r.greenWeb.green ? `✓ Green hosted by ${r.greenWeb.hostedBy ?? "verified provider"}` : "Not verified as green hosted") : "Check unavailable"}
              >
                {r.greenWeb?.available ? (
                  <>
                    <StatRow label="GREEN HOSTED" value={r.greenWeb.green ? "✓ VERIFIED" : "✕ NOT VERIFIED"} accent={r.greenWeb.green ? "#00ff88" : "rgba(0,255,136,0.4)"} />
                    <StatRow label="HOSTED BY" value={r.greenWeb.hostedBy ?? "Unknown"} />
                    {r.greenWeb.hostedByWebsite && <StatRow label="PROVIDER SITE" value={r.greenWeb.hostedByWebsite} />}
                    {r.greenWeb.green
                      ? <AlertRow text={`Verified renewable energy hosting: ${r.greenWeb.hostedBy}`} severity="info" />
                      : <AlertRow text="Host not verified as using renewable energy by The Green Web Foundation" severity="info" />
                    }
                  </>
                ) : <AlertRow text={r.greenWeb?.note || "Green web check unavailable"} severity="info" />}
              </ModuleCard>
            </div>

            {/* PDF Download */}
            <div style={{ textAlign: "center", padding: "40px 0", borderTop: "1px solid rgba(0,255,136,0.07)" }}>
              <button onClick={downloadPDF} disabled={isDownloading}
                style={{ fontFamily: "'Orbitron', monospace", fontWeight: 700, fontSize: "11px", letterSpacing: "0.18em", textTransform: "uppercase", color: isDownloading ? "rgba(0,255,136,0.4)" : "#020804", background: isDownloading ? "rgba(0,255,136,0.08)" : "#00ff88", border: isDownloading ? "1px solid rgba(0,255,136,0.2)" : "none", padding: "16px 36px", cursor: isDownloading ? "not-allowed" : "pointer", display: "inline-flex", alignItems: "center", gap: "10px", boxShadow: isDownloading ? "none" : "0 0 24px rgba(0,255,136,0.3)" }}
                onMouseEnter={e => { if (!isDownloading) e.currentTarget.style.transform = "translateY(-2px)"; }}
                onMouseLeave={e => { e.currentTarget.style.transform = "translateY(0)"; }}>
                <FaFileDownload /> {isDownloading ? "PREPARING REPORT..." : "DOWNLOAD PDF REPORT"}
              </button>
              <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", color: "rgba(0,255,136,0.5)", marginTop: "12px", letterSpacing: "0.1em" }}>
                Includes full findings, evidence & remediation guidance
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}