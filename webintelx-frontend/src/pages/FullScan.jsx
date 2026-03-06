import { useState, useRef } from "react";
import axios from "axios";
import {
  FaSearch, FaFingerprint, FaNetworkWired, FaBug,
  FaUserSecret, FaListUl, FaFileDownload,
} from "react-icons/fa";

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
  return <div style={{ position: "fixed", inset: 0, pointerEvents: "none", zIndex: 1, background: "repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,255,136,0.012) 2px, rgba(0,255,136,0.012) 4px)" }} />;
}

const riskAccent = (risk) => {
  const r = (risk || "").toUpperCase();
  if (r === "CRITICAL") return "#ff2222";
  if (r === "HIGH") return "#ff6b35";
  if (r === "MEDIUM") return "#fbbf24";
  return "#00ff88";
};

/* ── CAPABILITY CARD ── */
const CapabilityCard = ({ icon, title, desc, accent }) => (
  <div style={{
    background: "rgba(0,0,0,0.55)", border: "1px solid rgba(0,255,136,0.08)",
    borderLeft: `3px solid ${accent}`, padding: "24px", position: "relative", overflow: "hidden",
  }}>
    <div style={{ position: "absolute", top: 0, right: 0, width: 0, height: 0, borderStyle: "solid", borderWidth: "0 28px 28px 0", borderColor: `transparent ${accent}18 transparent transparent` }} />
    <div style={{ display: "flex", alignItems: "flex-start", gap: "16px" }}>
      <div style={{ fontSize: "20px", marginTop: "2px", filter: `drop-shadow(0 0 6px ${accent})`, flexShrink: 0 }}>{icon}</div>
      <div>
        <h4 style={{ fontFamily: "'Orbitron', monospace", fontWeight: 600, fontSize: "13px", color: "#e8ffe8", marginBottom: "8px", letterSpacing: "0.04em" }}>{title}</h4>
        <p style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: "14px", color: "rgba(180,255,180,0.45)", lineHeight: 1.65 }}>{desc}</p>
      </div>
    </div>
  </div>
);

/* ── MODULE BLOCK ── */
const ModuleBlock = ({ keyName, title, found, expanded, onToggle, children }) => (
  <div style={{
    background: "rgba(0,0,0,0.55)",
    border: `1px solid ${found ? "rgba(255,107,53,0.25)" : "rgba(0,255,136,0.1)"}`,
    borderLeft: `3px solid ${found ? "#ff6b35" : "#00ff88"}`,
    marginBottom: "12px", overflow: "hidden",
  }}>
    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "18px 24px" }}>
      <div style={{ display: "flex", alignItems: "center", gap: "14px" }}>
        <span style={{
          fontFamily: "'Orbitron', monospace", fontWeight: 700, fontSize: "9px",
          letterSpacing: "0.15em", padding: "4px 10px",
          background: found ? "rgba(255,107,53,0.15)" : "rgba(0,255,136,0.1)",
          border: `1px solid ${found ? "#ff6b3540" : "#00ff8840"}`,
          color: found ? "#ff6b35" : "#00ff88",
        }}>
          {found ? "VULNERABLE" : "NOT FOUND"}
        </span>
        <h4 style={{ fontFamily: "'Orbitron', monospace", fontWeight: 600, fontSize: "13px", color: "#e8ffe8", letterSpacing: "0.04em" }}>{title}</h4>
      </div>
      <button
        onClick={() => onToggle(keyName)}
        style={{
          fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", letterSpacing: "0.12em",
          color: "rgba(0,255,136,0.6)", background: "rgba(0,255,136,0.06)",
          border: "1px solid rgba(0,255,136,0.15)", padding: "6px 14px",
          cursor: "pointer", transition: "all 0.2s",
        }}
        onMouseEnter={e => { e.target.style.color = "#00ff88"; e.target.style.borderColor = "#00ff88"; }}
        onMouseLeave={e => { e.target.style.color = "rgba(0,255,136,0.6)"; e.target.style.borderColor = "rgba(0,255,136,0.15)"; }}
      >
        {expanded ? "▲ HIDE" : "▼ DETAILS"}
      </button>
    </div>
    {expanded && (
      <div style={{ padding: "0 24px 22px", borderTop: "1px solid rgba(0,255,136,0.07)", paddingTop: "18px" }}>
        <div style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: "14px", color: "rgba(180,255,180,0.6)", lineHeight: 1.7 }}>
          {children}
        </div>
      </div>
    )}
  </div>
);

export default function FullScan() {
  const [input, setInput] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [scanDone, setScanDone] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [expanded, setExpanded] = useState({});
  const [error, setError] = useState(null);
  const [showRawDomFindings, setShowRawDomFindings] = useState(false);
  const loaderRef = useRef(null);

  const handleScan = async () => {
    if (!input.trim()) return alert("Please enter a domain or company name");
    setIsScanning(true); setScanDone(false); setScanResult(null); setError(null);
    setTimeout(() => loaderRef.current?.scrollIntoView({ behavior: "smooth" }), 100);
    try {
      const resp = await axios.post("http://localhost:5000/api/fullscan", { url: input }, { timeout: 0 });
      setScanResult(resp.data); setScanDone(true);
    } catch (err) {
      setError(err.response ? err.response.data.error || "Invalid target" : "Backend not reachable or network error.");
    } finally { setIsScanning(false); }
  };

  const downloadPDF = async () => {
    const resp = await axios.post("/api/fullscan/pdf", { scanData: scanResult, target: scanResult.target }, { responseType: "blob" });
    const blob = new Blob([resp.data], { type: "application/pdf" });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `FullScan-${scanResult.target}.pdf`; a.click();
  };

  const toggle = (key) => setExpanded(s => ({ ...s, [key]: !s[key] }));

  const capabilities = [
    { icon: <FaUserSecret style={{ color: "#b06aff" }} />, title: "Deep OSINT Enumeration", desc: "Scrapes public records, social sources, leak databases, DNS history, WHOIS, emails & metadata.", accent: "#b06aff" },
    { icon: <FaNetworkWired style={{ color: "#00ff88" }} />, title: "Infrastructure Reconnaissance", desc: "Maps subdomains, servers, CDN layers, firewalls, hosting providers & entry points.", accent: "#00ff88" },
    { icon: <FaBug style={{ color: "#ff6b35" }} />, title: "Vulnerability Assessment", desc: "Detects SQLi, XSS (DOM/Stored/Reflected), Clickjacking, Command Injection & exposed sensitive files.", accent: "#ff6b35" },
    { icon: <FaFingerprint style={{ color: "#fbbf24" }} />, title: "Technology Fingerprinting", desc: "Identifies CMS, frameworks, JS libraries, outdated components & vulnerable versions.", accent: "#fbbf24" },
    { icon: <FaListUl style={{ color: "#00d4ff" }} />, title: "Port & Service Mapping", desc: "Performs deep port scans to fingerprint running services & detect outdated servers.", accent: "#00d4ff" },
    { icon: <FaSearch style={{ color: "#00ff88" }} />, title: "Malware & Phishing Indicators", desc: "Scans domain reputation, blocklists, suspicious redirects & malware hosting markers.", accent: "#00ff88" },
  ];

  return (
    <div style={{ backgroundColor: "#020804", minHeight: "100vh", color: "#e8ffe8", overflowX: "hidden", cursor: "crosshair" }}>
      <link rel="stylesheet" href={FONT_URL} />
      <style>{`
        @keyframes pulse { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:0.3;transform:scale(0.75)} }
        @keyframes fadeUp { from{opacity:0;transform:translateY(24px)} to{opacity:1;transform:translateY(0)} }
        @keyframes spin { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }
        @keyframes scanPulse { 0%,100%{opacity:0.5} 50%{opacity:1} }
        @keyframes flicker { 0%,89%,91%,96%,100%{opacity:1} 90%{opacity:0.5} 95%{opacity:0.75} }
        * { box-sizing:border-box; margin:0; padding:0; }
        ::selection { background:rgba(0,255,136,0.2); color:#00ff88; }
        ::-webkit-scrollbar { width:3px; }
        ::-webkit-scrollbar-track { background:#010502; }
        ::-webkit-scrollbar-thumb { background:#00ff8855; }
        pre { white-space: pre-wrap; font-family: 'Share Tech Mono', monospace; font-size: 11px; color: rgba(0,255,136,0.6); }
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
          <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", color: "rgba(255,107,53,0.6)", letterSpacing: "0.15em" }}>FULL_SCAN // MODULE_02</span>
          <div style={{ width: "7px", height: "7px", background: isScanning ? "#fbbf24" : "#ff6b35", borderRadius: "50%", boxShadow: `0 0 10px ${isScanning ? "#fbbf24" : "#ff6b35"}`, animation: "pulse 2s ease-in-out infinite" }} />
          <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", color: isScanning ? "#fbbf24" : "#ff6b35", letterSpacing: "0.15em" }}>
            {isScanning ? "DEEP_SCANNING..." : "READY"}
          </span>
        </div>
      </nav>

      <div style={{ position: "relative", zIndex: 2, maxWidth: "1100px", margin: "0 auto", padding: "120px 40px 80px" }}>

        {/* Header */}
        <div style={{ marginBottom: "52px", animation: "fadeUp 0.6s ease 0.1s both" }}>
          <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", letterSpacing: "0.35em", color: "rgba(255,107,53,0.5)", marginBottom: "14px" }}>// MODULE_02 / FULL_SCAN</div>
          <h1 style={{ fontFamily: "'Orbitron', monospace", fontWeight: 900, fontSize: "clamp(28px, 4vw, 52px)", color: "#e8ffe8", letterSpacing: "0.04em", lineHeight: 1.1, marginBottom: "16px" }}>
            FULL <span style={{ color: "#ff6b35" }}>SCAN</span>
          </h1>
          <p style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: "17px", color: "rgba(180,255,180,0.5)", lineHeight: 1.7, maxWidth: "580px" }}>
            Deep OSINT + Reconnaissance + Vulnerability Assessment for complete intelligence on your target surface.
          </p>
          <div style={{ width: "48px", height: "2px", background: "#ff6b35", marginTop: "18px", boxShadow: "0 0 10px rgba(255,107,53,0.5)" }} />
        </div>

        {/* Capabilities Grid */}
        <div style={{ marginBottom: "56px", animation: "fadeUp 0.6s ease 0.2s both" }}>
          <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", letterSpacing: "0.3em", color: "rgba(0,255,136,0.38)", marginBottom: "20px" }}>// WHAT_FULL_SCAN_INCLUDES</div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))", gap: "14px" }}>
            {capabilities.map((c, i) => <CapabilityCard key={i} {...c} />)}
          </div>
        </div>

        {/* Input Card */}
        <div style={{ background: "rgba(0,0,0,0.7)", border: "1px solid rgba(255,107,53,0.2)", borderTop: "2px solid #ff6b35", padding: "36px", maxWidth: "600px", marginBottom: "32px", animation: "fadeUp 0.6s ease 0.3s both", position: "relative", overflow: "hidden" }}>
          <div style={{ position: "absolute", top: 0, right: 0, width: 0, height: 0, borderStyle: "solid", borderWidth: "0 40px 40px 0", borderColor: "transparent rgba(255,107,53,0.15) transparent transparent" }} />
          <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", color: "rgba(255,107,53,0.5)", letterSpacing: "0.25em", marginBottom: "20px" }}>
            TARGET_INPUT // DOMAIN_OR_URL
          </div>
          <label style={{ fontFamily: "'Orbitron', monospace", fontSize: "12px", letterSpacing: "0.1em", color: "#e8ffe8", display: "block", marginBottom: "12px" }}>
            ENTER DOMAIN OR URL
          </label>
          <div style={{ display: "flex", gap: "12px", flexWrap: "wrap" }}>
            <input
              type="text" value={input}
              onChange={e => setInput(e.target.value)}
              placeholder="example.com or company"
              onKeyDown={e => e.key === "Enter" && handleScan()}
              style={{
                flex: "1 1 240px", padding: "12px 16px",
                background: "rgba(0,0,0,0.8)", border: "1px solid rgba(255,107,53,0.25)",
                color: "#ff6b35", fontFamily: "'Share Tech Mono', monospace", fontSize: "13px",
                outline: "none", letterSpacing: "0.05em", transition: "border-color 0.2s",
              }}
              onFocus={e => e.target.style.borderColor = "#ff6b35"}
              onBlur={e => e.target.style.borderColor = "rgba(255,107,53,0.25)"}
            />
            <button
              onClick={handleScan}
              style={{
                fontFamily: "'Orbitron', monospace", fontWeight: 700, fontSize: "11px",
                letterSpacing: "0.18em", color: "#020804", background: "#ff6b35", border: "none",
                padding: "12px 28px", cursor: "pointer", textTransform: "uppercase",
                transition: "all 0.25s", display: "flex", alignItems: "center", gap: "8px",
                boxShadow: "0 0 20px rgba(255,107,53,0.25)",
              }}
              onMouseEnter={e => { e.currentTarget.style.background = "#ff8c5a"; e.currentTarget.style.transform = "translateY(-2px)"; }}
              onMouseLeave={e => { e.currentTarget.style.background = "#ff6b35"; e.currentTarget.style.transform = "translateY(0)"; }}
            >
              <FaSearch style={{ fontSize: "12px" }} /> START SCAN
            </button>
          </div>
        </div>

        {/* Error */}
        {error && (
          <div style={{ maxWidth: "600px", marginBottom: "24px", padding: "14px 20px", background: "rgba(255,34,34,0.08)", border: "1px solid rgba(255,34,34,0.25)", borderLeft: "3px solid #ff2222", fontFamily: "'Share Tech Mono', monospace", fontSize: "11px", color: "#ff6b6b", letterSpacing: "0.1em" }}>
            ✕ ERROR: {error}
          </div>
        )}

        {/* Loader */}
        {isScanning && (
          <div ref={loaderRef} style={{ marginBottom: "40px" }}>
            <div style={{ background: "rgba(0,0,0,0.6)", border: "1px solid rgba(255,107,53,0.2)", borderLeft: "3px solid #ff6b35", padding: "28px 32px", maxWidth: "600px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "16px", marginBottom: "18px" }}>
                <div style={{ width: "20px", height: "20px", border: "2px solid rgba(255,107,53,0.2)", borderTop: "2px solid #ff6b35", borderRadius: "50%", animation: "spin 0.8s linear infinite" }} />
                <span style={{ fontFamily: "'Orbitron', monospace", fontWeight: 700, fontSize: "14px", color: "#ff6b35", letterSpacing: "0.1em" }}>RUNNING DEEP SCAN</span>
              </div>
              <p style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "11px", color: "rgba(0,255,136,0.4)", marginBottom: "16px", letterSpacing: "0.1em" }}>This may take several minutes</p>
              {["Enumerating subdomains & infrastructure...", "Running OSINT correlation...", "Testing for SQL injection vectors...", "Scanning XSS attack surfaces...", "Checking CSRF, clickjacking, command injection...", "Generating vulnerability report..."].map((line, i) => (
                <div key={i} style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "11px", color: "rgba(255,107,53,0.5)", lineHeight: 1.9, letterSpacing: "0.08em", animation: `scanPulse 2s ease ${i * 0.4}s infinite` }}>
                  › {line}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* RESULTS */}
        {scanDone && !isScanning && (
          <div style={{ animation: "fadeUp 0.6s ease both" }}>

            {/* Completion Banner */}
            <div style={{ background: "rgba(0,255,136,0.04)", border: "1px solid rgba(0,255,136,0.2)", borderLeft: "4px solid #00ff88", padding: "24px 32px", marginBottom: "32px", position: "relative", overflow: "hidden" }}>
              <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: "1px", background: "linear-gradient(90deg, #00ff88, transparent)" }} />
              <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", letterSpacing: "0.3em", color: "rgba(0,255,136,0.4)", marginBottom: "8px" }}>// SCAN_COMPLETE</div>
              <h2 style={{ fontFamily: "'Orbitron', monospace", fontWeight: 700, fontSize: "22px", color: "#00ff88", letterSpacing: "0.06em" }}>FULL SCAN COMPLETED</h2>
              <p style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: "15px", color: "rgba(180,255,180,0.5)", marginTop: "8px" }}>
                Complete breakdown of vulnerabilities and exposed assets below.
              </p>
            </div>

            {/* Scan Meta */}
            <div style={{ background: "rgba(0,0,0,0.55)", border: "1px solid rgba(0,255,136,0.1)", padding: "20px 24px", marginBottom: "24px", fontFamily: "'Share Tech Mono', monospace", fontSize: "11px", lineHeight: 2 }}>
              {[
                { label: "TARGET", val: (scanResult?.target || input), color: "#00d4ff" },
                { label: "STARTED", val: scanResult?.meta?.startedAt ? new Date(scanResult.meta.startedAt).toLocaleString() : "—", color: "#fbbf24" },
                { label: "COMPLETED", val: scanResult?.meta?.completedAt ? new Date(scanResult.meta.completedAt).toLocaleString() : "—", color: "#fbbf24" },
                { label: "DURATION", val: (scanResult?.meta?.startedAt && scanResult?.meta?.completedAt) ? `${Math.max(0, (new Date(scanResult.meta.completedAt) - new Date(scanResult.meta.startedAt)) / 1000).toFixed(0)}s` : "—", color: "#00ff88" },
              ].map((m, i) => (
                <div key={i} style={{ color: "rgba(0,255,136,0.4)" }}>
                  › <span style={{ color: "rgba(0,255,136,0.6)" }}>{m.label}:</span> <span style={{ color: m.color }}>{m.val}</span>
                </div>
              ))}
            </div>

            {/* Risk Summary */}
            <div style={{ display: "flex", gap: "12px", flexWrap: "wrap", marginBottom: "36px" }}>
              {[
                { label: "CRITICAL", val: scanResult?.summary?.critical ?? 0, color: "#ff2222" },
                { label: "HIGH", val: scanResult?.summary?.high ?? 0, color: "#ff6b35" },
                { label: "MEDIUM", val: scanResult?.summary?.medium ?? 0, color: "#fbbf24" },
                { label: "LOW", val: scanResult?.summary?.low ?? 0, color: "#00ff88" },
              ].map((s, i) => (
                <div key={i} style={{ flex: "1 1 120px", background: "rgba(0,0,0,0.55)", border: `1px solid ${s.color}25`, borderTop: `2px solid ${s.color}`, padding: "16px 20px" }}>
                  <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", letterSpacing: "0.2em", color: "rgba(0,255,136,0.35)", marginBottom: "8px" }}>{s.label}</div>
                  <div style={{ fontFamily: "'Orbitron', monospace", fontWeight: 700, fontSize: "28px", color: s.color, lineHeight: 1, textShadow: `0 0 20px ${s.color}40` }}>{s.val}</div>
                </div>
              ))}
            </div>

            {/* Quick Scan Summary */}
            <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", letterSpacing: "0.3em", color: "rgba(0,255,136,0.38)", marginBottom: "16px" }}>
              // QUICK_SCAN_SUMMARY
            </div>
            <div style={{ background: "rgba(0,0,0,0.55)", border: "1px solid rgba(0,255,136,0.1)", padding: "20px 24px", marginBottom: "36px", fontFamily: "'Share Tech Mono', monospace", fontSize: "11px", lineHeight: 2 }}>
              {[
                { label: "SUBDOMAINS_DISCOVERED", val: scanResult?.quickscan?.attackSurface?.subdomainCount ?? 0, color: "#00d4ff" },
                { label: "PARAMETERIZED_ENDPOINTS", val: scanResult?.quickscan?.attackSurface?.endpointCount ?? 0, color: "#00d4ff" },
                { label: "OPEN_PORTS", val: scanResult?.quickscan?.attackSurface?.openPorts ?? 0, color: "#fbbf24" },
                { label: "BACKEND_TECH", val: scanResult?.quickscan?.technology?.backend ?? "Unknown", color: "#00ff88" },
                { label: "SSL_ENABLED", val: scanResult?.quickscan?.technology?.ssl ? "YES" : "NO", color: scanResult?.quickscan?.technology?.ssl ? "#00ff88" : "#ff6b35" },
              ].map((m, i) => (
                <div key={i} style={{ color: "rgba(0,255,136,0.4)" }}>
                  › <span style={{ color: "rgba(0,255,136,0.55)" }}>{m.label}:</span> <span style={{ color: m.color }}>{m.val}</span>
                </div>
              ))}
            </div>

            {/* Vulnerability Results */}
            <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", letterSpacing: "0.3em", color: "rgba(255,107,53,0.5)", marginBottom: "20px" }}>
              // VULNERABILITY_ASSESSMENT_RESULTS
            </div>

            {(() => {
              const v = scanResult?.vulnerabilities || {};

              const DetailText = ({ children }) => (
                <div style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: "14px", color: "rgba(180,255,180,0.55)", lineHeight: 1.7 }}>{children}</div>
              );
              const DetailMono = ({ children }) => (
                <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "11px", color: "rgba(0,255,136,0.5)", lineHeight: 1.8 }}>{children}</div>
              );
              const Label = ({ children, color = "#fbbf24" }) => (
                <span style={{ color, fontFamily: "'Share Tech Mono', monospace", fontSize: "11px" }}>{children}</span>
              );

              return (
                <div>
                  {/* SQL Injection */}
                  <ModuleBlock keyName="sql" title="SQL INJECTION" found={!!v.sqlInjection?.found} expanded={expanded.sql} onToggle={toggle}>
                    {v.sqlInjection?.details?.findings?.length > 0 ? (
                      v.sqlInjection.details.findings.map((f, i) => (
                        <div key={i} style={{ marginBottom: "14px", paddingLeft: "12px", borderLeft: "2px solid rgba(255,107,53,0.3)" }}>
                          <DetailMono>› Endpoint: <Label color="#00d4ff">{f.url}</Label></DetailMono>
                          <DetailMono>› Parameter: <Label color="#fbbf24">{f.param}</Label></DetailMono>
                          <DetailMono>› Databases: <Label color="#00ff88">{(f.databases || []).join(", ") || "N/A"}</Label></DetailMono>
                        </div>
                      ))
                    ) : <DetailText>No vulnerability details provided by module.</DetailText>}
                  </ModuleBlock>

                  {/* DOM XSS */}
                  <ModuleBlock keyName="dom" title="DOM XSS" found={!!v.domXss?.found} expanded={expanded.dom} onToggle={toggle}>
                    {v.domXss?.details ? (() => {
                      const findings = Array.isArray(v.domXss.details.evidence) ? v.domXss.details.evidence : [];
                      const highMedium = findings.filter(f => ["high","medium"].includes((f.confidence||"").toLowerCase()));
                      const lowCount = findings.length - highMedium.length;
                      if (highMedium.length > 0) return (
                        <div>
                          <DetailMono>› Confirmed findings: <Label color="#ff6b35">{highMedium.length}</Label></DetailMono>
                          {highMedium.map((f, i) => (
                            <div key={i} style={{ marginTop: "10px", paddingLeft: "12px", borderLeft: "2px solid rgba(255,107,53,0.3)" }}>
                              <DetailMono>› Type: <Label color="#fbbf24">{f.type || "DOM XSS"}</Label></DetailMono>
                              <DetailMono>› Location: <Label color="#00d4ff">{f.location || "N/A"}</Label></DetailMono>
                              <DetailMono>› Confidence: <Label color="#00ff88">{f.confidence || "Unknown"}</Label></DetailMono>
                            </div>
                          ))}
                          {lowCount > 0 && <DetailText style={{ marginTop: "10px" }}>{lowCount} low-confidence finding(s) suppressed.</DetailText>}
                          <button onClick={() => setShowRawDomFindings(s => !s)} style={{ marginTop: "10px", fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", color: "#00d4ff", background: "none", border: "none", cursor: "pointer", letterSpacing: "0.1em" }}>
                            {showRawDomFindings ? "▲ HIDE RAW" : "▼ SHOW RAW FINDINGS"}
                          </button>
                          {showRawDomFindings && <pre style={{ marginTop: "10px", maxHeight: "200px", overflowY: "auto" }}>{JSON.stringify(findings, null, 2)}</pre>}
                        </div>
                      );
                      if (findings.length > 0) return (
                        <div>
                          <DetailText>No confirmed High/Medium findings. {findings.length} low-confidence finding(s) detected.</DetailText>
                          <button onClick={() => setShowRawDomFindings(s => !s)} style={{ marginTop: "8px", fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", color: "#00d4ff", background: "none", border: "none", cursor: "pointer", letterSpacing: "0.1em" }}>
                            {showRawDomFindings ? "▲ HIDE RAW" : "▼ SHOW RAW FINDINGS"}
                          </button>
                        </div>
                      );
                      return <DetailText>No vulnerability detected</DetailText>;
                    })() : <DetailText>No vulnerability detected</DetailText>}
                  </ModuleBlock>

                  {/* Stored XSS */}
                  <ModuleBlock keyName="stored" title="STORED XSS" found={!!v.storedXss?.found} expanded={expanded.stored} onToggle={toggle}>
                    {v.storedXss?.details?.evidence ? (
                      Array.isArray(v.storedXss.details.evidence)
                        ? v.storedXss.details.evidence.map((f, i) => (
                          <div key={i} style={{ marginBottom: "14px", paddingLeft: "12px", borderLeft: "2px solid rgba(255,107,53,0.3)" }}>
                            <DetailMono>› Location: <Label color="#00d4ff">{f.location || "N/A"}</Label></DetailMono>
                            <DetailMono>› Payload: <Label color="#fbbf24">{f.payload ? f.payload.substring(0, 50) : "N/A"}...</Label></DetailMono>
                            <DetailMono>› Evidence: <Label color="#00ff88">{f.evidence || "N/A"}</Label></DetailMono>
                            <DetailMono>› Confidence: <Label color="#ff6b35">{f.confidence || "Unknown"}</Label></DetailMono>
                          </div>
                        ))
                        : <DetailText>{v.storedXss.details.notes || "Vulnerability detected but details unavailable"}</DetailText>
                    ) : <DetailText>No vulnerability detected</DetailText>}
                  </ModuleBlock>

                  {/* Reflected XSS */}
                  <ModuleBlock keyName="reflected" title="REFLECTED XSS" found={!!v.reflectedXss?.found} expanded={expanded.reflected} onToggle={toggle}>
                    {v.reflectedXss?.details ? (
                      <div>
                        <DetailMono>› Endpoints tested: <Label color="#00d4ff">{v.reflectedXss.details.testedEndpoints || 0}</Label></DetailMono>
                        <DetailMono>› Vulnerable endpoints: <Label color="#ff6b35">{(v.reflectedXss.details.vulnerableEndpoints || []).length || 0}</Label></DetailMono>
                        {v.reflectedXss.details.vulnerableEndpoints?.length > 0 && (
                          <div style={{ marginTop: "12px" }}>
                            {v.reflectedXss.details.vulnerableEndpoints.slice(0, 10).map((ep, i) => (
                              <div key={i} style={{ marginBottom: "10px", paddingLeft: "12px", borderLeft: "2px solid rgba(255,107,53,0.3)" }}>
                                <DetailMono>› URL: <Label color="#fbbf24">{ep.url || "Unknown"}</Label></DetailMono>
                                {Array.isArray(ep.findings) && ep.findings.length > 0 && (
                                  <DetailMono>› Payloads: <Label color="#00ff88">{ep.findings.length}</Label></DetailMono>
                                )}
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    ) : <DetailText>No vulnerability detected</DetailText>}
                  </ModuleBlock>

                  {/* Clickjacking */}
                  <ModuleBlock keyName="click" title="CLICKJACKING" found={!!v.clickjacking?.vulnerable} expanded={expanded.click} onToggle={toggle}>
                    {v.clickjacking?.vulnerable ? (
                      <div>
                        <DetailMono>› Issue: <Label color="#ff6b35">{v.clickjacking.details?.issue || "Missing X-Frame-Options / CSP frame-ancestors"}</Label></DetailMono>
                        {v.clickjacking.details?.headers && Object.keys(v.clickjacking.details.headers).length > 0 && (
                          <div style={{ marginTop: "10px" }}>
                            <DetailMono style={{ marginBottom: "6px" }}>› Security Headers:</DetailMono>
                            {Object.entries(v.clickjacking.details.headers || {}).slice(0, 8).map(([k, val]) => (
                              <div key={k} style={{ paddingLeft: "12px" }}>
                                <DetailMono>› <Label color="#fbbf24">{k}:</Label> <Label color="rgba(180,255,180,0.5)">{String(val).substring(0, 60)}...</Label></DetailMono>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    ) : <DetailText>No vulnerability detected</DetailText>}
                  </ModuleBlock>

                  {/* Command Injection */}
                  <ModuleBlock keyName="cmd" title="COMMAND INJECTION" found={!!v.commandInjection?.found} expanded={expanded.cmd} onToggle={toggle}>
                    {v.commandInjection?.found ? (
                      <div>
                        <DetailMono>› Confidence: <Label color="#ff6b35">{v.commandInjection.details?.confidence || "Unknown"}</Label></DetailMono>
                        <DetailMono>› Notes: <Label color="rgba(180,255,180,0.6)">{v.commandInjection.details?.notes || "Command execution vulnerability confirmed"}</Label></DetailMono>
                        {Array.isArray(v.commandInjection.details?.evidence) && v.commandInjection.details.evidence.slice(0, 5).map((f, i) => (
                          <div key={i} style={{ marginTop: "10px", paddingLeft: "12px", borderLeft: "2px solid rgba(255,107,53,0.3)" }}>
                            <DetailMono>› Parameter: <Label color="#fbbf24">{f.parameter || "Unknown"}</Label></DetailMono>
                            <DetailMono>› Payload: <Label color="#00ff88">{f.payload ? f.payload.substring(0, 40) : "N/A"}...</Label></DetailMono>
                            <DetailMono>› Evidence: <Label color="#00d4ff">{f.evidence || "N/A"}</Label></DetailMono>
                          </div>
                        ))}
                      </div>
                    ) : <DetailText>No vulnerability detected</DetailText>}
                  </ModuleBlock>

                  {/* CSRF */}
                  <ModuleBlock keyName="csrf" title="CSRF — CROSS-SITE REQUEST FORGERY" found={!!v.csrf?.found} expanded={expanded.csrf} onToggle={toggle}>
                    {v.csrf?.found ? (
                      <div>
                        <DetailMono>› Total endpoints tested: <Label color="#00d4ff">{v.csrf.details?.summary?.totalEndpoints || 0}</Label></DetailMono>
                        <DetailMono>› Vulnerable: <Label color="#ff6b35">{v.csrf.details?.summary?.vulnerable || 0}</Label></DetailMono>
                        <DetailMono>› Safe: <Label color="#00ff88">{v.csrf.details?.summary?.safe || 0}</Label></DetailMono>
                        {v.csrf.details?.vulnerableEndpoints?.length > 0 && (
                          <div style={{ marginTop: "12px" }}>
                            {v.csrf.details.vulnerableEndpoints.slice(0, 10).map((ep, i) => (
                              <div key={i} style={{ marginBottom: "10px", paddingLeft: "12px", borderLeft: "2px solid rgba(255,107,53,0.3)" }}>
                                <DetailMono>› Endpoint: <Label color="#fbbf24">{ep.endpoint || "Unknown"}</Label></DetailMono>
                                <DetailMono>› Method: <Label color="#00d4ff">{ep.method || "POST"}</Label> · Confidence: <Label color="#ff6b35">{ep.confidence || "Unknown"}</Label> · Risk: <Label color={ep.risk === "HIGH" ? "#ff2222" : "#fbbf24"}>{ep.risk || "MEDIUM"}</Label></DetailMono>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    ) : <DetailText>No vulnerability detected</DetailText>}
                  </ModuleBlock>
                </div>
              );
            })()}

            {/* PDF Download */}
            <div style={{ textAlign: "center", paddingTop: "40px", paddingBottom: "20px" }}>
              <button
                onClick={downloadPDF}
                style={{
                  fontFamily: "'Orbitron', monospace", fontWeight: 700, fontSize: "11px",
                  letterSpacing: "0.18em", textTransform: "uppercase",
                  color: "#020804", background: "#00ff88", border: "none",
                  padding: "16px 36px", cursor: "pointer",
                  display: "inline-flex", alignItems: "center", gap: "10px",
                  transition: "all 0.25s", boxShadow: "0 0 24px rgba(0,255,136,0.3)",
                }}
                onMouseEnter={e => { e.target.style.transform = "translateY(-2px)"; e.target.style.boxShadow = "0 0 40px rgba(0,255,136,0.5)"; }}
                onMouseLeave={e => { e.target.style.transform = "translateY(0)"; e.target.style.boxShadow = "0 0 24px rgba(0,255,136,0.3)"; }}
              >
                <FaFileDownload /> DOWNLOAD FULL PDF REPORT
              </button>
            </div>
          </div>
        )}
        <div style={{ height: "60px" }} />
      </div>
    </div>
  );
}