import { useState, useRef } from "react";
import {
  FaSearch, FaBug, FaShieldAlt, FaExclamationTriangle, FaFileDownload,
} from "react-icons/fa";

const FONT_URL = "https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;600;700;900&family=Rajdhani:wght@300;400;500;600;700&display=swap";

/* ── RISK HELPERS ── */
const calculateOverallRisk = (data) => {
  let score = 0;
  if (data?.securityTrails?.risk === "HIGH") score += 2;
  if (data?.securityTrails?.risk === "MEDIUM") score += 1;
  if (data?.endpoints?.length > 30) score += 2;
  else if (data?.endpoints?.length > 15) score += 1;
  if (data?.headers?.["x-powered-by"]?.includes("PHP/5")) score += 2;
  if (data?.ssl?.error) score += 1;
  if (!data?.dns) score += 1;
  if (!data?.whois) score += 1;
  if (!data?.ping) score += 1;
  if (!data?.traceroute || data.traceroute.length === 0) score += 1;
  if (data?.emailReputation?.risk === "HIGH") score += 2;
  if (data?.emailReputation?.risk === "MEDIUM") score += 1;
  if (score >= 8) return "CRITICAL";
  if (score >= 5) return "HIGH";
  if (score >= 3) return "MEDIUM";
  return "LOW";
};

const riskAccent = (risk) => {
  if (risk === "CRITICAL") return "#ff2222";
  if (risk === "HIGH") return "#ff6b35";
  if (risk === "MEDIUM") return "#fbbf24";
  return "#00ff88";
};

const riskBg = (risk) => {
  if (risk === "CRITICAL") return "rgba(255,34,34,0.1)";
  if (risk === "HIGH") return "rgba(255,107,53,0.1)";
  if (risk === "MEDIUM") return "rgba(251,191,36,0.1)";
  return "rgba(0,255,136,0.1)";
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

/* ── SUMMARY CARD ── */
const SummaryCard = ({ title, icon, summary, risk, details = [] }) => {
  const accent = riskAccent(risk);
  return (
    <div style={{
      background: "rgba(0,0,0,0.55)", border: `1px solid rgba(0,255,136,0.1)`,
      borderLeft: `3px solid ${accent}`, padding: "24px", position: "relative", overflow: "hidden",
    }}>
      <div style={{ position: "absolute", top: 0, right: 0, width: 0, height: 0, borderStyle: "solid", borderWidth: "0 28px 28px 0", borderColor: `transparent ${accent}20 transparent transparent` }} />
      <div style={{ display: "flex", alignItems: "flex-start", gap: "16px" }}>
        <div style={{ fontSize: "20px", marginTop: "2px", filter: `drop-shadow(0 0 6px ${accent})` }}>{icon}</div>
        <div style={{ flex: 1 }}>
          <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", letterSpacing: "0.25em", color: "rgba(0,255,136,0.4)", marginBottom: "6px", textTransform: "uppercase" }}>
            MODULE //
          </div>
          <h4 style={{ fontFamily: "'Orbitron', monospace", fontWeight: 600, fontSize: "13px", color: "#e8ffe8", marginBottom: "8px", letterSpacing: "0.04em" }}>{title}</h4>
          <p style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: "14px", color: "rgba(180,255,180,0.5)", lineHeight: 1.6, marginBottom: details.length ? "12px" : 0 }}>{summary}</p>
          {details.length > 0 && (
            <ul style={{ listStyle: "none", padding: 0, marginBottom: risk ? "12px" : 0 }}>
              {details.map((d, i) => (
                <li key={i} style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "11px", color: "rgba(0,255,136,0.5)", lineHeight: 1.8, paddingLeft: "12px", position: "relative" }}>
                  <span style={{ position: "absolute", left: 0, color: accent }}>›</span> {d}
                </li>
              ))}
            </ul>
          )}
          {risk && (
            <span style={{
              fontFamily: "'Orbitron', monospace", fontWeight: 700, fontSize: "10px",
              letterSpacing: "0.15em", color: accent,
              background: riskBg(risk), border: `1px solid ${accent}40`,
              padding: "4px 12px", display: "inline-block",
            }}>{risk}</span>
          )}
        </div>
      </div>
    </div>
  );
};

/* ── MAIN ── */
export default function QuickScan() {
  const [input, setInput] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [scanDone, setScanDone] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState("");
  const [isDownloading, setIsDownloading] = useState(false);
  const loaderRef = useRef(null);

  const isValidURL = (url) => {
    try {
      new URL(url.startsWith("http") ? url : `http://${url}`);
      return true;
    } catch { return false; }
  };

  const handleScan = async () => {
    if (!input.trim()) return alert("Please enter a URL");
    if (!isValidURL(input)) return alert("Invalid URL format");
    setIsScanning(true);
    setError("");
    setResults(null);
    setScanDone(false);
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
      setScanDone(true);
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
        body: JSON.stringify({ target: input, scanData: results }),
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

  const overallRisk = results ? calculateOverallRisk(results) : null;
  const techStack = results?.wappalyzer
    ? Object.entries(results.wappalyzer).map(([tech, version]) => version !== "Unknown" ? `${tech} ${version}` : tech)
    : [];

  return (
    <div style={{ backgroundColor: "#020804", minHeight: "100vh", color: "#e8ffe8", overflowX: "hidden", cursor: "crosshair" }}>
      <link rel="stylesheet" href={FONT_URL} />
      <style>{`
        @keyframes pulse { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:0.3;transform:scale(0.75)} }
        @keyframes fadeUp { from{opacity:0;transform:translateY(24px)} to{opacity:1;transform:translateY(0)} }
        @keyframes spin { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }
        @keyframes scanPulse { 0%,100%{opacity:0.6} 50%{opacity:1} }
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
        <div style={{ display: "flex", alignItems: "center", gap: "12px", cursor: "pointer" }} onClick={() => window.location.href = "/"}>
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
        <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
          <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", color: "rgba(0,255,136,0.4)", letterSpacing: "0.15em" }}>QUICK_SCAN // MODULE_01</span>
          <div style={{ width: "7px", height: "7px", background: isScanning ? "#fbbf24" : "#00ff88", borderRadius: "50%", boxShadow: `0 0 10px ${isScanning ? "#fbbf24" : "#00ff88"}`, animation: "pulse 2s ease-in-out infinite" }} />
          <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", color: isScanning ? "#fbbf24" : "#00ff88", letterSpacing: "0.15em" }}>
            {isScanning ? "SCANNING..." : "READY"}
          </span>
        </div>
      </nav>

      <div style={{ position: "relative", zIndex: 2, maxWidth: "1100px", margin: "0 auto", padding: "120px 40px 80px" }}>

        {/* Header */}
        <div style={{ marginBottom: "52px", animation: "fadeUp 0.6s ease 0.1s both" }}>
          <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", letterSpacing: "0.35em", color: "rgba(0,255,136,0.4)", marginBottom: "14px" }}>// MODULE_01 / QUICK_SCAN</div>
          <h1 style={{ fontFamily: "'Orbitron', monospace", fontWeight: 900, fontSize: "clamp(28px, 4vw, 52px)", color: "#e8ffe8", letterSpacing: "0.04em", lineHeight: 1.1, marginBottom: "16px" }}>
            QUICK <span style={{ color: "#00ff88" }}>SCAN</span>
          </h1>
          <p style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: "17px", color: "rgba(180,255,180,0.5)", lineHeight: 1.7, maxWidth: "540px" }}>
            High-level security snapshot to identify immediate risks. Recon + OSINT surface analysis in approximately 2 minutes.
          </p>
          <div style={{ width: "48px", height: "2px", background: "#00ff88", marginTop: "18px", boxShadow: "0 0 10px rgba(0,255,136,0.5)" }} />
        </div>

        {/* Input Card */}
        <div style={{ background: "rgba(0,0,0,0.7)", border: "1px solid rgba(0,255,136,0.15)", borderTop: "2px solid #00ff88", padding: "36px", maxWidth: "600px", marginBottom: "40px", animation: "fadeUp 0.6s ease 0.2s both", position: "relative", overflow: "hidden" }}>
          <div style={{ position: "absolute", top: 0, right: 0, width: 0, height: 0, borderStyle: "solid", borderWidth: "0 40px 40px 0", borderColor: "transparent rgba(0,255,136,0.15) transparent transparent" }} />

          <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", color: "rgba(0,255,136,0.4)", letterSpacing: "0.25em", marginBottom: "20px" }}>
            TARGET_INPUT // ENTER_URL_OR_DOMAIN
          </div>

          <label style={{ fontFamily: "'Orbitron', monospace", fontSize: "12px", letterSpacing: "0.1em", color: "#e8ffe8", display: "block", marginBottom: "12px" }}>
            TARGET URL
          </label>

          <div style={{ display: "flex", gap: "12px", flexWrap: "wrap" }}>
            <input
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleScan()}
              placeholder="example.com"
              style={{
                flex: "1 1 240px", padding: "12px 16px",
                background: "rgba(0,0,0,0.8)", border: "1px solid rgba(0,255,136,0.2)",
                color: "#00ff88", fontFamily: "'Share Tech Mono', monospace", fontSize: "13px",
                outline: "none", letterSpacing: "0.05em",
                transition: "border-color 0.2s",
              }}
              onFocus={e => e.target.style.borderColor = "#00ff88"}
              onBlur={e => e.target.style.borderColor = "rgba(0,255,136,0.2)"}
            />
            <button
              onClick={handleScan}
              style={{
                fontFamily: "'Orbitron', monospace", fontWeight: 700, fontSize: "11px",
                letterSpacing: "0.18em", color: "#020804", background: "#00ff88", border: "none",
                padding: "12px 28px", cursor: "pointer", textTransform: "uppercase",
                transition: "all 0.25s", display: "flex", alignItems: "center", gap: "8px",
                boxShadow: "0 0 20px rgba(0,255,136,0.25)",
              }}
              onMouseEnter={e => { e.currentTarget.style.background = "#33ffaa"; e.currentTarget.style.transform = "translateY(-2px)"; }}
              onMouseLeave={e => { e.currentTarget.style.background = "#00ff88"; e.currentTarget.style.transform = "translateY(0)"; }}
            >
              <FaSearch style={{ fontSize: "12px" }} /> SCAN
            </button>
          </div>

          {error && (
            <div style={{ marginTop: "14px", fontFamily: "'Share Tech Mono', monospace", fontSize: "11px", color: "#ff6b6b", letterSpacing: "0.1em", display: "flex", alignItems: "center", gap: "8px" }}>
              <span style={{ color: "#ff6b6b" }}>✕</span> ERROR: {error}
            </div>
          )}
        </div>

        {/* LOADER */}
        {isScanning && (
          <div ref={loaderRef} style={{ marginBottom: "40px", animation: "fadeUp 0.4s ease both" }}>
            <div style={{ background: "rgba(0,0,0,0.6)", border: "1px solid rgba(251,191,36,0.25)", borderLeft: "3px solid #fbbf24", padding: "28px 32px", maxWidth: "600px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "16px", marginBottom: "16px" }}>
                <div style={{ width: "20px", height: "20px", border: "2px solid rgba(0,255,136,0.2)", borderTop: "2px solid #00ff88", borderRadius: "50%", animation: "spin 0.8s linear infinite" }} />
                <span style={{ fontFamily: "'Orbitron', monospace", fontWeight: 700, fontSize: "14px", color: "#fbbf24", letterSpacing: "0.1em" }}>RUNNING SECURITY CHECKS</span>
              </div>
              <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "11px", color: "rgba(0,255,136,0.4)", letterSpacing: "0.1em", lineHeight: 1.8 }}>
                {["Enumerating subdomains...", "Scanning endpoints...", "Checking SSL certificate...", "Querying WHOIS...", "Probing open ports..."].map((line, i) => (
                  <div key={i} style={{ animation: `scanPulse 1.5s ease ${i * 0.3}s infinite` }}>› {line}</div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* RESULTS */}
        {scanDone && results && (
          <div style={{ animation: "fadeUp 0.6s ease both" }}>

            {/* Overall Risk Banner */}
            <div style={{
              background: riskBg(overallRisk), border: `1px solid ${riskAccent(overallRisk)}40`,
              borderLeft: `4px solid ${riskAccent(overallRisk)}`,
              padding: "28px 32px", marginBottom: "40px", position: "relative", overflow: "hidden",
            }}>
              <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: "1px", background: `linear-gradient(90deg, ${riskAccent(overallRisk)}, transparent)` }} />
              <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", letterSpacing: "0.3em", color: "rgba(0,255,136,0.4)", marginBottom: "10px" }}>OVERALL_RISK_ASSESSMENT //</div>
              <div style={{ display: "flex", alignItems: "center", gap: "20px", flexWrap: "wrap" }}>
                <span style={{ fontFamily: "'Orbitron', monospace", fontWeight: 900, fontSize: "clamp(22px, 3vw, 36px)", color: riskAccent(overallRisk), letterSpacing: "0.08em", textShadow: `0 0 30px ${riskAccent(overallRisk)}60` }}>
                  {overallRisk} RISK
                </span>
                <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "11px", color: "rgba(0,255,136,0.45)", letterSpacing: "0.1em" }}>
                  TARGET: {input}
                </span>
              </div>
            </div>

            {/* Core Security Section */}
            <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", letterSpacing: "0.3em", color: "rgba(0,255,136,0.38)", marginBottom: "20px" }}>
              // CORE_SECURITY_SIGNALS
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(440px, 1fr))", gap: "16px", marginBottom: "48px" }}>
              <SummaryCard
                title="Attack Surface (SecurityTrails)"
                icon={<FaSearch style={{ color: "#00ff88" }} />}
                summary={`${results.securityTrails.subdomainCount} subdomains discovered`}
                risk={results.securityTrails.risk}
                details={[`Examples: ${results.securityTrails.subdomains.slice(0, 3).join(", ")}`, "Large historical DNS footprint detected"]}
              />
              <SummaryCard
                title="Exposed Endpoints"
                icon={<FaBug style={{ color: "#ff6b35" }} />}
                summary={`${results.endpoints.length} parameterized URLs found`}
                risk={results.endpoints.length > 20 ? "HIGH" : results.endpoints.length > 10 ? "MEDIUM" : "LOW"}
                details={[`Unique parameters detected: ${new Set(results.endpoints.map(e => e.param)).size}`, `Example endpoint: ${results.endpoints[0]?.url || "N/A"}`]}
              />
              <SummaryCard
                title="Technology Stack"
                icon={<FaShieldAlt style={{ color: "#00ff88" }} />}
                summary={`Server: ${results?.headers?.server || "Unknown"}`}
                risk={results?.headers["x-powered-by"]?.includes("PHP/5") ? "HIGH" : "LOW"}
                details={[`Backend: ${results.headers["x-powered-by"] || "Unknown"}`, "Detected Technologies:", ...techStack.slice(0, 5)]}
              />
              <SummaryCard
                title="Network & Transport"
                icon={<FaExclamationTriangle style={{ color: "#fbbf24" }} />}
                summary={`Open ports: ${results.openPorts.length}`}
                risk={results.ssl.error ? "MEDIUM" : "LOW"}
                details={[results.ssl.error ? "HTTPS not enforced" : "TLS enabled", results.openPorts.length ? `Ports: ${results.openPorts.map(p => p.port).join(", ")}` : "No common ports exposed"]}
              />
            </div>

            {/* Infrastructure Section */}
            <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", letterSpacing: "0.3em", color: "rgba(0,255,136,0.38)", marginBottom: "20px" }}>
              // INFRASTRUCTURE_INTELLIGENCE
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(440px, 1fr))", gap: "16px", marginBottom: "48px" }}>
              <SummaryCard
                title="DNS Intelligence"
                icon={<FaSearch style={{ color: "#00d4ff" }} />}
                summary={results.dns ? "DNS records resolved successfully" : "DNS resolution failed"}
                risk={!results.dns ? "MEDIUM" : "LOW"}
                details={results.dns ? [`A Records: ${results.dns.A?.length || 0}`, `Primary IP: ${results.dns.A?.[0] || "N/A"}`] : ["No DNS response received"]}
              />
              <SummaryCard
                title="WHOIS Information"
                icon={<FaShieldAlt style={{ color: "#b06aff" }} />}
                summary="Domain registration metadata"
                risk={!results.whois ? "MEDIUM" : "LOW"}
                details={results.whois ? [`Registrar: ${results.whois.registrar || "Unknown"}`, `Created: ${results.whois.creationDate || "N/A"}`] : ["WHOIS information unavailable"]}
              />
              <SummaryCard
                title="Network Path (Traceroute)"
                icon={<FaExclamationTriangle style={{ color: "#fbbf24" }} />}
                summary={`${results.traceroute?.length || 0} network hops identified`}
                risk={results.traceroute?.length > 25 ? "MEDIUM" : "LOW"}
                details={results.traceroute ? [`Final Hop: ${results.traceroute[results.traceroute.length - 1]?.ip || "Unknown"}`, `Total Hops: ${results.traceroute.length}`] : ["Traceroute blocked or unavailable"]}
              />
              <SummaryCard
                title="Host Reachability (Ping)"
                icon={<FaBug style={{ color: "#00ff88" }} />}
                summary={results.ping ? "Host responded to ICMP echo requests" : "No ICMP response"}
                risk={!results.ping ? "MEDIUM" : "LOW"}
                details={results.ping ? [`Average Latency: ${results.ping.avgTime || "N/A"} ms`, `Packet Loss: ${results.ping.packetLoss || "0%"}`] : ["ICMP echo disabled or filtered"]}
              />
              <SummaryCard
                title="Email / Domain Reputation"
                icon={<FaBug style={{ color: "#b06aff" }} />}
                summary={`Reputation level: ${results.emailReputation?.risk || "Unknown"}`}
                risk={results.emailReputation?.risk || "LOW"}
                details={[results.emailReputation?.note || "No significant abuse indicators detected"]}
              />
            </div>

            {/* PDF Download */}
            <div style={{ textAlign: "center", padding: "40px 0" }}>
              <button
                onClick={downloadPDF}
                disabled={isDownloading}
                style={{
                  fontFamily: "'Orbitron', monospace", fontWeight: 700, fontSize: "11px",
                  letterSpacing: "0.18em", textTransform: "uppercase",
                  color: isDownloading ? "rgba(0,255,136,0.4)" : "#020804",
                  background: isDownloading ? "rgba(0,255,136,0.08)" : "#00ff88",
                  border: isDownloading ? "1px solid rgba(0,255,136,0.2)" : "none",
                  padding: "16px 36px", cursor: isDownloading ? "not-allowed" : "pointer",
                  display: "inline-flex", alignItems: "center", gap: "10px",
                  transition: "all 0.25s", boxShadow: isDownloading ? "none" : "0 0 24px rgba(0,255,136,0.3)",
                }}
                onMouseEnter={e => { if (!isDownloading) e.currentTarget.style.transform = "translateY(-2px)"; }}
                onMouseLeave={e => { e.currentTarget.style.transform = "translateY(0)"; }}
              >
                <FaFileDownload /> {isDownloading ? "PREPARING REPORT..." : "DOWNLOAD PDF REPORT"}
              </button>
              <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", color: "rgba(0,255,136,0.3)", marginTop: "12px", letterSpacing: "0.1em" }}>
                Includes full findings, evidence & remediation guidance
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}