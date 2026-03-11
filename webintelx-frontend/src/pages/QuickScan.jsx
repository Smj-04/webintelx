import { useState, useRef } from "react";
import {
  FaSearch, FaBug, FaShieldAlt, FaFileDownload,
  FaGlobe, FaServer, FaLock, FaUnlock, FaNetworkWired, FaEnvelope,
  FaRoute, FaFingerprint, FaChevronDown, FaCode,
  FaLeaf, FaMapMarkerAlt, FaCookieBite,
  FaVirus, FaEye, FaExclamationTriangle
} from "react-icons/fa";

const FONTS = "https://fonts.googleapis.com/css2?family=DM+Mono:wght@300;400;500&family=Syne:wght@400;500;600;700;800&family=DM+Sans:wght@300;400;500;600&family=Orbitron:wght@400;600;700;900&family=Share+Tech+Mono&family=Rajdhani:wght@400;500;600;700&display=swap";

/* ─── PALETTE ─────────────────────────────────────
   bg:        #F7F8F9   near-white with blue-grey tint
   surface:   #FFFFFF
   border:    #E4E8EC
   text-1:    #0F1923   near-black
   text-2:    #3A4A58   dark slate
   text-3:    #6B7C8D   medium slate
   accent:    #0A6640   deep forest green
   accent-lt: #EAF4EE   tinted green bg
─────────────────────────────────────────────────── */

const C = {
  bg: "#F7F8F9", surface: "#FFFFFF", border: "#E4E8EC",
  t1: "#0F1923", t2: "#3A4A58", t3: "#6B7C8D",
  accent: "#0A6640", accentLt: "#EAF4EE",
  red: "#C0312B", redLt: "#FEF2F2", redBorder: "#FECACA",
  orange: "#B54A0C", orangeLt: "#FFF7ED", orangeBorder: "#FED7AA",
  amber: "#92600A", amberLt: "#FFFBEB", amberBorder: "#FDE68A",
  green: "#0A6640", greenLt: "#EAF4EE", greenBorder: "#A7D7BC",
};

const riskColor   = r => r==="CRITICAL"?C.red    : r==="HIGH"?C.orange    : r==="MEDIUM"?C.amber    : C.green;
const riskLt      = r => r==="CRITICAL"?C.redLt  : r==="HIGH"?C.orangeLt  : r==="MEDIUM"?C.amberLt  : C.greenLt;
const riskBorder  = r => r==="CRITICAL"?C.redBorder:r==="HIGH"?C.orangeBorder:r==="MEDIUM"?C.amberBorder:C.greenBorder;

/* ─── OUTDATED DB ─────────────────────────────────────────── */
const OUTDATED_DB = {
  "jquery migrate": { latest:"3.",   eol:["1.","2."],                      severity:"MEDIUM",   note:"jQuery Migrate 1.x/2.x is deprecated — upgrade to 3.x" },
  "jquery ui":      { latest:"1.13", eol:["1.10","1.11","1.12"],           severity:"MEDIUM",   note:"jQuery UI older versions have CSRF and XSS issues" },
  "jquery":         { latest:"3.7",  eol:["1.","2."],                      severity:"HIGH",     note:"jQuery 1.x/2.x have known XSS vulnerabilities — upgrade to 3.x" },
  "bootstrap":      { latest:"5.",   eol:["2.","3."],                      severity:"MEDIUM",   note:"Bootstrap 2.x/3.x are EOL — XSS risks in older components" },
  "font awesome":   { latest:"6.",   eol:["4."],                           severity:"LOW",      note:"Font Awesome 4.x is EOL — consider upgrading to 6.x" },
  "wordpress":      { latest:"6.",   eol:["3.","4.","5.0","5.1","5.2","5.3","5.4","5.5","5.6","5.7","5.8","5.9"], severity:"CRITICAL", note:"Outdated WordPress is the #1 target for web attacks — update immediately" },
  "drupal":         { latest:"10.",  eol:["6.","7.","8.","9.0","9.1","9.2","9.3","9.4"], severity:"HIGH", note:"Outdated Drupal — known RCE vulnerabilities (Drupalgeddon)" },
  "joomla":         { latest:"5.",   eol:["2.","3."],                      severity:"HIGH",     note:"Joomla 3.x reached EOL — multiple known exploits exist" },
  "php":            { latest:"8.",   eol:["4.","5.","7.0","7.1","7.2","7.3","7.4"], severity:"CRITICAL", note:"PHP version is EOL — no security patches — upgrade to PHP 8.x" },
  "apache":         { latest:"2.4",  eol:["1.","2.0","2.2"],              severity:"HIGH",     note:"Apache 2.2 is EOL — no longer receives security patches" },
  "nginx":          { latest:"1.24", eol:["0.","1.0","1.2","1.4","1.6","1.8","1.10","1.12","1.14","1.16","1.18","1.20"], severity:"MEDIUM", note:"Outdated Nginx stable branch — upgrade to latest" },
  "openssl":        { latest:"3.",   eol:["1.0","1.1"],                   severity:"CRITICAL", note:"OpenSSL 1.0/1.1 are EOL — known CVEs including Heartbleed lineage" },
  "react":          { latest:"18.",  eol:["0.","1.","2.","3.","4.","5.","6.","7.","8.","9.","10.","11.","12.","13.","14.","15.","16."], severity:"LOW", note:"Outdated React — upgrade for security patches" },
  "angular":        { latest:"17.",  eol:["1.","2.","3.","4.","5.","6.","7.","8.","9.","10.","11.","12.","13.","14."], severity:"MEDIUM", note:"Outdated Angular version — upgrade for XSS fixes" },
  "vue.js":         { latest:"3.",   eol:["1."],                          severity:"MEDIUM",   note:"Vue 1.x is EOL — multiple XSS vulnerabilities exist" },
  "moment.js":      { latest:null,   eol:["*"],                           severity:"MEDIUM",   note:"Moment.js is deprecated — migrate to day.js or date-fns" },
  "mootools":       { latest:null,   eol:["*"],                           severity:"MEDIUM",   note:"MooTools is unmaintained since 2021 — consider migrating" },
  "prototype":      { latest:null,   eol:["*"],                           severity:"HIGH",     note:"Prototype.js is abandoned and has known XSS vulnerabilities" },
  "owl carousel":   { latest:"2.",   eol:["1."],                          severity:"LOW",      note:"Owl Carousel 1.x is deprecated — upgrade to 2.x" },
  "lodash":         { latest:"4.",   eol:["1.","2.","3."],                severity:"MEDIUM",   note:"Lodash 1-3.x has prototype pollution vulnerabilities" },
};

function checkOutdated(techName, version) {
  if (!version || version === "Unknown") return null;
  const key = Object.keys(OUTDATED_DB).find(k => techName.toLowerCase().includes(k));
  if (!key) return null;
  const db = OUTDATED_DB[key];
  if (db.eol.includes("*")) return db;
  return db.eol.some(p => version.startsWith(p)) ? db : null;
}

const severityColor = s =>
  s==="CRITICAL" ? C.red : s==="HIGH" ? C.orange : s==="MEDIUM" ? C.amber : C.green;

/* ══════════════════════════════════════════════════
   DESIGN SYSTEM COMPONENTS
══════════════════════════════════════════════════ */

/* Pill badge */
const Badge = ({ label, color = C.accent, bg, border }) => (
  <span style={{
    display: "inline-flex", alignItems: "center",
    fontFamily: "'DM Mono', monospace", fontSize: "10px", fontWeight: 500,
    letterSpacing: "0.06em", textTransform: "uppercase",
    color, background: bg || `${color}15`,
    border: `1px solid ${border || `${color}30`}`,
    padding: "3px 9px", borderRadius: "4px",
    whiteSpace: "nowrap",
  }}>{label}</span>
);

/* Risk badge — wider to fit CRITICAL */
const RiskBadge = ({ risk }) => (
  <span style={{
    display: "inline-flex", alignItems: "center", justifyContent: "center",
    fontFamily: "'DM Mono', monospace", fontSize: "10px", fontWeight: 500,
    letterSpacing: "0.08em", textTransform: "uppercase",
    color: riskColor(risk),
    background: riskLt(risk),
    border: `1px solid ${riskBorder(risk)}`,
    padding: "4px 12px", borderRadius: "4px",
    minWidth: "80px", whiteSpace: "nowrap",
  }}>{risk}</span>
);

/* Section header — clean typographic divider */
const SectionTitle = ({ num, label }) => (
  <div style={{ display: "flex", alignItems: "center", gap: "14px", margin: "48px 0 16px" }}>
    <span style={{ fontFamily: "'DM Mono', monospace", fontSize: "11px", color: C.accent, fontWeight: 500 }}>
      {String(num).padStart(2,"0")}
    </span>
    <div style={{ width: "1px", height: "18px", background: C.border }} />
    <span style={{ fontFamily: "'Syne', sans-serif", fontSize: "13px", fontWeight: 700, color: C.t1, letterSpacing: "0.08em", textTransform: "uppercase" }}>
      {label}
    </span>
    <div style={{ flex: 1, height: "1px", background: C.border }} />
  </div>
);

/* Data row inside a card */
const DataRow = ({ label, value, valueColor, mono = true }) => (
  <div style={{
    display: "flex", justifyContent: "space-between", alignItems: "flex-start",
    padding: "9px 20px", borderBottom: `1px solid ${C.border}`,
    gap: "16px",
  }}>
    <span style={{
      fontFamily: "'DM Mono', monospace", fontSize: "11px",
      color: C.t3, textTransform: "uppercase", letterSpacing: "0.06em",
      flexShrink: 0, paddingTop: "1px",
    }}>{label}</span>
    <span style={{
      fontFamily: mono ? "'DM Mono', monospace" : "'DM Sans', sans-serif",
      fontSize: mono ? "12px" : "13px",
      color: valueColor || C.t1, fontWeight: mono ? 400 : 500,
      textAlign: "right", wordBreak: "break-all", lineHeight: 1.5,
    }}>{value ?? "—"}</span>
  </div>
);

/* Alert / finding row */
const Finding = ({ text, level = "warn" }) => {
  const map = {
    critical: { color: C.red,    bg: C.redLt,    icon: "●" },
    warn:     { color: C.amber,  bg: C.amberLt,  icon: "▲" },
    info:     { color: C.accent, bg: C.greenLt,  icon: "✓" },
  };
  const s = map[level] || map.info;
  return (
    <div style={{
      display: "flex", gap: "10px", alignItems: "flex-start",
      padding: "10px 20px",
      background: s.bg,
      borderBottom: `1px solid ${C.border}`,
    }}>
      <span style={{ color: s.color, fontSize: "10px", flexShrink: 0, marginTop: "3px" }}>{s.icon}</span>
      <span style={{ fontFamily: "'DM Sans', sans-serif", fontSize: "13px", color: C.t1, lineHeight: 1.6, fontWeight: 400 }}>{text}</span>
    </div>
  );
};

/* Sub-section label inside a card */
const CardSection = ({ label }) => (
  <div style={{
    padding: "10px 20px 6px",
    fontFamily: "'DM Mono', monospace", fontSize: "10px",
    color: C.t3, letterSpacing: "0.1em", textTransform: "uppercase",
    borderBottom: `1px solid ${C.border}`,
    background: C.bg,
  }}>{label}</div>
);

/* Tag chip */
const Chip = ({ label, color = C.accent }) => (
  <span style={{
    fontFamily: "'DM Mono', monospace", fontSize: "11px",
    color, background: `${color}12`,
    border: `1px solid ${color}28`,
    padding: "3px 9px", borderRadius: "4px",
  }}>{label}</span>
);

/* Module card */
const Card = ({ title, icon, risk, summary, children, defaultOpen = false }) => {
  const [open, setOpen] = useState(defaultOpen);
  const rc = riskColor(risk);

  return (
    <div style={{
      background: C.surface,
      border: `1px solid ${C.border}`,
      borderRadius: "8px",
      overflow: "hidden",
      boxShadow: "0 1px 3px rgba(0,0,0,0.04)",
      animation: "fadeUp 0.3s ease both",
    }}>
      {/* Header */}
      <div
        onClick={() => setOpen(o => !o)}
        style={{
          display: "flex", alignItems: "center",
          padding: "0", cursor: "pointer", userSelect: "none",
          minHeight: "60px", gap: "0",
        }}
        onMouseEnter={e => e.currentTarget.style.background = C.bg}
        onMouseLeave={e => e.currentTarget.style.background = "transparent"}
      >
        {/* Coloured left strip */}
        <div style={{ width: "4px", alignSelf: "stretch", background: rc, flexShrink: 0 }} />

        {/* Icon box */}
        <div style={{
          width: "52px", flexShrink: 0, alignSelf: "stretch",
          display: "flex", alignItems: "center", justifyContent: "center",
          color: rc, fontSize: "16px",
          borderRight: `1px solid ${C.border}`,
        }}>{icon}</div>

        {/* Text */}
        <div style={{ flex: 1, minWidth: 0, padding: "12px 18px", display: "flex", flexDirection: "column", gap: "3px" }}>
          <div style={{
            fontFamily: "'Syne', sans-serif", fontWeight: 700, fontSize: "13px",
            color: C.t1, letterSpacing: "0.01em",
            overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
          }}>{title}</div>
          <div style={{
            fontFamily: "'DM Sans', sans-serif", fontSize: "13px",
            color: C.t2, fontWeight: 400,
            overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
          }}>{summary}</div>
        </div>

        {/* Risk badge + chevron — never overlaps because flex + shrink 0 */}
        <div style={{ flexShrink: 0, display: "flex", alignItems: "center", gap: "12px", padding: "0 18px", borderLeft: `1px solid ${C.border}` }}>
          <RiskBadge risk={risk} />
          <span style={{
            color: C.t3, fontSize: "12px", transition: "transform 0.2s",
            transform: open ? "rotate(180deg)" : "rotate(0deg)", flexShrink: 0,
          }}>
            <FaChevronDown />
          </span>
        </div>
      </div>

      {/* Body */}
      {open && (
        <div style={{ borderTop: `1px solid ${C.border}` }}>
          {children}
        </div>
      )}
    </div>
  );
};

/* TechTag */
const TechTag = ({ name, version, outdated }) => {
  const base = outdated ? severityColor(outdated.severity) : "#2563AB";
  return (
    <div style={{ display: "inline-flex", alignItems: "center", borderRadius: "4px", overflow: "hidden", border: `1px solid ${base}28` }}>
      <span style={{ fontFamily: "'DM Mono', monospace", fontSize: "11px", color: base, background: `${base}0f`, padding: "4px 9px" }}>
        {name}{version ? ` ${version}` : ""}
      </span>
      {outdated && (
        <span style={{ fontFamily: "'DM Mono', monospace", fontSize: "10px", fontWeight: 500, color: "#fff", background: base, padding: "4px 8px" }}>
          OUTDATED
        </span>
      )}
    </div>
  );
};

/* ══════════════════════════════════════════════════
   MAIN COMPONENT
══════════════════════════════════════════════════ */
export default function QuickScan() {
  const [input, setInput]             = useState("");
  const [isScanning, setIsScanning]   = useState(false);
  const [scanDone, setScanDone]       = useState(false);
  const [results, setResults]         = useState(null);
  const [riskAssessment, setRA]       = useState(null);
  const [error, setError]             = useState("");
  const [isDownloading, setDL]        = useState(false);
  const loaderRef  = useRef(null);
  const resultsRef = useRef(null);

  const isValidTarget = val => {
    const t = val.trim();
    try {
      const u = new URL(t.startsWith("http") ? t : `http://${t}`);
      const h = u.hostname;
      return /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(h)
          || /^(\d{1,3}\.){3}\d{1,3}$/.test(h) || h === "localhost";
    } catch { return false; }
  };

  const handleScan = async () => {
    if (!input.trim()) return alert("Please enter a URL");
    if (!isValidTarget(input)) { setError("Invalid target. Enter a valid domain or full URL."); return; }
    setIsScanning(true); setError(""); setResults(null); setScanDone(false); setRA(null);
    setTimeout(() => loaderRef.current?.scrollIntoView({ behavior: "smooth" }), 100);
    try {
      const res  = await fetch("http://localhost:5000/api/quickscan", {
        method:"POST", headers:{"Content-Type":"application/json"},
        body: JSON.stringify({ url: input }),
      });
      const data = await res.json();
      if (!data.success) { setError(data.error); setIsScanning(false); return; }
      setResults(data.data); setRA(data.riskAssessment); setScanDone(true);
      setTimeout(() => resultsRef.current?.scrollIntoView({ behavior:"smooth" }), 200);
    } catch { setError("Server unreachable"); }
    setIsScanning(false);
  };

  const downloadPDF = async () => {
    if (!results) return;
    setDL(true);
    try {
      const res = await fetch("http://localhost:5000/api/report/quickscan/pdf", {
        method:"POST", headers:{"Content-Type":"application/json"},
        body: JSON.stringify({ target:input, scanData:results, riskAssessment }),
      });
      if (!res.ok) throw new Error();
      const blob = await res.blob();
      const url  = window.URL.createObjectURL(blob);
      const a    = document.createElement("a");
      a.href = url; a.download = `QuickScan-${input.replace(/[^a-z0-9]/gi,"_")}.pdf`; a.click();
      window.URL.revokeObjectURL(url);
    } catch { alert("Failed to download PDF report"); }
    setDL(false);
  };

  /* derived */
  const r            = results;
  const overallRisk  = riskAssessment?.risk || "LOW";
  const techEntries  = r?.wappalyzer
    ? Object.entries(r.wappalyzer).map(([tech, version]) => ({
        name: tech, version: version !== "Unknown" ? version : null,
        outdated: checkOutdated(tech, version),
      }))
    : [];
  const outdatedTechs    = techEntries.filter(t => t.outdated);
  const criticalOutdated = outdatedTechs.filter(t => t.outdated.severity === "CRITICAL");
  const highOutdated     = outdatedTechs.filter(t => t.outdated.severity === "HIGH");
  const techRisk = criticalOutdated.length>0 ? "CRITICAL" : highOutdated.length>0 ? "HIGH"
    : outdatedTechs.length>0 ? "MEDIUM"
    : (r?.headers?.poweredBy?.includes("PHP/5")||r?.headers?.poweredBy?.includes("PHP/4")) ? "HIGH"
    : techEntries.length>0 ? "LOW" : "LOW";
  const techSummary = outdatedTechs.length>0
    ? `${outdatedTechs.length} outdated component${outdatedTechs.length>1?"s":""} / ${techEntries.length} detected`
    : `${techEntries.length} technologies detected`;

  return (
    <div style={{ background: C.bg, minHeight:"100vh", color:C.t1, overflowX:"hidden" }}>
      <link rel="stylesheet" href={FONTS} />
      <style>{`
        @keyframes fadeUp { from{opacity:0;transform:translateY(10px)} to{opacity:1;transform:translateY(0)} }
        @keyframes spin    { to{transform:rotate(360deg)} }
        @keyframes pulse   { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:0.4;transform:scale(0.7)} }
        @keyframes barFill { from{width:0} to{width:100%} }
        @keyframes shimmer { 0%,100%{opacity:0.5} 50%{opacity:1} }
        * { box-sizing:border-box; margin:0; padding:0; }
        ::selection { background:#0A664020; color:#0A6640; }
        ::-webkit-scrollbar { width:4px; }
        ::-webkit-scrollbar-track { background:${C.bg}; }
        ::-webkit-scrollbar-thumb { background:${C.border}; border-radius:2px; }
        input::placeholder { color:${C.t3}; }
      `}</style>

      {/* ── NAV ── */}
      <nav style={{
        position:"fixed", top:0, left:0, right:0, zIndex:200,
        height:"64px", background:"#ffffff",
        borderBottom:`1px solid ${C.border}`,
        display:"flex", alignItems:"center", justifyContent:"space-between",
        padding:"0 48px",
        boxShadow:"0 1px 8px rgba(0,0,0,0.06)",
      }}>
        <div style={{ display:"flex", alignItems:"center", gap:"12px", cursor:"pointer" }}
             onClick={() => window.location.href = "/"}>
          <svg viewBox="0 0 36 36" width="32" height="32">
            <polygon points="18,2 34,11 34,25 18,34 2,25 2,11" fill="none" stroke={C.accent} strokeWidth="1.5"/>
            <polygon points="18,8 28,14 28,22 18,28 8,22 8,14" fill="none" stroke={C.accent} strokeWidth="0.8" opacity="0.4"/>
            <circle cx="18" cy="18" r="3" fill={C.accent}>
              <animate attributeName="r" values="3;4.2;3" dur="2.5s" repeatCount="indefinite"/>
            </circle>
          </svg>
          <div>
            <div style={{ fontFamily:"'Orbitron',monospace", fontWeight:900, fontSize:"14px", letterSpacing:"0.14em", color:C.t1, lineHeight:1 }}>WEBINTELX</div>
            <div style={{ fontFamily:"'Share Tech Mono',monospace", fontSize:"10px", color:C.t3, letterSpacing:"0.18em", marginTop:"3px" }}>THREAT INTELLIGENCE SYS</div>
          </div>
        </div>
        <div style={{ display:"flex", alignItems:"center", gap:"20px" }}>
          <span style={{ fontFamily:"'Share Tech Mono',monospace", fontSize:"11px", color:C.t3, letterSpacing:"0.1em" }}>QUICK_SCAN // MODULE_01</span>
          <div style={{
            display:"flex", alignItems:"center", gap:"7px",
            background: isScanning ? "#FFFBEB" : "#EAF4EE",
            border:`1px solid ${isScanning ? C.amberBorder : C.greenBorder}`,
            padding:"5px 13px", borderRadius:"20px",
          }}>
            <span style={{ width:"6px", height:"6px", borderRadius:"50%", background: isScanning ? C.amber : C.accent, display:"inline-block", animation:"pulse 2s ease-in-out infinite" }}/>
            <span style={{ fontFamily:"'Share Tech Mono',monospace", fontSize:"11px", color: isScanning ? C.amber : C.accent, letterSpacing:"0.1em" }}>
              {isScanning ? "SCANNING..." : "READY"}
            </span>
          </div>
        </div>
      </nav>

      {/* ── PAGE ── */}
      <div style={{ maxWidth:"1100px", margin:"0 auto", padding:"100px 40px 80px" }}>

        {/* Hero */}
        <div style={{ marginBottom:"52px", animation:"fadeUp 0.5s ease 0.1s both" }}>
          <div style={{ display:"flex", alignItems:"center", gap:"10px", marginBottom:"14px" }}>
            <div style={{ width:"3px", height:"18px", background:C.accent }}/>
            <span style={{ fontFamily:"'Share Tech Mono',monospace", fontSize:"11px", color:C.accent, letterSpacing:"0.22em" }}>// MODULE_01 / QUICK_SCAN</span>
          </div>
          <h1 style={{
            fontFamily:"'Orbitron',monospace", fontWeight:900,
            fontSize:"clamp(26px,4.5vw,52px)", color:C.t1,
            letterSpacing:"0.02em", lineHeight:1.1, marginBottom:"16px",
          }}>
            QUICK <span style={{ color:C.accent }}>SCAN</span>
          </h1>
          <p style={{ fontFamily:"'Rajdhani',sans-serif", fontSize:"17px", color:C.t2, lineHeight:1.75, maxWidth:"500px", fontWeight:500 }}>
            High-level security snapshot to identify immediate risks. Recon + OSINT surface analysis in approximately 2 minutes.
          </p>
          <div style={{ width:"40px", height:"3px", background:C.accent, marginTop:"18px" }}/>
        </div>

        {/* ── INPUT CARD ── */}
        <div style={{
          background:C.surface, border:`1px solid ${C.border}`,
          borderTop:`3px solid ${C.accent}`,
          padding:"32px 36px",
          maxWidth:"620px", marginBottom:"36px",
          animation:"fadeUp 0.5s ease 0.2s both",
          boxShadow:"0 2px 12px rgba(0,0,0,0.06)",
        }}>
          <div style={{ fontFamily:"'Share Tech Mono',monospace", fontSize:"10px", color:C.t3, letterSpacing:"0.22em", marginBottom:"18px" }}>TARGET_INPUT // ENTER_URL_OR_DOMAIN</div>
          <label style={{ fontFamily:"'Orbitron',monospace", fontSize:"11px", letterSpacing:"0.12em", color:C.t2, display:"block", marginBottom:"12px" }}>TARGET URL</label>
          <div style={{ display:"flex", gap:"10px", flexWrap:"wrap" }}>
            <input
              value={input}
              onChange={e => { setInput(e.target.value); if (error) setError(""); }}
              onKeyDown={e => e.key === "Enter" && handleScan()}
              placeholder="example.com"
              style={{
                flex:"1 1 240px", padding:"12px 16px",
                background:C.bg, border:`1.5px solid ${C.border}`,
                color:C.t1, fontFamily:"'Share Tech Mono',monospace",
                fontSize:"14px", outline:"none",
                letterSpacing:"0.04em", transition:"border-color 0.15s",
              }}
              onFocus={e => e.target.style.borderColor = C.accent}
              onBlur={e  => e.target.style.borderColor = C.border}
            />
            <button
              onClick={handleScan}
              style={{
                fontFamily:"'Orbitron',monospace", fontWeight:700, fontSize:"12px",
                letterSpacing:"0.18em", color:"#fff",
                background:C.accent,
                border:"none", padding:"12px 28px",
                cursor: isScanning ? "default" : "pointer",
                display:"flex", alignItems:"center", gap:"8px",
                boxShadow:"0 2px 10px rgba(10,102,64,0.25)",
                opacity: isScanning ? 0.75 : 1,
                transition:"all 0.15s",
              }}
              onMouseEnter={e => { if (!isScanning) e.currentTarget.style.background = "#0d7a4e"; }}
              onMouseLeave={e => { e.currentTarget.style.background = C.accent; }}
            >
              {isScanning
                ? <><span style={{ width:"12px", height:"12px", border:"2px solid rgba(255,255,255,0.3)", borderTop:"2px solid #fff", borderRadius:"50%", animation:"spin 0.7s linear infinite", display:"inline-block" }}/> SCANNING</>
                : <><FaSearch style={{ fontSize:"11px" }}/> SCAN</>
              }
            </button>
          </div>
          {error && (
            <div style={{ marginTop:"12px", fontFamily:"'Share Tech Mono',monospace", fontSize:"12px", color:C.red, letterSpacing:"0.06em" }}>
              ✕ {error}
            </div>
          )}
        </div>

        {/* ── LOADER ── */}
        {isScanning && (
          <div ref={loaderRef} style={{ maxWidth:"620px", marginBottom:"36px", animation:"fadeUp 0.4s ease both" }}>
            <div style={{
              background:C.surface, border:`1px solid ${C.amberBorder}`,
              borderLeft:`4px solid ${C.amber}`,
              padding:"28px 32px",
              boxShadow:"0 2px 8px rgba(0,0,0,0.05)",
            }}>
              <div style={{ display:"flex", alignItems:"center", gap:"14px", marginBottom:"18px" }}>
                <div style={{ width:"18px", height:"18px", border:`2px solid ${C.border}`, borderTop:`2px solid ${C.accent}`, borderRadius:"50%", animation:"spin 0.8s linear infinite", flexShrink:0 }}/>
                <span style={{ fontFamily:"'Orbitron',monospace", fontWeight:700, fontSize:"13px", color:C.amber, letterSpacing:"0.08em" }}>RUNNING SECURITY CHECKS</span>
              </div>
              <div style={{ height:"3px", background:C.border, overflow:"hidden", marginBottom:"18px" }}>
                <div style={{ height:"100%", background:C.accent, animation:"barFill 90s linear forwards" }}/>
              </div>
              <div style={{ display:"flex", flexDirection:"column", gap:"6px" }}>
                {["› Enumerating subdomains via crt.sh (Certificate Transparency)...","› Probing HTTP headers & security posture...","› Scanning open ports...","› Verifying SSL/TLS certificate...","› Querying WHOIS registration data...","› Running DNS resolution...","› Analysing technology stack (Wappalyzer)...","› Running traceroute...","› Checking email / domain reputation..."].map((line,i) => (
                  <div key={i} style={{ fontFamily:"'Share Tech Mono',monospace", fontSize:"12px", color:C.t2, animation:`shimmer 2s ease ${i*0.4}s infinite`, letterSpacing:"0.02em", lineHeight:2 }}>{line}</div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ══════════════════════════════════════════════
            RESULTS
        ══════════════════════════════════════════════ */}
        {scanDone && r && (
          <div ref={resultsRef} style={{ animation:"fadeUp 0.4s ease both" }}>

            {/* ── RISK SUMMARY BANNER ── */}
            <div style={{
              background:C.surface, border:`1px solid ${riskBorder(overallRisk)}`,
              borderLeft:`5px solid ${riskColor(overallRisk)}`,
              borderRadius:"8px", overflow:"hidden",
              marginBottom:"8px",
              boxShadow:"0 4px 16px rgba(0,0,0,0.06)",
            }}>
              <div style={{ display:"grid", gridTemplateColumns:"240px 1fr", minHeight:"140px" }}>

                {/* Left: score */}
                <div style={{
                  padding:"24px 24px",
                  borderRight:`1px solid ${C.border}`,
                  display:"flex", flexDirection:"column", justifyContent:"center", gap:"12px",
                }}>
                  <div>
                    <div style={{ fontFamily:"'DM Mono',monospace", fontSize:"10px", color:C.t3, letterSpacing:"0.1em", marginBottom:"8px" }}>RISK LEVEL</div>
                    <div style={{
                      fontFamily:"'Orbitron',monospace", fontWeight:900,
                      fontSize:"clamp(22px,2.8vw,32px)", color:riskColor(overallRisk),
                      lineHeight:1, letterSpacing:"0.02em",
                      whiteSpace:"nowrap",
                    }}>{overallRisk}</div>
                  </div>
                  <div>
                    <div style={{ display:"flex", justifyContent:"space-between", marginBottom:"5px" }}>
                      <span style={{ fontFamily:"'DM Mono',monospace", fontSize:"10px", color:C.t3 }}>Score</span>
                      <span style={{ fontFamily:"'DM Mono',monospace", fontSize:"12px", color:riskColor(overallRisk), fontWeight:500 }}>
                        {riskAssessment?.score ?? "—"}<span style={{ color:C.t3, fontWeight:400 }}>/15</span>
                      </span>
                    </div>
                    <div style={{ height:"5px", background:C.border, borderRadius:"3px", overflow:"hidden" }}>
                      <div style={{
                        height:"100%",
                        width:`${((riskAssessment?.score??0)/15)*100}%`,
                        background:riskColor(overallRisk),
                        borderRadius:"3px", transition:"width 0.8s ease",
                      }}/>
                    </div>
                  </div>
                  <div>
                    <div style={{ fontFamily:"'DM Mono',monospace", fontSize:"10px", color:C.t3, marginBottom:"3px" }}>TARGET</div>
                    <div style={{ fontFamily:"'DM Mono',monospace", fontSize:"12px", color:C.t1, wordBreak:"break-all", lineHeight:1.4 }}>{input}</div>
                  </div>
                </div>

                {/* Right: findings */}
                <div style={{ padding:"20px 24px" }}>
                  <div style={{ fontFamily:"'DM Mono',monospace", fontSize:"10px", color:C.t3, letterSpacing:"0.1em", marginBottom:"12px" }}>KEY FINDINGS</div>
                  {riskAssessment?.findings?.length > 0 ? (
                    <div style={{ display:"flex", flexDirection:"column", gap:"6px" }}>
                      {riskAssessment.findings.map((f,i) => (
                        <Finding key={i} text={f} level={overallRisk==="CRITICAL"||overallRisk==="HIGH"?"critical":"warn"} />
                      ))}
                    </div>
                  ) : (
                    <Finding text="No critical findings detected in this scan" level="info" />
                  )}
                </div>
              </div>
            </div>

            {/* ── 01 CORE SECURITY ── */}
            <SectionTitle num={1} label="Core Security Signals" />
            <div style={{ display:"flex", flexDirection:"column", gap:"8px" }}>

              {/* SSL */}
              <Card title="SSL / TLS Certificate"
                icon={r.ssl?.valid ? <FaLock/> : <FaUnlock/>}
                risk={!r.ssl?.valid?"HIGH":r.ssl?.daysRemaining<30?"MEDIUM":"LOW"}
                summary={r.ssl?.valid ? `Valid · ${r.ssl?.daysRemaining??'?'} days remaining` : "Certificate invalid or missing"}
                defaultOpen={!r.ssl?.valid}>
                <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr" }}>
                  <DataRow label="Status"    value={r.ssl?.valid?"✓ Valid":"✕ Invalid"} valueColor={r.ssl?.valid?C.green:C.red} />
                  <DataRow label="Days Left" value={r.ssl?.daysRemaining??'N/A'} valueColor={r.ssl?.daysRemaining<30?C.amber:C.t1} />
                  <DataRow label="Valid From" value={r.ssl?.validFrom?r.ssl.validFrom.split("T")[0]:"N/A"} />
                  <DataRow label="Valid To"   value={r.ssl?.validTo?r.ssl.validTo.split("T")[0]:"N/A"} />
                  <DataRow label="Issuer"  value={r.ssl?.issuer??"Unknown"} />
                  <DataRow label="Subject" value={r.ssl?.subject??"N/A"} />
                </div>
                {!r.ssl?.valid && <Finding text="HTTPS not enforced — data transmitted in plaintext" level="critical"/>}
                {r.ssl?.daysRemaining<30 && r.ssl?.valid && <Finding text={`Certificate expires in ${r.ssl.daysRemaining} days — renew immediately`} level="warn"/>}
              </Card>

              {/* HTTP Headers */}
              <Card title="HTTP Security Headers"
                icon={<FaShieldAlt/>}
                risk={r.headers?.missingSecurityHeaders?.length>=3?"HIGH":r.headers?.missingSecurityHeaders?.length>0?"MEDIUM":"LOW"}
                summary={`${r.headers?.missingSecurityHeaders?.length??0} missing security headers`}
                defaultOpen={r.headers?.missingSecurityHeaders?.length>=2}>
                <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr" }}>
                  <DataRow label="Server"        value={r.headers?.server??"Hidden"} valueColor={r.headers?.server?C.orange:C.green} />
                  <DataRow label="X-Powered-By"  value={r.headers?.poweredBy??"Hidden"} valueColor={r.headers?.poweredBy?C.orange:C.green} />
                  <DataRow label="HSTS"          value={r.headers?.strictTransport?"Present":"MISSING"} valueColor={r.headers?.strictTransport?C.green:C.red} />
                  <DataRow label="X-Frame-Options" value={r.headers?.xFrameOptions||"MISSING"} valueColor={r.headers?.xFrameOptions?C.green:C.red} />
                  <DataRow label="CSP"           value={r.headers?.csp?"Present":"MISSING"} valueColor={r.headers?.csp?C.green:C.red} />
                  <DataRow label="Referrer-Policy" value={r.headers?.referrer??"MISSING"} valueColor={r.headers?.referrer?C.green:C.red} />
                  <DataRow label="CORS"          value={r.headers?.cors??"Not set"} valueColor={r.headers?.cors==="*"?C.red:C.t1} />
                  <DataRow label="XSS-Protection" value={r.headers?.xssProtection??"Not set"} />
                </div>
                {r.headers?.missingSecurityHeaders?.length>0&&(<>
                  <CardSection label="Missing Headers"/>
                  {r.headers.missingSecurityHeaders.map((h,i)=><Finding key={i} text={h} level="warn"/>)}
                </>)}
                {r.headers?.cors==="*"&&<Finding text="Wildcard CORS allows any origin to make cross-site requests" level="critical"/>}
                {r.headers?.poweredBy?.includes("PHP/5")&&<Finding text="PHP 5.x is end-of-life and contains known vulnerabilities" level="critical"/>}
              </Card>

              {/* Tech Stack */}
              <Card title="Technology Stack" icon={<FaCode/>} risk={techRisk} summary={techSummary} defaultOpen={outdatedTechs.length>0}>
                {techEntries.length>0 ? (<>
                  {outdatedTechs.length>0&&(
                    <div style={{ margin:"16px 20px", background:C.orangeLt, border:`1px solid ${C.orangeBorder}`, borderRadius:"6px", overflow:"hidden" }}>
                      <div style={{ padding:"10px 16px", display:"flex", alignItems:"center", gap:"8px", borderBottom:`1px solid ${C.orangeBorder}` }}>
                        <FaExclamationTriangle style={{ color:C.orange, fontSize:"12px" }}/>
                        <span style={{ fontFamily:"'DM Mono',monospace", fontSize:"11px", color:C.orange, fontWeight:500 }}>OUTDATED COMPONENTS DETECTED</span>
                      </div>
                      {outdatedTechs.map((t,i)=>{
                        const col = severityColor(t.outdated.severity);
                        return (
                          <div key={i} style={{ display:"flex", gap:"12px", padding:"12px 16px", borderBottom:`1px solid ${C.orangeBorder}`, alignItems:"flex-start" }}>
                            <Badge label={t.outdated.severity} color={col} bg={`${col}15`} border={`${col}30`}/>
                            <div>
                              <div style={{ fontFamily:"'DM Mono',monospace", fontSize:"12px", color:C.t1, marginBottom:"3px" }}>
                                {t.name}{t.version?` ${t.version}`:""}
                                {t.outdated.latest&&<span style={{ color:C.green, marginLeft:"10px" }}>→ Latest: {t.outdated.latest}x</span>}
                              </div>
                              <div style={{ fontFamily:"'DM Sans',sans-serif", fontSize:"13px", color:C.t2, lineHeight:1.5 }}>{t.outdated.note}</div>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}
                  <CardSection label="Detected Stack"/>
                  <div style={{ display:"flex", flexWrap:"wrap", gap:"6px", padding:"12px 20px" }}>
                    {techEntries.map((t,i)=><TechTag key={i} name={t.name} version={t.version} outdated={t.outdated}/>)}
                  </div>
                  <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr" }}>
                    <DataRow label="Total Technologies"  value={techEntries.length}/>
                    <DataRow label="Outdated Components" value={outdatedTechs.length} valueColor={outdatedTechs.length>0?C.orange:C.green}/>
                    <DataRow label="Server Software"     value={r.headers?.server??"Unknown"}/>
                    <DataRow label="Backend Language"    value={r.headers?.poweredBy??"Unknown"} valueColor={r.headers?.poweredBy?.includes("PHP/5")?C.orange:C.t1}/>
                  </div>
                  {r.headers?.poweredBy?.includes("PHP/5")&&!outdatedTechs.find(t=>t.name.toLowerCase().includes("php"))&&
                    <Finding text="PHP 5.x reached EOL in Dec 2018 — upgrade to PHP 8.x" level="critical"/>}
                </>) : <Finding text="No technology fingerprints detected" level="info"/>}
              </Card>

              {/* Endpoints */}
              <Card title="Exposed Endpoints" icon={<FaBug/>}
                risk={r.endpoints?.length>20?"HIGH":r.endpoints?.length>10?"MEDIUM":"LOW"}
                summary={`${r.endpoints?.length??0} parameterized endpoints discovered`}>
                <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr" }}>
                  <DataRow label="Total Endpoints"  value={r.endpoints?.length??0} valueColor={r.endpoints?.length>20?C.orange:C.t1}/>
                  <DataRow label="Unique Params"     value={r.endpoints?new Set(r.endpoints.map(e=>e.param)).size:0}/>
                </div>
                {r.endpoints?.length>0&&(<>
                  <CardSection label="Sample Endpoints"/>
                  <div style={{ display:"flex", flexDirection:"column", gap:"4px", padding:"8px 20px" }}>
                    {r.endpoints.slice(0,8).map((ep,i)=>(
                      <div key={i} style={{ fontFamily:"'DM Mono',monospace", fontSize:"12px", color:C.t1, padding:"8px 12px", background:C.bg, border:`1px solid ${C.border}`, borderRadius:"5px", display:"flex", gap:"10px", alignItems:"baseline" }}>
                        <span style={{ color:C.amber, fontSize:"10px", fontWeight:500, flexShrink:0 }}>[{ep.param?.toUpperCase()??"?"}]</span>
                        <span style={{ color:C.t2, wordBreak:"break-all" }}>{ep.url}</span>
                      </div>
                    ))}
                    {r.endpoints.length>8&&<div style={{ fontFamily:"'DM Mono',monospace", fontSize:"11px", color:C.t3, padding:"4px 0" }}>+{r.endpoints.length-8} more endpoints</div>}
                  </div>
                  {r.endpoints?.length>20&&<Finding text="Large number of parameterized endpoints increases SQL injection attack surface" level="warn"/>}
                </>)}
              </Card>

              {/* Open Ports */}
              <Card title="Network & Open Ports" icon={<FaNetworkWired/>}
                risk={r.openPorts?.some(p=>[21,23,3306].includes(p.port))?"HIGH":r.openPorts?.length>3?"MEDIUM":"LOW"}
                summary={`${r.openPorts?.length??0} open ports detected`}>
                {r.openPorts?.length>0?(<>
                  <div style={{ padding:"16px 20px", display:"flex", flexWrap:"wrap", gap:"8px" }}>
                    {r.openPorts.map((p,i)=>{
                      const danger=[21,23,25,3306].includes(p.port);
                      const col=danger?C.orange:p.port===443?C.green:"#2563AB";
                      return (
                        <div key={i} style={{ fontFamily:"'DM Mono',monospace", fontSize:"12px", color:col, background:`${col}0f`, border:`1px solid ${col}28`, padding:"10px 16px", borderRadius:"6px", display:"flex", flexDirection:"column", alignItems:"center", gap:"3px", minWidth:"60px" }}>
                          <span style={{ fontSize:"16px", fontWeight:500 }}>{p.port}</span>
                          <span style={{ fontSize:"10px", color:C.t3 }}>{p.name}</span>
                          {danger&&<span style={{ fontSize:"9px", color:C.orange, fontWeight:500 }}>⚠ RISK</span>}
                        </div>
                      );
                    })}
                  </div>
                  {r.openPorts.filter(p=>[21,23].includes(p.port)).map((p,i)=><Finding key={i} text={`Port ${p.port} (${p.name}) transmits credentials in plaintext — disable or restrict`} level="critical"/>)}
                  {r.openPorts.find(p=>p.port===3306)&&<Finding text="MySQL port 3306 exposed to public — restrict to localhost only" level="critical"/>}
                  {!r.openPorts.find(p=>p.port===443)&&<Finding text="HTTPS (port 443) not detected — traffic may be unencrypted" level="warn"/>}
                </>):<Finding text="No common ports detected as open" level="info"/>}
              </Card>

              {/* Attack Surface */}
              <Card title="Attack Surface (crt.sh)" icon={<FaSearch/>}
                risk={r.securityTrails?.risk??"LOW"}
                summary={`${r.securityTrails?.subdomainCount??0} subdomains discovered`}>
                <DataRow label="Subdomain Count" value={r.securityTrails?.subdomainCount??0} valueColor={r.securityTrails?.subdomainCount>10?C.orange:C.t1}/>
                <DataRow label="Scan Method" value={`Passive — ${r.securityTrails?.note?.replace("Subdomain enumeration via ","")||"crt.sh"}`}/>
                {r.securityTrails?.subdomains?.length>0&&(<>
                  <CardSection label="Discovered Subdomains"/>
                  <div style={{ display:"flex", flexWrap:"wrap", gap:"6px", padding:"10px 20px" }}>
                    {r.securityTrails.subdomains.slice(0,12).map((s,i)=><Chip key={i} label={s}/>)}
                  </div>
                  {r.securityTrails.subdomains.length>12&&<div style={{ fontFamily:"'DM Mono',monospace", fontSize:"11px", color:C.t3, padding:"4px 20px 12px" }}>+{r.securityTrails.subdomains.length-12} more subdomains</div>}
                </>)}
                {r.securityTrails?.subdomainCount>30&&<Finding text="Large subdomain count indicates broad attack surface — audit each subdomain" level="warn"/>}
              </Card>
            </div>

            {/* ── 02 INFRASTRUCTURE ── */}
            <SectionTitle num={2} label="Infrastructure Intelligence" />
            <div style={{ display:"flex", flexDirection:"column", gap:"8px" }}>

              {/* DNS */}
              <Card title="DNS Intelligence" icon={<FaGlobe/>}
                risk={!r.dns?.resolvedSuccessfully?"MEDIUM":"LOW"}
                summary={r.dns?.resolvedSuccessfully?`Resolved · Primary IP: ${r.dns?.primaryIP??"N/A"}`:"DNS resolution failed"}>
                <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr" }}>
                  <DataRow label="Resolved"   value={r.dns?.resolvedSuccessfully?"✓ Yes":"✕ No"} valueColor={r.dns?.resolvedSuccessfully?C.green:C.red}/>
                  <DataRow label="Primary IP" value={r.dns?.primaryIP??"N/A"}/>
                  <DataRow label="A Records"  value={r.dns?.A?.length??0}/>
                  <DataRow label="MX Records" value={r.dns?.MX?.length??0}/>
                  <DataRow label="NS Records" value={r.dns?.NS?.length??0}/>
                </div>
                {r.dns?.A?.length>1&&(<><CardSection label="IP Addresses"/><div style={{ display:"flex", flexWrap:"wrap", gap:"6px", padding:"10px 20px" }}>{r.dns.A.map((a,i)=><Chip key={i} label={a}/>)}</div></>)}
                {r.dns?.MX?.length>0&&(<><CardSection label="Mail Servers"/><div style={{ display:"flex", flexWrap:"wrap", gap:"6px", padding:"10px 20px" }}>{r.dns.MX.map((m,i)=><Chip key={i} label={m} color="#7C3AED"/>)}</div></>)}
                {r.dns?.NS?.length>0&&(<><CardSection label="Name Servers"/><div style={{ display:"flex", flexWrap:"wrap", gap:"6px", padding:"10px 20px" }}>{r.dns.NS.map((n,i)=><Chip key={i} label={n} color="#2563AB"/>)}</div></>)}
              </Card>

              {/* WHOIS */}
              <Card title="WHOIS Registration" icon={<FaFingerprint/>}
                risk={!r.whois||r.whois.registrar==="Unknown"?"MEDIUM":"LOW"}
                summary={r.whois?.registrar!=="Unknown"?`Registrar: ${r.whois?.registrar}`:"Registration data unavailable"}>
                <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr" }}>
                  <DataRow label="Registrar"      value={r.whois?.registrar??"Unknown"}/>
                  <DataRow label="Registrant Org" value={r.whois?.registrantOrg??"Unknown"}/>
                  <DataRow label="Created"        value={r.whois?.creationDate??"N/A"}/>
                  <DataRow label="Expires"        value={r.whois?.expiryDate??"N/A"}/>
                  <DataRow label="Last Updated"   value={r.whois?.updatedDate??"N/A"}/>
                  <DataRow label="Country"        value={r.whois?.country??"Unknown"}/>
                  <DataRow label="DNSSEC"         value={r.whois?.dnssec??"Unknown"}/>
                  <DataRow label="Nameservers"    value={r.whois?.nameservers?.length??0}/>
                </div>
                {r.whois?.nameservers?.length>0&&(<><CardSection label="Nameservers"/><div style={{ display:"flex", flexWrap:"wrap", gap:"6px", padding:"10px 20px" }}>{r.whois.nameservers.map((n,i)=><Chip key={i} label={n} color="#7C3AED"/>)}</div></>)}
              </Card>

              {/* Ping */}
              <Card title="Host Reachability" icon={<FaServer/>}
                risk={!r.ping?.reachable?"HIGH":r.ping?.packetLoss!=="0%"?"MEDIUM":"LOW"}
                summary={r.ping?.reachable?`Reachable · ${r.ping?.avgTime!=="N/A"?r.ping.avgTime+"ms avg":"latency N/A"}`:"Host unreachable"}>
                <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr" }}>
                  <DataRow label="Reachable"    value={r.ping?.reachable?"✓ Yes":"✕ No"} valueColor={r.ping?.reachable?C.green:C.red}/>
                  <DataRow label="Avg Latency"  value={r.ping?.avgTime!=="N/A"?`${r.ping.avgTime} ms`:"N/A"} valueColor={parseFloat(r.ping?.avgTime)>200?C.amber:C.t1}/>
                  <DataRow label="Packet Loss"  value={r.ping?.packetLoss??"0%"} valueColor={r.ping?.packetLoss!=="0%"?C.amber:C.t1}/>
                  <DataRow label="Packets Sent" value={r.ping?.sent??4}/>
                  <DataRow label="Received"     value={r.ping?.received??"N/A"}/>
                </div>
                {!r.ping?.reachable&&<Finding text="Host not responding to ICMP — may have firewall blocking ping" level="warn"/>}
                {parseFloat(r.ping?.avgTime)>300&&<Finding text="High latency detected — possible performance or routing issue" level="warn"/>}
              </Card>

              {/* Traceroute */}
              <Card title="Network Path (Traceroute)" icon={<FaRoute/>}
                risk={r.traceroute?.totalHops>20?"MEDIUM":"LOW"}
                summary={r.traceroute?`${r.traceroute.totalHops} hops · Final: ${r.traceroute.finalHop}`:"Traceroute unavailable"}>
                {r.traceroute?(<>
                  <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr" }}>
                    <DataRow label="Total Hops"     value={r.traceroute.totalHops} valueColor={r.traceroute.totalHops>20?C.amber:C.t1}/>
                    <DataRow label="Reachable Hops" value={r.traceroute.reachableHops}/>
                    <DataRow label="Final Hop"      value={r.traceroute.finalHop}/>
                    <DataRow label="Avg Latency"    value={r.traceroute.avgLatency?`${r.traceroute.avgLatency} ms`:"N/A"}/>
                  </div>
                  {r.traceroute.hops?.length>0&&(<>
                    <CardSection label="Network Path"/>
                    <div style={{ maxHeight:"200px", overflowY:"auto", display:"flex", flexDirection:"column", gap:"2px", padding:"8px 20px" }}>
                      {r.traceroute.hops.slice(0,20).map((hop,i)=>{
                        const isTimeout=hop.ip==="*"||hop.ip?.toLowerCase().includes("request");
                        return (
                          <div key={i} style={{ display:"flex", alignItems:"center", gap:"10px", fontFamily:"'DM Mono',monospace", fontSize:"12px", opacity:isTimeout?0.4:1 }}>
                            <span style={{ color:C.t3, width:"22px", textAlign:"right", flexShrink:0 }}>{hop.hop}</span>
                            <span style={{ width:"6px", height:"6px", borderRadius:"50%", background:isTimeout?C.border:C.accent, flexShrink:0 }}/>
                            <span style={{ color:isTimeout?C.t3:C.t1, fontStyle:isTimeout?"italic":"normal" }}>
                              {isTimeout?"* * *  (no response)":hop.ip}
                            </span>
                            {hop.hostname&&!isTimeout&&<span style={{ color:C.t3, fontSize:"11px" }}>({hop.hostname})</span>}
                            {hop.latency&&!isTimeout&&<span style={{ color:C.t3, marginLeft:"auto" }}>{hop.latency}ms</span>}
                          </div>
                        );
                      })}
                    </div>
                  </>)}
                </>):<Finding text="Traceroute blocked or timed out" level="info"/>}
              </Card>

              {/* Email Intel */}
              <Card title="Email & Domain Intelligence" icon={<FaEnvelope/>}
                risk={r.emailIntelligence?.risk??"LOW"}
                summary={(() => {
                  const d=r.emailIntelligence; if(!d) return "Check unavailable";
                  const pts=[];
                  if(d.dnsbl?.listed) pts.push(`⚠ Listed on ${d.dnsbl.listCount} blocklist(s)`); else pts.push("✓ Not blacklisted");
                  if(d.hunter?.available) pts.push(`${d.hunter.totalEmails} emails found`);
                  return pts.join(" · ");
                })()}
                defaultOpen={r.emailIntelligence?.blacklisted}>
                <CardSection label="DNS Blocklist"/>
                <DataRow label="Blacklisted" value={r.emailIntelligence?.dnsbl?.listed?`YES — ${r.emailIntelligence.dnsbl.listCount} list(s)`:"NO ✓"} valueColor={r.emailIntelligence?.dnsbl?.listed?C.red:C.green}/>
                <DataRow label="IP Address"  value={r.emailIntelligence?.dnsbl?.ip??"N/A"}/>
                {r.emailIntelligence?.dnsbl?.listedOn?.length>0&&(<>
                  <CardSection label="Listed On"/>
                  <div style={{ display:"flex", flexWrap:"wrap", gap:"6px", padding:"10px 20px" }}>{r.emailIntelligence.dnsbl.listedOn.map((l,i)=><Chip key={i} label={l} color={C.red}/>)}</div>
                  <Finding text={`Listed on ${r.emailIntelligence.dnsbl.listCount} DNS blocklist(s) — likely associated with spam or malicious activity`} level="critical"/>
                </>)}
                {r.emailIntelligence?.dnsbl?.clean&&<Finding text="Domain and IP are clean across Spamhaus, SURBL, URIBL, Barracuda, and SpamCop" level="info"/>}
                {r.emailIntelligence?.hunter?.available?(<>
                  <CardSection label="Hunter.io Email Intelligence"/>
                  <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr" }}>
                    <DataRow label="Organisation"  value={r.emailIntelligence.hunter.organization??"Unknown"}/>
                    <DataRow label="Total Emails"  value={r.emailIntelligence.hunter.totalEmails} valueColor="#7C3AED"/>
                    <DataRow label="Email Pattern" value={r.emailIntelligence.hunter.pattern??"Unknown"} valueColor="#2563AB"/>
                    <DataRow label="MX Record"     value={r.emailIntelligence.hunter.mxRecord??"None"}/>
                    <DataRow label="Webmail"       value={r.emailIntelligence.hunter.webmail?"Yes":"No"}/>
                    <DataRow label="Accept-All"    value={r.emailIntelligence.hunter.acceptAll?"Yes ⚠":"No"} valueColor={r.emailIntelligence.hunter.acceptAll?C.amber:C.t1}/>
                  </div>
                  {r.emailIntelligence.hunter.emails?.length>0&&(<>
                    <CardSection label="Discovered Emails"/>
                    <div style={{ display:"flex", flexDirection:"column", gap:"6px", padding:"10px 20px" }}>
                      {r.emailIntelligence.hunter.emails.map((e,i)=>(
                        <div key={i} style={{ padding:"12px 16px", background:C.bg, border:`1px solid ${C.border}`, borderLeft:`3px solid #7C3AED`, borderRadius:"6px" }}>
                          <div style={{ display:"flex", alignItems:"center", gap:"8px", flexWrap:"wrap", marginBottom:"4px" }}>
                            <span style={{ fontFamily:"'DM Mono',monospace", fontSize:"13px", color:"#7C3AED" }}>{e.email}</span>
                            <Badge label={`${e.confidence}% confidence`} color="#7C3AED"/>
                            {e.type&&<Badge label={e.type} color="#2563AB"/>}
                          </div>
                          {(e.firstName||e.position)&&<div style={{ fontFamily:"'DM Sans',sans-serif", fontSize:"13px", color:C.t2 }}>{[e.firstName,e.lastName].filter(Boolean).join(" ")}{e.position?` · ${e.position}`:""}</div>}
                        </div>
                      ))}
                      {r.emailIntelligence.hunter.totalEmails>6&&<div style={{ fontFamily:"'DM Mono',monospace", fontSize:"11px", color:C.t3 }}>+{r.emailIntelligence.hunter.totalEmails-6} more on Hunter.io</div>}
                    </div>
                  </>)}
                </>):<Finding text={r.emailIntelligence?.hunter?.note||"Add HUNTER_API_KEY to .env to enable email discovery"} level="info"/>}
              </Card>
            </div>

            {/* ── 03 THREAT INTEL ── */}
            <SectionTitle num={3} label="Threat Intelligence" />
            <div style={{ display:"flex", flexDirection:"column", gap:"8px" }}>

              {/* Safe Browsing */}
              <Card title="Google Safe Browsing" icon={<FaShieldAlt/>}
                risk={r.safeBrowsing?.risk??"LOW"}
                summary={!r.safeBrowsing?.available?"API key not configured":r.safeBrowsing?.safe===false?`${r.safeBrowsing.threatCount} threat(s) detected`:"No threats detected"}
                defaultOpen={r.safeBrowsing?.safe===false}>
                {r.safeBrowsing?.available?(<>
                  <DataRow label="Status"       value={r.safeBrowsing.safe?"✓ Clean":"✕ Flagged"} valueColor={r.safeBrowsing.safe?C.green:C.red}/>
                  <DataRow label="Threats Found" value={r.safeBrowsing.threatCount??0} valueColor={r.safeBrowsing.threatCount>0?C.red:C.t1}/>
                  {r.safeBrowsing.threats?.length>0&&(<><CardSection label="Threat Types"/><div style={{ display:"flex", flexWrap:"wrap", gap:"6px", padding:"10px 20px" }}>{r.safeBrowsing.threats.map((t,i)=><Chip key={i} label={t} color={C.red}/>)}</div><Finding text="Domain flagged by Google Safe Browsing — high risk to visitors" level="critical"/></>)}
                  {r.safeBrowsing.safe&&<Finding text="Domain is not flagged in Google's threat database" level="info"/>}
                </>):<Finding text={r.safeBrowsing?.note||"Add GOOGLE_SAFE_BROWSING_KEY to .env to enable"} level="info"/>}
              </Card>

              {/* VirusTotal */}
              <Card title="VirusTotal Domain Report" icon={<FaVirus/>}
                risk={r.virusTotal?.risk??"LOW"}
                summary={!r.virusTotal?.available?"API key not configured":`${r.virusTotal?.malicious??0}/${r.virusTotal?.total??0} engines flagged`}
                defaultOpen={r.virusTotal?.malicious>0}>
                {r.virusTotal?.available?(<>
                  <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr" }}>
                    <DataRow label="Malicious"       value={r.virusTotal.malicious} valueColor={r.virusTotal.malicious>0?C.red:C.t1}/>
                    <DataRow label="Suspicious"      value={r.virusTotal.suspicious} valueColor={r.virusTotal.suspicious>0?C.amber:C.t1}/>
                    <DataRow label="Harmless"        value={r.virusTotal.harmless} valueColor={C.green}/>
                    <DataRow label="Total Engines"   value={r.virusTotal.total}/>
                    <DataRow label="Community Score" value={r.virusTotal.communityScore} valueColor={r.virusTotal.communityScore<0?C.orange:C.t1}/>
                    <DataRow label="Last Analysis"   value={r.virusTotal.lastAnalysis??"N/A"}/>
                  </div>
                  {r.virusTotal.categories?.length>0&&(<><CardSection label="Categories"/><div style={{ display:"flex", flexWrap:"wrap", gap:"6px", padding:"10px 20px" }}>{r.virusTotal.categories.map((c,i)=><Chip key={i} label={c} color="#2563AB"/>)}</div></>)}
                  {r.virusTotal.popularity?.length>0&&(<><CardSection label="Popularity Rankings"/><div style={{ display:"flex", flexWrap:"wrap", gap:"6px", padding:"10px 20px" }}>{r.virusTotal.popularity.map((p,i)=><Chip key={i} label={p} color="#7C3AED"/>)}</div></>)}
                  {r.virusTotal.malicious>0&&<Finding text={`${r.virusTotal.malicious} security vendors flagged this domain as malicious`} level="critical"/>}
                </>):<Finding text={r.virusTotal?.note||"Add VIRUSTOTAL_API_KEY to .env to enable"} level={r.virusTotal?.warn?"warn":"info"}/>}
              </Card>

              {/* Shodan */}
              <Card title="Shodan Intelligence" icon={<FaEye/>}
                risk={r.shodan?.risk??"LOW"}
                summary={!r.shodan?.available?(r.shodan?.note||"API key not configured"):r.shodan?.note?r.shodan.note.substring(0,60)+"...":
                  `${r.shodan?.portCount??0} ports · ${r.shodan?.vulnCount??0} CVEs${r.shodan?.kevCount>0?` · ${r.shodan.kevCount} KEV`:""}`}
                defaultOpen={r.shodan?.vulnCount>0}>
                {r.shodan?.available&&!r.shodan?.note?(<>
                  <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr" }}>
                    <DataRow label="IP"          value={r.shodan.ip??"N/A"}/>
                    <DataRow label="Org"         value={r.shodan.org??"Unknown"}/>
                    <DataRow label="ISP"         value={r.shodan.isp??"Unknown"}/>
                    <DataRow label="ASN"         value={r.shodan.asn??"N/A"}/>
                    <DataRow label="Location"    value={r.shodan.city&&r.shodan.country?`${r.shodan.city}, ${r.shodan.country}`:"Unknown"}/>
                    <DataRow label="Last Seen"   value={r.shodan.lastSeen?.split("T")[0]??"N/A"}/>
                    <DataRow label="Open Ports"  value={r.shodan.portCount} valueColor={r.shodan.portCount>5?C.amber:C.t1}/>
                    <DataRow label="Total CVEs"  value={r.shodan.vulnCount} valueColor={r.shodan.vulnCount>0?C.red:C.t1}/>
                    <DataRow label="Critical CVEs (9+)" value={r.shodan.criticalCount??0} valueColor={r.shodan.criticalCount>0?C.red:C.t1}/>
                    <DataRow label="CISA KEV Count"     value={r.shodan.kevCount??0} valueColor={r.shodan.kevCount>0?C.red:C.t1}/>
                  </div>
                  {r.shodan.tags?.length>0&&(<><CardSection label="Shodan Tags"/><div style={{ display:"flex", flexWrap:"wrap", gap:"6px", padding:"10px 20px" }}>{r.shodan.tags.map((t,i)=><Chip key={i} label={t} color="#7C3AED"/>)}</div></>)}
                  {r.shodan.ports?.length>0&&(<><CardSection label="Open Ports"/><div style={{ display:"flex", flexWrap:"wrap", gap:"6px", padding:"10px 20px" }}>{r.shodan.ports.map((p,i)=><Chip key={i} label={String(p)} color="#2563AB"/>)}</div></>)}
                  {r.shodan.vulnDetails?.length>0&&(<>
                    <CardSection label="CVE Details"/>
                    <div style={{ display:"flex", flexDirection:"column", gap:"8px", padding:"12px 20px" }}>
                      {r.shodan.vulnDetails.map((cve,i)=>{
                        const cc=cve.cvss>=9?C.red:cve.cvss>=7?C.orange:C.amber;
                        return (
                          <div key={i} style={{ padding:"14px 16px", background:C.bg, border:`1px solid ${C.border}`, borderLeft:`3px solid ${cc}`, borderRadius:"6px" }}>
                            <div style={{ display:"flex", alignItems:"center", gap:"8px", marginBottom:"8px", flexWrap:"wrap" }}>
                              <span style={{ fontFamily:"'Syne',sans-serif", fontWeight:700, fontSize:"13px", color:cc }}>{cve.id}</span>
                              {cve.cvss&&<Badge label={`CVSS ${cve.cvss}`} color={cc}/>}
                              {cve.epss&&<Badge label={`EPSS ${cve.epss}%`} color={C.amber}/>}
                              {cve.kev&&<Badge label="⚠ CISA KEV" color={C.red}/>}
                            </div>
                            {cve.summary&&<div style={{ fontFamily:"'DM Sans',sans-serif", fontSize:"13px", color:C.t2, lineHeight:1.6 }}>{cve.summary}{cve.summary.length>=180?"...":""}</div>}
                          </div>
                        );
                      })}
                    </div>
                    {r.shodan.kevCount>0&&<Finding text={`${r.shodan.kevCount} CVE(s) on CISA's Known Exploited Vulnerabilities catalog — actively exploited in the wild`} level="critical"/>}
                  </>)}
                </>):<Finding text={r.shodan?.note||"Add SHODAN_API_KEY to .env to enable"} level="info"/>}
              </Card>
            </div>

            {/* ── 04 HOST INTEL ── */}
            <SectionTitle num={4} label="Host Intelligence" />
            <div style={{ display:"flex", flexDirection:"column", gap:"8px", marginBottom:"60px" }}>

              {/* ASN Geo */}
              <Card title="ASN & IP Geolocation" icon={<FaMapMarkerAlt/>}
                risk={r.asnGeo?.risk??"LOW"}
                summary={r.asnGeo?.available?`${r.asnGeo.city??"Unknown city"}, ${r.asnGeo.country??"Unknown"} · ${r.asnGeo.org??"Unknown org"}`:"Geolocation unavailable"}>
                {r.asnGeo?.available?(<>
                  <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr" }}>
                    <DataRow label="IP Address"   value={r.asnGeo.ip??"N/A"}/>
                    <DataRow label="Country"      value={r.asnGeo.country?`${r.asnGeo.country} (${r.asnGeo.countryCode})`:"Unknown"}/>
                    <DataRow label="City"         value={r.asnGeo.city??"Unknown"}/>
                    <DataRow label="Region"       value={r.asnGeo.region??"Unknown"}/>
                    <DataRow label="ISP"          value={r.asnGeo.isp??"Unknown"}/>
                    <DataRow label="Org"          value={r.asnGeo.org??"Unknown"}/>
                    <DataRow label="ASN"          value={r.asnGeo.asn??"N/A"}/>
                    <DataRow label="Timezone"     value={r.asnGeo.timezone??"Unknown"}/>
                    <DataRow label="Cloud Hosted" value={r.asnGeo.isCloud?`Yes — ${r.asnGeo.cloudProvider}`:"No"} valueColor={r.asnGeo.isCloud?"#2563AB":C.t1}/>
                    <DataRow label="Coordinates"  value={r.asnGeo.latitude?`${r.asnGeo.latitude}, ${r.asnGeo.longitude}`:"N/A"}/>
                  </div>
                  {r.asnGeo.isCloud&&<Finding text={`Hosted on ${r.asnGeo.cloudProvider} — shared IP space possible`} level="info"/>}
                </>):<Finding text={r.asnGeo?.note||"Geolocation lookup failed"} level="info"/>}
              </Card>

              {/* Cookies */}
              <Card title="HTTP Cookies Analysis" icon={<FaCookieBite/>}
                risk={r.cookies?.risk??"LOW"}
                summary={r.cookies?.available?`${r.cookies.cookieCount} cookie(s) · ${r.cookies.issues?.length??0} security issue(s)`:"Analysis unavailable"}
                defaultOpen={r.cookies?.issues?.length>0}>
                {r.cookies?.available?(<>
                  <DataRow label="Cookies Set"     value={r.cookies.cookieCount}/>
                  <DataRow label="Security Issues" value={r.cookies.issues?.length??0} valueColor={r.cookies.issues?.length>0?C.amber:C.t1}/>
                  {r.cookies.cookies?.length>0&&(<>
                    <CardSection label="Cookie Flags"/>
                    <div style={{ display:"flex", flexDirection:"column", gap:"6px", padding:"10px 20px" }}>
                      {r.cookies.cookies.map((c,i)=>(
                        <div key={i} style={{ padding:"10px 14px", background:C.bg, border:`1px solid ${C.border}`, borderRadius:"6px", display:"flex", gap:"10px", flexWrap:"wrap", alignItems:"center" }}>
                          <span style={{ fontFamily:"'Syne',sans-serif", fontWeight:600, fontSize:"12px", color:C.t1 }}>{c.name}</span>
                          <Badge label={`Secure: ${c.secure?"✓":"✕"}`} color={c.secure?C.green:C.red}/>
                          <Badge label={`HttpOnly: ${c.httpOnly?"✓":"✕"}`} color={c.httpOnly?C.green:C.red}/>
                          <Badge label={`SameSite: ${c.sameSite||"none"}`} color={c.sameSite?C.green:C.amber}/>
                        </div>
                      ))}
                    </div>
                  </>)}
                  {r.cookies.issues?.length>0&&(<><CardSection label="Issues"/>{r.cookies.issues.slice(0,6).map((issue,i)=><Finding key={i} text={issue} level="warn"/>)}</>)}
                </>):<Finding text={r.cookies?.note||"Cookie analysis failed"} level="info"/>}
              </Card>

              {/* Green */}
              <Card title="Carbon / Green Hosting" icon={<FaLeaf/>} risk="LOW"
                summary={r.greenWeb?.available?(r.greenWeb.green?`✓ Green hosted by ${r.greenWeb.hostedBy??"verified provider"}`:"Not verified as green hosted"):"Check unavailable"}>
                {r.greenWeb?.available?(<>
                  <DataRow label="Green Hosted"    value={r.greenWeb.green?"✓ Verified":"✕ Not Verified"} valueColor={r.greenWeb.green?C.green:C.t2}/>
                  <DataRow label="Hosted By"       value={r.greenWeb.hostedBy??"Unknown"}/>
                  {r.greenWeb.hostedByWebsite&&<DataRow label="Provider Site" value={r.greenWeb.hostedByWebsite}/>}
                  {r.greenWeb.green
                    ?<Finding text={`Verified renewable energy hosting: ${r.greenWeb.hostedBy}`} level="info"/>
                    :<Finding text="Host not verified as using renewable energy by The Green Web Foundation" level="info"/>}
                </>):<Finding text={r.greenWeb?.note||"Green web check unavailable"} level="info"/>}
              </Card>
            </div>

            {/* PDF Download */}
            <div style={{ borderTop:`1px solid ${C.border}`, paddingTop:"36px", textAlign:"center" }}>
              <button
                onClick={downloadPDF} disabled={isDownloading}
                style={{
                  fontFamily:"'Syne',sans-serif", fontWeight:700, fontSize:"14px",
                  color: isDownloading ? C.t3 : "#fff",
                  background: isDownloading
                    ? C.bg
                    : "linear-gradient(135deg,#0A6640,#138050)",
                  border: isDownloading ? `1px solid ${C.border}` : "none",
                  padding:"14px 36px", borderRadius:"8px",
                  cursor: isDownloading ? "not-allowed" : "pointer",
                  display:"inline-flex", alignItems:"center", gap:"10px",
                  boxShadow: isDownloading ? "none" : "0 4px 16px rgba(10,102,64,0.25)",
                  transition:"all 0.2s",
                }}
                onMouseEnter={e => { if(!isDownloading) e.currentTarget.style.transform="translateY(-2px)"; }}
                onMouseLeave={e => { e.currentTarget.style.transform="translateY(0)"; }}
              >
                <FaFileDownload style={{ fontSize:"14px" }}/>
                {isDownloading ? "Preparing report…" : "Download PDF Report"}
              </button>
              <div style={{ fontFamily:"'DM Mono',monospace", fontSize:"11px", color:C.t3, marginTop:"10px" }}>
                Includes full findings, evidence & remediation guidance
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}