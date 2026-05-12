import { useState, useRef, useEffect } from "react";
import {
  FaSearch, FaBug, FaShieldAlt, FaFileDownload,
  FaGlobe, FaServer, FaLock, FaUnlock, FaNetworkWired, FaEnvelope,
  FaRoute, FaChevronDown, FaChevronUp, FaCode,
  FaLeaf, FaSkull, FaMapMarkerAlt, FaCookieBite,
  FaVirus, FaEye, FaWordpress, FaExchangeAlt,
} from "react-icons/fa";
import axios from "axios";

const FONT_URL = "https://fonts.googleapis.com/css2?family=DM+Mono:ital,wght@0,300;0,400;0,500;1,400&family=Rajdhani:wght@500;600;700&family=DM+Sans:ital,opsz,wght@0,9..40,300;0,9..40,400;0,9..40,500;0,9..40,600;1,9..40,400&display=swap";

const C = {
  bg: "#F7F8F9", white: "#FFFFFF", border: "#E4E8EC", borderDark: "#CDD4DB",
  text: "#0F1923", textSecondary: "#3A4A58", textMuted: "#6B7C8D", textXMuted: "#9BAAB7",
  accent: "#6D28D9", accentLight: "#F5F3FF", accentBorder: "#DDD6FE", accentHover: "#5B21B6",
  green: "#0A6640", greenBg: "#EAF4EE", greenBorder: "#A7D7BC",
  amber: "#92600A", amberBg: "#FFFBEB", amberBorder: "#FDE68A",
  orange: "#B54A0C", orangeBg: "#FFF7ED", orangeBorder: "#FED7AA",
  red: "#C0312B", redBg: "#FEF2F2", redBorder: "#FECACA",
  blue: "#2563AB", blueBg: "#EFF6FF", blueBorder: "#BFDBFE",
  purple: "#6D28D9", purpleBg: "#F5F3FF", purpleBorder: "#DDD6FE",
  sidebarBg: "#0F1923", sidebarBorder: "#1E2A36", sidebarHover: "#1A2535",
  sidebarText: "#E6EDF3", sidebarMuted: "#8B949E", sidebarFaint: "#3D4E5E",
};

const riskColor  = (r) => ({ CRITICAL: C.red, HIGH: C.orange, MEDIUM: C.amber, LOW: C.green }[r] || C.green);
const riskBgCol  = (r) => ({ CRITICAL: C.redBg, HIGH: C.orangeBg, MEDIUM: C.amberBg, LOW: C.greenBg }[r] || C.greenBg);
const riskBorder = (r) => ({ CRITICAL: C.redBorder, HIGH: C.orangeBorder, MEDIUM: C.amberBorder, LOW: C.greenBorder }[r] || C.greenBorder);

// ─── ATOMS ────────────────────────────────────────────────────────────────────
const StatRow = ({ label, value, accent = C.blue }) => (
  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", padding: "10px 0", borderBottom: `1px solid ${C.border}`, gap: "16px" }}>
    <span style={{ fontFamily: "'DM Mono', monospace", fontSize: "13px", color: C.textSecondary, flexShrink: 0, fontWeight: 500 }}>{label}</span>
    <span style={{ fontFamily: "'DM Mono', monospace", fontSize: "13px", color: accent, textAlign: "right", wordBreak: "break-all", lineHeight: 1.5, fontWeight: 500 }}>{value ?? "N/A"}</span>
  </div>
);

const AlertRow = ({ text, severity = "warn" }) => {
  const map = {
    critical: { color: C.red, bg: C.redBg, border: C.redBorder, icon: "✕" },
    warn:     { color: C.amber, bg: C.amberBg, border: C.amberBorder, icon: "⚠" },
    info:     { color: C.green, bg: C.greenBg, border: C.greenBorder, icon: "✓" },
  };
  const s = map[severity] || map.warn;
  return (
    <div style={{ display: "flex", gap: "8px", alignItems: "flex-start", padding: "8px 12px", margin: "6px 0", borderRadius: "4px", background: s.bg, border: `1px solid ${s.border}` }}>
      <span style={{ color: s.color, fontSize: "14px", flexShrink: 0, marginTop: "1px" }}>{s.icon}</span>
      <span style={{ fontFamily: "'DM Sans', sans-serif", fontSize: "14px", color: s.color, lineHeight: 1.6, fontWeight: 500 }}>{text}</span>
    </div>
  );
};

const Tag = ({ children, color = C.purple }) => (
  <span style={{ fontFamily: "'DM Mono', monospace", fontSize: "12px", color, background: color + "18", border: `1px solid ${color}40`, padding: "4px 12px", borderRadius: "4px", marginRight: "6px", marginBottom: "6px", display: "inline-block", fontWeight: 500 }}>{children}</span>
);

const TagList = ({ items, color = C.purple }) => (
  <div style={{ display: "flex", flexWrap: "wrap", gap: "4px", margin: "8px 0" }}>
    {items.map((item, i) => <Tag key={i} color={color}>{item}</Tag>)}
  </div>
);

// ─── MODULE CARD ──────────────────────────────────────────────────────────────
const ModuleCard = ({ title, icon, risk, summary, children, defaultOpen = false }) => {
  const [open, setOpen] = useState(defaultOpen);
  const rc = riskColor(risk || "LOW"), rb = riskBgCol(risk || "LOW"), rbd = riskBorder(risk || "LOW");
  return (
    <div style={{ background: C.white, border: `1px solid ${open ? rbd : C.border}`, borderLeft: `4px solid ${rc}`, borderRadius: "0 6px 6px 0", overflow: "hidden", boxShadow: "0 1px 4px rgba(0,0,0,0.04)", transition: "border-color 0.15s" }}>
      <div onClick={() => setOpen(!open)} style={{ display: "flex", alignItems: "center", gap: "12px", padding: "14px 18px", cursor: "pointer", background: open ? rb : C.white, transition: "background 0.15s" }}
        onMouseEnter={e => { if (!open) e.currentTarget.style.background = C.bg; }}
        onMouseLeave={e => { if (!open) e.currentTarget.style.background = C.white; }}>
        <span style={{ color: rc, fontSize: "14px", flexShrink: 0 }}>{icon}</span>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontFamily: "'DM Mono', monospace", fontSize: "11px", color: C.textSecondary, marginBottom: "2px", letterSpacing: "0.04em", fontWeight: 500 }}>module</div>
          <div style={{ fontFamily: "'Syne', sans-serif", fontWeight: 700, fontSize: "15px", color: C.text }}>{title}</div>
        </div>
        {summary && <span style={{ fontFamily: "'DM Mono', monospace", fontSize: "13px", color: C.textSecondary, textAlign: "right", flexShrink: 0, maxWidth: "200px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontWeight: 500 }}>{summary}</span>}
        <span style={{ fontFamily: "'DM Mono', monospace", fontSize: "11px", fontWeight: 700, color: rc, background: rb, border: `1px solid ${rbd}`, borderRadius: "20px", padding: "3px 12px", flexShrink: 0 }}>{risk || "LOW"}</span>
        <span style={{ color: C.textSecondary, fontSize: "13px", flexShrink: 0 }}>{open ? <FaChevronUp /> : <FaChevronDown />}</span>
      </div>
      {open && <div style={{ padding: "16px 18px", borderTop: `1px solid ${C.border}` }}>{children}</div>}
    </div>
  );
};

function FaFingerprint(props) { return <FaSearch {...props} />; }

// ─── MODULE GROUPS ────────────────────────────────────────────────────────────
const MODULE_GROUPS = [
  {
    label: "Infrastructure", color: C.blue,
    modules: [
      { id: "dns",        label: "DNS Intelligence",    icon: <FaGlobe />,        desc: "Resolve A/MX/NS records" },
      { id: "whois",      label: "WHOIS / RDAP",        icon: <FaServer />,       desc: "Domain registration data" },
      { id: "ping",       label: "Ping / Reachability", icon: <FaNetworkWired />, desc: "ICMP echo & latency" },
      { id: "traceroute", label: "Traceroute",           icon: <FaRoute />,        desc: "Network path analysis" },
      { id: "ports",      label: "Port Scanner",         icon: <FaServer />,       desc: "Top 20 TCP ports" },
    ],
  },
  {
    label: "Web Security", color: C.purple,
    modules: [
      { id: "ssl",        label: "SSL / TLS",           icon: <FaLock />,        desc: "Certificate validation" },
      { id: "headers",    label: "Security Headers",    icon: <FaShieldAlt />,   desc: "HTTP security headers" },
      { id: "endpoints",  label: "Endpoint Discovery",  icon: <FaCode />,        desc: "Parameterized URLs" },
      { id: "wappalyzer", label: "Tech Stack",           icon: <FaFingerprint />, desc: "Technology fingerprinting" },
    ],
  },
  {
    label: "OSINT", color: "#7C3AED",
    modules: [
      { id: "shodan",       label: "Shodan Intelligence", icon: <FaEye />,          desc: "Host & CVE intelligence" },
      { id: "virusTotal",   label: "VirusTotal",          icon: <FaVirus />,        desc: "AV engine domain scan" },
      { id: "safeBrowsing", label: "Safe Browsing",       icon: <FaShieldAlt />,    desc: "Google threat database" },
      { id: "asnGeo",       label: "ASN & Geolocation",   icon: <FaMapMarkerAlt />, desc: "IP, ASN, cloud detection" },
      { id: "subdomains",   label: "Subdomain Enum",      icon: <FaGlobe />,        desc: "Passive DNS via HackerTarget" },
      { id: "email",        label: "Email Intelligence",  icon: <FaEnvelope />,     desc: "DNSBL + Hunter.io" },
    ],
  },
  {
    label: "Host", color: "#D97706",
    modules: [
      { id: "cookies",  label: "Cookie Analysis", icon: <FaCookieBite />, desc: "Cookie security flags" },
      { id: "greenWeb", label: "Green Hosting",   icon: <FaLeaf />,       desc: "Renewable energy check" },
    ],
  },
  {
    label: "Vulnerability", color: C.orange,
    modules: [
      { id: "sqlInjection",     label: "SQL Injection",      icon: <FaBug />,           desc: "SQLMap automated scan" },
      { id: "xss",              label: "XSS",                icon: <FaBug />,           desc: "Reflected/DOM/Stored XSS" },
      { id: "csrf",             label: "CSRF",               icon: <FaUnlock />,        desc: "Cross-site request forgery" },
      { id: "clickjacking",     label: "Clickjacking",       icon: <FaSkull />,         desc: "X-Frame-Options check" },
      { id: "commandInjection", label: "Command Injection",  icon: <FaBug />,           desc: "OS command injection" },
      { id: "sensitiveFiles",   label: "Sensitive Files",    icon: <FaSearch />,        desc: "Exposed config & backup files" },
      { id: "openRedirect",     label: "Open Redirect",      icon: <FaRoute />,         desc: "URL redirect abuse" },
      // ── NEW ──────────────────────────────────────────────────────────────────
      { id: "cors",             label: "CORS",               icon: <FaExchangeAlt />,   desc: "Cross-origin policy misconfiguration" },
      { id: "wordpress",        label: "WordPress Security", icon: <FaWordpress />,     desc: "WP version, plugins & CVEs" },
    ],
  },
];

const ALL_MODULE_IDS = MODULE_GROUPS.flatMap(g => g.modules.map(m => m.id));

// ─── SIDEBAR CHECK ROW ────────────────────────────────────────────────────────
const SideCheckRow = ({ id, label, on, color, toggle }) => (
  <div onClick={() => toggle(id)} style={{ display: "flex", alignItems: "center", gap: "8px", padding: "5px 10px", borderRadius: "4px", cursor: "pointer", transition: "background 0.12s" }}
    onMouseEnter={e => e.currentTarget.style.background = C.sidebarHover}
    onMouseLeave={e => e.currentTarget.style.background = "transparent"}>
    <div style={{ width: "14px", height: "14px", borderRadius: "3px", flexShrink: 0, border: `1.5px solid ${on ? color : C.sidebarFaint}`, background: on ? color : "transparent", display: "flex", alignItems: "center", justifyContent: "center", transition: "all 0.12s" }}>
      {on && <span style={{ color: C.sidebarBg, fontSize: "9px", fontWeight: 700, lineHeight: 1 }}>✓</span>}
    </div>
    <span style={{ fontFamily: "'DM Mono', monospace", fontSize: "11px", color: on ? C.sidebarText : C.sidebarMuted, transition: "color 0.12s" }}>{label}</span>
  </div>
);

// ─── RESULTS VIEW ─────────────────────────────────────────────────────────────
function ResultsView({ r, riskAssessment, target, onDownload, isDownloading }) {
  const risk = riskAssessment?.risk || "LOW", score = riskAssessment?.score ?? 0, findings = riskAssessment?.findings || [];
  const rc = riskColor(risk), rb = riskBgCol(risk), rbd = riskBorder(risk);

  return (
    <div style={{ animation: "fadeUp 0.5s ease forwards" }}>
 

      <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>

        {/* SSL */}
        {r.ssl && (
          <ModuleCard title="SSL / TLS Certificate" icon={<FaLock />} risk={r.ssl.valid ? "LOW" : "HIGH"} summary={r.ssl.valid ? `Valid · ${r.ssl.daysRemaining}d remaining` : "Invalid"}>
            <StatRow label="STATUS"         value={r.ssl.valid ? "Valid" : "Invalid"}      accent={r.ssl.valid ? C.green : C.red} />
            <StatRow label="ISSUER"         value={r.ssl.issuer}                           accent={C.textSecondary} />
            <StatRow label="VALID_FROM"     value={r.ssl.validFrom?.split("T")[0]}         accent={C.textSecondary} />
            <StatRow label="VALID_TO"       value={r.ssl.validTo?.split("T")[0]}           accent={C.textSecondary} />
            <StatRow label="DAYS_REMAINING" value={r.ssl.daysRemaining}                    accent={r.ssl.daysRemaining < 30 ? C.amber : C.green} />
            {!r.ssl.valid && <AlertRow text="HTTPS not enforced — data transmitted in plaintext" severity="critical" />}
          </ModuleCard>
        )}

        {/* Security Headers */}
        {r.headers && (
          <ModuleCard title="Security Headers" icon={<FaShieldAlt />} risk={(r.headers.missingSecurityHeaders || []).length >= 3 ? "MEDIUM" : "LOW"} summary={`${(r.headers.missingSecurityHeaders || []).length} missing`}>
            <StatRow label="SERVER"               value={r.headers.server}                        accent={C.textSecondary} />
            <StatRow label="X-POWERED-BY"         value={r.headers.poweredBy || "Hidden"}        accent={C.textMuted} />
            <StatRow label="STRICT-TRANSPORT-SEC" value={r.headers.strictTransport || "MISSING"} accent={r.headers.strictTransport ? C.green : C.red} />
            <StatRow label="X-FRAME-OPTIONS"      value={r.headers.xFrameOptions || "MISSING"}   accent={r.headers.xFrameOptions ? C.green : C.red} />
            <StatRow label="CONTENT-SECURITY-POL" value={r.headers.csp || "MISSING"}             accent={r.headers.csp ? C.green : C.red} />
            <StatRow label="REFERRER-POLICY"      value={r.headers.referrer || "MISSING"}        accent={r.headers.referrer ? C.green : C.red} />
            {(r.headers.missingSecurityHeaders || []).length > 0 && (
              <div style={{ marginTop: "12px" }}>
                <div style={{ fontFamily: "'DM Mono', monospace", fontSize: "12px", color: C.textSecondary, letterSpacing: "0.06em", marginBottom: "10px", fontWeight: 500 }}>// missing_headers</div>
                {r.headers.missingSecurityHeaders.map((h, i) => <AlertRow key={i} text={h} severity="warn" />)}
              </div>
            )}
          </ModuleCard>
        )}

        {/* Tech Stack */}
        {r.wappalyzer && (() => {
          const techs = Object.entries(r.wappalyzer);
          const outdated = techs.filter(([, v]) => v.outdated);
          const risk = outdated.some(([, v]) => v.severity === "CRITICAL") ? "HIGH" : outdated.length > 0 ? "MEDIUM" : "LOW";
          return (
            <ModuleCard title="Technology Stack" icon={<FaServer />} risk={risk} summary={`${techs.length} detected · ${outdated.length} outdated`}>
              {outdated.length > 0 && (
                <div style={{ marginBottom: "16px" }}>
                  <div style={{ fontFamily: "'DM Mono', monospace", fontSize: "12px", color: C.textSecondary, letterSpacing: "0.06em", marginBottom: "10px", fontWeight: 500 }}>// outdated_versions</div>
                  {outdated.map(([tech, info]) => {
                    const c  = info.severity === "CRITICAL" ? C.red : info.severity === "HIGH" ? C.orange : C.amber;
                    const bg = info.severity === "CRITICAL" ? C.redBg : info.severity === "HIGH" ? C.orangeBg : C.amberBg;
                    const bd = info.severity === "CRITICAL" ? C.redBorder : info.severity === "HIGH" ? C.orangeBorder : C.amberBorder;
                    return (
                      <div key={tech} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "10px 12px", background: bg, border: `1px solid ${bd}`, borderRadius: "4px", marginBottom: "6px" }}>
                        <div>
                          <span style={{ fontFamily: "'Syne', sans-serif", fontWeight: 700, fontSize: "13px", color: c }}>{tech}</span>
                          <span style={{ fontFamily: "'DM Mono', monospace", fontSize: "13px", color: C.textSecondary, marginLeft: "10px", fontWeight: 500 }}>v{info.version} → v{info.latest}</span>
                        </div>
                        <span style={{ fontFamily: "'DM Mono', monospace", fontSize: "12px", fontWeight: 700, color: c, background: C.white, border: `1px solid ${bd}`, borderRadius: "20px", padding: "3px 12px" }}>{info.severity}</span>
                      </div>
                    );
                  })}
                </div>
              )}
              <div style={{ fontFamily: "'DM Mono', monospace", fontSize: "12px", color: C.textSecondary, letterSpacing: "0.06em", marginBottom: "10px", fontWeight: 500 }}>// all_detected</div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                {techs.map(([tech, info]) => {
                  const c = info.outdated ? (info.severity === "CRITICAL" ? C.red : info.severity === "HIGH" ? C.orange : C.amber) : C.blue;
                  return <Tag key={tech} color={c}>{tech}{info.version && info.version !== "Unknown" ? ` v${info.version}` : ""}{info.outdated ? " ⚠" : ""}</Tag>;
                })}
              </div>
            </ModuleCard>
          );
        })()}

        {/* Endpoints */}
        {r.endpoints && (
          <ModuleCard title="Endpoint Discovery" icon={<FaCode />} risk={r.endpoints.length > 20 ? "MEDIUM" : "LOW"} summary={`${r.endpoints.length} endpoints`}>
            <StatRow label="TOTAL_ENDPOINTS" value={r.endpoints.length} accent={C.purple} />
            {r.endpoints.length > 0 && (
              <div style={{ marginTop: "10px", display: "flex", flexDirection: "column", gap: "2px" }}>
                {r.endpoints.slice(0, 8).map((e, i) => (
                  <div key={i} style={{ fontFamily: "'DM Mono', monospace", fontSize: "13px", color: C.blue, padding: "7px 10px", background: C.blueBg, borderRadius: "3px", wordBreak: "break-all", fontWeight: 500 }}>{e.url || e}</div>
                ))}
              </div>
            )}
          </ModuleCard>
        )}

        {/* DNS */}
        {r.dns && (
          <ModuleCard title="DNS Intelligence" icon={<FaGlobe />} risk="LOW" summary={r.dns.resolvedSuccessfully ? "Resolved" : "Failed"}>
            <StatRow label="RESOLVED"   value={r.dns.resolvedSuccessfully ? "Yes" : "No"} accent={r.dns.resolvedSuccessfully ? C.green : C.red} />
            <StatRow label="PRIMARY_IP" value={r.dns.primaryIP}                           accent={C.blue} />
            <StatRow label="A_RECORDS"  value={(r.dns.A || []).join(", ") || "None"}      accent={C.textSecondary} />
            <StatRow label="MX_RECORDS" value={(r.dns.MX || []).length}                  accent={C.textSecondary} />
            <StatRow label="NS_RECORDS" value={(r.dns.NS || []).length}                  accent={C.textSecondary} />
          </ModuleCard>
        )}

        {/* WHOIS */}
        {r.whois && (
          <ModuleCard title="WHOIS / Registration" icon={<FaServer />} risk="LOW" summary={r.whois.registrar}>
            <StatRow label="REGISTRAR"      value={r.whois.registrar}     accent={C.textSecondary} />
            <StatRow label="REGISTRANT_ORG" value={r.whois.registrantOrg} accent={C.textSecondary} />
            <StatRow label="CREATED"        value={r.whois.creationDate}  accent={C.textSecondary} />
            <StatRow label="EXPIRES"        value={r.whois.expiryDate}    accent={C.amber} />
            <StatRow label="DNSSEC"         value={r.whois.dnssec}        accent={C.textSecondary} />
            {(r.whois.nameservers || []).length > 0 && <TagList items={r.whois.nameservers} color={C.blue} />}
          </ModuleCard>
        )}

        {/* Ping */}
        {r.ping && (
          <ModuleCard title="Reachability (Ping)" icon={<FaNetworkWired />} risk={r.ping.reachable ? "LOW" : "HIGH"} summary={r.ping.reachable ? `${r.ping.avgTime} ms avg` : "Unreachable"}>
            <StatRow label="REACHABLE"   value={r.ping.reachable ? "Yes" : "No"}                                              accent={r.ping.reachable ? C.green : C.red} />
            <StatRow label="AVG_LATENCY" value={r.ping.avgTime && r.ping.avgTime !== "N/A" ? `${r.ping.avgTime} ms` : "N/A"} accent={C.blue} />
            <StatRow label="PACKET_LOSS" value={r.ping.packetLoss || "0%"}                                                    accent={C.textSecondary} />
          </ModuleCard>
        )}

        {/* Traceroute */}
        {r.traceroute && (
          <ModuleCard title="Traceroute" icon={<FaRoute />} risk="LOW" summary={`${r.traceroute.totalHops} hops · ${r.traceroute.avgLatency} ms avg`}>
            <StatRow label="TOTAL_HOPS"     value={r.traceroute.totalHops}                                           accent={C.blue} />
            <StatRow label="REACHABLE_HOPS" value={r.traceroute.reachableHops}                                      accent={C.green} />
            <StatRow label="FINAL_HOP"      value={r.traceroute.finalHop}                                           accent={C.textSecondary} />
            <StatRow label="AVG_LATENCY"    value={r.traceroute.avgLatency ? `${r.traceroute.avgLatency} ms` : "N/A"} accent={C.blue} />
          </ModuleCard>
        )}

        {/* Ports */}
        {r.openPorts && (
          <ModuleCard title="Port Scanner" icon={<FaServer />} risk="LOW" summary={`${r.openPorts.length} open`}>
            <div style={{ display: "flex", flexWrap: "wrap", gap: "8px", marginTop: "6px" }}>
              {r.openPorts.map((p, i) => {
                const isSensitive = [21, 22, 23, 25, 3306, 5432, 6379, 27017, 8080, 8443, 1433, 3389].includes(Number(p.port));
                return (
                  <div key={i} style={{ background: isSensitive ? C.orangeBg : C.blueBg, border: `1px solid ${isSensitive ? C.orangeBorder : C.blueBorder}`, borderRadius: "6px", padding: "10px 14px", textAlign: "center", minWidth: "60px" }}>
                    <div style={{ fontFamily: "'Syne', sans-serif", fontWeight: 800, fontSize: "18px", color: isSensitive ? C.orange : C.blue, lineHeight: 1 }}>{p.port}</div>
                    <div style={{ fontFamily: "'DM Mono', monospace", fontSize: "12px", color: C.textSecondary, marginTop: "4px", fontWeight: 500 }}>{p.name}</div>
                    {isSensitive && <div style={{ fontFamily: "'DM Mono', monospace", fontSize: "9px", color: C.orange, marginTop: "2px" }}>⚠</div>}
                  </div>
                );
              })}
            </div>
          </ModuleCard>
        )}

        {/* ASN Geo */}
        {r.asnGeo && (
          <ModuleCard title="ASN & Geolocation" icon={<FaMapMarkerAlt />} risk="LOW" summary={`${r.asnGeo.city || "Unknown"}, ${r.asnGeo.countryCode || ""}`}>
            <StatRow label="IP_ADDRESS"   value={r.asnGeo.ip}                                                               accent={C.blue} />
            <StatRow label="COUNTRY"      value={r.asnGeo.country ? `${r.asnGeo.country} (${r.asnGeo.countryCode})` : "N/A"} accent={C.textSecondary} />
            <StatRow label="CITY"         value={r.asnGeo.city}                                                             accent={C.textSecondary} />
            <StatRow label="ISP"          value={r.asnGeo.isp}                                                              accent={C.textSecondary} />
            <StatRow label="ORG"          value={r.asnGeo.org}                                                              accent={C.textSecondary} />
            <StatRow label="ASN"          value={r.asnGeo.asn}                                                              accent={C.textSecondary} />
            <StatRow label="CLOUD_HOSTED" value={r.asnGeo.isCloud ? `Yes — ${r.asnGeo.cloudProvider}` : "No"}             accent={r.asnGeo.isCloud ? C.amber : C.green} />
            {r.asnGeo.isCloud && <AlertRow text={`Hosted on cloud infrastructure (${r.asnGeo.cloudProvider}) — shared IP space possible`} severity="warn" />}
          </ModuleCard>
        )}

        {/* Subdomains */}
        {r.securityTrails && (
          <ModuleCard title="Attack Surface (Subdomains)" icon={<FaSearch />} risk={r.securityTrails.risk || "LOW"} summary={`${r.securityTrails.subdomainCount} subdomains`}>
            <StatRow label="SUBDOMAIN_COUNT" value={r.securityTrails.subdomainCount} accent={C.purple} />
            <StatRow label="SOURCE"          value={r.securityTrails.note}           accent={C.textMuted} />
            {(r.securityTrails.subdomains || []).length > 0 && (
              <div style={{ marginTop: "12px" }}>
                <div style={{ fontFamily: "'DM Mono', monospace", fontSize: "12px", color: C.textSecondary, letterSpacing: "0.06em", marginBottom: "10px", fontWeight: 500 }}>// subdomains</div>
                <TagList items={r.securityTrails.subdomains.slice(0, 12)} color={C.purple} />
                {r.securityTrails.subdomains.length > 12 && <div style={{ fontFamily: "'DM Mono', monospace", fontSize: "13px", color: C.textMuted, marginTop: "6px", fontWeight: 500 }}>+{r.securityTrails.subdomains.length - 12} more</div>}
              </div>
            )}
          </ModuleCard>
        )}

        {/* Cookies */}
        {r.cookies && (
          <ModuleCard title="Cookie Security" icon={<FaCookieBite />} risk={r.cookies.risk || "LOW"} summary={`${r.cookies.cookieCount} cookies · ${(r.cookies.issues || []).length} issues`}>
            <StatRow label="COOKIES_SET"     value={r.cookies.cookieCount}           accent={C.blue} />
            <StatRow label="SECURITY_ISSUES" value={(r.cookies.issues || []).length} accent={(r.cookies.issues || []).length > 0 ? C.amber : C.green} />
            {(r.cookies.cookies || []).map((c, i) => (
              <div key={i} style={{ padding: "8px 10px", background: C.bg, borderRadius: "4px", marginTop: "6px", border: `1px solid ${C.border}` }}>
                <div style={{ fontFamily: "'Syne', sans-serif", fontWeight: 600, fontSize: "12px", color: C.text, marginBottom: "4px" }}>{c.name}</div>
                <div style={{ display: "flex", gap: "12px", flexWrap: "wrap" }}>
                  <span style={{ fontFamily: "'DM Mono', monospace", fontSize: "13px", color: c.secure ? C.green : C.red, fontWeight: 500 }}>Secure: {c.secure ? "Yes" : "No"}</span>
                  <span style={{ fontFamily: "'DM Mono', monospace", fontSize: "13px", color: c.httpOnly ? C.green : C.red, fontWeight: 500 }}>HttpOnly: {c.httpOnly ? "Yes" : "No"}</span>
                  <span style={{ fontFamily: "'DM Mono', monospace", fontSize: "13px", color: c.sameSite ? C.green : C.amber, fontWeight: 500 }}>SameSite: {c.sameSite || "Missing"}</span>
                </div>
              </div>
            ))}
            {(r.cookies.issues || []).map((issue, i) => <AlertRow key={i} text={issue} severity="warn" />)}
          </ModuleCard>
        )}

        {/* Green Web */}
        {r.greenWeb && (
          <ModuleCard title="Green Hosting" icon={<FaLeaf />} risk="LOW" summary={r.greenWeb.green ? "Verified green" : "Not verified"}>
            <StatRow label="GREEN_VERIFIED" value={r.greenWeb.green ? "Verified" : "Not verified"} accent={r.greenWeb.green ? C.green : C.textMuted} />
            {r.greenWeb.hostedBy && <StatRow label="HOSTED_BY" value={r.greenWeb.hostedBy} accent={C.textSecondary} />}
          </ModuleCard>
        )}

        {/* Email Intelligence */}
        {r.emailIntelligence && (
          <ModuleCard title="Email Intelligence" icon={<FaEnvelope />} risk={r.emailIntelligence.dnsbl?.listed ? "HIGH" : "LOW"} summary={r.emailIntelligence.dnsbl?.listed ? "Blacklisted" : "Clean"}>
            <StatRow label="BLACKLISTED" value={r.emailIntelligence.dnsbl?.listed ? "Yes" : "No"}                 accent={r.emailIntelligence.dnsbl?.listed ? C.red : C.green} />
            <StatRow label="LISTED_ON"   value={(r.emailIntelligence.dnsbl?.listedOn || []).join(", ") || "None"} accent={C.textSecondary} />
            {r.emailIntelligence.hunter?.available && (
              <>
                <div style={{ fontFamily: "'DM Mono', monospace", fontSize: "12px", color: C.textSecondary, letterSpacing: "0.06em", margin: "12px 0 10px", fontWeight: 500 }}>// hunter.io</div>
                <StatRow label="ORGANIZATION"  value={r.emailIntelligence.hunter.organization} accent={C.textSecondary} />
                <StatRow label="TOTAL_EMAILS"  value={r.emailIntelligence.hunter.totalEmails}  accent={C.blue} />
                <StatRow label="EMAIL_PATTERN" value={r.emailIntelligence.hunter.pattern}      accent={C.purple} />
                {(r.emailIntelligence.hunter.emails || []).slice(0, 4).map((e, i) => (
                  <div key={i} style={{ padding: "7px 10px", background: C.purpleBg, border: `1px solid ${C.purpleBorder}`, borderRadius: "4px", marginTop: "5px" }}>
                    <div style={{ fontFamily: "'DM Mono', monospace", fontSize: "14px", color: C.purple, fontWeight: 500 }}>{e.email}</div>
                    <div style={{ fontFamily: "'DM Sans', sans-serif", fontSize: "12px", color: C.textMuted, marginTop: "2px" }}>
                      {e.confidence}% confidence · {e.firstName} {e.lastName}{e.position ? ` — ${e.position}` : ""}
                    </div>
                  </div>
                ))}
              </>
            )}
          </ModuleCard>
        )}

        {/* Safe Browsing */}
        {r.safeBrowsing && (
          <ModuleCard title="Google Safe Browsing" icon={<FaShieldAlt />} risk={r.safeBrowsing.safe === false ? "CRITICAL" : "LOW"} summary={r.safeBrowsing.available ? (r.safeBrowsing.safe ? "Clean" : `${r.safeBrowsing.threatCount} threats`) : "N/A"}>
            {r.safeBrowsing.available ? (
              <>
                <StatRow label="STATUS"        value={r.safeBrowsing.safe ? "Clean" : "Flagged"}  accent={r.safeBrowsing.safe ? C.green : C.red} />
                <StatRow label="THREATS_FOUND" value={r.safeBrowsing.threatCount ?? 0}             accent={r.safeBrowsing.threatCount > 0 ? C.red : C.green} />
                {!r.safeBrowsing.safe && <AlertRow text={`Threats: ${r.safeBrowsing.threats?.join(", ")}`} severity="critical" />}
                {r.safeBrowsing.safe  && <AlertRow text="Domain is not flagged in Google's threat database" severity="info" />}
              </>
            ) : <AlertRow text={r.safeBrowsing.note || "Not configured"} severity="info" />}
          </ModuleCard>
        )}

        {/* VirusTotal */}
        {r.virusTotal && (
          <ModuleCard title="VirusTotal" icon={<FaVirus />} risk={r.virusTotal.risk || "LOW"} summary={r.virusTotal.available ? `${r.virusTotal.malicious}/${r.virusTotal.total} flagged` : "N/A"}>
            {r.virusTotal.available ? (
              <>
                <StatRow label="MALICIOUS"       value={r.virusTotal.malicious}      accent={r.virusTotal.malicious > 0 ? C.red : C.green} />
                <StatRow label="SUSPICIOUS"      value={r.virusTotal.suspicious}     accent={r.virusTotal.suspicious > 0 ? C.amber : C.textSecondary} />
                <StatRow label="HARMLESS"        value={r.virusTotal.harmless}       accent={C.green} />
                <StatRow label="TOTAL_ENGINES"   value={r.virusTotal.total}          accent={C.textSecondary} />
                <StatRow label="COMMUNITY_SCORE" value={r.virusTotal.communityScore} accent={C.textSecondary} />
                <StatRow label="LAST_ANALYSIS"   value={r.virusTotal.lastAnalysis}   accent={C.textMuted} />
                {(r.virusTotal.popularity || []).length > 0 && <TagList items={r.virusTotal.popularity} color={C.purple} />}
              </>
            ) : <AlertRow text={r.virusTotal.note || "Not configured"} severity={r.virusTotal.warn ? "warn" : "info"} />}
          </ModuleCard>
        )}

        {/* Shodan */}
        {r.shodan && (
          <ModuleCard title="Shodan Intelligence" icon={<FaEye />} risk={r.shodan.risk || "LOW"} summary={r.shodan.available ? (r.shodan.note ? r.shodan.note.substring(0, 50) + "..." : `${r.shodan.portCount} ports · ${r.shodan.vulnCount} CVEs`) : "N/A"}>
            {r.shodan.available ? (
              r.shodan.note ? <AlertRow text={r.shodan.note} severity="info" /> : (
                <>
                  <StatRow label="IP"         value={r.shodan.ip}                                 accent={C.blue} />
                  <StatRow label="ORG"        value={r.shodan.org}                                accent={C.textSecondary} />
                  <StatRow label="OPEN_PORTS" value={(r.shodan.ports || []).join(", ") || "None"} accent={C.textSecondary} />
                  <StatRow label="CVE_COUNT"  value={r.shodan.vulnCount}                          accent={r.shodan.vulnCount > 0 ? C.red : C.green} />
                  <StatRow label="CISA_KEV"   value={r.shodan.kevCount}                           accent={r.shodan.kevCount > 0 ? C.red : C.green} />
                  {(r.shodan.vulnDetails || []).slice(0, 5).map((v, i) => (
                    <div key={i} style={{ padding: "7px 10px", marginTop: "5px", borderRadius: "4px", background: v.kev ? C.redBg : C.bg, border: `1px solid ${v.kev ? C.redBorder : C.border}` }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                        <span style={{ fontFamily: "'DM Mono', monospace", fontSize: "13px", color: v.kev ? C.red : C.orange, fontWeight: 700 }}>{v.id}</span>
                        <div style={{ display: "flex", gap: "6px", alignItems: "center" }}>
                          {v.cvss && <span style={{ fontFamily: "'DM Mono', monospace", fontSize: "12px", color: C.textSecondary, fontWeight: 500 }}>CVSS: {v.cvss}</span>}
                          {v.kev && <span style={{ fontFamily: "'DM Mono', monospace", fontSize: "12px", color: C.red, background: C.redBg, border: `1px solid ${C.redBorder}`, padding: "2px 10px", borderRadius: "10px", fontWeight: 600 }}>CISA KEV</span>}
                        </div>
                      </div>
                      {v.summary && <div style={{ fontFamily: "'DM Sans', sans-serif", fontSize: "12px", color: C.textMuted, marginTop: "3px" }}>{v.summary.substring(0, 80)}…</div>}
                    </div>
                  ))}
                </>
              )
            ) : <AlertRow text={r.shodan.note || "Not configured"} severity="info" />}
          </ModuleCard>
        )}

        {/* ── VULNERABILITY MODULES ─────────────────────────────────────────── */}
        {r.vulnerabilities && Object.entries(r.vulnerabilities).map(([key, vuln]) => {
          const labels = {
            sqlInjection: "SQL Injection", xss: "XSS", csrf: "CSRF",
            clickjacking: "Clickjacking", commandInjection: "Command Injection",
            sensitiveFiles: "Sensitive Files", openRedirect: "Open Redirect",
            cors: "CORS Misconfiguration", wordpress: "WordPress Security",
          };
          const found = vuln.found || vuln.vulnerable || vuln.details?.vulnerable;

          // ── XSS (combined) ────────────────────────────────────────────────
          if (key === "xss") {
            const d = vuln.details || {};
            const reflected = d.reflected || {}, dom = d.dom || {}, stored = d.stored || {};
            const endpoints = reflected.vulnerableEndpoints || [];
            return (
              <ModuleCard key={key} title="XSS (Cross-Site Scripting)" icon={<FaBug />}
                risk={found ? "HIGH" : "LOW"}
                summary={found ? `Vulnerable — ${endpoints.length} reflected${dom.found ? " + DOM" : ""}${stored.found ? " + Stored" : ""}` : "Not detected"}
                defaultOpen={found}>
                <StatRow label="STATUS"           value={found ? "Vulnerable" : "Clean"}                                accent={found ? C.red : C.green} />
                <StatRow label="REFLECTED"        value={reflected.found ? `Yes — ${endpoints.length} endpoint(s)` : "No"} accent={reflected.found ? C.red : C.green} />
                <StatRow label="DOM_XSS"          value={dom.found    ? "Yes" : "No"}                                  accent={dom.found    ? C.red : C.green} />
                <StatRow label="STORED_XSS"       value={stored.found ? "Yes" : "No"}                                  accent={stored.found ? C.red : C.green} />
                <StatRow label="TESTED_ENDPOINTS" value={reflected.testedEndpoints || 0}                               accent={C.textSecondary} />
                {endpoints.length > 0 && (
                  <div style={{ marginTop: "12px" }}>
                    <div style={{ fontFamily: "'DM Mono', monospace", fontSize: "12px", color: C.textSecondary, letterSpacing: "0.06em", marginBottom: "10px", fontWeight: 500 }}>// vulnerable_endpoints</div>
                    {endpoints.slice(0, 6).map((ep, i) => (
                      <div key={i} style={{ fontFamily: "'DM Mono', monospace", fontSize: "13px", color: C.red, padding: "7px 12px", background: C.redBg, border: `1px solid ${C.redBorder}`, borderRadius: "3px", marginBottom: "4px", wordBreak: "break-all", fontWeight: 500 }}>
                        {typeof ep === "string" ? ep : (ep.url || ep.endpoint || JSON.stringify(ep).substring(0, 80))}
                      </div>
                    ))}
                    {endpoints.length > 6 && <div style={{ fontFamily: "'DM Mono', monospace", fontSize: "13px", color: C.textSecondary, marginTop: "6px", fontWeight: 500 }}>+{endpoints.length - 6} more endpoints</div>}
                  </div>
                )}
                {found  && <AlertRow text="XSS vulnerability detected — attackers can inject malicious scripts into pages viewed by other users" severity="critical" />}
                {!found && <AlertRow text="No XSS vulnerabilities detected" severity="info" />}
              </ModuleCard>
            );
          }

          // ── CORS ──────────────────────────────────────────────────────────
          if (key === "cors") {
            const d    = vuln.details || {};
            const sum  = d.summary   || {};
            const corsFindings = d.findings || d.vulnerableEndpoints || [];
            const corsRisk = sum.critical > 0 ? "CRITICAL" : sum.high > 0 ? "HIGH" : found ? "MEDIUM" : "LOW";
            return (
              <ModuleCard key={key} title="CORS Misconfiguration" icon={<FaExchangeAlt />}
                risk={corsRisk}
                summary={found ? `Misconfigured${sum.critical ? ` — ${sum.critical} critical` : ""}` : "Not detected"}
                defaultOpen={found}>
                <StatRow label="STATUS"          value={found ? "Vulnerable" : "Clean"}     accent={found ? C.red : C.green} />
                {sum.critical !== undefined && <StatRow label="CRITICAL_ISSUES" value={sum.critical} accent={sum.critical > 0 ? C.red : C.green} />}
                {sum.high     !== undefined && <StatRow label="HIGH_ISSUES"     value={sum.high}     accent={sum.high > 0 ? C.orange : C.green} />}
                {corsFindings.length > 0 && (
                  <div style={{ marginTop: "12px" }}>
                    <div style={{ fontFamily: "'DM Mono', monospace", fontSize: "12px", color: C.textSecondary, letterSpacing: "0.06em", marginBottom: "10px", fontWeight: 500 }}>// misconfigured_origins</div>
                    {corsFindings.slice(0, 8).map((f, i) => {
                      const fUrl   = typeof f === "object" ? (f.url || f.endpoint || f.origin || "") : f;
                      const fIssue = typeof f === "object" ? (f.issue || f.type || "") : "";
                      return (
                        <div key={i} style={{ padding: "8px 12px", background: C.redBg, border: `1px solid ${C.redBorder}`, borderRadius: "4px", marginBottom: "5px" }}>
                          <div style={{ fontFamily: "'DM Mono', monospace", fontSize: "13px", color: C.red, wordBreak: "break-all", fontWeight: 500 }}>{fUrl.length > 65 ? fUrl.substring(0, 65) + "…" : fUrl || "Unknown endpoint"}</div>
                          {fIssue && <div style={{ fontFamily: "'DM Sans', sans-serif", fontSize: "12px", color: C.orange, marginTop: "3px" }}>{fIssue}</div>}
                        </div>
                      );
                    })}
                    {corsFindings.length > 8 && <div style={{ fontFamily: "'DM Mono', monospace", fontSize: "13px", color: C.textMuted, marginTop: "6px" }}>+{corsFindings.length - 8} more</div>}
                  </div>
                )}
                {found  && <AlertRow text="CORS misconfiguration detected — overly permissive origin policy may allow cross-origin attacks" severity="critical" />}
                {!found && <AlertRow text="No CORS misconfiguration detected" severity="info" />}
                {found  && <AlertRow text="Restrict Access-Control-Allow-Origin to trusted domains only. Never use wildcard (*) with credentials." severity="warn" />}
              </ModuleCard>
            );
          }

          // ── WordPress ─────────────────────────────────────────────────────
          if (key === "wordpress") {
            const wp      = vuln.details || {};
            const wpLevel = wp.riskScore?.level || "LOW";
            const wpRisk  = found ? wpLevel : "LOW";
            const plugins = wp.vulnerablePlugins || wp.plugins || [];
            const cves    = wp.cves || [];
            return (
              <ModuleCard key={key} title="WordPress Security" icon={<FaWordpress />}
                risk={wpRisk}
                summary={found ? `WordPress detected${wp.version ? ` v${wp.version}` : ""}${plugins.length ? ` · ${plugins.length} vuln plugin${plugins.length > 1 ? "s" : ""}` : ""}` : "Not WordPress"}
                defaultOpen={found && (wpLevel === "CRITICAL" || wpLevel === "HIGH")}>
                <StatRow label="WORDPRESS_DETECTED" value={found ? "Yes" : "No"}                                  accent={found ? C.blue : C.textMuted} />
                {wp.version   && <StatRow label="WP_VERSION"    value={wp.version}                               accent={C.textSecondary} />}
                {wp.theme     && <StatRow label="ACTIVE_THEME"  value={wp.theme}                                 accent={C.textSecondary} />}
                {wp.riskScore && <StatRow label="RISK_SCORE"    value={`${wp.riskScore.score} (${wpLevel})`}     accent={riskColor(wpLevel)} />}
                {plugins.length > 0 && (
                  <div style={{ marginTop: "12px" }}>
                    <div style={{ fontFamily: "'DM Mono', monospace", fontSize: "12px", color: C.textSecondary, letterSpacing: "0.06em", marginBottom: "10px", fontWeight: 500 }}>// vulnerable_plugins ({plugins.length})</div>
                    {plugins.slice(0, 8).map((p, i) => {
                      const name = typeof p === "object" ? (p.name || p.plugin || JSON.stringify(p)) : p;
                      return (
                        <div key={i} style={{ fontFamily: "'DM Mono', monospace", fontSize: "13px", color: C.orange, padding: "7px 12px", background: C.orangeBg, border: `1px solid ${C.orangeBorder}`, borderRadius: "3px", marginBottom: "4px", fontWeight: 500 }}>
                          {name}
                        </div>
                      );
                    })}
                    {plugins.length > 8 && <div style={{ fontFamily: "'DM Mono', monospace", fontSize: "13px", color: C.textMuted, marginTop: "6px" }}>+{plugins.length - 8} more plugins</div>}
                  </div>
                )}
                {cves.length > 0 && (
                  <div style={{ marginTop: "12px" }}>
                    <div style={{ fontFamily: "'DM Mono', monospace", fontSize: "12px", color: C.textSecondary, letterSpacing: "0.06em", marginBottom: "10px", fontWeight: 500 }}>// cves ({cves.length})</div>
                    {cves.slice(0, 5).map((c, i) => (
                      <div key={i} style={{ fontFamily: "'DM Mono', monospace", fontSize: "13px", color: C.red, padding: "6px 12px", background: C.redBg, border: `1px solid ${C.redBorder}`, borderRadius: "3px", marginBottom: "4px", fontWeight: 600 }}>
                        {typeof c === "object" ? (c.id || c.cve) : c}
                      </div>
                    ))}
                    {cves.length > 5 && <div style={{ fontFamily: "'DM Mono', monospace", fontSize: "13px", color: C.textMuted, marginTop: "6px" }}>+{cves.length - 5} more CVEs</div>}
                  </div>
                )}
                {found  && <AlertRow text="WordPress installation detected — keep core, themes and plugins updated to prevent exploitation" severity={wpLevel === "LOW" ? "warn" : "critical"} />}
                {!found && <AlertRow text="Target does not appear to be running WordPress" severity="info" />}
              </ModuleCard>
            );
          }

          // ── Generic vuln card (sql, csrf, clickjacking, cmd, sensitiveFiles, openRedirect) ──
          return (
            <ModuleCard key={key} title={labels[key] || key} icon={<FaBug />}
              risk={found ? "HIGH" : "LOW"}
              summary={found ? "Vulnerable" : "Not detected"}
              defaultOpen={found}>
              <StatRow label="STATUS" value={found ? "Vulnerable" : "Clean"} accent={found ? C.red : C.green} />
              {vuln.details?.summary && <StatRow label="SUMMARY" value={JSON.stringify(vuln.details.summary).substring(0, 80)} accent={C.textSecondary} />}
              {found  && <AlertRow text={`${labels[key] || key} vulnerability detected — requires immediate remediation`} severity="critical" />}
              {!found && <AlertRow text={`No ${labels[key] || key} vulnerabilities detected`} severity="info" />}
            </ModuleCard>
          );
        })}
      </div>

      {/* PDF Download */}
      <div style={{ marginTop: "36px", textAlign: "center", paddingBottom: "40px" }}>
        <button onClick={onDownload} disabled={isDownloading}
          style={{ fontFamily: "'Syne', sans-serif", fontWeight: 700, fontSize: "14px", color: C.white, background: isDownloading ? C.accentBorder : C.accent, border: "none", padding: "14px 32px", borderRadius: "4px", cursor: isDownloading ? "not-allowed" : "pointer", display: "inline-flex", alignItems: "center", gap: "10px", boxShadow: `0 4px 16px ${C.accent}40`, transition: "all 0.2s" }}
          onMouseEnter={e => { if (!isDownloading) { e.currentTarget.style.background = C.accentHover; e.currentTarget.style.transform = "translateY(-2px)"; } }}
          onMouseLeave={e => { e.currentTarget.style.background = isDownloading ? C.accentBorder : C.accent; e.currentTarget.style.transform = "translateY(0)"; }}>
          <FaFileDownload /> {isDownloading ? "Generating PDF…" : "Download PDF Report"}
        </button>
        <div style={{ fontFamily: "'DM Mono', monospace", fontSize: "11px", color: C.textXMuted, marginTop: "8px" }}>
          Includes findings for all {r.selectedModules?.length || 0} selected modules
        </div>
      </div>
    </div>
  );
}

// ─── MAIN ─────────────────────────────────────────────────────────────────────
export default function CustomScan() {
  const [input,          setInput]      = useState("");
  const [selected,       setSelected]   = useState(new Set(["dns", "ssl", "headers", "wappalyzer", "subdomains", "asnGeo", "virusTotal", "safeBrowsing", "shodan"]));
  const [scanning,       setScanning]   = useState(false);
  const [results,        setResults]    = useState(null);
  const [riskAssessment, setRisk]       = useState(null);
  const [error,          setError]      = useState("");
  const [isDownloading,  setDownload]   = useState(false);
  const [scanTarget,     setScanTarget] = useState("");
  const [elapsed,        setElapsed]    = useState(0);
  const timerRef   = useRef(null);
  const resultsRef = useRef(null);

  useEffect(() => {
    if (scanning) {
      setElapsed(0);
      timerRef.current = setInterval(() => setElapsed(t => t + 1), 1000);
    } else {
      clearInterval(timerRef.current);
    }
    return () => clearInterval(timerRef.current);
  }, [scanning]);

  const fmtTime = s => `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;

  const toggleModule = id => setSelected(prev => { const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n; });
  const toggleGroup  = mods => {
    const ids = mods.map(m => m.id), allOn = ids.every(id => selected.has(id));
    setSelected(prev => { const n = new Set(prev); ids.forEach(id => allOn ? n.delete(id) : n.add(id)); return n; });
  };
  const selectAll  = () => setSelected(new Set(ALL_MODULE_IDS));
  const selectNone = () => setSelected(new Set());

  const handleScan = async () => {
    if (!input.trim() || selected.size === 0) { setError("Enter a target and select at least one module."); return; }
    setScanning(true); setResults(null); setError("");
    try {
      const res = await axios.post("http://localhost:5000/api/customscan", { url: input.trim(), modules: [...selected] }, { timeout: 300000 });
      setScanTarget(input.trim());
      setResults(res.data);
      setRisk(res.data.riskAssessment);
      setTimeout(() => resultsRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }), 100);
    } catch (err) {
      setError(err.response?.data?.error || "Scan failed — check the target and try again.");
    }
    setScanning(false);
  };

  const handleDownload = async () => {
    if (!results) return;
    setDownload(true);
    try {
      const res = await fetch("http://localhost:5000/api/report/customscan/pdf", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: scanTarget, scanData: results, riskAssessment }),
      });
      if (!res.ok) throw new Error();
      const blob = await res.blob(), url = window.URL.createObjectURL(blob), a = document.createElement("a");
      a.href = url; a.download = `CustomScan-${scanTarget.replace(/[^a-z0-9]/gi, "_")}.pdf`; a.click();
      window.URL.revokeObjectURL(url);
    } catch { alert("Failed to download PDF report."); }
    setDownload(false);
  };

  return (
    <div style={{ background: C.bg, height: "100vh", overflow: "hidden", display: "flex", flexDirection: "column" }}>
      <link rel="stylesheet" href={FONT_URL} />
      <style>{`
        @keyframes fadeUp { from{opacity:0;transform:translateY(10px)} to{opacity:1;transform:translateY(0)} }
        @keyframes spin   { to{transform:rotate(360deg)} }
        @keyframes pulse  { 0%,100%{opacity:1} 50%{opacity:0.35} }
        * { box-sizing:border-box; margin:0; padding:0; }
        ::selection { background:rgba(109,40,217,0.15); color:${C.purple}; }
        ::-webkit-scrollbar { width:4px; }
        ::-webkit-scrollbar-track { background:${C.sidebarBg}; }
        ::-webkit-scrollbar-thumb { background:${C.sidebarFaint}; border-radius:2px; }
        input::placeholder { color:${C.sidebarFaint}; }
        input:focus { outline: none; }
      `}</style>

      {/* TOP NAV */}
      <header style={{ height: "52px", display: "flex", alignItems: "center", justifyContent: "space-between", padding: "0 28px", background: C.sidebarBg, borderBottom: `1px solid ${C.sidebarBorder}`, flexShrink: 0, position: "sticky", top: 0, zIndex: 200 }}>
        <div style={{ display: "flex", alignItems: "center", gap: "12px", cursor: "pointer" }} onClick={() => window.location.href = "/"}>
          <svg viewBox="0 0 36 36" width="24" height="24">
            <polygon points="18,2 34,11 34,25 18,34 2,25 2,11" fill="none" stroke={C.purple} strokeWidth="1.5" />
            <polygon points="18,8 28,14 28,22 18,28 8,22 8,14" fill="none" stroke={C.purple} strokeWidth="0.8" opacity="0.5" />
            <circle cx="18" cy="18" r="3" fill={C.purple}><animate attributeName="r" values="3;4;3" dur="2.5s" repeatCount="indefinite" /></circle>
          </svg>
          <div>
            <div style={{ fontFamily: "'Syne', sans-serif", fontWeight: 800, fontSize: "14px", letterSpacing: "0.06em", color: C.sidebarText }}>WebIntelX</div>
            <div style={{ fontFamily: "'DM Mono', monospace", fontSize: "9px", color: C.sidebarFaint, letterSpacing: "0.1em" }}>Threat Intelligence</div>
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
          <span style={{ fontFamily: "'DM Mono', monospace", fontSize: "10px", color: C.sidebarFaint }}>custom_scan · module_03</span>
          <div style={{ display: "flex", alignItems: "center", gap: "7px", padding: "4px 12px", borderRadius: "20px", background: scanning ? "rgba(109,40,217,0.2)" : "rgba(255,255,255,0.06)", border: `1px solid ${scanning ? C.purple + "60" : C.sidebarBorder}`, transition: "all 0.3s" }}>
            <div style={{ width: "7px", height: "7px", borderRadius: "50%", background: scanning ? C.purple : C.sidebarFaint, animation: scanning ? "pulse 1.4s ease-in-out infinite" : "none", boxShadow: scanning ? `0 0 8px ${C.purple}` : "none", transition: "all 0.3s" }} />
            <span style={{ fontFamily: "'DM Mono', monospace", fontSize: "10px", color: scanning ? C.accentBorder : C.sidebarMuted }}>{scanning ? `Scanning ${fmtTime(elapsed)}` : "Ready"}</span>
          </div>
        </div>
      </header>

      {/* BODY */}
      <div style={{ flex: 1, display: "flex", overflow: "hidden", height: "calc(100vh - 52px)" }}>

        {/* SIDEBAR */}
        <aside style={{ width: "264px", flexShrink: 0, background: C.sidebarBg, borderRight: `1px solid ${C.sidebarBorder}`, display: "flex", flexDirection: "column", height: "100%", overflow: "hidden", position: "sticky", top: 0 }}>
          <div style={{ flex: 1, overflowY: "auto", padding: "18px 10px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "0 6px", marginBottom: "14px" }}>
              <span style={{ fontFamily: "'DM Mono', monospace", fontSize: "9px", color: C.sidebarFaint, letterSpacing: "0.12em" }}>MODULES ({selected.size}/{ALL_MODULE_IDS.length})</span>
              <div style={{ display: "flex", gap: "10px" }}>
                <span onClick={selectAll}  style={{ fontFamily: "'DM Mono', monospace", fontSize: "9px", color: C.accentBorder, cursor: "pointer", letterSpacing: "0.04em" }}>all</span>
                <span onClick={selectNone} style={{ fontFamily: "'DM Mono', monospace", fontSize: "9px", color: C.sidebarFaint,  cursor: "pointer", letterSpacing: "0.04em" }}>none</span>
              </div>
            </div>
            {MODULE_GROUPS.map(group => {
              const gSel = group.modules.filter(m => selected.has(m.id)).length;
              const allOn = gSel === group.modules.length;
              return (
                <div key={group.label} style={{ marginBottom: "18px" }}>
                  <div onClick={() => toggleGroup(group.modules)} style={{ display: "flex", alignItems: "center", gap: "8px", padding: "4px 8px", cursor: "pointer", marginBottom: "4px", borderRadius: "4px" }}
                    onMouseEnter={e => e.currentTarget.style.background = C.sidebarHover}
                    onMouseLeave={e => e.currentTarget.style.background = "transparent"}>
                    <div style={{ width: "3px", height: "13px", background: allOn ? group.color : C.sidebarFaint, borderRadius: "1px", flexShrink: 0, transition: "background 0.2s" }} />
                    <span style={{ fontFamily: "'Syne', sans-serif", fontWeight: 700, fontSize: "11px", color: allOn ? C.sidebarText : C.sidebarMuted, flex: 1, letterSpacing: "0.04em", transition: "color 0.2s" }}>{group.label}</span>
                    <span style={{ fontFamily: "'DM Mono', monospace", fontSize: "9px", color: allOn ? group.color : C.sidebarFaint, background: allOn ? group.color + "18" : "transparent", border: `1px solid ${allOn ? group.color + "40" : C.sidebarBorder}`, padding: "1px 7px", borderRadius: "10px", transition: "all 0.2s" }}>{gSel}/{group.modules.length}</span>
                  </div>
                  {group.modules.map(mod => (
                    <SideCheckRow key={mod.id} id={mod.id} label={mod.label} on={selected.has(mod.id)} color={group.color} toggle={toggleModule} />
                  ))}
                </div>
              );
            })}
          </div>
        </aside>

        {/* MAIN CONTENT */}
        <main style={{ flex: 1, overflowY: "auto", background: C.bg, display: "flex", flexDirection: "column", height: "100%" }}>

          {/* Sticky re-scan bar */}
          {(results || scanning) && (
            <div style={{ position: "sticky", top: 0, zIndex: 10, background: C.white, borderBottom: `1px solid ${C.border}`, borderTop: `3px solid ${C.accent}`, padding: "14px 48px", display: "flex", alignItems: "center", gap: "12px", boxShadow: "0 2px 8px rgba(0,0,0,0.06)" }}>
              <div style={{ fontFamily: "'DM Mono', monospace", fontSize: "10px", color: C.textXMuted, letterSpacing: "0.1em", flexShrink: 0, whiteSpace: "nowrap" }}>NEW TARGET</div>
              <input value={input} onChange={e => { setInput(e.target.value); if (error) setError(""); }} onKeyDown={e => e.key === "Enter" && handleScan()} placeholder="example.com"
                style={{ flex: 1, padding: "9px 14px", background: C.bg, border: `1px solid ${C.border}`, color: C.text, fontFamily: "'DM Mono', monospace", fontSize: "13px", borderRadius: "4px", outline: "none", transition: "border-color 0.15s", minWidth: 0 }}
                onFocus={e => e.target.style.borderColor = C.accent} onBlur={e => e.target.style.borderColor = C.border} />
              <button onClick={handleScan} disabled={scanning || !input.trim() || selected.size === 0}
                style={{ fontFamily: "'Rajdhani', sans-serif", fontWeight: 700, fontSize: "14px", letterSpacing: "0.1em", textTransform: "uppercase", color: (scanning || !input.trim() || selected.size === 0) ? C.textXMuted : C.white, background: (scanning || !input.trim() || selected.size === 0) ? C.border : C.accent, border: "none", padding: "9px 24px", borderRadius: "4px", cursor: (scanning || !input.trim() || selected.size === 0) ? "not-allowed" : "pointer", display: "flex", alignItems: "center", gap: "8px", flexShrink: 0, boxShadow: (scanning || !input.trim() || selected.size === 0) ? "none" : `0 2px 8px ${C.accent}50`, transition: "all 0.15s", whiteSpace: "nowrap" }}
                onMouseEnter={e => { if (!scanning && input.trim() && selected.size > 0) { e.currentTarget.style.background = C.accentHover; e.currentTarget.style.transform = "translateY(-1px)"; }}}
                onMouseLeave={e => { e.currentTarget.style.background = (scanning || !input.trim() || selected.size === 0) ? C.border : C.accent; e.currentTarget.style.transform = "translateY(0)"; }}>
                {scanning ? <span style={{ animation: "spin 0.8s linear infinite", display: "inline-block", fontSize: "11px" }}>◌</span> : <FaSearch style={{ fontSize: "11px" }} />}
                {scanning ? "Scanning…" : "Run Scan"}
              </button>
              {error && <div style={{ fontFamily: "'DM Mono', monospace", fontSize: "11px", color: C.red, flexShrink: 0 }}>✕ {error}</div>}
            </div>
          )}

          {/* Welcome state */}
          {!results && !scanning && (
            <div style={{ padding: "52px 48px", animation: "fadeUp 0.5s ease both", maxWidth: "780px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "22px" }}>
                <div style={{ width: "3px", height: "18px", background: C.accent, borderRadius: "1px", flexShrink: 0 }} />
                <span style={{ fontFamily: "'DM Mono', monospace", fontSize: "11px", color: C.accent, letterSpacing: "0.14em" }}>// MODULE_03 / CUSTOM_SCAN</span>
              </div>
              <h1 style={{ fontFamily: "'Rajdhani', sans-serif", fontWeight: 700, fontSize: "clamp(52px, 7vw, 88px)", color: C.text, lineHeight: 0.95, letterSpacing: "0.02em", textTransform: "uppercase", marginBottom: "22px" }}>
                CUSTOM <span style={{ color: C.accent }}>SCAN</span>
              </h1>
              <p style={{ fontFamily: "'DM Sans', sans-serif", fontSize: "15px", color: C.textMuted, lineHeight: 1.75, maxWidth: "520px", marginBottom: "24px" }}>
                Select modules from the sidebar, enter a target domain or URL, and run a fully customised security assessment on your chosen attack surface.
              </p>
              <div style={{ width: "48px", height: "3px", background: C.accent, borderRadius: "1px", marginBottom: "44px" }} />
              <div style={{ background: C.white, border: `1px solid ${C.border}`, borderTop: `3px solid ${C.accent}`, borderRadius: "0 0 8px 8px", padding: "28px 32px", boxShadow: "0 2px 10px rgba(0,0,0,0.05)" }}>
                <div style={{ fontFamily: "'DM Mono', monospace", fontSize: "10px", color: C.textXMuted, letterSpacing: "0.12em", marginBottom: "14px" }}>TARGET_INPUT // ENTER_URL_OR_DOMAIN</div>
                <div style={{ fontFamily: "'DM Mono', monospace", fontSize: "11px", fontWeight: 600, color: C.text, letterSpacing: "0.06em", marginBottom: "10px", textTransform: "uppercase" }}>TARGET URL</div>
                <div style={{ display: "flex", gap: "10px", flexWrap: "wrap" }}>
                  <input value={input} onChange={e => { setInput(e.target.value); if (error) setError(""); }} onKeyDown={e => e.key === "Enter" && handleScan()} placeholder="example.com"
                    style={{ flex: "1 1 220px", padding: "11px 16px", background: C.bg, border: `1px solid ${C.border}`, color: C.text, fontFamily: "'DM Mono', monospace", fontSize: "13px", borderRadius: "4px", transition: "border-color 0.15s" }}
                    onFocus={e => e.target.style.borderColor = C.accent} onBlur={e => e.target.style.borderColor = C.border} />
                  <button onClick={handleScan} disabled={scanning || !input.trim() || selected.size === 0}
                    style={{ fontFamily: "'Rajdhani', sans-serif", fontWeight: 700, fontSize: "15px", letterSpacing: "0.1em", textTransform: "uppercase", color: (scanning || !input.trim() || selected.size === 0) ? C.textXMuted : C.white, background: (scanning || !input.trim() || selected.size === 0) ? C.border : C.accent, border: "none", padding: "11px 28px", borderRadius: "4px", cursor: (scanning || !input.trim() || selected.size === 0) ? "not-allowed" : "pointer", display: "flex", alignItems: "center", gap: "9px", boxShadow: (scanning || !input.trim() || selected.size === 0) ? "none" : `0 2px 10px ${C.accent}50`, transition: "all 0.15s" }}
                    onMouseEnter={e => { if (!scanning && input.trim() && selected.size > 0) { e.currentTarget.style.background = C.accentHover; e.currentTarget.style.transform = "translateY(-1px)"; }}}
                    onMouseLeave={e => { e.currentTarget.style.background = (scanning || !input.trim() || selected.size === 0) ? C.border : C.accent; e.currentTarget.style.transform = "translateY(0)"; }}>
                    {scanning ? <span style={{ animation: "spin 0.8s linear infinite", display: "inline-block", fontSize: "12px" }}>◌</span> : <FaSearch style={{ fontSize: "12px" }} />}
                    {scanning ? "Scanning…" : "Scan"}
                  </button>
                </div>
                {error && <div style={{ marginTop: "12px", padding: "10px 14px", background: C.redBg, border: `1px solid ${C.redBorder}`, borderRadius: "4px", fontFamily: "'DM Mono', monospace", fontSize: "12px", color: C.red }}>✕ {error}</div>}
              </div>
              <div style={{ display: "flex", gap: "16px", marginTop: "32px", flexWrap: "wrap" }}>
                {[{ label: "Total Modules", value: ALL_MODULE_IDS.length }, { label: "Selected", value: selected.size }, { label: "Categories", value: MODULE_GROUPS.length }].map(stat => (
                  <div key={stat.label} style={{ padding: "16px 22px", background: C.white, border: `1px solid ${C.border}`, borderBottom: `3px solid ${C.accent}`, borderRadius: "4px 4px 0 0", minWidth: "120px" }}>
                    <div style={{ fontFamily: "'Rajdhani', sans-serif", fontWeight: 700, fontSize: "32px", color: C.accent, lineHeight: 1 }}>{stat.value}</div>
                    <div style={{ fontFamily: "'DM Mono', monospace", fontSize: "9px", color: C.textMuted, marginTop: "5px", letterSpacing: "0.08em", textTransform: "uppercase" }}>{stat.label}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Scanning state */}
          {scanning && (
            <div style={{ padding: "52px 48px", animation: "fadeUp 0.3s ease both", maxWidth: "780px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "22px" }}>
                <div style={{ width: "3px", height: "18px", background: C.accent, borderRadius: "1px", flexShrink: 0 }} />
                <span style={{ fontFamily: "'DM Mono', monospace", fontSize: "11px", color: C.accent, letterSpacing: "0.14em" }}>// EXECUTING SCAN</span>
              </div>
              <h2 style={{ fontFamily: "'Rajdhani', sans-serif", fontWeight: 700, fontSize: "clamp(40px, 5vw, 64px)", color: C.text, lineHeight: 0.95, letterSpacing: "0.02em", textTransform: "uppercase", marginBottom: "20px" }}>
                RUNNING <span style={{ color: C.accent }}>{selected.size} MODULE{selected.size !== 1 ? "S" : ""}</span>
              </h2>
              <div style={{ display: "flex", alignItems: "center", gap: "14px", marginBottom: "16px" }}>
                <div style={{ width: "18px", height: "18px", border: `2px solid ${C.border}`, borderTop: `2px solid ${C.accent}`, borderRadius: "50%", animation: "spin 0.7s linear infinite", flexShrink: 0 }} />
                <span style={{ fontFamily: "'DM Mono', monospace", fontSize: "14px", color: C.textMuted, letterSpacing: "0.06em" }}>{fmtTime(elapsed)}</span>
              </div>
              <div style={{ width: "48px", height: "3px", background: C.accent, borderRadius: "1px", marginBottom: "24px" }} />
              <p style={{ fontFamily: "'DM Mono', monospace", fontSize: "11px", color: C.textMuted, marginBottom: "24px", letterSpacing: "0.04em" }}>Vulnerability modules may take up to 3 minutes. Please wait.</p>
              <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                {[...selected].map(id => {
                  const grp = MODULE_GROUPS.find(g => g.modules.find(m => m.id === id));
                  const mod = grp?.modules.find(m => m.id === id);
                  return <span key={id} style={{ fontFamily: "'DM Mono', monospace", fontSize: "10px", color: grp?.color || C.purple, background: (grp?.color || C.purple) + "12", border: `1px solid ${(grp?.color || C.purple)}30`, padding: "3px 10px", borderRadius: "4px" }}>{mod?.label || id}</span>;
                })}
              </div>
            </div>
          )}

          {/* Results */}
          {results && !scanning && (
            <div ref={resultsRef} style={{ padding: "32px 48px" }}>
              <div style={{ fontFamily: "'DM Mono', monospace", fontSize: "13px", color: C.textSecondary, letterSpacing: "0.08em", marginBottom: "20px", fontWeight: 500 }}>// scan_results</div>
              <ResultsView r={results} riskAssessment={riskAssessment} target={scanTarget} onDownload={handleDownload} isDownloading={isDownloading} />
            </div>
          )}
        </main>
      </div>
    </div>
  );
}