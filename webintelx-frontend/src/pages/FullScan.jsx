//fullscan.jsx - A comprehensive, detailed report of all reconnaissance and intelligence findings related to the target, including technology fingerprinting, open ports, HTTP headers, OSINT data, and more. This is the "kitchen sink" page where we dump every useful piece of info we can find in a clean, organized way for analysts to pore over.

import { useState, useRef } from "react";
import axios from "axios";
import {
  FaSearch, FaFingerprint, FaNetworkWired, FaBug,
  FaUserSecret, FaListUl, FaFileDownload, FaGlobe,
  FaServer, FaShieldAlt, FaLock, FaCode, FaExclamationTriangle,
  FaCheckCircle, FaTimesCircle, FaEnvelope, FaMapMarkerAlt,
} from "react-icons/fa";

const FONT_URL = "https://fonts.googleapis.com/css2?family=DM+Mono:ital,wght@0,300;0,400;0,500;1,400&family=Rajdhani:wght@500;600;700&family=Syne:wght@400;500;600;700;800&family=DM+Sans:ital,opsz,wght@0,9..40,300;0,9..40,400;0,9..40,500;0,9..40,600;1,9..40,400&display=swap";

const C = {
  bg: "#F7F8F9", white: "#FFFFFF", border: "#E4E8EC", borderDark: "#CDD4DB",
  text: "#0F1923", textSecondary: "#3A4A58", textMuted: "#6B7C8D", textXMuted: "#9BAAB7",
  accent: "#B54A0C", accentLight: "#FFF7ED", accentBorder: "#FED7AA", accentHover: "#9A3E0A",
  green: "#0A6640", greenBg: "#EAF4EE", greenBorder: "#A7D7BC",
  amber: "#92600A", amberBg: "#FFFBEB", amberBorder: "#FDE68A",
  orange: "#B54A0C", orangeBg: "#FFF7ED", orangeBorder: "#FED7AA",
  red: "#C0312B", redBg: "#FEF2F2", redBorder: "#FECACA",
  blue: "#2563AB", blueBg: "#EFF6FF", blueBorder: "#BFDBFE",
  purple: "#6d28d9", purpleBg: "#F5F3FF", purpleBorder: "#DDD6FE",
  sidebarBg: "#0F1923", sidebarBorder: "#1E2A36", sidebarFaint: "#3D4E5E", sidebarText: "#E6EDF3",
};

const riskAccent = (risk) => {
  const r = (risk || "").toUpperCase();
  if (r === "CRITICAL") return C.red;
  if (r === "HIGH") return C.orange;
  if (r === "MEDIUM") return C.amber;
  if (r === "LOW") return C.green;
  return C.textMuted;
};
const riskBg     = (risk) => { const r=(risk||"").toUpperCase(); if(r==="CRITICAL")return C.redBg;    if(r==="HIGH")return C.orangeBg;    if(r==="MEDIUM")return C.amberBg;    return C.greenBg; };
const riskBorder = (risk) => { const r=(risk||"").toUpperCase(); if(r==="CRITICAL")return C.redBorder; if(r==="HIGH")return C.orangeBorder; if(r==="MEDIUM")return C.amberBorder; return C.greenBorder; };

// ─── PRIMITIVES ──────────────────────────────────────────────────────────────

const Tag = ({ children, color = C.green }) => (
  <span style={{ fontFamily:"'DM Mono',monospace", fontSize:"11px", color, background:color+"12", border:`1px solid ${color}30`, padding:"3px 10px", borderRadius:"4px", marginRight:"6px", marginBottom:"6px", display:"inline-block" }}>{children}</span>
);

const KV = ({ label, value, valueColor, mono = true }) => {
  if (value === null || value === undefined || value === "") return null;
  const str = typeof value === "object" ? JSON.stringify(value) : String(value);
  if (str === "" || str === "null" || str === "undefined") return null;
  return (
    <div style={{ display:"flex", alignItems:"flex-start", gap:"12px", padding:"7px 0", borderBottom:`1px solid ${C.border}` }}>
      <span style={{ fontFamily:"'DM Mono',monospace", fontSize:"11px", color:C.textMuted, minWidth:"190px", flexShrink:0, paddingTop:"1px", textTransform:"uppercase", letterSpacing:"0.04em" }}>{label}</span>
      <span style={{ fontFamily: mono?"'DM Mono',monospace":"'DM Sans',sans-serif", fontSize: mono?"12px":"13px", color: valueColor||C.blue, wordBreak:"break-all", lineHeight:1.5 }}>{str}</span>
    </div>
  );
};

const Mono = ({ children, color = C.textSecondary }) => (
  <div style={{ fontFamily:"'DM Mono',monospace", fontSize:"12px", color, lineHeight:1.9 }}>{children}</div>
);

const SubHead = ({ children, color = C.textMuted }) => (
  <div style={{ fontFamily:"'DM Mono',monospace", fontSize:"10px", color, textTransform:"uppercase", letterSpacing:"0.1em", marginTop:"16px", marginBottom:"8px", paddingBottom:"4px", borderBottom:`1px solid ${C.border}` }}>{children}</div>
);

const RiskChip = ({ level }) => {
  if (!level) return null;
  const r = level.toUpperCase();
  return (
    <span style={{ fontFamily:"'DM Mono',monospace", fontSize:"10px", fontWeight:600, letterSpacing:"0.06em", padding:"2px 8px", borderRadius:"4px", border:`1px solid ${riskBorder(r)}`, background:riskBg(r), color:riskAccent(r) }}>{r}</span>
  );
};

const SectionHeader = ({ icon, title, accent = C.green, count }) => (
  <div style={{ display:"flex", alignItems:"center", gap:"10px", marginBottom:"16px", paddingBottom:"12px", borderBottom:`1px solid ${C.border}` }}>
    <span style={{ color:accent, fontSize:"14px", flexShrink:0 }}>{icon}</span>
    <span style={{ fontFamily:"'Syne',sans-serif", fontWeight:700, fontSize:"13px", color:C.text, letterSpacing:"0.02em" }}>{title}</span>
    {count !== undefined && (
      <span style={{ marginLeft:"auto", fontFamily:"'DM Mono',monospace", fontSize:"11px", color:accent, background:accent+"12", border:`1px solid ${accent}30`, padding:"2px 10px", borderRadius:"20px" }}>{count}</span>
    )}
  </div>
);

const Panel = ({ children, accentColor = C.green, style = {} }) => (
  <div style={{ background:C.white, border:`1px solid ${C.border}`, borderLeft:`4px solid ${accentColor}`, borderRadius:"0 6px 6px 0", padding:"24px", marginBottom:"12px", boxShadow:"0 1px 4px rgba(0,0,0,0.04)", ...style }}>
    {children}
  </div>
);

// Recursively renders any object/array of data — no assumptions, no junk
const AutoKV = ({ obj, skipKeys = [] }) => {
  if (!obj || typeof obj !== "object") return null;
  const skip = new Set(skipKeys);
  return Object.entries(obj).map(([k, val]) => {
    if (skip.has(k) || val === null || val === undefined || val === "") return null;
    if (Array.isArray(val)) {
      if (!val.length) return null;
      if (typeof val[0] !== "object") {
        return (
          <div key={k}>
            <SubHead>{k.replace(/_/g," ").toUpperCase()}</SubHead>
            <div style={{ display:"flex", flexWrap:"wrap", gap:"4px" }}>
              {val.map((item,i) => <Tag key={i} color={C.blue}>{String(item)}</Tag>)}
            </div>
          </div>
        );
      }
      return (
        <div key={k}>
          <SubHead>{k.replace(/_/g," ").toUpperCase()} ({val.length})</SubHead>
          {val.map((item,i) => (
            <div key={i} style={{ marginBottom:"8px", paddingLeft:"12px", borderLeft:`2px solid ${C.border}` }}>
              <AutoKV obj={item} />
            </div>
          ))}
        </div>
      );
    }
    if (typeof val === "object") {
      return (
        <div key={k}>
          <SubHead>{k.replace(/_/g," ").toUpperCase()}</SubHead>
          <div style={{ paddingLeft:"12px", borderLeft:`2px solid ${C.border}` }}>
            <AutoKV obj={val} />
          </div>
        </div>
      );
    }
    return <KV key={k} label={k.replace(/_/g," ").toUpperCase()} value={String(val)} valueColor={C.blue} />;
  });
};

// ─── MODULE BLOCK ─────────────────────────────────────────────────────────────
const ModuleBlock = ({ keyName, title, found, expanded, onToggle, children }) => (
  <div style={{ background:C.white, border:`1px solid ${found?C.orangeBorder:C.border}`, borderLeft:`4px solid ${found?C.orange:C.green}`, borderRadius:"0 6px 6px 0", marginBottom:"10px", overflow:"hidden", boxShadow:"0 1px 3px rgba(0,0,0,0.04)" }}>
    <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", padding:"16px 20px" }}>
      <div style={{ display:"flex", alignItems:"center", gap:"12px" }}>
        <span style={{ fontFamily:"'DM Mono',monospace", fontWeight:500, fontSize:"11px", letterSpacing:"0.04em", padding:"3px 10px", borderRadius:"20px", background:found?C.orangeBg:C.greenBg, border:`1px solid ${found?C.orangeBorder:C.greenBorder}`, color:found?C.orange:C.green }}>
          {found?"Vulnerable":"Not found"}
        </span>
        <h4 style={{ fontFamily:"'Syne',sans-serif", fontWeight:700, fontSize:"14px", color:C.text }}>{title}</h4>
      </div>
      <button onClick={() => onToggle(keyName)} style={{ fontFamily:"'DM Mono',monospace", fontSize:"11px", color:C.textMuted, background:C.bg, border:`1px solid ${C.border}`, padding:"5px 14px", borderRadius:"4px", cursor:"pointer", transition:"all 0.15s" }}
        onMouseEnter={e => { e.currentTarget.style.background=C.border; e.currentTarget.style.color=C.text; }}
        onMouseLeave={e => { e.currentTarget.style.background=C.bg; e.currentTarget.style.color=C.textMuted; }}>
        {expanded ? "▲ Hide" : "▼ Details"}
      </button>
    </div>
    {expanded && (
      <div style={{ padding:"16px 20px 20px", borderTop:`1px solid ${C.border}` }}>
        {children}
      </div>
    )}
  </div>
);

// ─── QUICKSCAN RESULTS ────────────────────────────────────────────────────────
function QuickScanResults({ data }) {
  const qs = data?.quickscan || {};
  const [expandedSections, setExpandedSections] = useState({ headers:true, tech:true, ports:true, osint:true });
  const [showDebug, setShowDebug] = useState(false);
  const toggle = (key) => setExpandedSections(s => ({ ...s, [key]: !s[key] }));

  const tech  = qs.technology || {};
  const ports = qs.ports || qs.portScan || {};
  const osint = qs.osint || qs.reputation || {};
  const hdrs  = qs.headers || qs.securityHeaders || qs.httpHeaders || {};

  const hasTech    = Object.keys(tech).length > 0;
  const hasPorts   = Object.keys(ports).length > 0;
  const hasHeaders = Object.keys(hdrs).length > 0;
  const hasOsintAlert = !!(osint.virusTotal?.malicious > 0 || osint.safeBrowsing?.safe === false || osint.blacklisted === true || osint.cves?.count > 0);
  const hasAnyData = hasTech || hasPorts || hasHeaders || hasOsintAlert;

  const CollapseBtn = ({ section }) => (
    <button onClick={() => toggle(section)} style={{ marginLeft:"auto", fontFamily:"'DM Mono',monospace", fontSize:"11px", color:C.textMuted, background:C.bg, border:`1px solid ${C.border}`, padding:"4px 12px", borderRadius:"4px", cursor:"pointer", transition:"all 0.15s", flexShrink:0 }}
      onMouseEnter={e => { e.currentTarget.style.background=C.border; e.currentTarget.style.color=C.text; }}
      onMouseLeave={e => { e.currentTarget.style.background=C.bg; e.currentTarget.style.color=C.textMuted; }}>
      {expandedSections[section] ? "▲ Hide" : "▼ Show"}
    </button>
  );

  return (
    <div>
      <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:"20px" }}>
        <div style={{ fontFamily:"'DM Mono',monospace", fontSize:"11px", color:C.textXMuted, letterSpacing:"0.05em" }}>// reconnaissance_intelligence</div>
        <button onClick={() => setShowDebug(s => !s)} style={{ fontFamily:"'DM Mono',monospace", fontSize:"11px", color:showDebug?C.amber:C.textMuted, background:showDebug?C.amberBg:C.bg, border:`1px solid ${showDebug?C.amberBorder:C.border}`, padding:"4px 12px", borderRadius:"4px", cursor:"pointer", transition:"all 0.2s" }}>
          {showDebug ? "▲ Hide raw data" : "▼ Debug: raw quickscan"}
        </button>
      </div>

      {showDebug && (
        <div style={{ marginBottom:"20px", background:C.amberBg, border:`1px solid ${C.amberBorder}`, borderLeft:`4px solid ${C.amber}`, borderRadius:"0 6px 6px 0", padding:"16px" }}>
          <div style={{ fontFamily:"'Syne',sans-serif", fontWeight:700, fontSize:"12px", color:C.amber, marginBottom:"10px" }}>⚙ Raw quickscan keys</div>
          <pre style={{ maxHeight:"300px", overflowY:"auto", fontSize:"11px", color:C.textSecondary, background:C.white, padding:"12px", border:`1px solid ${C.border}`, borderRadius:"4px" }}>{JSON.stringify(qs, null, 2)}</pre>
        </div>
      )}

      {!hasAnyData && (
        <Panel accentColor={C.amber}>
          <div style={{ fontFamily:"'DM Mono',monospace", fontSize:"12px", color:C.amber, lineHeight:1.8 }}>
            <div style={{ marginBottom:"8px" }}>⚠ No reconnaissance data found in <span style={{ fontWeight:600 }}>scanResult.quickscan</span></div>
            <div style={{ color:C.textMuted }}>Enable the debug toggle above to inspect what your backend is returning.</div>
          </div>
        </Panel>
      )}

      {/* Technology */}
      {hasTech && (
        <Panel accentColor={C.amber}>
          <div style={{ display:"flex", alignItems:"center", gap:"12px", marginBottom:expandedSections.tech?"20px":0 }}>
            <SectionHeader icon={<FaFingerprint />} title="Technology Fingerprint" accent={C.amber} />
            <CollapseBtn section="tech" />
          </div>
          {expandedSections.tech && (
            <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fill, minmax(280px, 1fr))", gap:"12px" }}>
              {(tech.server||tech.backend||tech.serverVersion||tech.os||tech.poweredBy) && (
                <div style={{ background:C.amberBg, border:`1px solid ${C.amberBorder}`, borderRadius:"6px", padding:"16px" }}>
                  <div style={{ fontFamily:"'Syne',sans-serif", fontWeight:700, fontSize:"11px", color:C.amber, textTransform:"uppercase", letterSpacing:"0.06em", marginBottom:"10px" }}>Server</div>
                  <KV label="WEB_SERVER"  value={tech.server}         valueColor={C.amber} />
                  <KV label="BACKEND"     value={tech.backend}        valueColor={C.amber} />
                  <KV label="VERSION"     value={tech.serverVersion}  valueColor={tech.serverVersionOutdated?C.red:C.amber} />
                  <KV label="OS"          value={tech.os}             valueColor={C.textSecondary} />
                  <KV label="POWERED_BY"  value={tech.poweredBy}      valueColor={C.amber} />
                </div>
              )}
              {(tech.ssl!==undefined||tech.https!==undefined) && (
                <div style={{ background:(tech.ssl||tech.https)?C.greenBg:C.redBg, border:`1px solid ${(tech.ssl||tech.https)?C.greenBorder:C.redBorder}`, borderRadius:"6px", padding:"16px" }}>
                  <div style={{ fontFamily:"'Syne',sans-serif", fontWeight:700, fontSize:"11px", color:(tech.ssl||tech.https)?C.green:C.red, textTransform:"uppercase", letterSpacing:"0.06em", marginBottom:"10px" }}>SSL / HTTPS</div>
                  <KV label="SSL_ENABLED"    value={(tech.ssl||tech.https)?"YES":"NO"} valueColor={(tech.ssl||tech.https)?C.green:C.red} />
                  <KV label="PROTOCOL"       value={tech.tlsVersion}       valueColor={C.blue} />
                  <KV label="GRADE"          value={tech.sslGrade}         valueColor={C.amber} />
                  <KV label="ISSUER"         value={tech.sslIssuer}        valueColor={C.textSecondary} />
                  <KV label="EXPIRES"        value={tech.sslExpiry}        valueColor={C.textSecondary} />
                  <KV label="DAYS_REMAINING" value={tech.sslDaysRemaining} valueColor={tech.sslDaysRemaining<30?C.red:C.green} />
                </div>
              )}
              {tech.cms && (
                <div style={{ background:C.blueBg, border:`1px solid ${C.blueBorder}`, borderRadius:"6px", padding:"16px" }}>
                  <div style={{ fontFamily:"'Syne',sans-serif", fontWeight:700, fontSize:"11px", color:C.blue, textTransform:"uppercase", letterSpacing:"0.06em", marginBottom:"10px" }}>CMS / Platform</div>
                  <KV label="CMS"      value={tech.cms}        valueColor={C.blue} />
                  <KV label="VERSION"  value={tech.cmsVersion} valueColor={tech.cmsOutdated?C.red:C.blue} />
                  <KV label="THEME"    value={tech.cmsTheme}   valueColor={C.textSecondary} />
                  {tech.cmsOutdated && <div style={{ marginTop:"6px", fontFamily:"'DM Mono',monospace", fontSize:"11px", color:C.red }}>⚠ Outdated version detected</div>}
                  {Array.isArray(tech.plugins) && tech.plugins.length > 0 && (
                    <>
                      <div style={{ fontFamily:"'DM Mono',monospace", fontSize:"11px", color:C.textMuted, marginTop:"10px", marginBottom:"6px" }}>PLUGINS ({tech.plugins.length})</div>
                      <div style={{ display:"flex", flexWrap:"wrap", gap:"4px" }}>
                        {tech.plugins.map((p,i) => <Tag key={i} color={C.blue}>{p}</Tag>)}
                      </div>
                    </>
                  )}
                </div>
              )}
              {(tech.frameworks?.length>0||tech.jsFrameworks?.length>0||tech.libraries?.length>0) && (
                <div style={{ background:C.purpleBg, border:`1px solid ${C.purpleBorder}`, borderRadius:"6px", padding:"16px" }}>
                  <div style={{ fontFamily:"'Syne',sans-serif", fontWeight:700, fontSize:"11px", color:C.purple, textTransform:"uppercase", letterSpacing:"0.06em", marginBottom:"10px" }}>Frameworks & Libraries</div>
                  <div style={{ display:"flex", flexWrap:"wrap", gap:"6px" }}>
                    {[...(tech.frameworks||[]),...(tech.jsFrameworks||[]),...(tech.libraries||[])].map((f,i) => <Tag key={i} color={C.purple}>{f}</Tag>)}
                  </div>
                </div>
              )}
              {(tech.cdn||tech.hosting||tech.cloudProvider||tech.waf||tech.reverseProxy) && (
                <div style={{ background:C.greenBg, border:`1px solid ${C.greenBorder}`, borderRadius:"6px", padding:"16px" }}>
                  <div style={{ fontFamily:"'Syne',sans-serif", fontWeight:700, fontSize:"11px", color:C.green, textTransform:"uppercase", letterSpacing:"0.06em", marginBottom:"10px" }}>Infrastructure</div>
                  <KV label="CDN"           value={tech.cdn}           valueColor={C.green} />
                  <KV label="HOSTING"       value={tech.hosting}       valueColor={C.green} />
                  <KV label="CLOUD"         value={tech.cloudProvider} valueColor={C.green} />
                  <KV label="WAF"           value={tech.waf}           valueColor={C.amber} />
                  <KV label="REVERSE_PROXY" value={tech.reverseProxy}  valueColor={C.textSecondary} />
                </div>
              )}
              {(tech.analytics?.length>0||tech.trackers?.length>0) && (
                <div style={{ background:C.orangeBg, border:`1px solid ${C.orangeBorder}`, borderRadius:"6px", padding:"16px" }}>
                  <div style={{ fontFamily:"'Syne',sans-serif", fontWeight:700, fontSize:"11px", color:C.orange, textTransform:"uppercase", letterSpacing:"0.06em", marginBottom:"10px" }}>Analytics & Trackers</div>
                  <div style={{ display:"flex", flexWrap:"wrap", gap:"6px" }}>
                    {[...(tech.analytics||[]),...(tech.trackers||[])].map((t,i) => <Tag key={i} color={C.orange}>{t}</Tag>)}
                  </div>
                </div>
              )}
              {/* Remaining tech fields */}
              {(() => {
                const handled = new Set(["server","backend","serverVersion","serverVersionOutdated","os","ssl","https","tlsVersion","sslGrade","sslIssuer","sslExpiry","sslDaysRemaining","cms","cmsVersion","cmsOutdated","cmsTheme","plugins","frameworks","jsFrameworks","libraries","cdn","hosting","cloudProvider","waf","reverseProxy","analytics","trackers","poweredBy"]);
                const extra = Object.entries(tech).filter(([k,v]) => !handled.has(k) && v!==null && v!==undefined && v!=="");
                if (!extra.length) return null;
                return (
                  <div style={{ background:C.blueBg, border:`1px solid ${C.blueBorder}`, borderRadius:"6px", padding:"16px" }}>
                    <div style={{ fontFamily:"'Syne',sans-serif", fontWeight:700, fontSize:"11px", color:C.blue, textTransform:"uppercase", letterSpacing:"0.06em", marginBottom:"10px" }}>Additional</div>
                    {extra.map(([k,v]) => <KV key={k} label={k.toUpperCase().replace(/_/g," ")} value={typeof v==="object"?JSON.stringify(v):String(v)} valueColor={C.blue} />)}
                  </div>
                );
              })()}
            </div>
          )}
        </Panel>
      )}

      {/* HTTP Headers */}
      <Panel accentColor={C.blue}>
        <div style={{ display:"flex", alignItems:"center", gap:"12px", marginBottom:expandedSections.headers?"20px":0 }}>
          <SectionHeader icon={<FaShieldAlt />} title="HTTP Security Headers" accent={C.blue}
            count={hasHeaders?`${Object.values(hdrs).filter(v=>v&&v!=="MISSING"&&v!==false).length} / ${Object.keys(hdrs).length} present`:"No data"} />
          <CollapseBtn section="headers" />
        </div>
        {expandedSections.headers && (
          hasHeaders ? (
            <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fill, minmax(280px, 1fr))", gap:"8px" }}>
              {Object.entries(hdrs).map(([header, value]) => {
                const present = !!value && value !== "MISSING" && value !== false && value !== "false";
                const strVal  = typeof value === "string" ? value : JSON.stringify(value);
                return (
                  <div key={header} style={{ background:present?C.greenBg:C.redBg, border:`1px solid ${present?C.greenBorder:C.redBorder}`, borderRadius:"6px", padding:"12px 14px", display:"flex", flexDirection:"column", gap:"5px" }}>
                    <div style={{ display:"flex", alignItems:"center", gap:"8px" }}>
                      <span style={{ color:present?C.green:C.red, fontSize:"12px", flexShrink:0 }}>{present?<FaCheckCircle/>:<FaTimesCircle/>}</span>
                      <span style={{ fontFamily:"'DM Mono',monospace", fontSize:"11px", color:present?C.green:C.red, wordBreak:"break-all", fontWeight:500 }}>{header}</span>
                    </div>
                    {present && typeof value === "string" && value !== "true" && value.length > 0 && (
                      <div style={{ fontFamily:"'DM Mono',monospace", fontSize:"10px", color:C.textMuted, wordBreak:"break-all", lineHeight:1.5 }}>
                        {strVal.length > 120 ? strVal.substring(0,120)+"…" : strVal}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          ) : <div style={{ fontFamily:"'DM Mono',monospace", fontSize:"12px", color:C.textMuted }}>No header data returned.</div>
        )}
      </Panel>

      {/* Ports */}
      <Panel accentColor={C.blue}>
        <div style={{ display:"flex", alignItems:"center", gap:"12px", marginBottom:expandedSections.ports?"20px":0 }}>
          <SectionHeader icon={<FaServer />} title="Open Ports & Services" accent={C.blue}
            count={hasPorts?`${(ports.open||ports.list||ports.ports||[]).length} open`:"No data"} />
          <CollapseBtn section="ports" />
        </div>
        {expandedSections.ports && (
          hasPorts ? (
            <div>
              <KV label="TARGET_IP" value={ports.ip}       valueColor={C.blue} />
              <KV label="ASN"       value={ports.asn}      valueColor={C.textSecondary} />
              <KV label="ORG"       value={ports.org}      valueColor={C.textSecondary} />
              <KV label="ISP"       value={ports.isp}      valueColor={C.textSecondary} />
              <KV label="COUNTRY"   value={ports.country}  valueColor={C.amber} />
              <KV label="HOSTNAME"  value={ports.hostname} valueColor={C.textSecondary} />
              {(ports.open||ports.list||ports.ports||[]).length > 0 && (
                <div style={{ marginTop:"16px", display:"grid", gridTemplateColumns:"repeat(auto-fill, minmax(160px, 1fr))", gap:"8px" }}>
                  {(ports.open||ports.list||ports.ports||[]).map((port,i) => {
                    const portNum = typeof port==="object"?(port.port||port.number):port;
                    const service = typeof port==="object"?(port.service||port.name||port.protocol):null;
                    const banner  = typeof port==="object"?(port.banner||port.version||port.product):null;
                    const state   = typeof port==="object"?port.state:null;
                    const cpe     = typeof port==="object"?port.cpe:null;
                    const isSensitive = [21,22,23,25,3306,5432,6379,27017,8080,8443,1433,3389].includes(Number(portNum));
                    return (
                      <div key={i} style={{ background:isSensitive?C.orangeBg:C.blueBg, border:`1px solid ${isSensitive?C.orangeBorder:C.blueBorder}`, borderRadius:"6px", padding:"14px" }}>
                        <div style={{ fontFamily:"'Syne',sans-serif", fontWeight:800, fontSize:"24px", color:isSensitive?C.orange:C.blue, marginBottom:"4px", lineHeight:1 }}>{portNum}</div>
                        {service && <div style={{ fontFamily:"'DM Mono',monospace", fontSize:"11px", color:C.textMuted, marginBottom:"3px" }}>{service}</div>}
                        {state   && <div style={{ fontFamily:"'DM Mono',monospace", fontSize:"10px", color:C.textXMuted }}>state: {state}</div>}
                        {banner  && <div style={{ fontFamily:"'DM Mono',monospace", fontSize:"10px", color:C.textXMuted, marginTop:"3px", wordBreak:"break-all" }}>{String(banner).substring(0,60)}</div>}
                        {cpe     && <div style={{ fontFamily:"'DM Mono',monospace", fontSize:"10px", color:C.textXMuted, marginTop:"3px", wordBreak:"break-all" }}>{String(cpe).substring(0,60)}</div>}
                        {isSensitive && <div style={{ fontFamily:"'DM Mono',monospace", fontSize:"10px", color:C.orange, marginTop:"6px" }}>⚠ Sensitive</div>}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          ) : <div style={{ fontFamily:"'DM Mono',monospace", fontSize:"12px", color:C.textMuted }}>Port scan returned no results.</div>
        )}
      </Panel>

      {/* OSINT */}
      {hasOsintAlert && (
        <Panel accentColor={C.purple}>
          <div style={{ display:"flex", alignItems:"center", gap:"12px", marginBottom:expandedSections.osint?"20px":0 }}>
            <SectionHeader icon={<FaUserSecret />} title="OSINT & Reputation Intel" accent={C.purple} count="⚠ Findings" />
            <CollapseBtn section="osint" />
          </div>
          {expandedSections.osint && (
            <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fill, minmax(260px, 1fr))", gap:"12px" }}>
              {osint.virusTotal && (
                <div style={{ background:C.orangeBg, border:`1px solid ${C.orangeBorder}`, borderRadius:"6px", padding:"16px" }}>
                  <div style={{ fontFamily:"'Syne',sans-serif", fontWeight:700, fontSize:"11px", color:C.orange, textTransform:"uppercase", letterSpacing:"0.06em", marginBottom:"10px" }}>VirusTotal</div>
                  <KV label="MALICIOUS"       value={osint.virusTotal.malicious}      valueColor={osint.virusTotal.malicious>0?C.red:C.green} />
                  <KV label="SUSPICIOUS"      value={osint.virusTotal.suspicious}     valueColor={osint.virusTotal.suspicious>0?C.amber:C.green} />
                  <KV label="HARMLESS"        value={osint.virusTotal.harmless}       valueColor={C.green} />
                  <KV label="UNDETECTED"      value={osint.virusTotal.undetected}     valueColor={C.textMuted} />
                  <KV label="TOTAL_ENGINES"   value={osint.virusTotal.total}          valueColor={C.textSecondary} />
                  <KV label="COMMUNITY_SCORE" value={osint.virusTotal.communityScore} valueColor={osint.virusTotal.communityScore<0?C.red:C.textSecondary} />
                  <KV label="LAST_ANALYSIS"   value={osint.virusTotal.lastAnalysis}   valueColor={C.textMuted} />
                  {osint.virusTotal.categories?.length>0 && <div style={{ marginTop:"8px", display:"flex", flexWrap:"wrap", gap:"4px" }}>{osint.virusTotal.categories.map((c,i)=><Tag key={i} color={C.orange}>{c}</Tag>)}</div>}
                  {osint.virusTotal.engines?.length>0 && (
                    <>
                      <SubHead>Flagged By</SubHead>
                      <div style={{ display:"flex", flexWrap:"wrap", gap:"4px" }}>{osint.virusTotal.engines.slice(0,20).map((e,i)=><Tag key={i} color={C.red}>{e}</Tag>)}</div>
                    </>
                  )}
                </div>
              )}
              {osint.safeBrowsing && osint.safeBrowsing.safe===false && (
                <div style={{ background:C.redBg, border:`1px solid ${C.redBorder}`, borderRadius:"6px", padding:"16px" }}>
                  <div style={{ fontFamily:"'Syne',sans-serif", fontWeight:700, fontSize:"11px", color:C.red, textTransform:"uppercase", letterSpacing:"0.06em", marginBottom:"10px" }}>Google Safe Browsing</div>
                  <KV label="STATUS"       value="⚠ UNSAFE"                       valueColor={C.red} />
                  <KV label="THREAT_COUNT" value={osint.safeBrowsing.threatCount}  valueColor={C.red} />
                  {osint.safeBrowsing.threats?.length>0 && <div style={{ marginTop:"8px", display:"flex", flexWrap:"wrap", gap:"4px" }}>{osint.safeBrowsing.threats.map((t,i)=><Tag key={i} color={C.red}>{t}</Tag>)}</div>}
                </div>
              )}
            </div>
          )}
        </Panel>
      )}
    </div>
  );
}

// ─── CAPABILITY CARD ──────────────────────────────────────────────────────────
const CapabilityCard = ({ icon, title, desc, accent }) => (
  <div style={{ background:C.white, border:`1px solid ${C.border}`, borderLeft:`3px solid ${accent}`, borderRadius:"0 6px 6px 0", padding:"20px 22px", boxShadow:"0 1px 3px rgba(0,0,0,0.04)", transition:"box-shadow 0.2s, transform 0.2s" }}
    onMouseEnter={e => { e.currentTarget.style.boxShadow="0 4px 12px rgba(0,0,0,0.08)"; e.currentTarget.style.transform="translateY(-1px)"; }}
    onMouseLeave={e => { e.currentTarget.style.boxShadow="0 1px 3px rgba(0,0,0,0.04)"; e.currentTarget.style.transform="translateY(0)"; }}>
    <div style={{ display:"flex", alignItems:"flex-start", gap:"14px" }}>
      <div style={{ fontSize:"18px", marginTop:"2px", color:accent, flexShrink:0 }}>{icon}</div>
      <div>
        <h4 style={{ fontFamily:"'Syne',sans-serif", fontWeight:700, fontSize:"14px", color:C.text, marginBottom:"6px" }}>{title}</h4>
        <p style={{ fontFamily:"'DM Sans',sans-serif", fontSize:"13px", color:C.textMuted, lineHeight:1.6 }}>{desc}</p>
      </div>
    </div>
  </div>
);

// ─── MAIN ─────────────────────────────────────────────────────────────────────
export default function FullScan() {
  const [input, setInput] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [scanDone, setScanDone] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [expanded, setExpanded] = useState({});
  const [error, setError] = useState(null);
  const [showRawDomFindings, setShowRawDomFindings] = useState(false);
  const [isPaused, setIsPaused] = useState(false);
  const loaderRef = useRef(null);

  const isValidTarget = (val) => {
    const t = val.trim();
    try {
      const u = new URL(t.startsWith("http")?t:`http://${t}`);
      const h = u.hostname;
      return /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(h)||/^(\d{1,3}\.){3}\d{1,3}$/.test(h)||h==="localhost";
    } catch { return false; }
  };

  const handleScan = async () => {
    if (!input.trim()) return alert("Please enter a domain or URL");
    if (!isValidTarget(input)) { setError("Invalid target."); return; }
    setIsScanning(true); setScanDone(false); setScanResult(null); setError(null); setIsPaused(false);
    setTimeout(() => loaderRef.current?.scrollIntoView({ behavior:"smooth" }), 100);
    try {
          const resp = await axios.post("http://localhost:5000/api/fullscan", { url:input }, { timeout:0 });
          setScanResult(resp.data);
          setScanDone(true);
          setIsScanning(false);
          setIsPaused(false);
        } catch (err) {
          setError(err.response ? err.response.data.error||"Invalid target" : "Backend not reachable.");
          setIsScanning(false);
          setIsPaused(false);
        }
  };

  const downloadPDF = async () => {
    const resp = await axios.post("/api/fullscan/pdf", { scanData:scanResult, target:scanResult.target }, { responseType:"blob" });
    const blob = new Blob([resp.data], { type:"application/pdf" });
    const url  = window.URL.createObjectURL(blob);
    const a    = document.createElement("a"); a.href=url; a.download=`FullScan-${scanResult.target}.pdf`; a.click();
  };

  const toggle = (key) => setExpanded(s => ({ ...s, [key]: !s[key] }));

  const capabilities = [
    { icon:<FaUserSecret style={{color:C.purple}}/>,   title:"Deep OSINT Enumeration",       desc:"Scrapes public records, social sources, leak databases, DNS history, WHOIS, emails & metadata.", accent:C.purple },
    { icon:<FaNetworkWired style={{color:C.green}}/>,  title:"Infrastructure Reconnaissance", desc:"Maps subdomains, servers, CDN layers, firewalls, hosting providers & entry points.", accent:C.green },
    { icon:<FaBug style={{color:C.orange}}/>,          title:"Vulnerability Assessment",      desc:"Detects SQLi, XSS (DOM/Stored/Reflected), Clickjacking, Command Injection & exposed sensitive files.", accent:C.orange },
    { icon:<FaFingerprint style={{color:C.amber}}/>,   title:"Technology Fingerprinting",     desc:"Identifies CMS, frameworks, JS libraries, outdated components & vulnerable versions.", accent:C.amber },
    { icon:<FaListUl style={{color:C.blue}}/>,         title:"Port & Service Mapping",        desc:"Performs deep port scans to fingerprint running services & detect outdated servers.", accent:C.blue },
    { icon:<FaSearch style={{color:C.green}}/>,        title:"Malware & Phishing Indicators", desc:"Scans domain reputation, blocklists, suspicious redirects & malware hosting markers.", accent:C.green },
  ];

  return (
    <div style={{ backgroundColor:C.bg, minHeight:"100vh", color:C.text }}>
      <link rel="stylesheet" href={FONT_URL} />
      <style>{`
        @keyframes fadeUp { from{opacity:0;transform:translateY(12px)} to{opacity:1;transform:translateY(0)} }
        @keyframes spin { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }
        @keyframes pulse { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:0.4;transform:scale(0.8)} }
        @keyframes shimmer { 0%,100%{opacity:0.4} 50%{opacity:1} }
        @keyframes pauseBlink { 0%,100%{opacity:1} 50%{opacity:0.35} }
        * { box-sizing:border-box; margin:0; padding:0; }
        ::selection { background:rgba(181,74,12,0.15); color:${C.orange}; }
        ::-webkit-scrollbar { width:4px; }
        ::-webkit-scrollbar-track { background:${C.bg}; }
        ::-webkit-scrollbar-thumb { background:${C.borderDark}; border-radius:2px; }
        pre { white-space:pre-wrap; font-family:'DM Mono',monospace; font-size:11px; color:${C.textSecondary}; }
      `}</style>

      {/* NAV */}
      <nav style={{ position:"fixed", top:0, left:0, right:0, zIndex:200, display:"flex", alignItems:"center", justifyContent:"space-between", padding:"0 48px", height:"56px", background:C.sidebarBg, borderBottom:`1px solid ${C.sidebarBorder}` }}>
        <div style={{ display:"flex", alignItems:"center", gap:"12px", cursor:"pointer" }} onClick={() => window.location.href="/"}>
          <svg viewBox="0 0 36 36" width="26" height="26">
            <polygon points="18,2 34,11 34,25 18,34 2,25 2,11" fill="none" stroke={C.orange} strokeWidth="1.5"/>
            <polygon points="18,8 28,14 28,22 18,28 8,22 8,14" fill="none" stroke={C.orange} strokeWidth="0.8" opacity="0.4"/>
            <circle cx="18" cy="18" r="3" fill={C.orange}><animate attributeName="r" values="3;4;3" dur="2.5s" repeatCount="indefinite"/></circle>
          </svg>
          <div>
            <div style={{ fontFamily:"'Syne',sans-serif", fontWeight:800, fontSize:"14px", letterSpacing:"0.06em", color:C.sidebarText }}>WebIntelX</div>
            <div style={{ fontFamily:"'DM Mono',monospace", fontSize:"9px", color:C.sidebarFaint, letterSpacing:"0.1em", marginTop:"1px" }}>Threat Intelligence</div>
          </div>
        </div>
        <div style={{ display:"flex", alignItems:"center", gap:"12px" }}>
          <span style={{ fontFamily:"'DM Mono',monospace", fontSize:"10px", color:C.sidebarFaint, background:"rgba(255,255,255,0.05)", border:`1px solid ${C.sidebarBorder}`, padding:"4px 12px", borderRadius:"20px" }}>full_scan · module_02</span>
          <div style={{ display:"flex", alignItems:"center", gap:"7px", background:isPaused?"rgba(146,96,10,0.15)":isScanning?"rgba(181,74,12,0.15)":"rgba(255,255,255,0.05)", border:`1px solid ${isPaused?C.amberBorder+"60":isScanning?C.orangeBorder+"60":C.sidebarBorder}`, padding:"4px 12px", borderRadius:"20px", transition:"all 0.3s" }}>
            <div style={{ width:"7px", height:"7px", borderRadius:"50%", background:isPaused?C.amber:isScanning?C.orange:C.sidebarFaint, animation:isScanning&&!isPaused?"pulse 1.4s ease-in-out infinite":"none" }}/>
            <span style={{ fontFamily:"'DM Mono',monospace", fontSize:"10px", color:isPaused?C.amber:isScanning?C.orange:C.sidebarFaint }}>
              {isPaused?"Paused":isScanning?"Scanning…":"Ready"}
            </span>
          </div>
        </div>
      </nav>

      <div style={{ maxWidth:"1100px", margin:"0 auto", padding:"88px 40px 80px" }}>

        {/* Header */}
        <div style={{ marginBottom:"48px", animation:"fadeUp 0.5s ease 0.1s both", maxWidth:"780px" }}>
          <div style={{ display:"flex", alignItems:"center", gap:"10px", marginBottom:"22px" }}>
            <div style={{ width:"3px", height:"18px", background:C.orange, borderRadius:"1px", flexShrink:0 }}/>
            <span style={{ fontFamily:"'DM Mono',monospace", fontSize:"11px", color:C.orange, letterSpacing:"0.14em" }}>// MODULE_02 / FULL_SCAN</span>
          </div>
          <h1 style={{ fontFamily:"'Rajdhani',sans-serif", fontWeight:700, fontSize:"clamp(52px,7vw,88px)", color:C.text, lineHeight:0.95, letterSpacing:"0.02em", textTransform:"uppercase", marginBottom:"22px" }}>
            FULL <span style={{ color:C.orange }}>SCAN</span>
          </h1>
          <p style={{ fontFamily:"'DM Sans',sans-serif", fontSize:"15px", color:C.textMuted, lineHeight:1.75, maxWidth:"520px", marginBottom:"24px" }}>
            Deep OSINT + Reconnaissance + Vulnerability Assessment for complete intelligence on your target surface.
          </p>
          <div style={{ width:"48px", height:"3px", background:C.orange, borderRadius:"1px" }}/>
        </div>

        {/* Capabilities */}
        <div style={{ marginBottom:"52px", animation:"fadeUp 0.5s ease 0.2s both" }}>
          <div style={{ fontFamily:"'DM Mono',monospace", fontSize:"11px", color:C.textXMuted, letterSpacing:"0.08em", marginBottom:"18px" }}>// what_full_scan_includes</div>
          <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fill, minmax(300px, 1fr))", gap:"12px" }}>
            {capabilities.map((c,i) => <CapabilityCard key={i} {...c} />)}
          </div>
        </div>

        {/* Input */}
        <div style={{ background:C.white, border:`1px solid ${C.border}`, borderTop:`3px solid ${C.orange}`, borderRadius:"0 0 8px 8px", padding:"28px 32px", maxWidth:"600px", marginBottom:"28px", boxShadow:"0 2px 10px rgba(0,0,0,0.05)", animation:"fadeUp 0.5s ease 0.3s both" }}>
          <div style={{ fontFamily:"'DM Mono',monospace", fontSize:"10px", color:C.textXMuted, letterSpacing:"0.12em", marginBottom:"14px" }}>TARGET_INPUT // ENTER_URL_OR_DOMAIN</div>
          <div style={{ fontFamily:"'DM Mono',monospace", fontSize:"11px", fontWeight:600, color:C.text, letterSpacing:"0.06em", marginBottom:"10px", textTransform:"uppercase" }}>TARGET URL</div>
          <div style={{ display:"flex", gap:"10px", flexWrap:"wrap" }}>
            <input type="text" value={input} onChange={e => { setInput(e.target.value); if(error) setError(null); }} placeholder="example.com or https://company.com" onKeyDown={e => e.key==="Enter"&&handleScan()}
              style={{ flex:"1 1 220px", padding:"11px 16px", background:C.bg, border:`1px solid ${C.border}`, color:C.text, fontFamily:"'DM Mono',monospace", fontSize:"13px", outline:"none", borderRadius:"4px", transition:"border-color 0.15s" }}
              onFocus={e => e.target.style.borderColor=C.orange} onBlur={e => e.target.style.borderColor=C.border}/>
            <button onClick={handleScan} style={{ fontFamily:"'Rajdhani',sans-serif", fontWeight:700, fontSize:"15px", letterSpacing:"0.1em", textTransform:"uppercase", color:C.white, background:C.orange, border:"none", padding:"11px 28px", borderRadius:"4px", cursor:"pointer", display:"flex", alignItems:"center", gap:"9px", boxShadow:`0 2px 10px ${C.orange}50`, transition:"all 0.15s" }}
              onMouseEnter={e => { e.currentTarget.style.background=C.accentHover; e.currentTarget.style.transform="translateY(-1px)"; }}
              onMouseLeave={e => { e.currentTarget.style.background=C.orange; e.currentTarget.style.transform="translateY(0)"; }}>
              <FaSearch style={{ fontSize:"12px" }}/> Scan
            </button>
          </div>
        </div>

        {error && <div style={{ maxWidth:"600px", marginBottom:"20px", padding:"12px 16px", background:C.redBg, border:`1px solid ${C.redBorder}`, borderLeft:`4px solid ${C.red}`, borderRadius:"0 4px 4px 0", fontFamily:"'DM Mono',monospace", fontSize:"12px", color:C.red }}>✕ {error}</div>}

        {/* Loader */}
        {isScanning && (
          <div ref={loaderRef} style={{ marginBottom:"36px" }}>
            <div style={{ background:C.white, border:`1px solid ${isPaused?C.amberBorder:C.orangeBorder}`, borderLeft:`4px solid ${isPaused?C.amber:C.orange}`, borderRadius:"0 8px 8px 0", padding:"24px 28px", maxWidth:"600px", boxShadow:"0 2px 8px rgba(0,0,0,0.06)" }}>
              <div style={{ display:"flex", alignItems:"center", gap:"14px", marginBottom:"16px" }}>
                <div style={{ width:"18px", height:"18px", border:`2px solid ${C.border}`, borderTop:`2px solid ${isPaused?C.amber:C.orange}`, borderRadius:"50%", animation:isPaused?"none":"spin 0.8s linear infinite", flexShrink:0 }}/>
                <span style={{ fontFamily:"'Rajdhani',sans-serif", fontWeight:700, fontSize:"18px", letterSpacing:"0.04em", textTransform:"uppercase", color:isPaused?C.amber:C.orange }}>{isPaused?"SCAN PAUSED":"RUNNING DEEP SCAN"}</span>
              </div>
              <p style={{ fontFamily:"'DM Mono',monospace", fontSize:"12px", color:C.textMuted, marginBottom:"14px" }}>{isPaused?"Scan is paused — press Resume to continue":"This may take several minutes"}</p>
              {["Enumerating subdomains & infrastructure…","Running OSINT correlation…","Testing for SQL injection vectors…","Scanning XSS attack surfaces…","Checking CSRF, clickjacking, command injection…","Generating vulnerability report…"].map((line,i) => (
                <div key={i} style={{ fontFamily:"'DM Mono',monospace", fontSize:"12px", color:isPaused?C.textXMuted:C.textMuted, lineHeight:2, animation:isPaused?"none":`shimmer 2.5s ease ${i*0.4}s infinite` }}>› {line}</div>
              ))}
              <div style={{ display:"flex", gap:"10px", marginTop:"20px" }}>
                {!isPaused ? (
                  <button onClick={() => setIsPaused(true)} style={{ fontFamily:"'Rajdhani',sans-serif", fontWeight:700, fontSize:"13px", letterSpacing:"0.08em", textTransform:"uppercase", color:C.amber, background:C.amberBg, border:`1px solid ${C.amberBorder}`, padding:"8px 20px", borderRadius:"4px", cursor:"pointer" }}>⏸ Pause</button>
                ) : (
                  <button onClick={() => setIsPaused(false)} style={{ fontFamily:"'Rajdhani',sans-serif", fontWeight:700, fontSize:"13px", letterSpacing:"0.08em", textTransform:"uppercase", color:C.green, background:C.greenBg, border:`1px solid ${C.greenBorder}`, padding:"8px 20px", borderRadius:"4px", cursor:"pointer", animation:"pauseBlink 1.5s ease infinite" }}>▶ Resume</button>
                )}
              </div>
            </div>
          </div>
        )}

        {/* RESULTS */}
        {scanDone && !isScanning && scanResult && (
          <div style={{ animation:"fadeUp 0.5s ease both", paddingBottom:"100px" }}>

            <div style={{ background:C.greenBg, border:`1px solid ${C.greenBorder}`, borderLeft:`4px solid ${C.green}`, borderRadius:"0 8px 8px 0", padding:"20px 28px", marginBottom:"28px" }}>
              <div style={{ fontFamily:"'DM Mono',monospace", fontSize:"10px", color:C.green, letterSpacing:"0.1em", marginBottom:"6px" }}>// scan_complete</div>
              <h2 style={{ fontFamily:"'Rajdhani',sans-serif", fontWeight:700, fontSize:"28px", letterSpacing:"0.04em", textTransform:"uppercase", color:C.green }}>FULL SCAN COMPLETED</h2>
              <p style={{ fontFamily:"'DM Sans',sans-serif", fontSize:"14px", color:C.textMuted, marginTop:"6px" }}>Complete breakdown of vulnerabilities and exposed assets below.</p>
            </div>

            {/* Meta */}
            <div style={{ background:C.white, border:`1px solid ${C.border}`, borderRadius:"6px", padding:"16px 20px", marginBottom:"20px", fontFamily:"'DM Mono',monospace", fontSize:"12px", lineHeight:2 }}>
              {[
                { label:"TARGET",    val:scanResult?.target||input,               color:C.blue },
                { label:"STARTED",   val:scanResult?.meta?.startedAt   ? new Date(scanResult.meta.startedAt).toLocaleString()   : "—", color:C.amber },
                { label:"COMPLETED", val:scanResult?.meta?.completedAt ? new Date(scanResult.meta.completedAt).toLocaleString() : "—", color:C.amber },
                { label:"DURATION",  val:(scanResult?.meta?.startedAt&&scanResult?.meta?.completedAt)?`${Math.max(0,(new Date(scanResult.meta.completedAt)-new Date(scanResult.meta.startedAt))/1000).toFixed(0)}s`:"—", color:C.green },
              ].map((m,i) => (
                <div key={i} style={{ color:C.textMuted }}>
                  › <span style={{ color:C.textSecondary }}>{m.label}:</span> <span style={{ color:m.color }}>{m.val}</span>
                </div>
              ))}
            </div>

            {/* Risk counters */}
            {(() => {
              const v = scanResult?.vulnerabilities||{};
              const counts = { critical:0, high:0, medium:0, low:0 };
              [
                { found:!!v.sqlInjection?.found,      level:"critical" },
                { found:!!v.commandInjection?.found,  level:"critical" },
                { found:!!v.domXss?.found,            level:"high" },
                { found:!!v.storedXss?.found,         level:"high" },
                { found:!!v.reflectedXss?.found,      level:"high" },
                { found:!!v.openRedirect?.found,      level:"high" },
                { found:!!v.cors?.found,              level:"high" },
                { found:!!v.wordpress?.found,         level:"high" },
                { found:!!v.csrf?.found,              level:"medium" },
                { found:!!v.clickjacking?.vulnerable, level:"medium" },
                { found:!!v.sensitiveFiles?.found,    level:"low" },
              ].forEach(m => { if(m.found) counts[m.level]++; });
              return (
                <div style={{ display:"flex", gap:"10px", flexWrap:"wrap", marginBottom:"32px" }}>
                  {[
                    { label:"Critical", val:counts.critical, color:C.red,    bg:C.redBg,    border:C.redBorder },
                    { label:"High",     val:counts.high,     color:C.orange, bg:C.orangeBg, border:C.orangeBorder },
                    { label:"Medium",   val:counts.medium,   color:C.amber,  bg:C.amberBg,  border:C.amberBorder },
                    { label:"Low",      val:counts.low,      color:C.green,  bg:C.greenBg,  border:C.greenBorder },
                  ].map((s,i) => (
                    <div key={i} style={{ flex:"1 1 110px", background:s.bg, border:`1px solid ${s.border}`, borderTop:`3px solid ${s.color}`, borderRadius:"0 0 6px 6px", padding:"14px 18px" }}>
                      <div style={{ fontFamily:"'DM Mono',monospace", fontSize:"10px", color:C.textMuted, textTransform:"uppercase", letterSpacing:"0.06em", marginBottom:"6px" }}>{s.label}</div>
                      <div style={{ fontFamily:"'Rajdhani',sans-serif", fontWeight:700, fontSize:"32px", color:s.color, lineHeight:1 }}>{s.val}</div>
                    </div>
                  ))}
                </div>
              );
            })()}

            <QuickScanResults data={scanResult} />

            <div style={{ fontFamily:"'DM Mono',monospace", fontSize:"11px", color:C.textXMuted, letterSpacing:"0.08em", marginBottom:"16px", marginTop:"36px" }}>
              // vulnerability_assessment_results
            </div>

            {(() => {
              const v = scanResult?.vulnerabilities||{};
              return (
                <div>

                  {/* ── SQL INJECTION ── */}
                  <ModuleBlock keyName="sql" title="SQL Injection" found={!!v.sqlInjection?.found} expanded={expanded.sql} onToggle={toggle}>
                    {v.sqlInjection?.details ? (() => {
                      const d = v.sqlInjection.details;
                        console.log("SQLi details:", JSON.stringify(d, null, 2)); // ADD THIS

                      // Backend: details = { findings: [{ url, param, databases[] }] }
                      const findings = Array.isArray(d.findings) ? d.findings : [];
                      const isFlatResult = !!(d.url || d.param);
                      return (
                        <div>
                          <KV label="ENDPOINTS_SCANNED" value={d.scanned||d.testedEndpoints||d.totalTested} valueColor={C.blue} />
                          <KV label="TOTAL_ENDPOINTS"   value={d.total}        valueColor={C.textSecondary} />
                          <KV label="CONFIDENCE"        value={d.confidence}   valueColor={C.amber} />
                          <KV label="TOOL_USED"         value={d.tool}         valueColor={C.textMuted} />

                          {/* Flat single-result from backend */}
                          {isFlatResult && (
                            <>
                              <SubHead>Injection Point</SubHead>
                              <div style={{ padding:"12px 14px", background:C.redBg, border:`1px solid ${C.redBorder}`, borderLeft:`3px solid ${C.red}`, borderRadius:"0 6px 6px 0" }}>
                                <KV label="URL"        value={d.url}    valueColor={C.blue} />
                                <KV label="PARAMETER"  value={d.param}  valueColor={C.amber} />
                                <KV label="METHOD"     value={d.method} valueColor={C.textSecondary} />
                                <KV label="PAYLOAD"    value={d.payload} valueColor={C.red} />
                                <KV label="TYPE"       value={d.type}   valueColor={C.orange} />
                                <KV label="DB_VERSION" value={d.dbVersion} valueColor={C.textMuted} />
                                <KV label="EVIDENCE"   value={d.evidence}  valueColor={C.textMuted} />
                                {Array.isArray(d.databases) && d.databases.length > 0 && (
                                  <>
                                    <SubHead>Databases Extracted ({d.databases.length})</SubHead>
                                    <div style={{ display:"flex", flexWrap:"wrap", gap:"6px", paddingTop:"4px" }}>
                                      {d.databases.map((db, i) => (
                                        <span key={i} style={{ fontFamily:"'DM Mono',monospace", fontSize:"12px", fontWeight:500, color:C.green, background:C.greenBg, border:`1px solid ${C.greenBorder}`, padding:"4px 12px", borderRadius:"4px" }}>{db}</span>
                                      ))}
                                    </div>
                                  </>
                                )}
                                {Array.isArray(d.tables) && d.tables.length > 0 && (
                                  <>
                                    <SubHead>Tables Extracted ({d.tables.length})</SubHead>
                                    <div style={{ display:"flex", flexWrap:"wrap", gap:"6px", paddingTop:"4px" }}>
                                      {d.tables.map((t, i) => (
                                        <span key={i} style={{ fontFamily:"'DM Mono',monospace", fontSize:"12px", color:C.blue, background:C.blueBg, border:`1px solid ${C.blueBorder}`, padding:"4px 12px", borderRadius:"4px" }}>{t}</span>
                                      ))}
                                    </div>
                                  </>
                                )}
                                <AutoKV obj={d} skipKeys={["url","param","method","payload","type","databases","tables","dbVersion","confidence","evidence","tool","scanned","total","testedEndpoints","totalTested","findings","vulnerable"]} />
                              </div>
                            </>
                          )}

                          {/* Array of findings (alternative backend shape) */}
                          {findings.length > 0 && (
                            <>
                              <SubHead>Injection Points ({findings.length})</SubHead>
                              {findings.map((f,i) => (
                                <div key={i} style={{ marginBottom:"14px", padding:"12px 14px", background:C.redBg, border:`1px solid ${C.redBorder}`, borderLeft:`3px solid ${C.red}`, borderRadius:"0 6px 6px 0" }}>
                                      { console.log("finding:", JSON.stringify(f)) }

                                  <KV label="URL"        value={f.url}       valueColor={C.blue} />
                                  <KV label="PARAMETER"  value={f.param}     valueColor={C.amber} />
                                  <KV label="METHOD"     value={f.method}    valueColor={C.textSecondary} />
                                  <KV label="PAYLOAD"    value={f.payload}   valueColor={C.red} />
                                  <KV label="TYPE"       value={f.type}      valueColor={C.orange} />
                                  <KV label="DB_VERSION" value={f.dbVersion} valueColor={C.textMuted} />
                                  <KV label="CONFIDENCE" value={f.confidence} valueColor={C.amber} />
                                  <KV label="EVIDENCE"   value={f.evidence}  valueColor={C.textMuted} />
                                  {Array.isArray(f.databases) && f.databases.length > 0 && (
                                    <>
                                      <SubHead>Databases ({f.databases.length})</SubHead>
                                      <div style={{ display:"flex", flexWrap:"wrap", gap:"6px", paddingTop:"4px" }}>
                                        {f.databases.map((db,j) => <span key={j} style={{ fontFamily:"'DM Mono',monospace", fontSize:"12px", color:C.green, background:C.greenBg, border:`1px solid ${C.greenBorder}`, padding:"4px 12px", borderRadius:"4px" }}>{db}</span>)}
                                      </div>
                                    </>
                                  )}
                                  {Array.isArray(f.tables) && f.tables.length > 0 && (
                                    <>
                                      <SubHead>Tables ({f.tables.length})</SubHead>
                                      <div style={{ display:"flex", flexWrap:"wrap", gap:"6px", paddingTop:"4px" }}>
                                        {f.tables.map((t,j) => <span key={j} style={{ fontFamily:"'DM Mono',monospace", fontSize:"12px", color:C.blue, background:C.blueBg, border:`1px solid ${C.blueBorder}`, padding:"4px 12px", borderRadius:"4px" }}>{t}</span>)}
                                      </div>
                                    </>
                                  )}
                                  <AutoKV obj={f} skipKeys={["url","param","method","payload","type","databases","tables","dbVersion","confidence","evidence"]} />
                                </div>
                              ))}
                            </>
                          )}
                        </div>
                      );
                    })() : <Mono color={C.textMuted}>No vulnerability detected.</Mono>}
                  </ModuleBlock>

                  {/* ── DOM XSS ── */}
                  <ModuleBlock keyName="dom" title="DOM XSS" found={!!v.domXss?.found} expanded={expanded.dom} onToggle={toggle}>
                    {v.domXss?.details ? (() => {
                      const d = v.domXss.details;
                      const evidence = Array.isArray(d.evidence) ? d.evidence : [];
                      const high = evidence.filter(f => ["high","medium"].includes((f.confidence||"").toLowerCase()));
                      const low  = evidence.filter(f => !["high","medium"].includes((f.confidence||"").toLowerCase()));
                      return (
                        <div>
                          <KV label="TOTAL_FINDINGS"  value={evidence.length}   valueColor={C.blue} />
                          <KV label="HIGH_CONFIDENCE" value={high.length}       valueColor={high.length>0?C.red:C.textMuted} />
                          <KV label="LOW_CONFIDENCE"  value={low.length}        valueColor={C.textMuted} />
                          <KV label="PAGES_SCANNED"   value={d.pagesScanned}    valueColor={C.textSecondary} />
                          <KV label="TOOL"            value={d.tool}            valueColor={C.textMuted} />
                          <AutoKV obj={d} skipKeys={["evidence","pagesScanned","tool"]} />
                          {high.length > 0 && (
                            <>
                              <SubHead>High / Medium Confidence ({high.length})</SubHead>
                              {high.map((f,i) => (
                                <div key={i} style={{ marginBottom:"12px", padding:"12px 14px", background:C.orangeBg, border:`1px solid ${C.orangeBorder}`, borderLeft:`3px solid ${C.orange}`, borderRadius:"0 6px 6px 0" }}>
                                  <KV label="TYPE"       value={f.type}       valueColor={C.amber} />
                                  <KV label="LOCATION"   value={f.location}   valueColor={C.blue} />
                                  <KV label="SINK"       value={f.sink}       valueColor={C.orange} />
                                  <KV label="SOURCE"     value={f.source}     valueColor={C.textSecondary} />
                                  <KV label="CONFIDENCE" value={f.confidence} valueColor={C.amber} />
                                  <KV label="URL"        value={f.url}        valueColor={C.blue} />
                                  <KV label="PAYLOAD"    value={f.payload}    valueColor={C.red} />
                                  <KV label="LINE"       value={f.line}       valueColor={C.textMuted} />
                                  <AutoKV obj={f} skipKeys={["type","location","sink","source","confidence","url","payload","line"]} />
                                </div>
                              ))}
                            </>
                          )}
                          {low.length > 0 && (
                            <>
                              <SubHead>Low Confidence ({low.length})</SubHead>
                              {low.map((f,i) => (
                                <div key={i} style={{ marginBottom:"8px", padding:"10px 12px", background:C.bg, border:`1px solid ${C.border}`, borderRadius:"4px" }}>
                                  <KV label="TYPE"       value={f.type}       valueColor={C.textSecondary} />
                                  <KV label="LOCATION"   value={f.location}   valueColor={C.blue} />
                                  <KV label="CONFIDENCE" value={f.confidence} valueColor={C.textMuted} />
                                  <AutoKV obj={f} skipKeys={["type","location","confidence"]} />
                                </div>
                              ))}
                            </>
                          )}
                          <button onClick={() => setShowRawDomFindings(s=>!s)} style={{ marginTop:"10px", fontFamily:"'DM Mono',monospace", fontSize:"11px", color:C.blue, background:"none", border:"none", cursor:"pointer" }}>
                            {showRawDomFindings?"▲ Hide raw findings JSON":"▼ Show raw findings JSON"}
                          </button>
                          {showRawDomFindings && <pre style={{ marginTop:"10px", maxHeight:"200px", overflowY:"auto", background:C.bg, padding:"12px", borderRadius:"4px", border:`1px solid ${C.border}` }}>{JSON.stringify(evidence, null, 2)}</pre>}
                        </div>
                      );
                    })() : <Mono color={C.textMuted}>No vulnerability detected.</Mono>}
                  </ModuleBlock>

                  {/* ── STORED XSS ── */}
                  <ModuleBlock keyName="stored" title="Stored XSS" found={!!v.storedXss?.found} expanded={expanded.stored} onToggle={toggle}>
                    {v.storedXss?.details ? (() => {
                      const d = v.storedXss.details;
                      const evidence = Array.isArray(d.evidence) ? d.evidence : [];
                      return (
                        <div>
                          <KV label="ENDPOINTS_TESTED" value={d.endpointsTested||d.totalTested} valueColor={C.blue} />
                          <KV label="INPUTS_TESTED"    value={d.inputsTested}                   valueColor={C.blue} />
                          <KV label="VULNERABLE_COUNT" value={d.vulnerableCount||evidence.length} valueColor={evidence.length>0?C.red:C.textMuted} />
                          <KV label="NOTES"            value={d.notes}                          valueColor={C.textMuted} mono={false} />
                          <AutoKV obj={d} skipKeys={["evidence","endpointsTested","totalTested","inputsTested","vulnerableCount","notes"]} />
                          {evidence.length > 0 && (
                            <>
                              <SubHead>Evidence ({evidence.length})</SubHead>
                              {evidence.map((f,i) => (
                                <div key={i} style={{ marginBottom:"12px", padding:"12px 14px", background:C.redBg, border:`1px solid ${C.redBorder}`, borderLeft:`3px solid ${C.red}`, borderRadius:"0 6px 6px 0" }}>
                                  <KV label="LOCATION"     value={f.location}    valueColor={C.blue} />
                                  <KV label="PAYLOAD"      value={f.payload}     valueColor={C.red} />
                                  <KV label="CONFIDENCE"   value={f.confidence}  valueColor={C.amber} />
                                  <KV label="FORM_ACTION"  value={f.formAction}  valueColor={C.textSecondary} />
                                  <KV label="STORED_AT"    value={f.storedAt}    valueColor={C.textMuted} />
                                  <KV label="REFLECTED_AT" value={f.reflectedAt} valueColor={C.textMuted} />
                                  <KV label="INPUT_FIELD"  value={f.inputField}  valueColor={C.textSecondary} />
                                  <AutoKV obj={f} skipKeys={["location","payload","confidence","formAction","storedAt","reflectedAt","inputField"]} />
                                </div>
                              ))}
                            </>
                          )}
                        </div>
                      );
                    })() : <Mono color={C.textMuted}>No vulnerability detected.</Mono>}
                  </ModuleBlock>

                  {/* ── REFLECTED XSS ── */}
                  <ModuleBlock keyName="reflected" title="Reflected XSS" found={!!v.reflectedXss?.found} expanded={expanded.reflected} onToggle={toggle}>
                    {v.reflectedXss?.details ? (() => {
                      const d = v.reflectedXss.details;
                      const vulnEps = Array.isArray(d.vulnerableEndpoints) ? d.vulnerableEndpoints : [];
                      return (
                        <div>
                          <KV label="ENDPOINTS_TESTED"     value={d.testedEndpoints}       valueColor={C.blue} />
                          <KV label="VULNERABLE_ENDPOINTS" value={vulnEps.length||d.vulnerableCount} valueColor={vulnEps.length>0?C.red:C.textMuted} />
                          <KV label="PAYLOADS_TESTED"      value={d.payloadsTested}         valueColor={C.textSecondary} />
                          <KV label="TOOL"                 value={d.tool}                   valueColor={C.textMuted} />
                          <AutoKV obj={d} skipKeys={["vulnerableEndpoints","testedEndpoints","vulnerableCount","payloadsTested","tool"]} />
                          {vulnEps.length > 0 && (
                            <>
                              <SubHead>Vulnerable Endpoints ({vulnEps.length})</SubHead>
                              {vulnEps.map((ep,i) => (
                                <div key={i} style={{ marginBottom:"12px", padding:"12px 14px", background:C.redBg, border:`1px solid ${C.redBorder}`, borderLeft:`3px solid ${C.red}`, borderRadius:"0 6px 6px 0" }}>
                                  <KV label="URL"        value={typeof ep==="string"?ep:ep.url}  valueColor={C.blue} />
                                  <KV label="PARAMETER"  value={ep.param||ep.parameter}          valueColor={C.amber} />
                                  <KV label="PAYLOAD"    value={ep.payload}                      valueColor={C.red} />
                                  <KV label="METHOD"     value={ep.method}                       valueColor={C.textSecondary} />
                                  <KV label="CONTEXT"    value={ep.context}                      valueColor={C.textMuted} />
                                  <KV label="CONFIDENCE" value={ep.confidence}                   valueColor={C.amber} />
                                  <KV label="EVIDENCE"   value={ep.evidence}                     valueColor={C.textMuted} />
                                  {typeof ep==="object" && <AutoKV obj={ep} skipKeys={["url","param","parameter","payload","method","context","confidence","evidence"]} />}
                                </div>
                              ))}
                            </>
                          )}
                        </div>
                      );
                    })() : <Mono color={C.textMuted}>No vulnerability detected.</Mono>}
                  </ModuleBlock>

                  {/* ── CLICKJACKING ── */}
                  <ModuleBlock keyName="click" title="Clickjacking" found={!!v.clickjacking?.vulnerable} expanded={expanded.click} onToggle={toggle}>
                    {v.clickjacking ? (() => {
                      const d = v.clickjacking.details || v.clickjacking;
                      return (
                        <div>
                          <KV label="VULNERABLE"          value={String(v.clickjacking.vulnerable)} valueColor={v.clickjacking.vulnerable?C.red:C.green} />
                          <KV label="X_FRAME_OPTIONS"     value={d.xFrameOptions||d.xfo}            valueColor={(!d.xFrameOptions&&!d.xfo)?C.red:C.green} />
                          <KV label="CSP_FRAME_ANCESTORS" value={d.cspFrameAncestors||d.frameAncestors} valueColor={(!d.cspFrameAncestors&&!d.frameAncestors)?C.red:C.green} />
                          <KV label="ISSUE"               value={d.issue}                           valueColor={C.orange} mono={false} />
                          <KV label="RECOMMENDATION"      value={d.recommendation||d.fix}           valueColor={C.textMuted} mono={false} />
                          <AutoKV obj={d} skipKeys={["xFrameOptions","xfo","cspFrameAncestors","frameAncestors","issue","recommendation","fix"]} />
                        </div>
                      );
                    })() : <Mono color={C.textMuted}>No vulnerability detected.</Mono>}
                  </ModuleBlock>

                  {/* ── COMMAND INJECTION ── */}
                  <ModuleBlock keyName="cmd" title="Command Injection" found={!!v.commandInjection?.found} expanded={expanded.cmd} onToggle={toggle}>
                    {v.commandInjection?.found && v.commandInjection?.details ? (() => {
                      const d = v.commandInjection.details;
                      const evidence = Array.isArray(d.evidence) ? d.evidence : [];
                      return (
                        <div>
                          <KV label="CONFIDENCE"       value={d.confidence}                valueColor={C.amber} />
                          <KV label="ENDPOINTS_TESTED" value={d.tested}                    valueColor={C.blue} />
                          <KV label="VULNERABLE_COUNT" value={d.vulnerable||evidence.length} valueColor={C.red} />
                          <AutoKV obj={d} skipKeys={["evidence","confidence","tested","vulnerable"]} />
                          {evidence.length > 0 && (
                            <>
                              <SubHead>Evidence ({evidence.length})</SubHead>
                              {evidence.map((f,i) => (
                                <div key={i} style={{ marginBottom:"12px", padding:"12px 14px", background:C.redBg, border:`1px solid ${C.redBorder}`, borderLeft:`3px solid ${C.red}`, borderRadius:"0 6px 6px 0" }}>
                                  <KV label="URL"        value={f.url}        valueColor={C.blue} />
                                  <KV label="PARAMETER"  value={f.param}      valueColor={C.amber} />
                                  <KV label="PAYLOAD"    value={f.payload}    valueColor={C.red} />
                                  <KV label="OUTPUT"     value={f.output}     valueColor={C.textSecondary} />
                                  <KV label="CONFIDENCE" value={f.confidence} valueColor={C.amber} />
                                  <AutoKV obj={f} skipKeys={["url","param","payload","output","confidence"]} />
                                </div>
                              ))}
                            </>
                          )}
                        </div>
                      );
                    })() : <Mono color={C.textMuted}>No vulnerability detected.</Mono>}
                  </ModuleBlock>

                  {/* ── CSRF ── */}
                  <ModuleBlock keyName="csrf" title="CSRF — Cross-Site Request Forgery" found={!!v.csrf?.found} expanded={expanded.csrf} onToggle={toggle}>
                    {v.csrf?.found && v.csrf?.details ? (() => {
                      const d    = v.csrf.details;
                      // Backend shape: { module, target, summary: { totalEndpoints, vulnerable, safe }, vulnerableEndpoints[], safeEndpoints[] }
                      const sum  = d.summary || {};
                      const vulnEps = Array.isArray(d.vulnerableEndpoints) ? d.vulnerableEndpoints : [];
                      const safeEps = Array.isArray(d.safeEndpoints)       ? d.safeEndpoints       : [];
                      return (
                        <div>
                          <KV label="TARGET"           value={d.target}            valueColor={C.blue} />
                          <KV label="TOTAL_ENDPOINTS"  value={sum.totalEndpoints}  valueColor={C.blue} />
                          <KV label="VULNERABLE"       value={sum.vulnerable}      valueColor={sum.vulnerable>0?C.red:C.textMuted} />
                          <KV label="SAFE"             value={sum.safe}            valueColor={C.green} />

                          {vulnEps.length > 0 && (
                            <>
                              <SubHead>Vulnerable Endpoints ({vulnEps.length})</SubHead>
                              {vulnEps.map((ep,i) => (
                                <div key={i} style={{ marginBottom:"10px", padding:"12px 14px", background:C.redBg, border:`1px solid ${C.redBorder}`, borderLeft:`3px solid ${C.red}`, borderRadius:"0 6px 6px 0" }}>
                                  <KV label="URL"          value={ep.url||ep.action}      valueColor={C.blue} />
                                  <KV label="METHOD"       value={ep.method}              valueColor={C.textSecondary} />
                                  <KV label="FORM_ACTION"  value={ep.formAction}          valueColor={C.textMuted} />
                                  <KV label="ISSUE"        value={ep.issue||ep.reason||ep.vulnerability} valueColor={C.orange} mono={false} />
                                  <KV label="TOKEN_PRESENT" value={ep.hasToken!=null?(ep.hasToken?"YES":"NO"):undefined} valueColor={ep.hasToken?C.green:C.red} />
                                  <KV label="TOKEN_VALUE"  value={ep.token||ep.csrfToken} valueColor={ep.token?C.green:C.red} />
                                  <KV label="FIELDS"       value={Array.isArray(ep.fields)?ep.fields.join(", "):ep.fields} valueColor={C.textSecondary} />
                                  <KV label="ENCTYPE"      value={ep.enctype}             valueColor={C.textMuted} />
                                  <AutoKV obj={ep} skipKeys={["url","action","method","formAction","issue","reason","vulnerability","hasToken","token","csrfToken","fields","enctype"]} />
                                </div>
                              ))}
                            </>
                          )}

                          {safeEps.length > 0 && (
                            <>
                              <SubHead>Safe Endpoints ({safeEps.length})</SubHead>
                              <div style={{ display:"flex", flexDirection:"column", gap:"6px" }}>
                                {safeEps.map((ep,i) => (
                                  <div key={i} style={{ padding:"8px 14px", background:C.greenBg, border:`1px solid ${C.greenBorder}`, borderLeft:`3px solid ${C.green}`, borderRadius:"0 6px 6px 0", display:"flex", alignItems:"center", gap:"10px", flexWrap:"wrap" }}>
                                    <span style={{ fontFamily:"'DM Mono',monospace", fontSize:"12px", color:C.blue, wordBreak:"break-all" }}>{ep.url||ep.action||String(ep)}</span>
                                    {ep.method && <span style={{ fontFamily:"'DM Mono',monospace", fontSize:"10px", color:C.textMuted }}>{ep.method}</span>}
                                    {(ep.hasToken||ep.token) && <span style={{ fontFamily:"'DM Mono',monospace", fontSize:"10px", color:C.green }}>✓ token present</span>}
                                  </div>
                                ))}
                              </div>
                            </>
                          )}
                        </div>
                      );
                    })() : <Mono color={C.textMuted}>No vulnerability detected.</Mono>}
                  </ModuleBlock>

                  {/* ── SENSITIVE FILES ── */}
                  <ModuleBlock keyName="sensitive" title="Sensitive File Exposure" found={!!v.sensitiveFiles?.found} expanded={expanded.sensitive} onToggle={toggle}>
                    {v.sensitiveFiles?.details ? (() => {
                      const d     = v.sensitiveFiles.details;
                      const sum   = d.summary || {};
                      const files = Array.isArray(d.exposedFiles) ? d.exposedFiles : [];
                      return (
                        <div>
                          <KV label="TOTAL_EXPOSED" value={sum.total||files.length} valueColor={files.length>0?C.red:C.textMuted} />
                          <KV label="CRITICAL"      value={sum.critical}            valueColor={sum.critical>0?C.red:C.textMuted} />
                          <KV label="HIGH"          value={sum.high}                valueColor={sum.high>0?C.orange:C.textMuted} />
                          <KV label="MEDIUM"        value={sum.medium}              valueColor={sum.medium>0?C.amber:C.textMuted} />
                          <KV label="LOW"           value={sum.low}                 valueColor={sum.low>0?C.green:C.textMuted} />
                          <KV label="PATHS_CHECKED" value={d.pathsChecked}          valueColor={C.textSecondary} />
                          {files.length > 0 && (
                            <>
                              <SubHead>Exposed Files ({files.length})</SubHead>
                              {files.map((f,i) => (
                                <div key={i} style={{ marginBottom:"10px", padding:"10px 14px", background:riskBg(f.severity), border:`1px solid ${riskBorder(f.severity)}`, borderLeft:`3px solid ${riskAccent(f.severity)}`, borderRadius:"0 6px 6px 0" }}>
                                  <div style={{ display:"flex", alignItems:"center", gap:"8px", marginBottom:"6px" }}>
                                    <RiskChip level={f.severity} />
                                    <span style={{ fontFamily:"'DM Mono',monospace", fontSize:"12px", color:C.blue, wordBreak:"break-all" }}>{f.path||f.url}</span>
                                  </div>
                                  <KV label="STATUS_CODE"  value={f.statusCode||f.status} valueColor={C.textSecondary} />
                                  <KV label="CONTENT_TYPE" value={f.contentType}           valueColor={C.textMuted} />
                                  <KV label="SIZE"         value={f.size}                  valueColor={C.textMuted} />
                                  <KV label="DESCRIPTION"  value={f.description}           valueColor={C.textMuted} mono={false} />
                                  <KV label="SNIPPET"      value={f.snippet}               valueColor={C.orange} />
                                  <AutoKV obj={f} skipKeys={["path","url","severity","statusCode","status","contentType","size","description","snippet"]} />
                                </div>
                              ))}
                            </>
                          )}
                        </div>
                      );
                    })() : <Mono color={C.textMuted}>No sensitive files detected.</Mono>}
                  </ModuleBlock>

                  {/* ── OPEN REDIRECT ── */}
                  <ModuleBlock keyName="openRedirect" title="Open Redirect" found={!!v.openRedirect?.found} expanded={expanded.openRedirect} onToggle={toggle}>
                    {v.openRedirect?.details ? (() => {
                      const d = v.openRedirect.details;
                      const evidence = Array.isArray(d.evidence) ? d.evidence : [];
                      return (
                        <div>
                          <KV label="TESTED_PARAMS" value={d.testedParams||d.totalTested} valueColor={C.blue} />
                          <KV label="VULNERABLE"    value={evidence.length||d.vulnerable}  valueColor={evidence.length>0?C.red:C.textMuted} />
                          <KV label="TOOL"          value={d.tool}                         valueColor={C.textMuted} />
                          <AutoKV obj={d} skipKeys={["evidence","testedParams","totalTested","vulnerable","tool"]} />
                          {evidence.length > 0 && (
                            <>
                              <SubHead>Evidence ({evidence.length})</SubHead>
                              {evidence.map((e,i) => (
                                <div key={i} style={{ marginBottom:"12px", padding:"12px 14px", background:C.orangeBg, border:`1px solid ${C.orangeBorder}`, borderLeft:`3px solid ${C.orange}`, borderRadius:"0 6px 6px 0" }}>
                                  <KV label="URL"          value={e.url}         valueColor={C.blue} />
                                  <KV label="PARAMETER"    value={e.parameter}   valueColor={C.amber} />
                                  <KV label="PAYLOAD"      value={e.payload}     valueColor={C.orange} />
                                  <KV label="REDIRECTS_TO" value={e.redirectsTo} valueColor={C.red} />
                                  <KV label="STATUS_CODE"  value={e.statusCode}  valueColor={C.textSecondary} />
                                  <KV label="METHOD"       value={e.method}      valueColor={C.textMuted} />
                                  <AutoKV obj={e} skipKeys={["url","parameter","payload","redirectsTo","statusCode","method"]} />
                                </div>
                              ))}
                            </>
                          )}
                        </div>
                      );
                    })() : <Mono color={C.textMuted}>No open redirect vulnerabilities detected.</Mono>}
                  </ModuleBlock>

                  {/* ── CORS ── */}
                  <ModuleBlock keyName="cors" title="CORS Misconfiguration" found={!!v.cors?.found} expanded={expanded.cors} onToggle={toggle}>
                    {v.cors?.details ? (() => {
                      const d = v.cors.details;
                      const evidence = Array.isArray(d.evidence) ? d.evidence : [];
                      return (
                        <div>
                          <KV label="ENDPOINTS_TESTED"  value={d.testedEndpoints||d.totalTested} valueColor={C.blue} />
                          <KV label="MISCONFIGURATIONS" value={evidence.length||d.misconfigCount} valueColor={evidence.length>0?C.red:C.textMuted} />
                          <KV label="WILDCARD_DETECTED" value={d.wildcardDetected?"YES":"NO"}     valueColor={d.wildcardDetected?C.red:C.green} />
                          <KV label="NULL_ORIGIN"       value={d.nullOriginAllowed?"YES":"NO"}    valueColor={d.nullOriginAllowed?C.red:C.green} />
                          <AutoKV obj={d} skipKeys={["evidence","testedEndpoints","totalTested","misconfigCount","wildcardDetected","nullOriginAllowed"]} />
                          {evidence.length > 0 && (
                            <>
                              <SubHead>Issues ({evidence.length})</SubHead>
                              {evidence.map((e,i) => (
                                <div key={i} style={{ marginBottom:"12px", padding:"12px 14px", background:riskBg(e.severity), border:`1px solid ${riskBorder(e.severity)}`, borderLeft:`3px solid ${riskAccent(e.severity)}`, borderRadius:"0 6px 6px 0" }}>
                                  <div style={{ display:"flex", alignItems:"center", gap:"8px", marginBottom:"6px" }}><RiskChip level={e.severity}/></div>
                                  <KV label="TYPE"        value={e.type}        valueColor={C.text} />
                                  <KV label="URL"         value={e.url}         valueColor={C.blue} />
                                  <KV label="ORIGIN_SENT" value={e.originSent}  valueColor={C.textSecondary} />
                                  <KV label="ACAO_HEADER" value={e.acaoHeader}  valueColor={e.acaoHeader==="*"?C.red:C.orange} />
                                  <KV label="ACAC_HEADER" value={e.acacHeader}  valueColor={C.textMuted} />
                                  <KV label="DESCRIPTION" value={e.description} valueColor={C.textMuted} mono={false} />
                                  <KV label="IMPACT"      value={e.impact}      valueColor={C.orange} mono={false} />
                                  <AutoKV obj={e} skipKeys={["type","url","severity","originSent","acaoHeader","acacHeader","description","impact"]} />
                                </div>
                              ))}
                            </>
                          )}
                        </div>
                      );
                    })() : <Mono color={C.textMuted}>No CORS misconfigurations detected.</Mono>}
                  </ModuleBlock>

                  {/* ── WORDPRESS ── */}
                  <ModuleBlock keyName="wordpress" title="WordPress Security" found={!!v.wordpress?.found} expanded={!!expanded.wordpress} onToggle={toggle}>
                    {v.wordpress?.found && v.wordpress?.details ? (() => {
                      const d       = v.wordpress.details;
                      const risk    = d.riskScore || {};
                      const vulns   = Array.isArray(d.vulnerabilities) ? d.vulnerabilities : [];
                      const plugins = Array.isArray(d.plugins) ? d.plugins : [];
                      const themes  = Array.isArray(d.themes)  ? d.themes  : [];
                      const users   = Array.isArray(d.users)   ? d.users   : [];
                      return (
                        <div>
                          {risk.score !== undefined && (
                            <div style={{ display:"flex", alignItems:"center", gap:"12px", marginBottom:"16px", padding:"12px 16px", background:riskBg(risk.level), border:`1px solid ${riskBorder(risk.level)}`, borderRadius:"6px" }}>
                              <div style={{ fontFamily:"'Rajdhani',sans-serif", fontWeight:700, fontSize:"36px", color:riskAccent(risk.level), lineHeight:1 }}>{risk.score}</div>
                              <div>
                                <div style={{ fontFamily:"'DM Mono',monospace", fontSize:"10px", color:C.textMuted, textTransform:"uppercase", letterSpacing:"0.06em" }}>Risk Score / 100</div>
                                <RiskChip level={risk.level} />
                              </div>
                            </div>
                          )}
                          <KV label="WP_VERSION"       value={d.version}                     valueColor={d.versionOutdated?C.red:C.blue} />
                          <KV label="VERSION_OUTDATED" value={d.versionOutdated?"YES":"NO"}   valueColor={d.versionOutdated?C.red:C.green} />
                          <KV label="THEME"            value={d.activeTheme||d.theme}         valueColor={C.textSecondary} />
                          <KV label="XMLRPC_ENABLED"   value={d.xmlrpc?"YES":"NO"}            valueColor={d.xmlrpc?C.red:C.green} />
                          <KV label="USER_ENUMERATION" value={d.userEnumeration?"YES":"NO"}   valueColor={d.userEnumeration?C.orange:C.green} />
                          <KV label="README_EXPOSED"   value={d.readmeExposed?"YES":"NO"}     valueColor={d.readmeExposed?C.amber:C.green} />
                          <KV label="DEBUG_LOG_EXPOSED" value={d.debugLogExposed?"YES":"NO"}  valueColor={d.debugLogExposed?C.red:C.green} />
                          <KV label="USERS_FOUND"      value={users.length}                   valueColor={users.length>0?C.orange:C.textMuted} />
                          <KV label="PLUGINS_FOUND"    value={plugins.length}                 valueColor={plugins.length>0?C.blue:C.textMuted} />
                          <KV label="THEMES_FOUND"     value={themes.length}                  valueColor={C.textMuted} />
                          <AutoKV obj={d} skipKeys={["riskScore","version","versionOutdated","activeTheme","theme","users","plugins","themes","vulnerabilities","xmlrpc","userEnumeration","readmeExposed","debugLogExposed"]} />
                          {users.length > 0 && (
                            <>
                              <SubHead>Enumerated Users ({users.length})</SubHead>
                              <div style={{ display:"flex", flexWrap:"wrap", gap:"4px" }}>
                                {users.map((u,i) => <Tag key={i} color={C.orange}>{typeof u==="object"?(u.login||u.name||JSON.stringify(u)):u}</Tag>)}
                              </div>
                            </>
                          )}
                          {plugins.length > 0 && (
                            <>
                              <SubHead>Plugins ({plugins.length})</SubHead>
                              {plugins.map((p,i) => (
                                <div key={i} style={{ marginBottom:"8px", padding:"10px 12px", background:p.vulnerable?C.redBg:C.bg, border:`1px solid ${p.vulnerable?C.redBorder:C.border}`, borderRadius:"4px" }}>
                                  <KV label="NAME"     value={p.name||p.slug} valueColor={C.blue} />
                                  <KV label="VERSION"  value={p.version}      valueColor={p.outdated?C.red:C.textSecondary} />
                                  <KV label="OUTDATED" value={p.outdated?"YES":"NO"} valueColor={p.outdated?C.red:C.green} />
                                  <KV label="CVES"     value={Array.isArray(p.cves)?p.cves.join(", "):p.cves} valueColor={C.red} />
                                  <AutoKV obj={p} skipKeys={["name","slug","version","outdated","cves","vulnerable"]} />
                                </div>
                              ))}
                            </>
                          )}
                          {themes.length > 0 && (
                            <>
                              <SubHead>Themes ({themes.length})</SubHead>
                              {themes.map((t,i) => (
                                <div key={i} style={{ marginBottom:"6px", padding:"8px 12px", background:C.bg, border:`1px solid ${C.border}`, borderRadius:"4px" }}>
                                  <KV label="NAME"    value={t.name||t.slug} valueColor={C.blue} />
                                  <KV label="VERSION" value={t.version}      valueColor={C.textSecondary} />
                                  <AutoKV obj={t} skipKeys={["name","slug","version"]} />
                                </div>
                              ))}
                            </>
                          )}
                          {vulns.length > 0 && (
                            <>
                              <SubHead>CVEs / Vulnerabilities ({vulns.length})</SubHead>
                              {vulns.map((vuln,i) => (
                                <div key={i} style={{ marginBottom:"12px", padding:"12px 14px", background:riskBg(vuln.severity), border:`1px solid ${riskBorder(vuln.severity)}`, borderLeft:`3px solid ${riskAccent(vuln.severity)}`, borderRadius:"0 6px 6px 0" }}>
                                  <div style={{ display:"flex", alignItems:"center", gap:"8px", marginBottom:"8px" }}>
                                    <RiskChip level={vuln.severity} />
                                    <span style={{ fontFamily:"'Syne',sans-serif", fontWeight:700, fontSize:"13px", color:C.text }}>{vuln.title||vuln.name}</span>
                                  </div>
                                  <KV label="CVE"         value={vuln.cve}         valueColor={C.red} />
                                  <KV label="CVSS"        value={vuln.cvss}        valueColor={C.orange} />
                                  <KV label="COMPONENT"   value={vuln.component}   valueColor={C.blue} />
                                  <KV label="FIXED_IN"    value={vuln.fixedIn}     valueColor={C.green} />
                                  <KV label="DESCRIPTION" value={vuln.description} valueColor={C.textMuted} mono={false} />
                                  <AutoKV obj={vuln} skipKeys={["title","name","severity","cve","cvss","component","fixedIn","description"]} />
                                </div>
                              ))}
                            </>
                          )}
                        </div>
                      );
                    })() : <Mono color={C.textMuted}>Target is not running WordPress or no issues detected.</Mono>}
                  </ModuleBlock>

                </div>
              );
            })()}

            {/* PDF */}
            <div style={{ textAlign:"center", paddingTop:"36px", paddingBottom:"16px" }}>
              <button onClick={downloadPDF} style={{ fontFamily:"'Rajdhani',sans-serif", fontWeight:700, fontSize:"15px", letterSpacing:"0.1em", textTransform:"uppercase", color:C.white, background:C.orange, border:"none", padding:"14px 32px", borderRadius:"4px", cursor:"pointer", display:"inline-flex", alignItems:"center", gap:"10px", boxShadow:`0 4px 16px ${C.orange}40`, transition:"all 0.2s" }}
                onMouseEnter={e => { e.currentTarget.style.transform="translateY(-2px)"; e.currentTarget.style.boxShadow=`0 8px 24px ${C.orange}50`; }}
                onMouseLeave={e => { e.currentTarget.style.transform="translateY(0)"; e.currentTarget.style.boxShadow=`0 4px 16px ${C.orange}40`; }}>
                <FaFileDownload /> Download Full PDF Report
              </button>
            </div>
          </div>
        )}
        <div style={{ height:"60px" }} />
      </div>
    </div>
  );
}
