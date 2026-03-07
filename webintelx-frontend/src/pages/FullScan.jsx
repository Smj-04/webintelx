import { useState, useRef } from "react";
import axios from "axios";
import {
  FaSearch, FaFingerprint, FaNetworkWired, FaBug,
  FaUserSecret, FaListUl, FaFileDownload, FaGlobe,
  FaServer, FaShieldAlt, FaLock, FaCode, FaExclamationTriangle,
  FaCheckCircle, FaTimesCircle, FaEnvelope, FaMapMarkerAlt,
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

const StatusBadge = ({ value, trueColor = "#00ff88", falseColor = "#ff6b35" }) => {
  const isGood = value === true || value === "YES" || value === "ENABLED" || value === "PRESENT";
  return (
    <span style={{
      fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", letterSpacing: "0.12em",
      padding: "3px 9px", border: `1px solid ${isGood ? trueColor : falseColor}40`,
      background: `${isGood ? trueColor : falseColor}12`,
      color: isGood ? trueColor : falseColor,
    }}>
      {isGood ? "✓" : "✕"} {String(value)}
    </span>
  );
};

const InfoRow = ({ label, value, valueColor = "#00d4ff", mono = true }) => (
  <div style={{ display: "flex", alignItems: "flex-start", gap: "12px", padding: "6px 0", borderBottom: "1px solid rgba(0,255,136,0.04)" }}>
    <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", color: "rgba(0,255,136,0.4)", letterSpacing: "0.12em", minWidth: "180px", flexShrink: 0 }}>{label}</span>
    <span style={{ fontFamily: mono ? "'Share Tech Mono', monospace" : "'Rajdhani', sans-serif", fontSize: mono ? "11px" : "14px", color: valueColor, letterSpacing: mono ? "0.05em" : "0", wordBreak: "break-all" }}>{value}</span>
  </div>
);

const SectionHeader = ({ icon, title, accent = "#00ff88", count }) => (
  <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: "16px", paddingBottom: "10px", borderBottom: `1px solid ${accent}20` }}>
    <span style={{ color: accent, fontSize: "14px", filter: `drop-shadow(0 0 6px ${accent})` }}>{icon}</span>
    <span style={{ fontFamily: "'Orbitron', monospace", fontWeight: 700, fontSize: "12px", color: "#e8ffe8", letterSpacing: "0.08em" }}>{title}</span>
    {count !== undefined && (
      <span style={{ marginLeft: "auto", fontFamily: "'Share Tech Mono', monospace", fontSize: "11px", color: accent, background: `${accent}15`, border: `1px solid ${accent}30`, padding: "2px 10px", letterSpacing: "0.1em" }}>
        {count}
      </span>
    )}
  </div>
);

const Panel = ({ children, accent = "rgba(0,255,136,0.12)", leftAccent = "#00ff88", style = {} }) => (
  <div style={{
    background: "rgba(0,0,0,0.55)", border: `1px solid ${accent}`,
    borderLeft: `3px solid ${leftAccent}`, padding: "24px", marginBottom: "14px",
    position: "relative", overflow: "hidden", ...style,
  }}>
    {children}
  </div>
);

const Tag = ({ children, color = "#00ff88" }) => (
  <span style={{
    fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", letterSpacing: "0.1em",
    color, background: `${color}12`, border: `1px solid ${color}30`,
    padding: "3px 10px", marginRight: "8px", marginBottom: "6px", display: "inline-block",
  }}>{children}</span>
);

// ─── FULL QUICKSCAN RESULTS DISPLAY ───────────────────────────────────────────
function QuickScanResults({ data }) {
  const qs = data?.quickscan || {};
  const [expandedSections, setExpandedSections] = useState({
    headers: true, tech: true, ports: true, osint: true,
  });
  const [showDebug, setShowDebug] = useState(false);
  const toggle = (key) => setExpandedSections(s => ({ ...s, [key]: !s[key] }));

  // ── flexible getters ──────────────────────────────────────────────────────
  const tech  = qs.technology || {};
  const ports = qs.ports || qs.portScan || {};
  const osint = qs.osint || qs.reputation || {};
  const hdrs  = qs.headers || qs.securityHeaders || qs.httpHeaders || {};

  // ── always-show: present even if empty/clean ─────────────────────────────
  const hasTech    = Object.keys(tech).length > 0;
  const hasPorts   = Object.keys(ports).length > 0;
  const hasHeaders = Object.keys(hdrs).length > 0;

  // ── conditional: only show if there's an actual finding ──────────────────
  const osintFindings = osint.virusTotal || osint.safeBrowsing || osint.blacklisted || osint.cves;
  const hasOsintAlert = !!(
    osint.virusTotal?.malicious > 0 ||
    osint.safeBrowsing?.safe === false ||
    osint.blacklisted === true ||
    osint.cves?.count > 0 ||
    osintFindings
  );
  const hasShodanAlert = !!(osint.cves?.count > 0);

  const hasAnyData = hasTech || hasPorts || hasHeaders || hasOsintAlert;

  const CollapseBtn = ({ section }) => (
    <button
      onClick={() => toggle(section)}
      style={{
        marginLeft: "auto", fontFamily: "'Share Tech Mono', monospace", fontSize: "10px",
        letterSpacing: "0.1em", color: "rgba(0,255,136,0.5)", background: "rgba(0,255,136,0.05)",
        border: "1px solid rgba(0,255,136,0.12)", padding: "4px 12px", cursor: "pointer",
        flexShrink: 0,
      }}
    >
      {expandedSections[section] ? "▲ HIDE" : "▼ SHOW"}
    </button>
  );

  // helper: render any unknown object as key/value rows
  const RenderObject = ({ obj, depth = 0 }) => {
    if (!obj || typeof obj !== "object") return <InfoRow label="VALUE" value={String(obj)} />;
    return Object.entries(obj).map(([k, v]) => {
      if (v === null || v === undefined) return null;
      if (Array.isArray(v)) {
        if (v.length === 0) return null;
        if (typeof v[0] !== "object") {
          return (
            <div key={k} style={{ padding: "6px 0", borderBottom: "1px solid rgba(0,255,136,0.04)" }}>
              <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", color: "rgba(0,255,136,0.4)", letterSpacing: "0.12em", marginBottom: "6px" }}>{k.toUpperCase()}</div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: "5px" }}>
                {v.map((item, i) => <Tag key={i} color="#00d4ff">{String(item)}</Tag>)}
              </div>
            </div>
          );
        }
        return (
          <div key={k} style={{ marginBottom: "10px" }}>
            <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", color: "rgba(0,255,136,0.4)", letterSpacing: "0.12em", marginBottom: "6px" }}>{k.toUpperCase()} ({v.length})</div>
            {v.slice(0, 10).map((item, i) => (
              <div key={i} style={{ paddingLeft: "12px", borderLeft: "2px solid rgba(0,255,136,0.15)", marginBottom: "6px" }}>
                <RenderObject obj={item} depth={depth + 1} />
              </div>
            ))}
          </div>
        );
      }
      if (typeof v === "object") {
        if (depth > 1) return <InfoRow key={k} label={k.toUpperCase()} value={JSON.stringify(v).substring(0, 80)} valueColor="rgba(180,255,180,0.5)" />;
        return (
          <div key={k} style={{ marginBottom: "8px" }}>
            <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", color: "rgba(0,255,136,0.4)", letterSpacing: "0.12em", marginBottom: "4px" }}>{k.toUpperCase()}</div>
            <div style={{ paddingLeft: "12px", borderLeft: "2px solid rgba(0,255,136,0.1)" }}>
              <RenderObject obj={v} depth={depth + 1} />
            </div>
          </div>
        );
      }
      const strVal = String(v);
      const isNeg = strVal === "false" || strVal === "NO" || strVal === "MISSING" || strVal === "0";
      const isPos = strVal === "true" || strVal === "YES" || strVal === "PRESENT";
      return <InfoRow key={k} label={k.toUpperCase().replace(/_/g, " ")} value={strVal}
        valueColor={isPos ? "#00ff88" : isNeg ? "#ff6b35" : "#00d4ff"} />;
    });
  };

  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "20px" }}>
        <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", letterSpacing: "0.3em", color: "rgba(0,255,136,0.38)" }}>
          // RECONNAISSANCE_INTELLIGENCE
        </div>
        {/* Debug toggle — helps identify backend key names */}
        <button
          onClick={() => setShowDebug(s => !s)}
          style={{
            fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", letterSpacing: "0.15em",
            color: showDebug ? "#fbbf24" : "rgba(251,191,36,0.3)",
            background: showDebug ? "rgba(251,191,36,0.08)" : "transparent",
            border: `1px solid ${showDebug ? "rgba(251,191,36,0.3)" : "rgba(251,191,36,0.1)"}`,
            padding: "4px 12px", cursor: "pointer", transition: "all 0.2s",
          }}
        >
          {showDebug ? "▲ HIDE RAW DATA" : "▼ DEBUG: SHOW RAW QUICKSCAN"}
        </button>
      </div>

      {/* ── DEBUG PANEL ── */}
      {showDebug && (
        <div style={{ marginBottom: "20px", background: "rgba(251,191,36,0.04)", border: "1px solid rgba(251,191,36,0.2)", borderLeft: "3px solid #fbbf24", padding: "16px" }}>
          <div style={{ fontFamily: "'Orbitron', monospace", fontSize: "11px", color: "#fbbf24", letterSpacing: "0.1em", marginBottom: "10px" }}>⚙ RAW QUICKSCAN KEYS — use this to verify backend data shape</div>
          <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", color: "rgba(0,255,136,0.5)", marginBottom: "8px" }}>
            Top-level keys in <span style={{ color: "#fbbf24" }}>scanResult.quickscan</span>: {Object.keys(qs).join(", ") || "(none — quickscan is empty or missing)"}
          </div>
          <pre style={{ maxHeight: "300px", overflowY: "auto", fontSize: "10px", color: "rgba(0,255,136,0.55)", background: "rgba(0,0,0,0.4)", padding: "12px", border: "1px solid rgba(0,255,136,0.08)" }}>
            {JSON.stringify(qs, null, 2)}
          </pre>
        </div>
      )}

      {/* ── NO DATA FALLBACK ── */}
      {!hasAnyData && (
        <Panel leftAccent="#fbbf24" accent="rgba(251,191,36,0.1)">
          <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "11px", color: "rgba(251,191,36,0.6)", lineHeight: 1.8 }}>
            <div style={{ marginBottom: "8px" }}>⚠ No reconnaissance data found in <span style={{ color: "#fbbf24" }}>scanResult.quickscan</span></div>
            <div>Enable the debug toggle above to inspect what your backend is returning.</div>
          </div>
        </Panel>
      )}

      {/* ── TECHNOLOGY FINGERPRINT ── */}
      {hasTech && (
        <Panel leftAccent="#fbbf24" accent="rgba(251,191,36,0.1)">
          <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: expandedSections.tech ? "20px" : 0 }}>
            <SectionHeader icon={<FaFingerprint />} title="TECHNOLOGY FINGERPRINT" accent="#fbbf24" />
            <CollapseBtn section="tech" />
          </div>
          {expandedSections.tech && (
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))", gap: "14px" }}>
              {/* Server / Backend block */}
              {(tech.server || tech.backend || tech.serverVersion || tech.os) && (
                <div style={{ background: "rgba(251,191,36,0.04)", border: "1px solid rgba(251,191,36,0.1)", padding: "16px" }}>
                  <div style={{ fontFamily: "'Orbitron', monospace", fontSize: "10px", color: "#fbbf24", letterSpacing: "0.12em", marginBottom: "10px" }}>SERVER</div>
                  {tech.server && <InfoRow label="WEB_SERVER" value={tech.server} valueColor="#fbbf24" />}
                  {tech.backend && <InfoRow label="BACKEND" value={tech.backend} valueColor="#fbbf24" />}
                  {tech.serverVersion && <InfoRow label="VERSION" value={tech.serverVersion} valueColor={tech.serverVersionOutdated ? "#ff6b35" : "#fbbf24"} />}
                  {tech.os && <InfoRow label="OS" value={tech.os} valueColor="rgba(180,255,180,0.6)" />}
                  {tech.poweredBy && <InfoRow label="POWERED_BY" value={tech.poweredBy} valueColor="#fbbf24" />}
                </div>
              )}
              {/* SSL quick status */}
              {(tech.ssl !== undefined || tech.https !== undefined) && (
                <div style={{ background: "rgba(0,255,136,0.04)", border: "1px solid rgba(0,255,136,0.1)", padding: "16px" }}>
                  <div style={{ fontFamily: "'Orbitron', monospace", fontSize: "10px", color: "#00ff88", letterSpacing: "0.12em", marginBottom: "10px" }}>SSL / HTTPS</div>
                  <InfoRow label="SSL_ENABLED" value={tech.ssl || tech.https ? "YES" : "NO"} valueColor={tech.ssl || tech.https ? "#00ff88" : "#ff6b35"} />
                </div>
              )}
              {/* CMS */}
              {tech.cms && (
                <div style={{ background: "rgba(0,212,255,0.04)", border: "1px solid rgba(0,212,255,0.1)", padding: "16px" }}>
                  <div style={{ fontFamily: "'Orbitron', monospace", fontSize: "10px", color: "#00d4ff", letterSpacing: "0.12em", marginBottom: "10px" }}>CMS / PLATFORM</div>
                  <InfoRow label="CMS" value={tech.cms} valueColor="#00d4ff" />
                  {tech.cmsVersion && <InfoRow label="VERSION" value={tech.cmsVersion} valueColor={tech.cmsOutdated ? "#ff6b35" : "#00d4ff"} />}
                  {tech.cmsOutdated && <div style={{ marginTop: "6px", fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", color: "#ff6b35" }}>⚠ OUTDATED VERSION DETECTED</div>}
                </div>
              )}
              {/* Frameworks */}
              {(tech.frameworks?.length > 0 || tech.jsFrameworks?.length > 0 || tech.libraries?.length > 0) && (
                <div style={{ background: "rgba(176,106,255,0.04)", border: "1px solid rgba(176,106,255,0.1)", padding: "16px" }}>
                  <div style={{ fontFamily: "'Orbitron', monospace", fontSize: "10px", color: "#b06aff", letterSpacing: "0.12em", marginBottom: "10px" }}>FRAMEWORKS & LIBRARIES</div>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                    {[...(tech.frameworks || []), ...(tech.jsFrameworks || []), ...(tech.libraries || [])].map((f, i) => <Tag key={i} color="#b06aff">{f}</Tag>)}
                  </div>
                </div>
              )}
              {/* CDN / Infra */}
              {(tech.cdn || tech.hosting || tech.cloudProvider || tech.waf) && (
                <div style={{ background: "rgba(0,255,136,0.04)", border: "1px solid rgba(0,255,136,0.1)", padding: "16px" }}>
                  <div style={{ fontFamily: "'Orbitron', monospace", fontSize: "10px", color: "#00ff88", letterSpacing: "0.12em", marginBottom: "10px" }}>INFRASTRUCTURE</div>
                  {tech.cdn && <InfoRow label="CDN" value={tech.cdn} valueColor="#00ff88" />}
                  {tech.hosting && <InfoRow label="HOSTING" value={tech.hosting} valueColor="#00ff88" />}
                  {tech.cloudProvider && <InfoRow label="CLOUD" value={tech.cloudProvider} valueColor="#00ff88" />}
                  {tech.waf && <InfoRow label="WAF" value={tech.waf} valueColor="#fbbf24" />}
                </div>
              )}
              {/* Analytics */}
              {(tech.analytics?.length > 0 || tech.trackers?.length > 0) && (
                <div style={{ background: "rgba(255,107,53,0.04)", border: "1px solid rgba(255,107,53,0.1)", padding: "16px" }}>
                  <div style={{ fontFamily: "'Orbitron', monospace", fontSize: "10px", color: "#ff6b35", letterSpacing: "0.12em", marginBottom: "10px" }}>ANALYTICS & TRACKERS</div>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                    {[...(tech.analytics || []), ...(tech.trackers || [])].map((t, i) => <Tag key={i} color="#ff6b35">{t}</Tag>)}
                  </div>
                </div>
              )}
              {/* Any remaining tech keys we haven't handled explicitly */}
              {(() => {
                const handled = new Set(["server","backend","serverVersion","serverVersionOutdated","os","ssl","https","cms","cmsVersion","cmsOutdated","frameworks","jsFrameworks","libraries","cdn","hosting","cloudProvider","waf","analytics","trackers","poweredBy"]);
                const extra = Object.entries(tech).filter(([k, v]) => !handled.has(k) && v !== null && v !== undefined && v !== "");
                if (extra.length === 0) return null;
                return (
                  <div style={{ background: "rgba(0,212,255,0.04)", border: "1px solid rgba(0,212,255,0.08)", padding: "16px" }}>
                    <div style={{ fontFamily: "'Orbitron', monospace", fontSize: "10px", color: "#00d4ff", letterSpacing: "0.12em", marginBottom: "10px" }}>ADDITIONAL TECH DATA</div>
                    <RenderObject obj={Object.fromEntries(extra)} />
                  </div>
                );
              })()}
            </div>
          )}
        </Panel>
      )}

      {/* ── HTTP SECURITY HEADERS — always shown ── */}
      <Panel leftAccent="#00d4ff" accent="rgba(0,212,255,0.1)">
        <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: expandedSections.headers ? "20px" : 0 }}>
          <SectionHeader icon={<FaShieldAlt />} title="HTTP SECURITY HEADERS" accent="#00d4ff"
            count={hasHeaders ? `${Object.values(hdrs).filter(v => v && v !== "MISSING" && v !== false).length} / ${Object.keys(hdrs).length}` : "NO DATA"} />
          <CollapseBtn section="headers" />
        </div>
        {expandedSections.headers && (
          hasHeaders ? (
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(260px, 1fr))", gap: "10px" }}>
              {Object.entries(hdrs).map(([header, value]) => {
                const present = !!value && value !== "MISSING" && value !== false && value !== "false";
                return (
                  <div key={header} style={{
                    background: present ? "rgba(0,255,136,0.04)" : "rgba(255,34,34,0.04)",
                    border: `1px solid ${present ? "rgba(0,255,136,0.12)" : "rgba(255,34,34,0.12)"}`,
                    padding: "12px 16px", display: "flex", flexDirection: "column", gap: "6px",
                  }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                      <span style={{ color: present ? "#00ff88" : "#ff2222", fontSize: "11px", flexShrink: 0 }}>{present ? <FaCheckCircle /> : <FaTimesCircle />}</span>
                      <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", color: present ? "#00ff88" : "#ff6b35", letterSpacing: "0.06em", wordBreak: "break-all" }}>{header}</span>
                    </div>
                    {present && typeof value === "string" && value !== "true" && value.length > 0 && (
                      <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", color: "rgba(0,255,136,0.4)", wordBreak: "break-all", lineHeight: 1.5 }}>
                        {value.length > 80 ? value.substring(0, 80) + "…" : value}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          ) : (
            <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "11px", color: "rgba(251,191,36,0.5)", padding: "8px 0" }}>
              No header data returned from quickscan.
            </div>
          )
        )}
      </Panel>

      {/* ── OPEN PORTS & SERVICES — always shown ── */}
      <Panel leftAccent="#00d4ff" accent="rgba(0,212,255,0.1)">
        <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: expandedSections.ports ? "20px" : 0 }}>
          <SectionHeader icon={<FaServer />} title="OPEN PORTS & SERVICES" accent="#00d4ff"
            count={hasPorts ? `${(ports.open || ports.list || ports.ports || []).length} OPEN` : "NO DATA"} />
          <CollapseBtn section="ports" />
        </div>
        {expandedSections.ports && (
          hasPorts ? (
            <div>
              {ports.ip      && <InfoRow label="TARGET_IP" value={ports.ip}      valueColor="#00d4ff" />}
              {ports.asn     && <InfoRow label="ASN"       value={ports.asn}     valueColor="rgba(180,255,180,0.6)" />}
              {ports.org     && <InfoRow label="ORG"       value={ports.org}     valueColor="rgba(180,255,180,0.6)" />}
              {ports.country && <InfoRow label="LOCATION"  value={ports.country} valueColor="#fbbf24" />}
              {(ports.open || ports.list || ports.ports || []).length > 0 && (
                <div style={{ marginTop: "16px", display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(160px, 1fr))", gap: "8px" }}>
                  {(ports.open || ports.list || ports.ports || []).map((port, i) => {
                    const portNum = typeof port === "object" ? (port.port || port.number) : port;
                    const service = typeof port === "object" ? (port.service || port.name || port.protocol) : null;
                    const banner  = typeof port === "object" ? (port.banner || port.version || port.product) : null;
                    const isSensitive = [21, 22, 23, 25, 3306, 5432, 6379, 27017, 8080, 8443, 1433, 3389].includes(Number(portNum));
                    return (
                      <div key={i} style={{ background: isSensitive ? "rgba(255,107,53,0.06)" : "rgba(0,212,255,0.04)", border: `1px solid ${isSensitive ? "rgba(255,107,53,0.2)" : "rgba(0,212,255,0.12)"}`, padding: "12px 14px" }}>
                        <div style={{ fontFamily: "'Orbitron', monospace", fontWeight: 700, fontSize: "20px", color: isSensitive ? "#ff6b35" : "#00d4ff", marginBottom: "4px" }}>{portNum}</div>
                        {service && <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", color: "rgba(0,255,136,0.6)", letterSpacing: "0.08em" }}>{service}</div>}
                        {banner  && <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px",  color: "rgba(0,255,136,0.35)", marginTop: "4px", wordBreak: "break-all" }}>{String(banner).substring(0, 36)}</div>}
                        {isSensitive && <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "8px", color: "#ff6b35", marginTop: "4px" }}>⚠ SENSITIVE</div>}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          ) : (
            <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "11px", color: "rgba(0,212,255,0.4)", padding: "8px 0" }}>
              Port scan returned no results or was not completed.
            </div>
          )
        )}
      </Panel>

      {/* ── OSINT & REPUTATION — only shown if a real finding exists ── */}
      {hasOsintAlert && (
        <Panel leftAccent="#b06aff" accent="rgba(176,106,255,0.1)">
          <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: expandedSections.osint ? "20px" : 0 }}>
            <SectionHeader icon={<FaUserSecret />} title="OSINT & REPUTATION INTEL" accent="#b06aff"
              count="⚠ FINDINGS DETECTED" />
            <CollapseBtn section="osint" />
          </div>
          {expandedSections.osint && (
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(260px, 1fr))", gap: "14px" }}>
              {/* VirusTotal */}
              {osint.virusTotal && (
                <div style={{ background: "rgba(255,107,53,0.05)", border: "1px solid rgba(255,107,53,0.18)", padding: "16px" }}>
                  <div style={{ fontFamily: "'Orbitron', monospace", fontSize: "10px", color: "#ff6b35", letterSpacing: "0.12em", marginBottom: "10px" }}>VIRUSTOTAL</div>
                  <InfoRow label="MALICIOUS"  value={osint.virusTotal.malicious  ?? 0} valueColor={osint.virusTotal.malicious  > 0 ? "#ff2222" : "#00ff88"} />
                  <InfoRow label="SUSPICIOUS" value={osint.virusTotal.suspicious ?? 0} valueColor={osint.virusTotal.suspicious > 0 ? "#fbbf24" : "#00ff88"} />
                  <InfoRow label="HARMLESS"   value={osint.virusTotal.harmless   ?? 0} valueColor="rgba(0,255,136,0.6)" />
                  {osint.virusTotal.categories?.length > 0 && (
                    <div style={{ marginTop: "8px", display: "flex", flexWrap: "wrap", gap: "4px" }}>
                      {osint.virusTotal.categories.map((c, i) => <Tag key={i} color="#ff6b35">{c}</Tag>)}
                    </div>
                  )}
                </div>
              )}
              {/* Safe Browsing */}
              {osint.safeBrowsing && osint.safeBrowsing.safe === false && (
                <div style={{ background: "rgba(255,34,34,0.06)", border: "1px solid rgba(255,34,34,0.2)", padding: "16px" }}>
                  <div style={{ fontFamily: "'Orbitron', monospace", fontSize: "10px", color: "#ff2222", letterSpacing: "0.12em", marginBottom: "10px" }}>GOOGLE SAFE BROWSING</div>
                  <InfoRow label="STATUS" value="⚠ UNSAFE" valueColor="#ff2222" />
                  {osint.safeBrowsing.threats?.length > 0 && (
                    <div style={{ marginTop: "8px", display: "flex", flexWrap: "wrap", gap: "4px" }}>
                      {osint.safeBrowsing.threats.map((t, i) => <Tag key={i} color="#ff2222">{t}</Tag>)}
                    </div>
                  )}
                </div>
              )}
              {/* DNSBL Blacklist */}
              {osint.blacklisted && (
                <div style={{ background: "rgba(255,107,53,0.05)", border: "1px solid rgba(255,107,53,0.18)", padding: "16px" }}>
                  <div style={{ fontFamily: "'Orbitron', monospace", fontSize: "10px", color: "#ff6b35", letterSpacing: "0.12em", marginBottom: "10px" }}>DNSBL BLACKLISTS</div>
                  <InfoRow label="BLACKLISTED" value="YES" valueColor="#ff2222" />
                  {osint.blacklistHits?.length > 0 && (
                    <div style={{ marginTop: "8px", display: "flex", flexWrap: "wrap", gap: "4px" }}>
                      {osint.blacklistHits.map((b, i) => <Tag key={i} color="#ff6b35">{b}</Tag>)}
                    </div>
                  )}
                </div>
              )}
              {/* Shodan CVEs */}
              {osint.cves?.count > 0 && (
                <div style={{ background: "rgba(255,34,34,0.06)", border: "1px solid rgba(255,34,34,0.2)", padding: "16px" }}>
                  <div style={{ fontFamily: "'Orbitron', monospace", fontSize: "10px", color: "#ff2222", letterSpacing: "0.12em", marginBottom: "10px" }}>SHODAN CVEs</div>
                  <InfoRow label="TOTAL_CVEs"    value={osint.cves.count}    valueColor="#ff2222" />
                  <InfoRow label="CRITICAL"      value={osint.cves.critical ?? 0} valueColor={osint.cves.critical > 0 ? "#ff2222" : "rgba(0,255,136,0.5)"} />
                  <InfoRow label="KEV_CONFIRMED" value={osint.cves.kev    ?? 0} valueColor={osint.cves.kev    > 0 ? "#ff6b35" : "rgba(0,255,136,0.5)"} />
                  {osint.cves.details?.length > 0 && (
                    <div style={{ marginTop: "10px", display: "flex", flexDirection: "column", gap: "4px" }}>
                      {osint.cves.details.slice(0, 5).map((cve, i) => (
                        <div key={i} style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", color: "#ff6b35", background: "rgba(255,107,53,0.06)", padding: "5px 10px" }}>
                          {typeof cve === "object" ? (cve.id || cve.cve || JSON.stringify(cve)) : cve}
                        </div>
                      ))}
                      {osint.cves.details.length > 5 && (
                        <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", color: "rgba(255,107,53,0.5)" }}>
                          +{osint.cves.details.length - 5} more CVEs
                        </div>
                      )}
                    </div>
                  )}
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

// ─── MODULE BLOCK ─────────────────────────────────────────────────────────────
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

// ─── MAIN COMPONENT ───────────────────────────────────────────────────────────
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


    
  // ← ADD THIS right before handleScan
  const isValidTarget = (val) => {
    const trimmed = val.trim();
    try {
      const u = new URL(trimmed.startsWith("http") ? trimmed : `http://${trimmed}`);
      const host = u.hostname;
      const domainRegex = /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
      const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
      return domainRegex.test(host) || ipRegex.test(host) || host === "localhost";
    } catch {
      return false;
    }
  };

  // ← REPLACE the existing handleScan with this:
  const handleScan = async () => {
    if (!input.trim()) return alert("Please enter a domain or URL");
    if (!isValidTarget(input)) {
      setError("Invalid target. Please enter a valid domain (e.g. example.com) or URL (e.g. https://example.com).");
      return;
    }
    setIsScanning(true);
    setScanDone(false);
    setScanResult(null);
    setError(null);
    setIsPaused(false);
    setTimeout(() => loaderRef.current?.scrollIntoView({ behavior: "smooth" }), 100);
    try {
      const resp = await axios.post("http://localhost:5000/api/fullscan", { url: input }, { timeout: 0 });
      setScanResult(resp.data);
      setScanDone(true);
    } catch (err) {
      setError(err.response ? err.response.data.error || "Invalid target" : "Backend not reachable or network error.");
    } finally {
      setIsScanning(false);
      setIsPaused(false);
    }
  };

  const handlePause = () => setIsPaused(true);
  const handleResume = () => setIsPaused(false);

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
        @keyframes pauseBlink { 0%,100%{opacity:1} 50%{opacity:0.3} }
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
          <div style={{
            width: "7px", height: "7px", borderRadius: "50%",
            background: isPaused ? "#fbbf24" : isScanning ? "#fbbf24" : "#ff6b35",
            boxShadow: `0 0 10px ${isPaused ? "#fbbf24" : isScanning ? "#fbbf24" : "#ff6b35"}`,
            animation: isPaused ? "pauseBlink 1s ease infinite" : "pulse 2s ease-in-out infinite"
          }} />
          <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", letterSpacing: "0.15em", color: isPaused ? "#fbbf24" : isScanning ? "#fbbf24" : "#ff6b35" }}>
            {isPaused ? "PAUSED" : isScanning ? "DEEP_SCANNING..." : "READY"}
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
              onChange={e => { setInput(e.target.value); if (error) setError(null); }}
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
            <div style={{
              background: "rgba(0,0,0,0.6)",
              border: `1px solid ${isPaused ? "rgba(251,191,36,0.3)" : "rgba(255,107,53,0.2)"}`,
              borderLeft: `3px solid ${isPaused ? "#fbbf24" : "#ff6b35"}`,
              padding: "28px 32px", maxWidth: "600px", transition: "border-color 0.3s",
            }}>
              <div style={{ display: "flex", alignItems: "center", gap: "16px", marginBottom: "18px" }}>
                <div style={{
                  width: "20px", height: "20px",
                  border: `2px solid ${isPaused ? "rgba(251,191,36,0.2)" : "rgba(255,107,53,0.2)"}`,
                  borderTop: `2px solid ${isPaused ? "#fbbf24" : "#ff6b35"}`,
                  borderRadius: "50%",
                  animation: isPaused ? "none" : "spin 0.8s linear infinite",
                }} />
                <span style={{ fontFamily: "'Orbitron', monospace", fontWeight: 700, fontSize: "14px", color: isPaused ? "#fbbf24" : "#ff6b35", letterSpacing: "0.1em" }}>
                  {isPaused ? "SCAN PAUSED" : "RUNNING DEEP SCAN"}
                </span>
              </div>
              <p style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "11px", color: "rgba(0,255,136,0.4)", marginBottom: "16px", letterSpacing: "0.1em" }}>
                {isPaused ? "Scan is paused — press RESUME to continue" : "This may take several minutes"}
              </p>
              {["Enumerating subdomains & infrastructure...", "Running OSINT correlation...", "Testing for SQL injection vectors...", "Scanning XSS attack surfaces...", "Checking CSRF, clickjacking, command injection...", "Generating vulnerability report..."].map((line, i) => (
                <div key={i} style={{
                  fontFamily: "'Share Tech Mono', monospace", fontSize: "11px",
                  color: isPaused ? "rgba(251,191,36,0.25)" : "rgba(255,107,53,0.5)",
                  lineHeight: 1.9, letterSpacing: "0.08em",
                  animation: isPaused ? "none" : `scanPulse 2s ease ${i * 0.4}s infinite`,
                }}>
                  › {line}
                </div>
              ))}
              <div style={{ display: "flex", gap: "12px", marginTop: "24px", alignItems: "center" }}>
                {!isPaused ? (
                  <button onClick={handlePause} style={{ fontFamily: "'Orbitron', monospace", fontWeight: 700, fontSize: "10px", letterSpacing: "0.15em", color: "#020804", background: "#fbbf24", border: "none", padding: "10px 22px", cursor: "pointer", boxShadow: "0 0 14px rgba(251,191,36,0.35)", transition: "all 0.2s", display: "flex", alignItems: "center", gap: "7px" }}
                    onMouseEnter={e => { e.currentTarget.style.transform = "translateY(-2px)"; }}
                    onMouseLeave={e => { e.currentTarget.style.transform = "translateY(0)"; }}>
                    ⏸ PAUSE SCAN
                  </button>
                ) : (
                  <button onClick={handleResume} style={{ fontFamily: "'Orbitron', monospace", fontWeight: 700, fontSize: "10px", letterSpacing: "0.15em", color: "#020804", background: "#00ff88", border: "none", padding: "10px 22px", cursor: "pointer", boxShadow: "0 0 14px rgba(0,255,136,0.35)", transition: "all 0.2s", display: "flex", alignItems: "center", gap: "7px", animation: "pauseBlink 1.5s ease infinite" }}
                    onMouseEnter={e => { e.currentTarget.style.transform = "translateY(-2px)"; e.currentTarget.style.animation = "none"; }}
                    onMouseLeave={e => { e.currentTarget.style.transform = "translateY(0)"; e.currentTarget.style.animation = "pauseBlink 1.5s ease infinite"; }}>
                    ▶ RESUME SCAN
                  </button>
                )}
              </div>
              {isPaused && (
                <div style={{ marginTop: "14px", display: "flex", alignItems: "center", gap: "10px", fontFamily: "'Share Tech Mono', monospace", fontSize: "11px", color: "#fbbf24", letterSpacing: "0.12em" }}>
                  ⏸ SCAN PAUSED
                </div>
              )}
            </div>
          </div>
        )}

        {/* RESULTS */}
        {scanDone && !isScanning && (
          <div style={{ animation: "fadeUp 0.6s ease both", paddingBottom: "120px" }}>

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

            {/* ── FULL QUICKSCAN RESULTS ── */}
            <QuickScanResults data={scanResult} />

            {/* ── VULNERABILITY ASSESSMENT ── */}
            <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", letterSpacing: "0.3em", color: "rgba(255,107,53,0.5)", marginBottom: "20px", marginTop: "40px" }}>
              // VULNERABILITY_ASSESSMENT_RESULTS
            </div>

            {(() => {
              const v = scanResult?.vulnerabilities || {};
              const DetailText = ({ children }) => <div style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: "14px", color: "rgba(180,255,180,0.55)", lineHeight: 1.7 }}>{children}</div>;
              const DetailMono = ({ children }) => <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "11px", color: "rgba(0,255,136,0.5)", lineHeight: 1.8 }}>{children}</div>;
              const Label = ({ children, color = "#fbbf24" }) => <span style={{ color, fontFamily: "'Share Tech Mono', monospace", fontSize: "11px" }}>{children}</span>;

              return (
                <div>
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

                  <ModuleBlock keyName="sensitive" title="SENSITIVE FILE EXPOSURE" found={!!v.sensitiveFiles?.found} expanded={expanded.sensitive} onToggle={toggle}>
                    {v.sensitiveFiles?.details?.exposedFiles?.length > 0 ? (
                      <div>
                        <DetailMono>
                          › Total exposed: <Label color="#ff6b35">{v.sensitiveFiles.details.summary?.total || 0}</Label>
                          {"  "}Critical: <Label color="#ff2222">{v.sensitiveFiles.details.summary?.critical || 0}</Label>
                          {"  "}High: <Label color="#ff6b35">{v.sensitiveFiles.details.summary?.high || 0}</Label>
                          {"  "}Medium: <Label color="#fbbf24">{v.sensitiveFiles.details.summary?.medium || 0}</Label>
                          {"  "}Low: <Label color="#00ff88">{v.sensitiveFiles.details.summary?.low || 0}</Label>
                        </DetailMono>
                        <div style={{ marginTop: "14px" }}>
                          {v.sensitiveFiles.details.exposedFiles.map((f, i) => (
                            <div key={i} style={{ marginBottom: "10px", paddingLeft: "12px", borderLeft: `2px solid ${riskAccent(f.severity)}55` }}>
                              <DetailMono>› <Label color={riskAccent(f.severity)}>[{f.severity}]</Label>{" "}<Label color="#00d4ff">{f.path}</Label></DetailMono>
                              <DetailMono>› Status: <Label color="#fbbf24">{f.status}</Label>{"  "}Desc: <Label color="rgba(180,255,180,0.55)">{f.desc}</Label></DetailMono>
                              {f.contentType && <DetailMono>› Content-Type: <Label color="rgba(180,255,180,0.4)">{f.contentType}</Label></DetailMono>}
                            </div>
                          ))}
                        </div>
                      </div>
                    ) : <DetailText>No sensitive files detected</DetailText>}
                  </ModuleBlock>

                  <ModuleBlock keyName="openRedirect" title="OPEN REDIRECT" found={!!v.openRedirect?.found} expanded={expanded.openRedirect} onToggle={toggle}>
                    {v.openRedirect?.details?.evidence?.length > 0 ? (
                      <div>
                        <DetailMono>› Parameters affected: <Label color="#ff6b35">{v.openRedirect.details.summary?.total || 0}</Label>{"  "}Params: <Label color="#ff2222">{v.openRedirect.details.summary?.parameters?.join(", ") || "—"}</Label></DetailMono>
                        <div style={{ marginTop: "14px" }}>
                          {v.openRedirect.details.evidence.map((e, i) => (
                            <div key={i} style={{ marginBottom: "10px", paddingLeft: "12px", borderLeft: "2px solid #ff6b3555" }}>
                              <DetailMono>› <Label color="#ff6b35">[HIGH]</Label>{" "}<Label color="#fff">Parameter: {e.parameter}</Label></DetailMono>
                              <DetailMono>› Payload: <Label color="#ff9800">{e.payload}</Label></DetailMono>
                              <DetailMono>› Redirects to: <Label color="#ff2222">{e.redirectsTo}</Label></DetailMono>
                              <DetailMono>› Status: <Label color="#fbbf24">{e.statusCode}</Label>{"  "}Type: <Label color="rgba(180,255,180,0.55)">{e.type}</Label></DetailMono>
                              <DetailMono>› Test URL: <Label color="#00d4ff">{e.url}</Label></DetailMono>
                            </div>
                          ))}
                        </div>
                        <DetailMono style={{ marginTop: "8px" }}>› <Label color="rgba(180,255,180,0.5)">{v.openRedirect.details.notes}</Label></DetailMono>
                      </div>
                    ) : <DetailText>No open redirect vulnerabilities detected</DetailText>}
                  </ModuleBlock>

                  <ModuleBlock keyName="cors" title="CORS MISCONFIGURATION" found={!!v.cors?.found} expanded={expanded.cors} onToggle={toggle}>
                    {v.cors?.details?.evidence?.length > 0 ? (
                      <div>
                        <DetailMono>› Total issues: <Label color="#ff6b35">{v.cors.details.summary?.total || 0}</Label>{"  "}Critical: <Label color="#ff2222">{v.cors.details.summary?.critical || 0}</Label>{"  "}High: <Label color="#ff6b35">{v.cors.details.summary?.high || 0}</Label>{"  "}Medium: <Label color="#fbbf24">{v.cors.details.summary?.medium || 0}</Label>{"  "}Exploitable: <Label color="#ff2222">{v.cors.details.summary?.exploitable || 0}</Label></DetailMono>
                        <div style={{ marginTop: "14px" }}>
                          {v.cors.details.evidence.map((e, i) => (
                            <div key={i} style={{ marginBottom: "10px", paddingLeft: "12px", borderLeft: `2px solid ${riskAccent(e.severity)}55` }}>
                              <DetailMono>› <Label color={riskAccent(e.severity)}>[{e.severity}]</Label>{" "}<Label color="#fff">{e.type}</Label></DetailMono>
                              <DetailMono>› <Label color="rgba(180,255,180,0.55)">{e.description}</Label></DetailMono>
                              <DetailMono>› Endpoint: <Label color="#00d4ff">{e.url}</Label></DetailMono>
                              <DetailMono>› Header: <Label color="#ff9800">{e.header}</Label></DetailMono>
                              <DetailMono>› Exploitable: <Label color={e.exploitable ? "#ff2222" : "#00ff88"}>{e.exploitable ? "Yes" : "No (browser blocks)"}</Label></DetailMono>
                            </div>
                          ))}
                        </div>
                        <DetailMono style={{ marginTop: "8px" }}>› <Label color="rgba(180,255,180,0.5)">{v.cors.details.notes}</Label></DetailMono>
                      </div>
                    ) : <DetailText>No CORS misconfigurations detected</DetailText>}
                  </ModuleBlock>

                  <ModuleBlock keyName="wordpress" title="WORDPRESS SECURITY" found={!!v.wordpress?.found} expanded={!!expanded.wordpress} onToggle={toggle}>
                    {v.wordpress?.found ? (
                      <div>
                        <div style={{ marginBottom: "14px", paddingLeft: "12px", borderLeft: "2px solid rgba(255,107,53,0.3)" }}>
                          <DetailMono>› Risk Score: <Label color={riskAccent(v.wordpress.details?.riskScore?.level)}>{v.wordpress.details?.riskScore?.score ?? "?"}/100 ({v.wordpress.details?.riskScore?.level ?? "UNKNOWN"})</Label></DetailMono>
                          <DetailMono>› Site: <Label color="#00d4ff">{v.wordpress.details?.url}</Label></DetailMono>
                          <DetailMono>› Scanned At: <Label color="#fbbf24">{v.wordpress.details?.scannedAt ? new Date(v.wordpress.details.scannedAt).toLocaleString() : "—"}</Label></DetailMono>
                        </div>
                        <div style={{ marginBottom: "14px", paddingLeft: "12px", borderLeft: "2px solid rgba(0,255,136,0.3)" }}>
                          <DetailMono>› WP Version: <Label color="#00ff88">{v.wordpress.details?.results?.coreVersion?.version || "Not detected"}</Label></DetailMono>
                          {(v.wordpress.details?.results?.coreVersion?.vulnerabilities || []).map((cv, i) => (
                            <DetailMono key={i}>› <Label color="#ff2222">[{cv.severity}]</Label> {cv.issue} — fix in <Label color="#fbbf24">{cv.fixedIn}</Label></DetailMono>
                          ))}
                        </div>
                        {(v.wordpress.details?.results?.plugins || []).filter(p => p.vulnerabilities?.length > 0).length > 0 && (
                          <div style={{ marginBottom: "14px", paddingLeft: "12px", borderLeft: "2px solid rgba(255,34,34,0.4)" }}>
                            <DetailMono>› Vulnerable Plugins: <Label color="#ff2222">{v.wordpress.details.results.plugins.filter(p => p.vulnerabilities?.length > 0).length}</Label></DetailMono>
                            {v.wordpress.details.results.plugins.filter(p => p.vulnerabilities?.length > 0).map((p, i) => (
                              <div key={i} style={{ marginTop: "6px" }}>
                                <DetailMono>&nbsp;&nbsp;· <Label color={riskAccent(p.severity)}>[{p.severity}]</Label>{" "}<Label color="#fbbf24">{p.slug}</Label>{p.version && <Label color="rgba(180,255,180,0.5)"> v{p.version}</Label>}</DetailMono>
                                <DetailMono>&nbsp;&nbsp;&nbsp;&nbsp;↳ <Label color="rgba(180,255,180,0.55)">{p.vulnerabilities[0]?.issue}</Label></DetailMono>
                              </div>
                            ))}
                          </div>
                        )}
                        {v.wordpress.details?.results?.theme?.name && (
                          <div style={{ marginBottom: "14px", paddingLeft: "12px", borderLeft: "2px solid rgba(0,255,136,0.2)" }}>
                            <DetailMono>› Active Theme: <Label color="#00ff88">{v.wordpress.details.results.theme.name}</Label>{v.wordpress.details.results.theme.version && <Label color="rgba(180,255,180,0.5)"> v{v.wordpress.details.results.theme.version}</Label>}</DetailMono>
                          </div>
                        )}
                        {v.wordpress.details?.results?.userEnumeration?.exposed && (
                          <div style={{ marginBottom: "10px", paddingLeft: "12px", borderLeft: "2px solid rgba(255,34,34,0.4)" }}>
                            <DetailMono>› <Label color="#ff2222">[HIGH]</Label> User Enumeration: <Label color="#ff6b35">{(v.wordpress.details.results.userEnumeration.users || []).length} user(s) exposed</Label></DetailMono>
                            {(v.wordpress.details.results.userEnumeration.users || []).slice(0, 5).map((u, i) => (
                              <DetailMono key={i}>&nbsp;&nbsp;· <Label color="#fbbf24">{u.name}</Label> <Label color="rgba(180,255,180,0.4)">via {u.source}</Label></DetailMono>
                            ))}
                          </div>
                        )}
                        {v.wordpress.details?.results?.loginExposure?.wpLoginExposed && (
                          <DetailMono style={{ marginBottom: "10px" }}>› <Label color="#ff6b35">[MEDIUM]</Label> wp-login.php publicly accessible{!v.wordpress.details.results.loginExposure.bruteForceProtection && <Label color="#ff2222"> — No brute-force protection detected</Label>}</DetailMono>
                        )}
                        {v.wordpress.details?.results?.xmlRpc?.enabled && (
                          <DetailMono style={{ marginBottom: "10px" }}>› <Label color={v.wordpress.details.results.xmlRpc.multicallEnabled ? "#ff2222" : "#ff6b35"}>[{v.wordpress.details.results.xmlRpc.multicallEnabled ? "CRITICAL" : "HIGH"}]</Label>{" "}XML-RPC enabled{v.wordpress.details.results.xmlRpc.multicallEnabled ? " + system.multicall (brute-force amplifier)" : ""}</DetailMono>
                        )}
                        {(v.wordpress.details?.results?.securityHeaders?.missing || []).length > 0 && (
                          <div style={{ paddingLeft: "12px", borderLeft: "2px solid rgba(251,191,36,0.3)" }}>
                            <DetailMono>› Missing security headers: <Label color="#fbbf24">{v.wordpress.details.results.securityHeaders.missing.length}</Label></DetailMono>
                            {v.wordpress.details.results.securityHeaders.missing.map((h, i) => (
                              <DetailMono key={i}>&nbsp;&nbsp;· <Label color="rgba(180,255,180,0.5)">{h.header}</Label></DetailMono>
                            ))}
                          </div>
                        )}
                      </div>
                    ) : <DetailText>Target is not running WordPress or no issues detected.</DetailText>}
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
                onMouseEnter={e => { e.currentTarget.style.transform = "translateY(-2px)"; e.currentTarget.style.boxShadow = "0 0 40px rgba(0,255,136,0.5)"; }}
                onMouseLeave={e => { e.currentTarget.style.transform = "translateY(0)"; e.currentTarget.style.boxShadow = "0 0 24px rgba(0,255,136,0.3)"; }}
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