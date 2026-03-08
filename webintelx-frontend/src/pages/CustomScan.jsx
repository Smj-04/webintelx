import { useState, useRef } from "react";
import {
  FaSearch, FaBug, FaShieldAlt, FaFileDownload,
  FaGlobe, FaServer, FaLock, FaUnlock, FaNetworkWired, FaEnvelope,
  FaRoute, FaChevronDown, FaChevronUp, FaCode,
  FaLeaf, FaSkull, FaMapMarkerAlt, FaCookieBite,
  FaVirus, FaEye, FaSlidersH, FaCheckSquare, FaSquare,
} from "react-icons/fa";
import axios from "axios";

const FONT_URL = "https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;600;700;900&family=Rajdhani:wght@300;400;500;600;700&display=swap";

const riskAccent = (r) => ({ CRITICAL:"#ff2222", HIGH:"#ff6b35", MEDIUM:"#fbbf24" }[r] || "#b06aff");
const riskBg     = (r) => ({ CRITICAL:"rgba(255,34,34,0.08)", HIGH:"rgba(255,107,53,0.08)", MEDIUM:"rgba(251,191,36,0.08)" }[r] || "rgba(176,106,255,0.06)");

// ── Background ─────────────────────────────────────────────────────────────────
function HexGrid() {
  const hexes = [];
  for (let r = 0; r < 8; r++)
    for (let c = 0; c < 16; c++) {
      const w=52,h=46, x=c*w*0.75+(r%2===0?0:w*0.375), y=r*h*0.87;
      hexes.push({x,y,key:`${r}-${c}`,d:(r+c)*0.08});
    }
  const hexPath=(x,y,s=22)=>Array.from({length:6},(_,i)=>{const a=(Math.PI/180)*(60*i-30);return`${x+s*Math.cos(a)},${y+s*Math.sin(a)}`;}).join(" ");
  return (
    <svg style={{position:"fixed",inset:0,width:"100%",height:"100%",opacity:0.04,pointerEvents:"none",zIndex:0}} viewBox="0 0 1300 500" preserveAspectRatio="xMidYMid slice">
      {hexes.map(h=>(
        <polygon key={h.key} points={hexPath(h.x+26,h.y+26)} fill="none" stroke="#00ff88" strokeWidth="0.6">
          <animate attributeName="opacity" values="0.3;1;0.3" dur={`${4+(h.d%3)}s`} begin={`${h.d%2}s`} repeatCount="indefinite"/>
        </polygon>
      ))}
    </svg>
  );
}

// ── Shared components ─────────────────────────────────────────────────────────
const StatRow = ({label,value,accent="rgba(176,106,255,0.7)"}) => (
  <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"6px 0",borderBottom:"1px solid rgba(0,255,136,0.04)"}}>
    <span style={{fontFamily:"'Share Tech Mono',monospace",fontSize:"9px",color:"rgba(0,255,136,0.4)",letterSpacing:"0.2em"}}>{label}</span>
    <span style={{fontFamily:"'Share Tech Mono',monospace",fontSize:"11px",color:accent,textAlign:"right",maxWidth:"60%",wordBreak:"break-all"}}>{value ?? "N/A"}</span>
  </div>
);

const AlertRow = ({text,severity="warn"}) => {
  const c = severity==="critical"?"#ff2222":severity==="info"?"rgba(0,212,255,0.8)":"#fbbf24";
  const ic = severity==="critical"?"✕":severity==="info"?"✓":"⚠";
  return (
    <div style={{display:"flex",gap:"8px",alignItems:"flex-start",padding:"8px 10px",background:`${c}11`,border:`1px solid ${c}33`,borderRadius:"3px",margin:"6px 0"}}>
      <span style={{color:c,fontSize:"11px",flexShrink:0}}>{ic}</span>
      <span style={{fontFamily:"'Share Tech Mono',monospace",fontSize:"10px",color:c,lineHeight:1.5}}>{text}</span>
    </div>
  );
};

const ModuleCard = ({title,icon,risk,summary,children,defaultOpen=false}) => {
  const [open,setOpen]=useState(defaultOpen);
  const accent=riskAccent(risk||"LOW");
  const riskLabel=risk||"LOW";
  return (
    <div style={{border:`1px solid ${accent}33`,borderRadius:"4px",overflow:"hidden",background:"rgba(0,10,2,0.6)"}}>
      <div onClick={()=>setOpen(!open)} style={{display:"flex",alignItems:"center",gap:"12px",padding:"14px 18px",cursor:"pointer",background:open?`${accent}08`:"transparent"}}>
        <span style={{color:accent,fontSize:"14px",flexShrink:0}}>{icon}</span>
        <div style={{flex:1,minWidth:0}}>
          <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:"8px",color:"rgba(0,255,136,0.35)",letterSpacing:"0.2em",marginBottom:"2px"}}>MODULE //</div>
          <div style={{fontFamily:"'Orbitron',monospace",fontSize:"11px",color:accent,fontWeight:600}}>{title}</div>
        </div>
        {summary&&<span style={{fontFamily:"'Share Tech Mono',monospace",fontSize:"9px",color:"rgba(176,106,255,0.5)",textAlign:"right",flexShrink:0,maxWidth:"180px"}}>{summary}</span>}
        <span style={{fontFamily:"'Orbitron',monospace",fontSize:"8px",fontWeight:700,color:accent,background:`${accent}18`,border:`1px solid ${accent}44`,borderRadius:"2px",padding:"2px 8px",flexShrink:0}}>{riskLabel}</span>
        <span style={{color:accent,fontSize:"10px",flexShrink:0}}>{open?<FaChevronUp/>:<FaChevronDown/>}</span>
      </div>
      {open&&<div style={{padding:"16px 18px",borderTop:`1px solid ${accent}22`}}>{children}</div>}
    </div>
  );
};

const TagList = ({items,color="#b06aff"}) => (
  <div style={{display:"flex",flexWrap:"wrap",gap:"6px",margin:"6px 0"}}>
    {items.map((item,i)=>(
      <span key={i} style={{fontFamily:"'Share Tech Mono',monospace",fontSize:"9px",color,background:`${color}15`,border:`1px solid ${color}44`,borderRadius:"2px",padding:"2px 8px"}}>{item}</span>
    ))}
  </div>
);

// ── Module definitions ─────────────────────────────────────────────────────────
const MODULE_GROUPS = [
  {
    label: "INFRASTRUCTURE",
    color: "#00d4ff",
    modules: [
      { id:"dns",        label:"DNS Intelligence",    icon:<FaGlobe/>,       desc:"Resolve A/MX/NS records" },
      { id:"whois",      label:"WHOIS / RDAP",        icon:<FaServer/>,      desc:"Domain registration data" },
      { id:"ping",       label:"Ping / Reachability", icon:<FaNetworkWired/>,desc:"ICMP echo & latency" },
      { id:"traceroute", label:"Traceroute",          icon:<FaRoute/>,       desc:"Network path analysis" },
      { id:"ports",      label:"Port Scanner",        icon:<FaServer/>,      desc:"Top 20 TCP ports" },
    ],
  },
  {
    label: "WEB SECURITY",
    color: "#b06aff",
    modules: [
      { id:"ssl",        label:"SSL / TLS",           icon:<FaLock/>,        desc:"Certificate validation" },
      { id:"headers",    label:"Security Headers",    icon:<FaShieldAlt/>,   desc:"HTTP security headers" },
      { id:"endpoints",  label:"Endpoint Discovery",  icon:<FaCode/>,        desc:"Parameterized URLs" },
      { id:"wappalyzer", label:"Tech Stack",          icon:<FaFingerprint/>, desc:"Technology fingerprinting" },
    ],
  },
  {
    label: "OSINT",
    color: "#b06aff",
    modules: [
      { id:"shodan",       label:"Shodan Intelligence", icon:<FaEye/>,         desc:"Host & CVE intelligence" },
      { id:"virusTotal",   label:"VirusTotal",          icon:<FaVirus/>,       desc:"AV engine domain scan" },
      { id:"safeBrowsing", label:"Safe Browsing",       icon:<FaShieldAlt/>,   desc:"Google threat database" },
      { id:"asnGeo",       label:"ASN & Geolocation",   icon:<FaMapMarkerAlt/>,desc:"IP, ASN, cloud detection" },
      { id:"subdomains",   label:"Subdomain Enum",      icon:<FaGlobe/>,       desc:"Passive DNS via HackerTarget" },
      { id:"email",        label:"Email Intelligence",  icon:<FaEnvelope/>,    desc:"DNSBL + Hunter.io" },
    ],
  },
  {
    label: "HOST",
    color: "#fbbf24",
    modules: [
      { id:"cookies",  label:"Cookie Analysis",   icon:<FaCookieBite/>, desc:"Cookie security flags" },
      { id:"greenWeb", label:"Green Hosting",     icon:<FaLeaf/>,       desc:"Renewable energy check" },
    ],
  },
  {
    label: "VULNERABILITY",
    color: "#ff6b35",
    modules: [
      { id:"sqlInjection",     label:"SQL Injection",        icon:<FaBug/>,       desc:"SQLMap automated scan" },
      { id:"xss",              label:"XSS",                  icon:<FaBug/>,       desc:"Reflected/DOM/Stored XSS" },
      { id:"csrf",             label:"CSRF",                 icon:<FaUnlock/>,    desc:"Cross-site request forgery" },
      { id:"clickjacking",     label:"Clickjacking",        icon:<FaSkull/>,     desc:"X-Frame-Options check" },
      { id:"commandInjection", label:"Command Injection",   icon:<FaBug/>,       desc:"OS command injection" },
      { id:"sensitiveFiles",   label:"Sensitive Files",     icon:<FaSearch/>,    desc:"Exposed config & backup files" },
      { id:"openRedirect",     label:"Open Redirect",       icon:<FaRoute/>,     desc:"URL redirect abuse" },
    ],
  },
];

const ALL_MODULE_IDS = MODULE_GROUPS.flatMap(g => g.modules.map(m => m.id));

// ── Result renderers ───────────────────────────────────────────────────────────
function FaFingerprint(props) { return <FaSearch {...props}/>; }

function ResultsView({ r, riskAssessment, target, onDownload, isDownloading }) {
  const risk = riskAssessment?.risk || "LOW";
  const score = riskAssessment?.score ?? 0;
  const findings = riskAssessment?.findings || [];

  return (
    <div style={{animation:"fadeUp 0.5s ease forwards"}}>
      {/* Risk assessment */}
      <div style={{border:`1px solid ${riskAccent(risk)}55`,borderRadius:"4px",background:riskBg(risk),padding:"24px",marginBottom:"32px"}}>
        <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:"9px",color:"rgba(0,255,136,0.4)",letterSpacing:"0.3em",marginBottom:"8px"}}>OVERALL_RISK_ASSESSMENT //</div>
        <div style={{fontFamily:"'Orbitron',monospace",fontSize:"24px",fontWeight:900,color:riskAccent(risk),marginBottom:"4px"}}>{risk} RISK</div>
        <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:"11px",color:"rgba(176,106,255,0.6)",marginBottom:"12px"}}>TARGET: {target} &nbsp;|&nbsp; RISK SCORE: {score}/20</div>
        {findings.length>0&&(
          <>
            <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:"9px",color:"rgba(0,255,136,0.4)",letterSpacing:"0.2em",marginBottom:"8px"}}>KEY FINDINGS //</div>
            {findings.map((f,i)=><AlertRow key={i} text={f} severity={risk==="CRITICAL"||risk==="HIGH"?"critical":"warn"}/>)}
          </>
        )}
      </div>

      <div style={{display:"flex",flexDirection:"column",gap:"12px"}}>

        {/* SSL */}
        {r.ssl&&<ModuleCard title="SSL / TLS Certificate" icon={<FaLock style={{color:r.ssl.valid?"#b06aff":"#ff6b35"}}/>} risk={r.ssl.valid?"LOW":"HIGH"} summary={r.ssl.valid?`Valid · ${r.ssl.daysRemaining}d remaining`:"Invalid"}>
          <StatRow label="STATUS" value={r.ssl.valid?"[VALID]":"[INVALID]"} accent={r.ssl.valid?"#b06aff":"#ff2222"}/>
          <StatRow label="ISSUER" value={r.ssl.issuer}/>
          <StatRow label="VALID FROM" value={r.ssl.validFrom?.split("T")[0]}/>
          <StatRow label="VALID TO" value={r.ssl.validTo?.split("T")[0]}/>
          <StatRow label="DAYS REMAINING" value={r.ssl.daysRemaining} accent={r.ssl.daysRemaining<30?"#fbbf24":"#b06aff"}/>
          {!r.ssl.valid&&<AlertRow text="HTTPS not enforced — data transmitted in plaintext" severity="critical"/>}
        </ModuleCard>}

        {/* Headers */}
        {r.headers&&<ModuleCard title="Security Headers" icon={<FaShieldAlt style={{color:"#00d4ff"}}/>} risk={(r.headers.missingSecurityHeaders||[]).length>=3?"MEDIUM":"LOW"} summary={`${(r.headers.missingSecurityHeaders||[]).length} missing`}>
          <StatRow label="SERVER" value={r.headers.server}/>
          <StatRow label="X-POWERED-BY" value={r.headers.poweredBy||"Hidden"}/>
          <StatRow label="STRICT-TRANSPORT-SEC" value={r.headers.strictTransport||"MISSING"} accent={r.headers.strictTransport?"#b06aff":"#ff2222"}/>
          <StatRow label="X-FRAME-OPTIONS" value={r.headers.xFrameOptions||"MISSING"} accent={r.headers.xFrameOptions?"#b06aff":"#ff2222"}/>
          <StatRow label="CONTENT-SECURITY-POLICY" value={r.headers.csp||"MISSING"} accent={r.headers.csp?"#b06aff":"#ff2222"}/>
          <StatRow label="REFERRER-POLICY" value={r.headers.referrer||"MISSING"} accent={r.headers.referrer?"#b06aff":"#ff2222"}/>
          {(r.headers.missingSecurityHeaders||[]).length>0&&(
            <><div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:"9px",color:"rgba(255,191,36,0.7)",letterSpacing:"0.2em",margin:"12px 0 8px"}}>MISSING HEADERS //</div>
            {r.headers.missingSecurityHeaders.map((h,i)=><AlertRow key={i} text={h} severity="warn"/>)}</>
          )}
        </ModuleCard>}

        {/* Tech Stack */}
        {r.wappalyzer&&(()=>{
          const techs = Object.entries(r.wappalyzer);
          const outdated = techs.filter(([,v])=>v.outdated);
          const risk = outdated.some(([,v])=>v.severity==="CRITICAL")?"HIGH":outdated.length>0?"MEDIUM":"LOW";
          return (
            <ModuleCard title="Technology Stack" icon={<FaServer style={{color:"#00d4ff"}}/>} risk={risk} summary={`${techs.length} detected · ${outdated.length} outdated`}>
              {outdated.length>0&&(
                <>
                  <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:"9px",color:"rgba(255,107,53,0.7)",letterSpacing:"0.2em",margin:"4px 0 8px"}}>OUTDATED VERSIONS //</div>
                  {outdated.map(([tech,info])=>{
                    const c = info.severity==="CRITICAL"?"#ff2222":info.severity==="HIGH"?"#ff6b35":"#fbbf24";
                    return (
                      <div key={tech} style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"8px 10px",background:`${c}0d`,border:`1px solid ${c}33`,borderRadius:"3px",marginBottom:"6px"}}>
                        <div>
                          <span style={{fontFamily:"'Share Tech Mono',monospace",fontSize:"10px",color:c,fontWeight:700}}>{tech}</span>
                          <span style={{fontFamily:"'Share Tech Mono',monospace",fontSize:"9px",color:`${c}99`,marginLeft:"8px"}}>v{info.version} → latest v{info.latest}</span>
                        </div>
                        <span style={{fontFamily:"'Orbitron',monospace",fontSize:"8px",fontWeight:700,color:c,background:`${c}20`,border:`1px solid ${c}44`,borderRadius:"2px",padding:"2px 8px",flexShrink:0}}>{info.severity}</span>
                      </div>
                    );
                  })}
                  <div style={{height:"1px",background:"rgba(0,255,136,0.06)",margin:"10px 0"}}/>
                </>
              )}
              <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:"9px",color:"rgba(0,255,136,0.4)",letterSpacing:"0.2em",marginBottom:"8px"}}>ALL DETECTED //</div>
              <div style={{display:"flex",flexWrap:"wrap",gap:"6px"}}>
                {techs.map(([tech,info])=>{
                  const c = info.outdated?(info.severity==="CRITICAL"?"#ff2222":info.severity==="HIGH"?"#ff6b35":"#fbbf24"):"#00d4ff";
                  return (
                    <span key={tech} style={{fontFamily:"'Share Tech Mono',monospace",fontSize:"9px",color:c,background:`${c}10`,border:`1px solid ${c}30`,borderRadius:"2px",padding:"3px 10px"}}>
                      {tech}{info.version&&info.version!=="Unknown"?` v${info.version}`:""}
                      {info.outdated?" ⚠":""}
                    </span>
                  );
                })}
              </div>
            </ModuleCard>
          );
        })()}

        {/* Endpoints */}
        {r.endpoints&&<ModuleCard title="Endpoint Discovery" icon={<FaCode style={{color:"#b06aff"}}/>} risk={r.endpoints.length>20?"MEDIUM":"LOW"} summary={`${r.endpoints.length} endpoints`}>
          <StatRow label="TOTAL ENDPOINTS" value={r.endpoints.length}/>
          {r.endpoints.length>0&&(
            <>{(r.endpoints||[]).slice(0,8).map((e,i)=>(
              <div key={i} style={{fontFamily:"'Share Tech Mono',monospace",fontSize:"9px",color:"rgba(176,106,255,0.5)",padding:"4px 0",borderBottom:"1px solid rgba(0,255,136,0.04)"}}>{e.url||e}</div>
            ))}</>
          )}
        </ModuleCard>}

        {/* DNS */}
        {r.dns&&<ModuleCard title="DNS Intelligence" icon={<FaGlobe style={{color:"#00d4ff"}}/>} risk="LOW" summary={r.dns.resolvedSuccessfully?"Resolved":"Failed"} defaultOpen={false}>
          <StatRow label="RESOLVED" value={r.dns.resolvedSuccessfully?"YES":"NO"} accent={r.dns.resolvedSuccessfully?"#b06aff":"#ff2222"}/>
          <StatRow label="PRIMARY IP" value={r.dns.primaryIP}/>
          <StatRow label="A RECORDS" value={(r.dns.A||[]).join(", ")||"None"}/>
          <StatRow label="MX RECORDS" value={(r.dns.MX||[]).length}/>
          <StatRow label="NS RECORDS" value={(r.dns.NS||[]).length}/>
        </ModuleCard>}

        {/* WHOIS */}
        {r.whois&&<ModuleCard title="WHOIS / Registration" icon={<FaServer style={{color:"#00d4ff"}}/>} risk="LOW" summary={r.whois.registrar}>
          <StatRow label="REGISTRAR" value={r.whois.registrar}/>
          <StatRow label="REGISTRANT ORG" value={r.whois.registrantOrg}/>
          <StatRow label="CREATED" value={r.whois.creationDate}/>
          <StatRow label="EXPIRES" value={r.whois.expiryDate}/>
          <StatRow label="DNSSEC" value={r.whois.dnssec}/>
          {(r.whois.nameservers||[]).length>0&&<TagList items={r.whois.nameservers} color="#00d4ff"/>}
        </ModuleCard>}

        {/* Ping */}
        {r.ping&&<ModuleCard title="Reachability (Ping)" icon={<FaNetworkWired style={{color:r.ping.reachable?"#b06aff":"#ff2222"}}/>} risk={r.ping.reachable?"LOW":"HIGH"} summary={r.ping.reachable?`${r.ping.avgTime} ms avg`:"Unreachable"}>
          <StatRow label="REACHABLE" value={r.ping.reachable?"YES":"NO"} accent={r.ping.reachable?"#b06aff":"#ff2222"}/>
          <StatRow label="AVG LATENCY" value={r.ping.avgTime&&r.ping.avgTime!=="N/A"?`${r.ping.avgTime} ms`:"N/A"}/>
          <StatRow label="PACKET LOSS" value={r.ping.packetLoss||"0%"}/>
        </ModuleCard>}

        {/* Traceroute */}
        {r.traceroute&&<ModuleCard title="Traceroute" icon={<FaRoute style={{color:"#00d4ff"}}/>} risk="LOW" summary={`${r.traceroute.totalHops} hops · ${r.traceroute.avgLatency} ms avg`}>
          <StatRow label="TOTAL HOPS" value={r.traceroute.totalHops}/>
          <StatRow label="REACHABLE HOPS" value={r.traceroute.reachableHops}/>
          <StatRow label="FINAL HOP" value={r.traceroute.finalHop}/>
          <StatRow label="AVG LATENCY" value={r.traceroute.avgLatency?`${r.traceroute.avgLatency} ms`:"N/A"}/>
        </ModuleCard>}

        {/* Ports */}
        {r.openPorts&&<ModuleCard title="Port Scanner" icon={<FaServer style={{color:"#00d4ff"}}/>} risk="LOW" summary={`${r.openPorts.length} open`}>
          <div style={{display:"flex",flexWrap:"wrap",gap:"8px",marginTop:"8px"}}>
            {(r.openPorts||[]).map((p,i)=>(
              <div key={i} style={{fontFamily:"'Share Tech Mono',monospace",fontSize:"9px",color:"#b06aff",background:"rgba(176,106,255,0.08)",border:"1px solid rgba(176,106,255,0.2)",borderRadius:"2px",padding:"4px 10px",textAlign:"center"}}>
                <div style={{fontSize:"13px",fontWeight:700}}>{p.port}</div>
                <div style={{fontSize:"8px",opacity:0.6}}>{p.name}</div>
              </div>
            ))}
          </div>
        </ModuleCard>}

        {/* ASN Geo */}
        {r.asnGeo&&<ModuleCard title="ASN & Geolocation" icon={<FaMapMarkerAlt style={{color:"#b06aff"}}/>} risk="LOW" summary={`${r.asnGeo.city||"Unknown"}, ${r.asnGeo.countryCode||""}`}>
          <StatRow label="IP ADDRESS" value={r.asnGeo.ip}/>
          <StatRow label="COUNTRY" value={r.asnGeo.country?`${r.asnGeo.country} (${r.asnGeo.countryCode})`:"N/A"}/>
          <StatRow label="CITY" value={r.asnGeo.city}/>
          <StatRow label="ISP" value={r.asnGeo.isp}/>
          <StatRow label="ORG" value={r.asnGeo.org}/>
          <StatRow label="ASN" value={r.asnGeo.asn}/>
          <StatRow label="CLOUD HOSTED" value={r.asnGeo.isCloud?`YES — ${r.asnGeo.cloudProvider}`:"NO"} accent={r.asnGeo.isCloud?"#fbbf24":"#b06aff"}/>
          {r.asnGeo.isCloud&&<AlertRow text={`Hosted on cloud infrastructure (${r.asnGeo.cloudProvider}) — shared IP space possible`} severity="info"/>}
        </ModuleCard>}

        {/* Subdomains */}
        {r.securityTrails&&<ModuleCard title="Attack Surface (Subdomains)" icon={<FaSearch style={{color:"#b06aff"}}/>} risk={r.securityTrails.risk||"LOW"} summary={`${r.securityTrails.subdomainCount} subdomains`}>
          <StatRow label="SUBDOMAIN COUNT" value={r.securityTrails.subdomainCount}/>
          <StatRow label="SOURCE" value={r.securityTrails.note}/>
          {(r.securityTrails.subdomains||[]).length>0&&(
            <><div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:"9px",color:"rgba(0,255,136,0.4)",letterSpacing:"0.2em",margin:"12px 0 8px"}}>SUBDOMAINS //</div>
            <TagList items={r.securityTrails.subdomains.slice(0,12)} color="#b06aff"/>
            {r.securityTrails.subdomains.length>12&&<div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:"9px",color:"rgba(0,255,136,0.4)",marginTop:"6px"}}>+{r.securityTrails.subdomains.length-12} more</div>}</>
          )}
        </ModuleCard>}

        {/* Cookies */}
        {r.cookies&&<ModuleCard title="Cookie Security" icon={<FaCookieBite style={{color:"#fbbf24"}}/>} risk={r.cookies.risk||"LOW"} summary={`${r.cookies.cookieCount} cookies · ${(r.cookies.issues||[]).length} issues`}>
          <StatRow label="COOKIES SET" value={r.cookies.cookieCount}/>
          <StatRow label="SECURITY ISSUES" value={(r.cookies.issues||[]).length} accent={(r.cookies.issues||[]).length>0?"#fbbf24":"#b06aff"}/>
          {(r.cookies.cookies||[]).map((c,i)=>(
            <div key={i} style={{fontFamily:"'Share Tech Mono',monospace",fontSize:"9px",color:"rgba(176,106,255,0.6)",padding:"6px 0",borderBottom:"1px solid rgba(0,255,136,0.04)"}}>
              {c.name} &nbsp;·&nbsp; Secure:{c.secure?"YES":"NO"} &nbsp;·&nbsp; HttpOnly:{c.httpOnly?"YES":"NO"} &nbsp;·&nbsp; SameSite:{c.sameSite||"MISSING"}
            </div>
          ))}
          {(r.cookies.issues||[]).map((issue,i)=><AlertRow key={i} text={issue} severity="warn"/>)}
        </ModuleCard>}

        {/* Green Web */}
        {r.greenWeb&&<ModuleCard title="Green Hosting" icon={<FaLeaf style={{color:r.greenWeb.green?"#b06aff":"#6b7280"}}/>} risk="LOW" summary={r.greenWeb.green?"Verified green":"Not verified"}>
          <StatRow label="GREEN VERIFIED" value={r.greenWeb.green?"[VERIFIED]":"NOT VERIFIED"} accent={r.greenWeb.green?"#b06aff":"#6b7280"}/>
          {r.greenWeb.hostedBy&&<StatRow label="HOSTED BY" value={r.greenWeb.hostedBy}/>}
        </ModuleCard>}

        {/* Email Intelligence */}
        {r.emailIntelligence&&<ModuleCard title="Email Intelligence" icon={<FaEnvelope style={{color:"#00d4ff"}}/>} risk={r.emailIntelligence.dnsbl?.listed?"HIGH":"LOW"} summary={r.emailIntelligence.dnsbl?.listed?"BLACKLISTED":"Clean"}>
          <StatRow label="BLACKLISTED" value={r.emailIntelligence.dnsbl?.listed?"YES":"NO"} accent={r.emailIntelligence.dnsbl?.listed?"#ff2222":"#b06aff"}/>
          <StatRow label="LISTED ON" value={(r.emailIntelligence.dnsbl?.listedOn||[]).join(", ")||"None"}/>
          {r.emailIntelligence.hunter?.available&&(<>
            <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:"9px",color:"rgba(0,255,136,0.4)",letterSpacing:"0.2em",margin:"12px 0 6px"}}>HUNTER.IO //</div>
            <StatRow label="ORGANIZATION" value={r.emailIntelligence.hunter.organization}/>
            <StatRow label="TOTAL EMAILS" value={r.emailIntelligence.hunter.totalEmails}/>
            <StatRow label="EMAIL PATTERN" value={r.emailIntelligence.hunter.pattern}/>
            {(r.emailIntelligence.hunter.emails||[]).slice(0,4).map((e,i)=>(
              <div key={i} style={{fontFamily:"'Share Tech Mono',monospace",fontSize:"9px",color:"rgba(176,106,255,0.6)",padding:"5px 0",borderBottom:"1px solid rgba(0,255,136,0.04)"}}>
                {e.email} · {e.confidence}% · {e.firstName} {e.lastName} {e.position?`— ${e.position}`:""}
              </div>
            ))}
          </>)}
        </ModuleCard>}

        {/* Safe Browsing */}
        {r.safeBrowsing&&<ModuleCard title="Google Safe Browsing" icon={<FaShieldAlt style={{color:r.safeBrowsing.safe===false?"#ff2222":"#b06aff"}}/>} risk={r.safeBrowsing.safe===false?"CRITICAL":"LOW"} summary={r.safeBrowsing.available?(r.safeBrowsing.safe?"Clean":`${r.safeBrowsing.threatCount} threats`):"N/A"}>
          {r.safeBrowsing.available?(<>
            <StatRow label="STATUS" value={r.safeBrowsing.safe?"[CLEAN]":"[FLAGGED]"} accent={r.safeBrowsing.safe?"#b06aff":"#ff2222"}/>
            <StatRow label="THREATS FOUND" value={r.safeBrowsing.threatCount??0}/>
            {!r.safeBrowsing.safe&&<AlertRow text={`Threats: ${r.safeBrowsing.threats?.join(", ")}`} severity="critical"/>}
            {r.safeBrowsing.safe&&<AlertRow text="Domain is not flagged in Google's threat database" severity="info"/>}
          </>):<AlertRow text={r.safeBrowsing.note||"Not configured"} severity="info"/>}
        </ModuleCard>}

        {/* VirusTotal */}
        {r.virusTotal&&<ModuleCard title="VirusTotal" icon={<FaVirus style={{color:r.virusTotal.malicious>0?"#ff6b35":"#b06aff"}}/>} risk={r.virusTotal.risk||"LOW"} summary={r.virusTotal.available?`${r.virusTotal.malicious}/${r.virusTotal.total} flagged`:"N/A"}>
          {r.virusTotal.available?(<>
            <StatRow label="MALICIOUS" value={r.virusTotal.malicious} accent={r.virusTotal.malicious>0?"#ff4444":"#b06aff"}/>
            <StatRow label="SUSPICIOUS" value={r.virusTotal.suspicious}/>
            <StatRow label="HARMLESS" value={r.virusTotal.harmless}/>
            <StatRow label="TOTAL ENGINES" value={r.virusTotal.total}/>
            <StatRow label="COMMUNITY SCORE" value={r.virusTotal.communityScore}/>
            <StatRow label="LAST ANALYSIS" value={r.virusTotal.lastAnalysis}/>
            {(r.virusTotal.popularity||[]).length>0&&<TagList items={r.virusTotal.popularity} color="#b06aff"/>}
          </>):<AlertRow text={r.virusTotal.note||"Not configured"} severity={r.virusTotal.warn?"warn":"info"}/>}
        </ModuleCard>}

        {/* Shodan */}
        {r.shodan&&<ModuleCard title="Shodan Intelligence" icon={<FaEye style={{color:r.shodan.kevCount>0?"#ff2222":r.shodan.vulnCount>0?"#ff6b35":"#00d4ff"}}/>} risk={r.shodan.risk||"LOW"} summary={r.shodan.available?(r.shodan.note?r.shodan.note.substring(0,50)+"...":`${r.shodan.portCount} ports · ${r.shodan.vulnCount} CVEs`):"N/A"}>
          {r.shodan.available?(<>
            {r.shodan.note?<AlertRow text={r.shodan.note} severity="info"/>:(<>
              <StatRow label="IP" value={r.shodan.ip}/>
              <StatRow label="ORG" value={r.shodan.org}/>
              <StatRow label="OPEN PORTS" value={(r.shodan.ports||[]).join(", ")||"None"}/>
              <StatRow label="CVE COUNT" value={r.shodan.vulnCount} accent={r.shodan.vulnCount>0?"#ff4444":"#b06aff"}/>
              <StatRow label="CISA KEV" value={r.shodan.kevCount} accent={r.shodan.kevCount>0?"#ff2222":"#b06aff"}/>
              {(r.shodan.vulnDetails||[]).slice(0,5).map((v,i)=>(
                <div key={i} style={{fontFamily:"'Share Tech Mono',monospace",fontSize:"9px",color:v.kev?"#ff2222":"rgba(176,106,255,0.6)",padding:"5px 0",borderBottom:"1px solid rgba(0,255,136,0.04)"}}>
                  {v.id} · CVSS:{v.cvss??"N/A"}{v.kev?" [CISA KEV]":""}{v.summary?` · ${v.summary.substring(0,60)}...`:""}
                </div>
              ))}
            </>)}
          </>):<AlertRow text={r.shodan.note||"Not configured"} severity="info"/>}
        </ModuleCard>}

        {/* Vulnerability modules */}
        {r.vulnerabilities&&Object.entries(r.vulnerabilities).map(([key,vuln])=>{
          const labels={sqlInjection:"SQL Injection",xss:"XSS",csrf:"CSRF",clickjacking:"Clickjacking",commandInjection:"Command Injection",sensitiveFiles:"Sensitive Files",openRedirect:"Open Redirect"};
          const found = vuln.found || vuln.vulnerable || vuln.details?.vulnerable;

          // XSS — special detailed renderer
          if (key === "xss") {
            const d = vuln.details || {};
            const reflected = d.reflected || {};
            const dom       = d.dom       || {};
            const stored    = d.stored    || {};
            const endpoints = reflected.vulnerableEndpoints || [];
            return (
              <ModuleCard key={key} title="XSS (Cross-Site Scripting)" icon={<FaBug style={{color:found?"#ff2222":"#b06aff"}}/>} risk={found?"HIGH":"LOW"} summary={found?`VULNERABLE — ${endpoints.length} reflected endpoint${endpoints.length!==1?"s":""}${dom.found?" + DOM":""}${stored.found?" + Stored":""}`:"Not detected"} defaultOpen={found}>
                <StatRow label="STATUS"    value={found?"[VULNERABLE]":"[CLEAN]"} accent={found?"#ff2222":"#b06aff"}/>
                <StatRow label="REFLECTED" value={reflected.found?`YES — ${endpoints.length} endpoint(s)`:"No"} accent={reflected.found?"#ff4444":"#b06aff"}/>
                <StatRow label="DOM XSS"   value={dom.found    ?"YES":"No"} accent={dom.found   ?"#ff4444":"#b06aff"}/>
                <StatRow label="STORED XSS" value={stored.found ?"YES":"No"} accent={stored.found?"#ff4444":"#b06aff"}/>
                <StatRow label="TESTED ENDPOINTS" value={reflected.testedEndpoints||0}/>
                {endpoints.length>0&&(<>
                  <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:"9px",color:"rgba(176,106,255,0.4)",letterSpacing:"0.2em",margin:"10px 0 6px"}}>VULNERABLE ENDPOINTS //</div>
                  {endpoints.slice(0,6).map((ep,i)=>(
                    <div key={i} style={{fontFamily:"'Share Tech Mono',monospace",fontSize:"9px",color:"#ff4444",padding:"5px 0",borderBottom:"1px solid rgba(255,34,34,0.1)"}}>
                      {typeof ep === "string" ? ep : (ep.url || ep.endpoint || JSON.stringify(ep).substring(0,80))}
                    </div>
                  ))}
                  {endpoints.length>6&&<div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:"9px",color:"rgba(255,68,68,0.5)",marginTop:"4px"}}>+{endpoints.length-6} more endpoints</div>}
                </>)}
                {found&&<AlertRow text="XSS vulnerability detected — attackers can inject malicious scripts into pages viewed by other users" severity="critical"/>}
                {!found&&<AlertRow text="No XSS vulnerabilities detected" severity="info"/>}
              </ModuleCard>
            );
          }

          return (
            <ModuleCard key={key} title={labels[key]||key} icon={<FaBug style={{color:found?"#ff2222":"#b06aff"}}/>} risk={found?"HIGH":"LOW"} summary={found?"VULNERABLE":"Not detected"} defaultOpen={found}>
              <StatRow label="STATUS" value={found?"[VULNERABLE]":"[CLEAN]"} accent={found?"#ff2222":"#b06aff"}/>
              {vuln.details?.summary&&<StatRow label="SUMMARY" value={JSON.stringify(vuln.details.summary).substring(0,80)}/>}
              {found&&<AlertRow text={`${labels[key]||key} vulnerability detected — requires immediate remediation`} severity="critical"/>}
              {!found&&<AlertRow text={`No ${labels[key]||key} vulnerabilities detected`} severity="info"/>}
            </ModuleCard>
          );
        })}

      </div>

      {/* Download PDF */}
      <div style={{marginTop:"40px",textAlign:"center"}}>
        <button onClick={onDownload} disabled={isDownloading} style={{fontFamily:"'Orbitron',monospace",fontSize:"11px",fontWeight:700,color:"#020804",background:isDownloading?"rgba(0,255,136,0.3)":"#b06aff",border:"none",borderRadius:"3px",padding:"14px 40px",cursor:isDownloading?"not-allowed":"pointer",letterSpacing:"0.15em",display:"inline-flex",alignItems:"center",gap:"10px"}}>
          <FaFileDownload/> {isDownloading?"GENERATING PDF...":"DOWNLOAD PDF REPORT"}
        </button>
        <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:"9px",color:"rgba(0,255,136,0.3)",marginTop:"8px"}}>Includes findings for all {r.selectedModules?.length||0} selected modules</div>
      </div>
    </div>
  );
}

// ── Main component ─────────────────────────────────────────────────────────────
export default function CustomScan() {
  const [input,       setInput]       = useState("");
  const [selected,    setSelected]    = useState(new Set(["dns","ssl","headers","wappalyzer","subdomains","asnGeo","virusTotal","safeBrowsing","shodan"]));
  const [scanning,    setScanning]    = useState(false);
  const [results,     setResults]     = useState(null);
  const [riskAssessment, setRisk]     = useState(null);
  const [error,       setError]       = useState("");
  const [isDownloading, setDownload]  = useState(false);
  const [scanTarget,  setScanTarget]  = useState("");
  const resultsRef = useRef(null);

  const scrollToResults = () => {
    setTimeout(() => {
      resultsRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    }, 100);
  };

  const toggleModule = (id) => {
    setSelected(prev => { const n=new Set(prev); n.has(id)?n.delete(id):n.add(id); return n; });
  };
  const toggleGroup = (groupModules) => {
    const ids = groupModules.map(m=>m.id);
    const allOn = ids.every(id=>selected.has(id));
    setSelected(prev=>{ const n=new Set(prev); ids.forEach(id=>allOn?n.delete(id):n.add(id)); return n; });
  };
  const selectAll  = () => setSelected(new Set(ALL_MODULE_IDS));
  const selectNone = () => setSelected(new Set());

  const handleScan = async () => {
    if (!input.trim()) return;
    if (selected.size===0) { setError("Select at least one module"); return; }
    setScanning(true); setResults(null); setError("");
    try {
      const res = await axios.post("http://localhost:5000/api/customscan", { url: input.trim(), modules: [...selected] }, { timeout: 300000 });
      setScanTarget(input.trim());
      setResults(res.data);
      setRisk(res.data.riskAssessment);
      scrollToResults();
    } catch (err) {
      setError(err.response?.data?.error || "Scan failed — check the target and try again");
    }
    setScanning(false);
  };

  const handleDownload = async () => {
    if (!results) return;
    setDownload(true);
    try {
      const res = await fetch("http://localhost:5000/api/report/customscan/pdf", {
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body: JSON.stringify({ target: scanTarget, scanData: results, riskAssessment }),
      });
      if (!res.ok) throw new Error();
      const blob = await res.blob();
      const url  = window.URL.createObjectURL(blob);
      const a    = document.createElement("a");
      a.href=url; a.download=`CustomScan-${scanTarget.replace(/[^a-z0-9]/gi,"_")}.pdf`; a.click();
      window.URL.revokeObjectURL(url);
    } catch { alert("Failed to download PDF report"); }
    setDownload(false);
  };

  return (
    <div style={{backgroundColor:"#020804",minHeight:"100vh",color:"#e8ffe8",overflowX:"hidden",cursor:"crosshair"}}>
      <link rel="stylesheet" href={FONT_URL}/>
      <style>{`
        @keyframes fadeUp{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}
        @keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}
        @keyframes scanPulse{0%,100%{opacity:0.5}50%{opacity:1}}
      `}</style>
      <HexGrid/>

      <div style={{position:"relative",zIndex:1,maxWidth:"900px",margin:"0 auto",padding:"40px 20px"}}>
     
      {/* Header */}
      <div style={{ marginBottom: "52px", animation: "fadeUp 0.6s ease 0.1s both" }}>
        <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "10px", letterSpacing: "0.35em", color: "rgba(176,106,255,0.5)", marginBottom: "14px" }}>{"// MODULE_03 / CUSTOM_SCAN"}</div>
        <h1 style={{ fontFamily: "'Orbitron', monospace", fontWeight: 900, fontSize: "clamp(28px,4vw,52px)", color: "#e8ffe8", letterSpacing: "0.04em", lineHeight: 1.1, marginBottom: "16px" }}>
          CUSTOM <span style={{ color: "#b06aff" }}>SCAN</span>
        </h1>
        <p style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: "17px", color: "rgba(200,180,255,0.6)", lineHeight: 1.7, maxWidth: "540px" }}>
          Select modules and run a targeted security assessment on your chosen attack surface.
        </p>
        <div style={{ width: "48px", height: "2px", background: "#b06aff", marginTop: "18px", boxShadow: "0 0 10px rgba(176,106,255,0.5)" }} />
      </div>

      {/* Target input */}
      <div style={{ background: "rgba(0,0,0,0.7)", border: "1px solid rgba(176,106,255,0.2)", borderTop: "2px solid #b06aff", padding: "36px", maxWidth: "600px", marginBottom: "32px", animation: "fadeUp 0.6s ease 0.3s both", position: "relative", overflow: "hidden" }}>
        <div style={{ position: "absolute", top: 0, right: 0, width: 0, height: 0, borderStyle: "solid", borderWidth: "0 40px 40px 0", borderColor: "transparent rgba(176,106,255,0.15) transparent transparent" }} />
        <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "9px", color: "rgba(176,106,255,0.5)", letterSpacing: "0.25em", marginBottom: "20px" }}>TARGET_INPUT // ENTER_URL_OR_DOMAIN</div>
        <label style={{ fontFamily: "'Orbitron', monospace", fontSize: "12px", letterSpacing: "0.1em", color: "#e8ffe8", display: "block", marginBottom: "12px" }}>TARGET URL</label>
        <div style={{ display: "flex", gap: "12px", flexWrap: "wrap" }}>
          <input
            value={input} onChange={e => { setInput(e.target.value); if (error) setError(""); }}
            onKeyDown={e => e.key === "Enter" && handleScan()}
            placeholder="example.com"
            style={{ flex: "1 1 240px", padding: "12px 16px", background: "rgba(0,0,0,0.8)", border: "1px solid rgba(176,106,255,0.25)", color: "#b06aff", fontFamily: "'Share Tech Mono', monospace", fontSize: "13px", outline: "none", letterSpacing: "0.05em" }}
            onFocus={e => e.target.style.borderColor = "#b06aff"}
            onBlur={e => e.target.style.borderColor = "rgba(176,106,255,0.25)"}
          />
          <button
            onClick={handleScan}
            disabled={scanning || !input.trim() || selected.size === 0}
            style={{ fontFamily: "'Orbitron', monospace", fontWeight: 700, fontSize: "11px", letterSpacing: "0.18em", color: "#020804", background: scanning || !input.trim() || selected.size === 0 ? "rgba(176,106,255,0.35)" : "#b06aff", border: "none", padding: "12px 28px", cursor: scanning || !input.trim() || selected.size === 0 ? "not-allowed" : "pointer", display: "flex", alignItems: "center", gap: "8px", boxShadow: "0 0 20px rgba(176,106,255,0.25)" }}
            onMouseEnter={e => { if (!scanning && input.trim() && selected.size > 0) { e.currentTarget.style.background = "#c490ff"; e.currentTarget.style.transform = "translateY(-2px)"; } }}
            onMouseLeave={e => { e.currentTarget.style.background = scanning || !input.trim() || selected.size === 0 ? "rgba(176,106,255,0.35)" : "#b06aff"; e.currentTarget.style.transform = "translateY(0)"; }}
          >
            {scanning ? <span style={{ animation: "spin 1s linear infinite", display: "inline-block" }}>◌</span> : <FaSlidersH />}
            {scanning ? "SCANNING..." : "SCAN"}
          </button>
        </div>
        {error && <div style={{ marginTop: "14px", fontFamily: "'Share Tech Mono', monospace", fontSize: "11px", color: "#ff6b6b", letterSpacing: "0.1em" }}>✕ ERROR: {error}</div>}
      </div>

        {/* Module selector */}
        <div style={{border:"1px solid rgba(255, 255, 255, 0.2)",borderRadius:"4px",padding:"20px",marginBottom:"28px",background:"rgba(176,106,255,0.01)"}}>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:"16px"}}>
            <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:"9px",color:"rgba(0,255,136,0.4)",letterSpacing:"0.3em"}}>MODULE_SELECTION // {selected.size}/{ALL_MODULE_IDS.length} SELECTED</div>
            <div style={{display:"flex",gap:"10px"}}>
              <button onClick={selectAll}  style={{fontFamily:"'Share Tech Mono',monospace",fontSize:"9px",color:"#b06aff",background:"rgba(176,106,255,0.08)",border:"1px solid rgba(176,106,255,0.2)",borderRadius:"2px",padding:"4px 12px",cursor:"pointer"}}>SELECT ALL</button>
              <button onClick={selectNone} style={{fontFamily:"'Share Tech Mono',monospace",fontSize:"9px",color:"rgba(176,106,255,0.5)",background:"transparent",border:"1px solid rgba(176,106,255,0.15)",borderRadius:"2px",padding:"4px 12px",cursor:"pointer"}}>CLEAR</button>
            </div>
          </div>

          {MODULE_GROUPS.map(group=>(
            <div key={group.label} style={{marginBottom:"20px"}}>
              <div style={{display:"flex",alignItems:"center",gap:"10px",marginBottom:"10px",cursor:"pointer"}} onClick={()=>toggleGroup(group.modules)}>
                <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:"9px",color:group.color,letterSpacing:"0.25em",opacity:0.8}}>{group.label}</div>
                <div style={{flex:1,height:"1px",background:`${group.color}22`}}/>
                <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:"8px",color:`${group.color}66`}}>{group.modules.filter(m=>selected.has(m.id)).length}/{group.modules.length}</div>
              </div>
              <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(200px,1fr))",gap:"8px"}}>
                {group.modules.map(mod=>{
                  const on=selected.has(mod.id);
                  return (
                    <div key={mod.id} onClick={()=>toggleModule(mod.id)}
                      style={{display:"flex",alignItems:"center",gap:"10px",padding:"10px 12px",border:`1px solid ${on?group.color+"44":"rgba(176,106,255,0.15)"}`,borderRadius:"3px",cursor:"pointer",background:on?`${group.color}08`:"transparent",transition:"all 0.15s"}}>
                      <span style={{color:on?group.color:"rgba(0,255,136,0.25)",fontSize:"11px",flexShrink:0}}>{on?<FaCheckSquare/>:<FaSquare/>}</span>
                      <span style={{color:on?group.color:"rgba(0,255,136,0.25)",fontSize:"9px",flexShrink:0}}>{mod.icon}</span>
                      <div style={{minWidth:0}}>
                        <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:"9px",color:on?group.color:"rgba(0,255,136,0.3)",fontWeight:on?700:400,whiteSpace:"nowrap",overflow:"hidden",textOverflow:"ellipsis"}}>{mod.label}</div>
                        <div style={{fontFamily:"'Rajdhani',sans-serif",fontSize:"10px",color:"rgba(0,255,136,0.25)",whiteSpace:"nowrap",overflow:"hidden",textOverflow:"ellipsis"}}>{mod.desc}</div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </div>

        {/* Scanning indicator */}
        {scanning&&(
          <div style={{textAlign:"center",padding:"60px 0"}}>
            <div style={{fontFamily:"'Orbitron',monospace",fontSize:"11px",color:"#c490ff",letterSpacing:"0.3em",animation:"scanPulse 1.5s ease-in-out infinite"}}>
              RUNNING {selected.size} MODULE{selected.size!==1?"S":""} · PLEASE WAIT...
            </div>
            <div style={{fontFamily:"'Share Tech Mono',monospace",fontSize:"9px",color:"rgba(0,255,136,0.35)",marginTop:"12px"}}>
              Vulnerability modules may take up to 3 minutes
            </div>
          </div>
        )}

        {/* Results */}
        {results&&!scanning&&(
          <div ref={resultsRef}>
            <ResultsView r={results} riskAssessment={riskAssessment} target={scanTarget} onDownload={handleDownload} isDownloading={isDownloading}/>
          </div>
        )}

      </div>
    </div>
  );
}